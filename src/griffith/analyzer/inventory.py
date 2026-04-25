"""Parse and inventory plugin components via filesystem walking.

Component discovery is filesystem-driven: plugin.json carries metadata only,
and components are enumerated from conventional directory names. Walks are
recursive (compound-engineering nests agents under agents/<category>/<name>.md)
but never follow symlinks — symlinked files and directories are recorded as
`is_symlink=True` with empty content, protecting against symlink-escape
into ~/.ssh or similar sensitive paths.

Untrusted content from the plugin (frontmatter strings, plugin name) is
sanitized before embedding in the inventory so that downstream report
consumers (Rich terminal + LMF wrapper → Claude session) don't receive
control chars, ANSI escapes, bidi overrides, or oversized payloads.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import yaml

from griffith.sanitize import sanitize_frontmatter, sanitize_string

# Per-file size cap for content reads. Files above this are enumerated but
# not opened for line counting or frontmatter parsing. Matches the limit
# documented in the Phase 1 plan (Key Technical Decisions → Size caps).
MAX_READ_BYTES = 2 * 1024 * 1024  # 2 MB

# Directory names pruned from the walk by default. These are either
# vendored-dependency trees (scanning them produces false-positive noise
# against third-party code that isn't the plugin's own) or build output
# caches that shouldn't be audited. Matches the set osv-scanner's
# --experimental-exclude already uses for Tier 2 CVE lookup, plus
# __pycache__ which is never meaningful plugin content.
#
# Callers that want to audit everything (e.g. for supply-chain review
# of a specific dependency) can pass `skip_dirs=frozenset()` to
# `PluginInventory.from_path`.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "vendor",
    "__pycache__",
})


@dataclass
class ComponentFile:
    """A single file discovered in a plugin component directory."""

    path: str  # relative to plugin root, forward-slash
    lines: int = 0
    is_symlink: bool = False
    size_skipped: bool = False
    frontmatter: dict = field(default_factory=dict)


@dataclass
class PluginInventory:
    """Component inventory for a single plugin tree."""

    name: str
    path: Path
    agents: list[ComponentFile] = field(default_factory=list)
    commands: list[ComponentFile] = field(default_factory=list)
    skills: list[ComponentFile] = field(default_factory=list)
    hooks: list[ComponentFile] = field(default_factory=list)
    mcp_servers: list[ComponentFile] = field(default_factory=list)
    personas: list[ComponentFile] = field(default_factory=list)
    templates: list[ComponentFile] = field(default_factory=list)
    unknown: list[ComponentFile] = field(default_factory=list)
    manifest: dict | None = None
    warnings: list[str] = field(default_factory=list)
    # Top-level directory names that were pruned from the walk because
    # they matched `skip_dirs` (e.g. node_modules, vendor). Empty when
    # the plugin had no vendored dirs or when `--include-vendored` was
    # passed. Surfaced in the rendered report so users know what wasn't
    # scanned.
    skipped_dirs: list[str] = field(default_factory=list)

    # Conventional directories that this inventory knows how to categorize.
    _CONVENTIONAL_DIRS: ClassVar[set[str]] = {
        "agents",
        "commands",
        "skills",
        "hooks",
        "mcp_servers",
        "mcp-servers",
        "personas",
        "templates",
    }

    # --- @property count derivations -----------------------------------------

    @property
    def agents_count(self) -> int:
        return len(self.agents)

    @property
    def commands_count(self) -> int:
        return len(self.commands)

    @property
    def skills_count(self) -> int:
        return len(self.skills)

    @property
    def hooks_count(self) -> int:
        return len(self.hooks)

    @property
    def mcp_servers_count(self) -> int:
        return len(self.mcp_servers)

    @property
    def personas_count(self) -> int:
        return len(self.personas)

    @property
    def templates_count(self) -> int:
        return len(self.templates)

    @property
    def unknown_count(self) -> int:
        return len(self.unknown)

    @property
    def total_files(self) -> int:
        return (
            self.agents_count
            + self.commands_count
            + self.skills_count
            + self.hooks_count
            + self.mcp_servers_count
            + self.personas_count
            + self.templates_count
            + self.unknown_count
        )

    @property
    def total_lines(self) -> int:
        buckets = (
            self.agents,
            self.commands,
            self.skills,
            self.hooks,
            self.mcp_servers,
            self.personas,
            self.templates,
            self.unknown,
        )
        return sum(cf.lines for bucket in buckets for cf in bucket)

    # --- construction --------------------------------------------------------

    @classmethod
    def from_path(
        cls,
        path: Path | str,
        *,
        skip_dirs: frozenset[str] | None = None,
    ) -> PluginInventory:
        """Walk a plugin directory and return a structured inventory.

        `skip_dirs` is the set of directory names pruned from the walk at
        every level (vendored trees, build output). Defaults to
        `DEFAULT_SKIP_DIRS`. Pass `frozenset()` to scan everything,
        including `node_modules/`.
        """
        plugin_root = Path(path)
        if not plugin_root.exists():
            raise FileNotFoundError(f"Plugin path does not exist: {plugin_root}")
        if not plugin_root.is_dir():
            raise NotADirectoryError(f"Plugin path is not a directory: {plugin_root}")

        plugin_root = plugin_root.resolve()

        if skip_dirs is None:
            skip_dirs = DEFAULT_SKIP_DIRS

        manifest, manifest_warnings = _load_manifest(plugin_root)
        name = _derive_name(manifest, plugin_root)

        inv = cls(name=name, path=plugin_root, manifest=manifest, warnings=list(manifest_warnings))

        inv.agents = _walk_component(plugin_root, "agents", _is_markdown, skip_dirs)
        inv.commands = _walk_component(plugin_root, "commands", _is_markdown, skip_dirs)
        inv.skills = _collect_skills(plugin_root)
        inv.hooks = _walk_component(plugin_root, "hooks", _is_any_file, skip_dirs)
        inv.mcp_servers = _walk_component(
            plugin_root, "mcp_servers", _is_any_file, skip_dirs
        ) + _walk_component(plugin_root, "mcp-servers", _is_any_file, skip_dirs)
        inv.personas = _walk_component(plugin_root, "personas", _is_markdown, skip_dirs)
        inv.templates = _walk_component(plugin_root, "templates", _is_any_file, skip_dirs)
        inv.unknown, skipped_at_root = _collect_unknown(
            plugin_root, inv._CONVENTIONAL_DIRS, skip_dirs
        )

        inv.skipped_dirs = sorted(skipped_at_root)
        for skipped in inv.skipped_dirs:
            inv.warnings.append(f"Skipped vendored directory: {skipped}/")

        return inv


# ============================================================================
# Helpers
# ============================================================================


def _load_manifest(plugin_root: Path) -> tuple[dict | None, list[str]]:
    manifest_path = plugin_root / ".claude-plugin" / "plugin.json"
    if not manifest_path.exists():
        return None, [f"Missing .claude-plugin/plugin.json at {plugin_root}"]
    try:
        with manifest_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return None, [f"Failed to parse plugin.json: {e}"]
    if not isinstance(raw, dict):
        return None, [f"plugin.json must be a JSON object, got {type(raw).__name__}"]
    return raw, []


def _derive_name(manifest: dict | None, plugin_root: Path) -> str:
    if manifest and isinstance(manifest.get("name"), str):
        return sanitize_string(manifest["name"], 80)
    return plugin_root.name


def _is_markdown(filename: str) -> bool:
    return filename.endswith(".md")


def _is_any_file(filename: str) -> bool:
    # Skip editor tempfiles and other dotfiles; everything else counts.
    if filename.startswith(".") or filename.endswith("~"):
        return False
    return True


def _walk_component(
    plugin_root: Path,
    subdir_name: str,
    file_predicate,
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
) -> list[ComponentFile]:
    """Walk `plugin_root/subdir_name` recursively without following symlinks.

    Subdirectories that are symlinks are recorded but not descended into.
    Directories whose name is in `skip_dirs` are pruned silently (vendored
    trees, build caches).
    Files that are symlinks are recorded with empty content and `is_symlink=True`.
    Files whose real path escapes the plugin root are skipped (realpath containment).
    """
    base = plugin_root / subdir_name
    if not base.exists():
        return []
    if base.is_symlink():
        return [_symlink_component(plugin_root, base)]
    if not base.is_dir():
        return []

    results: list[ComponentFile] = []
    plugin_root_real = plugin_root.resolve()

    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        # Prune vendored / build dirs from the walk before we descend.
        # Mutating `dirnames` in place is the documented mechanism for
        # os.walk to skip descent.
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]

        # Record and prune symlinked subdirs so they don't descend.
        for d in list(dirnames):
            sub = Path(dirpath) / d
            if sub.is_symlink():
                results.append(_symlink_component(plugin_root, sub))
                dirnames.remove(d)

        for fname in filenames:
            if not file_predicate(fname):
                continue
            full = Path(dirpath) / fname
            if full.is_symlink():
                results.append(_symlink_component(plugin_root, full))
                continue
            try:
                real = full.resolve()
            except OSError:
                continue
            if not _is_within(real, plugin_root_real):
                continue
            results.append(_read_component(full, plugin_root))

    return results


def _collect_skills(plugin_root: Path) -> list[ComponentFile]:
    """Skills follow the `skills/<name>/SKILL.md` convention — not arbitrary *.md."""
    base = plugin_root / "skills"
    if not base.exists() or base.is_symlink() or not base.is_dir():
        return []
    results: list[ComponentFile] = []
    plugin_root_real = plugin_root.resolve()
    for child in base.iterdir():
        if child.is_symlink():
            results.append(_symlink_component(plugin_root, child))
            continue
        if not child.is_dir():
            continue
        skill_file = child / "SKILL.md"
        if not skill_file.exists():
            continue
        if skill_file.is_symlink():
            results.append(_symlink_component(plugin_root, skill_file))
            continue
        try:
            real = skill_file.resolve()
        except OSError:
            continue
        if not _is_within(real, plugin_root_real):
            continue
        results.append(_read_component(skill_file, plugin_root))
    return results


def _collect_unknown(
    plugin_root: Path,
    conventional: set[str],
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
) -> tuple[list[ComponentFile], set[str]]:
    """Any top-level directory not in the conventional set is recorded as `unknown`.

    Directories whose name is in `skip_dirs` are pruned at top level and
    during descent. Returns the component list plus the set of top-level
    directory names that were pruned (so the caller can surface them as
    warnings).
    """
    results: list[ComponentFile] = []
    skipped_at_root: set[str] = set()
    plugin_root_real = plugin_root.resolve()
    for child in plugin_root.iterdir():
        if not child.is_dir():
            continue
        # Skip dotdirs (e.g., .claude-plugin, .git).
        if child.name.startswith("."):
            continue
        if child.name in conventional:
            continue
        if child.name in skip_dirs:
            skipped_at_root.add(child.name)
            continue
        if child.is_symlink():
            results.append(_symlink_component(plugin_root, child))
            continue
        # Walk and collect files from unknown dir
        for dirpath, dirnames, filenames in os.walk(child, followlinks=False):
            # Prune vendored / build dirs during descent too.
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for d in list(dirnames):
                sub = Path(dirpath) / d
                if sub.is_symlink():
                    results.append(_symlink_component(plugin_root, sub))
                    dirnames.remove(d)
            for fname in filenames:
                full = Path(dirpath) / fname
                if full.is_symlink():
                    results.append(_symlink_component(plugin_root, full))
                    continue
                try:
                    real = full.resolve()
                except OSError:
                    continue
                if not _is_within(real, plugin_root_real):
                    continue
                results.append(_read_component(full, plugin_root))
    return results, skipped_at_root


def _symlink_component(plugin_root: Path, path: Path) -> ComponentFile:
    try:
        rel = path.relative_to(plugin_root)
    except ValueError:
        rel = Path(path.name)
    return ComponentFile(path=str(rel), lines=0, is_symlink=True, size_skipped=False)


def _read_component(path: Path, plugin_root: Path) -> ComponentFile:
    rel = str(path.relative_to(plugin_root))
    try:
        size = path.stat().st_size
    except OSError:
        return ComponentFile(path=rel, lines=0, size_skipped=True)

    if size > MAX_READ_BYTES:
        return ComponentFile(path=rel, lines=0, size_skipped=True)

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ComponentFile(path=rel, lines=0, size_skipped=True)

    lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
    frontmatter = _parse_frontmatter(content)
    return ComponentFile(path=rel, lines=lines, frontmatter=frontmatter)


def _parse_frontmatter(content: str) -> dict:
    """Extract YAML frontmatter from a markdown file. `yaml.safe_load` only."""
    if not content.startswith("---"):
        return {}
    first_line_end = content.find("\n")
    if first_line_end == -1:
        return {}
    body = content[first_line_end + 1 :]
    end = body.find("\n---")
    if end == -1:
        return {}
    yaml_text = body[:end]
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return sanitize_frontmatter(parsed)


def _is_within(candidate: Path, root: Path) -> bool:
    """True if `candidate` is inside `root` (after symlink resolution)."""
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False
