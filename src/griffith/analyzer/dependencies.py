"""DependencyAnalyzer — Tier 1 detection (walk + recognize manifests/lockfiles).

Phase 1.5 Unit 1 scope: detection only. Walks a plugin tree and records paths
of recognized manifest and lockfile files. Does NOT parse contents; packages
remain empty. Parsing for Python + Node lands in Units 2-3; CVE scanning via
osv-scanner lands in Unit 6.

Hardening invariants (mirrors Inventory):
- os.walk(followlinks=False) — symlinked directories are listed but not
  descended into
- Symlinked manifest/lockfile files are recorded with is_symlink=True;
  content is never read
- Files larger than MAX_READ_BYTES (2 MB) are recorded with size_skipped=True
  so downstream parsers (Units 2-3) skip them
- .git/ subdirectories are skipped during the walk

Wider vendored-tree handling (node_modules/, .venv/, vendor/) is explicitly
deferred to Phase 1.6.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from griffith.sanitize import (
    DEFAULT_MAX_DESCRIPTION_LENGTH,
    DEFAULT_MAX_NAME_LENGTH,
    sanitize_string,
)

# Per-file read cap inherited from Inventory's MAX_READ_BYTES convention.
MAX_READ_BYTES = 2 * 1024 * 1024  # 2 MB

ScanStatus = Literal[
    "ok",
    "tier1_only",
    "sca_requested_and_failed",
    "sca_requested_and_timed_out",
    "sca_malformed_output",
]

# Directories pruned during the walk. Kept minimal for Phase 1.5 —
# Vendored-code detection (node_modules/, .venv/, vendor/) is a separate
# follow-up.
_SKIP_DIR_NAMES: set[str] = {".git"}

# Manifest filenames that map directly by exact-name match.
_EXACT_MANIFEST_NAMES: set[str] = {
    "pyproject.toml",
    "package.json",
    "Gemfile",
    "go.mod",
    "Cargo.toml",
}

# requirements.txt, requirements-dev.txt, requirements_test.txt, etc.
_REQUIREMENTS_TXT_RE = re.compile(r"^requirements[\w.\-]*\.txt$")

# Anchored bounded regex for package specs (PEP 508-ish).
# - Group 1: package name (ASCII letters/digits/._-); 1-200 chars
# - Group 2: optional extras block like [extra1,extra2] (up to 100 chars)
# - Group 3: rest of line (constraint like >=1.0,<2.0 or env marker)
# Anchored + bounded repetition → ReDoS-safe against megabyte inputs.
_REQ_SPEC_RE = re.compile(r"^([A-Za-z0-9._-]{1,200})(\[[^\]]{0,100}\])?\s*(.*)$")

# Recursion limit used for untrusted TOML parsing (depth-bomb defense).
_PARSE_RECURSION_LIMIT = 500

# Lockfile filenames.
_LOCKFILE_NAMES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
    "go.sum",
    "Cargo.lock",
    "poetry.lock",
}


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class ManifestInfo:
    """A manifest or lockfile discovered in the plugin tree."""

    path: str  # relative to plugin root, forward-slash
    is_symlink: bool = False
    size_skipped: bool = False


@dataclass
class DependencyPackage:
    """A declared package. Populated in Units 2-3 (not Unit 1)."""

    ecosystem: str  # "PyPI", "npm", "rubygems", "go", "cargo"
    name: str
    constraint: str  # as-written, possibly empty
    kind: str  # "runtime" | "dev" | "optional" | "peer"
    manifest: str  # relative path of declaring manifest


@dataclass
class Vulnerability:
    """A CVE finding from osv-scanner. Populated in Unit 6 (not Unit 1)."""

    id: str  # CVE-2024-12345 or GHSA-...
    severity: str  # Griffith severity enum: critical|high|medium|low|info|unknown
    severity_raw: str  # as emitted by osv-scanner (CVSS numeric or vector string)
    summary: str
    affected_package: str
    fixed_versions: list[str] = field(default_factory=list)


@dataclass
class SCAResult:
    """Tier 2 CVE result. None when --sca not set. Populated in Unit 6."""

    osv_scanner_version: str
    vulnerability_count: int
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    note: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DependencyReport:
    """Tier 1 detection output plus optional Tier 2 SCA result."""

    manifests: list[ManifestInfo] = field(default_factory=list)
    lockfiles: list[ManifestInfo] = field(default_factory=list)
    packages: list[DependencyPackage] = field(default_factory=list)
    unscanned_manifests: list[str] = field(default_factory=list)
    scan_status: ScanStatus = "tier1_only"
    sca: Optional[SCAResult] = None

    @property
    def package_count(self) -> int:
        return len(self.packages)

    @property
    def ecosystems(self) -> list[str]:
        return sorted({p.ecosystem for p in self.packages})


# ============================================================================
# DependencyAnalyzer
# ============================================================================


class DependencyAnalyzer:
    """Walk a plugin tree, detect manifests + lockfiles.

    Phase 1.5 Unit 1 scope: detection only. `sca=True` raises
    `NotImplementedError` until Unit 6 lands the osv-scanner integration.
    """

    def analyze(
        self,
        plugin_path: Path | str,
        sca: bool = False,
    ) -> DependencyReport:
        if sca:
            raise NotImplementedError(
                "Tier 2 (--sca CVE scan) is not implemented until Phase 1.5 "
                "Unit 6. Call analyze(path, sca=False) for Tier 1 listing."
            )

        plugin_root = Path(plugin_path)
        if not plugin_root.exists():
            raise FileNotFoundError(
                f"Plugin path does not exist: {plugin_root}"
            )
        if not plugin_root.is_dir():
            raise NotADirectoryError(
                f"Plugin path is not a directory: {plugin_root}"
            )

        plugin_root = plugin_root.resolve()

        manifests: list[ManifestInfo] = []
        lockfiles: list[ManifestInfo] = []

        for dirpath, dirnames, filenames in os.walk(
            plugin_root, followlinks=False
        ):
            # Prune .git subtrees in-place so os.walk skips them.
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]

            for fname in filenames:
                full = Path(dirpath) / fname
                if _is_manifest_name(fname):
                    manifests.append(_make_info(full, plugin_root))
                elif fname in _LOCKFILE_NAMES:
                    lockfiles.append(_make_info(full, plugin_root))

        # Stable ordering so downstream serialization is deterministic.
        manifests.sort(key=lambda m: m.path)
        lockfiles.sort(key=lambda lf: lf.path)

        # Unit 2+: parse manifests into packages (Python in Unit 2;
        # Node in Unit 3; Ruby/Go/Rust deferred).
        packages: list[DependencyPackage] = []
        unscanned_manifests: list[str] = []
        for m in manifests:
            if m.is_symlink or m.size_skipped:
                continue
            full = plugin_root / m.path
            if full.name == "pyproject.toml":
                packages.extend(_parse_pyproject(full, m.path, unscanned_manifests))
            elif _REQUIREMENTS_TXT_RE.fullmatch(full.name):
                packages.extend(_parse_requirements_txt(full, m.path, unscanned_manifests))
            # else: package.json / Gemfile / go.mod / Cargo.toml — not yet parsed

        return DependencyReport(
            manifests=manifests,
            lockfiles=lockfiles,
            packages=packages,
            unscanned_manifests=unscanned_manifests,
            scan_status="tier1_only",
            sca=None,
        )


# ============================================================================
# Helpers
# ============================================================================


def _is_manifest_name(filename: str) -> bool:
    if filename in _EXACT_MANIFEST_NAMES:
        return True
    if _REQUIREMENTS_TXT_RE.fullmatch(filename):
        return True
    return False


def _make_info(path: Path, plugin_root: Path) -> ManifestInfo:
    """Build a ManifestInfo from a discovered file path.

    Sets is_symlink when the file is itself a symlink (content is not read).
    Sets size_skipped when the file exceeds MAX_READ_BYTES or stat() fails.
    Relative path uses forward-slashes to match Inventory's convention.
    """
    rel = str(path.relative_to(plugin_root))
    if path.is_symlink():
        return ManifestInfo(path=rel, is_symlink=True, size_skipped=False)
    try:
        size = path.stat().st_size
    except OSError:
        return ManifestInfo(path=rel, is_symlink=False, size_skipped=True)
    size_skipped = size > MAX_READ_BYTES
    return ManifestInfo(path=rel, is_symlink=False, size_skipped=size_skipped)


# ============================================================================
# Python parsers — Unit 2
# ============================================================================


def _parse_requirements_txt(
    full_path: Path,
    rel_path: str,
    unscanned: list[str],
) -> list[DependencyPackage]:
    """Parse a requirements.txt file line-by-line.

    Skips comments, blank lines, and pip-option lines (-r, -e, -c, --flags).
    Malformed package-spec lines are skipped silently; file-level read
    failures add the manifest to `unscanned`.
    """
    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        unscanned.append(rel_path)
        return []

    packages: list[DependencyPackage] = []
    for raw_line in content.splitlines():
        # Strip inline comments (# and anything after)
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-"):
            continue  # -r, -e, -c, --extra-index-url, etc.
        pkg = _pep508_spec_to_package(line, "runtime", rel_path)
        if pkg is not None:
            packages.append(pkg)
    return packages


def _parse_pyproject(
    full_path: Path,
    rel_path: str,
    unscanned: list[str],
) -> list[DependencyPackage]:
    """Parse a pyproject.toml file covering both PEP 621 and Poetry sections.

    Parse order: PEP 621 first, then Poetry. Dedup by (name, kind) keeping
    the first-seen constraint so PEP 621 (the modern standard) wins when
    both declare the same package+kind.

    Depth-bomb defense: temporarily lower sys.setrecursionlimit to
    _PARSE_RECURSION_LIMIT around the tomllib.load call and catch any
    resulting RecursionError alongside TOMLDecodeError / OSError.
    """
    original_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(_PARSE_RECURSION_LIMIT)
        with full_path.open("rb") as f:
            data = tomllib.load(f)
    except (RecursionError, tomllib.TOMLDecodeError, OSError, ValueError):
        unscanned.append(rel_path)
        return []
    finally:
        sys.setrecursionlimit(original_limit)

    if not isinstance(data, dict):
        unscanned.append(rel_path)
        return []

    packages: list[DependencyPackage] = []
    seen: set[tuple[str, str]] = set()

    # PEP 621 first
    project = data.get("project")
    if isinstance(project, dict):
        for spec in project.get("dependencies") or []:
            pkg = _pep508_spec_to_package(spec, "runtime", rel_path)
            if pkg is not None and (pkg.name, pkg.kind) not in seen:
                packages.append(pkg)
                seen.add((pkg.name, pkg.kind))
        optional_deps = project.get("optional-dependencies") or {}
        if isinstance(optional_deps, dict):
            for specs in optional_deps.values():
                if not isinstance(specs, list):
                    continue
                for spec in specs:
                    pkg = _pep508_spec_to_package(spec, "optional", rel_path)
                    if pkg is not None and (pkg.name, pkg.kind) not in seen:
                        packages.append(pkg)
                        seen.add((pkg.name, pkg.kind))

    # Poetry second (PEP 621 wins on dedup)
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            main_deps = poetry.get("dependencies") or {}
            if isinstance(main_deps, dict):
                for name, value in main_deps.items():
                    if name == "python":
                        continue  # python version spec, not a dep
                    pkg = _poetry_value_to_package(name, value, "runtime", rel_path)
                    if pkg is not None and (pkg.name, pkg.kind) not in seen:
                        packages.append(pkg)
                        seen.add((pkg.name, pkg.kind))
            groups = poetry.get("group") or {}
            if isinstance(groups, dict):
                for group_name, group_data in groups.items():
                    if not isinstance(group_data, dict):
                        continue
                    kind = "dev" if group_name in ("dev", "test") else "optional"
                    group_deps = group_data.get("dependencies") or {}
                    if not isinstance(group_deps, dict):
                        continue
                    for name, value in group_deps.items():
                        if name == "python":
                            continue
                        pkg = _poetry_value_to_package(name, value, kind, rel_path)
                        if pkg is not None and (pkg.name, pkg.kind) not in seen:
                            packages.append(pkg)
                            seen.add((pkg.name, pkg.kind))

    return packages


def _pep508_spec_to_package(
    spec: object,
    kind: str,
    manifest: str,
) -> Optional[DependencyPackage]:
    """Convert a PEP 508-ish spec string into a DependencyPackage.

    Returns None if the spec is not a string or doesn't match the anchored
    bounded regex.
    """
    if not isinstance(spec, str):
        return None
    stripped = spec.strip()
    if not stripped:
        return None
    m = _REQ_SPEC_RE.match(stripped)
    if not m:
        return None
    name = m.group(1)
    constraint = m.group(3).strip()
    return DependencyPackage(
        ecosystem="PyPI",
        name=sanitize_string(name, DEFAULT_MAX_NAME_LENGTH),
        constraint=sanitize_string(constraint, DEFAULT_MAX_DESCRIPTION_LENGTH),
        kind=kind,
        manifest=manifest,
    )


def _poetry_value_to_package(
    name: str,
    value: object,
    kind: str,
    manifest: str,
) -> Optional[DependencyPackage]:
    """Convert a Poetry dep value (string or table) into a DependencyPackage.

    Table form: `{version = "^1.0", extras = [...]}` — extract `version`
    field; fall back to empty constraint if absent.
    """
    if isinstance(value, str):
        constraint = value
    elif isinstance(value, dict):
        version = value.get("version", "")
        constraint = version if isinstance(version, str) else ""
    else:
        return None
    return DependencyPackage(
        ecosystem="PyPI",
        name=sanitize_string(name, DEFAULT_MAX_NAME_LENGTH),
        constraint=sanitize_string(constraint, DEFAULT_MAX_DESCRIPTION_LENGTH),
        kind=kind,
        manifest=manifest,
    )
