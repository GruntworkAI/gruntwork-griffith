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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

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

        return DependencyReport(
            manifests=manifests,
            lockfiles=lockfiles,
            packages=[],
            unscanned_manifests=[],
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
