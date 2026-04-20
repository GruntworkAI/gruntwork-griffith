"""Griffith CLI — plugin analysis and comparison tools."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from griffith.analyzer import (
    ArchitectureAssessor,
    DependencyAnalyzer,
    FootprintEstimator,
    PluginInventory,
    SecurityScanner,
)
from griffith.analyzer.osv_adapter import INSTALL_PITCH, OSVScannerMissingError
from griffith.reporter import render_json, render_rich
from griffith.schema import (
    Report,
    SourceType,
    build_marketplace_report,
    build_report,
)
from griffith.sources import GriffithCloneError, resolve

console_err = Console(stderr=True)


@click.group()
@click.version_option()
def main():
    """Griffith - Plugin Observatory for Claude Code.

    Analyze, compare, and monitor Claude Code plugins.
    """
    pass


@main.command()
@click.argument("source")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON to stdout.")
@click.option(
    "--strict",
    is_flag=True,
    help="Enable broader (noisier) security rules.",
)
@click.option(
    "--sca",
    is_flag=True,
    help=(
        "Run Tier 2 supply-chain analysis (requires osv-scanner on PATH). "
        "Hard-fails with exit code 2 when osv-scanner is unavailable."
    ),
)
def analyze(source: str, as_json: bool, strict: bool, sca: bool):
    """Analyze a plugin from a git URL, GitHub shorthand, or local path.

    SOURCE can be:

      - GitHub shorthand: owner/repo

      - Git URL: https://..., http://..., git@host:org/repo.git

      - Local path: ./my-plugin or /absolute/path
    """
    try:
        with resolve(source) as (path, source_type):
            _run_analysis(
                path, source, source_type,
                as_json=as_json, strict=strict, sca=sca,
            )
    except OSVScannerMissingError as e:
        console_err.print(f"[bold red]--sca requested but osv-scanner not found:[/] {e}")
        console_err.print()
        console_err.print(INSTALL_PITCH)
        sys.exit(2)
    except GriffithCloneError as e:
        console_err.print(f"[bold red]Clone failed:[/] {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        console_err.print(f"[bold red]Not found:[/] {e}")
        sys.exit(1)
    except ValueError as e:
        console_err.print(f"[bold red]Invalid source:[/] {e}")
        sys.exit(1)


def _run_analysis(
    path: Path,
    source: str,
    source_type: SourceType,
    *,
    as_json: bool,
    strict: bool,
    sca: bool,
) -> None:
    """Detect single-plugin vs marketplace, analyze, render.

    Marketplace detection: presence of `.claude-plugin/marketplace.json`
    is the sole signal. Bundled marketplaces (with a `plugins/` subdir),
    federated marketplaces (entries with URL / path source objects),
    and mixed marketplaces (both) are all handled uniformly by reading
    the manifest's `plugins[]` array.
    """
    marketplace_manifest = path / ".claude-plugin" / "marketplace.json"

    if marketplace_manifest.exists():
        reports = _analyze_marketplace(
            path, marketplace_manifest, source, source_type,
            strict=strict, sca=sca,
        )
        mp_report = build_marketplace_report(
            reports=reports,
            source=source,
            source_type=source_type,
            marketplace_path=str(path),
        )
        if as_json:
            render_json(mp_report)
        else:
            render_rich(mp_report)
        return

    # Single plugin path
    report = _analyze_single(path, source, source_type, strict=strict, sca=sca)
    if as_json:
        render_json(report)
    else:
        render_rich(report)


def _analyze_single(
    plugin_path: Path,
    source: str,
    source_type: SourceType,
    *,
    strict: bool,
    sca: bool = False,
    plugin_path_override: str | None = None,
) -> Report:
    inv = PluginInventory.from_path(plugin_path)
    scanner = SecurityScanner(strict=strict)
    sec_findings = scanner.scan(inv)
    footprint = FootprintEstimator().estimate(inv)
    architecture = ArchitectureAssessor().assess(inv)
    dependency_report = DependencyAnalyzer().analyze(plugin_path, sca=sca)
    return build_report(
        inventory=inv,
        security_findings=sec_findings,
        footprint=footprint,
        architecture=architecture,
        dependency_report=dependency_report,
        source=source,
        source_type=source_type,
        plugin_path_override=plugin_path_override,
        ast_parse_failures=scanner.ast_parse_failures,
    )


def _analyze_marketplace(
    marketplace_root: Path,
    marketplace_manifest: Path,
    source: str,
    source_type: SourceType,
    *,
    strict: bool,
    sca: bool,
) -> list[Report]:
    """Walk a marketplace manifest and analyze each plugin entry.

    Each entry in `plugins[]` has a `source` field of one of three shapes:

    - string starting with `./` or `/` — bundled, relative to marketplace root
    - {"source": "url", "url": "..."} — federated, cloned via sources.resolve
    - {"source": "path", "path": "..."} — federated, local path

    Bundled entries keep the existing semantics: plugin.source = outer
    source, plugin.path = relative path under marketplace root.
    Federated entries use a concatenated source field
    (`outer_source → inner_ref`) so the rendered audit shows full
    provenance at a glance.

    Per-plugin clone failures propagate — a failed clone raises
    GriffithCloneError, which the CLI handler maps to exit 1. Assumption:
    clone failures are rare + typically transient; user reruns rather
    than consuming a partial marketplace report.
    """
    try:
        with marketplace_manifest.open() as f:
            manifest_data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(
            f"Could not read marketplace manifest at {marketplace_manifest}: {e}"
        )

    entries = manifest_data.get("plugins") or []
    if not isinstance(entries, list):
        raise ValueError(
            f"marketplace.json `plugins` must be a list, got {type(entries).__name__}"
        )

    reports: list[Report] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        reports.append(
            _analyze_marketplace_entry(
                entry, marketplace_root, source, strict=strict, sca=sca,
            )
        )
    return reports


def _analyze_marketplace_entry(
    entry: dict[str, Any],
    marketplace_root: Path,
    outer_source: str,
    *,
    strict: bool,
    sca: bool,
) -> Report:
    """Analyze a single marketplace entry, dispatching on its source shape."""
    entry_source = entry.get("source")

    # Shape 1: string source → bundled, relative to marketplace root.
    if isinstance(entry_source, str):
        rel = entry_source.removeprefix("./")
        plugin_path = (marketplace_root / rel).resolve()
        if not plugin_path.exists():
            raise FileNotFoundError(
                f"Bundled plugin path does not exist: {plugin_path} "
                f"(from marketplace.json entry {entry.get('name', '?')!r})"
            )
        return _analyze_single(
            plugin_path,
            outer_source,  # bundled keeps outer-source semantics
            "path",
            strict=strict, sca=sca,
            plugin_path_override=rel,
        )

    # Shape 2+: object source → federated.
    if isinstance(entry_source, dict):
        kind = entry_source.get("source")
        if kind == "url":
            inner_url = entry_source.get("url", "")
            if not inner_url:
                raise ValueError(
                    f"Federated marketplace entry {entry.get('name', '?')!r} "
                    f"has source type=url but no url field"
                )
            concat_source = f"{outer_source} → {inner_url}"
            # Clone the inner URL (hardened) and analyze.
            with resolve(inner_url) as (inner_path, _inner_type):
                return _analyze_single(
                    inner_path,
                    concat_source,
                    "url",
                    strict=strict, sca=sca,
                    plugin_path_override=".",
                )
        if kind == "path":
            inner_path_str = entry_source.get("path", "")
            if not inner_path_str:
                raise ValueError(
                    f"Federated marketplace entry {entry.get('name', '?')!r} "
                    f"has source type=path but no path field"
                )
            inner_path = (marketplace_root / inner_path_str).resolve()
            if not inner_path.exists():
                raise FileNotFoundError(
                    f"Federated path source does not exist: {inner_path} "
                    f"(from marketplace.json entry {entry.get('name', '?')!r})"
                )
            concat_source = f"{outer_source} → {inner_path_str}"
            return _analyze_single(
                inner_path,
                concat_source,
                "path",
                strict=strict, sca=sca,
                plugin_path_override=".",
            )
        raise ValueError(
            f"Unknown federated source kind {kind!r} in marketplace entry "
            f"{entry.get('name', '?')!r} (expected 'url' or 'path')"
        )

    raise ValueError(
        f"Marketplace entry {entry.get('name', '?')!r} has malformed source: "
        f"expected string or object, got {type(entry_source).__name__}"
    )


@main.command()
@click.argument("plugin1")
@click.argument("plugin2")
def compare(plugin1: str, plugin2: str):
    """Compare two plugins side-by-side.

    [Stub — full implementation deferred to Phase 1.5.]
    """
    console_err.print(
        "[yellow]compare not yet implemented; see docs/design.md Phase 2.[/]"
    )
    sys.exit(1)


@main.command(name="scan-installed")
def scan_installed():
    """Scan all installed plugins for analysis.

    [Stub — full implementation deferred to Phase 1.5.]
    """
    console_err.print(
        "[yellow]scan-installed not yet implemented; see docs/design.md Phase 2.[/]"
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
