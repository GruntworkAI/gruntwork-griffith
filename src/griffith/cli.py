"""Griffith CLI — plugin analysis and comparison tools."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from griffith.analyzer import (
    ArchitectureAssessor,
    FootprintEstimator,
    PluginInventory,
    SecurityScanner,
)
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
def analyze(source: str, as_json: bool, strict: bool):
    """Analyze a plugin from a git URL, GitHub shorthand, or local path.

    SOURCE can be:

      - GitHub shorthand: owner/repo

      - Git URL: https://..., http://..., git@host:org/repo.git

      - Local path: ./my-plugin or /absolute/path
    """
    try:
        with resolve(source) as (path, source_type):
            _run_analysis(path, source, source_type, as_json=as_json, strict=strict)
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
) -> None:
    """Detect single-plugin vs marketplace, analyze, render."""
    marketplace_manifest = path / ".claude-plugin" / "marketplace.json"
    plugins_dir = path / "plugins"

    if marketplace_manifest.exists() and plugins_dir.is_dir():
        reports = _analyze_marketplace(
            path, plugins_dir, source, source_type, strict=strict
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
    report = _analyze_single(path, source, source_type, strict=strict)
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
    plugin_path_override: str | None = None,
) -> Report:
    inv = PluginInventory.from_path(plugin_path)
    sec_findings = SecurityScanner(strict=strict).scan(inv)
    footprint = FootprintEstimator().estimate(inv)
    architecture = ArchitectureAssessor().assess(inv)
    return build_report(
        inventory=inv,
        security_findings=sec_findings,
        footprint=footprint,
        architecture=architecture,
        source=source,
        source_type=source_type,
        plugin_path_override=plugin_path_override,
    )


def _analyze_marketplace(
    marketplace_root: Path,
    plugins_dir: Path,
    source: str,
    source_type: SourceType,
    *,
    strict: bool,
) -> list[Report]:
    reports: list[Report] = []
    for child in sorted(plugins_dir.iterdir()):
        if not child.is_dir() or child.is_symlink():
            continue
        manifest = child / ".claude-plugin" / "plugin.json"
        if not manifest.exists():
            continue
        rel_path = str(child.relative_to(marketplace_root))
        reports.append(
            _analyze_single(
                child,
                source,
                source_type,
                strict=strict,
                plugin_path_override=rel_path,
            )
        )
    return reports


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
