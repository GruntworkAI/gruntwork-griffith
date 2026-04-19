"""Render Griffith reports as JSON or Rich-formatted terminal output.

Two primary consumers in Phase 1:
    1. Humans reading `griffith analyze` in their terminal (Rich output)
    2. The LMF /run-audit-plugin wrapper skill (JSON output)

Both are first-class — Rich output is a real deliverable, not a cosmetic side
channel. JSON output is the stable-shape contract for downstream consumers.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from griffith.schema import MarketplaceReport, Report

# Severity → Rich style color
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "bold orange3",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
    "none": "green",
}

_EFFICIENCY_STYLE = {
    "excellent": "bold green",
    "good": "green",
    "moderate": "yellow",
    "heavy": "bold orange3",
    "excessive": "bold red",
}

_PATTERN_STYLE = {
    "skill-first": "bold green",
    "agent-heavy": "bold yellow",
    "mcp-based": "bold orange3",
    "hybrid": "cyan",
}


# ============================================================================
# JSON
# ============================================================================


def render_json(report: Report | MarketplaceReport, stream: TextIO | None = None) -> None:
    """Emit a Report or MarketplaceReport as indented JSON to `stream` (default stdout)."""
    stream = stream or sys.stdout
    json.dump(report, stream, indent=2, sort_keys=False)
    stream.write("\n")


# ============================================================================
# Rich terminal output
# ============================================================================


def render_rich(
    report: Report | MarketplaceReport, console: Console | None = None
) -> None:
    """Render a Report or MarketplaceReport to a Rich Console (default stderr-safe stdout)."""
    console = console or Console()
    if _is_marketplace(report):
        _render_marketplace_rich(report, console)  # type: ignore[arg-type]
    else:
        _render_single_rich(report, console)  # type: ignore[arg-type]


def _is_marketplace(report: Report | MarketplaceReport) -> bool:
    return "marketplace" in report


def _render_single_rich(report: Report, console: Console) -> None:
    _render_header(report, console)
    console.print()
    _render_inventory(report, console)
    console.print()
    _render_security(report, console)
    console.print()
    _render_footprint(report, console)
    console.print()
    _render_architecture(report, console)
    console.print()
    _render_dependencies(report, console)
    console.print()
    _render_footer(report, console)


def _render_marketplace_rich(report: MarketplaceReport, console: Console) -> None:
    market = report["marketplace"]
    summary = report["summary"]
    title = Text(f"Marketplace: {market['source']}", style="bold")
    subtitle = Text(
        f"{summary['plugin_count']} plugin(s) analyzed",
        style="dim",
    )
    console.print(Panel.fit(Text.assemble(title, "\n", subtitle), border_style="cyan"))

    risk_counts = summary["risk_level_counts"]
    pattern_counts = summary["patterns"]
    summary_table = Table(title="Summary", show_header=True, header_style="bold")
    summary_table.add_column("Plugins by risk")
    summary_table.add_column("Plugins by pattern")
    max_rows = max(len(risk_counts), len(pattern_counts), 1)
    risk_items = list(risk_counts.items())
    pattern_items = list(pattern_counts.items())
    for i in range(max_rows):
        left = ""
        right = ""
        if i < len(risk_items):
            k, v = risk_items[i]
            left = f"[{_SEVERITY_STYLE.get(k, 'white')}]{k}[/]: {v}"
        if i < len(pattern_items):
            k, v = pattern_items[i]
            right = f"[{_PATTERN_STYLE.get(k, 'white')}]{k}[/]: {v}"
        summary_table.add_row(left, right)
    console.print(summary_table)
    console.print()

    for i, plugin_report in enumerate(report["reports"]):
        console.rule(f"Plugin {i + 1} of {summary['plugin_count']}")
        _render_single_rich(plugin_report, console)
        console.print()


def _render_header(report: Report, console: Console) -> None:
    plugin = report["plugin"]
    meta = report["meta"]
    name = Text(plugin["name"], style="bold cyan")
    info = Text.assemble(
        "source: ", (plugin["source"], "dim"), "\n",
        "griffith ", (meta["griffith_version"], "bold"),
        " | schema ", (report["schema_version"] + " (unstable)", "yellow"),
    )
    console.print(Panel.fit(
        Text.assemble("Plugin: ", name, "\n", info),
        border_style="cyan",
    ))


def _render_inventory(report: Report, console: Console) -> None:
    counts = report["inventory"]["counts"]
    totals = report["inventory"]["totals"]
    table = Table(title="Inventory", show_header=False, box=None, padding=(0, 2))
    table.add_column("type", style="bold")
    table.add_column("count", justify="right")
    for key in ("agents", "commands", "skills", "hooks", "mcp_servers", "personas", "templates", "unknown"):
        v = counts.get(key, 0)
        style = "" if v > 0 else "dim"
        table.add_row(key, f"[{style}]{v}[/]" if style else str(v))
    table.add_row("", "", style="dim")
    table.add_row("[dim]total files[/]", f"[dim]{totals['files']}[/]")
    table.add_row("[dim]total lines[/]", f"[dim]{totals['lines']:,}[/]")
    console.print(table)


def _render_security(report: Report, console: Console) -> None:
    sec = report["security"]
    risk = sec["risk_level"]
    style = _SEVERITY_STYLE.get(risk, "white")
    title = Text.assemble(
        "Security  ",
        (f"risk: {risk}", style),
        f"  ({sec['finding_count']} finding(s))",
    )
    console.print(title, style="bold")

    if not sec["findings"]:
        console.print("  [green]no findings[/]")
        return

    # Group by severity
    by_sev: dict[str, list] = {}
    for f in sec["findings"]:
        by_sev.setdefault(f["severity"], []).append(f)

    for sev in ("critical", "high", "medium", "low", "info"):
        group = by_sev.get(sev)
        if not group:
            continue
        sev_style = _SEVERITY_STYLE.get(sev, "white")
        console.print(f"  [{sev_style}]{sev}[/] ({len(group)})")
        for f in group[:5]:  # cap display; full list is in JSON output
            console.print(
                f"    [dim]{f['file']}:{f['line']}[/] "
                f"{f['rule_id']}  [dim]{f['message']}[/]"
            )
        if len(group) > 5:
            console.print(f"    [dim]... +{len(group) - 5} more[/]")


def _render_footprint(report: Report, console: Console) -> None:
    fp = report["footprint"]
    rating = fp["efficiency_rating"]
    rating_style = _EFFICIENCY_STYLE.get(rating, "white")
    title = Text.assemble(
        "Footprint  ",
        (f"efficiency: {rating}", rating_style),
    )
    console.print(title, style="bold")
    console.print(
        f"  baseline:      [bold]{fp['baseline_tokens_approx_cl100k']:>7,}[/] tokens "
        f"[dim](approx cl100k — not Claude's actual tokenizer)[/]"
    )
    console.print(
        f"  on-demand max: [bold]{fp['on_demand_max']:>7,}[/] tokens"
    )
    console.print(f"  primary driver: [cyan]{fp['primary_driver']}[/]")
    if fp["per_component"]:
        breakdown = [
            f"{k}={v:,}"
            for k, v in sorted(
                fp["per_component"].items(), key=lambda kv: -kv[1]
            )
            if v > 0
        ]
        if breakdown:
            console.print(f"  [dim]breakdown: {'  '.join(breakdown)}[/]")


def _render_architecture(report: Report, console: Console) -> None:
    arch = report["architecture"]
    pattern = arch["pattern"]
    style = _PATTERN_STYLE.get(pattern, "white")
    title = Text.assemble(
        "Architecture  ",
        (f"pattern: {pattern}", style),
    )
    console.print(title, style="bold")
    if arch["efficiency_notes"]:
        console.print("  [bold]notes:[/]")
        for note in arch["efficiency_notes"]:
            console.print(f"    - {note}")
    if arch["recommendations"]:
        console.print("  [bold]recommendations:[/]")
        for rec in arch["recommendations"]:
            console.print(f"    - [cyan]{rec}[/]")


def _render_dependencies(report: Report, console: Console) -> None:
    """Render the Dependencies section (Phase 1.5 Unit 5 — Tier 1 only).

    Skip entirely when the plugin has no dep manifests / lockfiles /
    unscanned entries (most plugins). Symlink-only-manifests case renders a
    single safety-refusal line rather than an empty package table. The Tier
    2 CVE branch lands in Unit 6.
    """
    deps = report["dependencies"]
    manifests = deps.get("manifests") or []
    lockfiles = deps.get("lockfiles") or []
    packages = deps.get("packages") or []
    unscanned = deps.get("unscanned_manifests") or []

    if not manifests and not lockfiles and not packages and not unscanned:
        return  # terse minimal-plugin case; omit section entirely

    console.print("Dependencies", style="bold")

    # Symlink-only case: every detected manifest is a symlink
    symlink_only_manifests = manifests and all(m.get("is_symlink") for m in manifests)
    if symlink_only_manifests and not packages and not lockfiles:
        console.print(
            "  [yellow]Symlinked manifests refused for safety "
            "— see Security findings[/]"
        )
        return

    # Ecosystem + package summary
    ecosystems = deps.get("ecosystems") or []
    if ecosystems:
        console.print(
            f"  ecosystems: [cyan]{', '.join(ecosystems)}[/]  "
            f"packages: [bold]{deps['package_count']}[/]"
        )
    elif packages:
        console.print(f"  packages: [bold]{deps['package_count']}[/]")

    # Per-manifest grouping of packages (cap 10 per manifest)
    if packages:
        by_manifest: dict[str, list[dict]] = {}
        for p in packages:
            by_manifest.setdefault(p["manifest"], []).append(p)
        for manifest_path in sorted(by_manifest):
            group = by_manifest[manifest_path]
            console.print(f"  [dim]{manifest_path}[/]  ({len(group)})")
            for p in group[:10]:
                # kind field is Griffith-controlled (runtime/dev/optional/peer);
                # use parens so Rich doesn't treat e.g. "[optional]" as a style tag
                kind_tag = f"[dim]({p['kind']})[/] " if p["kind"] != "runtime" else ""
                constraint = f" [dim]{p['constraint']}[/]" if p["constraint"] else ""
                console.print(f"    {kind_tag}[cyan]{p['name']}[/]{constraint}")
            if len(group) > 10:
                console.print(f"    [dim]... +{len(group) - 10} more[/]")

    # Lockfiles (detected, not parsed in Tier 1)
    if lockfiles:
        lf_paths = sorted(lf["path"] for lf in lockfiles)
        console.print(f"  [dim]lockfiles ({len(lf_paths)}):[/]")
        for lf in lf_paths[:5]:
            console.print(f"    [dim]- {lf}[/]")
        if len(lf_paths) > 5:
            console.print(f"    [dim]... +{len(lf_paths) - 5} more[/]")

    # Unscanned manifests (parse failures) — info-level warning
    if unscanned:
        console.print(f"  [yellow]⚠ could not parse ({len(unscanned)}):[/]")
        for path in unscanned[:5]:
            console.print(f"    [yellow]- {path}[/]")
        if len(unscanned) > 5:
            console.print(f"    [yellow]... +{len(unscanned) - 5} more[/]")


def _render_footer(report: Report, console: Console) -> None:
    meta = report["meta"]
    scope = ", ".join(report["analysis_scope"])
    console.print(
        Text.assemble(
            ("Analyzed ", "dim"),
            (meta["analyzed_at"], "dim"),
            ("  |  scope: ", "dim"),
            (scope, "dim"),
            ("  |  hardening v", "dim"),
            (meta["griffith_hardening_version"], "dim"),
        )
    )
