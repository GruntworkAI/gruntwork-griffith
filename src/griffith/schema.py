"""JSON report schema — authoritative contract for Griffith's structured output.

This schema is explicitly v0.1 and unstable. The primary consumer is the LMF
`/run-audit-plugin` wrapper skill, which does not yet exist — so the shape is
free to evolve until the first real consumer pins it.

Downstream consumers should read `schema_version` before unpacking fields.
Breaking-change promise: any change to these TypedDicts bumps schema_version.

Untrusted content:
    Every field value originating from plugin content (plugin name, frontmatter
    descriptions, path basenames, etc.) is listed in the top-level
    `untrusted_fields` array by its dotted path. Consumers that render these
    fields in a Claude session should wrap them in an instruction-neutral
    envelope (code fence, escaped block) to prevent prompt injection.
"""

from __future__ import annotations

import datetime
from typing import Any, Literal, TypedDict

from griffith import __version__

# Bumped when hardening controls (clone env scrub, symlink refusal, YAML
# safe_load, etc.) change. Consumers can gate on this to require a minimum
# hardening level.
GRIFFITH_HARDENING_VERSION = "1"
SCHEMA_VERSION = "0.1"
ANALYSIS_SCOPE: list[Literal["static"]] = ["static"]

SourceType = Literal["url", "shorthand", "path"]
RiskLevel = Literal["critical", "high", "medium", "low", "info", "none"]
EfficiencyRating = Literal["excellent", "good", "moderate", "heavy", "excessive"]
ArchitecturePattern = Literal["agent-heavy", "skill-first", "mcp-based", "hybrid"]


class PluginInfo(TypedDict):
    name: str  # untrusted — from plugin.json, sanitized
    path: str  # relative to clone root / plugin root
    source: str  # original user-provided source string


class InventoryCounts(TypedDict):
    agents: int
    commands: int
    skills: int
    hooks: int
    mcp_servers: int
    personas: int
    templates: int
    unknown: int


class InventoryTotals(TypedDict):
    files: int
    lines: int


class InventoryDict(TypedDict):
    counts: InventoryCounts
    totals: InventoryTotals


class FindingDict(TypedDict):
    rule_id: str
    severity: str
    file: str
    line: int
    message: str


class SecurityDict(TypedDict):
    risk_level: RiskLevel
    finding_count: int
    findings: list[FindingDict]


class FootprintDict(TypedDict):
    baseline_tokens_approx_cl100k: int
    on_demand_max: int
    primary_driver: str
    efficiency_rating: EfficiencyRating
    per_component: dict[str, int]


class ArchitectureDict(TypedDict):
    pattern: ArchitecturePattern
    efficiency_notes: list[str]
    recommendations: list[str]


class MetaDict(TypedDict):
    griffith_version: str
    griffith_hardening_version: str
    analyzed_at: str  # ISO-8601 UTC
    source_type: SourceType


class Report(TypedDict):
    schema_version: str
    plugin: PluginInfo
    inventory: InventoryDict
    security: SecurityDict
    footprint: FootprintDict
    architecture: ArchitectureDict
    analysis_scope: list[str]
    untrusted_fields: list[str]
    meta: MetaDict


class MarketplaceSummary(TypedDict):
    plugin_count: int
    risk_level_counts: dict[str, int]
    patterns: dict[str, int]


class MarketplaceInfo(TypedDict):
    source: str
    path: str


class MarketplaceReport(TypedDict):
    schema_version: str
    marketplace: MarketplaceInfo
    reports: list[Report]
    summary: MarketplaceSummary
    meta: MetaDict


# ============================================================================
# Builders: dataclasses → TypedDict-shaped dicts
# ============================================================================

# Dotted paths of fields whose content originated from plugin input. Consumers
# rendering these in a Claude session should wrap them in an instruction-
# neutral envelope to prevent prompt injection.
UNTRUSTED_FIELDS: list[str] = [
    "plugin.name",
    "security.findings[].file",
    "architecture.efficiency_notes[]",
    "architecture.recommendations[]",
]


def build_report(
    *,
    inventory,
    security_findings: list,
    footprint,
    architecture,
    source: str,
    source_type: SourceType,
    plugin_path_override: str | None = None,
) -> Report:
    """Compose a single-plugin Report dict from analyzer outputs."""
    risk_level = _derive_risk_level(security_findings)
    return Report(
        schema_version=SCHEMA_VERSION,
        plugin=PluginInfo(
            name=inventory.name,
            path=plugin_path_override if plugin_path_override is not None else ".",
            source=source,
        ),
        inventory=InventoryDict(
            counts=InventoryCounts(
                agents=inventory.agents_count,
                commands=inventory.commands_count,
                skills=inventory.skills_count,
                hooks=inventory.hooks_count,
                mcp_servers=inventory.mcp_servers_count,
                personas=inventory.personas_count,
                templates=inventory.templates_count,
                unknown=inventory.unknown_count,
            ),
            totals=InventoryTotals(
                files=inventory.total_files,
                lines=inventory.total_lines,
            ),
        ),
        security=SecurityDict(
            risk_level=risk_level,
            finding_count=len(security_findings),
            findings=[
                FindingDict(
                    rule_id=f.rule_id,
                    severity=f.severity,
                    file=f.file,
                    line=f.line,
                    message=f.message,
                )
                for f in security_findings
            ],
        ),
        footprint=FootprintDict(
            baseline_tokens_approx_cl100k=footprint.baseline_tokens,
            on_demand_max=footprint.on_demand_max,
            primary_driver=footprint.primary_driver,
            efficiency_rating=footprint.efficiency_rating,
            per_component=dict(footprint.per_component),
        ),
        architecture=ArchitectureDict(
            pattern=architecture.pattern,
            efficiency_notes=list(architecture.efficiency_notes),
            recommendations=list(architecture.recommendations),
        ),
        analysis_scope=list(ANALYSIS_SCOPE),
        untrusted_fields=list(UNTRUSTED_FIELDS),
        meta=_build_meta(source_type),
    )


def build_marketplace_report(
    *,
    reports: list[Report],
    source: str,
    source_type: SourceType,
    marketplace_path: str,
) -> MarketplaceReport:
    """Compose a marketplace-level report wrapping N single-plugin Reports."""
    return MarketplaceReport(
        schema_version=SCHEMA_VERSION,
        marketplace=MarketplaceInfo(source=source, path=marketplace_path),
        reports=reports,
        summary=_summarize(reports),
        meta=_build_meta(source_type),
    )


def _derive_risk_level(findings: list) -> RiskLevel:
    """Highest severity present across all findings."""
    if not findings:
        return "none"
    order = ["critical", "high", "medium", "low", "info"]
    seen = {f.severity for f in findings}
    for sev in order:
        if sev in seen:
            return sev  # type: ignore[return-value]
    return "none"


def _summarize(reports: list[Report]) -> MarketplaceSummary:
    risk_counts: dict[str, int] = {}
    pattern_counts: dict[str, int] = {}
    for r in reports:
        risk = r["security"]["risk_level"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        pat = r["architecture"]["pattern"]
        pattern_counts[pat] = pattern_counts.get(pat, 0) + 1
    return MarketplaceSummary(
        plugin_count=len(reports),
        risk_level_counts=risk_counts,
        patterns=pattern_counts,
    )


def _build_meta(source_type: SourceType) -> MetaDict:
    return MetaDict(
        griffith_version=__version__,
        griffith_hardening_version=GRIFFITH_HARDENING_VERSION,
        analyzed_at=datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        source_type=source_type,
    )
