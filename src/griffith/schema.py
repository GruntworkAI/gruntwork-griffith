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
from typing import Any, Literal, Optional, TypedDict

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


# Phase 1.5 Unit 5: dependencies section (Tier 1)
ScanStatus = Literal[
    "ok",
    "tier1_only",
    "sca_requested_and_failed",
    "sca_requested_and_timed_out",
    "sca_malformed_output",
]


class DependencyPackageDict(TypedDict):
    ecosystem: str  # untrusted
    name: str  # untrusted
    constraint: str  # untrusted
    kind: str  # trusted (runtime|dev|optional|peer)
    manifest: str  # untrusted (plugin-controlled path)


class ManifestInfoDict(TypedDict):
    path: str  # untrusted
    is_symlink: bool
    size_skipped: bool


class VulnerabilityDict(TypedDict):
    id: str  # untrusted (from osv-scanner output)
    severity: str  # trusted Griffith enum: critical|high|medium|low|info
    severity_raw: str  # untrusted (CVSS numeric or vector as emitted)
    summary: str  # untrusted
    affected_package: str  # untrusted
    fixed_versions: list[str]  # untrusted


class SCAResultDict(TypedDict):
    osv_scanner_version: str  # trusted (probed from --version)
    vulnerability_count: int
    vulnerabilities: list[VulnerabilityDict]
    note: Optional[str]  # trusted (griffith-authored explanation)
    error: Optional[str]  # untrusted tail of osv-scanner stderr may be embedded


class DependencyDict(TypedDict):
    scan_status: ScanStatus
    manifests: list[ManifestInfoDict]
    lockfiles: list[ManifestInfoDict]
    unscanned_manifests: list[str]
    ecosystems: list[str]
    package_count: int
    packages: list[DependencyPackageDict]
    sca: Optional[SCAResultDict]  # populated in Unit 6 when --sca is used


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
    dependencies: DependencyDict  # Phase 1.5 Unit 5: Tier 1 detection; Tier 2 SCA in Unit 6
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
    # Phase 1.5 Unit 5 Tier 1 dependency fields (all plugin-controlled content).
    # Tier 2 SCA fields (dependencies.sca.*) are appended in Unit 6.
    "dependencies.manifests[].path",
    "dependencies.lockfiles[].path",
    "dependencies.unscanned_manifests[]",
    "dependencies.packages[].ecosystem",
    "dependencies.packages[].name",
    "dependencies.packages[].constraint",
    "dependencies.packages[].manifest",
    # Phase 1.5 Unit 6 Tier 2 (--sca) fields. osv-scanner output is treated
    # as untrusted: its JSON reflects vulnerability metadata sourced from
    # upstream registries (GHSA / CVE / OSV) that Griffith does not audit.
    "dependencies.sca.vulnerabilities[].id",
    "dependencies.sca.vulnerabilities[].severity_raw",
    "dependencies.sca.vulnerabilities[].summary",
    "dependencies.sca.vulnerabilities[].affected_package",
    "dependencies.sca.vulnerabilities[].fixed_versions[]",
    "dependencies.sca.error",
]


def build_report(
    *,
    inventory,
    security_findings: list,
    footprint,
    architecture,
    dependency_report,
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
        dependencies=_build_dependency_dict(dependency_report),
        analysis_scope=list(ANALYSIS_SCOPE),
        untrusted_fields=list(UNTRUSTED_FIELDS),
        meta=_build_meta(source_type),
    )


def _build_dependency_dict(dep_report) -> DependencyDict:
    """Convert a DependencyReport dataclass to its JSON-ready TypedDict shape."""
    return DependencyDict(
        scan_status=dep_report.scan_status,
        manifests=[
            ManifestInfoDict(
                path=m.path, is_symlink=m.is_symlink, size_skipped=m.size_skipped
            )
            for m in dep_report.manifests
        ],
        lockfiles=[
            ManifestInfoDict(
                path=lf.path, is_symlink=lf.is_symlink, size_skipped=lf.size_skipped
            )
            for lf in dep_report.lockfiles
        ],
        unscanned_manifests=list(dep_report.unscanned_manifests),
        ecosystems=list(dep_report.ecosystems),
        package_count=dep_report.package_count,
        packages=[
            DependencyPackageDict(
                ecosystem=p.ecosystem,
                name=p.name,
                constraint=p.constraint,
                kind=p.kind,
                manifest=p.manifest,
            )
            for p in dep_report.packages
        ],
        sca=_build_sca_dict(dep_report.sca) if dep_report.sca is not None else None,
    )


def _build_sca_dict(sca) -> SCAResultDict:
    """Convert an SCAResult dataclass to its JSON-ready TypedDict shape.

    `scan_status` on SCAResult is intentionally NOT surfaced here — the top-
    level `dependencies.scan_status` field is the canonical consumer surface
    and is populated from sca.scan_status by DependencyAnalyzer.
    """
    return SCAResultDict(
        osv_scanner_version=sca.osv_scanner_version,
        vulnerability_count=sca.vulnerability_count,
        vulnerabilities=[
            VulnerabilityDict(
                id=v.id,
                severity=v.severity,
                severity_raw=v.severity_raw,
                summary=v.summary,
                affected_package=v.affected_package,
                fixed_versions=list(v.fixed_versions),
            )
            for v in sca.vulnerabilities
        ],
        note=sca.note,
        error=sca.error,
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
