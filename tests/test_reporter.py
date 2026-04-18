"""Tests for schema builders + JSON + Rich rendering."""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from griffith.analyzer import (
    ArchitectureAssessor,
    FootprintEstimator,
    PluginInventory,
    SecurityScanner,
)
from griffith.reporter import render_json, render_rich
from griffith.schema import (
    SCHEMA_VERSION,
    build_marketplace_report,
    build_report,
)


@pytest.fixture
def sample_report(minimal_plugin):
    inv = PluginInventory.from_path(minimal_plugin)
    findings = SecurityScanner().scan(inv)
    fp = FootprintEstimator().estimate(inv)
    arch = ArchitectureAssessor().assess(inv)
    return build_report(
        inventory=inv,
        security_findings=findings,
        footprint=fp,
        architecture=arch,
        source=str(minimal_plugin),
        source_type="path",
    )


class TestReportShape:
    def test_schema_version_is_present(self, sample_report):
        assert sample_report["schema_version"] == SCHEMA_VERSION

    def test_all_top_level_keys_present(self, sample_report):
        for key in (
            "schema_version",
            "plugin",
            "inventory",
            "security",
            "footprint",
            "architecture",
            "analysis_scope",
            "untrusted_fields",
            "meta",
        ):
            assert key in sample_report

    def test_plugin_fields(self, sample_report):
        assert sample_report["plugin"]["name"] == "minimal"
        assert "source" in sample_report["plugin"]
        assert "path" in sample_report["plugin"]

    def test_inventory_counts_match_expected(self, sample_report):
        counts = sample_report["inventory"]["counts"]
        assert counts["agents"] == 1
        assert counts["commands"] == 1
        assert counts["skills"] == 1
        assert counts["hooks"] == 1
        assert counts["mcp_servers"] == 0

    def test_security_risk_level_none_when_no_findings(self, sample_report):
        if not sample_report["security"]["findings"]:
            assert sample_report["security"]["risk_level"] == "none"

    def test_footprint_uses_cl100k_approx_name(self, sample_report):
        """The JSON field must be the approx-cl100k-named version, not the
        internal dataclass name."""
        assert "baseline_tokens_approx_cl100k" in sample_report["footprint"]
        assert "baseline_tokens" not in sample_report["footprint"]

    def test_analysis_scope_declares_static_only(self, sample_report):
        assert sample_report["analysis_scope"] == ["static"]

    def test_untrusted_fields_listed(self, sample_report):
        # Must include at least the plugin name (always untrusted)
        assert "plugin.name" in sample_report["untrusted_fields"]

    def test_meta_has_required_fields(self, sample_report):
        meta = sample_report["meta"]
        for k in ("griffith_version", "griffith_hardening_version", "analyzed_at", "source_type"):
            assert k in meta
        assert meta["source_type"] == "path"


class TestJsonSerialization:
    def test_json_output_is_valid(self, sample_report):
        stream = io.StringIO()
        render_json(sample_report, stream)
        output = stream.getvalue()
        parsed = json.loads(output)
        assert parsed["schema_version"] == SCHEMA_VERSION

    def test_json_output_pipeable_to_jq_compat(self, sample_report):
        """Output is a single JSON object terminated with newline — jq-compatible."""
        stream = io.StringIO()
        render_json(sample_report, stream)
        output = stream.getvalue()
        assert output.endswith("\n")
        # Must parse as a single object
        json.loads(output)

    def test_json_output_is_indented(self, sample_report):
        stream = io.StringIO()
        render_json(sample_report, stream)
        output = stream.getvalue()
        assert "  " in output  # two-space indentation


class TestRiskLevelDerivation:
    def test_risk_level_tracks_highest_severity(self, fixtures_dir):
        inv = PluginInventory.from_path(fixtures_dir / "security-traps-plugin")
        findings = SecurityScanner().scan(inv)
        fp = FootprintEstimator().estimate(inv)
        arch = ArchitectureAssessor().assess(inv)
        report = build_report(
            inventory=inv,
            security_findings=findings,
            footprint=fp,
            architecture=arch,
            source=str(fixtures_dir / "security-traps-plugin"),
            source_type="path",
        )
        assert report["security"]["risk_level"] == "critical"


class TestRichRendering:
    def test_render_rich_does_not_crash(self, sample_report):
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=False, width=120)
        render_rich(sample_report, console)
        output = buffer.getvalue()
        # Expect some recognizable content
        assert "minimal" in output
        assert "Inventory" in output
        assert "Security" in output
        assert "Footprint" in output
        assert "Architecture" in output

    def test_render_rich_with_findings(self, fixtures_dir):
        inv = PluginInventory.from_path(fixtures_dir / "security-traps-plugin")
        findings = SecurityScanner().scan(inv)
        fp = FootprintEstimator().estimate(inv)
        arch = ArchitectureAssessor().assess(inv)
        report = build_report(
            inventory=inv,
            security_findings=findings,
            footprint=fp,
            architecture=arch,
            source=str(fixtures_dir / "security-traps-plugin"),
            source_type="path",
        )
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=False, width=120)
        render_rich(report, console)
        output = buffer.getvalue()
        assert "critical" in output


class TestMarketplaceReport:
    def test_marketplace_summary(self, fixtures_dir):
        """Building a marketplace report over 2 plugins."""
        mp_dir = fixtures_dir / "minimal-marketplace"
        reports = []
        for plugin_name in ("plugin-alpha", "plugin-beta"):
            pdir = mp_dir / "plugins" / plugin_name
            inv = PluginInventory.from_path(pdir)
            reports.append(
                build_report(
                    inventory=inv,
                    security_findings=SecurityScanner().scan(inv),
                    footprint=FootprintEstimator().estimate(inv),
                    architecture=ArchitectureAssessor().assess(inv),
                    source=str(mp_dir),
                    source_type="path",
                    plugin_path_override=f"plugins/{plugin_name}",
                )
            )
        mp = build_marketplace_report(
            reports=reports,
            source=str(mp_dir),
            source_type="path",
            marketplace_path=str(mp_dir),
        )
        assert mp["summary"]["plugin_count"] == 2
        assert len(mp["reports"]) == 2
        # risk_level_counts has 'none' for both (no findings)
        assert mp["summary"]["risk_level_counts"].get("none") == 2

    def test_marketplace_json_renders(self, fixtures_dir):
        mp_dir = fixtures_dir / "minimal-marketplace"
        pdir = mp_dir / "plugins" / "plugin-alpha"
        inv = PluginInventory.from_path(pdir)
        one_report = build_report(
            inventory=inv,
            security_findings=[],
            footprint=FootprintEstimator().estimate(inv),
            architecture=ArchitectureAssessor().assess(inv),
            source=str(mp_dir),
            source_type="path",
        )
        mp = build_marketplace_report(
            reports=[one_report],
            source=str(mp_dir),
            source_type="path",
            marketplace_path=str(mp_dir),
        )
        stream = io.StringIO()
        render_json(mp, stream)
        parsed = json.loads(stream.getvalue())
        assert "marketplace" in parsed
        assert "reports" in parsed
        assert "summary" in parsed
