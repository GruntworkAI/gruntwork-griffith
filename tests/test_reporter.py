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
    from griffith.analyzer import DependencyAnalyzer

    inv = PluginInventory.from_path(minimal_plugin)
    findings = SecurityScanner().scan(inv)
    fp = FootprintEstimator().estimate(inv)
    arch = ArchitectureAssessor().assess(inv)
    dep = DependencyAnalyzer().analyze(minimal_plugin)
    return build_report(
        inventory=inv,
        security_findings=findings,
        footprint=fp,
        architecture=arch,
        dependency_report=dep,
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
        from griffith.analyzer import DependencyAnalyzer

        inv = PluginInventory.from_path(fixtures_dir / "security-traps-plugin")
        findings = SecurityScanner().scan(inv)
        fp = FootprintEstimator().estimate(inv)
        arch = ArchitectureAssessor().assess(inv)
        dep = DependencyAnalyzer().analyze(fixtures_dir / "security-traps-plugin")
        report = build_report(
            inventory=inv,
            security_findings=findings,
            footprint=fp,
            architecture=arch,
            dependency_report=dep,
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
        from griffith.analyzer import DependencyAnalyzer

        inv = PluginInventory.from_path(fixtures_dir / "security-traps-plugin")
        findings = SecurityScanner().scan(inv)
        fp = FootprintEstimator().estimate(inv)
        arch = ArchitectureAssessor().assess(inv)
        dep = DependencyAnalyzer().analyze(fixtures_dir / "security-traps-plugin")
        report = build_report(
            inventory=inv,
            security_findings=findings,
            footprint=fp,
            architecture=arch,
            dependency_report=dep,
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
        from griffith.analyzer import DependencyAnalyzer

        for plugin_name in ("plugin-alpha", "plugin-beta"):
            pdir = mp_dir / "plugins" / plugin_name
            inv = PluginInventory.from_path(pdir)
            reports.append(
                build_report(
                    inventory=inv,
                    security_findings=SecurityScanner().scan(inv),
                    footprint=FootprintEstimator().estimate(inv),
                    architecture=ArchitectureAssessor().assess(inv),
                    dependency_report=DependencyAnalyzer().analyze(pdir),
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
        from griffith.analyzer import DependencyAnalyzer

        mp_dir = fixtures_dir / "minimal-marketplace"
        pdir = mp_dir / "plugins" / "plugin-alpha"
        inv = PluginInventory.from_path(pdir)
        one_report = build_report(
            inventory=inv,
            security_findings=[],
            footprint=FootprintEstimator().estimate(inv),
            architecture=ArchitectureAssessor().assess(inv),
            dependency_report=DependencyAnalyzer().analyze(pdir),
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


# ============================================================================
# Phase 1.5 Unit 5: Dependencies section
# ============================================================================


def _build_report_for(plugin_path):
    """Helper: build a complete Report for any plugin path."""
    from griffith.analyzer import DependencyAnalyzer

    inv = PluginInventory.from_path(plugin_path)
    return build_report(
        inventory=inv,
        security_findings=SecurityScanner().scan(inv),
        footprint=FootprintEstimator().estimate(inv),
        architecture=ArchitectureAssessor().assess(inv),
        dependency_report=DependencyAnalyzer().analyze(plugin_path),
        source=str(plugin_path),
        source_type="path",
    )


class TestDependenciesSchema:
    def test_top_level_dependencies_key_present(self, minimal_plugin):
        report = _build_report_for(minimal_plugin)
        assert "dependencies" in report

    def test_dependencies_shape_tier1_only(self, minimal_plugin):
        report = _build_report_for(minimal_plugin)
        deps = report["dependencies"]
        for key in (
            "scan_status",
            "manifests",
            "lockfiles",
            "unscanned_manifests",
            "ecosystems",
            "package_count",
            "packages",
            "sca",
        ):
            assert key in deps

    def test_sca_is_none_in_tier1(self, minimal_plugin):
        report = _build_report_for(minimal_plugin)
        assert report["dependencies"]["sca"] is None

    def test_scan_status_is_tier1_only(self, minimal_plugin):
        report = _build_report_for(minimal_plugin)
        assert report["dependencies"]["scan_status"] == "tier1_only"

    def test_untrusted_fields_includes_dep_paths(self, minimal_plugin):
        report = _build_report_for(minimal_plugin)
        untrusted = report["untrusted_fields"]
        assert "dependencies.packages[].name" in untrusted
        assert "dependencies.packages[].constraint" in untrusted
        assert "dependencies.unscanned_manifests[]" in untrusted

    def test_python_plugin_packages_in_json(self, fixtures_dir):
        report = _build_report_for(fixtures_dir / "deps-python-plugin")
        deps = report["dependencies"]
        assert deps["package_count"] == 9
        assert "PyPI" in deps["ecosystems"]
        names = {p["name"] for p in deps["packages"]}
        assert "requests" in names
        assert "fastapi" in names


class TestDependenciesRichRender:
    def test_section_omitted_when_no_deps(self, minimal_plugin):
        """Terse minimal-plugin case — Dependencies section should NOT appear."""
        report = _build_report_for(minimal_plugin)
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=False, width=120)
        render_rich(report, console)
        output = buffer.getvalue()
        # No dep manifests → section skipped
        assert "Dependencies" not in output or "Dependencies\n" not in output
        # More precise: "Dependencies\n  " (heading with content) should not appear
        assert "  ecosystems:" not in output

    def test_section_rendered_with_python_deps(self, fixtures_dir):
        report = _build_report_for(fixtures_dir / "deps-python-plugin")
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=False, width=120)
        render_rich(report, console)
        output = buffer.getvalue()
        assert "Dependencies" in output
        assert "PyPI" in output
        assert "fastapi" in output
        assert "requests" in output

    def test_optional_kind_rendered_with_parens_not_brackets(self, fixtures_dir):
        """Ensure the `[optional]` marker is rendered as `(optional)` so
        Rich's markup parser doesn't swallow it as a style tag."""
        report = _build_report_for(fixtures_dir / "deps-python-plugin")
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=False, width=120)
        render_rich(report, console)
        output = buffer.getvalue()
        # pytest and black are optional-kind in the fixture
        assert "(optional)" in output


# (CLI E2E tests for the dependencies section live in test_cli.py)
