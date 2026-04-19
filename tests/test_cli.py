"""End-to-end CLI tests — `griffith analyze` via the Click runner."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from griffith.cli import main


@pytest.fixture
def runner():
    # Click 8.2+ separates stdout/stderr by default.
    return CliRunner()


class TestAnalyzeLocal:
    def test_local_path_exits_zero(self, runner, minimal_plugin):
        result = runner.invoke(main, ["analyze", str(minimal_plugin)])
        assert result.exit_code == 0, result.stderr
        # Rich output written to stdout
        assert "minimal" in result.stdout
        assert "Inventory" in result.stdout

    def test_local_path_json_emits_valid_json(self, runner, minimal_plugin):
        result = runner.invoke(main, ["analyze", str(minimal_plugin), "--json"])
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        assert parsed["schema_version"] == "0.1"
        assert parsed["plugin"]["name"] == "minimal"
        assert parsed["inventory"]["counts"]["agents"] == 1

    def test_json_output_deterministic_modulo_meta(
        self, runner, minimal_plugin
    ):
        r1 = runner.invoke(main, ["analyze", str(minimal_plugin), "--json"])
        r2 = runner.invoke(main, ["analyze", str(minimal_plugin), "--json"])
        d1 = json.loads(r1.stdout)
        d2 = json.loads(r2.stdout)
        # Strip only the timestamp (changes between runs); everything else
        # should be byte-identical for the same input.
        d1["meta"]["analyzed_at"] = "_"
        d2["meta"]["analyzed_at"] = "_"
        assert d1 == d2


class TestAnalyzeErrors:
    def test_nonexistent_path_exits_nonzero(self, runner, tmp_path):
        result = runner.invoke(main, ["analyze", str(tmp_path / "does-not-exist")])
        assert result.exit_code != 0
        assert "not found" in result.stderr.lower() or "does not exist" in result.stderr.lower()

    def test_refused_protocol_exits_nonzero(self, runner):
        result = runner.invoke(main, ["analyze", "file:///etc/passwd"])
        assert result.exit_code != 0
        assert "refused" in result.stderr.lower() or "invalid" in result.stderr.lower()


class TestAnalyzeStrict:
    def test_strict_flag_activates_strict_rules(self, runner, fixtures_dir):
        """`broad-credential-assignment` is a strict-only rule; it must appear
        with --strict but not in default mode."""
        target = str(fixtures_dir / "security-traps-plugin")
        default_result = runner.invoke(main, ["analyze", target, "--json"])
        strict_result = runner.invoke(main, ["analyze", target, "--json", "--strict"])
        assert default_result.exit_code == 0
        assert strict_result.exit_code == 0
        default_ids = {f["rule_id"] for f in json.loads(default_result.stdout)["security"]["findings"]}
        strict_ids = {f["rule_id"] for f in json.loads(strict_result.stdout)["security"]["findings"]}
        assert "broad-credential-assignment" not in default_ids
        assert "broad-credential-assignment" in strict_ids


class TestAnalyzeMarketplace:
    def test_marketplace_produces_n_reports(self, runner, fixtures_dir):
        mp = str(fixtures_dir / "minimal-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        # Marketplace report has `reports` key
        assert "reports" in parsed
        assert len(parsed["reports"]) == 2
        names = {r["plugin"]["name"] for r in parsed["reports"]}
        assert names == {"plugin-alpha", "plugin-beta"}

    def test_marketplace_rich_output_shows_summary(self, runner, fixtures_dir):
        mp = str(fixtures_dir / "minimal-marketplace")
        result = runner.invoke(main, ["analyze", mp])
        assert result.exit_code == 0, result.stderr
        # Marketplace Rich output mentions plugin count and both plugin names
        assert "2 plugin" in result.stdout or "plugin 1" in result.stdout.lower()
        assert "plugin-alpha" in result.stdout
        assert "plugin-beta" in result.stdout


class TestStubCommands:
    def test_compare_is_stub(self, runner):
        result = runner.invoke(main, ["compare", "a", "b"])
        assert result.exit_code != 0
        assert "not yet implemented" in result.stderr.lower()

    def test_scan_installed_is_stub(self, runner):
        result = runner.invoke(main, ["scan-installed"])
        assert result.exit_code != 0
        assert "not yet implemented" in result.stderr.lower()


# ============================================================================
# Phase 1.5 Unit 5: Dependencies section E2E
# ============================================================================


class TestDependenciesCliE2E:
    def test_cli_json_contains_deps_section(self, runner, fixtures_dir):
        result = runner.invoke(
            main, ["analyze", str(fixtures_dir / "deps-python-plugin"), "--json"]
        )
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        assert "dependencies" in parsed
        assert parsed["dependencies"]["package_count"] == 9
        names = {p["name"] for p in parsed["dependencies"]["packages"]}
        assert "fastapi" in names
        assert "requests" in names

    def test_cli_rich_shows_dependencies_section(self, runner, fixtures_dir):
        result = runner.invoke(
            main, ["analyze", str(fixtures_dir / "deps-python-plugin")]
        )
        assert result.exit_code == 0, result.stderr
        assert "Dependencies" in result.stdout

    def test_cli_json_minimal_plugin_has_empty_deps(self, runner, minimal_plugin):
        result = runner.invoke(main, ["analyze", str(minimal_plugin), "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        deps = parsed["dependencies"]
        assert deps["scan_status"] == "tier1_only"
        assert deps["packages"] == []
        assert deps["manifests"] == []
        assert deps["sca"] is None

    def test_cli_scan_status_and_ecosystems_in_marketplace_reports(
        self, runner, fixtures_dir
    ):
        """Each plugin in a marketplace scan gets its own dependencies section."""
        mp = str(fixtures_dir / "minimal-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        for r in parsed["reports"]:
            assert "dependencies" in r
            assert r["dependencies"]["scan_status"] == "tier1_only"
