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


@pytest.fixture
def stub_federated_url_resolve(monkeypatch, fixtures_dir):
    """Map the federated-marketplace fixture's URL entry to a local path.

    The fixture uses `https://example.invalid/external-a.git` for its
    URL-type entry; this stub lets the tests exercise the URL code
    path without leaving the repo.
    """
    import griffith.cli as cli_mod
    from contextlib import contextmanager

    real_resolve = cli_mod.resolve
    external_a = (fixtures_dir / "federated-marketplace" / "external-a").resolve()

    @contextmanager
    def _fake_resolve(src):
        if src == "https://example.invalid/external-a.git":
            yield external_a, "url"
        else:
            with real_resolve(src) as result:
                yield result

    monkeypatch.setattr(cli_mod, "resolve", _fake_resolve)


class TestAnalyzeFederatedMarketplace:
    """Federated marketplaces — marketplace.json lists plugins with URL
    or path-object sources, rather than bundling them under plugins/.

    The federated-marketplace fixture uses one URL-type entry + one
    path-type entry. The URL entry is stubbed to a local fixture so
    tests stay hermetic without losing code-path coverage.
    """

    def test_federated_marketplace_detected_without_plugins_dir(
        self, runner, fixtures_dir, stub_federated_url_resolve,
    ):
        """Regression from superpowers-marketplace: a marketplace.json
        with NO bundled plugins/ dir must still be treated as a
        marketplace, not fall through to single-plugin mode."""
        mp = str(fixtures_dir / "federated-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        assert "reports" in parsed, "expected MarketplaceReport shape"
        assert parsed["summary"]["plugin_count"] == 2

    def test_federated_plugin_names_extracted(
        self, runner, fixtures_dir, stub_federated_url_resolve,
    ):
        mp = str(fixtures_dir / "federated-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        parsed = json.loads(result.stdout)
        names = {r["plugin"]["name"] for r in parsed["reports"]}
        assert names == {"federated-alpha", "federated-beta"}

    def test_federated_source_field_concatenated(
        self, runner, fixtures_dir, stub_federated_url_resolve,
    ):
        """Decision #1: plugin.source for federated entries concatenates
        the outer marketplace source with the inner plugin source,
        separated by ` → `."""
        mp = str(fixtures_dir / "federated-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        parsed = json.loads(result.stdout)
        sources = {r["plugin"]["name"]: r["plugin"]["source"] for r in parsed["reports"]}
        # URL-type federated entry
        assert " → " in sources["federated-alpha"]
        assert "https://example.invalid/external-a.git" in sources["federated-alpha"]
        # Path-type federated entry — the inner ref is included after " → ".
        assert " → " in sources["federated-beta"]

    def test_mixed_marketplace_supported(self, runner, fixtures_dir):
        """Decision #3: a marketplace can mix bundled (./plugins/x) and
        federated (source-object) entries. Both resolve correctly."""
        mp = str(fixtures_dir / "mixed-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        names = {r["plugin"]["name"] for r in parsed["reports"]}
        assert names == {"bundled-one", "federated-c"}

    def test_federated_clone_failure_aborts_scan(self, runner, fixtures_dir, monkeypatch):
        """Decision #2: a per-plugin clone failure propagates as a whole-
        scan error (exit 1). Assumption: clone failures are rare and
        typically transient; user reruns rather than consuming a partial
        report."""
        from griffith.sources import GriffithCloneError
        import griffith.cli as cli_mod

        real_resolve = cli_mod.resolve

        from contextlib import contextmanager

        @contextmanager
        def _fake_resolve(src):
            if src.startswith("https://"):
                raise GriffithCloneError(f"simulated clone failure for {src}")
            with real_resolve(src) as result:
                yield result

        monkeypatch.setattr(cli_mod, "resolve", _fake_resolve)

        mp = str(fixtures_dir / "federated-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        # Whole scan errors out (exit 1).
        assert result.exit_code == 1
        assert "clone failed" in result.stderr.lower() or "simulated" in result.stderr.lower()

    def test_existing_bundled_marketplace_unchanged(self, runner, fixtures_dir):
        """Regression: bundled-only marketplaces (the pre-federated path)
        behave identically. Source is the outer marketplace string; path
        is plugins/<name>."""
        mp = str(fixtures_dir / "minimal-marketplace")
        result = runner.invoke(main, ["analyze", mp, "--json"])
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        names = {r["plugin"]["name"] for r in parsed["reports"]}
        assert names == {"plugin-alpha", "plugin-beta"}
        # Bundled entries still use the outer source verbatim (no " → ").
        for r in parsed["reports"]:
            assert r["plugin"]["source"] == mp
            assert r["plugin"]["path"].startswith("plugins/")


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


# ============================================================================
# Phase 1.5 Unit 6: --sca flag (Tier 2 CVE scanning)
# ============================================================================


class TestScaCliE2E:
    def test_sca_hard_fails_with_exit_2_when_binary_missing(
        self, runner, minimal_plugin, monkeypatch
    ):
        """--sca must exit 2 (distinct from 1) when osv-scanner is not found."""
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.find_osv_scanner",
            lambda **kw: None,
        )
        result = runner.invoke(main, ["analyze", str(minimal_plugin), "--sca"])
        assert result.exit_code == 2, f"stderr={result.stderr}"
        assert "osv-scanner" in result.stderr.lower()
        # Install pitch must surface
        assert "brew install osv-scanner" in result.stderr

    def test_no_sca_never_probes_for_osv_scanner(
        self, runner, minimal_plugin, monkeypatch
    ):
        """Default (no --sca) path must not call find_osv_scanner at all."""
        called = {"n": 0}

        def tripwire(**kw):
            called["n"] += 1
            return None

        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.find_osv_scanner", tripwire
        )
        result = runner.invoke(main, ["analyze", str(minimal_plugin)])
        assert result.exit_code == 0, result.stderr
        assert called["n"] == 0

    def test_sca_populates_sca_field_in_json(
        self, runner, fixtures_dir, tmp_path, monkeypatch
    ):
        """Stubbed adapter yields a populated dependencies.sca in JSON."""
        from griffith.analyzer.dependencies import SCAResult, Vulnerability

        fake_result = SCAResult(
            osv_scanner_version="2.3.5",
            vulnerability_count=2,
            vulnerabilities=[
                Vulnerability(
                    id="GHSA-crit",
                    severity="critical",
                    severity_raw="9.8",
                    summary="Critical RCE",
                    affected_package="requests",
                    fixed_versions=["2.31.0"],
                ),
                Vulnerability(
                    id="GHSA-high",
                    severity="high",
                    severity_raw="7.5",
                    summary="SSRF",
                    affected_package="requests",
                    fixed_versions=[],
                ),
            ],
            scan_status="ok",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.find_osv_scanner",
            lambda **kw: tmp_path / "fake-osv",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.run_osv_scanner",
            lambda *a, **kw: fake_result,
        )
        result = runner.invoke(
            main,
            ["analyze", str(fixtures_dir / "deps-python-plugin"), "--sca", "--json"],
        )
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        deps = parsed["dependencies"]
        assert deps["scan_status"] == "ok"
        assert deps["sca"] is not None
        assert deps["sca"]["osv_scanner_version"] == "2.3.5"
        assert deps["sca"]["vulnerability_count"] == 2
        ids = [v["id"] for v in deps["sca"]["vulnerabilities"]]
        assert "GHSA-crit" in ids
        assert "GHSA-high" in ids

    def test_sca_untrusted_fields_includes_tier2_paths(
        self, runner, minimal_plugin, tmp_path, monkeypatch
    ):
        """untrusted_fields should list Tier 2 dotted paths after --sca."""
        from griffith.analyzer.dependencies import SCAResult

        fake = SCAResult(
            osv_scanner_version="2.3.5",
            vulnerability_count=0,
            vulnerabilities=[],
            scan_status="ok",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.find_osv_scanner",
            lambda **kw: tmp_path / "fake-osv",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.run_osv_scanner",
            lambda *a, **kw: fake,
        )
        result = runner.invoke(
            main, ["analyze", str(minimal_plugin), "--sca", "--json"]
        )
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        untrusted = parsed["untrusted_fields"]
        assert "dependencies.sca.vulnerabilities[].id" in untrusted
        assert "dependencies.sca.vulnerabilities[].severity_raw" in untrusted
        assert "dependencies.sca.error" in untrusted

    def test_sca_rich_renders_cve_section(
        self, runner, fixtures_dir, tmp_path, monkeypatch
    ):
        """Rich output includes a 'CVE scan' header and finding detail."""
        from griffith.analyzer.dependencies import SCAResult, Vulnerability

        fake = SCAResult(
            osv_scanner_version="2.3.5",
            vulnerability_count=1,
            vulnerabilities=[
                Vulnerability(
                    id="GHSA-demo",
                    severity="high",
                    severity_raw="7.5",
                    summary="demo SSRF",
                    affected_package="requests",
                    fixed_versions=["2.31.0"],
                )
            ],
            scan_status="ok",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.find_osv_scanner",
            lambda **kw: tmp_path / "fake-osv",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.run_osv_scanner",
            lambda *a, **kw: fake,
        )
        result = runner.invoke(
            main, ["analyze", str(fixtures_dir / "deps-python-plugin"), "--sca"]
        )
        assert result.exit_code == 0, result.stderr
        assert "CVE scan" in result.stdout
        assert "GHSA-demo" in result.stdout
        assert "requests" in result.stdout

    def test_sca_failed_scan_shows_error(
        self, runner, fixtures_dir, tmp_path, monkeypatch
    ):
        from griffith.analyzer.dependencies import SCAResult

        fake = SCAResult(
            osv_scanner_version="2.3.5",
            vulnerability_count=0,
            vulnerabilities=[],
            error="osv-scanner exited with code 3: boom",
            scan_status="sca_requested_and_failed",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.find_osv_scanner",
            lambda **kw: tmp_path / "fake-osv",
        )
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.run_osv_scanner",
            lambda *a, **kw: fake,
        )
        result = runner.invoke(
            main, ["analyze", str(fixtures_dir / "deps-python-plugin"), "--sca", "--json"]
        )
        assert result.exit_code == 0, result.stderr
        parsed = json.loads(result.stdout)
        deps = parsed["dependencies"]
        assert deps["scan_status"] == "sca_requested_and_failed"
        assert "boom" in deps["sca"]["error"]
