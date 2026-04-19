"""Unit 1: DependencyAnalyzer walk + dataclasses (detection only, no parsing).

Phase 1.5 test file. Replaces an earlier draft that encoded the since-pivoted
"roll our own parsers" API. Unit 1's scope is strictly detection — walking the
plugin tree and recognizing manifest/lockfile filenames. Parsing lands in
Units 2-3; CVE scanning in Unit 6.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from griffith.analyzer.dependencies import (
    DependencyAnalyzer,
    DependencyPackage,
    DependencyReport,
    ManifestInfo,
    SCAResult,
    Vulnerability,
)


# ============================================================================
# Basic detection against existing fixtures
# ============================================================================


class TestBasicDetection:
    def test_minimal_plugin_has_no_deps(self, minimal_plugin):
        report = DependencyAnalyzer().analyze(minimal_plugin)
        assert report.manifests == []
        assert report.lockfiles == []
        assert report.packages == []
        assert report.unscanned_manifests == []
        assert report.scan_status == "tier1_only"

    def test_python_plugin_detects_both_manifests(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        paths = {m.path for m in report.manifests}
        assert "requirements.txt" in paths
        assert "pyproject.toml" in paths
        # Unit 1 does not populate packages
        assert report.packages == []

    def test_node_plugin_detects_nested_package_json(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-node-plugin")
        paths = {m.path for m in report.manifests}
        assert "skills/node-skill/package.json" in paths
        assert report.packages == []

    def test_multi_ecosystem_plugin_detects_all_three(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(
            fixtures_dir / "deps-multi-ecosystem-plugin"
        )
        paths = {m.path for m in report.manifests}
        assert "Gemfile" in paths
        assert "go.mod" in paths
        assert "Cargo.toml" in paths
        # Unit 1 detects but never parses Ruby/Go/Rust
        assert report.packages == []


# ============================================================================
# Scan status and sca=True guard
# ============================================================================


class TestScanStatus:
    def test_default_is_tier1_only(self, minimal_plugin):
        report = DependencyAnalyzer().analyze(minimal_plugin)
        assert report.scan_status == "tier1_only"

    def test_sca_true_raises_not_implemented_pointing_at_unit_6(self, minimal_plugin):
        with pytest.raises(NotImplementedError, match="Unit 6"):
            DependencyAnalyzer().analyze(minimal_plugin, sca=True)


# ============================================================================
# Shape invariants — Unit 1 keeps packages empty and sca=None
# ============================================================================


class TestShape:
    def test_packages_always_empty_in_unit_1(self, fixtures_dir):
        for name in (
            "deps-python-plugin",
            "deps-node-plugin",
            "deps-multi-ecosystem-plugin",
        ):
            report = DependencyAnalyzer().analyze(fixtures_dir / name)
            assert report.packages == []
            assert report.package_count == 0

    def test_package_count_matches_len(self, minimal_plugin):
        report = DependencyAnalyzer().analyze(minimal_plugin)
        assert report.package_count == len(report.packages)

    def test_manifest_paths_are_relative(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        for m in report.manifests:
            assert not m.path.startswith("/"), (
                f"manifest path should be relative: {m.path}"
            )

    def test_lockfile_paths_are_relative(self, tmp_path):
        plugin = tmp_path / "lockfile-plugin"
        plugin.mkdir()
        (plugin / "poetry.lock").write_text("# empty\n")
        report = DependencyAnalyzer().analyze(plugin)
        for lf in report.lockfiles:
            assert not lf.path.startswith("/")

    def test_sca_is_none_in_tier1(self, minimal_plugin):
        report = DependencyAnalyzer().analyze(minimal_plugin)
        assert report.sca is None


# ============================================================================
# Lockfile-only detection
# ============================================================================


class TestLockfiles:
    def test_lockfile_only_plugin(self, tmp_path):
        plugin = tmp_path / "lockfile-only"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text(
            '{"name": "lockfile-only"}'
        )
        (plugin / "poetry.lock").write_text("# empty lockfile\n")
        (plugin / "package-lock.json").write_text("{}\n")

        report = DependencyAnalyzer().analyze(plugin)
        assert report.manifests == []
        lockfile_paths = {lf.path for lf in report.lockfiles}
        assert "poetry.lock" in lockfile_paths
        assert "package-lock.json" in lockfile_paths

    def test_all_documented_lockfile_formats_detected(self, tmp_path):
        plugin = tmp_path / "all-lockfiles"
        plugin.mkdir()
        for name in (
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Gemfile.lock",
            "go.sum",
            "Cargo.lock",
            "poetry.lock",
        ):
            (plugin / name).write_text("# placeholder\n")
        report = DependencyAnalyzer().analyze(plugin)
        paths = {lf.path for lf in report.lockfiles}
        assert paths == {
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Gemfile.lock",
            "go.sum",
            "Cargo.lock",
            "poetry.lock",
        }


# ============================================================================
# Edge cases
# ============================================================================


class TestEdgeCases:
    def test_empty_plugin_no_error(self, tmp_path):
        plugin = tmp_path / "empty-plugin"
        plugin.mkdir()
        report = DependencyAnalyzer().analyze(plugin)
        assert report.manifests == []
        assert report.lockfiles == []
        assert report.scan_status == "tier1_only"

    def test_nonexistent_path_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            DependencyAnalyzer().analyze(tmp_path / "does-not-exist")

    def test_file_instead_of_directory_raises_not_a_directory(self, tmp_path):
        not_a_dir = tmp_path / "not-a-dir.txt"
        not_a_dir.write_text("hello")
        with pytest.raises(NotADirectoryError):
            DependencyAnalyzer().analyze(not_a_dir)

    def test_git_directory_is_not_walked(self, tmp_path):
        plugin = tmp_path / "git-plugin"
        (plugin / ".git").mkdir(parents=True)
        # If .git were walked, this would be picked up as a manifest
        (plugin / ".git" / "pyproject.toml").write_text("# should NOT be discovered")
        report = DependencyAnalyzer().analyze(plugin)
        assert report.manifests == []

    def test_accepts_string_path(self, minimal_plugin):
        # analyze() must accept both Path and str per API contract
        report = DependencyAnalyzer().analyze(str(minimal_plugin))
        assert report.scan_status == "tier1_only"

    def test_requirements_dev_variant_detected(self, tmp_path):
        plugin = tmp_path / "req-variants"
        plugin.mkdir()
        (plugin / "requirements.txt").write_text("")
        (plugin / "requirements-dev.txt").write_text("")
        (plugin / "requirements_test.txt").write_text("")
        report = DependencyAnalyzer().analyze(plugin)
        paths = {m.path for m in report.manifests}
        assert "requirements.txt" in paths
        assert "requirements-dev.txt" in paths
        assert "requirements_test.txt" in paths


# ============================================================================
# Adversarial — hardening invariants
# ============================================================================


class TestAdversarial:
    @pytest.mark.adversarial
    def test_symlinked_manifest_recorded_but_not_followed(self, tmp_path):
        """A symlink like requirements.txt → /etc/hosts MUST be recorded with
        is_symlink=True and its content never read. Unit 1 does no content
        reads anyway, but the is_symlink flag is the signal Units 2-3 use to
        refuse parsing."""
        plugin = tmp_path / "symlink-plugin"
        plugin.mkdir()
        (plugin / ".claude-plugin").mkdir()
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "symlink"}')
        (plugin / "requirements.txt").symlink_to("/etc/hosts")

        report = DependencyAnalyzer().analyze(plugin)
        assert len(report.manifests) == 1
        m = report.manifests[0]
        assert m.path == "requirements.txt"
        assert m.is_symlink is True

    @pytest.mark.adversarial
    def test_oversized_manifest_is_size_skipped(self, tmp_path):
        """A 3 MB requirements.txt exceeds the 2 MB cap. Unit 1 records it
        with size_skipped=True so Units 2-3 know not to parse."""
        plugin = tmp_path / "oversized-plugin"
        plugin.mkdir()
        (plugin / ".claude-plugin").mkdir()
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "oversized"}')
        big = plugin / "requirements.txt"
        with big.open("wb") as f:
            f.truncate(3 * 1024 * 1024)

        report = DependencyAnalyzer().analyze(plugin)
        assert len(report.manifests) == 1
        m = report.manifests[0]
        assert m.is_symlink is False
        assert m.size_skipped is True

    @pytest.mark.adversarial
    def test_symlinked_directory_not_descended(self, tmp_path):
        """A symlinked subdirectory (e.g. skills → /etc) must not have its
        contents walked."""
        plugin = tmp_path / "symlink-dir-plugin"
        plugin.mkdir()
        (plugin / ".claude-plugin").mkdir()
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "sd"}')
        # Point a subdir at /etc via symlink
        (plugin / "skills").symlink_to("/etc")

        report = DependencyAnalyzer().analyze(plugin)
        # /etc/ is full of files; none of them should surface as manifests
        for m in report.manifests:
            assert not m.path.startswith("skills/"), (
                f"Walk descended through symlinked skills/: {m.path}"
            )


# ============================================================================
# Dataclass shapes — defined in Unit 1 even though Units 2-3/6 populate
# ============================================================================


class TestDataclasses:
    def test_manifest_info_fields(self):
        m = ManifestInfo(path="requirements.txt")
        assert m.path == "requirements.txt"
        assert m.is_symlink is False
        assert m.size_skipped is False

    def test_dependency_package_fields(self):
        pkg = DependencyPackage(
            ecosystem="PyPI",
            name="requests",
            constraint=">=2.0",
            kind="runtime",
            manifest="requirements.txt",
        )
        assert pkg.ecosystem == "PyPI"
        assert pkg.name == "requests"

    def test_vulnerability_fields(self):
        vuln = Vulnerability(
            id="CVE-2024-1",
            severity="high",
            severity_raw="7.5",
            summary="example",
            affected_package="requests",
        )
        assert vuln.fixed_versions == []

    def test_sca_result_fields(self):
        sca = SCAResult(osv_scanner_version="2.3.5", vulnerability_count=0)
        assert sca.vulnerabilities == []
        assert sca.note is None
        assert sca.error is None

    def test_dependency_report_defaults(self):
        report = DependencyReport()
        assert report.manifests == []
        assert report.lockfiles == []
        assert report.packages == []
        assert report.unscanned_manifests == []
        assert report.scan_status == "tier1_only"
        assert report.sca is None
        assert report.package_count == 0
