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

    def test_node_plugin_detects_nested_package_json(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-node-plugin")
        paths = {m.path for m in report.manifests}
        assert "skills/node-skill/package.json" in paths

    def test_multi_ecosystem_plugin_detects_all_three(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(
            fixtures_dir / "deps-multi-ecosystem-plugin"
        )
        paths = {m.path for m in report.manifests}
        assert "Gemfile" in paths
        assert "go.mod" in paths
        assert "Cargo.toml" in paths
        # Ruby/Go/Rust parsing deferred to Phase 1.6
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
    def test_multi_ecosystem_still_has_empty_packages(self, fixtures_dir):
        # Ruby/Go/Rust parsing deferred to Phase 1.6.
        report = DependencyAnalyzer().analyze(
            fixtures_dir / "deps-multi-ecosystem-plugin"
        )
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


# ============================================================================
# Unit 2: requirements.txt parser
# ============================================================================


class TestRequirementsTxt:
    def test_all_expected_packages_parsed(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        req_pkgs = [p for p in report.packages if p.manifest == "requirements.txt"]
        names = {p.name for p in req_pkgs}
        assert names == {
            "requests",
            "Pillow",
            "click",
            "tiktoken",
            "package-with-extras",
        }, f"got: {names}"

    def test_constraints_preserved(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        by_name = {
            p.name: p for p in report.packages if p.manifest == "requirements.txt"
        }
        assert by_name["requests"].constraint == ">=2.25.0"
        assert by_name["Pillow"].constraint == ">=10.0.0,<11.0.0"
        assert by_name["tiktoken"].constraint == "==0.8.0"
        assert by_name["click"].constraint == ""  # no constraint

    def test_extras_stripped_from_name(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        by_name = {
            p.name: p for p in report.packages if p.manifest == "requirements.txt"
        }
        # Fixture has "package-with-extras[full]>=1.0" — name should be
        # "package-with-extras" with extras stripped
        assert "package-with-extras" in by_name
        assert by_name["package-with-extras"].constraint == ">=1.0"

    def test_all_requirements_are_pypi_runtime(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        req_pkgs = [p for p in report.packages if p.manifest == "requirements.txt"]
        assert all(p.ecosystem == "PyPI" for p in req_pkgs)
        assert all(p.kind == "runtime" for p in req_pkgs)

    def test_option_lines_skipped(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        names = {p.name for p in report.packages if p.manifest == "requirements.txt"}
        # -r dev-requirements.txt, -e ./local-lib, --index-url should not appear
        for noise in ("dev-requirements.txt", "./local-lib", "simple", "https"):
            assert noise not in names

    def test_comments_skipped(self, tmp_path):
        plugin = tmp_path / "comments-plugin"
        plugin.mkdir()
        (plugin / "requirements.txt").write_text(
            "# comment line\n"
            "requests\n"
            "Pillow  # inline comment\n"
            "\n"
            "click  #trailing comment without space\n"
        )
        report = DependencyAnalyzer().analyze(plugin)
        names = {p.name for p in report.packages}
        assert names == {"requests", "Pillow", "click"}


# ============================================================================
# Unit 2: pyproject.toml — PEP 621
# ============================================================================


class TestPyprojectPEP621:
    def test_parses_pep621_runtime_dependencies(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        by_name = {
            p.name: p for p in report.packages if p.manifest == "pyproject.toml"
        }
        assert "fastapi" in by_name
        assert by_name["fastapi"].kind == "runtime"
        assert by_name["fastapi"].constraint == ">=0.100"

    def test_pep621_optional_dependencies_classified_as_optional(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        by_name = {
            p.name: p for p in report.packages if p.manifest == "pyproject.toml"
        }
        assert by_name["pytest"].kind == "optional"
        assert by_name["black"].kind == "optional"

    def test_pep621_extras_stripped(self, fixtures_dir):
        # fixture has "uvicorn[standard]>=0.20"
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-python-plugin")
        by_name = {
            p.name: p for p in report.packages if p.manifest == "pyproject.toml"
        }
        assert "uvicorn" in by_name
        assert by_name["uvicorn"].constraint == ">=0.20"


# ============================================================================
# Unit 2: pyproject.toml — Poetry style
# ============================================================================


class TestPyprojectPoetry:
    def test_parses_poetry_runtime_dependencies(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-poetry-plugin")
        by_name = {p.name: p for p in report.packages}
        assert "requests" in by_name
        assert by_name["requests"].kind == "runtime"
        assert by_name["requests"].constraint == "^2.28"

    def test_python_version_key_is_skipped(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-poetry-plugin")
        names = {p.name for p in report.packages}
        assert "python" not in names

    def test_table_form_version_extracted(self, fixtures_dir):
        # Fixture has `click = {version = "^8.1", extras = [...]}`
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-poetry-plugin")
        by_name = {p.name: p for p in report.packages}
        assert "click" in by_name
        assert by_name["click"].constraint == "^8.1"

    def test_dev_group_kind_is_dev(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-poetry-plugin")
        by_name = {p.name: p for p in report.packages}
        assert by_name["pytest"].kind == "dev"

    def test_test_group_kind_is_dev(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-poetry-plugin")
        by_name = {p.name: p for p in report.packages}
        assert by_name["pytest-cov"].kind == "dev"

    def test_other_groups_kind_is_optional(self, fixtures_dir):
        # docs group is neither dev nor test
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-poetry-plugin")
        by_name = {p.name: p for p in report.packages}
        assert by_name["sphinx"].kind == "optional"

    def test_pep621_and_poetry_coexistence(self, tmp_path):
        """If a pyproject declares both PEP 621 AND Poetry sections, parse PEP 621 first,
        then Poetry; dedup by (name, kind) keeping first constraint."""
        plugin = tmp_path / "coexist-plugin"
        plugin.mkdir()
        (plugin / "pyproject.toml").write_text(
            '[project]\n'
            'name = "coexist"\n'
            'dependencies = ["requests>=2.30"]\n'
            '\n'
            '[tool.poetry]\n'
            'name = "coexist"\n'
            '\n'
            '[tool.poetry.dependencies]\n'
            'python = "^3.11"\n'
            'requests = "^2.28"\n'  # duplicate (name, kind=runtime); PEP 621 wins
            'numpy = "^1.25"\n'  # only in Poetry
        )
        report = DependencyAnalyzer().analyze(plugin)
        by_name = {p.name: p for p in report.packages}
        assert by_name["requests"].constraint == ">=2.30", "PEP 621 should win"
        assert "numpy" in by_name
        assert by_name["numpy"].constraint == "^1.25"


# ============================================================================
# Unit 2: malformed manifest handling
# ============================================================================


class TestMalformedManifests:
    def test_malformed_toml_in_unscanned_manifests(self, tmp_path):
        plugin = tmp_path / "bad-toml"
        plugin.mkdir()
        (plugin / "pyproject.toml").write_text("[project\nname = ")  # unclosed
        report = DependencyAnalyzer().analyze(plugin)
        assert any(
            "pyproject.toml" in u for u in report.unscanned_manifests
        ), f"unscanned: {report.unscanned_manifests}"
        pyproj_pkgs = [
            p for p in report.packages if p.manifest.endswith("pyproject.toml")
        ]
        assert pyproj_pkgs == []

    def test_malformed_requirements_line_skipped_silently(self, tmp_path):
        plugin = tmp_path / "bad-reqs"
        plugin.mkdir()
        (plugin / "requirements.txt").write_text(
            "requests>=2.0\n"
            "@#$% bogus line\n"
            "Pillow\n"
        )
        report = DependencyAnalyzer().analyze(plugin)
        names = {p.name for p in report.packages}
        # Valid lines still parsed; malformed line silently skipped
        assert "requests" in names
        assert "Pillow" in names
        # File itself is readable; not in unscanned
        assert not any(
            "requirements.txt" in u for u in report.unscanned_manifests
        )


# ============================================================================
# Unit 2: adversarial parser defense
# ============================================================================


class TestAdversarialParsers:
    @pytest.mark.adversarial
    def test_long_line_in_requirements_doesnt_hang(self, tmp_path):
        """A very long single line must not hang the regex (ReDoS defense
        via anchored, bounded-repetition pattern)."""
        import time

        plugin = tmp_path / "long-line"
        plugin.mkdir()
        # 100 KB single line (stay well under the 2 MB size_skipped cap so
        # the parser actually reads it)
        huge = "a" * (100 * 1024)
        (plugin / "requirements.txt").write_text(huge + "\n")

        start = time.monotonic()
        report = DependencyAnalyzer().analyze(plugin)
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"scan took {elapsed:.1f}s (possible ReDoS)"
        # The single long line is malformed (exceeds bounded regex); skipped silently
        assert isinstance(report, DependencyReport)

    @pytest.mark.adversarial
    def test_deeply_nested_pyproject_does_not_crash(self, tmp_path):
        """Deeply-nested inline tables may raise RecursionError or
        TOMLDecodeError in tomllib; Griffith must catch and continue."""
        plugin = tmp_path / "depth-bomb"
        plugin.mkdir()
        depth = 2000
        # Build deeply nested inline table: a = { b = { b = { ... v = 1 } } }
        nested = (
            "[project]\nname = \"depth\"\n\n"
            "[extra]\nval = "
            + "{ inner = " * depth
            + "1"
            + " }" * depth
            + "\n"
        )
        (plugin / "pyproject.toml").write_text(nested)
        # Must return without propagating RecursionError
        report = DependencyAnalyzer().analyze(plugin)
        # File ends up in unscanned_manifests (or packages empty); either way no crash
        assert isinstance(report, DependencyReport)


# ============================================================================
# Unit 2: real-plugin integration (R11 pin)
# ============================================================================


REAL_CE = Path.home() / ".claude/plugins/cache/every-marketplace/compound-engineering/2.67.0"


@pytest.mark.skipif(not REAL_CE.exists(), reason="compound-engineering not cached")
class TestRealPluginCompoundEngineering:
    def test_r11_pin_surfaces_google_genai_and_pillow(self):
        """R11 requires that scanning CE@2.67.0 surfaces google-genai + Pillow
        from skills/gemini-imagegen/requirements.txt."""
        report = DependencyAnalyzer().analyze(REAL_CE)
        names = {p.name for p in report.packages}
        assert "google-genai" in names
        assert "Pillow" in names

    def test_r11_packages_are_runtime(self):
        report = DependencyAnalyzer().analyze(REAL_CE)
        by_name = {p.name: p for p in report.packages}
        assert by_name["google-genai"].kind == "runtime"
        assert by_name["Pillow"].kind == "runtime"

    def test_r11_manifest_path_is_nested(self):
        report = DependencyAnalyzer().analyze(REAL_CE)
        by_name = {p.name: p for p in report.packages}
        assert by_name["Pillow"].manifest == "skills/gemini-imagegen/requirements.txt"


# ============================================================================
# Unit 3: Node parser (package.json)
# ============================================================================


class TestPackageJson:
    def test_all_four_dep_kinds_parsed(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-node-plugin")
        by_name = {p.name: p for p in report.packages}
        # Fixture has dependencies (express, axios), devDependencies (jest),
        # peerDependencies (react). No optionalDependencies in the fixture.
        assert "express" in by_name
        assert "axios" in by_name
        assert "jest" in by_name
        assert "react" in by_name

    def test_kinds_classified_correctly(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-node-plugin")
        by_name = {p.name: p for p in report.packages}
        assert by_name["express"].kind == "runtime"
        assert by_name["axios"].kind == "runtime"
        assert by_name["jest"].kind == "dev"
        assert by_name["react"].kind == "peer"

    def test_constraints_preserved(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-node-plugin")
        by_name = {p.name: p for p in report.packages}
        assert by_name["express"].constraint == "^4.18.0"
        assert by_name["axios"].constraint == "~1.6.0"
        assert by_name["jest"].constraint == "^29.0.0"
        assert by_name["react"].constraint == ">=18"

    def test_ecosystem_is_npm(self, fixtures_dir):
        report = DependencyAnalyzer().analyze(fixtures_dir / "deps-node-plugin")
        node_pkgs = [
            p for p in report.packages if p.manifest.endswith("package.json")
        ]
        assert all(p.ecosystem == "npm" for p in node_pkgs)

    def test_optional_dependencies_classified(self, tmp_path):
        """Inline coverage for optionalDependencies since the shared fixture
        doesn't have one."""
        plugin = tmp_path / "node-optional"
        plugin.mkdir()
        (plugin / "package.json").write_text(
            '{"name": "x", "optionalDependencies": {"fsevents": "^2.3"}}'
        )
        report = DependencyAnalyzer().analyze(plugin)
        by_name = {p.name: p for p in report.packages}
        assert "fsevents" in by_name
        assert by_name["fsevents"].kind == "optional"

    def test_package_json_without_dep_sections_returns_empty(self, tmp_path):
        plugin = tmp_path / "no-deps"
        plugin.mkdir()
        (plugin / "package.json").write_text(
            '{"name": "x", "version": "1.0.0"}'
        )
        report = DependencyAnalyzer().analyze(plugin)
        assert report.packages == []
        # Manifest itself is valid, not in unscanned
        assert not any(
            "package.json" in u for u in report.unscanned_manifests
        )

    def test_wrong_shape_dep_section_skipped(self, tmp_path):
        """A dep section that isn't a dict should be skipped; other valid
        sections should still parse."""
        plugin = tmp_path / "weird-shape"
        plugin.mkdir()
        (plugin / "package.json").write_text(
            '{'
            '"dependencies": "this should be a dict but is a string",'
            '"devDependencies": {"jest": "^29.0.0"}'
            '}'
        )
        report = DependencyAnalyzer().analyze(plugin)
        by_name = {p.name: p for p in report.packages}
        # devDependencies still parses
        assert "jest" in by_name
        assert by_name["jest"].kind == "dev"
        # No packages from the malformed "dependencies" key
        assert not any(p.kind == "runtime" for p in report.packages)

    def test_malformed_json_recorded_in_unscanned(self, tmp_path):
        plugin = tmp_path / "bad-json"
        plugin.mkdir()
        (plugin / "package.json").write_text("{ this is not valid json")
        report = DependencyAnalyzer().analyze(plugin)
        assert any(
            "package.json" in u for u in report.unscanned_manifests
        )
        assert report.packages == []


# ============================================================================
# Unit 3: adversarial Node parser defense
# ============================================================================


class TestNodeAdversarial:
    @pytest.mark.adversarial
    def test_deeply_nested_package_json_does_not_crash(self, tmp_path):
        """Deeply-nested JSON arrays/objects must be caught by the
        RecursionError defense rather than crashing."""
        plugin = tmp_path / "node-depth-bomb"
        plugin.mkdir()
        depth = 2000
        # Build a deeply-nested object: {"a": {"a": {"a": ... 1}}}
        content = "{" + '"a":' * depth + "1" + "}" * depth
        (plugin / "package.json").write_text(content)
        # Must return without propagating RecursionError
        report = DependencyAnalyzer().analyze(plugin)
        assert isinstance(report, DependencyReport)
        # No valid deps in the payload; file may or may not be in unscanned
        # (depends on which error triggers first — that's fine)

    @pytest.mark.adversarial
    def test_package_json_with_attacker_named_package_sanitized(self, tmp_path):
        """Package names with embedded control chars / bidi overrides / ANSI
        escape must be sanitized before embedding in the report."""
        plugin = tmp_path / "node-injection"
        plugin.mkdir()
        # Use \x1b (ESC) in name; \u202e bidi override; all inside a valid
        # npm-ish name space. sanitize_string strips these.
        (plugin / "package.json").write_text(
            '{"dependencies": {"evil\\u202ename\\u001b[31m": "^1.0"}}'
        )
        report = DependencyAnalyzer().analyze(plugin)
        # All names must have had control chars stripped
        for p in report.packages:
            assert "\x1b" not in p.name
            assert "\u202e" not in p.name
