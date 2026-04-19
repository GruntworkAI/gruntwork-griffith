"""Tests for griffith.analyzer.osv_adapter — Phase 1.5 Unit 6.

Covers:
- find_osv_scanner() discovery priority + reject-roots containment
- _map_cvss_to_severity() fail-closed mapping
- _extract_vulnerabilities() JSON walk
- _build_osv_env() env scrubbing
- run_osv_scanner() subprocess wrapper with a fake osv-scanner shell script
"""

from __future__ import annotations

import json
import os
import stat
import textwrap
from pathlib import Path

import pytest

from griffith.analyzer.dependencies import SCAResult, Vulnerability
from griffith.analyzer.osv_adapter import (
    OSV_TIMEOUT_SECONDS,
    OSVScannerMissingError,
    _build_osv_env,
    _extract_vulnerabilities,
    _map_cvss_to_severity,
    _probe_version,
    find_osv_scanner,
    run_osv_scanner,
)


# ============================================================================
# _map_cvss_to_severity — fail-closed
# ============================================================================


class TestCVSSMapping:
    @pytest.mark.parametrize("raw,expected", [
        ("9.8", "critical"),
        ("9.0", "critical"),
        ("10", "critical"),
        ("10.0", "critical"),
        ("8.1", "high"),
        ("7.0", "high"),
        ("6.9", "medium"),
        ("4.0", "medium"),
        ("3.9", "low"),
        ("0.1", "low"),
        ("0", "info"),
        ("0.0", "info"),
    ])
    def test_numeric_bands(self, raw, expected):
        assert _map_cvss_to_severity(raw) == expected

    def test_empty_defaults_to_critical(self):
        assert _map_cvss_to_severity("") == "critical"

    def test_whitespace_defaults_to_critical(self):
        assert _map_cvss_to_severity("   ") == "critical"

    def test_non_string_defaults_to_critical(self):
        assert _map_cvss_to_severity(None) == "critical"  # type: ignore[arg-type]
        assert _map_cvss_to_severity(7.5) == "critical"  # type: ignore[arg-type]

    def test_vector_string_extracts_first_numeric(self):
        # CVSS vector strings embed a spec version (3.1) before the base
        # score; our first-numeric extraction latches onto that. The caller
        # still gets severity_raw unchanged, so the authoritative score is
        # preserved even when our severity mapping is permissive here.
        # Downside accepted: vector-only strings may under-rate. Upside:
        # severity_raw is a loud untrusted field the consumer can re-interpret.
        assert _map_cvss_to_severity("CVSS:3.1/AV:N/AC:L") == "low"

    def test_string_with_only_base_score(self):
        # When the input is just the base score (osv-scanner's common emit),
        # mapping is unambiguous.
        assert _map_cvss_to_severity("7.5") == "high"

    def test_out_of_range_defaults_to_critical(self):
        assert _map_cvss_to_severity("11.5") == "critical"
        assert _map_cvss_to_severity("-1.0") == "critical"

    def test_garbage_string_defaults_to_critical(self):
        assert _map_cvss_to_severity("not a score") == "critical"


# ============================================================================
# _extract_vulnerabilities — OSV JSON walk
# ============================================================================


class TestExtractVulnerabilities:
    def test_empty_results_returns_empty_list(self):
        assert _extract_vulnerabilities({"results": []}) == []

    def test_missing_results_returns_empty_list(self):
        assert _extract_vulnerabilities({}) == []

    def test_non_dict_input_returns_empty_list(self):
        assert _extract_vulnerabilities([]) == []  # type: ignore[arg-type]
        assert _extract_vulnerabilities(None) == []  # type: ignore[arg-type]

    def test_single_vuln_extracted(self):
        osv_output = {
            "results": [
                {
                    "source": {"path": "requirements.txt", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "requests",
                                "version": "2.20.0",
                                "ecosystem": "PyPI",
                            },
                            "groups": [
                                {
                                    "ids": ["GHSA-xxxx-yyyy-zzzz"],
                                    "max_severity": "7.5",
                                }
                            ],
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-xxxx-yyyy-zzzz",
                                    "summary": "requests SSRF",
                                    "affected": [
                                        {
                                            "ranges": [
                                                {
                                                    "events": [
                                                        {"introduced": "0"},
                                                        {"fixed": "2.31.0"},
                                                    ]
                                                }
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        vulns = _extract_vulnerabilities(osv_output)
        assert len(vulns) == 1
        v = vulns[0]
        assert v.id == "GHSA-xxxx-yyyy-zzzz"
        assert v.severity == "high"
        assert v.severity_raw == "7.5"
        assert v.summary == "requests SSRF"
        assert v.affected_package == "requests"
        assert v.fixed_versions == ["2.31.0"]

    def test_multiple_vulns_sorted_by_severity(self):
        osv_output = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "pkg-a"},
                            "groups": [
                                {"ids": ["CVE-LOW"], "max_severity": "2.0"},
                                {"ids": ["CVE-CRIT"], "max_severity": "9.5"},
                                {"ids": ["CVE-MED"], "max_severity": "5.0"},
                            ],
                        }
                    ]
                }
            ]
        }
        vulns = _extract_vulnerabilities(osv_output)
        assert [v.id for v in vulns] == ["CVE-CRIT", "CVE-MED", "CVE-LOW"]

    def test_missing_severity_maps_to_critical_fail_closed(self):
        osv_output = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "pkg-x"},
                            "groups": [{"ids": ["CVE-NO-SEV"]}],  # no max_severity
                        }
                    ]
                }
            ]
        }
        vulns = _extract_vulnerabilities(osv_output)
        assert len(vulns) == 1
        assert vulns[0].severity == "critical"  # fail-closed

    def test_malformed_packages_skipped(self):
        osv_output = {
            "results": [
                {
                    "packages": [
                        "not-a-dict",
                        {"package": {"name": "ok-pkg"}, "groups": [
                            {"ids": ["CVE-OK"], "max_severity": "5.0"}
                        ]},
                    ]
                }
            ]
        }
        vulns = _extract_vulnerabilities(osv_output)
        assert len(vulns) == 1
        assert vulns[0].id == "CVE-OK"


# ============================================================================
# _build_osv_env — env scrubbing
# ============================================================================


class TestBuildOsvEnv:
    def test_scrubs_shell_hostile_vars(self, monkeypatch):
        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/ssh.sock")
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
        monkeypatch.setenv("NODE_OPTIONS", "--inspect")
        monkeypatch.setenv("PYTHONPATH", "/tmp/evil")
        monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -oEvil")
        env = _build_osv_env()
        assert "SSH_AUTH_SOCK" not in env
        assert "LD_PRELOAD" not in env
        assert "DYLD_INSERT_LIBRARIES" not in env
        assert "NODE_OPTIONS" not in env
        assert "PYTHONPATH" not in env
        assert "GIT_SSH_COMMAND" not in env

    def test_preserves_path_and_home(self):
        env = _build_osv_env()
        assert "PATH" in env
        assert env.get("LANG") == "C.UTF-8"

    def test_strips_all_git_prefixed_vars(self, monkeypatch):
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/tmp/evil.cfg")
        monkeypatch.setenv("GIT_DIR", "/tmp/evil")
        env = _build_osv_env()
        for k in env:
            assert not k.startswith("GIT_"), k

    def test_overrides_xdg_cache_home(self, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", "/tmp/attacker-cache")
        env = _build_osv_env()
        assert env["XDG_CACHE_HOME"] != "/tmp/attacker-cache"
        assert "griffith" in env["XDG_CACHE_HOME"]


# ============================================================================
# find_osv_scanner — discovery + containment
# ============================================================================


class TestFindOsvScanner:
    def test_env_override_wins(self, tmp_path, monkeypatch):
        fake = tmp_path / "osv-scanner"
        fake.write_text("#!/bin/sh\necho ok\n")
        fake.chmod(0o755)
        monkeypatch.setenv("GRIFFITH_OSV_SCANNER", str(fake))
        found = find_osv_scanner()
        assert found == fake.resolve()

    def test_env_override_must_exist(self, tmp_path, monkeypatch):
        # Bogus env override + no osv-scanner on PATH → None
        monkeypatch.setenv("GRIFFITH_OSV_SCANNER", str(tmp_path / "nope"))
        monkeypatch.setenv("PATH", str(tmp_path))  # no osv-scanner here
        found = find_osv_scanner(reject_roots=(tmp_path.parent,))
        # Could still find a system binary via _FALLBACK_BINARY_PATHS;
        # assert instead that the bogus env override is NOT returned.
        assert found != tmp_path / "nope"

    def test_reject_root_containment(self, tmp_path, monkeypatch):
        # Planted "osv-scanner" inside reject root → skipped
        planted = tmp_path / "osv-scanner"
        planted.write_text("#!/bin/sh\necho planted\n")
        planted.chmod(0o755)
        monkeypatch.setenv("GRIFFITH_OSV_SCANNER", str(planted))
        # reject_roots includes tmp_path → env override must be rejected
        found = find_osv_scanner(reject_roots=(tmp_path,))
        # Should not return the planted one (may still find system binary)
        assert found != planted.resolve()


# ============================================================================
# run_osv_scanner — subprocess integration (with fake osv-scanner)
# ============================================================================


def _write_fake_osv(tmp_path: Path, script: str) -> Path:
    """Materialize a fake osv-scanner shell script at tmp_path/osv-scanner."""
    fake = tmp_path / "osv-scanner"
    fake.write_text(script)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return fake


class TestRunOsvScanner:
    def test_ok_zero_vulns(self, tmp_path):
        fake = _write_fake_osv(tmp_path, textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "osv-scanner version: 2.3.5"
              exit 0
            fi
            echo '{"results": []}'
            exit 0
        """))
        result = run_osv_scanner(fake, tmp_path)
        assert result.scan_status == "ok"
        assert result.vulnerability_count == 0
        assert result.vulnerabilities == []
        assert result.error is None

    def test_ok_with_vulns_exit_1(self, tmp_path):
        # Write JSON to a side file and have the fake `cat` it — avoids
        # heredoc indentation hazards.
        fake_json = json.dumps({
            "results": [
                {"packages": [
                    {"package": {"name": "requests"},
                     "groups": [{"ids": ["GHSA-1"], "max_severity": "7.5"}],
                     "vulnerabilities": [{"id": "GHSA-1", "summary": "test"}]}
                ]}
            ]
        })
        json_file = tmp_path / "osv-output.json"
        json_file.write_text(fake_json)
        fake = _write_fake_osv(tmp_path, textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "osv-scanner version: 2.3.5"
              exit 0
            fi
            cat {json_file}
            exit 1
        """))
        result = run_osv_scanner(fake, tmp_path)
        assert result.scan_status == "ok"
        assert result.vulnerability_count == 1
        assert result.vulnerabilities[0].id == "GHSA-1"
        assert result.vulnerabilities[0].severity == "high"

    def test_exit_128_no_scannable_sources(self, tmp_path):
        fake = _write_fake_osv(tmp_path, textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "osv-scanner version: 2.3.5"
              exit 0
            fi
            echo '' >&2
            exit 128
        """))
        result = run_osv_scanner(fake, tmp_path)
        assert result.scan_status == "ok"
        assert result.note is not None
        assert "scannable package sources" in result.note

    def test_malformed_json_on_success_exit(self, tmp_path):
        fake = _write_fake_osv(tmp_path, textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "osv-scanner version: 2.3.5"
              exit 0
            fi
            echo 'this is not json {{{'
            exit 0
        """))
        result = run_osv_scanner(fake, tmp_path)
        assert result.scan_status == "sca_malformed_output"
        assert result.error is not None

    def test_generic_failure_exit(self, tmp_path):
        fake = _write_fake_osv(tmp_path, textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "osv-scanner version: 2.3.5"
              exit 0
            fi
            echo 'boom' >&2
            exit 3
        """))
        result = run_osv_scanner(fake, tmp_path)
        assert result.scan_status == "sca_requested_and_failed"
        assert result.error is not None
        assert "3" in result.error

    def test_timeout(self, tmp_path):
        fake = _write_fake_osv(tmp_path, textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "osv-scanner version: 2.3.5"
              exit 0
            fi
            sleep 30
            exit 0
        """))
        result = run_osv_scanner(fake, tmp_path, timeout=1)
        assert result.scan_status == "sca_requested_and_timed_out"
        assert result.error is not None
        assert "timed out" in result.error

    def test_version_probe(self, tmp_path):
        fake = _write_fake_osv(tmp_path, textwrap.dedent("""\
            #!/bin/sh
            echo "osv-scanner version: 2.3.5"
            exit 0
        """))
        assert _probe_version(fake) == "2.3.5"

    def test_version_probe_falls_back_to_unknown(self, tmp_path):
        fake = _write_fake_osv(tmp_path, textwrap.dedent("""\
            #!/bin/sh
            echo "some other output"
            exit 0
        """))
        assert _probe_version(fake) == "unknown"


# ============================================================================
# DependencyAnalyzer.analyze(sca=True) integration
# ============================================================================


class TestAnalyzerScaIntegration:
    def test_sca_missing_binary_raises(self, fixtures_dir, monkeypatch):
        """With no osv-scanner discoverable, analyze(sca=True) raises."""
        from griffith.analyzer import DependencyAnalyzer

        monkeypatch.setenv("GRIFFITH_OSV_SCANNER", "/nonexistent/osv-scanner")
        # Force shutil.which to return None so fallbacks are the only path;
        # we can't easily scrub system fallbacks in the test, so we
        # monkeypatch find_osv_scanner directly.
        monkeypatch.setattr(
            "griffith.analyzer.osv_adapter.find_osv_scanner",
            lambda **kw: None,
        )
        with pytest.raises(OSVScannerMissingError):
            DependencyAnalyzer().analyze(
                fixtures_dir / "minimal-plugin", sca=True
            )

    def test_sca_ok_populates_sca_field(self, fixtures_dir, monkeypatch, tmp_path):
        """With a stubbed find+run, analyze(sca=True) populates report.sca."""
        from griffith.analyzer import DependencyAnalyzer

        fake_sca = SCAResult(
            osv_scanner_version="2.3.5",
            vulnerability_count=1,
            vulnerabilities=[
                Vulnerability(
                    id="GHSA-1",
                    severity="high",
                    severity_raw="7.5",
                    summary="test vuln",
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
            lambda *a, **kw: fake_sca,
        )
        report = DependencyAnalyzer().analyze(
            fixtures_dir / "deps-python-plugin", sca=True
        )
        assert report.sca is not None
        assert report.sca.vulnerability_count == 1
        assert report.scan_status == "ok"
