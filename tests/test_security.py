"""Tests for SecurityScanner — YAML-rule regex scanner with ReDoS defense."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from griffith.analyzer.inventory import PluginInventory
from griffith.analyzer.security import SecurityFinding, SecurityScanner

REAL_PLUGIN_LMF = Path(
    os.path.expanduser("~/.claude/plugins/cache/gruntwork-marketplace/lastmilefirst/0.14.0")
)
REAL_PLUGIN_CE = Path(
    os.path.expanduser(
        "~/.claude/plugins/cache/every-marketplace/compound-engineering/2.67.0"
    )
)


@pytest.fixture
def traps_inventory(fixtures_dir):
    return PluginInventory.from_path(fixtures_dir / "security-traps-plugin")


@pytest.fixture
def minimal_inventory(minimal_plugin):
    return PluginInventory.from_path(minimal_plugin)


def _ids(findings: list[SecurityFinding]) -> set[str]:
    return {f.rule_id for f in findings}


def _by_severity(findings: list[SecurityFinding], severity: str) -> list[SecurityFinding]:
    return [f for f in findings if f.severity == severity]


# ============================================================================
# Default-mode rule firings
# ============================================================================


class TestDefaultRuleFirings:
    def test_curl_pipe_shell_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "curl-pipe-shell" in _ids(findings)
        hit = [f for f in findings if f.rule_id == "curl-pipe-shell"][0]
        assert hit.severity == "critical"
        assert "curl-pipe.sh" in hit.file

    def test_python_eval_exec_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "python-eval-exec" in _ids(findings)

    def test_subprocess_in_hooks_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "subprocess-in-hooks" in _ids(findings)

    def test_hooks_path_tampering_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "hooks-path-tampering" in _ids(findings)

    def test_claude_settings_write_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "claude-settings-write" in _ids(findings)

    def test_ssh_key_reference_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "ssh-key-reference" in _ids(findings)

    def test_aws_credentials_reference_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "aws-credentials-reference" in _ids(findings)

    def test_dotfile_write_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "dotfile-write" in _ids(findings)

    def test_launch_agent_write_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "launch-agent-write" in _ids(findings)

    def test_osascript_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "osascript-exec" in _ids(findings)

    def test_network_egress_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "network-egress-shell" in _ids(findings)

    def test_bash_c_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "bash-c-inline" in _ids(findings)

    def test_chmod_777_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "chmod-777" in _ids(findings)

    def test_path_traversal_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "path-traversal" in _ids(findings)

    def test_bidi_override_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "bidi-override-chars" in _ids(findings)

    def test_webfetch_info_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "skill-uses-webfetch" in _ids(findings)

    def test_bash_skill_info_detected(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "skill-uses-bash" in _ids(findings)

    def test_gh_cli_info_in_hooks(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert "hook-requires-gh-cli" in _ids(findings)


# ============================================================================
# Strict mode: rules gated by `strict: true`
# ============================================================================


class TestStrictMode:
    def test_broad_credential_assignment_not_in_default(self, traps_inventory):
        findings = SecurityScanner(strict=False).scan(traps_inventory)
        assert "broad-credential-assignment" not in _ids(findings)

    def test_broad_credential_assignment_fires_in_strict(self, traps_inventory):
        findings = SecurityScanner(strict=True).scan(traps_inventory)
        assert "broad-credential-assignment" in _ids(findings)


# ============================================================================
# Context and exclude globs
# ============================================================================


class TestContextGlobs:
    def test_py_only_rule_skips_sh_files(self, traps_inventory):
        """python-eval-exec is scoped to **/*.py. The eval/exec in curl-pipe.sh (not present
        there anyway) must never match .sh files regardless of content."""
        findings = SecurityScanner().scan(traps_inventory)
        # Find all python-eval-exec findings; they must all be in .py files
        eval_findings = [f for f in findings if f.rule_id == "python-eval-exec"]
        assert all(f.file.endswith(".py") for f in eval_findings)

    def test_hooks_only_rule_skips_non_hooks(self, traps_inventory):
        """subprocess-in-hooks is scoped to hooks/**/*."""
        findings = SecurityScanner().scan(traps_inventory)
        subproc = [f for f in findings if f.rule_id == "subprocess-in-hooks"]
        assert all(f.file.startswith("hooks/") for f in subproc)

    def test_skills_only_rule_skips_hooks(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        webfetch = [f for f in findings if f.rule_id == "skill-uses-webfetch"]
        assert all(f.file.startswith("skills/") for f in webfetch)

    def test_gh_cli_rule_skips_agents_md(self, traps_inventory):
        """The agent mentions `gh` but it's in agents/ not hooks/ — should not fire."""
        findings = SecurityScanner().scan(traps_inventory)
        gh_findings = [f for f in findings if f.rule_id == "hook-requires-gh-cli"]
        assert all(f.file.startswith("hooks/") for f in gh_findings)


# ============================================================================
# Severity sort + finding shape
# ============================================================================


class TestFindingShape:
    def test_findings_sorted_critical_first(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        severity_order = ["critical", "high", "medium", "low", "info"]
        seen_severities = [f.severity for f in findings]
        for i in range(len(seen_severities) - 1):
            assert severity_order.index(seen_severities[i]) <= severity_order.index(
                seen_severities[i + 1]
            ), f"Findings not sorted at position {i}"

    def test_finding_has_rule_id_file_line_message(self, traps_inventory):
        findings = SecurityScanner().scan(traps_inventory)
        assert findings  # ensure we have something to check
        f = findings[0]
        assert isinstance(f.rule_id, str) and f.rule_id
        assert isinstance(f.file, str) and f.file
        assert isinstance(f.line, int) and f.line >= 1
        assert isinstance(f.message, str) and f.message
        assert isinstance(f.severity, str)

    def test_empty_plugin_produces_no_findings(self, tmp_path):
        plugin = tmp_path / "empty-plugin"
        plugin.mkdir()
        (plugin / ".claude-plugin").mkdir()
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "empty"}')
        inv = PluginInventory.from_path(plugin)
        findings = SecurityScanner().scan(inv)
        assert findings == []


# ============================================================================
# Snippet safety (matched bytes must not leak into findings)
# ============================================================================


class TestSnippetSafety:
    def test_matched_bytes_not_in_finding_string(self, tmp_path):
        """If a file contains an AWS-key-like literal, the finding must not echo the
        literal bytes back — snippet carries message + file:line only."""
        plugin = tmp_path / "aws-key-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "aws-key-test"}')
        (plugin / "hooks").mkdir()
        aws_literal = "AKIAIOSFODNN7EXAMPLE"
        (plugin / "hooks" / "leak.sh").write_text(
            f"#!/usr/bin/env bash\n"
            f"cat ~/.aws/credentials  # reference rule will fire\n"
            f"# nearby literal: {aws_literal}\n"
        )

        inv = PluginInventory.from_path(plugin)
        findings = SecurityScanner().scan(inv)
        # The rule fires for `~/.aws/credentials` reference; finding text must not
        # contain the AWS key literal even though it's a few lines away.
        for f in findings:
            combined = f"{f.rule_id} {f.file} {f.message}"
            assert aws_literal not in combined, (
                "SecurityFinding must not echo matched-or-neighbor bytes"
            )


# ============================================================================
# Symlink findings (from inventory walk)
# ============================================================================


class TestSymlinkFindings:
    @pytest.mark.adversarial
    def test_symlink_in_plugin_tree_becomes_critical_finding(self, tmp_path):
        plugin = tmp_path / "symlink-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "symlink-test"}')
        (plugin / "skills" / "evil").mkdir(parents=True)
        (plugin / "skills" / "evil" / "SKILL.md").symlink_to("/etc/hosts")

        inv = PluginInventory.from_path(plugin)
        findings = SecurityScanner().scan(inv)
        symlink_findings = [f for f in findings if f.rule_id == "symlink-in-plugin-tree"]
        assert len(symlink_findings) == 1
        assert symlink_findings[0].severity == "critical"


# ============================================================================
# Adversarial — ReDoS defense and long-line truncation
# ============================================================================


class TestAdversarial:
    @pytest.mark.adversarial
    def test_long_line_truncated_and_flagged(self, tmp_path):
        plugin = tmp_path / "long-line-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "long-line"}')
        (plugin / "hooks").mkdir()
        # 32 KB single line (default cap is 16 KB)
        huge_line = "A" * (32 * 1024)
        (plugin / "hooks" / "huge.sh").write_text(huge_line + "\n")

        inv = PluginInventory.from_path(plugin)
        findings = SecurityScanner().scan(inv)
        assert "truncated-long-line" in _ids(findings), (
            "Lines over 16 KB should emit a truncated-long-line finding"
        )

    @pytest.mark.adversarial
    def test_redos_payload_completes_within_timeout(self, tmp_path):
        """A pathological input + vulnerable regex would hang `re`. The `regex` lib
        with timeout=1s must bound the match and emit a regex-timeout finding rather
        than hang the scan."""
        import time

        plugin = tmp_path / "redos-plugin"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "redos"}')
        (plugin / "hooks").mkdir()
        # 10 KB of 'a' then '!' — catastrophic backtracking against (a+)+$
        # Our rules aren't obviously vulnerable, so this mainly proves no hang.
        (plugin / "hooks" / "redos.sh").write_text("a" * 10000 + "!\n")

        inv = PluginInventory.from_path(plugin)
        start = time.monotonic()
        findings = SecurityScanner().scan(inv)
        elapsed = time.monotonic() - start
        # Scan must complete; bound at ~30s to catch infinite-backtrack hangs.
        # With the regex lib's per-file timeout, actual elapsed should be well under 5s.
        assert elapsed < 30, f"Scan took too long: {elapsed:.1f}s"
        # Ensure scan still returned a list (not crashed)
        assert isinstance(findings, list)


# ============================================================================
# Rule-loading behavior
# ============================================================================


class TestRuleLoading:
    def test_missing_rules_file_surfaces_clear_error_at_scan(
        self, tmp_path, monkeypatch, minimal_inventory
    ):
        """Per plan: lazy-load means missing file errors at scan(), not import."""
        import griffith.analyzer.security as security_mod

        missing = tmp_path / "nowhere" / "security_patterns.yaml"
        monkeypatch.setattr(security_mod, "_DEFAULT_RULES_PATH", missing)

        scanner = SecurityScanner()
        with pytest.raises((FileNotFoundError, OSError)) as excinfo:
            scanner.scan(minimal_inventory)
        assert "security_patterns.yaml" in str(excinfo.value) or "No such file" in str(
            excinfo.value
        )


# ============================================================================
# Integration: real plugins on disk
# ============================================================================


@pytest.mark.skipif(not REAL_PLUGIN_LMF.exists(), reason="lastmilefirst not cached")
class TestRealPluginLastMileFirst:
    def test_finds_subprocess_in_hooks(self):
        """lastmilefirst hooks use subprocess.run — this is the pinned correctness guard."""
        inv = PluginInventory.from_path(REAL_PLUGIN_LMF)
        findings = SecurityScanner().scan(inv)
        subproc_findings = [
            f
            for f in findings
            if f.rule_id == "subprocess-in-hooks" and f.file.startswith("hooks/")
        ]
        assert len(subproc_findings) >= 1, (
            "Scanner should detect subprocess.run in lastmilefirst hooks"
        )

    def test_scan_completes_without_timeouts(self):
        inv = PluginInventory.from_path(REAL_PLUGIN_LMF)
        findings = SecurityScanner().scan(inv)
        timeouts = [f for f in findings if f.rule_id == "regex-timeout"]
        assert not timeouts, f"Scan against lastmilefirst hit regex timeouts: {timeouts}"


@pytest.mark.skipif(not REAL_PLUGIN_CE.exists(), reason="compound-engineering not cached")
class TestRealPluginCompoundEngineering:
    def test_scan_completes_without_timeouts(self):
        inv = PluginInventory.from_path(REAL_PLUGIN_CE)
        findings = SecurityScanner().scan(inv)
        timeouts = [f for f in findings if f.rule_id == "regex-timeout"]
        assert not timeouts


# ============================================================================
# Fingerprint-snapshot gates — R12 + R15
# ============================================================================


from griffith import __version__ as _GRIFFITH_VERSION  # noqa: E402
from tests.helpers.snapshots import assert_snapshot  # noqa: E402

SECURITY_TRAPS_FIXTURE = (
    Path(__file__).parent / "fixtures" / "security-traps-plugin"
)


class TestSecurityTrapsSnapshot:
    """R15: unconditional snapshot against a checked-in fixture so CI
    environments without cached marketplace plugins still gate on rule
    output. Runs without skipif.
    """

    @pytest.mark.timeout(5)
    def test_security_traps_snapshot_matches(self):
        inv = PluginInventory.from_path(SECURITY_TRAPS_FIXTURE)
        findings = SecurityScanner().scan(inv)
        assert_snapshot(
            "security-traps-plugin",
            findings,
            griffith_version=_GRIFFITH_VERSION,
        )


@pytest.mark.skipif(not REAL_PLUGIN_LMF.exists(), reason="lastmilefirst not cached")
class TestRealPluginLastMileFirstSnapshot:
    @pytest.mark.timeout(5)
    def test_lmf_snapshot_matches(self):
        inv = PluginInventory.from_path(REAL_PLUGIN_LMF)
        findings = SecurityScanner().scan(inv)
        assert_snapshot(
            "lastmilefirst-0.14.0",
            findings,
            griffith_version=_GRIFFITH_VERSION,
        )


@pytest.mark.skipif(not REAL_PLUGIN_CE.exists(), reason="compound-engineering not cached")
class TestRealPluginCompoundEngineeringSnapshot:
    @pytest.mark.timeout(5)
    def test_ce_snapshot_matches(self):
        inv = PluginInventory.from_path(REAL_PLUGIN_CE)
        findings = SecurityScanner().scan(inv)
        assert_snapshot(
            "compound-engineering-2.67.0",
            findings,
            griffith_version=_GRIFFITH_VERSION,
        )
