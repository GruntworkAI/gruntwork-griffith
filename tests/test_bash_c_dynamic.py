"""Unit 2 tests — bash-c-dynamic-interpolated (critical) + bash-c-dynamic-literal-dollar (medium).

Two YAML regex rules that refine `bash-c-inline`:

- `bash-c-dynamic-interpolated` (critical): double-quoted or unquoted
  `-c` arg with `$VAR`/`${...}`/`$(...)`/backticks
- `bash-c-dynamic-literal-dollar` (medium): single-quoted `-c` arg with
  literal `$` (usually deferred-shell intent)

Both fire additively; `bash-c-inline` info-level capability always fires.

Truth table from the plan's Unit 2 section, exhaustive:
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from griffith.analyzer.inventory import PluginInventory
from griffith.analyzer.security import SecurityScanner


@pytest.fixture
def tmp_plugin(tmp_path: Path) -> Path:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "test-plugin"})
    )
    (tmp_path / "hooks").mkdir()
    return tmp_path


def _scan_sh(tmp_plugin: Path, content: str):
    (tmp_plugin / "hooks" / "script.sh").write_text(content + "\n")
    inv = PluginInventory.from_path(tmp_plugin)
    return SecurityScanner().scan(inv)


def _ids(findings):
    return {f.rule_id for f in findings}


def _by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


class TestCapabilityAlwaysFires:
    def test_static_bash_c_info_only(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "echo hello"')
        assert _by_id(findings, "bash-c-inline")
        assert not _by_id(findings, "bash-c-dynamic-interpolated")
        assert not _by_id(findings, "bash-c-dynamic-literal-dollar")

    def test_capability_severity_is_info(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "echo hello"')
        cap = _by_id(findings, "bash-c-inline")
        assert len(cap) == 1
        assert cap[0].severity == "info"


class TestDoubleQuotedInterpolation:
    """bash-c-dynamic-interpolated (critical) — double-quoted -c with
    $VAR / ${...} / $(...) / backticks."""

    def test_env_var(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "$HOME/bin/tool"')
        assert _by_id(findings, "bash-c-dynamic-interpolated")
        assert _by_id(findings, "bash-c-inline")  # capability still fires

    def test_severity_critical(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "$HOME/x"')
        rule = _by_id(findings, "bash-c-dynamic-interpolated")
        assert rule and rule[0].severity == "critical"

    def test_command_substitution(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "$(date)"')
        assert _by_id(findings, "bash-c-dynamic-interpolated")

    def test_brace_expansion(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "${VAR:-default}"')
        assert _by_id(findings, "bash-c-dynamic-interpolated")

    def test_backticks(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "`whoami`"')
        assert _by_id(findings, "bash-c-dynamic-interpolated")

    def test_timeout_wrapped_static(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'timeout 30 bash -c "echo hello"')
        assert not _by_id(findings, "bash-c-dynamic-interpolated")
        assert _by_id(findings, "bash-c-inline")  # capability

    def test_timeout_wrapped_dynamic(self, tmp_plugin):
        """superpowers regression: `timeout "$t" bash -c "$cmd"`."""
        findings = _scan_sh(
            tmp_plugin, 'timeout "$timeout" bash -c "$cmd"'
        )
        assert _by_id(findings, "bash-c-dynamic-interpolated")

    def test_sh_dash_c(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'sh -c "$X"')
        assert _by_id(findings, "bash-c-dynamic-interpolated")

    def test_zsh_dash_c(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'zsh -c "$X"')
        assert _by_id(findings, "bash-c-dynamic-interpolated")

    def test_escaped_inner_quote_with_var(self, tmp_plugin):
        r"""`bash -c "echo \"$V\""` — escaped inner quote around $V."""
        findings = _scan_sh(
            tmp_plugin, r'bash -c "echo \"$V\""'
        )
        assert _by_id(findings, "bash-c-dynamic-interpolated")


class TestUnquotedDynamic:
    """bash-c-dynamic-interpolated (critical) — unquoted -c arg with $."""

    def test_bare_dollar_token(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, "bash -c $CMD")
        assert _by_id(findings, "bash-c-dynamic-interpolated")


class TestSingleQuotedLiteralDollar:
    """bash-c-dynamic-literal-dollar (medium) — single-quoted -c arg
    with literal $. Shell suppresses interpolation; usually
    deferred-shell intent."""

    def test_single_quoted_dollar_var(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, "bash -c 'echo $VAR'")
        assert _by_id(findings, "bash-c-dynamic-literal-dollar")

    def test_severity_medium(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, "bash -c 'echo $VAR'")
        rule = _by_id(findings, "bash-c-dynamic-literal-dollar")
        assert rule and rule[0].severity == "medium"

    def test_single_quoted_no_dollar_info_only(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, "bash -c 'echo hello'")
        assert not _by_id(findings, "bash-c-dynamic-literal-dollar")
        assert not _by_id(findings, "bash-c-dynamic-interpolated")
        assert _by_id(findings, "bash-c-inline")

    def test_single_quoted_does_not_fire_double_rule(self, tmp_plugin):
        """Single-quoted $ should only fire the medium rule, not the
        critical double-quote/unquoted rule."""
        findings = _scan_sh(tmp_plugin, "bash -c 'echo $VAR'")
        assert not _by_id(findings, "bash-c-dynamic-interpolated")


class TestScope:
    def test_fires_in_hooks_sh(self, tmp_plugin):
        findings = _scan_sh(tmp_plugin, 'bash -c "$CMD"')
        assert _by_id(findings, "bash-c-dynamic-interpolated")

    def test_does_not_fire_in_agents(self, tmp_plugin):
        """bash-c rules only apply to hooks/ and *.sh; markdown in
        agents/ shouldn't trigger."""
        (tmp_plugin / "agents").mkdir(exist_ok=True)
        (tmp_plugin / "agents" / "a.md").write_text(
            '---\nname: a\n---\nExample: `bash -c "$VAR"`\n'
        )
        inv = PluginInventory.from_path(tmp_plugin)
        findings = SecurityScanner().scan(inv)
        # Match against agent file only, not hook
        in_agent = [
            f for f in findings
            if f.file.startswith("agents/") and "bash-c" in f.rule_id
        ]
        assert not in_agent
