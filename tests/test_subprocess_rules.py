"""Unit 1 tests — subprocess-dynamic-command + subprocess-no-timeout.

subprocess-shell-true already landed in Unit 0b. These tests cover
the other two subprocess-family rules plus their interactions.

Key behavioral expectations per the plan:
- subprocess-dynamic-command uses an INVERTED check: fires on any arg[0]
  that's not provably-static. Catches bare Name, Subscript, Attribute,
  Starred(Name), f-string, BinOp, list-with-non-Constant, **kwargs.
- subprocess-no-timeout excludes Popen (Popen's timeout lives on
  .wait()/.communicate(), not __init__).
- All three subprocess-family rules (shell-true, dynamic, no-timeout)
  can stack additively on the same call site.
"""

from __future__ import annotations

import json
import textwrap
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


def _scan_hook(tmp_plugin: Path, source: str):
    (tmp_plugin / "hooks" / "h.py").write_text(textwrap.dedent(source))
    inv = PluginInventory.from_path(tmp_plugin)
    return SecurityScanner().scan(inv)


def _ids(findings):
    return {f.rule_id for f in findings}


def _by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# ============================================================================
# subprocess-dynamic-command
# ============================================================================


class TestSubprocessDynamicCommand:
    """Inverted check: fires unless arg[0] is provably static (Constant,
    or List/Tuple of all-Constants, or Starred(List/Tuple of Constants))."""

    def test_bare_name_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            cmd = "git status"
            subprocess.run(cmd)
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_subscript_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            import sys
            subprocess.run(sys.argv[1:])
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_attribute_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess

            class X:
                cmd = None

            x = X()
            subprocess.run(x.cmd)
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_starred_of_name_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            args = ["git", "status"]
            subprocess.run([*args])
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_starred_of_constant_tuple_does_not_fire(self, tmp_plugin):
        """Deterministic: `[*("a","b")]` has all-Constant inner elements
        via Starred-of-Tuple; is_provably_static treats this as static."""
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run([*("a", "b")])
            """,
        )
        assert not _by_id(findings, "subprocess-dynamic-command")

    def test_list_with_non_constant_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            user = "x"
            subprocess.run(["git", user])
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_binop_fires(self, tmp_plugin):
        """lmf run.py:31 shape: `cmd.split() + ["--version"]`."""
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            cmd = "python"
            subprocess.run(cmd.split() + ["--version"])
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_fstring_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            x = "target"
            subprocess.run(f"git {x}")
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_format_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            x = "target"
            subprocess.run("git {}".format(x))
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_kwargs_unpack_fires(self, tmp_plugin):
        """Zero positional args (all via **kwargs) means we can't verify
        any arg is static — fire high conservatively."""
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            opts = {"args": ["git"]}
            subprocess.run(**opts)
            """,
        )
        assert _by_id(findings, "subprocess-dynamic-command")

    def test_static_list_does_not_fire(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run(["git", "status"])
            """,
        )
        assert not _by_id(findings, "subprocess-dynamic-command")

    def test_pure_constant_does_not_fire(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run("git status")
            """,
        )
        assert not _by_id(findings, "subprocess-dynamic-command")


# ============================================================================
# subprocess-no-timeout
# ============================================================================


class TestSubprocessNoTimeout:
    def test_no_timeout_fires_low(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run(["git", "status"])
            """,
        )
        rule = _by_id(findings, "subprocess-no-timeout")
        assert len(rule) == 1
        assert rule[0].severity == "low"

    def test_with_timeout_does_not_fire(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run(["git"], timeout=5)
            """,
        )
        assert not _by_id(findings, "subprocess-no-timeout")

    def test_popen_excluded(self, tmp_plugin):
        """Popen doesn't accept `timeout=` at construction — rule skips
        to avoid false positives on every Popen call."""
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.Popen(["git"])
            """,
        )
        assert not _by_id(findings, "subprocess-no-timeout")

    def test_popen_aliased_excluded(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess as sp
            sp.Popen(["git"])
            """,
        )
        assert not _by_id(findings, "subprocess-no-timeout")

    def test_check_output_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.check_output(["git"])
            """,
        )
        assert _by_id(findings, "subprocess-no-timeout")

    def test_check_call_fires(self, tmp_plugin):
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.check_call(["git"])
            """,
        )
        assert _by_id(findings, "subprocess-no-timeout")


# ============================================================================
# Stacking — subprocess family rules additive on same call
# ============================================================================


class TestSubprocessRuleStacking:
    def test_all_four_stack_on_single_call(self, tmp_plugin):
        """`subprocess.run(f"git {x}", shell=True)` hits capability (info),
        shell-true (critical), dynamic (high), and no-timeout (low)."""
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            x = "y"
            subprocess.run(f"git {x}", shell=True)
            """,
        )
        ids = _ids(findings)
        assert "subprocess-in-hooks" in ids       # info capability
        assert "subprocess-shell-true" in ids     # critical
        assert "subprocess-dynamic-command" in ids  # high
        assert "subprocess-no-timeout" in ids     # low


# ============================================================================
# Regression: lmf-shaped fixtures
# ============================================================================


class TestLastmilefirstLikeShape:
    """Mirrors the ground-truth-verified subprocess call shapes from
    lastmilefirst 0.14.0 hooks. Expected: info capability always fires;
    BinOp + non-Constant → high dynamic; all-Constant list → no dynamic
    finding."""

    def test_lmf_run_py_line_31_shape(self, tmp_plugin):
        """`subprocess.run(cmd.split() + ["--version"], timeout=5)`."""
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            cmd = "python3"
            subprocess.run(cmd.split() + ["--version"], timeout=5)
            """,
        )
        assert _by_id(findings, "subprocess-in-hooks")       # info
        assert _by_id(findings, "subprocess-dynamic-command")  # high
        assert not _by_id(findings, "subprocess-shell-true")
        assert not _by_id(findings, "subprocess-no-timeout")   # has timeout=

    def test_lmf_session_start_shape(self, tmp_plugin):
        """`subprocess.run(["git", "rev-parse", "--git-dir"], timeout=5)`
        — all-constant list, timeout set: info only, no stricter findings."""
        findings = _scan_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run(["git", "rev-parse", "--git-dir"], timeout=5)
            """,
        )
        assert _by_id(findings, "subprocess-in-hooks")
        assert not _by_id(findings, "subprocess-dynamic-command")
        assert not _by_id(findings, "subprocess-shell-true")
        assert not _by_id(findings, "subprocess-no-timeout")
