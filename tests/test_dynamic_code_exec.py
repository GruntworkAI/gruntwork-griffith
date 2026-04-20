"""Unit 1 tests — dynamic-code-exec family (info capability + medium dynamic-arg).

`dynamic-code-exec` fires on any `exec()` or `eval()` call in hooks/
as a capability signal (info). `dynamic-code-exec-dynamic-arg` fires
additively at medium when args[0] is not a Constant — catches the
`exec(compile(...))` / `exec(base64.b64decode(...))` evasion pattern
that the security review surfaced.
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
    (tmp_path / "templates").mkdir()
    return tmp_path


def _scan(tmp_plugin: Path, filename: str, source: str):
    (tmp_plugin / filename).write_text(textwrap.dedent(source))
    inv = PluginInventory.from_path(tmp_plugin)
    return SecurityScanner().scan(inv)


def _by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


class TestDynamicCodeExecCapability:
    def test_exec_fires_info(self, tmp_plugin):
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            'exec("print(1)")',
        )
        rule = _by_id(findings, "dynamic-code-exec")
        assert len(rule) == 1
        assert rule[0].severity == "info"

    def test_eval_fires_info(self, tmp_plugin):
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            'eval("1 + 1")',
        )
        assert _by_id(findings, "dynamic-code-exec")

    def test_exec_only_applies_to_hooks(self, tmp_plugin):
        """Rule scope is hooks/**/*.py; exec in templates/ does not fire."""
        findings = _scan(
            tmp_plugin, "templates/t.py",
            'exec("print(1)")',
        )
        assert not _by_id(findings, "dynamic-code-exec")

    def test_method_named_exec_does_not_fire(self, tmp_plugin):
        """`self.exec(...)` / `obj.exec(...)` — attribute call, not the
        builtin — should NOT fire the rule."""
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            """
            class X:
                def exec(self, s): pass

            X().exec("x")
            """,
        )
        assert not _by_id(findings, "dynamic-code-exec")


class TestDynamicCodeExecDynamicArg:
    """Additive medium when args[0] is not a Constant."""

    def test_exec_constant_no_medium(self, tmp_plugin):
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            'exec("print(1)")',
        )
        assert _by_id(findings, "dynamic-code-exec")  # info capability
        assert not _by_id(findings, "dynamic-code-exec-dynamic-arg")

    def test_exec_bare_name_fires_medium(self, tmp_plugin):
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            """
            code = "print(1)"
            exec(code)
            """,
        )
        assert _by_id(findings, "dynamic-code-exec-dynamic-arg")

    def test_exec_of_compile_fires_medium(self, tmp_plugin):
        """Known evasion pattern: `exec(compile(src, '<x>', 'exec'))`.
        args[0] is a Call, not Constant → fires medium."""
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            """
            src = "print(1)"
            exec(compile(src, '<x>', 'exec'))
            """,
        )
        rule = _by_id(findings, "dynamic-code-exec-dynamic-arg")
        assert len(rule) == 1
        assert rule[0].severity == "medium"

    def test_exec_of_b64decode_fires_medium(self, tmp_plugin):
        """Another classic evasion: `exec(base64.b64decode(...))`."""
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            """
            import base64
            payload = b"..."
            exec(base64.b64decode(payload))
            """,
        )
        assert _by_id(findings, "dynamic-code-exec-dynamic-arg")

    def test_eval_dynamic_fires_medium(self, tmp_plugin):
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            """
            x = "1+1"
            eval(x)
            """,
        )
        assert _by_id(findings, "dynamic-code-exec-dynamic-arg")

    def test_capability_always_fires_with_dynamic(self, tmp_plugin):
        """Stacking invariant: dynamic-arg finding never silences the
        capability-level info finding."""
        findings = _scan(
            tmp_plugin, "hooks/h.py",
            """
            code = "x"
            exec(code)
            """,
        )
        assert _by_id(findings, "dynamic-code-exec")           # info
        assert _by_id(findings, "dynamic-code-exec-dynamic-arg")  # medium
