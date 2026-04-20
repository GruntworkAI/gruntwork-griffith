"""Unit 0b tests — AST rule infrastructure + first real rule (subprocess-shell-true).

Covers:
- Alias table construction (plain, aliased, from, from-aliased, dotted,
  dotted-aliased)
- Resolver (bare name, attribute chain, dotted imports, unresolvable)
- is_provably_static (Constant, List/Tuple, Starred variants)
- AST pass orchestration + parse-failure handling (hook → finding,
  non-hook → meta field)
- subprocess-shell-true dispatch as the integration proof-of-life
"""

from __future__ import annotations

import ast
import json
import textwrap
from pathlib import Path

import pytest

from griffith.analyzer.ast_rules import (
    AST_RULES,
    ASTRuleSpec,
    build_alias_table,
    is_provably_static,
    resolve_call_target,
)
from griffith.analyzer.inventory import PluginInventory
from griffith.analyzer.security import SecurityScanner


@pytest.fixture
def test_rule_for_templates():
    """Register a no-op AST rule with `**/*.py` filter for the duration of
    a test. Used to exercise non-hook .py file parsing paths since 0b's
    real rules are all hook-scoped (Unit 3 adds a wider-filter rule)."""
    def _noop_check(ctx):
        return []
    spec = ASTRuleSpec(
        rule_id="test-any-py-rule",
        severity="info",
        file_filter="**/*.py",
        check=_noop_check,
    )
    AST_RULES.append(spec)
    yield
    AST_RULES.remove(spec)


# ============================================================================
# Alias table
# ============================================================================


class TestAliasTable:
    def _parse(self, src: str) -> ast.Module:
        return ast.parse(textwrap.dedent(src))

    def test_plain_import(self):
        tree = self._parse("import subprocess")
        assert build_alias_table(tree) == {"subprocess": "subprocess"}

    def test_aliased_import(self):
        tree = self._parse("import subprocess as sp")
        assert build_alias_table(tree) == {"sp": "subprocess"}

    def test_dotted_import_no_as(self):
        """Python binds only the root of `import a.b.c`. Table stores
        the short root; resolver walks the attribute chain to rebuild."""
        tree = self._parse("import a.b.c")
        assert build_alias_table(tree) == {"a": "a"}

    def test_dotted_import_with_as(self):
        tree = self._parse("import a.b.c as q")
        assert build_alias_table(tree) == {"q": "a.b.c"}

    def test_from_import(self):
        tree = self._parse("from subprocess import run")
        assert build_alias_table(tree) == {"run": "subprocess.run"}

    def test_from_import_aliased(self):
        tree = self._parse("from subprocess import run as r")
        assert build_alias_table(tree) == {"r": "subprocess.run"}

    def test_from_dotted_module(self):
        tree = self._parse("from a.b import c")
        assert build_alias_table(tree) == {"c": "a.b.c"}

    def test_multiple_imports(self):
        tree = self._parse(
            """
            import subprocess
            import os
            from subprocess import run as r
            """
        )
        table = build_alias_table(tree)
        assert table == {
            "subprocess": "subprocess",
            "os": "os",
            "r": "subprocess.run",
        }


class TestResolveCallTarget:
    def _call(self, src: str) -> tuple[ast.Call, dict]:
        tree = ast.parse(textwrap.dedent(src))
        table = build_alias_table(tree)
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        return call, table

    def test_plain_attribute_call(self):
        call, table = self._call("import subprocess; subprocess.run([])")
        assert resolve_call_target(call, table) == "subprocess.run"

    def test_aliased_module(self):
        call, table = self._call("import subprocess as sp; sp.run([])")
        assert resolve_call_target(call, table) == "subprocess.run"

    def test_from_import_bare_name(self):
        call, table = self._call("from subprocess import run; run([])")
        assert resolve_call_target(call, table) == "subprocess.run"

    def test_from_import_aliased_bare_name(self):
        call, table = self._call("from subprocess import run as r; r([])")
        assert resolve_call_target(call, table) == "subprocess.run"

    def test_dotted_attribute_chain(self):
        call, table = self._call("import a.b.c; a.b.c.func()")
        assert resolve_call_target(call, table) == "a.b.c.func"

    def test_unresolvable_call_of_call(self):
        call, table = self._call("import functools; functools.partial(f)()")
        assert resolve_call_target(call, table) is None

    def test_builtin_bare_name(self):
        """`exec("...")` — no import; resolver returns the bare name
        unchanged (builtins aren't in the alias table)."""
        call, table = self._call('exec("x")')
        assert resolve_call_target(call, table) == "exec"


# ============================================================================
# is_provably_static
# ============================================================================


class TestIsProvablyStatic:
    def _first_arg(self, src: str) -> ast.expr:
        tree = ast.parse(textwrap.dedent(src))
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        return call.args[0]

    def test_string_constant(self):
        assert is_provably_static(self._first_arg('f("hello")'))

    def test_int_constant(self):
        assert is_provably_static(self._first_arg("f(42)"))

    def test_none_constant(self):
        assert is_provably_static(self._first_arg("f(None)"))

    def test_list_of_constants(self):
        assert is_provably_static(self._first_arg('f(["a", "b"])'))

    def test_tuple_of_constants(self):
        assert is_provably_static(self._first_arg('f(("a", "b"))'))

    def test_empty_list(self):
        assert is_provably_static(self._first_arg("f([])"))

    def test_starred_of_constant_list(self):
        """`[*("a","b")]` unpacks a constant tuple inside a list literal."""
        assert is_provably_static(self._first_arg('f([*("a", "b")])'))

    def test_starred_of_name_not_static(self):
        assert not is_provably_static(self._first_arg("f([*args])"))

    def test_bare_name_not_static(self):
        assert not is_provably_static(self._first_arg("f(x)"))

    def test_subscript_not_static(self):
        assert not is_provably_static(self._first_arg("f(x[0])"))

    def test_attribute_not_static(self):
        assert not is_provably_static(self._first_arg("f(obj.attr)"))

    def test_call_not_static(self):
        assert not is_provably_static(self._first_arg("f(g())"))

    def test_fstring_not_static(self):
        assert not is_provably_static(self._first_arg('f(f"hello {x}")'))

    def test_binop_not_static(self):
        assert not is_provably_static(self._first_arg('f("a" + x)'))

    def test_list_with_nonconstant_not_static(self):
        assert not is_provably_static(self._first_arg('f(["a", x])'))


# ============================================================================
# AST pass orchestration — parse failures, hook vs non-hook
# ============================================================================


@pytest.fixture
def tmp_plugin(tmp_path: Path) -> Path:
    """Build a minimal plugin scaffold under tmp_path with basic structure.

    Inventory picks up .py files from hooks/, mcp-servers/, templates/
    (any file); NOT from agents/ (markdown only). Tests use templates/
    as the canonical "non-hook Python" location.
    """
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "test-plugin"})
    )
    (tmp_path / "hooks").mkdir()
    (tmp_path / "templates").mkdir()
    (tmp_path / "agents").mkdir()
    return tmp_path


class TestParseFailureHandling:
    def test_hook_parse_failure_emits_high_finding(self, tmp_plugin: Path):
        """Malformed Python in hooks/ → ast-parse-failed at HIGH severity.
        Structural analysis disabled on executable code is a security signal."""
        (tmp_plugin / "hooks" / "bad.py").write_text("def foo(: invalid syntax")
        inv = PluginInventory.from_path(tmp_plugin)
        findings = SecurityScanner().scan(inv)
        parse_failed = [f for f in findings if f.rule_id == "ast-parse-failed"]
        assert len(parse_failed) == 1
        assert parse_failed[0].severity == "high"
        assert parse_failed[0].file.startswith("hooks/")

    def test_non_hook_parse_failure_records_meta_only(
        self, tmp_plugin: Path, test_rule_for_templates
    ):
        """Malformed Python in templates/ → meta.ast_parse_failures entry,
        NOT a finding. Non-hook Python is less sensitive."""
        (tmp_plugin / "templates" / "bad.py").write_text("def foo(: invalid")
        inv = PluginInventory.from_path(tmp_plugin)
        scanner = SecurityScanner()
        findings = scanner.scan(inv)
        # No ast-parse-failed finding.
        assert not any(f.rule_id == "ast-parse-failed" for f in findings)
        # But the path shows up in the meta list.
        assert any("templates/bad.py" in p for p in scanner.ast_parse_failures)

    def test_both_paths_disjoint(
        self, tmp_plugin: Path, test_rule_for_templates
    ):
        """Hook malformed AND template malformed → 1 finding + 1 meta entry;
        the hook is NOT in meta, the template is NOT in findings."""
        (tmp_plugin / "hooks" / "bad.py").write_text("def h(: bad")
        (tmp_plugin / "templates" / "bad.py").write_text("def a(: bad")
        inv = PluginInventory.from_path(tmp_plugin)
        scanner = SecurityScanner()
        findings = scanner.scan(inv)
        parse_failed = [f for f in findings if f.rule_id == "ast-parse-failed"]
        assert len(parse_failed) == 1
        assert parse_failed[0].file.startswith("hooks/")
        # Meta contains only the template path.
        assert all(not p.startswith("hooks/") for p in scanner.ast_parse_failures)
        assert any("templates/bad.py" in p for p in scanner.ast_parse_failures)

    def test_valid_python_no_parse_failure(self, tmp_plugin: Path):
        """Control: well-formed Python → no ast-parse-failed finding,
        no meta entry."""
        (tmp_plugin / "hooks" / "good.py").write_text("print('hi')\n")
        inv = PluginInventory.from_path(tmp_plugin)
        scanner = SecurityScanner()
        findings = scanner.scan(inv)
        assert not any(f.rule_id == "ast-parse-failed" for f in findings)
        assert scanner.ast_parse_failures == []

    def test_non_python_file_no_parse_attempt(self, tmp_plugin: Path):
        """A .sh file in hooks/ is not AST-parsed; no failure should fire."""
        (tmp_plugin / "hooks" / "run.sh").write_text(
            "#!/bin/sh\nbash -c 'echo hi'\n"
        )
        inv = PluginInventory.from_path(tmp_plugin)
        scanner = SecurityScanner()
        findings = scanner.scan(inv)
        assert not any(f.rule_id == "ast-parse-failed" for f in findings)
        assert scanner.ast_parse_failures == []


# ============================================================================
# subprocess-shell-true — first real AST rule, proves dispatch
# ============================================================================


class TestSubprocessShellTrue:
    def _inv_with_hook(self, tmp_plugin: Path, source: str) -> PluginInventory:
        (tmp_plugin / "hooks" / "h.py").write_text(textwrap.dedent(source))
        return PluginInventory.from_path(tmp_plugin)

    def test_plain_shell_true_fires_critical(self, tmp_plugin: Path):
        inv = self._inv_with_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run(["git"], shell=True)
            """,
        )
        findings = SecurityScanner().scan(inv)
        critical_shell = [f for f in findings if f.rule_id == "subprocess-shell-true"]
        assert len(critical_shell) == 1
        assert critical_shell[0].severity == "critical"
        # Capability signal info-level still fires.
        info_cap = [f for f in findings if f.rule_id == "subprocess-in-hooks"]
        assert len(info_cap) >= 1
        assert info_cap[0].severity == "info"

    def test_aliased_import_shell_true(self, tmp_plugin: Path):
        """`import subprocess as sp; sp.run([], shell=True)` — alias table
        resolves sp.run to subprocess.run."""
        inv = self._inv_with_hook(
            tmp_plugin,
            """
            import subprocess as sp
            sp.run([], shell=True)
            """,
        )
        findings = SecurityScanner().scan(inv)
        assert any(f.rule_id == "subprocess-shell-true" for f in findings)

    def test_from_import_shell_true(self, tmp_plugin: Path):
        """`from subprocess import run; run([], shell=True)` — alias table
        resolves bare `run` to subprocess.run."""
        inv = self._inv_with_hook(
            tmp_plugin,
            """
            from subprocess import run
            run([], shell=True)
            """,
        )
        findings = SecurityScanner().scan(inv)
        assert any(f.rule_id == "subprocess-shell-true" for f in findings)

    def test_popen_shell_true(self, tmp_plugin: Path):
        """Popen with shell=True also fires critical."""
        inv = self._inv_with_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.Popen(["x"], shell=True)
            """,
        )
        findings = SecurityScanner().scan(inv)
        assert any(f.rule_id == "subprocess-shell-true" for f in findings)

    def test_shell_false_does_not_fire(self, tmp_plugin: Path):
        inv = self._inv_with_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run(["git"], shell=False)
            """,
        )
        findings = SecurityScanner().scan(inv)
        assert not any(f.rule_id == "subprocess-shell-true" for f in findings)

    def test_no_shell_kwarg_does_not_fire(self, tmp_plugin: Path):
        inv = self._inv_with_hook(
            tmp_plugin,
            """
            import subprocess
            subprocess.run(["git"])
            """,
        )
        findings = SecurityScanner().scan(inv)
        assert not any(f.rule_id == "subprocess-shell-true" for f in findings)

    def test_shell_true_on_non_subprocess_does_not_fire(self, tmp_plugin: Path):
        """A non-subprocess call with shell=True (e.g., a wrapper) shouldn't
        fire the subprocess rule."""
        inv = self._inv_with_hook(
            tmp_plugin,
            """
            import other
            other.run([], shell=True)
            """,
        )
        findings = SecurityScanner().scan(inv)
        assert not any(f.rule_id == "subprocess-shell-true" for f in findings)

    def test_rule_only_applies_to_hooks(self, tmp_plugin: Path):
        """subprocess-shell-true is scoped to hooks/**/*.py; a subprocess
        call in templates/foo.py should NOT fire the rule."""
        (tmp_plugin / "templates" / "t.py").write_text(
            textwrap.dedent(
                """
                import subprocess
                subprocess.run(["git"], shell=True)
                """
            )
        )
        inv = PluginInventory.from_path(tmp_plugin)
        findings = SecurityScanner().scan(inv)
        shell_true_in_template = [
            f for f in findings
            if f.rule_id == "subprocess-shell-true"
            and f.file.startswith("templates/")
        ]
        assert shell_true_in_template == []


# ============================================================================
# Regression: existing test_security tests still pass
# ============================================================================


class TestExistingBehaviorUnchanged:
    """Smoke: scanning the traps fixture with Unit 0b infrastructure in
    place doesn't break the existing assertions. (Full suite covers this
    too; this is a sanity check.)"""

    def test_scan_returns_findings_list(self, security_traps_plugin):
        inv = PluginInventory.from_path(security_traps_plugin)
        findings = SecurityScanner().scan(inv)
        assert isinstance(findings, list)
        assert len(findings) > 0
