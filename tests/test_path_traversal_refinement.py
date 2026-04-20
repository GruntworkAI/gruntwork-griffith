"""Unit 3 tests — path-traversal-dynamic-{python,js,shell}.

Three rules sharing a conceptual purpose, one per engine:

- path-traversal-dynamic-python (AST, **/*.py) — f-string with `../`
  + FormattedValue, OR BinOp `+` where one operand contains `../`
  and the other is non-Constant
- path-traversal-dynamic-js (shell-regex, **/*.{js,ts}) — `../` near
  `${...}` (template literal) or `$var` or string concat with identifier
- path-traversal-dynamic-shell (shell-regex, **/*.sh) — `../` adjacent
  to `$var` / `${...}` / `$(...)`

The info-level `path-traversal` capability signal continues to fire
on all files with `../..` substring.
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


def _by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# ============================================================================
# Python
# ============================================================================


class TestPythonDynamic:
    def _scan_py(self, tmp_plugin: Path, source: str):
        (tmp_plugin / "hooks" / "h.py").write_text(textwrap.dedent(source))
        inv = PluginInventory.from_path(tmp_plugin)
        return SecurityScanner().scan(inv)

    def test_fstring_with_traversal(self, tmp_plugin):
        findings = self._scan_py(
            tmp_plugin,
            """
            user = "x"
            open(f"../../{user}")
            """,
        )
        rule = _by_id(findings, "path-traversal-dynamic-python")
        assert rule
        assert rule[0].severity == "high"

    def test_concat_traversal(self, tmp_plugin):
        findings = self._scan_py(
            tmp_plugin,
            """
            path = "foo"
            open("../../" + path)
            """,
        )
        assert _by_id(findings, "path-traversal-dynamic-python")

    def test_pure_constant_no_dynamic_finding(self, tmp_plugin):
        findings = self._scan_py(
            tmp_plugin,
            """
            open("../../etc/passwd")
            """,
        )
        # Info capability still fires (regex catches `../..`), but no
        # high-severity dynamic finding.
        assert not _by_id(findings, "path-traversal-dynamic-python")
        assert _by_id(findings, "path-traversal")  # info capability

    def test_os_path_join_all_constants(self, tmp_plugin):
        """`os.path.join("..", "..", "x")` — the source has ".." and
        ".." as separate Constants; no `../` substring in the source
        text, so even the info regex doesn't fire."""
        findings = self._scan_py(
            tmp_plugin,
            """
            import os
            os.path.join("..", "..", "x")
            """,
        )
        assert not _by_id(findings, "path-traversal-dynamic-python")
        # The info regex matches `../..` literally; source here contains
        # `".." + "," + " ..."` which has no `../..` substring.
        assert not _by_id(findings, "path-traversal")


# ============================================================================
# JavaScript / TypeScript
# ============================================================================


class TestJavaScriptDynamic:
    def _scan_js(self, tmp_plugin: Path, content: str, filename: str = "h.js"):
        (tmp_plugin / "templates" / filename).write_text(content + "\n")
        inv = PluginInventory.from_path(tmp_plugin)
        return SecurityScanner().scan(inv)

    def test_template_literal_with_interpolation(self, tmp_plugin):
        findings = self._scan_js(
            tmp_plugin, 'const p = `../../${user}`;',
        )
        rule = _by_id(findings, "path-traversal-dynamic-js")
        assert rule and rule[0].severity == "high"

    def test_template_literal_without_interpolation(self, tmp_plugin):
        """`\\`../../static\\`` has no ${...} — info only, no high."""
        findings = self._scan_js(
            tmp_plugin, 'const p = `../../literal`;',
        )
        assert not _by_id(findings, "path-traversal-dynamic-js")

    def test_string_concat_with_identifier(self, tmp_plugin):
        findings = self._scan_js(
            tmp_plugin, 'const p = "../../" + userPath;',
        )
        assert _by_id(findings, "path-traversal-dynamic-js")

    def test_path_join_dirname_static_no_dynamic(self, tmp_plugin):
        """superpowers regression: Node test setup uses
        `path.join(__dirname, '../../static')` — static string, no
        high-severity finding expected."""
        findings = self._scan_js(
            tmp_plugin,
            "const p = path.join(__dirname, '../../skills/foo');",
        )
        assert not _by_id(findings, "path-traversal-dynamic-js")

    def test_path_join_dirname_template_dynamic(self, tmp_plugin):
        findings = self._scan_js(
            tmp_plugin,
            "const p = path.join(__dirname, `../../${dyn}`);",
        )
        assert _by_id(findings, "path-traversal-dynamic-js")

    def test_ts_file_covered(self, tmp_plugin):
        findings = self._scan_js(
            tmp_plugin, 'const p: string = `../../${user}`;',
            filename="h.ts",
        )
        assert _by_id(findings, "path-traversal-dynamic-js")


# ============================================================================
# Shell
# ============================================================================


class TestShellDynamic:
    def _scan_sh(self, tmp_plugin: Path, content: str):
        (tmp_plugin / "hooks" / "h.sh").write_text(content + "\n")
        inv = PluginInventory.from_path(tmp_plugin)
        return SecurityScanner().scan(inv)

    def test_dollar_var_adjacent_to_traversal(self, tmp_plugin):
        findings = self._scan_sh(tmp_plugin, "cat ../../$FILE")
        rule = _by_id(findings, "path-traversal-dynamic-shell")
        assert rule and rule[0].severity == "high"

    def test_brace_var_adjacent(self, tmp_plugin):
        findings = self._scan_sh(tmp_plugin, "cat ../../${FILE}")
        assert _by_id(findings, "path-traversal-dynamic-shell")

    def test_command_substitution_adjacent(self, tmp_plugin):
        findings = self._scan_sh(tmp_plugin, "cat ../../$(cmd)")
        assert _by_id(findings, "path-traversal-dynamic-shell")

    def test_static_traversal_no_dynamic(self, tmp_plugin):
        findings = self._scan_sh(tmp_plugin, "cat ../../static/file")
        assert not _by_id(findings, "path-traversal-dynamic-shell")


# ============================================================================
# Capability (info-level) preservation — always fires
# ============================================================================


class TestCapabilityAlwaysFires:
    """The info-level `path-traversal` rule should fire regardless of
    whether the stricter dynamic rule also fires. Additive invariant."""

    def test_python_dynamic_and_capability(self, tmp_plugin):
        (tmp_plugin / "hooks" / "h.py").write_text(
            textwrap.dedent(
                """
                user = "x"
                open(f"../../{user}")
                """
            )
        )
        inv = PluginInventory.from_path(tmp_plugin)
        findings = SecurityScanner().scan(inv)
        # path-traversal (info regex) fires on `../../` substring in source
        # PLUS path-traversal-dynamic-python fires on f-string structure.
        assert _by_id(findings, "path-traversal-dynamic-python")
        assert _by_id(findings, "path-traversal")

    def test_js_dynamic_and_capability(self, tmp_plugin):
        (tmp_plugin / "templates" / "h.js").write_text(
            "const p = `../../${user}`;\n"
        )
        inv = PluginInventory.from_path(tmp_plugin)
        findings = SecurityScanner().scan(inv)
        assert _by_id(findings, "path-traversal-dynamic-js")
        assert _by_id(findings, "path-traversal")

    def test_shell_dynamic_and_capability(self, tmp_plugin):
        (tmp_plugin / "hooks" / "h.sh").write_text("cat ../../$FILE\n")
        inv = PluginInventory.from_path(tmp_plugin)
        findings = SecurityScanner().scan(inv)
        assert _by_id(findings, "path-traversal-dynamic-shell")
        assert _by_id(findings, "path-traversal")
