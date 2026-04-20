"""Tests for `_build_parsed_file` — the scanner-level helper that owns
AST parse + alias-table construction.

Rationale: `run_ast_rules` previously did two things (parse the file AND
run applicable rules). Architecture review flagged this as an SRP
violation. These tests pin the behavior of the extracted helper so
`run_ast_rules` can shrink to a pure rule-dispatcher.

The helper returns a tuple `(ParsedFile | None, error_str | None)` so
the caller (scanner) can split hook vs non-hook parse-failure handling
without the helper owning that policy.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from griffith.analyzer.ast_rules import (
    ParsedFile,
    build_alias_table,
)
from griffith.analyzer.inventory import ComponentFile, PluginInventory
from griffith.analyzer.security import SecurityScanner


@pytest.fixture
def tmp_plugin(tmp_path: Path) -> Path:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "helper-test"})
    )
    (tmp_path / "hooks").mkdir()
    (tmp_path / "templates").mkdir()
    return tmp_path


def _run_helper(plugin_root: Path, rel_path: str):
    """Thin wrapper — calls the helper on a ComponentFile for rel_path."""
    cf = ComponentFile(path=rel_path)
    scanner = SecurityScanner()
    return scanner._build_parsed_file(plugin_root, cf)


class TestBuildParsedFileHappyPath:
    def test_returns_parsed_file_on_valid_python(self, tmp_plugin: Path):
        (tmp_plugin / "hooks" / "h.py").write_text(
            "import subprocess\nsubprocess.run(['ls'], timeout=5)\n"
        )
        parsed, err = _run_helper(tmp_plugin, "hooks/h.py")
        assert err is None
        assert parsed is not None
        assert isinstance(parsed, ParsedFile)
        assert parsed.path == "hooks/h.py"
        assert isinstance(parsed.tree, ast.Module)
        assert parsed.alias_table == {"subprocess": "subprocess"}

    def test_alias_table_matches_direct_build(self, tmp_plugin: Path):
        """Helper's alias_table must match build_alias_table(tree) exactly."""
        source = "import subprocess as sp\nfrom pathlib import Path\n"
        (tmp_plugin / "hooks" / "h.py").write_text(source)
        parsed, err = _run_helper(tmp_plugin, "hooks/h.py")
        assert err is None
        expected = build_alias_table(ast.parse(source))
        assert parsed.alias_table == expected


class TestBuildParsedFileErrorPaths:
    def test_syntax_error_returns_error_message(self, tmp_plugin: Path):
        (tmp_plugin / "hooks" / "bad.py").write_text("def foo(: invalid")
        parsed, err = _run_helper(tmp_plugin, "hooks/bad.py")
        assert parsed is None
        assert err is not None
        assert "hooks/bad.py" in err
        assert "SyntaxError" in err or "Parse error" in err

    def test_os_error_returns_error_message(self, tmp_plugin: Path):
        """File missing on disk — helper reports OSError cleanly, not crash."""
        # Don't create the file; ComponentFile claims it exists.
        parsed, err = _run_helper(tmp_plugin, "hooks/does_not_exist.py")
        assert parsed is None
        assert err is not None
        assert "hooks/does_not_exist.py" in err

    def test_non_python_file_returns_none_none(self, tmp_plugin: Path):
        """.sh files are not parseable; helper short-circuits without error."""
        (tmp_plugin / "hooks" / "run.sh").write_text("#!/bin/sh\necho hi\n")
        parsed, err = _run_helper(tmp_plugin, "hooks/run.sh")
        assert parsed is None
        assert err is None

    def test_alias_table_recursion_error_returns_error_message(
        self, tmp_plugin: Path
    ):
        """Two-stage exception contract: parse can succeed but a
        deeply-nested tree can make `build_alias_table` (via ast.walk)
        hit RecursionError. Helper must catch this separately from
        parse errors and surface it via the error_str return — NOT
        propagate the exception.
        """
        (tmp_plugin / "hooks" / "h.py").write_text("import subprocess\n")

        with patch(
            "griffith.analyzer.ast_rules.build_alias_table",
            side_effect=RecursionError("mocked walk error"),
        ):
            parsed, err = _run_helper(tmp_plugin, "hooks/h.py")

        assert parsed is None
        assert err is not None
        assert "hooks/h.py" in err
        # Message should indicate walk/alias-table stage, not parse stage.
        assert "walk" in err.lower() or "alias" in err.lower() or "recursion" in err.lower()


class TestBuildParsedFileRecursionGuard:
    def test_recursion_limit_set_during_parse(self, tmp_plugin: Path):
        """The helper temporarily lowers sys.setrecursionlimit during parse
        (matching the predecessor's _PARSE_RECURSION_LIMIT discipline) and
        restores it afterward, even on error."""
        import sys
        from griffith.analyzer.ast_rules import _PARSE_RECURSION_LIMIT

        (tmp_plugin / "hooks" / "h.py").write_text("x = 1\n")
        original_limit = sys.getrecursionlimit()

        # Track what limit was active during ast.parse.
        seen_limits = []

        real_parse = ast.parse

        def spy_parse(*args, **kwargs):
            seen_limits.append(sys.getrecursionlimit())
            return real_parse(*args, **kwargs)

        with patch("griffith.analyzer.ast_rules.ast.parse", side_effect=spy_parse):
            _run_helper(tmp_plugin, "hooks/h.py")

        assert seen_limits == [_PARSE_RECURSION_LIMIT]
        # Limit restored after the helper returned.
        assert sys.getrecursionlimit() == original_limit


class TestAstParseCalledOncePerFile:
    """Regression guard: the scanner must call ast.parse AT MOST ONCE
    per distinct .py file per scan(), regardless of how many AST rules
    apply to that file. This was already true in the predecessor's
    run_ast_rules; the extraction preserves it."""

    def test_parse_count_equals_py_file_count(self, tmp_plugin: Path):
        """Two hook .py files + one template .py file = 3 parses, no more.
        Even though 6 AST rules are registered (5 hook-scoped + dynamic-
        code-exec covers all .py), parse happens once per file."""
        (tmp_plugin / "hooks" / "a.py").write_text("import subprocess\n")
        (tmp_plugin / "hooks" / "b.py").write_text("import subprocess\n")
        (tmp_plugin / "templates" / "c.py").write_text("x = 1\n")
        inv = PluginInventory.from_path(tmp_plugin)

        real_parse = ast.parse
        parse_paths = []

        def spy_parse(source, filename="<unknown>", *args, **kwargs):
            parse_paths.append(filename)
            return real_parse(source, filename, *args, **kwargs)

        with patch("griffith.analyzer.ast_rules.ast.parse", side_effect=spy_parse):
            SecurityScanner().scan(inv)

        # Each .py file parsed exactly once.
        parse_counts = {p: parse_paths.count(p) for p in set(parse_paths)}
        for path, count in parse_counts.items():
            assert count == 1, f"File {path} parsed {count} times"
        # All three .py files got parsed.
        assert len(parse_paths) == 3
