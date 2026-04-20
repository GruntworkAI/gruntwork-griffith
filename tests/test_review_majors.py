"""Tests for post-merge code-review majors on the AST refinement PR.

Covers:
- **M4**: `GRIFFITH_REGENERATE_SNAPSHOTS=1` mode must announce on stderr
  that a snapshot was rewritten. Previously the helper printed to
  stdout, which mixes with pytest's normal output and gets lost in
  `-q` mode. A stderr warning is visible regardless.
- **M5**: `meta.ast_parse_failures` list length is capped. An
  adversarial plugin with thousands of broken .py files could bloat
  the report indefinitely. Cap at a sentinel size; once exceeded,
  append a `"... <N> more omitted"` marker and stop growing.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from griffith.analyzer.inventory import PluginInventory
from griffith.analyzer.security import SecurityScanner


# ============================================================================
# M4: snapshot regenerate announces on stderr
# ============================================================================


class TestRegenerateAnnouncesOnStderr:
    def test_regenerate_prints_to_stderr(
        self, tmp_path: Path, monkeypatch
    ):
        """When GRIFFITH_REGENERATE_SNAPSHOTS=1, the helper writes the
        snapshot file AND announces via stderr so the action is visible
        under `pytest -q`."""
        from tests.helpers import snapshots as snapshot_helpers

        monkeypatch.setattr(
            snapshot_helpers, "SNAPSHOT_DIR", tmp_path / "snapshots"
        )
        monkeypatch.setenv("GRIFFITH_REGENERATE_SNAPSHOTS", "1")

        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            snapshot_helpers.assert_snapshot(
                "test_snap", [], griffith_version="0.1.0"
            )

        stderr_output = stderr_capture.getvalue()
        assert "Regenerated" in stderr_output or "regenerated" in stderr_output
        assert "test_snap" in stderr_output

    def test_regenerate_does_not_print_to_stdout(
        self, tmp_path: Path, monkeypatch
    ):
        """Stdout stays clean so programmatic consumers of test output
        (CI dashboards, structured loggers) don't see snapshot-
        regeneration chatter mixed with test results."""
        from tests.helpers import snapshots as snapshot_helpers

        monkeypatch.setattr(
            snapshot_helpers, "SNAPSHOT_DIR", tmp_path / "snapshots"
        )
        monkeypatch.setenv("GRIFFITH_REGENERATE_SNAPSHOTS", "1")

        stdout_capture = io.StringIO()
        with patch("sys.stdout", stdout_capture):
            snapshot_helpers.assert_snapshot(
                "test_snap", [], griffith_version="0.1.0"
            )

        assert "Regenerated" not in stdout_capture.getvalue()


# ============================================================================
# M5: meta.ast_parse_failures capped
# ============================================================================


@pytest.fixture
def tmp_plugin_with_many_broken_pys(tmp_path: Path) -> Path:
    """Create a plugin with many broken non-hook .py files."""
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "many-broken"})
    )
    (tmp_path / "hooks").mkdir()
    (tmp_path / "templates").mkdir()
    # Create 300 broken .py files — well over any reasonable cap.
    for i in range(300):
        (tmp_path / "templates" / f"bad_{i:03d}.py").write_text(
            f"def broken_{i}(: syntax error"
        )
    return tmp_path


class TestAstParseFailuresCapped:
    def test_cap_constant_exists(self):
        """A named constant declares the cap; magic numbers discouraged."""
        from griffith.analyzer.security import _AST_PARSE_FAILURES_CAP
        assert isinstance(_AST_PARSE_FAILURES_CAP, int)
        assert _AST_PARSE_FAILURES_CAP > 0

    def test_failures_list_capped(self, tmp_plugin_with_many_broken_pys: Path):
        """Scanner stops growing ast_parse_failures once the cap is hit."""
        from griffith.analyzer.security import _AST_PARSE_FAILURES_CAP
        inv = PluginInventory.from_path(tmp_plugin_with_many_broken_pys)
        scanner = SecurityScanner()
        scanner.scan(inv)
        # List is at most cap + 1 entries (the +1 is the overflow marker).
        assert len(scanner.ast_parse_failures) <= _AST_PARSE_FAILURES_CAP + 1

    def test_overflow_marker_present_when_capped(
        self, tmp_plugin_with_many_broken_pys: Path
    ):
        """When the cap is exceeded, the list ends with a `... <N> more
        omitted` entry so the consumer knows the list is truncated."""
        from griffith.analyzer.security import _AST_PARSE_FAILURES_CAP
        inv = PluginInventory.from_path(tmp_plugin_with_many_broken_pys)
        scanner = SecurityScanner()
        scanner.scan(inv)
        if len(scanner.ast_parse_failures) > _AST_PARSE_FAILURES_CAP:
            last = scanner.ast_parse_failures[-1]
            assert "omitted" in last or "more" in last
            # Marker must not look like a file path (don't mislead
            # consumers into treating it as a scanned file).
            assert not last.endswith(".py")

    def test_no_marker_when_under_cap(self, tmp_path: Path):
        """Under the cap, the list is just paths — no marker sentinel."""
        (tmp_path / ".claude-plugin").mkdir()
        (tmp_path / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": "few-broken"})
        )
        (tmp_path / "hooks").mkdir()
        (tmp_path / "templates").mkdir()
        # Only 2 broken files — well under any sensible cap.
        (tmp_path / "templates" / "a.py").write_text("def a(: bad")
        (tmp_path / "templates" / "b.py").write_text("def b(: bad")
        inv = PluginInventory.from_path(tmp_path)
        scanner = SecurityScanner()
        scanner.scan(inv)
        assert len(scanner.ast_parse_failures) == 2
        assert all(p.endswith(".py") for p in scanner.ast_parse_failures)
