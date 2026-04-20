"""Contract tests for docs/json-schema.md.

These tests guard contract invariants that downstream consumers rely on.
Breaking them typically indicates a documentation change that needs to
be paired with a schema_version bump OR a consumer migration note.
"""

from __future__ import annotations

from pathlib import Path


_DOC_PATH = Path(__file__).parent.parent / "docs" / "json-schema.md"


class TestSeverityStabilityCarveout:
    """R11 from the AST-rule-refinement plan: docs/json-schema.md must
    explicitly permit severity shifts on existing rule_ids within v0.1.

    The literal anchor phrase is load-bearing — if someone rewords the
    bullet (even innocently), consumers who read the doc for the exact
    carve-out will silently miss it. The grep asserts the anchor phrase
    verbatim.
    """

    ANCHOR_PHRASE = "may change within the enum set without bumping schema_version"

    def test_stability_guarantees_contain_severity_shift_bullet(self):
        # Strip markdown backticks so the anchor phrase matches regardless
        # of the exact styling (`schema_version` vs schema_version). The
        # *semantic* phrase is what matters — rewording the semantics
        # fails the test.
        text = _DOC_PATH.read_text(encoding="utf-8").replace("`", "")
        assert self.ANCHOR_PHRASE in text, (
            f"docs/json-schema.md is missing the required R11 carve-out bullet.\n"
            f"Expected the literal phrase:\n  {self.ANCHOR_PHRASE!r}\n"
            f"See .claude/work/plans/2026-04-20-001-feat-ast-security-rule-"
            f"refinement-plan.md (R11)."
        )

    def test_one_time_carveout_framing_present(self):
        """The carve-out is explicitly a one-time v0.1 concession — future
        loosenings of the stability contract MUST bump schema_version.
        Framing the carve-out as one-time prevents precedent drift."""
        text = _DOC_PATH.read_text(encoding="utf-8")
        assert "one-time v0.1 concession" in text, (
            "R11's one-time-carve-out framing missing from json-schema.md "
            "stability guarantees."
        )


class TestAstParseFailuresDocumented:
    """R7: meta.ast_parse_failures must be documented so consumers know
    to read both security.findings[] AND this meta field when interpreting
    AST-analysis coverage."""

    def test_meta_field_documented(self):
        text = _DOC_PATH.read_text(encoding="utf-8")
        assert "meta.ast_parse_failures" in text, (
            "meta.ast_parse_failures must be documented in docs/json-schema.md."
        )
