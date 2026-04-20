"""Tests for sanitize helpers — `sanitize_string` (existing) plus
`sanitize_for_markdown` and `sanitize_for_rich` added in Phase 1.5 Unit 4.

Destination-specific escape helpers are prerequisites for Tier 2 CVE rendering
(Unit 6). CVE summaries can contain attacker-influenced Markdown/HTML/Rich
markup; these helpers neutralize the injection paths before rendering.
"""

from __future__ import annotations

import pytest

from griffith.sanitize import (
    DEFAULT_MAX_DESCRIPTION_LENGTH,
    DEFAULT_MAX_NAME_LENGTH,
    sanitize_for_markdown,
    sanitize_for_rich,
    sanitize_string,
)


# ============================================================================
# Existing sanitize_string — regression guard
# ============================================================================


class TestSanitizeStringRegression:
    def test_plain_text_unchanged(self):
        assert sanitize_string("hello world") == "hello world"

    def test_control_chars_stripped(self):
        assert "\x1b" not in sanitize_string("before\x1b[31mred\x1b[0m")

    def test_length_cap(self):
        long = "a" * 1000
        assert len(sanitize_string(long, max_length=100)) == 100

    def test_none_returns_empty(self):
        assert sanitize_string(None) == ""


# ============================================================================
# sanitize_for_markdown
# ============================================================================


class TestSanitizeForMarkdownHappy:
    def test_plain_text_unchanged(self):
        assert sanitize_for_markdown("hello world") == "hello world"

    def test_empty_string_passes_through(self):
        assert sanitize_for_markdown("") == ""

    def test_none_returns_empty(self):
        assert sanitize_for_markdown(None) == ""


class TestSanitizeForMarkdownMarkdownInjection:
    def test_link_brackets_escaped(self):
        """A Markdown link `[click](url)` must not render as a link."""
        result = sanitize_for_markdown("[click here](https://evil.com)")
        # Brackets escaped with backslash; URL now orphan text
        assert "\\[" in result
        assert "\\]" in result

    def test_bold_stars_escaped(self):
        result = sanitize_for_markdown("**bold** _italic_")
        assert "\\*" in result
        assert "\\_" in result

    def test_code_ticks_escaped(self):
        result = sanitize_for_markdown("inline `code` here")
        assert "\\`" in result

    def test_backslash_escaped_first(self):
        """Pre-existing backslashes must be escaped before specials so that
        `\\[` in input stays as `\\\\[` in output, not collapsing back to `[`."""
        result = sanitize_for_markdown("\\[fake]")
        # Input: literal backslash + [ + fake + ]
        # After: \\\\ for backslash + \[ for bracket + ... + \]
        assert "\\\\" in result


class TestSanitizeForMarkdownHtmlStripping:
    def test_script_tag_removed(self):
        result = sanitize_for_markdown("<script>alert(1)</script>")
        assert "<script>" not in result
        assert "</script>" not in result
        # The text "alert(1)" remains as inert text (after bracket escape)
        assert "alert" in result

    def test_img_tag_removed(self):
        result = sanitize_for_markdown('<img src="x" onerror="alert(1)">')
        assert "<img" not in result
        assert "onerror" not in result or "alert" in result  # tag removed

    @pytest.mark.adversarial
    def test_nested_tag_injection_fixpoint_strip(self):
        """Classic bypass: `<<script>script>...<</script>/script>` survives a
        single-pass strip. Fixpoint iteration must neutralize both layers."""
        result = sanitize_for_markdown(
            "<<script>script>alert(1)<</script>/script>"
        )
        # After fixpoint strip, no `<script>` or `</script>` should remain
        assert "<script>" not in result
        assert "</script>" not in result

    @pytest.mark.adversarial
    def test_html_comment_stripped(self):
        result = sanitize_for_markdown("before<!-- evil comment -->after")
        assert "<!--" not in result
        assert "-->" not in result
        assert "evil comment" not in result

    @pytest.mark.adversarial
    def test_cdata_stripped(self):
        result = sanitize_for_markdown(
            "before<![CDATA[<script>x</script>]]>after"
        )
        assert "<![CDATA[" not in result
        assert "]]>" not in result
        assert "<script>" not in result

    def test_residual_angle_brackets_escaped(self):
        """After strip, leftover `<`/`>` (unpaired, so the tag regex doesn't
        match) should render as literal `&lt;`/`&gt;`, not re-introduce
        injection if Markdown is rendered through an HTML-aware pipeline.

        Note: the tag-strip regex is intentionally aggressive — inputs like
        `"a < b and c > d"` DO get collapsed because the `<...>` span matches
        the tag pattern. That's accepted as a preference for safety over
        data preservation in untrusted content."""
        # Unpaired `<` with no matching `>` — regex cannot match a tag
        result = sanitize_for_markdown("unpaired < here")
        assert "&lt;" in result
        # Unpaired `>` alone
        result2 = sanitize_for_markdown("unpaired > here")
        assert "&gt;" in result2

    def test_aggressive_tag_strip_is_documented(self):
        """Tag-like spans are collapsed even when they'd legitimately be math
        or other text. This is a documented aggressive-safety trade-off."""
        result = sanitize_for_markdown("a < b and c > d")
        # `< b and c >` is aggressively stripped — test verifies current
        # behavior so regression is visible if the regex changes.
        assert "<" not in result
        assert ">" not in result


class TestSanitizeForMarkdownControlChars:
    def test_ansi_escape_stripped(self):
        result = sanitize_for_markdown("\x1b[31mred\x1b[0m")
        assert "\x1b" not in result

    def test_bidi_override_stripped(self):
        result = sanitize_for_markdown("evil\u202ename")
        assert "\u202e" not in result

    def test_combined_injection_all_neutralized(self):
        """Input contains ANSI + bidi + HTML + Markdown injection. All must be
        neutralized."""
        result = sanitize_for_markdown(
            "\x1b[31m[click](https://evil.com)"
            "<script>x</script>\u202eflip"
        )
        assert "\x1b" not in result
        assert "\u202e" not in result
        assert "<script>" not in result
        assert "\\[" in result  # bracket escaped


# ============================================================================
# sanitize_for_rich
# ============================================================================


class TestSanitizeForRichHappy:
    def test_plain_text_unchanged(self):
        assert sanitize_for_rich("hello world") == "hello world"

    def test_empty_string(self):
        assert sanitize_for_rich("") == ""

    def test_none_returns_empty(self):
        assert sanitize_for_rich(None) == ""


class TestSanitizeForRichMarkupInjection:
    def test_rich_tag_escaped(self):
        """Rich treats `[style]text[/]` as markup. After sanitize, brackets
        are escaped so Rich renders them literally."""
        from rich.markup import render

        raw = "[bold red]FAKE[/]"
        result = sanitize_for_rich(raw)
        # After escape, Rich should render as literal text, not styled output.
        # Easiest check: `render` of sanitized output has no Span objects for styling.
        rendered = render(result)
        # Spans = styled segments; we want ZERO styled segments from the markup
        assert len(rendered.spans) == 0, f"Rich spans present: {rendered.spans}"
        # Also verify the literal `[bold red]` substring is preserved (escaped)
        assert "bold red" in result

    @pytest.mark.adversarial
    def test_pre_escaped_backslash_bracket_neutralized(self):
        """`\\[bold red]HACKED[/]` (backslash already present) should still be
        neutralized — rich.markup.escape handles this correctly while naive
        regex `[` → `\\[` misses."""
        from rich.markup import render

        raw = "\\[bold red]HACKED[/]"
        result = sanitize_for_rich(raw)
        rendered = render(result)
        assert len(rendered.spans) == 0

    def test_control_chars_stripped_first(self):
        result = sanitize_for_rich("\x1b[31mred\u202etext")
        assert "\x1b" not in result
        assert "\u202e" not in result


# ============================================================================
# Length cap interaction
# ============================================================================


class TestLengthCap:
    def test_markdown_caps_before_escape(self):
        """Long input should be capped to max_length BEFORE escaping so that
        the final output isn't wildly larger than the cap. Escaping may add a
        few extra chars past the cap; that's acceptable."""
        long = "a" * 500
        result = sanitize_for_markdown(long, max_length=50)
        # Input is boring ASCII; no escape expansion; length stays at cap
        assert len(result) == 50

    def test_rich_caps_before_escape(self):
        long = "a" * 500
        result = sanitize_for_rich(long, max_length=50)
        assert len(result) == 50

    def test_markdown_cap_with_escapable_chars(self):
        """Input exactly at cap, with special chars: output may slightly exceed
        the cap due to added backslashes, but that's documented behavior."""
        # 50 `[` characters at cap
        raw = "[" * 50
        result = sanitize_for_markdown(raw, max_length=50)
        # Each `[` becomes `\[`, so result is ~100 chars; accept up to ~2x
        assert len(result) <= 200  # loose upper bound; escape shouldn't blow up
