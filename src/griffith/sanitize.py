"""Sanitize strings derived from untrusted plugin content for safe report embedding.

Strips control characters, ANSI escape sequences, Unicode bidi overrides, and
zero-width codepoints. Replaces stripped characters with a single space and
collapses whitespace runs. Length-caps to prevent oversized fields from
flooding the report.

This is defensive against two threat models:
- Injection through rendered Claude sessions (ANSI + bidi + newlines enable
  visual and control-flow tricks).
- Prompt injection where plugin content flows into an LLM prompt verbatim.

The sanitizer does NOT filter semantic content ("Ignore prior instructions"
survives as prose). The defense is in the encoding: consumers should render
untrusted fields inside an instruction-neutral envelope (e.g. escaped code
fence). This module makes that envelope safe to display.
"""

from __future__ import annotations

import re

# Union regex: C0/DEL controls, ANSI CSI escapes, bidi overrides, zero-width.
# Bidi: U+202A..U+202E (LRE/RLE/PDF/LRO/RLO), U+2066..U+2069 (LRI/RLI/FSI/PDI)
# Zero-width: U+200B..U+200D (ZWSP/ZWNJ/ZWJ), U+FEFF (BOM)
_STRIP_RE = re.compile(
    r"[\x00-\x1F\x7F]"
    r"|\x1b\[[0-9;?]*[a-zA-Z]"
    r"|[\u202A-\u202E\u2066-\u2069]"
    r"|[\u200B-\u200D\uFEFF]"
)

DEFAULT_MAX_NAME_LENGTH = 80
DEFAULT_MAX_DESCRIPTION_LENGTH = 240
DEFAULT_MAX_SNIPPET_LENGTH = 120


def sanitize_string(value: object, max_length: int = DEFAULT_MAX_DESCRIPTION_LENGTH) -> str:
    """Strip control/ANSI/bidi/zero-width codepoints; collapse whitespace; cap length.

    Non-string values are coerced via str(). None returns empty string.
    """
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    s = _STRIP_RE.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_length:
        s = s[:max_length].rstrip()
    return s


def sanitize_frontmatter(frontmatter: dict) -> dict:
    """Sanitize string values in a parsed frontmatter dict.

    Length caps: name=80, description=240, everything else=240.
    Non-string values pass through unchanged.
    """
    if not isinstance(frontmatter, dict):
        return {}
    out: dict[str, object] = {}
    for key, value in frontmatter.items():
        if isinstance(value, str):
            max_len = (
                DEFAULT_MAX_NAME_LENGTH if key == "name" else DEFAULT_MAX_DESCRIPTION_LENGTH
            )
            out[key] = sanitize_string(value, max_len)
        else:
            out[key] = value
    return out
