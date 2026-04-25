# Follow-up: Path-existence test for CLAUDE.md (drift guard)

**Why this exists (2026-04-25):**

PR #6 refreshed CLAUDE.md to match Phase 1.5 reality. Self-review of
PR #6 found two factual errors imported from the previous (stale)
CLAUDE.md without verification:

- `rules/efficiency_heuristics.yaml` and `rules/known_overlaps.yaml`
  were listed but never existed (planned in the original CLAUDE.md,
  never built).
- Test count was undercounted (claimed "419 + 2 network" — actual is
  439 total).

Both errors are the exact failure mode the refresh was meant to fix.
Doc-vs-reality drift is the recurring problem here, and "I'll be
careful next time" doesn't scale across contributors or LLM-assisted
edits.

## Fix

Add `tests/test_claude_md_paths.py` that:

1. Reads `CLAUDE.md`.
2. Extracts every path-like string (`src/...`, `tests/...`, `docs/...`,
   `rules/...`, `.claude/...`).
3. Asserts each one exists relative to repo root.

Could also extract the test count claim and assert it matches
`pytest --collect-only` output, but that's noisier (changes every
time tests are added) — probably overkill. Path existence is the
high-value invariant.

## Cheaper alternative

A pre-commit hook that greps for the same path patterns and runs the
existence check. Same effect without polluting the test suite. Either
approach works.

## Effort

~30 lines of Python for the pytest version. Could share a helper if
similar drift guards land for `README.md` later.

## Priority

Low-medium. The drift problem is real but only bites when CLAUDE.md
is edited (rare). Ship the next time CLAUDE.md is touched
substantially, or as a quick standalone PR.
