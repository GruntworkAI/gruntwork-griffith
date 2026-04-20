# Followup: add `superpowers-marketplace` snapshot (M6 from post-merge review)

**Status: deferred. Scope needs judgment on regeneration story.**

**Surfaced during:** architecture-strategist M6 in the post-merge code
review of `feat/ast-security-rule-refinement` (2026-04-20). Merged
predecessor: commit `5343aa7`.

## Context

Per predecessor plan R15, Griffith ships unconditional fingerprint
snapshots as binding integration tests. Three snapshots currently
check in:

- `tests/snapshots/security-traps-plugin.json` — local fixture
- `tests/snapshots/lastmilefirst-0.14.0.json` — real plugin, version-pinned
- `tests/snapshots/compound-engineering-2.67.0.json` — real plugin, version-pinned

M6 proposed adding a fourth: `superpowers-marketplace`. This matters
because superpowers is a popular public marketplace plugin that
exercises the path-traversal-dynamic-{js,shell} rules heavily — the
very rules whose noise reduction was the motivating case for the
whole AST refinement epic (see plan for "Case B" framing).

## Why deferred

Adding a binding snapshot for `superpowers-marketplace` requires:

1. **Version pinning.** The snapshot is keyed on a specific version
   (per the naming convention `<plugin>-<version>.json`); we need to
   pick one and document how regeneration on upgrade works.
2. **Fixture discipline.** Today's snapshots run on locally-cached
   plugin clones (`~/.claude/plugins/cache/...`). `superpowers-
   marketplace` isn't in the LMF profile, so any dev running the
   test suite would need the fixture. Options:
   - Check the cached plugin into `tests/fixtures/`
     (pro: no setup; con: license + size)
   - Mark the test `skipif` when the cache is missing
     (pro: no friction; con: silently skipped locally + CI)
   - Download-on-demand via pytest fixture with a deterministic
     commit pin (pro: reproducible; con: network dep in tests)
3. **Snapshot baseline.** The first run needs
   `GRIFFITH_REGENERATE_SNAPSHOTS=1` to produce the snapshot. The
   baseline findings list is the reviewable artifact — needs an
   intentional review pass before commit.

Each option has a different maintenance profile; choosing requires a
deliberate call.

## Trigger conditions to revisit

- A future refinement pass touches the path-traversal rules (JS or
  shell) and we need a regression gate on the popular-plugin case.
- Somebody adds a general "download and snapshot N popular
  marketplace plugins" mechanism that other projects could adopt.
- `superpowers-marketplace` itself is updated in a way that changes
  Griffith's findings materially and we want to capture the delta.

## Related

- Predecessor plan: `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md`
- Snapshot helper: `tests/helpers/snapshots.py`
- Existing version-pinned snapshots pattern: `tests/snapshots/lastmilefirst-0.14.0.json`
