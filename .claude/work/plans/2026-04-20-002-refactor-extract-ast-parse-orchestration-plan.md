---
status: active
created: 2026-04-20
depth: lightweight
origin: .claude/work/followups/unify-rule-registry.md
predecessor: .claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md
supersedes: .claude/work/plans/archive/2026-04-20-002-refactor-unify-rule-registry-plan.md
execution_note: test-first; snapshots must still pass (binding contract)
---

# Plan: Extract AST parse + orchestration from `run_ast_rules`

## Problem frame

`src/griffith/analyzer/ast_rules.py::run_ast_rules` today has two
responsibilities:

1. Parse the source file and build an alias table (per-file
   orchestration).
2. Dispatch applicable AST rules against the parsed tree (rule
   running).

The architecture-strategist's M1 finding on the predecessor PR called
this out as a single-responsibility violation. It's independent of the
broader "unify YAML + AST registries" question — the SRP fix has
standalone value and no speculative abstraction.

The unification question was deferred: see
`.claude/work/followups/unify-rule-registry.md` for trigger conditions
that would make the full refactor worth revisiting.

## Scope

### In

- Extract parse + alias-table build into a scanner-level helper
  `_build_parsed_file(cf: ComponentFile) -> ParsedFile | None` that
  returns either a parsed file or the parse error message (whichever
  `run_ast_rules` currently returns internally).
- New `ParsedFile` dataclass: `(path: str, tree: ast.Module, alias_table: dict[str, str])`.
  Lives in `ast_rules.py` (no new module needed for one dataclass).
- `run_ast_rules` becomes `run_ast_rules(parsed: ParsedFile) -> list[SecurityFinding]`:
  given a `ParsedFile`, run every applicable AST rule.
- `SecurityScanner.scan()` orchestrates:
  - for each .py file: build `ParsedFile` once (via helper)
  - handle parse-failure split (hook-path → `ast-parse-failed` finding; else `meta.ast_parse_failures`)
  - call `run_ast_rules(parsed)` for the dispatch

### Out

- No new rules, severities, YAML changes, schema changes.
- No unified `Rule` dataclass, no adapter pattern, no cross-engine
  dispatch unification — that's the future enhancement.
- No change to `@ast_rule` decorator signature.
- No change to rule-applicability semantics (hook-path always-parse;
  non-hook skip-if-no-applicable-rule).

## Why this is worth doing now

- Single-responsibility fix flagged in post-merge code review.
- Concrete, small (~30 LOC moved), easy to verify (snapshots are
  binding).
- Enables Griffith-side inspection of parsed trees for future
  non-rule uses (e.g., an import-graph analyzer) without re-parsing.
- No speculative abstraction. No `engine_kind` discriminator. No
  future-conditional ROI.

## Files

### Modify

- `src/griffith/analyzer/ast_rules.py`:
  - Add `ParsedFile` dataclass
  - `run_ast_rules` signature changes to accept `ParsedFile` (breaking
    internal change; only called from `security.py`)
  - Parse + alias-table build logic moves to scanner helper
- `src/griffith/analyzer/security.py`:
  - New `_build_parsed_file(cf)` helper, returns `(ParsedFile | None, parse_error | None)`
  - `scan()`'s AST pass loop calls the helper, handles the split, then
    `run_ast_rules(parsed)` if parsed ok

### Tests

- New `tests/test_parsed_file_helper.py` (or extension of
  `test_ast_rule_infra.py`):
  - `_build_parsed_file` returns a `ParsedFile` on valid Python
  - `_build_parsed_file` returns `(None, error_str)` on syntax error
  - `_build_parsed_file` returns `(None, error_str)` on OSError
  - `_build_parsed_file` respects `_PARSE_RECURSION_LIMIT` guard
  - `_build_parsed_file` returns the same alias table as
    `build_alias_table(tree)` (shape parity)
- Existing tests stay green:
  - `tests/test_ast_rule_infra.py` (migrate call sites if they call
    `run_ast_rules` directly)
  - `tests/test_subprocess_rules.py`, `test_dynamic_code_exec.py`,
    `test_bash_c_dynamic.py`, `test_path_traversal_refinement.py`
- **Snapshots unchanged (binding contract):**
  - `tests/snapshots/security-traps-plugin.json`
  - `tests/snapshots/lastmilefirst-0.14.0.json`
  - `tests/snapshots/compound-engineering-2.67.0.json`

## Test-first execution

Per the predecessor plan's posture and user preference:

1. Write `test_parsed_file_helper.py` with the 5 scenarios above.
   Verify they fail because `_build_parsed_file` doesn't exist.
2. Implement `ParsedFile` dataclass + `_build_parsed_file` helper
   in `security.py`.
3. Verify the new tests pass.
4. Update `run_ast_rules` to accept `ParsedFile`. Update the single
   call site in `scan()` to use the helper.
5. Run full pytest suite — expect 415 + new tests green. Snapshots
   unchanged.

## Risks

| Risk | Mitigation |
|------|------------|
| Parse-failure handling regression (hook vs non-hook split). | Existing tests in `test_ast_rule_infra.py` cover both branches. Snapshot gate would catch silent drops. |
| `run_ast_rules` signature change breaks a test that imports it directly. | Grep for direct callers before change; migrate with the signature change. |
| Recursion-limit guard lands in the wrong location. | Keep the `try/finally` around parse exactly where it lives today; move as a unit. |
| AST parse called twice per file (cache regression). | Assertion test: mock `ast.parse`; scan a fixture with 2+ applicable rules on one file; assert call count = 1. |

## Scope boundaries (non-goals)

- No unified `Rule` dataclass. Two registries stay today.
- No `engine_kind` field. No adapters. No `from_ast_spec` /
  `from_compiled_regex` factories.
- No changes to YAML scoping vocabulary (`context`/`exclude`).
- No changes to AST rule authoring experience (`@ast_rule` unchanged).

## Estimated effort

~30 LOC net moved (not added). 1 hour focused work, snapshot-gated.

## Sources

- **Origin code review finding:** architecture-strategist M1 from
  post-merge review of predecessor (2026-04-20)
- **Predecessor plan:** `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md`
- **Deferred full refactor:** `.claude/work/followups/unify-rule-registry.md`
- **Archived v2 plan (the full unification, deferred):**
  `.claude/work/plans/archive/2026-04-20-002-refactor-unify-rule-registry-plan.md`
- **Adversarial review output that prompted scope narrowing:**
  captured inline in user conversation on 2026-04-20
