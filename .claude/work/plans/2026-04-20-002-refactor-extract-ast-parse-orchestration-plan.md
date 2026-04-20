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
  `_build_parsed_file(plugin_root: Path, cf: ComponentFile) -> tuple[ParsedFile | None, str | None]`
  that returns `(parsed, None)` on success OR `(None, error_str)` on
  any parse-time failure (syntax error, OSError, recursion during
  parse, recursion during alias-table build). The two-stage exception
  contract from `run_ast_rules` is preserved: recursion during parse
  is caught inside the recursion-limit `try/finally`; recursion during
  `build_alias_table(tree)` is caught in a separate `except
  RecursionError` after parse succeeds. Both surface as the
  `error_str` return.
- New `ParsedFile` dataclass: `(path: str, tree: ast.Module, alias_table: dict[str, str])`.
  Lives in `ast_rules.py` (no new module needed for one dataclass).
- `run_ast_rules` becomes `run_ast_rules(parsed: ParsedFile) -> list[SecurityFinding]`:
  given a `ParsedFile`, run every applicable AST rule.
- `SecurityScanner.scan()` orchestrates, preserving the predecessor's
  applicability semantics exactly:
  - Only .py files call into the helper. Other files skip the AST
    pass entirely.
  - Non-hook .py files with zero applicable rules skip the parse
    (helper not called). This matches predecessor behavior: we don't
    want to grow `meta.ast_parse_failures` for files nothing will
    ever inspect.
  - Hook .py files ALWAYS call the helper, even with zero applicable
    rules — the parse itself is the security signal (predecessor:
    "structural analysis disabled on executable hook code is a
    concerning signal").
  - On `(parsed, None)`: call `run_ast_rules(parsed)` and extend
    findings.
  - On `(None, error_str)`: hook-path → emit `ast-parse-failed`
    finding (high); else → append to `self._ast_parse_failures` for
    `meta.ast_parse_failures`.

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

- New `tests/test_parsed_file_helper.py`:
  - `_build_parsed_file` returns a `ParsedFile` on valid Python
  - `_build_parsed_file` returns `(None, error_str)` on syntax error
  - `_build_parsed_file` returns `(None, error_str)` on OSError
  - `_build_parsed_file` returns `(None, error_str)` when
    `build_alias_table` raises RecursionError (two-stage exception
    contract — parse succeeds, walk fails)
  - `_build_parsed_file` respects `_PARSE_RECURSION_LIMIT` guard
    (active during parse, restored on exit)
  - `_build_parsed_file` returns the same alias table as
    `build_alias_table(tree)` (shape parity)
  - `ast.parse` called exactly once per .py file per scan (cache
    regression guard)
- Additional scanner-orchestration test in `test_ast_rule_infra.py`:
  - Hook .py with zero applicable rules + syntax error STILL emits
    `ast-parse-failed` (pins hook-path always-parse invariant against
    a future rule-filter narrowing)
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

1. Write `test_parsed_file_helper.py` with the 7 scenarios above
   (helper behavior + parse-once cache guard). Add the additional
   scanner-orchestration test to `test_ast_rule_infra.py`.
   Verify the new tests fail because `_build_parsed_file` doesn't
   exist.
2. Implement `ParsedFile` dataclass in `ast_rules.py`. Implement
   `_build_parsed_file` as a method on `SecurityScanner` in
   `security.py`.
3. Verify the new tests pass.
4. Update `run_ast_rules` to accept `ParsedFile`. Update the single
   call site in `scan()` to use the helper (pre-filter non-hook
   .py files by applicability before calling helper, preserving
   predecessor semantics).
5. Run full pytest suite — all pre-existing tests pass plus the new
   test scenarios. Snapshots unchanged.

## Risks

| Risk | Mitigation |
|------|------------|
| Parse-failure handling regression (hook vs non-hook split). | Existing tests in `test_ast_rule_infra.py` cover both branches. Snapshot gate would catch silent drops. |
| `run_ast_rules` signature change breaks a test. | Verified at plan time: grep of `tests/` shows no direct importers of `run_ast_rules` (only `security.py::scan` calls it). No test migration needed. |
| Recursion-limit guard lands in the wrong location. | Keep the `try/finally` around parse exactly where it lives today; move as a unit. |
| AST parse called twice per file (cache regression). | Assertion test in `test_parsed_file_helper.py` (listed in the Tests section): mock `ast.parse`; scan a fixture with multiple .py files; assert exactly one parse per file. |
| Alias-table RecursionError handling lost in the split (two-stage exception contract). | Dedicated test (`test_parsed_file_helper.py`) asserts `(None, error_str)` when `build_alias_table` raises RecursionError. Helper preserves predecessor's `except RecursionError` around `build_alias_table(tree)`. |
| Non-hook .py parse semantics drift (e.g., always-parse when predecessor skipped). | Scanner-side pre-filter preserves `non-hook .py skip-if-no-applicable-rule` behavior; helper is called only for files that either are .py AND hook-pathed, OR .py AND have ≥1 applicable rule. Snapshot gate catches any drift. |

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
