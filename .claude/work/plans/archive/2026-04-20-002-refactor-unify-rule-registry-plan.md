---
status: deferred
created: 2026-04-20
deferred: 2026-04-20
deferral_reason: "Adversarial reviewer surfaced future-conditional cost/benefit; user approved narrowing scope to Unit 3 (parse-cache extraction) only. Full unification gated on concrete 3rd-engine trigger."
superseded_by: .claude/work/plans/2026-04-20-002-refactor-extract-ast-parse-orchestration-plan.md
future_enhancement_doc: .claude/work/followups/unify-rule-registry.md
depth: standard
origin: .claude/work/followups/unify-rule-registry.md
predecessor: .claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md
execution_note: test-first; snapshots must still pass (binding contract)
---

> **DEFERRED 2026-04-20** — This plan is preserved as the design artifact
> for when the unification triggers (see the future-enhancement doc
> at `.claude/work/followups/unify-rule-registry.md`) become concrete.
> The narrowed Unit 3 scope shipped via the successor plan at
> `2026-04-20-002-refactor-extract-ast-parse-orchestration-plan.md`.

# Plan: Unify YAML regex + AST rule registries (DEFERRED)

## Problem frame

The AST-security-refinement PR (merged commit 5343aa7) shipped with two
parallel rule registries instead of the unified `Rule` dataclass + adapter
specified in the predecessor plan's R10 and Decision 2:

- `_CompiledRule` + `self._rules` for YAML regex rules (loaded per-scanner
  at init)
- `ASTRuleSpec` + module-level `AST_RULES` for AST rules (populated at
  import via `@ast_rule`)

`SecurityScanner.scan()` has two separate dispatch loops. Two registries,
two dispatch paths, two scoping vocabularies (YAML `context: list[str]` +
`exclude: list[str]` vs AST `file_filter: str`). This was weighed during
the predecessor's code review and deferred to this plan as a focused
follow-up so the refinement PR stayed reviewable.

This plan implements what Decision 2 specified.

## Requirements traceability

From the predecessor plan's R10 (verbatim, for contract fidelity):

> Unified `Rule` dataclass (NOT protocol — see Decision 2) with
> `engine_kind: Literal["regex", "ast", "shell-regex"]` discriminator.
> Wraps YAML regex rules and AST-registered functions; single registry
> populated at scanner init + module import.

From Decision 2:

> YAML-authored regex rules compile through the existing `_CompiledRule`
> path and get wrapped in a `Rule` adapter at scanner init. AST rules
> register directly via `@ast_rule(...)` decorator. One registry,
> dispatched by `engine_kind`.

### Scope (in)

- New module `src/griffith/analyzer/rule.py` — `Rule` dataclass + adapter
  factories + `RULE_REGISTRY`
- `SecurityScanner._rules` becomes a filtered view over `RULE_REGISTRY`
  (or the registry itself, scoped by strict-mode at build time)
- `SecurityScanner.scan()` collapses the two dispatch loops into one
  registry iteration with dispatch by `engine_kind`
- Unify scoping vocabulary: `file_filter` becomes `list[str]` on both
  engines; add optional `exclude: list[str]` to AST rules (no-op if
  unused; preserves YAML exclude behavior)
- Extract AST orchestration (parse + alias-table build + per-file cache)
  from `run_ast_rules` into a scanner helper so "rule runner" and
  "per-file parser" are separate concerns

### Scope (out)

- No new rules
- No severity changes
- No schema changes — external JSON contract stays identical
- No YAML schema changes — `context`/`exclude` keys keep current names
  and behavior (the internal `file_filter` unification is a code-side
  concern)
- No migration of AST rules to YAML (the decorator-registered shape
  stays — only the spec wrapper changes)
- No Protocol-based Rule abstraction (dataclass + adapter per Decision 2)

## Key decisions

1. **Dataclass, not Protocol.** Decision 2 is preserved verbatim.
   `Rule.run: Callable[[RuleContext], list[SecurityFinding]]` is a field,
   not a method — so adapter factories construct `Rule` instances without
   inheritance.

2. **`file_filter` is `list[str]`, not `str`.** YAML already uses a list;
   the AST single-glob form widens to list. Rule authoring for single-glob
   AST rules stays one-line: `file_filter=["hooks/**/*.py"]`. The existing
   `@ast_rule(file_filter="hooks/**/*.py")` decorator call accepts either
   `str` or `list[str]` for backwards compatibility with the 6 in-tree
   AST rules; decorator normalizes to list.

3. **`RULE_REGISTRY` is module-level in `rule.py`, YAML loader populates
   at scanner init.** AST rules populate at import time via `@ast_rule`
   (unchanged registration site — the list just lives in `rule.py`
   instead of `ast_rules.py`). YAML rules populate via
   `SecurityScanner._load_rules` which now produces `Rule` instances
   directly.

4. **Strict-mode scoping happens at registry-read time, not at
   registration time.** `RULE_REGISTRY` holds every rule; the scanner
   filters by `rule.strict <= self.strict` when iterating. This keeps the
   registry global (shared across scanner instances) while respecting
   per-instance strict mode.

5. **Per-file AST parse + alias-table cache moves to the scanner.** Today
   `run_ast_rules` parses once per file (good) but the orchestration
   lives in the AST-rules module. After: scanner builds a per-file
   `ParsedFile` struct (path, tree, alias_table, parse_error) once, hands
   it to every AST `Rule.run()` on that file. This makes the scanner the
   single authority for "what context does this rule get."

6. **`RuleContext` dataclass grows a `ParsedFile` field (optional, AST
   only).** Regex rules' `RuleContext` has `content: str` + `path: str`.
   AST rules' `RuleContext` has the existing `tree`, `path`, `alias_table`.
   Shell-regex rules use the same context shape as regex. A union type
   keeps the three engines' signatures explicit.

7. **Circular-import risk mitigation:** `rule.py` depends on `findings`
   (already extracted to `findings.py`) and on stdlib only. Both
   `security.py` and `ast_rules.py` import FROM `rule.py`. No back-edges.

8. **Engine-kind discriminator drives dispatch.** `scan()` iterates once;
   per-file, per-rule, it picks `_build_regex_context`,
   `_build_ast_context`, or `_build_shell_regex_context` based on
   `rule.engine_kind`. Context builders may be no-op for the regex path
   today (reuses content-per-line iteration) — that's fine; the point is
   to have one call site.

## Existing patterns to follow

- `src/griffith/analyzer/findings.py` is the precedent for a "no
  scanner-deps" module that breaks cycles. `rule.py` follows the same
  pattern: dataclass + stdlib + `findings.SecurityFinding` only.
- `dataclass`-with-`Callable`-field pattern already present in
  `ASTRuleSpec`. Generalizing, not inventing.
- YAML loading stays in `security.py` — only the output shape changes
  from `_CompiledRule` to `Rule`.
- Snapshot fingerprint tests (`tests/snapshots/*.json` via
  `tests/helpers/snapshots.py`) are the binding contract. Every existing
  test MUST still pass with no snapshot regeneration.

## Files

### Create

- `src/griffith/analyzer/rule.py` — `Rule` dataclass, `RULE_REGISTRY`,
  `RuleContext` (union shape), engine-kind literal, adapter factories
  `Rule.from_ast_spec(ASTRuleSpec)` and `Rule.from_compiled_regex(_CompiledRule)`
- `tests/test_rule_registry.py` — unit tests for `Rule` construction,
  adapter fidelity, registry membership, strict-mode filtering

### Modify

- `src/griffith/analyzer/security.py` — `_load_rules` returns
  `list[Rule]` (via adapter); `scan()` single-loop-with-dispatch;
  extract per-file `ParsedFile` builder; `_scan_file` and the AST pass
  collapse into one orchestrator
- `src/griffith/analyzer/ast_rules.py` — `AST_RULES` list moves into
  `rule.py` as `RULE_REGISTRY` (or `ast_rules.py` delegates — decide at
  implementation); `@ast_rule` decorator widens `file_filter` to accept
  `str | list[str]`; `run_ast_rules` orchestration function retires (its
  body moves to the scanner's per-file builder; decorator-registered
  rules still live here)

### Tests — mirror the implementation-unit scope

- `tests/test_rule_registry.py` — new, see above
- `tests/test_security.py` — no behavior change expected; all passing
  tests stay passing
- `tests/test_ast_rule_infra.py` — adjust to new registry location
  (import path change only; no semantic change)
- `tests/snapshots/*.json` — MUST not change. Binding contract.

## Test scenarios

### Rule dataclass + adapters (`test_rule_registry.py`)

- **Rule construction:** `Rule(rule_id, severity, engine_kind, run, file_filter=[...])` builds cleanly; `run` is callable.
- **Engine-kind literal set:** Passing a value outside `{"regex", "ast", "shell-regex"}` raises (dataclass with `Literal` type, optional runtime check).
- **Adapter fidelity — `from_ast_spec`:** An `ASTRuleSpec` with `rule_id="subprocess-shell-true"`, `severity="critical"`, `file_filter="hooks/**/*.py"` produces a `Rule` with identical `rule_id`, `severity`, `engine_kind="ast"`, `file_filter=["hooks/**/*.py"]` (normalized to list).
- **Adapter fidelity — `from_compiled_regex`:** A `_CompiledRule` with `context=["**/*.sh"]`, `exclude=["**/*.md"]`, `strict=False` produces a `Rule` with `file_filter=["**/*.sh"]`, `exclude=["**/*.md"]`, `engine_kind="regex"`, `strict=False`.
- **Adapter — shell-regex detection:** Rules whose IDs start with `bash-c-dynamic-` or `path-traversal-dynamic-{js,shell}` are adapted with `engine_kind="shell-regex"`, NOT `"regex"`. Rationale: the predecessor plan's Decision 2 names three engines; keep the signal for future dispatch logic that may branch per-engine.
- **Registry — strict filter:** With `RULE_REGISTRY` containing one `strict=True` rule and one `strict=False` rule, calling scanner's strict-mode filter with `strict=False` excludes the strict rule and includes the non-strict one; with `strict=True`, both are included.
- **Registry — no duplicate rule_ids across engines:** If a YAML rule and an AST rule share `rule_id`, the scanner's init raises `ValueError` (same posture as the existing `@ast_rule` duplicate guard).
- **Registry — AST rule registration still works via decorator:** `@ast_rule(rule_id="test-x", severity="info", file_filter="**/*.py")` on a fresh test function adds a `Rule` (not an `ASTRuleSpec`) to `RULE_REGISTRY`, with `engine_kind="ast"`.

### Scanner dispatch (`test_security.py` additions)

- **Unified dispatch — regex rules still fire:** `python-eval-exec` regex rule fires on `eval("x")` in a non-hook .py file after the refactor (exact same behavior as before).
- **Unified dispatch — AST rules still fire:** `subprocess-shell-true` fires on `subprocess.run("ls", shell=True)` in a hook .py file after the refactor.
- **Unified dispatch — shell-regex rules still fire:** `bash-c-dynamic-interpolated` fires on `bash -c "$user_input"` in a .sh file.
- **Per-file AST parse cache:** For a hook .py file with 3 applicable AST rules, `ast.parse` is called exactly ONCE per scan (mock-based assertion on parse call count; proves the scanner-level cache works).
- **AST rule `file_filter` widening:** An AST rule registered with `file_filter="hooks/**/*.py"` (string form, backcompat) matches the same files as one registered with `file_filter=["hooks/**/*.py"]` (list form).
- **Optional AST exclude:** An AST rule registered with `file_filter=["**/*.py"]`, `exclude=["tests/**/*"]` does not fire on `tests/foo.py`. New capability; previously AST rules had no exclude support.

### Snapshot regression (binding)

- `security-traps-plugin` snapshot: unchanged.
- `lastmilefirst-0.14.0` snapshot: unchanged.
- `compound-engineering-2.67.0` snapshot: unchanged.

All three run unconditionally per R15.

## Implementation units

Test-first across all units. Each unit's tests write FIRST, then
implementation follows.

### Unit 1: `rule.py` module — dataclass + adapters + registry

**Goal:** Establish the shared type surface without changing any
existing dispatch. Adapter factories implemented; existing scanner code
unchanged.

**Files:**
- Create `src/griffith/analyzer/rule.py`
- Create `tests/test_rule_registry.py`

**Execution note:** test-first. Write the adapter fidelity and registry
tests first; verify they fail because `rule.py` doesn't exist yet;
implement; verify they pass.

**Patterns to follow:** `src/griffith/analyzer/findings.py` for the
module layering; `src/griffith/analyzer/ast_rules.py::ASTRuleSpec` for
the dataclass shape.

**Test scenarios:** The 8 tests under "Rule dataclass + adapters" above.

**Verification:** `poetry run pytest tests/test_rule_registry.py` green;
`poetry run pytest` overall still 415 green (Unit 1 is purely additive).

### Unit 2: `@ast_rule` widens `file_filter` + registers `Rule`

**Goal:** Decorator accepts `str | list[str]`, normalizes to list, and
registers a `Rule` (via `Rule.from_ast_spec` equivalent inline) into
`RULE_REGISTRY`. `ASTRuleSpec` can stay as an internal intermediate or
be retired — decide at implementation.

**Files:**
- Modify `src/griffith/analyzer/ast_rules.py`
- Update `tests/test_ast_rule_infra.py` (existing tests update to new
  registry location / shape)
- Add tests for the `file_filter` widening + exclude support

**Execution note:** test-first for the new capabilities (list-form
`file_filter`, optional `exclude`). Existing tests migrate mechanically.

**Patterns to follow:** The existing decorator's duplicate-registration
guard (keep as-is).

**Verification:** All 6 in-tree AST rules still register and fire;
`poetry run pytest tests/test_ast_rule_infra.py tests/test_subprocess_rules.py tests/test_dynamic_code_exec.py tests/test_bash_c_dynamic.py tests/test_path_traversal_refinement.py` green; snapshots unchanged.

### Unit 3: Scanner-side per-file parse cache (extract from `run_ast_rules`)

**Goal:** Move AST parse + alias-table build out of `run_ast_rules` into
a scanner helper `_build_parsed_file(cf) -> ParsedFile | None`. The
scanner calls this once per .py file before any AST `Rule.run()` is
invoked on it. `run_ast_rules` shrinks to "given a `ParsedFile`, run
applicable rules"; or retires entirely into `scan()`.

**Files:**
- Modify `src/griffith/analyzer/security.py`
- Modify `src/griffith/analyzer/ast_rules.py`
- Add test: `test_security.py::test_ast_parse_called_once_per_file`

**Execution note:** test-first for the parse-count assertion. Existing
behavior (hook-path always-parse semantics; ast-parse-failed finding
split by path) must be preserved — covered by existing tests plus the
snapshot gate.

**Patterns to follow:** `security.py::scan`'s existing per-pass
orchestration structure. The parse cache is plain: a dict keyed on
`cf.path`, populated lazily, cleared at end of `scan()`.

**Verification:** All tests green; snapshots unchanged. Parse count test
asserts exactly one `ast.parse` call per distinct .py file.

### Unit 4: Unified dispatch in `scan()`

**Goal:** `scan()` iterates `RULE_REGISTRY` once (filtered by strict),
dispatches per-rule by `engine_kind`. The two legacy loops retire. Entry
point to this change is a branch-by-engine in a single per-file
iteration.

**Files:**
- Modify `src/griffith/analyzer/security.py` — `scan()` + `_scan_file`
  collapse; `_load_rules` returns `list[Rule]`
- Add tests for cross-engine dispatch (5 tests under "Scanner dispatch"
  above)

**Execution note:** test-first for the unified-dispatch tests.
Snapshots are the safety net — any finding dropped, duplicated, or
mis-ordered will fail the snapshot gate before merge.

**Patterns to follow:** Existing `_scan_file` for per-line regex
iteration; existing `run_ast_rules` for AST per-file orchestration
(now collapsed into `scan()`'s inner loop).

**Verification:** `poetry run pytest` full suite green (target: 415 +
new tests from Units 1-4); all three snapshots unchanged;
`poetry run griffith analyze <path> --json` output byte-equivalent (or
structurally equivalent modulo JSON key order — snapshots use stable
serialization) to pre-refactor output on the security-traps fixture.

### Unit 5: Cleanup + documentation

**Goal:** Retire dead code (`_CompiledRule` if no longer referenced;
`ASTRuleSpec` if fully collapsed into `Rule`); update module docstrings
in `security.py`, `ast_rules.py`, `rule.py` to describe the unified
shape; amend the followup + the predecessor plan with a "DONE" marker
and merge commit reference.

**Files:**
- `src/griffith/analyzer/security.py`, `ast_rules.py`, `rule.py`
  (docstrings)
- `.claude/work/followups/unify-rule-registry.md` — archive to
  `.claude/work/followups/archive/unify-rule-registry.md` with DONE +
  commit ref
- `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md`
  — update "Post-implementation amendments" section to note Decision 2
  shipped in this follow-up plan

**Execution note:** no new tests; housekeeping.

**Verification:** `poetry run pytest` green; no lint warnings about
unused classes; `rg -n "_CompiledRule\b" src/` returns only the
definition (if kept) or zero hits (if retired).

## Risks + mitigations

| Risk | Mitigation |
|------|------------|
| Regression in the hot scan path silently drops or duplicates findings. | Snapshot-based integration tests (3 unconditional snapshots) catch behavioral drift before merge. Run full pytest before each commit. |
| Circular-import re-emergence between `security.py` and `ast_rules.py`. | `rule.py` depends only on `findings.py` + stdlib. Both consumers import FROM it. Predecessor plan's B3 (SecurityFinding extraction) already paved this pattern. |
| `file_filter` widening breaks existing AST-rule decoration. | Decorator accepts `str | list[str]` for backcompat; the 6 in-tree rules are not modified, they continue using the string form. |
| Strict-mode filter timing regression (strict rules fire when they shouldn't or vice versa). | Explicit test: registry contains both strict and non-strict rules; scanner-init filtering behavior is asserted directly. |
| Engine-kind literal typo-at-construction-time. | Unit test rejects values outside the literal set. Runtime check in `Rule.__post_init__` if mypy isn't used at this call site. |
| YAML `exclude` semantics diverges from AST `exclude` if both are added. | Use the same glob-matching function (`_matches_any_glob`) in both code paths. Tests assert equivalence for a known path. |

## Scope boundaries / non-goals

These are explicit non-goals. Refer back if implementation pulls toward
them:

- No new rules. Adding rules during this refactor would tangle coverage
  regressions with rule-engine refactor concerns.
- No severity changes. Severity regression is easy to miss in diffs; the
  snapshot gate catches it, but ambiguity still costs review time.
- No schema changes. The external JSON contract stays byte-equivalent
  (modulo stable-key-order) to pre-refactor output on the security-traps
  fixture. That's the binding gate.
- No YAML file changes. `context`/`exclude` keys keep their current
  names and behavior.
- No Protocol-based Rule abstraction. Dataclass + adapter per
  Decision 2. If a future author pushes toward Protocol, direct them to
  this plan's Key Decisions #1.

## Estimated effort

~150 LOC net added (new `rule.py` + test file minus trimmed
orchestration); 2-3 hours focused work. Snapshots should absorb zero
diff — any diff surfaced during iteration is a regression, not a change.

## Sources

- Followup origin: `.claude/work/followups/unify-rule-registry.md`
- Predecessor plan (R10 + Decision 2):
  `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md`
- Code review findings that surfaced the follow-up:
  architecture-strategist M1 + M4 (2026-04-20); coherence reviewer
  blocker section; kieran H3
- Merged predecessor: commit 5343aa7 on `main`
