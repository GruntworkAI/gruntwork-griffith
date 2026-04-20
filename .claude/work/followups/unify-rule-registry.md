# Follow-up: unify YAML regex + AST rule registries

**Surfaced during code review of feat/ast-security-rule-refinement (2026-04-20).**

Both architecture and coherence reviewers flagged that the shipped implementation kept two parallel registries (`_CompiledRule` + `self._rules` for YAML regex rules; `ASTRuleSpec` + module-level `AST_RULES` for AST rules) instead of the unified `Rule` dataclass + adapter specified in the plan's R10 + Decision 2. The deviation was weighed during review and deferred to this followup; see the amendment in `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md` for the decision rationale.

## Current state

`src/griffith/analyzer/security.py`:
- `_CompiledRule` dataclass (regex + context globs + exclude + severity + message + strict)
- `SecurityScanner._rules: list[_CompiledRule]` instance registry, loaded at init from YAML
- Regex pass iterates `self._rules` in `scan()`

`src/griffith/analyzer/ast_rules.py`:
- `ASTRuleSpec` dataclass (rule_id + severity + file_filter + check callable)
- `AST_RULES: list[ASTRuleSpec]` module-level registry, populated at import via `@ast_rule` decorator
- AST pass iterates `AST_RULES` in `scan()` (separate loop)

Shell-regex rules live in YAML and use the `_CompiledRule` path; they're functionally identical to regex rules, distinguished only by naming (`bash-c-dynamic-*`, `path-traversal-dynamic-{js,shell}`).

## Why unify

1. **Extension surface.** A 3rd engine (e.g., JS AST via tree-sitter) arriving means a 3rd registry and a 3rd dispatch loop unless unified first.
2. **Cross-registry queries.** Questions like "list all rules firing at high severity" or "which rules apply to `hooks/**/*.py`" currently require walking two lists with different shapes.
3. **Consistency.** Scoping vocabularies differ (AST `file_filter: str` single glob vs YAML `context: list[str]` + `exclude: list[str]`). Unifying the registry should probably unify the scoping too.
4. **Testability.** A single registry means a single test helper for "given rules X, Y, Z, scan fixture F and assert findings" — today the AST path and regex path need separate scaffolding.
5. **Plan fidelity.** The plan specified it; the plan passed review specifying it. Shipping the unified shape closes that gap.

## Proposed shape

```python
# src/griffith/analyzer/rule.py (new module)
@dataclass
class Rule:
    rule_id: str
    severity: str
    file_filter: list[str]          # context globs (list for multiple matches)
    exclude: list[str]               # exclude globs
    engine_kind: Literal["regex", "ast", "shell-regex"]
    run: Callable[[RuleContext], list[SecurityFinding]]

RULE_REGISTRY: list[Rule] = []
```

Adapters:
- `Rule.from_compiled_regex(_CompiledRule) -> Rule` — wraps regex rules; `run` closes over the compiled pattern
- `Rule.from_ast_spec(ASTRuleSpec) -> Rule` — wraps AST-registered functions; `run` builds/reuses the per-file AST tree + alias table

`SecurityScanner.scan()` iterates `RULE_REGISTRY` once per file, dispatching by `engine_kind`. Parse-once-per-file optimization for AST rules still applies via a per-file cache keyed on path.

## Scope

- New module `rule.py` with `Rule` dataclass + `RULE_REGISTRY` + adapter factories
- `SecurityScanner._rules` becomes `RULE_REGISTRY` (or a filtered view of it scoped by strict-mode)
- `scan()` rewritten to single-loop-with-dispatch
- AST rule orchestration (parse, alias table) moves to a scanner helper method so `run_ast_rules` isn't both rule runner and orchestrator (architecture review's M1 from the code review also points at this)
- Unify YAML `context`/`exclude` and AST `file_filter`; widen AST to accept a list + optional exclude

## Non-scope

- No new rules
- No severity changes
- No schema changes (the external contract stays identical — consumers see the same `SecurityFinding` shape)

## Risks

- Refactor touches the hot scan path. Test suite is green at 415; a regression in rule dispatch could silently drop findings or produce duplicates. Mitigation: snapshot-based integration tests (shipped in Unit 4) catch behavioral drift before merge.
- Potential circular-import re-emergence if the new `rule.py` depends on both `security.py` and `ast_rules.py`. Mitigation: `rule.py` depends on nothing scanner-specific; both consumers import FROM it.

## Estimated effort

~150 LOC net + regression iteration. Plan's Option A estimated 2-3 hours focused work; this remains accurate.

## Related

- Origin plan: `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md`
- Code review findings (2026-04-20): architecture-strategist M1 + M4; coherence reviewer blocker section; kieran H3
