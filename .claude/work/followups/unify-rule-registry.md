# Future enhancement: unify YAML regex + AST rule registries

**Status: DEFERRED — awaiting concrete trigger. Not scheduled.**

**Original surfacing:** code review of `feat/ast-security-rule-refinement`
(2026-04-20). Merged predecessor: commit `5343aa7`.

**Deferral decision:** 2026-04-20, after document-review of
`.claude/work/plans/2026-04-20-002-refactor-unify-rule-registry-plan.md`.

## Why deferred

The predecessor plan's R10 + Decision 2 specified a unified `Rule`
dataclass + adapter pattern. The shipped implementation kept two
parallel registries (`_CompiledRule` + `self._rules` for YAML regex;
`ASTRuleSpec` + module-level `AST_RULES` for AST). This was weighed
during review and accepted as shippable.

Planning a unification follow-up (v2 plan on 2026-04-20) surfaced
that the benefits are future-conditional:

- "Extension surface for a 3rd engine" — no 3rd engine on the roadmap
- "Cross-registry queries" — not a requested feature
- "Plan fidelity" — the prior review already forgave the deviation

The refactor's cost (150 LOC on the hot scan path + snapshot-gate
regression risk + review time) is paid today against a benefit that
may never land, or may land with a shape the current abstraction
doesn't fit. Abstractions designed for one concrete consumer are
usually wrong; we'd be designing for zero concrete consumers.

## What we DID ship from the v2 plan

The adversarial review identified Unit 3 (extract AST parse +
alias-table build out of `run_ast_rules` into a scanner helper) as
standalone-valuable: a single-responsibility cleanup independent of
the unification question. Also flagged by architecture-strategist
M1 in the post-merge code review.

**Shipped separately:** `.claude/work/plans/2026-04-20-002-refactor-extract-ast-parse-orchestration-plan.md`.

## Trigger conditions to revisit

Reopen this follow-up when **any** of these becomes concrete:

1. **JavaScript/TypeScript AST engine lands.** `tree-sitter-javascript`
   or equivalent, replacing the regex-based
   `path-traversal-dynamic-js` with structural analysis. At that point
   the 3rd engine is real, the unification has a concrete shape
   driver, and the adapter pattern earns its keep.
2. **Shell AST engine lands.** `tree-sitter-bash` or equivalent,
   replacing `bash-c-dynamic-interpolated` with structural
   parsing. Same argument.
3. **Cross-registry query becomes a product feature.** e.g., a
   `griffith rules --filter severity=high` CLI, a
   `griffith rules --applying-to hooks/` lookup, or external
   consumers (LMF wrapper, Observatory service) asking for rule
   introspection that today requires walking two lists.
4. **3rd YAML-authored engine-kind beyond regex/shell-regex.** e.g.,
   structural YAML rules with path-shape detection.
5. **Rule-metadata changes that apply to both engines diverge in
   shape across registries.** If AST rules need tagging, scoring,
   or ordering that YAML regex rules also need, the current
   two-registry shape forces duplicate implementations.

## Original proposal (preserved for when we revisit)

```python
# src/griffith/analyzer/rule.py (new module)
@dataclass
class Rule:
    rule_id: str
    severity: str
    file_filter: list[str]
    exclude: list[str]
    engine_kind: Literal["regex", "ast", "shell-regex"]
    run: Callable[[RuleContext], list[SecurityFinding]]
    strict: bool = False

RULE_REGISTRY: list[Rule] = []
```

Adapters: `Rule.from_compiled_regex(_CompiledRule) -> Rule` and
`Rule.from_ast_spec(ASTRuleSpec) -> Rule`. `SecurityScanner.scan()`
iterates the unified registry with dispatch by `engine_kind`.

See v2 plan for the full design + test scenarios, preserved at
`.claude/work/plans/archive/2026-04-20-002-refactor-unify-rule-registry-plan.md`
once archived.

## Known design gaps to resolve when we revisit

These surfaced during the v2 plan's document-review and remain
unresolved — they should shape the design when the trigger lands:

- **Shell-regex classification.** Today distinguishable only by
  rule-ID prefix (`bash-c-dynamic-`, `path-traversal-dynamic-{js,shell}`).
  Encoding engine identity in the registry makes prefixes
  load-bearing. At revisit time, pick: (a) optional `engine:` YAML
  key, (b) explicit allowlist in `rule.py`, or (c) reclassify these
  as plain regex rules and drop the shell-regex distinction.
- **Strict-mode timing.** Current `_load_rules(path, strict)` filters
  at load time — with a module-level registry, the first scanner's
  strict flag determines which rules ever populate. Resolution:
  always load every rule; filter at iteration. Cross-scanner
  pollution trap must be explicitly handled.
- **`RuleContext` shape.** Regex needs `content` + `path`; AST needs
  `tree` + `path` + `alias_table`; shell-regex currently reuses the
  regex shape. Single dataclass with optional fields vs TypeAlias
  union is undecided.
- **`_CompiledRule` and `ASTRuleSpec` retirement.** Plan-time decision,
  not implementation-time. Deferred in the v2 plan; resolve at revisit.

## Related

- **Origin predecessor plan:** `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md`
- **Code review findings (2026-04-20):** architecture-strategist M1 + M4; coherence reviewer blocker section; kieran H3
- **v2 plan + its document review:** see plan file for review outputs
- **Standalone Unit 3 work:** `.claude/work/plans/2026-04-20-002-refactor-extract-ast-parse-orchestration-plan.md`
