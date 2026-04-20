# Followup: `is_provably_static` asymmetry on `Starred(Name)` (M7 from post-merge review)

**Status: deferred. Needs a design call on intended semantics.**

**Surfaced during:** architecture-strategist M7 in the post-merge code
review of `feat/ast-security-rule-refinement` (2026-04-20).

## The asymmetry

`is_provably_static` in `src/griffith/analyzer/ast_rules.py` decides
whether a subprocess call's `args[0]` is a literal (safe) vs dynamic
(potentially command-injection). It currently fires
`subprocess-dynamic-command` at high severity when:

| `args[0]` shape | Fires? | Rationale |
|---|---|---|
| `Constant("ls")` | no | literal string |
| `List([Constant, Constant])` | no | all-literal list |
| `List([Constant, Name("x")])` | **yes** | list with dynamic element |
| `Starred(List([Constant, Constant]))` | no | unpacked literal list |
| `Starred(Name("args"))` | **no** | unpacked unknown variable |
| `Name("cmd")` | **yes** | bare variable |

The asymmetry: a bare `Name` fires, but `Starred(Name)` does not.
In shell-injection terms, `subprocess.run(cmd, shell=False)` is
dangerous if `cmd` is runtime-controlled, and
`subprocess.run(*args, shell=False)` is dangerous on the same axis.

The shipped implementation treats `Starred(Name)` as "we can't know,
so don't fire" (conservative, accepting false negatives) while bare
`Name` is "we can't know, so fire" (aggressive, accepting false
positives).

## Why deferred

Both interpretations are defensible:

- **Symmetry-by-firing:** both should fire, because in both cases the
  runtime value is uninspectable at static-analysis time. This is
  consistent with the rule's existing posture for bare `Name`.
- **Symmetry-by-silence:** neither should fire, because we'd be
  guessing. This would also make `Name` not fire, which is a
  behavior regression.
- **Keep asymmetry:** the current mix — some coverage better than
  none, but `Starred(Name)` is a less common pattern in hooks that
  we're less confident about.

The predecessor plan's Decision 5 explicitly covered the "inverted
static check" logic but did not enumerate `Starred(Name)` as a
deliberate case. So this is an oversight, not a deliberate choice —
which makes "pick one direction and own it" the right resolution,
not a status-quo preservation argument.

## Trigger conditions to revisit

- A real-world plugin surfaces a `subprocess(*args, ...)` pattern
  that should fire but doesn't — confirmed false negative → push
  toward symmetry-by-firing.
- A real-world plugin surfaces a `subprocess(cmd, ...)` pattern
  where `cmd` is obviously a literal bound one line above, and the
  rule fires spuriously → push toward static-tracing improvement
  (a deeper change than just `Starred(Name)`).
- A contributor asks "why does one fire but not the other?" — that's
  the social signal this asymmetry has started costing us.

## Proposed resolution (when we revisit)

Most likely: fire on `Starred(Name)`. Rationale matches bare `Name`
behavior; authors wanting to silence should switch to `Starred(List)`
or add a rule-disable comment at the call site.

If we revisit and instead decide to go silent on both, that's a
larger change — it would require removing the bare-`Name` coverage,
which we'd need real-world FP evidence to justify.

## Related

- Predecessor plan: `.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md` (Decision 5)
- Implementation: `src/griffith/analyzer/ast_rules.py` — `is_provably_static`
- Tests: `tests/test_ast_rule_infra.py::TestIsProvablyStatic`
