# Follow-up: commands vs skills — which convention is better?

**Observed during Unit 3 (2026-04-17):**

- **compound-engineering 2.67.0**: 0 commands, 43 skills. Everything you invoke as `/ce:something` is a skill (e.g., `/ce:work` → `skills/ce-work/SKILL.md`).
- **lastmilefirst 0.14.0**: 20 commands + 21 skills. The `/run-*` entrypoints are commands (thin wrappers) that delegate to same-named skills.

Both approaches produce identical UX (`/foo` from the user's perspective), but they differ architecturally:

| Aspect | Commands | Skills |
|--------|---------|--------|
| Directory | `commands/*.md` | `skills/<name>/SKILL.md` |
| Always-in-context | Body loaded only on invocation | Name + description always visible to Claude |
| Discoverability | Listed under "commands" | Listed under "skills" |
| Context cost | Low baseline | Medium baseline (description always loaded) |
| Implicit invocation | No — user must type `/name` | Yes — Claude can invoke a skill based on description match |

## The question

**CE uses skills only** — simpler, no wrapper layer, but every `/ce:*` adds to always-on context cost.

**LMF uses both** — commands wrap skills. Thin command body can call a Python script; skill can hold richer instructions. Slightly more ceremony, potentially lower always-on cost if commands are short.

Which is right? Is there a third way?

## Worth exploring

- Measure the actual context cost difference (Unit 5's footprint estimator will make this visible)
- Read Anthropic's plugin architecture docs if a spec has been published since the current state
- Check whether other well-designed plugins (if they exist) have converged on one pattern
- Consider whether Griffith itself should weigh in: its footprint report could flag plugins with many skills-used-as-commands as "consider converting to commands for lower baseline"

## Priority

Low — both work; this is a refinement question, not a blocker. Revisit after Griffith Phase 1 ships and the footprint estimator provides concrete numbers.
