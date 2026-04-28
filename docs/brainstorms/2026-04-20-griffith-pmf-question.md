---
status: active
created: 2026-04-20
type: strategic-brainstorm
author: Michael Fisher + Claude
---

# Griffith — is this a real product?

## The fundamental question

Griffith Phase 1 + 1.5 are complete. 430 tests pass. The audit-plugin
wrapper ships Griffith to Claude Code sessions. The code is in good
shape.

But the next move is genuinely unclear. The design doc sketches
Phases 2 (Runtime Monitor) and 3 (Observatory) as the roadmap — but
those are real investments (4-8 weeks and months respectively) and
the assumption underneath them is unvalidated: **does anyone besides
Michael want this?**

This brainstorm exists to make that question explicit and to lay out
cheap ways to answer it before more code is written.

## Why this matters now

The roadmap I had been operating on was a *technical* roadmap — "do
Phase 2, then Phase 3." That implicitly assumed:

- Enough Claude Code users exist to support a service
- A non-trivial fraction of them would install a plugin audit tool
- They'd find the audit output actionable enough to change behavior
- Some subset would pay for Observatory-as-service

None of those assumptions have been tested with anyone but Michael.

The Observatory in particular is a big bet: hosting cost, telemetry
infrastructure, privacy posture, web UI, sustained operation. Building
it before validating demand is the classic "build it and they will
come" mistake.

## What we know right now

### Evidence *for* demand

- Michael built Griffith because he needed it (N=1 is real; it's just small)
- 4 real plugins have produced meaningful audit findings:
  `lastmilefirst 0.14.0`, `compound-engineering 2.67.0`,
  `superpowers-marketplace` (path-traversal false positives),
  `trailofbits/skills-curated` (federated marketplace shape)
- The audit-plugin wrapper makes Griffith session-usable — which Michael
  hasn't yet actually used against a "should I install this?" decision
  (worth trying)
- Skills momentum on openclaw.ai is a real external signal — demand
  for *skills* is real, even if demand for *skill audits* is less certain

### Evidence *neutral or against*

- Claude Code plugin ecosystem is small (launched late 2025, ~6 months old)
- Developers who install plugins already read code — the "I need a
  tool to audit this" purchase question isn't the same as "I got
  burned by a bad plugin" motivation question
- No one has reported a real plugin-related incident publicly — could
  mean nothing is happening, OR things are happening silently
- The design doc's business model (free + $9/mo + enterprise) was
  sketched in January 2026 and hasn't been validated against any user
  conversation
- Griffith currently addresses context-cost waste clearly but addresses
  discovery ("which plugin should I install?") not at all — discovery
  may be the actual pain

## Four paths forward

These aren't rivalrous — (4) is compatible with any of the others.

### Path 1: Build the Observatory (Phase 3 per design doc)

**Description:** Public aggregator, web UI, telemetry contribution, SaaS tiers.

**Pros:**
- Biggest potential upside if demand is real
- Matches the design doc's original vision
- Creates a discovery surface Griffith doesn't have today

**Cons:**
- Biggest bet stacked on the most unvalidated assumptions
- Months of work; easy to build the wrong thing
- Ongoing operational cost (hosting, privacy, uptime)
- Needs Phase 2 data quality before aggregation is interesting

**When this makes sense:** After strong demand signal from cheap
investigation (see Path 3).

### Path 2: Pivot to skills-first

**Description:** Narrow Griffith's marketing focus to skill analysis.
Skills are smaller units; analysis scope is smaller; ship faster.

**Rationale for this framing:**
- Skills are a simpler unit (one SKILL.md + fixtures) vs plugins
  (commands + agents + skills + hooks + MCP)
- Skill authoring is more chaotic — fewer quality signals today
- openclaw.ai skill demand suggests the audience is larger for skills
  than for full plugins
- ~80% of Griffith's existing plugin analysis code is reusable for
  skills (skills are already a parsed component type)
- `griffith analyze-skill <url>` could ship in ~2 weeks

**Pros:**
- Concrete MVP with clear audience
- Faster feedback loop than Observatory
- Doesn't preclude plugin support staying
- If demand is real, can extend to Observatory later

**Cons:**
- Assumes skill-audit demand exists (same unvalidated assumption)
- openclaw momentum could be fashion, not durable signal

**When this makes sense:** If Path 3 investigation shows demand for
skill-level tooling specifically.

### Path 3: Validate demand before more building

**Description:** A week (or a few hours over several days) of cheap
investigation answers "is this real?" before more code.

**Four concrete investigations:**

1. **Ask 3-5 real users.** Post on r/ClaudeAI or an active community:
   *"I've been auditing Claude Code plugins/skills before I install
   them. What would you want an auditor to tell you? Is this a thing
   you'd even run?"* Qualitative, blurry, but tells you which narrative
   lands (security vs context cost vs discovery) and whether anyone
   cares.

2. **Audit something popular + publish it.** Pick a popular skill or
   plugin, run Griffith, write up findings in a public post. If people
   share it / comment / ask how to run it → signal. Silence → signal.

3. **Check competition.** Who else is trying to solve this? Absence
   is either opportunity or a signal that demand isn't there.

4. **Count the audience.** Rough TAM: Claude Code MAU × plugin/skill
   adoption rate × would-run-audit rate. Tells you whether this
   supports SaaS or only hobby.

**Pros:**
- Cheapest option (no code)
- Produces real data, not assumptions
- Answer is probably "mixed" — which usefully narrows scope

**Cons:**
- Requires outreach (social cost, not technical)
- Answer may be ambiguous
- Delays building

**When this makes sense:** Before any of the other paths, as a gate.

### Path 4 (non-rivalrous): Keep running Griffith + post upstream PRs

**Description:** Use Griffith continuously on plugins we evaluate.
When Griffith surfaces a real issue, file a PR to the upstream plugin.
Compound value: real-world signal for Griffith's accuracy, real
contributions to the ecosystem, demonstrable evidence that the tool
produces actionable output.

**Pending candidates (immediate):**

- **Superpowers marketplace** — Griffith's path-traversal-dynamic-js
  rule refinements reduce ~20 false positives in superpowers' test
  suite. Worth offering the rule refinement back to them as a
  working example? Or offering the Griffith audit report as-is?
  Decision point: are we contributing to *superpowers*, or pitching
  *Griffith* to their users?

- **trailofbits/skills-curated** — federated marketplace detection
  shipped partly because of this repo's shape. Less clear what the
  PR would be — Griffith now understands their shape, which is
  mostly a Griffith fix, not a superpowers-style upstream
  contribution. Might be "here's a Griffith report for your skills"
  instead.

**Pros:**
- Zero assumption stacking — even if Griffith-as-product fails,
  upstream PRs are real contributions
- Generates external validation / citations / visibility
- Produces real-world findings that feed back into Griffith's
  rule quality
- Compatible with Paths 1/2/3 — you can do this alongside anything

**Cons:**
- Requires polish per PR (upstream review, formatting,
  collaboration)
- Distraction risk — can spend time on polish without moving the
  core product question forward

**When this makes sense:** Always; in parallel with Path 3.

## Decision framing (when we come back to this)

The Path 3 investigation outputs roughly three possible states:

| Signal | Recommended action |
|---|---|
| **Strong demand** | Skills-first MVP (Path 2), then Phase 2 or Observatory |
| **Weak signal** | Keep Griffith working for personal use, stop treating it as a product; harvest learnings into other work; continue Path 4 opportunistically |
| **Mixed signal** | Narrow the audience — "plugin authors who want to self-audit before publishing" is a different market than "plugin consumers who want to screen before installing". Pick one and retest. |

## Open questions

- **Has Michael used the audit-plugin wrapper against a real "should
  I install this?" decision yet?** If not, try it once before
  deciding anything. That's the cheapest possible validation of his
  own use case.
- **Is there overlap between Griffith's audience and LMF Advisors'
  audience?** If Griffith output is an input to security / quality
  advisory work, that's a different positioning than consumer-facing
  plugin audits.
- **What's the actual size of the Claude Code plugin ecosystem
  today?** 50 plugins? 500? 5000? Roughly determines Phase 3
  economics.
- **Skills vs plugins — are they the same market or different?** If
  skill authors and plugin consumers are different people, positioning
  matters.
- **Should Griffith aim to be an individual-developer tool (CLI you
  run) or an ecosystem-infrastructure play (Observatory) or an
  embedded-in-marketplace thing (GitHub Action / marketplace
  integration)?** These have different economics and different proof
  points.

## Immediate next actions (proposed)

Not a commitment — just the list so we don't lose it:

1. **Try the wrapper on a real "should I install this" decision.**
   Lowest cost, answers own-use-case validation. 10 minutes.
2. **File superpowers PR** (or publish audit report). Decide framing:
   contributing to superpowers vs pitching Griffith. ~1-2 hours.
3. **Decide on trailofbits action.** Likely a report, not a PR.
4. **Outreach post** to r/ClaudeAI or equivalent asking about audit
   demand. 30 minutes + whatever responses come back.
5. **Competition search.** 1 hour.

Ideally 1, 4, 5 happen before more code gets written. 2 and 3 are
independent and can happen any time.

## Update 2026-04-20 (post-first-audit): Path 4's PR half has a low ceiling

Ran Griffith against `obra/superpowers` (the flagship plugin in the
superpowers-marketplace ecosystem) to test the "contribute fixes
upstream" branch of Path 4. Two concrete findings — one about the
plugin, one about the contribution model.

**About the plugin.** Griffith's refined rules worked as designed: the
pre-refinement signal would have been 20 noisy findings (19
path-traversals + 1 bash-c-inline). Post-refinement, the output was
19 info capability-signals + 1 *real* critical finding (`bash -c
"$cmd"` with interpolated variable in `tests/claude-code/test-
helpers.sh`). Clean demonstration of the noise-reduction Phase 1.5 +
the AST refinement were supposed to deliver.

**About the contribution model — the more important finding.**
Superpowers' `CLAUDE.md` / `AGENTS.md` explicitly rejects exactly
the kind of contribution Griffith produces:

> Every PR must solve a real problem that someone actually
> experienced. "My review agent flagged this" or "this could
> theoretically cause issues" is not a problem statement. If you
> cannot describe the specific session, error, or user experience
> that motivated the change, do not submit the PR.

Their stated PR rejection rate is 94%. They close "slop" PRs from
agents within hours. Griffith's finding — technically correct, no
incident attached — is by their definition slop.

**Implication for Path 4:**

- The "post upstream PRs" half has a **low ceiling** for
  maintainers with a strong anti-slop posture. Expect closes, not
  merges, unless we're backing findings with real incidents.
- The "audit report / public" half is still viable and strong —
  doesn't require upstream coordination, demonstrates Griffith's
  value directly, respects a project's posture without asking for
  their cooperation.
- **Griffith's primary value is consumer-facing, not author-facing.**
  A pre-install audit tool for someone deciding whether to install
  matters; a post-install contribution-generator for someone who
  already ships the plugin matters less.

**Implication for the product question:** this sharpens the positioning.
"Tool that helps plugin *consumers* decide what to install" is a
cleaner thesis than "tool that helps plugin *authors* ship safer
code." The two audiences have different needs:

- **Consumer:** wants pre-install audit, context cost estimate,
  security triage, discovery help. Griffith does most of this today.
- **Author:** wants self-audit before publishing (similar), OR
  outbound signal that their plugin meets quality bars (Observatory).
  The author use case today is weak because they already know their
  own code.

The consumer thesis is where Phase 2 (Runtime Monitor) and the
skills-first pivot (Path 2) actually compound — both are
consumer-oriented. Observatory is consumer-facing too (browse +
choose) even though it has author-facing side effects.

Adjust the decision table accordingly: strong demand signal →
skills-first consumer MVP. Weak signal → stop.

**First audit report shipped:**
`docs/audits/2026-04-20-superpowers.md` — Griffith vs obra/superpowers.
Becomes the template for future audit reports if we keep running this
pattern.

## Update 2026-04-21: first external engagement signals

Two small positive data points came in the day after the PMF
brainstorm was written. Neither is conclusive, but they're the first
evidence that anyone besides Michael interacts with Griffith's
output.

**Upstream PR merged.** The Pillow CVE floor bump filed to
`EveryInc/compound-engineering-plugin` (derived from Griffith's
`--sca` findings during the audit-plugin wrapper development) was
accepted and merged. Matters because: it's a concrete case where
Griffith's output produced a contribution a reputable upstream was
willing to take. It's also an existence proof for Path 4 — even
after the superpowers contribution-policy finding said "don't send
review-agent PRs upstream," there are maintainers who DO take PRs
like this. The variable is the upstream's posture, not Griffith's
output quality.

**First external star on `GruntworkAI/gruntwork-griffith`.** One
person outside the author's own identity starred the repo. Tiny by
any absolute measure, but the count went from 0 to 1, which is the
number that actually matters for the "am I the only one who cares"
question.

**How this updates the decision table:**

| Signal strength | Previous read | Updated read |
|---|---|---|
| Upstream interest | Unknown | At least one upstream takes Griffith-sourced PRs |
| External awareness | Unknown | At least one external viewer starred the repo |

Still not enough to justify investing in Phase 2 (Runtime Monitor)
or Phase 3 (Observatory). But enough to keep Path 4 alive
(continued opportunistic audit reports + upstream contributions
where maintainer posture welcomes them) without it feeling like
shouting into the void.

**Recommended posture shift:** continue Path 4 as a low-cost
signal-gathering exercise. Each audit + each PR + each star is
another data point. Revisit the PMF brainstorm with the accumulated
data in ~30 days — if the count of external engagements has grown
meaningfully, re-open the skills-first MVP option (Path 2). If it's
plateaued at 1-2, the signal is "useful for me, maybe a few others,
not a product" and Phase 2/3 should stay deferred.

## Update 2026-04-28: audit corpus growing + positioning sharpens

A week into the lightweight Path 4 cadence, two things have come into
focus.

**Audits accumulating into a real corpus.** Three published audits
now live in `docs/audits/`:

- `2026-04-20-superpowers.md` — single popular plugin, 1 critical
  test-scoped finding, 20 info signals
- `2026-04-27-trailofbits-skills-curated.md` — 28-plugin federated
  marketplace, completely clean (4 info, 0 CVEs)
- `2026-04-28-bmad-method.md` — 2 plugins / 39 skills / 1,044-file
  repo, 0 actionable security findings + 19 dev-dep CVEs framed as
  build-tooling-only (not end-user runtime risk)

Combined audit count: ~33 plugins across 4 marketplaces. That's
enough data to start drawing ecosystem-level observations:

- Most plugins are clean. The signal-to-noise of the Claude Code
  plugin ecosystem (at the slice we've sampled) is good.
- The rare real findings are usually subtle. Superpowers' one
  critical was a test-scoped shell-injection antipattern, not a
  user-facing exploit. BMAD's CVEs were all in dev-dep build chains.
- Federated marketplace handling works. BMAD surfaced a Griffith
  bug (plugin-name resolution when `source: "./"`); fix tracked at
  `.claude/work/followups/marketplace-plugin-name-resolution.md`.

**Positioning sharpens: static analysis vs AI security theater.**
The community-pressure context that surfaced during the superpowers
audit (94% PR rejection rate, explicit "your review agent flagged
this isn't a problem statement" policy) is the bigger story.
Open-source maintainers are flooded with LLM-generated security
"reviews" that hallucinate findings, fabricate CVE IDs, and demand
attention. Maintainer trust in agent-sourced contributions is at a
floor.

Griffith's positioning as a deterministic, reproducible, source-cited
static analyzer is **structurally distinct** from that slop wave —
and that distinction is now the most compelling thing about the
project, not a footnote. The audits already document this implicitly
(citing rule names, line numbers, reproducible commands). Making it
explicit in:

- The Griffith README (a "How Griffith differs from AI security
  review" section)
- Every PR/issue Griffith findings produce (a slop-aware template
  that names the problem upfront)
- Public-facing posts (the framing should be the thesis, not buried
  in the methodology section)

This positioning shift is independent of the PMF outcome. Even if
Griffith never grows past Michael's personal use, distinguishing
deterministic tooling from review-agent output is a real public
service. If Griffith does scale, this becomes the pitch.

**Updated decision-table read:**

| Signal | 2026-04-21 | 2026-04-28 |
|---|---|---|
| External upstream interest | 1 merged PR | 1 merged PR + 1 actionable issue queued (BMAD dev-dep CVEs) |
| External awareness | 1 star | 1 star + audits referenced internally |
| Aggregate audit corpus | 1 plugin | 33 plugins / 3 publishable reports |
| Positioning clarity | "Plugin Observatory" | "Deterministic alternative to AI security theater" |

**Posture for next 30 days:**

- Continue Path 4: opportunistic audits when interesting plugins
  surface, file respectful issues only when findings are real and
  actionable.
- File the BMAD dev-dep-CVE issue using the slop-aware PR template
  (drafted at `.claude/work/drafts/2026-04-28-bmad-issue.md`).
- Draft the public post (Tier C from the engagement-signal triage)
  with the slop-distinction framing as the thesis. Substack canonical
  + HN/Reddit distribution if/when ready.
- Revisit this brainstorm at the 30-day mark (~2026-05-20). If
  external engagement has compounded meaningfully — multiple
  ecosystem people referencing Griffith, audits getting cited
  externally, plugin maintainers reaching out — re-open Path 2
  (skills-first MVP) seriously. If plateaued, hold.

## Sources

- Current design doc: `docs/design.md` (Phases 1-3 + business model)
- Current state: Phase 1 + 1.5 shipped (430 tests, 5 merged PRs in
  this session)
- Session context: long conversation on 2026-04-20 ending in this
  strategic reflection
- Related followups: `.claude/work/followups/` (6 items, all
  trigger-gated)
- First audit report: `docs/audits/2026-04-20-superpowers.md`
- superpowers' contribution posture:
  https://github.com/obra/superpowers/blob/main/AGENTS.md
