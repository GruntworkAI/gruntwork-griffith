---
audit_date: 2026-04-27
plugin: skills-curated
plugin_repo: https://github.com/trailofbits/skills-curated
plugin_shape: federated marketplace
plugins_audited: 28
griffith_version: 0.1.0
griffith_hardening_version: 1
osv_scanner_version: 2.3.5
auditor: Griffith (gruntwork-griffith)
report_type: consumer pre-install audit
---

# Griffith audit — `trailofbits/skills-curated`

## TL;DR

`trailofbits/skills-curated` is exceptionally clean. 28 plugins
audited end-to-end via Griffith's federated-marketplace handling.
**Zero critical, high, medium, or low findings across the entire
marketplace.** Four `info`-level capability signals (all
`skill-uses-webfetch`, all expected for the skills they tag) and
zero CVEs across the one Python dependency.

| Dimension | Result |
|---|---|
| Plugins audited | 28 |
| Critical / high / medium / low findings | **0** |
| Info findings (capability signals) | 4 |
| CVE count | 0 |
| Architecture pattern (most common) | skill-first (26/28) |
| Context-cost rating | excellent (28/28) |

## Why this report exists

Griffith is a static-analysis tool that evaluates Claude Code plugins
before installation. The motivating question for any consumer:
*can I install this safely, and what will it cost me in context
budget?*

This report is published as a third-party consumer audit. No PR or
issue was filed against `trailofbits/skills-curated` because there
are no findings that would warrant a contribution. The point of
publishing it here is to document the result so other Claude Code
users evaluating the marketplace can reference an independent
analysis.

This is also the first real-world test of Griffith's
federated-marketplace handling at this scale — 28 distinct plugin
repos cloned and audited in one `griffith analyze` invocation.

## Marketplace shape

`trailofbits/skills-curated` is a federated Claude Code marketplace.
Its `.claude-plugin/marketplace.json` enumerates 28 plugins, each
hosted as a separate component within the marketplace tree
(skills-only design). When Griffith analyzes the marketplace URL, it
walks each plugin and produces an aggregated report.

The 28 plugins fall into three loose groupings:

- **OpenAI-branded skills** (15): `openai-cloudflare-deploy`,
  `openai-develop-web-game`, `openai-doc`, `openai-gh-address-comments`,
  `openai-gh-fix-ci`, `openai-jupyter-notebook`,
  `openai-netlify-deploy`, `openai-pdf`, `openai-playwright`,
  `openai-screenshot`, `openai-security-best-practices`,
  `openai-security-ownership-map`, `openai-security-threat-model`,
  `openai-sentry`, `openai-spreadsheet`, `openai-yeet`
- **Security/research tools** (~6): `security-awareness`,
  `x-research`, `ffuf-web-fuzzing`, `wooyun-legacy`,
  `ghidra-headless`, `scv-scan`
- **General-purpose** (~7): `humanizer`, `skill-extractor`,
  `planning-with-files`, `last30days`, `react-pdf`,
  `python-code-simplifier`

## Findings inventory

| Severity | Count | Plugins affected |
|---|---|---|
| critical | 0 | — |
| high | 0 | — |
| medium | 0 | — |
| low | 0 | — |
| info (capability) | 4 | `x-research` (3), `security-awareness` (1) |

### The four info findings

All four are `skill-uses-webfetch` — Griffith's capability signal that
records "this skill calls the WebFetch tool." Severity is intentionally
`info` because WebFetch on its own is not a vulnerability; it's a
capability the skill needs to do its stated job.

| File | Line | Plugin | Notes |
|---|---|---|---|
| `skills/x-research/SKILL.md` | 18 | x-research | Research skill — WebFetch is core function |
| `skills/x-research/SKILL.md` | 134 | x-research | Same skill, secondary mention |
| `skills/x-research/SKILL.md` | 145 | x-research | Same skill, tertiary mention |
| `skills/security-awareness/SKILL.md` | 12 | security-awareness | Security skill (likely fetches threat advisories) |

These are exactly the kind of signals Griffith's
"additive-never-silence" rule design is meant to surface: each
network capability is recorded at `info`, with stricter context-aware
rules layered above for cases that *do* warrant escalation. None of
those stricter rules fired here.

## Dependencies

- 27 of 28 plugins have **zero external dependencies** (no
  `package.json`, no `requirements.txt`, no `pyproject.toml`).
- 1 plugin has a single Python dependency:
  - `x-research`: `httpx>=0.27` in
    `skills/x-research/scripts/pyproject.toml`
  - osv-scanner reports zero known vulnerabilities for httpx ≥0.27.

## Context cost (footprint)

All 28 plugins rated `excellent` on context-cost efficiency:

- The vast majority are minimal: 1 skill + 1 file. A skill's
  "always-on" cost in context is only its description (~20 tokens);
  the skill body loads only when invoked.
- Largest plugin is `last30days` at 19 files; still rated
  `excellent` on baseline.
- Architecture patterns: 26 skill-first, 1 hybrid
  (`planning-with-files`, which has a hook), 1 agent-heavy
  (`python-code-simplifier`).

A user installing the entire marketplace would pay essentially zero
always-on context cost — every skill is description-only at baseline.

## Why this looks the way it does

The clean result is consistent with how `trailofbits/skills-curated`
is curated:

1. **Each plugin is intentionally narrow.** Most are 1 skill, 1
   file. Minimum surface area means fewer places for risky patterns
   to live.
2. **No checked-in dependencies.** 27 of 28 plugins are pure
   markdown/instruction content. Only `x-research` depends on an
   external Python package, and that's a current, well-maintained
   library.
3. **No hooks executing shell commands.** Only `planning-with-files`
   has a hook, and it didn't trigger any of Griffith's
   subprocess-execution rules.
4. **The curation gate is real.** This is `trailofbits/skills-curated`
   — a security-focused organization curating skills. The result
   matches the brand promise.

## Comparison to other audits

For context, Griffith's recent audits of other marketplaces /
plugins:

| Target | Plugins | Critical | High | Info | CVEs |
|---|---|---|---|---|---|
| **trailofbits/skills-curated** (this audit) | 28 | 0 | 0 | 4 | 0 |
| `obra/superpowers` (single plugin) | 1 | 1 | 0 | 20 | 0 |
| `EveryInc/compound-engineering` v2.68.1 | 1 | 0 | 0 | 2 | 2 |
| `lastmilefirst` 0.14.0 | 1 | 0 | 8 (`subprocess-in-hooks` capability signals) | 4 | 0 |

`trailofbits/skills-curated` is the cleanest of the marketplaces
Griffith has audited so far, by a considerable margin.

## Methodology

Audit produced by:

```bash
griffith analyze https://github.com/trailofbits/skills-curated --sca --json
```

Griffith clones the marketplace into a hardened temp dir
(`--depth 1 --no-tags --no-recurse-submodules`, env scrubbed,
`core.symlinks=false`, `core.hooksPath=/dev/null`), enumerates the
federated plugins per `marketplace.json`, walks each plugin tree
(default-skipping `node_modules/`, `.venv/`, `vendor/`, `.git/`,
etc.), runs the regex + AST security rule catalog, builds a Tier 1
dependency manifest, and runs osv-scanner Tier 2 for CVE lookup.

Griffith version `0.1.0`; hardening version `1`; osv-scanner
`2.3.5`. Schema is explicitly `v0.1, unstable` — consumers should
read `schema_version` before depending on the JSON shape.

## What this report is and isn't

**Is:** An independent third-party static-analysis pass on the
marketplace. Useful for someone evaluating whether to install
plugins from `trailofbits/skills-curated` or use it as a reference
for what a clean marketplace looks like.

**Isn't:**

- A comprehensive security audit. Griffith is one tool; manual
  review and threat modeling cover dimensions Griffith does not.
- A behavioral evaluation. Griffith doesn't execute the plugins or
  evaluate the quality of skill output.
- An endorsement. "Clean" by Griffith's static-analysis criteria
  doesn't guarantee the plugins do what they claim or fit your use
  case.

## Related

- Griffith: https://github.com/GruntworkAI/gruntwork-griffith
- Trailofbits skills-curated: https://github.com/trailofbits/skills-curated
- Prior audit (single plugin): `docs/audits/2026-04-20-superpowers.md`
- Griffith's federated-marketplace detection: shipped in commit
  `c2439ce` as part of Phase 1.5
