---
audit_date: 2026-04-28
plugin: BMAD-METHOD
plugin_repo: https://github.com/bmad-code-org/BMAD-METHOD
plugin_shape: federated marketplace (2 plugins)
plugins_audited: 2
griffith_version: 0.1.0
griffith_hardening_version: 1
osv_scanner_version: 2.3.5
auditor: Griffith (gruntwork-griffith)
report_type: consumer pre-install audit
---

# Griffith audit — `bmad-code-org/BMAD-METHOD`

## TL;DR

BMAD-METHOD ("Breakthrough Method of Agile AI-driven Development")
is a Claude Code marketplace with two plugins (`bmad-pro-skills`,
`bmad-method-lifecycle`) totaling 39 skills. Static-analysis
findings are clean — **zero critical, high, medium, or low security
findings** across the entire 1,044-file repo. Twenty-four info-level
capability signals, all in non-plugin paths (test fixtures, build
tooling, website infrastructure).

The notable finding is **19 CVEs in dev dependencies** (5 high + 14
medium), concentrated in the build/SSG toolchain that powers BMAD's
documentation site (vite, astro, picomatch, postcss, markdown-it,
yaml, others). These dependencies are **not pulled by end users
installing BMAD's skills** — Claude Code reads the plugin
markdown/instruction content; it does not execute npm
`devDependencies`. The CVEs matter for BMAD contributors and CI, not
for someone running `/plugin install bmad-pro-skills@...`.

| Dimension | Result |
|---|---|
| Plugins audited | 2 |
| Total skills declared | 39 (11 + 28) |
| Critical / high / medium / low security findings | **0** |
| Info security findings | 24 |
| CVE count (dev deps) | 19 (5 high + 14 medium) |
| CVE count affecting end-user install | **0** (all CVEs are dev/build deps) |
| Repo size | 1,044 files / 180,846 lines |

## Marketplace shape

`.claude-plugin/marketplace.json` declares two plugins, both with
`source: "./"` (i.e., both point at the repo root):

| Plugin | Skills declared |
|---|---|
| `bmad-pro-skills` | 11 (advanced prompting, agent management) |
| `bmad-method-lifecycle` | 28 (full lifecycle: analysis, planning, architecture, implementation) |

A user installing one of these via `/plugin install
bmad-pro-skills@bmad-method-marketplace` clones the repo and Claude
Code reads the listed skills. The repo also contains tooling, tests,
and a documentation website — none of which is part of the plugin
surface delivered to end users.

### Griffith caveat surfaced by this audit

When a marketplace declares multiple plugins from the same `./`
source, Griffith currently labels both with `plugin.name = "repo"`
instead of the explicit `name` field from the marketplace.json entry.
Both BMAD plugins thus appear as `"repo"` in the JSON output. This
is a Griffith bug, not a BMAD issue; tracked as a followup in the
Griffith repo (`.claude/work/followups/marketplace-plugin-name-resolution.md`).
The audit findings themselves are unaffected — the file-walk and
finding emission are correct; only the display name is wrong.

## Findings inventory (security rules)

| Severity | Count | Rule | Where |
|---|---|---|---|
| critical | 0 | — | — |
| high | 0 | — | — |
| medium | 0 | — | — |
| low | 0 | — | — |
| info | 22 | `path-traversal` (capability signal) | tests/, tools/, website/ |
| info | 2 | `oversized-file-skipped` | (large files, content not scanned) |

**Where the 22 path-traversal info findings live:**

| Location | Count | What's there |
|---|---|---|
| `test/test-rehype-plugins.mjs` | 5 | Test fixtures using relative paths |
| `tools/installer/*.js` | 5 | CLI installer build code |
| `website/...` | 2 | Static-site-generator content paths |

None of the 22 findings are in actual plugin skill content. The
stricter `path-traversal-dynamic-{js,shell,python}` rules did not
fire — these are all static `../..` strings in conventional
locations, not runtime-concatenated traversal.

## Dependency analysis

`package.json` at the repo root declares many `devDependencies`
backing BMAD's website (Astro-based docs site) and CLI installer
tooling. Tier 1 inventory:

- **Ecosystem:** npm
- **Total declared packages:** 33 (across `package.json` +
  lockfile resolution)

### CVE summary (Tier 2, via osv-scanner 2.3.5)

19 CVEs across the 33-package dependency tree:

| Severity | Count |
|---|---|
| critical | 0 |
| high | 5 |
| medium | 14 |
| low | 0 |

**High-severity CVEs:**

| CVE | Package | Notes |
|---|---|---|
| GHSA-737v-mqg7-c878 | `defu` | Prototype pollution in deep-merge utility |
| GHSA-rf6f-7fwh-wjgh | `flatted` | Inefficient ReDoS pattern |
| GHSA-c2c7-rcm5-vvqj (×2) | `picomatch` | ReDoS in glob matcher (transitive) |
| GHSA-p9ff-h696-f583 | `vite` | URL traversal in dev server |

**Medium-severity CVEs (sample):** `astro` (×2), `brace-expansion`
(×3), `h3` (×2), `markdown-it`, `picomatch` (×2), `postcss`,
`smol-toml`, `vite`, `yaml`.

### Crucial framing: are these CVEs end-user risks?

**No, not for someone installing BMAD's plugins via Claude Code.**

When a user runs `/plugin install bmad-pro-skills@bmad-method-marketplace`,
Claude Code:

1. Clones the repo (or fetches via the marketplace mechanism)
2. Reads the `.claude-plugin/plugin.json` and the listed
   `skills/*/SKILL.md` files
3. Loads the markdown content into the model context

It does **not** install npm dependencies. It does **not** execute
`vite`, `astro`, or any of BMAD's build tooling. The CVE-bearing
dependencies live in `package.json` and are pulled only when
someone runs `npm install` to build BMAD's docs or develop on the
project.

**Where these CVEs matter:**

- BMAD contributors running `npm install` locally
- BMAD's CI pipeline (if it builds the website)
- Any third-party tooling that clones BMAD and runs the build

**Where they do not matter:**

- End users installing BMAD plugins through Claude Code
- The runtime behavior of the plugins themselves

This is an honest distinction worth preserving in the report.
Static dependency scanning at the repo level finds CVEs Griffith
must surface; understanding their actual blast radius requires
context that Griffith doesn't (and shouldn't) infer.

## Context cost (footprint)

Both plugins rated `hybrid` architecture (skills + tooling), with
`info`-level risk from the capability signals. Footprint efficiency
ratings: both rated `excellent` despite the large overall repo
(because the plugin surface — only the listed skills — is small;
the tooling, tests, and website are not loaded into context).

A user installing either plugin pays the always-on cost of the
listed skill descriptions only (~20 tokens each):

- `bmad-pro-skills`: 11 skills × ~20 tokens ≈ 220 tokens baseline
- `bmad-method-lifecycle`: 28 skills × ~20 tokens ≈ 560 tokens baseline

Both well within the "low always-on context cost" range.

## What would warrant action

For BMAD maintainers (separate from Griffith's static-analysis
result):

1. **High-severity dev-dep CVEs (5)** — defu, flatted, picomatch,
   vite. Floor bumps on transitive deps may require updates to
   primary deps (astro, vite). Worth at least filing a tracking
   issue.
2. **Document the dev-deps-vs-runtime distinction** in BMAD's
   security posture so users running CVE scanners don't get
   misled. A short note in the README or SECURITY.md is enough.
3. **Optionally pin vite + astro versions** with up-to-date floors
   in `package.json` to make osv-scanner output cleaner.

For end users evaluating BMAD-METHOD via this audit:

- The plugins themselves are safe to install as far as Griffith
  can determine.
- The CVE noise in the npm dependency tree is real but does not
  affect plugin runtime.
- Verify the dev-dep distinction yourself if you're integrating
  BMAD into a build pipeline or running the site locally.

## Comparison to other audits

| Target | Plugins | Critical | High | Info | CVEs |
|---|---|---|---|---|---|
| `trailofbits/skills-curated` | 28 | 0 | 0 | 4 | 0 |
| `bmad-code-org/BMAD-METHOD` (this audit) | 2 | 0 | 0 | 24 | 19 dev-deps |
| `obra/superpowers` | 1 | 1 | 0 | 20 | 0 |
| `EveryInc/compound-engineering` v2.68.1 | 1 | 0 | 0 | 2 | 2 (Pillow) |

BMAD's footprint is unusual in that the repo bundles substantial
non-plugin content (build, docs, tests). The CVE count looks alarming
in isolation but reflects the website tooling, not the plugin
surface.

## Methodology

Audit produced by:

```bash
griffith analyze https://github.com/bmad-code-org/BMAD-METHOD --sca --json
```

Griffith clones the marketplace into a hardened temp dir, walks the
federated plugin set per `marketplace.json`, runs the regex + AST
security rule catalog, builds a Tier 1 dependency manifest, and runs
osv-scanner Tier 2 for CVE lookup.

Griffith version `0.1.0`; hardening version `1`; osv-scanner
`2.3.5`. Schema is explicitly `v0.1, unstable`.

## What this report is and isn't

**Is:** An independent third-party static-analysis pass on the
marketplace, distinguishing plugin-surface findings from build/dev
infrastructure findings.

**Isn't:**

- A behavioral evaluation of the plugins (Griffith doesn't execute
  them).
- A guarantee. Manual review and threat modeling cover dimensions
  Griffith does not.
- An endorsement or rejection. The CVE surface is real but largely
  out-of-band for end users; consumers should weigh the distinction
  for their own use case.

## Related

- Griffith: https://github.com/GruntworkAI/gruntwork-griffith
- BMAD-METHOD: https://github.com/bmad-code-org/BMAD-METHOD
- Prior audits: `docs/audits/2026-04-20-superpowers.md`,
  `docs/audits/2026-04-27-trailofbits-skills-curated.md`
- Griffith plugin-name-resolution bug surfaced here, tracked at
  `.claude/work/followups/marketplace-plugin-name-resolution.md`
