# Draft GitHub issue: BMAD-METHOD dev-dependency CVEs

**Status: DRAFT — for Michael's review before filing.**
**Target: https://github.com/bmad-code-org/BMAD-METHOD/issues/new**

## Pre-flight checklist before posting

BMAD's `CONTRIBUTING.md` requires:
- [ ] Search existing issues for similar reports
  ```
  https://github.com/bmad-code-org/BMAD-METHOD/issues?q=is%3Aissue+CVE+dev+dependency
  https://github.com/bmad-code-org/BMAD-METHOD/issues?q=is%3Aissue+vite+OR+astro+OR+picomatch
  ```
- [ ] Search closed issues + discussions for prior fixes/conversations
- [ ] If maintainers prefer a heads-up before larger conversations, consider Discord first (linked in their CONTRIBUTING.md)

This is an **issue** (FYI), not a PR — should land within their stated process. If they direct it to Discord instead, that's fine; move it.

---

## Suggested title

> Static-analysis report: 5 high + 14 medium CVEs in dev-dependency tree (build/website tooling)

---

## Suggested body

```markdown
## Static-analysis findings — not an LLM-generated review

I ran [Griffith](https://github.com/GruntworkAI/gruntwork-griffith), an open-source static analyzer for Claude Code plugins, against this repo on 2026-04-28. The findings below come from deterministic regex + AST rules and a Tier 2 osv-scanner pass — not from an LLM generating prose. Every CVE ID below is sourced from osv.dev; every finding is reproducible.

I'm aware open-source maintainers are getting flooded with AI-generated security PRs and issues that hallucinate findings. I've tried to make this distinct: no fabricated CVE IDs, no speculative claims, no invented vulnerabilities, no prose-style "concerns." Just the osv-scanner output and a precise scope statement.

**Reproduce:**
```bash
git clone https://github.com/GruntworkAI/gruntwork-griffith
cd gruntwork-griffith
poetry install
brew install osv-scanner   # or your platform equivalent
poetry run griffith analyze https://github.com/bmad-code-org/BMAD-METHOD --sca --json | jq '.reports[0].dependencies.sca.vulnerabilities'
```

**Full audit report:** [docs/audits/2026-04-28-bmad-method.md](https://github.com/GruntworkAI/gruntwork-griffith/blob/main/docs/audits/2026-04-28-bmad-method.md)

## Scope of the finding

**19 CVEs across the npm dependency tree** (5 high + 14 medium severity, per osv-scanner 2.3.5):

### High severity (5)

| CVE | Package | Notes |
|---|---|---|
| GHSA-737v-mqg7-c878 | `defu` | Prototype pollution in deep-merge utility |
| GHSA-rf6f-7fwh-wjgh | `flatted` | Inefficient regex / ReDoS pattern |
| GHSA-c2c7-rcm5-vvqj (×2) | `picomatch` | ReDoS in glob matcher (transitive) |
| GHSA-p9ff-h696-f583 | `vite` | URL traversal in dev server |

### Medium severity (14)

`astro` (×2), `brace-expansion` (×3), `h3` (×2), `markdown-it`, `picomatch` (×2), `postcss`, `smol-toml`, `vite`, `yaml`.

(Full list with osv-scanner output in the linked audit report.)

## Important framing: where these CVEs do and don't matter

These CVEs live in the **build/SSG dependency tree** that powers BMAD-METHOD's documentation website (`astro` + `vite` + assorted plugins) and the CLI installer tooling under `tools/`. They are **not pulled by end users installing BMAD plugins via Claude Code** — `/plugin install bmad-pro-skills@bmad-method-marketplace` reads the plugin's markdown/instruction content, it does not run `npm install`.

So:

- **Where these CVEs matter:** BMAD contributors running `npm install` locally; CI pipelines building the website; anyone running BMAD's installer tooling against an untrusted environment.
- **Where they don't matter:** End users installing the plugins via Claude Code.

I want to be honest about this scope: the CVE count alone is misleading without the runtime-vs-build distinction. The audit report makes this distinction explicit and recommends BMAD document it in your security posture so users running CVE scanners aren't misled.

## What might be worth doing (your call)

This is a **heads-up issue, not a fix demand**. Suggestions in order of effort:

1. **Document the dev-deps-vs-runtime distinction** in `SECURITY.md` or the README so users running their own CVE scans understand the scope. Lowest effort; high value.
2. **Floor-bump transitive deps** that show high-severity CVEs (`defu`, `flatted`, `picomatch`, `vite`) when you next touch `package.json`. May require coordinating updates to primary deps (`astro` etc.); doesn't need to be urgent.
3. **No action.** Defensible if you decide the CI / contributor-machine surface is acceptable.

I have no opinion on what you choose. The goal of this issue is to surface the data with enough context that you can decide.

## Why I'm filing this

I've been auditing Claude Code plugins with Griffith and publishing the reports. BMAD-METHOD's audit was the first I ran where the SCA pass surfaced real CVEs at the dev-dep layer. The numbers look alarming in isolation — "19 CVEs!" — and I wanted to surface them with the runtime-vs-build context attached so they don't get cited out of context.

Happy to discuss in Discord or here, whichever you prefer. If this would be more appropriate as a discussion thread or a SECURITY.md PR rather than an issue, just let me know and I'll move it.

— Michael
```

---

## Notes for posting

- Replace `— Michael` with whatever signature you prefer.
- If their search reveals an existing issue/discussion about dev-deps or CVEs, link it in the body and frame as additional data instead.
- Optional: ping a maintainer's Discord first per their CONTRIBUTING.md guidance if you want to test the waters before opening publicly.
- If they push back or close it as out-of-scope, that's a useful data point — feeds back into Path 4's signal-gathering even if the specific contribution doesn't land.
