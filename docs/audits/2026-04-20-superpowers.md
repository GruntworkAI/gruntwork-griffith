---
audit_date: 2026-04-20
plugin: superpowers
plugin_version: 5.0.7
plugin_commit: b557764
plugin_repo: https://github.com/obra/superpowers
griffith_version: 0.1.0
griffith_hardening_version: 1
osv_scanner_version: 2.3.5
auditor: Griffith (gruntwork-griffith)
report_type: consumer pre-install audit
---

# Griffith audit — `obra/superpowers` 5.0.7

## TL;DR

Superpowers is a well-structured Claude Code plugin. Architecture is
skill-first. Context footprint is efficient (530 baseline tokens). No
CVEs in its npm dependencies. Static analysis produces **one
actionable finding** worth noting in a test helper, plus informational
capability signals that are not concerning on their own.

| Dimension | Result |
|---|---|
| Risk tier (security) | critical (1 finding, test-scoped) |
| CVE count | 0 |
| Context-cost rating | good |
| Architecture pattern | skill-first |
| Component count | 1 agent, 3 commands, 14 skills, 4 hooks |
| Footprint: baseline | 530 tokens |
| Footprint: on-demand max | 3,863 tokens |

## Why this report exists

Griffith is a static-analysis tool that evaluates Claude Code plugins
before installation. The motivating question: *can I install this
safely, and what will it cost me in context budget?*

This report is published as-is — not submitted as a PR to the
upstream maintainer. The superpowers project has an explicit policy
against static-analysis-sourced contributions without incident
evidence (their `AGENTS.md` and `CLAUDE.md` reject "my review agent
flagged this" as a PR problem statement, and the project reports a
94% PR rejection rate). That policy is reasonable and this report
respects it: the one real finding is described so a user deciding
whether to install has the context, and the maintainer can
incorporate it on their own terms if they find it useful.

## Findings summary

21 total findings after Griffith's 2026-04-20 AST + regex refinement
pass. Breakdown:

| Severity | Count | Rule |
|---|---|---|
| critical | 1 | `bash-c-dynamic-interpolated` |
| info | 19 | `path-traversal` (capability signal) |
| info | 1 | `bash-c-inline` (capability signal) |

### The one critical finding

**File:** `tests/claude-code/test-helpers.sh:19`
**Rule:** `bash-c-dynamic-interpolated`
**Severity:** critical

**Pattern:** `bash -c "$cmd"` where `$cmd` is a shell-quoted string
built by interpolating the function's `$prompt` argument. If a caller
ever passes a `$prompt` containing a double-quote plus shell
metacharacters, the outer quote is closed, the subsequent text
becomes executable shell, and `bash -c` runs it.

**Context at the call site:**

```bash
run_claude() {
    local prompt="$1"
    local timeout="${2:-60}"
    local allowed_tools="${3:-}"
    local output_file=$(mktemp)

    local cmd="claude -p \"$prompt\""
    if [ -n "$allowed_tools" ]; then
        cmd="$cmd --allowed-tools=$allowed_tools"
    fi

    if timeout "$timeout" bash -c "$cmd" > "$output_file" 2>&1; then
        # ...
    fi
}
```

**Risk assessment (honest):**

- **In practice, this is test-only code.** `run_claude` is called
  from test scripts authored by the plugin's maintainers; `$prompt`
  is static test-fixture text in every observed call site. There's
  no evidence of an incident, and no obvious attack surface because
  no caller threads attacker-controlled input into `$prompt`.
- **The pattern is a shell antipattern** that's worth knowing about:
  building a command string with `"..."` and then re-evaluating it
  via `bash -c` defeats the safety of argv-based execution. If this
  helper ever gets reused in a context where `$prompt` is less
  tightly controlled, the pattern becomes exploitable without
  additional code changes.
- **Severity is "critical" because the rule fires on dynamic shell
  expansion inside `bash -c`,** which is the class of pattern
  shell-injection attacks use. The severity grade is the rule's
  judgment about the *pattern*, not an assertion that this specific
  call is exploitable today.

**Possible mitigation** (for the maintainer, not Griffith):

```bash
local args=(claude -p "$prompt")
[ -n "$allowed_tools" ] && args+=(--allowed-tools="$allowed_tools")
timeout "$timeout" "${args[@]}" > "$output_file" 2>&1
```

Passing args as an array avoids the build-string-then-re-parse
pattern. Whether this is worth changing is a maintainer call — test
code has a different risk profile than production hooks.

### Informational findings (capability signals)

The other 20 findings are informational — Griffith's "capability
signal" rules record that a pattern was seen without classifying it
as a finding to act on:

- 19 `path-traversal` matches — `../..` substrings in test shell
  scripts and test JS files. In every case these are test-fixture
  path manipulation (`path.join(__dirname, '../../skills/...')` in
  Node tests, `cd "$(dirname "$0")/.."` in shell test runners).
  **Griffith's stricter `path-traversal-dynamic-{js,shell}` rules
  (which would flag runtime-concatenated traversal) did not fire
  here** — these are all static paths that are correctly classified
  as safe.
- 1 `bash-c-inline` match — same line as the critical finding above;
  the capability signal always fires alongside the stricter rule so
  the pattern is visible even if the stricter rule were ever
  disabled.

These informational findings are the output of Griffith's
"additive-never-silence" design: the capability signal always fires
at `info`, and stricter context-aware rules stack on top. For a
consumer, info-level findings are reading-glasses for "here's where
this plugin does $X" — not an alert.

## Pre-refinement vs post-refinement noise reduction

Before Griffith's April 2026 AST + regex refinement (which this audit
uses), the same plugin would have produced:

| Severity | Count | Rule |
|---|---|---|
| high | 1 | `bash-c-inline` |
| medium | 19 | `path-traversal` |

That's 20 noisy findings the consumer would have had to triage
manually. Almost all of them were test-directory false positives.

Post-refinement: 20 of those become `info` (capability signals that
don't demand triage), and the one actionable pattern is correctly
elevated to `critical`. 20:1 noise-to-signal shift, correct direction.

This is the behavior the refinement was designed to produce. Seeing
it on a real plugin confirms the design is working outside the
planned fixtures.

## Inventory

| Component type | Count |
|---|---|
| agents | 1 |
| commands | 3 |
| skills | 14 |
| hooks | 4 |
| mcp-servers | 0 |
| personas / templates | 0 |
| other (tests, docs, scripts) | 65 |

Total: 87 files, 14,834 lines. The "unknown" bucket is mostly test
scaffolding and documentation that Griffith doesn't classify as a
Claude Code component type — not a concern.

## Footprint (context cost)

| Metric | Value |
|---|---|
| Baseline tokens (cl100k) | ~530 |
| On-demand max | ~3,863 |
| Primary driver | skills |
| Efficiency rating | good |

Baseline is the always-on context cost at session start. On-demand
max is what you'd pay if every command / skill got loaded in a single
session. Superpowers' baseline is low because skills contribute only
their description (~20 tokens each) to the always-on surface; the
skill body loads only when invoked.

## Architecture

**Pattern:** skill-first (14 skills, 3 commands, 1 agent).

Griffith's architecture observations:

- No MCP servers — low always-on context cost.
- 4 hook files — these execute outside the model's context (zero
  token cost) but can shell out. The one critical finding above is
  in a hook-adjacent test helper, not in a hook itself.

## Dependencies

| Ecosystem | Packages | CVEs |
|---|---|---|
| npm | 1 | 0 |

Single npm dependency in `package.json`; osv-scanner 2.3.5 reports no
known vulnerabilities. Clean.

## Methodology

This audit was produced by running:

```bash
griffith analyze <path-to-superpowers> --sca --json
```

Griffith is a static analyzer (no plugin execution) with these
disciplines relevant to this audit:

- **Symlink containment** — symlinked files would produce a critical
  finding instead of being scanned; none present here.
- **Long-line / ReDoS defense** — per-line regex with timeout.
- **AST-based security rules** for Python hook files (subprocess
  shell-true, dynamic command args, dynamic code exec, path
  traversal).
- **Additive-never-silence rule posture** — capability signals stay
  at `info`; stricter context-aware rules stack on top. Prevents a
  bug class where a refinement silently hides the signal that
  motivated the rule.
- **Tier 2 SCA** via osv-scanner on package manifests.

Griffith's current schema is `0.1 — unstable` and may change. This
report reflects Griffith 0.1.0 output on 2026-04-20.

## What this report is and isn't

**Is:** A consumer-facing evaluation for someone deciding whether to
install superpowers, with enough detail that a reader can judge the
one real finding's severity in their own context.

**Isn't:**

- A vulnerability disclosure. No novel exploit technique is published
  here; the pattern (`bash -c "$string"`) is widely documented as a
  shell antipattern.
- A PR against superpowers. The maintainers' contribution guidelines
  explicitly reject static-analysis-sourced contributions without
  incident evidence, and this report respects that policy.
- A comprehensive security audit. Griffith is one tool, focused on
  Claude Code plugin shape + a defined catalog of patterns. A
  thorough security review would include additional methods and
  manual review.

## Addendum (2026-04-25): SCA bug verification

On 2026-04-22, PR #3 fixed a silent false-negative in Griffith's
`--sca` invocation: `osv-scanner` skipped `.gitignore`'d subdirectory
lockfiles unless `--no-ignore` was passed. The original argv omitted
the flag.

Because this audit was produced on 2026-04-20 (pre-fix), the
**`0 CVEs` claim in the Dependencies section was reverified** against
superpowers v5.0.7 using the fixed Griffith code on 2026-04-25:

- Lockfile present at `tests/brainstorm-server/package-lock.json`
  (subdirectory — exactly the shape that triggered the bug elsewhere)
- Superpowers' root `.gitignore` does **not** exclude `tests/`
- `osv-scanner` correctly scans the lockfile both pre- and post-`--no-ignore`
  (63 dirs visited, 1 lockfile, 1 package, 0 vulnerabilities — identical
  output between the two invocations)

**Conclusion:** the bug did not affect this audit. The `0 CVEs` claim
was accurate at the time of publication and remains accurate.

(Generalized recheck of all published audits is tracked in
`.claude/work/followups/published-audit-sca-recheck.md`; superpowers
is the only published audit at this time.)

## Related

- Griffith: https://github.com/GruntworkAI/gruntwork-griffith
- Superpowers: https://github.com/obra/superpowers
- Superpowers' contribution posture (worth reading): https://github.com/obra/superpowers/blob/main/AGENTS.md
- Griffith's rule catalog: `rules/security_patterns.yaml` + `src/griffith/analyzer/ast_rules.py`
