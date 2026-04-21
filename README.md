<p align="center">
  <img src="docs/img/griffith-logo-web.jpg" alt="Griffith — Plugin Observatory for Claude Code" width="720">
</p>

# Griffith

> Plugin Observatory for Claude Code

Griffith helps you evaluate Claude Code plugins before installing them — and re-audit them after. Named after the [Griffith Observatory](https://griffithobservatory.org/) in Los Angeles.

**Status:** Phase 1 + Phase 1.5 shipped. Core analyzer, dependency analyzer, and supply-chain (SCA) scan work end-to-end against real plugins. AST-based security rule refinement ships alongside the regex ruleset. `compare` and `scan-installed` remain stubs. Phase 2+ is an open product question — see [the PMF brainstorm](docs/brainstorms/2026-04-20-griffith-pmf-question.md).

## What it does

Griffith runs static analysis on a plugin's source tree and produces a structured report across five dimensions:

| Analysis | What it answers |
|----------|-----------------|
| **Inventory** | What components does this plugin contain? (agents, commands, skills, hooks, MCP servers, personas, templates) |
| **Security** | What risky patterns are in the code? 25 YAML regex rules + 6 AST rules. Capability signals at `info`; stricter context-aware rules (subprocess shell-true, dynamic command, bash -c interpolation, dynamic path traversal, dynamic eval/exec) stack on top at higher severities. |
| **Footprint** | What's the context cost? Always-on baseline + on-demand max, efficiency rating from excellent to excessive. |
| **Architecture** | What pattern does this plugin follow? (agent-heavy, skill-first, mcp-based, hybrid) + recommendations. |
| **Dependencies** | What packages does this plugin bring in? Tier 1 inventory across npm, PyPI, and more. With `--sca`, Tier 2 osv-scanner CVE lookup. |

## Installation

```bash
git clone https://github.com/GruntworkAI/gruntwork-griffith
cd gruntwork-griffith
poetry install
poetry run griffith --help
```

For `--sca` supply-chain analysis, also install [osv-scanner](https://github.com/google/osv-scanner):
```bash
brew install osv-scanner  # or see osv-scanner install docs for other platforms
```

Packaging for `pipx install griffith` remains a followup.

## Quick Start

```bash
# Analyze a plugin from a git URL (clones to temp dir, analyzes, cleans up)
poetry run griffith analyze https://github.com/EveryInc/every-marketplace

# Analyze an already-installed plugin (post-install re-audit)
poetry run griffith analyze ~/.claude/plugins/cache/every-marketplace/compound-engineering/2.67.0

# Analyze a local dev copy
poetry run griffith analyze ./my-plugin

# GitHub shorthand
poetry run griffith analyze obra/superpowers

# JSON output for programmatic consumption (LMF wrapper, CI, etc.)
poetry run griffith analyze ./my-plugin --json | jq

# Supply-chain scan with CVE lookup (requires osv-scanner on PATH)
poetry run griffith analyze ./my-plugin --sca

# Broader (noisier) security rules
poetry run griffith analyze ./my-plugin --strict
```

## Example output

Excerpt from auditing a real plugin (`obra/superpowers 5.0.7`; full report at [docs/audits/2026-04-20-superpowers.md](docs/audits/2026-04-20-superpowers.md)):

```
Plugin: superpowers
  griffith 0.1.0 | schema 0.1 (unstable)

Inventory
  agents       1   commands    3   skills    14   hooks    4
  mcp_servers  0   personas    0   templates  0
  files: 87    lines: 14,834

Security  risk: critical  (21 finding(s))
  critical (1)
    tests/claude-code/test-helpers.sh:19  bash-c-dynamic-interpolated
      bash -c argument contains dynamic shell expansion — runtime-
      controlled inputs can enable command injection.
  info (20)   — capability signals; not alarming on their own
    19 × path-traversal in tests/  (static ../.. — stricter
    path-traversal-dynamic-{js,shell} rules did not fire)
    1 × bash-c-inline at the same line as the critical finding

Footprint  efficiency: good
  baseline:    530 tokens
  on-demand:   3,863 tokens
  primary driver: skills

Architecture  pattern: skill-first
  - No MCP servers — low always-on context cost.
  - 4 hook files — execute outside model context but can shell out.

Dependencies
  npm: 1 package
  SCA: 0 known vulnerabilities (osv-scanner 2.3.5)
```

The post-refinement output shows Griffith's "additive-never-silence" rule posture: capability signals stay at `info`; stricter context-aware rules (`bash-c-dynamic-interpolated` here, `subprocess-shell-true`, `path-traversal-dynamic-*`, etc.) surface the real concerns at higher severities.

## Two input workflows

Griffith accepts URLs and local paths as equal first-class inputs. They serve different workflows:

| Input | Use case |
|-------|----------|
| **Git URL / GitHub shorthand** | Pre-install vetting — "should I install this plugin?" Clones into a hardened temp dir, analyzes, cleans up. |
| **Local path** | Point-in-time re-audit of an installed plugin — "what does this plugin on my machine currently contain?" Catches drift from updates, inadvertent edits, or compromised upstream. |

## Threat model

Griffith itself clones and reads untrusted plugin content. Defenses built in:

- **Hardened git clone** — `--depth 1 --no-tags --no-recurse-submodules` plus `filter.lfs.smudge=`, `core.symlinks=false`, `core.hooksPath=/dev/null`, `protocol.{file,ext}.allow=never`, empty `HOME`, scrubbed env (no `SSH_AUTH_SOCK` / `GIT_ASKPASS` / `GIT_SSH_COMMAND`), 120s timeout.
- **Refused protocols** — `file://` and `ssh://` rejected.
- **Symlink refusal** — `os.walk(followlinks=False)`; symlinks recorded but content never read. Realpath containment check on all walks.
- **YAML safe_load** — no `!!python/object/apply` RCE path.
- **Size & file-count caps** — 2 MB per file, 10,000 files per plugin.
- **ReDoS-safe scanning** — `regex` library with per-file wall-clock timeout; 16 KB line cap.
- **AST parse hardening** — reduced `sys.setrecursionlimit` during untrusted-source parsing so deeply-nested expressions can't blow the C stack. Two-stage exception contract (parse-stage + alias-walk-stage) surfaces cleanly to callers.
- **No matched-byte leaks** — `SecurityFinding` carries `rule_id + file + line + message` only, never the matched content.
- **Untrusted-field tagging** — JSON output lists every field derived from plugin content in `untrusted_fields[]` so downstream LLM consumers can render them inside an instruction-neutral envelope.
- **Bounded `meta.ast_parse_failures`** — adversarial plugins with many broken files can't grow the meta field unboundedly.

See [docs/design.md](docs/design.md) for the full design.

## JSON output contract

The JSON report is the contract for downstream tools (notably the LMF `/run-audit-plugin` wrapper skill). Schema is explicitly **v0.1 and unstable** — consumers should read `schema_version` before unpacking. See [docs/json-schema.md](docs/json-schema.md) for the current shape.

## Development

```bash
# First-time setup
poetry install

# Run tests
poetry run pytest

# Only offline tests (skip real-network clone test)
poetry run pytest -m "not network"

# Regenerate binding snapshots after an intentional change (prints
# to stderr when a snapshot is rewritten — not stdout)
GRIFFITH_REGENERATE_SNAPSHOTS=1 poetry run pytest tests/test_security.py

# Run Griffith against itself
poetry run griffith analyze .
```

The project has **430 tests** across the analyzer, schema, scanner, AST rules, dependencies, and snapshot layers. Three real-plugin fingerprint snapshots (`security-traps-plugin`, `lastmilefirst-0.14.0`, `compound-engineering-2.67.0`) gate every run.

## Why Griffith?

The Claude Code plugin ecosystem lacks quality infrastructure that mature ecosystems have:

| Ecosystem | Quality Tools |
|-----------|--------------|
| npm | Download counts, vulnerability scanning, bundle size |
| VS Code | Ratings, reviews, verified publishers |
| **Claude Plugins** | GitHub stars only |

Griffith's Phase 1 + 1.5 address the static-analysis gap. Whether Griffith should grow into the full Observatory design (runtime tracking + public aggregation + business model) is an open product question tracked in [the PMF brainstorm](docs/brainstorms/2026-04-20-griffith-pmf-question.md).

## Roadmap

- **Phase 1** (shipped): Static analyzer CLI — inventory, security, footprint, architecture.
- **Phase 1.5** (shipped): Dependencies (Tier 1 + Tier 2 osv-scanner SCA); federated-marketplace detection; AST-based security rule refinement with additive-never-silence design; fingerprint-snapshot integration tests; LMF `/run-audit-plugin` wrapper consumes the JSON contract.
- **Phase 2** (open / gated on PMF validation): Runtime monitor — local usage tracking, utilization / ROI reports.
- **Phase 3** (open / gated on Phase 2): Public observatory — aggregated data + web UI + opt-in telemetry.

Before Phase 2 or Phase 3 get built, the product question — *does anyone besides the author want this?* — needs concrete evidence. See [the PMF brainstorm](docs/brainstorms/2026-04-20-griffith-pmf-question.md) for decision framing, cheap investigation paths, and the first published audit report.

## Documentation

- [Design Document](docs/design.md) — original architecture and roadmap
- [JSON Schema](docs/json-schema.md) — output contract for programmatic consumers
- [PMF Brainstorm](docs/brainstorms/2026-04-20-griffith-pmf-question.md) — current strategic question on Phase 2 / 3
- [Audit Reports](docs/audits/) — published Griffith evaluations of real plugins
- [Phase 1 Plan](.claude/work/plans/phase-1-analyzer-mvp.md) — original build plan
- [Phase 1.5 Plan](.claude/work/plans/phase-1.5-dependency-analyzer.md) — dependency analyzer build plan
- [Security Rules](rules/security_patterns.yaml) — YAML regex rule catalog
- [AST Rules](src/griffith/analyzer/ast_rules.py) — Python AST-based rule implementations
- [Followups](.claude/work/followups/) — trigger-gated deferred enhancements

## License

MIT

---

*Built by [Gruntwork.ai](https://gruntwork.ai)*
