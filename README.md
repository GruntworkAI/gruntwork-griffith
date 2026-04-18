# Griffith 🔭

> Plugin Observatory for Claude Code

Griffith helps you evaluate Claude Code plugins before installing them — and re-audit them after. Named after the [Griffith Observatory](https://griffithobservatory.org/) in Los Angeles.

Status: **Phase 1 MVP shipped.** Core analyzer works end-to-end against real plugins; `compare` and `scan-installed` remain stubs for Phase 1.5.

## What it does

Griffith runs static analysis on a plugin's source tree and produces a structured report across four dimensions:

| Analysis | What it answers |
|----------|-----------------|
| **Inventory** | What components does this plugin contain? (agents, commands, skills, hooks, MCP servers, personas, templates) |
| **Security** | What risky patterns are in the code? (hook shell execution, credential refs, settings tampering, ReDoS-resistant regex scanner, 22 rules) |
| **Footprint** | What's the context cost? (always-on baseline + on-demand max, efficiency rating from excellent to excessive) |
| **Architecture** | What pattern does this plugin follow? (agent-heavy, skill-first, mcp-based, hybrid) + recommendations |

## Installation

```bash
git clone https://github.com/GruntworkAI/gruntwork-griffith
cd gruntwork-griffith
poetry install
poetry run griffith --help
```

Packaging for `pipx install griffith` is Phase 1.5.

## Quick Start

```bash
# Analyze a plugin from a git URL (clones to temp dir, analyzes, cleans up)
poetry run griffith analyze https://github.com/EveryInc/every-marketplace

# Analyze an already-installed plugin (post-install re-audit)
poetry run griffith analyze ~/.claude/plugins/cache/every-marketplace/compound-engineering/2.67.0

# Analyze a local dev copy
poetry run griffith analyze ./my-plugin

# GitHub shorthand works too
poetry run griffith analyze GruntworkAI/some-plugin

# Get JSON output for programmatic consumption (LMF wrapper, CI, etc.)
poetry run griffith analyze ./my-plugin --json | jq

# Turn on broader (noisier) security rules
poetry run griffith analyze ./my-plugin --strict
```

## Example output

Analyzing a real plugin:

```
╭─────────────────────────────────────────────────────────────╮
│ Plugin: lastmilefirst                                       │
│ source: ~/.claude/plugins/cache/gruntwork-marketplace/...   │
│ griffith 0.1.0 | schema 0.1 (unstable)                      │
╰─────────────────────────────────────────────────────────────╯

        Inventory
  agents             13
  commands           20
  skills             21
  hooks               7
  mcp_servers         0
  personas           13
  templates           6
  total files        80
  total lines    10,916

Security  risk: high  (10 finding(s))
  high (8)
    hooks/scripts/run.py:31 subprocess-in-hooks  ...
    ... +3 more
  info (2)
    hooks/scripts/session_start.py:277 hook-requires-gh-cli  ...

Footprint  efficiency: moderate
  baseline:        2,720 tokens (approx cl100k — not Claude's actual tokenizer)
  on-demand max:  12,609 tokens
  primary driver: agents
  breakdown: agents=1,300  commands=1,000  skills=420

Architecture  pattern: hybrid
  notes:
    - No MCP servers — low always-on context cost.
    - Contains 7 hook file(s) — audit via security scan.
  recommendations:
    - Balanced architecture — no obvious consolidation opportunity...
```

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
- **No matched-byte leaks** — `SecurityFinding` carries `rule_id + file + line + message` only, never the matched content.
- **Untrusted-field tagging** — JSON output lists every field derived from plugin content in `untrusted_fields[]` so downstream LLM consumers can render them inside an instruction-neutral envelope.

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

# Run griffith against itself
poetry run griffith analyze .
```

The project currently has **138 tests** across 7 modules.

## Why Griffith?

The Claude Code plugin ecosystem lacks quality infrastructure that mature ecosystems have:

| Ecosystem | Quality Tools |
|-----------|--------------|
| npm | Download counts, vulnerability scanning, bundle size |
| VS Code | Ratings, reviews, verified publishers |
| **Claude Plugins** | GitHub stars only |

Griffith fills this gap with static analysis today, plus runtime tracking and community intelligence in later phases.

## Roadmap

- **Phase 1** (shipped): Static analyzer CLI with inventory, security, footprint, architecture
- **Phase 1.5** (next): AST-based security rule refinement; `compare`; `scan-installed`; pipx packaging
- **Phase 2**: Runtime monitor (local usage tracking)
- **Phase 3**: Public observatory (opt-in aggregation + web UI)

See [docs/design.md](docs/design.md) for the full roadmap.

## Documentation

- [Design Document](docs/design.md) — full architecture and roadmap
- [JSON Schema](docs/json-schema.md) — output contract for programmatic consumers
- [Phase 1 Plan](.claude/work/plans/phase-1-analyzer-mvp.md) — the build plan that produced this MVP
- [Security Rules](rules/security_patterns.yaml) — what the scanner checks for

## License

MIT

---

*Built by [Gruntwork.ai](https://gruntwork.ai)*
