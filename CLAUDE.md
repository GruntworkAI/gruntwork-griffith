# Griffith - Claude Code Plugin Observatory

## Archetype: Usable

## Overview

Griffith is a plugin evaluation and analytics system for the Claude Code ecosystem. Named after the Griffith Observatory in Los Angeles, it provides visibility into plugin quality, usage, and security.

## Architecture

Three-layer system (see `docs/design.md` for full details):

1. **Plugin Analyzer** — Static analysis before installation. **Shipped (Phase 1 + 1.5).**
2. **Runtime Monitor** — Usage tracking during sessions. *Future, gated on PMF validation.*
3. **Plugin Observatory** — Public aggregation service. *Future, gated on Phase 2.*

## Current state (2026-04)

**Phase 1 + 1.5 are shipped.** The next move is a deliberately open product question, not a planned build phase — see `docs/brainstorms/2026-04-20-griffith-pmf-question.md` for the strategic framing and the cheap investigations that gate Phase 2.

What works end-to-end:

- `griffith analyze <source>` — single-plugin and marketplace analysis (bundled, federated, mixed marketplaces all handled).
- Five analysis dimensions: inventory, security (regex + AST rules), footprint (token cost), architecture, dependencies (Tier 1 manifest enumeration + Tier 2 osv-scanner CVE lookup behind `--sca`).
- Hardened clone for URL inputs (env scrubbed, symlinks refused, size + file count caps, ReDoS-safe regex with timeout, AST parse hardening).
- Versioned JSON schema (`v0.1, unstable`) for downstream consumers.
- LMF `/run-audit-plugin` wrapper skill consumes the JSON contract.

What's still stubbed:

- `griffith compare plugin1 plugin2`
- `griffith scan-installed`

What's deferred pending PMF validation:

- Phase 2 (runtime monitor) and Phase 3 (public observatory).

## Tech Stack

- **Language**: Python 3.11+ (poetry env)
- **CLI**: Click 8.x
- **Token estimation**: tiktoken (`cl100k_base` — approximate; not Claude's tokenizer)
- **Output**: Rich (terminal) + JSON (programmatic)
- **Regex**: `regex` library (ReDoS-safe with per-line wall-clock timeout)
- **YAML**: PyYAML with `safe_load` only (refuses `!!python/object/apply`)
- **External CVE source**: osv-scanner 2.x (`brew install osv-scanner`) — invoked via subprocess with bounded stdout/stderr, scrubbed env, 120s timeout
- **Tests**: pytest 7.x with `pytest-timeout`, `pytest-cov`. Markers: `network` (osv.dev or real git clone), `adversarial` (defensive behavior against malicious inputs)
- **Lint/format**: ruff 0.1.x, black, mypy strict

## Project Structure

```
gruntwork-griffith/
├── src/griffith/
│   ├── __init__.py
│   ├── cli.py              # Click entry point + analyze/compare/scan-installed dispatch
│   ├── reporter.py         # Rich terminal + JSON rendering
│   ├── sanitize.py         # Sanitize untrusted plugin strings for safe rendering
│   ├── schema.py           # JSON contract (TypedDict) + build_report() composer
│   ├── sources.py          # URL / GitHub-shorthand / local-path resolver + hardened clone
│   └── analyzer/
│       ├── architecture.py # Pattern detection (agent-heavy / skill-first / mcp-based / hybrid)
│       ├── ast_rules.py    # Python AST-based security rules (subprocess shell-true, eval, etc.)
│       ├── dependencies.py # Tier 1 manifest enumeration + Tier 2 SCA result orchestration
│       ├── findings.py     # SecurityFinding dataclass
│       ├── footprint.py    # Token-cost estimation (baseline + on-demand max)
│       ├── inventory.py    # Filesystem walk + ComponentFile collection (default-skips vendored dirs)
│       ├── osv_adapter.py  # osv-scanner subprocess wrapper (find_osv_scanner + run_osv_scanner)
│       └── security.py     # Regex + AST rule dispatch + scan() entry point
├── rules/
│   ├── security_patterns.yaml   # Regex rule catalog
│   ├── efficiency_heuristics.yaml
│   └── known_overlaps.yaml
├── tests/
│   ├── fixtures/                # Plugin trees for integration testing
│   ├── snapshots/               # Fingerprint snapshots for 3 real plugins
│   ├── helpers/snapshots.py     # assert_snapshot helper + GRIFFITH_REGENERATE_SNAPSHOTS env
│   └── test_*.py                # 419 offline tests + 2 network tests
├── docs/
│   ├── design.md
│   ├── json-schema.md           # Output contract (v0.1, unstable)
│   ├── audits/                  # Published Griffith evaluations of real plugins
│   └── brainstorms/             # Strategic decision documents
├── .claude/work/
│   ├── plans/                   # Build plans (per phase / unit)
│   └── followups/               # Trigger-gated deferred items
├── pyproject.toml
└── README.md
```

## Commands

```bash
# Analyze a plugin (URL, GitHub shorthand, or local path)
poetry run griffith analyze https://github.com/owner/plugin
poetry run griffith analyze owner/plugin           # GitHub shorthand
poetry run griffith analyze ./local/path

# JSON output (for downstream consumers like the LMF wrapper)
poetry run griffith analyze ./my-plugin --json

# Tier 2 SCA: requires osv-scanner on PATH; hard-fails with exit 2 if missing
poetry run griffith analyze ./my-plugin --sca

# Broader (noisier) security rules
poetry run griffith analyze ./my-plugin --strict

# Scan vendored / build directories that are skipped by default
# (node_modules, .venv, venv, vendor, __pycache__, .git)
poetry run griffith analyze ./my-plugin --include-vendored
```

## Development

```bash
# First-time setup
poetry install

# Full test run (offline)
poetry run pytest -q -m "not network"

# Include network-bound tests (osv.dev queries, real git clone)
poetry run pytest -q

# Regenerate fingerprint snapshots after an intentional rule change
GRIFFITH_REGENERATE_SNAPSHOTS=1 poetry run pytest tests/test_security.py

# Run Griffith against itself (sanity check)
poetry run griffith analyze .
```

Three real-plugin fingerprint snapshots gate every run: `security-traps-plugin`, `lastmilefirst-0.14.0`, `compound-engineering-2.67.0`. The latter two skip locally if those plugins aren't cached at `~/.claude/plugins/cache/...`; CI runs them.

## JSON contract

The JSON output is the contract for downstream tools (the LMF `/run-audit-plugin` wrapper skill). Schema is **v0.1, explicitly unstable** — consumers MUST read `schema_version` before unpacking. See `docs/json-schema.md` for the current shape.

Per `src/griffith/schema.py`'s own promise: any change to the TypedDicts bumps `schema_version`. There is currently a one-time v0.1 carve-out for severity shifts on existing rule_ids — see the stability-guarantees section of the schema doc.

## Related Projects

- **lastmilefirst** — provides Overwatch (session-start workspace alerter) and the `/run-audit-plugin` wrapper skill that consumes Griffith's JSON output.
- **compound-engineering** — `security-sentinel` agent for manual audits (orthogonal: Griffith is static, security-sentinel is LLM-judgment).

## Key references

- **Design + roadmap**: `docs/design.md`
- **JSON contract**: `docs/json-schema.md`
- **Strategic state (Phase 2/3 PMF question)**: `docs/brainstorms/2026-04-20-griffith-pmf-question.md`
- **Published audits**: `docs/audits/`
- **Build plans**: `.claude/work/plans/`
- **Deferred items**: `.claude/work/followups/`
- **Security rule catalog**: `rules/security_patterns.yaml` + `src/griffith/analyzer/ast_rules.py`

*Inherits from ~/Code/gruntwork/CLAUDE.md*
