---
title: Griffith Phase 1.5 — Dependency Analyzer (Python + Node listing; optional CVE scan via osv-scanner)
type: feat
status: active
date: 2026-04-18
origin: .claude/work/followups/dependency-analysis.md
---

# Griffith Phase 1.5 — Dependency Analyzer

## Overview

Add a fifth analyzer that surfaces plugin dependencies and, optionally, known vulnerabilities in those dependencies.

**Architecture (informed by ground-truth investigation):**

- **Tier 1 — dependency listing (always on, offline, in-process).** Griffith's own parsers detect and parse language manifests to emit a full list of declared packages regardless of vulnerability status. Phase 1.5 scope: Python (`requirements*.txt`, `pyproject.toml` — PEP 621 and Poetry) + Node (`package.json`). Ruby/Go/Rust deferred.
- **Tier 2 — CVE findings (opt-in via `--sca`, requires osv-scanner binary).** Griffith shells out to OSV-Scanner, parses its JSON output, emits CVE findings with fail-closed severity mapping. osv-scanner reads manifests itself for CVE lookup; it does NOT produce a clean package listing (confirmed by ground-truth against v2.3.5: filters output to vulnerable packages only).

This architecture emerged after the plan's original Option C (OSV-Scanner owns both listing + CVE) was invalidated by ground-truthing osv-scanner 2.3.5. Osv-scanner is a vulnerability scanner that does not list clean packages; CycloneDX SBOM mode is similarly filtered. The investigation is recorded in commit history and followup files; this plan assumes the corrected architecture without relitigating.

## Problem Frame

Dependency supply chains are a well-documented attack vector in adjacent ecosystems. Python package typosquats (`ctx`, `colourama`, `request` vs `requests`), malicious npm post-install scripts (`ua-parser-js` 2021, `event-stream` 2018), and PyPI account takeovers have all distributed malware through trusted dependency graphs. The Claude Code plugin ecosystem is young; there are no publicly-documented plugin-side supply chain incidents yet, but plugins that declare Python or Node dependencies inherit the risk of their upstream ecosystems.

Griffith Phase 1 scans plugin source code but explicitly does not evaluate declared dependencies. Concrete observed example: `compound-engineering@2.67.0` ships `skills/gemini-imagegen/requirements.txt` with `google-genai>=1.0.0` + `Pillow>=10.0.0`. Griffith's current report says nothing about this manifest. After Phase 1.5: the manifest is detected, both packages are listed with their constraints, and `--sca` against the same plugin surfaces known Pillow CVEs (ground-truthed: 4 CVEs on `Pillow 10.0.0`).

## Requirements Trace

- **R1** — New `DependencyAnalyzer` walks the plugin tree and detects language manifest files (`requirements*.txt`, `pyproject.toml`, `package.json`) plus companion lockfiles (presence recorded; contents not parsed). Also detects Ruby/Go/Rust manifests in `manifests[]` (no parsing)
- **R2** — Python parser handles `requirements.txt` (line-by-line, respecting `#` comments, skipping `-r`/`-e`/`-c`/`--` option lines, stripping extras like `pkg[full]`, preserving constraint strings)
- **R3** — Python parser handles `pyproject.toml` via `tomllib` (stdlib), covering PEP 621 `[project.dependencies]` + `[project.optional-dependencies]` and Poetry `[tool.poetry.dependencies]` + `[tool.poetry.group.*.dependencies]`
- **R4** — Node parser handles `package.json` via `json.load`, covering `dependencies` (runtime), `devDependencies` (dev), `peerDependencies` (peer), `optionalDependencies` (optional)
- **R5** — Report includes a `dependencies` section with: `manifests[]`, `lockfiles[]`, `packages[]` (each with ecosystem, name, constraint, kind, manifest), `unscanned_manifests[]` (malformed manifests Griffith's parser couldn't read), `ecosystems[]`, `package_count`, `scan_status` (see below), and optional `sca` subsection
- **R6** — New `--sca` flag opt-in: shells out to osv-scanner, parses its JSON, emits CVE findings with fail-closed severity
- **R7** — When `--sca` used and osv-scanner missing: hard-fail with install instructions (exit code 2). When `--sca` NOT used: Dependencies section contains listing only; NO install pitch appears
- **R8** — `scan_status` field disambiguates states: `"ok"` (analysis succeeded, with or without CVE findings), `"tier1_only"` (listing done; no CVE scan requested), `"sca_requested_and_failed"` (osv-scanner exited with unexpected nonzero or malformed output), `"sca_requested_and_timed_out"`, `"sca_malformed_output"` (osv exited 0 but JSON unparseable — distinct security-signal case). Downstream consumers MUST check `scan_status` before treating zero-CVE output as clean.
- **R9** — Hardening invariants match Inventory: `os.walk(followlinks=False)`, symlinks recorded but never read, realpath containment, 2 MB per-file read cap; same for manifests. Applies before osv-scanner is invoked (pre-walk refuses symlink manifests rather than delegating trust).
- **R10** — Untrusted-content sanitization applies to every plugin-derived string (package name, constraint, manifest path) and every osv-scanner-derived string (CVE IDs, summaries, affected-package names). CVE summaries additionally escape Markdown/HTML/Rich-markup before rendering.
- **R11** — Real-plugin validation pins: CE@2.67.0 surfaces `google-genai` + `Pillow` in Tier 1 (regardless of --sca); with --sca, CE also surfaces at least 1 Pillow CVE. LMF@0.14.0 has zero manifests.
- **R12** — Downstream LMF wrapper updates are tracked in a SEPARATE plan in the `gruntwork-marketplace` repo. This plan does not modify marketplace files.

## Scope Boundaries

**In scope:**
- Python manifests: `requirements*.txt` + `pyproject.toml` (PEP 621 and Poetry)
- Node manifest: `package.json`
- osv-scanner integration via `--sca` for CVE findings (Python + Node + whatever osv-scanner additionally supports)
- Graceful degradation architecture: `--sca` without osv-scanner = hard fail; no `--sca` = tier-1-only, no install pitch
- `DependencyAnalyzer` new module; schema + reporter + CLI integration; auto-fixable improvements to existing analyzer patterns

**Non-goals (explicit):**
- **Ruby, Go, Rust parsers** — deferred to Phase 1.6 or 2.0. Rationale: Python + Node covers 90%+ of Claude plugins observed. Users who audit a Ruby/Go/Rust plugin with `--sca` still get CVE findings via osv-scanner's own manifest support; they just don't get Griffith-side package listing.
- **Lockfile parsing** — `package-lock.json`, `Gemfile.lock`, `go.sum`, `Cargo.lock`, `poetry.lock`. Tier 1 presence recorded in `lockfiles[]`; contents not cracked. osv-scanner reads lockfiles natively when `--sca` is set.
- **Vendored-code detection** — `node_modules/`, `.venv/`, `vendor/` trees. Separate followup.
- **MCP server runtime deps** — the inventory walker already captures MCP component files; no special dep-analysis handling.
- **System-binary requirement expansion** — separate rule-tuning concern.
- **Auto-install of osv-scanner** — rejected as magical.
- **SBOM export** (CycloneDX, SPDX) — out of scope.
- **Dependency-graph visualization** — out of scope.

### Deferred to Separate Tasks

- **Ruby / Go / Rust parser support** — Phase 1.6 or later. Follow-up file: `.claude/work/followups/dependency-analysis.md` already captures the broader scope.
- **LMF audit-plugin wrapper update** — separate plan in `gruntwork-marketplace/plugins/lastmilefirst/.claude/work/plans/` once Griffith Phase 1.5 ships.
- **Tier 3: CVE scanning refinement** — richer CVE presentation (e.g., upgrade-path recommendations) beyond basic severity/ID surface.

## Context & Research

### Ground-Truth Against OSV-Scanner 2.3.5

Verified against the installed binary (`brew install osv-scanner`):

- **CLI:** `osv-scanner scan source -r --format json <path>`. Recursive flag `-r` required for nested manifests.
- **Output shape (top-level):** `{"results": [{"source": {"path", "type"}, "packages": [...]}], "experimental_config": {...}}`
- **Per-package shape:** `{"package": {"name", "version", "ecosystem"}, "groups": [{"ids", "aliases", "max_severity"}], "vulnerabilities": [...]}`
- **Severity:** `max_severity` is a **CVSS numeric string** (e.g. `"6.1"`, `"5.3"`), NOT an enum label. Mapping to Griffith severity must derive from CVSS score.
- **Ecosystem casing:** `"PyPI"`, not `"pypi"`. Case-sensitive.
- **Clean packages filtered:** packages with zero known vulnerabilities are absent from output. Confirmed with all output formats including `cyclonedx-1-5`.
- **pyproject.toml NOT parsed** by osv-scanner's source scan; only `requirements*.txt` and `package.json`-style manifests extract packages.
- **`--offline` without prior DB download:** returns empty results + stderr error `"unable to fetch OSV database: no offline version of the OSV database is available"`. Not a usable mode without `--download-offline-databases` first.
- **Stderr bleed:** osv-scanner prints progress and filesystem-walk status to stderr. Must capture and discard rather than parse.

### Relevant Code and Patterns

- `src/griffith/sources.py::_clone_hardened` — reference hardened subprocess pattern. **Do NOT copy wholesale for osv-scanner.** `_clone_hardened` empties HOME and scrubs all env; osv-scanner legitimately needs network (HTTPS_PROXY / SSL_CERT_FILE) and writable cache (HOME / XDG_CACHE_HOME) or its first-run DB fetch will fail and timeouts will follow. Build `_build_osv_env` separately (see Key Technical Decisions).
- `src/griffith/analyzer/inventory.py` — canonical filesystem walking with symlink refusal + realpath containment + 2 MB file cap. DependencyAnalyzer's walk mirrors these invariants.
- `src/griffith/analyzer/security.py` — precedent for YAML-driven loading; not directly reused here but establishes the "lazy-load rules on first call" pattern.
- `src/griffith/sanitize.py` — `sanitize_string` + `sanitize_frontmatter`. Applied to every plugin-derived string. **Insufficient for CVE summary content** (doesn't escape Markdown/HTML/Rich-markup) — add `sanitize_for_markdown` and `sanitize_for_rich` helpers.
- `src/griffith/schema.py::build_report` — composition pattern. Add `dependency_report` param.
- `src/griffith/reporter.py::_render_security` — severity-grouped rendering pattern; reuse for CVE findings block.

### Institutional Learnings

- Phase 1 showed users will install auxiliary tools when the value is clear (gitleaks, gh). osv-scanner install friction is a real cost, but — unlike the original Option C framing — it's now tied only to the `--sca` flag. Users who never ask for CVE analysis never see an install prompt.
- Untrusted content from plugins can prompt-inject downstream renderings; sanitize before embedding. Extends to CVE summary content because both originate indirectly from plugin-author-controlled manifest entries.
- The D-revised architecture preserves Griffith's zero-runtime-dep property for the default path. External binary is required only for CVE scanning, which is explicitly opt-in.

### External References

- [OSV-Scanner](https://google.github.io/osv-scanner/) — source and docs for the `--sca` integration
- [OSV-Scanner JSON schema](https://google.github.io/osv-scanner/output/) — Tier 2 parse target
- [osv-scalibr](https://github.com/google/osv-scalibr) — checked for standalone listing mode; not usable (no prebuilt binaries, no documented list-only mode, requires Go to install). Ruled out during ground-truth investigation.
- `tomllib` — Python 3.11+ stdlib, used for `pyproject.toml` + `Cargo.toml` parsing (though Cargo parsing is deferred)

### Pre-Plan Artifacts (Reference, Not Authoritative)

The following files exist from earlier exploration and should be read before Unit work begins. **All of them were written before the architecture landed on D-revised**; tests and test expectations will need revision:

- `tests/test_dependencies.py` — original design sketch; API mostly right for D-revised but per-ecosystem test coverage needs trimming to Python + Node only
- `tests/fixtures/deps-python-plugin/` — reusable; includes requirements.txt + pyproject.toml with edge cases
- `tests/fixtures/deps-node-plugin/` — reusable
- `tests/fixtures/deps-multi-ecosystem-plugin/` — contains Ruby/Go/Rust manifests; **retain as fixture** since future Phase 1.6 will need them; Phase 1.5 tests skip these ecosystems

## Key Technical Decisions

### Architecture

- **Tier 1 (listing) and Tier 2 (CVE) are separate subsystems.** Tier 1 always runs (cheap, offline, always-useful). Tier 2 is opt-in via `--sca` and shells out to osv-scanner. They do not share parsing code; they're complementary capabilities.

- **Scope Python + Node for Tier 1; defer Ruby/Go/Rust.** Empirical rationale: Claude plugins observed to date are predominantly Python (hooks, scripts) and TypeScript/JavaScript. Ruby/Go/Rust plugins are rare; those that exist still get CVE findings via osv-scanner when `--sca` is used. Shipping Tier 1 with narrower scope means one fewer parser unit and faster delivery; broader parser coverage lives in a Phase 1.6 plan that can be ordered by real observed demand.

- **Tier 2 is a hard-fail (not soft) when osv-scanner is missing.** Rationale: users who pass `--sca` are explicitly requesting CVE analysis. If the binary isn't installed, failing loudly with install instructions is clearer than producing a report that implies CVE analysis happened. Exit code 2 (distinct from 1 for other errors). Without `--sca`, osv-scanner is not even looked for — no install pitch, no nag.

- **Tier 2 Node coverage requires a lockfile** — verified against osv-scanner v2.3.5. Bare `package.json` without `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` produces exit 128 "no package sources found"; even declared-as-vulnerable packages in `dependencies` are not scanned. This is osv-scanner's policy (it only scans resolved deps, not declared ranges). Implication: Node plugins without a lockfile get Tier 1 listing via Griffith's parser, but `--sca` yields zero CVEs. Must document in README, surface as an info finding in the scan result (`"note": "Node CVE scan requires lockfile; found 0 scannable sources"`), and not conflate with `sca_requested_and_failed`.

- **osv-scanner exit code handling.** Verified semantics:
  - `0` — scan succeeded, no vulnerabilities found
  - `1` — scan succeeded, vulnerabilities found (NOT a failure — treat as `ok`)
  - `128` — "no package sources found" (e.g. bare `package.json` without lockfile) — treat as `ok` + emit info note
  - Other nonzero — `sca_requested_and_failed` with stderr preserved

  Plan-sketch pseudocode had this wrong. Unit 6 must explicitly test exit-1-with-vulns as a success case to prevent regression.

- **`scan_status` field is authoritative for consumer trust decisions.** States: `ok`, `tier1_only`, `sca_requested_and_failed`, `sca_requested_and_timed_out`, `sca_malformed_output`. The `sca_malformed_output` state is distinct from `sca_requested_and_failed` because it signals a potentially adversarial condition (shadowed binary, MITM on DB fetch producing crafted-but-invalid output) that downstream CI consumers may want to treat more severely than a normal operational failure. Downstream consumers MUST check `scan_status == "ok"` before treating zero CVEs as clean. This is in `docs/json-schema.md`.

### Hardening

- **`_build_osv_env` differs from `_build_scrubbed_env`.** osv-scanner needs network (proxy support), TLS (custom CA support), and a writable cache. The function:
  - Starts from a copy of `os.environ` (not from scratch)
  - Strips shell-hostile and credential-leaking vars: `SSH_AUTH_SOCK`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_SSH_COMMAND`, `LD_PRELOAD`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`
  - Preserves: `PATH`, `HOME`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, `ALL_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`
  - Sets: `LANG=C.UTF-8` (avoid locale-driven parser surprises)

- **Stdout AND stderr are bounded.** `capture_output=True` naive usage is a JSON-bomb DoS. Use `subprocess.Popen` with a concurrent dual-reader (selectors loop or two reader threads) draining both streams independently. Caps: stdout 32 MB, stderr 1 MB (stderr is progress noise, not data). Overflow on either stream → terminate subprocess and record `scan_status == "sca_requested_and_failed"`. Concurrent drain is required because osv-scanner can legitimately fill stderr with walk-progress messages while stdout is being read, blocking on pipe-buffer fill (~64 KB) if stderr isn't drained in parallel.

- **Osv-scanner discovery is path-integrity-checked.** Auto-discovery order:
  1. `GRIFFITH_OSV_SCANNER` env var (user-provided absolute path) — highest precedence, intentional override
  2. `shutil.which("osv-scanner")` — standard PATH lookup
  3. Fallback absolute paths: `/opt/homebrew/bin/osv-scanner`, `/usr/local/bin/osv-scanner`, `~/go/bin/osv-scanner`, `/usr/bin/osv-scanner`
  After resolution, verify: (a) `.resolve()` is not inside the plugin tree being analyzed; (b) `osv-scanner --version` runs and matches a supported version range. If version is too old, emit a warning and proceed (may produce degraded output).

- **Subprocess uses `--` separator to block argument injection via plugin path.** `[osv, 'scan', 'source', '-r', '--format', 'json', '--', str(plugin_path)]` — plugin paths that start with `-` or `--` are treated as literal paths, not osv-scanner flags.

- **Symlink manifests are pre-filtered by Griffith, not delegated.** Before invoking osv-scanner, DependencyAnalyzer walks the plugin tree with `os.walk(followlinks=False)` and emits a Griffith security finding for any symlinked manifest. osv-scanner is then invoked with `--experimental-exclude` flags pointing at those symlink paths (if osv-scanner supports exclude; otherwise: skip osv-scanner invocation entirely and emit a warning if symlinked manifests are present). Rationale: Phase 1 refused symlinks explicitly; transferring that trust to an external tool without verification would be a regression.

### Untrusted Content

- **Sanitize layers (per destination):**
  - JSON output: `sanitize_string` strips control/ANSI/bidi/zero-width; length-cap. Current helper is sufficient.
  - Rich output: use `rich.markup.escape()` from the Rich library (maintained, handles backslash edge cases); do NOT roll a custom `[` → `\\[` regex (the custom approach fails on `\\\\[bold]` and other backslash pre-escape forms).
  - Markdown output (LMF wrapper consumption): strip HTML tags with an iterate-until-fixpoint loop (neutralizes nested `<<script>script>` patterns); also strip `<!--...-->` and `<![CDATA[...]]>`; escape any residual `<`/`>` as literals; escape Markdown special chars (`[`, `]`, backtick, `*`, `_`); render URLs as plain text (never as clickable Markdown links).
- **Per-field tagging:** every untrusted field has a path added to `UNTRUSTED_FIELDS`. The full Tier 1 + Tier 2 enumeration (Unit 5 adds the Tier 1 paths; Unit 6 adds the Tier 2 paths):

  **Tier 1 (added in Unit 5):**
  - `dependencies.manifests[]`
  - `dependencies.lockfiles[]`
  - `dependencies.unscanned_manifests[]`
  - `dependencies.packages[].ecosystem`
  - `dependencies.packages[].name`
  - `dependencies.packages[].constraint`
  - `dependencies.packages[].manifest`

  **Tier 2 (added in Unit 6):**
  - `dependencies.sca.vulnerabilities[].id`
  - `dependencies.sca.vulnerabilities[].summary`
  - `dependencies.sca.vulnerabilities[].affected_package`
  - `dependencies.sca.vulnerabilities[].fixed_versions[]`
  - `dependencies.sca.vulnerabilities[].severity_raw`
  - `dependencies.sca.error` (embeds stderr text from osv-scanner; stderr is plugin-influenced via package names + paths)

  **Excluded (authored by Griffith, trusted):** `dependencies.scan_status`, `dependencies.ecosystems[]`, `dependencies.package_count`, `dependencies.sca.osv_scanner_version`, `dependencies.sca.install_command`, `dependencies.sca.install_url`, `dependencies.sca.vulnerability_count`

### CVE Severity Mapping (Fail-Closed)

Osv-scanner emits `max_severity` as a CVSS numeric score string (version not normalized — OSV advisories mix CVSS v2, v3, v4; all share the 0-10 range, but vector-version semantics differ slightly). On rare occasions osv-scanner may emit the full vector string (`CVSS:3.1/AV:N/...`) instead of just the numeric — the parser must tolerate both forms: extract the base score from vector strings, fall back to severity=`unknown` (not critical) with a logged warning when parsing fails on an unexpected format. Unparseable numerics (empty, NaN, out-of-range) fail closed to `critical`. Map to Griffith enum:

| CVSS score | Griffith severity |
|-----------|-------------------|
| 9.0–10.0 | critical |
| 7.0–8.9 | high |
| 4.0–6.9 | medium |
| 0.1–3.9 | low |
| 0.0 | info |
| Unparseable / missing / empty | **critical** (fail-closed) |

Rationale: a malformed CVSS score must NOT silently become `low` or `info`. CI pipelines that gate on severity ≥ `high` would miss a real critical CVE due to upstream schema drift. `severity_raw` field preserves the original string so consumers can re-derive if needed.

### Schema

- **`schema_version` stays at `0.1`.** Per schema docs, adding fields is allowed without bumping; removing fields or changing enum meanings requires a bump. This plan only adds.
- **All fields present always, values vary by state.** Shape A from the document-review: `dependencies` always has every key (`scan_status`, `manifests`, `lockfiles`, `packages`, `ecosystems`, `package_count`, `sca`); `sca` is either `null` (when `--sca` not used) or an object with `osv_scanner_version`, `vulnerabilities`, etc. No `NotRequired` / conditional-key patterns — consumers always know what to expect.
- **`--require-osv-scanner` flag (alternative name: `--sca-required`, decide in Unit 6)** — CI-friendly: in `--sca` mode, if osv-scanner can't be found or the scan fails, exit with code 2. Default behavior in `--sca` mode is the same (hard fail) so this flag is primarily explicit signal for clarity, not a separate code path.

### Voice / Messaging

- **Install text uses "Recommended" not "STRONGLY RECOMMENDED".** Placement (prominent section + install command in a code fence) does the work. Caps framing reads as lecturing.
- **Supply-chain framing is specific and evidenced.** Name Python typosquat incidents (ctx, colourama) and Node post-install incidents (ua-parser-js, event-stream) explicitly. Acknowledge that Claude-plugin-ecosystem supply-chain incidents are not yet publicly documented — it's risk by inheritance from Python/Node ecosystems, not demonstrated-in-the-wild attacks. This is an honest distinction the original plan fudged.
- **Install pitch appears ONLY when `--sca` is requested and osv-scanner is missing.** Default-mode users who don't ask for CVE analysis see no pitch. Eliminates the "nag dialog" risk flagged in the document review.

## Open Questions

### Resolved During Planning

- **Our parsers vs orchestrate osv-scanner for listing?** Our parsers. Ground-truth showed osv-scanner filters output to vulnerable packages only.
- **Python + Node vs all five ecosystems in Tier 1?** Python + Node only; Ruby/Go/Rust deferred. Empirical plugin-ecosystem distribution.
- **Lockfile parsing?** No; detect and record presence only.
- **Schema version bump?** No — additive field, stays at 0.1.
- **Soft-fail or hard-fail on missing osv-scanner with `--sca`?** Hard-fail. User explicitly requested CVE analysis; silent degradation is wrong.
- **Install pitch on every default run?** No. Only when `--sca` used without osv-scanner.
- **CVE severity mapping?** Fail-closed table; unparseable → critical; `severity_raw` preserved.
- **STRONGLY RECOMMENDED caps?** No — drop, use "Recommended".
- **Flag name: `--sca`?** Keep. Alternatives (`--cves`, `--check-cves`) are defensible; `--sca` is standard AppSec vocabulary that's short and specific. Revisit in Phase 1.6 if user feedback suggests churn.
- **LMF wrapper in this plan?** No. Cross-repo work goes to a separate plan in `gruntwork-marketplace`.

### Deferred to Implementation

- **Osv-scanner supported-version range.** First implementation tests against 2.3.5 (current stable); add version-check + range check in Unit 5 after observing output across a couple of versions.
- **Symlink handling w.r.t. osv-scanner.** If osv-scanner supports `--experimental-exclude` for symlinks, we pass the pre-discovered symlink paths. If not, we skip osv-scanner invocation when symlinked manifests are present (emit scan_status=`sca_requested_and_failed` with a clear reason). Resolve by testing in Unit 5.
- **Poetry vs PEP 621 coexistence in the same pyproject.toml.** Parse PEP 621 (`[project]`) first, then Poetry (`[tool.poetry]`), union packages and de-dup by `(name, kind)` keeping first-seen constraint. Rationale: PEP 621 is the modern standard; prefer its constraint form when both are present.

## Output Structure

```
gruntwork-griffith/
├── src/griffith/
│   ├── analyzer/
│   │   ├── __init__.py                # [modify] export DependencyAnalyzer + related dataclasses
│   │   ├── dependencies.py            # [new] DependencyAnalyzer (Tier 1 walk + Python+Node parsers)
│   │   └── osv_adapter.py             # [new] Tier 2 adapter: osv-scanner subprocess, version check, JSON parse
│   ├── sanitize.py                    # [modify] add sanitize_for_markdown + sanitize_for_rich
│   ├── schema.py                      # [modify] add DependencyDict + SCAResultDict; UNTRUSTED_FIELDS; build_report
│   ├── reporter.py                    # [modify] add _render_dependencies with listing + optional CVE section
│   └── cli.py                         # [modify] wire analyzer, add --sca flag + (optional) --require-osv-scanner
├── tests/
│   ├── fixtures/
│   │   ├── deps-python-plugin/        # [exists — reuse]
│   │   ├── deps-node-plugin/          # [exists — reuse]
│   │   ├── deps-multi-ecosystem-plugin/  # [exists — retain; Phase 1.5 tests skip; Phase 1.6 will activate]
│   │   └── deps-poetry-plugin/        # [new] pyproject.toml with Poetry-style sections
│   ├── test_dependencies.py           # [rewrite] Python+Node parser tests + Tier 1 shape
│   ├── test_osv_adapter.py            # [new] --sca / osv-scanner subprocess tests (mocked + marked-network)
│   ├── test_reporter.py               # [modify] new dependencies section coverage
│   ├── test_cli.py                    # [modify] --sca flag behavior; hard-fail when osv missing
│   └── test_sanitize.py               # [new or modify] sanitize_for_markdown/sanitize_for_rich coverage
├── docs/
│   └── json-schema.md                 # [modify] dependencies section; scan_status enum; untrusted_fields updates
└── README.md                          # [modify] add dependencies dimension; osv-scanner optional install note

# Downstream (separate plan, separate repo):
gruntwork-marketplace/plugins/lastmilefirst/.claude/work/plans/
└── audit-plugin-dependencies-support.md  # [separate plan, tracked but not executed here]
```

## High-Level Technical Design

> *Directional guidance for review, not implementation specification.*

### Two-tier data flow

```
analyze(plugin_path, sca=False):
    # Tier 1 — always runs
    manifests, lockfiles = detect_manifests(plugin_path)      # walk with hardening
    packages = []
    for m in manifests:
        if is_python(m): packages.extend(parse_python(m))
        elif is_node(m): packages.extend(parse_node(m))
        # Ruby/Go/Rust: detected in manifests[] but not parsed; osv-scanner covers CVE if --sca
    dep_report = DependencyReport(manifests, lockfiles, packages, scan_status="tier1_only")

    # Tier 2 — only when requested
    if sca:
        osv = find_osv_scanner()  # PATH → fallbacks → GRIFFITH_OSV_SCANNER → None
        if osv is None:
            print(INSTALL_PITCH_WITH_REASON, file=sys.stderr)
            sys.exit(2)  # hard fail — user explicitly asked for --sca
        sca_result = run_osv_hardened(osv, plugin_path)       # bounded stdout, scrubbed env
        dep_report.sca = sca_result
        dep_report.scan_status = sca_result.scan_status       # "ok" | "sca_requested_and_failed" | "sca_requested_and_timed_out"

    return dep_report
```

### JSON contract (authoritative shape)

When `--sca` not used:
```json
"dependencies": {
  "scan_status": "tier1_only",
  "manifests": ["skills/gemini-imagegen/requirements.txt"],
  "lockfiles": [],
  "unscanned_manifests": [],
  "ecosystems": ["PyPI"],
  "package_count": 2,
  "packages": [
    {"ecosystem": "PyPI", "name": "google-genai", "constraint": ">=1.0.0", "kind": "runtime", "manifest": "skills/gemini-imagegen/requirements.txt"},
    {"ecosystem": "PyPI", "name": "Pillow", "constraint": ">=10.0.0", "kind": "runtime", "manifest": "skills/gemini-imagegen/requirements.txt"}
  ],
  "sca": null
}
```

When `--sca` used and osv-scanner succeeded (exit 0 or 1):
```json
"dependencies": {
  "scan_status": "ok",
  "manifests": [...],
  "lockfiles": [...],
  "unscanned_manifests": [],
  "ecosystems": ["PyPI"],
  "package_count": 2,
  "packages": [...],
  "sca": {
    "osv_scanner_version": "2.3.5",
    "vulnerability_count": 4,
    "note": null,
    "vulnerabilities": [
      {
        "id": "CVE-2024-28219",
        "severity": "high",
        "severity_raw": "7.5",
        "summary": "Buffer overflow in Pillow's _imagingcms",
        "affected_package": "Pillow",
        "fixed_versions": ["10.2.0"]
      }
    ]
  }
}
```

When `--sca` used and osv-scanner returns exit 128 (no scannable sources — common for Node without lockfile):
```json
"dependencies": {
  "scan_status": "ok",
  "manifests": ["skills/node-skill/package.json"],
  "lockfiles": [],
  "unscanned_manifests": [],
  "ecosystems": ["npm"],
  "package_count": 4,
  "packages": [...],
  "sca": {
    "osv_scanner_version": "2.3.5",
    "vulnerability_count": 0,
    "note": "osv-scanner found no scannable package sources (Node CVE scan requires package-lock.json, yarn.lock, or pnpm-lock.yaml)",
    "vulnerabilities": []
  }
}
```

When `--sca` used and osv-scanner scan failed (unexpected nonzero exit):
```json
"dependencies": {
  "scan_status": "sca_requested_and_failed",
  "manifests": [...],
  "lockfiles": [...],
  "unscanned_manifests": [],
  "ecosystems": [...],
  "package_count": N,
  "packages": [...],
  "sca": {
    "osv_scanner_version": "2.3.5",
    "vulnerability_count": 0,
    "note": null,
    "vulnerabilities": [],
    "error": "osv-scanner exited with code 130: <sanitized stderr tail>"
  }
}
```

When `--sca` used and osv-scanner emitted malformed JSON (distinct from generic failure — potential tampering signal):
```json
"dependencies": {
  "scan_status": "sca_malformed_output",
  "manifests": [...],
  "lockfiles": [...],
  "unscanned_manifests": [],
  "ecosystems": [...],
  "package_count": N,
  "packages": [...],
  "sca": {
    "osv_scanner_version": "2.3.5",
    "vulnerability_count": 0,
    "note": null,
    "vulnerabilities": [],
    "error": "osv-scanner exited 0 but stdout was not valid JSON (possible binary shadowing or format drift)"
  }
}
```

## Implementation Units

- [ ] **Unit 1: Foundation — DependencyAnalyzer walk + dataclasses (detection only)**

**Goal:** Establish the analyzer module with its data types and a filesystem walk that detects manifests and lockfiles without parsing. Proves hardening invariants before parser logic is added.

**Requirements:** R1, R9

**Dependencies:** None

**Files:**
- Create: `src/griffith/analyzer/dependencies.py` (DependencyAnalyzer stub with walk; DependencyReport + DependencyPackage dataclasses with `unscanned_manifests: list[str] = []` field; no parsers yet)
- Modify: `src/griffith/analyzer/__init__.py` (export)
- Rewrite: `tests/test_dependencies.py` (Phase 1.5 scope — trim multi-ecosystem tests; focus Unit 1 on walk + shape)

**Approach:**
- `DependencyAnalyzer.analyze(plugin_path, sca=False)` — context for Unit 1: `sca=False` is the only supported path; sca=True raises NotImplementedError with a TODO pointing at Unit 6
- Walk mirrors Inventory: `os.walk(followlinks=False)`; symlink manifests recorded but content never read; realpath containment; 2 MB file size cap (but don't parse yet — just record)
- Detect:
  - Python manifests: `requirements*.txt` (via regex match), `pyproject.toml` (NOT `setup.py` — deferred; R1 scope is the three canonical manifests)
  - Node manifests: `package.json`
  - Ruby: `Gemfile`
  - Go: `go.mod`
  - Rust: `Cargo.toml`
  - Lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`, `go.sum`, `Cargo.lock`, `poetry.lock`
- Return `DependencyReport(manifests, lockfiles, packages=[], unscanned_manifests=[], scan_status="tier1_only")` — `packages` and `unscanned_manifests` populated by later units

**Execution note:** Test-first. Hardening correctness (especially symlink refusal) is load-bearing.

**Patterns to follow:**
- `src/griffith/analyzer/inventory.py::_walk_component` — symlink + containment
- `src/griffith/sanitize.py::sanitize_string` — every captured path is sanitized

**Test scenarios:**
- Happy: minimal plugin (no deps) → `DependencyReport(manifests=[], lockfiles=[], packages=[], scan_status="tier1_only")`
- Happy: `deps-python-plugin` detects `requirements.txt` + `pyproject.toml` in `manifests`; zero `packages` at this unit
- Happy: `deps-node-plugin` detects `skills/node-skill/package.json`
- Happy: `deps-multi-ecosystem-plugin` detects `Gemfile`, `go.mod`, `Cargo.toml` in `manifests` (Phase 1.5 scope excludes parsing; detection still happens)
- Happy: lockfile-only (synthesized): record in `lockfiles[]`, `manifests[]` empty
- Edge: empty plugin yields zero detection; no errors
- Edge: nonexistent path raises `FileNotFoundError`
- **Adversarial (symlink):** `requirements.txt` is a symlink → recorded in `manifests[]` with `is_symlink: true` + zero packages from that path; no read of target
- **Adversarial (oversized):** 3 MB `requirements.txt` → recorded with zero packages
- Shape: `DependencyReport.package_count == len(packages)`; paths relative to plugin root

**Verification:**
- `poetry run pytest tests/test_dependencies.py::TestWalk` green
- Full suite regresses to 138 + new Unit 1 tests

---

- [ ] **Unit 2: Python parsers — requirements.txt + pyproject.toml**

**Goal:** Parse Python manifests into `DependencyPackage` lists with ecosystem, name, constraint, kind, manifest fields.

**Requirements:** R2, R3, R11 (CE pin)

**Dependencies:** Unit 1

**Files:**
- Modify: `src/griffith/analyzer/dependencies.py` (add `_parse_requirements_txt`, `_parse_pyproject`)
- Create: `tests/fixtures/deps-poetry-plugin/` (Poetry-style pyproject for group test coverage)
- Modify: `tests/test_dependencies.py`

**Approach:**
- `_parse_requirements_txt`: line-iterator; strip `#` comments; skip lines starting with `-r`, `-e`, `-c`, `--`, `--extra-index-url`, etc.; anchored + bounded-repetition regex `^([A-Za-z0-9._-]{1,200})(\[[^\]]{0,100}\])?\s*(.*)$` (ReDoS defense against 2 MB input lines); preserve constraint string; kind = `"runtime"`
- `_parse_pyproject` via `tomllib`:
  - PEP 621: `data["project"]["dependencies"]` (list[str]) → kind=`runtime`; `data["project"]["optional-dependencies"]` (dict[str, list[str]]) → kind=`optional`
  - Poetry: `data["tool"]["poetry"]["dependencies"]` (dict; skip `python` key; values may be string or table with `version`) → kind=`runtime`; `data["tool"]["poetry"]["group"][<name>]["dependencies"]` → kind=`dev` when name is `dev`/`test`, else `optional`
  - PEP 621 parsed FIRST, then Poetry; de-dup by `(name, kind)` keeping first constraint
- Parse with `try/except (RecursionError, tomllib.TOMLDecodeError, OSError, ValueError)` — depth-bomb defense plus malformed-file tolerance; temporarily lower `sys.setrecursionlimit(500)` around parse and restore after
- All strings sanitized via `sanitize_string` (name/constraint length-capped)
- Malformed files recorded in `DependencyReport.unscanned_manifests`; don't crash

**Patterns to follow:**
- `src/griffith/analyzer/security.py` — `tomllib` usage
- `src/griffith/sanitize.py`

**Test scenarios:**
- Happy (requirements.txt): `deps-python-plugin/requirements.txt` yields `requests`, `Pillow`, `click`, `tiktoken`, `package-with-extras` (name only; extras stripped); constraints preserved (`requests` → `>=2.25.0`, `click` → `""`)
- Edge: `-r other.txt`, `-e ./local`, `--index-url` lines skipped
- Happy (PEP 621): `deps-python-plugin/pyproject.toml` → `fastapi`, `uvicorn`, `pytest`, `black` (last two with kind=`optional`)
- Happy (Poetry): new `deps-poetry-plugin` fixture → runtime + dev + optional classified correctly; `python` version spec excluded
- Edge: malformed TOML → in `unscanned_manifests[]`, no crash
- **Integration (real CE@2.67.0):** scanning cached plugin → `google-genai` + `Pillow` both present; constraints match fixture (`>=1.0.0`, `>=10.0.0`)

**Verification:**
- `poetry run pytest tests/test_dependencies.py::TestPythonParsers` green
- Real-CE scan shows both packages

---

- [ ] **Unit 3: Node parser — package.json**

**Goal:** Parse `package.json` with all four dependency kinds.

**Requirements:** R4

**Dependencies:** Unit 1

**Files:**
- Modify: `src/griffith/analyzer/dependencies.py` (add `_parse_package_json`)
- Modify: `tests/test_dependencies.py`

**Approach:**
- `json.load`; iterate four kind-keyed sections; each is `dict[str, str]` of name → constraint
- `dependencies` → `runtime`; `devDependencies` → `dev`; `peerDependencies` → `peer`; `optionalDependencies` → `optional`
- Wrap parse in `try/except (RecursionError, json.JSONDecodeError, OSError, ValueError)` with temp `sys.setrecursionlimit(500)` around `json.load` (depth-bomb defense)
- Sanitize names/constraints via `sanitize_string`
- Malformed JSON → `unscanned_manifests[]`, no crash

**Test scenarios:**
- Happy (all four kinds): `deps-node-plugin/skills/node-skill/package.json` → `express` (runtime), `axios` (runtime), `jest` (dev), `react` (peer)
- Edge: package.json without dep sections → empty packages list
- Edge: dep section that's not a dict (malformed) → skip that section, continue
- Error: invalid JSON → recorded in `unscanned_manifests[]`

**Verification:**
- `poetry run pytest tests/test_dependencies.py::TestNodeParser` green

---

- [ ] **Unit 4: Sanitization helpers (prerequisite for Unit 5 and 6)**

**Goal:** Add `sanitize_for_markdown` and `sanitize_for_rich` to the existing sanitize module. These are needed before any untrusted CVE content is rendered.

**Requirements:** R10

**Dependencies:** None upstream (can be landed before or in parallel with Units 1-3). Must land before Unit 5 (which depends on it) and Unit 6 (which renders untrusted CVE content).

**Files:**
- Modify: `src/griffith/sanitize.py`
- Create or modify: `tests/test_sanitize.py`

**Approach:**
- `sanitize_for_markdown(s: str, max_length: int) -> str`:
  - First call `sanitize_string` (strips control/ANSI/bidi/zero-width, length cap)
  - Strip HTML tags + comments + CDATA iteratively until fixpoint (re-run regex while the string keeps changing) — neutralizes nested `<<script>script>` patterns. Regexes: `<\s*/?\s*\w+[^>]*>`, `<!--[\s\S]*?-->`, `<!\[CDATA\[[\s\S]*?\]\]>`
  - Escape any residual `<`/`>` as literals (`&lt;`/`&gt;`)
  - Escape Markdown specials: `[ ] \` * _`
  - URLs kept as inert text; **do not** render as Markdown links (prevents `[fake](attacker.com)` injection)
- `sanitize_for_rich(s: str, max_length: int) -> str`:
  - First call `sanitize_string`
  - Then delegate to `rich.markup.escape(s)` (maintained by the Rich project; handles backslash edge cases like `\\[bold]` that a custom `[` → `\\[` regex misses)
- Leave existing `sanitize_string` unchanged (many callers; don't cascade)

**Test scenarios:**
- Happy: plain text passes through unchanged
- Adversarial: input `[click here](https://evil.com)` → markdown version escapes brackets; string is inert
- Adversarial: input `[bold red]FAKE[/]` → rich version escapes via `rich.markup.escape`; string doesn't style
- Adversarial: input `<script>alert(1)</script>` → markdown version removes tags
- Adversarial: nested `<<script>script>alert(1)<</script>/script>` → fixpoint iterate strips both layers; residual angle brackets escaped
- Adversarial: `<!-- hidden -->` comment + `<![CDATA[<script>x</script>]]>` → both forms stripped
- Adversarial: `\\[bold red]HACKED[/]` (pre-escaped backslash) → `rich.markup.escape` handles without regression
- Adversarial: input contains both ANSI `\x1b[31m` + bidi `\u202e` + markdown `[x](y)` → all neutralized
- Edge: empty string → empty string
- Edge: length-cap interaction with escape sequences (cap first, then escape — escape-first could leave mid-escape truncation)

**Verification:**
- `poetry run pytest tests/test_sanitize.py` green
- No existing callers of `sanitize_string` affected

---

- [ ] **Unit 5: Tier 1 integration — schema + reporter + CLI wiring (NO osv-scanner yet)**

**Goal:** Wire the DependencyAnalyzer Tier 1 output into the report pipeline. Rich renderer shows listing; JSON output has `dependencies` section with `sca: null`. No `--sca` flag yet.

**Requirements:** R5, R8 (partial — tier1_only + scan_status field)

**Dependencies:** Units 1-4

**Files:**
- Modify: `src/griffith/schema.py` (add `DependencyDict` + `DependencyPackageDict`; update `build_report()` signature to accept `dep_report`; add paths to `UNTRUSTED_FIELDS` — enumerate from Key Decisions)
- Modify: `src/griffith/reporter.py` (add `_render_dependencies`: listing + per-ecosystem/manifest grouping)
- Modify: `src/griffith/cli.py` (call `DependencyAnalyzer().analyze(plugin_path, sca=False)`; pass into `build_report`)
- Modify: `tests/test_reporter.py`
- Modify: `tests/test_cli.py`
- Modify: `docs/json-schema.md` (dependencies section, Tier 1 shape only; note Tier 2 is Unit 6)

**Approach:**
- Schema: `DependencyDict` has `scan_status`, `manifests`, `lockfiles`, `unscanned_manifests`, `ecosystems`, `package_count`, `packages`, `sca` (always present; None in Tier 1)
- `UNTRUSTED_FIELDS` additions: add the **Tier 1 paths only** from the Key Technical Decisions enumeration (Tier 2 `sca.*` paths are added in Unit 6):
  - `dependencies.manifests[]`, `dependencies.lockfiles[]`, `dependencies.unscanned_manifests[]`, `dependencies.packages[].ecosystem`, `dependencies.packages[].name`, `dependencies.packages[].constraint`, `dependencies.packages[].manifest`
- Rich renderer:
  - Skip section entirely if `manifests == []` AND `packages == []` AND `unscanned_manifests == []` (terse minimal-plugin case)
  - Symlink-only-manifests case (all entries in `manifests[]` have `is_symlink: true`; packages empty): render section with a single line "Symlinked manifests refused for safety — see Security findings" (cross-reference, no duplicate detail)
  - `unscanned_manifests` non-empty: render as an info-level warning line per manifest ("Could not parse: `path`") beneath the package table
  - Otherwise: "Dependencies" heading, ecosystem summary, per-manifest package list (cap 10 per manifest, "+N more")
  - No install-pitch branch in this unit (Tier 2 adds it)
- CLI: analyzer always runs (cheap); no flag yet

**Test scenarios:**
- Happy (Python): `griffith analyze tests/fixtures/deps-python-plugin --json` → `dependencies.manifests` has both Python files; `packages` has 8+ entries across both
- Happy (Node): `griffith analyze tests/fixtures/deps-node-plugin --json` → `dependencies.packages` has 4 entries
- Happy (Rich): rendered output contains "Dependencies" header and package listing
- Happy (empty): `minimal-plugin` → `scan_status: "tier1_only"`, packages empty, manifests empty, unscanned_manifests empty; Rich skips section
- Happy (symlink-only): fixture with `requirements.txt → /etc/hosts` only → manifests has 1 entry `is_symlink=true`, packages=[], unscanned_manifests=[]; Rich section shows single "refused for safety" line
- Happy (unscanned_manifests): fixture with malformed JSON package.json → surfaces in `unscanned_manifests[]`; Rich section shows "Could not parse" warning
- Integration (real CE): JSON contains `google-genai` + `Pillow` (Tier 1 listing; unrelated to CVEs)
- Shape: `sca` is always present in JSON (value null in Tier 1); all Tier 1 keys present always per Shape A
- Schema: adding `dependencies.*` Tier 1 paths to `UNTRUSTED_FIELDS` doesn't break existing tests

**Verification:**
- Full test suite + Unit 5 additions green
- `docs/json-schema.md` updated for Tier 1

---

- [ ] **Unit 6: Tier 2 — osv-scanner adapter + `--sca` flag**

**Goal:** Add the OSV adapter, wire `--sca` flag, implement hard-fail + fail-closed severity + bounded stdout + env-hardening + symlink pre-filter.

**Requirements:** R6, R7, R8 (full), R9 (osv invocation boundary), R10 (CVE content sanitization), R11 (Pillow CVE on CE)

**Dependencies:** Unit 5

**Files:**
- Create: `src/griffith/analyzer/osv_adapter.py` (subprocess invocation, JSON parse, severity mapping)
- Modify: `src/griffith/analyzer/dependencies.py` (call OSV adapter when `sca=True`; populate `sca` subsection)
- Modify: `src/griffith/schema.py` (add `SCAResultDict` / `VulnerabilityDict`; extend `UNTRUSTED_FIELDS`)
- Modify: `src/griffith/reporter.py` (add CVE findings rendering; install-pitch branch that appears ONLY in `--sca` path when osv missing)
- Modify: `src/griffith/cli.py` (add `--sca` flag; hard-fail exit code 2 when osv-scanner missing AND `--sca` set)
- Create: `tests/test_osv_adapter.py`
- Modify: `tests/test_cli.py` (test `--sca` flag + hard-fail)
- Modify: `docs/json-schema.md` (Tier 2 shape)

**Approach:**
- OSV adapter:
  - `find_osv_scanner()` — priority: `GRIFFITH_OSV_SCANNER` env → `shutil.which` → fallback paths (including `~/go/bin/osv-scanner`); verify resolved path is not inside plugin tree, marketplace root, griffith cache dir, or tempfile root (expanded containment set); run `--version` to confirm compatibility
  - `run_osv(plugin_path)` — subprocess.Popen with **concurrent dual-reader**: stdout bounded at 32 MB, stderr bounded at 1 MB, both drained in parallel so neither blocks the other; `--` separator before plugin path; scrubbed env from `_build_osv_env` with `XDG_CACHE_HOME` set to `griffith_cache_dir() / "osv-scanner"` (avoids network-mounted HOME corrupting cache); 120s timeout
  - osv-scanner invocation flags: `scan source -r --format json --experimental-exclude g:.git --experimental-exclude g:node_modules --experimental-exclude g:.venv --experimental-exclude g:vendor <plus any symlinked manifests from pre-walk> -- <plugin_path>` (the `--experimental-exclude` flag accepts `g:<pattern>` glob syntax per v2.3.5; prunes `-r` walk from entering version control / vendored / virtual-env trees)
  - Pre-walk symlink filter: discover symlinked manifests via DependencyAnalyzer's own walk; pass them as additional `--experimental-exclude g:<abs_path>` flags. If osv-scanner invocation would exclude all manifests (every one is symlinked), skip with `scan_status="sca_requested_and_failed"` + reason. Alternative considered: copy-to-sandbox approach (copy non-symlink manifests to a temp dir, scan the sandbox). Deferred to Unit 6 implementation; `--experimental-exclude` is the preferred first path.
  - Exit code handling (verified against v2.3.5):
    - `0` → `scan_status="ok"`, zero CVEs
    - `1` → `scan_status="ok"`, CVEs populated from JSON (exit 1 is osv-scanner's "vulnerabilities found" success signal, NOT a failure)
    - `128` → `scan_status="ok"`, emit a note "osv-scanner found no scannable package sources (common for Node plugins without a lockfile)"; zero CVEs
    - Other nonzero + valid JSON parse → `scan_status="sca_requested_and_failed"`, stderr tail preserved in `sca.error`
    - Exit 0 + invalid JSON → `scan_status="sca_malformed_output"` (distinct from `sca_requested_and_failed` — signals potential tampering)
    - TimeoutExpired → `scan_status="sca_requested_and_timed_out"`
  - JSON parse: wrap in `try/except RecursionError` (depth-bomb defense; also set `sys.setrecursionlimit(500)` around the parse call and restore); iterate `results[].packages[]`; emit one `Vulnerability` per `groups[]` entry; map `max_severity` to Griffith severity via fail-closed table (critical default); preserve `severity_raw` (sanitized via `sanitize_string`)
  - Stderr capture: preserve the tail (last 1 KB), sanitize via `sanitize_for_markdown`, embed in `sca.error` when applicable (stderr contains plugin-influenced content per the "Stderr bleed" note)
- CLI: `--sca` flag; if set and osv-scanner missing → emit install pitch to stderr, exit 2. `--require-osv-scanner` accepted as an alias (same behavior; explicit CI signal). Decide final naming in-session (commit message can document).
- Reporter: CVE section only when `sca` is populated; install pitch only triggered by --sca-without-binary path (never in Tier 1 path)
- Install pitch text — structured constant in `osv_adapter.py`:
  - "Recommended for plugins with declared dependencies"
  - One sentence on supply-chain risk (Python typosquats, npm post-install); honest caveat that Claude-plugin-specific incidents aren't yet documented
  - `brew install osv-scanner` (macOS) + link to docs for other platforms
  - Mention `GRIFFITH_OSV_SCANNER` env override for custom paths

**Test scenarios:**
- Happy (exit 0, no vulns): mocked osv output with zero CVEs → `scan_status="ok"`, `sca.vulnerability_count==0`
- Happy (exit 1, vulns found): mocked osv output with 4 Pillow CVEs + exit code 1 → `scan_status="ok"` (NOT `sca_requested_and_failed`), CVEs populated. **Load-bearing test**: catches the P0 bug where exit-1-is-failure inverts R11's value.
- Happy (exit 128, no sources): bare `package.json` without lockfile → `scan_status="ok"`, empty CVEs, `sca.note` explains "osv-scanner found no scannable package sources (Node CVE scan requires lockfile)"
- Happy (no --sca): Tier 1 runs normally; `sca` is null; `scan_status == "tier1_only"`
- Happy (real osv, --sca, network-marked test): scan CE@2.67.0 → at least 1 Pillow CVE surfaces (R11 pin; exit code is 1, scan_status must be `ok`)
- Happy (mock pattern): use a `MockPopen` helper class exposing the Popen interface used by the adapter (`stdout.read` chunks, `stderr.read`, `wait(timeout)`, `terminate`, `returncode`) since existing `test_sources.py` patches `subprocess.run` which has a different shape
- Error (--sca, osv missing): mocked `find_osv_scanner` returns None → exit code 2 + install pitch on stderr + no partial report written
- Error (subprocess timeout): mocked Popen times out → `scan_status="sca_requested_and_timed_out"` in report; Tier 1 packages still present
- Error (stdout overflow): mocked subprocess emits 50 MB to stdout → process killed; `scan_status="sca_requested_and_failed"` with reason
- Error (stderr overflow): mocked subprocess emits 5 MB to stderr while stdout blocks on cap → concurrent dual-reader drains, stderr cap trips first → process killed; `scan_status="sca_requested_and_failed"`
- Error (malformed JSON): mocked subprocess exits 0 with `{malformed` stdout → `scan_status="sca_malformed_output"` (distinct from generic failure)
- Adversarial (CVE summary injection): mocked osv returns CVE with summary `"[click](https://evil.com)"` → rendered output shows inert text; JSON contains sanitized string without executable markdown
- Adversarial (nested-tag injection): mocked osv returns CVE with summary `"<<script>script>alert(1)<</script>/script>"` → fixpoint iterate neutralizes; inert text in all renderings
- Adversarial (Rich markup injection): mocked osv returns summary `"\\[bold red]FAKE[/]"` → `rich.markup.escape` handles pre-escaped backslash; Rich doesn't style
- Adversarial (symlink manifest): plugin with `requirements.txt → /etc/hosts` + `--sca` → osv-scanner invoked with `--experimental-exclude g:<abs_path_to_symlink>`; verify via captured argv; osv output contains no packages from that path
- Adversarial (all manifests symlinked): every detected manifest is a symlink → skip osv-scanner invocation entirely with `scan_status="sca_requested_and_failed"` + explicit symlink reason
- Adversarial (PATH shadow): mocked `which` returns path inside plugin tree OR inside marketplace root OR inside griffith cache dir → refused; `find_osv_scanner` returns None
- Adversarial (path argument): plugin_path like `--rm-rf` → osv-scanner invocation uses `--` separator; argument treated as path
- Adversarial (depth-bomb pyproject): 2 MB pyproject.toml with 10k-deep nested inline tables → `RecursionError` caught; manifest in `unscanned_manifests[]`
- Adversarial (CVSS vector instead of numeric): mocked osv emits `max_severity="CVSS:3.1/AV:N/AC:L/..."` → parser extracts base score OR falls back to severity="unknown" with logged warning (NOT fail-closed critical — would flood false positives if osv changes format)
- Severity (fail-closed): mocked osv emits CVE with `max_severity=""` (empty) → Griffith severity is `critical`, not `info`
- Severity (CVSS 9.5): → `critical`
- Severity (CVSS 7.1): → `high`
- Severity (CVSS 4.0): → `medium`
- Severity (CVSS 3.9): → `low`
- Severity (CVSS 0.0): → `info`
- Integration: `griffith analyze tests/fixtures/deps-python-plugin --json --sca` with real osv-scanner → Tier 1 listing + Tier 2 CVE on `requests` (pinned to 2.25.0)
- Integration (Node without lockfile): `griffith analyze tests/fixtures/deps-node-plugin --json --sca` → exit 128 from osv-scanner → `scan_status="ok"`, `sca.note` present, zero CVEs, Tier 1 listing still shows 4 packages

**Verification:**
- Full suite green (network tests skippable via `-m 'not network'`)
- Real-plugin end-to-end confirms R11 pin (Pillow CVE on CE)
- Manual: `griffith analyze <plugin> --json --sca | jq '.dependencies.sca'` shows expected shape

## System-Wide Impact

- **Interaction graph:** CLI → sources.resolve → Inventory → (Security, Footprint, Architecture, DependencyAnalyzer) → Report → reporter → stdout. DependencyAnalyzer additive; Tier 2 is a conditional branch within it.
- **Error propagation:** Tier 1 parser failures → `unscanned_manifests[]`, no crash. Tier 2 osv-scanner failures → `scan_status` reflects failure state + error field, Tier 1 output preserved, exit code 0. The only hard-fail path is `--sca` without osv-scanner installed → exit code 2 (user-explicit request for a missing tool).
- **State lifecycle risks:** None new. No caching, no persistent state, no network in Tier 1; Tier 2 hits osv.dev via osv-scanner (osv-scanner's concern, not ours).
- **API surface parity:** JSON schema additive. CLI gains one flag (`--sca`). Exit codes: 0 (ok), 1 (hard errors like unreadable path), 2 (`--sca` without osv-scanner). Missing osv-scanner when `--sca` is NOT used is not an event.
- **Integration coverage:** End-to-end test via `griffith analyze --json` against real plugins (Tier 1) and mocked + real osv-scanner (Tier 2).
- **Unchanged invariants:**
  - `schema_version = "0.1"` (kept — additive)
  - Existing analyzers (Inventory, Security, Footprint, Architecture) unchanged
  - Security scanner findings list does NOT merge with CVE findings (separate section, separate concern)
  - `sources.resolve` unchanged
  - Phase 1 hardening patterns preserved; osv-scanner subprocess uses `_build_osv_env` (NOT the clone's env scrub)
  - Default-path operation remains network-free + zero-external-dep (osv-scanner only required for `--sca`)

## Risks & Dependencies

| Risk | Owning unit | Mitigation |
|------|-------------|------------|
| Malformed manifest crashes parser (includes depth bombs + ReDoS) | Units 2-3 | `try/except` covers `RecursionError`, `JSONDecodeError`, `TOMLDecodeError`, OSError, ValueError; temp `setrecursionlimit(500)` around parse; requirements.txt regex is anchored + bounded-repetition; malformed entries in `unscanned_manifests[]`; other manifests still parse |
| Symlinked manifest escape | Unit 1 (walk) + Unit 6 (osv filter) | Pre-walk refuses symlinks; osv-scanner invoked with `--experimental-exclude g:<path>` per symlinked manifest; if ALL manifests are symlinked, skip osv-scanner entirely with `scan_status="sca_requested_and_failed"`. Copy-to-sandbox alternative (copy non-symlinked manifests to temp dir and scan there) documented as Unit 6 fallback if --experimental-exclude proves unreliable. |
| Unbounded osv-scanner output → OOM or pipe-deadlock | Unit 6 | Concurrent dual-reader: stdout 32 MB cap + stderr 1 MB cap, both drained in parallel. Overflow on either → subprocess killed + scan_status failed. Prevents both size-based DoS and pipe-buffer deadlock. |
| Shadowed osv-scanner binary | Unit 6 | Realpath check rejects paths inside plugin tree, marketplace root, griffith cache dir, or tempfile root; `GRIFFITH_OSV_SCANNER` env override for pinning |
| CVE summary contains Markdown/HTML/Rich markup injection | Units 4, 6 | `sanitize_for_markdown` iterates-until-fixpoint (neutralizes nested `<<script>script>`); strips HTML comments + CDATA; `sanitize_for_rich` uses `rich.markup.escape` (handles backslash edge cases); full `UNTRUSTED_FIELDS` enumeration for Tier 1 + Tier 2 including `severity_raw`, `sca.error`, `unscanned_manifests[]` |
| Unknown CVSS → silent severity downgrade | Unit 6 | Fail-closed mapping: unparseable → critical; `severity_raw` preserved and sanitized; vector-string format tolerated via fallback to severity="unknown" rather than flood-critical |
| Exit code 1 misclassified as failure | Unit 6 | Explicit exit-code table (0/1 → ok with or without vulns; 128 → ok + no-sources note; other → failed). Load-bearing test enforces exit-1-with-vulns == ok. |
| Node package.json without lockfile returns empty CVE | Unit 6 + docs | Surface as `sca.note` field when exit 128; README documents the requirement; distinct from `sca_requested_and_failed` |
| False-clean in CI when osv-scanner missing | Unit 6 + docs/json-schema.md | `scan_status` field authoritative; `--sca` without osv → hard fail (exit 2); docs call out consumers must check status; `sca_malformed_output` distinguishes tampering signal from generic failure |
| osv-scanner env-scrub breaks network or cache | Unit 6 | `_build_osv_env` preserves PATH, HTTPS_PROXY, SSL_CERT_FILE, XDG_*; overrides XDG_CACHE_HOME to griffith cache dir (avoids network-mounted-HOME corruption); tests verify network-required run still works |
| osv-scanner subprocess slow on first run | Unit 6 | 120s timeout; first-run DB fetch within budget on reasonable networks; XDG_CACHE_HOME override means DB persists across runs |
| osv-scanner output format drift across versions | Unit 6 | Version detection on init; graceful handling of unknown top-level keys; log unexpected keys to stderr; CVSS vector-string fallback handles osv format drift |
| Untrusted package content prompt-inject LMF renderer | Units 4, 5, 6 | Full `UNTRUSTED_FIELDS` enumeration; LMF wrapper MUST read UNTRUSTED_FIELDS dynamically (not hardcoded); tracked in separate LMF plan |
| LMF release lags Griffith → new untrusted fields rendered unsanitized | Release sequencing | Before shipping Griffith v-next, verify LMF wrapper iterates UNTRUSTED_FIELDS dynamically. If hardcoded: sequence LMF update first. Call out in LMF plan. |
| OSV-Scanner project durability (Google OSS track record) | Architecture | `osv_adapter.py` isolates the integration; preferred fallback: **trivy** (`trivy fs --format json`) for SBOM + CVE; alternative: syft+grype. Ground-truth fallback comparison tracked in separate `.claude/work/followups/sca-tool-fallbacks.md`. |

## Documentation / Operational Notes

- `docs/json-schema.md`: add `dependencies` section (Tier 1 shape, Tier 2 success/128/failed/malformed-output shapes, `scan_status` enum with full explanation, `untrusted_fields` update including `severity_raw` + `sca.error` + `unscanned_manifests[]`)
- `README.md`:
  - New "Dependencies" bullet in "What it does" table
  - "Optional: install osv-scanner for CVE analysis" one-paragraph section with brew command + docs link
  - `--sca` flag in Quick Start examples
  - Explicit note: **Node CVE scanning requires a lockfile** (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`) — bare `package.json` yields Tier 1 listing only
  - Note on `scan_status` as the authoritative consumer trust signal (critically: `scan_status == "ok"` is the only state where zero CVEs means "no known vulns")
- Exit code table in README: 0 (ok), 1 (hard errors like unreadable path), 2 (`--sca` without osv-scanner)
- New followup to create: `.claude/work/followups/sca-tool-fallbacks.md` — tracks ground-truth comparison for trivy / syft+grype as future replacements if osv-scanner becomes unviable
- No migration / rollout concerns (additive). Cross-repo: LMF wrapper update lands in a separate plan in `gruntwork-marketplace`; verify LMF reads `untrusted_fields` dynamically (not hardcoded) before Griffith v-next ships, or sequence LMF update first.

## Sources & References

- **Origin followup:** `.claude/work/followups/dependency-analysis.md`
- **Phase 1 plan:** `.claude/work/plans/phase-1-analyzer-mvp.md` (conventions)
- **Schema stability contract:** `docs/json-schema.md`
- **OSV-Scanner:** https://google.github.io/osv-scanner/
- **OSV-Scanner ground-truth:** verified against v2.3.5 — output filters to vulnerable packages only; pyproject.toml not parsed; CVSS numeric severity; `scan source -r --format json` is the correct invocation
- **Related followups:**
  - `.claude/work/followups/refine-subprocess-rule-with-ast.md` (complementary)
  - `.claude/work/followups/commands-vs-skills-convention.md` (unrelated)
- **Pre-plan reference artifacts (expectations revised by this plan):**
  - `tests/test_dependencies.py` (rewrite for Phase 1.5 scope)
  - `tests/fixtures/deps-python-plugin/` + `deps-node-plugin/` + `deps-multi-ecosystem-plugin/` (retained)
