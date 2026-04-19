# Griffith JSON Schema (v0.1)

This document describes the JSON output contract produced by `griffith analyze --json`.

**Status: v0.1, explicitly unstable.** The primary consumer is the LMF `/run-audit-plugin` wrapper skill. Until that consumer stabilizes, the schema may change between minor releases. Downstream consumers MUST read the top-level `schema_version` field before unpacking.

## Two top-level shapes

Griffith produces one of two root shapes depending on the source:

1. **Single-plugin `Report`** — when analyzing a single plugin directory or URL
2. **`MarketplaceReport`** — when analyzing a marketplace root (contains `.claude-plugin/marketplace.json`)

Consumers can disambiguate by presence of the `marketplace` key: `"marketplace" in report`.

## Single-plugin Report

```json
{
  "schema_version": "0.1",
  "plugin": {
    "name": "minimal",
    "path": ".",
    "source": "./tests/fixtures/minimal-plugin"
  },
  "inventory": {
    "counts": {
      "agents": 1,
      "commands": 1,
      "skills": 1,
      "hooks": 1,
      "mcp_servers": 0,
      "personas": 0,
      "templates": 0,
      "unknown": 0
    },
    "totals": {
      "files": 4,
      "lines": 20
    }
  },
  "security": {
    "risk_level": "none",
    "finding_count": 0,
    "findings": []
  },
  "footprint": {
    "baseline_tokens_approx_cl100k": 170,
    "on_demand_max": 208,
    "primary_driver": "agents",
    "efficiency_rating": "excellent",
    "per_component": {
      "agents": 100,
      "commands": 50,
      "skills": 20,
      "hooks": 0,
      "mcp_servers": 0
    }
  },
  "architecture": {
    "pattern": "hybrid",
    "efficiency_notes": [
      "No MCP servers — low always-on context cost.",
      "No hooks — no out-of-band execution."
    ],
    "recommendations": [
      "Balanced architecture — no obvious consolidation opportunity..."
    ]
  },
  "analysis_scope": ["static"],
  "untrusted_fields": [
    "plugin.name",
    "security.findings[].file",
    "architecture.efficiency_notes[]",
    "architecture.recommendations[]"
  ],
  "meta": {
    "griffith_version": "0.1.0",
    "griffith_hardening_version": "1",
    "analyzed_at": "2026-04-17T22:00:00Z",
    "source_type": "path"
  }
}
```

### Fields

| Path | Type | Notes |
|------|------|-------|
| `schema_version` | string | Always compare before unpacking. Breaking changes bump this. |
| `plugin.name` | string | **Untrusted** (from plugin.json, sanitized) |
| `plugin.path` | string | Relative to clone root for URL sources; `.` or plugin-root for local; `plugins/<name>` for marketplace entries |
| `plugin.source` | string | Original user-provided source string |
| `inventory.counts` | object | One int per component type |
| `inventory.totals.{files,lines}` | int | Across all component files |
| `security.risk_level` | enum | `critical` / `high` / `medium` / `low` / `info` / `none` — derived from highest severity finding |
| `security.finding_count` | int | `len(findings)` |
| `security.findings[]` | array | See Finding shape below |
| `footprint.baseline_tokens_approx_cl100k` | int | Always-on context cost (heuristic tuned to approximate cl100k; **not Claude's actual tokenizer**) |
| `footprint.on_demand_max` | int | Peak total when everything invoked |
| `footprint.primary_driver` | string | Component type with largest baseline contribution, or `"none"` |
| `footprint.efficiency_rating` | enum | `excellent` (<500) / `good` (<1500) / `moderate` (<3000) / `heavy` (<5000) / `excessive` (≥5000) |
| `footprint.per_component` | object | Breakdown by component type |
| `architecture.pattern` | enum | `agent-heavy` / `skill-first` / `mcp-based` / `hybrid` |
| `architecture.efficiency_notes[]` | array of string | Qualitative observations |
| `architecture.recommendations[]` | array of string | Optional suggestions |
| `dependencies.scan_status` | enum | `tier1_only` when `--sca` is not used; `ok`, `sca_requested_and_failed`, `sca_requested_and_timed_out`, `sca_malformed_output` when `--sca` is used. **Consumers MUST check `scan_status == "ok"` before treating zero CVEs as clean** — any other status means the CVE scan did not produce authoritative output. |
| `dependencies.manifests[]` | array of object | Each: `{path, is_symlink, size_skipped}`. **`path` untrusted.** |
| `dependencies.lockfiles[]` | array of object | Same shape as manifests. Presence recorded; contents not parsed in Tier 1. |
| `dependencies.unscanned_manifests[]` | array of string | Paths of manifests the parser could not read (malformed, too large, etc.). **Untrusted.** |
| `dependencies.ecosystems[]` | array of string | Sorted list of ecosystems present in `packages[]` (e.g. `["PyPI", "npm"]`). |
| `dependencies.package_count` | int | `len(packages)`. |
| `dependencies.packages[]` | array of object | See Package shape below. |
| `dependencies.sca` | object or null | Tier 2 CVE result. `null` when `--sca` is not used; otherwise an SCAResult object (see shape below). |
| `analysis_scope` | array | Always `["static"]` in v0.1. Does **not** include LLM-based skill review. |
| `untrusted_fields[]` | array | Dotted paths of fields derived from plugin content |
| `meta.griffith_version` | string | e.g. `"0.1.0"` |
| `meta.griffith_hardening_version` | string | Increments when clone/analyzer hardening changes |
| `meta.analyzed_at` | string | ISO-8601 UTC |
| `meta.source_type` | enum | `url` / `shorthand` / `path` |

### Package shape (Tier 1 dependencies)

```json
{
  "ecosystem": "PyPI",
  "name": "Pillow",
  "constraint": ">=10.0.0,<11.0.0",
  "kind": "runtime",
  "manifest": "skills/gemini-imagegen/requirements.txt"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `ecosystem` | string | `"PyPI"` / `"npm"` / (future: rubygems, go, cargo). **Untrusted.** |
| `name` | string | Package name. Extras (`[full]`) are stripped. **Untrusted.** |
| `constraint` | string | Version spec as written (`>=1.0`, `^2.3`, empty for unpinned). **Untrusted.** |
| `kind` | enum | `runtime` / `dev` / `optional` / `peer`. Griffith-controlled (not untrusted). |
| `manifest` | string | Relative path to the manifest declaring this package. **Untrusted.** |

Phase 1.5 Unit 5 parses Python (`requirements*.txt`, `pyproject.toml` — PEP 621 + Poetry) and Node (`package.json`). Ruby / Go / Rust manifests are **detected** (surface in `manifests[]`) but not parsed; their packages are deferred to Phase 1.6.

### SCAResult shape (Tier 2 dependencies — `--sca` only)

`dependencies.sca` is `null` unless `griffith analyze --sca` is used. When present, the object has this shape:

```json
{
  "osv_scanner_version": "2.3.5",
  "vulnerability_count": 2,
  "vulnerabilities": [ /* Vulnerability objects — see below */ ],
  "note": null,
  "error": null
}
```

| Field | Type | Notes |
|-------|------|-------|
| `osv_scanner_version` | string | Probed via `osv-scanner --version`. `"unknown"` if the probe fails. |
| `vulnerability_count` | int | `len(vulnerabilities)`. |
| `vulnerabilities[]` | array of object | See Vulnerability shape below. |
| `note` | string or null | Griffith-authored explanation (e.g. "osv-scanner found no scannable package sources"). Trusted. |
| `error` | string or null | Failure tail when `scan_status != "ok"`. **Untrusted** — may contain osv-scanner stderr. |

**Status variants (driven by top-level `dependencies.scan_status`):**

- `ok` with `vulnerability_count == 0`, `note == null`, `error == null` — clean scan.
- `ok` with `note` set, `vulnerabilities == []` — osv-scanner returned exit 128 (no scannable sources). Common for Node plugins without a lockfile.
- `sca_requested_and_failed` — non-zero exit from osv-scanner; `error` contains a stderr tail.
- `sca_requested_and_timed_out` — wall-clock timeout (default 120s); `error` describes the timeout.
- `sca_malformed_output` — exit 0 but stdout was not valid JSON. Possible tampering / version drift signal.

### Vulnerability shape

```json
{
  "id": "GHSA-xxxx-yyyy-zzzz",
  "severity": "high",
  "severity_raw": "7.5",
  "summary": "requests SSRF",
  "affected_package": "requests",
  "fixed_versions": ["2.31.0"]
}
```

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | CVE / GHSA / OSV identifier. **Untrusted.** |
| `severity` | enum | `critical` / `high` / `medium` / `low` / `info`. Griffith-controlled; derived from `severity_raw` via fail-closed CVSS mapping. Unparseable CVSS → `critical` (not `info`) so CI gates don't miss real criticals due to upstream schema drift. |
| `severity_raw` | string | As-emitted CVSS value (numeric like `"7.5"` or vector like `"CVSS:3.1/AV:N/AC:L/…"`). **Untrusted.** |
| `summary` | string | One-line description. **Untrusted.** |
| `affected_package` | string | Package name as osv-scanner reported it. **Untrusted.** |
| `fixed_versions[]` | array of string | Versions that remediate this vulnerability, drawn from the OSV `affected[].ranges[].events[].fixed` fields. **Untrusted.** |

### Finding shape

```json
{
  "rule_id": "curl-pipe-shell",
  "severity": "critical",
  "file": "hooks/evil.sh",
  "line": 3,
  "message": "Pipe to shell (curl | sh) — remote code execution vector"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `rule_id` | string | Stable identifier per rule |
| `severity` | enum | `critical` / `high` / `medium` / `low` / `info` |
| `file` | string | Relative to plugin root. **Untrusted** (plugin-controlled path component) |
| `line` | int | 1-indexed; `0` for file-level findings (symlinks, oversized) |
| `message` | string | Human-readable description (from rule config, not plugin content) |

**Important:** `SecurityFinding` never carries matched bytes. A rule that fires near a secret will not echo that secret. If you need content context, read the source file yourself — do not rely on Griffith.

## MarketplaceReport

When the source is a marketplace root:

```json
{
  "schema_version": "0.1",
  "marketplace": {
    "source": "~/Code/every/every-marketplace",
    "path": "/tmp/griffith-abc123/repo"
  },
  "reports": [
    { /* Report, one per plugin under plugins/ */ },
    { /* ... */ }
  ],
  "summary": {
    "plugin_count": 2,
    "risk_level_counts": {"none": 1, "info": 1},
    "patterns": {"agent-heavy": 1, "hybrid": 1}
  },
  "meta": { /* same shape as single-plugin meta */ }
}
```

### Fields

| Path | Type | Notes |
|------|------|-------|
| `marketplace.source` | string | User-provided source (URL / path) |
| `marketplace.path` | string | Local path to the marketplace root (clone tempdir or original local) |
| `reports[]` | array of Report | One entry per `plugins/<name>` directory with a valid `plugin.json` |
| `summary.plugin_count` | int | `len(reports)` |
| `summary.risk_level_counts` | object | Plugins grouped by their `security.risk_level` |
| `summary.patterns` | object | Plugins grouped by their `architecture.pattern` |

## Handling untrusted content

Every string in `untrusted_fields` originated from the plugin itself (plugin.json, markdown frontmatter, file paths). Before rendering these to a Claude session or any LLM prompt:

1. **Wrap in an instruction-neutral envelope** — a code fence, a quoted block, or similar. Claude should never mistake plugin content for an instruction from the user.
2. **Sanitize (Griffith already does this for you)** — control chars, ANSI escapes, Unicode bidi overrides, and zero-width codepoints are stripped before the field is embedded.
3. **Length-cap honored** — Griffith caps `name` at 80 chars, `description` at 240.

If you write a new downstream consumer, walk `untrusted_fields[]` and apply the envelope to each dotted path.

## Error handling

On error, `griffith analyze` exits non-zero (1) and writes an error message to **stderr**. `stdout` is empty in that case. Consumers should check the exit code before parsing stdout as JSON.

```bash
griffith analyze /does/not/exist --json
# Exit code: 1
# stderr: "Not found: Plugin path does not exist: /does/not/exist"
# stdout: ""
```

## Stability guarantees (v0.1)

Until `schema_version` reaches `1.0`:

- **Fields may be added** without bumping schema_version
- **Fields may be removed** with a schema_version bump
- **Field semantics may change** with a schema_version bump
- **Enum values may be added** (e.g., new severity levels, new patterns)

Consumers should treat unknown enum values and unknown fields gracefully.

## Version history

- **0.1** (2026-04) — initial schema; Phase 1 MVP
