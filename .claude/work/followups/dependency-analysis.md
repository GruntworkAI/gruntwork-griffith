# Follow-up: dependency analysis (SCA) is missing from Phase 1

**Surfaced during Phase 1 polish (2026-04-18).**

Griffith Phase 1 scans plugin source trees for Claude-specific threats
(hook shell execution, symlinks, YAML RCE, etc.) but does not evaluate the
plugin's **supply chain**. A plugin can ship a `requirements.txt`,
`package.json`, `Gemfile`, or `go.mod` and Griffith will silently pass over
it. The user sees a "clean" report, then pip/npm/etc. pulls in N transitive
deps at install time — including potentially vulnerable versions.

## Evidence

Concrete example found in the wild: `compound-engineering@2.67.0` ships
`skills/gemini-imagegen/requirements.txt`:

```
google-genai>=1.0.0
Pillow>=10.0.0
```

Current Griffith output against this plugin:
- `risk_level: info` (zero critical/high)
- `unknown components: 0`
- Zero findings that mention `requirements.txt` or its packages

A user running `/run-audit-plugin EveryInc/every-marketplace` today would
have no idea that installing the `gemini-imagegen` skill pulls a Python
dependency chain, let alone which versions.

## Scope of the gap

| Category | Current state | What's needed |
|----------|--------------|---------------|
| Dep manifest detection | Not detected; silently skipped | File-presence scan at plugin root + per-subdir |
| Dep listing in report | Absent | Parse each manifest (Python, Node, Ruby, Go, Rust) and enumerate packages + version constraints |
| CVE / SCA scanning | Absent | Integrate OSV-Scanner (OSS, Google, multi-ecosystem) as optional step |
| Vendored code detection | Not detected (bundled `node_modules/`, `.venv/` invisible) | Flag presence + optionally recursively scan |
| System binary requirements | Partial (`hook-requires-gh-cli` only) | Generic rule: detect `\b(gh|git|docker|aws|terraform|jq|curl|wget|node|python3?)\s` in hooks |
| MCP runtime deps | Absent (MCP dir walked as opaque files) | Parse MCP server manifests if present |

## Proposed architecture: new `analyzer/dependencies.py`

```python
@dataclass
class DependencyFinding:
    ecosystem: str           # "pypi", "npm", "rubygems", "go", "cargo", "system"
    manifest: str            # relative path, e.g. "skills/foo/requirements.txt"
    package: str             # "Pillow"
    constraint: str          # ">=10.0.0"
    # CVE fields populated only when --sca is enabled and osv-scanner succeeds:
    cve_ids: list[str] | None
    max_cvss: float | None

@dataclass
class DependencyReport:
    findings: list[DependencyFinding]
    manifests_detected: list[str]   # all dep-manifest files seen
    vendored_trees: list[str]       # paths like "node_modules/", ".venv/"
    unscanned_ecosystems: list[str] # e.g., if OSV-Scanner not installed
```

### Integration points
- **Inventory**: add a `dep_manifests: list[ComponentFile]` bucket during walk
  (or classify in `unknown` with a subtype)
- **Report schema**: add top-level `dependencies: DependencyReport` field
- **Rich renderer**: new "Dependencies" section listing ecosystems + CVE counts
- **JSON schema**: bump `schema_version` to 0.2; add the new section
- **CLI**: `--sca` flag to enable CVE lookups (network-dependent; slower)

## Manifest detection heuristics

| Ecosystem | Manifest files | Notes |
|-----------|---------------|-------|
| Python | `pyproject.toml`, `requirements*.txt`, `setup.py`, `setup.cfg`, `Pipfile`, `poetry.lock` | Parse `[project.dependencies]` from pyproject; regex for requirements.txt |
| Node | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `dependencies` + `devDependencies` |
| Ruby | `Gemfile`, `Gemfile.lock`, `*.gemspec` | |
| Go | `go.mod`, `go.sum` | |
| Rust | `Cargo.toml`, `Cargo.lock` | |

Detection should walk the whole plugin tree (recursive) — real plugins put
manifests at any depth (e.g. CE's `skills/gemini-imagegen/requirements.txt`).

## OSV-Scanner integration (optional, gated by `--sca`)

OSV-Scanner is Google's OSS SCA tool. Multi-ecosystem, reads manifest files
directly, queries osv.dev's aggregate advisory DB.

```bash
# Shell out; parse JSON output
osv-scanner scan source --format json <plugin-root>
```

- Free, no API key
- Covers every ecosystem listed above
- Aggregates GitHub Advisory DB + OSV + distro-specific DBs
- Report is detailed per-package with CVE IDs and CVSS scores

Prereqs:
- User installs OSV-Scanner: `brew install osv-scanner` or Go install
- Griffith detects presence; if missing + `--sca` passed, show install
  instructions and exit (same pattern as audit-plugin + griffith itself)

## Sanity-check heuristic (even without OSV-Scanner)

Before full SCA integration, a cheap win: flag manifest presence + list
package names in the report. Users can copy-paste into their own auditing.

```
## Dependencies

The plugin declares the following dep manifests:
- skills/gemini-imagegen/requirements.txt (pypi, 2 packages)
  - google-genai >=1.0.0
  - Pillow >=10.0.0

Run `griffith analyze <source> --sca` for CVE scanning (requires osv-scanner).
```

This alone is a significant transparency upgrade from "nothing."

## Vendored-code detection

Heuristic: presence of any of these directory names in the plugin tree is a
red flag warranting a finding at info severity:

- `node_modules/`
- `.venv/`, `venv/`, `env/`, `.env/` (the dir, not the file)
- `vendor/` (Go, PHP, Ruby convention)
- `target/` (Rust artifacts)

Vendored code means:
1. Plugin authors shipped dependency source directly
2. That source was not built from the manifest at install time (so hash
   checks and CVE DBs may not apply to what's actually on disk)
3. A malicious dep can hide inside the vendored tree without showing up in
   the manifest

The inventory walk already has containment checks; vendored trees should
be flagged + potentially scanned recursively with existing rules.

## System binary requirements

Low-hanging fruit: expand the existing `hook-requires-gh-cli` rule into a
generic "hook-requires-external-binary" rule that scans for common binaries:

```yaml
- id: hook-requires-external-binary
  severity: info
  pattern: '\b(gh|docker|aws|terraform|kubectl|jq|curl|wget|node|python3?|poetry|npm|yarn|pnpm|go|cargo|ruby|bundle)\s'
  context: "hooks/**/*"
  message: "Hook requires external binary — verify it is installed before running"
```

Phase 1.5 Security Rules work should include this.

## Priority

**High.** Dependency supply-chain attacks are a known, active threat class
(XZ Utils, event-stream, ua-parser-js, pycrypto typosquats, etc.). A plugin
auditor that misses the plugin's own supply chain is a meaningful gap in
the value proposition.

## Testing

When built, extend `tests/fixtures/` with:

- `fixtures/deps-python-plugin/` — with `requirements.txt` and `pyproject.toml`
- `fixtures/deps-node-plugin/` — with `package.json`
- `fixtures/deps-vendored-plugin/` — with a fake `node_modules/` tree
- `fixtures/deps-multi-ecosystem-plugin/` — Python + Node + Ruby

Real-plugin integration:
- `compound-engineering` should surface `skills/gemini-imagegen/requirements.txt`
  with 2 packages
- `lastmilefirst` should report zero manifests

## Related

- [refine-subprocess-rule-with-ast.md](refine-subprocess-rule-with-ast.md) —
  addresses code-level subprocess analysis; complementary to this follow-up
  which is manifest-level
- [commands-vs-skills-convention.md](commands-vs-skills-convention.md) —
  unrelated to deps but same Phase 1.5 polish cohort
