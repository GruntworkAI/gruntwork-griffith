---
title: "feat: AST-based refinement of noisy security rules"
type: feat
status: active
date: 2026-04-20
reviewed: 2026-04-20
origin: .claude/work/followups/refine-subprocess-rule-with-ast.md
---

# AST-based refinement of noisy security rules

## Overview

Three of Griffith's regex security rules produce false positives against real plugins in ways that erode the audit tool's signal:

- `subprocess-in-hooks` (high) — fires on every `subprocess.*` call in `hooks/**/*`. lastmilefirst 0.14.0: 8/8 calls; ground-truth verification shows 5 use pure-constant list args, 2 use dynamic args, all 8 set `timeout=`.
- `path-traversal` (medium) — fires on every `../../` substring. obra/superpowers-marketplace: 19/19 are in test files using `path.join(__dirname, '../../...')`, a standard Node test pattern.
- `bash-c-inline` (high) — fires on every `bash -c "..."`. superpowers: 1/1 is `timeout "$timeout" bash -c "$cmd"` in a test helper — actually dynamic (`$cmd` is a variable), so the correct refined signal is 1 critical finding, not 0.

Each is "regex matches correctly, security conclusion wrong." The fix is to use *structure* (Python AST for subprocess/path refinement; structure-aware regex for shell) to tell safe from risky, applying the origin followup's additive-never-silence design posture uniformly.

Post-refinement: existing rule IDs stay emitted at `info` (capability signals never silenced); new stricter rules fire additively when structure detects risky patterns; real findings surface at actionable severities; regex-noise findings drop to `info`.

## Problem Frame

The origin followup contains the load-bearing design warning (lines 39-65) against the naive refactor — downgrading `subprocess-in-hooks` to `info` *only when safe patterns are detected*. That creates real security holes: `subprocess.run(["git", "clone", attacker_url], timeout=30)` passes "looks safe" checks but is vulnerable to git's `--upload-pack` argument-injection.

The correct posture: capability signal always fires (as `info`); stricter rules stack on top when risky patterns are structurally present. This plan extends that posture to `path-traversal` and `bash-c-inline` because both exhibit the same "regex match correct, context lost" pattern.

Blanket `tests/` exclusion was rejected during planning — it creates an attack surface where malicious code hides under test-named paths. Refinement preserves full scanning coverage.

**Consumer impact.** The LMF `/run-audit-plugin` wrapper (shipped in `gruntwork-marketplace`) renders findings grouped by severity and derives `verdict` from the highest severity. This plan shifts the severity distribution for three existing rule IDs. That is a **contract change** for any consumer that pins on specific rule-ID severity values. Mitigation: R11 adds the explicit carve-out to the schema stability guarantees.

## Requirements Trace

- **R1.** Refine `subprocess-in-hooks`: downgrade to `info`; add `subprocess-shell-true` (critical), `subprocess-dynamic-command` (high, inverted check — fires on any non-provably-static arg), `subprocess-no-timeout` (low, reliability). AST-based, `hooks/**/*.py`. Excludes `subprocess.Popen` from the no-timeout rule.
- **R2.** Refine `path-traversal`: downgrade to `info`; add `path-traversal-dynamic` (high) — Python AST for `.py` files + structure-aware regex for `.js/.ts/.sh`.
- **R3.** Refine `bash-c-inline`: downgrade to `info`; add **two** separate rule IDs:
  - `bash-c-dynamic-interpolated` (critical) — double-quoted or unquoted `-c` arg with `$VAR`/`${…}`/`$(…)`/backticks
  - `bash-c-dynamic-literal-dollar` (medium) — single-quoted `-c` arg containing literal `$`
- **R4.** Add `dynamic-code-exec` (info) and `dynamic-code-exec-dynamic-arg` (medium):
  - `dynamic-code-exec` (info) — any `exec()`/`eval()` in hooks (capability signal)
  - `dynamic-code-exec-dynamic-arg` (medium) — `exec`/`eval` where `args[0]` is not a `Constant`. Mirrors the subprocess inverted check. The security review's repeated concern about info-level findings being filtered out by consumers — this resolves it.
- **R5.** Preserve always-fires capability signals — existing rule IDs keep firing at `info`.
- **R6.** No full-scan coverage reduction — no blanket-exclude of test paths.
- **R7.** AST parsing of hostile Python source never crashes. Per-file failure in hook path emits **high** `ast-parse-failed` finding; elsewhere emits to `meta.ast_parse_failures: [...]` only.
- **R8.** Build an **alias table** from `Import`/`ImportFrom` nodes. Correctly handle dotted imports: `import a.b.c` binds `a` locally (not `a.b.c`). Resolver reconstructs the full attribute chain from a root `Name`. See Design section for working code.
- **R9.** `subprocess.Popen` is special-cased: `subprocess-no-timeout` does NOT fire on Popen calls (Popen's timeout lives on `.wait()/.communicate()`).
- **R10.** Unified `Rule` dataclass (NOT protocol — see Decision 2) with `engine_kind: Literal["regex", "ast", "shell-regex"]` discriminator. Wraps YAML regex rules and AST-registered functions; single registry populated at scanner init + module import.
- **R11.** Amend `docs/json-schema.md` stability guarantees with the literal bullet text:
  > **In schema_version `0.1`, the `severity` assigned to a given `rule_id` may change within the enum set without bumping `schema_version`. Consumers SHOULD group findings by severity bucket and/or match on allow-listed `rule_id` sets; consumers SHOULD NOT hard-code a specific `(rule_id, severity)` tuple as a gate. This carve-out is a one-time v0.1 concession; future loosenings require a version bump.**

  Unit 0a's verification greps for the literal anchor phrase `may change within the enum set without bumping schema_version` — any rewording breaks the test.
- **R12.** Real-plugin integration via **fingerprint snapshots** with stable `(rule_id, file)` multiset key; `line_hint` is informational only (resilient to line-number drift); `griffith_version` recorded but not asserted.
- **R13.** Performance: one AST parse per Python file per scan; tree reused. Real-plugin snapshot tests use `@pytest.mark.timeout(5)` to enforce ≤5s wall-clock each.
- **R14.** Schema stays at `schema_version = "0.1"` under R11's carve-out.
- **R15.** At least one snapshot test runs **unconditionally** (no `skipif`) against a checked-in fixture so CI environments without cached real plugins still gate on rule output.

## Scope Boundaries

- **Not implementing** full semantic taint analysis. Dynamic detection is a signal, not proof.
- **Not implementing** a full shell parser. `bash-c-dynamic-*` uses carefully-specified regex.
- **Not implementing** pathlib/os.path traversal tracking beyond f-string + concat.
- **Not migrating** existing YAML regex rules to Python. Only new AST rules live in Python; YAML rules wrap through the `Rule` dataclass adapter.
- **Not adding** `category` (capability/vuln/hygiene) field on rules.
- **Not adding** in-source `# griffith:ok` suppression comments.
- **Not refining** `compile()` / `FunctionType(compile(...).co_consts[0], globals())` evasion paths (Decision 15 note).

### Deferred to Separate Tasks

- Full taint propagation tracking (Phase 2).
- JS/TS AST-based refinement (separate effort; current JS coverage is structure-aware regex only).
- `compile()` evasion detection.
- In-source suppression mechanism.
- `category` classification field on rules.

## Context & Research

### Relevant Code and Patterns

**Scanner engine:**
- `src/griffith/analyzer/security.py` — `SecurityScanner`, `_CompiledRule`, `SecurityFinding`, `_scan_file`.
- `rules/security_patterns.yaml` — target rules at lines 70-74, 82-86, 125-130.

**Robust untrusted-source parsing (copy this shape):**
- `src/griffith/analyzer/dependencies.py::_parse_pyproject` lines 324-348 — `sys.setrecursionlimit` guard, broad exception catch, fallback to unscanned list, `finally` restore.

**Schema contract:**
- `docs/json-schema.md` lines 274-283 — stability guarantees. R11 amends.

**Test harness:**
- `tests/test_security.py` — 7 classes, `@pytest.mark.adversarial`, `TestRealPlugin*` integration with soft ceiling (replaced by fingerprint snapshots).
- `tests/fixtures/security-traps-plugin/` — existing intentionally-bad fixtures. Will receive new hook files + one checked-in snapshot per R15.

**Consumer:**
- `gruntwork-marketplace/plugins/lastmilefirst/skills/audit-plugin/scripts/audit_plugin.py` — consumes Griffith JSON, renders by severity.

### Ground-truth verification (completed during planning)

lmf 0.14.0 hooks — 8 subprocess calls:

| File:Line | Shape | Expected fingerprint |
|-----------|-------|-----------------------|
| `run.py:31` | `subprocess.run(cmd.split() + ["--version"], timeout=5)` | info capability + **high dynamic** |
| `run.py:68` | `subprocess.run([sys.executable, str(p)] + args, timeout=30)` | info + **high dynamic** |
| `session_start.py:49, 58, 280` | `subprocess.run(["git"/"gh", ...], timeout=5)` | info only |
| `session_start.py:289` | `subprocess.run(["gh", …-list-of-constants…], timeout=5)` | info only |
| `stop_hook.py:28, 38` | `subprocess.run(["git", ...], timeout=5)` | info only |

All 8 have `timeout=`, none have `shell=True`. Expected post-refinement: 8 info + 2 high + 0 critical + 0 low + 0 Popen. The 2 high findings are correct signal.

## Key Technical Decisions

1. **Additive-never-silence, uniformly applied.** All existing rule IDs stay firing; severities downgrade to `info`; new stricter rules stack on top. Applies to `dynamic-code-exec` and the new `dynamic-code-exec-dynamic-arg` the same way.

2. **Unified `Rule` dataclass** (not Protocol). Dataclass-with-adapter chosen because `run(ctx) -> list[Finding]` needs behavior, not just shape. Shape:
    ```
    @dataclass
    class Rule:
        rule_id: str
        severity: str
        file_filter: str                          # glob
        engine_kind: Literal["regex", "ast", "shell-regex"]
        run: Callable[[RuleContext], list[Finding]]
    ```
    YAML-authored regex rules compile through the existing `_CompiledRule` path and get wrapped in a `Rule` adapter at scanner init. AST rules register directly via `@ast_rule(...)` decorator. One registry, dispatched by `engine_kind`.

3. **AST rules as decorator-registered functions.** `@ast_rule(id=..., severity=..., file_filter=...)` decorates `def check(ctx) -> list[SecurityFinding]`. `RuleContext` dataclass carries `tree, path, alias_table` (and leaves room for future `prior_findings`). Authoring overhead: ~15 LOC per new rule.

4. **Alias table correctly handles dotted imports.** See Design section for working code. Key invariants: (a) `import a.b.c` (no `as`) binds `a` locally; alias_table key is `"a"`, canonical value tracks the full `"a.b.c"`; (b) resolver reconstructs the full attribute chain from the root `Name`, then prepends the canonical root; (c) `from X.Y import Z` stores `{"Z": "X.Y.Z"}`.

5. **`subprocess-dynamic-command` uses an inverted check.** Dynamic = "not provably static." Fires unless `args[0]` is `Constant` OR `List/Tuple` with all-Constant elements OR `Starred` of `List/Tuple` of all-Constants. Everything else (bare `Name`, `Subscript`, `Call`, f-string, `BinOp`, list with any non-Constant, `Starred(Name)`, unpacking) fires high. Also handles **`**kwargs` unpacking case**: if the call has no positional args (`args == []`), the rule fires high (unknown command construction via kwargs).

6. **`subprocess.Popen` special-cased for `subprocess-no-timeout`.** Popen doesn't accept `timeout=` at construction.

7. **`subprocess-no-timeout` at `low` severity, reliability framing.** Timeout is a DoS/reliability signal, not a security signal.

8. **`bash-c-dynamic-interpolated` (critical) and `bash-c-dynamic-literal-dollar` (medium) are separate rule IDs.** The earlier "one rule with two severities" ambiguity resolved: two rules, two YAML entries, two separate IDs in the catalog.

9. **`path-traversal-dynamic` covers Python AST + JS/shell regex** (not Python-only). Three rule-IDs under the shared conceptual purpose, one per engine:
    - `path-traversal-dynamic-python` (ast, `**/*.py`)
    - `path-traversal-dynamic-js` (shell-regex, `**/*.{js,ts}`)
    - `path-traversal-dynamic-shell` (shell-regex, `**/*.sh`)

10. **`ast-parse-failed` severity is context-dependent.** In `hooks/**/*.py`: high finding (structural tampering signal). Elsewhere: `meta.ast_parse_failures: [paths]` only. A plugin with both a malformed hook AND a malformed agent produces **1 finding + 1 meta entry**, disjoint by design.

11. **Real-plugin integration: fingerprint snapshots with stable multiset key.** Snapshot entries are sorted `(rule_id, file)` tuples — `line_hint` is informational, not part of equality comparison. Drift from line-number reshuffling doesn't churn snapshots. Regeneration via explicit `--regenerate-snapshots` pytest flag.

12. **Schema-stability amendment (R11) is in Unit 0a with an exact literal-phrase test gate.** Ships before severity-changing YAML edits so the contract is honest at merge time.

13. **Schema stays at v0.1 under R11's carve-out.** Architecture review noted this sets a precedent; plan acknowledges it's a **one-time** carve-out (per R11's literal text), future stability-guarantee loosenings require a version bump.

14. **Unit 0 splits into 0a + 0b.** 0a is a 9-line trivial diff (severity + doc); 0b is the infrastructure (protocol, AST scaffolding, alias table, meta field, **first real rule: `subprocess-shell-true`** — which proves dispatch instead of a placeholder).

15. **`dynamic-code-exec` family** (info capability + medium dynamic-arg variant). Acknowledged as the first of a "dangerous builtin capability" family that could extend to `compile`, `__import__`, `pickle.loads`. Current plan ships exec/eval; family members are followups.

## Open Questions

### Resolved During Planning

- Shell coverage: regex for `bash-c-dynamic-*` + `path-traversal-dynamic-{js,shell}`.
- Rule location: YAML wrapped in `Rule`, AST via `@ast_rule`, unified registry.
- Rule naming: see catalog.
- Severity scope: three existing downgrades + five new rules.
- `subprocess-no-timeout` severity: low, reliability framing.
- `ast-parse-failed` severity: context-dependent.
- Schema-doc: literal bullet text specified (R11); grep anchor phrase pinned.
- Integration gate: fingerprint snapshots with stable multiset key (R12).
- Alias-import handling: working resolver in Design section.
- Popen + timeout: special-cased.
- `dynamic-code-exec-dynamic-arg`: medium, ships in this plan.
- Unit 0 split: 0a + 0b.
- CI snapshot gate: at least one unconditional snapshot (R15).
- `Rule` shape: dataclass, not Protocol.

### Deferred to Implementation

- Whether `--regenerate-snapshots` pytest flag is a fixture vs a pytest plugin hook (1-5 LOC either way).
- Whether `RuleContext` lands with `prior_findings` field active or reserved for a followup.

### New rule catalog

| Rule ID | Severity | `engine_kind` | Applies to | Detects |
|---------|----------|---------------|------------|---------|
| `subprocess-in-hooks` | ~~high~~ → **info** | `regex` | `hooks/**/*` | Any `subprocess.*` call (capability signal) |
| `subprocess-shell-true` | **critical** (new) | `ast` | `hooks/**/*.py` | `subprocess.*` with `shell=True` kwarg. **Ships in Unit 0b** as dispatch-prover. |
| `subprocess-dynamic-command` | **high** (new) | `ast` | `hooks/**/*.py` | `subprocess.*` where args[0] is not provably static OR args list is empty (`**kwargs` unpack) |
| `subprocess-no-timeout` | **low** (new, reliability) | `ast` | `hooks/**/*.py` | `subprocess.{call,run,check_output,check_call}` without `timeout=`. Excludes `Popen`. |
| `path-traversal` | ~~medium~~ → **info** | `regex` | `**/*`, except `**/*.md` | `../../` substring (capability signal) |
| `path-traversal-dynamic-python` | **high** (new) | `ast` | `**/*.py` | `../` inside f-string with a `FormattedValue`, or `+`-concat of a `../` Constant with a non-Constant |
| `path-traversal-dynamic-js` | **high** (new) | `shell-regex` | `**/*.{js,ts}` | `../` inside a template-literal `${…}` or string-concat `"../" + ident` |
| `path-traversal-dynamic-shell` | **high** (new) | `shell-regex` | `**/*.sh` | `../` adjacent to `$VAR`/`${…}`/`$(…)` |
| `bash-c-inline` | ~~high~~ → **info** | `regex` | `hooks/**/*`, `**/*.sh` | `bash/sh/zsh -c ...` (capability signal) |
| `bash-c-dynamic-interpolated` | **critical** (new) | `shell-regex` | `hooks/**/*`, `**/*.sh` | Double-quoted or unquoted `-c` arg with `$VAR`/`${…}`/`$(…)`/backticks |
| `bash-c-dynamic-literal-dollar` | **medium** (new) | `shell-regex` | `hooks/**/*`, `**/*.sh` | Single-quoted `-c` arg with literal `$` |
| `dynamic-code-exec` | **info** (new, capability) | `ast` | `hooks/**/*.py` | Any `exec()`/`eval()` call |
| `dynamic-code-exec-dynamic-arg` | **medium** (new) | `ast` | `hooks/**/*.py` | `exec`/`eval` where `args[0]` is not a `Constant` |
| `ast-parse-failed` | **high** (hooks) / meta-only (else) | infrastructure | `**/*.py` | Python file failed to parse |

Engine naming normalized to the Decision 2 literal set (`regex` / `ast` / `shell-regex`).

## High-Level Technical Design

> *Directional guidance for review, not implementation specification.*

**Rule dispatch:**

```
SecurityScanner.scan(inventory)
├── regex pass        (existing _CompiledRule path, wrapped in Rule adapter)
├── AST pass          (new)
│   └── for each matching Python file:
│       ├── parse once → tree, alias_table, parse_error
│       ├── if error in hook path:   emit ast-parse-failed (high); skip AST rules
│       ├── elif error elsewhere:    meta.ast_parse_failures.append(path); skip AST rules
│       └── else: for each @ast_rule matching filter: run(RuleContext(tree, path, alias_table))
├── shell-regex pass  (existing _CompiledRule path for the new bash-c + path-traversal rules)
└── findings sorted by (severity, file, line)
```

**Alias table — working code sketch (handles dotted imports correctly):**

```python
def build_alias_table(tree) -> dict[str, str]:
    """Map local_name → canonical_dotted_name.

    Invariants:
      - `import X` or `import X as Y`: binds Y (or X) to canonical X.
      - `import X.Y.Z`: Python binds only X locally. Key is X; canonical is X.Y.Z.
        (The resolver walks attribute chains to recover the rest of the dotted path.)
      - `import X.Y.Z as Q`: binds Q to canonical X.Y.Z.
      - `from X import Z` or `from X import Z as Q`: binds Z (or Q) to X.Z.
    """
    table: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    table[alias.asname] = alias.name
                else:
                    # Python binds the root of dotted imports (top level only)
                    root = alias.name.split(".", 1)[0]
                    table[root] = alias.name   # canonical tracks full dotted name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                table[local] = f"{module}.{alias.name}" if module else alias.name
    return table


def resolve_call_target(call: ast.Call, alias_table: dict[str, str]) -> str | None:
    """Resolve a Call's func node to a canonical dotted path like 'subprocess.run'.

    Walks Attribute chains to the root Name, reads the alias table for the root's
    canonical name, then prepends it to the reconstructed attribute tail.
    """
    # Collect the attribute chain from outermost to innermost.
    parts: list[str] = []
    node = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None                       # Call(Call(...)) etc. — unresolvable
    root_canonical = alias_table.get(node.id, node.id)  # default: bare name
    parts.reverse()                        # attr order: outermost-first → root-first
    if parts:
        return f"{root_canonical}." + ".".join(parts)
    return root_canonical
```

Traces:
- `import subprocess as sp; sp.run(...)` → root=`sp`, canonical=`subprocess`, parts=`['run']` → `"subprocess.run"` ✓
- `from subprocess import run; run(...)` → root=`run`, canonical=`subprocess.run`, parts=`[]` → `"subprocess.run"` ✓
- `import a.b.c; a.b.c.func(...)` → root=`a`, canonical=`a.b.c`, parts=`['b','c','func']` → `"a.b.c.b.c.func"` — ❌ would double-up
  - **Fix noted in Design**: when `root_canonical` already contains dots AND `parts[0]` matches the first dot-segment of `root_canonical`, strip the matching prefix. Alternative: store dotted imports as `{"a": "a"}` (binding-truth only) and let the resolver reconstruct the full chain via attributes. Final approach left as implementation-time choice in Unit 0b's "Deferred to Implementation."
- `import subprocess; subprocess.Popen(...)` → root=`subprocess`, canonical=`subprocess`, parts=`['Popen']` → `"subprocess.Popen"` ✓

**`is_provably_static` for dynamic-command check:**

```python
def is_provably_static(arg_node) -> bool:
    if isinstance(arg_node, ast.Constant):
        return True
    if isinstance(arg_node, (ast.List, ast.Tuple)):
        def elem_static(e):
            if isinstance(e, ast.Starred):
                return (isinstance(e.value, (ast.List, ast.Tuple))
                        and all(isinstance(x, ast.Constant) for x in e.value.elts))
            return is_provably_static(e)
        return all(elem_static(e) for e in arg_node.elts)
    return False
# Rule fires when: no positional args at all (implies **kwargs) OR NOT is_provably_static(call.args[0])
```

## Output Structure

```
src/griffith/analyzer/
├── ast_rules.py             (new: @ast_rule decorator, registry, alias table, resolver)
└── security.py              (modified: Rule dataclass + adapter, AST pass + shell-regex pass wiring, meta.ast_parse_failures)

rules/
└── security_patterns.yaml   (modified: 3 severity downgrades + 2 bash-c + 2 JS/shell path-traversal rules)

docs/
└── json-schema.md           (modified: R11 stability bullet + meta.ast_parse_failures docs)

tests/
├── test_ast_rule_infra.py       (new)
├── test_subprocess_rules.py     (new)
├── test_path_traversal_refinement.py (new)
├── test_bash_c_dynamic.py       (new)
├── test_dynamic_code_exec.py    (new)
├── test_security.py             (modified: severity expectations)
├── fixtures/security-traps-plugin/hooks/
│   ├── malformed.py                  (new)
│   ├── subprocess_dynamic.py         (new)
│   ├── subprocess_popen.py           (new)
│   ├── traversal_dynamic.py          (new)
│   ├── traversal_dynamic.js          (new)
│   ├── traversal_static.js           (new)
│   └── exec_capability.py            (new)
├── helpers/snapshots.py         (new)
└── snapshots/
    ├── security-traps-plugin.json           (new; CHECKED IN, UNCONDITIONAL per R15)
    ├── lastmilefirst-0.14.0.json            (new; skipif uncached)
    ├── compound-engineering-2.67.0.json     (new; skipif uncached)
    └── superpowers-marketplace.json         (new; skipif uncached)
```

(No `subprocess-safe-plugin` fixture — snapshots cover negative proofs via the checked-in `security-traps-plugin` and real-plugin fixtures.)

## Implementation Units

- [ ] **Unit 0a: Severity downgrades + schema-doc amendment**

**Goal:** Trivial, standalone diff. Downgrade severity on three existing rules. Amend `docs/json-schema.md` with the R11 carve-out bullet (literal text).

**Requirements:** R5, R11, R14.

**Dependencies:** None. Ships first; subsequent units build on the downgraded severities.

**Files:**
- Modify: `rules/security_patterns.yaml` (three severity edits + message updates on `subprocess-in-hooks`, `path-traversal`, `bash-c-inline`)
- Modify: `docs/json-schema.md` (add R11 literal-text bullet to "Stability guarantees" section; add `meta.ast_parse_failures` field documentation as pre-emptive schema note for 0b)
- Modify: `tests/test_security.py::TestDefaultRuleFirings` (update severity expectations for the three rules)
- Create: `tests/test_schema_doc_contract.py` — grep test asserting the literal phrase `may change within the enum set without bumping schema_version` appears in `docs/json-schema.md`

**Approach:**
- YAML: three single-field edits. Messages updated to reflect "capability signal" role.
- Schema doc: insert R11's full bullet text verbatim under the existing stability-guarantees list.
- Grep test: simple file-read + `in` check on the anchor phrase.

**Execution note:** Test-first. Write the grep test to fail, edit the doc, grep passes.

**Test scenarios:**
- **Schema-doc grep:** reading `docs/json-schema.md` contains the literal anchor phrase. Fails loudly if someone rewords.
- **Severity shift — subprocess:** existing fixture exercises `subprocess.run(...)` in hook; finding now has severity `info`, not `high`.
- **Severity shift — path-traversal:** fixture exercises `../..`; severity `info`, not `medium`.
- **Severity shift — bash-c-inline:** fixture exercises `bash -c ...`; severity `info`, not `high`.
- **Existing tests pass:** rest of `test_security.py` is unchanged.

**Verification:**
- `poetry run pytest tests/test_security.py tests/test_schema_doc_contract.py` green.
- Visual diff review: three YAML severity fields flipped, one doc bullet added.

- [ ] **Unit 0b: Foundation — Rule dataclass, AST infrastructure, alias table, first real AST rule**

**Goal:** Land the shared infrastructure AND the first real AST rule (`subprocess-shell-true`) to prove dispatch without a placeholder. Plus `meta.ast_parse_failures` field and `ast-parse-failed` finding.

**Requirements:** R7, R8, R10, R15 (partial — unconditional snapshot built in 0b/Unit 4 boundary).

**Dependencies:** Unit 0a.

**Files:**
- Modify: `src/griffith/schema.py` (add `ast_parse_failures: list[str]` to `MetaDict`)
- Modify: `src/griffith/analyzer/security.py` (introduce `Rule` dataclass + adapter, AST pass orchestration, meta field plumbing)
- Create: `src/griffith/analyzer/ast_rules.py` (@ast_rule decorator, registry, `build_alias_table`, `resolve_call_target`, `is_provably_static`, first rule `subprocess-shell-true`)
- Create: `tests/test_ast_rule_infra.py`
- Create: `tests/fixtures/security-traps-plugin/hooks/malformed.py` (deliberately unparseable — `def foo(: pass`)

**Approach:**
- Per Decision 2: `Rule` is a dataclass with adapter. YAML rules continue loading through `_CompiledRule`; adapter wraps each into a `Rule(engine_kind="regex", run=...)`.
- Per Decision 3: `@ast_rule(id=..., severity=..., file_filter=...)` decorator registers in a module-level `AST_RULES` list; scanner iterates this list for each matching file.
- Per Decision 4 + Design: alias-table + resolver handle dotted imports correctly. Implementation-time choice (noted in Open Questions): how to avoid double-prefix when canonical already contains dots.
- `subprocess-shell-true`: ships as the dispatch-prover. Full implementation:
  - Walk `ast.Call` nodes
  - Resolve via alias table
  - When canonical name in `{"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}` AND any `keyword` is `shell=True` → emit critical finding
- AST parse errors: broad exception catch (`SyntaxError, RecursionError, ValueError, OSError`), hook-path detection based on file glob against `hooks/**/*.py`, dispatch to finding-or-meta.

**Execution note:** Test-first.

**Test scenarios:**
- **Rule registry (happy):** after module import, `Rule.registry` contains both YAML-wrapped regex rules AND decorator-registered AST rules; `len(registry) == yaml_count + ast_count`.
- **AST dispatch (happy):** hook `.py` with `subprocess.run([], shell=True)` → 1 critical `subprocess-shell-true` + 1 info `subprocess-in-hooks`.
- **AST dispatch (aliased import):** `from subprocess import run; run([], shell=True)` → same output via alias-table resolution.
- **AST dispatch (aliased module):** `import subprocess as sp; sp.run([], shell=True)` → same.
- **Alias table — plain import:** `import subprocess` → `{"subprocess": "subprocess"}`.
- **Alias table — aliased import:** `import subprocess as sp` → `{"sp": "subprocess"}`.
- **Alias table — dotted no-as:** `import a.b.c` → `{"a": "a.b.c"}`. (Key is root `a`.)
- **Alias table — dotted with-as:** `import a.b.c as q` → `{"q": "a.b.c"}`.
- **Alias table — from:** `from subprocess import run` → `{"run": "subprocess.run"}`.
- **Alias table — from aliased:** `from subprocess import run as r` → `{"r": "subprocess.run"}`.
- **Resolver — bare name after from-import:** `from subprocess import run; run(...)` → `"subprocess.run"`.
- **Resolver — attribute chain:** `import subprocess; subprocess.Popen(...)` → `"subprocess.Popen"`.
- **Resolver — unresolvable Call(Call())`:** `functools.partial(f)(...)` → `None` (doesn't fire shell-true).
- **AST parse failure in hook:** `hooks/scripts/malformed.py` → `high` `ast-parse-failed` finding; AST rules skip; regex rules still scan.
- **AST parse failure elsewhere:** `agents/malformed.py` → path appended to `meta.ast_parse_failures`; no finding; regex rules still scan.
- **AST parse failure — both:** hook malformed + agent malformed → 1 finding + 1 meta entry; DISJOINT (hook is NOT in meta, agent is NOT in findings).
- **AST parse failure — adversarial (recursion bomb):** 1000-level-nested expression in hook file → parse fails cleanly, `high` finding, scanner continues, recursion limit restored.
- **AST parse failure — parse-succeeds but walk-bombs:** deliberately-constructed file where `ast.parse` succeeds but `ast.walk` hits RecursionError → caught by same handler; emits `ast-parse-failed` with message indicating walk-time failure.

**Verification:**
- `poetry run pytest tests/test_ast_rule_infra.py` green.
- Full `test_security.py` suite green with updated severity expectations from 0a.

- [ ] **Unit 1: Subprocess family (dynamic-command, no-timeout) + dynamic-code-exec family**

**Goal:** Three remaining AST rules on the subprocess side + two `exec`/`eval` rules. All use Unit 0b's infrastructure.

**Requirements:** R1, R4, R9.

**Dependencies:** Unit 0b.

**Files:**
- Modify: `src/griffith/analyzer/ast_rules.py` (four new rule functions)
- Create: `tests/test_subprocess_rules.py`
- Create: `tests/test_dynamic_code_exec.py`
- Create: `tests/fixtures/security-traps-plugin/hooks/subprocess_dynamic.py` (bare Name, Subscript, Starred(Name), BinOp, f-string, .format, `**kwargs`)
- Create: `tests/fixtures/security-traps-plugin/hooks/subprocess_popen.py` (Popen variants — no-timeout rule must skip)
- Create: `tests/fixtures/security-traps-plugin/hooks/exec_capability.py` (static + dynamic exec/eval)

**Approach:**
- `subprocess-dynamic-command`: inverted check per Decision 5 + Design. Special case: zero args positional (`**kwargs` only) → fires high.
- `subprocess-no-timeout`: whitelist `{subprocess.call, subprocess.run, subprocess.check_output, subprocess.check_call}`; explicitly excludes `subprocess.Popen`.
- `dynamic-code-exec`: walk `ast.Call`; when canonical name is `exec` or `eval` (also handles `builtins.exec` via alias resolver) → emit info.
- `dynamic-code-exec-dynamic-arg`: same walk; when `args[0]` is not a `Constant` → emit medium additive. Parallels subprocess-dynamic-command logic but simpler (no list-handling — exec takes a single string/code).

**Execution note:** Test-first.

**Test scenarios:**
- **dynamic-command (bare Name):** `subprocess.run(cmd)` → high + info.
- **dynamic-command (Subscript):** `subprocess.run(sys.argv[1:])` → high + info.
- **dynamic-command (Attribute):** `subprocess.run(self.cmd)` → high + info.
- **dynamic-command (Starred of Name):** `subprocess.run([*args])` → high + info.
- **dynamic-command (Starred of List-of-Constants):** `subprocess.run([*("a","b")])` → **info only, deterministic**. The is_provably_static logic explicitly treats this as static (no ambiguity).
- **dynamic-command (List with non-Constant):** `subprocess.run(["git", user])` → high + info.
- **dynamic-command (BinOp + Name):** `subprocess.run(cmd.split() + ["--x"])` → high + info. *(lmf `run.py:31` case)*
- **dynamic-command (f-string):** `subprocess.run(f"git {x}")` → high + info.
- **dynamic-command (.format):** `subprocess.run("git {}".format(x))` → high + info.
- **dynamic-command (kwargs unpack, no positional args):** `subprocess.run(**opts)` → **high + info** (rule fires on empty positional args).
- **dynamic-command (static list):** `subprocess.run(["git", "status"])` → info only.
- **no-timeout (happy):** `subprocess.run(["git"])` → low + info.
- **no-timeout (with timeout):** `subprocess.run(["git"], timeout=5)` → info only.
- **no-timeout (Popen direct):** `subprocess.Popen(["git"])` — NO low finding; only info.
- **no-timeout (Popen aliased):** `import subprocess as sp; sp.Popen([])` — still skipped.
- **no-timeout (check_output):** `subprocess.check_output(["git"])` → low + info.
- **exec-capability (static):** `exec("print('hi')")` → info.
- **exec-capability (eval):** `eval("1+1")` → info.
- **exec-capability (builtins):** `import builtins; builtins.exec(...)` → info (via alias).
- **exec-dynamic-arg (bare Name):** `exec(code)` where `code` is a Name → medium + info.
- **exec-dynamic-arg (Call):** `exec(compile(src, '<x>', 'exec'))` → medium + info. Also catches the obfuscation vector.
- **exec-dynamic-arg (static):** `exec("print('hi')")` → info only.
- **stacking:** `subprocess.run(f"git {x}", shell=True)` → critical + high + low + info = 4 findings.
- **lmf regression:** fixture mirroring lmf hooks → 8 info + 2 high `subprocess-dynamic-command`; 0 critical; 0 low; 0 Popen.

**Verification:**
- All new tests pass.
- Fixtures produce expected counts.

- [ ] **Unit 2: `bash-c-dynamic-interpolated` (critical) + `bash-c-dynamic-literal-dollar` (medium)**

**Goal:** Two separate YAML regex rules; explicit patterns with a truth table. Reference tests for exhaustive cases (not duplicated in plan prose).

**Requirements:** R3.

**Dependencies:** Unit 0a (severity downgrade of `bash-c-inline`).

**Files:**
- Modify: `rules/security_patterns.yaml` (add two new rules)
- Modify: `tests/fixtures/security-traps-plugin/hooks/shell-tricks.sh` (ensure coverage of quoted variants)
- Create: `tests/test_bash_c_dynamic.py`

**Approach:** Three patterns, two rules:

```yaml
# Rule: bash-c-dynamic-interpolated (CRITICAL)
# Matches double-quoted or unquoted -c arg containing dynamic markers.
# Pattern A: double-quoted arg, body handles escaped inner quotes (\")
pattern: '(?<![\w-])(?:bash|sh|zsh)\s+-c\s+"(?:[^"\\]|\\.)*?(?:\$[A-Za-z_\{]|\$\(|`)'
# Pattern C (same rule, alternation): unquoted bare -c with $ token
# Combined via regex alternation in the single rule entry.

# Rule: bash-c-dynamic-literal-dollar (MEDIUM)
# Pattern B: single-quoted arg with literal $
pattern: "(?<![\\w-])(?:bash|sh|zsh)\\s+-c\\s+'[^']*\\$[A-Za-z_\\{][^']*'"
```

Truth table (full exhaustive cases in `tests/test_bash_c_dynamic.py`; this plan shows representative cases only):

| Input | Outcome |
|-------|---------|
| `bash -c "echo hello"` | info only |
| `bash -c "$HOME/bin/tool"` | **critical** + info |
| `bash -c "$(date)"` | **critical** + info |
| `bash -c "${VAR}"` | **critical** + info |
| ``bash -c "`whoami`"`` | **critical** + info |
| `timeout 30 bash -c "echo hello"` | info only |
| `timeout "$t" bash -c "$cmd"` (superpowers case) | **critical** + info |
| `bash -c 'echo $VAR'` | **medium** + info |
| `bash -c 'echo hello'` | info only |
| `bash -c $CMD` | **critical** + info (pattern C) |
| `bash -c "echo \"$V\""` | **critical** + info |
| `sh -c "$X"`, `zsh -c "$X"` | **critical** + info |

Edge cases accepted as known limitations (documented in rule message): multi-line `-c` args with `\` continuation; heredocs inside `-c`.

**Execution note:** Test-first.

**Test scenarios:** full truth table → see `tests/test_bash_c_dynamic.py`. Plan lists representative cases only.

**Verification:**
- All truth-table cases pass.
- superpowers snapshot reflects 1 critical `bash-c-dynamic-interpolated` + 0 high `bash-c-inline` (shifted from high → info).

- [ ] **Unit 3: `path-traversal-dynamic-{python,js,shell}`**

**Goal:** Three rules sharing a conceptual purpose, one per engine. Uses Unit 0b's AST infrastructure for Python; YAML regex for JS/shell.

**Requirements:** R2.

**Dependencies:** Unit 0b (for Python AST rule); Unit 0a (severity downgrade on `path-traversal`).

**Files:**
- Modify: `src/griffith/analyzer/ast_rules.py` (`path_traversal_dynamic_python`)
- Modify: `rules/security_patterns.yaml` (`path-traversal-dynamic-js`, `path-traversal-dynamic-shell`)
- Create: `tests/fixtures/security-traps-plugin/hooks/traversal_dynamic.py`
- Create: `tests/fixtures/security-traps-plugin/hooks/traversal_dynamic.js`
- Create: `tests/fixtures/security-traps-plugin/hooks/traversal_static.js` (must NOT fire dynamic)
- Create: `tests/test_path_traversal_refinement.py`

**Approach:**
- Python AST rule: walk `ast.JoinedStr` (f-strings); fire high if any `Constant` part contains `"../"` AND at least one `FormattedValue` exists. Also walk `ast.BinOp` with `Add`: fire if one operand is `Constant` containing `"../"` and the other is non-Constant.
- JS regex: match `\.\./` followed or preceded by `\$\{` (template literal) OR `\$\w+` (bash-style var — rare in JS but handles edge) OR `+\s*[A-Za-z_]` (string concat with identifier).
- Shell regex: match `\.\./` adjacent to `\$\w+` / `\$\{` / `\$\(`.

**Test scenarios:**
- **Python (f-string):** `f"../../{user}"` → high + info.
- **Python (concat):** `"../../" + path` → high + info.
- **Python (safe constant):** `open("../../../etc/passwd", "r")` → info only.
- **Python (os.path.join all-constant):** `os.path.join("..", "..", "x")` → **0 findings** (regex needs `../` substring; source text has `".."` and `",", "..,"` but no literal `../` substring).
- **Python (pathlib):** `Path("../config.yaml")` → info only (regex needs `../..` — does not match single `../`). Confirm regex specifics during implementation; if regex only requires `../`, this becomes info.
- **JS (template literal dynamic):** `` `../../${user}` `` → high + info.
- **JS (template literal static):** `` `../../literal` `` (no `${...}`) → **info only** — explicitly tested to avoid false-positive on template-literal without interpolation.
- **JS (concat dynamic):** `"../../" + userPath` → high + info.
- **JS (path.join __dirname static):** `path.join(__dirname, '../../static')` → info only (superpowers case).
- **JS (path.join __dirname dynamic):** `` path.join(__dirname, `../../${dyn}`) `` → high + info.
- **Shell (dynamic):** `cat ../../$FILE` → high + info.
- **Shell (static):** `cat ../../static/file` → info only.
- **superpowers regression:** 19 existing findings drop from medium to info; 0 new high (all use static template literals / constant strings).

**Verification:**
- Tests pass. superpowers snapshot reflects the expected shift.

- [ ] **Unit 4: Real-plugin integration via fingerprint snapshots + followup archival**

**Goal:** Lock in expected findings for real plugins. Include one checked-in unconditional snapshot (R15) so CI gates without cached marketplaces. Archive the origin followup at the end of the unit (merged from former Unit 5).

**Requirements:** R12, R13, R15.

**Dependencies:** Units 0a, 0b, 1, 2, 3 merged.

**Files:**
- Create: `tests/helpers/snapshots.py` — loader/compare helper with diff output; `--regenerate-snapshots` flag handling (implementation-time choice: pytest option OR env var)
- Create: `tests/snapshots/security-traps-plugin.json` (CHECKED IN — unconditional snapshot per R15)
- Create: `tests/snapshots/lastmilefirst-0.14.0.json` (skipif uncached)
- Create: `tests/snapshots/compound-engineering-2.67.0.json` (skipif uncached)
- Create: `tests/snapshots/superpowers-marketplace.json` (skipif uncached)
- Modify: `tests/test_security.py::TestRealPluginLastMileFirst`, `TestRealPluginCompoundEngineering`, add `TestRealPluginSuperpowers`, add `TestSecurityTrapsSnapshot` (unconditional)
- Move: `.claude/work/followups/refine-subprocess-rule-with-ast.md` → `.claude/work/followups/archive/refine-subprocess-rule-with-ast.md` with DONE marker + merge commit reference

**Approach:**
- Snapshot format:
  ```json
  {
    "griffith_version": "0.1.0",
    "generated_at": "2026-04-20T00:00:00Z",
    "findings": [
      {"rule_id": "subprocess-in-hooks", "file": "hooks/scripts/run.py", "line_hint": 31},
      {"rule_id": "subprocess-dynamic-command", "file": "hooks/scripts/run.py", "line_hint": 31},
      ...
    ]
  }
  ```
- Comparison: compute `Counter((rule_id, file) for f in findings)` for both live and snapshot; assert equality. `line_hint` and `griffith_version` are informational — diffs print them for debugging but don't fail the test.
- Duplicate entries: `Counter` multiset handles `{rule_id, file}` appearing multiple times (e.g., 2 findings in same file) correctly.
- Unconditional `security-traps-plugin` snapshot: checked into repo; runs in every CI environment without fixture preconditions.
- Real-plugin tests: `@pytest.mark.timeout(5)` on each; `skipif` on absence of the cached marketplace directory.

**Execution note:** Regenerate snapshots during this unit from live runs; diff review by the implementer before committing.

**Test scenarios:**
- **Unconditional fixture snapshot:** `security-traps-plugin` live scan == checked-in snapshot (multiset equality). RUNS IN CI WITHOUT SKIPIF.
- **lmf snapshot:** cached-plugin scan == lastmilefirst-0.14.0.json. Expected multiset includes 8× `(subprocess-in-hooks, hooks/scripts/*.py)` + 2× `(subprocess-dynamic-command, hooks/scripts/run.py)`.
- **CE snapshot:** cached-plugin scan == compound-engineering-2.67.0.json.
- **superpowers snapshot:** cached-marketplace scan == superpowers-marketplace.json. Expected: 0 medium/high `path-traversal*`, 0 high `bash-c-inline`, 1 critical `bash-c-dynamic-interpolated`.
- **Drift detection:** sim test where a bogus extra finding is injected → snapshot comparison fails with clear diff (added vs removed vs expected).
- **Timeout enforcement:** `@pytest.mark.timeout(5)` fails the test if scan exceeds 5s wall-clock.
- **Regenerate mode:** `--regenerate-snapshots` (or env var) rewrites the file; git diff becomes the reviewable artifact. Implementer confirms mode before commit.

**Verification:**
- Unconditional snapshot test green in CI without any fixture preconditions.
- All four snapshot tests pass when run locally with cached plugins.
- Followup archived with DONE marker + merge commit ref.
- Wrapper spot-check: `/run-audit-plugin ~/.claude/plugins/cache/gruntwork-marketplace/lastmilefirst/0.14.0` reports `verdict: review` (not `block`) because 2 high dynamic findings are the new ceiling, not 8.

## System-Wide Impact

- **Interaction graph:** `SecurityScanner.scan` gains an AST pass + shell-regex pass alongside existing regex pass. All rules flow through the unified `Rule` registry.
- **Error propagation:** AST parse failure → hook-high-finding or meta-only; no exceptions escape scanner.
- **State lifecycle:** Stateless per call.
- **API surface parity:**
  - `security.findings[]`: new rule IDs additively; severity values shift on three existing IDs.
  - `meta.ast_parse_failures: list[str]` new field.
  - `--strict` unchanged.
  - CLI flags unchanged.
- **Consumer impact (LMF wrapper):** severity-count rendering auto-handles the shift. No wrapper change needed.
- **Unchanged invariants:**
  - `schema_version = "0.1"` (permitted under R11 one-time carve-out).
  - `SecurityFinding` shape.
  - `PluginInventory` consumption pattern.
  - Hardened file-size + symlink handling.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Inverted dynamic check fires on legitimate validated-input patterns. | Real-plugin snapshots lock expected counts; new false positives visible as fingerprint diffs. Rule message frames as heuristic. `subprocess-in-hooks` info always fires. |
| Alias-table resolver double-prefix bug on dotted imports. | Design section documents the concern; Unit 0b implementation-time choice resolves. Specific tests: `import a.b.c; a.b.c.f()` trace. |
| Malformed Python crashes scanner. | Broad exception + recursion-limit guard + `ast-parse-failed` emit. Adversarial fixtures verify. |
| Malformed hook hides code from AST rules. | `ast-parse-failed` at high severity (Decision 10) prevents the attacker from silencing analysis. |
| `bash-c-dynamic-*` regex misses nested-quoting edge cases. | Documented in rule message. `bash-c-inline` info still fires. |
| Single-quoted literal `$` medium severity is a false positive for some plugins. | Medium severity reflects uncertainty; info capability still fires. |
| `subprocess.Popen` callers still need `.wait()/.communicate()` discipline. | `no-timeout` rule's message points at this; stricter Popen rule is a followup. |
| JS/shell dynamic traversal precision is lower than Python AST. | Accepted — catches common attacks; full JS parser deferred. |
| Snapshots churn on real-plugin version bumps. | Version-pinned filenames; new version = new snapshot file. `line_hint` informational resists line-number drift. |
| CI lacks cached plugins → snapshot gate silently skipped. | **R15**: unconditional `security-traps-plugin` snapshot runs without skipif; always gates. |
| Consumers hard-coded on `(rule_id, severity)` break when severity shifts. | R11 literal bullet documents contract change; grep test enforces doc presence. |
| Retroactive v0.1 carve-out (R11) sets precedent. | R11 text explicitly labels as one-time concession; future loosenings require version bump. |
| Line-number drift breaks snapshots. | Multiset key is `(rule_id, file)`; `line_hint` not part of equality. |
| Dotted-import resolver edge case (`import a.b.c; a.b.c.func()`). | Working resolver in Design; final-form choice deferred to Unit 0b implementation. |
| `dynamic-code-exec-dynamic-arg` at medium still can't catch `exec(getattr(obj, 'attr')(''))`. | Accepted coverage limit; the `exec()` call itself always fires info capability. Stricter variant = followup. |

## Post-implementation amendments

**2026-04-20 — Decision 2 partially deferred to followup.** Code review
surfaced that the implementation shipped with two parallel registries
(`_CompiledRule` + `self._rules` for YAML regex; `ASTRuleSpec` + module-
level `AST_RULES` for AST) instead of the unified `Rule` dataclass + adapter
specified in R10 and Decision 2. Dispatch is implicit via two separate
loops in `SecurityScanner.scan()`.

The two-registry shape ships working at 415 tests green. The unified
adapter was weighed and deferred:

- Refactor scope is ~150 LOC + regression risk across the hot path
  (rule dispatch is on every scan of every file). Current behavior is
  correct; the refactor is architectural consistency with no user-
  visible change today.
- Concrete benefit lands when a 3rd engine is added (JS AST parser),
  cross-registry queries become common, or rule priority/composition
  becomes a feature. None are on the immediate roadmap.
- Separate follow-up keeps the refinement PR focused and reviewable;
  the unification PR gets its own review surface.

Followup filed: `.claude/work/followups/unify-rule-registry.md`.

Other post-implementation adjustments (also applied before merge, not
deferred):
- **B2**: `python-eval-exec` now excludes `hooks/**/*.py`. AST rules
  (`dynamic-code-exec` info + `dynamic-code-exec-dynamic-arg` medium)
  cover hook-scope eval/exec with the additive-never-silence posture;
  the critical YAML rule would have double-fired on static calls.
- **B3**: `SecurityFinding` moved to `src/griffith/analyzer/findings.py`
  to break the circular import between `security.py` and `ast_rules.py`.
  The `make_finding` shim disappeared; AST rules construct
  `SecurityFinding` directly. Cleaner module layering.
- **B4**: `@ast_rule(id=...)` renamed to `@ast_rule(rule_id=...)` for
  consistency with `SecurityFinding.rule_id` and `ASTRuleSpec.rule_id`.
  Also added: `@ast_rule` now raises `ValueError` on duplicate
  registration (silent double-count prevention).
- **B5**: `test_rule_for_templates` wrapped in `try/finally` so test
  exceptions before cleanup don't leak the rule into subsequent tests.

## Documentation / Operational Notes

- `docs/json-schema.md` amended in Unit 0a (R11 + `meta.ast_parse_failures` pre-docs).
- Archive origin followup in Unit 4 with DONE marker + merge commit reference.
- No consumer changes required — LMF wrapper renders by severity count.

## Sources & References

- **Origin:** `.claude/work/followups/refine-subprocess-rule-with-ast.md`
- **Prior companion archives:** `.claude/work/followups/archive/osv-fixed-versions-per-ecosystem.md` (cd74302), `federated-marketplace-detection.md` (c2439ce)
- **Related plans:** `.claude/work/plans/phase-1.5-dependency-analyzer.md`
- **Python `ast`:** https://docs.python.org/3/library/ast.html
- **Ground-truth:** lmf 0.14.0 hooks grep (planning-time); superpowers-marketplace; CE 2.67.0.
- **Review history:** two review passes on 2026-04-20 (security-sentinel, architecture-strategist, code-simplicity-reviewer, general-purpose composite); v1 blockers + v2 targeted issues all integrated into this v3.
