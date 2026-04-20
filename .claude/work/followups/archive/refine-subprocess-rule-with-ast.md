# Follow-up: refine `subprocess-in-hooks` rule to distinguish safe from risky

**Status: DONE (2026-04-20).** Shipped across 5 implementation units
(0a, 0b, 1, 2, 3, 4) on feat/ast-security-rule-refinement. Scope
expanded during planning to cover path-traversal and bash-c-inline
refinement — same additive-never-silence design posture applied
uniformly. Real-plugin snapshot gates:
- lastmilefirst 0.14.0: 8 info + 2 high (down from 8 high — the
  high findings are real actionable signals on dynamic args in the
  python-discovery fallback).
- compound-engineering 2.67.0: 2 info (unchanged; CE has no
  subprocess in hooks to begin with).
Plan:
.claude/work/plans/2026-04-20-001-feat-ast-security-rule-refinement-plan.md

**Surfaced during Unit 4 scan of lastmilefirst 0.14.0 (2026-04-17).**

## The problem

The current `subprocess-in-hooks` rule (severity: high) fires on every match of
`subprocess\.(call|run|Popen|check_output|check_call)` in `hooks/**/*`.

This is correct as a capability signal ("this plugin shells out from hooks"),
but it produces findings on plugins that use subprocess safely — i.e. with:

- Argument-list form (`subprocess.run([...])`, not `shell=True`)
- Constant or validated-path inputs
- `timeout=` set
- Explicit exception handlers

For lastmilefirst 0.14.0, all 8 matches are safe by these criteria. Every other
well-behaved plugin that legitimately needs to shell out to git/gh/python will
produce similar noise.

## Why AST-based is the right fix

Regex can detect `subprocess.run`, but it can't distinguish:

```python
# Safe: list args, no shell, timeout set, static inputs
subprocess.run(["git", "status"], capture_output=True, timeout=5)

# Risky: shell=True + string interpolation
subprocess.run(f"git {user_input}", shell=True)
```

AST analysis can:
1. Detect `shell=True` as a separate, higher-severity finding
2. Detect missing `timeout=` as a medium finding
3. Detect string concatenation / f-strings in the command argument (taint proxy)

## Do NOT collapse the capability signal — additive only

The naive refactor — "downgrade subprocess-in-hooks to info when shell=False
+ timeout set + list args" — creates a real security hole. Static analysis
cannot tell that an argument is attacker-controlled. Example:

```python
subprocess.run(["git", "clone", attacker_controlled_url], timeout=30)
# Passes all the "safe" checks.
# But if attacker_controlled_url is "--upload-pack=/tmp/evil.sh", git's
# argument parsing executes /tmp/evil.sh. This is argument injection,
# not shell injection. No static rule can catch this without semantic
# knowledge of git's CLI.
```

Similar classes: `cat ["shell", path]` where path is `/etc/shadow`;
`python ["subprocess", "run", ["python", path]]` where path is attacker-chosen.

**Design rule: new stricter detections are ADDITIVE to the capability signal.**
- `subprocess-in-hooks` (INFO) — always fires; capability signal, unchanged
- `subprocess-shell-true` (CRITICAL) — adds when shell=True detected
- `subprocess-dynamic-command` (HIGH) — adds when first arg has f-string/concat
- `subprocess-no-timeout` (MEDIUM) — adds when timeout= kwarg missing

User always sees "this plugin uses subprocess." They additionally see stricter
findings where the pattern is more dangerous. Nothing gets silenced.

## Suggested rule split (all additive)

| Rule ID | Severity | Detects | Replaces |
|---------|----------|---------|----------|
| `subprocess-in-hooks` | info | any `subprocess.*` call in hooks/ | current `high` severity |
| `subprocess-shell-true` | critical | `shell=True` kwarg | new |
| `subprocess-dynamic-command` | high | first arg contains f-string / `.format()` / `+` concat | new |
| `subprocess-no-timeout` | medium | `timeout=` kwarg missing | new |

The only change to the existing rule is the severity downgrade from `high` to
`info`. This reflects that "subprocess is used" is a capability fact, not a
defect. Plugins that shell out for legitimate reasons (git, gh, python) get
one `info` finding per call site. Dangerous patterns get additional, stricter
findings stacked on top.

## Implementation approach

Use Python's `ast` module (no new deps):

```python
import ast
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = ast.unparse(node.func)
        if func.startswith("subprocess."):
            # inspect node.args, node.keywords for shell=True, timeout, etc.
```

Only runs on `hooks/**/*.py` files. Per-file cost: one AST parse, small tree
traversal — negligible relative to regex scanning.

## Scope

- Phase 1.5 (post-MVP) — not blocking Unit 5/6/7
- Expand coverage beyond subprocess: `eval`/`exec` with constant-string arg
  (test code) vs dynamic arg (risky); `os.system` already singled out

## Priority

Medium. Current scanner produces correct-but-noisy findings that a thoughtful
user can triage. Tool's trust erodes if noise persists across real plugins.

## Testing

When built, reuse existing fixtures plus new:
- `fixtures/subprocess-safe/` — list args + timeout + static (no finding)
- `fixtures/subprocess-shell-true/` — shell=True (critical finding)
- `fixtures/subprocess-dynamic/` — f-string in arg (high finding)
- `fixtures/subprocess-no-timeout/` — missing timeout kwarg (medium finding)
- Real integration: re-scan lastmilefirst expecting 0 high-severity subprocess
  findings after the refinement ships
