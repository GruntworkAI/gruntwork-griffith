# Follow-up: refine `subprocess-in-hooks` rule to distinguish safe from risky

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
4. Downgrade the "bare subprocess in hook" finding from `high` to `info` when
   the other checks pass

## Suggested rule split

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `subprocess-shell-true` | critical | `subprocess.*` with `shell=True` anywhere |
| `subprocess-no-timeout` | medium | `subprocess.*` without `timeout=` kwarg |
| `subprocess-dynamic-command` | high | first arg contains f-string, `.format()`, or `+` concat |
| `subprocess-in-hooks` | info | capability signal, after the stricter rules pass |

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
