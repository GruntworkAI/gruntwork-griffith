"""AST-based security rules — run alongside YAML regex rules.

Python's `ast` module (stdlib) lets rules inspect *structure* (node types,
argument shapes, keyword presence) rather than just matching text. This
catches false-positive classes that regex can't distinguish — e.g.
`subprocess.run(["git", "status"], timeout=5)` (safe list-of-literals +
timeout) vs. `subprocess.run(f"git {user}", shell=True)` (dynamic arg with
shell=True).

Per the plan's Decision 3, rules are decorator-registered functions, not
classes. Each rule is a callable `check(ctx: RuleContext) -> list[SecurityFinding]`.

Hardening invariants (mirror `dependencies.py::_parse_pyproject`):
- Untrusted source is parsed under a reduced `sys.setrecursionlimit` so
  deeply-nested expressions can't blow the C-level stack.
- Broad exception catch: SyntaxError, RecursionError, ValueError, OSError.
  On failure the orchestrator emits `ast-parse-failed` (high in hooks;
  meta-only elsewhere) and skips AST rules for that file.
- Recursion limit is always restored in `finally`.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from griffith.analyzer.findings import SecurityFinding
from griffith.analyzer.inventory import ComponentFile


# Recursion-limit guard around untrusted AST parse. Mirrors
# dependencies.py::_PARSE_RECURSION_LIMIT.
_PARSE_RECURSION_LIMIT = 500

# Hook path glob — fixed per the plan. Files under this glob that fail
# AST parsing emit a `high` severity finding (structural tampering
# signal for executable code). Everything else records to
# `meta.ast_parse_failures` only.
_HOOK_PATH_PREFIX = "hooks/"


# ============================================================================
# RuleContext + decorator + registry
# ============================================================================


@dataclass
class RuleContext:
    """Inputs handed to each @ast_rule check function.

    Kept minimal. `prior_findings` is a reserved extension point for
    future rules that want to inspect what's already been emitted on the
    same file; not populated yet.
    """

    tree: ast.Module
    path: str                            # relative path, forward-slash
    alias_table: dict[str, str]
    prior_findings: list = field(default_factory=list)


@dataclass
class ASTRuleSpec:
    """Metadata for a registered AST rule."""

    rule_id: str
    severity: str
    file_filter: str                     # glob pattern
    check: Callable[["RuleContext"], list]


@dataclass
class ParsedFile:
    """Result of parsing a single .py file.

    Produced by the scanner's `_build_parsed_file` helper; consumed by
    `run_ast_rules`. The split separates "per-file orchestration"
    (parse + alias-table + recursion-limit guard) from "rule dispatch"
    (match applicable rules against the parsed tree) — the two
    responsibilities used to live together in `run_ast_rules`.
    """

    path: str                            # relative, forward-slash
    tree: ast.Module
    alias_table: dict[str, str]


# Module-level registry. Decorator populates at import.
AST_RULES: list[ASTRuleSpec] = []


def ast_rule(
    *, rule_id: str, severity: str, file_filter: str
) -> Callable[[Callable], Callable]:
    """Decorator: register an AST rule.

    Usage:

        @ast_rule(rule_id="subprocess-shell-true", severity="critical",
                  file_filter="hooks/**/*.py")
        def check(ctx: RuleContext) -> list[SecurityFinding]:
            ...

    The decorated function stays callable; the spec is registered as a
    side effect. No class hierarchy, no inheritance — the simplest shape
    that supports multiple rules sharing one module.

    Raises ValueError on duplicate rule_id registration — silent
    double-registration (e.g., from module reload) would silently
    double-count findings. Fail loudly instead.
    """

    def _register(func: Callable) -> Callable:
        if any(spec.rule_id == rule_id for spec in AST_RULES):
            raise ValueError(
                f"AST rule {rule_id!r} is already registered. "
                "Duplicate registration usually indicates a module "
                "reload or a typo. Use a distinct rule_id."
            )
        AST_RULES.append(
            ASTRuleSpec(
                rule_id=rule_id, severity=severity,
                file_filter=file_filter, check=func,
            )
        )
        return func

    return _register


# ============================================================================
# Alias table — maps local names in a module to canonical dotted names
# ============================================================================


def build_alias_table(tree: ast.Module) -> dict[str, str]:
    """Build `{local_name: canonical_dotted_name}` from `Import` / `ImportFrom`.

    Invariants:
      - `import X` → `{"X": "X"}`.
      - `import X as Y` → `{"Y": "X"}`.
      - `import X.Y.Z` (no as) → Python binds only `X` locally. Key is
        `X`; the canonical value is the SHORT root-name `X` (not the
        full dotted path). Rationale: if we stored `X.Y.Z` here, the
        resolver would concatenate it with attribute tails and produce
        `X.Y.Z.func` for `X.Y.Z.func(...)` — but the correct canonical
        IS `X.Y.Z.func`. Storing short-root + letting the resolver walk
        the full attribute chain keeps the resolver's math right.
      - `import X.Y.Z as Q` → `{"Q": "X.Y.Z"}`.
      - `from X import Z` → `{"Z": "X.Z"}`.
      - `from X import Z as Q` → `{"Q": "X.Z"}`.
      - `from X.Y import Z` → `{"Z": "X.Y.Z"}`.
      - Relative imports (`from .foo import bar`) → `{"bar": "foo.bar"}`
        (best-effort; missing the package context). Documented as a
        known limitation; hooks typically don't use relative imports.
    """
    table: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    table[alias.asname] = alias.name
                else:
                    # `import a.b.c` — Python binds `a` locally only.
                    # Store short-root → short-root; resolver walks
                    # the attribute chain to recover the full dotted path.
                    root = alias.name.split(".", 1)[0]
                    table[root] = root
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                if module:
                    table[local] = f"{module}.{alias.name}"
                else:
                    # `from . import bar` — keep bare name.
                    table[local] = alias.name
    return table


def resolve_call_target(
    call: ast.Call, alias_table: dict[str, str]
) -> Optional[str]:
    """Resolve a `Call` func node to a canonical dotted path.

    Walks attribute chains to the root `Name`, looks up the root in the
    alias table, and prepends the canonical root to the reconstructed
    attribute tail.

    Examples:
      - `subprocess.run(...)` (after `import subprocess`):
        root `subprocess` → canonical `subprocess`, tail `["run"]`
        → `"subprocess.run"` ✓
      - `sp.run(...)` (after `import subprocess as sp`):
        root `sp` → canonical `subprocess`, tail `["run"]`
        → `"subprocess.run"` ✓
      - `run(...)` (after `from subprocess import run`):
        root `run` → canonical `subprocess.run`, tail `[]`
        → `"subprocess.run"` ✓
      - `a.b.c.func(...)` (after `import a.b.c`):
        root `a` → canonical `a` (short-root per build_alias_table),
        tail `["b", "c", "func"]` → `"a.b.c.func"` ✓

    Returns None if the func is a non-Name/Attribute (e.g. `Call(Call(...))`).
    """
    parts: list[str] = []
    node = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    root_canonical = alias_table.get(node.id, node.id)
    parts.reverse()
    if parts:
        return f"{root_canonical}." + ".".join(parts)
    return root_canonical


# ============================================================================
# is_provably_static — used by dynamic-detection rules (subprocess, exec, ...)
# ============================================================================


def is_provably_static(arg_node: ast.expr) -> bool:
    """Conservative "this arg is a literal, not a runtime value" check.

    True only for:
      - `ast.Constant` (string/int/None/True/False/...)
      - `ast.List`/`ast.Tuple` whose elements are ALL provably-static
        (recursively), OR `Starred` of a List/Tuple of Constants.

    Everything else → False:
      - bare Name (variable reference)
      - Subscript, Attribute, Call
      - f-string (JoinedStr)
      - BinOp (string concat, arithmetic)
      - list/tuple containing any non-static element
      - Starred(Name) or Starred(Call)
      - Dict, Set, GeneratorExp, etc.

    The rule consuming this fires when its arg is NOT provably static —
    i.e., when static analysis cannot guarantee the arg is a literal.
    """
    if isinstance(arg_node, ast.Constant):
        return True
    if isinstance(arg_node, (ast.List, ast.Tuple)):
        for element in arg_node.elts:
            if isinstance(element, ast.Starred):
                # Starred inside a list is OK only if the unpacked value is
                # itself a List/Tuple of constants.
                if not isinstance(element.value, (ast.List, ast.Tuple)):
                    return False
                if not all(
                    isinstance(inner, ast.Constant)
                    for inner in element.value.elts
                ):
                    return False
                continue
            if not is_provably_static(element):
                return False
        return True
    return False


# ============================================================================
# AST pass orchestration — called by SecurityScanner
# ============================================================================


def run_ast_rules(parsed: ParsedFile) -> list[SecurityFinding]:
    """Dispatch applicable @ast_rules against a ParsedFile.

    The scanner produces `ParsedFile` once per .py file (see
    `SecurityScanner._build_parsed_file`) and hands it here for rule
    dispatch. Before this split, `run_ast_rules` did BOTH the parsing
    and the dispatch — architecture review flagged that as a
    single-responsibility violation.
    """
    # _matches_any_glob lives in security.py and is imported lazily here
    # only to keep the module-load order cycle-free.
    from griffith.analyzer.security import _matches_any_glob

    applicable = [
        spec for spec in AST_RULES
        if _matches_any_glob(parsed.path, [spec.file_filter])
    ]

    ctx = RuleContext(
        tree=parsed.tree, path=parsed.path, alias_table=parsed.alias_table
    )

    findings: list[SecurityFinding] = []
    for spec in applicable:
        try:
            rule_findings = spec.check(ctx)
        except RecursionError:
            # A rule's walk could also hit the limit on adversarial input.
            # Don't let one rule's failure taint others; continue.
            continue
        findings.extend(rule_findings)
    return findings


# ============================================================================
# Rule: subprocess-shell-true (critical)
# First real AST rule — also the dispatch-prover per Unit 0b.
# ============================================================================


_SUBPROCESS_CALL_NAMES = frozenset({
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
})


@ast_rule(
    rule_id="subprocess-shell-true",
    severity="critical",
    file_filter="hooks/**/*.py",
)
def _check_subprocess_shell_true(ctx: RuleContext) -> list:
    """Fire CRITICAL when a subprocess call sets `shell=True`.

    shell=True is the canonical shell-injection surface: anything passed
    as the first positional arg is parsed by /bin/sh, including
    user-controlled substrings. The rule fires regardless of whether the
    arg looks safe — additive to the subprocess-in-hooks capability signal.
    """
    findings = []
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        canonical = resolve_call_target(node, ctx.alias_table)
        if canonical not in _SUBPROCESS_CALL_NAMES:
            continue
        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                findings.append(
                    SecurityFinding(
                        rule_id="subprocess-shell-true",
                        severity="critical",
                        file=ctx.path,
                        line=getattr(node, "lineno", 0),
                        message=(
                            "subprocess call uses shell=True — any "
                            "command string is parsed by /bin/sh, "
                            "enabling shell injection. Prefer list-form "
                            "args with shell=False."
                        ),
                    )
                )
                break
    return findings


@ast_rule(
    rule_id="subprocess-dynamic-command",
    severity="high",
    file_filter="hooks/**/*.py",
)
def _check_subprocess_dynamic_command(ctx: RuleContext) -> list:
    """Fire HIGH on any subprocess call where args[0] is not provably static.

    Inverted check: `is_provably_static(arg)` means "the argument is a
    literal Constant OR a List/Tuple of literal Constants (incl. Starred
    of literal sequences)." Anything else — bare Name, Subscript,
    Attribute, Call, f-string, BinOp, list containing any non-Constant,
    or zero positional args at all (implies **kwargs unpacking) — fires.

    Rationale: static analysis cannot prove "safe" for runtime-constructed
    arguments. The fallback is the conservative surface: if we can't
    verify the arg is a literal, flag it as dynamic. Complemented by
    the always-firing info capability finding, so no legitimate call is
    invisible to the user.
    """
    findings = []
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        canonical = resolve_call_target(node, ctx.alias_table)
        if canonical not in _SUBPROCESS_CALL_NAMES:
            continue
        # Zero positional args → args come from **kwargs; can't verify.
        if not node.args:
            findings.append(
                SecurityFinding(
                    rule_id="subprocess-dynamic-command",
                    severity="high",
                    file=ctx.path,
                    line=getattr(node, "lineno", 0),
                    message=(
                        "subprocess call has no positional args — "
                        "arguments come from **kwargs unpacking; static "
                        "analysis cannot verify they are literal. "
                        "Heuristic signal, not proof."
                    ),
                )
            )
            continue
        if not is_provably_static(node.args[0]):
            findings.append(
                SecurityFinding(
                    rule_id="subprocess-dynamic-command",
                    severity="high",
                    file=ctx.path,
                    line=getattr(node, "lineno", 0),
                    message=(
                        "subprocess call's command argument is not "
                        "provably a literal (f-string, concat, variable, "
                        "or non-constant list). Static analysis cannot "
                        "tell whether the input is attacker-influenced. "
                        "Heuristic signal, not proof."
                    ),
                )
            )
    return findings


# Subprocess call names that accept `timeout=` at construction.
# Popen's timeout is on .wait()/.communicate() — NOT .__init__() — so
# Popen is excluded from the no-timeout rule to avoid false positives.
_SUBPROCESS_TIMEOUT_ACCEPTING = frozenset({
    "subprocess.call",
    "subprocess.run",
    "subprocess.check_output",
    "subprocess.check_call",
})


@ast_rule(
    rule_id="subprocess-no-timeout",
    severity="low",
    file_filter="hooks/**/*.py",
)
def _check_subprocess_no_timeout(ctx: RuleContext) -> list:
    """Fire LOW when a subprocess call (excluding Popen) omits `timeout=`.

    This is a reliability / DoS signal, not a security signal. A
    5-second timeout on `subprocess.run(..., shell=True)` with dynamic
    args is still exploitable within that 5-second window. Documented
    explicitly: timeout absence is a hint about hangs, not safety.
    """
    findings = []
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        canonical = resolve_call_target(node, ctx.alias_table)
        if canonical not in _SUBPROCESS_TIMEOUT_ACCEPTING:
            continue
        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
        if not has_timeout:
            findings.append(
                SecurityFinding(
                    rule_id="subprocess-no-timeout",
                    severity="low",
                    file=ctx.path,
                    line=getattr(node, "lineno", 0),
                    message=(
                        "subprocess call without timeout= kwarg; command "
                        "may hang indefinitely. Reliability hint — does "
                        "not by itself imply exploitability. Note: "
                        "Popen's timeout lives on .wait()/.communicate() "
                        "and is intentionally excluded from this rule."
                    ),
                )
            )
    return findings


# ============================================================================
# dynamic-code-exec family — info capability + medium dynamic-arg
# ============================================================================


_EXEC_BUILTIN_NAMES = frozenset({"exec", "eval"})


def _is_exec_or_eval_builtin(call: ast.Call, alias_table: dict[str, str]) -> bool:
    """True if the call is a direct invocation of the builtin exec/eval.

    `self.exec(...)` / `obj.exec(...)` are attribute calls (not the
    builtin) and don't fire. `builtins.exec(...)` resolves through the
    alias table.
    """
    canonical = resolve_call_target(call, alias_table)
    if canonical is None:
        return False
    # Bare builtins, or via `from builtins import exec` / `import builtins`.
    if canonical in _EXEC_BUILTIN_NAMES:
        return True
    if canonical in ("builtins.exec", "builtins.eval"):
        return True
    return False


@ast_rule(
    rule_id="dynamic-code-exec",
    severity="info",
    file_filter="hooks/**/*.py",
)
def _check_dynamic_code_exec(ctx: RuleContext) -> list:
    """Fire INFO on any exec() or eval() call in hook code.

    Capability signal — always fires regardless of whether the argument
    is a literal string or dynamic code. Complemented by
    `dynamic-code-exec-dynamic-arg` (medium) when the argument is not
    a Constant, catching the `exec(compile(...))` /
    `exec(base64.b64decode(...))` evasion patterns.
    """
    findings = []
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_exec_or_eval_builtin(node, ctx.alias_table):
            continue
        findings.append(
            SecurityFinding(
                rule_id="dynamic-code-exec",
                severity="info",
                file=ctx.path,
                line=getattr(node, "lineno", 0),
                message=(
                    "Capability signal: plugin uses exec()/eval() in a "
                    "hook. See dynamic-code-exec-dynamic-arg (medium) "
                    "for stricter findings when the argument is not a "
                    "literal."
                ),
            )
        )
    return findings


@ast_rule(
    rule_id="path-traversal-dynamic-python",
    severity="high",
    file_filter="**/*.py",
)
def _check_path_traversal_dynamic_python(ctx: RuleContext) -> list:
    """Fire HIGH on Python code where `../` is composed with a runtime value.

    Two patterns caught:
      1. f-string where any Constant part contains `../` AND at least
         one FormattedValue exists.
      2. BinOp `+` where one operand is a Constant string containing
         `../` and the other operand is non-Constant.

    Pure-constant path strings (`open("../../etc/passwd")`) do NOT fire —
    those emit the info-level capability signal via the YAML regex only.
    """
    findings = []
    for node in ast.walk(ctx.tree):
        # Pattern 1: f-string (JoinedStr) with `../` in a Constant part
        # and at least one dynamic FormattedValue.
        if isinstance(node, ast.JoinedStr):
            has_traversal = any(
                isinstance(v, ast.Constant)
                and isinstance(v.value, str)
                and "../" in v.value
                for v in node.values
            )
            has_dynamic = any(
                isinstance(v, ast.FormattedValue) for v in node.values
            )
            if has_traversal and has_dynamic:
                findings.append(
                    SecurityFinding(
                        rule_id="path-traversal-dynamic-python",
                        severity="high",
                        file=ctx.path,
                        line=getattr(node, "lineno", 0),
                        message=(
                            "f-string contains '../' composed with a "
                            "runtime value — potential path traversal "
                            "with attacker-influenced segment."
                        ),
                    )
                )
                continue

        # Pattern 2: BinOp + where one side is constant `../` and the
        # other is non-Constant.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_const = (
                isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and "../" in node.left.value
            )
            right_const = (
                isinstance(node.right, ast.Constant)
                and isinstance(node.right.value, str)
                and "../" in node.right.value
            )
            left_dynamic = not isinstance(node.left, ast.Constant)
            right_dynamic = not isinstance(node.right, ast.Constant)
            if (left_const and right_dynamic) or (right_const and left_dynamic):
                findings.append(
                    SecurityFinding(
                        rule_id="path-traversal-dynamic-python",
                        severity="high",
                        file=ctx.path,
                        line=getattr(node, "lineno", 0),
                        message=(
                            "String concatenation combines '../' with a "
                            "runtime value — potential path traversal "
                            "with attacker-influenced segment."
                        ),
                    )
                )
    return findings


@ast_rule(
    rule_id="dynamic-code-exec-dynamic-arg",
    severity="medium",
    file_filter="hooks/**/*.py",
)
def _check_dynamic_code_exec_dynamic_arg(ctx: RuleContext) -> list:
    """Fire MEDIUM when exec()/eval() is called with a non-Constant arg.

    Catches the common evasion patterns:
    - `exec(compile(src, '<x>', 'exec'))`
    - `exec(base64.b64decode(payload))`
    - `exec(user_input)`

    The info-level `dynamic-code-exec` capability finding always fires
    too; this rule adds escalation, never silencing.
    """
    findings = []
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_exec_or_eval_builtin(node, ctx.alias_table):
            continue
        # No positional args → **kwargs (unusual for exec/eval). Skip.
        if not node.args:
            continue
        if not isinstance(node.args[0], ast.Constant):
            findings.append(
                SecurityFinding(
                    rule_id="dynamic-code-exec-dynamic-arg",
                    severity="medium",
                    file=ctx.path,
                    line=getattr(node, "lineno", 0),
                    message=(
                        "exec()/eval() called with a non-literal argument "
                        "— evasion patterns like exec(compile(...)) or "
                        "exec(base64.b64decode(...)) pass static-text "
                        "rules while still executing attacker-controlled "
                        "code. Heuristic signal, not proof."
                    ),
                )
            )
    return findings
