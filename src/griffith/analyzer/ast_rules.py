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

from griffith.analyzer.inventory import ComponentFile

# Forward-reference the finding type to avoid a circular import with
# security.py (which imports this module).
# At runtime we import from security to construct SecurityFinding.


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


# Module-level registry. Decorator populates at import.
AST_RULES: list[ASTRuleSpec] = []


def ast_rule(
    *, id: str, severity: str, file_filter: str
) -> Callable[[Callable], Callable]:
    """Decorator: register an AST rule.

    Usage:

        @ast_rule(id="subprocess-shell-true", severity="critical",
                  file_filter="hooks/**/*.py")
        def check(ctx: RuleContext) -> list[SecurityFinding]:
            ...

    The decorated function stays callable; the spec is registered as a
    side effect. No class hierarchy, no inheritance — the simplest shape
    that supports multiple rules sharing one module.
    """

    def _register(func: Callable) -> Callable:
        AST_RULES.append(
            ASTRuleSpec(
                rule_id=id, severity=severity,
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


def run_ast_rules(
    plugin_root: Path, cf: ComponentFile
) -> tuple[list, Optional[str]]:
    """Parse a Python file and run every applicable @ast_rule against it.

    Returns `(findings, parse_error_message_or_None)`. The caller
    (SecurityScanner) uses the parse_error to decide finding vs meta
    entry per the plan's hook vs non-hook split.
    """
    # Import locally to avoid a circular import at module-load time.
    from griffith.analyzer.security import SecurityFinding

    # Only .py files are AST-parseable.
    if not cf.path.endswith(".py"):
        return [], None

    from griffith.analyzer.security import _matches_any_glob

    applicable = [
        spec for spec in AST_RULES
        if _matches_any_glob(cf.path, [spec.file_filter])
    ]

    # Hook-path .py files: always attempt parse (parse failure in
    # executable hook code is itself a security signal — the
    # `ast-parse-failed` finding fires even if no rule would have run).
    # Non-hook .py files: skip the parse when no rule applies; there's
    # no work to do and no signal to surface.
    is_hook_path = cf.path.startswith(_HOOK_PATH_PREFIX)
    if not applicable and not is_hook_path:
        return [], None

    full = plugin_root / cf.path
    original_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(_PARSE_RECURSION_LIMIT)
        try:
            source = full.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return [], f"OSError reading {cf.path}: {e}"
        try:
            tree = ast.parse(source, filename=cf.path)
        except (SyntaxError, ValueError, RecursionError) as e:
            return [], f"Parse error in {cf.path}: {type(e).__name__}: {e}"
    finally:
        sys.setrecursionlimit(original_limit)

    # Build alias table once per file; hand to every rule.
    try:
        alias_table = build_alias_table(tree)
    except RecursionError:
        # ast.walk can blow the stack on a deeply-nested tree that parsed OK.
        return [], f"Walk error in {cf.path}: RecursionError during alias-table build"

    ctx = RuleContext(tree=tree, path=cf.path, alias_table=alias_table)

    findings: list[SecurityFinding] = []
    for spec in applicable:
        try:
            rule_findings = spec.check(ctx)
        except RecursionError:
            # A rule's walk could also hit the limit on adversarial input.
            # Don't let one rule's failure taint others; continue.
            continue
        findings.extend(rule_findings)
    return findings, None


# ============================================================================
# Helper: SecurityFinding constructor shim (avoids circular import)
# ============================================================================


def make_finding(
    rule_id: str, severity: str, file: str, line: int, message: str
):
    """Build a SecurityFinding; defers import to break the cycle."""
    from griffith.analyzer.security import SecurityFinding

    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        file=file,
        line=line,
        message=message,
    )


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
    id="subprocess-shell-true",
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
                    make_finding(
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
