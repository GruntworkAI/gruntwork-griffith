"""Security scanning — apply YAML-driven regex rules to a plugin's inventory.

The scanner consumes a PluginInventory (already walked, with symlinks/oversized
files marked) and applies rules from rules/security_patterns.yaml line-by-line.

Defenses built in:
- ReDoS: uses the `regex` library with per-match wall-clock timeout instead of
  `re`. Timeouts emit a regex-timeout finding rather than hanging the scan.
- Long-line attacks: lines over max_line_bytes (16 KB by default) are truncated
  for scanning and emit a truncated-long-line finding.
- Snippet leakage: SecurityFinding carries only rule_id + file + line + message.
  Matched bytes are never included, so a rule that fires near a secret does not
  echo that secret into the JSON report.
- Symlink escape: inventory already marks symlinks; scanner surfaces them as
  critical findings (symlink-in-plugin-tree) without reading their content.

Rules and limits load lazily on first scan() call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import ClassVar, Iterable

import regex  # pip: regex — supports timeout=
import yaml

from griffith.analyzer.findings import SecurityFinding
from griffith.analyzer.inventory import ComponentFile, PluginInventory

__all__ = ["SecurityFinding", "SecurityScanner"]

_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent.parent  # project root
_DEFAULT_RULES_PATH = _PROJECT_ROOT / "rules" / "security_patterns.yaml"
_DEFAULT_LIMITS_PATH = _PROJECT_ROOT / "rules" / "limits.yaml"

_DEFAULT_MAX_LINE_BYTES = 16 * 1024
_DEFAULT_REGEX_TIMEOUT = 1.0

# Upper bound on the `meta.ast_parse_failures` list. An adversarial plugin
# with thousands of unparseable .py files could otherwise bloat the report.
# Once the cap is exceeded, an overflow sentinel replaces the tail so the
# consumer sees exactly how many entries were truncated.
_AST_PARSE_FAILURES_CAP = 100

SEVERITY_ORDER: ClassVar = ["critical", "high", "medium", "low", "info"]


@dataclass
class _CompiledRule:
    id: str
    severity: str
    pattern_src: str
    pattern: "regex.Pattern"
    context: list[str]
    exclude: list[str]
    message: str
    strict: bool


# ============================================================================
# Glob → regex translator (ASCII-only; supports **, *, ?)
# ============================================================================


def _glob_to_regex(pattern: str) -> re.Pattern:
    parts: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                if i + 2 < len(pattern) and pattern[i + 2] == "/":
                    parts.append(r"(?:.*/)?")
                    i += 3
                else:
                    parts.append(r".*")
                    i += 2
            else:
                parts.append(r"[^/]*")
                i += 1
        elif c == "?":
            parts.append(r"[^/]")
            i += 1
        elif c in r".+()[]{}^$|":
            parts.append("\\" + c)
            i += 1
        else:
            parts.append(c)
            i += 1
    parts.append("$")
    return re.compile("".join(parts))


@lru_cache(maxsize=512)
def _compiled_glob(pattern: str) -> re.Pattern:
    return _glob_to_regex(pattern)


def _matches_any_glob(path: str, patterns: Iterable[str]) -> bool:
    return any(_compiled_glob(p).match(path) for p in patterns)


def _as_list(v: object) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return []


# ============================================================================
# SecurityScanner
# ============================================================================


class SecurityScanner:
    """Apply YAML-driven regex rules to a plugin inventory.

    Parameters:
        strict: include rules marked `strict: true` in the ruleset (default False).
        rules_path: override path to security_patterns.yaml (for tests).
        limits_path: override path to limits.yaml (for tests).

    Rules and limits load on first `scan()` call and are cached on the instance.
    """

    def __init__(
        self,
        *,
        strict: bool = False,
        rules_path: Path | None = None,
        limits_path: Path | None = None,
    ):
        self.strict = strict
        self._rules_path = rules_path
        self._limits_path = limits_path
        self._rules: list[_CompiledRule] | None = None
        self._max_line_bytes: int | None = None
        self._regex_timeout: float | None = None
        # Non-hook .py files whose AST analysis failed to parse, populated
        # during `scan()`. Consumers read via the `ast_parse_failures`
        # property and pass through to `meta.ast_parse_failures`.
        # Hook-path parse failures are emitted as `ast-parse-failed`
        # findings, NOT recorded here.
        self._ast_parse_failures: list[str] = []

    @property
    def ast_parse_failures(self) -> list[str]:
        """Relative paths of non-hook .py files whose AST parse failed
        during the most recent `scan()` call. Hook-path parse failures
        are emitted as findings in `security.findings[]`, not here.

        Capped at `_AST_PARSE_FAILURES_CAP` entries; if the cap is
        exceeded, an overflow sentinel `"... <N> more omitted"` is
        appended so the consumer sees the truncation.
        """
        raw = self._ast_parse_failures
        if len(raw) <= _AST_PARSE_FAILURES_CAP:
            return list(raw)
        omitted = len(raw) - _AST_PARSE_FAILURES_CAP
        return list(raw[:_AST_PARSE_FAILURES_CAP]) + [
            f"... {omitted} more omitted"
        ]

    def _ensure_loaded(self) -> None:
        if self._rules is None:
            rules_path = self._rules_path or _DEFAULT_RULES_PATH
            self._rules = self._load_rules(rules_path, self.strict)
        if self._max_line_bytes is None or self._regex_timeout is None:
            limits_path = self._limits_path or _DEFAULT_LIMITS_PATH
            self._max_line_bytes, self._regex_timeout = self._load_limits(limits_path)

    @staticmethod
    def _load_rules(path: Path, strict: bool) -> list[_CompiledRule]:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict) or "rules" not in data:
            raise ValueError(f"{path}: missing top-level `rules:` list")
        raw_rules = data["rules"]
        compiled: list[_CompiledRule] = []
        for r in raw_rules:
            if not isinstance(r, dict):
                continue
            is_strict_rule = bool(r.get("strict", False))
            if is_strict_rule and not strict:
                continue
            try:
                compiled.append(
                    _CompiledRule(
                        id=r["id"],
                        severity=r["severity"],
                        pattern_src=r["pattern"],
                        pattern=regex.compile(r["pattern"]),
                        context=_as_list(r.get("context")),
                        exclude=_as_list(r.get("exclude")),
                        message=r["message"],
                        strict=is_strict_rule,
                    )
                )
            except (KeyError, regex.error) as e:
                # Malformed rule — skip, don't crash the whole scan
                raise ValueError(f"{path}: rule {r.get('id', '?')} invalid: {e}") from e
        return compiled

    @staticmethod
    def _load_limits(path: Path) -> tuple[int, float]:
        max_line = _DEFAULT_MAX_LINE_BYTES
        timeout = _DEFAULT_REGEX_TIMEOUT
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                max_line = int(data.get("file", {}).get("max_line_bytes", max_line))
                timeout = float(
                    data.get("regex", {}).get("per_file_timeout_seconds", timeout)
                )
            except (yaml.YAMLError, OSError, ValueError, TypeError):
                pass  # fall back to defaults
        return max_line, timeout

    # -- scan -----------------------------------------------------------------

    def scan(self, inventory: PluginInventory) -> list[SecurityFinding]:
        self._ensure_loaded()
        assert self._rules is not None  # _ensure_loaded populates

        # Reset per-scan state.
        self._ast_parse_failures = []

        findings: list[SecurityFinding] = []

        # 1. Inventory-walk findings (symlinks, oversized files)
        for cf in _all_components(inventory):
            if cf.is_symlink:
                findings.append(
                    SecurityFinding(
                        rule_id="symlink-in-plugin-tree",
                        severity="critical",
                        file=cf.path,
                        line=0,
                        message=(
                            "Symlink inside plugin tree; content was not read. "
                            "Plugins should not contain symlinks to external paths."
                        ),
                    )
                )
                continue
            if cf.size_skipped:
                findings.append(
                    SecurityFinding(
                        rule_id="oversized-file-skipped",
                        severity="info",
                        file=cf.path,
                        line=0,
                        message="File exceeded size cap and was not content-scanned.",
                    )
                )

        # 2. Per-file regex rule firings
        for cf in _all_components(inventory):
            if cf.is_symlink or cf.size_skipped:
                continue
            findings.extend(self._scan_file(inventory.path, cf))

        # 3. AST pass — applies to Python files under any registered
        # @ast_rule's file_filter. Per-file parse failures split by path:
        # hook-path failures emit `ast-parse-failed` findings (high);
        # non-hook failures accumulate in self._ast_parse_failures for
        # `meta.ast_parse_failures`.
        #
        # Orchestration split (2026-04-20): `_build_parsed_file` owns
        # "parse + alias-table build" as a scanner-level concern.
        # `run_ast_rules` is now a pure dispatcher that takes the
        # ParsedFile and runs applicable @ast_rule checks.
        #
        # Applicability pre-filter: predecessor's `run_ast_rules`
        # short-circuited on `not applicable and not is_hook_path`.
        # We preserve that here (before calling the helper) so we
        # don't grow `meta.ast_parse_failures` for non-hook .py files
        # that nothing would have inspected anyway.
        from griffith.analyzer.ast_rules import AST_RULES, run_ast_rules

        for cf in _all_components(inventory):
            if cf.is_symlink or cf.size_skipped:
                continue
            if not cf.path.endswith(".py"):
                continue

            is_hook_path = cf.path.startswith("hooks/")
            has_applicable_rule = any(
                _matches_any_glob(cf.path, [spec.file_filter])
                for spec in AST_RULES
            )
            if not is_hook_path and not has_applicable_rule:
                # Non-hook .py with no rule that would apply. Skip the
                # parse entirely — matches predecessor semantics; no
                # meta-failure growth possible.
                continue

            parsed, parse_err = self._build_parsed_file(inventory.path, cf)
            if parsed is not None:
                findings.extend(run_ast_rules(parsed))
            if parse_err is not None:
                if is_hook_path:
                    findings.append(
                        SecurityFinding(
                            rule_id="ast-parse-failed",
                            severity="high",
                            file=cf.path,
                            line=0,
                            message=(
                                "Hook Python file could not be parsed. "
                                "AST rules skipped for this file — "
                                "structural analysis disabled on "
                                "executable hook code is a concerning "
                                "signal. Detail: " + parse_err
                            ),
                        )
                    )
                else:
                    self._ast_parse_failures.append(cf.path)

        # 4. Sort: severity (critical → info), then file, then line
        findings.sort(
            key=lambda f: (SEVERITY_ORDER.index(f.severity), f.file, f.line)
        )
        return findings

    def _scan_file(
        self, plugin_root: Path, cf: ComponentFile
    ) -> list[SecurityFinding]:
        full = plugin_root / cf.path
        try:
            content = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        assert self._rules is not None
        assert self._max_line_bytes is not None
        assert self._regex_timeout is not None

        applicable: list[_CompiledRule] = []
        for rule in self._rules:
            if rule.context and not _matches_any_glob(cf.path, rule.context):
                continue
            if rule.exclude and _matches_any_glob(cf.path, rule.exclude):
                continue
            applicable.append(rule)

        if not applicable:
            return []

        results: list[SecurityFinding] = []
        max_chars = self._max_line_bytes  # conservative: 1 byte per char upper bound
        timeout = self._regex_timeout

        for lineno, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line
            if len(raw_line) > max_chars:
                line = raw_line[:max_chars]
                results.append(
                    SecurityFinding(
                        rule_id="truncated-long-line",
                        severity="info",
                        file=cf.path,
                        line=lineno,
                        message=(
                            f"Line exceeded {max_chars}-char cap; "
                            "truncated for scanning."
                        ),
                    )
                )
            for rule in applicable:
                try:
                    match = rule.pattern.search(line, timeout=timeout)
                except TimeoutError:
                    results.append(
                        SecurityFinding(
                            rule_id="regex-timeout",
                            severity="info",
                            file=cf.path,
                            line=lineno,
                            message=(
                                f"Regex timeout on rule {rule.id}; "
                                "remaining rules still applied to this line."
                            ),
                        )
                    )
                    continue
                except regex.error:
                    continue
                if match:
                    results.append(
                        SecurityFinding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file=cf.path,
                            line=lineno,
                            message=rule.message,
                        )
                    )
        return results

    def _build_parsed_file(
        self, plugin_root: Path, cf: ComponentFile
    ) -> "tuple[ParsedFile | None, str | None]":
        """Parse a single .py file and build its alias table.

        Returns `(ParsedFile, None)` on success or `(None, error_str)` on
        any parse-time failure. The two-stage exception contract is:
          1. Inside the `try/finally` that lowers
             `sys.setrecursionlimit` to `_PARSE_RECURSION_LIMIT`:
             - OSError on read → `(None, "OSError reading ...")`
             - SyntaxError / ValueError / RecursionError during
               `ast.parse` → `(None, "Parse error ...")`
          2. After the recursion limit is restored:
             - RecursionError during `build_alias_table` → `(None,
               "Walk error ...")`

        Non-.py files short-circuit with `(None, None)` — neither a
        parse nor an error; the caller skips them silently.

        Ownership rationale (lives on SecurityScanner, not ast_rules):
          - Parse + alias-table build is per-file orchestration.
          - Rule dispatch (`run_ast_rules`) is per-rule orchestration.
          - The scanner owns the split — it knows the plugin root and
            controls iteration order over components.
        """
        from griffith.analyzer.ast_rules import (
            ParsedFile,
            _PARSE_RECURSION_LIMIT,
            build_alias_table,
        )
        import ast as _ast
        import sys as _sys

        if not cf.path.endswith(".py"):
            return None, None

        full = plugin_root / cf.path
        original_limit = _sys.getrecursionlimit()
        tree: "_ast.Module | None" = None
        try:
            _sys.setrecursionlimit(_PARSE_RECURSION_LIMIT)
            try:
                source = full.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                return None, f"OSError reading {cf.path}: {e}"
            try:
                tree = _ast.parse(source, filename=cf.path)
            except (SyntaxError, ValueError, RecursionError) as e:
                return None, (
                    f"Parse error in {cf.path}: {type(e).__name__}: {e}"
                )
        finally:
            _sys.setrecursionlimit(original_limit)

        # Second stage: alias-table build under the original recursion
        # limit. A deeply-nested-but-parseable tree can still exhaust
        # the stack during ast.walk; catch separately so the scanner
        # sees a clean error string instead of an uncaught exception.
        try:
            alias_table = build_alias_table(tree)
        except RecursionError:
            return None, (
                f"Walk error in {cf.path}: "
                "RecursionError during alias-table build"
            )

        return ParsedFile(path=cf.path, tree=tree, alias_table=alias_table), None


def _all_components(inventory: PluginInventory) -> Iterable[ComponentFile]:
    for bucket in (
        inventory.agents,
        inventory.commands,
        inventory.skills,
        inventory.hooks,
        inventory.mcp_servers,
        inventory.personas,
        inventory.templates,
        inventory.unknown,
    ):
        yield from bucket
