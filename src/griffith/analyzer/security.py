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

from griffith.analyzer.inventory import ComponentFile, PluginInventory

_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent.parent  # project root
_DEFAULT_RULES_PATH = _PROJECT_ROOT / "rules" / "security_patterns.yaml"
_DEFAULT_LIMITS_PATH = _PROJECT_ROOT / "rules" / "limits.yaml"

_DEFAULT_MAX_LINE_BYTES = 16 * 1024
_DEFAULT_REGEX_TIMEOUT = 1.0

SEVERITY_ORDER: ClassVar = ["critical", "high", "medium", "low", "info"]


@dataclass
class SecurityFinding:
    """A single security concern raised against one file.

    `message` is the rule's human-readable description — safe for embedding.
    The matched bytes are never included to prevent secret leakage.
    """

    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    # Deprecated field kept for backwards-compat with the original stub.
    # Carries the rule's regex pattern source for debugging; NOT the matched
    # bytes. Not embedded in the JSON report.
    pattern: str = ""


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

        # 3. Sort: severity (critical → info), then file, then line
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
