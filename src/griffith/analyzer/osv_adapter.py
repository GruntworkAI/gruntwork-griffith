"""OSV-Scanner adapter — Tier 2 (CVE scanning) for Phase 1.5 Unit 6.

Shells out to osv-scanner (https://google.github.io/osv-scanner/), parses its
JSON output, and emits structured CVE findings. The adapter is invoked only
when the user passes --sca; without that flag, osv-scanner is never looked
for. Hard-fails with exit code 2 when --sca is set but osv-scanner is missing.

Hardening highlights:
- Auto-discovery with path-integrity check (realpath must not be inside plugin
  tree, marketplace root, griffith cache dir, or tempfile root). Refuses
  shadowed binaries.
- GRIFFITH_OSV_SCANNER env var override for custom paths.
- Scrubbed subprocess env preserves PATH + HOME + XDG_* + proxy + TLS vars
  (osv-scanner needs these for network + DB cache), strips shell-hostile
  vars (SSH_AUTH_SOCK, GIT_*, LD_PRELOAD, DYLD_*, NODE_OPTIONS, PYTHONPATH).
  XDG_CACHE_HOME overridden to griffith-local dir so network-mounted HOME
  doesn't corrupt osv's DB cache.
- Concurrent dual-reader with per-stream caps (stdout 32 MB, stderr 1 MB) —
  prevents JSON-bomb DoS and pipe-buffer deadlock.
- -- separator before plugin path blocks argument injection.
- 120s wall-clock timeout.

Exit code semantics (verified against osv-scanner v2.3.5):
- 0 → scan ok, zero vulns found
- 1 → scan ok, vulnerabilities found (NOT a failure)
- 128 → no scannable package sources (e.g. Node plugin without a lockfile)
- other nonzero → sca_requested_and_failed
- exit 0 + malformed JSON → sca_malformed_output (distinct tampering signal)

CVE severity mapping is fail-closed: unparseable / empty CVSS → critical
(not info), so CI pipelines that gate on severity can't miss a real
critical CVE due to schema drift.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from griffith.analyzer.dependencies import SCAResult, Vulnerability

# Subprocess bounds + timeouts
OSV_TIMEOUT_SECONDS = 120
OSV_STDOUT_MAX_BYTES = 32 * 1024 * 1024   # 32 MB
OSV_STDERR_MAX_BYTES = 1 * 1024 * 1024    # 1 MB

# Drain chunk size
_READ_CHUNK = 65536

# Auto-discovery fallback paths (in priority order after $GRIFFITH_OSV_SCANNER
# and shutil.which).
_FALLBACK_BINARY_PATHS = [
    Path("/opt/homebrew/bin/osv-scanner"),  # Apple Silicon brew
    Path("/usr/local/bin/osv-scanner"),     # Intel brew / Linux
    Path.home() / "go" / "bin" / "osv-scanner",  # go install
    Path("/usr/bin/osv-scanner"),           # distro packages
]

# Trees under which a discovered binary must NOT live (defense against
# shadowed-binary attacks).
_CONTAINMENT_REJECT_ROOTS_DEFAULT: tuple[Path, ...] = (
    Path.home() / ".cache" / "griffith",
)

# Install pitch — single-source text rendered in JSON output, Rich panel,
# and LMF wrapper markdown. Claim-light on purpose (honest about what we
# know vs. what we're extrapolating from).
INSTALL_PITCH = (
    "Recommended: install osv-scanner for dependency CVE analysis.\n"
    "\n"
    "Plugins declaring Python or Node dependencies inherit the supply-chain "
    "risk of their upstream ecosystems. Documented incidents include npm "
    "post-install attacks (ua-parser-js 2021, event-stream 2018) and PyPI "
    "typosquats (ctx, colourama). The Claude Code plugin ecosystem itself "
    "has no publicly-documented supply-chain incidents yet — this is risk "
    "by inheritance, not demonstrated-in-the-wild attack.\n"
    "\n"
    "Install:\n"
    "  macOS:   brew install osv-scanner\n"
    "  Other:   https://google.github.io/osv-scanner/installation/\n"
    "\n"
    "Override the binary path with the GRIFFITH_OSV_SCANNER env var if you "
    "have a custom install location."
)


# ============================================================================
# Public API
# ============================================================================


class OSVScannerMissingError(RuntimeError):
    """Raised when --sca is set but osv-scanner cannot be found / resolved."""


@dataclass
class _SubprocessResult:
    """Internal: stdout/stderr/returncode from the bounded Popen helper."""

    stdout: str
    stderr: str
    returncode: int
    stdout_truncated: bool
    stderr_truncated: bool


def find_osv_scanner(
    *,
    reject_roots: tuple[Path, ...] = _CONTAINMENT_REJECT_ROOTS_DEFAULT,
) -> Optional[Path]:
    """Locate an osv-scanner binary.

    Priority:
      1. `GRIFFITH_OSV_SCANNER` env var (user-provided absolute path)
      2. `shutil.which("osv-scanner")` — standard PATH lookup
      3. Known fallback paths (brew / go install / distro)

    Rejects resolved paths inside any of `reject_roots` (defense against
    shadowed binaries planted in attacker-writable locations).

    Returns None if no valid binary is found.
    """
    candidates: list[Path] = []

    env_override = os.environ.get("GRIFFITH_OSV_SCANNER")
    if env_override:
        candidates.append(Path(env_override))

    which_hit = shutil.which("osv-scanner")
    if which_hit:
        candidates.append(Path(which_hit))

    candidates.extend(_FALLBACK_BINARY_PATHS)

    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            real = candidate.resolve()
        except OSError:
            continue
        if _is_in_any(real, reject_roots):
            continue
        return real
    return None


def run_osv_scanner(
    osv_binary: Path,
    plugin_path: Path,
    *,
    exclude_globs: Optional[list[str]] = None,
    timeout: int = OSV_TIMEOUT_SECONDS,
) -> SCAResult:
    """Shell out to osv-scanner and return a structured SCAResult.

    Applies all hardening invariants (bounded stdout/stderr, scrubbed env,
    timeout, `--` separator). Maps osv-scanner exit codes and JSON output to
    Griffith's scan_status + severity enum.
    """
    exclude_globs = exclude_globs or []
    osv_scanner_version = _probe_version(osv_binary)

    cmd = [
        str(osv_binary),
        "scan",
        "source",
        "-r",
        "--format", "json",
    ]
    # Base excludes: version control + common vendored-tree dirs.
    base_excludes = ["g:.git", "g:node_modules", "g:.venv", "g:venv", "g:vendor"]
    for pattern in base_excludes + exclude_globs:
        cmd.extend(["--experimental-exclude", pattern])
    cmd.extend(["--", str(plugin_path)])

    env = _build_osv_env()

    try:
        result = _run_bounded(
            cmd, env=env, timeout=timeout,
            stdout_cap=OSV_STDOUT_MAX_BYTES,
            stderr_cap=OSV_STDERR_MAX_BYTES,
        )
    except subprocess.TimeoutExpired:
        return SCAResult(
            osv_scanner_version=osv_scanner_version,
            vulnerability_count=0,
            vulnerabilities=[],
            note=None,
            error=f"osv-scanner timed out after {timeout}s",
            scan_status="sca_requested_and_timed_out",
        )
    except OSError as e:
        return SCAResult(
            osv_scanner_version=osv_scanner_version,
            vulnerability_count=0,
            vulnerabilities=[],
            note=None,
            error=f"osv-scanner subprocess error: {e}",
            scan_status="sca_requested_and_failed",
        )

    if result.stdout_truncated or result.stderr_truncated:
        return SCAResult(
            osv_scanner_version=osv_scanner_version,
            vulnerability_count=0,
            vulnerabilities=[],
            note=None,
            error=(
                f"osv-scanner output exceeded bounds "
                f"(stdout_truncated={result.stdout_truncated}, "
                f"stderr_truncated={result.stderr_truncated})"
            ),
            scan_status="sca_requested_and_failed",
        )

    # Exit 128 → "no scannable sources found" — treat as ok with note
    if result.returncode == 128:
        return SCAResult(
            osv_scanner_version=osv_scanner_version,
            vulnerability_count=0,
            vulnerabilities=[],
            note=(
                "osv-scanner found no scannable package sources. "
                "Common causes: Node plugin without a lockfile "
                "(package-lock.json / yarn.lock / pnpm-lock.yaml required), "
                "or manifest formats osv-scanner doesn't recognize."
            ),
            error=None,
            scan_status="ok",
        )

    # Exit 0 or 1 → normal scan outcome (1 means vulns found, still success)
    if result.returncode in (0, 1):
        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            # Exit 0 but malformed JSON → potential tampering signal
            return SCAResult(
                osv_scanner_version=osv_scanner_version,
                vulnerability_count=0,
                vulnerabilities=[],
                note=None,
                error=(
                    "osv-scanner exited successfully but stdout was not valid "
                    "JSON. Possible binary tampering, version mismatch, or "
                    "output format drift."
                ),
                scan_status="sca_malformed_output",
            )
        vulnerabilities = _extract_vulnerabilities(data)
        return SCAResult(
            osv_scanner_version=osv_scanner_version,
            vulnerability_count=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            note=None,
            error=None,
            scan_status="ok",
        )

    # Any other non-zero exit → failed
    stderr_tail = _tail(result.stderr, 500)
    return SCAResult(
        osv_scanner_version=osv_scanner_version,
        vulnerability_count=0,
        vulnerabilities=[],
        note=None,
        error=(
            f"osv-scanner exited with code {result.returncode}: {stderr_tail}"
        ),
        scan_status="sca_requested_and_failed",
    )


# ============================================================================
# Version probe + severity mapping
# ============================================================================


_VERSION_RE = re.compile(r"osv-scanner version:\s*(\S+)")


def _probe_version(osv_binary: Path) -> str:
    """Run `osv-scanner --version` and extract the version string."""
    try:
        result = subprocess.run(
            [str(osv_binary), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    m = _VERSION_RE.search(result.stdout or "")
    return m.group(1) if m else "unknown"


# CVSS v3 qualitative severity ratings (FIRST standard):
#   9.0–10.0: critical / 7.0–8.9: high / 4.0–6.9: medium /
#   0.1–3.9: low / 0.0: none
# Griffith maps "none" → info and unparseable → critical (fail-closed).
_SEVERITY_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def _map_cvss_to_severity(raw: str) -> str:
    """Map a CVSS severity string (numeric or vector form) to Griffith enum.

    Fail-closed: any parse failure → "critical" so CI gates can't miss a
    real critical CVE due to upstream schema drift. Vector-string form
    (`CVSS:3.1/AV:N/...`) is tolerated by extracting the numeric base score
    if present; otherwise → "critical".
    """
    if not isinstance(raw, str) or not raw.strip():
        return "critical"  # fail-closed on missing/empty
    stripped = raw.strip()
    # Try direct float parse first (`"7.5"` / `"0"`)
    try:
        score = float(stripped)
    except ValueError:
        # Try to find a numeric score inside a vector string
        m = re.search(r"\b([0-9]+(?:\.[0-9]+)?)\b", stripped)
        if not m:
            return "critical"
        try:
            score = float(m.group(1))
        except ValueError:
            return "critical"
    if not (0.0 <= score <= 10.0):
        return "critical"
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "critical"  # unreachable except on NaN


def _extract_vulnerabilities(osv_output: dict) -> list[Vulnerability]:
    """Walk osv-scanner JSON and extract Vulnerability dataclasses.

    OSV v2 JSON shape (simplified):
        {"results": [
            {"source": {"path", "type"},
             "packages": [
                {"package": {"name", "version", "ecosystem"},
                 "groups": [{"ids", "aliases", "max_severity"}],
                 "vulnerabilities": [{"id", "summary", "affected", ...}]}
             ]}
        ]}

    We emit one Vulnerability per group (groups collate aliases of the same
    underlying CVE).
    """
    from griffith.sanitize import (
        DEFAULT_MAX_DESCRIPTION_LENGTH,
        DEFAULT_MAX_NAME_LENGTH,
        sanitize_string,
    )

    findings: list[Vulnerability] = []
    results = osv_output.get("results") if isinstance(osv_output, dict) else None
    if not isinstance(results, list):
        return findings

    for entry in results:
        if not isinstance(entry, dict):
            continue
        packages = entry.get("packages") or []
        if not isinstance(packages, list):
            continue
        for pkg_entry in packages:
            if not isinstance(pkg_entry, dict):
                continue
            pkg = pkg_entry.get("package") or {}
            pkg_name = (
                pkg.get("name", "") if isinstance(pkg, dict) else ""
            )
            groups = pkg_entry.get("groups") or []
            vulns_by_id = {
                v.get("id"): v
                for v in (pkg_entry.get("vulnerabilities") or [])
                if isinstance(v, dict)
            }
            for group in groups:
                if not isinstance(group, dict):
                    continue
                ids = group.get("ids") or []
                if not isinstance(ids, list) or not ids:
                    continue
                primary_id = str(ids[0])
                severity_raw = str(group.get("max_severity", ""))
                severity = _map_cvss_to_severity(severity_raw)
                vuln_detail = vulns_by_id.get(primary_id) or {}
                summary = (
                    vuln_detail.get("summary", "")
                    if isinstance(vuln_detail, dict)
                    else ""
                )
                fixed_versions = _extract_fixed_versions(vuln_detail)
                findings.append(
                    Vulnerability(
                        id=sanitize_string(primary_id, DEFAULT_MAX_NAME_LENGTH),
                        severity=severity,
                        severity_raw=sanitize_string(severity_raw, 32),
                        summary=sanitize_string(
                            summary, DEFAULT_MAX_DESCRIPTION_LENGTH
                        ),
                        affected_package=sanitize_string(
                            str(pkg_name), DEFAULT_MAX_NAME_LENGTH
                        ),
                        fixed_versions=[
                            sanitize_string(v, DEFAULT_MAX_NAME_LENGTH)
                            for v in fixed_versions
                        ],
                    )
                )
    # Sort by severity (critical first) for stable display
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda v: _SEVERITY_ORDER.get(v.severity, 99))
    return findings


def _extract_fixed_versions(vuln_detail: dict) -> list[str]:
    """Walk the vulnerability's affected[] array to find FIXED event versions."""
    if not isinstance(vuln_detail, dict):
        return []
    fixed: list[str] = []
    for affected in vuln_detail.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for r in affected.get("ranges") or []:
            if not isinstance(r, dict):
                continue
            for event in r.get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    fixed.append(str(event["fixed"]))
    return fixed


# ============================================================================
# Subprocess helpers (hardened env + bounded dual-stream reader)
# ============================================================================


_ENV_STRIP = {
    "SSH_AUTH_SOCK", "SSH_ASKPASS",
    "GIT_ASKPASS", "GIT_SSH_COMMAND",
    "LD_PRELOAD", "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
    "NODE_OPTIONS", "PYTHONPATH",
}


def _build_osv_env() -> dict[str, str]:
    """Build a scrubbed env for the osv-scanner subprocess.

    Preserves what osv-scanner needs (PATH, HOME, XDG_*, proxy, TLS) and
    strips shell-hostile / credential-leaking vars. Overrides
    XDG_CACHE_HOME to a griffith-managed path so network-mounted HOME
    doesn't corrupt osv's DB cache.
    """
    env: dict[str, str] = {}
    for k, v in os.environ.items():
        if k in _ENV_STRIP or k.startswith("GIT_"):
            continue
        env[k] = v

    # Preserve PATH with a sane fallback if the source env is unusual
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    # Force UTF-8 locale so osv-scanner doesn't hit locale-driven parser bugs
    env["LANG"] = "C.UTF-8"
    # Pin cache dir so network-mounted HOME doesn't corrupt osv's DB
    griffith_cache = Path.home() / ".cache" / "griffith" / "osv-scanner"
    griffith_cache.mkdir(parents=True, exist_ok=True)
    env["XDG_CACHE_HOME"] = str(griffith_cache.parent)
    return env


def _run_bounded(
    cmd: list[str],
    *,
    env: dict[str, str],
    timeout: int,
    stdout_cap: int,
    stderr_cap: int,
) -> _SubprocessResult:
    """Run a subprocess with per-stream size caps and a wall-clock timeout.

    Uses two reader threads to drain stdout and stderr concurrently. This
    prevents (a) stdout/stderr pipe-buffer deadlock, (b) JSON-bomb DoS via
    unbounded stdout, and (c) noisy-stderr exhaustion. On overflow, the
    subprocess is terminated and the result signals truncation.
    """
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_overflow = [False]
    stderr_overflow = [False]

    def _drain(stream, buf: bytearray, cap: int, overflow: list[bool]) -> None:
        try:
            while True:
                chunk = stream.read(_READ_CHUNK)
                if not chunk:
                    break
                if len(buf) + len(chunk) > cap:
                    # Take what fits, then mark overflow and stop
                    room = cap - len(buf)
                    if room > 0:
                        buf.extend(chunk[:room])
                    overflow[0] = True
                    break
                buf.extend(chunk)
        except Exception:
            # Stream closed / decoder error — stop draining but don't crash
            pass

    t_out = threading.Thread(
        target=_drain, args=(proc.stdout, stdout_buf, stdout_cap, stdout_overflow)
    )
    t_err = threading.Thread(
        target=_drain, args=(proc.stderr, stderr_buf, stderr_cap, stderr_overflow)
    )
    t_out.daemon = True
    t_err.daemon = True
    t_out.start()
    t_err.start()

    try:
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        t_out.join(timeout=2)
        t_err.join(timeout=2)
        raise

    # Join reader threads (they should exit quickly once pipes close)
    t_out.join(timeout=5)
    t_err.join(timeout=5)

    # Overflow → kill subprocess if still running (defense-in-depth)
    if (stdout_overflow[0] or stderr_overflow[0]) and proc.poll() is None:
        proc.kill()
        proc.wait()

    return _SubprocessResult(
        stdout=stdout_buf.decode("utf-8", errors="replace"),
        stderr=stderr_buf.decode("utf-8", errors="replace"),
        returncode=returncode,
        stdout_truncated=stdout_overflow[0],
        stderr_truncated=stderr_overflow[0],
    )


# ============================================================================
# Small utilities
# ============================================================================


def _is_in_any(path: Path, roots: tuple[Path, ...]) -> bool:
    """Return True if `path` is inside any of `roots` (after resolve)."""
    for root in roots:
        try:
            path.relative_to(root.resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def _tail(s: str, max_chars: int) -> str:
    """Return the last `max_chars` of a string, one-line safe."""
    if len(s) <= max_chars:
        return s.replace("\n", " ").strip()
    return s[-max_chars:].replace("\n", " ").strip()
