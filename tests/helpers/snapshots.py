"""Fingerprint-snapshot testing for real-plugin integration gates.

Per the plan's Decision 11 + R12, real-plugin integration tests assert
the set of `(rule_id, file)` pairs produced by a live scan matches a
checked-in snapshot. Multiset equality (via `collections.Counter`) —
line-number drift does NOT break snapshots; the `line_hint` field is
informational only.

Snapshot format:
    {
      "griffith_version": "0.1.0",
      "generated_at": "2026-04-20T00:00:00Z",
      "findings": [
        {"rule_id": "...", "file": "...", "line_hint": 31},
        ...
      ]
    }

To regenerate: set the environment variable `GRIFFITH_REGENERATE_SNAPSHOTS=1`.
In that mode, `assert_snapshot` writes the current findings to disk
instead of asserting against the stored snapshot. The resulting git
diff becomes the reviewable artifact.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path


SNAPSHOT_DIR = Path(__file__).parent.parent / "snapshots"
_REGENERATE_ENV = "GRIFFITH_REGENERATE_SNAPSHOTS"


def _findings_to_records(findings) -> list[dict]:
    """Normalize SecurityFinding objects to snapshot records."""
    records = []
    for f in findings:
        records.append({
            "rule_id": f.rule_id,
            "file": f.file,
            "line_hint": f.line,
        })
    # Deterministic ordering for snapshot stability (by rule_id, file, line).
    records.sort(key=lambda r: (r["rule_id"], r["file"], r["line_hint"]))
    return records


def _stable_key(record: dict) -> tuple[str, str]:
    """Return the (rule_id, file) tuple used for multiset equality.

    `line_hint` is intentionally omitted — line-number drift from
    source reshuffling doesn't churn snapshots.
    """
    return (record["rule_id"], record["file"])


def _multiset(records: list[dict]) -> Counter:
    return Counter(_stable_key(r) for r in records)


def assert_snapshot(snapshot_name: str, findings, *, griffith_version: str):
    """Compare live findings against a stored snapshot.

    In regenerate mode, rewrites the snapshot file instead of asserting.
    Diffs on failure show added / removed fingerprints with a plain-English
    description so the developer can see what changed.
    """
    path = SNAPSHOT_DIR / f"{snapshot_name}.json"
    live_records = _findings_to_records(findings)

    if os.environ.get(_REGENERATE_ENV) == "1":
        import datetime
        snapshot = {
            "griffith_version": griffith_version,
            "generated_at": datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "findings": live_records,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(snapshot, indent=2) + "\n")
        print(f"Regenerated snapshot: {path}")
        return

    if not path.exists():
        raise AssertionError(
            f"Snapshot missing: {path}\n"
            f"Run with {_REGENERATE_ENV}=1 to create it, then commit."
        )

    stored = json.loads(path.read_text())
    stored_records = stored.get("findings", [])

    live_ms = _multiset(live_records)
    stored_ms = _multiset(stored_records)

    if live_ms == stored_ms:
        return

    added = live_ms - stored_ms
    removed = stored_ms - live_ms

    lines = [f"Snapshot mismatch: {path}"]
    if added:
        lines.append(f"  Added {sum(added.values())} finding(s):")
        for (rule_id, file), count in sorted(added.items()):
            suffix = f" (×{count})" if count > 1 else ""
            lines.append(f"    + {rule_id}  {file}{suffix}")
    if removed:
        lines.append(f"  Removed {sum(removed.values())} finding(s):")
        for (rule_id, file), count in sorted(removed.items()):
            suffix = f" (×{count})" if count > 1 else ""
            lines.append(f"    - {rule_id}  {file}{suffix}")
    lines.append(
        f"\nIf the change is intentional, regenerate:\n"
        f"  {_REGENERATE_ENV}=1 poetry run pytest <this test path>"
    )
    raise AssertionError("\n".join(lines))
