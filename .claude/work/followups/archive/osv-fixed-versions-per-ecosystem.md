# Follow-up: osv adapter renders cross-ecosystem `fixed_versions`

**Status: DONE (2026-04-19).** Fixed on main at commit `cd74302`.
`_extract_fixed_versions` now takes `target_ecosystem` and filters
`affected[]` entries. Real-world check on compound-engineering 2.67.0
shows GHSA-j7hp-h8jx-5ppr now renders `fixed: 10.0.1` (was
`fixed: 0.1.8, 0.9.3, 22.3.24, +16`).

**Surfaced while drafting the PR to EveryInc for the Pillow CVEs (2026-04-19).**

Griffith's osv adapter (`src/griffith/analyzer/osv_adapter.py::
_extract_vulnerabilities`) flattens `affected[].ranges[].events[].fixed`
from osv-scanner's JSON output into a single list per
`Vulnerability.fixed_versions`, across **all ecosystems** in the OSV
advisory. For a CVE that affects multiple ecosystems, the rendered
"Fixed in" column becomes a jumble that a user can't act on.

## Evidence

`GHSA-j7hp-h8jx-5ppr` (libwebp OOB write / CVE-2023-4863) is present
in OSV across eleven ecosystems (PyPI `pillow`, crates.io
`libwebp-sys`, npm `electron`, NuGet `SkiaSharp`, Go `chai2010/webp`,
and more).

Griffith's Rich renderer output for this vuln, when scanning a Python
plugin pinning `Pillow>=10.0.0`, shows:

```
pillow | GHSA-j7hp-h8jx-5ppr | 8.8 | libwebp: OOB write in BuildHuffmanTable
  fixed: 0.1.8, 0.9.3, 22.3.24, +16
```

The actual PyPI-Pillow fix is **10.0.1**. The versions `0.1.8`,
`0.9.3`, `22.3.24` are libwebp-sys2 / libwebp-sys / Electron. None of
them are applicable to a user on `Pillow>=10.0.0`.

A user reading the wrapper output would reasonably conclude either
that the vulnerability doesn't apply (no version looks like a Pillow
version) or that they need to pin some combination of unfamiliar
libraries. The correct fix (`Pillow>=10.0.1`) is invisible to them.

## Why it matters

1. **Actionability is the product.** A CVE finding that doesn't tell
   the user how to fix it is close to useless.
2. **Confidence-undermining.** Once a user notices the list is
   nonsense for their ecosystem, the trust-by-default posture erodes;
   they start second-guessing every other finding.
3. **Verifying manually is tedious.** I caught this when drafting
   the PR to EveryInc (PR #608 on compound-engineering-plugin) and
   had to hit `api.osv.dev/v1/vulns/<id>` directly to get the
   per-ecosystem fix. That's fine for me; unacceptable as a user
   workflow.

## Recommended fix

In `_extract_vulnerabilities`, narrow the `fixed_versions` collection
to entries whose `affected[].package.ecosystem` matches the ecosystem
of the package being analyzed. The outer loop already knows the
package (`pkg_entry["package"]["ecosystem"]` is the scanned package's
ecosystem); feed that into the helper.

Pseudocode:

```python
def _extract_fixed_versions(vuln_detail: dict, target_ecosystem: str) -> list[str]:
    fixed = []
    for affected in vuln_detail.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != target_ecosystem:
            continue   # skip cross-ecosystem noise
        for r in affected.get("ranges") or []:
            for event in r.get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    fixed.append(str(event["fixed"]))
    return fixed
```

And at the call site, pass through the ecosystem string.

## Test scenarios

- A vuln with only one ecosystem → result identical to current output.
- A vuln with N ecosystems → result contains only the target
  ecosystem's fix versions.
- A vuln with zero affected entries matching the target ecosystem
  (unlikely but possible if osv-scanner's package matching returns a
  cross-ecosystem alias) → empty `fixed_versions` rather than a
  misleading list.
- Adversarial: `affected[]` with a missing / malformed `package` key
  (skip gracefully).

## Scope boundary

- Does NOT require schema changes. `fixed_versions` stays
  `list[str]`, just becomes narrower.
- Does NOT change severity mapping or any other fields.
- Does NOT require walking multi-ecosystem registries or API calls
  — the data is already in the osv-scanner JSON payload.

## Related

- `federated-marketplace-detection.md` — companion follow-up from
  the same session.
- PR #608 on `EveryInc/compound-engineering-plugin` cites this as a
  known limitation in its "How this was found" section — worth
  closing this gap before the wrapper has many external users.
