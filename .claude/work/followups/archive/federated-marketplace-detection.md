# Follow-up: federated marketplaces aren't detected

**Status: DONE (2026-04-20).** Shipped on main at commit `c2439ce`.
Real-world verification against `obra/superpowers-marketplace`: 10
plugins surfaced (previously 0), source fields show
`outer → inner_url` per Decision #1, clone failures error out whole
scan (Decision #2), mixed fixture verifies Decision #3.

**Surfaced during audit-plugin wrapper smoke testing (2026-04-19).**

Griffith currently detects marketplace shape by requiring both a
`.claude-plugin/marketplace.json` **and** a sibling `plugins/` directory
(`src/griffith/cli.py::_run_analysis`). Any repo that ships a
`marketplace.json` pointing to **external** plugin repos — a federated
marketplace — falls through the check, gets treated as a single plugin,
and silently renders a near-empty report with a synthesized plugin
name (`repo`, from the clone directory).

## Evidence

Concrete example: [`obra/superpowers-marketplace`](https://github.com/obra/superpowers-marketplace)
(Jesse Vincent's curated skills marketplace — a popular installation
target; referenced in multiple Claude Code community threads).

Its layout:

```
obra/superpowers-marketplace/
├── .claude-plugin/
│   └── marketplace.json     # 7 plugins listed
├── LICENSE
└── README.md                # No plugins/ directory
```

Each entry in `marketplace.json` has:

```json
{
  "name": "superpowers",
  "source": {
    "source": "url",
    "url": "https://github.com/obra/superpowers.git"
  },
  "version": "5.0.7"
}
```

Against this repo, `griffith analyze obra/superpowers-marketplace`
produces:

```
Plugin: repo               # synthesized from clone dir name
components: 0 (all types)
findings: 0
```

...which is technically accurate for the marketplace root itself, but
deeply misleading as a user-facing audit result. A user running the
LMF audit wrapper against this URL gets "clean plugin!" when in fact
Griffith never looked at any of the seven plugins.

## Why it matters

1. **Adoption friction.** Federated marketplaces are a real shape in
   the wild — any curator who doesn't want to vendor-and-sync other
   people's code will end up here. Current handling silently drops
   them on the floor.
2. **False-clean reports.** The output says "plugin looks fine" with
   zero findings. A user who doesn't read carefully may install the
   whole marketplace thinking Griffith vetted it.
3. **Distinct from TrailOfBits-style**, which bundles under `plugins/`
   and works today.

## Recommended fix

Small scope — the changes all live in `src/griffith/cli.py`:

1. **Broaden detection**: a repo counts as a marketplace when
   `marketplace.json` exists, regardless of `plugins/` presence.
2. **Federated branch**: when there's no `plugins/` dir, walk
   `marketplace.json["plugins"]` and, for each entry with a `source`
   URL, clone-and-analyze it via the same `sources.resolve()` path
   used for single-URL audits. Aggregate into the existing
   `MarketplaceReport` shape.
3. **Bundled branch**: keep current logic.
4. **Mixed marketplaces** (some entries under `plugins/`, some via
   `source.url`) are possible in theory — plan should resolve whether
   to support them or explicitly reject.
5. **New fixture**: synthetic `federated-marketplace/` in
   `tests/fixtures/` with a `marketplace.json` pointing at two
   mini-plugins plus a separate repo via URL.

## Scope boundary

Does NOT require:
- New hardening for cloning (existing `sources.resolve()` is already
  hardened for arbitrary URLs)
- Schema bump — the resulting `MarketplaceReport` already supports
  arbitrary `plugins` counts and shapes
- Per-plugin cache (one audit = N clones; each federated plugin is a
  fresh clone, same as the single-URL path today)

Does need a decision about:
- What to show in the per-plugin report's `source` field — the outer
  marketplace URL, the per-plugin URL, or both?
- How to handle per-plugin clone failures — partial marketplace report
  with some entries showing "clone failed" seems right, but must not
  crash the whole audit.

## Related

- Audit-plugin wrapper plan: `~/Code/gruntwork/gruntwork-marketplace/
  plugins/lastmilefirst/.claude/work/plans/2026-04-18-001-feat-audit-
  plugin-phase-1.5-plan.md` — the smoke test that surfaced this.
- Companion follow-up: `osv-fixed-versions-per-ecosystem.md` — a
  rendering issue surfaced in the same session.
