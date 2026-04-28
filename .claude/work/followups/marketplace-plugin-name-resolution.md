# Followup: marketplace plugin-name resolution when source is `./`

**Status: open. Surfaced 2026-04-28 during BMAD-METHOD audit.**

## The bug

When a Claude Code marketplace's `marketplace.json` declares
multiple plugins with `source: "./"` (i.e., all plugins live at the
repo root, distinguished only by their plugin-entry `name` and the
listed `skills` paths), Griffith's audit output labels every plugin
with `plugin.name = "repo"` instead of using the explicit `name`
field from the marketplace entry.

**Concrete example** — `bmad-code-org/BMAD-METHOD`:

```json
{
  "plugins": [
    {
      "name": "bmad-pro-skills",
      "source": "./",
      "skills": ["./src/core-skills/bmad-help", ...]
    },
    {
      "name": "bmad-method-lifecycle",
      "source": "./",
      "skills": ["./src/lifecycle-skills/...", ...]
    }
  ]
}
```

Griffith's report:

```json
{
  "marketplace": { ... },
  "reports": [
    { "plugin": { "name": "repo", "path": "", "source": "https://..." }, ... },
    { "plugin": { "name": "repo", "path": "", "source": "https://..." }, ... }
  ]
}
```

Both reports show `name: "repo"` — should be `bmad-pro-skills` and
`bmad-method-lifecycle`.

## Why it matters

- **Audit reports become ambiguous.** Two plugins with the same name
  in the same `reports[]` array can't be distinguished without
  rederiving from `skills` paths.
- **Downstream consumers** (the LMF wrapper renders by `plugin.name`)
  display the wrong name.
- **Future cross-marketplace queries** ("which plugins fired
  rule X?") collapse to the repo name.

The audit's findings themselves are unaffected — file walk and rule
emission are correct. Only the display name is wrong.

## Likely cause

Griffith probably extracts `plugin.name` from the basename of the
resolved plugin source path. When `source` is `./`, the resolved
path is the repo root and the basename is something like the
clone-temp directory name (which Griffith normalizes to `"repo"`).
The marketplace.json's `name` field is ignored at this layer.

## Fix sketch

In `src/griffith/sources.py` (or wherever
`_resolve_marketplace_plugin` produces per-plugin metadata):

1. When the plugin entry has an explicit `name` field in
   `marketplace.json`, use it as `plugin.name` instead of deriving
   from the path.
2. Preserve the path-derived name as a fallback when `name` is
   absent.
3. Add a regression test using a fixture marketplace where 2+
   plugins share `source: "./"` with distinct `name` fields.

## Test scenarios needed

- Two plugins with `source: "./"`, distinct `name` fields → both
  preserved correctly.
- Plugin with `source: "./subdir"`, distinct `name` → uses the
  marketplace `name`, not `"subdir"`.
- Plugin without an explicit `name` → falls back to path-basename
  (current behavior).
- Federated marketplace mixing both shapes (some plugins as URLs,
  some as `./`) — both name resolutions correct.

## Related

- Surfaced during: `docs/audits/2026-04-28-bmad-method.md`
- Griffith feature originally shipped: federated-marketplace
  detection in commit `c2439ce` (Phase 1.5).
