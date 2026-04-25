# Follow-up: Default-skip vendored dirs — refinements (deferred from PR #5)

**Observed during PR #5 self-review (2026-04-25):**

PR #5 added `DEFAULT_SKIP_DIRS` pruning to `PluginInventory.from_path`,
plus `--include-vendored` override and visibility surface (Rich line +
`InventoryDict.skipped_dirs`). Four refinements surfaced during review
were deferred to keep the initial PR focused. None are blocking; all
are defense-in-depth or coordination items.

## 1. Security-rule integration test for skipped content

**What:** `TestSkipDirsDefault` asserts inventory shape (no node_modules
files in `inv.unknown` etc.) but does *not* directly assert that the
`SecurityScanner` emits zero findings against skipped vendored content.

**Risk:** The colleague's bug was reported as *315 false-critical
findings* — a security-output symptom. The current tests prove the
upstream cause (inventory pruning) but don't tie the regression to
the user-visible output. A future change that re-introduces vendored
content to the security scanner via a different code path would slip
through.

**Fix:** Add a fixture with vendored content that *would* trigger
security rules (e.g. a `node_modules/some-pkg/script.sh` containing
a `curl-pipe` pattern) and assert
`SecurityScanner().scan(inv).findings == []` by default.

**Effort:** ~15-line test addition; can reuse `vendor-dirs-plugin`
fixture by adding one tripwire file.

## 2. Marketplace-flow CLI integration test for `--include-vendored`

**What:** The CLI threads `include_vendored` through `_run_analysis →
_analyze_marketplace → _analyze_marketplace_entry → _analyze_single`.
PR #5 verified the single-plugin path end-to-end via CLI smoke but
not the marketplace path.

**Risk:** A future refactor that drops the kwarg propagation in the
marketplace dispatch would silently break the flag for marketplace
inputs. Single-plugin tests would still pass.

**Fix:** Add a click-runner test (using `CliRunner` from `click.testing`)
that runs `griffith analyze <fixture-marketplace> --include-vendored`
and asserts the per-plugin reports contain the expected
`inventory.skipped_dirs` value.

**Effort:** ~25-line test addition.

## 3. Schema_version bump + v0.1 carve-out coordination

**What:** PR #5 added `skipped_dirs` as a required field on
`InventoryDict`. Per `schema.py`'s own promise — *"any change to these
TypedDicts bumps schema_version"* — this should bump `0.1 → 0.2`.

**Why deferred:** The v0.1 severity carve-out
(`docs/json-schema.md:283`) is explicitly scoped to v0.1 with the
phrase *"this carve-out is a one-time v0.1 concession; future
loosenings require a version bump."* A bump should re-evaluate the
carve-out as one batch — either keep it under a new "v0.2 carve-out"
clause or remove it.

**Fix:** Coordinated sweep:
- Bump `SCHEMA_VERSION` to `"0.2"` in `src/griffith/schema.py`
- Update `tests/test_cli.py:31` (`assert parsed["schema_version"] == "0.1"`)
- Update `docs/json-schema.md` references (header, two example blocks,
  stability guarantees section)
- Decide: drop the severity carve-out entirely, or re-scope to v0.2
- Update `tests/test_schema_doc_contract.py` if the carve-out anchor
  phrase changes
- Update README's "Schema is explicitly **v0.1 and unstable**" line

**Effort:** ~30 minutes. Requires a clear decision on the carve-out.

## 4. Surface nested-skip events (or document top-level-only scope)

**What:** `inv.skipped_dirs` only tracks top-level pruning. If a plugin
has `hooks/foo/node_modules/` deep inside a conventional dir, the walker
silently prunes it without surfacing in the report.

**Risk:** Realistically rare — plugins seldom have deeply-nested
vendored dirs — but a future contributor reading `skipped_dirs` and
seeing `[]` might reasonably assume *no* pruning occurred at all.

**Fix:** Two options, ordered by effort:

- **Cheap:** add a sentence to the `InventoryDict.skipped_dirs`
  docstring and `PluginInventory.skipped_dirs` field comment:
  *"Top-level only. Nested skips during walk descent are not recorded."*
- **Thorough:** track nested skip paths during walk and add a
  `nested_skipped_paths: list[str]` field. More complete but more
  surface area.

**Recommendation:** start with the cheap doc fix. Promote to the
thorough fix only if a real plugin hits the surprise case.

## Priority

All four are low-to-medium priority:

- #1 (security-rule test) is the most defensible from a "don't trust
  the test you wrote" perspective. Worth doing soonest.
- #2 (marketplace integration) is cheap insurance; bundle with #1.
- #3 (schema bump) is mechanical but needs the carve-out decision.
- #4 (nested-skip visibility) is the cheapest cosmetic fix; defer
  until a real surprise surfaces.

Reasonable bundling: #1 + #2 + #4-cheap as a single follow-up PR;
#3 as its own coordinated sweep.
