# Follow-up: SCA regression test refinements (deferred from PR #4)

**Observed during PR #4 self-review (2026-04-24):**

PR #4 added an end-to-end regression test (`TestScaRegression`) against
the `--no-ignore` silent false-negative bug fixed in PR #3. The review
surfaced three minor improvements that were deferred to keep the
initial PR focused. All three are nice-to-haves, not correctness
concerns.

## 1. Fixture README — warn about future callers

**What:** The fixture at `tests/fixtures/sca-regression-plugin/`
contains a `.gitignore` that excludes `cli/`. `osv-scanner` honors it
during directory walk; other tree-walkers may too.

**Risk:** If a future test points `PluginInventory.from_path` (or any
other walker) at this fixture expecting to discover the full tree, the
gitignore could cause surprising skips — the same class of silent
false-negative this fixture was built to catch.

**Fix:** Add a line to `tests/fixtures/sca-regression-plugin/README.md`:

> This fixture is intentionally scoped to `run_osv_scanner` tests.
> Other callers (e.g. `PluginInventory.from_path`) may see unexpected
> results from the embedded `.gitignore`.

**Effort:** 1-line edit.

## 2. Higher-level regression at `DependencyAnalyzer.analyze(sca=True)`

**What:** `TestScaRegression` calls `run_osv_scanner` directly, not the
public `DependencyAnalyzer().analyze(sca=True)` entrypoint.

**Risk:** If a future change breaks the wire-up between
`analyze(sca=True)` and `run_osv_scanner` — e.g., a refactor
accidentally drops the osv call path, or the result isn't attached to
`DependencyReport.sca` — the current test still passes because it
bypasses that layer.

**Fix:** Add a second regression test that:

1. Calls `DependencyAnalyzer().analyze(fixture, sca=True)` (with
   real osv-scanner, `@pytest.mark.network`, skip if binary missing).
2. Asserts `report.sca.vulnerability_count > 0` and at least one of
   the expected GHSA IDs appears in `report.sca.vulnerabilities`.

**Effort:** ~20-line test addition; reuses the existing fixture.

## 3. Naming — `sca-regression-plugin` vs `deps-sca-regression-plugin`

**What:** Existing dependency-related fixtures follow a `deps-<flavor>-plugin`
naming pattern:

- `deps-node-plugin`
- `deps-poetry-plugin`
- `deps-python-plugin`
- `deps-multi-ecosystem-plugin`

The new fixture is named `sca-regression-plugin`, breaking the pattern.

**Judgment call:** The current name is clearer about *intent* (it's a
regression test fixture, not a general deps fixture). The convention
name would be more discoverable if someone greps for `deps-*` fixtures.
Either choice is defensible.

**If we rename:** trivial rename + update path in `test_osv_adapter.py`.

## Priority

All three are low priority. #1 is the cheapest (1 line) and most
valuable as a foot-gun prevention for future contributors. #2 closes a
real but narrow coverage gap. #3 is pure bike-shedding unless someone
hits the naming pattern question.

Bundle all three into a single small follow-up PR when touching this
area again.
