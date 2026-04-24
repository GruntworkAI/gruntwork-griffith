# sca-regression-plugin

Integration-test fixture for the `--sca` silent-false-negative regression
(see test_osv_adapter.py::TestScaRegression).

Structure:

- `.gitignore` excludes `cli/` — simulates the real-world case where a
  plugin's `.gitignore` causes `osv-scanner` to skip subdirectories
  during directory walk unless `--no-ignore` is passed.
- `cli/package-lock.json` pins `lodash@4.17.19`, a version with
  multiple published GHSA advisories (ReDoS, prototype pollution,
  command injection).

The regression test runs `run_osv_scanner` against this fixture and
asserts at least one expected GHSA ID surfaces. If any future change
drops `--no-ignore` from the invocation, the `.gitignore` causes the
subdir scan to be skipped, the test fails loudly instead of silently
reporting "0 vulnerabilities found."

`cli/` is added to the repo with `git add -f` because the fixture's own
`.gitignore` would otherwise prevent tracking.
