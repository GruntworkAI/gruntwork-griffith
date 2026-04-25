# vendor-dirs-plugin

Test fixture for the default-skip-vendored-directories behavior in
`PluginInventory.from_path`.

- `hooks/real-hook.sh` — real plugin content; always walked.
- `node_modules/some-pkg/noisy.md` — npm vendored content; skipped by default.
- `vendor/gem/noisy.rb` — Ruby/Go vendored content; skipped by default.

With `skip_dirs=frozenset()` (the `--include-vendored` CLI flag), the
vendored files are also walked.

The other default-skip dir names (`.git`, `.venv`, `venv`, `__pycache__`)
are covered by parametrized tmp_path tests in `test_inventory.py`
because the repo's top-level `.gitignore` excludes them from tracking
here.
