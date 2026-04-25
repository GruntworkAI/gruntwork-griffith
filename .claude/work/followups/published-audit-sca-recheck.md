# Follow-up: Published-audit SCA recheck protocol

**Why this exists (2026-04-25):**

PR #3 (2026-04-22) fixed a silent false-negative in Griffith's `--sca`
invocation. Any audit with SCA results published *before* PR #3 was
produced under the buggy code and theoretically might claim "0 CVEs"
when CVEs were silently skipped. The bug only manifested when:

1. The audited plugin had lockfiles in subdirectories, AND
2. Those subdirectories were `.gitignore`-excluded

Failing both conditions → bug had no effect → audit was correct.

## Current state

Only one published audit at the time of writing:

| Audit | Date | Bug-affected? | Action |
|---|---|---|---|
| `docs/audits/2026-04-20-superpowers.md` | 2026-04-20 (pre-fix) | **No** — superpowers' .gitignore doesn't exclude its lockfile-bearing `tests/` subdir; verified `--no-ignore` produces identical output | Addendum appended to the audit file confirming verification (2026-04-25). |

## Protocol for future pre-fix audits

If audits with SCA results from before 2026-04-22 are discovered later
(e.g. blog posts, internal reports), recheck each one:

1. Clone the audited plugin at the same commit (or closest tag if commit
   unknown).
2. Run `osv-scanner scan source -r --format json --experimental-exclude
   g:.git --experimental-exclude g:node_modules --experimental-exclude
   g:.venv --experimental-exclude g:venv --experimental-exclude g:vendor
   -- .` (no `--no-ignore` — recreates the buggy invocation).
3. Run the same command WITH `--no-ignore` — recreates the fixed
   invocation.
4. Compare the two outputs. If identical → audit was unaffected, append
   a verification addendum. If different → the audit was silently wrong,
   re-publish with corrected SCA section and a clear "corrected on
   <date>" note.

## Non-action

For audits published *after* 2026-04-22, no recheck needed; they used
the fixed invocation by construction.

## Priority

Reactive — only run this protocol if a pre-fix audit surfaces. No
known additional pre-fix audits exist.
