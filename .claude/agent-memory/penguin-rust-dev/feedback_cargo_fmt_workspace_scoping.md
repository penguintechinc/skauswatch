---
name: feedback-cargo-fmt-workspace-scoping
description: cargo fmt --all reformats the whole workspace and can touch sibling services another concurrent agent owns — use cargo fmt -p <pkg> ... -- --check/--fix instead
metadata:
  type: feedback
---

`cargo fmt --all` operates workspace-wide regardless of which packages you
actually touched. In a shared skauswatch working tree with another agent
concurrently editing a sibling service (e.g. `services/depgate` while I
worked in `worker-codescan`/`codescan-backend`), running `cargo fmt --all`
reformats their in-progress files too — safe in the sense that fmt is
whitespace-only, but still an out-of-scope write to a directory I was told
not to touch, and it can race with their own saves.

**Fix:** use `cargo fmt -p <pkg1> -p <pkg2> ... -- --check` (and the same
`-p` flags without `-- --check` to auto-fix) to scope formatting to only
the packages relevant to the current task. Confirmed this correctly
excludes untouched packages' diffs from both the check and the fix.

**How to apply:** every multi-agent/worktree session touching a shared
Cargo workspace — default to package-scoped `cargo fmt -p`, never
`--all`, once other agents' directories are off-limits. See
[[project_skauswatch_tenancy_retrofit]] for the broader multi-agent
skauswatch convention this session followed.
