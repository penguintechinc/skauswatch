---
name: feedback-clippy-expect-used-per-module-allow
description: this workspace's clippy config denies expect()/unwrap() inside cfg(test) modules unless that specific module carries its own #[allow(clippy::expect_used)] — it is not blanket-exempted for test code
metadata:
  type: feedback
---

skauswatch's workspace lint config (`-D warnings` with clippy defaults) does
**not** give `#[cfg(test)] mod tests` blocks a free pass on
`clippy::expect_used`/`clippy::unwrap_used`/`clippy::panic`. Each test module
that wants to use `.expect()`/`.unwrap()`/`panic!()` needs its own explicit
`#[allow(...)]` immediately above `mod tests { ... }` — e.g.
`#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design`,
the exact phrasing already used in `services/s3scan/src/db.rs` and
`handler.rs`.

**Why this matters:** some test modules in a file only carry `#[allow(clippy::panic)]`
(no `expect_used`) because their original tests only used `assert!`/`assert_eq!`
and never called `.expect()`. Adding a new helper to that *same* module that
calls `.expect()` (e.g. `"11111111-...".parse().expect("valid uuid literal")`
for a fixed test-tenant UUID constant) fails `cargo clippy --all-targets -- -D
warnings` even though nearly identical code compiles fine in a sibling module
of the same file. `services/s3scan/src/message.rs` and `enumerate.rs` hit this
exact case (2026-07-31): their test modules had `#[allow(clippy::panic)]` only,
and adding an `.expect()`-based UUID-literal helper failed clippy until
`clippy::expect_used` was added to that module's own allow list.

**How to apply:** before adding `.expect()`/`.unwrap()` to any existing test
module in this codebase, check its `#[allow(...)]` attribute first — don't
assume test code is exempt. If missing, add `clippy::expect_used` (and
`clippy::panic` if `panic!`/`assert!` failure messages are involved) to that
module's attribute, matching the `db.rs`/`handler.rs` convention, rather than
restructuring the helper to avoid `.expect()`.
