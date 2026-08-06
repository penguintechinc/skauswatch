---
name: env-rust-docker-quirks
description: Docker/rustup environment gotchas when running isolated Rust workspace verification for skauswatch — CARGO_HOME redirection, toolchain install races, cargo-deny git ownership
metadata:
  type: project
---

Three infra-only (non-code) failures hit when running `rust:1.97-slim-bookworm` in an isolated Docker container with `CARGO_HOME` redirected to a scratchpad path (per test-runner env convention: `CARGO_HOME=<scratchpad>/cargo-cache`).

**1. Redirecting `CARGO_HOME` breaks rustup's proxy shims.** The official rust image installs rustup's `cargo`/`rustc`/`clippy-driver`/etc. shims at `/usr/local/cargo/bin` (all symlinks to the `rustup` binary, which uses argv0 + its own location to resolve the active toolchain). Pointing `CARGO_HOME` at a fresh scratchpad dir means `$CARGO_HOME/bin` doesn't contain those shims, and invoking `cargo` (still resolved via PATH's `/usr/local/cargo/bin`) then fails with `error: rustup is not installed at '<new CARGO_HOME>'`.
**Fix:** `cp -a /usr/local/cargo/bin/. $CARGO_HOME/bin/` once, then prepend `$CARGO_HOME/bin` to PATH for all subsequent `docker exec` calls (`-e PATH=$CARGO_HOME/bin:...`). `cargo install` targets (`cargo-llvm-cov`, `cargo-deny`) land correctly in `$CARGO_HOME/bin` once this is done.

**2. Concurrent `docker exec` cargo invocations race on first-time rustup toolchain install.** If the pinned toolchain (from `rust-toolchain.toml`) isn't installed yet and two cargo commands are launched in parallel (e.g. `cargo install cargo-llvm-cov` + `cargo check --workspace` at the same time), both trigger `rustup` to download/install the same toolchain concurrently, corrupting the partial install (`error: the 'cargo' binary ... is not applicable`, `could not rename 'downloaded' file ... No such file or directory`).
**Fix:** `rustup toolchain uninstall <ver>` then `rustup toolchain install <ver> --profile minimal --component clippy --component rustfmt` **serially, alone**, before running anything else. Only after that succeeds is it safe to run other cargo commands (sequential or parallel) — see [[skauswatch-verify-env]].

**3. `cargo deny check` fails with git "dubious ownership" when the advisory-db cache lives under a bind-mounted `CARGO_HOME` and the container runs as root.** `cargo-deny` clones `RustSec/advisory-db` into `$CARGO_HOME/advisory-dbs/...`; git (≥2.35) refuses to `reset --hard`/`fetch` in a repo owned by a different UID than the current process — and a host-mounted scratchpad dir (owned by the host user, e.g. UID 1000) accessed by container-root (UID 0) trips this every time.
**Fix:** `git config --global --add safe.directory '*'` inside the container before running `cargo deny check`.

**Also:** piping a long-running cargo command through `| tail -N` or `| tee` in a backgrounded `docker exec` hides ALL output until the underlying process exits (tail buffers until EOF) — read progress via a `tee`'d file path directly inside the container instead of relying on the backgrounded task's stdout tail.
