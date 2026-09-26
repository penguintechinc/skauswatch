---
name: feedback-docker-build-env-gotchas
description: two non-obvious gotchas running cargo builds in rust:*-slim-bookworm containers for skauswatch — login-shell PATH reset and cargo llvm-cov flag ordering
metadata:
  type: feedback
---

Two things that cost debugging time running containerized Rust
builds/tests for skauswatch services (per `docs/v2-port/testing-pattern.md`
/ per-service verify instructions):

1. **`bash -lc '...'` (login shell) resets `PATH`, dropping
   `/usr/local/cargo/bin`** — the official `rust:*-bookworm` image sets
   `cargo`/`rustc` on `PATH` via Docker `ENV`, but Debian's `/etc/profile`
   (sourced by a login shell) unconditionally overwrites `PATH` to the
   system default, silently losing it. Symptom: `cargo: command not found`
   even though `which cargo` works fine without `-l`. **Fix: use
   `bash -c '...'`, never `bash -lc '...'`,** for one-shot container
   commands that need the image's own toolchain on `PATH`.

2. **`rustup component add llvm-tools-preview -q` fails** — `-q` isn't a
   valid flag for `rustup component add` in this rustup version (only for
   some subcommands). Drop it; the component-add step doesn't need
   quieting since its output is short.

**How to apply:** both apply to every skauswatch Rust service's
Docker-based build/test/coverage runs, not just codescan-backend — reuse
this exact invocation shape (`docker run ... bash -c "..."`, no `-l`) for
future per-service verification passes.
