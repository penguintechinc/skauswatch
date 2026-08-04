---
name: feedback-no-sudo-for-docker-chown
description: never shell out to sudo to fix root-owned scratch/target dirs left by a docker build container — global rule forbids sudo entirely, even for throwaway scratchpad paths
metadata:
  type: feedback
---

The global rule set (`~/code/admin/.claude/rules/general.md` Red Flags) bans
running `sudo` outright — "ask user to run manually" — with no carve-out for
scratch/temp directories. When a Docker build container runs as root (e.g.
the plain `rust:1.97-slim-bookworm` image with no `--user` flag) and writes
into a bind-mounted `CARGO_HOME`/`CARGO_TARGET_DIR` under the scratchpad,
those files land root-owned on the host. The fix is **not** `sudo chown`
after the fact.

**Why this matters:** even though the scratchpad is disposable and low-risk,
`sudo` is a hard "never" in this org's rules with no risk-based exception —
using it "because it's just a temp dir" is exactly the kind of shortcut the
rule exists to prevent, and it sets a bad precedent for reaching for `sudo`
under time pressure elsewhere.

**How to apply:** when running a docker build/verify container that writes
into host-mounted cache/target dirs, either (a) pass `--user
$(id -u):$(id -g)` on `docker run` so files are never root-owned in the
first place, or (b) do the cleanup chown from *inside* the same container
(`docker exec <container> chown -R 1000:1000 /cargo-cache /target`) before
tearing it down — the container's root can chown its own bind-mounted
output without the host ever needing `sudo`. Only ask the user to run `sudo`
manually if both of those are impractical.
