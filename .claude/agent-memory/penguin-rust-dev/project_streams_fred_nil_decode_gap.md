---
name: project-streams-fred-nil-decode-gap
description: skauswatch-streams StreamConsumer::read_new errors (doesn't return Ok) on a genuinely-empty XREADGROUP reply because the workspace's fred dependency doesn't enable default-nil-types — found 2026-08-06 while adding real-Valkey tests, not fixed
metadata:
  type: project
---

`crates/skauswatch-streams/src/consumer.rs::StreamConsumer::read_new` calls
`fred`'s `xreadgroup_map`, which fails to parse a genuine "no new messages"
XREADGROUP reply (a bare RESP nil) into its response map type. Root cause:
`fred::types::args::Value::into_map` only maps `Value::Null` to an empty map
when the crate's `default-nil-types` feature is enabled
(`fred-10.1.0/src/types/args.rs:1073`); this workspace's `fred = "=10.1.0"`
(root `Cargo.toml`) does not enable it, so `HashMap::from_value` hits its
generic `_ => Err("Cannot convert to map.")` arm instead.

**Impact:** every idle poll cycle (no new messages after the block times
out) surfaces as a `StreamError::Transport` from `read_new`. In production
this routes through `StreamConsumer::run`'s `Err(e) => { warn!(...);
sleep(block_ms) }` arm, so a worker never crashes, but it logs a spurious
warning and sleeps an extra `block_ms` on every truly-idle cycle across
every stream consumer in the fleet (s3scan, scanner, worker-codescan).

**Why:** discovered while writing a real-Valkey unit test for the "no new
entries" branch of `read_new` (`consumer.rs::tests::
read_new_currently_errors_when_no_new_entries_are_pending`) — the test
originally expected `Ok(())` and failed against the real broker. Not fixed
as part of that work: flipping `default-nil-types` is a workspace-wide
`fred` behavior change (affects every crate depending on `fred`, not a
test-only tweak), out of scope for a coverage-focused pass and requiring its
own review/testing.

**How to apply:** if asked to reduce idle-consumer log noise/latency in any
stream-consuming service, or to add the `fred/default-nil-types` feature,
this is the root cause and the fix location. The test above documents
current (undesired) behavior with an explicit comment pointing here —
update both the test and this memory if the feature gets enabled and the
behavior changes to a clean `Ok(())`.
