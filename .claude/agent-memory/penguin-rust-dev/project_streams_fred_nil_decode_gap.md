---
name: project-streams-fred-nil-decode-gap
description: FIXED 2026-08-08 — skauswatch-streams StreamConsumer::read_new no longer errors on a genuinely-empty XREADGROUP reply; workspace fred dependency now enables default-nil-types
metadata:
  type: project
---

**Status: fixed.** Root cause and impact as originally diagnosed (below) —
`crates/skauswatch-streams/src/consumer.rs::StreamConsumer::read_new` was
erroring on a genuine "no new messages" XREADGROUP reply (bare RESP nil)
because `fred::types::args::Value::into_map` only maps `Value::Null` to an
empty map when the crate's `default-nil-types` feature is enabled, and the
workspace's `fred = "=10.1.0"` dependency didn't enable it.

**Fix:** root `Cargo.toml` now declares `fred = { version = "=10.1.0",
features = ["default-nil-types"] }`. No code change was needed in
`read_new` itself — the feature flip alone makes the nil XREADGROUP reply
decode to an empty `HashMap` (traced through
`into_xread_response` → `flatten_array_values` → `HashMap::from_value` →
`Value::into_map`), and `read_new`'s existing `let Some(entries) =
resp.get(&key) else { return Ok(()); }` already handled an empty map
correctly. The test (renamed
`read_new_returns_empty_when_no_new_entries_are_pending`, was
`read_new_currently_errors_when_no_new_entries_are_pending`) now asserts
`Ok(())` + no handler dispatch.

**Safety of the workspace-wide `fred` feature flip:** audited every fred
command call site across the workspace (all confined to
`crates/skauswatch-streams/src/{lib,consumer}.rs` — other services only use
the `StreamProducer`/`StreamConsumer` wrapper, never call `fred` directly).
`default-nil-types` only changes decode of `Value::Null` into *non-Option*
concrete types (map/set/bytes/bool/etc.) from an error into a sensible
default (empty/false/zero) — `Option<T>::from_value` already mapped `Null`
to `None` unconditionally, gated by nothing. So the change is purely
widening: no call site here decodes into a bare non-Option scalar where a
nil reply was both possible and previously relied upon to error (xadd/ping
return non-nil bulk strings, xack/xlen return integers, xautoclaim/xpending
return arrays). Confirmed via `fred-10.1.0/src/modules/response.rs` and
`types/args.rs`.

**How to apply:** if this surfaces again (e.g. a future `fred` major bump
resets the feature default), the fix location and root cause are here —
same feature flip, same safety argument re-applies as long as no new
fred call site is added elsewhere in the workspace outside
`skauswatch-streams`.
