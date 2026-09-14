---
name: feedback-cross-service-stream-tenant-break
description: fixing a tenant-isolation IDOR on the producer side of a Redis Stream can break the consumer's parsing — expected, not a regression to "fix" out of scope
metadata:
  type: feedback
---

When retrofitting tenant isolation in a service that publishes onto a Redis
Stream another service consumes (e.g. codescan-backend -> `codescan:tasks`
-> worker-codescan), the correct fix on the producer side often changes a
field's *type*, not just its correctness — e.g. `tenant_id` goes from a
small integer (`repo_config.tenant_id.unwrap_or(0)`, itself
client-body-controlled pre-fix) to a stringified tenant UUID sourced from
the validated JWT. The consumer's existing parser (e.g. `_tenant_id: i64`
in `worker-codescan/src/message.rs`) will then fail to parse every future
message.

**Why this is fine, not a blocker:** per `docs/v2-port/tenancy-model.md`,
this org's tenancy retrofit is sequenced per-service (see
[[project-skauswatch-tenancy-retrofit]]) — the consumer service gets its own
R2 pass to update its parsing to the new tenant shape. v2 has never hit
prod, so a transitional breakage on this stream between two waves landing
concurrently is expected, not a regression. Fixing the consumer is out of
scope for the producer's task even if you can see the exact line that will
break.

**How to apply:** when scope says "touch only service X," do the
technically-correct fix on X's side (real tenant value, not a stale/
meaningless placeholder to preserve wire compatibility), leave a code
comment pointing at the consumer file/line that needs a follow-up, and
name the gap explicitly in your final report. Do not water down the fix to
avoid breaking an out-of-scope consumer — that would just leave the IDOR
half-fixed to preserve a contract that's already scheduled to change.
