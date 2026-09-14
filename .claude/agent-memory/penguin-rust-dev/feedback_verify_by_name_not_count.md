---
name: feedback_verify_by_name_not_count
description: when comparing a new test-run's failures against a known-benign baseline (e.g. "these are all Postgres-timeout failures"), diff the failing test NAMES, not just the pass/fail counts
metadata:
  type: feedback
---

When re-running a test suite after a code change and comparing against a
prior "known failures are infra, not bugs" baseline (e.g. local `cargo test`
with no Postgres available — see `[[skauswatch-verify-env]]`), don't just
check that the failure count moved by the expected delta. Grep the actual
list of failing test names/paths each time and diff it against the prior
run's list.

**Why:** during DepGate P4, a real bug (`go_path::parse`'s `/@v/list`
handling, off-by-one on a separator that already consumed a slash) was
sitting inside a local test-suite failure count that "matched expectations"
(74→77 failures, exactly the +3 new DB-dependent tests added that session) —
the new failure was masked by assuming the delta was homogeneous. It was
only caught because a *separate*, mandatory Docker+real-Postgres run was
required anyway for the final gate; if that gate hadn't existed, the count-
only check would have shipped a broken route.

**How to apply:** any time "N failures, all expected to be the same known
cause" is the justification for treating a run as green, actually list the
failing test names (`grep 'FAILED$'` or equivalent) and confirm each one —
not just the total — matches the known-benign pattern (e.g. same panic
message/location). This is a specific instance of the general Verification
Integrity rule ("report the denominator, not just the verdict") — counts are
not names.
