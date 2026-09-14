---
name: feedback-functions-metric-panic-closures
description: this codebase's own `.unwrap_or_else(|e| panic!("...: {e}"))` test idiom inflates the llvm-cov Functions denominator with closures that only run on the (never-hit) failure path — chasing workspace Functions % via more tests hits a structural ceiling, not a real-coverage gap
metadata:
  type: feedback
---

skauswatch's near-universal test idiom for "this call must succeed in a
passing test" is `.unwrap_or_else(|e| panic!("context: {e}"))` rather than
`.unwrap()`/`.expect()` (see `feedback_clippy_expect_used_per_module_allow`
for the related clippy-allow requirement). Each such call is a *closure*
under `cargo llvm-cov`'s function-coverage instrumentation, and a closure
that only executes on `Err` is permanently uncovered in a suite where that
call always succeeds. A file with dense, thorough tests written in this
idiom (e.g. `crates/skauswatch-vault/src/credential_cipher.rs`,
`services/manager/src/grpc/pki_client.rs`) can show a mediocre Functions %
purely from this, not from any real behavioral gap — confirmed via lcov
FN/FNDA inspection (2026-08-06): `credential_cipher.rs`'s 12 "missed
functions" out of 25 were almost entirely never-fired test-closures plus one
cross-crate-instantiation phantom duplicate (see below), despite the file
having 8 dedicated tests covering every real code path.

**Compounding effect on the workspace-wide metric:** adding *more* tests in
this same idiom to genuinely-uncovered production code (done 2026-08-06 for
`crates/skauswatch-ai/{openai,anthropic,ollama}.rs` and
`crates/skauswatch-streams/src/consumer.rs`) raised real executed-function
counts substantially (+110 across 5 files) but only nudged the workspace
Functions % by +0.11 points (87.06%→87.17%), because each new test also adds
~1-3 never-fired panic closures to the denominator — the new tests' own
closure overhead ate most of the numerator gain. Coverage baseline/analysis
script used: lcov FN/FNDA grouped by (file, canonicalized-symbol-minus-crate-hash)
to separate real gaps from (a) these closures, (b) untestable `from_env()`
bootstrap functions requiring live infra (documented convention already —
see `EnvelopeEncryption::from_env`'s own doc comment), and (c) a minor
(~130-count) phantom-duplicate effect from the same generic function being
monomorphized once per consuming service's test binary.

**How to apply:** don't treat a low workspace Functions % as proof of thin
testing, and don't chase a Functions-%-only target by writing more tests in
this codebase's idiom — it has a structural ceiling well under 100% that
more tests in the *same style* cannot close. If a hard Functions gate is
wanted, either (a) set the threshold well below what Lines-coverage
suggests (this workspace sits ~87% Functions vs ~94% Lines at 2026-08-06),
or (b) the org would need to change the test idiom itself (e.g. plain
`.expect("static message")` on infallible-by-construction calls, dropping
the interpolated error detail) — a team-wide convention change, not
something to do unilaterally inside a coverage task.
