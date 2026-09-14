---
name: project-depgate-p4
description: DepGate P4 (Socket.dev, cosign provenance, asymmetric bundle signing, crates.io+Go proxy) — key design decisions and a real bug found
metadata:
  type: project
---

DepGate's final phase (issue #101, `docs/v2-port/v2.1-depgate.md` §5/§9/§10)
landed 2026-08-23 on `release/v2.0.x`, unstaged for the orchestrator to
review. `services/depgate/src/{socket,provenance,crates_io,go_path,go_proxy}.rs`
+ `routes/{crates_io,go}.rs` are new; `bundle.rs`/`policy.rs`/`db.rs`/
`scanpipe.rs`/`state.rs` extended.

**Key decisions:**
- Socket.dev and cosign provenance both feed the EXISTING `crate::policy`
  engine as ordinary `RiskFinding`s / a `provenance` match dimension — no
  parallel decision path. `ScanPipeline` gained two new mandatory fields
  (`socket: &SocketClient`, `cosign_public_key: Option<&str>`), which meant
  touching all ~17 existing test-literal construction sites across
  `scanpipe.rs`/`seed.rs` — expected churn for this struct, not a mistake.
- No new crypto crate needed for either cosign RSA-signature verification
  or bundle asymmetric signing — reused `rsa`+`sha2` primitives already
  proven in `services/worker-vault-sync/src/providers/oracle.rs` (OCI
  request signing). Full cosign (ECDSA default keygen, Sigstore
  keyless/Fulcio/Rekor) explicitly deferred — RSA-keyed cosign only.
- RSA test keypairs are generated at runtime (`src/test_support.rs`,
  `RsaPrivateKey::new(&mut OsRng, 2048)`), never committed as static PEM —
  gitleaks' `private-key` rule flags a literal `-----BEGIN ... PRIVATE
  KEY-----` in source even for an inert test fixture. Same pattern already
  existed in `worker-vault-sync/src/providers/mod.rs::generate_rsa_private_key_pem`.
- Bundle format bumped to `BUNDLE_VERSION = 2` (added `signature_algorithm`
  field, `#[serde(default)]`) but kept `MIN_SUPPORTED_BUNDLE_VERSION = 1` so
  P3-exported HMAC-signed bundles still import/verify unchanged.
- crates.io needs no path-parsing module (crate names never contain `/`);
  Go module proxy does (`go_path.rs`) since module paths do.

**Real bug caught only by the Docker+real-Postgres gate** (local
`cargo test` without Postgres masks nothing about this — it was a pure-logic
bug): `go_path::parse`'s `/@v/list` branch used `tail.strip_suffix("/list")`
after already splitting on the `/@v/` separator (which consumes the
slash before "list"), so `tail` was bare `"list"` and the suffix check
could never match — every `GET /go/{module}/@v/list` request 404'd. Fixed
to `tail == "list"` (exact match, not a suffix strip).

This was actually visible in a local offline `cargo test` run BEFORE the
Docker pass (failure count went from 74→77 across two local runs, matching
the expected +3 new DB-dependent tests — but `go_path::tests::parses_list_request`
was hiding inside that same delta and got missed because I diffed pass/fail
*counts*, not the actual failing-test *names*, against the "these are all
Postgres timeouts" assumption from an earlier run). See
`[[feedback_verify_by_name_not_count]]` — don't repeat that shortcut.

**Verify env note reconfirmed:** local `cargo test` (no Postgres) reports
~74-80 DB-connection-timeout failures unrelated to code correctness — the
Docker+`sw-d4-pg`/`sw-d4-vk` run is the only trustworthy signal, matching
`[[skauswatch-verify-env]]`.
