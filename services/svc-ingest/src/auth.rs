//! mTLS SPIFFE + ingest-token + UDP-CIDR tenant resolution — stub until
//! Task 1.4 fills in `resolve_via_mtls`/`resolve_via_token`/
//! `resolve_via_udp_cidr` (see `docs/v2-port/ingest-module-spec.md` §6).

/// PostHog flag gating the entire service (Professional tier, default
/// OFF) — see `services/manager/src/flags.rs`'s module flag list. Same
/// constant name/value as `services/logs/src/ingest.rs::LOG_INGEST_FLAG`;
/// it is the same flag.
// dead_code: not yet referenced by a flag-gate check — Task 1.3 wires this
// into the HTTPS listener's `penguin_licensing::axum::flag_gate`.
#[allow(dead_code)]
pub const LOG_INGEST_FLAG: &str = "skauswatch.log-ingest";
