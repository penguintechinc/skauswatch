//! Applies manager's admin-adjustable SVID TTL policy
//! (`routes::admin::update_svid_ttl`) to the live SPIRE deployment via the
//! SPIRE Server **Entry** API (`spire.api.server.entry.v1.Entry` —
//! `ListEntries`/`BatchUpdateEntry`, see `crates/skauswatch-spire-entry`),
//! replacing the earlier persist+log-only seam.
//!
//! Manager reaches the SPIRE server over mTLS on the same network listener
//! used for node/agent traffic (`spire.server.ports.grpc`, default `8081`
//! — see `k8s/helm/spire/README.md#admin-adjustable-svid-ttl`), presenting
//! its own X.509-SVID: manager's registration entry is the sole one in
//! that chart with `admin: true`, which is what SPIRE's Entry API accepts
//! in place of "local" access for a remote caller. The client TLS config
//! itself is built by `skauswatch-identity` (never tonic's own TLS
//! feature), mirroring [`crate::grpc::pki_client`]'s identical pattern for
//! manager's (not-yet-live) pki caller.
//!
//! Fail-safe throughout: every function here returns an [`ApplyStatus`]
//! rather than propagating a hard error — `routes::admin::apply_svid_ttl_to_spire`
//! never blocks or fails the request that already persisted the setting to
//! the database, matching the fail-safe policy in
//! `docs/v2-port/service-auth-model.md` and every other identity-adjacent
//! fallback in this service.

use std::time::Duration;

use skauswatch_identity::{
    IdentityError, IdentityProvider, SpiffeId, SpiffeIdError, SpiffeIdMatcher,
};
use skauswatch_spire_entry::{ApplyOutcome, SpireEntryClient};

/// Whole-operation timeout (connect + both RPC round-trips, worst case
/// across every `ListEntries` page) — bounds `update_svid_ttl`'s response
/// time even if the SPIRE server is reachable but slow/hung, matching this
/// workspace's "timeout every external call" convention
/// (`backend-rust.md`).
const APPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// TCP+TLS+HTTP2 connect timeout — a smaller bound than [`APPLY_TIMEOUT`]
/// so an unreachable server fails fast, leaving headroom for the RPCs
/// themselves once connected.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default SPIRE server admin/node gRPC address — matches the Helm chart's
/// `spire.server.ports.grpc` default (`k8s/helm/spire/README.md`). Override
/// via `SPIRE_SERVER_ADDRESS` for any non-default Service name/namespace.
const DEFAULT_SPIRE_SERVER_ADDRESS: &str = "spire-server:8081";
/// Default SPIRE server's own SPIFFE ID, presented on its TLS leaf
/// certificate for this listener — SPIRE's own `idutil.ServerID`
/// convention (`spiffe://<trust domain>/spire/server`). Override via
/// `SPIRE_SERVER_SPIFFE_ID` if a deployment's child-server topology
/// presents a different (e.g. per-child-suffixed) identity here — see the
/// caveat in [`spire_server_matcher`].
const DEFAULT_SPIRE_SERVER_SPIFFE_ID: &str = "spiffe://penguintech.io/spire/server";

/// Outcome of attempting to apply the SVID TTL policy to the live SPIRE
/// deployment — always fail-safe, never an `Err` a caller has to propagate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplyStatus {
    /// Applied to every entry `ListEntries` returned.
    Applied {
        /// Entries successfully updated.
        updated: u32,
        /// Entries the server reported a failure for (still persisted in
        /// skauswatch's own DB regardless — see module docs).
        failed: u32,
    },
    /// Persisted to the database, but not yet applied to SPIRE — the
    /// caller should log this clearly and move on; never fail the request.
    PersistedNotApplied {
        /// Human-readable reason (no identity held, connect failure, RPC
        /// failure, ...).
        reason: String,
    },
}

fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_owned(),
    }
}

/// `SPIRE_SERVER_ADDRESS` (`"host:port"`), default [`DEFAULT_SPIRE_SERVER_ADDRESS`].
fn spire_server_address() -> String {
    env_or("SPIRE_SERVER_ADDRESS", DEFAULT_SPIRE_SERVER_ADDRESS)
}

/// The one identity manager's SPIRE Entry API client trusts: the SPIRE
/// server's own SPIFFE ID (`SPIRE_SERVER_SPIFFE_ID`, default
/// [`DEFAULT_SPIRE_SERVER_SPIFFE_ID`]).
///
/// **Deployment caveat**: `k8s/helm/spire/values.yaml`'s multi-level
/// root/child topology registers each *child* server on its upstream under
/// a per-child-suffixed downstream ID (e.g.
/// `spiffe://penguintech.io/spire/server/dal2-beta`) — that suffix is the
/// identity the ROOT uses to refer to the child as a downstream peer, not
/// necessarily what the child presents to clients on its own local admin
/// listener. If a given deployment's child server does present a
/// suffixed ID here, override `SPIRE_SERVER_SPIFFE_ID` accordingly; the
/// unsuffixed default matches SPIRE's own un-topology-aware
/// `idutil.ServerID` convention.
fn spire_server_matcher() -> Result<SpiffeIdMatcher, SpiffeIdError> {
    let id = SpiffeId::new(env_or(
        "SPIRE_SERVER_SPIFFE_ID",
        DEFAULT_SPIRE_SERVER_SPIFFE_ID,
    ))?;
    Ok(SpiffeIdMatcher::new().allow_exact(id))
}

/// Applies `x509_ttl_seconds`/`jwt_ttl_seconds` to every SPIRE registration
/// entry via the Entry API, using `identity`'s own X.509-SVID for mTLS.
/// Never returns an `Err` — every failure mode collapses into
/// [`ApplyStatus::PersistedNotApplied`] with a human-readable reason.
pub(crate) async fn apply_svid_ttl(
    identity: &IdentityProvider,
    x509_ttl_seconds: i64,
    jwt_ttl_seconds: i64,
) -> ApplyStatus {
    let x509_ttl_seconds = match i32::try_from(x509_ttl_seconds) {
        Ok(v) => v,
        Err(_) => {
            return ApplyStatus::PersistedNotApplied {
                reason: format!("x509_ttl_seconds {x509_ttl_seconds} out of i32 range"),
            };
        }
    };
    let jwt_ttl_seconds = match i32::try_from(jwt_ttl_seconds) {
        Ok(v) => v,
        Err(_) => {
            return ApplyStatus::PersistedNotApplied {
                reason: format!("jwt_ttl_seconds {jwt_ttl_seconds} out of i32 range"),
            };
        }
    };

    let matcher = match spire_server_matcher() {
        Ok(m) => m,
        Err(e) => {
            return ApplyStatus::PersistedNotApplied {
                reason: format!("SPIRE server SPIFFE ID for Entry API mTLS: {e}"),
            };
        }
    };
    let tls_config = match identity.client_tls_config(&matcher) {
        Ok(cfg) => cfg,
        Err(IdentityError::Degraded) => {
            return ApplyStatus::PersistedNotApplied {
                reason: "no attested SPIFFE identity held (SPIRE agent unreachable/unattested)"
                    .to_owned(),
            };
        }
        Err(e) => {
            return ApplyStatus::PersistedNotApplied {
                reason: format!("SPIRE Entry API mTLS client config: {e}"),
            };
        }
    };

    let address = spire_server_address();
    let apply = async {
        let mut client =
            SpireEntryClient::connect_mtls(&address, tls_config, CONNECT_TIMEOUT).await?;
        client
            .apply_svid_ttl(x509_ttl_seconds, jwt_ttl_seconds)
            .await
    };

    match tokio::time::timeout(APPLY_TIMEOUT, apply).await {
        Ok(Ok(ApplyOutcome { updated, failed })) => ApplyStatus::Applied { updated, failed },
        Ok(Err(e)) => ApplyStatus::PersistedNotApplied {
            reason: format!("SPIRE Server Entry API at {address}: {e}"),
        },
        Err(_) => ApplyStatus::PersistedNotApplied {
            reason: format!(
                "SPIRE Server Entry API at {address} did not respond within {APPLY_TIMEOUT:?}"
            ),
        },
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn spire_server_address_defaults_to_the_helm_service_name() {
        assert!(std::env::var("SPIRE_SERVER_ADDRESS").is_err());
        assert_eq!(spire_server_address(), DEFAULT_SPIRE_SERVER_ADDRESS);
    }

    #[test]
    fn spire_server_matcher_accepts_only_the_configured_server_identity() {
        assert!(std::env::var("SPIRE_SERVER_SPIFFE_ID").is_err());
        let matcher = spire_server_matcher().unwrap_or_else(|e| panic!("matcher: {e}"));
        let id = |s: &str| SpiffeId::new(s).unwrap_or_else(|e| panic!("spiffe id {s}: {e}"));

        assert!(matcher.matches(&id("spiffe://penguintech.io/spire/server")));
        assert!(!matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        assert!(!matcher.matches(&id("spiffe://penguintech.io/spire/server/dal2-beta")));
        assert!(!matcher.matches(&id("spiffe://customer.example/spire/server")));
    }

    #[tokio::test]
    async fn apply_svid_ttl_degrades_cleanly_when_identity_is_unattested() {
        let identity = IdentityProvider::degraded_for_test();
        let status = apply_svid_ttl(&identity, 300, 300).await;
        assert!(matches!(status, ApplyStatus::PersistedNotApplied { .. }));
    }

    #[tokio::test]
    async fn apply_svid_ttl_out_of_range_ttl_never_panics() {
        let identity = IdentityProvider::degraded_for_test();
        let status = apply_svid_ttl(&identity, i64::MAX, 300).await;
        assert!(matches!(status, ApplyStatus::PersistedNotApplied { .. }));
    }
}
