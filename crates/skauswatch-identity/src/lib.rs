//! SPIFFE Workload API integration shared by every skauswatch service that
//! needs SVID-based mTLS or AWS federation
//! (`sts:AssumeRoleWithWebIdentity` via JWT-SVID).
//!
//! [`IdentityProvider`] is the entry point: it attests to the local SPIFFE
//! Workload API (typically a SPIRE agent Unix domain socket named by
//! `SPIFFE_ENDPOINT_SOCKET`), holds the resulting X.509-SVID and trust
//! bundle set, and builds mTLS `rustls` configs from them via
//! [`IdentityProvider::server_tls_config`] / [`IdentityProvider::client_tls_config`].
//! [`SpiffeIdMatcher`] is the caller-supplied allowlist those configs
//! enforce against the peer's SPIFFE ID — see its docs for how federated
//! trust domains are admitted.
//!
//! # Fail-safe policy
//!
//! Mirrors `skauswatch_auth::load_jwt_verify_key`'s house fail-fast pattern: a
//! service that requires an identity and can't get one must not silently
//! run without one. Whether the Workload API is unreachable at startup or
//! a later [`IdentityProvider::refresh`] fails, the same rule applies —
//! production (`RELEASE_MODE` != `"false"`, per
//! `skauswatch_auth::is_production`) hard-fails with
//! [`IdentityError::WorkloadApiUnavailable`]; anywhere else, a WARN is
//! logged and the provider proceeds with no identity
//! ([`IdentityError::Degraded`] from every method that needs one).
//! [`IdentityProvider::connect`]/[`IdentityProvider`] never panics — every
//! fallible path returns `Result`.
//!
//! **Deliberately no deployment-domain bypass of this hard-fail.** Unlike
//! `penguin_licensing::config::LicenseConfig`'s bypass-domain mechanism,
//! this crate has no `bypass_domains`/`connect_with_domain` parameter at
//! all: per this house's `general.md` (Feature Toggling & License
//! Enforcement), a domain-based bypass is for license/feature-flag gating
//! only and must never exempt authentication or identity. `RELEASE_MODE=
//! false` is the *only* supported way to run this crate outside production
//! posture — no product `.app` domain, `penguintech.cloud`, or any other
//! deployment domain can weaken it. (An earlier revision carried exactly
//! such a parameter, mirrored from the license client's bypass-domain
//! convention; it was removed because a service's own production domain —
//! e.g. `skauswatch.app`, which really is this product's production
//! domain — is precisely the domain that must never be able to disable its
//! own identity requirement.)
//!
//! # Testing without a live SPIRE agent
//!
//! [`IdentityProvider::from_svid_for_test`] and
//! [`IdentityProvider::degraded_for_test`] (behind `#[cfg(test)]` or the
//! `testutil` feature) construct a provider directly from injected
//! SVID/bundle material or with no identity at all, bypassing the Workload
//! API entirely. They exist so downstream services can integration-test
//! real mTLS accept/reject against
//! [`IdentityProvider::server_tls_config`]/[`IdentityProvider::client_tls_config`]
//! without a live SPIRE agent — see [`testutil`] for the fixture helpers
//! (`TestCa` etc.) that build the SVID/bundle material itself. Neither
//! constructor is reachable from a normal production build.
//!
//! # TLS configs are snapshots
//!
//! [`IdentityProvider::server_tls_config`] and
//! [`IdentityProvider::client_tls_config`] build a `rustls` config from
//! whatever X.509-SVID is currently held; they do not track expiry or
//! rotate the config in place. SPIFFE X.509-SVIDs are typically short-lived
//! (SPIRE's default is about one hour), so a long-running service must
//! call [`IdentityProvider::refresh`] and rebuild its TLS config
//! periodically — this crate does not do that on the caller's behalf.

mod matcher;
mod source;
#[cfg(any(test, feature = "testutil"))]
pub mod testutil;
mod tls;

use std::sync::Arc;

use arc_swap::ArcSwapOption;
pub use matcher::SpiffeIdMatcher;
pub use spiffe::{JwtSvid, SpiffeId, SpiffeIdError, TrustDomain};
use spiffe::{X509BundleSet, X509Svid};

use source::{RealWorkloadApiSource, WorkloadApiSource, WorkloadApiSourceError};

/// A required workload identity was unavailable in production. Startup (or
/// a later refresh) must not proceed as if the workload were validly
/// attested — see the crate-level fail-safe policy docs.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The SPIFFE Workload API was unreachable (or returned no usable
    /// X.509-SVID) while running in production posture.
    #[error(
        "SPIFFE Workload API unreachable and a workload identity is mandatory in production: {0}"
    )]
    WorkloadApiUnavailable(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// No workload identity is currently held — either the initial
    /// attestation degraded outside production, or a later
    /// [`IdentityProvider::refresh`] has not yet succeeded once. Callers
    /// must not build mTLS configs or fetch JWT-SVIDs while degraded.
    #[error("no workload identity available — running without SPIFFE attestation (dev mode)")]
    Degraded,

    /// Fetching a JWT-SVID from the SPIFFE Workload API failed.
    #[error("failed to fetch JWT-SVID: {0}")]
    Jwt(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The SPIFFE Workload API returned an X.509 context with no SVID for
    /// this workload (selectors did not match any registration entry).
    #[error("SPIFFE Workload API returned no X.509-SVID for this workload")]
    NoDefaultSvid,

    /// The held `X509BundleSet` has no trust authorities in it at all — a
    /// mTLS config built from it could not validate any peer, so building
    /// one is refused rather than silently trusting nothing.
    #[error(
        "X.509 bundle set has no trust authorities; refusing to build a mTLS config that would trust nothing"
    )]
    EmptyTrustBundle,

    /// Building a rustls TLS config from the held SVID/bundle material
    /// failed.
    #[error(transparent)]
    Tls(#[from] rustls::Error),

    /// Building the peer certificate verifier failed.
    #[error(transparent)]
    VerifierBuild(#[from] rustls::server::VerifierBuilderError),
}

/// One attestation's worth of material: the workload's current X.509-SVID
/// and the trust bundle set it was issued alongside (which may span more
/// than one trust domain — see [`SpiffeIdMatcher`]).
#[derive(Debug, Clone)]
struct IdentityState {
    svid: Arc<X509Svid>,
    bundles: Arc<X509BundleSet>,
}

/// Attestation failures internal to this crate — a strict superset of
/// [`WorkloadApiSourceError`] that also covers "the Workload API answered
/// but issued nothing". Never exposed directly; callers only ever see the
/// mapped [`IdentityError`].
#[derive(Debug, thiserror::Error)]
enum AttestError {
    /// The underlying Workload API call failed.
    #[error(transparent)]
    Source(#[from] WorkloadApiSourceError),
    /// The Workload API answered with an empty SVID list.
    #[error("SPIFFE Workload API returned no X.509-SVID for this workload")]
    NoDefaultSvid,
}

impl From<AttestError> for IdentityError {
    fn from(e: AttestError) -> Self {
        match e {
            AttestError::NoDefaultSvid => Self::NoDefaultSvid,
            AttestError::Source(e) => Self::WorkloadApiUnavailable(Box::new(e)),
        }
    }
}

/// Fetches the current X.509 context from `source` and extracts the
/// workload's default SVID and bundle set. The one piece of "business
/// logic" in the attestation path that isn't already covered by
/// `WorkloadApiSource`'s own error handling.
async fn attest(source: &dyn WorkloadApiSource) -> Result<IdentityState, AttestError> {
    let ctx = source.fetch_x509_context().await?;
    let svid = ctx
        .default_svid()
        .cloned()
        .ok_or(AttestError::NoDefaultSvid)?;
    Ok(IdentityState {
        svid,
        bundles: Arc::clone(ctx.bundle_set()),
    })
}

/// SPIFFE Workload API client for one workload: holds the current
/// X.509-SVID and trust bundle set, and builds mTLS `rustls` configs and
/// JWT-SVIDs from them. See the crate-level docs for the fail-safe policy
/// and the "TLS configs are snapshots" caveat.
pub struct IdentityProvider {
    source: Option<Arc<dyn WorkloadApiSource>>,
    state: ArcSwapOption<IdentityState>,
    production: bool,
}

impl std::fmt::Debug for IdentityProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityProvider")
            .field("has_source", &self.source.is_some())
            .field("has_identity", &self.state.load().is_some())
            .field("production", &self.production)
            .finish()
    }
}

impl IdentityProvider {
    /// Connects to the SPIFFE Workload API named by
    /// `SPIFFE_ENDPOINT_SOCKET`, applying the house fail-safe policy: in
    /// production posture (`RELEASE_MODE` != `"false"`, per
    /// `skauswatch_auth::is_production` — see the crate-level fail-safe
    /// policy docs), an unreachable Workload API or an attestation with no
    /// SVID is a hard error; otherwise a WARN is logged and the provider
    /// starts with no held identity. There is no deployment-domain
    /// parameter and no way to weaken this from a caller — see the
    /// crate-level docs for why.
    pub async fn connect() -> Result<Self, IdentityError> {
        let production = skauswatch_auth::is_production();
        let connect_result = RealWorkloadApiSource::connect_env()
            .await
            .map(|source| Arc::new(source) as Arc<dyn WorkloadApiSource>);
        Self::bootstrap(connect_result, production).await
    }

    /// Core fail-safe bootstrap, factored out from [`IdentityProvider::connect`]
    /// so it can be exercised in tests with a fake [`WorkloadApiSource`]
    /// instead of a live SPIRE agent.
    async fn bootstrap(
        connect_result: Result<Arc<dyn WorkloadApiSource>, WorkloadApiSourceError>,
        production: bool,
    ) -> Result<Self, IdentityError> {
        match connect_result {
            Ok(source) => {
                let attested = attest(source.as_ref()).await;
                Self::finish_bootstrap(Some(source), attested, production)
            }
            Err(e) => Self::finish_bootstrap(None, Err(AttestError::Source(e)), production),
        }
    }

    /// Applies the fail-safe decision to one attestation attempt's outcome.
    fn finish_bootstrap(
        source: Option<Arc<dyn WorkloadApiSource>>,
        attested: Result<IdentityState, AttestError>,
        production: bool,
    ) -> Result<Self, IdentityError> {
        match attested {
            Ok(state) => Ok(Self {
                source,
                state: ArcSwapOption::from_pointee(state),
                production,
            }),
            Err(e) if production => Err(e.into()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "SPIFFE Workload API attestation failed — starting without a workload identity (dev mode)"
                );
                Ok(Self {
                    source,
                    state: ArcSwapOption::empty(),
                    production,
                })
            }
        }
    }

    /// Re-attests to the SPIFFE Workload API and replaces the held
    /// identity. Applies the same fail-safe policy as
    /// [`IdentityProvider::connect`]: in production, a failed
    /// refresh is returned as an error and the previously held identity
    /// (if any) is left in place — a transient Workload API hiccup must
    /// not drop a running service's identity out from under it. Outside
    /// production, a failed refresh degrades the same way an initial
    /// failed attestation does (also without clearing a prior identity).
    ///
    /// Returns [`IdentityError::Degraded`] if no source was ever connected
    /// (i.e. the provider has been degraded since [`IdentityProvider::connect`]).
    pub async fn refresh(&self) -> Result<(), IdentityError> {
        let source = self.source.as_ref().ok_or(IdentityError::Degraded)?;
        match attest(source.as_ref()).await {
            Ok(state) => {
                self.state.store(Some(Arc::new(state)));
                Ok(())
            }
            Err(e) if self.production => Err(e.into()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "SPIFFE Workload API refresh failed — keeping the previously held identity, if any"
                );
                Ok(())
            }
        }
    }

    /// Fetches a JWT-SVID scoped to `audience` for this workload's default
    /// identity — for `sts:AssumeRoleWithWebIdentity` or service-to-service
    /// JWT auth. Always makes a fresh Workload API call; JWT-SVIDs are not
    /// cached across calls.
    ///
    /// Returns [`IdentityError::Degraded`] if no Workload API source is
    /// held (see the fail-safe policy).
    pub async fn fetch_jwt_svid(&self, audience: &str) -> Result<JwtSvid, IdentityError> {
        let source = self.source.as_ref().ok_or(IdentityError::Degraded)?;
        source
            .fetch_jwt_svid(audience)
            .await
            .map_err(|e| IdentityError::Jwt(Box::new(e)))
    }

    /// Builds a mTLS `rustls::ServerConfig` presenting the currently held
    /// X.509-SVID, requiring every connecting peer's certificate to chain
    /// to an authority in the held bundle set and its SPIFFE ID to satisfy
    /// `allowed`. See the crate-level "TLS configs are snapshots" caveat.
    ///
    /// Returns [`IdentityError::Degraded`] if no identity is currently
    /// held.
    pub fn server_tls_config(
        &self,
        allowed: &SpiffeIdMatcher,
    ) -> Result<rustls::ServerConfig, IdentityError> {
        let state = self.state.load();
        let state = state.as_deref().ok_or(IdentityError::Degraded)?;
        tls::server_tls_config(&state.svid, &state.bundles, allowed)
    }

    /// Builds a mTLS `rustls::ClientConfig` presenting the currently held
    /// X.509-SVID as the client certificate, requiring the connecting
    /// server's certificate to chain to an authority in the held bundle
    /// set and its SPIFFE ID to satisfy `allowed`. See the crate-level
    /// "TLS configs are snapshots" caveat.
    ///
    /// Returns [`IdentityError::Degraded`] if no identity is currently
    /// held.
    pub fn client_tls_config(
        &self,
        allowed: &SpiffeIdMatcher,
    ) -> Result<rustls::ClientConfig, IdentityError> {
        let state = self.state.load();
        let state = state.as_deref().ok_or(IdentityError::Degraded)?;
        tls::client_tls_config(&state.svid, &state.bundles, allowed)
    }

    /// Whether an attested identity is currently held. `false` after a
    /// dev-mode degrade, or before the first successful
    /// [`IdentityProvider::refresh`] following one.
    #[must_use]
    pub fn has_identity(&self) -> bool {
        self.state.load().is_some()
    }

    /// Test-only constructor: builds a provider that already holds `svid`
    /// and `bundles` as its identity, with no Workload API source at all
    /// (`refresh`/`fetch_jwt_svid` always return [`IdentityError::Degraded`]
    /// — this constructor never re-attests). Lets a downstream service
    /// integration-test real mTLS accept/reject via
    /// [`Self::server_tls_config`]/[`Self::client_tls_config`] against an
    /// injected fake SPIFFE identity (see [`testutil`]) instead of a live
    /// SPIRE agent. Not reachable from a normal production build — see the
    /// crate-level "Testing without a live SPIRE agent" docs.
    #[cfg(any(test, feature = "testutil"))]
    #[must_use]
    pub fn from_svid_for_test(svid: X509Svid, bundles: X509BundleSet) -> Self {
        Self {
            source: None,
            state: ArcSwapOption::from_pointee(IdentityState {
                svid: Arc::new(svid),
                bundles: Arc::new(bundles),
            }),
            production: false,
        }
    }

    /// Test-only constructor: a provider holding no identity at all — the
    /// state a real provider settles into outside production when the
    /// Workload API is unreachable. Lets a downstream service exercise its
    /// own "no identity held"/degraded-provider fallback deterministically,
    /// without touching `RELEASE_MODE` or requiring a live (or even
    /// reachable-but-empty) Workload API socket. Not reachable from a
    /// normal production build.
    #[cfg(any(test, feature = "testutil"))]
    #[must_use]
    pub fn degraded_for_test() -> Self {
        Self {
            source: None,
            state: ArcSwapOption::empty(),
            production: false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use spiffe::{WorkloadApiError, X509Context};

    use super::*;
    use crate::testutil::{TestCa, bundle_set, trust_domain};

    #[derive(Debug)]
    enum FakeOutcome {
        Success(X509Context),
        Fail,
    }

    /// A scripted [`WorkloadApiSource`]: each call to `fetch_x509_context`
    /// pops the next outcome, panicking if the script is exhausted (a
    /// clear test-authoring bug, not a real assertion failure).
    #[derive(Debug)]
    struct FakeSource {
        script: Mutex<VecDeque<FakeOutcome>>,
    }

    impl FakeSource {
        fn new(script: Vec<FakeOutcome>) -> Self {
            Self {
                script: Mutex::new(script.into()),
            }
        }

        fn shared(script: Vec<FakeOutcome>) -> Arc<dyn WorkloadApiSource> {
            Arc::new(Self::new(script))
        }
    }

    #[async_trait::async_trait]
    impl WorkloadApiSource for FakeSource {
        async fn fetch_x509_context(&self) -> Result<X509Context, WorkloadApiSourceError> {
            let mut script = self
                .script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match script.pop_front() {
                Some(FakeOutcome::Success(ctx)) => Ok(ctx),
                Some(FakeOutcome::Fail) => Err(WorkloadApiError::EmptyResponse.into()),
                None => panic!("FakeSource script exhausted"),
            }
        }

        async fn fetch_jwt_svid(&self, _audience: &str) -> Result<JwtSvid, WorkloadApiSourceError> {
            Err(WorkloadApiError::EmptyResponse.into())
        }
    }

    fn attested_context() -> (X509Context, TrustDomain) {
        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let ctx = X509Context::new([Arc::new(svid)], bundle_set(&[(&td, &ca)]));
        (ctx, td)
    }

    #[tokio::test]
    async fn connect_hard_fails_in_production_when_workload_api_unreachable() {
        let connect_result: Result<Arc<dyn WorkloadApiSource>, WorkloadApiSourceError> =
            Err(WorkloadApiError::MissingEndpointSocket.into());
        let result = IdentityProvider::bootstrap(connect_result, true).await;
        assert!(matches!(
            result,
            Err(IdentityError::WorkloadApiUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn connect_degrades_outside_production_when_workload_api_unreachable() {
        let connect_result: Result<Arc<dyn WorkloadApiSource>, WorkloadApiSourceError> =
            Err(WorkloadApiError::MissingEndpointSocket.into());
        let provider = IdentityProvider::bootstrap(connect_result, false)
            .await
            .expect("dev mode must degrade, not fail");
        assert!(!provider.has_identity());
        assert!(matches!(
            provider.server_tls_config(&SpiffeIdMatcher::new()),
            Err(IdentityError::Degraded)
        ));
        assert!(matches!(
            provider.client_tls_config(&SpiffeIdMatcher::new()),
            Err(IdentityError::Degraded)
        ));
        assert!(matches!(
            provider.fetch_jwt_svid("aud").await,
            Err(IdentityError::Degraded)
        ));
        assert!(matches!(
            provider.refresh().await,
            Err(IdentityError::Degraded)
        ));
    }

    #[tokio::test]
    async fn bootstrap_hard_fails_in_production_when_initial_fetch_fails() {
        let source = FakeSource::shared(vec![FakeOutcome::Fail]);
        let result = IdentityProvider::bootstrap(Ok(source), true).await;
        assert!(matches!(
            result,
            Err(IdentityError::WorkloadApiUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn bootstrap_degrades_outside_production_when_initial_fetch_fails() {
        let source = FakeSource::shared(vec![FakeOutcome::Fail]);
        let provider = IdentityProvider::bootstrap(Ok(source), false)
            .await
            .expect("dev mode must degrade, not fail");
        assert!(!provider.has_identity());
    }

    #[tokio::test]
    async fn bootstrap_succeeds_and_holds_a_usable_identity() {
        let (ctx, td) = attested_context();
        let source = FakeSource::shared(vec![FakeOutcome::Success(ctx)]);
        let provider = IdentityProvider::bootstrap(Ok(source), true)
            .await
            .expect("bootstrap with a valid attestation must succeed");
        assert!(provider.has_identity());

        let allowed = SpiffeIdMatcher::new().allow_trust_domain(td);
        assert!(provider.server_tls_config(&allowed).is_ok());
        assert!(provider.client_tls_config(&allowed).is_ok());
    }

    #[tokio::test]
    async fn refresh_replaces_the_held_identity_on_success() {
        let (ctx, _td) = attested_context();
        let source = FakeSource::shared(vec![FakeOutcome::Fail, FakeOutcome::Success(ctx)]);
        let provider = IdentityProvider::bootstrap(Ok(source), false)
            .await
            .expect("dev mode degrade on first (failing) attempt");
        assert!(!provider.has_identity());

        provider.refresh().await.expect("second attempt succeeds");
        assert!(provider.has_identity());
    }

    #[tokio::test]
    async fn refresh_in_production_errors_but_preserves_prior_identity() {
        let (ctx, td) = attested_context();
        let source = FakeSource::shared(vec![FakeOutcome::Success(ctx), FakeOutcome::Fail]);
        let provider = IdentityProvider::bootstrap(Ok(source), true)
            .await
            .expect("initial attestation succeeds");
        assert!(provider.has_identity());

        let err = provider.refresh().await.expect_err("second attempt fails");
        assert!(matches!(err, IdentityError::WorkloadApiUnavailable(_)));
        // The prior identity must still be usable — a transient refresh
        // failure in production must not drop a running service's identity.
        assert!(provider.has_identity());
        let allowed = SpiffeIdMatcher::new().allow_trust_domain(td);
        assert!(provider.server_tls_config(&allowed).is_ok());
    }

    #[tokio::test]
    async fn refresh_outside_production_degrades_without_clearing_prior_identity() {
        let (ctx, td) = attested_context();
        let source = FakeSource::shared(vec![FakeOutcome::Success(ctx), FakeOutcome::Fail]);
        let provider = IdentityProvider::bootstrap(Ok(source), false)
            .await
            .expect("initial attestation succeeds");
        assert!(provider.has_identity());

        // Outside production a failed refresh is not an error at all — it
        // just warns and leaves the prior identity in place.
        provider
            .refresh()
            .await
            .expect("dev mode never errors here");
        assert!(provider.has_identity());
        let allowed = SpiffeIdMatcher::new().allow_trust_domain(td);
        assert!(provider.server_tls_config(&allowed).is_ok());
    }

    #[tokio::test]
    async fn bootstrap_hard_fails_when_workload_api_issues_no_svid() {
        let empty_ctx = X509Context::new(Vec::new(), X509BundleSet::new());
        let source = FakeSource::shared(vec![FakeOutcome::Success(empty_ctx)]);
        let err = IdentityProvider::bootstrap(Ok(source), true)
            .await
            .expect_err("no SVID at all must not be treated as a valid attestation");
        assert!(matches!(err, IdentityError::NoDefaultSvid));
    }

    #[tokio::test]
    async fn fetch_jwt_svid_maps_source_failures_once_attested() {
        let (ctx, _td) = attested_context();
        let source = FakeSource::shared(vec![FakeOutcome::Success(ctx)]);
        let provider = IdentityProvider::bootstrap(Ok(source), true)
            .await
            .expect("bootstrap succeeds");
        // FakeSource::fetch_jwt_svid always fails — this exercises the
        // "source present but the Workload API call itself errored" path,
        // distinct from the Degraded (no source at all) path already
        // covered elsewhere.
        let err = provider
            .fetch_jwt_svid("aud")
            .await
            .expect_err("FakeSource always fails JWT-SVID fetches");
        assert!(matches!(err, IdentityError::Jwt(_)));
    }

    #[test]
    fn identity_provider_debug_reports_state_without_leaking_material() {
        let provider = IdentityProvider {
            source: None,
            state: ArcSwapOption::empty(),
            production: true,
        };
        let debug = format!("{provider:?}");
        assert!(debug.contains("has_source: false"));
        assert!(debug.contains("has_identity: false"));
        assert!(debug.contains("production: true"));
    }

    #[tokio::test]
    async fn connect_fails_deterministically_without_a_live_workload_api_socket() {
        // No SPIRE agent runs in this test environment and
        // `SPIFFE_ENDPOINT_SOCKET` is not set, so `connect_env()` fails
        // immediately (no network I/O attempted) — this exercises the real
        // `IdentityProvider::connect`/`RealWorkloadApiSource::connect_env`
        // path deterministically, without requiring a live agent or
        // mutating process-wide environment variables (RELEASE_MODE is
        // left at its ambient/unset value, which defaults to production
        // posture — see `skauswatch_auth::is_production`).
        //
        // Also doubles as the regression for the identity prod-hard-fail
        // bypass fix: `connect()` takes no deployment-domain argument at
        // all (unlike the removed `connect_with_domain`), so there is
        // nothing a caller could pass here — e.g. a product's own `.app`
        // domain — to make this degrade instead of hard-fail.
        assert!(
            std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err(),
            "test assumes no Workload API socket is configured in this environment"
        );
        let result = IdentityProvider::connect().await;
        assert!(matches!(
            result,
            Err(IdentityError::WorkloadApiUnavailable(_))
        ));
    }
}
