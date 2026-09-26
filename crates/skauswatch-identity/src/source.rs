//! Abstraction over the raw SPIFFE Workload API calls [`crate::IdentityProvider`]
//! depends on.
//!
//! [`WorkloadApiSource`] exists purely so the provider's fail-safe bootstrap
//! logic (production hard-fail vs. dev-mode degrade) can be exercised in
//! tests against a fake implementation, instead of requiring a live SPIRE
//! Workload API socket. [`RealWorkloadApiSource`] is the thin production
//! adapter; it has no logic of its own worth unit testing beyond what its
//! `#[from]` error conversion already covers.

use spiffe::{JwtSvid, WorkloadApiClient, WorkloadApiError, X509Context};

/// The subset of [`WorkloadApiClient`] behavior [`crate::IdentityProvider`]
/// needs, factored out as a trait so tests can substitute a fake source.
#[async_trait::async_trait]
pub(crate) trait WorkloadApiSource: std::fmt::Debug + Send + Sync {
    /// Fetches the workload's current X.509-SVID(s) and trust bundle set.
    async fn fetch_x509_context(&self) -> Result<X509Context, WorkloadApiSourceError>;

    /// Fetches a JWT-SVID scoped to `audience` for the workload's default
    /// identity.
    async fn fetch_jwt_svid(&self, audience: &str) -> Result<JwtSvid, WorkloadApiSourceError>;
}

/// Errors surfaced by a [`WorkloadApiSource`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkloadApiSourceError {
    /// The underlying SPIFFE Workload API call failed.
    #[error(transparent)]
    Workload(#[from] WorkloadApiError),
}

/// The real [`WorkloadApiSource`], backed by a live gRPC connection to the
/// SPIFFE Workload API (typically a SPIRE agent Unix domain socket).
///
/// Deliberately thin: every decision this crate makes (production posture,
/// SPIFFE ID matching, TLS config construction) lives elsewhere and is
/// covered by unit tests that never touch this type. This adapter can only
/// be meaningfully exercised against a live SPIRE agent, so it is excluded
/// from the crate's unit test coverage target — see the crate root docs.
#[derive(Debug)]
pub(crate) struct RealWorkloadApiSource(WorkloadApiClient);

impl RealWorkloadApiSource {
    /// Connects using the endpoint named by `SPIFFE_ENDPOINT_SOCKET`.
    pub(crate) async fn connect_env() -> Result<Self, WorkloadApiSourceError> {
        Ok(Self(WorkloadApiClient::connect_env().await?))
    }
}

#[async_trait::async_trait]
impl WorkloadApiSource for RealWorkloadApiSource {
    async fn fetch_x509_context(&self) -> Result<X509Context, WorkloadApiSourceError> {
        Ok(self.0.fetch_x509_context().await?)
    }

    async fn fetch_jwt_svid(&self, audience: &str) -> Result<JwtSvid, WorkloadApiSourceError> {
        Ok(self.0.fetch_jwt_svid([audience], None).await?)
    }
}
