//! Shared application state: license/flag client now; DB pool, Valkey, and
//! gRPC clients join as routers are ported.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};

/// Inner state shared across all handlers via `Arc`.
pub struct AppStateInner {
    /// License entitlement + PostHog flag client (fail-safe).
    pub license: Arc<LicenseClient>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    /// Builds state from environment configuration. Never fails on license
    /// server unavailability — the client degrades to cached/community.
    pub async fn from_env() -> anyhow::Result<AppState> {
        let cfg = LicenseConfig::from_env("skauswatch")
            .map_err(|e| anyhow::anyhow!("license config: {e}"))?
            .with_bypass_domain("skauswatch.app");
        let license =
            LicenseClient::new(cfg).map_err(|e| anyhow::anyhow!("license client: {e}"))?;
        // Best-effort startup validation; errors are logged inside refresh.
        let _ = license.refresh().await;
        Ok(Arc::new(Self { license }))
    }

    /// Test constructor with a caller-supplied license client.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn for_tests(license: Arc<LicenseClient>) -> AppState {
        Arc::new(Self { license })
    }
}
