//! Placeholder [`super::CloudProvider`] for targets not yet ported to
//! Rust: Azure Key Vault, GCP Secret Manager, Oracle Cloud (OCI) Vault, and
//! Kubernetes Secrets. Every v1 provider (`providers/{azure,gcp,oracle,
//! kubernetes}.py`) had a real cloud-SDK-backed implementation; porting all
//! four alongside AWS, the crypto gate, and the full REST backend in one
//! pass was not achievable — this is an explicit, tracked deferral (see
//! `docs/v2-port/v2.1-backlog.md`), not a silently-stubbed feature.
//!
//! Operations fail loudly (`ProviderError::NotImplemented`) rather than
//! silently succeeding, so a misconfigured integration surfaces immediately
//! in `vault_cloud_sync_state.sync_status` instead of appearing to work.

use super::{CloudProvider, ProviderError, SyncResult};

/// A [`CloudProvider`] stand-in that reports every operation as not yet
/// implemented for `provider_name`.
pub struct NotImplementedProvider {
    provider_name: &'static str,
}

impl NotImplementedProvider {
    /// Builds a stand-in for `provider_name` (one of `azure`, `gcp`,
    /// `oracle`, `kubernetes`).
    pub fn new(provider_name: &'static str) -> Self {
        Self { provider_name }
    }
}

#[async_trait::async_trait]
impl CloudProvider for NotImplementedProvider {
    async fn push_secret(&self, _name: &str, _value: &str, secret_id: &str) -> SyncResult {
        SyncResult {
            secret_id: secret_id.to_owned(),
            external_ref: String::new(),
            success: false,
            error: Some(ProviderError::NotImplemented(self.provider_name).to_string()),
            action: "skipped".to_owned(),
        }
    }

    async fn pull_secret(&self, _external_ref: &str) -> Result<Option<String>, ProviderError> {
        Err(ProviderError::NotImplemented(self.provider_name))
    }

    async fn delete_secret(&self, _external_ref: &str) -> Result<bool, ProviderError> {
        Err(ProviderError::NotImplemented(self.provider_name))
    }

    async fn list_secrets(&self) -> Result<Vec<String>, ProviderError> {
        Err(ProviderError::NotImplemented(self.provider_name))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn push_reports_failure_not_a_panic() {
        let provider = NotImplementedProvider::new("azure");
        let result = provider.push_secret("n", "v", "secret-1").await;
        assert!(!result.success);
        assert_eq!(result.action, "skipped");
        assert!(result.error.expect("error message").contains("azure"));
    }

    #[tokio::test]
    async fn other_operations_return_not_implemented_error() {
        let provider = NotImplementedProvider::new("gcp");
        assert!(provider.pull_secret("ref").await.is_err());
        assert!(provider.delete_secret("ref").await.is_err());
        assert!(provider.list_secrets().await.is_err());
    }
}
