//! Cloud provider abstraction for Vault↔cloud secret sync. Rust port of
//! `icebox/services/sync-worker/providers/__init__.py`.

pub mod aws;
pub mod not_implemented;

use serde_json::Value;

/// Result of a single secret sync operation — matches v1 `SyncResult`.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Vault secret id this operation was for.
    pub secret_id: String,
    /// Provider-specific resource identifier (ARN / resource name / etc.).
    pub external_ref: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error detail when `success` is `false`.
    pub error: Option<String>,
    /// One of: created, updated, synced, skipped, deleted.
    pub action: String,
}

/// Errors a [`CloudProvider`] may return for `pull_secret`/`list_secrets`,
/// where there is no per-item `SyncResult` to carry `success`/`error` on.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// The provider rejected the request or the transport failed.
    #[error("{0}")]
    Failed(String),
    /// This provider is not yet implemented in the v2 Rust port.
    #[error(
        "cloud provider {0} sync is not yet implemented in the v2 Rust port \
         (tracked in docs/v2-port/v2.1-backlog.md)"
    )]
    NotImplemented(&'static str),
}

/// Common interface for all cloud secret providers, matching v1
/// `CloudProvider` (ABC).
///
/// `pull_secret`/`list_secrets` are part of the interface (and fully
/// implemented for AWS) but have no caller yet: v1's `worker.py` never
/// invoked them either — the `cloud_to_vault`/`bidirectional` pull-sync
/// direction was never wired to a polling loop despite
/// `SyncWorkerConfig.pull_poll_interval` existing for it. Preserved 1:1;
/// wiring an actual poll loop is v2.1 scope, not a v2.0 regression.
#[async_trait::async_trait]
pub trait CloudProvider: Send + Sync {
    /// Pushes a secret value to the cloud provider, creating or updating it.
    async fn push_secret(&self, name: &str, value: &str, secret_id: &str) -> SyncResult;

    /// Pulls a secret value from the cloud provider by its external ref.
    #[allow(dead_code)]
    async fn pull_secret(&self, external_ref: &str) -> Result<Option<String>, ProviderError>;

    /// Deletes a secret from the cloud provider. Returns `true` if deleted,
    /// `false` if it was already absent.
    async fn delete_secret(&self, external_ref: &str) -> Result<bool, ProviderError>;

    /// Lists all Vault-managed secret refs in this provider.
    #[allow(dead_code)]
    async fn list_secrets(&self) -> Result<Vec<String>, ProviderError>;
}

/// Factory: instantiates the correct [`CloudProvider`] for `provider_name`.
/// Matches v1 `get_provider`.
pub fn get_provider(
    provider_name: &str,
    credentials: &Value,
    config: &Value,
) -> Result<Box<dyn CloudProvider>, ProviderError> {
    match provider_name {
        "aws" => Ok(Box::new(aws::AwsProvider::new(credentials, config))),
        "azure" => Ok(Box::new(not_implemented::NotImplementedProvider::new(
            "azure",
        ))),
        "gcp" => Ok(Box::new(not_implemented::NotImplementedProvider::new(
            "gcp",
        ))),
        "oracle" => Ok(Box::new(not_implemented::NotImplementedProvider::new(
            "oracle",
        ))),
        "kubernetes" => Ok(Box::new(not_implemented::NotImplementedProvider::new(
            "kubernetes",
        ))),
        other => Err(ProviderError::Failed(format!(
            "Unknown provider '{other}'. Valid options: aws, azure, gcp, oracle, kubernetes"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn get_provider_aws_dispatches_to_the_real_aws_wire_protocol() {
        // Proves `get_provider("aws", ...)` returns a genuine `AwsProvider`
        // (not e.g. accidentally falling through to `NotImplementedProvider`
        // for an unmatched pattern arm) by actually round-tripping through a
        // mocked AWS Secrets Manager endpoint — `NotImplementedProvider`
        // never makes an HTTP call at all, so a request landing on the mock
        // is proof positive of correct dispatch.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-amz-target", "secretsmanager.PutSecretValue"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ARN": "arn:1", "Name": "vault/dispatch-check", "VersionId": "v1",
            })))
            .mount(&server)
            .await;
        let credentials =
            serde_json::json!({"access_key_id": "AKIATEST", "secret_access_key": "secret"});
        let config = serde_json::json!({"endpoint_url": server.uri()});

        let provider =
            get_provider("aws", &credentials, &config).expect("aws provider construction");
        let result = provider.push_secret("dispatch-check", "v", "id-1").await;

        assert!(result.success);
        let requests = server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn get_provider_dispatches_each_not_implemented_target() {
        for name in ["azure", "gcp", "oracle", "kubernetes"] {
            let provider = get_provider(name, &Value::Null, &Value::Null)
                .unwrap_or_else(|e| panic!("{name} provider construction: {e}"));
            let result = provider.push_secret("n", "v", "id").await;
            assert!(!result.success, "{name} push_secret should fail");
            let error = result
                .error
                .unwrap_or_else(|| panic!("{name} push_secret should carry an error"));
            assert!(
                error.contains(name),
                "{name} error message should name the provider: {error}"
            );

            assert!(provider.pull_secret("ref").await.is_err());
            assert!(provider.delete_secret("ref").await.is_err());
            assert!(provider.list_secrets().await.is_err());
        }
    }

    #[test]
    fn get_provider_rejects_unknown_provider_name() {
        let result = get_provider("not-a-real-provider", &Value::Null, &Value::Null);
        match result {
            Err(ProviderError::Failed(msg)) => {
                assert!(msg.contains("not-a-real-provider"));
                assert!(msg.contains("aws, azure, gcp, oracle, kubernetes"));
            }
            Err(other) => panic!("expected ProviderError::Failed, got {other:?}"),
            Ok(_) => panic!("expected an error for an unknown provider name"),
        }
    }
}
