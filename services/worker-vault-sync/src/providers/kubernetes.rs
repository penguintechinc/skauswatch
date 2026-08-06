//! Kubernetes Secrets cloud provider. Rust port of
//! `icebox/services/sync-worker/providers/kubernetes.py`.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret as K8sSecret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use secrecy::SecretString;
use serde_json::Value;

use super::{CloudProvider, ProviderError, SyncResult, str_field};

/// Label applied to every Secret Vault creates, so `list_secrets` can filter
/// to Vault-managed resources only (matches v1 `ICEBOX_LABEL_KEY`/`_VALUE`,
/// renamed for the v2 rebrand).
const VAULT_LABEL_KEY: &str = "vault-managed";
const VAULT_LABEL_VALUE: &str = "true";
const VAULT_SECRET_ID_LABEL: &str = "vault-secret-id";
/// Field manager for the (non-server-side-apply) JSON merge patch this
/// provider issues — required by the k8s API on every write.
const FIELD_MANAGER: &str = "skauswatch-vault-sync";
/// The single data key every Vault-managed Secret stores its value under —
/// matches v1's `data={"value": encoded}`.
const VALUE_KEY: &str = "value";

/// K8s Secret names: lowercase alphanumeric and dashes only (matches v1
/// `KubernetesProvider._secret_name`). A free function (rather than only a
/// method) so it's directly unit-testable without a live `Client`.
fn sanitize_secret_name(prefix: &str, name: &str) -> String {
    let safe = name.to_lowercase().replace(['/', '_', '.'], "-");
    format!("{prefix}{safe}")
}

/// Syncs secrets between Vault and Kubernetes Secrets.
pub struct KubernetesProvider {
    client: Client,
    namespace: String,
    prefix: String,
}

impl KubernetesProvider {
    /// Builds a client from the decrypted `credentials` blob and the
    /// integration's `config` (matches v1 `KubernetesProvider.__init__`).
    ///
    /// Credential resolution, in priority order (matches v1):
    /// 1. `credentials.api_server_url` (+ optional `bearer_token`) — an
    ///    explicit override, e.g. syncing to a *different* cluster than the
    ///    one this worker runs in.
    /// 2. `credentials.in_cluster = true` — explicit in-cluster ServiceAccount.
    /// 3. `credentials.kubeconfig_path` — an explicit kubeconfig file.
    /// 4. Otherwise, infer (try in-cluster, fall back to the default
    ///    kubeconfig) — matches v1's own try/except fallback chain.
    pub async fn new(credentials: &Value, config: &Value) -> Result<Self, ProviderError> {
        let namespace = str_field(credentials, "namespace").unwrap_or_else(|| "default".to_owned());
        let prefix = str_field(config, "secret_prefix").unwrap_or_else(|| "vault-".to_owned());
        let client = Self::build_client(credentials, &namespace).await?;
        Ok(Self {
            client,
            namespace,
            prefix,
        })
    }

    async fn build_client(credentials: &Value, namespace: &str) -> Result<Client, ProviderError> {
        super::ensure_default_crypto_provider();
        if let Some(api_url) = str_field(credentials, "api_server_url") {
            let uri: http::Uri = api_url
                .parse()
                .map_err(|e| ProviderError::Failed(format!("invalid api_server_url: {e}")))?;
            let mut cfg = Config::new(uri);
            cfg.default_namespace = namespace.to_owned();
            if let Some(token) = str_field(credentials, "bearer_token") {
                cfg.auth_info.token = Some(SecretString::from(token));
            }
            return Client::try_from(cfg)
                .map_err(|e| ProviderError::Failed(format!("kube client (api_server_url): {e}")));
        }

        let in_cluster = credentials
            .get("in_cluster")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if in_cluster {
            let cfg = Config::incluster()
                .map_err(|e| ProviderError::Failed(format!("in-cluster config: {e}")))?;
            return Client::try_from(cfg)
                .map_err(|e| ProviderError::Failed(format!("kube client (in-cluster): {e}")));
        }

        if let Some(path) = str_field(credentials, "kubeconfig_path") {
            let kubeconfig = Kubeconfig::read_from(&path)
                .map_err(|e| ProviderError::Failed(format!("read kubeconfig {path}: {e}")))?;
            let cfg = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                .await
                .map_err(|e| ProviderError::Failed(format!("kubeconfig {path}: {e}")))?;
            return Client::try_from(cfg)
                .map_err(|e| ProviderError::Failed(format!("kube client (kubeconfig): {e}")));
        }

        let cfg = Config::infer()
            .await
            .map_err(|e| ProviderError::Failed(format!("infer kube config: {e}")))?;
        Client::try_from(cfg)
            .map_err(|e| ProviderError::Failed(format!("kube client (infer): {e}")))
    }

    /// K8s Secret names: lowercase alphanumeric and dashes only (matches v1
    /// `_secret_name`).
    fn secret_name(&self, name: &str) -> String {
        sanitize_secret_name(&self.prefix, name)
    }

    fn api(&self) -> Api<K8sSecret> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn is_not_found(err: &kube::Error) -> bool {
        matches!(err, kube::Error::Api(status) if status.code == 404)
    }
}

#[async_trait::async_trait]
impl CloudProvider for KubernetesProvider {
    async fn push_secret(&self, name: &str, value: &str, secret_id: &str) -> SyncResult {
        let k8s_name = self.secret_name(name);

        let mut labels = BTreeMap::new();
        labels.insert(VAULT_LABEL_KEY.to_owned(), VAULT_LABEL_VALUE.to_owned());
        // K8s label values: max 63 chars.
        labels.insert(
            VAULT_SECRET_ID_LABEL.to_owned(),
            secret_id.chars().take(63).collect(),
        );

        let mut data = BTreeMap::new();
        data.insert(VALUE_KEY.to_owned(), ByteString(value.as_bytes().to_vec()));

        let body = K8sSecret {
            metadata: ObjectMeta {
                name: Some(k8s_name.clone()),
                namespace: Some(self.namespace.clone()),
                labels: Some(labels),
                ..Default::default()
            },
            type_: Some("Opaque".to_owned()),
            data: Some(data),
            ..Default::default()
        };

        let api = self.api();
        // JSON merge patch (not server-side apply) — matches v1's
        // `patch_namespaced_secret`, which does not auto-create on a
        // missing resource, so the explicit not-found→create fallback below
        // is required (unlike SSA, which would silently create on first
        // apply and change v1's semantics).
        let patch_params = PatchParams {
            field_manager: Some(FIELD_MANAGER.to_owned()),
            ..PatchParams::default()
        };
        match api
            .patch(&k8s_name, &patch_params, &Patch::Merge(&body))
            .await
        {
            Ok(_) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: k8s_name,
                success: true,
                error: None,
                action: "updated".to_owned(),
            },
            Err(e) if Self::is_not_found(&e) => {
                match api.create(&PostParams::default(), &body).await {
                    Ok(_) => SyncResult {
                        secret_id: secret_id.to_owned(),
                        external_ref: k8s_name,
                        success: true,
                        error: None,
                        action: "created".to_owned(),
                    },
                    Err(create_err) => SyncResult {
                        secret_id: secret_id.to_owned(),
                        external_ref: k8s_name,
                        success: false,
                        error: Some(create_err.to_string()),
                        action: "skipped".to_owned(),
                    },
                }
            }
            Err(e) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: k8s_name,
                success: false,
                error: Some(e.to_string()),
                action: "skipped".to_owned(),
            },
        }
    }

    async fn pull_secret(&self, external_ref: &str) -> Result<Option<String>, ProviderError> {
        match self.api().get(external_ref).await {
            Ok(secret) => {
                let value = secret
                    .data
                    .and_then(|mut d| d.remove(VALUE_KEY))
                    .map(|b| String::from_utf8_lossy(&b.0).into_owned());
                Ok(value)
            }
            Err(e) if Self::is_not_found(&e) => Ok(None),
            Err(e) => Err(ProviderError::Failed(e.to_string())),
        }
    }

    async fn delete_secret(&self, external_ref: &str) -> Result<bool, ProviderError> {
        match self
            .api()
            .delete(external_ref, &DeleteParams::default())
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if Self::is_not_found(&e) => Ok(false),
            Err(e) => Err(ProviderError::Failed(e.to_string())),
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>, ProviderError> {
        let selector = format!("{VAULT_LABEL_KEY}={VAULT_LABEL_VALUE}");
        let lp = ListParams::default().labels(&selector);
        let list = self
            .api()
            .list(&lp)
            .await
            .map_err(|e| ProviderError::Failed(e.to_string()))?;
        Ok(list
            .items
            .into_iter()
            .filter_map(|s| s.metadata.name)
            .collect())
    }
}

// ── Kubernetes wire-protocol tests ──────────────────────────────────────
//
// `credentials.api_server_url` (the same override real deployments use to
// sync into a *different* cluster than the one this worker runs in — see
// `KubernetesProvider::build_client`) points the real `kube::Client` at a
// wiremock server, so these tests exercise the exact request-building/
// response-parsing code the production path uses, same technique as the
// AWS provider's own tests.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn status_body(code: u16, reason: &str) -> serde_json::Value {
        json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": reason, "reason": reason, "code": code,
        })
    }

    fn secret_body(name: &str) -> serde_json::Value {
        json!({
            "kind": "Secret", "apiVersion": "v1",
            "metadata": {"name": name, "namespace": "default"},
            "type": "Opaque", "data": {"value": "aHVudGVyMg=="},
        })
    }

    async fn provider_for(server: &MockServer) -> KubernetesProvider {
        let credentials = json!({"api_server_url": server.uri()});
        KubernetesProvider::new(&credentials, &Value::Null)
            .await
            .expect("build provider against wiremock api server")
    }

    #[test]
    fn secret_name_lowercases_and_sanitizes() {
        assert_eq!(
            sanitize_secret_name("vault-", "App/DB_Password.env"),
            "vault-app-db-password-env"
        );
    }

    // ── push_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn push_secret_updates_via_merge_patch_when_secret_exists() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/namespaces/default/secrets/vault-db-password"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(secret_body("vault-db-password")),
            )
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        let result = provider
            .push_secret("db-password", "hunter2", "secret-1")
            .await;

        assert!(result.success, "{result:?}");
        assert_eq!(result.action, "updated");
        assert_eq!(result.external_ref, "vault-db-password");
    }

    #[tokio::test]
    async fn push_secret_creates_when_patch_reports_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/namespaces/default/secrets/vault-new"))
            .respond_with(ResponseTemplate::new(404).set_body_json(status_body(404, "NotFound")))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/namespaces/default/secrets"))
            .respond_with(ResponseTemplate::new(201).set_body_json(secret_body("vault-new")))
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        let result = provider.push_secret("new", "s3cr3t", "secret-2").await;

        assert!(result.success, "{result:?}");
        assert_eq!(result.action, "created");
    }

    #[tokio::test]
    async fn push_secret_other_patch_error_does_not_attempt_create() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/namespaces/default/secrets/vault-x"))
            .respond_with(ResponseTemplate::new(403).set_body_json(status_body(403, "Forbidden")))
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        let result = provider.push_secret("x", "v", "secret-3").await;

        assert!(!result.success);
        assert_eq!(result.action, "skipped");
        let requests = server.received_requests().await.expect("recording enabled");
        assert_eq!(
            requests.len(),
            1,
            "must not attempt create on non-404 patch error"
        );
    }

    // ── pull_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pull_secret_returns_value_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/default/secrets/vault-p"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_body("vault-p")))
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        let result = provider.pull_secret("vault-p").await;
        assert_eq!(result, Ok(Some("hunter2".to_owned())));
    }

    #[tokio::test]
    async fn pull_secret_returns_none_when_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/default/secrets/vault-missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(status_body(404, "NotFound")))
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        let result = provider.pull_secret("vault-missing").await;
        assert_eq!(result, Ok(None));
    }

    // ── delete_secret ────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_returns_true_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/namespaces/default/secrets/vault-d"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_body("vault-d")))
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        assert_eq!(provider.delete_secret("vault-d").await, Ok(true));
    }

    #[tokio::test]
    async fn delete_secret_returns_false_when_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/namespaces/default/secrets/vault-missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(status_body(404, "NotFound")))
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        assert_eq!(provider.delete_secret("vault-missing").await, Ok(false));
    }

    // ── list_secrets ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_sends_the_managed_label_selector() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/default/secrets"))
            .and(query_param("labelSelector", "vault-managed=true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kind": "SecretList", "apiVersion": "v1",
                "items": [secret_body("vault-a"), secret_body("vault-b")],
            })))
            .mount(&server)
            .await;
        let provider = provider_for(&server).await;

        let result = provider.list_secrets().await;
        assert_eq!(result, Ok(vec!["vault-a".to_owned(), "vault-b".to_owned()]));
    }

    // ── namespace / prefix defaults ──────────────────────────────────────

    #[tokio::test]
    async fn new_defaults_namespace_and_prefix() {
        let server = MockServer::start().await;
        let credentials = json!({"api_server_url": server.uri()});
        let provider = KubernetesProvider::new(&credentials, &Value::Null)
            .await
            .expect("build provider");
        assert_eq!(provider.namespace, "default");
        assert_eq!(provider.prefix, "vault-");
    }

    #[tokio::test]
    async fn new_honors_namespace_and_prefix_overrides() {
        let server = MockServer::start().await;
        let credentials = json!({"api_server_url": server.uri(), "namespace": "prod"});
        let config = json!({"secret_prefix": "myapp-"});
        let provider = KubernetesProvider::new(&credentials, &config)
            .await
            .expect("build provider");
        assert_eq!(provider.namespace, "prod");
        assert_eq!(provider.prefix, "myapp-");
    }
}
