//! Azure Key Vault cloud provider. Rust port of
//! `icebox/services/sync-worker/providers/azure.py`.
//!
//! Uses `azure_security_keyvault_secrets` — the actively developed
//! generated client (modern `azure_core` 1.x stack) — rather than the
//! legacy, unmaintained `azure_security_keyvault` crate (its own
//! `Cargo.toml` homepage still points at `azure-sdk-for-rust`'s `legacy`
//! branch). See `docs/v2-port/phase12-scope-infra.md` §1.

use std::collections::HashMap;
use std::sync::Arc;

use azure_core::credentials::{Secret as AzureSecret, TokenCredential};
use azure_core::http::StatusCode;
use azure_identity::{ClientSecretCredential, ManagedIdentityCredential};
use azure_security_keyvault_secrets::models::SetSecretParameters;
use azure_security_keyvault_secrets::{ResourceExt, SecretClient, SecretClientOptions};
use futures::TryStreamExt as _;
use serde_json::Value;

use super::{CloudProvider, ProviderError, SyncResult, str_field};

/// Tag applied to every secret Vault creates, so `list_secrets` can filter
/// to Vault-managed resources only (matches v1 `ICEBOX_TAG`, renamed for
/// the v2 rebrand).
const VAULT_TAG_KEY: &str = "vault-managed";
const VAULT_TAG_VALUE: &str = "true";
const VAULT_SECRET_ID_TAG: &str = "vault-secret-id";

/// Syncs secrets between Vault and Azure Key Vault.
pub struct AzureProvider {
    client: SecretClient,
    prefix: String,
}

impl AzureProvider {
    /// Builds a client from the decrypted `credentials` blob and the
    /// integration's `config` (matches v1 `AzureProvider.__init__`: service
    /// principal auth when `tenant_id`/`client_id`/`client_secret` are all
    /// present, else the closest 1:1 equivalent to v1's
    /// `DefaultAzureCredential()` for a headless server workload —
    /// [`ManagedIdentityCredential`] — since `azure_identity` 1.x has no
    /// single broad-chain "default credential" type; the interactive/dev-only
    /// credential kinds `DefaultAzureCredential` also covers aren't
    /// appropriate for this sync worker anyway).
    ///
    /// `config.verify_challenge_resource` (default: unset, which behaves as
    /// `true`) is a test-only escape hatch — not part of v1 — mirroring
    /// [`super::aws::AwsProvider`]'s `endpoint_url` config key, so tests can
    /// point `vault_url` at a local mock server (whose host will never
    /// satisfy Key Vault's real subdomain challenge-resource check).
    pub fn new(credentials: &Value, config: &Value) -> Result<Self, ProviderError> {
        super::ensure_default_crypto_provider();
        let vault_url = str_field(credentials, "vault_url").ok_or_else(|| {
            ProviderError::Failed("azure: credentials.vault_url is required".to_owned())
        })?;
        let prefix = str_field(config, "secret_prefix").unwrap_or_else(|| "vault-".to_owned());

        let credential = Self::build_credential(credentials)?;
        let options = SecretClientOptions {
            verify_challenge_resource: config
                .get("verify_challenge_resource")
                .and_then(Value::as_bool),
            ..Default::default()
        };
        let client = SecretClient::new(&vault_url, credential, Some(options))
            .map_err(|e| ProviderError::Failed(format!("azure: build client: {e}")))?;

        Ok(Self { client, prefix })
    }

    /// Builds directly from an already-constructed client — the real
    /// [`AzureProvider::new`] uses this after resolving credentials; this
    /// module's tests use it with a fake [`TokenCredential`] test double, so
    /// `push_secret`/etc. can be exercised against a wiremock endpoint
    /// without a real `ClientSecretCredential`/`ManagedIdentityCredential`
    /// attempting to reach Azure AD over the network.
    #[cfg(test)]
    pub(crate) fn from_client(client: SecretClient, prefix: String) -> Self {
        Self { client, prefix }
    }

    fn build_credential(credentials: &Value) -> Result<Arc<dyn TokenCredential>, ProviderError> {
        let tenant_id = str_field(credentials, "tenant_id");
        let client_id = str_field(credentials, "client_id");
        let client_secret = str_field(credentials, "client_secret");
        if let (Some(tenant_id), Some(client_id), Some(client_secret)) =
            (tenant_id, client_id, client_secret)
        {
            let cred = ClientSecretCredential::new(
                &tenant_id,
                client_id,
                AzureSecret::new(client_secret),
                None,
            )
            .map_err(|e| ProviderError::Failed(format!("azure: client secret credential: {e}")))?;
            Ok(cred as Arc<dyn TokenCredential>)
        } else {
            let cred = ManagedIdentityCredential::new(None).map_err(|e| {
                ProviderError::Failed(format!("azure: managed identity credential: {e}"))
            })?;
            Ok(cred as Arc<dyn TokenCredential>)
        }
    }

    /// Azure Key Vault names: alphanumeric + dashes only (matches v1
    /// `_secret_name`).
    fn secret_name(&self, name: &str) -> String {
        let safe = name.replace(['_', '/', '.'], "-");
        format!("{}{safe}", self.prefix)
    }

    fn is_not_found(err: &azure_core::Error) -> bool {
        err.http_status() == Some(StatusCode::NotFound)
    }
}

#[async_trait::async_trait]
impl CloudProvider for AzureProvider {
    async fn push_secret(&self, name: &str, value: &str, secret_id: &str) -> SyncResult {
        let az_name = self.secret_name(name);
        let mut tags = HashMap::new();
        tags.insert(VAULT_TAG_KEY.to_owned(), VAULT_TAG_VALUE.to_owned());
        tags.insert(VAULT_SECRET_ID_TAG.to_owned(), secret_id.to_owned());

        let params = SetSecretParameters {
            value: Some(value.to_owned()),
            tags: Some(tags),
            ..Default::default()
        };
        let body = match params.try_into() {
            Ok(b) => b,
            Err(e) => {
                return SyncResult {
                    secret_id: secret_id.to_owned(),
                    external_ref: az_name,
                    success: false,
                    error: Some(format!("azure: serialize request: {e}")),
                    action: "skipped".to_owned(),
                };
            }
        };

        // `set_secret` always creates-or-updates in one call — matches v1,
        // which unconditionally reports `action="updated"` for this
        // provider (no separate create/update branching, unlike AWS/GCP/K8s).
        match self.client.set_secret(&az_name, body, None).await {
            Ok(_) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: az_name,
                success: true,
                error: None,
                action: "updated".to_owned(),
            },
            Err(e) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: az_name,
                success: false,
                error: Some(e.to_string()),
                action: "skipped".to_owned(),
            },
        }
    }

    async fn pull_secret(&self, external_ref: &str) -> Result<Option<String>, ProviderError> {
        match self.client.get_secret(external_ref, None).await {
            Ok(resp) => {
                let secret = resp
                    .into_model()
                    .map_err(|e| ProviderError::Failed(e.to_string()))?;
                Ok(secret.value)
            }
            Err(e) if Self::is_not_found(&e) => Ok(None),
            Err(e) => Err(ProviderError::Failed(e.to_string())),
        }
    }

    async fn delete_secret(&self, external_ref: &str) -> Result<bool, ProviderError> {
        match self.client.delete_secret(external_ref, None).await {
            Ok(_) => Ok(true),
            Err(e) if Self::is_not_found(&e) => Ok(false),
            Err(e) => Err(ProviderError::Failed(e.to_string())),
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>, ProviderError> {
        let mut pager = self
            .client
            .list_secret_properties(None)
            .map_err(|e| ProviderError::Failed(e.to_string()))?;
        let mut names = Vec::new();
        while let Some(props) = pager
            .try_next()
            .await
            .map_err(|e| ProviderError::Failed(e.to_string()))?
        {
            let managed = props
                .tags
                .as_ref()
                .and_then(|t| t.get(VAULT_TAG_KEY))
                .map(String::as_str)
                == Some(VAULT_TAG_VALUE);
            if managed {
                let name = props
                    .resource_id()
                    .map_err(|e| ProviderError::Failed(e.to_string()))?
                    .name;
                names.push(name);
            }
        }
        Ok(names)
    }
}

// ── Azure Key Vault wire-protocol tests ─────────────────────────────────
//
// Key Vault requires a discover-then-authenticate challenge flow (see
// `KeyVaultAuthorizer` in `azure_security_keyvault_secrets`): the client's
// first request per `SecretClient` instance goes out unauthenticated, the
// server responds 401 with a `WWW-Authenticate` challenge, and only then
// does the client attach a bearer token and retry. A real
// `ClientSecretCredential`/`ManagedIdentityCredential` would try to reach
// Azure AD for that token — unusable in a sandboxed test — so these tests
// build the client via `AzureProvider::from_client` with a fake
// `TokenCredential` instead, exercising the exact same wire protocol and
// request-building code AWS's own wiremock tests exercise.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn secret_name_applies_configured_prefix() {
        let provider = AzureProvider {
            client: fake_client(""),
            prefix: "vault-".to_owned(),
        };
        assert_eq!(provider.secret_name("db-password"), "vault-db-password");
    }

    #[test]
    fn secret_name_sanitizes_disallowed_characters() {
        let provider = AzureProvider {
            client: fake_client(""),
            prefix: "vault-".to_owned(),
        };
        assert_eq!(
            provider.secret_name("app/db_password.env"),
            "vault-app-db-password-env"
        );
    }

    #[test]
    fn secret_name_honors_custom_prefix() {
        let provider = AzureProvider {
            client: fake_client(""),
            prefix: "myapp-".to_owned(),
        };
        assert_eq!(provider.secret_name("x"), "myapp-x");
    }

    /// A `TokenCredential` double that returns a static token instantly —
    /// no network I/O, unlike every real credential type this provider uses
    /// in production.
    #[derive(Debug)]
    struct FakeCredential;

    #[async_trait::async_trait]
    impl TokenCredential for FakeCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
        ) -> azure_core::Result<azure_core::credentials::AccessToken> {
            Ok(azure_core::credentials::AccessToken::new(
                "fake-test-token",
                time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            ))
        }
    }

    /// A no-request client — only for the pure `secret_name` sanitization
    /// unit tests below, which never call `.send()`.
    fn fake_client(_unused: &str) -> SecretClient {
        super::super::ensure_default_crypto_provider();
        SecretClient::new(
            "https://unused.example.invalid",
            Arc::new(FakeCredential) as Arc<dyn TokenCredential>,
            Some(SecretClientOptions {
                verify_challenge_resource: Some(false),
                ..Default::default()
            }),
        )
        .expect("build fake-credential client")
    }

    /// A [`azure_core::http::policies::Policy`] installed as the pipeline's
    /// terminal transport, redirecting the actual bytes-on-the-wire to a
    /// wiremock server regardless of what URL the rest of the pipeline
    /// believes it's talking to.
    ///
    /// This exists because `BearerTokenAuthorizationPolicy` (upstream of
    /// this policy in the pipeline) unconditionally refuses to send *any*
    /// request — even the unauthenticated discovery leg — when
    /// `request.url().scheme() != "https"`, with no config bypass (a
    /// deliberate, correct anti-token-leakage guard, not a bug). `wiremock`
    /// itself has no HTTPS support at all. So `SecretClient` is built with a
    /// fake `https://` `vault_url` (satisfying the guard, which runs before
    /// this policy ever sees the request), and this transport rewrites the
    /// scheme/host/port to the real (plain-HTTP) wiremock server only after
    /// every upstream policy — including the auth guard and the actual
    /// bearer-token attachment — has already run.
    #[derive(Debug)]
    struct RedirectToMock {
        http_client: Arc<dyn azure_core::http::HttpClient>,
        target: azure_core::http::Url,
    }

    #[async_trait::async_trait]
    impl azure_core::http::policies::Policy for RedirectToMock {
        async fn send(
            &self,
            _ctx: &azure_core::http::Context,
            request: &mut azure_core::http::Request,
            _next: &[Arc<dyn azure_core::http::policies::Policy>],
        ) -> azure_core::http::policies::PolicyResult {
            let mut url = request.url().clone();
            let _ = url.set_scheme(self.target.scheme());
            let _ = url.set_host(self.target.host_str());
            let _ = url.set_port(self.target.port());
            *request.url_mut() = url;
            self.http_client.execute_request(request).await
        }
    }

    fn fake_client_for(server: &MockServer) -> SecretClient {
        super::super::ensure_default_crypto_provider();
        let target: azure_core::http::Url = server.uri().parse().expect("valid mock server url");
        let redirect = RedirectToMock {
            http_client: azure_core::http::new_http_client(None),
            target,
        };
        SecretClient::new(
            "https://fake-vault.example.invalid",
            Arc::new(FakeCredential) as Arc<dyn TokenCredential>,
            Some(SecretClientOptions {
                verify_challenge_resource: Some(false),
                client_options: azure_core::http::ClientOptions {
                    transport: Some(typespec_client_core::http::Transport::with_policy(
                        Arc::new(redirect),
                    )),
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .expect("build fake-credential client")
    }

    fn provider_for(server: &MockServer) -> AzureProvider {
        AzureProvider::from_client(fake_client_for(server), "vault-".to_owned())
    }

    /// Mounts the two-leg challenge dance for one `(method, path)` pair,
    /// then the real authenticated response.
    async fn mount_challenge_then(
        server: &MockServer,
        http_method: &str,
        secret_path: &str,
        status: u16,
        body: serde_json::Value,
    ) {
        Mock::given(method(http_method))
            .and(path(secret_path))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                "Bearer authorization=\"https://login.microsoftonline.com/t\", resource=\"https://vault.azure.net\"",
            ))
            .up_to_n_times(1)
            .mount(server)
            .await;
        Mock::given(method(http_method))
            .and(path(secret_path))
            .and(header("authorization", "Bearer fake-test-token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    // ── push_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn push_secret_reaches_the_real_key_vault_wire_protocol() {
        let server = MockServer::start().await;
        mount_challenge_then(
            &server,
            "PUT",
            "/secrets/vault-db-password",
            200,
            json!({"value": "hunter2", "id": format!("{}/secrets/vault-db-password/v1", server.uri())}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider
            .push_secret("db-password", "hunter2", "secret-1")
            .await;

        assert!(result.success, "{result:?}");
        assert_eq!(result.action, "updated");
        assert_eq!(result.external_ref, "vault-db-password");
        assert!(result.error.is_none());

        let requests = server.received_requests().await.expect("recording enabled");
        // Discovery (401) + authenticated retry (200).
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn push_secret_reports_failure_on_non_success_response() {
        let server = MockServer::start().await;
        mount_challenge_then(
            &server,
            "PUT",
            "/secrets/vault-x",
            400,
            json!({"error": {"code": "BadParameter", "message": "bad input"}}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.push_secret("x", "v", "secret-2").await;

        assert!(!result.success);
        assert_eq!(result.action, "skipped");
        assert!(result.error.is_some());
    }

    // ── pull_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pull_secret_returns_value_on_success() {
        let server = MockServer::start().await;
        // `get_secret`'s URL always includes the (here, empty — "latest")
        // version segment: `/secrets/{name}/{version}`, so with no version
        // requested this is `/secrets/vault-p/` — trailing slash included.
        mount_challenge_then(
            &server,
            "GET",
            "/secrets/vault-p/",
            200,
            json!({"value": "the-value", "id": format!("{}/secrets/vault-p/v1", server.uri())}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("vault-p").await;
        assert_eq!(result, Ok(Some("the-value".to_owned())));
    }

    #[tokio::test]
    async fn pull_secret_returns_none_when_not_found() {
        let server = MockServer::start().await;
        mount_challenge_then(
            &server,
            "GET",
            "/secrets/vault-missing/",
            404,
            json!({"error": {"code": "SecretNotFound", "message": "gone"}}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("vault-missing").await;
        assert_eq!(result, Ok(None));
    }

    // ── delete_secret ────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_returns_true_on_success() {
        let server = MockServer::start().await;
        mount_challenge_then(
            &server,
            "DELETE",
            "/secrets/vault-d",
            200,
            json!({"id": format!("{}/secrets/vault-d", server.uri()), "recoveryId": null}),
        )
        .await;
        let provider = provider_for(&server);

        assert_eq!(provider.delete_secret("vault-d").await, Ok(true));
    }

    #[tokio::test]
    async fn delete_secret_returns_false_when_not_found() {
        let server = MockServer::start().await;
        mount_challenge_then(
            &server,
            "DELETE",
            "/secrets/vault-missing",
            404,
            json!({"error": {"code": "SecretNotFound", "message": "gone"}}),
        )
        .await;
        let provider = provider_for(&server);

        assert_eq!(provider.delete_secret("vault-missing").await, Ok(false));
    }

    // ── list_secrets ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_filters_by_managed_tag() {
        let server = MockServer::start().await;
        let managed_id = format!("{}/secrets/vault-a", server.uri());
        let unmanaged_id = format!("{}/secrets/other", server.uri());
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                "Bearer authorization=\"https://login.microsoftonline.com/t\", resource=\"https://vault.azure.net\"",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(header("authorization", "Bearer fake-test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    {"id": managed_id, "tags": {"vault-managed": "true"}},
                    {"id": unmanaged_id, "tags": {}},
                ],
            })))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.list_secrets().await;
        assert_eq!(result, Ok(vec!["vault-a".to_owned()]));
    }

    // ── build_credential ─────────────────────────────────────────────────

    #[test]
    fn build_credential_uses_client_secret_when_all_three_fields_present() {
        let credentials = json!({"tenant_id": "t", "client_id": "c", "client_secret": "s"});
        assert!(AzureProvider::build_credential(&credentials).is_ok());
    }

    #[test]
    fn build_credential_falls_back_to_managed_identity_when_incomplete() {
        for credentials in [
            json!({}),
            json!({"tenant_id": "t"}),
            json!({"tenant_id": "t", "client_id": "c"}),
        ] {
            assert!(
                AzureProvider::build_credential(&credentials).is_ok(),
                "managed identity construction must succeed without network I/O for {credentials}"
            );
        }
    }

    #[test]
    fn new_requires_vault_url() {
        let result = AzureProvider::new(&json!({}), &json!({}));
        match result {
            Err(ProviderError::Failed(msg)) => assert!(msg.contains("vault_url")),
            Ok(_) => panic!("expected construction to fail without vault_url"),
        }
    }
}
