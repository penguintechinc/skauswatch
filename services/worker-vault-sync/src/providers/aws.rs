//! AWS Secrets Manager cloud provider. Rust port of
//! `icebox/services/sync-worker/providers/aws.py`.

use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_secretsmanager::types::Tag;
use serde_json::Value;

use super::{CloudProvider, ProviderError, SyncResult};

/// Tag applied to every secret Vault creates, so `list_secrets` can filter
/// to Vault-managed resources only (matches v1 `VAULT_TAG_KEY`/`_VALUE`).
const VAULT_TAG_KEY: &str = "vault:managed";
const VAULT_TAG_VALUE: &str = "true";

fn str_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Resolves the AWS region for an `AwsProvider`: `credentials.region`, then
/// `config.region`, then `us-east-1` — matches v1 `AwsProvider.__init__`.
/// Exposed (crate-private) so `handler.rs` can resolve the same region when
/// pre-fetching own-AWS federated credentials (see
/// [`AwsProvider::with_federated_fallback`]), without duplicating the
/// fallback chain.
pub(crate) fn resolve_region(credentials: &Value, config: &Value) -> String {
    str_field(credentials, "region")
        .or_else(|| str_field(config, "region"))
        .unwrap_or_else(|| "us-east-1".to_owned())
}

/// True when `credentials` carries a static `access_key_id`/`secret_access_key`
/// pair — the customer-supplied path [`AwsProvider`] always prefers. When
/// `false`, [`AwsProvider::with_federated_fallback`]'s `federated_credentials`
/// (if any) is used instead of leaving the client with no credentials
/// provider at all — today's behavior, which resolves to nothing on dal2
/// (see `docs/v2-port/aws-identity-runbook.md`).
pub(crate) fn has_static_credentials(credentials: &Value) -> bool {
    str_field(credentials, "access_key_id").is_some()
        && str_field(credentials, "secret_access_key").is_some()
}

/// Syncs secrets between Vault and AWS Secrets Manager.
pub struct AwsProvider {
    client: Client,
    prefix: String,
}

impl AwsProvider {
    /// Builds a client from the decrypted `credentials` blob and the
    /// integration's `config` (matches v1 `AwsProvider.__init__`: region
    /// falls back from credentials to config to `us-east-1`; the
    /// `secret_prefix` config key defaults to `vault/`).
    ///
    /// An optional `endpoint_url` config key overrides the regional AWS
    /// endpoint — not part of v1, added so integrations can point at a
    /// non-AWS-hosted Secrets-Manager-compatible endpoint (e.g. LocalStack,
    /// or the `wiremock` server this module's tests use) the same way
    /// `secret_prefix`/`region` are already sourced from `config`.
    ///
    /// The one production call site (`get_provider`) always goes through
    /// [`AwsProvider::with_federated_fallback`] instead, so this stays as a
    /// convenience constructor for this module's own pre-existing tests
    /// (equivalent to passing `federated_credentials: None`).
    #[allow(dead_code)]
    pub fn new(credentials: &Value, config: &Value) -> Self {
        Self::with_federated_fallback(credentials, config, None)
    }

    /// Same as [`AwsProvider::new`], but when `credentials` carries no
    /// static access-key/secret pair, uses `federated_credentials` —
    /// already resolved via
    /// `skauswatch_s3::credentials::federated_base_credentials` — as this
    /// worker's own-AWS identity instead of leaving the client with no
    /// credentials provider at all (today's behavior: the SDK's default
    /// credential-provider chain, which has nothing to resolve to on dal2
    /// — see `docs/v2-port/aws-identity-runbook.md`). `None` here preserves
    /// today's behavior exactly; a customer's static credentials, when
    /// present, always win over federation.
    pub fn with_federated_fallback(
        credentials: &Value,
        config: &Value,
        federated_credentials: Option<Credentials>,
    ) -> Self {
        let region = resolve_region(credentials, config);
        let prefix = str_field(config, "secret_prefix").unwrap_or_else(|| "vault/".to_owned());

        let mut builder = aws_sdk_secretsmanager::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region));

        if let Some(endpoint_url) = str_field(config, "endpoint_url") {
            builder = builder.endpoint_url(endpoint_url);
        }

        if let (Some(key), Some(secret)) = (
            str_field(credentials, "access_key_id"),
            str_field(credentials, "secret_access_key"),
        ) {
            let session_token = str_field(credentials, "session_token");
            builder = builder.credentials_provider(Credentials::new(
                key,
                secret,
                session_token,
                None,
                "vault-cloud-integration",
            ));
        } else if let Some(creds) = federated_credentials {
            builder = builder.credentials_provider(creds);
        }

        Self {
            client: Client::from_conf(builder.build()),
            prefix,
        }
    }

    fn secret_name(&self, name: &str) -> String {
        format!("{}{name}", self.prefix)
    }
}

#[async_trait::async_trait]
impl CloudProvider for AwsProvider {
    async fn push_secret(&self, name: &str, value: &str, secret_id: &str) -> SyncResult {
        let secret_name = self.secret_name(name);

        // Try update first (v1 parity: PutSecretValue, fall back to
        // CreateSecret on ResourceNotFoundException).
        match self
            .client
            .put_secret_value()
            .secret_id(&secret_name)
            .secret_string(value)
            .send()
            .await
        {
            Ok(_) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: secret_name,
                success: true,
                error: None,
                action: "updated".to_owned(),
            },
            Err(err) => {
                let is_not_found = err
                    .as_service_error()
                    .map(|e| e.is_resource_not_found_exception())
                    .unwrap_or(false);
                if !is_not_found {
                    return SyncResult {
                        secret_id: secret_id.to_owned(),
                        external_ref: secret_name,
                        success: false,
                        error: Some(err.to_string()),
                        action: "skipped".to_owned(),
                    };
                }

                let create = self
                    .client
                    .create_secret()
                    .name(&secret_name)
                    .secret_string(value)
                    .tags(
                        Tag::builder()
                            .key(VAULT_TAG_KEY)
                            .value(VAULT_TAG_VALUE)
                            .build(),
                    )
                    .tags(
                        Tag::builder()
                            .key("vault:secret_id")
                            .value(secret_id)
                            .build(),
                    )
                    .send()
                    .await;
                match create {
                    Ok(resp) => SyncResult {
                        secret_id: secret_id.to_owned(),
                        external_ref: resp.arn().unwrap_or(&secret_name).to_owned(),
                        success: true,
                        error: None,
                        action: "created".to_owned(),
                    },
                    Err(create_err) => SyncResult {
                        secret_id: secret_id.to_owned(),
                        external_ref: secret_name,
                        success: false,
                        error: Some(create_err.to_string()),
                        action: "skipped".to_owned(),
                    },
                }
            }
        }
    }

    async fn pull_secret(&self, external_ref: &str) -> Result<Option<String>, ProviderError> {
        match self
            .client
            .get_secret_value()
            .secret_id(external_ref)
            .send()
            .await
        {
            Ok(resp) => Ok(resp.secret_string().map(str::to_owned)),
            Err(err) => {
                let not_found = err
                    .as_service_error()
                    .map(|e| {
                        e.is_resource_not_found_exception() || e.is_invalid_request_exception()
                    })
                    .unwrap_or(false);
                if not_found {
                    Ok(None)
                } else {
                    Err(ProviderError::Failed(err.to_string()))
                }
            }
        }
    }

    async fn delete_secret(&self, external_ref: &str) -> Result<bool, ProviderError> {
        match self
            .client
            .delete_secret()
            .secret_id(external_ref)
            .recovery_window_in_days(7)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => {
                let not_found = err
                    .as_service_error()
                    .map(|e| e.is_resource_not_found_exception())
                    .unwrap_or(false);
                if not_found {
                    Ok(false)
                } else {
                    Err(ProviderError::Failed(err.to_string()))
                }
            }
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>, ProviderError> {
        let mut arns = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut req = self.client.list_secrets().filters(
                aws_sdk_secretsmanager::types::Filter::builder()
                    .key(aws_sdk_secretsmanager::types::FilterNameStringType::TagKey)
                    .values(VAULT_TAG_KEY)
                    .build(),
            );
            if let Some(token) = &next_token {
                req = req.next_token(token);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| ProviderError::Failed(e.to_string()))?;
            for secret in resp.secret_list() {
                arns.push(
                    secret
                        .arn()
                        .or(secret.name())
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
            next_token = resp.next_token().map(str::to_owned);
            if next_token.is_none() {
                break;
            }
        }
        Ok(arns)
    }
}

// ── AWS Secrets Manager wire-protocol tests ─────────────────────────────
//
// `aws_sdk_secretsmanager` speaks the AWS JSON 1.1 protocol: every operation
// is `POST /` with an `x-amz-target: secretsmanager.{Operation}` header and
// a JSON body; errors are a non-2xx status with `{"__type": "...",
// "message": "..."}`. `AwsProvider::new`'s `endpoint_url` config override
// (added alongside these tests) lets these point the real SDK client at a
// `wiremock` server instead of AWS, so the tests exercise the actual
// request-building/signing/response-parsing code, not a hand-rolled double.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{header, header_regex, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn secret_name_applies_configured_prefix() {
        let provider = AwsProvider::new(&serde_json::json!({}), &serde_json::json!({}));
        assert_eq!(provider.secret_name("db-password"), "vault/db-password");
    }

    #[test]
    fn secret_name_honors_custom_prefix() {
        let provider = AwsProvider::new(
            &serde_json::json!({}),
            &serde_json::json!({"secret_prefix": "myapp/"}),
        );
        assert_eq!(provider.secret_name("x"), "myapp/x");
    }

    /// Static test credentials — required so `AwsProvider::new` configures a
    /// `credentials_provider`; without one the SDK falls back to the default
    /// provider chain (env/IMDS/profile resolution), which is slow and
    /// network-dependent rather than failing fast, and is not what these
    /// tests want to exercise.
    fn test_credentials() -> Value {
        json!({"access_key_id": "AKIATEST", "secret_access_key": "test-secret"})
    }

    fn test_config(endpoint: &str) -> Value {
        json!({"endpoint_url": endpoint, "region": "us-east-1"})
    }

    fn provider_for(server: &MockServer) -> AwsProvider {
        AwsProvider::new(&test_credentials(), &test_config(&server.uri()))
    }

    /// AWS JSON 1.1 error body: `{"__type": ..., "message": ...}`. The
    /// exception name matches on the unqualified `__type` (no namespace
    /// prefix needed — see `aws-sdk-secretsmanager`'s `json_errors.rs`).
    fn error_body(exception: &str, message: &str) -> serde_json::Value {
        json!({"__type": exception, "message": message})
    }

    async fn mount_target(server: &MockServer, target: &str, status: u16, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-amz-target", format!("secretsmanager.{target}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    // ── push_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn push_secret_updates_existing_secret_via_put_secret_value() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            200,
            json!({"ARN": "arn:aws:secretsmanager:us-east-1:1:secret:vault/db-password", "Name": "vault/db-password", "VersionId": "v1"}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider
            .push_secret("db-password", "hunter2", "secret-1")
            .await;

        assert!(result.success);
        assert_eq!(result.action, "updated");
        assert_eq!(result.external_ref, "vault/db-password");
        assert_eq!(result.secret_id, "secret-1");
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn push_secret_creates_new_secret_when_put_reports_not_found() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            400,
            error_body("ResourceNotFoundException", "no such secret"),
        )
        .await;
        mount_target(
            &server,
            "CreateSecret",
            200,
            json!({"ARN": "arn:aws:secretsmanager:us-east-1:1:secret:vault/new-secret-Ab12", "Name": "vault/new-secret", "VersionId": "v1"}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider
            .push_secret("new-secret", "s3cr3t", "secret-2")
            .await;

        assert!(result.success);
        assert_eq!(result.action, "created");
        assert_eq!(
            result.external_ref,
            "arn:aws:secretsmanager:us-east-1:1:secret:vault/new-secret-Ab12"
        );

        let requests = server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(
            requests.len(),
            2,
            "expected PutSecretValue then CreateSecret"
        );
    }

    #[tokio::test]
    async fn push_secret_other_put_error_does_not_attempt_create() {
        let server = MockServer::start().await;
        // Only PutSecretValue is mocked; if the code incorrectly fell
        // through to CreateSecret on a non-not-found error, the second
        // request would hit an unmocked route and still be recorded.
        mount_target(
            &server,
            "PutSecretValue",
            400,
            error_body("InvalidParameterException", "bad input"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.push_secret("x", "v", "secret-3").await;

        assert!(!result.success);
        assert_eq!(result.action, "skipped");
        assert!(result.error.is_some());

        let requests = server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(requests.len(), 1, "CreateSecret must not be attempted");
    }

    #[tokio::test]
    async fn push_secret_create_secret_also_fails_after_not_found() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            400,
            error_body("ResourceNotFoundException", "no such secret"),
        )
        .await;
        mount_target(
            &server,
            "CreateSecret",
            400,
            error_body("InvalidParameterException", "create also invalid"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.push_secret("x", "v", "secret-4").await;

        assert!(!result.success);
        assert_eq!(result.action, "skipped");
        assert!(result.error.is_some());
    }

    // ── delete_secret ────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_returns_true_on_success() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "DeleteSecret",
            200,
            json!({"ARN": "arn:1", "Name": "vault/d", "DeletionDate": 1.0}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.delete_secret("vault/d").await;
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn delete_secret_returns_false_when_not_found() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "DeleteSecret",
            400,
            error_body("ResourceNotFoundException", "gone"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.delete_secret("vault/missing").await;
        assert_eq!(result, Ok(false));
    }

    #[tokio::test]
    async fn delete_secret_returns_err_on_other_failure() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "DeleteSecret",
            400,
            error_body("InvalidParameterException", "bad ref"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.delete_secret("vault/bad").await;
        assert!(matches!(result, Err(ProviderError::Failed(_))));
    }

    // ── pull_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pull_secret_returns_value_on_success() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "GetSecretValue",
            200,
            json!({"ARN": "arn:1", "Name": "vault/p", "SecretString": "the-value"}),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("vault/p").await;
        assert_eq!(result, Ok(Some("the-value".to_owned())));
    }

    #[tokio::test]
    async fn pull_secret_returns_none_when_not_found() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "GetSecretValue",
            400,
            error_body("ResourceNotFoundException", "gone"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("vault/missing").await;
        assert_eq!(result, Ok(None));
    }

    #[tokio::test]
    async fn pull_secret_returns_none_on_invalid_request() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "GetSecretValue",
            400,
            error_body("InvalidRequestException", "not in a valid state"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("vault/mid-delete").await;
        assert_eq!(result, Ok(None));
    }

    #[tokio::test]
    async fn pull_secret_returns_err_on_other_failure() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "GetSecretValue",
            400,
            error_body("InvalidParameterException", "bad ref"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("vault/bad").await;
        assert!(matches!(result, Err(ProviderError::Failed(_))));
    }

    // ── list_secrets ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_paginates_across_next_token() {
        let server = MockServer::start().await;
        // First page (no `NextToken` present in a fresh request): consumed
        // exactly once, then wiremock falls through to the second-mounted
        // mock — see `Mock::up_to_n_times` docs for this sequencing idiom.
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-amz-target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "SecretList": [{"ARN": "arn:1", "Name": "vault/a"}],
                "NextToken": "page2",
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-amz-target", "secretsmanager.ListSecrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "SecretList": [{"ARN": "arn:2", "Name": "vault/b"}],
            })))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.list_secrets().await;
        assert_eq!(result, Ok(vec!["arn:1".to_owned(), "arn:2".to_owned()]));
    }

    #[tokio::test]
    async fn list_secrets_returns_err_on_failure() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "ListSecrets",
            400,
            error_body("InvalidParameterException", "bad filter"),
        )
        .await;
        let provider = provider_for(&server);

        let result = provider.list_secrets().await;
        assert!(matches!(result, Err(ProviderError::Failed(_))));
    }

    // ── AwsProvider::new construction paths ─────────────────────────────

    #[tokio::test]
    async fn push_secret_without_static_credentials_falls_back_gracefully() {
        // No access_key_id/secret_access_key in credentials — exercises the
        // constructor branch that skips `.credentials_provider(...)`
        // entirely, leaving the client with no way to sign a request.
        // Still points `endpoint_url` at the local mock (with no route
        // mounted) so that IF the SDK attempted a network call despite
        // having no credentials, it would hit a fast local 404 rather than
        // stalling on an unreachable real AWS endpoint — but the expected
        // behavior is that request construction fails locally before any
        // request is dispatched, so `received_requests()` should stay empty.
        let server = MockServer::start().await;
        let provider = AwsProvider::new(&json!({}), &test_config(&server.uri()));

        let result = provider.push_secret("x", "v", "secret-5").await;

        assert!(!result.success);
        assert_eq!(result.action, "skipped");
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn region_falls_back_from_credentials_then_config_then_default() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            200,
            json!({"ARN": "arn:1", "Name": "vault/r", "VersionId": "v1"}),
        )
        .await;
        // Region only present under `credentials`, not `config` — exercises
        // the `str_field(credentials, "region")` preferred branch.
        let credentials = json!({
            "access_key_id": "AKIATEST",
            "secret_access_key": "test-secret",
            "region": "eu-west-1",
        });
        let config = json!({"endpoint_url": server.uri()});
        let provider = AwsProvider::new(&credentials, &config);

        let result = provider.push_secret("r", "v", "secret-6").await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn session_token_is_forwarded_when_present() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            200,
            json!({"ARN": "arn:1", "Name": "vault/s", "VersionId": "v1"}),
        )
        .await;
        let credentials = json!({
            "access_key_id": "AKIATEST",
            "secret_access_key": "test-secret",
            "session_token": "session-token-value",
        });
        let provider = AwsProvider::new(&credentials, &test_config(&server.uri()));

        // The session token only affects SigV4 signing, not the response
        // shape — this proves construction with a session token present
        // still produces a working, successfully-signed client.
        let result = provider.push_secret("s", "v", "secret-7").await;
        assert!(result.success);
    }

    // ── has_static_credentials / resolve_region ─────────────────────────

    #[test]
    fn has_static_credentials_requires_both_fields() {
        assert!(has_static_credentials(&json!({
            "access_key_id": "AK", "secret_access_key": "SK",
        })));
        assert!(!has_static_credentials(&json!({"access_key_id": "AK"})));
        assert!(!has_static_credentials(&json!({"secret_access_key": "SK"})));
        assert!(!has_static_credentials(&Value::Null));
        assert!(!has_static_credentials(&json!({})));
    }

    #[test]
    fn resolve_region_precedence_and_default() {
        assert_eq!(
            resolve_region(
                &json!({"region": "eu-west-1"}),
                &json!({"region": "us-west-2"})
            ),
            "eu-west-1"
        );
        assert_eq!(
            resolve_region(&json!({}), &json!({"region": "us-west-2"})),
            "us-west-2"
        );
        assert_eq!(resolve_region(&json!({}), &json!({})), "us-east-1");
    }

    // ── AwsProvider::with_federated_fallback ────────────────────────────

    #[tokio::test]
    async fn federated_fallback_used_when_no_static_credentials_present() {
        // No access_key_id/secret_access_key in `credentials` — the
        // federated `Credentials` override must be what actually signs the
        // request, proving `with_federated_fallback` reaches its `else`
        // branch rather than silently leaving the client unauthenticated
        // (today's pre-fix behavior, still exercised above by
        // `push_secret_without_static_credentials_falls_back_gracefully`
        // for the `federated_credentials: None` case).
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            200,
            json!({"ARN": "arn:1", "Name": "vault/fed", "VersionId": "v1"}),
        )
        .await;
        let federated = Credentials::new(
            "AKIAFEDERATED",
            "federatedSecret",
            Some("federated-session-token".to_owned()),
            None,
            "skauswatch-federated-base",
        );
        let provider = AwsProvider::with_federated_fallback(
            &json!({}),
            &test_config(&server.uri()),
            Some(federated),
        );

        let result = provider.push_secret("fed", "v", "secret-fed").await;
        assert!(result.success, "{result:?}");
    }

    #[tokio::test]
    async fn static_credentials_win_over_federated_fallback() {
        // Both a static pair AND a federated override are supplied —
        // static must win (matches `AwsProvider`'s customer-first
        // priority). SigV4's `Authorization` header embeds the signing
        // access-key-id in its `Credential=` component, so asserting on it
        // proves which credentials actually signed the request, not just
        // that a request was sent.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-amz-target", "secretsmanager.PutSecretValue"))
            .and(header_regex("Authorization", "Credential=AKIASTATIC/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ARN": "arn:1", "Name": "vault/precedence", "VersionId": "v1",
            })))
            .mount(&server)
            .await;

        let credentials =
            json!({"access_key_id": "AKIASTATIC", "secret_access_key": "staticSecret"});
        let federated = Credentials::new(
            "AKIAFEDERATED",
            "federatedSecret",
            None,
            None,
            "skauswatch-federated-base",
        );
        let provider = AwsProvider::with_federated_fallback(
            &credentials,
            &test_config(&server.uri()),
            Some(federated),
        );

        let result = provider.push_secret("precedence", "v", "secret-p").await;
        assert!(
            result.success,
            "expected the request signed with the static credentials to match the mock: {result:?}"
        );
    }
}
