//! GCP Secret Manager cloud provider. Rust port of
//! `icebox/services/sync-worker/providers/gcp.py`.

use std::collections::HashMap;

use google_cloud_gax::error::rpc::Code;
use google_cloud_gax::paginator::ItemPaginator as _;
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model::replication::Automatic;
use google_cloud_secretmanager_v1::model::{Replication, Secret, SecretPayload};
use serde_json::Value;

use super::{CloudProvider, ProviderError, SyncResult, str_field};

/// Label applied to every secret Vault creates, so `list_secrets` can filter
/// to Vault-managed resources only (matches v1 `ICEBOX_LABEL_KEY`/`_VALUE`,
/// renamed for the v2 rebrand). GCP labels are lowercase-only and forbid
/// colons/uppercase, hence underscores rather than AWS's `vault:managed`.
const VAULT_LABEL_KEY: &str = "vault_managed";
const VAULT_LABEL_VALUE: &str = "true";
const VAULT_SECRET_ID_LABEL: &str = "vault_secret_id";

/// Syncs secrets between Vault and GCP Secret Manager.
pub struct GcpProvider {
    client: SecretManagerService,
    project_id: String,
    prefix: String,
}

impl GcpProvider {
    /// Builds a client from the decrypted `credentials` blob and the
    /// integration's `config` (matches v1 `GcpProvider.__init__`: a service
    /// account JSON key when `credentials.service_account_json` is present
    /// (as a JSON object or a JSON-encoded string), else Application
    /// Default Credentials — works unmodified on GKE Workload Identity).
    ///
    /// An optional `config.endpoint_url` overrides the regional endpoint —
    /// not part of v1, added purely so integrations can point at a
    /// non-Google-hosted Secret-Manager-compatible endpoint the same way
    /// [`super::aws::AwsProvider`] does; this module's own tests instead use
    /// [`GcpProvider::from_client`] with [`SecretManagerService::from_stub`]
    /// (this SDK's first-class mock support), since a stub sidesteps the
    /// OAuth token exchange a wiremock endpoint alone can't intercept.
    pub async fn new(credentials: &Value, config: &Value) -> Result<Self, ProviderError> {
        let project_id = str_field(credentials, "project_id").ok_or_else(|| {
            ProviderError::Failed("gcp: credentials.project_id is required".to_owned())
        })?;
        let prefix = str_field(config, "secret_prefix").unwrap_or_else(|| "vault_".to_owned());

        let mut builder = SecretManagerService::builder();
        if let Some(endpoint) = str_field(config, "endpoint_url") {
            builder = builder.with_endpoint(endpoint);
        }
        if let Some(sa_json) = credentials.get("service_account_json") {
            let key: Value = match sa_json {
                Value::String(s) => serde_json::from_str(s).map_err(|e| {
                    ProviderError::Failed(format!("gcp: parse service_account_json: {e}"))
                })?,
                other => other.clone(),
            };
            let creds = google_cloud_auth::credentials::service_account::Builder::new(key)
                .build()
                .map_err(|e| {
                    ProviderError::Failed(format!("gcp: service account credentials: {e}"))
                })?;
            builder = builder.with_credentials(creds);
        }
        // else: default Application Default Credentials chain — matches v1's
        // fallback to `SecretManagerServiceClient()` with no explicit
        // credentials (works on GKE via Workload Identity).

        let client = builder
            .build()
            .await
            .map_err(|e| ProviderError::Failed(format!("gcp: build client: {e}")))?;
        Ok(Self::from_client(client, project_id, prefix))
    }

    /// Builds directly from an already-constructed client — the real
    /// [`GcpProvider::new`] uses this after resolving credentials; this
    /// module's tests use it with [`SecretManagerService::from_stub`].
    pub(crate) fn from_client(
        client: SecretManagerService,
        project_id: String,
        prefix: String,
    ) -> Self {
        Self {
            client,
            project_id,
            prefix,
        }
    }

    /// GCP secret IDs: alphanumeric, dashes, underscores (matches v1
    /// `_secret_id`).
    fn secret_id_for(&self, name: &str) -> String {
        let safe = name.replace(['/', '.', '-'], "_");
        format!("{}{safe}", self.prefix)
    }

    fn parent(&self) -> String {
        format!("projects/{}", self.project_id)
    }

    fn secret_path(&self, gcp_id: &str) -> String {
        format!("{}/secrets/{gcp_id}", self.parent())
    }

    fn version_path(&self, gcp_id: &str) -> String {
        format!("{}/versions/latest", self.secret_path(gcp_id))
    }

    fn code_of(err: &google_cloud_gax::error::Error) -> Option<Code> {
        err.status().map(|s| s.code)
    }
}

#[async_trait::async_trait]
impl CloudProvider for GcpProvider {
    async fn push_secret(&self, name: &str, value: &str, secret_id: &str) -> SyncResult {
        let gcp_id = self.secret_id_for(name);
        let mut labels = HashMap::new();
        labels.insert(VAULT_LABEL_KEY.to_owned(), VAULT_LABEL_VALUE.to_owned());
        labels.insert(
            VAULT_SECRET_ID_LABEL.to_owned(),
            secret_id
                .chars()
                .take(63)
                .collect::<String>()
                .to_lowercase(),
        );

        // Ensure the secret resource exists (create if missing, tolerate
        // AlreadyExists) — matches v1's create-then-add-version two-step.
        let secret = Secret::new()
            .set_replication(Replication::new().set_automatic(Automatic::new()))
            .set_labels(labels);
        let action = match self
            .client
            .create_secret()
            .set_parent(self.parent())
            .set_secret_id(&gcp_id)
            .set_secret(secret)
            .send()
            .await
        {
            Ok(_) => "created",
            Err(e) if Self::code_of(&e) == Some(Code::AlreadyExists) => "updated",
            Err(e) => {
                return SyncResult {
                    secret_id: secret_id.to_owned(),
                    external_ref: gcp_id,
                    success: false,
                    error: Some(e.to_string()),
                    action: "skipped".to_owned(),
                };
            }
        };

        let payload =
            SecretPayload::new().set_data(bytes::Bytes::copy_from_slice(value.as_bytes()));
        match self
            .client
            .add_secret_version()
            .set_parent(self.secret_path(&gcp_id))
            .set_payload(payload)
            .send()
            .await
        {
            Ok(_) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: gcp_id,
                success: true,
                error: None,
                action: action.to_owned(),
            },
            Err(e) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: gcp_id,
                success: false,
                error: Some(e.to_string()),
                action: "skipped".to_owned(),
            },
        }
    }

    async fn pull_secret(&self, external_ref: &str) -> Result<Option<String>, ProviderError> {
        match self
            .client
            .access_secret_version()
            .set_name(self.version_path(external_ref))
            .send()
            .await
        {
            Ok(resp) => {
                let value = resp
                    .payload
                    .map(|p| String::from_utf8_lossy(&p.data).into_owned());
                Ok(value)
            }
            Err(e) if Self::code_of(&e) == Some(Code::NotFound) => Ok(None),
            Err(e) => Err(ProviderError::Failed(e.to_string())),
        }
    }

    async fn delete_secret(&self, external_ref: &str) -> Result<bool, ProviderError> {
        match self
            .client
            .delete_secret()
            .set_name(self.secret_path(external_ref))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if Self::code_of(&e) == Some(Code::NotFound) => Ok(false),
            Err(e) => Err(ProviderError::Failed(e.to_string())),
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>, ProviderError> {
        let mut items = self
            .client
            .list_secrets()
            .set_parent(self.parent())
            .by_item();
        let mut ids = Vec::new();
        while let Some(secret) = items
            .next()
            .await
            .transpose()
            .map_err(|e: google_cloud_gax::error::Error| ProviderError::Failed(e.to_string()))?
        {
            let managed =
                secret.labels.get(VAULT_LABEL_KEY).map(String::as_str) == Some(VAULT_LABEL_VALUE);
            if managed {
                // Return just the id portion (last path segment), matching v1.
                if let Some(id) = secret.name.rsplit('/').next() {
                    ids.push(id.to_owned());
                }
            }
        }
        Ok(ids)
    }
}

// ── GCP Secret Manager stub-based tests ─────────────────────────────────
//
// `google-cloud-secretmanager-v1` ships first-class mock support
// (`stub::SecretManagerService` + `SecretManagerService::from_stub`) instead
// of the wiremock-a-real-HTTP-endpoint technique the AWS/Azure/Kubernetes
// providers use — a real request here would first need a real OAuth token
// exchange with Google (service-account JWT assertion -> access token),
// which a wiremock endpoint alone can't intercept. The stub sidesteps that
// entirely: it implements the same trait the generated client's transport
// layer implements, so these tests exercise the exact same request-building
// (`GcpProvider`'s own code) and response-interpretation logic without any
// network I/O at all.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use google_cloud_gax::error::Error as GaxError;
    use google_cloud_gax::error::rpc::{Code, Status};
    use google_cloud_gax::options::RequestOptions;
    use google_cloud_gax::response::Response;
    use google_cloud_secretmanager_v1::Result as GcpResult;
    use google_cloud_secretmanager_v1::model::{
        AccessSecretVersionRequest, AccessSecretVersionResponse, AddSecretVersionRequest,
        CreateSecretRequest, DeleteSecretRequest, ListSecretsRequest, ListSecretsResponse, Secret,
        SecretVersion,
    };

    use super::*;

    fn service_error(code: Code, message: &str) -> GaxError {
        GaxError::service(Status::default().set_code(code).set_message(message))
    }

    /// A [`super::super::stub::SecretManagerService`]-implementing double —
    /// each method's canned outcome is set independently, consumed exactly
    /// once via `Mutex::take` (every test here calls each configured RPC at
    /// most once; `GaxError` isn't `Clone`, so a reusable/repeatable canned
    /// value isn't an option). Unconfigured methods fall back to the
    /// trait's own "unimplemented" default, which surfaces as a clear test
    /// failure rather than a silent success.
    #[derive(Default)]
    struct FakeStub {
        create_secret: Mutex<Option<GcpResult<Secret>>>,
        add_secret_version: Mutex<Option<GcpResult<SecretVersion>>>,
        access_secret_version: Mutex<Option<GcpResult<AccessSecretVersionResponse>>>,
        delete_secret: Mutex<Option<GcpResult<()>>>,
        list_secrets: Mutex<Option<GcpResult<ListSecretsResponse>>>,
    }

    impl std::fmt::Debug for FakeStub {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeStub").finish()
        }
    }

    impl google_cloud_secretmanager_v1::stub::SecretManagerService for FakeStub {
        async fn create_secret(
            &self,
            _req: CreateSecretRequest,
            _options: RequestOptions,
        ) -> GcpResult<Response<Secret>> {
            match self
                .create_secret
                .lock()
                .expect("lock")
                .take()
                .expect("create_secret not configured")
            {
                Ok(s) => Ok(Response::from(s)),
                Err(e) => Err(e),
            }
        }

        async fn add_secret_version(
            &self,
            _req: AddSecretVersionRequest,
            _options: RequestOptions,
        ) -> GcpResult<Response<SecretVersion>> {
            match self
                .add_secret_version
                .lock()
                .expect("lock")
                .take()
                .expect("add_secret_version not configured")
            {
                Ok(v) => Ok(Response::from(v)),
                Err(e) => Err(e),
            }
        }

        async fn access_secret_version(
            &self,
            _req: AccessSecretVersionRequest,
            _options: RequestOptions,
        ) -> GcpResult<Response<AccessSecretVersionResponse>> {
            match self
                .access_secret_version
                .lock()
                .expect("lock")
                .take()
                .expect("access_secret_version not configured")
            {
                Ok(r) => Ok(Response::from(r)),
                Err(e) => Err(e),
            }
        }

        async fn delete_secret(
            &self,
            _req: DeleteSecretRequest,
            _options: RequestOptions,
        ) -> GcpResult<Response<()>> {
            match self
                .delete_secret
                .lock()
                .expect("lock")
                .take()
                .expect("delete_secret not configured")
            {
                Ok(()) => Ok(Response::from(())),
                Err(e) => Err(e),
            }
        }

        async fn list_secrets(
            &self,
            _req: ListSecretsRequest,
            _options: RequestOptions,
        ) -> GcpResult<Response<ListSecretsResponse>> {
            match self
                .list_secrets
                .lock()
                .expect("lock")
                .take()
                .expect("list_secrets not configured")
            {
                Ok(r) => Ok(Response::from(r)),
                Err(e) => Err(e),
            }
        }
    }

    fn provider_with(stub: FakeStub) -> GcpProvider {
        let client = SecretManagerService::from_stub(stub);
        GcpProvider::from_client(client, "test-project".to_owned(), "vault_".to_owned())
    }

    // ── secret_id_for / paths ────────────────────────────────────────────

    #[test]
    fn secret_id_for_applies_prefix_and_sanitizes() {
        let provider = provider_with(FakeStub::default());
        assert_eq!(provider.secret_id_for("db-password"), "vault_db_password");
        assert_eq!(provider.secret_id_for("app/db.name"), "vault_app_db_name");
    }

    #[test]
    fn paths_are_well_formed() {
        let provider = provider_with(FakeStub::default());
        assert_eq!(provider.parent(), "projects/test-project");
        assert_eq!(
            provider.secret_path("s1"),
            "projects/test-project/secrets/s1"
        );
        assert_eq!(
            provider.version_path("s1"),
            "projects/test-project/secrets/s1/versions/latest"
        );
    }

    // ── push_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn push_secret_creates_when_no_existing_secret() {
        let provider = provider_with(FakeStub {
            create_secret: Mutex::new(Some(Ok(
                Secret::new().set_name("projects/test-project/secrets/vault_db_password")
            ))),
            add_secret_version: Mutex::new(Some(Ok(SecretVersion::new()))),
            ..Default::default()
        });

        let result = provider
            .push_secret("db-password", "hunter2", "secret-1")
            .await;

        assert!(result.success, "{result:?}");
        assert_eq!(result.action, "created");
        assert_eq!(result.external_ref, "vault_db_password");
    }

    #[tokio::test]
    async fn push_secret_updates_when_secret_already_exists() {
        let provider = provider_with(FakeStub {
            create_secret: Mutex::new(Some(Err(service_error(
                Code::AlreadyExists,
                "already exists",
            )))),
            add_secret_version: Mutex::new(Some(Ok(SecretVersion::new()))),
            ..Default::default()
        });

        let result = provider
            .push_secret("db-password", "hunter2", "secret-2")
            .await;

        assert!(result.success, "{result:?}");
        assert_eq!(result.action, "updated");
    }

    #[tokio::test]
    async fn push_secret_reports_create_failure_other_than_already_exists() {
        let provider = provider_with(FakeStub {
            create_secret: Mutex::new(Some(Err(service_error(Code::PermissionDenied, "denied")))),
            ..Default::default()
        });

        let result = provider.push_secret("x", "v", "secret-3").await;

        assert!(!result.success);
        assert_eq!(result.action, "skipped");
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn push_secret_reports_add_version_failure() {
        let provider = provider_with(FakeStub {
            create_secret: Mutex::new(Some(Ok(Secret::new()))),
            add_secret_version: Mutex::new(Some(Err(service_error(Code::Internal, "boom")))),
            ..Default::default()
        });

        let result = provider.push_secret("x", "v", "secret-4").await;

        assert!(!result.success);
        assert_eq!(result.action, "skipped");
    }

    // ── pull_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pull_secret_returns_value_on_success() {
        let payload = SecretPayload::new().set_data(bytes::Bytes::from_static(b"the-value"));
        let provider = provider_with(FakeStub {
            access_secret_version: Mutex::new(Some(Ok(
                AccessSecretVersionResponse::new().set_payload(payload)
            ))),
            ..Default::default()
        });

        let result = provider.pull_secret("vault_p").await;
        assert_eq!(result, Ok(Some("the-value".to_owned())));
    }

    #[tokio::test]
    async fn pull_secret_returns_none_when_not_found() {
        let provider = provider_with(FakeStub {
            access_secret_version: Mutex::new(Some(Err(service_error(Code::NotFound, "gone")))),
            ..Default::default()
        });

        let result = provider.pull_secret("vault_missing").await;
        assert_eq!(result, Ok(None));
    }

    // ── delete_secret ────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_returns_true_on_success() {
        let provider = provider_with(FakeStub {
            delete_secret: Mutex::new(Some(Ok(()))),
            ..Default::default()
        });
        assert_eq!(provider.delete_secret("vault_d").await, Ok(true));
    }

    #[tokio::test]
    async fn delete_secret_returns_false_when_not_found() {
        let provider = provider_with(FakeStub {
            delete_secret: Mutex::new(Some(Err(service_error(Code::NotFound, "gone")))),
            ..Default::default()
        });
        assert_eq!(provider.delete_secret("vault_missing").await, Ok(false));
    }

    // ── list_secrets ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_filters_by_managed_label() {
        let mut managed_labels = std::collections::HashMap::new();
        managed_labels.insert(VAULT_LABEL_KEY.to_owned(), VAULT_LABEL_VALUE.to_owned());
        let managed = Secret::new()
            .set_name("projects/test-project/secrets/vault_a")
            .set_labels(managed_labels);
        let unmanaged = Secret::new().set_name("projects/test-project/secrets/other");

        let provider = provider_with(FakeStub {
            list_secrets: Mutex::new(Some(Ok(
                ListSecretsResponse::new().set_secrets([managed, unmanaged])
            ))),
            ..Default::default()
        });

        let result = provider.list_secrets().await;
        assert_eq!(result, Ok(vec!["vault_a".to_owned()]));
    }
}
