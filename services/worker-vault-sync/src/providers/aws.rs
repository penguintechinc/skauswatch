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
    pub fn new(credentials: &Value, config: &Value) -> Self {
        let region = str_field(credentials, "region")
            .or_else(|| str_field(config, "region"))
            .unwrap_or_else(|| "us-east-1".to_owned());
        let prefix = str_field(config, "secret_prefix").unwrap_or_else(|| "vault/".to_owned());

        let mut builder = aws_sdk_secretsmanager::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region));

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
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
}
