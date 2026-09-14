//! Oracle Cloud Infrastructure (OCI) Vault cloud provider. Rust port of
//! `icebox/services/sync-worker/providers/oracle.py`.
//!
//! **The one provider that is not an SDK swap** — no mature Rust SDK exists
//! for OCI. This is `reqwest` plus hand-rolled RSA-SHA256 request signing
//! (see [`signing`]), per `docs/v2-port/phase12-scope-infra.md` §1's L-effort
//! flag for this item.

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CloudProvider, ProviderError, SyncResult, str_field};

const VAULT_TAG_MANAGED_KEY: &str = "vault-managed";
const VAULT_TAG_MANAGED_VALUE: &str = "true";
const VAULT_TAG_SECRET_ID_KEY: &str = "vault-secret-id";

/// OCI's [request-signing scheme][sign]: RSA-SHA256 over a canonical subset
/// of headers, referenced from a `keyId` of `{tenancy}/{user}/{fingerprint}`.
///
/// [sign]: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
pub mod signing {
    use base64::Engine as _;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::sha2::{Digest, Sha256};
    use rsa::signature::Signer as _;

    /// A parsed OCI API signing key — an RSA private key plus the identity
    /// fields that make up `keyId`. Passphrase-protected keys are not
    /// supported (a documented, deliberate scope limit — see
    /// [`super::OracleProvider::new`]).
    pub struct SigningIdentity {
        signing_key: SigningKey<Sha256>,
        key_id: String,
    }

    impl SigningIdentity {
        /// Parses `private_key_pem` (PKCS#1 `RSA PRIVATE KEY` or PKCS#8
        /// `PRIVATE KEY`, unencrypted) and builds the `{tenancy}/{user}/
        /// {fingerprint}` key id OCI expects.
        pub fn new(
            private_key_pem: &str,
            tenancy: &str,
            user: &str,
            fingerprint: &str,
        ) -> Result<Self, String> {
            let key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_pem))
                .map_err(|e| {
                    format!("invalid RSA private key (PKCS#1/PKCS#8 only, unencrypted): {e}")
                })?;
            Ok(Self {
                signing_key: SigningKey::<Sha256>::new(key),
                key_id: format!("{tenancy}/{user}/{fingerprint}"),
            })
        }

        /// Builds the `Authorization` header value for one request, plus the
        /// other headers that must accompany it (`date`, `host`, and — for
        /// requests with a body — `content-length`/`content-type`/
        /// `x-content-sha256`). `body` is `None` for GET/DELETE.
        pub fn sign(
            &self,
            method: &str,
            path_and_query: &str,
            host: &str,
            date: &str,
            body: Option<&[u8]>,
        ) -> Vec<(String, String)> {
            let mut headers: Vec<(String, String)> = vec![
                (
                    "(request-target)".to_owned(),
                    format!("{} {path_and_query}", method.to_lowercase()),
                ),
                ("date".to_owned(), date.to_owned()),
                ("host".to_owned(), host.to_owned()),
            ];
            let mut extra: Vec<(String, String)> = Vec::new();
            if let Some(body) = body {
                let content_length = body.len().to_string();
                let content_type = "application/json".to_owned();
                let digest = Sha256::digest(body);
                let x_content_sha256 = base64::engine::general_purpose::STANDARD.encode(digest);
                headers.push(("content-length".to_owned(), content_length.clone()));
                headers.push(("content-type".to_owned(), content_type.clone()));
                headers.push(("x-content-sha256".to_owned(), x_content_sha256.clone()));
                extra.push(("content-length".to_owned(), content_length));
                extra.push(("content-type".to_owned(), content_type));
                extra.push(("x-content-sha256".to_owned(), x_content_sha256));
            }

            let signing_string = headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\n");
            let signature = self.signing_key.sign(signing_string.as_bytes());
            let signature_bytes: Box<[u8]> = signature.into();
            let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature_bytes);
            let header_names = headers
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let authorization = format!(
                "Signature version=\"1\",headers=\"{header_names}\",keyId=\"{}\",algorithm=\"rsa-sha256\",signature=\"{signature_b64}\"",
                self.key_id
            );

            let mut result = vec![
                ("date".to_owned(), date.to_owned()),
                ("authorization".to_owned(), authorization),
            ];
            result.extend(extra);
            result
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod tests {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier as _;
        use std::sync::LazyLock;

        use super::*;

        // A fresh, throwaway 2048-bit RSA key generated once per test-binary
        // run (not committed — see `providers::test_support`, and the doc
        // comment on `signature_verifies_against_an_independently_derived_public_key`
        // below for why generated-and-verified replaced a fixed known-vector).
        static TEST_KEY_PEM: LazyLock<String> =
            LazyLock::new(crate::providers::test_support::generate_rsa_private_key_pem);

        #[test]
        fn sign_produces_a_well_formed_authorization_header() {
            let identity = SigningIdentity::new(&TEST_KEY_PEM, "tenancy1", "user1", "fp:1:2:3")
                .expect("parse key");
            let headers = identity.sign(
                "get",
                "/20180608/secrets?compartmentId=c1",
                "vaults.us-ashburn-1.oci.oraclecloud.com",
                "Thu, 05 Jan 2023 22:57:22 GMT",
                None,
            );
            let auth = headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.clone())
                .expect("authorization header present");

            assert!(auth.starts_with("Signature version=\"1\","));
            assert!(auth.contains("headers=\"(request-target) date host\""));
            assert!(auth.contains("keyId=\"tenancy1/user1/fp:1:2:3\""));
            assert!(auth.contains("algorithm=\"rsa-sha256\""));
            assert!(auth.contains("signature=\""));
        }

        #[test]
        fn sign_includes_body_headers_for_a_request_with_a_payload() {
            let identity = SigningIdentity::new(&TEST_KEY_PEM, "t", "u", "fp").expect("parse key");
            let body = br#"{"hello":"world"}"#;
            let headers = identity.sign(
                "post",
                "/20180608/secrets",
                "vaults.us-ashburn-1.oci.oraclecloud.com",
                "Thu, 05 Jan 2023 22:57:22 GMT",
                Some(body),
            );
            let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
            assert!(names.contains(&"content-length"));
            assert!(names.contains(&"content-type"));
            assert!(names.contains(&"x-content-sha256"));

            let auth = headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.clone())
                .expect("authorization header present");
            assert!(auth.contains(
                "headers=\"(request-target) date host content-length content-type x-content-sha256\""
            ));
        }

        /// Round-trip test: verifies the signature `sign()` produces is a
        /// valid RSA-SHA256/PKCS#1v1.5 signature over the OCI canonical
        /// signing string, using a public key independently derived from
        /// the (freshly generated, per-run) private key and a *different*
        /// code path than the one that produced it — [`VerifyingKey`]
        /// instead of the [`SigningKey`] `sign()` uses internally.
        ///
        /// This replaces a fixed-key/fixed-expected-signature vector
        /// cross-checked against `openssl dgst -sha256 -sign`: that
        /// approach required a private key fixed enough to commit to the
        /// repo, which a secret scanner (rightly) treats as a live RSA key
        /// regardless of "test-only" intent. A per-run generated key can't
        /// be pinned to a precomputed expected signature, so verification
        /// against an independently-derived public key is what proves
        /// correctness instead — the expected signing string below is
        /// written out per the OCI signing spec directly (not read out of
        /// `sign()`'s internals), so a canonicalization bug in `sign()`
        /// still fails this test rather than trivially self-validating.
        #[test]
        fn signature_verifies_against_an_independently_derived_public_key() {
            let identity = SigningIdentity::new(&TEST_KEY_PEM, "tenancy1", "user1", "fp:1:2:3")
                .expect("parse key");
            let headers = identity.sign(
                "get",
                "/20180608/secrets?compartmentId=c1",
                "vaults.us-ashburn-1.oci.oraclecloud.com",
                "Thu, 05 Jan 2023 22:57:22 GMT",
                None,
            );
            let auth = headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.clone())
                .expect("authorization header present");
            let signature_b64 = auth
                .split("signature=\"")
                .nth(1)
                .and_then(|s| s.strip_suffix('"'))
                .expect("signature field present");
            let signature_bytes = base64::engine::general_purpose::STANDARD
                .decode(signature_b64)
                .expect("signature is valid base64");
            let signature = Signature::try_from(signature_bytes.as_slice())
                .expect("valid PKCS#1v1.5 signature");

            // Independently reconstructed per the OCI signing spec — same
            // string the reproduction snippet this test used to hand to
            // `openssl dgst` before the fixture was removed.
            let signing_string = "(request-target): get /20180608/secrets?compartmentId=c1\n\
                date: Thu, 05 Jan 2023 22:57:22 GMT\n\
                host: vaults.us-ashburn-1.oci.oraclecloud.com";

            let private_key = RsaPrivateKey::from_pkcs1_pem(&TEST_KEY_PEM).expect("parse test key");
            let verifying_key = VerifyingKey::<Sha256>::new(private_key.to_public_key());
            verifying_key
                .verify(signing_string.as_bytes(), &signature)
                .expect("signature verifies against independently derived public key");
        }
    }
}

/// Syncs secrets between Vault and Oracle Cloud Infrastructure (OCI) Vault.
pub struct OracleProvider {
    http: reqwest::Client,
    identity: signing::SigningIdentity,
    compartment_id: String,
    vault_id: String,
    vault_key_id: String,
    vaults_host: String,
    vaults_base: String,
    secrets_host: String,
    secrets_base: String,
    prefix: String,
}

#[derive(Deserialize)]
struct OciSecretSummary {
    id: String,
    #[serde(rename = "freeformTags", default)]
    freeform_tags: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct OciSecret {
    id: String,
}

#[derive(Deserialize)]
struct OciSecretBundle {
    #[serde(rename = "secretBundleContent")]
    secret_bundle_content: OciSecretBundleContent,
}

#[derive(Deserialize)]
struct OciSecretBundleContent {
    content: String,
}

#[derive(Deserialize)]
struct OciErrorBody {
    #[serde(default)]
    message: String,
}

impl OracleProvider {
    /// Builds a client from the decrypted `credentials` blob and the
    /// integration's `config` (matches v1 `OracleProvider.__init__`).
    /// Encrypted (passphrase-protected) private keys are not supported —
    /// deliberately out of scope for this restoration pass (no mature
    /// pure-Rust encrypted-PKCS#8 decoder wired up here); such a key fails
    /// construction with a clear error rather than being silently mishandled.
    pub fn new(credentials: &Value, config: &Value) -> Result<Self, ProviderError> {
        let user = str_field(credentials, "user").ok_or_else(|| {
            ProviderError::Failed("oracle: credentials.user is required".to_owned())
        })?;
        let private_key_pem = str_field(credentials, "private_key_pem").ok_or_else(|| {
            ProviderError::Failed("oracle: credentials.private_key_pem is required".to_owned())
        })?;
        let fingerprint = str_field(credentials, "fingerprint").ok_or_else(|| {
            ProviderError::Failed("oracle: credentials.fingerprint is required".to_owned())
        })?;
        let tenancy = str_field(credentials, "tenancy").ok_or_else(|| {
            ProviderError::Failed("oracle: credentials.tenancy is required".to_owned())
        })?;
        let region = str_field(credentials, "region").unwrap_or_else(|| "us-ashburn-1".to_owned());
        let compartment_id = str_field(credentials, "compartment_id").ok_or_else(|| {
            ProviderError::Failed("oracle: credentials.compartment_id is required".to_owned())
        })?;
        let vault_id = str_field(credentials, "vault_id").ok_or_else(|| {
            ProviderError::Failed("oracle: credentials.vault_id is required".to_owned())
        })?;
        let vault_key_id = str_field(credentials, "vault_key_id").ok_or_else(|| {
            ProviderError::Failed("oracle: credentials.vault_key_id is required".to_owned())
        })?;
        let prefix = str_field(config, "secret_prefix").unwrap_or_else(|| "vault-".to_owned());

        if credentials.get("private_key_passphrase").is_some() {
            return Err(ProviderError::Failed(
                "oracle: passphrase-protected private keys are not supported".to_owned(),
            ));
        }

        let identity =
            signing::SigningIdentity::new(&private_key_pem, &tenancy, &user, &fingerprint)
                .map_err(|e| ProviderError::Failed(format!("oracle: {e}")))?;

        // Test-only overrides (config keys, not credentials — same
        // `endpoint_url`-for-testability pattern as `AwsProvider`), so
        // wiremock can stand in for OCI's control-plane (`vaults.*`) and
        // data-plane (`secrets.*`) hosts independently.
        let vaults_base = str_field(config, "vaults_endpoint")
            .unwrap_or_else(|| format!("https://vaults.{region}.oci.oraclecloud.com"));
        let secrets_base = str_field(config, "secrets_endpoint")
            .unwrap_or_else(|| format!("https://secrets.{region}.oci.oraclecloud.com"));
        let vaults_host = host_of(&vaults_base);
        let secrets_host = host_of(&secrets_base);

        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ProviderError::Failed(format!("oracle: build http client: {e}")))?;

        Ok(Self {
            http,
            identity,
            compartment_id,
            vault_id,
            vault_key_id,
            vaults_host,
            vaults_base,
            secrets_host,
            secrets_base,
            prefix,
        })
    }

    /// OCI secret names: alphanumeric, dashes, underscores (matches v1
    /// `_secret_name`).
    fn secret_name_for(&self, name: &str) -> String {
        let safe = name.replace(['/', '.'], "-");
        format!("{}{safe}", self.prefix)
    }

    async fn signed_request(
        &self,
        method: reqwest::Method,
        base: &str,
        host: &str,
        path_and_query: &str,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, String> {
        let date = http_date_now();
        let signed = self.identity.sign(
            method.as_str(),
            path_and_query,
            host,
            &date,
            body.as_deref(),
        );

        let url = format!("{base}{path_and_query}");
        let mut req = self.http.request(method, url);
        for (name, value) in signed {
            req = req.header(name, value);
        }
        if let Some(body) = body {
            req = req.body(body);
        }
        req.send().await.map_err(|e| e.to_string())
    }

    /// Looks up an existing secret's OCID by name, if any — mirrors v1's
    /// pre-push `list_secrets(..., name=oci_name)` existence check.
    async fn find_existing(&self, oci_name: &str) -> Result<Option<String>, String> {
        let path = format!(
            "/20180608/secrets?compartmentId={}&vaultId={}&name={}",
            urlenc(&self.compartment_id),
            urlenc(&self.vault_id),
            urlenc(oci_name),
        );
        let resp = self
            .signed_request(
                reqwest::Method::GET,
                &self.vaults_base,
                &self.vaults_host,
                &path,
                None,
            )
            .await?;
        if !resp.status().is_success() {
            return Err(format!("list_secrets failed: HTTP {}", resp.status()));
        }
        let items: Vec<OciSecretSummary> = resp.json().await.map_err(|e| e.to_string())?;
        Ok(items.into_iter().next().map(|s| s.id))
    }
}

/// RFC 7231 HTTP-date (`Thu, 05 Jan 2023 22:57:22 GMT`), required for OCI's
/// `date` signed header — chrono's `%a`/`%b` are always English abbreviations
/// regardless of system locale, so no extra locale handling is needed.
fn http_date_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn host_of(base_url: &str) -> String {
    base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned()
}

/// Minimal percent-encoding for query-string values — OCI's REST filters
/// (`name`, resource OCIDs) never contain characters outside this set in
/// practice, but names come from a customer-supplied Vault secret name, so
/// this still encodes defensively rather than assuming.
fn urlenc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[async_trait::async_trait]
impl CloudProvider for OracleProvider {
    async fn push_secret(&self, name: &str, value: &str, secret_id: &str) -> SyncResult {
        let oci_name = self.secret_name_for(name);
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        let freeform_tags = json!({
            VAULT_TAG_MANAGED_KEY: VAULT_TAG_MANAGED_VALUE,
            VAULT_TAG_SECRET_ID_KEY: secret_id,
        });

        let existing = match self.find_existing(&oci_name).await {
            Ok(existing) => existing,
            Err(e) => {
                return SyncResult {
                    secret_id: secret_id.to_owned(),
                    external_ref: oci_name,
                    success: false,
                    error: Some(e),
                    action: "skipped".to_owned(),
                };
            }
        };

        let (method, path, body_json, action) = match &existing {
            Some(existing_id) => (
                reqwest::Method::PUT,
                format!("/20180608/secrets/{}", urlenc(existing_id)),
                json!({
                    "secretContent": {"contentType": "BASE64", "content": encoded},
                    "freeformTags": freeform_tags,
                }),
                "updated",
            ),
            None => (
                reqwest::Method::POST,
                "/20180608/secrets".to_owned(),
                json!({
                    "compartmentId": self.compartment_id,
                    "vaultId": self.vault_id,
                    "keyId": self.vault_key_id,
                    "secretName": oci_name,
                    "secretContent": {"contentType": "BASE64", "content": encoded},
                    "freeformTags": freeform_tags,
                }),
                "created",
            ),
        };
        let body = match serde_json::to_vec(&body_json) {
            Ok(b) => b,
            Err(e) => {
                return SyncResult {
                    secret_id: secret_id.to_owned(),
                    external_ref: oci_name,
                    success: false,
                    error: Some(format!("serialize request: {e}")),
                    action: "skipped".to_owned(),
                };
            }
        };

        let resp = self
            .signed_request(
                method,
                &self.vaults_base,
                &self.vaults_host,
                &path,
                Some(body),
            )
            .await;
        match resp {
            Ok(resp) if resp.status().is_success() => {
                let external_ref = match existing {
                    Some(id) => id,
                    None => match resp.json::<OciSecret>().await {
                        Ok(s) => s.id,
                        Err(e) => {
                            return SyncResult {
                                secret_id: secret_id.to_owned(),
                                external_ref: oci_name,
                                success: false,
                                error: Some(format!("parse create response: {e}")),
                                action: "skipped".to_owned(),
                            };
                        }
                    },
                };
                SyncResult {
                    secret_id: secret_id.to_owned(),
                    external_ref,
                    success: true,
                    error: None,
                    action: action.to_owned(),
                }
            }
            Ok(resp) => {
                let status = resp.status();
                let message = resp
                    .json::<OciErrorBody>()
                    .await
                    .map(|b| b.message)
                    .unwrap_or_else(|_| format!("HTTP {status}"));
                SyncResult {
                    secret_id: secret_id.to_owned(),
                    external_ref: oci_name,
                    success: false,
                    error: Some(message),
                    action: "skipped".to_owned(),
                }
            }
            Err(e) => SyncResult {
                secret_id: secret_id.to_owned(),
                external_ref: oci_name,
                success: false,
                error: Some(e),
                action: "skipped".to_owned(),
            },
        }
    }

    async fn pull_secret(&self, external_ref: &str) -> Result<Option<String>, ProviderError> {
        let path = format!("/20190301/secretbundles/{}", urlenc(external_ref));
        let resp = self
            .signed_request(
                reqwest::Method::GET,
                &self.secrets_base,
                &self.secrets_host,
                &path,
                None,
            )
            .await
            .map_err(ProviderError::Failed)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(ProviderError::Failed(format!(
                "get_secret_bundle failed: HTTP {}",
                resp.status()
            )));
        }
        let bundle: OciSecretBundle = resp
            .json()
            .await
            .map_err(|e| ProviderError::Failed(e.to_string()))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(bundle.secret_bundle_content.content)
            .map_err(|e| ProviderError::Failed(format!("decode secret bundle content: {e}")))?;
        Ok(Some(String::from_utf8_lossy(&decoded).into_owned()))
    }

    async fn delete_secret(&self, external_ref: &str) -> Result<bool, ProviderError> {
        let path = format!(
            "/20180608/secrets/{}/actions/scheduleDeletion",
            urlenc(external_ref)
        );
        // Matches v1: schedule deletion 30 days out (OCI Vault has no
        // synchronous hard-delete — this is the equivalent of AWS's
        // `recovery_window_in_days`).
        let time_of_deletion = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
        let body = serde_json::to_vec(&json!({"timeOfDeletion": time_of_deletion}))
            .map_err(|e| ProviderError::Failed(format!("serialize request: {e}")))?;
        let resp = self
            .signed_request(
                reqwest::Method::POST,
                &self.vaults_base,
                &self.vaults_host,
                &path,
                Some(body),
            )
            .await
            .map_err(ProviderError::Failed)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            return Err(ProviderError::Failed(format!(
                "schedule_secret_deletion failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(true)
    }

    async fn list_secrets(&self) -> Result<Vec<String>, ProviderError> {
        let path = format!(
            "/20180608/secrets?compartmentId={}&vaultId={}",
            urlenc(&self.compartment_id),
            urlenc(&self.vault_id),
        );
        let resp = self
            .signed_request(
                reqwest::Method::GET,
                &self.vaults_base,
                &self.vaults_host,
                &path,
                None,
            )
            .await
            .map_err(ProviderError::Failed)?;
        if !resp.status().is_success() {
            return Err(ProviderError::Failed(format!(
                "list_secrets failed: HTTP {}",
                resp.status()
            )));
        }
        let items: Vec<OciSecretSummary> = resp
            .json()
            .await
            .map_err(|e| ProviderError::Failed(e.to_string()))?;
        Ok(items
            .into_iter()
            .filter(|s| {
                s.freeform_tags
                    .get(VAULT_TAG_MANAGED_KEY)
                    .map(String::as_str)
                    == Some(VAULT_TAG_MANAGED_VALUE)
            })
            .map(|s| s.id)
            .collect())
    }
}

// ── OCI Vault wire-protocol tests ───────────────────────────────────────
//
// Plain `reqwest` over HTTP, unlike the Azure/GCP SDKs — a wiremock server
// works directly, same technique as the AWS provider's own tests.
// `config.vaults_endpoint`/`secrets_endpoint` (test-only, mirroring
// `AwsProvider`'s `endpoint_url`) point both OCI API surfaces at it
// independently.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::LazyLock;

    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    // Fresh, throwaway 2048-bit RSA key generated once per test-binary run
    // — see `providers::test_support` for why this isn't a checked-in
    // fixture.
    static TEST_KEY_PEM: LazyLock<String> =
        LazyLock::new(crate::providers::test_support::generate_rsa_private_key_pem);

    fn test_credentials() -> Value {
        json!({
            "user": "ocid1.user.oc1..u1",
            "private_key_pem": TEST_KEY_PEM.as_str(),
            "fingerprint": "aa:bb:cc",
            "tenancy": "ocid1.tenancy.oc1..t1",
            "compartment_id": "ocid1.compartment.oc1..c1",
            "vault_id": "ocid1.vault.oc1..v1",
            "vault_key_id": "ocid1.key.oc1..k1",
        })
    }

    fn test_config(server: &MockServer) -> Value {
        json!({"vaults_endpoint": server.uri(), "secrets_endpoint": server.uri()})
    }

    fn provider_for(server: &MockServer) -> OracleProvider {
        OracleProvider::new(&test_credentials(), &test_config(server)).expect("build provider")
    }

    #[test]
    fn secret_name_for_applies_prefix_and_sanitizes() {
        let server_url = "http://127.0.0.1:1"; // unused — construction is offline
        let credentials = test_credentials();
        let config = json!({"vaults_endpoint": server_url, "secrets_endpoint": server_url});
        let provider = OracleProvider::new(&credentials, &config).expect("build provider");
        assert_eq!(
            provider.secret_name_for("app/db.password"),
            "vault-app-db-password"
        );
    }

    #[test]
    fn new_requires_every_credential_field() {
        for missing in [
            "user",
            "private_key_pem",
            "fingerprint",
            "tenancy",
            "compartment_id",
            "vault_id",
            "vault_key_id",
        ] {
            let mut creds = test_credentials();
            creds.as_object_mut().expect("object").remove(missing);
            let result = OracleProvider::new(&creds, &Value::Null);
            assert!(result.is_err(), "expected error when {missing} is missing");
        }
    }

    #[test]
    fn new_rejects_passphrase_protected_keys() {
        let mut creds = test_credentials();
        creds["private_key_passphrase"] = json!("secret-passphrase");
        let result = OracleProvider::new(&creds, &Value::Null);
        match result {
            Err(ProviderError::Failed(msg)) => assert!(msg.contains("passphrase")),
            Ok(_) => panic!("expected construction to fail with a passphrase-protected key"),
        }
    }

    // ── push_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn push_secret_creates_when_no_existing_secret() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/20180608/secrets"))
            .and(query_param("name", "vault-db-password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/20180608/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "ocid1.vaultsecret.oc1..new1", "secretName": "vault-db-password",
            })))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider
            .push_secret("db-password", "hunter2", "secret-1")
            .await;

        assert!(result.success, "{result:?}");
        assert_eq!(result.action, "created");
        assert_eq!(result.external_ref, "ocid1.vaultsecret.oc1..new1");
    }

    #[tokio::test]
    async fn push_secret_updates_when_existing_secret_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/20180608/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "ocid1.vaultsecret.oc1..existing1", "secretName": "vault-db-password"},
            ])))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/20180608/secrets/ocid1.vaultsecret.oc1..existing1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "ocid1.vaultsecret.oc1..existing1",
            })))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider
            .push_secret("db-password", "hunter2", "secret-2")
            .await;

        assert!(result.success, "{result:?}");
        assert_eq!(result.action, "updated");
        assert_eq!(result.external_ref, "ocid1.vaultsecret.oc1..existing1");
    }

    #[tokio::test]
    async fn push_secret_reports_find_existing_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/20180608/secrets"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "boom"})))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.push_secret("x", "v", "secret-3").await;
        assert!(!result.success);
        assert_eq!(result.action, "skipped");
    }

    #[tokio::test]
    async fn push_secret_reports_create_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/20180608/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/20180608/secrets"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"message": "bad request"})),
            )
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.push_secret("x", "v", "secret-4").await;
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("bad request"));
    }

    // ── pull_secret ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pull_secret_returns_value_on_success() {
        let server = MockServer::start().await;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"the-value");
        Mock::given(method("GET"))
            .and(path("/20190301/secretbundles/ocid1.vaultsecret.oc1..p"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secretId": "ocid1.vaultsecret.oc1..p",
                "secretBundleContent": {"contentType": "BASE64", "content": encoded},
            })))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("ocid1.vaultsecret.oc1..p").await;
        assert_eq!(result, Ok(Some("the-value".to_owned())));
    }

    #[tokio::test]
    async fn pull_secret_returns_none_when_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/20190301/secretbundles/ocid1.vaultsecret.oc1..missing",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "gone"})))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.pull_secret("ocid1.vaultsecret.oc1..missing").await;
        assert_eq!(result, Ok(None));
    }

    // ── delete_secret ────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_returns_true_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/20180608/secrets/ocid1.vaultsecret.oc1..d/actions/scheduleDeletion",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        assert_eq!(
            provider.delete_secret("ocid1.vaultsecret.oc1..d").await,
            Ok(true)
        );
    }

    #[tokio::test]
    async fn delete_secret_returns_false_when_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/20180608/secrets/ocid1.vaultsecret.oc1..missing/actions/scheduleDeletion",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "gone"})))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        assert_eq!(
            provider
                .delete_secret("ocid1.vaultsecret.oc1..missing")
                .await,
            Ok(false)
        );
    }

    // ── list_secrets ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_filters_by_managed_tag() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/20180608/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": "ocid1.vaultsecret.oc1..a", "secretName": "vault-a", "freeformTags": {"vault-managed": "true"}},
                {"id": "ocid1.vaultsecret.oc1..b", "secretName": "other", "freeformTags": {}},
            ])))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.list_secrets().await;
        assert_eq!(result, Ok(vec!["ocid1.vaultsecret.oc1..a".to_owned()]));
    }

    // ── signing integration (the actual Authorization header on the wire) ──

    #[tokio::test]
    async fn requests_carry_a_well_formed_oci_authorization_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/20180608/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/20180608/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "new1"})))
            .mount(&server)
            .await;
        let provider = provider_for(&server);

        let result = provider.push_secret("hdr-check", "v", "secret-5").await;
        assert!(result.success, "{result:?}");

        let requests = server.received_requests().await.expect("recording enabled");
        let create_req = requests
            .iter()
            .find(|r| r.method.as_str() == "POST")
            .expect("create request recorded");
        let auth = create_req
            .headers
            .get("authorization")
            .expect("authorization header present")
            .to_str()
            .expect("valid header string");
        assert!(auth.starts_with("Signature version=\"1\","));
        assert!(auth.contains("keyId=\"ocid1.tenancy.oc1..t1/ocid1.user.oc1..u1/aa:bb:cc\""));
        assert!(create_req.headers.get("x-content-sha256").is_some());
    }
}
