//! Hybrid credential resolver for `s3_bucket_configs` (manager REST CRUD +
//! s3scan worker per-job client build). Two modes, selected per row by
//! `credential_mode`:
//!
//! - `assume_role` (preferred): exchanges a customer-supplied `role_arn`
//!   (+ optional `external_id`) for short-lived credentials via
//!   `sts:AssumeRole`, called using this service's own ambient AWS identity
//!   (default credential-provider chain — IRSA/instance-profile/env; a later
//!   round swaps the base identity to a JWT-SVID). No customer secret is
//!   ever stored. Only valid against a genuine AWS S3 endpoint — S3-compatible
//!   third-party endpoints (MinIO, Wasabi, ...) have no STS to assume against.
//! - `static` (fallback): the customer's access-key-id/secret-access-key pair,
//!   envelope-encrypted at rest via `skauswatch_vault::EnvelopeEncryption`
//!   (see `docs/v2-port/vault-crypto-gate.md`) and decrypted here just before
//!   building the client. Required for S3-compatible endpoints.
//!
//! [`federated_base_credentials`] is a separate, opt-in entry point for a
//! caller's own-AWS access (not a `s3_bucket_configs` row at all — see
//! `docs/v2-port/aws-identity-runbook.md`): it exchanges this service's own
//! JWT-SVID for temporary AWS credentials via `sts:AssumeRoleWithWebIdentity`,
//! dal2's IRSA equivalent. Its result is meant to feed
//! [`assume_role_credentials`]'s existing `base_credentials_override`
//! parameter, so a customer's cross-account `AssumeRole` chain keeps working
//! unchanged on top of it.
//!
//! Nothing in this module ever logs a decrypted credential value.

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use skauswatch_vault::{EnvelopeEncryption, EnvelopeError};

/// `sts:AssumeRole`/`sts:AssumeRoleWithWebIdentity` session name — must
/// match `[\w+=,.@-]{2,64}`.
const ROLE_SESSION_NAME: &str = "skauswatch-s3scan";

/// AWS's fixed required audience for `AssumeRoleWithWebIdentity`-compatible
/// OIDC tokens — matches the convention EKS/IRSA itself uses for its own
/// projected service-account tokens. See
/// `docs/v2-port/aws-identity-runbook.md`.
pub const AWS_STS_AUDIENCE: &str = "sts.amazonaws.com";

/// Resolved bucket-credential shape needed to build an S3 client, decoupled
/// from any particular DB row type so both the manager and s3scan worker can
/// map their own row structs into it.
#[derive(Debug, Clone)]
pub struct BucketCredentialConfig {
    /// `"assume_role"` or `"static"` (matches the `s3_bucket_configs`
    /// `credential_mode` CHECK constraint).
    pub credential_mode: String,
    /// `static` mode: the envelope-encrypted `{"ciphertext","dek","version"}`
    /// JSON blob wrapping `{"access_key_id","secret_access_key"}` — see
    /// [`EnvelopeEncryption::encrypt_json`]/`decrypt_json`. `None` for
    /// `assume_role` rows.
    pub credential_enc: Option<String>,
    /// `assume_role` mode: the customer's IAM role ARN to assume.
    pub role_arn: Option<String>,
    /// `assume_role` mode: optional external id (confused-deputy mitigation).
    pub external_id: Option<String>,
    /// S3 (and, for `assume_role`, STS) endpoint URL.
    pub endpoint_url: String,
    /// AWS region.
    pub region: String,
    /// Path-style addressing (required for most S3-compatible stores).
    pub path_style: bool,
}

/// Errors resolving stored bucket credentials into a usable S3 client.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// `credential_mode` was neither `"assume_role"` nor `"static"`.
    #[error("credential_mode {0:?} is not one of \"assume_role\"/\"static\"")]
    UnknownMode(String),
    /// `static` mode with no stored `credential_enc` blob.
    #[error("static credential_mode requires a stored credential_enc blob")]
    MissingStaticCredential,
    /// The decrypted `credential_enc` JSON was missing the expected fields.
    #[error("stored credential blob is missing access_key_id/secret_access_key")]
    MalformedStaticCredential,
    /// `assume_role` mode with no stored `role_arn`.
    #[error("assume_role credential_mode requires role_arn")]
    MissingRoleArn,
    /// `assume_role` requested against a non-AWS S3-compatible endpoint,
    /// which has no STS to assume a role against.
    #[error(
        "assume_role is not supported against non-AWS S3-compatible endpoint {0} (no STS) — \
         use static credentials for this endpoint"
    )]
    AssumeRoleRequiresAwsEndpoint(String),
    /// Envelope decryption of the stored `credential_enc` blob failed.
    #[error("failed to decrypt stored credentials: {0}")]
    Decrypt(#[from] EnvelopeError),
    /// The `sts:AssumeRole` call itself failed (network/permissions/etc).
    #[error("sts:AssumeRole failed: {0}")]
    AssumeRole(String),
    /// `sts:AssumeRole` succeeded but returned no temporary credentials.
    #[error("sts:AssumeRole returned no temporary credentials")]
    AssumeRoleEmptyResponse,
    /// Fetching a JWT-SVID from the local SPIFFE identity source failed —
    /// no identity currently attested, Workload API unreachable, etc.
    /// Callers of [`federated_base_credentials`] should treat this as
    /// "federation unavailable right now" and fall back to the default AWS
    /// credential-provider chain, never as fatal.
    #[error("failed to fetch JWT-SVID for AWS federation: {0}")]
    Identity(String),
    /// `assume_role` was requested on a deployment explicitly configured
    /// with `AWS_IDENTITY_MODE=static` (`AwsIdentityModeKind::Static`) — no
    /// STS/federation route exists for this service's own base identity by
    /// design (S3-compatible-only deployments), so the request is rejected
    /// immediately rather than falling through to the default AWS
    /// credential-provider chain, which would silently attempt to resolve
    /// ambient credentials on a cluster that is not expected to have any.
    #[error(
        "assume_role requires a base AWS identity, but this deployment is configured with \
         AWS_IDENTITY_MODE=static (no own-AWS federation route) — use static bucket credentials \
         instead"
    )]
    AssumeRoleUnavailableStaticIdentity,
}

impl CredentialError {
    /// True for configuration-shape errors that will never succeed on retry
    /// without an admin fixing the bucket config; false for the transient/
    /// network variants ([`Self::AssumeRole`], [`Self::Identity`]) worth
    /// retrying.
    pub fn is_permanent(&self) -> bool {
        !matches!(
            self,
            CredentialError::AssumeRole(_) | CredentialError::Identity(_)
        )
    }
}

/// The `awsIdentity.mode` value as loaded from config/env
/// (`AWS_IDENTITY_MODE` / Helm `awsIdentity.mode`) — see
/// `docs/v2-port/aws-identity-runbook.md` §0. Selected explicitly once per
/// deployment; never inferred from whether a federation role ARN happens to
/// be configured (that was the previous, implicit-fallback behavior this
/// type replaces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsIdentityModeKind {
    /// dal2/on-prem (no EKS/IRSA control plane): resolve this service's own
    /// base AWS identity via JWT-SVID -> `sts:AssumeRoleWithWebIdentity`
    /// federation ([`federated_base_credentials`]).
    Spire,
    /// EKS: rely on the default AWS credential-provider chain — IRSA
    /// discovers the projected service-account token itself, no
    /// application-level federation needed.
    Irsa,
    /// S3-compatible-only deployments with no STS at all (MinIO, Wasabi,
    /// B2, ...): never attempt to resolve a base AWS identity for this
    /// service — only customer-supplied `static` bucket credentials are
    /// expected to exist.
    Static,
}

impl AwsIdentityModeKind {
    /// Reads `AWS_IDENTITY_MODE` (case-insensitive `"spire"`/`"irsa"`/
    /// `"static"`); unset or unrecognized falls back to [`Self::Spire`],
    /// matching the Helm charts' base `values.yaml` default (skauswatch's
    /// current on-prem clusters have no IRSA to fall back to).
    pub fn from_env() -> Self {
        Self::parse(std::env::var("AWS_IDENTITY_MODE").ok().as_deref())
    }

    /// Pure parsing logic behind [`Self::from_env`].
    fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::to_ascii_lowercase).as_deref() {
            Some("irsa") => Self::Irsa,
            Some("static") => Self::Static,
            _ => Self::Spire,
        }
    }
}

/// Explicit, deployment-configured selection of how [`resolve_client`]
/// resolves this service's own base AWS identity before layering a
/// customer's `sts:AssumeRole` on top — only consulted for
/// `credential_mode = "assume_role"` bucket rows; `static`-mode rows never
/// touch this at all. Built from [`AwsIdentityModeKind`] plus (for
/// [`Self::Spire`]) the identity source/role ARN needed to actually
/// federate — see [`Self::from_kind`].
pub enum AwsIdentityMode<'a> {
    /// Resolve via JWT-SVID -> `sts:AssumeRoleWithWebIdentity`
    /// ([`federated_base_credentials`]) before the customer's `AssumeRole`
    /// hop.
    Spire {
        /// SPIFFE identity source used to fetch this service's own JWT-SVID.
        identity: &'a dyn JwtSvidSource,
        /// This service's own federation IAM role ARN — never a customer's.
        own_role_arn: &'a str,
    },
    /// Defer to the default AWS credential-provider chain (IRSA or no
    /// override at all) — equivalent to today's implicit fallback.
    Irsa,
    /// No base-identity route exists on this deployment; `assume_role`
    /// bucket rows are rejected immediately (see
    /// [`CredentialError::AssumeRoleUnavailableStaticIdentity`]).
    Static,
}

impl<'a> AwsIdentityMode<'a> {
    /// Builds the runtime mode from a configured `kind` plus an optional
    /// `(identity, own_role_arn)` federation pair. `Spire` with no
    /// federation pair available degrades to `Irsa` rather than erroring —
    /// fail-safe: a deployment configured for SPIRE federation but missing
    /// its role ARN/identity still has the default credential chain as a
    /// last resort, matching the "no identity -> default chain, never
    /// crash" policy used throughout this module.
    pub fn from_kind(
        kind: AwsIdentityModeKind,
        federation: Option<(&'a dyn JwtSvidSource, &'a str)>,
    ) -> Self {
        match (kind, federation) {
            (AwsIdentityModeKind::Static, _) => Self::Static,
            (AwsIdentityModeKind::Spire, Some((identity, own_role_arn))) => Self::Spire {
                identity,
                own_role_arn,
            },
            (AwsIdentityModeKind::Spire, None) | (AwsIdentityModeKind::Irsa, _) => Self::Irsa,
        }
    }
}

/// True when `endpoint_url`'s host is a genuine AWS S3 endpoint
/// (`*.amazonaws.com`) rather than an S3-compatible third-party endpoint
/// (MinIO, Wasabi, Backblaze B2, ...) that has no STS to assume a role
/// against.
pub fn is_aws_endpoint(endpoint_url: &str) -> bool {
    url::Url::parse(endpoint_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|h| h == "amazonaws.com" || h.ends_with(".amazonaws.com"))
}

/// Exchanges `role_arn` (+ optional `external_id`) for temporary STS
/// credentials via `sts:AssumeRole`.
///
/// `sts_endpoint_override`/`base_credentials_override` are test-only seams
/// (wiremock STS endpoint + a hermetic caller identity that never touches
/// the real default credential-provider chain / IMDS). Production callers
/// pass `None` for both: the real STS endpoint, and this service's own
/// ambient AWS identity as the caller.
///
/// # Errors
/// Returns [`CredentialError::AssumeRole`] on any STS failure, or
/// [`CredentialError::AssumeRoleEmptyResponse`] if STS returns no
/// credentials.
pub async fn assume_role_credentials(
    role_arn: &str,
    external_id: Option<&str>,
    region: &str,
    sts_endpoint_override: Option<&str>,
    base_credentials_override: Option<Credentials>,
) -> Result<Credentials, CredentialError> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_owned()));
    if let Some(base) = base_credentials_override {
        loader = loader.credentials_provider(base);
    }
    let shared = loader.load().await;

    let mut sts_builder = aws_sdk_sts::config::Builder::from(&shared);
    if let Some(ep) = sts_endpoint_override {
        sts_builder = sts_builder.endpoint_url(ep);
    }
    let sts_client = aws_sdk_sts::Client::from_conf(sts_builder.build());

    let mut req = sts_client
        .assume_role()
        .role_arn(role_arn)
        .role_session_name(ROLE_SESSION_NAME);
    if let Some(eid) = external_id {
        req = req.external_id(eid);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| CredentialError::AssumeRole(e.to_string()))?;
    let creds = resp
        .credentials()
        .ok_or(CredentialError::AssumeRoleEmptyResponse)?;

    // Expiration intentionally omitted: this `Credentials` is built fresh
    // for one S3 client per request/job and never reused past that call —
    // a cached/long-lived resolver would need to honor STS's real
    // expiration instead.
    Ok(Credentials::new(
        creds.access_key_id(),
        creds.secret_access_key(),
        Some(creds.session_token().to_owned()),
        None,
        "skauswatch-assume-role",
    ))
}

/// Minimal capability [`federated_base_credentials`] needs from a SPIFFE
/// identity source: fetch a JWT-SVID token scoped to an audience. The sole
/// production implementor is [`skauswatch_identity::IdentityProvider`] (see
/// the blanket impl just below). Kept as a trait — rather than taking the
/// concrete type directly — so callers in `s3scan`/`worker-vault-sync` (and
/// this crate's own tests) can substitute a hermetic fake without depending
/// on `skauswatch-identity`'s attestation internals, which are deliberately
/// private to that crate (no test-only way to construct an attested
/// `IdentityProvider` from outside it).
#[async_trait::async_trait]
pub trait JwtSvidSource: Send + Sync {
    /// Fetches a JWT-SVID token for `audience`. Implementations must
    /// surface "no identity currently held" (a degraded/unattested
    /// provider, an unreachable Workload API, etc.) as an `Err` —
    /// [`federated_base_credentials`] callers treat any error here as a
    /// signal to fall back to the default AWS credential-provider chain,
    /// never as fatal.
    async fn fetch_jwt_svid_token(&self, audience: &str) -> Result<String, CredentialError>;
}

#[async_trait::async_trait]
impl JwtSvidSource for skauswatch_identity::IdentityProvider {
    async fn fetch_jwt_svid_token(&self, audience: &str) -> Result<String, CredentialError> {
        let jwt = self
            .fetch_jwt_svid(audience)
            .await
            .map_err(|e| CredentialError::Identity(e.to_string()))?;
        Ok(jwt.token().to_owned())
    }
}

/// Exchanges this service's own JWT-SVID (fetched from `identity`, scoped to
/// [`AWS_STS_AUDIENCE`]) for temporary base AWS credentials via
/// `sts:AssumeRoleWithWebIdentity` against `own_role_arn` — a service-owned
/// IAM role pre-configured to trust the SPIRE OIDC issuer (one-time AWS-side
/// setup; see `docs/v2-port/aws-identity-runbook.md`). This is dal2's IRSA
/// equivalent: on-prem has no EKS control plane, so there is no ambient AWS
/// identity (IMDS/instance-profile/env) to fall back to for this call.
///
/// `own_role_arn` is **not** a customer's `role_arn` — the returned
/// `Credentials` are meant to feed [`assume_role_credentials`]'s existing
/// `base_credentials_override` parameter unchanged, so a customer's
/// cross-account `AssumeRole` chain keeps layering on top exactly as
/// before. Callers should treat any `Err` here as "federation unavailable
/// right now" and fall back to the default AWS credential-provider chain —
/// never as fatal (see the fail-safe policy in
/// `docs/v2-port/service-auth-model.md` §4 and
/// `docs/v2-port/aws-identity-runbook.md`).
///
/// `AssumeRoleWithWebIdentity` requires no caller credentials of its own —
/// AWS models it with an anonymous auth scheme — so this deliberately never
/// resolves an ambient AWS identity to make the call.
///
/// # Errors
/// [`CredentialError::Identity`] if fetching the JWT-SVID failed.
/// [`CredentialError::AssumeRole`]/[`CredentialError::AssumeRoleEmptyResponse`]
/// on STS failure, same as [`assume_role_credentials`].
pub async fn federated_base_credentials(
    identity: &dyn JwtSvidSource,
    own_role_arn: &str,
    region: &str,
) -> Result<Credentials, CredentialError> {
    federated_base_credentials_inner(identity, own_role_arn, region, None).await
}

/// Full implementation behind [`federated_base_credentials`];
/// `sts_endpoint_override` is the same test-only seam
/// [`assume_role_credentials`] uses (wiremock STS, no real network call).
async fn federated_base_credentials_inner(
    identity: &dyn JwtSvidSource,
    own_role_arn: &str,
    region: &str,
    sts_endpoint_override: Option<&str>,
) -> Result<Credentials, CredentialError> {
    // Fetch the JWT-SVID first — if the identity source has nothing to
    // offer (degraded/unattested/unreachable), fail before ever touching
    // the network, so a caller falling back to the default credential
    // chain never pays for a doomed STS round-trip.
    let token = identity.fetch_jwt_svid_token(AWS_STS_AUDIENCE).await?;

    let mut sts_builder = aws_sdk_sts::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_owned()));
    if let Some(ep) = sts_endpoint_override {
        sts_builder = sts_builder.endpoint_url(ep);
    }
    let sts_client = aws_sdk_sts::Client::from_conf(sts_builder.build());

    let resp = sts_client
        .assume_role_with_web_identity()
        .role_arn(own_role_arn)
        .role_session_name(ROLE_SESSION_NAME)
        .web_identity_token(&token)
        .send()
        .await
        .map_err(|e| CredentialError::AssumeRole(e.to_string()))?;
    let creds = resp
        .credentials()
        .ok_or(CredentialError::AssumeRoleEmptyResponse)?;

    Ok(Credentials::new(
        creds.access_key_id(),
        creds.secret_access_key(),
        Some(creds.session_token().to_owned()),
        None,
        "skauswatch-federated-base",
    ))
}

/// Decrypts a `static`-mode `credential_enc` blob into AWS `Credentials`.
fn static_credentials(
    envelope: &EnvelopeEncryption,
    credential_enc: &str,
) -> Result<Credentials, CredentialError> {
    let value = envelope.decrypt_json(credential_enc)?;
    let access_key_id = value
        .get("access_key_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(CredentialError::MalformedStaticCredential)?;
    let secret_access_key = value
        .get("secret_access_key")
        .and_then(serde_json::Value::as_str)
        .ok_or(CredentialError::MalformedStaticCredential)?;
    Ok(Credentials::new(
        access_key_id,
        secret_access_key,
        None,
        None,
        "skauswatch-static",
    ))
}

/// Resolves a stored bucket credential config into a ready-to-use S3
/// client. Preferred entry point for production code — see
/// [`resolve_client_inner`] for the test-only override seam.
///
/// `identity_mode` deterministically selects how this service's own base
/// AWS identity is resolved for `credential_mode = "assume_role"` rows (see
/// [`AwsIdentityMode`]); `static`-mode rows never consult it.
///
/// # Errors
/// See [`CredentialError`] variants.
pub async fn resolve_client(
    envelope: &EnvelopeEncryption,
    cfg: &BucketCredentialConfig,
    identity_mode: &AwsIdentityMode<'_>,
) -> Result<Client, CredentialError> {
    resolve_client_inner(envelope, cfg, identity_mode, None, None).await
}

/// Full implementation behind [`resolve_client`]; `sts_endpoint_override`/
/// `base_credentials_override` let tests exercise the `assume_role` branch
/// against a wiremock STS server without depending on ambient AWS
/// credentials or network-reachable IMDS — when `base_credentials_override`
/// is `Some`, it wins outright and `identity_mode` is not consulted at all
/// (the test-only escape hatch pre-dating `AwsIdentityMode`). Not part of
/// the public API surface beyond the crate (tests live in this same
/// module).
async fn resolve_client_inner(
    envelope: &EnvelopeEncryption,
    cfg: &BucketCredentialConfig,
    identity_mode: &AwsIdentityMode<'_>,
    sts_endpoint_override: Option<&str>,
    base_credentials_override: Option<Credentials>,
) -> Result<Client, CredentialError> {
    let creds = match cfg.credential_mode.as_str() {
        "assume_role" => {
            if !is_aws_endpoint(&cfg.endpoint_url) {
                return Err(CredentialError::AssumeRoleRequiresAwsEndpoint(
                    cfg.endpoint_url.clone(),
                ));
            }
            let role_arn = cfg
                .role_arn
                .as_deref()
                .ok_or(CredentialError::MissingRoleArn)?;
            let resolved_base = match base_credentials_override {
                Some(creds) => Some(creds),
                None => match identity_mode {
                    AwsIdentityMode::Static => {
                        return Err(CredentialError::AssumeRoleUnavailableStaticIdentity);
                    }
                    AwsIdentityMode::Irsa => None,
                    AwsIdentityMode::Spire {
                        identity,
                        own_role_arn,
                    } => {
                        match federated_base_credentials_inner(
                            *identity,
                            own_role_arn,
                            &cfg.region,
                            sts_endpoint_override,
                        )
                        .await
                        {
                            Ok(creds) => Some(creds),
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "own-AWS JWT-SVID federation unavailable for customer \
                                     assume_role base identity — falling back to the default \
                                     AWS credential-provider chain"
                                );
                                None
                            }
                        }
                    }
                },
            };
            assume_role_credentials(
                role_arn,
                cfg.external_id.as_deref(),
                &cfg.region,
                sts_endpoint_override,
                resolved_base,
            )
            .await?
        }
        "static" => {
            let blob = cfg
                .credential_enc
                .as_deref()
                .ok_or(CredentialError::MissingStaticCredential)?;
            static_credentials(envelope, blob)?
        }
        other => return Err(CredentialError::UnknownMode(other.to_owned())),
    };

    let sdk_config = aws_sdk_s3::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(cfg.region.clone()))
        .endpoint_url(&cfg.endpoint_url)
        .force_path_style(cfg.path_style)
        .credentials_provider(creds)
        .build();
    Ok(Client::from_conf(sdk_config))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use std::collections::HashMap;

    use skauswatch_vault::MekVersion;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn test_envelope() -> EnvelopeEncryption {
        EnvelopeEncryption::new(
            HashMap::from([(
                1,
                MekVersion {
                    version: 1,
                    key_bytes: [9u8; 32],
                },
            )]),
            1,
        )
    }

    fn static_cfg(endpoint_url: &str, credential_enc: String) -> BucketCredentialConfig {
        BucketCredentialConfig {
            credential_mode: "static".to_owned(),
            credential_enc: Some(credential_enc),
            role_arn: None,
            external_id: None,
            endpoint_url: endpoint_url.to_owned(),
            region: "us-east-1".to_owned(),
            path_style: true,
        }
    }

    fn assume_role_cfg(endpoint_url: &str, role_arn: &str) -> BucketCredentialConfig {
        BucketCredentialConfig {
            credential_mode: "assume_role".to_owned(),
            credential_enc: None,
            role_arn: Some(role_arn.to_owned()),
            external_id: Some("customer-external-id".to_owned()),
            endpoint_url: endpoint_url.to_owned(),
            region: "us-east-1".to_owned(),
            path_style: false,
        }
    }

    fn hermetic_base_creds() -> Credentials {
        Credentials::new("test-caller-ak", "test-caller-sk", None, None, "test")
    }

    fn assume_role_success_xml(access_key: &str, secret_key: &str, session_token: &str) -> String {
        format!(
            "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
             <AssumeRoleResult><Credentials>\
             <AccessKeyId>{access_key}</AccessKeyId>\
             <SecretAccessKey>{secret_key}</SecretAccessKey>\
             <SessionToken>{session_token}</SessionToken>\
             <Expiration>2099-01-01T00:00:00Z</Expiration>\
             </Credentials>\
             <AssumedRoleUser><AssumedRoleId>AROAEXAMPLE:skauswatch-s3scan</AssumedRoleId>\
             <Arn>arn:aws:sts::123456789012:assumed-role/demo/skauswatch-s3scan</Arn>\
             </AssumedRoleUser></AssumeRoleResult>\
             <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>\
             </AssumeRoleResponse>"
        )
    }

    // ── is_aws_endpoint ──────────────────────────────────────────────────

    #[test]
    fn is_aws_endpoint_recognizes_aws_hosts() {
        assert!(is_aws_endpoint("https://s3.amazonaws.com"));
        assert!(is_aws_endpoint("https://s3.us-west-2.amazonaws.com"));
        assert!(is_aws_endpoint("https://AMAZONAWS.COM"));
    }

    #[test]
    fn is_aws_endpoint_rejects_third_party_and_invalid() {
        assert!(!is_aws_endpoint("https://minio.example.com:9000"));
        assert!(!is_aws_endpoint("http://localhost:9000"));
        assert!(!is_aws_endpoint("https://s3.wasabisys.com"));
        // A host that merely *contains* "amazonaws.com" as a substring
        // (not a suffix-matched label) must not pass.
        assert!(!is_aws_endpoint("https://amazonaws.com.evil.example"));
        assert!(!is_aws_endpoint("not a url"));
    }

    // ── static mode ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_client_static_mode_builds_usable_client() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let envelope = test_envelope();
        let blob = envelope
            .encrypt_json(&serde_json::json!({
                "access_key_id": "AKIASTATICEXAMPLE",
                "secret_access_key": "staticSecretExampleKey",
            }))
            .expect("encrypt_json");
        let cfg = static_cfg(&server.uri(), blob);

        let client = resolve_client(&envelope, &cfg, &AwsIdentityMode::Irsa)
            .await
            .expect("resolve");
        let result = client.head_bucket().bucket("static-bucket").send().await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn resolve_client_static_mode_missing_blob_is_error() {
        let envelope = test_envelope();
        let mut cfg = static_cfg("https://s3.example", String::new());
        cfg.credential_enc = None;
        assert!(matches!(
            resolve_client(&envelope, &cfg, &AwsIdentityMode::Irsa).await,
            Err(CredentialError::MissingStaticCredential)
        ));
    }

    #[tokio::test]
    async fn resolve_client_static_mode_undecryptable_blob_is_error() {
        // Envelope with a MEK that does not match the one used to encrypt.
        let wrong_envelope = EnvelopeEncryption::new(
            HashMap::from([(
                1,
                MekVersion {
                    version: 1,
                    key_bytes: [1u8; 32],
                },
            )]),
            1,
        );
        let envelope = test_envelope();
        let blob = envelope
            .encrypt_json(&serde_json::json!({
                "access_key_id": "AK",
                "secret_access_key": "SK",
            }))
            .expect("encrypt_json");
        let cfg = static_cfg("https://s3.example", blob);

        assert!(matches!(
            resolve_client(&wrong_envelope, &cfg, &AwsIdentityMode::Irsa).await,
            Err(CredentialError::Decrypt(_))
        ));
    }

    #[tokio::test]
    async fn resolve_client_static_mode_malformed_credential_json_is_error() {
        let envelope = test_envelope();
        // Valid envelope, but the *decrypted* plaintext isn't the expected shape.
        let blob = envelope
            .encrypt_json(&serde_json::json!({"unexpected": "shape"}))
            .expect("encrypt_json");
        let cfg = static_cfg("https://s3.example", blob);

        assert!(matches!(
            resolve_client(&envelope, &cfg, &AwsIdentityMode::Irsa).await,
            Err(CredentialError::MalformedStaticCredential)
        ));
    }

    // ── assume_role mode ─────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_client_assume_role_rejects_non_aws_endpoint_without_network() {
        let envelope = test_envelope();
        let cfg = assume_role_cfg(
            "https://minio.example.com:9000",
            "arn:aws:iam::123456789012:role/skauswatch-scan",
        );
        let result = resolve_client(&envelope, &cfg, &AwsIdentityMode::Irsa).await;
        assert!(matches!(
            result,
            Err(CredentialError::AssumeRoleRequiresAwsEndpoint(ref e))
                if e == "https://minio.example.com:9000"
        ));
    }

    #[tokio::test]
    async fn resolve_client_assume_role_missing_role_arn_is_error() {
        let envelope = test_envelope();
        let mut cfg = assume_role_cfg("https://s3.amazonaws.com", "unused");
        cfg.role_arn = None;
        assert!(matches!(
            resolve_client(&envelope, &cfg, &AwsIdentityMode::Irsa).await,
            Err(CredentialError::MissingRoleArn)
        ));
    }

    #[tokio::test]
    async fn assume_role_credentials_parses_sts_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .and(body_string_contains("RoleSessionName=skauswatch-s3scan"))
            .and(body_string_contains("ExternalId=customer-external-id"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                assume_role_success_xml("AKIATEMP", "tempSecretKey", "session-token-value"),
                "text/xml",
            ))
            .mount(&server)
            .await;

        let creds = assume_role_credentials(
            "arn:aws:iam::123456789012:role/demo",
            Some("customer-external-id"),
            "us-east-1",
            Some(&server.uri()),
            Some(hermetic_base_creds()),
        )
        .await
        .expect("assume_role_credentials");

        assert_eq!(creds.access_key_id(), "AKIATEMP");
        assert_eq!(creds.secret_access_key(), "tempSecretKey");
        assert_eq!(creds.session_token(), Some("session-token-value"));
    }

    #[tokio::test]
    async fn resolve_client_assume_role_success_builds_client_via_mocked_sts() {
        let sts_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                assume_role_success_xml("AKIATEMP2", "tempSecretKey2", "session-token-2"),
                "text/xml",
            ))
            .mount(&sts_server)
            .await;

        let envelope = test_envelope();
        // A genuinely AWS-shaped endpoint so the guard passes; the actual S3
        // client built from it is never dialed in this test — only STS is,
        // via the override — so no real network call to AWS occurs.
        let cfg = assume_role_cfg(
            "https://s3.amazonaws.com",
            "arn:aws:iam::123456789012:role/demo",
        );

        let client = resolve_client_inner(
            &envelope,
            &cfg,
            &AwsIdentityMode::Irsa,
            Some(&sts_server.uri()),
            Some(hermetic_base_creds()),
        )
        .await
        .expect("resolve_client_inner");
        // Successfully constructing the client is the observable outcome —
        // it proves the assume_role branch ran end to end (guard passed,
        // STS call succeeded, credentials resolved) without ever touching
        // the real STS/S3 endpoints.
        drop(client);
    }

    #[tokio::test]
    async fn assume_role_credentials_propagates_sts_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_raw(
                "<ErrorResponse><Error><Code>AccessDenied</Code>\
                     <Message>not authorized</Message></Error>\
                     <RequestId>r</RequestId></ErrorResponse>",
                "text/xml",
            ))
            .mount(&server)
            .await;

        let result = assume_role_credentials(
            "arn:aws:iam::123456789012:role/demo",
            None,
            "us-east-1",
            Some(&server.uri()),
            Some(hermetic_base_creds()),
        )
        .await;
        assert!(matches!(result, Err(CredentialError::AssumeRole(_))));
    }

    #[test]
    fn credential_error_is_permanent_classification() {
        assert!(CredentialError::MissingRoleArn.is_permanent());
        assert!(CredentialError::MissingStaticCredential.is_permanent());
        assert!(CredentialError::MalformedStaticCredential.is_permanent());
        assert!(CredentialError::UnknownMode("bogus".to_owned()).is_permanent());
        assert!(CredentialError::AssumeRoleRequiresAwsEndpoint("x".to_owned()).is_permanent());
        assert!(CredentialError::AssumeRoleEmptyResponse.is_permanent());
        assert!(!CredentialError::AssumeRole("timeout".to_owned()).is_permanent());
        assert!(!CredentialError::Identity("degraded".to_owned()).is_permanent());
        assert!(CredentialError::AssumeRoleUnavailableStaticIdentity.is_permanent());
    }

    #[tokio::test]
    async fn resolve_client_unknown_mode_is_error() {
        let envelope = test_envelope();
        let mut cfg = static_cfg("https://s3.example", String::new());
        cfg.credential_mode = "bogus".to_owned();
        assert!(matches!(
            resolve_client(&envelope, &cfg, &AwsIdentityMode::Irsa).await,
            Err(CredentialError::UnknownMode(ref m)) if m == "bogus"
        ));
    }

    // ── AwsIdentityModeKind / AwsIdentityMode ───────────────────────────────

    #[test]
    fn aws_identity_mode_kind_parses_case_insensitively_and_defaults_to_spire() {
        assert_eq!(
            AwsIdentityModeKind::parse(Some("irsa")),
            AwsIdentityModeKind::Irsa
        );
        assert_eq!(
            AwsIdentityModeKind::parse(Some("IRSA")),
            AwsIdentityModeKind::Irsa
        );
        assert_eq!(
            AwsIdentityModeKind::parse(Some("static")),
            AwsIdentityModeKind::Static
        );
        assert_eq!(
            AwsIdentityModeKind::parse(Some("STATIC")),
            AwsIdentityModeKind::Static
        );
        assert_eq!(
            AwsIdentityModeKind::parse(Some("spire")),
            AwsIdentityModeKind::Spire
        );
        // Unset/unrecognized both fall back to Spire — dal2's on-prem
        // clusters have no IRSA, so this must never silently become Irsa.
        assert_eq!(AwsIdentityModeKind::parse(None), AwsIdentityModeKind::Spire);
        assert_eq!(
            AwsIdentityModeKind::parse(Some("bogus")),
            AwsIdentityModeKind::Spire
        );
    }

    #[test]
    fn aws_identity_mode_from_kind_static_ignores_federation_pair() {
        let identity = FakeJwtSource::Token("unused");
        assert!(matches!(
            AwsIdentityMode::from_kind(AwsIdentityModeKind::Static, Some((&identity, "arn"))),
            AwsIdentityMode::Static
        ));
        assert!(matches!(
            AwsIdentityMode::from_kind(AwsIdentityModeKind::Static, None),
            AwsIdentityMode::Static
        ));
    }

    #[test]
    fn aws_identity_mode_from_kind_irsa_ignores_federation_pair() {
        let identity = FakeJwtSource::Token("unused");
        assert!(matches!(
            AwsIdentityMode::from_kind(AwsIdentityModeKind::Irsa, Some((&identity, "arn"))),
            AwsIdentityMode::Irsa
        ));
        assert!(matches!(
            AwsIdentityMode::from_kind(AwsIdentityModeKind::Irsa, None),
            AwsIdentityMode::Irsa
        ));
    }

    #[test]
    fn aws_identity_mode_from_kind_spire_uses_pair_when_present() {
        let identity = FakeJwtSource::Token("unused");
        match AwsIdentityMode::from_kind(AwsIdentityModeKind::Spire, Some((&identity, "arn:role")))
        {
            AwsIdentityMode::Spire { own_role_arn, .. } => assert_eq!(own_role_arn, "arn:role"),
            AwsIdentityMode::Irsa | AwsIdentityMode::Static => {
                panic!("expected Spire variant")
            }
        }
    }

    #[test]
    fn aws_identity_mode_from_kind_spire_degrades_to_irsa_without_pair() {
        // Fail-safe: SPIRE configured but no identity/role available yet
        // (startup ordering, degraded provider) must never error — it falls
        // back to the default AWS credential-provider chain.
        assert!(matches!(
            AwsIdentityMode::from_kind(AwsIdentityModeKind::Spire, None),
            AwsIdentityMode::Irsa
        ));
    }

    #[tokio::test]
    async fn resolve_client_assume_role_static_identity_mode_is_rejected_without_network() {
        let envelope = test_envelope();
        let cfg = assume_role_cfg(
            "https://s3.amazonaws.com",
            "arn:aws:iam::123456789012:role/demo",
        );
        let result = resolve_client(&envelope, &cfg, &AwsIdentityMode::Static).await;
        assert!(matches!(
            result,
            Err(CredentialError::AssumeRoleUnavailableStaticIdentity)
        ));
    }

    #[tokio::test]
    async fn resolve_client_assume_role_spire_mode_federates_base_identity_then_assumes_customer_role()
     {
        let sts_server = MockServer::start().await;
        // Two hops against the same mocked STS endpoint: the service's own
        // AssumeRoleWithWebIdentity (federation), then the customer's
        // AssumeRole — both must be observed.
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                assume_role_with_web_identity_success_xml(
                    "AKIAOWNBASE",
                    "ownBaseSecret",
                    "own-base-session-token",
                ),
                "text/xml",
            ))
            .mount(&sts_server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole&"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                assume_role_success_xml("AKIACUSTOMER", "customerSecret", "customer-session"),
                "text/xml",
            ))
            .mount(&sts_server)
            .await;

        let envelope = test_envelope();
        let cfg = assume_role_cfg(
            "https://s3.amazonaws.com",
            "arn:aws:iam::123456789012:role/customer",
        );
        let identity = FakeJwtSource::Token("fake-spiffe-jwt-token");
        let mode = AwsIdentityMode::Spire {
            identity: &identity,
            own_role_arn: TEST_ROLE_ARN,
        };

        let client = resolve_client_inner(&envelope, &cfg, &mode, Some(&sts_server.uri()), None)
            .await
            .expect("resolve_client_inner");
        drop(client);

        let requests = sts_server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(
            requests.len(),
            2,
            "expected both the own-base federation hop and the customer AssumeRole hop"
        );
    }

    #[tokio::test]
    async fn resolve_client_assume_role_spire_mode_falls_back_to_default_chain_when_identity_degraded()
     {
        let sts_server = MockServer::start().await;
        // Only the customer AssumeRole route is mocked — if the code
        // incorrectly attempted AssumeRoleWithWebIdentity despite the
        // degraded identity, the default credential-provider chain (never
        // touched by this test's mock) would be the only thing left able to
        // sign the customer AssumeRole call.
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole&"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                assume_role_success_xml("AKIACUSTOMER2", "customerSecret2", "customer-session-2"),
                "text/xml",
            ))
            .mount(&sts_server)
            .await;

        let envelope = test_envelope();
        let cfg = assume_role_cfg(
            "https://s3.amazonaws.com",
            "arn:aws:iam::123456789012:role/customer",
        );
        let identity = FakeJwtSource::Degraded;
        let mode = AwsIdentityMode::Spire {
            identity: &identity,
            own_role_arn: TEST_ROLE_ARN,
        };

        let result =
            resolve_client_inner(&envelope, &cfg, &mode, Some(&sts_server.uri()), None).await;
        // Degraded federation must never surface as a crash or a permanent
        // config error — it degrades to the default AWS credential-provider
        // chain (Irsa-equivalent). In a hermetic test environment with no
        // ambient AWS identity that chain has nothing to resolve to and the
        // customer AssumeRole call fails to sign — exactly what a real dal2
        // deployment with degraded SPIRE federation and no IRSA would see
        // too — which must be a *transient* `CredentialError::AssumeRole`,
        // never a hard failure/panic and never misclassified as permanent.
        // An environment that happens to have real ambient credentials
        // (e.g. a developer's own AWS-configured shell) succeeds instead.
        match result {
            Ok(client) => drop(client),
            Err(e) => assert!(!e.is_permanent(), "expected a transient error, got {e:?}"),
        }
    }

    // ── federated_base_credentials (JWT-SVID -> sts:AssumeRoleWithWebIdentity) ──
    //
    // `IdentityProvider` itself can't be faked hermetically from outside
    // `skauswatch-identity` (its attestation internals are deliberately
    // private), so these tests exercise `federated_base_credentials`
    // against a local `JwtSvidSource` test double instead — exactly the
    // seam the trait exists for. See the trait's own doc comment.

    /// Service-owned federation role ARN used by every test below — never
    /// a customer's `role_arn`.
    const TEST_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/skauswatch-base";

    /// A [`JwtSvidSource`] double that either yields a fixed token or fails
    /// like a degraded/unattested `IdentityProvider` would.
    enum FakeJwtSource {
        Token(&'static str),
        Degraded,
    }

    #[async_trait::async_trait]
    impl JwtSvidSource for FakeJwtSource {
        async fn fetch_jwt_svid_token(&self, audience: &str) -> Result<String, CredentialError> {
            assert_eq!(
                audience, AWS_STS_AUDIENCE,
                "federated_base_credentials must request the AWS-documented audience"
            );
            match self {
                FakeJwtSource::Token(t) => Ok((*t).to_owned()),
                FakeJwtSource::Degraded => Err(CredentialError::Identity(
                    "no identity held (test double)".to_owned(),
                )),
            }
        }
    }

    fn assume_role_with_web_identity_success_xml(
        access_key: &str,
        secret_key: &str,
        session_token: &str,
    ) -> String {
        format!(
            "<AssumeRoleWithWebIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
             <AssumeRoleWithWebIdentityResult><Credentials>\
             <AccessKeyId>{access_key}</AccessKeyId>\
             <SecretAccessKey>{secret_key}</SecretAccessKey>\
             <SessionToken>{session_token}</SessionToken>\
             <Expiration>2099-01-01T00:00:00Z</Expiration>\
             </Credentials>\
             <AssumedRoleUser><AssumedRoleId>AROAEXAMPLE:skauswatch-s3scan</AssumedRoleId>\
             <Arn>arn:aws:sts::123456789012:assumed-role/demo/skauswatch-s3scan</Arn>\
             </AssumedRoleUser></AssumeRoleWithWebIdentityResult>\
             <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>\
             </AssumeRoleWithWebIdentityResponse>"
        )
    }

    #[tokio::test]
    async fn federated_base_credentials_sends_jwt_and_role_arn_to_sts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
            .and(body_string_contains("RoleSessionName=skauswatch-s3scan"))
            .and(body_string_contains(
                "WebIdentityToken=fake-spiffe-jwt-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                assume_role_with_web_identity_success_xml(
                    "AKIAFEDERATED",
                    "federatedSecretKey",
                    "federated-session-token",
                ),
                "text/xml",
            ))
            .mount(&server)
            .await;

        let identity = FakeJwtSource::Token("fake-spiffe-jwt-token");
        let creds = federated_base_credentials_inner(
            &identity,
            TEST_ROLE_ARN,
            "us-east-1",
            Some(&server.uri()),
        )
        .await
        .expect("federated_base_credentials_inner");

        assert_eq!(creds.access_key_id(), "AKIAFEDERATED");
        assert_eq!(creds.secret_access_key(), "federatedSecretKey");
        assert_eq!(creds.session_token(), Some("federated-session-token"));
    }

    #[tokio::test]
    async fn federated_base_credentials_short_circuits_when_identity_degraded() {
        // No identity held (Workload API unreachable/unattested) — the STS
        // call must never even be attempted. A mock server with zero
        // mounted routes proves this: if the code incorrectly dialed STS
        // anyway, `received_requests()` would be non-empty.
        let server = MockServer::start().await;
        let identity = FakeJwtSource::Degraded;

        let result = federated_base_credentials_inner(
            &identity,
            TEST_ROLE_ARN,
            "us-east-1",
            Some(&server.uri()),
        )
        .await;

        assert!(matches!(result, Err(CredentialError::Identity(_))));
        let requests = server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert!(
            requests.is_empty(),
            "STS must not be called when the identity source is degraded"
        );
    }

    #[tokio::test]
    async fn federated_base_credentials_propagates_sts_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_raw(
                "<ErrorResponse><Error><Code>AccessDenied</Code>\
                     <Message>not authorized</Message></Error>\
                     <RequestId>r</RequestId></ErrorResponse>",
                "text/xml",
            ))
            .mount(&server)
            .await;

        let identity = FakeJwtSource::Token("fake-spiffe-jwt-token");
        let result = federated_base_credentials_inner(
            &identity,
            TEST_ROLE_ARN,
            "us-east-1",
            Some(&server.uri()),
        )
        .await;

        assert!(matches!(result, Err(CredentialError::AssumeRole(_))));
    }

    #[tokio::test]
    async fn federated_base_credentials_public_entry_point_reaches_real_sts_config() {
        // `federated_base_credentials` (the public, non-`_inner` entry
        // point) always passes `sts_endpoint_override: None` — this proves
        // it still runs the full JWT-fetch-then-STS-call sequence (using
        // the real STS endpoint, which a degraded identity source never
        // lets it reach) rather than merely delegating in a way coverage
        // can't see. Degraded is sufficient here since it fails before any
        // network I/O.
        let identity = FakeJwtSource::Degraded;
        let result = federated_base_credentials(&identity, TEST_ROLE_ARN, "us-east-1").await;
        assert!(matches!(result, Err(CredentialError::Identity(_))));
    }
}
