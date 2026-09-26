//! Gated live-AWS smoke test: proves `skauswatch_s3::credentials`'s two
//! keyless credential-exchange entry points — [`assume_role_credentials`]
//! (Path 1: hybrid customer-role model) and [`federated_base_credentials`]
//! (Path 2: SPIFFE-federated `AssumeRoleWithWebIdentity`, dal2's IRSA
//! equivalent) — actually obtain temporary credentials from real AWS STS,
//! not the wiremock harness used everywhere else in this crate.
//!
//! The SPIRE Workload API fetch itself is shimmed: [`FixedJwtSource`] below
//! stands in for `skauswatch_identity::IdentityProvider`, returning a
//! pre-minted JWT that `run.sh` signed against a throwaway self-hosted OIDC
//! issuer (an S3 bucket serving `.well-known/openid-configuration` + JWKS —
//! the AWS-documented technique for a self-managed OIDC provider, the same
//! shape IRSA itself uses against EKS's built-in issuer). Only the
//! AWS-facing token exchange (`sts:AssumeRoleWithWebIdentity`) is exercised
//! against real AWS; nothing in `skauswatch-identity`'s own SPIFFE
//! attestation path runs here — see
//! `docs/v2-port/aws-identity-runbook.md` for the full chain this
//! federation hop sits inside of.
//!
//! # Running
//! Skipped (no-op, exit 0) unless `SKAUSWATCH_AWS_LIVE=1` is set — normal CI
//! has neither this env var nor the AWS/OIDC fixtures it depends on, so it
//! silently no-ops there. Driven end to end by
//! `tests/smoke/aws_identity/run.sh`, which provisions the throwaway IAM
//! roles/OIDC provider/bucket (all named `skauswatch-awslive-*`), exports
//! `AR_ROLE_ARN`/`AR_EXTERNAL_ID`/`WID_ROLE_ARN`/`WID_TOKEN`, runs this
//! test, then unconditionally tears every resource back down:
//!
//! ```sh
//! tests/smoke/aws_identity/run.sh
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use skauswatch_s3::credentials::{
    CredentialError, JwtSvidSource, assume_role_credentials, federated_base_credentials,
};

/// Env var that gates every test in this file. Absent -> no-op (see module
/// docs).
const AWS_LIVE_ENV: &str = "SKAUSWATCH_AWS_LIVE";

/// True (after printing why) when the live-AWS fixtures aren't present —
/// every test in this file starts with `if skip() { return; }`.
fn skip() -> bool {
    if std::env::var(AWS_LIVE_ENV).is_err() {
        eprintln!(
            "skipping: set {AWS_LIVE_ENV}=1 (with the tests/smoke/aws_identity/run.sh fixtures) \
             to run against real AWS"
        );
        return true;
    }
    false
}

/// Reads a fixture env var `run.sh` is responsible for exporting; panicking
/// here means the test was invoked directly instead of via `run.sh`.
fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set by run.sh"))
}

/// [`JwtSvidSource`] test double standing in for
/// `skauswatch_identity::IdentityProvider` — returns the fixed JWT `run.sh`
/// minted against the throwaway S3-hosted OIDC issuer, regardless of the
/// requested audience. The real `IdentityProvider` impl always requests
/// [`skauswatch_s3::credentials::AWS_STS_AUDIENCE`]; this test's JWT was
/// minted with that exact audience baked into its claims already, so no
/// audience branching is needed here.
struct FixedJwtSource(String);

#[async_trait::async_trait]
impl JwtSvidSource for FixedJwtSource {
    async fn fetch_jwt_svid_token(&self, _audience: &str) -> Result<String, CredentialError> {
        Ok(self.0.clone())
    }
}

/// Path 1 (hybrid customer-role model): [`assume_role_credentials`]
/// exchanges a role ARN + external ID for temporary credentials via real
/// `sts:AssumeRole`, with no base-credentials override — i.e. using this
/// process's own ambient AWS identity (the `skauswatch-test` IAM user, via
/// `AWS_SHARED_CREDENTIALS_FILE`/`AWS_PROFILE`) as the caller, exactly as
/// production does when `AwsIdentityMode::Irsa` (or a resolved `Spire` base
/// identity) supplies no override.
#[tokio::test]
async fn assume_role_hybrid_against_real_sts() {
    if skip() {
        return;
    }
    let role_arn = env_var("AR_ROLE_ARN");
    let external_id = env_var("AR_EXTERNAL_ID");

    let creds = assume_role_credentials(&role_arn, Some(&external_id), "us-east-1", None, None)
        .await
        .expect("assume_role_credentials against real STS");
    assert!(!creds.access_key_id().is_empty());
    assert!(!creds.secret_access_key().is_empty());
    assert!(creds.session_token().is_some_and(|t| !t.is_empty()));

    let identity = caller_identity_arn(&creds).await;
    assert!(
        identity.contains("assumed-role/skauswatch-awslive-arrole"),
        "expected an assumed-role ARN for skauswatch-awslive-arrole, got {identity}"
    );
}

/// Path 2 (SPIFFE federation): [`federated_base_credentials`] exchanges a
/// JWT (fetched from the [`FixedJwtSource`] shim) for temporary base AWS
/// credentials via real `sts:AssumeRoleWithWebIdentity` — dal2's IRSA
/// equivalent, exercised end to end against the throwaway self-hosted OIDC
/// issuer `run.sh` stood up.
#[tokio::test]
async fn spiffe_webidentity_against_real_sts() {
    if skip() {
        return;
    }
    let role_arn = env_var("WID_ROLE_ARN");
    let token = env_var("WID_TOKEN");
    let identity_source = FixedJwtSource(token);

    let creds = federated_base_credentials(&identity_source, &role_arn, "us-east-1")
        .await
        .expect("federated_base_credentials against real STS");
    assert!(!creds.access_key_id().is_empty());
    assert!(!creds.secret_access_key().is_empty());
    assert!(creds.session_token().is_some_and(|t| !t.is_empty()));

    let identity = caller_identity_arn(&creds).await;
    assert!(
        identity.contains("assumed-role/skauswatch-awslive-widrole"),
        "expected an assumed-role ARN for skauswatch-awslive-widrole, got {identity}"
    );
}

/// Builds an `aws_sdk_sts` client from freshly obtained temporary
/// credentials and calls `sts:GetCallerIdentity` — the only reliable way to
/// prove the credentials handed back by our two functions are real and
/// resolve to the expected assumed role, not merely structurally
/// non-empty strings.
async fn caller_identity_arn(creds: &Credentials) -> String {
    let sts_config = aws_sdk_sts::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(creds.clone())
        .build();
    let client = aws_sdk_sts::Client::from_conf(sts_config);
    let resp = client
        .get_caller_identity()
        .send()
        .await
        .expect("get_caller_identity with freshly assumed-role credentials");
    resp.arn()
        .expect("GetCallerIdentity response has an ARN")
        .to_owned()
}
