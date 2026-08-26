//! OCI image provenance verification (`docs/v2-port/v2.1-depgate.md` §5/§9):
//! cosign signature discovery via the `<digest>.sig` OCI tag convention,
//! verified against a single operator-configured RSA public key
//! (`DEPGATE_COSIGN_PUBLIC_KEY_PEM`).
//!
//! **Scope, stated plainly:** this implements ONE real, working
//! verification mode — an RSA-keyed cosign signature (`cosign sign --key
//! rsa.key`) checked with `RSASSA-PKCS1-v1_5`-SHA256 over the "simple
//! signing" payload, using this workspace's existing `rsa`+`sha2`
//! dependencies (see `services/worker-vault-sync/src/providers/oracle.rs`
//! for the same primitives already exercised elsewhere in this workspace).
//! It deliberately does NOT implement:
//! - cosign's own default keygen (ECDSA P-256) — no generic
//!   ECDSA-signature-verification crate is currently a workspace
//!   dependency; adding one (e.g. `p256`/`ecdsa`) for this alone was judged
//!   disproportionate to this phase's scope. RSA-keyed cosign signing is a
//!   real, documented cosign mode (`cosign generate-key-pair` supports
//!   `--key-algorithm rsa`), just not cosign's default.
//! - Sigstore keyless/Fulcio/Rekor verification (short-lived cert + public
//!   transparency-log inclusion proof) — a materially larger trust-root and
//!   transparency-log integration, deferred to a future phase.
//! - SLSA provenance *attestation* verification — attestations (`<digest>.att`
//!   tags, DSSE-enveloped in-toto statements) are not fetched or checked at
//!   all in this phase; only image *signatures* are.
//!
//! Default-permissive per §9/§10 ("Default must not break existing pulls"):
//! [`ProvenanceStatus::Invalid`] is only ever returned when a signature was
//! actually found AND a verification key is configured AND the check failed
//! — every other case (no `.sig` tag, a `.sig` tag with unexpected shape, no
//! key configured to check against, or any fetch failure) resolves to
//! [`ProvenanceStatus::Unsigned`], which the default policy never blocks on
//! (`crate::policy::default_decision` does not consult provenance at all —
//! only an admin-configured `depgate_policy_rules.provenance` rule does).

use crate::upstream::UpstreamClient;

/// The three provenance dispositions a policy rule can match on
/// (`crate::policy::PolicyRule::provenance`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProvenanceStatus {
    /// No cosign signature found (or found but unverifiable/unrecognized
    /// shape, or no verification key configured) — the safe, never-blocking
    /// default.
    Unsigned,
    /// A cosign signature was found and cryptographically verifies against
    /// the configured public key.
    Verified,
    /// A cosign signature was found, a verification key is configured, and
    /// the signature does NOT verify against it.
    Invalid,
}

impl ProvenanceStatus {
    /// Canonical lowercase string, matching the DB `CHECK` constraint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProvenanceStatus::Unsigned => "unsigned",
            ProvenanceStatus::Verified => "verified",
            ProvenanceStatus::Invalid => "invalid",
        }
    }
}

impl std::str::FromStr for ProvenanceStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unsigned" => Ok(ProvenanceStatus::Unsigned),
            "verified" => Ok(ProvenanceStatus::Verified),
            "invalid" => Ok(ProvenanceStatus::Invalid),
            other => Err(format!("unrecognized provenance status: {other:?}")),
        }
    }
}

/// cosign's tag-convention for an image's detached signature manifest:
/// `sha256:<hex>` -> `sha256-<hex>.sig`.
#[must_use]
fn sig_tag(sha256_hex: &str) -> String {
    format!("sha256-{sha256_hex}.sig")
}

/// Extracts `(payload_blob_digest, base64_signature)` from a cosign
/// signature OCI manifest — the first layer's `digest` plus its
/// `dev.cosignproject.cosign/signature` annotation. `None` for anything
/// that isn't shaped like a cosign signature manifest (a `.sig`-tagged
/// artifact that is something else entirely, or a malformed one).
fn parse_cosign_manifest(bytes: &[u8]) -> Option<(String, String)> {
    let doc: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let layer = doc.get("layers")?.as_array()?.first()?;
    let digest = layer.get("digest")?.as_str()?.to_owned();
    let signature = layer
        .get("annotations")?
        .get("dev.cosignproject.cosign/signature")?
        .as_str()?
        .to_owned();
    Some((digest, signature))
}

/// Verifies `payload` against `signature_b64` using `public_key_pem`
/// (accepts either PKCS#8 SPKI `-----BEGIN PUBLIC KEY-----` or PKCS#1
/// `-----BEGIN RSA PUBLIC KEY-----` PEM). `false` for any parse or
/// cryptographic failure — never panics on attacker-influenced input.
fn verify_rsa_signature(public_key_pem: &str, payload: &[u8], signature_b64: &str) -> bool {
    use base64::Engine as _;
    use rsa::RsaPublicKey;
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier as _;

    let Ok(pub_key) = RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
    else {
        return false;
    };
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    verifying_key.verify(payload, &signature).is_ok()
}

/// Discovers and (when `public_key_pem` is configured) verifies a cosign
/// signature for the OCI artifact `name`@`sha256_hex` via `upstream`. Never
/// fails the caller's request — every error path (registry unreachable,
/// `.sig` tag absent, malformed manifest, payload blob missing) resolves to
/// [`ProvenanceStatus::Unsigned`], never propagated as a hard error, per
/// this module's default-permissive contract.
pub async fn verify(
    upstream: &UpstreamClient,
    name: &str,
    sha256_hex: &str,
    public_key_pem: Option<&str>,
    max_bytes: u64,
) -> ProvenanceStatus {
    let tag = sig_tag(sha256_hex);
    let fetched = match upstream.fetch_manifest(name, &tag, max_bytes).await {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(error = %e, name, sha256_hex, "no cosign signature manifest found");
            return ProvenanceStatus::Unsigned;
        }
    };

    let Some((payload_digest, signature_b64)) = parse_cosign_manifest(&fetched.bytes) else {
        return ProvenanceStatus::Unsigned;
    };

    let Some(pem) = public_key_pem else {
        // A signature exists but nothing is configured to check it against
        // — we cannot vouch for it, but we also cannot prove it invalid.
        return ProvenanceStatus::Unsigned;
    };

    let payload = match upstream.fetch_blob(name, &payload_digest, max_bytes).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, name, payload_digest, "cosign signature payload blob fetch failed");
            return ProvenanceStatus::Unsigned;
        }
    };

    if verify_rsa_signature(pem, &payload.bytes, &signature_b64) {
        ProvenanceStatus::Verified
    } else {
        ProvenanceStatus::Invalid
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::UpstreamConfig;
    use crate::test_support::{other_test_public_key_pem, test_keypair};

    fn test_public_key_pem() -> &'static str {
        &test_keypair().1
    }

    fn sign_payload(payload: &[u8]) -> String {
        use base64::Engine as _;
        use rsa::RsaPrivateKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey as _;
        use rsa::sha2::Sha256;
        use rsa::signature::{SignatureEncoding as _, Signer as _};

        let key = RsaPrivateKey::from_pkcs8_pem(&test_keypair().0).expect("parse test key");
        let signing_key = SigningKey::<Sha256>::new(key);
        let signature = signing_key.sign(payload);
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    }

    fn upstream_client(base_url: &str) -> UpstreamClient {
        UpstreamClient::new(
            reqwest::Client::new(),
            UpstreamConfig {
                base_url: base_url.to_owned(),
                auth_url: format!("{base_url}/token"),
                service: "test-registry".to_owned(),
                username: None,
                password: None,
            },
        )
    }

    #[test]
    fn sig_tag_follows_the_cosign_convention() {
        assert_eq!(sig_tag("deadbeef"), "sha256-deadbeef.sig");
    }

    #[test]
    fn status_round_trips() {
        for s in [
            ProvenanceStatus::Unsigned,
            ProvenanceStatus::Verified,
            ProvenanceStatus::Invalid,
        ] {
            assert_eq!(
                s.as_str().parse::<ProvenanceStatus>().expect("round trip"),
                s
            );
        }
        assert!("bogus".parse::<ProvenanceStatus>().is_err());
    }

    #[test]
    fn parse_cosign_manifest_extracts_digest_and_signature() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "layers": [{
                "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                "digest": "sha256:abc123",
                "annotations": {"dev.cosignproject.cosign/signature": "c2ln"}
            }]
        });
        let (digest, sig) =
            parse_cosign_manifest(&serde_json::to_vec(&manifest).expect("serialize"))
                .expect("parses");
        assert_eq!(digest, "sha256:abc123");
        assert_eq!(sig, "c2ln");
    }

    #[test]
    fn parse_cosign_manifest_returns_none_for_unrelated_shape() {
        let manifest = serde_json::json!({"schemaVersion": 2, "layers": []});
        assert!(
            parse_cosign_manifest(&serde_json::to_vec(&manifest).expect("serialize")).is_none()
        );
    }

    #[test]
    fn verify_rsa_signature_round_trips() {
        let payload = b"simple signing payload bytes";
        let sig = sign_payload(payload);
        assert!(verify_rsa_signature(test_public_key_pem(), payload, &sig));
    }

    #[test]
    fn verify_rsa_signature_rejects_wrong_key() {
        let payload = b"simple signing payload bytes";
        let sig = sign_payload(payload);
        assert!(!verify_rsa_signature(
            &other_test_public_key_pem(),
            payload,
            &sig
        ));
    }

    #[test]
    fn verify_rsa_signature_rejects_tampered_payload() {
        let sig = sign_payload(b"original payload");
        assert!(!verify_rsa_signature(
            test_public_key_pem(),
            b"tampered payload",
            &sig
        ));
    }

    #[test]
    fn verify_rsa_signature_rejects_malformed_base64() {
        assert!(!verify_rsa_signature(
            test_public_key_pem(),
            b"payload",
            "not-base64!!"
        ));
    }

    #[tokio::test]
    async fn verify_returns_unsigned_when_no_sig_tag_exists() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/sha256-deadbeef.sig"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let upstream = upstream_client(&server.uri());
        let status = upstream
            .fetch_manifest("library/nginx", "sha256-deadbeef.sig", 1024)
            .await;
        assert!(status.is_err());
        let got = verify(&upstream, "library/nginx", "deadbeef", None, 1024).await;
        assert_eq!(got, ProvenanceStatus::Unsigned);
    }

    #[tokio::test]
    async fn verify_returns_unsigned_when_sig_exists_but_no_key_configured() {
        let server = MockServer::start().await;
        let payload = b"simple signing payload";
        let payload_hex = skauswatch_scan_core::compute_hashes(payload).sha256;
        let sig = sign_payload(payload);
        let manifest = serde_json::json!({
            "layers": [{
                "digest": format!("sha256:{payload_hex}"),
                "annotations": {"dev.cosignproject.cosign/signature": sig}
            }]
        });
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/sha256-deadbeef.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(manifest))
            .mount(&server)
            .await;

        let upstream = upstream_client(&server.uri());
        let got = verify(&upstream, "library/nginx", "deadbeef", None, 1024 * 1024).await;
        assert_eq!(got, ProvenanceStatus::Unsigned);
    }

    #[tokio::test]
    async fn verify_returns_verified_for_a_valid_signature() {
        let server = MockServer::start().await;
        let payload = b"simple signing payload bytes for verified case";
        let payload_hex = skauswatch_scan_core::compute_hashes(payload).sha256;
        let sig = sign_payload(payload);
        let manifest = serde_json::json!({
            "layers": [{
                "digest": format!("sha256:{payload_hex}"),
                "annotations": {"dev.cosignproject.cosign/signature": sig}
            }]
        });
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/sha256-deadbeef.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(manifest))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/blobs/sha256:{payload_hex}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.to_vec()))
            .mount(&server)
            .await;

        let upstream = upstream_client(&server.uri());
        let got = verify(
            &upstream,
            "library/nginx",
            "deadbeef",
            Some(test_public_key_pem()),
            1024 * 1024,
        )
        .await;
        assert_eq!(got, ProvenanceStatus::Verified);
    }

    #[tokio::test]
    async fn verify_returns_invalid_for_a_signature_that_does_not_match_the_configured_key() {
        let server = MockServer::start().await;
        let payload = b"simple signing payload bytes for invalid case";
        let payload_hex = skauswatch_scan_core::compute_hashes(payload).sha256;
        let sig = sign_payload(payload);
        let manifest = serde_json::json!({
            "layers": [{
                "digest": format!("sha256:{payload_hex}"),
                "annotations": {"dev.cosignproject.cosign/signature": sig}
            }]
        });
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/sha256-deadbeef.sig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(manifest))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/library/nginx/blobs/sha256:{payload_hex}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.to_vec()))
            .mount(&server)
            .await;

        let upstream = upstream_client(&server.uri());
        // Configured with a DIFFERENT public key than the one that signed.
        let got = verify(
            &upstream,
            "library/nginx",
            "deadbeef",
            Some(&other_test_public_key_pem()),
            1024 * 1024,
        )
        .await;
        assert_eq!(got, ProvenanceStatus::Invalid);
    }

    #[tokio::test]
    async fn verify_returns_unsigned_when_the_sig_tag_manifest_is_not_cosign_shaped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/sha256-deadbeef.sig"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"schemaVersion": 2})),
            )
            .mount(&server)
            .await;
        let upstream = upstream_client(&server.uri());
        let got = verify(
            &upstream,
            "library/nginx",
            "deadbeef",
            Some(test_public_key_pem()),
            1024,
        )
        .await;
        assert_eq!(got, ProvenanceStatus::Unsigned);
    }
}
