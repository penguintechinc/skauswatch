//! The SSH certificate authority engine: CA key loading and OpenSSH
//! certificate signing.
//!
//! This replaces the v1 hand-rolled byte builder (`_build_ssh_certificate`),
//! which emitted certificates `ssh-keygen -L` could not parse (no leading
//! cert-type string in the signed blob, mis-laid-out subject key fields, a
//! hardcoded `ssh-rsa-cert-v01` type regardless of the subject algorithm, and
//! a signature over the wrong byte range). Certificates are now produced by
//! the `ssh-key` crate, so they are standards-compliant OpenSSH certificates.
//!
//! Preserved v1 template semantics: type→User(1)/Host(2), `key_id` format,
//! validity as a `valid_after..valid_after+duration` window, principals, and
//! caller-supplied extensions/critical options.

use std::collections::BTreeMap;
use std::path::Path;

use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};

use crate::model::CertificateType;

/// Loaded CA signing identity plus its cached public representations.
pub struct SshCa {
    ca_key: PrivateKey,
    ca_public_key_openssh: String,
    ca_fingerprint: String,
}

/// Inputs to a single signing operation (already-resolved defaults).
pub struct SignParams<'a> {
    /// User or host certificate.
    pub certificate_type: CertificateType,
    /// Subject public key as an OpenSSH line.
    pub public_key_line: &'a str,
    /// Certificate principals.
    pub principals: &'a [String],
    /// Serial number.
    pub serial: u64,
    /// Certificate key id.
    pub key_id: &'a str,
    /// Unix seconds the certificate becomes valid.
    pub valid_after: u64,
    /// Unix seconds the certificate expires.
    pub valid_before: u64,
    /// Certificate extensions (flag values are empty strings).
    pub extensions: &'a BTreeMap<String, String>,
    /// Certificate critical options.
    pub critical_options: &'a BTreeMap<String, String>,
}

/// Output of a signing operation.
pub struct SignedCert {
    /// The signed OpenSSH certificate line.
    pub signed_certificate: String,
    /// Subject key SHA256 fingerprint (`SHA256:…`).
    pub public_key_fingerprint: String,
}

/// Signing errors, split so the caller can return 400 (bad client input) vs
/// 500 (CA-side failure).
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The subject public key could not be decoded — a client error (400).
    #[error("invalid subject public key: {0}")]
    InvalidSubjectKey(String),
    /// A CA-side failure while building/signing/encoding the certificate (500).
    #[error("certificate signing failure: {0}")]
    Signing(String),
}

impl SshCa {
    /// Loads the CA private key from `path` (OpenSSH format), or generates an
    /// ephemeral Ed25519 CA key with a loud warning when the file is absent.
    ///
    /// The generate-on-missing fallback preserves v1's demo behaviour (v1
    /// generated an in-memory RSA-2048 key); it is unsafe for production —
    /// certificates it signs cannot be verified after a restart. Deployments
    /// MUST mount a persistent CA key.
    pub fn load_or_generate(path: &Path) -> anyhow::Result<Self> {
        let ca_key = if path.exists() {
            let key = PrivateKey::read_openssh_file(path)
                .map_err(|e| anyhow::anyhow!("failed to load CA key {}: {e}", path.display()))?;
            // The pinned ssh-key 0.6.7 backend cannot sign with RSA CA keys
            // (upstream bug: RSA private-key reconstruction uses prime `p`
            // twice instead of `p`/`q`, so every RSA signature errors). Fail
            // fast with actionable guidance rather than 500-ing per request.
            // Ed25519 is preferred; ECDSA P-256/P-384 also work.
            if matches!(key.algorithm(), Algorithm::Rsa { .. }) {
                anyhow::bail!(
                    "CA key {} is RSA, which is unsupported by this build \
                     (ssh-key 0.6.7 cannot sign with RSA CA keys). Use an \
                     Ed25519 CA key: `ssh-keygen -t ed25519 -f {}`",
                    path.display(),
                    path.display()
                );
            }
            tracing::info!(path = %path.display(), algorithm = %key.algorithm(), "CA key loaded");
            key
        } else {
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .map_err(|e| anyhow::anyhow!("failed to generate ephemeral CA key: {e}"))?;
            tracing::warn!(
                path = %path.display(),
                "CA key file missing — generated an EPHEMERAL Ed25519 CA key; \
                 certificates will not verify after restart. Mount a persistent \
                 CA key for production."
            );
            key
        };

        let ca_public_key_openssh = ca_key
            .public_key()
            .to_openssh()
            .map_err(|e| anyhow::anyhow!("failed to encode CA public key: {e}"))?;
        let ca_fingerprint = ca_key.public_key().fingerprint(HashAlg::Sha256).to_string();

        Ok(Self {
            ca_key,
            ca_public_key_openssh,
            ca_fingerprint,
        })
    }

    /// CA public key as an OpenSSH line (v1 `get_ca_public_key`).
    pub fn public_key_openssh(&self) -> &str {
        &self.ca_public_key_openssh
    }

    /// CA key OpenSSH SHA256 fingerprint (`SHA256:…`). Replaces v1's
    /// non-standard hex-of-sha256 fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.ca_fingerprint
    }

    /// Signs an OpenSSH certificate for `params`. A subject key that cannot be
    /// decoded yields `SignError::InvalidSubjectKey` (client 400); every other
    /// failure is `SignError::Signing` (server 500).
    pub fn sign(&self, params: &SignParams<'_>) -> Result<SignedCert, SignError> {
        let subject = PublicKey::from_openssh(params.public_key_line)
            .map_err(|e| SignError::InvalidSubjectKey(e.to_string()))?;
        let public_key_fingerprint = subject.fingerprint(HashAlg::Sha256).to_string();

        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            subject.key_data().clone(),
            params.valid_after,
            params.valid_before,
        )
        .map_err(|e| SignError::Signing(format!("builder init: {e}")))?;

        builder
            .serial(params.serial)
            .map_err(|e| SignError::Signing(format!("set serial: {e}")))?;
        builder
            .key_id(params.key_id.to_owned())
            .map_err(|e| SignError::Signing(format!("set key id: {e}")))?;
        let cert_type = match params.certificate_type {
            CertificateType::User => CertType::User,
            CertificateType::Host => CertType::Host,
        };
        builder
            .cert_type(cert_type)
            .map_err(|e| SignError::Signing(format!("set cert type: {e}")))?;

        // Empty principals ⇒ valid for all principals (documented contract,
        // `docs/v2-port/sshca-contract.md`). The `ssh-key` builder treats an
        // unset `valid_principals` as an error unless `all_principals_valid`
        // is called explicitly — omitting this call previously made every
        // request with an empty/omitted `principals` list fail signing with
        // a 500 instead of producing the documented "golden ticket" cert.
        if params.principals.is_empty() {
            builder
                .all_principals_valid()
                .map_err(|e| SignError::Signing(format!("mark all principals valid: {e}")))?;
        } else {
            for principal in params.principals {
                builder
                    .valid_principal(principal.clone())
                    .map_err(|e| SignError::Signing(format!("add principal: {e}")))?;
            }
        }
        for (name, data) in params.critical_options {
            builder
                .critical_option(name.clone(), data.clone())
                .map_err(|e| SignError::Signing(format!("add critical option {name}: {e}")))?;
        }
        for (name, data) in params.extensions {
            builder
                .extension(name.clone(), data.clone())
                .map_err(|e| SignError::Signing(format!("add extension {name}: {e}")))?;
        }

        let cert = builder
            .sign(&self.ca_key)
            .map_err(|e| SignError::Signing(format!("sign: {e}")))?;
        let signed_certificate = cert
            .to_openssh()
            .map_err(|e| SignError::Signing(format!("encode: {e}")))?;

        Ok(SignedCert {
            signed_certificate,
            public_key_fingerprint,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ssh_key::Certificate;

    fn gen_ca() -> SshCa {
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("generate ca key");
        let ca_public_key_openssh = ca_key.public_key().to_openssh().expect("ca pub");
        let ca_fingerprint = ca_key.public_key().fingerprint(HashAlg::Sha256).to_string();
        SshCa {
            ca_key,
            ca_public_key_openssh,
            ca_fingerprint,
        }
    }

    fn gen_subject() -> String {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("subject key");
        key.public_key().to_openssh().expect("subject pub")
    }

    #[test]
    fn signs_valid_user_certificate_with_expected_template() -> anyhow::Result<()> {
        let ca = gen_ca();
        let subject = gen_subject();
        let principals = vec!["alice".to_owned(), "bob".to_owned()];
        let mut extensions = BTreeMap::new();
        extensions.insert("permit-pty".to_owned(), String::new());
        let critical_options = BTreeMap::new();

        let signed = ca.sign(&SignParams {
            certificate_type: CertificateType::User,
            public_key_line: &subject,
            principals: &principals,
            serial: 1_000_001,
            key_id: "user-req-1",
            valid_after: 1_000,
            valid_before: 4_600,
            extensions: &extensions,
            critical_options: &critical_options,
        })?;

        // The certificate must be a parseable OpenSSH certificate (v1's was not).
        let cert = Certificate::from_openssh(&signed.signed_certificate)?;
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.serial(), 1_000_001);
        assert_eq!(cert.key_id(), "user-req-1");
        assert_eq!(
            cert.valid_principals(),
            &["alice".to_owned(), "bob".to_owned()]
        );
        assert_eq!(cert.valid_after(), 1_000);
        assert_eq!(cert.valid_before(), 4_600);
        // Duration semantics preserved: window == validity_duration.
        assert_eq!(cert.valid_before() - cert.valid_after(), 3_600);
        assert!(cert.extensions().0.contains_key("permit-pty"));
        // The embedded signature key is our CA.
        assert_eq!(cert.signature_key(), ca.ca_key.public_key().key_data());
        // The signature cryptographically verifies, and the cert validates
        // against the CA fingerprint within its validity window.
        assert!(cert.verify_signature().is_ok());
        let ca_fp = ca.ca_key.public_key().fingerprint(HashAlg::Sha256);
        assert!(cert.validate_at(2_000, [ca_fp].iter()).is_ok());
        assert!(signed.public_key_fingerprint.starts_with("SHA256:"));
        Ok(())
    }

    /// Regression: an empty principals list must sign successfully as a
    /// "golden ticket" cert (documented contract, `sshca-contract.md`), not
    /// fail signing — the `ssh-key` builder errors on an *unset*
    /// `valid_principals`, which is a different state than "explicitly
    /// valid for all", so the empty case must be handled explicitly.
    #[test]
    fn empty_principals_signs_as_valid_for_all() -> anyhow::Result<()> {
        let ca = gen_ca();
        let subject = gen_subject();
        let signed = ca.sign(&SignParams {
            certificate_type: CertificateType::User,
            public_key_line: &subject,
            principals: &[],
            serial: 42,
            key_id: "user-req-golden",
            valid_after: 1_000,
            valid_before: 2_000,
            extensions: &BTreeMap::new(),
            critical_options: &BTreeMap::new(),
        })?;
        let cert = Certificate::from_openssh(&signed.signed_certificate)?;
        assert!(cert.valid_principals().is_empty());
        assert!(cert.verify_signature().is_ok());
        Ok(())
    }

    #[test]
    fn signs_host_certificate() -> anyhow::Result<()> {
        let ca = gen_ca();
        let subject = gen_subject();
        let principals = vec!["host.example.com".to_owned()];
        let signed = ca.sign(&SignParams {
            certificate_type: CertificateType::Host,
            public_key_line: &subject,
            principals: &principals,
            serial: 1_000_002,
            key_id: "host-req-1",
            valid_after: 1_000,
            valid_before: 4_600,
            extensions: &BTreeMap::new(),
            critical_options: &BTreeMap::new(),
        })?;
        let cert = Certificate::from_openssh(&signed.signed_certificate)?;
        assert_eq!(cert.cert_type(), CertType::Host);
        assert_eq!(cert.valid_principals(), &["host.example.com".to_owned()]);
        assert!(cert.extensions().0.is_empty());
        Ok(())
    }

    #[test]
    fn encodes_critical_options() -> anyhow::Result<()> {
        let ca = gen_ca();
        let subject = gen_subject();
        let mut critical_options = BTreeMap::new();
        critical_options.insert("force-command".to_owned(), "/usr/bin/true".to_owned());
        critical_options.insert("source-address".to_owned(), "10.0.0.0/8".to_owned());
        let signed = ca.sign(&SignParams {
            certificate_type: CertificateType::User,
            public_key_line: &subject,
            principals: &["carol".to_owned()],
            serial: 7,
            key_id: "user-req-2",
            valid_after: 1_000,
            valid_before: 2_000,
            extensions: &BTreeMap::new(),
            critical_options: &critical_options,
        })?;
        let cert = Certificate::from_openssh(&signed.signed_certificate)?;
        assert!(cert.critical_options().0.contains_key("force-command"));
        assert!(cert.critical_options().0.contains_key("source-address"));
        Ok(())
    }

    // Cross-parity emitter: when `SSHCA_PARITY_DIR` points at a directory
    // containing `ca_key` + subject fixtures, sign a user and host cert with
    // the real load+sign code path and write them out for an external
    // `ssh-keygen -L` diff against the OpenSSH golden. A no-op otherwise, so it
    // never runs (or touches the filesystem) during normal `cargo test`.
    #[test]
    fn emit_parity_certs_when_requested() -> anyhow::Result<()> {
        let Ok(dir) = std::env::var("SSHCA_PARITY_DIR") else {
            return Ok(());
        };
        let dir = std::path::PathBuf::from(dir);
        let ca = SshCa::load_or_generate(&dir.join("ca_key"))?;

        let user_permits = [
            "permit-X11-forwarding",
            "permit-agent-forwarding",
            "permit-port-forwarding",
            "permit-pty",
            "permit-user-rc",
        ];
        let mut ext = BTreeMap::new();
        for e in user_permits {
            ext.insert(e.to_owned(), String::new());
        }
        let subject_user = std::fs::read_to_string(dir.join("subj_ed25519.pub"))?;
        let user = ca.sign(&SignParams {
            certificate_type: CertificateType::User,
            public_key_line: subject_user.trim(),
            principals: &["alice".to_owned(), "bob".to_owned()],
            serial: 1_000_001,
            key_id: "user-req-USERID",
            valid_after: 1_000_000_000,
            valid_before: 1_000_003_600,
            extensions: &ext,
            critical_options: &BTreeMap::new(),
        })?;
        std::fs::write(
            dir.join("v2_user-cert.pub"),
            format!("{}\n", user.signed_certificate),
        )?;

        let subject_host = std::fs::read_to_string(dir.join("subj_rsa.pub"))?;
        let host = ca.sign(&SignParams {
            certificate_type: CertificateType::Host,
            public_key_line: subject_host.trim(),
            principals: &["host.example.com".to_owned()],
            serial: 1_000_002,
            key_id: "host-req-HOSTID",
            valid_after: 1_000_000_000,
            valid_before: 1_000_003_600,
            extensions: &BTreeMap::new(),
            critical_options: &BTreeMap::new(),
        })?;
        std::fs::write(
            dir.join("v2_host-cert.pub"),
            format!("{}\n", host.signed_certificate),
        )?;
        Ok(())
    }

    /// Unique scratch path under the OS temp dir — avoids collisions with
    /// any other test/process (`unsafe_code = "deny"` rules out reusing a
    /// fixed path across parallel tests via env-var tricks).
    fn scratch_key_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("skauswatch-sshca-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn load_or_generate_loads_a_real_ed25519_key_from_disk() -> anyhow::Result<()> {
        let path = scratch_key_path();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        key.write_openssh_file(&path, ssh_key::LineEnding::LF)?;

        let ca = SshCa::load_or_generate(&path)?;
        std::fs::remove_file(&path)?;

        assert!(ca.fingerprint().starts_with("SHA256:"));
        assert_eq!(
            ca.public_key_openssh(),
            key.public_key().to_openssh()?.as_str()
        );
        Ok(())
    }

    #[test]
    fn load_or_generate_rejects_rsa_ca_keys() -> anyhow::Result<()> {
        let path = scratch_key_path();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None })?;
        key.write_openssh_file(&path, ssh_key::LineEnding::LF)?;

        let result = SshCa::load_or_generate(&path);
        std::fs::remove_file(&path)?;

        let err = match result {
            Ok(_) => panic!("expected RSA CA key to be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("RSA"), "error was: {err}");
        Ok(())
    }

    #[test]
    fn load_or_generate_reports_a_corrupt_key_file() -> anyhow::Result<()> {
        let path = scratch_key_path();
        std::fs::write(&path, b"this is not an OpenSSH private key")?;

        let result = SshCa::load_or_generate(&path);
        std::fs::remove_file(&path)?;

        let err = match result {
            Ok(_) => panic!("expected a corrupt key file to fail to load"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("failed to load CA key"));
        Ok(())
    }

    #[test]
    fn load_or_generate_generates_ephemeral_key_when_file_missing() -> anyhow::Result<()> {
        let path = scratch_key_path(); // never written — guaranteed absent
        let ca = SshCa::load_or_generate(&path)?;
        assert!(ca.fingerprint().starts_with("SHA256:"));
        assert!(!ca.public_key_openssh().is_empty());
        Ok(())
    }

    #[test]
    fn rejects_invalid_subject_key() {
        let ca = gen_ca();
        let res = ca.sign(&SignParams {
            certificate_type: CertificateType::User,
            public_key_line: "not-a-key",
            principals: &[],
            serial: 1,
            key_id: "x",
            valid_after: 1,
            valid_before: 2,
            extensions: &BTreeMap::new(),
            critical_options: &BTreeMap::new(),
        });
        assert!(res.is_err());
    }
}
