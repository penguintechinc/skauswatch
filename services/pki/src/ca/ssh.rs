//! SSH Certificate Authority — port of v1's `ca/ssh_authority.py`. Like v1 it
//! shells out to `ssh-keygen`, so the issued certificate bytes are produced by
//! the exact same tool (inherent parity). Serial and KRL-version counters are
//! in-memory and reset on restart, matching v1.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::SshCaConfig;

/// Errors raised by the SSH CA engine.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    /// Caller-supplied input was invalid.
    #[error("{0}")]
    BadRequest(String),
    /// A crypto/subprocess/filesystem operation failed.
    #[error("{0}")]
    Internal(String),
}

/// Parameters for issuing one SSH certificate (mirrors v1 kwargs).
#[derive(Debug, Clone)]
pub struct SshIssueParams {
    /// The subject's SSH public key (OpenSSH single-line format).
    pub public_key: String,
    /// `user` or `host`.
    pub certificate_type: String,
    /// Optional key id; defaults to `skauswatch-{type}-{serial}`.
    pub key_id: Option<String>,
    /// Certificate principals (at least one required).
    pub principals: Vec<String>,
    /// Requested validity in seconds (capped at `max_validity_seconds`).
    pub validity_seconds: i64,
    /// Certificate extensions (user certs); insertion order preserved.
    pub extensions: Option<Vec<(String, String)>>,
    /// Critical options (user certs).
    pub critical_options: Option<Vec<(String, String)>>,
    /// Allowed source addresses (user certs).
    pub source_addresses: Vec<String>,
    /// Forced command (user certs).
    pub force_command: Option<String>,
    /// Hostname (host certs).
    pub hostname: Option<String>,
}

/// Result of issuing an SSH certificate.
#[derive(Debug, Clone)]
pub struct IssuedSsh {
    /// The signed certificate (OpenSSH `*-cert.pub` line).
    pub certificate: String,
    /// Serial number (decimal string, v1 form).
    pub serial: String,
    /// Effective key id.
    pub key_id: String,
    /// Certificate type echoed back.
    pub certificate_type: String,
    /// Principals echoed back.
    pub principals: Vec<String>,
    /// notBefore (naive UTC).
    pub valid_after: chrono::NaiveDateTime,
    /// notAfter (naive UTC).
    pub valid_before: chrono::NaiveDateTime,
    /// Detected subject key type (`rsa`/`ed25519`/`ecdsa`/`unknown`).
    pub key_type: String,
    /// Effective extensions applied (v1 echoes request or defaults).
    pub extensions: Vec<(String, String)>,
}

/// Default user-certificate extensions (v1 `DEFAULT_USER_EXTENSIONS`).
fn default_user_extensions() -> Vec<(String, String)> {
    vec![
        ("permit-agent-forwarding".into(), String::new()),
        ("permit-port-forwarding".into(), String::new()),
        ("permit-pty".into(), String::new()),
        ("permit-user-rc".into(), String::new()),
    ]
}

/// SSH Certificate Authority backed by `ssh-keygen`.
pub struct SshCa {
    config: SshCaConfig,
    ca_public_key: String,
    ca_fingerprint: String,
    serial_counter: AtomicU64,
    krl_version: AtomicU64,
}

impl SshCa {
    /// Loads the SSH CA key material, generating a new CA key if the private
    /// key file is absent (v1 `initialize`).
    pub fn load_or_generate(config: SshCaConfig) -> Result<Self, SshError> {
        if !std::path::Path::new(&config.ca_key_path).exists() {
            tracing::warn!("SSH CA key not found, generating new CA");
            generate_ca(&config)?;
        }
        let (ca_public_key, ca_fingerprint) = load_ca(&config)?;
        tracing::info!(fingerprint = %ca_fingerprint, "SSH CA initialized");
        Ok(Self {
            config,
            ca_public_key,
            ca_fingerprint,
            serial_counter: AtomicU64::new(1),
            krl_version: AtomicU64::new(0),
        })
    }

    /// Test-only in-memory CA: no `ssh-keygen` subprocess, no filesystem I/O.
    /// `ssh-keygen` isn't installed in the plain `rust:*-bookworm` CI/build
    /// image this workspace verifies against, so any test that only needs
    /// *a* constructible `SshCa` (e.g. building `AppStateInner` to exercise
    /// the auth gate, not actual cert signing) must not call
    /// `load_or_generate`, which unconditionally shells out.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            config: SshCaConfig {
                ca_key_path: String::new(),
                ca_public_key_path: String::new(),
                ca_key_password: None,
                default_validity_seconds: 86_400,
                max_validity_seconds: 604_800,
                default_key_type: "ed25519".to_owned(),
                krl_path: String::new(),
            },
            ca_public_key: "ssh-ed25519 AAAAtest test-ca".to_owned(),
            ca_fingerprint: "SHA256:testtesttesttesttesttesttesttesttesttest".to_owned(),
            serial_counter: AtomicU64::new(1),
            krl_version: AtomicU64::new(0),
        }
    }

    /// CA public key line (v1 `get_ca_public_key`).
    pub fn ca_public_key(&self) -> &str {
        &self.ca_public_key
    }

    /// CA fingerprint (v1 `get_ca_info` `fingerprint`).
    pub fn ca_fingerprint(&self) -> &str {
        &self.ca_fingerprint
    }

    /// CA key type derived from the public key prefix.
    pub fn ca_key_type(&self) -> String {
        detect_key_type(&self.ca_public_key)
    }

    /// Current serial counter (v1 `get_ca_info` `serial_counter`).
    pub fn serial_counter(&self) -> i64 {
        self.serial_counter.load(Ordering::SeqCst) as i64
    }

    /// Current KRL version (v1 `get_ca_info` `krl_version`).
    pub fn krl_version(&self) -> i64 {
        self.krl_version.load(Ordering::SeqCst) as i64
    }

    /// Issues an SSH certificate via `ssh-keygen -s`, reproducing v1's exact
    /// command construction.
    pub fn issue(&self, params: &SshIssueParams) -> Result<IssuedSsh, SshError> {
        if params.principals.is_empty() {
            return Err(SshError::BadRequest(
                "At least one principal is required".into(),
            ));
        }
        if params.certificate_type != "user" && params.certificate_type != "host" {
            return Err(SshError::BadRequest(format!(
                "Invalid certificate type: {}",
                params.certificate_type
            )));
        }

        let validity_seconds = params
            .validity_seconds
            .min(self.config.max_validity_seconds);
        let serial = self.serial_counter.fetch_add(1, Ordering::SeqCst);
        let key_id = params
            .key_id
            .clone()
            .filter(|k| !k.is_empty())
            .unwrap_or_else(|| format!("skauswatch-{}-{}", params.certificate_type, serial));

        let now = chrono::Utc::now();
        let valid_after = now.naive_utc();
        let valid_before = (now + chrono::Duration::seconds(validity_seconds)).naive_utc();

        let tmp = TempDir::new()?;
        let pub_file = tmp.path.join("key.pub");
        let cert_file = tmp.path.join("key-cert.pub");
        std::fs::write(&pub_file, &params.public_key)
            .map_err(|e| SshError::Internal(format!("write pubkey: {e}")))?;

        let mut cmd = Command::new("ssh-keygen");
        cmd.arg("-s")
            .arg(&self.config.ca_key_path)
            .arg("-I")
            .arg(&key_id)
            .arg("-z")
            .arg(serial.to_string())
            .arg("-V")
            .arg(format!("+{validity_seconds}s"));

        if params.certificate_type == "host" {
            cmd.arg("-h");
        }
        cmd.arg("-n").arg(params.principals.join(","));

        let effective_ext = if params.certificate_type == "user" {
            let ext = params
                .extensions
                .clone()
                .filter(|e| !e.is_empty())
                .unwrap_or_else(default_user_extensions);

            // Build the flat option list exactly as v1 does.
            let mut options: Vec<String> = Vec::new();
            for (name, value) in &ext {
                if value.is_empty() {
                    options.push(name.clone());
                } else {
                    options.push(format!("{name}={value}"));
                }
            }
            if let Some(crit) = &params.critical_options {
                for (name, value) in crit {
                    cmd.arg("-O").arg(format!("critical:{name}={value}"));
                }
            }
            if !params.source_addresses.is_empty() {
                cmd.arg("-O").arg(format!(
                    "source-address={}",
                    params.source_addresses.join(",")
                ));
            }
            if let Some(fc) = &params.force_command {
                cmd.arg("-O").arg(format!("force-command={fc}"));
            }
            for opt in &options {
                if opt.contains('=') {
                    cmd.arg("-O").arg(opt);
                } else {
                    cmd.arg("-O").arg(format!("extension:{opt}"));
                }
            }
            ext
        } else {
            Vec::new()
        };

        cmd.arg(&pub_file);
        run(&mut cmd, "sign certificate")?;

        let certificate = std::fs::read_to_string(&cert_file)
            .map_err(|e| SshError::Internal(format!("read cert: {e}")))?
            .trim()
            .to_owned();

        Ok(IssuedSsh {
            certificate,
            serial: serial.to_string(),
            key_id,
            certificate_type: params.certificate_type.clone(),
            principals: params.principals.clone(),
            valid_after,
            valid_before,
            key_type: detect_key_type(&params.public_key),
            extensions: effective_ext,
        })
    }

    /// Generates a KRL over the supplied entries via `ssh-keygen -k`,
    /// returning the binary KRL and the post-increment version (v1
    /// `generate_krl`).
    pub fn generate_krl(&self, entries: &[KrlEntry]) -> Result<(Vec<u8>, i64), SshError> {
        let version = self.krl_version.fetch_add(1, Ordering::SeqCst) + 1;
        let tmp = TempDir::new()?;
        let krl_file = tmp.path.join("revoked.krl");
        let spec_file = tmp.path.join("revoke_spec");

        let mut spec_lines: Vec<String> = Vec::new();
        for e in entries {
            match e {
                KrlEntry::Serial(s) => spec_lines.push(format!("serial: {s}")),
                KrlEntry::PublicKey(k) => spec_lines.push(format!("key: {k}")),
            }
        }
        std::fs::write(&spec_file, spec_lines.join("\n"))
            .map_err(|e| SshError::Internal(format!("write spec: {e}")))?;

        let mut cmd = Command::new("ssh-keygen");
        cmd.arg("-k")
            .arg("-f")
            .arg(&krl_file)
            .arg("-s")
            .arg(&self.config.ca_key_path)
            .arg(&spec_file);
        run(&mut cmd, "generate KRL")?;

        let krl =
            std::fs::read(&krl_file).map_err(|e| SshError::Internal(format!("read KRL: {e}")))?;

        // Persist to the configured path like v1.
        if let Some(parent) = std::path::Path::new(&self.config.krl_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.config.krl_path, &krl);

        Ok((krl, version as i64))
    }

    /// Parses and verifies an SSH certificate (v1 `check_certificate`).
    pub fn check_certificate(&self, certificate: &str) -> Result<serde_json::Value, SshError> {
        let tmp = TempDir::new()?;
        let cert_file = tmp.path.join("cert.pub");
        std::fs::write(&cert_file, certificate)
            .map_err(|e| SshError::Internal(format!("write cert: {e}")))?;

        let out = Command::new("ssh-keygen")
            .arg("-L")
            .arg("-f")
            .arg(&cert_file)
            .output()
            .map_err(|e| SshError::Internal(format!("ssh-keygen -L: {e}")))?;
        if !out.status.success() {
            return Err(SshError::BadRequest(format!(
                "Invalid certificate: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let mut info = parse_cert_info(&String::from_utf8_lossy(&out.stdout));

        let verify = Command::new("ssh-keygen")
            .arg("-c")
            .arg("-f")
            .arg(&cert_file)
            .arg("-I")
            .arg(&self.config.ca_public_key_path)
            .output();
        let verified = matches!(verify, Ok(o) if o.status.success());
        info["verified"] = serde_json::Value::Bool(verified);
        Ok(info)
    }

    /// `@cert-authority` known_hosts line (v1 `generate_known_hosts_entry`).
    pub fn known_hosts_entry(&self, hostnames: &[String], cert_authority: bool) -> String {
        let hosts = hostnames.join(",");
        let prefix = if cert_authority {
            "@cert-authority "
        } else {
            ""
        };
        format!("{prefix}{hosts} {}", self.ca_public_key)
    }

    /// authorized_keys `cert-authority,principals="…"` line (v1
    /// `generate_authorized_keys_entry`).
    pub fn authorized_keys_entry(
        &self,
        principals: &[String],
        options: &[(String, String)],
    ) -> String {
        let mut option_str = String::new();
        if !options.is_empty() {
            let opts: Vec<String> = options
                .iter()
                .map(|(k, v)| {
                    if v.is_empty() {
                        k.clone()
                    } else {
                        format!("{k}=\"{v}\"")
                    }
                })
                .collect();
            option_str = format!("{} ", opts.join(","));
        }
        format!(
            "{option_str}cert-authority,principals=\"{}\" {}",
            principals.join(","),
            self.ca_public_key
        )
    }

    /// SSH client config snippet for a host (v1 `generate_ssh_config`).
    pub fn ssh_config(
        &self,
        hostname: &str,
        port: i64,
        user: Option<&str>,
        identity_file: Option<&str>,
    ) -> String {
        let mut lines = vec![
            format!("Host {hostname}"),
            format!("    HostName {hostname}"),
            format!("    Port {port}"),
        ];
        if let Some(u) = user {
            lines.push(format!("    User {u}"));
        }
        if let Some(f) = identity_file {
            lines.push(format!("    IdentityFile {f}"));
            lines.push(format!("    CertificateFile {f}-cert.pub"));
        }
        lines.join("\n")
    }
}

/// A KRL revocation entry (by serial or by public key).
#[derive(Debug, Clone)]
pub enum KrlEntry {
    /// Revoke by serial number (decimal string).
    Serial(String),
    /// Revoke by full public key line.
    PublicKey(String),
}

fn load_ca(config: &SshCaConfig) -> Result<(String, String), SshError> {
    let pub_path = std::path::Path::new(&config.ca_public_key_path);
    let ca_public_key = if pub_path.exists() {
        std::fs::read_to_string(pub_path)
            .map_err(|e| SshError::Internal(format!("read CA pub: {e}")))?
            .trim()
            .to_owned()
    } else {
        let out = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&config.ca_key_path)
            .output()
            .map_err(|e| SshError::Internal(format!("ssh-keygen -y: {e}")))?;
        if !out.status.success() {
            return Err(SshError::Internal(format!(
                "ssh-keygen -y failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let key = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let _ = std::fs::write(pub_path, &key);
        key
    };

    let out = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(&config.ca_key_path)
        .output()
        .map_err(|e| SshError::Internal(format!("ssh-keygen -lf: {e}")))?;
    let fingerprint = if out.status.success() {
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned()
    } else {
        String::new()
    };
    Ok((ca_public_key, fingerprint))
}

fn generate_ca(config: &SshCaConfig) -> Result<(), SshError> {
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(parent) = std::path::Path::new(&config.ca_key_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SshError::Internal(format!("create SSH CA dir: {e}")))?;
    }
    let mut cmd = Command::new("ssh-keygen");
    cmd.arg("-t")
        .arg(&config.default_key_type)
        .arg("-f")
        .arg(&config.ca_key_path)
        .arg("-N")
        .arg(config.ca_key_password.clone().unwrap_or_default())
        .arg("-C")
        .arg("SkausWatch SSH CA");
    run(&mut cmd, "generate SSH CA key")?;
    let _ = std::fs::set_permissions(&config.ca_key_path, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::set_permissions(
        &config.ca_public_key_path,
        std::fs::Permissions::from_mode(0o644),
    );
    Ok(())
}

fn run(cmd: &mut Command, ctx: &str) -> Result<(), SshError> {
    let out = cmd
        .output()
        .map_err(|e| SshError::Internal(format!("{ctx}: {e}")))?;
    if !out.status.success() {
        return Err(SshError::Internal(format!(
            "Failed to {ctx}: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn detect_key_type(public_key: &str) -> String {
    if public_key.starts_with("ssh-rsa") {
        "rsa".into()
    } else if public_key.starts_with("ssh-ed25519") {
        "ed25519".into()
    } else if public_key.starts_with("ecdsa-sha2") {
        "ecdsa".into()
    } else {
        "unknown".into()
    }
}

/// Parses `ssh-keygen -L` output into the v1 info shape.
fn parse_cert_info(output: &str) -> serde_json::Value {
    let mut ty: Option<String> = None;
    let mut serial: Option<String> = None;
    let mut key_id: Option<String> = None;
    let mut valid_after: Option<String> = None;
    let mut valid_before: Option<String> = None;
    let mut principals: Vec<String> = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Type:") {
            ty = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("Serial:") {
            serial = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("Key ID:") {
            key_id = Some(v.trim().trim_matches('"').to_owned());
        } else if line.starts_with("Principals:") {
            continue;
        } else if let Some(v) = line.strip_prefix("Valid:") {
            let valid_str = v.trim();
            if let Some((after, before)) = valid_str.split_once(" to ") {
                // `ssh-keygen -L` renders this as `Valid: from <ts> to <ts>`
                // — strip the leading "from " so `valid_after` is a bare
                // timestamp like `valid_before`, not "from <timestamp>".
                let after = after.trim().strip_prefix("from ").unwrap_or(after.trim());
                valid_after = Some(after.trim().to_owned());
                valid_before = Some(before.trim().to_owned());
            }
        } else if line.contains("Extensions:") || line.contains("Critical Options:") {
            continue;
        } else if !line.is_empty() && !line.starts_with("Public key:") && !line.contains(':') {
            principals.push(line.to_owned());
        }
    }

    serde_json::json!({
        "type": ty,
        "serial": serial,
        "key_id": key_id,
        "principals": principals,
        "valid_after": valid_after,
        "valid_before": valid_before,
        "extensions": BTreeMap::<String, String>::new(),
        "critical_options": BTreeMap::<String, String>::new(),
    })
}

/// A self-cleaning temporary directory under the system temp dir.
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> Result<Self, SshError> {
        let path = std::env::temp_dir().join(format!("skauswatch-ssh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path)
            .map_err(|e| SshError::Internal(format!("create temp dir: {e}")))?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `SshCa` intentionally does not derive `Debug` (it holds CA key
    /// material references — never risk it reaching a `{:?}` log line), so
    /// `Result<SshCa, _>::unwrap_err()` isn't available. This extracts the
    /// error without requiring `Debug` on the `Ok` side.
    fn expect_err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    fn tmp_config() -> SshCaConfig {
        let dir =
            std::env::temp_dir().join(format!("skauswatch-ssh-test-{}", uuid::Uuid::new_v4()));
        SshCaConfig {
            ca_key_path: dir.join("sshca").to_string_lossy().into_owned(),
            ca_public_key_path: dir.join("sshca.pub").to_string_lossy().into_owned(),
            ca_key_password: None,
            default_validity_seconds: 86_400,
            max_validity_seconds: 604_800,
            default_key_type: "ed25519".into(),
            krl_path: dir.join("revoked_keys").to_string_lossy().into_owned(),
        }
    }

    /// Generates a fresh (non-CA) ed25519 keypair and returns the OpenSSH
    /// public key line — the "subject" being certified, distinct from the CA
    /// key itself.
    fn gen_subject_pubkey() -> String {
        let path =
            std::env::temp_dir().join(format!("skauswatch-ssh-subject-{}", uuid::Uuid::new_v4()));
        let status = Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-f")
            .arg(&path)
            .arg("-N")
            .arg("")
            .arg("-q")
            .status()
            .unwrap_or_else(|e| panic!("run ssh-keygen: {e}"));
        assert!(status.success(), "ssh-keygen keygen failed");
        std::fs::read_to_string(format!("{}.pub", path.display()))
            .unwrap_or_else(|e| panic!("read generated pubkey: {e}"))
            .trim()
            .to_owned()
    }

    fn base_params(pubkey: &str) -> SshIssueParams {
        SshIssueParams {
            public_key: pubkey.to_owned(),
            certificate_type: "user".into(),
            key_id: None,
            principals: vec!["alice".into()],
            validity_seconds: 3600,
            extensions: None,
            critical_options: None,
            source_addresses: vec![],
            force_command: None,
            hostname: None,
        }
    }

    #[test]
    fn load_or_generate_writes_then_reloads_and_regenerates_missing_pubkey() {
        let config = tmp_config();
        let ca = SshCa::load_or_generate(config.clone()).unwrap();
        assert!(ca.ca_public_key().starts_with("ssh-ed25519"));
        assert!(!ca.ca_fingerprint().is_empty());
        assert_eq!(ca.ca_key_type(), "ed25519");
        assert_eq!(ca.serial_counter(), 1);
        assert_eq!(ca.krl_version(), 0);

        // Reload: private key present, public key file present -> read path.
        let ca2 = SshCa::load_or_generate(config.clone()).unwrap();
        assert_eq!(ca2.ca_public_key(), ca.ca_public_key());

        // Remove the .pub file: load_ca must regenerate it via `ssh-keygen -y`.
        std::fs::remove_file(&config.ca_public_key_path).unwrap();
        let ca3 = SshCa::load_or_generate(config.clone()).unwrap();
        assert_eq!(ca3.ca_public_key(), ca.ca_public_key());
        assert!(std::path::Path::new(&config.ca_public_key_path).exists());
    }

    #[test]
    fn load_or_generate_fails_for_unsupported_key_type() {
        let mut config = tmp_config();
        config.default_key_type = "not-a-real-type".into();
        let err = expect_err(SshCa::load_or_generate(config));
        assert!(matches!(err, SshError::Internal(_)));
    }

    #[test]
    fn load_ca_fails_when_key_file_absent() {
        let config = tmp_config(); // paths never created
        let err = load_ca(&config).unwrap_err();
        assert!(matches!(err, SshError::Internal(_)));
    }

    #[test]
    fn load_ca_fingerprint_falls_back_to_empty_string_when_lf_fails() {
        // Public key file present (skips the `-y` regen branch) but the
        // private key file is garbage, so `ssh-keygen -lf` fails and the
        // fingerprint falls back to the empty-string branch.
        let config = tmp_config();
        std::fs::create_dir_all(std::path::Path::new(&config.ca_key_path).parent().unwrap())
            .unwrap();
        std::fs::write(&config.ca_key_path, "not a real key").unwrap();
        std::fs::write(&config.ca_public_key_path, "ssh-ed25519 AAAAfake fake").unwrap();
        let (pub_key, fingerprint) = load_ca(&config).unwrap();
        assert_eq!(pub_key, "ssh-ed25519 AAAAfake fake");
        assert_eq!(fingerprint, "");
    }

    #[test]
    fn for_tests_ca_has_fixed_canned_material() {
        let ca = SshCa::for_tests();
        assert_eq!(ca.ca_public_key(), "ssh-ed25519 AAAAtest test-ca");
        assert_eq!(ca.ca_key_type(), "ed25519");
        assert_eq!(ca.serial_counter(), 1);
        assert_eq!(ca.krl_version(), 0);
    }

    #[test]
    fn issue_user_certificate_with_default_extensions() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let pubkey = gen_subject_pubkey();
        let issued = ca.issue(&base_params(&pubkey)).unwrap();
        assert_eq!(issued.certificate_type, "user");
        assert_eq!(issued.principals, vec!["alice".to_owned()]);
        assert_eq!(issued.key_id, "skauswatch-user-1");
        assert_eq!(issued.key_type, "ed25519");
        assert!(issued.certificate.contains("cert-v01@openssh.com"));
        assert_eq!(issued.extensions.len(), default_user_extensions().len());
        assert!(issued.valid_before > issued.valid_after);
    }

    #[test]
    fn issue_user_certificate_with_custom_options_and_explicit_key_id() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let pubkey = gen_subject_pubkey();
        let mut p = base_params(&pubkey);
        p.key_id = Some("custom-id".into());
        // One empty-value extension ("-O extension:<name>") and one with a
        // value ("-O <name>=<value>", using a name ssh-keygen actually
        // recognizes for this form — "source-address" — since this is the
        // only place source_addresses is exercised via the `extensions`
        // param rather than the dedicated `source_addresses` field).
        p.extensions = Some(vec![
            ("permit-pty".into(), String::new()),
            ("source-address".into(), "10.0.0.0/8".into()),
        ]);
        p.critical_options = Some(vec![("force-command".into(), "/bin/true".into())]);
        p.force_command = Some("/bin/echo hi".into());
        let issued = ca.issue(&p).unwrap();
        assert_eq!(issued.key_id, "custom-id");
        assert_eq!(
            issued.extensions,
            vec![
                ("permit-pty".into(), String::new()),
                ("source-address".into(), "10.0.0.0/8".into()),
            ]
        );
    }

    #[test]
    fn issue_host_certificate_ignores_extensions_and_sets_h_flag() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let pubkey = gen_subject_pubkey();
        let mut p = base_params(&pubkey);
        p.certificate_type = "host".into();
        p.principals = vec!["host.example.com".into()];
        p.hostname = Some("host.example.com".into());
        p.extensions = Some(vec![("permit-pty".into(), String::new())]);
        let issued = ca.issue(&p).unwrap();
        assert_eq!(issued.certificate_type, "host");
        assert!(issued.extensions.is_empty());
    }

    #[test]
    fn issue_empty_key_id_falls_back_to_default() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let pubkey = gen_subject_pubkey();
        let mut p = base_params(&pubkey);
        p.key_id = Some(String::new());
        let issued = ca.issue(&p).unwrap();
        assert_eq!(issued.key_id, "skauswatch-user-1");
    }

    #[test]
    fn issue_rejects_empty_principals() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let pubkey = gen_subject_pubkey();
        let mut p = base_params(&pubkey);
        p.principals = vec![];
        let err = ca.issue(&p).unwrap_err();
        assert!(matches!(err, SshError::BadRequest(_)));
    }

    #[test]
    fn issue_rejects_invalid_certificate_type() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let pubkey = gen_subject_pubkey();
        let mut p = base_params(&pubkey);
        p.certificate_type = "bogus".into();
        let err = ca.issue(&p).unwrap_err();
        assert!(matches!(err, SshError::BadRequest(_)));
    }

    #[test]
    fn issue_validity_seconds_capped_at_max() {
        let mut config = tmp_config();
        config.max_validity_seconds = 60;
        let ca = SshCa::load_or_generate(config).unwrap();
        let pubkey = gen_subject_pubkey();
        let mut p = base_params(&pubkey);
        p.validity_seconds = 999_999;
        let issued = ca.issue(&p).unwrap();
        let secs = (issued.valid_before - issued.valid_after).num_seconds();
        assert!(secs <= 61, "expected capped validity, got {secs}s");
    }

    #[test]
    fn issue_fails_when_ca_key_path_is_bogus() {
        // Hand-construct an SshCa whose CA key path doesn't exist so
        // `ssh-keygen -s` fails -> exercises the `run()` error branch.
        let ca = SshCa {
            config: SshCaConfig {
                ca_key_path: "/nonexistent/path/to/sshca".into(),
                ca_public_key_path: String::new(),
                ca_key_password: None,
                default_validity_seconds: 86_400,
                max_validity_seconds: 604_800,
                default_key_type: "ed25519".into(),
                krl_path: std::env::temp_dir()
                    .join(format!("skauswatch-ssh-krl-{}", uuid::Uuid::new_v4()))
                    .to_string_lossy()
                    .into_owned(),
            },
            ca_public_key: "ssh-ed25519 AAAAtest test-ca".into(),
            ca_fingerprint: "SHA256:test".into(),
            serial_counter: AtomicU64::new(1),
            krl_version: AtomicU64::new(0),
        };
        let pubkey = gen_subject_pubkey();
        let err = ca.issue(&base_params(&pubkey)).unwrap_err();
        assert!(matches!(err, SshError::Internal(_)));
    }

    #[test]
    fn generate_krl_covers_serial_and_public_key_entries_and_persists() {
        let config = tmp_config();
        let ca = SshCa::load_or_generate(config.clone()).unwrap();
        let (bytes, version) = ca
            .generate_krl(&[
                KrlEntry::Serial("42".into()),
                KrlEntry::PublicKey(ca.ca_public_key().to_owned()),
            ])
            .unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(version, 1);
        assert!(std::path::Path::new(&config.krl_path).exists());

        let (_, version2) = ca.generate_krl(&[]).unwrap();
        assert_eq!(version2, 2);
    }

    #[test]
    fn check_certificate_parses_issued_cert_fields() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let pubkey = gen_subject_pubkey();
        let mut p = base_params(&pubkey);
        p.key_id = Some("check-me".into());
        let issued = ca.issue(&p).unwrap();
        let info = ca.check_certificate(&issued.certificate).unwrap();
        assert_eq!(info["key_id"], serde_json::json!("check-me"));
        assert_eq!(info["serial"], serde_json::json!(issued.serial));
        assert!(info.get("verified").is_some());
    }

    #[test]
    fn check_certificate_rejects_garbage() {
        let ca = SshCa::load_or_generate(tmp_config()).unwrap();
        let err = ca.check_certificate("not a certificate").unwrap_err();
        assert!(matches!(err, SshError::BadRequest(_)));
    }

    #[test]
    fn known_hosts_entry_with_and_without_cert_authority_prefix() {
        let ca = SshCa::for_tests();
        let entry = ca.known_hosts_entry(&["a.example.com".into(), "b.example.com".into()], true);
        assert!(entry.starts_with("@cert-authority a.example.com,b.example.com "));
        let entry2 = ca.known_hosts_entry(&["a.example.com".into()], false);
        assert!(!entry2.starts_with('@'));
    }

    #[test]
    fn authorized_keys_entry_with_and_without_options() {
        let ca = SshCa::for_tests();
        let entry = ca.authorized_keys_entry(&["alice".into(), "bob".into()], &[]);
        assert!(entry.starts_with("cert-authority,principals=\"alice,bob\" "));

        let entry2 = ca.authorized_keys_entry(
            &["alice".into()],
            &[
                ("no-port-forwarding".into(), String::new()),
                ("expiry-time".into(), "20300101".into()),
            ],
        );
        assert!(entry2.starts_with("no-port-forwarding,expiry-time=\"20300101\" cert-authority"));
    }

    #[test]
    fn ssh_config_snippet_with_and_without_optional_fields() {
        let ca = SshCa::for_tests();
        let minimal = ca.ssh_config("host.example.com", 22, None, None);
        assert!(minimal.contains("Host host.example.com"));
        assert!(!minimal.contains("User"));

        let full = ca.ssh_config("host.example.com", 2222, Some("deploy"), Some("/keys/id"));
        assert!(full.contains("User deploy"));
        assert!(full.contains("IdentityFile /keys/id"));
        assert!(full.contains("CertificateFile /keys/id-cert.pub"));
        assert!(full.contains("Port 2222"));
    }

    #[test]
    fn detect_key_type_covers_all_prefixes() {
        assert_eq!(detect_key_type("ssh-rsa AAA"), "rsa");
        assert_eq!(detect_key_type("ssh-ed25519 AAA"), "ed25519");
        assert_eq!(detect_key_type("ecdsa-sha2-nistp256 AAA"), "ecdsa");
        assert_eq!(detect_key_type("weird-type AAA"), "unknown");
    }

    #[test]
    fn parse_cert_info_extracts_fields_from_ssh_keygen_l_output() {
        let output = "key.pub:\n\
            Type: ssh-ed25519-cert-v01@openssh.com user certificate\n\
            Public key: ED25519-CERT SHA256:abc\n\
            Signing CA: ED25519 SHA256:def (using ssh-ed25519)\n\
            Key ID: \"my-key-id\"\n\
            Serial: 7\n\
            Valid: from 2026-01-01T00:00:00 to 2026-01-02T00:00:00\n\
            Principals: \n\
            \talice\n\
            \tbob\n\
            Critical Options: (none)\n\
            Extensions: \n\
            \tpermit-pty\n";
        let info = parse_cert_info(output);
        assert_eq!(info["key_id"], serde_json::json!("my-key-id"));
        assert_eq!(info["serial"], serde_json::json!("7"));
        assert_eq!(
            info["valid_after"],
            serde_json::json!("2026-01-01T00:00:00")
        );
        assert_eq!(
            info["valid_before"],
            serde_json::json!("2026-01-02T00:00:00")
        );
        assert_eq!(
            info["type"],
            serde_json::json!("ssh-ed25519-cert-v01@openssh.com user certificate")
        );
        let principals = info["principals"].as_array().unwrap();
        assert!(principals.contains(&serde_json::json!("alice")));
        assert!(principals.contains(&serde_json::json!("bob")));
    }

    #[test]
    fn default_user_extensions_matches_v1_permit_set() {
        let ext = default_user_extensions();
        assert_eq!(ext.len(), 4);
        assert!(ext.iter().any(|(k, _)| k == "permit-pty"));
        assert!(ext.iter().any(|(k, _)| k == "permit-agent-forwarding"));
        assert!(ext.iter().any(|(k, _)| k == "permit-port-forwarding"));
        assert!(ext.iter().any(|(k, _)| k == "permit-user-rc"));
    }
}
