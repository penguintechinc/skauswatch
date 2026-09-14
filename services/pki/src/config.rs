//! Runtime configuration read from the environment, preserving the v1
//! Quart service's variable names and defaults exactly (`config.py`).
//! The one intentional cutover is the database connection, which uses the
//! shared `skauswatch-db` `DB_*` convention like the merged Rust manager
//! (v1 read a single `DATABASE_URL`) — documented in `docs/v2-port/pki-contract.md`.

/// Reads an env var, falling back to `default` when unset or empty.
fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_owned(),
    }
}

/// Reads an optional env var (`None` when unset or empty).
fn env_opt(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Parses an integer env var, falling back to `default` on absence/parse error.
fn env_int(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// X.509 Certificate Authority configuration (v1 `X509CAConfig`).
#[derive(Debug, Clone)]
pub struct X509CaConfig {
    /// PEM CA private key path (`CA_KEY_PATH`, default `/etc/pki/ca.key`).
    pub ca_key_path: String,
    /// PEM CA certificate path (`CA_CERT_PATH`, default `/etc/pki/ca.crt`).
    pub ca_cert_path: String,
    /// Optional CA key passphrase (`CA_KEY_PASSWORD`).
    pub ca_key_password: Option<String>,
    /// Default certificate validity in days (`DEFAULT_VALIDITY_DAYS`, 365).
    pub default_validity_days: i64,
    /// Hard cap on validity in days (`MAX_VALIDITY_DAYS`, 825).
    pub max_validity_days: i64,
    /// Default key algorithm (`DEFAULT_KEY_ALGORITHM`, `RSA`).
    pub default_key_algorithm: String,
    /// Default key size in bits (`DEFAULT_KEY_SIZE`, 4096).
    pub default_key_size: i64,
    /// CRL validity window in days (`CRL_VALIDITY_DAYS`, 7).
    pub crl_validity_days: i64,
    /// Optional OCSP responder URL surfaced in CA info (`OCSP_RESPONDER_URL`).
    pub ocsp_responder_url: Option<String>,
}

impl X509CaConfig {
    /// Loads the X.509 CA config from the v1 environment variables.
    pub fn from_env() -> Self {
        Self {
            ca_key_path: env_or("CA_KEY_PATH", "/etc/pki/ca.key"),
            ca_cert_path: env_or("CA_CERT_PATH", "/etc/pki/ca.crt"),
            ca_key_password: env_opt("CA_KEY_PASSWORD"),
            default_validity_days: env_int("DEFAULT_VALIDITY_DAYS", 365),
            max_validity_days: env_int("MAX_VALIDITY_DAYS", 825),
            default_key_algorithm: env_or("DEFAULT_KEY_ALGORITHM", "RSA").to_uppercase(),
            default_key_size: env_int("DEFAULT_KEY_SIZE", 4096),
            crl_validity_days: env_int("CRL_VALIDITY_DAYS", 7),
            ocsp_responder_url: env_opt("OCSP_RESPONDER_URL"),
        }
    }
}

/// SSH Certificate Authority configuration (v1 `SSHCAConfig`).
#[derive(Debug, Clone)]
pub struct SshCaConfig {
    /// OpenSSH CA private key path (`SSHCA_KEY_PATH`, `/etc/pki/sshca`).
    pub ca_key_path: String,
    /// OpenSSH CA public key path (`SSHCA_PUBLIC_KEY_PATH`, `/etc/pki/sshca.pub`).
    pub ca_public_key_path: String,
    /// Optional CA key passphrase (`SSHCA_KEY_PASSWORD`).
    pub ca_key_password: Option<String>,
    /// Default certificate validity in seconds (`SSH_DEFAULT_VALIDITY_SECONDS`, 86400).
    pub default_validity_seconds: i64,
    /// Hard cap on validity in seconds (`SSH_MAX_VALIDITY_SECONDS`, 604800).
    pub max_validity_seconds: i64,
    /// Default CA key type when generating (`SSH_DEFAULT_KEY_TYPE`, `ed25519`).
    pub default_key_type: String,
    /// Persisted KRL path (`KRL_PATH`, `/etc/pki/revoked_keys`).
    pub krl_path: String,
}

impl SshCaConfig {
    /// Loads the SSH CA config from the v1 environment variables.
    pub fn from_env() -> Self {
        Self {
            ca_key_path: env_or("SSHCA_KEY_PATH", "/etc/pki/sshca"),
            ca_public_key_path: env_or("SSHCA_PUBLIC_KEY_PATH", "/etc/pki/sshca.pub"),
            ca_key_password: env_opt("SSHCA_KEY_PASSWORD"),
            default_validity_seconds: env_int("SSH_DEFAULT_VALIDITY_SECONDS", 86_400),
            max_validity_seconds: env_int("SSH_MAX_VALIDITY_SECONDS", 604_800),
            default_key_type: env_or("SSH_DEFAULT_KEY_TYPE", "ed25519").to_lowercase(),
            krl_path: env_or("KRL_PATH", "/etc/pki/revoked_keys"),
        }
    }
}

/// Deployment environment segment used both in this workload's own SPIFFE
/// ID and in the peer identities it trusts (`spiffe://penguintech.io/<env>/
/// ...` — `docs/v2-port/service-auth-model.md` §1). Read from `SPIFFE_ENV`,
/// defaulting to `"beta"` — every environment this service has actually run
/// in so far; the production trust-domain segment is a separate, explicitly
/// unresolved decision (that doc's §7 item 5) and is not settled by this
/// default.
pub fn spiffe_env() -> String {
    env_or("SPIFFE_ENV", "beta")
}

/// REST + gRPC bind settings (v1 `APIConfig` / `GRPCConfig`).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// REST bind port (`API_PORT`, default 8001).
    pub api_port: u16,
    /// gRPC bind port (`GRPC_PORT`, default 50052).
    pub grpc_port: u16,
}

impl ServerConfig {
    /// Loads REST/gRPC ports from the environment.
    pub fn from_env() -> Self {
        Self {
            api_port: env_int("API_PORT", 8001) as u16,
            grpc_port: env_int("GRPC_PORT", 50_052) as u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x509_defaults_match_v1() {
        // Env is not mutated here; from_env reads process env which is unset
        // for these keys in the test harness → v1 defaults.
        let cfg = X509CaConfig::from_env();
        assert_eq!(cfg.ca_key_path, "/etc/pki/ca.key");
        assert_eq!(cfg.ca_cert_path, "/etc/pki/ca.crt");
        assert_eq!(cfg.default_validity_days, 365);
        assert_eq!(cfg.max_validity_days, 825);
        assert_eq!(cfg.default_key_algorithm, "RSA");
        assert_eq!(cfg.default_key_size, 4096);
        assert_eq!(cfg.crl_validity_days, 7);
    }

    #[test]
    fn ssh_defaults_match_v1() {
        let cfg = SshCaConfig::from_env();
        assert_eq!(cfg.ca_key_path, "/etc/pki/sshca");
        assert_eq!(cfg.ca_public_key_path, "/etc/pki/sshca.pub");
        assert_eq!(cfg.default_validity_seconds, 86_400);
        assert_eq!(cfg.max_validity_seconds, 604_800);
        assert_eq!(cfg.default_key_type, "ed25519");
        assert_eq!(cfg.krl_path, "/etc/pki/revoked_keys");
    }

    #[test]
    fn server_defaults_match_v1() {
        let cfg = ServerConfig::from_env();
        assert_eq!(cfg.api_port, 8001);
        assert_eq!(cfg.grpc_port, 50_052);
    }

    #[test]
    fn spiffe_env_defaults_to_beta_when_unset() {
        assert!(std::env::var("SPIFFE_ENV").is_err());
        assert_eq!(spiffe_env(), "beta");
    }
}
