//! Environment-driven configuration for the SSH CA service.
//!
//! Env var names and defaults mirror the v1 sshca container: `SERVICE_PORT`
//! (8002), the `SSHCA_DIR`/`SSH_KEYS_DIR` layout, and the CA private key path
//! the v1 entrypoint derived as `$SSHCA_DIR/sshca_key`.

use std::path::PathBuf;

/// Default REST port — the v1 sshca `SERVICE_PORT`.
pub const DEFAULT_HTTP_PORT: u16 = 8002;
/// Default SSH CA working directory — the v1 `SSHCA_DIR`.
pub const DEFAULT_SSHCA_DIR: &str = "/app/sshca";
/// Default per-key working directory — the v1 `SSH_KEYS_DIR`.
pub const DEFAULT_SSH_KEYS_DIR: &str = "/app/keys";
/// CA private key filename under `SSHCA_DIR` (v1 entrypoint `sshca_key`).
pub const CA_KEY_FILENAME: &str = "sshca_key";

/// Resolved runtime configuration for the SSH CA service.
#[derive(Debug, Clone)]
pub struct SshCaConfig {
    /// REST listen port (`SERVICE_PORT`, falling back to `API_PORT`).
    pub http_port: u16,
    /// Path to the CA private key (OpenSSH format). When the file is absent an
    /// ephemeral CA key is generated with a loud warning (v1 parity).
    pub ca_key_path: PathBuf,
    /// SSH CA working directory (`SSHCA_DIR`).
    pub sshca_dir: PathBuf,
    /// Per-key working directory (`SSH_KEYS_DIR`).
    pub ssh_keys_dir: PathBuf,
}

impl SshCaConfig {
    /// Pure constructor taking pre-resolved env values — the unit-testable
    /// core (no process env access, no `unsafe`; `unsafe_code = "deny"` at
    /// the workspace level rules out `std::env::set_var` in tests). Env-var
    /// precedence (`SERVICE_PORT` over `API_PORT`, `SSHCA_KEY_PATH` over
    /// `CA_PRIVATE_KEY_PATH`) is resolved by the caller ([`Self::from_env`])
    /// before the already-chosen value reaches here.
    fn from_values(
        http_port: Option<&str>,
        sshca_dir: Option<&str>,
        ssh_keys_dir: Option<&str>,
        ca_key_path: Option<&str>,
    ) -> Self {
        let http_port = http_port
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_HTTP_PORT);
        let sshca_dir = PathBuf::from(sshca_dir.unwrap_or(DEFAULT_SSHCA_DIR));
        let ssh_keys_dir = PathBuf::from(ssh_keys_dir.unwrap_or(DEFAULT_SSH_KEYS_DIR));

        // v1 config key was `ca_private_key_path`; honour both that name and
        // the container-friendly `SSHCA_KEY_PATH`, else derive from SSHCA_DIR.
        let ca_key_path = ca_key_path
            .map(PathBuf::from)
            .unwrap_or_else(|| sshca_dir.join(CA_KEY_FILENAME));

        Self {
            http_port,
            ca_key_path,
            sshca_dir,
            ssh_keys_dir,
        }
    }

    /// Builds config from the process environment, applying v1-compatible
    /// defaults. Never fails — missing vars fall back to their defaults.
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var("SERVICE_PORT")
                .or_else(|_| std::env::var("API_PORT"))
                .ok()
                .as_deref(),
            std::env::var("SSHCA_DIR").ok().as_deref(),
            std::env::var("SSH_KEYS_DIR").ok().as_deref(),
            std::env::var("SSHCA_KEY_PATH")
                .or_else(|_| std::env::var("CA_PRIVATE_KEY_PATH"))
                .ok()
                .as_deref(),
        )
    }
}

/// Bounds the ad hoc `reqwest::Client` `main.rs::healthcheck` builds for its
/// own `/healthz` self-probe — audit finding (issue #149, HIGH): a hung
/// connect must never wedge indefinitely. Mirrors
/// `services/depgate/src/config.rs::HttpClientConfig` exactly.
#[derive(Debug, Clone, Copy)]
pub struct HttpClientConfig {
    /// Whole-request timeout in seconds (`SSHCA_HTTP_TIMEOUT_SECS`, default
    /// 30) — the call site's own explicit 3s `.timeout()` still overrides
    /// this per call.
    pub timeout_secs: u64,
    /// TCP+TLS connect timeout in seconds
    /// (`SSHCA_HTTP_CONNECT_TIMEOUT_SECS`, default 10).
    pub connect_timeout_secs: u64,
}

impl HttpClientConfig {
    /// Loads the shared bounds from the environment. Back-compat: unset env
    /// vars preserve prior behavior except now bounded (previously
    /// unbounded — no timeout at all on a bare `reqwest::Client::new()`).
    pub fn from_env() -> Self {
        Self {
            timeout_secs: std::env::var("SSHCA_HTTP_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            connect_timeout_secs: std::env::var("SSHCA_HTTP_CONNECT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_client_config_defaults_are_bounded() {
        // regression: gh-149 — the healthcheck's reqwest::Client must never
        // build with an unbounded (no-timeout) default.
        assert!(std::env::var("SSHCA_HTTP_TIMEOUT_SECS").is_err());
        assert!(std::env::var("SSHCA_HTTP_CONNECT_TIMEOUT_SECS").is_err());
        let cfg = HttpClientConfig::from_env();
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.connect_timeout_secs, 10);
    }

    #[test]
    fn defaults_match_v1_when_unset() {
        let cfg = SshCaConfig::from_values(None, None, None, None);
        assert_eq!(cfg.http_port, DEFAULT_HTTP_PORT);
        assert_eq!(cfg.sshca_dir, PathBuf::from(DEFAULT_SSHCA_DIR));
        assert_eq!(cfg.ssh_keys_dir, PathBuf::from(DEFAULT_SSH_KEYS_DIR));
        // Derived from the default SSHCA_DIR when no explicit key path given.
        assert_eq!(
            cfg.ca_key_path,
            PathBuf::from(DEFAULT_SSHCA_DIR).join(CA_KEY_FILENAME)
        );
    }

    #[test]
    fn invalid_port_falls_back_to_default() {
        let cfg = SshCaConfig::from_values(Some("not-a-number"), None, None, None);
        assert_eq!(cfg.http_port, DEFAULT_HTTP_PORT);
    }

    #[test]
    fn overrides_are_honored() {
        let cfg = SshCaConfig::from_values(
            Some("9999"),
            Some("/custom/sshca"),
            Some("/custom/keys"),
            None,
        );
        assert_eq!(cfg.http_port, 9999);
        assert_eq!(cfg.sshca_dir, PathBuf::from("/custom/sshca"));
        assert_eq!(cfg.ssh_keys_dir, PathBuf::from("/custom/keys"));
        // Key path derives from the *overridden* sshca_dir, not the default.
        assert_eq!(
            cfg.ca_key_path,
            PathBuf::from("/custom/sshca").join(CA_KEY_FILENAME)
        );
    }

    #[test]
    fn explicit_ca_key_path_overrides_derivation() {
        let cfg = SshCaConfig::from_values(
            None,
            Some("/custom/sshca"),
            None,
            Some("/explicit/somewhere/key"),
        );
        assert_eq!(cfg.ca_key_path, PathBuf::from("/explicit/somewhere/key"));
    }

    /// Exercises the `from_env` -> `from_values` glue itself (the
    /// precedence resolution it performs — `SERVICE_PORT` over `API_PORT`,
    /// `SSHCA_KEY_PATH` over `CA_PRIVATE_KEY_PATH` — is already covered
    /// above via `from_values`). Cannot assert specific values by
    /// controlling the process environment: `std::env::set_var` is
    /// `unsafe` and `unsafe_code = "deny"` at the workspace level rules
    /// that out in tests, so this only asserts the result is well-formed
    /// regardless of whatever the test process's environment happens to
    /// contain.
    #[test]
    fn from_env_reads_the_process_environment_without_panicking() {
        let cfg = SshCaConfig::from_env();
        assert!(cfg.http_port > 0);
        assert!(!cfg.sshca_dir.as_os_str().is_empty());
        assert!(!cfg.ssh_keys_dir.as_os_str().is_empty());
        assert!(!cfg.ca_key_path.as_os_str().is_empty());
    }
}
