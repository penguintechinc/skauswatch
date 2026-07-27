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
    /// Builds config from the process environment, applying v1-compatible
    /// defaults. Never fails — missing vars fall back to their defaults.
    pub fn from_env() -> Self {
        let http_port = std::env::var("SERVICE_PORT")
            .or_else(|_| std::env::var("API_PORT"))
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_HTTP_PORT);

        let sshca_dir = PathBuf::from(
            std::env::var("SSHCA_DIR").unwrap_or_else(|_| DEFAULT_SSHCA_DIR.to_owned()),
        );
        let ssh_keys_dir = PathBuf::from(
            std::env::var("SSH_KEYS_DIR").unwrap_or_else(|_| DEFAULT_SSH_KEYS_DIR.to_owned()),
        );

        // v1 config key was `ca_private_key_path`; honour both that name and
        // the container-friendly `SSHCA_KEY_PATH`, else derive from SSHCA_DIR.
        let ca_key_path = std::env::var("SSHCA_KEY_PATH")
            .or_else(|_| std::env::var("CA_PRIVATE_KEY_PATH"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| sshca_dir.join(CA_KEY_FILENAME));

        Self {
            http_port,
            ca_key_path,
            sshca_dir,
            ssh_keys_dir,
        }
    }
}
