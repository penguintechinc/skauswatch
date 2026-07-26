//! Shared application state: the certificate manager (CA engines + Postgres
//! pool) plus the X.509 CA config surfaced in CA-info responses.

use std::sync::Arc;

use crate::ca::ssh::SshCa;
use crate::ca::x509::X509Ca;
use crate::config::{ServerConfig, SshCaConfig, X509CaConfig};
use crate::manager::CertManager;

/// Inner state shared across all handlers via `Arc`.
pub struct AppStateInner {
    /// Certificate lifecycle manager (X.509 + SSH engines + DB).
    pub manager: Arc<CertManager>,
    /// X.509 CA config (for `ocsp_responder_url` etc. in CA info).
    pub x509_config: X509CaConfig,
    /// REST/gRPC bind ports.
    pub server: ServerConfig,
}

/// Cheap-to-clone handle used as axum/gRPC state.
pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    /// Builds state from the environment: loads/generates both CAs and
    /// connects the Postgres pool (with retry) via the shared `skauswatch-db`.
    pub async fn from_env() -> anyhow::Result<AppState> {
        let x509_config = X509CaConfig::from_env();
        let ssh_config = SshCaConfig::from_env();
        let server = ServerConfig::from_env();

        let x509 = Arc::new(
            X509Ca::load_or_generate(x509_config.clone())
                .map_err(|e| anyhow::anyhow!("X.509 CA init: {e}"))?,
        );
        let ssh = Arc::new(
            SshCa::load_or_generate(ssh_config).map_err(|e| anyhow::anyhow!("SSH CA init: {e}"))?,
        );

        let db_cfg =
            skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
        let db = skauswatch_db::connect_postgres(&db_cfg)
            .await
            .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

        let manager = Arc::new(CertManager::new(x509, ssh, db));
        Ok(Arc::new(Self {
            manager,
            x509_config,
            server,
        }))
    }
}
