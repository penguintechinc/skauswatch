//! Shared application state: the certificate manager (CA engines + Postgres
//! pool) plus the X.509 CA config surfaced in CA-info responses.

use std::sync::Arc;

use penguin_licensing::LicenseClient;

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
    /// Shared HS256 signing secret (`JWT_SECRET_KEY`) — every REST and gRPC
    /// endpoint requires a valid bearer token verified against this (finding
    /// #1): this service mints CA certificates and private keys, and had no
    /// authentication at all before this hardening pass.
    pub jwt_secret: String,
    /// License entitlement + PostHog flag client (fail-safe) — currently
    /// only used to gate the live `/api/v1/openapi.json` route.
    pub license: Arc<LicenseClient>,
}

/// Cheap-to-clone handle used as axum/gRPC state.
pub type AppState = Arc<AppStateInner>;

impl skauswatch_auth::JwtSecretSource for AppStateInner {
    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }
}

impl AppStateInner {
    /// Builds state from the environment: loads/generates both CAs and
    /// connects the Postgres pool (with retry) via the shared `skauswatch-db`.
    /// Fails fast (before any CA key material is touched) if `JWT_SECRET_KEY`
    /// is missing in production — see `skauswatch_auth::load_jwt_secret`.
    pub async fn from_env() -> anyhow::Result<AppState> {
        let jwt_secret = skauswatch_auth::load_jwt_secret().map_err(|e| anyhow::anyhow!("{e}"))?;

        let license_cfg = penguin_licensing::LicenseConfig::from_env("skauswatch")
            .map_err(|e| anyhow::anyhow!("license config: {e}"))?
            .with_bypass_domain("skauswatch.app");
        let license =
            LicenseClient::new(license_cfg).map_err(|e| anyhow::anyhow!("license client: {e}"))?;
        let _ = license.refresh().await;

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
            jwt_secret,
            license,
        }))
    }

    /// Dev-mode (unreleased) license client shared by every test constructor
    /// below that doesn't take an explicit one — `release_mode` defaults to
    /// `false`, so [`penguin_licensing::LicenseClient::flag_enabled`] always
    /// returns `true` (bypass). Fully offline/synchronous: no network calls.
    #[cfg(test)]
    #[allow(clippy::panic)] // test-only helper fails loudly by design
    fn dev_license() -> Arc<LicenseClient> {
        let cfg = penguin_licensing::LicenseConfig::new("skauswatch")
            .unwrap_or_else(|e| panic!("license config: {e}"));
        LicenseClient::new(cfg).unwrap_or_else(|e| panic!("license client: {e}"))
    }

    /// Self-contained test constructor mirroring the manager's
    /// `AppStateInner::for_tests`: a real (pure-Rust, `rcgen`-backed)
    /// ephemeral X.509 CA, an in-memory `SshCa::for_tests()` (no
    /// `ssh-keygen` subprocess — that binary isn't installed in the plain
    /// `rust:*-bookworm` image this workspace builds/tests in), a lazy
    /// (unconnected) Postgres pool, and a fixed, known `jwt_secret` so
    /// route/gRPC auth-gate tests can mint valid bearer tokens without
    /// touching the real environment or a live DB.
    #[cfg(test)]
    pub fn for_tests() -> AppState {
        Self::for_tests_with_license(Self::dev_license())
    }

    /// Like [`Self::for_tests`], but with a caller-supplied license client —
    /// used by `routes::openapi`'s tests to exercise the gated
    /// (`release_mode = true`) `/api/v1/openapi.json` path without touching
    /// every other zero-arg `for_tests()` call site in this crate.
    #[cfg(test)]
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    pub fn for_tests_with_license(license: Arc<LicenseClient>) -> AppState {
        let dir =
            std::env::temp_dir().join(format!("skauswatch-pki-test-{}", uuid::Uuid::new_v4()));
        let x509_config = X509CaConfig {
            ca_key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert_path: dir.join("ca.crt").to_string_lossy().into_owned(),
            ca_key_password: None,
            default_validity_days: 365,
            max_validity_days: 825,
            default_key_algorithm: "RSA".to_owned(),
            default_key_size: 2048,
            crl_validity_days: 7,
            ocsp_responder_url: None,
        };

        let x509 = Arc::new(
            X509Ca::load_or_generate(x509_config.clone())
                .unwrap_or_else(|e| panic!("test X.509 CA: {e}")),
        );
        let ssh = Arc::new(SshCa::for_tests());
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy test pool: {e}"));

        Arc::new(Self {
            manager: Arc::new(CertManager::new(x509, ssh, db)),
            x509_config,
            server: ServerConfig {
                api_port: 8001,
                grpc_port: 50_052,
            },
            jwt_secret: "test-secret".to_owned(),
            license,
        })
    }

    /// Builds a real (rcgen-backed X.509, `ssh-keygen`-backed SSH) pair of CA
    /// engines rooted at a fresh temp dir, plus the matching `X509CaConfig` —
    /// the shared setup behind [`Self::for_tests_with_real_ca`] and
    /// [`Self::for_tests_with_db`], so both test constructors build CA
    /// material identically and only differ in which DB pool they wire in.
    #[cfg(test)]
    #[allow(clippy::panic)] // test-only helper fails loudly by design
    fn real_test_cas() -> (Arc<X509Ca>, Arc<SshCa>, X509CaConfig) {
        let dir =
            std::env::temp_dir().join(format!("skauswatch-pki-realca-{}", uuid::Uuid::new_v4()));
        let x509_config = X509CaConfig {
            ca_key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert_path: dir.join("ca.crt").to_string_lossy().into_owned(),
            ca_key_password: None,
            default_validity_days: 365,
            max_validity_days: 825,
            default_key_algorithm: "RSA".to_owned(),
            default_key_size: 2048,
            crl_validity_days: 7,
            ocsp_responder_url: None,
        };
        let ssh_config = SshCaConfig {
            ca_key_path: dir.join("sshca").to_string_lossy().into_owned(),
            ca_public_key_path: dir.join("sshca.pub").to_string_lossy().into_owned(),
            ca_key_password: None,
            default_validity_seconds: 86_400,
            max_validity_seconds: 604_800,
            default_key_type: "ed25519".to_owned(),
            krl_path: dir.join("revoked_keys").to_string_lossy().into_owned(),
        };

        let x509 = Arc::new(
            X509Ca::load_or_generate(x509_config.clone())
                .unwrap_or_else(|e| panic!("real test X.509 CA: {e}")),
        );
        let ssh = Arc::new(
            SshCa::load_or_generate(ssh_config).unwrap_or_else(|e| panic!("real test SSH CA: {e}")),
        );
        (x509, ssh, x509_config)
    }

    /// Like [`Self::for_tests`], but with a *real* `ssh-keygen`-backed
    /// `SshCa::load_or_generate` instead of the canned `SshCa::for_tests()`
    /// — for router/gRPC tests that need genuine SSH certificate issuance to
    /// execute (real subprocess, real signing) before the still-unreachable
    /// DB call fails. Requires `ssh-keygen` on `PATH` (present on the CI
    /// `ubuntu-latest` runner; install `openssh-client` for local runs in a
    /// stripped-down `rust:*-bookworm` container — see
    /// `docs/v2-port/testing-pattern.md`).
    #[cfg(test)]
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    pub fn for_tests_with_real_ca() -> AppState {
        let (x509, ssh, x509_config) = Self::real_test_cas();
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy test pool: {e}"));

        Arc::new(Self {
            manager: Arc::new(CertManager::new(x509, ssh, db)),
            x509_config,
            server: ServerConfig {
                api_port: 8001,
                grpc_port: 50_052,
            },
            jwt_secret: "test-secret".to_owned(),
            license: Self::dev_license(),
        })
    }

    /// Same real CA engines as [`Self::for_tests_with_real_ca`], but wired to
    /// a real, migrated Postgres pool instead of a lazy/unreachable one — for
    /// DB-backed success-path tests (issue -> get, revoke -> get, list,
    /// CRL/KRL, statistics, audit log) per `docs/v2-port/testing-pattern.md`'s
    /// `for_tests_with_db` fan-out pattern.
    #[cfg(test)]
    pub fn for_tests_with_db(db: sqlx::PgPool) -> AppState {
        let (x509, ssh, x509_config) = Self::real_test_cas();
        Arc::new(Self {
            manager: Arc::new(CertManager::new(x509, ssh, db)),
            x509_config,
            server: ServerConfig {
                api_port: 8001,
                grpc_port: 50_052,
            },
            jwt_secret: "test-secret".to_owned(),
            license: Self::dev_license(),
        })
    }
}
