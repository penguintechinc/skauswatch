//! Database layer shared by all skauswatch services: `DB_*` env config,
//! `DB_TYPE` dispatch (postgres primary, sqlite for dev/tests), and pool
//! construction with retry. Schema authority is `sqlx migrate` run via K8s
//! Job — services never migrate at startup.

use std::collections::HashSet;
use std::time::Duration;

use serde::Deserialize;
use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;

/// Supported database backends, selected via the `DB_TYPE` env var.
/// MySQL/MariaDB support is deferred to v2.1 (additive behind this enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbType {
    /// PostgreSQL 16/17 — production backend.
    Postgresql,
    /// SQLite — development and hermetic tests only.
    Sqlite,
}

/// Connection settings read from the standard `DB_*` environment variables.
#[derive(Debug, Clone, Deserialize)]
pub struct DbConfig {
    /// Backend selector (`DB_TYPE`).
    #[serde(rename = "type")]
    pub db_type: DbType,
    /// Database host (`DB_HOST`).
    #[serde(default = "default_host")]
    pub host: String,
    /// Database port (`DB_PORT`).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Database name (`DB_NAME`).
    pub name: String,
    /// Per-service account name (`DB_USER`) — scoped grants, never shared.
    pub user: String,
    /// Password (`DB_PASS`), sourced from a secret.
    pub pass: String,
    /// Pool size (`DB_POOL_SIZE`).
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    /// Connection retry attempts at startup (`DB_MAX_RETRIES`).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Base retry delay in seconds, doubled each attempt (`DB_RETRY_DELAY`).
    #[serde(default = "default_retry_delay")]
    pub retry_delay: u64,
}

fn default_host() -> String {
    "localhost".to_owned()
}
fn default_port() -> u16 {
    5432
}
fn default_pool_size() -> u32 {
    10
}
fn default_max_retries() -> u32 {
    5
}
fn default_retry_delay() -> u64 {
    5
}

/// Errors raised by pool construction.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// All connection attempts were exhausted.
    #[error("database connection failed after {attempts} attempts: {source}")]
    Exhausted {
        /// Number of attempts made before giving up.
        attempts: u32,
        /// Final underlying sqlx error.
        source: sqlx::Error,
    },
    /// The requested backend is not valid for this entry point.
    #[error("unsupported DB_TYPE for this operation: {0}")]
    Unsupported(String),
    /// The pre-migration baseline query (`SELECT version FROM
    /// _sqlx_migrations`) failed for a reason other than a fresh,
    /// not-yet-migrated database — see [`run_migrations`].
    #[error("migration baseline query failed: {0}")]
    Query(#[from] sqlx::Error),
    /// The embedded migration set failed to apply.
    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

impl DbConfig {
    /// Loads config from the standard `DB_*` environment variables.
    pub fn from_env() -> Result<Self, skauswatch_common::Error> {
        skauswatch_common::load_config("DB_")
    }

    /// Renders the sqlx connection URL for this backend.
    pub fn url(&self) -> String {
        match self.db_type {
            DbType::Postgresql => format!(
                "postgres://{}:{}@{}:{}/{}",
                self.user, self.pass, self.host, self.port, self.name
            ),
            DbType::Sqlite => format!("sqlite://{}?mode=rwc", self.name),
        }
    }
}

/// Connects a PostgreSQL pool with exponential-backoff retry, per the
/// PenguinTech DB resilience standard. Fails after `max_retries` attempts.
pub async fn connect_postgres(cfg: &DbConfig) -> Result<PgPool, DbError> {
    if cfg.db_type != DbType::Postgresql {
        return Err(DbError::Unsupported(format!("{:?}", cfg.db_type)));
    }
    let mut delay = Duration::from_secs(cfg.retry_delay);
    let mut last_err: Option<sqlx::Error> = None;
    for attempt in 1..=cfg.max_retries {
        match PgPoolOptions::new()
            .max_connections(cfg.pool_size)
            .connect(&cfg.url())
            .await
        {
            Ok(pool) => return Ok(pool),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "database connection attempt failed");
                last_err = Some(e);
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
    Err(DbError::Exhausted {
        attempts: cfg.max_retries,
        source: last_err.unwrap_or(sqlx::Error::PoolClosed),
    })
}

/// Applies every pending migration in `migrator` against `pool`, logging
/// each newly-applied migration's version and description via `tracing`.
/// Called only from each service's `migrate` subcommand — the K8s Job
/// migration target — never from `serve` startup (see this module's
/// schema-authority policy above).
///
/// `migrator` is normally a `static` built with `sqlx::migrate!()` in the
/// calling service's own `main.rs`, so the migration set is embedded at
/// compile time (no DB needed to build) and always matches that service's
/// `migrations/` directory.
pub async fn run_migrations(pool: &PgPool, migrator: &Migrator) -> Result<(), DbError> {
    let already_applied: HashSet<i64> =
        match sqlx::query_scalar::<_, i64>("SELECT version FROM _sqlx_migrations")
            .fetch_all(pool)
            .await
        {
            Ok(versions) => versions.into_iter().collect(),
            // Fresh database: the migrations table doesn't exist yet
            // (Postgres `undefined_table`, SQLSTATE 42P01) — every
            // embedded migration is legitimately "newly applied" below.
            Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("42P01") => {
                HashSet::new()
            }
            Err(e) => return Err(DbError::Query(e)),
        };

    migrator.run(pool).await?;

    for migration in migrator.iter() {
        if !already_applied.contains(&migration.version) {
            tracing::info!(
                version = migration.version,
                description = %migration.description,
                "applied migration"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(db_type: DbType) -> DbConfig {
        DbConfig {
            db_type,
            host: "db.example".into(),
            port: 5432,
            name: "skauswatch".into(),
            user: "manager-rw".into(),
            pass: "s3cret".into(),
            pool_size: 10,
            max_retries: 5,
            retry_delay: 5,
        }
    }

    #[test]
    fn postgres_url_renders_all_parts() {
        assert_eq!(
            cfg(DbType::Postgresql).url(),
            "postgres://manager-rw:s3cret@db.example:5432/skauswatch"
        );
    }

    #[test]
    fn sqlite_url_uses_rwc_mode() {
        assert_eq!(cfg(DbType::Sqlite).url(), "sqlite://skauswatch?mode=rwc");
    }
}
