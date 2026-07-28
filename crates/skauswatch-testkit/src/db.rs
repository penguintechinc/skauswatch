//! Isolated-schema Postgres pools for handler/DB tests.
//!
//! `AppState.db` across every service is a concrete `sqlx::PgPool`, not a
//! trait object — so DB-layer coverage means exercising a real Postgres, not
//! mocking the pool. To let `cargo nextest`/`cargo test` run DB-backed tests
//! in parallel without them clobbering each other's rows, [`test_pool`]
//! provisions a fresh, uniquely-named schema per call and pins every pooled
//! connection's `search_path` to it via `after_connect`, then applies the
//! caller's sqlx migrations into that schema. No transactions-per-test
//! rollback trick is used (it would require threading a `Transaction`
//! through every handler as the executor type, which the existing
//! `AppStateInner.db: PgPool` shape does not support) — schema isolation
//! works with the pool shape services already have.
//!
//! Connection parameters come from the same `DB_HOST`/`DB_PORT`/`DB_NAME`/
//! `DB_USER`/`DB_PASS` variables `skauswatch_db::DbConfig` reads in
//! production, with test-friendly defaults matching the `postgres:17-bookworm`
//! service container used in CI (see `.github/workflows/rust.yml`) so
//! `cargo test` also works unmodified against a local
//! `docker run postgres:17-bookworm` on the default port.

use std::path::Path;

use sqlx::PgPool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Builds the Postgres connection URL from `DB_*` env vars (test defaults:
/// `localhost:5432`, db/user/pass all `postgres`) — matches the CI Postgres
/// service container credentials.
fn connection_url() -> String {
    let host = env_or("DB_HOST", "localhost");
    let port = env_or("DB_PORT", "5432");
    let name = env_or("DB_NAME", "postgres");
    let user = env_or("DB_USER", "postgres");
    let pass = env_or("DB_PASS", "postgres");
    format!("postgres://{user}:{pass}@{host}:{port}/{name}")
}

/// Provisions a fresh, isolated Postgres schema, applies the migrations
/// found under `migrations_dir` into it, and returns a pool whose
/// connections always operate against that schema.
///
/// `migrations_dir` is typically
/// `concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")` from the calling
/// service crate. Panics (test-infra fault, not a case under test) if the
/// database is unreachable or migrations fail to apply — callers are
/// expected to run against a real Postgres (CI service container, or
/// `docker run -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17-bookworm`
/// locally); this harness deliberately does not fall back to mocking the DB
/// layer.
#[allow(clippy::panic)] // test-infra bootstrap: fail loudly, not silently skip DB coverage
pub async fn test_pool(migrations_dir: impl AsRef<Path>) -> PgPool {
    let url = connection_url();
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());

    // Bootstrap connection (default search_path) — creates the schema
    // before any pooled connection pins its search_path to it.
    let bootstrap = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "skauswatch-testkit: connect to Postgres at {url} for schema bootstrap: {e}\n\
                 hint: start a test database, e.g.\n\
                 docker run --rm -d -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17-bookworm"
            )
        });
    // `schema` is generated here (UUID hex), never caller-supplied input —
    // safe to interpolate directly, matching the existing `sqlx::AssertSqlSafe`
    // dynamic-column-list pattern used for identifiers elsewhere in this repo.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&bootstrap)
        .await
        .unwrap_or_else(|e| panic!("skauswatch-testkit: create schema {schema}: {e}"));
    bootstrap.close().await;

    let schema_for_hook = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .after_connect(move |conn, _meta| {
            let schema = schema_for_hook.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SET search_path TO \"{schema}\""
                )))
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap_or_else(|e| panic!("skauswatch-testkit: connect scoped pool for {schema}: {e}"));

    let migrator = Migrator::new(migrations_dir.as_ref())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "skauswatch-testkit: load migrations from {}: {e}",
                migrations_dir.as_ref().display()
            )
        });
    migrator
        .run(&pool)
        .await
        .unwrap_or_else(|e| panic!("skauswatch-testkit: apply migrations into {schema}: {e}"));

    tracing::debug!(
        schema,
        "skauswatch-testkit: provisioned isolated test schema"
    );
    pool
}

/// Like [`test_pool`] but applies SEVERAL migration directories into one
/// isolated schema. For services whose handlers query tables OWNED by another
/// service — the manager reads s3scan's `s3_scan_*`/`adhoc_scan_results`, and
/// the workers read their backend's tables — this co-locates the borrowed
/// tables for tests WITHOUT duplicating any `CREATE TABLE` across services'
/// production migrations (each service still ships only the migration for the
/// tables it owns). Each dir's `*.sql` files are executed raw (simple query
/// protocol) in filename order, so two services' `0001_*` files never collide
/// on sqlx migration version numbers the way [`sqlx::migrate::Migrator`] would.
#[allow(clippy::panic)] // test-infra bootstrap: fail loudly, not silently skip DB coverage
pub async fn test_pool_multi(migration_dirs: &[&Path]) -> PgPool {
    let url = connection_url();
    let schema = format!("test_{}", uuid::Uuid::new_v4().simple());

    let bootstrap = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap_or_else(|e| panic!("skauswatch-testkit: connect to Postgres at {url}: {e}"));
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&bootstrap)
        .await
        .unwrap_or_else(|e| panic!("skauswatch-testkit: create schema {schema}: {e}"));
    bootstrap.close().await;

    let schema_for_hook = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .after_connect(move |conn, _meta| {
            let schema = schema_for_hook.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SET search_path TO \"{schema}\""
                )))
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap_or_else(|e| panic!("skauswatch-testkit: connect scoped pool for {schema}: {e}"));

    for dir in migration_dirs {
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| {
                panic!(
                    "skauswatch-testkit: read migration dir {}: {e}",
                    dir.display()
                )
            })
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        files.sort();
        for f in files {
            let sql = std::fs::read_to_string(&f)
                .unwrap_or_else(|e| panic!("skauswatch-testkit: read {}: {e}", f.display()));
            // Trusted, in-repo schema files (never user input) — assert safe so
            // sqlx's simple-query protocol runs the file's multiple statements.
            sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "skauswatch-testkit: apply {} into {schema}: {e}",
                        f.display()
                    )
                });
        }
    }
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_url_uses_test_defaults_when_unset() {
        // Deliberately does not touch process env (parallel test runs would
        // race on it) — exercises the pure default-substitution path only.
        assert_eq!(
            env_or("SKAUSWATCH_TESTKIT_UNSET_VAR", "fallback"),
            "fallback"
        );
    }

    #[test]
    fn connection_url_shape() {
        // No env overrides asserted here (see above); just checks the URL
        // renders with the `postgres://` scheme and all five parts present
        // in some form.
        let url = connection_url();
        assert!(url.starts_with("postgres://"));
        assert!(url.contains('@'));
        assert!(url.contains(':'));
    }
}
