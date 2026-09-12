//! Postgres-backed SPIFFE-path/ingest-token-hash -> tenant lookup (Task
//! 1.4, `docs/v2-port/ingest-module-spec.md` §6,
//! `migrations/0001_ingest_identity.sql`). These two tables are the ONLY
//! place an authenticated ingest identity resolves to a tenant --
//! `crate::auth` never trusts anything else (see that module's docs).

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// A resolved ingest-token row: the tenant it grants, plus the two fields
/// `crate::auth::resolve_via_token` needs to decide revoked/expired before
/// trusting it. Deliberately does not itself decide policy -- policy
/// (401 on revoked/expired) lives in `crate::auth`, this is a plain lookup
/// result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// Tenant the token is provisioned for.
    pub tenant: skauswatch_auth::Tenant,
    /// Set once the token is revoked (via the manager's provisioning
    /// API); `None` means still active.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Hard expiry -- every ingest token is short-lived by design (Spec
    /// §6b), never non-expiring.
    pub expires_at: DateTime<Utc>,
}

/// Raw row shape for `ingest_tokens`, mapped into the public
/// [`TokenRecord`] (which carries a [`skauswatch_auth::Tenant`], not a bare
/// `String`) by [`IdentityStore::tenant_for_token_hash`].
#[derive(Debug, sqlx::FromRow)]
struct TokenRow {
    tenant_id: String,
    revoked_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

/// Lookup store for mTLS SPIFFE paths and ingest-token hashes -> tenant,
/// backed by the `ingest_identities`/`ingest_tokens` tables. Every ingest
/// tenant assignment this service makes for an mTLS- or
/// token-authenticated source flows through this store.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    pool: PgPool,
}

impl IdentityStore {
    /// Wraps an already-connected pool (see
    /// `skauswatch_db::connect_postgres`). Schema is applied separately via
    /// the `migrate` subcommand -- this constructor never migrates.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Test-only accessor for the underlying pool -- lets `crate::auth`'s
    /// own test module (a sibling, not a descendant, of this module) seed
    /// fixture rows directly without a public production API surface for
    /// reaching around this store's lookup methods.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Resolves a peer's SPIFFE ID path segment (`spiffe::SpiffeId::path()`,
    /// e.g. `/prod/endpoint-agent`) to its provisioned tenant. `Ok(None)`
    /// means the path has no row -- an unrecognized/unprovisioned identity,
    /// which `crate::auth::resolve_via_mtls` treats as a 403, never a
    /// fallback tenant.
    ///
    /// # Errors
    /// Propagates any `sqlx::Error` from the underlying query (connection
    /// failure, etc.) -- callers fail closed on this, same as `Ok(None)`.
    pub async fn tenant_for_spiffe_path(
        &self,
        path: &str,
    ) -> sqlx::Result<Option<skauswatch_auth::Tenant>> {
        let tenant_id: Option<String> =
            sqlx::query_scalar("SELECT tenant_id FROM ingest_identities WHERE spiffe_path = $1")
                .bind(path)
                .fetch_optional(&self.pool)
                .await?;
        Ok(tenant_id.map(skauswatch_auth::Tenant))
    }

    /// Resolves a hex-encoded SHA-256 token hash (never the raw token --
    /// hashing happens in `crate::auth::resolve_via_token` before this is
    /// ever called) to its full [`TokenRecord`], letting the caller apply
    /// revoked/expired policy. `Ok(None)` means no token was ever
    /// provisioned with this hash.
    ///
    /// # Errors
    /// Propagates any `sqlx::Error` from the underlying query.
    pub async fn tenant_for_token_hash(&self, hash: &str) -> sqlx::Result<Option<TokenRecord>> {
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT tenant_id, revoked_at, expires_at FROM ingest_tokens WHERE token_hash = $1",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| TokenRecord {
            tenant: skauswatch_auth::Tenant(r.tenant_id),
            revoked_at: r.revoked_at,
            expires_at: r.expires_at,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use chrono::{Duration, SubsecRound};

    use super::*;

    async fn store() -> IdentityStore {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        IdentityStore::new(pool)
    }

    #[tokio::test]
    async fn tenant_for_spiffe_path_returns_provisioned_tenant() {
        let store = store().await;
        sqlx::query("INSERT INTO ingest_identities (spiffe_path, tenant_id) VALUES ($1, $2)")
            .bind("/prod/endpoint-agent")
            .bind("tenant-a")
            .execute(&store.pool)
            .await
            .unwrap();

        let tenant = store
            .tenant_for_spiffe_path("/prod/endpoint-agent")
            .await
            .unwrap();
        assert_eq!(tenant, Some(skauswatch_auth::Tenant("tenant-a".to_owned())));
    }

    #[tokio::test]
    async fn tenant_for_spiffe_path_unprovisioned_is_none() {
        let store = store().await;
        let tenant = store
            .tenant_for_spiffe_path("/prod/never-provisioned")
            .await
            .unwrap();
        assert_eq!(tenant, None);
    }

    #[tokio::test]
    async fn tenant_for_token_hash_returns_full_record() {
        let store = store().await;
        // Postgres `TIMESTAMPTZ` round-trips at microsecond precision;
        // `Utc::now()` carries nanoseconds. Truncate before binding so the
        // value read back compares equal to what we inserted, rather than
        // failing on a sub-microsecond remainder Postgres never stored.
        let expires = (Utc::now() + Duration::hours(1)).trunc_subsecs(6);
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind("deadbeef")
        .bind("tenant-b")
        .bind(expires)
        .execute(&store.pool)
        .await
        .unwrap();

        let record = store
            .tenant_for_token_hash("deadbeef")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            record.tenant,
            skauswatch_auth::Tenant("tenant-b".to_owned())
        );
        assert!(record.revoked_at.is_none());
        assert_eq!(record.expires_at, expires);
    }

    #[tokio::test]
    async fn tenant_for_token_hash_unknown_is_none() {
        let store = store().await;
        assert_eq!(
            store.tenant_for_token_hash("never-issued").await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn tenant_for_token_hash_reports_revoked_at() {
        let store = store().await;
        let expires = Utc::now() + Duration::hours(1);
        let revoked = Utc::now() - Duration::minutes(5);
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind("revoked-hash")
        .bind("tenant-c")
        .bind(revoked)
        .bind(expires)
        .execute(&store.pool)
        .await
        .unwrap();

        let record = store
            .tenant_for_token_hash("revoked-hash")
            .await
            .unwrap()
            .unwrap();
        assert!(record.revoked_at.is_some());
    }
}
