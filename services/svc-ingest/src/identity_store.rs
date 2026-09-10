//! Postgres-backed SPIFFE-path/ingest-token-hash → tenant lookup — stub
//! until Task 1.4 fills in `IdentityStore` (see
//! `docs/v2-port/ingest-module-spec.md` §6,
//! `migrations/0001_ingest_identity.sql`).

/// Lookup store for mTLS SPIFFE paths and ingest-token hashes → tenant.
/// Stub: holds no connection yet — Task 1.4 replaces this with the real
/// `sqlx::PgPool`-backed implementation.
// dead_code: unreferenced until Task 1.4 wires this into `crate::auth`.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct IdentityStore;
