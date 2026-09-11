//! mTLS SPIFFE + ingest-token + UDP-CIDR tenant resolution (Task 1.4, see
//! `docs/v2-port/ingest-module-spec.md` §6). Every function here answers
//! exactly one question -- "what tenant does this ALREADY-authenticated
//! caller belong to" -- and NEVER reads a tenant from the event
//! payload/request parameters: tenant is always derived from the validated
//! identity (mTLS SPIFFE ID row, ingest-token row, or the operator's
//! trusted-CIDR config) and stamped onto the document by the caller before
//! enqueueing (§6d, the house tenant-isolation rule).
//!
//! # Blocked (see task-1.4 report)
//!
//! Two pieces of this module reference symbols that do not exist yet in
//! files outside this task's file scope (`services/svc-ingest/Cargo.toml`,
//! `services/svc-ingest/src/config.rs`) and are therefore left as the
//! *intended, correct* implementation rather than routed around:
//!
//! - [`hash_token`] requires the `sha2` crate, which is workspace-pinned
//!   (`Cargo.toml`'s `[workspace.dependencies]`, `sha2 = "=0.10.9"`) but not
//!   yet added to `services/svc-ingest/Cargo.toml`'s own `[dependencies]`.
//! - [`resolve_via_udp_cidr`] requires a per-deployment "which tenant do
//!   trusted-CIDR UDP packets belong to" value, which
//!   `services/svc-ingest/src/config.rs::Config` does not yet expose as a
//!   field (its `SYSLOG_TRUSTED_CIDRS`/`syslog_trusted_cidrs` only encodes
//!   *which* source IPs are trusted, never *which tenant* they map to).
//!
//! Both gaps, and the exact minimal patch for each, are documented in
//! `.superpowers/sdd/svc-ingest/reports/task-1.4-report.md`.

// Wave 1 (Task 1.1/1.2/1.3, not this task) wires these functions into the
// syslog/OTLP/HTTPS listeners and `main.rs`'s `serve()` -- until then,
// `cargo build`'s reachability analysis (this crate has no `[lib]` target,
// only a `[[bin]]`) sees this whole module as unused from production code.
// Same pattern as the other Task-0.2/1.x stub modules'
// `#[allow(dead_code)]` (see `buffer/mod.rs`, `writer.rs`).
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::identity_store::IdentityStore;

/// PostHog flag gating the entire service (Professional tier, default
/// OFF) -- see `services/manager/src/flags.rs`'s module flag list. Same
/// constant name/value as `services/logs/src/ingest.rs::LOG_INGEST_FLAG`;
/// it is the same flag.
pub const LOG_INGEST_FLAG: &str = "skauswatch.log-ingest";

/// Ingest-token cache TTL (Spec §9b: "5 min cache, validate on every
/// request") -- a [`TokenCache`] hit within this window skips the
/// `ingest_tokens` DB round trip entirely; a miss or an expired entry
/// always re-queries [`IdentityStore`].
const TOKEN_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Expected SPIFFE trust domain for every ingest peer (`penguintech.md`:
/// `spiffe://penguintech.io/<env>/<service>` -- the environment segment is
/// part of the *path*, so this constant is env-invariant). `resolve_via_mtls`
/// checks this itself, as defense-in-depth on top of (never instead of)
/// `skauswatch_identity::tls`'s handshake-time chain/SPIFFE-ID validation --
/// this module has no test coverage of that upstream layer, so it should
/// not rely on it alone to keep a wrong-trust-domain peer from resolving.
const EXPECTED_TRUST_DOMAIN: &str = "penguintech.io";

/// Failures resolving an ingest source's tenant. Deliberately carries no
/// underlying `sqlx::Error`/parse detail: any internal failure (DB
/// unreachable, malformed row) fails CLOSED as [`AuthError::UnknownIdentity`]
/// rather than leaking why -- this enum only distinguishes the reject
/// *reason* a caller needs to pick an HTTP/gRPC status, never a
/// diagnostic. The underlying error is still logged via `tracing::error!`
/// at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No credential presented at all -- no mTLS peer identity, no bearer
    /// token (empty/absent `Authorization` header).
    #[error("no credential presented")]
    NoCredential,
    /// A client certificate was presented but is missing, malformed, or
    /// carries no valid SPIFFE ID (Spec §6a).
    #[error("invalid or unparsable client certificate")]
    InvalidCert,
    /// A successfully-authenticated identity (SPIFFE path or token hash)
    /// has no row in the identity tables, or the lookup itself failed.
    #[error("identity not provisioned for ingest")]
    UnknownIdentity,
    /// The ingest token matched a row, but it has been revoked.
    #[error("ingest token revoked")]
    TokenRevoked,
    /// The ingest token matched a row, but it is past `expires_at`.
    #[error("ingest token expired")]
    TokenExpired,
}

impl AuthError {
    /// HTTP status this failure maps to, per Spec §6a/§6b/§6d:
    /// `NoCredential`/`TokenRevoked`/`TokenExpired` are 401 (no/expired
    /// credential); `InvalidCert`/`UnknownIdentity` are 403 (credential
    /// presented but not trusted/provisioned). Listener tasks (1.1-1.3)
    /// use this instead of re-deriving the mapping themselves.
    #[must_use]
    pub fn status_code(self) -> axum::http::StatusCode {
        match self {
            AuthError::NoCredential | AuthError::TokenRevoked | AuthError::TokenExpired => {
                axum::http::StatusCode::UNAUTHORIZED
            }
            AuthError::InvalidCert | AuthError::UnknownIdentity => {
                axum::http::StatusCode::FORBIDDEN
            }
        }
    }
}

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status_code(),
            axum::Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// Resolves an already-verified mTLS peer's SPIFFE ID to its provisioned
/// tenant (Spec §6a). The caller (a listener's rustls acceptor) has
/// already completed the handshake and validated the certificate chain
/// before this is ever invoked -- `skauswatch_identity::tls`'s verifiers
/// reject an invalid chain or a certificate with no valid SPIFFE ID at the
/// TLS layer itself, before an application-level `SpiffeId` value can even
/// exist (that rejection surfaces to callers as [`AuthError::InvalidCert`]
/// without ever reaching this function).
///
/// Defense-in-depth: `peer.trust_domain_name()` MUST equal
/// [`EXPECTED_TRUST_DOMAIN`] before any tenant lookup happens at all -- a
/// syntactically-valid SPIFFE ID from an unexpected trust domain is
/// rejected even if its *path* happens to match a provisioned identity's,
/// never resolved to that identity's tenant. This does not depend on (and
/// is not a replacement for) the upstream handshake-time check; it exists
/// so this function is self-defending on its own inputs. Beyond that, an
/// unrecognized `peer.path()` -- no row in `ingest_identities` -- is
/// [`AuthError::UnknownIdentity`], never a fallback/default tenant.
///
/// # Errors
/// Returns [`AuthError::UnknownIdentity`] when `peer`'s trust domain isn't
/// [`EXPECTED_TRUST_DOMAIN`], when its SPIFFE path has no row in
/// `ingest_identities`, or when the lookup itself fails (fail closed --
/// never grants access on an internal error).
pub async fn resolve_via_mtls(
    peer: &spiffe::SpiffeId,
    store: &IdentityStore,
) -> Result<skauswatch_auth::Tenant, AuthError> {
    if peer.trust_domain_name() != EXPECTED_TRUST_DOMAIN {
        tracing::warn!(
            trust_domain = peer.trust_domain_name(),
            spiffe_path = peer.path(),
            "mTLS peer trust domain mismatch, rejecting without a tenant lookup"
        );
        return Err(AuthError::UnknownIdentity);
    }
    match store.tenant_for_spiffe_path(peer.path()).await {
        Ok(Some(tenant)) => Ok(tenant),
        Ok(None) => Err(AuthError::UnknownIdentity),
        Err(error) => {
            tracing::error!(%error, spiffe_path = peer.path(), "identity_store SPIFFE lookup failed");
            Err(AuthError::UnknownIdentity)
        }
    }
}

/// Hex-encoded SHA-256 digest of `raw_token`, computed BEFORE any DB
/// lookup, cache insertion, or log line touches the token (Spec §6b
/// security-evidence requirement: "never store or log a plaintext ingest
/// token").
///
/// BLOCKED: `sha2` is workspace-pinned but not yet a direct dependency of
/// `skauswatch-svc-ingest` -- see this module's top-level doc comment.
fn hash_token(raw_token: &str) -> String {
    let digest = Sha256::digest(raw_token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hand-rolled 5-minute TTL cache from ingest-token hash to resolved
/// tenant (Spec §9b: "5 min cache, validate on every request"). A cache
/// hit within [`TOKEN_CACHE_TTL`] skips
/// [`IdentityStore::tenant_for_token_hash`] entirely; a miss or an expired
/// entry always re-queries it. Only ever caches a token that was valid
/// (not revoked, not expired) at lookup time -- a revocation becomes
/// visible to this cache within one TTL window at worst, never cached
/// indefinitely.
#[derive(Debug, Clone, Default)]
pub struct TokenCache {
    entries: Arc<Mutex<HashMap<String, (skauswatch_auth::Tenant, Instant)>>>,
}

impl TokenCache {
    /// Builds an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached tenant for `hash` if present and still within
    /// [`TOKEN_CACHE_TTL`] of insertion. An expired entry is evicted as a
    /// side effect and never returned -- the caller re-queries
    /// [`IdentityStore`] on both `None` outcomes (missing vs. expired).
    fn get(&self, hash: &str) -> Option<skauswatch_auth::Tenant> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.get(hash) {
            Some((tenant, inserted_at)) if inserted_at.elapsed() < TOKEN_CACHE_TTL => {
                Some(tenant.clone())
            }
            Some(_) => {
                entries.remove(hash);
                None
            }
            None => None,
        }
    }

    /// Caches `tenant` for `hash`, timestamped `Instant::now()`.
    fn insert(&self, hash: String, tenant: skauswatch_auth::Tenant) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.insert(hash, (tenant, Instant::now()));
    }

    /// Test-only seam: inserts an entry timestamped with a caller-chosen
    /// `Instant`, so TTL-expiry tests don't need to sleep 5 real minutes.
    #[cfg(test)]
    fn insert_at(&self, hash: String, tenant: skauswatch_auth::Tenant, at: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.insert(hash, (tenant, at));
    }
}

/// Resolves a bearer ingest token to its provisioned tenant (Spec §6b).
///
/// `raw_token` empty/blank means no credential was presented at all -- the
/// caller had neither an mTLS peer identity nor a non-empty
/// `Authorization: Bearer` value -- which is [`AuthError::NoCredential`],
/// never a DB lookup. Otherwise: hash the token (the raw value is never
/// looked up, cached, or logged), consult `cache` first, and only fall
/// through to `store` on a miss or an expired cache entry. A successful
/// lookup (not revoked, not expired) is cached for [`TOKEN_CACHE_TTL`]
/// before returning.
///
/// # Errors
/// - [`AuthError::NoCredential`] if `raw_token` is empty/blank.
/// - [`AuthError::UnknownIdentity`] if the token hash has no row, or the
///   lookup itself fails (fail closed).
/// - [`AuthError::TokenRevoked`] / [`AuthError::TokenExpired`] per the
///   matched row's `revoked_at`/`expires_at`.
///
/// BLOCKED: depends on [`hash_token`] -- see this module's top-level doc
/// comment.
pub async fn resolve_via_token(
    raw_token: &str,
    store: &IdentityStore,
    cache: &TokenCache,
) -> Result<skauswatch_auth::Tenant, AuthError> {
    if raw_token.trim().is_empty() {
        return Err(AuthError::NoCredential);
    }
    let hash = hash_token(raw_token);

    if let Some(tenant) = cache.get(&hash) {
        return Ok(tenant);
    }

    let record = match store.tenant_for_token_hash(&hash).await {
        Ok(Some(record)) => record,
        Ok(None) => return Err(AuthError::UnknownIdentity),
        Err(error) => {
            tracing::error!(%error, "identity_store token lookup failed");
            return Err(AuthError::UnknownIdentity);
        }
    };

    if record.revoked_at.is_some() {
        return Err(AuthError::TokenRevoked);
    }
    if record.expires_at < chrono::Utc::now() {
        return Err(AuthError::TokenExpired);
    }

    cache.insert(hash, record.tenant.clone());
    Ok(record.tenant)
}

/// Resolves a UDP syslog packet's source IP to the fixed tenant the
/// operator configured for its trusted CIDR (Spec §6c). Returns `None` --
/// the caller silently drops the packet, no error raised, UDP has no
/// feedback channel -- when UDP syslog is disabled, `peer_ip` matches no
/// configured CIDR, or no fixed tenant is configured. NEVER reads a tenant
/// from the packet itself (Spec §6d).
///
/// BLOCKED: reads `cfg.syslog_udp_tenant_id`, a field
/// `services/svc-ingest/src/config.rs::Config` does not expose yet -- see
/// this module's top-level doc comment.
#[must_use]
pub fn resolve_via_udp_cidr(
    peer_ip: IpAddr,
    cfg: &crate::config::Config,
) -> Option<skauswatch_auth::Tenant> {
    if !cfg.syslog_udp_enabled {
        return None;
    }
    let trusted = cfg
        .syslog_trusted_cidrs
        .iter()
        .any(|cidr| cidr_contains(cidr, peer_ip));
    if !trusted {
        return None;
    }
    cfg.syslog_udp_tenant_id
        .clone()
        .map(skauswatch_auth::Tenant)
}

/// Whether `ip` falls inside `cidr` -- same address family only (an IPv4
/// CIDR never matches an IPv6 peer and vice versa). `cidr.prefix_len` is
/// guaranteed by `CidrBlock::parse` to be `<= 32` for a `V4` network and
/// `<= 128` for `V6`, so the shift amounts below never exceed the target
/// integer's bit width in the reachable branches; `checked_shl` still
/// guards the `/0` case (shift == bit width) without a panic.
fn cidr_contains(cidr: &crate::config::CidrBlock, ip: IpAddr) -> bool {
    match (cidr.network, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            let shift = 32u32 - u32::from(cidr.prefix_len);
            let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            let shift = 128u32 - u32::from(cidr.prefix_len);
            let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
            (u128::from(net) & mask) == (u128::from(addr) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::config::{CidrBlock, Config};

    use super::*;

    async fn store() -> IdentityStore {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        IdentityStore::new(pool)
    }

    fn spiffe_id(uri: &str) -> spiffe::SpiffeId {
        spiffe::SpiffeId::new(uri).expect("valid test SPIFFE URI")
    }

    // -- resolve_via_mtls -----------------------------------------------

    #[tokio::test]
    async fn mtls_cert_valid_ingests_and_stamps_tenant_from_spiffe_id() {
        let store = store().await;
        sqlx::query("INSERT INTO ingest_identities (spiffe_path, tenant_id) VALUES ($1, $2)")
            .bind("/prod/endpoint-agent")
            .bind("tenant-a")
            .execute(store_pool(&store))
            .await
            .unwrap();

        let peer = spiffe_id("spiffe://penguintech.io/prod/endpoint-agent");
        let tenant = resolve_via_mtls(&peer, &store).await.unwrap();
        assert_eq!(tenant, skauswatch_auth::Tenant("tenant-a".to_owned()));
    }

    #[tokio::test]
    async fn mtls_cert_with_mismatched_spiffe_tenant_is_403() {
        let store = store().await;
        // No row provisioned for this SPIFFE ID at all.
        let peer = spiffe_id("spiffe://penguintech.io/prod/unprovisioned-source");
        let err = resolve_via_mtls(&peer, &store).await.unwrap_err();
        assert_eq!(err, AuthError::UnknownIdentity);
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mtls_peer_with_known_path_but_wrong_trust_domain_is_not_resolved() {
        let store = store().await;
        // Same path a legitimate peer would use, provisioned for
        // "tenant-a" -- proves the trust-domain check runs (and rejects)
        // BEFORE any path-based lookup could resolve this to that tenant.
        sqlx::query("INSERT INTO ingest_identities (spiffe_path, tenant_id) VALUES ($1, $2)")
            .bind("/prod/endpoint-agent")
            .bind("tenant-a")
            .execute(store_pool(&store))
            .await
            .unwrap();

        let peer = spiffe_id("spiffe://evil.example.com/prod/endpoint-agent");
        let err = resolve_via_mtls(&peer, &store).await.unwrap_err();
        assert_eq!(err, AuthError::UnknownIdentity);
        assert_ne!(peer.trust_domain_name(), EXPECTED_TRUST_DOMAIN);
    }

    /// `mtls_cert_invalid_is_rejected_403`: an invalid/unparsable
    /// certificate never produces an application-level `SpiffeId` at all
    /// (rustls's SPIFFE verifiers reject it during the handshake itself --
    /// see `skauswatch_identity::tls`) so there is no `&SpiffeId` to pass
    /// to `resolve_via_mtls` in that case. The 403 mapping this test name
    /// asserts is `AuthError::InvalidCert::status_code()` itself -- the
    /// value a listener (Task 1.1-1.3) returns directly when certificate
    /// parsing/handshake verification fails, without ever calling this
    /// function.
    #[test]
    fn mtls_cert_invalid_is_rejected_403() {
        assert_eq!(
            AuthError::InvalidCert.status_code(),
            axum::http::StatusCode::FORBIDDEN
        );
    }

    // -- resolve_via_token ------------------------------------------------

    #[tokio::test]
    async fn ingest_token_valid_ingests_and_stamps_tenant_from_lookup() {
        let store = store().await;
        let hash = hash_token("s3cr3t-token");
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-b")
        .bind(expires)
        .execute(store_pool(&store))
        .await
        .unwrap();

        let cache = TokenCache::new();
        let tenant = resolve_via_token("s3cr3t-token", &store, &cache)
            .await
            .unwrap();
        assert_eq!(tenant, skauswatch_auth::Tenant("tenant-b".to_owned()));
    }

    #[tokio::test]
    async fn ingest_token_revoked_is_401() {
        let store = store().await;
        let hash = hash_token("revoked-token");
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        let revoked = chrono::Utc::now() - chrono::Duration::minutes(1);
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&hash)
        .bind("tenant-c")
        .bind(revoked)
        .bind(expires)
        .execute(store_pool(&store))
        .await
        .unwrap();

        let cache = TokenCache::new();
        let err = resolve_via_token("revoked-token", &store, &cache)
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::TokenRevoked);
        assert_eq!(err.status_code(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ingest_token_expired_is_401() {
        let store = store().await;
        let hash = hash_token("expired-token");
        let expires = chrono::Utc::now() - chrono::Duration::minutes(1);
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-d")
        .bind(expires)
        .execute(store_pool(&store))
        .await
        .unwrap();

        let cache = TokenCache::new();
        let err = resolve_via_token("expired-token", &store, &cache)
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::TokenExpired);
    }

    #[tokio::test]
    async fn bearer_token_absent_and_no_mtls_is_401() {
        let store = store().await;
        let cache = TokenCache::new();
        let err = resolve_via_token("", &store, &cache).await.unwrap_err();
        assert_eq!(err, AuthError::NoCredential);
        assert_eq!(err.status_code(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_cache_hit_skips_db_lookup_within_ttl() {
        let store = store().await;
        let hash = hash_token("cached-token");
        // DB row (if consulted) resolves to a DIFFERENT tenant than the
        // cached value -- proving a cache hit short-circuits the DB.
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-from-db")
        .bind(expires)
        .execute(store_pool(&store))
        .await
        .unwrap();

        let cache = TokenCache::new();
        cache.insert(
            hash,
            skauswatch_auth::Tenant("tenant-from-cache".to_owned()),
        );

        let tenant = resolve_via_token("cached-token", &store, &cache)
            .await
            .unwrap();
        assert_eq!(
            tenant,
            skauswatch_auth::Tenant("tenant-from-cache".to_owned())
        );
    }

    #[tokio::test]
    async fn token_cache_expires_after_five_minutes() {
        let store = store().await;
        let hash = hash_token("expiring-cache-token");
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(&hash)
        .bind("tenant-from-db")
        .bind(expires)
        .execute(store_pool(&store))
        .await
        .unwrap();

        let cache = TokenCache::new();
        // Seed a stale entry (older than the 5-minute TTL) for a DIFFERENT
        // tenant -- if the cache incorrectly treated this as live, the
        // result below would be "tenant-from-stale-cache" instead of the
        // DB's "tenant-from-db".
        cache.insert_at(
            hash,
            skauswatch_auth::Tenant("tenant-from-stale-cache".to_owned()),
            Instant::now() - Duration::from_secs(301),
        );

        let tenant = resolve_via_token("expiring-cache-token", &store, &cache)
            .await
            .unwrap();
        assert_eq!(tenant, skauswatch_auth::Tenant("tenant-from-db".to_owned()));
    }

    // -- resolve_via_udp_cidr ---------------------------------------------

    /// Builds a `Config` fixture via its public fields directly --
    /// `Config::from_values`/`CidrBlock::parse` are private to the
    /// `config` module, so a struct literal (every `Config`/`CidrBlock`
    /// field is `pub`) is the only way to construct one from `crate::auth`.
    /// Non-UDP fields are set to the same defaults `config.rs` documents.
    fn test_config(enabled: bool, cidrs: Vec<CidrBlock>, tenant: Option<&str>) -> Config {
        Config {
            http_port: 8443,
            syslog_port: 5140,
            syslog_tls_port: 6514,
            otlp_grpc_port: 4317,
            otlp_http_port: 4318,
            opensearch_url: "http://localhost:9200".to_owned(),
            nats_url: "nats://localhost:4222".to_owned(),
            nats_jetstream_subject_prefix: "svc-ingest.logs".to_owned(),
            syslog_udp_enabled: enabled,
            syslog_trusted_cidrs: cidrs,
            syslog_udp_tenant_id: tenant.map(str::to_owned),
        }
    }

    fn ipv4_cidr(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> CidrBlock {
        CidrBlock {
            network: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix_len,
        }
    }

    fn ipv6_cidr(addr: Ipv6Addr, prefix_len: u8) -> CidrBlock {
        CidrBlock {
            network: IpAddr::V6(addr),
            prefix_len,
        }
    }

    #[test]
    fn udp_packet_from_trusted_cidr_stamps_configured_tenant() {
        let cfg = test_config(true, vec![ipv4_cidr(10, 0, 0, 0, 8)], Some("tenant-udp"));
        let tenant = resolve_via_udp_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), &cfg);
        assert_eq!(
            tenant,
            Some(skauswatch_auth::Tenant("tenant-udp".to_owned()))
        );
    }

    #[test]
    fn udp_packet_from_untrusted_cidr_dropped_no_error() {
        let cfg = test_config(true, vec![ipv4_cidr(10, 0, 0, 0, 8)], Some("tenant-udp"));
        let tenant = resolve_via_udp_cidr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &cfg);
        assert_eq!(tenant, None);
    }

    #[test]
    fn udp_disabled_never_stamps_a_tenant_even_from_a_trusted_cidr() {
        let cfg = test_config(false, vec![ipv4_cidr(10, 0, 0, 0, 8)], Some("tenant-udp"));
        let tenant = resolve_via_udp_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), &cfg);
        assert_eq!(tenant, None);
    }

    #[test]
    fn udp_trusted_cidr_with_no_configured_tenant_is_none() {
        let cfg = test_config(true, vec![ipv4_cidr(10, 0, 0, 0, 8)], None);
        let tenant = resolve_via_udp_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), &cfg);
        assert_eq!(tenant, None);
    }

    #[test]
    fn ipv4_cidr_never_matches_an_ipv6_peer() {
        let cfg = test_config(true, vec![ipv4_cidr(10, 0, 0, 0, 8)], Some("tenant-udp"));
        let tenant = resolve_via_udp_cidr(IpAddr::V6(Ipv6Addr::LOCALHOST), &cfg);
        assert_eq!(tenant, None);
    }

    #[test]
    fn ipv6_trusted_cidr_matches_ipv6_peer() {
        let cfg = test_config(
            true,
            vec![ipv6_cidr(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 8)],
            Some("tenant-v6"),
        );
        let tenant =
            resolve_via_udp_cidr(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), &cfg);
        assert_eq!(
            tenant,
            Some(skauswatch_auth::Tenant("tenant-v6".to_owned()))
        );
    }

    #[test]
    fn cidr_contains_ipv4_prefix_zero_matches_every_address() {
        let cidr = ipv4_cidr(0, 0, 0, 0, 0);
        assert!(cidr_contains(&cidr, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(cidr_contains(
            &cidr,
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))
        ));
    }

    #[test]
    fn cidr_contains_ipv4_prefix_32_matches_only_the_exact_host() {
        let cidr = ipv4_cidr(10, 0, 0, 1, 32);
        assert!(cidr_contains(&cidr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!cidr_contains(
            &cidr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        ));
    }

    #[test]
    fn cidr_contains_ipv6_prefix_128_matches_only_the_exact_host() {
        let host = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let cidr = ipv6_cidr(host, 128);
        assert!(cidr_contains(&cidr, IpAddr::V6(host)));
        assert!(!cidr_contains(
            &cidr,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
        ));
    }

    /// Test-only accessor -- `IdentityStore`'s pool field is private, but
    /// tests in this module (not `identity_store`'s own `#[cfg(test)]`
    /// block) still need it to seed fixture rows directly.
    fn store_pool(store: &IdentityStore) -> &sqlx::PgPool {
        store.pool()
    }
}
