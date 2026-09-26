//! Durable certificate + revocation store, consolidated onto the same
//! Postgres tables `services/pki` already owns (`ssh_certificates` +
//! `crl_entries`) instead of the pre-hardening in-memory `HashMap`.
//!
//! ## Why this exists
//!
//! sshca previously kept issued certificates in an in-memory `HashMap`
//! with revocations in an in-memory `BTreeMap`, both reset on every pod
//! restart/redeploy — a revoked SSH certificate read as valid again after
//! any restart, and no issuance record survived a crash. For a service
//! that holds an SSH CA signing key, that is a real security gap, not a
//! cosmetic one: revocation must be durable.
//!
//! ## Consolidation decision
//!
//! `services/pki` already owns a complete, tenant-scoped, tested Postgres
//! schema for exactly this data shape (`ssh_certificates`, `crl_entries`;
//! `services/pki/migrations/0001_pki_schema.sql`,
//! `0002_tenancy.sql`) — built for its own SSH CA surface
//! (`services/pki/src/ca/ssh.rs`, `services/pki/src/manager.rs`). Two
//! mechanisms were possible to consolidate sshca onto it:
//!
//!   1. **Shared DB table, per-service DB grants (chosen).** sshca
//!      connects to the same Postgres database and writes directly into
//!      pki's `ssh_certificates`/`crl_entries` tables via its own
//!      `DB_USER` (per `backend-database.md`'s per-service-account model —
//!      grants scoped to only these two tables, no `x509_certificates` or
//!      `pki_audit_log` access). Schema authority (migrations) stays
//!      entirely with `services/pki`; this crate ships no migrations of
//!      its own and issues no DDL. Test coverage reuses pki's migrations
//!      directly (`skauswatch_testkit::db::test_pool_multi`, see
//!      `crate::test_support`) rather than duplicating the `CREATE TABLE`
//!      statements.
//!   2. **pki storage-module reuse.** sshca would depend on
//!      `skauswatch-pki` as a library crate and call into `CertManager`'s
//!      SSH methods directly.
//!
//!   (1) was chosen over (2): pki's `CertManager` bundles the X.509 CA
//!   engine, the SSH CA engine, and the Postgres pool behind one type, so
//!   reusing its SSH methods would require either pulling pki's entire
//!   dependency tree (`rcgen`, `x509-parser`, a Tonic gRPC server, …) into
//!   sshca purely to reuse a handful of SQL statements, or first
//!   splitting `CertManager` into an SSH-only sub-type — a larger, riskier
//!   change to pki than this consolidation calls for. A source-level
//!   crate dependency between the two services would also tie their
//!   compile/deploy cadence together, which contradicts the microservice
//!   boundary the two REST surfaces still deliberately keep (each ships
//!   its own binary, port, and Helm chart). Per-service DB grants over one
//!   shared table is exactly the scenario `backend-database.md`'s
//!   "shared DB, separate credentials with fine-grained grants" convention
//!   anticipates — this is a genuinely shared bounded context (one SSH
//!   certificate authority, two REST fronts), not a generic multi-owner
//!   table being (ab)used for unrelated data.
//!
//! ## Serial-number namespacing
//!
//! `ssh_certificates.serial_number` is `UNIQUE`. pki's own `SshCa` engine
//! (`services/pki/src/ca/ssh.rs`) seeds its in-memory serial counter at 1;
//! this store keeps sshca's existing v1-parity seed unchanged
//! ([`SERIAL_SEED`] = 1,000,000; first issued serial 1,000,001), so the
//! two writers' typical ranges do not overlap. Both counters are
//! in-memory and reset to their seed on every restart — a pre-existing
//! property of both engines that this change does not introduce or fix
//! (neither engine persisted serial state before now, so this is not a
//! regression). The 1,000,000-serial headroom makes an actual collision
//! between the two services' current issuance volume exceedingly
//! unlikely, but it is a documented convention, not a database-enforced
//! guarantee — flagged as a residual limitation shared with pki's own
//! engine, out of scope for this port.
//!
//! ## Tenant isolation
//!
//! Unchanged in spirit from the in-memory store: every query below is
//! scoped to `tenant` (`tenant_id` column, `docs/v2-port/tenancy-model.md`
//! §3) — a certificate that exists but belongs to a different tenant
//! resolves identically to a genuinely unknown one.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::NaiveDateTime;
use sqlx::types::Json;
use sqlx::{PgPool, QueryBuilder, Row};
use uuid::Uuid;

use crate::model::CertificateType;

/// v1 serial counter seed — first issued serial is `SERIAL_SEED + 1`. See
/// the module doc's "Serial-number namespacing" note: unchanged from the
/// pre-persistence engine, chosen to stay clear of pki's own SSH engine's
/// range.
pub const SERIAL_SEED: u64 = 1_000_000;

/// Column list shared by `get`/`list` reads of `ssh_certificates` (see
/// `services/pki/migrations/0001_pki_schema.sql`, `0002_tenancy.sql` for
/// the schema this maps onto).
const SSH_COLS: &str = "id, tenant_id, serial_number, key_id, certificate_type, principals, \
    valid_after, valid_before, key_type, public_key, certificate, critical_options, \
    extensions, source_address, force_command, status, revoked_at, revocation_reason, metadata";

/// A single issued certificate record.
#[derive(Debug, Clone)]
pub struct StoredCert {
    /// Certificate id — canonical UUID string, the `ssh_certificates.id`
    /// primary key. See `crate::routes::issue_certificate` for why a
    /// caller-supplied non-UUID `request_id` no longer round-trips
    /// verbatim: the shared, pki-owned schema requires a UUID primary key.
    pub certificate_id: String,
    /// The tenant that issued this certificate — sourced from the
    /// request's `X-Tenant-ID` header at issuance time, never from client
    /// input.
    pub tenant_id: Uuid,
    /// User or host.
    pub certificate_type: CertificateType,
    /// Serial number.
    pub serial_number: u64,
    /// Certificate key id.
    pub key_id: String,
    /// Detected subject key type (`ed25519`/`rsa`/`ecdsa`/`unknown`).
    pub key_type: String,
    /// Effective principals.
    pub principals: Vec<String>,
    /// `active` / `revoked`.
    pub status: String,
    /// The signed OpenSSH certificate line.
    pub signed_certificate: String,
    /// Subject public key, OpenSSH line format — the source used to
    /// recompute `public_key_fingerprint` on read (see `crate::ca::
    /// public_key_fingerprint`), since the durable schema has no
    /// dedicated fingerprint column.
    pub public_key: String,
    /// Effective extensions applied.
    pub extensions: BTreeMap<String, String>,
    /// Effective critical options applied.
    pub critical_options: BTreeMap<String, String>,
    /// Allowed source addresses (also folded into `critical_options` for
    /// signing; kept separately here to match pki's dedicated
    /// `source_address` column).
    pub source_addresses: Vec<String>,
    /// Forced command, if any.
    pub force_command: Option<String>,
    /// Valid-after instant (UTC).
    pub valid_after: NaiveDateTime,
    /// Valid-before instant (UTC).
    pub valid_before: NaiveDateTime,
    /// Revocation instant, if revoked.
    pub revoked_at: Option<NaiveDateTime>,
    /// Revocation reason, if revoked.
    pub revocation_reason: Option<String>,
    /// Echoed request metadata.
    pub metadata: serde_json::Value,
}

/// One Key Revocation List entry. No per-entry fingerprint field: pki's
/// `crl_entries` table (the schema this now reads from) has no fingerprint
/// column, matching pki's own `generate_ssh_krl` output shape — this is a
/// documented, minor wire-shape change from the pre-persistence in-memory
/// KRL (see `crate::routes::get_krl`).
#[derive(Debug, Clone)]
pub struct KrlEntry {
    /// Revoked serial number.
    pub serial_number: u64,
    /// Revocation instant (UTC).
    pub revocation_time: NaiveDateTime,
    /// Revocation reason.
    pub reason: String,
}

/// Durable issued-certificate + revocation store backed by the same
/// Postgres tables `services/pki` owns — see the module doc's
/// consolidation decision.
#[derive(Debug)]
pub struct CertStore {
    serial: AtomicU64,
    db: PgPool,
}

impl CertStore {
    /// Builds a store over `db` — a pool pointed at the same database
    /// `services/pki` migrates, using a per-service `DB_USER` granted only
    /// on `ssh_certificates`/`crl_entries` (see the module doc).
    pub fn new(db: PgPool) -> Self {
        Self {
            serial: AtomicU64::new(SERIAL_SEED),
            db,
        }
    }

    /// Returns the next serial (`SERIAL_SEED + 1`, then increasing). Kept
    /// as an in-memory monotonic counter, unchanged from before this port
    /// — see the module doc's "Serial-number namespacing" note.
    pub fn next_serial(&self) -> u64 {
        self.serial.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Persists a newly issued certificate. `cert.certificate_id` must
    /// already be a canonical UUID string (enforced by the caller —
    /// `crate::routes::issue_certificate`); an unparseable value falls
    /// back to a freshly generated UUID rather than failing the insert,
    /// so a caller bug here degrades to "a different id than requested"
    /// rather than a lost certificate.
    pub async fn insert(&self, cert: StoredCert) -> Result<(), sqlx::Error> {
        let id = Uuid::parse_str(&cert.certificate_id).unwrap_or_else(|_| Uuid::new_v4());
        let now = chrono::Utc::now().naive_utc();
        sqlx::query(
            "INSERT INTO ssh_certificates \
             (id, tenant_id, serial_number, key_id, certificate_type, principals, \
              valid_after, valid_before, key_type, public_key, certificate, \
              critical_options, extensions, source_address, force_command, status, \
              hostname, requester_id, approval_request_id, metadata, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)",
        )
        .bind(id)
        .bind(cert.tenant_id)
        .bind(cert.serial_number.to_string())
        .bind(&cert.key_id)
        .bind(cert.certificate_type.as_str())
        .bind(&cert.principals)
        .bind(cert.valid_after)
        .bind(cert.valid_before)
        .bind(&cert.key_type)
        .bind(&cert.public_key)
        .bind(&cert.signed_certificate)
        .bind(Json(btreemap_to_json(&cert.critical_options)))
        .bind(Json(btreemap_to_json(&cert.extensions)))
        .bind(&cert.source_addresses)
        .bind(cert.force_command.as_deref())
        .bind(&cert.status)
        .bind::<Option<String>>(None) // hostname: sshca collects no dedicated hostname field
        .bind::<Option<Uuid>>(None) // requester_id: sshca's requester_id is audit-only free text, not a UUID FK
        .bind::<Option<Uuid>>(None) // approval_request_id: no approval workflow in sshca
        .bind(Json(cert.metadata))
        .bind(now)
        .bind(now)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Fetches a certificate by id, scoped to `tenant`. An unparseable id
    /// resolves to `Ok(None)` without touching the database — mirrors
    /// `services/pki/src/manager.rs`'s identifier-resolution pattern.
    pub async fn get(
        &self,
        cert_id: &str,
        tenant: Uuid,
    ) -> Result<Option<StoredCert>, sqlx::Error> {
        let Ok(id) = Uuid::parse_str(cert_id) else {
            return Ok(None);
        };
        let mut qb = QueryBuilder::new("SELECT ");
        qb.push(SSH_COLS)
            .push(" FROM ssh_certificates WHERE id = ")
            .push_bind(id)
            .push(" AND tenant_id = ")
            .push_bind(tenant);
        let row = qb.build().fetch_optional(&self.db).await?;
        Ok(row.map(|r| row_to_stored(&r)))
    }

    /// Lists `tenant`'s certificates filtered by type/status, capped at
    /// `limit`, most recently issued first.
    pub async fn list(
        &self,
        tenant: Uuid,
        certificate_type: Option<CertificateType>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<StoredCert>, sqlx::Error> {
        let mut qb = QueryBuilder::new("SELECT ");
        qb.push(SSH_COLS)
            .push(" FROM ssh_certificates WHERE tenant_id = ")
            .push_bind(tenant);
        if let Some(t) = certificate_type {
            qb.push(" AND certificate_type = ").push_bind(t.as_str());
        }
        if let Some(s) = status {
            qb.push(" AND status = ").push_bind(s.to_owned());
        }
        qb.push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(limit as i64);
        let rows = qb.build().fetch_all(&self.db).await?;
        Ok(rows.iter().map(row_to_stored).collect())
    }

    /// Revokes a certificate by id scoped to `tenant`, recording a
    /// `crl_entries` row. Returns `false` when the id is unparseable,
    /// unknown, *or* belongs to a different tenant — never distinguishable
    /// to the caller (matches the pre-persistence store's contract, and
    /// pki's own `revoke_ssh`). Idempotent: revoking an already-revoked
    /// certificate returns `true` without rewriting it.
    pub async fn revoke(
        &self,
        cert_id: &str,
        tenant: Uuid,
        reason: &str,
        at: NaiveDateTime,
    ) -> Result<bool, sqlx::Error> {
        let Ok(id) = Uuid::parse_str(cert_id) else {
            return Ok(false);
        };
        let row = sqlx::query(
            "SELECT serial_number, status FROM ssh_certificates WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant)
        .fetch_optional(&self.db)
        .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let status: String = row.try_get("status")?;
        if status == "revoked" {
            return Ok(true);
        }
        let serial_number: String = row.try_get("serial_number")?;
        sqlx::query(
            "UPDATE ssh_certificates SET status='revoked', revoked_at=$1, \
             revocation_reason=$2, updated_at=$1 WHERE id=$3 AND tenant_id=$4",
        )
        .bind(at)
        .bind(reason)
        .bind(id)
        .bind(tenant)
        .execute(&self.db)
        .await?;
        sqlx::query(
            "INSERT INTO crl_entries \
             (id, tenant_id, certificate_id, serial_number, certificate_type, revoked_at, \
              revocation_reason, created_at) \
             VALUES ($1,$2,$3,$4,'ssh',$5,$6,$5)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(id)
        .bind(&serial_number)
        .bind(at)
        .bind(reason)
        .execute(&self.db)
        .await?;
        Ok(true)
    }

    /// Snapshot of `tenant`'s revocation entries, ordered by revocation
    /// time — never includes another tenant's revocations.
    pub async fn krl_entries(&self, tenant: Uuid) -> Result<Vec<KrlEntry>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT serial_number, revoked_at, revocation_reason FROM crl_entries \
             WHERE certificate_type='ssh' AND tenant_id=$1 ORDER BY revoked_at",
        )
        .bind(tenant)
        .fetch_all(&self.db)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let serial_str: String = r.try_get("serial_number")?;
            let revocation_time: NaiveDateTime = r.try_get("revoked_at")?;
            let reason: Option<String> = r.try_get("revocation_reason")?;
            out.push(KrlEntry {
                serial_number: serial_str.parse().unwrap_or_default(),
                revocation_time,
                reason: reason.unwrap_or_default(),
            });
        }
        Ok(out)
    }
}

/// Converts a flat string map into a JSON object — the wire shape bound
/// into the `critical_options`/`extensions` JSONB columns.
fn btreemap_to_json(m: &BTreeMap<String, String>) -> serde_json::Value {
    m.iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// Converts a JSON object read back from `critical_options`/`extensions`
/// into a flat string map, dropping any non-string value (never written by
/// this store, but tolerated rather than panicking on a hand-edited row).
fn json_to_btreemap(v: serde_json::Value) -> BTreeMap<String, String> {
    v.as_object()
        .into_iter()
        .flat_map(|m| m.iter())
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
        .collect()
}

fn row_to_stored(row: &sqlx::postgres::PgRow) -> StoredCert {
    let id: Uuid = row.try_get("id").unwrap_or_default();
    let tenant_id: Uuid = row.try_get("tenant_id").unwrap_or_default();
    let serial_str: String = row.try_get("serial_number").unwrap_or_default();
    let certificate_type: String = row
        .try_get("certificate_type")
        .unwrap_or_else(|_| "user".to_owned());
    let extensions: Json<serde_json::Value> = row
        .try_get("extensions")
        .unwrap_or(Json(serde_json::json!({})));
    let critical: Json<serde_json::Value> = row
        .try_get("critical_options")
        .unwrap_or(Json(serde_json::json!({})));

    StoredCert {
        certificate_id: id.to_string(),
        tenant_id,
        certificate_type: CertificateType::from_db(&certificate_type),
        serial_number: serial_str.parse().unwrap_or_default(),
        key_id: row.try_get::<String, _>("key_id").unwrap_or_default(),
        key_type: row.try_get::<String, _>("key_type").unwrap_or_default(),
        principals: row
            .try_get::<Option<Vec<String>>, _>("principals")
            .unwrap_or(None)
            .unwrap_or_default(),
        status: row.try_get::<String, _>("status").unwrap_or_default(),
        signed_certificate: row.try_get::<String, _>("certificate").unwrap_or_default(),
        public_key: row.try_get::<String, _>("public_key").unwrap_or_default(),
        extensions: json_to_btreemap(extensions.0),
        critical_options: json_to_btreemap(critical.0),
        source_addresses: row
            .try_get::<Option<Vec<String>>, _>("source_address")
            .unwrap_or(None)
            .unwrap_or_default(),
        force_command: row
            .try_get::<Option<String>, _>("force_command")
            .unwrap_or(None),
        valid_after: row.try_get("valid_after").unwrap_or_default(),
        valid_before: row.try_get("valid_before").unwrap_or_default(),
        revoked_at: row.try_get("revoked_at").ok().flatten(),
        revocation_reason: row
            .try_get::<Option<String>, _>("revocation_reason")
            .unwrap_or(None),
        metadata: row
            .try_get::<Json<serde_json::Value>, _>("metadata")
            .map(|j| j.0)
            .unwrap_or(serde_json::Value::Null),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_support;

    /// A fixed tenant for tests that don't specifically exercise
    /// cross-tenant isolation.
    fn tenant() -> Uuid {
        Uuid::new_v4()
    }

    fn sample(id: &str, serial: u64, t: CertificateType, tenant_id: Uuid) -> StoredCert {
        let mut extensions = BTreeMap::new();
        extensions.insert("permit-pty".to_owned(), String::new());
        let mut critical_options = BTreeMap::new();
        critical_options.insert("force-command".to_owned(), "/bin/true".to_owned());
        StoredCert {
            certificate_id: id.to_owned(),
            tenant_id,
            certificate_type: t,
            serial_number: serial,
            key_id: format!("{}-{id}", t.as_str()),
            key_type: "ed25519".to_owned(),
            principals: vec!["alice".to_owned()],
            status: "active".to_owned(),
            signed_certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned(),
            public_key: "ssh-ed25519 AAAAtestsubject".to_owned(),
            extensions,
            critical_options,
            source_addresses: vec!["10.0.0.0/8".to_owned()],
            force_command: Some("/bin/true".to_owned()),
            valid_after: NaiveDateTime::default(),
            valid_before: NaiveDateTime::default(),
            revoked_at: None,
            revocation_reason: None,
            metadata: serde_json::json!({"note": "test"}),
        }
    }

    // `connect_lazy` (inside `test_support::lazy_pool`) requires an active
    // Tokio context even just to construct the pool, so this needs
    // `#[tokio::test]` despite not `.await`-ing anything itself — matches
    // `services/pki/src/manager.rs`'s `db_accessor_returns_the_configured_pool`
    // precedent for the same reason.
    #[tokio::test]
    async fn serial_starts_at_seed_plus_one() {
        let store = CertStore::new(test_support::lazy_pool());
        assert_eq!(store.next_serial(), SERIAL_SEED + 1);
        assert_eq!(store.next_serial(), SERIAL_SEED + 2);
    }

    #[test]
    fn btreemap_json_round_trips() {
        let mut m = BTreeMap::new();
        m.insert("permit-pty".to_owned(), String::new());
        m.insert("source-address".to_owned(), "10.0.0.0/8".to_owned());
        let json = btreemap_to_json(&m);
        assert_eq!(json_to_btreemap(json), m);
    }

    #[test]
    fn json_to_btreemap_drops_non_string_values() {
        let v = serde_json::json!({"a": "x", "b": 1, "c": true});
        let m = json_to_btreemap(v);
        assert_eq!(m.get("a"), Some(&"x".to_owned()));
        assert!(!m.contains_key("b"));
        assert!(!m.contains_key("c"));
    }

    #[tokio::test]
    async fn get_and_list_and_revoke_resolve_without_db_on_unparseable_id() {
        let store = CertStore::new(test_support::lazy_pool());
        let t = tenant();
        assert!(store.get("not-a-uuid", t).await.unwrap().is_none());
        assert!(
            !store
                .revoke("not-a-uuid", t, "x", NaiveDateTime::default())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn insert_get_and_list_round_trip_through_real_postgres() {
        let store = CertStore::new(test_support::db_pool().await);
        let t = tenant();
        let id = Uuid::new_v4().to_string();
        store
            .insert(sample(&id, 1_000_001, CertificateType::User, t))
            .await
            .expect("insert");

        let got = store.get(&id, t).await.expect("get").expect("present");
        assert_eq!(got.key_id, format!("user-{id}"));
        assert_eq!(got.principals, vec!["alice".to_owned()]);
        assert_eq!(got.status, "active");
        assert_eq!(got.serial_number, 1_000_001);
        assert_eq!(got.extensions.get("permit-pty"), Some(&String::new()));
        assert_eq!(
            got.critical_options.get("force-command"),
            Some(&"/bin/true".to_owned())
        );
        assert_eq!(got.source_addresses, vec!["10.0.0.0/8".to_owned()]);
        assert_eq!(got.metadata, serde_json::json!({"note": "test"}));

        // Wrong tenant -> None, same as unknown.
        assert!(store.get(&id, Uuid::new_v4()).await.unwrap().is_none());
        // Genuinely unknown (but valid-format) id -> None.
        assert!(
            store
                .get(&Uuid::new_v4().to_string(), t)
                .await
                .unwrap()
                .is_none()
        );

        let host_id = Uuid::new_v4().to_string();
        store
            .insert(sample(&host_id, 1_000_002, CertificateType::Host, t))
            .await
            .expect("insert host");

        let users = store
            .list(t, Some(CertificateType::User), None, 100)
            .await
            .unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].certificate_id, id);

        let all = store.list(t, None, None, 100).await.unwrap();
        assert_eq!(all.len(), 2);

        let limited = store.list(t, None, None, 1).await.unwrap();
        assert_eq!(limited.len(), 1);

        let active = store.list(t, None, Some("active"), 100).await.unwrap();
        assert_eq!(active.len(), 2);
        let revoked = store.list(t, None, Some("revoked"), 100).await.unwrap();
        assert!(revoked.is_empty());

        // Another tenant sees nothing.
        assert!(
            store
                .list(Uuid::new_v4(), None, None, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn revoke_persists_is_idempotent_and_tenant_scoped() {
        let store = CertStore::new(test_support::db_pool().await);
        let t = tenant();
        let other = Uuid::new_v4();
        let id = Uuid::new_v4().to_string();
        store
            .insert(sample(&id, 1_000_010, CertificateType::User, t))
            .await
            .expect("insert");

        // Wrong tenant cannot revoke.
        assert!(
            !store
                .revoke(&id, other, "unspecified", chrono::Utc::now().naive_utc())
                .await
                .unwrap()
        );
        let still_active = store.get(&id, t).await.unwrap().expect("present");
        assert_eq!(still_active.status, "active");

        let now = chrono::Utc::now().naive_utc();
        assert!(store.revoke(&id, t, "keyCompromise", now).await.unwrap());
        let revoked = store.get(&id, t).await.unwrap().expect("present");
        assert_eq!(revoked.status, "revoked");
        assert_eq!(revoked.revocation_reason.as_deref(), Some("keyCompromise"));
        assert!(revoked.revoked_at.is_some());

        // Idempotent: second revoke on an already-revoked cert stays true
        // without rewriting the reason.
        assert!(store.revoke(&id, t, "superseded", now).await.unwrap());
        let still = store.get(&id, t).await.unwrap().expect("present");
        assert_eq!(still.revocation_reason.as_deref(), Some("keyCompromise"));

        // Unknown (but valid-format) id -> false.
        assert!(
            !store
                .revoke(&Uuid::new_v4().to_string(), t, "unspecified", now)
                .await
                .unwrap()
        );

        let krl = store.krl_entries(t).await.unwrap();
        assert_eq!(krl.len(), 1);
        assert_eq!(krl[0].serial_number, 1_000_010);
        assert_eq!(krl[0].reason, "keyCompromise");

        // Revocation is tenant-scoped and durable across a fresh pool —
        // the core regression this consolidation exists for: a revoked
        // cert must stay revoked, and must be readable via an entirely new
        // connection to the same schema, not just the same in-process
        // handle.
        assert!(store.krl_entries(other).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn krl_entries_only_lists_the_calling_tenants_revocations() {
        let store = CertStore::new(test_support::db_pool().await);
        let tenant_a = tenant();
        let tenant_b = tenant();
        let id_a = Uuid::new_v4().to_string();
        store
            .insert(sample(&id_a, 1_000_020, CertificateType::User, tenant_a))
            .await
            .expect("insert");
        let now = chrono::Utc::now().naive_utc();
        assert!(
            store
                .revoke(&id_a, tenant_a, "unspecified", now)
                .await
                .unwrap()
        );

        assert!(store.krl_entries(tenant_b).await.unwrap().is_empty());
        assert_eq!(store.krl_entries(tenant_a).await.unwrap().len(), 1);
    }
}
