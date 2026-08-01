//! In-memory certificate + revocation store.
//!
//! v1's `AsyncSSHProcessor` kept issued certs in a `self.certificates` dict,
//! revocations in `self.revoked_certificates`, and a `serial_counter` starting
//! at 1_000_000 (first issued serial 1_000_001). It never persisted to a
//! database (`_load_existing_data` was a stub and there is no ssh-cert table in
//! the live schema), so this port preserves the in-memory model exactly. If
//! durable storage is ever required it needs a new migration in a later phase.
//!
//! TENANT ISOLATION (`docs/v2-port/tenancy-model.md` §3): every record
//! carries the `tenant_id` of the caller that issued it
//! (`crate::tenant::TenantId`, sourced from the `X-Tenant-ID` header). Every
//! lookup/list/revoke operation takes a `tenant` filter — this store has no
//! SQL `WHERE tenant_id = $N` equivalent to lean on, so the filtering has to
//! happen explicitly in each method below instead.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::NaiveDateTime;
use uuid::Uuid;

use crate::model::CertificateType;

/// v1 serial counter seed — first issued serial is `SERIAL_SEED + 1`.
pub const SERIAL_SEED: u64 = 1_000_000;

/// A single issued certificate record (public material only).
#[derive(Debug, Clone)]
pub struct StoredCert {
    /// Certificate id (equals the issuing request id).
    pub certificate_id: String,
    /// The tenant that issued this certificate — sourced from the request's
    /// `X-Tenant-ID` header at issuance time, never from client input.
    pub tenant_id: Uuid,
    /// User or host.
    pub certificate_type: CertificateType,
    /// Serial number.
    pub serial_number: u64,
    /// Certificate key id.
    pub key_id: String,
    /// Effective principals.
    pub principals: Vec<String>,
    /// `active` / `revoked` / `expired`.
    pub status: String,
    /// The signed OpenSSH certificate line.
    pub signed_certificate: String,
    /// Subject key SHA256 fingerprint.
    pub public_key_fingerprint: String,
    /// CA key SHA256 fingerprint.
    pub ca_fingerprint: String,
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

/// One Key Revocation List entry (v1 `KRLEntry`).
#[derive(Debug, Clone)]
pub struct KrlEntry {
    /// The tenant that owned the revoked certificate — [`CertStore::krl_entries`]
    /// filters on this so one tenant's KRL never lists another's revocations.
    pub tenant_id: Uuid,
    /// Revoked serial number.
    pub serial_number: u64,
    /// Revocation instant (UTC).
    pub revocation_time: NaiveDateTime,
    /// Revocation reason.
    pub reason: String,
    /// Revoked certificate's subject fingerprint.
    pub certificate_fingerprint: Option<String>,
}

/// Thread-safe issued-certificate + revocation store with a monotonic serial.
#[derive(Debug)]
pub struct CertStore {
    serial: AtomicU64,
    certs: Mutex<HashMap<String, StoredCert>>,
    serial_index: Mutex<HashMap<u64, String>>,
    revoked: Mutex<BTreeMap<u64, KrlEntry>>,
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CertStore {
    /// Creates an empty store with the v1 serial seed.
    pub fn new() -> Self {
        Self {
            serial: AtomicU64::new(SERIAL_SEED),
            certs: Mutex::new(HashMap::new()),
            serial_index: Mutex::new(HashMap::new()),
            revoked: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns the next serial (`SERIAL_SEED + 1`, then increasing).
    pub fn next_serial(&self) -> u64 {
        self.serial.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Inserts an issued certificate record.
    pub fn insert(&self, cert: StoredCert) {
        let id = cert.certificate_id.clone();
        let serial = cert.serial_number;
        lock(&self.serial_index).insert(serial, id.clone());
        lock(&self.certs).insert(id, cert);
    }

    /// Fetches a certificate by id, scoped to `tenant` — a certificate that
    /// exists but belongs to a different tenant resolves to `None`, the same
    /// as a genuinely unknown id (never distinguishable to the caller).
    pub fn get(&self, cert_id: &str, tenant: Uuid) -> Option<StoredCert> {
        lock(&self.certs)
            .get(cert_id)
            .filter(|c| c.tenant_id == tenant)
            .cloned()
    }

    /// Lists `tenant`'s certificates filtered by type/status, capped at
    /// `limit`, oldest insertion order not guaranteed (parity with v1's
    /// dict iteration).
    pub fn list(
        &self,
        tenant: Uuid,
        certificate_type: Option<CertificateType>,
        status: Option<&str>,
        limit: usize,
    ) -> Vec<StoredCert> {
        let certs = lock(&self.certs);
        let mut out = Vec::new();
        for cert in certs.values() {
            if cert.tenant_id != tenant {
                continue;
            }
            if let Some(t) = certificate_type
                && cert.certificate_type != t
            {
                continue;
            }
            if let Some(s) = status
                && cert.status != s
            {
                continue;
            }
            out.push(cert.clone());
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    /// Revokes a certificate by id scoped to `tenant`, recording a KRL
    /// entry. Returns `false` when the certificate id is unknown *or*
    /// belongs to a different tenant (v1 raised on unknown; the handler
    /// maps both cases to 404 — never distinguishable to the caller).
    pub fn revoke(&self, cert_id: &str, tenant: Uuid, reason: &str, at: NaiveDateTime) -> bool {
        let mut certs = lock(&self.certs);
        let Some(cert) = certs.get_mut(cert_id).filter(|c| c.tenant_id == tenant) else {
            return false;
        };
        cert.status = "revoked".to_owned();
        cert.revoked_at = Some(at);
        cert.revocation_reason = Some(reason.to_owned());
        let entry = KrlEntry {
            tenant_id: tenant,
            serial_number: cert.serial_number,
            revocation_time: at,
            reason: reason.to_owned(),
            certificate_fingerprint: Some(cert.public_key_fingerprint.clone()),
        };
        lock(&self.revoked).insert(cert.serial_number, entry);
        true
    }

    /// Snapshot of `tenant`'s revocation entries, ordered by serial — never
    /// includes another tenant's revocations.
    pub fn krl_entries(&self, tenant: Uuid) -> Vec<KrlEntry> {
        lock(&self.revoked)
            .values()
            .filter(|e| e.tenant_id == tenant)
            .cloned()
            .collect()
    }
}

/// Locks a mutex, recovering the guard on poison rather than panicking (the
/// workspace lints forbid `unwrap`/`expect`/`panic`).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A fixed tenant for tests that don't specifically exercise
    /// cross-tenant isolation.
    fn tenant() -> Uuid {
        Uuid::new_v4()
    }

    fn sample(id: &str, serial: u64, t: CertificateType, tenant_id: Uuid) -> StoredCert {
        StoredCert {
            certificate_id: id.to_owned(),
            tenant_id,
            certificate_type: t,
            serial_number: serial,
            key_id: format!("{}-{id}", t.as_str()),
            principals: vec!["alice".to_owned()],
            status: "active".to_owned(),
            signed_certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned(),
            public_key_fingerprint: "SHA256:aaa".to_owned(),
            ca_fingerprint: "SHA256:bbb".to_owned(),
            valid_after: NaiveDateTime::default(),
            valid_before: NaiveDateTime::default(),
            revoked_at: None,
            revocation_reason: None,
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn default_impl_matches_new() {
        let store = CertStore::default();
        assert_eq!(store.next_serial(), SERIAL_SEED + 1);
        assert!(store.list(tenant(), None, None, 100).is_empty());
    }

    #[test]
    fn list_stops_once_limit_is_reached() {
        let store = CertStore::new();
        let t = tenant();
        for (i, serial) in (1_000_001..1_000_004).enumerate() {
            store.insert(sample(&format!("c{i}"), serial, CertificateType::User, t));
        }
        let limited = store.list(t, None, None, 1);
        assert_eq!(limited.len(), 1);
    }

    #[test]
    fn serial_starts_at_seed_plus_one() {
        let store = CertStore::new();
        assert_eq!(store.next_serial(), SERIAL_SEED + 1);
        assert_eq!(store.next_serial(), SERIAL_SEED + 2);
    }

    #[test]
    fn insert_get_and_list_filters() {
        let store = CertStore::new();
        let t = tenant();
        store.insert(sample("u1", 1_000_001, CertificateType::User, t));
        store.insert(sample("h1", 1_000_002, CertificateType::Host, t));

        assert!(store.get("u1", t).is_some());
        assert!(store.get("missing", t).is_none());

        let users = store.list(t, Some(CertificateType::User), None, 100);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].certificate_id, "u1");

        let all = store.list(t, None, None, 100);
        assert_eq!(all.len(), 2);

        let active = store.list(t, None, Some("active"), 100);
        assert_eq!(active.len(), 2);
        let revoked = store.list(t, None, Some("revoked"), 100);
        assert_eq!(revoked.len(), 0);
    }

    #[test]
    fn revoke_updates_status_and_krl() {
        let store = CertStore::new();
        let t = tenant();
        store.insert(sample("u1", 1_000_001, CertificateType::User, t));
        let now = NaiveDateTime::default();

        assert!(store.revoke("u1", t, "keyCompromise", now));
        assert!(!store.revoke("missing", t, "x", now));

        let cert = store.get("u1", t).expect("cert present");
        assert_eq!(cert.status, "revoked");
        assert_eq!(cert.revocation_reason.as_deref(), Some("keyCompromise"));

        let krl = store.krl_entries(t);
        assert_eq!(krl.len(), 1);
        assert_eq!(krl[0].serial_number, 1_000_001);
        assert_eq!(krl[0].reason, "keyCompromise");
    }

    // ===================== Cross-tenant isolation =====================

    #[test]
    fn get_cannot_see_another_tenants_certificate() {
        let store = CertStore::new();
        let tenant_a = tenant();
        let tenant_b = tenant();
        store.insert(sample("u1", 1_000_001, CertificateType::User, tenant_a));

        assert!(store.get("u1", tenant_b).is_none());
        assert!(store.get("u1", tenant_a).is_some());
    }

    #[test]
    fn list_only_returns_the_calling_tenants_rows() {
        let store = CertStore::new();
        let tenant_a = tenant();
        let tenant_b = tenant();
        store.insert(sample("a1", 1_000_001, CertificateType::User, tenant_a));
        store.insert(sample("b1", 1_000_002, CertificateType::User, tenant_b));

        let list_a = store.list(tenant_a, None, None, 100);
        assert_eq!(list_a.len(), 1);
        assert_eq!(list_a[0].certificate_id, "a1");

        let list_b = store.list(tenant_b, None, None, 100);
        assert_eq!(list_b.len(), 1);
        assert_eq!(list_b[0].certificate_id, "b1");
    }

    #[test]
    fn revoke_cannot_revoke_another_tenants_certificate() {
        let store = CertStore::new();
        let tenant_a = tenant();
        let tenant_b = tenant();
        store.insert(sample("u1", 1_000_001, CertificateType::User, tenant_a));
        let now = NaiveDateTime::default();

        assert!(!store.revoke("u1", tenant_b, "unspecified", now));
        let still_active = store.get("u1", tenant_a).expect("cert present");
        assert_eq!(still_active.status, "active");
    }

    #[test]
    fn krl_entries_only_lists_the_calling_tenants_revocations() {
        let store = CertStore::new();
        let tenant_a = tenant();
        let tenant_b = tenant();
        store.insert(sample("u1", 1_000_001, CertificateType::User, tenant_a));
        let now = NaiveDateTime::default();
        assert!(store.revoke("u1", tenant_a, "unspecified", now));

        assert!(store.krl_entries(tenant_b).is_empty());
        assert_eq!(store.krl_entries(tenant_a).len(), 1);
    }
}
