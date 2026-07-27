//! In-memory certificate + revocation store.
//!
//! v1's `AsyncSSHProcessor` kept issued certs in a `self.certificates` dict,
//! revocations in `self.revoked_certificates`, and a `serial_counter` starting
//! at 1_000_000 (first issued serial 1_000_001). It never persisted to a
//! database (`_load_existing_data` was a stub and there is no ssh-cert table in
//! the live schema), so this port preserves the in-memory model exactly. If
//! durable storage is ever required it needs a new migration in a later phase.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::NaiveDateTime;

use crate::model::CertificateType;

/// v1 serial counter seed — first issued serial is `SERIAL_SEED + 1`.
pub const SERIAL_SEED: u64 = 1_000_000;

/// A single issued certificate record (public material only).
#[derive(Debug, Clone)]
pub struct StoredCert {
    /// Certificate id (equals the issuing request id).
    pub certificate_id: String,
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

    /// Fetches a certificate by id.
    pub fn get(&self, cert_id: &str) -> Option<StoredCert> {
        lock(&self.certs).get(cert_id).cloned()
    }

    /// Lists certificates filtered by type/status, capped at `limit`, oldest
    /// insertion order not guaranteed (parity with v1's dict iteration).
    pub fn list(
        &self,
        certificate_type: Option<CertificateType>,
        status: Option<&str>,
        limit: usize,
    ) -> Vec<StoredCert> {
        let certs = lock(&self.certs);
        let mut out = Vec::new();
        for cert in certs.values() {
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

    /// Revokes a certificate by id, recording a KRL entry. Returns `false` when
    /// the certificate id is unknown (v1 raised; the handler maps to 404).
    pub fn revoke(&self, cert_id: &str, reason: &str, at: NaiveDateTime) -> bool {
        let mut certs = lock(&self.certs);
        let Some(cert) = certs.get_mut(cert_id) else {
            return false;
        };
        cert.status = "revoked".to_owned();
        cert.revoked_at = Some(at);
        cert.revocation_reason = Some(reason.to_owned());
        let entry = KrlEntry {
            serial_number: cert.serial_number,
            revocation_time: at,
            reason: reason.to_owned(),
            certificate_fingerprint: Some(cert.public_key_fingerprint.clone()),
        };
        lock(&self.revoked).insert(cert.serial_number, entry);
        true
    }

    /// Snapshot of all revocation entries, ordered by serial.
    pub fn krl_entries(&self) -> Vec<KrlEntry> {
        lock(&self.revoked).values().cloned().collect()
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

    fn sample(id: &str, serial: u64, t: CertificateType) -> StoredCert {
        StoredCert {
            certificate_id: id.to_owned(),
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
    fn serial_starts_at_seed_plus_one() {
        let store = CertStore::new();
        assert_eq!(store.next_serial(), SERIAL_SEED + 1);
        assert_eq!(store.next_serial(), SERIAL_SEED + 2);
    }

    #[test]
    fn insert_get_and_list_filters() {
        let store = CertStore::new();
        store.insert(sample("u1", 1_000_001, CertificateType::User));
        store.insert(sample("h1", 1_000_002, CertificateType::Host));

        assert!(store.get("u1").is_some());
        assert!(store.get("missing").is_none());

        let users = store.list(Some(CertificateType::User), None, 100);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].certificate_id, "u1");

        let all = store.list(None, None, 100);
        assert_eq!(all.len(), 2);

        let active = store.list(None, Some("active"), 100);
        assert_eq!(active.len(), 2);
        let revoked = store.list(None, Some("revoked"), 100);
        assert_eq!(revoked.len(), 0);
    }

    #[test]
    fn revoke_updates_status_and_krl() {
        let store = CertStore::new();
        store.insert(sample("u1", 1_000_001, CertificateType::User));
        let now = NaiveDateTime::default();

        assert!(store.revoke("u1", "keyCompromise", now));
        assert!(!store.revoke("missing", "x", now));

        let cert = store.get("u1").expect("cert present");
        assert_eq!(cert.status, "revoked");
        assert_eq!(cert.revocation_reason.as_deref(), Some("keyCompromise"));

        let krl = store.krl_entries();
        assert_eq!(krl.len(), 1);
        assert_eq!(krl[0].serial_number, 1_000_001);
        assert_eq!(krl[0].reason, "keyCompromise");
    }
}
