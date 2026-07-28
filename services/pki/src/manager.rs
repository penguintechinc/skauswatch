//! Certificate lifecycle + persistence — port of v1
//! `services/certificate_manager.py`. Wraps the X.509 and SSH CA engines and
//! the Postgres tables (`x509_certificates`, `ssh_certificates`, `crl_entries`,
//! `pki_audit_log`). Shared by the REST and gRPC surfaces, as in v1.
//!
//! sqlx runtime queries only (no compile-time macros; schema is authoritative
//! per the port contract). Dynamic list filters use `QueryBuilder`. Wire
//! timestamps render via `skauswatch_streams::py_isoformat`.

use std::sync::Arc;

use chrono::{NaiveDateTime, Utc};
use skauswatch_streams::{py_isoformat, py_isoformat_opt};
use sqlx::types::Json;
use sqlx::{PgPool, QueryBuilder, Row};
use uuid::Uuid;

use crate::ca::ssh::{IssuedSsh, KrlEntry, SshCa, SshIssueParams};
use crate::ca::x509::{CrlEntry, IssuedX509, X509Ca, X509IssueParams};

const X509_COLS: &str = "id, serial_number, subject, issuer, not_before, not_after, \
    key_algorithm, key_size, fingerprint_sha256, certificate_pem, private_key_pem, \
    san_dns, san_ip, san_email, status, revoked_at, revocation_reason, created_at";

const SSH_COLS: &str = "id, serial_number, key_id, certificate_type, principals, \
    valid_after, valid_before, key_type, public_key, certificate, hostname, status, \
    revoked_at, revocation_reason, extensions, critical_options, created_at";

/// Orchestrates issuance, persistence, revocation and reporting for both CAs.
pub struct CertManager {
    /// X.509 CA engine.
    pub x509: Arc<X509Ca>,
    /// SSH CA engine.
    pub ssh: Arc<SshCa>,
    db: PgPool,
}

impl CertManager {
    /// Builds a manager over the two CA engines and a Postgres pool.
    pub fn new(x509: Arc<X509Ca>, ssh: Arc<SshCa>, db: PgPool) -> Self {
        Self { x509, ssh, db }
    }

    /// Reference to the pool (health probe).
    pub fn db(&self) -> &PgPool {
        &self.db
    }

    // ===================== X.509 =====================

    /// Issues an X.509 certificate, persists it, logs an audit event, and
    /// returns the v1 response dict.
    pub async fn issue_x509(
        &self,
        params: X509IssueParams,
        requester_id: Option<&str>,
    ) -> Result<serde_json::Value, ManagerError> {
        // RSA key generation + signing block; run off the async runtime.
        let x509 = self.x509.clone();
        let engine_params = params.clone();
        let issued: IssuedX509 = tokio::task::spawn_blocking(move || x509.issue(&engine_params))
            .await
            .map_err(join_err)??;
        let cert_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        let key_size_db: Option<i32> = issued.key_size.map(|k| k as i32);

        sqlx::query(
            "INSERT INTO x509_certificates \
             (id, serial_number, subject, issuer, not_before, not_after, key_algorithm, \
              key_size, signature_algorithm, fingerprint_sha256, certificate_pem, \
              private_key_pem, csr_pem, san_dns, san_ip, san_email, key_usage, \
              extended_key_usage, is_ca, path_length, status, requester_id, \
              approval_request_id, metadata, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,\
              $21,$22,$23,$24,$25,$26)",
        )
        .bind(cert_id)
        .bind(&issued.serial_hex)
        .bind(&issued.subject)
        .bind(&issued.issuer)
        .bind(issued.not_before)
        .bind(issued.not_after)
        .bind(&issued.key_algorithm)
        .bind(key_size_db)
        .bind("SHA256")
        .bind(&issued.fingerprint_sha256)
        .bind(&issued.certificate_pem)
        .bind(issued.private_key_pem.as_deref())
        .bind(params.csr_pem.as_deref())
        .bind(&params.san_dns)
        .bind(&params.san_ip)
        .bind(&params.san_email)
        .bind(&params.key_usage)
        .bind(&params.extended_key_usage)
        .bind(params.is_ca)
        .bind(params.path_length.map(|p| p as i32))
        .bind("active")
        .bind(parse_uuid(requester_id))
        .bind::<Option<Uuid>>(None)
        .bind(Json(serde_json::json!({})))
        .bind(now)
        .bind(now)
        .execute(&self.db)
        .await?;

        self.audit(
            "certificate_issued",
            "x509",
            Some(cert_id),
            Some(&issued.serial_hex),
            Some(&issued.subject),
            "issue",
            "success",
            None,
        )
        .await;

        Ok(serde_json::json!({
            "id": cert_id.to_string(),
            "serial_number": issued.serial_hex,
            "subject": issued.subject,
            "issuer": issued.issuer,
            "not_before": py_isoformat(issued.not_before),
            "not_after": py_isoformat(issued.not_after),
            "key_algorithm": issued.key_algorithm,
            "key_size": issued.key_size,
            "fingerprint_sha256": issued.fingerprint_sha256,
            "certificate_pem": issued.certificate_pem,
            "private_key_pem": issued.private_key_pem,
            "san_dns": params.san_dns,
            "san_ip": params.san_ip,
            "status": "active",
            "created_at": py_isoformat(now),
        }))
    }

    /// Fetches one X.509 certificate as the v1 dict, or `None`.
    pub async fn get_x509(
        &self,
        cert_id: Option<&str>,
        serial: Option<&str>,
        include_pem: bool,
    ) -> Result<Option<serde_json::Value>, ManagerError> {
        let mut qb = QueryBuilder::new("SELECT ");
        qb.push(X509_COLS).push(" FROM x509_certificates WHERE ");
        match (cert_id.and_then(parse_uuid_owned), serial) {
            (Some(id), _) => {
                qb.push("id = ").push_bind(id);
            }
            (None, Some(sn)) => {
                qb.push("serial_number = ").push_bind(sn.to_owned());
            }
            (None, None) => return Ok(None),
        }
        let row = qb.build().fetch_optional(&self.db).await?;
        Ok(row.map(|r| x509_row_to_dict(&r, include_pem)))
    }

    /// Revokes an X.509 certificate (idempotent), recording a CRL entry and an
    /// audit event. Returns whether the certificate existed.
    pub async fn revoke_x509(
        &self,
        cert_id: Option<&str>,
        serial: Option<&str>,
        reason: &str,
        actor_id: Option<&str>,
    ) -> Result<bool, ManagerError> {
        let mut qb = QueryBuilder::new(
            "SELECT id, serial_number, subject, status FROM x509_certificates WHERE ",
        );
        match (cert_id.and_then(parse_uuid_owned), serial) {
            (Some(id), _) => {
                qb.push("id = ").push_bind(id);
            }
            (None, Some(sn)) => {
                qb.push("serial_number = ").push_bind(sn.to_owned());
            }
            (None, None) => return Ok(false),
        }
        let Some(row) = qb.build().fetch_optional(&self.db).await? else {
            return Ok(false);
        };
        let id: Uuid = row.try_get("id")?;
        let serial_number: String = row.try_get("serial_number")?;
        let subject: String = row.try_get("subject")?;
        let status: String = row.try_get("status")?;
        if status == "revoked" {
            return Ok(true);
        }
        let now = Utc::now().naive_utc();
        sqlx::query(
            "UPDATE x509_certificates SET status='revoked', revoked_at=$1, \
             revocation_reason=$2, updated_at=$1 WHERE id=$3",
        )
        .bind(now)
        .bind(reason)
        .bind(id)
        .execute(&self.db)
        .await?;
        sqlx::query(
            "INSERT INTO crl_entries \
             (id, certificate_id, serial_number, certificate_type, revoked_at, revocation_reason, created_at) \
             VALUES ($1,$2,$3,'x509',$4,$5,$4)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(&serial_number)
        .bind(now)
        .bind(reason)
        .execute(&self.db)
        .await?;
        self.audit(
            "certificate_revoked",
            "x509",
            Some(id),
            Some(&serial_number),
            Some(&subject),
            "revoke",
            "success",
            actor_id,
        )
        .await;
        Ok(true)
    }

    /// Lists X.509 certificates with optional filters + pagination, returning
    /// `(items, total)`.
    pub async fn list_x509(
        &self,
        status: Option<&str>,
        subject: Option<&str>,
        expires_before: Option<NaiveDateTime>,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<serde_json::Value>, i64), ManagerError> {
        let mut count = QueryBuilder::new("SELECT COUNT(*) FROM x509_certificates");
        push_x509_filters(&mut count, status, subject, expires_before);
        let total: i64 = count.build().fetch_one(&self.db).await?.try_get(0)?;

        let mut qb = QueryBuilder::new("SELECT ");
        qb.push(X509_COLS).push(" FROM x509_certificates");
        push_x509_filters(&mut qb, status, subject, expires_before);
        qb.push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(page_size)
            .push(" OFFSET ")
            .push_bind((page - 1).max(0) * page_size);
        let rows = qb.build().fetch_all(&self.db).await?;
        let items = rows.iter().map(|r| x509_row_to_dict(r, false)).collect();
        Ok((items, total))
    }

    /// Generates an X.509 CRL from stored revocations (v1 `generate_x509_crl`).
    pub async fn generate_x509_crl(&self) -> Result<serde_json::Value, ManagerError> {
        let rows = sqlx::query(
            "SELECT serial_number, revoked_at, revocation_reason FROM crl_entries \
             WHERE certificate_type='x509'",
        )
        .fetch_all(&self.db)
        .await?;
        let mut entries = Vec::with_capacity(rows.len());
        let mut revoked_json = Vec::with_capacity(rows.len());
        for r in &rows {
            let serial: String = r.try_get("serial_number")?;
            let revoked_at: NaiveDateTime = r.try_get("revoked_at")?;
            let reason: Option<String> = r.try_get("revocation_reason")?;
            revoked_json.push(serde_json::json!({
                "serial_number": serial,
                "revoked_at": py_isoformat(revoked_at),
                "reason": reason,
            }));
            entries.push(CrlEntry {
                serial_hex: serial,
                revoked_at,
                reason,
            });
        }
        let x509 = self.x509.clone();
        let (crl_pem, crl_number) =
            tokio::task::spawn_blocking(move || x509.generate_crl(&entries))
                .await
                .map_err(join_err)??;
        let now = Utc::now().naive_utc();
        let next = now + chrono::Duration::days(7);
        Ok(serde_json::json!({
            "crl_number": crl_number,
            "this_update": py_isoformat(now),
            "next_update": py_isoformat(next),
            "revoked_certificates": revoked_json,
            "crl_pem": crl_pem,
        }))
    }

    // ===================== SSH =====================

    /// Issues an SSH certificate, persists it, and returns the v1 dict.
    pub async fn issue_ssh(
        &self,
        params: SshIssueParams,
        requester_id: Option<&str>,
    ) -> Result<serde_json::Value, ManagerError> {
        // ssh-keygen subprocess blocks; run off the async runtime.
        let ssh = self.ssh.clone();
        let engine_params = params.clone();
        let issued: IssuedSsh = tokio::task::spawn_blocking(move || ssh.issue(&engine_params))
            .await
            .map_err(join_err)??;
        let cert_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        let ext_json: serde_json::Value = issued
            .extensions
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect::<serde_json::Map<_, _>>()
            .into();
        let crit_json: serde_json::Value = params
            .critical_options
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect::<serde_json::Map<_, _>>()
            .into();

        sqlx::query(
            "INSERT INTO ssh_certificates \
             (id, serial_number, key_id, certificate_type, principals, valid_after, \
              valid_before, key_type, public_key, certificate, critical_options, extensions, \
              source_address, force_command, status, hostname, requester_id, \
              approval_request_id, metadata, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)",
        )
        .bind(cert_id)
        .bind(&issued.serial)
        .bind(&issued.key_id)
        .bind(&issued.certificate_type)
        .bind(&issued.principals)
        .bind(issued.valid_after)
        .bind(issued.valid_before)
        .bind(&issued.key_type)
        .bind(&params.public_key)
        .bind(&issued.certificate)
        .bind(Json(crit_json.clone()))
        .bind(Json(ext_json.clone()))
        .bind(&params.source_addresses)
        .bind(params.force_command.as_deref())
        .bind("active")
        .bind(params.hostname.as_deref())
        .bind(parse_uuid(requester_id))
        .bind::<Option<Uuid>>(None)
        .bind(Json(serde_json::json!({})))
        .bind(now)
        .bind(now)
        .execute(&self.db)
        .await?;

        self.audit(
            "certificate_issued",
            "ssh",
            Some(cert_id),
            Some(&issued.serial),
            Some(&issued.key_id),
            "issue",
            "success",
            None,
        )
        .await;

        Ok(serde_json::json!({
            "id": cert_id.to_string(),
            "serial_number": issued.serial,
            "key_id": issued.key_id,
            "certificate_type": issued.certificate_type,
            "principals": issued.principals,
            "valid_after": py_isoformat(issued.valid_after),
            "valid_before": py_isoformat(issued.valid_before),
            "key_type": issued.key_type,
            "certificate": issued.certificate,
            "ca_public_key": self.ssh.ca_public_key(),
            "extensions": ext_json,
            "critical_options": crit_json,
            "status": "active",
            "created_at": py_isoformat(now),
        }))
    }

    /// Fetches one SSH certificate as the v1 dict, or `None`.
    pub async fn get_ssh(
        &self,
        cert_id: Option<&str>,
        serial: Option<&str>,
        include_cert: bool,
    ) -> Result<Option<serde_json::Value>, ManagerError> {
        let mut qb = QueryBuilder::new("SELECT ");
        qb.push(SSH_COLS).push(" FROM ssh_certificates WHERE ");
        match (cert_id.and_then(parse_uuid_owned), serial) {
            (Some(id), _) => {
                qb.push("id = ").push_bind(id);
            }
            (None, Some(sn)) => {
                qb.push("serial_number = ").push_bind(sn.to_owned());
            }
            (None, None) => return Ok(None),
        }
        let row = qb.build().fetch_optional(&self.db).await?;
        Ok(row.map(|r| ssh_row_to_dict(&r, include_cert)))
    }

    /// Revokes an SSH certificate (idempotent). Returns whether it existed.
    pub async fn revoke_ssh(
        &self,
        cert_id: Option<&str>,
        serial: Option<&str>,
        reason: &str,
        actor_id: Option<&str>,
    ) -> Result<bool, ManagerError> {
        let mut qb = QueryBuilder::new(
            "SELECT id, serial_number, key_id, status FROM ssh_certificates WHERE ",
        );
        match (cert_id.and_then(parse_uuid_owned), serial) {
            (Some(id), _) => {
                qb.push("id = ").push_bind(id);
            }
            (None, Some(sn)) => {
                qb.push("serial_number = ").push_bind(sn.to_owned());
            }
            (None, None) => return Ok(false),
        }
        let Some(row) = qb.build().fetch_optional(&self.db).await? else {
            return Ok(false);
        };
        let id: Uuid = row.try_get("id")?;
        let serial_number: String = row.try_get("serial_number")?;
        let key_id: String = row.try_get("key_id")?;
        let status: String = row.try_get("status")?;
        if status == "revoked" {
            return Ok(true);
        }
        let now = Utc::now().naive_utc();
        sqlx::query(
            "UPDATE ssh_certificates SET status='revoked', revoked_at=$1, \
             revocation_reason=$2, updated_at=$1 WHERE id=$3",
        )
        .bind(now)
        .bind(reason)
        .bind(id)
        .execute(&self.db)
        .await?;
        sqlx::query(
            "INSERT INTO crl_entries \
             (id, certificate_id, serial_number, certificate_type, revoked_at, revocation_reason, created_at) \
             VALUES ($1,$2,$3,'ssh',$4,$5,$4)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(&serial_number)
        .bind(now)
        .bind(reason)
        .execute(&self.db)
        .await?;
        self.audit(
            "certificate_revoked",
            "ssh",
            Some(id),
            Some(&serial_number),
            Some(&key_id),
            "revoke",
            "success",
            actor_id,
        )
        .await;
        Ok(true)
    }

    /// Lists SSH certificates with optional filters + pagination.
    pub async fn list_ssh(
        &self,
        status: Option<&str>,
        certificate_type: Option<&str>,
        principal: Option<&str>,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<serde_json::Value>, i64), ManagerError> {
        let mut count = QueryBuilder::new("SELECT COUNT(*) FROM ssh_certificates");
        push_ssh_filters(&mut count, status, certificate_type, principal);
        let total: i64 = count.build().fetch_one(&self.db).await?.try_get(0)?;

        let mut qb = QueryBuilder::new("SELECT ");
        qb.push(SSH_COLS).push(" FROM ssh_certificates");
        push_ssh_filters(&mut qb, status, certificate_type, principal);
        qb.push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(page_size)
            .push(" OFFSET ")
            .push_bind((page - 1).max(0) * page_size);
        let rows = qb.build().fetch_all(&self.db).await?;
        let items = rows.iter().map(|r| ssh_row_to_dict(r, false)).collect();
        Ok((items, total))
    }

    /// Generates an SSH KRL from stored revocations (v1 `generate_ssh_krl`).
    pub async fn generate_ssh_krl(&self) -> Result<serde_json::Value, ManagerError> {
        use base64::Engine as _;
        let rows =
            sqlx::query("SELECT serial_number FROM crl_entries WHERE certificate_type='ssh'")
                .fetch_all(&self.db)
                .await?;
        let mut entries = Vec::with_capacity(rows.len());
        let mut revoked_json = Vec::with_capacity(rows.len());
        for r in &rows {
            let serial: String = r.try_get("serial_number")?;
            revoked_json.push(serde_json::json!({ "serial_number": serial }));
            entries.push(KrlEntry::Serial(serial));
        }
        let ssh = self.ssh.clone();
        let (krl_binary, version) = tokio::task::spawn_blocking(move || ssh.generate_krl(&entries))
            .await
            .map_err(join_err)??;
        Ok(serde_json::json!({
            "version": version,
            "generated_at": py_isoformat(Utc::now().naive_utc()),
            "revoked_keys": revoked_json,
            "krl_binary": base64::engine::general_purpose::STANDARD.encode(&krl_binary),
        }))
    }

    /// PKI statistics across both CAs (v1 `get_statistics`).
    pub async fn statistics(&self) -> Result<serde_json::Value, ManagerError> {
        let now = Utc::now().naive_utc();
        let soon = now + chrono::Duration::days(30);
        let x_total = self.count("x509_certificates", "").await?;
        let x_active = self
            .count("x509_certificates", "WHERE status='active'")
            .await?;
        let x_revoked = self
            .count("x509_certificates", "WHERE status='revoked'")
            .await?;
        let x_expired: i64 =
            sqlx::query("SELECT COUNT(*) FROM x509_certificates WHERE not_after < $1")
                .bind(now)
                .fetch_one(&self.db)
                .await?
                .try_get(0)?;
        let x_expiring: i64 = sqlx::query(
            "SELECT COUNT(*) FROM x509_certificates WHERE status='active' AND not_after < $1 AND not_after > $2",
        )
        .bind(soon)
        .bind(now)
        .fetch_one(&self.db)
        .await?
        .try_get(0)?;
        let s_total = self.count("ssh_certificates", "").await?;
        let s_active = self
            .count("ssh_certificates", "WHERE status='active'")
            .await?;
        let s_revoked = self
            .count("ssh_certificates", "WHERE status='revoked'")
            .await?;
        Ok(serde_json::json!({
            "x509": { "total": x_total, "active": x_active, "revoked": x_revoked,
                      "expired": x_expired, "expiring_soon": x_expiring },
            "ssh": { "total": s_total, "active": s_active, "revoked": s_revoked },
            "timestamp": py_isoformat(now),
        }))
    }

    async fn count(&self, table: &str, clause: &str) -> Result<i64, ManagerError> {
        // table/clause are internal string constants only (never user input).
        let mut qb = QueryBuilder::new("SELECT COUNT(*) FROM ");
        qb.push(table);
        if !clause.is_empty() {
            qb.push(" ").push(clause);
        }
        Ok(qb.build().fetch_one(&self.db).await?.try_get(0)?)
    }

    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        event_type: &str,
        certificate_type: &str,
        certificate_id: Option<Uuid>,
        serial_number: Option<&str>,
        subject: Option<&str>,
        action: &str,
        status: &str,
        actor_id: Option<&str>,
    ) {
        let res = sqlx::query(
            "INSERT INTO pki_audit_log \
             (id, event_type, certificate_type, certificate_id, serial_number, subject, \
              actor_id, action, status, request_data, response_data, timestamp) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(Uuid::new_v4())
        .bind(event_type)
        .bind(certificate_type)
        .bind(certificate_id)
        .bind(serial_number)
        .bind(subject)
        .bind(parse_uuid(actor_id))
        .bind(action)
        .bind(status)
        .bind(Json(serde_json::json!({})))
        .bind(Json(serde_json::json!({})))
        .bind(Utc::now().naive_utc())
        .execute(&self.db)
        .await;
        if let Err(e) = res {
            tracing::warn!(error = %e, "audit log insert failed");
        }
    }
}

/// Errors surfaced by the certificate manager.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// Database error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// X.509 CA engine error.
    #[error(transparent)]
    X509(#[from] crate::ca::x509::X509Error),
    /// SSH CA engine error.
    #[error(transparent)]
    Ssh(#[from] crate::ca::ssh::SshError),
}

impl From<ManagerError> for crate::error::ApiError {
    fn from(e: ManagerError) -> Self {
        match e {
            ManagerError::Db(e) => crate::error::ApiError::internal("database", e),
            ManagerError::X509(e) => e.into(),
            ManagerError::Ssh(e) => e.into(),
        }
    }
}

fn push_x509_filters(
    qb: &mut QueryBuilder<sqlx::Postgres>,
    status: Option<&str>,
    subject: Option<&str>,
    expires_before: Option<NaiveDateTime>,
) {
    let mut first = true;
    let mut sep = |qb: &mut QueryBuilder<sqlx::Postgres>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(s) = status {
        sep(qb);
        qb.push("status = ").push_bind(s.to_owned());
    }
    if let Some(sub) = subject {
        sep(qb);
        qb.push("subject LIKE ").push_bind(format!("%{sub}%"));
    }
    if let Some(exp) = expires_before {
        sep(qb);
        qb.push("not_after < ").push_bind(exp);
    }
}

fn push_ssh_filters(
    qb: &mut QueryBuilder<sqlx::Postgres>,
    status: Option<&str>,
    certificate_type: Option<&str>,
    principal: Option<&str>,
) {
    let mut first = true;
    let mut sep = |qb: &mut QueryBuilder<sqlx::Postgres>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(s) = status {
        sep(qb);
        qb.push("status = ").push_bind(s.to_owned());
    }
    if let Some(t) = certificate_type {
        sep(qb);
        qb.push("certificate_type = ").push_bind(t.to_owned());
    }
    if let Some(p) = principal {
        sep(qb);
        qb.push_bind(p.to_owned()).push(" = ANY(principals)");
    }
}

fn x509_row_to_dict(row: &sqlx::postgres::PgRow, include_pem: bool) -> serde_json::Value {
    let id: Uuid = row.try_get("id").unwrap_or_default();
    let mut v = serde_json::json!({
        "id": id.to_string(),
        "serial_number": row.try_get::<String, _>("serial_number").unwrap_or_default(),
        "subject": row.try_get::<String, _>("subject").unwrap_or_default(),
        "issuer": row.try_get::<String, _>("issuer").unwrap_or_default(),
        "not_before": py_isoformat_opt(row.try_get("not_before").ok()),
        "not_after": py_isoformat_opt(row.try_get("not_after").ok()),
        "key_algorithm": row.try_get::<String, _>("key_algorithm").unwrap_or_default(),
        "key_size": row.try_get::<Option<i32>, _>("key_size").unwrap_or(None),
        "fingerprint_sha256": row.try_get::<String, _>("fingerprint_sha256").unwrap_or_default(),
        "san_dns": row.try_get::<Option<Vec<String>>, _>("san_dns").unwrap_or(None).unwrap_or_default(),
        "san_ip": row.try_get::<Option<Vec<String>>, _>("san_ip").unwrap_or(None).unwrap_or_default(),
        "san_email": row.try_get::<Option<Vec<String>>, _>("san_email").unwrap_or(None).unwrap_or_default(),
        "status": row.try_get::<String, _>("status").unwrap_or_default(),
        "revoked_at": py_isoformat_opt(row.try_get("revoked_at").ok().flatten()),
        "revocation_reason": row.try_get::<Option<String>, _>("revocation_reason").unwrap_or(None),
        "created_at": py_isoformat_opt(row.try_get("created_at").ok().flatten()),
    });
    if include_pem {
        v["certificate_pem"] =
            serde_json::Value::String(row.try_get("certificate_pem").unwrap_or_default());
        v["private_key_pem"] = match row.try_get::<Option<String>, _>("private_key_pem") {
            Ok(Some(p)) => serde_json::Value::String(p),
            _ => serde_json::Value::Null,
        };
    }
    v
}

fn ssh_row_to_dict(row: &sqlx::postgres::PgRow, include_cert: bool) -> serde_json::Value {
    let id: Uuid = row.try_get("id").unwrap_or_default();
    let extensions: Json<serde_json::Value> = row
        .try_get("extensions")
        .unwrap_or(Json(serde_json::json!({})));
    let critical: Json<serde_json::Value> = row
        .try_get("critical_options")
        .unwrap_or(Json(serde_json::json!({})));
    let mut v = serde_json::json!({
        "id": id.to_string(),
        "serial_number": row.try_get::<String, _>("serial_number").unwrap_or_default(),
        "key_id": row.try_get::<String, _>("key_id").unwrap_or_default(),
        "certificate_type": row.try_get::<String, _>("certificate_type").unwrap_or_default(),
        "principals": row.try_get::<Option<Vec<String>>, _>("principals").unwrap_or(None).unwrap_or_default(),
        "valid_after": py_isoformat_opt(row.try_get("valid_after").ok()),
        "valid_before": py_isoformat_opt(row.try_get("valid_before").ok()),
        "key_type": row.try_get::<String, _>("key_type").unwrap_or_default(),
        "hostname": row.try_get::<Option<String>, _>("hostname").unwrap_or(None),
        "status": row.try_get::<String, _>("status").unwrap_or_default(),
        "revoked_at": py_isoformat_opt(row.try_get("revoked_at").ok().flatten()),
        "revocation_reason": row.try_get::<Option<String>, _>("revocation_reason").unwrap_or(None),
        "extensions": extensions.0,
        "critical_options": critical.0,
        "created_at": py_isoformat_opt(row.try_get("created_at").ok().flatten()),
    });
    if include_cert {
        v["certificate"] =
            serde_json::Value::String(row.try_get("certificate").unwrap_or_default());
        v["public_key"] = serde_json::Value::String(row.try_get("public_key").unwrap_or_default());
    }
    v
}

fn join_err(e: tokio::task::JoinError) -> ManagerError {
    ManagerError::X509(crate::ca::x509::X509Error::Internal(format!(
        "blocking task join: {e}"
    )))
}

fn parse_uuid(s: Option<&str>) -> Option<Uuid> {
    s.and_then(|v| Uuid::parse_str(v).ok())
}

fn parse_uuid_owned(s: &str) -> Option<Uuid> {
    Uuid::parse_str(s).ok()
}

/// Unit tests for the parts of `CertManager` that don't require a real
/// Postgres instance (see `docs/v2-port/testing-pattern.md` — pki has no
/// `migrations/` directory, so DB-backed success paths — row-to-dict
/// conversion, "found" branches of get/revoke, statistics counts, audit-log
/// writes — cannot be exercised without one). What's covered here instead:
/// the pure QueryBuilder-filter helpers, UUID parsing, the real
/// error-mapping conversions, and every manager method's behavior up to
/// (and including) the point a lazy/unreachable pool fails a query —
/// including the fully-pure early-return branches (`(None, None)` identifier
/// lookups resolve to `Ok(None)`/`Ok(false)` without ever touching the DB).
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ca::ssh::SshCa;
    use crate::ca::x509::X509Ca;
    use crate::config::X509CaConfig;
    use crate::error::ApiError;

    fn tmp_x509_config() -> X509CaConfig {
        let dir =
            std::env::temp_dir().join(format!("skauswatch-manager-test-{}", uuid::Uuid::new_v4()));
        X509CaConfig {
            ca_key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert_path: dir.join("ca.crt").to_string_lossy().into_owned(),
            ca_key_password: None,
            default_validity_days: 365,
            max_validity_days: 825,
            default_key_algorithm: "RSA".into(),
            default_key_size: 2048,
            crl_validity_days: 7,
            ocsp_responder_url: None,
        }
    }

    fn unreachable_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy pool: {e}"))
    }

    fn test_manager() -> CertManager {
        let x509 = Arc::new(X509Ca::load_or_generate(tmp_x509_config()).unwrap());
        let ssh = Arc::new(SshCa::for_tests());
        CertManager::new(x509, ssh, unreachable_pool())
    }

    fn x509_params(subject: &str) -> crate::ca::x509::X509IssueParams {
        crate::ca::x509::X509IssueParams {
            subject: subject.into(),
            key_algorithm: "RSA".into(),
            key_size: 2048,
            validity_days: 30,
            san_dns: vec![],
            san_ip: vec![],
            san_email: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            is_ca: false,
            path_length: None,
            csr_pem: None,
        }
    }

    #[test]
    fn push_x509_filters_builds_expected_where_clauses() {
        let mut qb = QueryBuilder::new("SELECT 1 FROM x");
        push_x509_filters(&mut qb, None, None, None);
        assert_eq!(qb.sql().as_str(), "SELECT 1 FROM x");

        let mut qb2 = QueryBuilder::new("SELECT 1 FROM x");
        push_x509_filters(&mut qb2, Some("active"), None, None);
        assert!(qb2.sql().as_str().contains(" WHERE status = "));

        let mut qb3 = QueryBuilder::new("SELECT 1 FROM x");
        push_x509_filters(
            &mut qb3,
            Some("active"),
            Some("CN=x"),
            Some(Utc::now().naive_utc()),
        );
        assert!(qb3.sql().as_str().contains(" WHERE status = "));
        assert!(qb3.sql().as_str().contains(" AND subject LIKE "));
        assert!(qb3.sql().as_str().contains(" AND not_after < "));
    }

    #[test]
    fn push_ssh_filters_builds_expected_where_clauses() {
        let mut qb = QueryBuilder::new("SELECT 1 FROM x");
        push_ssh_filters(&mut qb, None, None, None);
        assert_eq!(qb.sql().as_str(), "SELECT 1 FROM x");

        let mut qb2 = QueryBuilder::new("SELECT 1 FROM x");
        push_ssh_filters(&mut qb2, Some("active"), Some("user"), Some("alice"));
        assert!(qb2.sql().as_str().contains(" WHERE status = "));
        assert!(qb2.sql().as_str().contains(" AND certificate_type = "));
        assert!(qb2.sql().as_str().contains(" = ANY(principals)"));
    }

    #[test]
    fn parse_uuid_helpers_accept_valid_and_reject_invalid() {
        let id = Uuid::new_v4();
        assert_eq!(parse_uuid(Some(&id.to_string())), Some(id));
        assert_eq!(parse_uuid(Some("not-a-uuid")), None);
        assert_eq!(parse_uuid(None), None);
        assert_eq!(parse_uuid_owned(&id.to_string()), Some(id));
        assert_eq!(parse_uuid_owned("not-a-uuid"), None);
    }

    #[tokio::test]
    async fn join_err_wraps_a_real_join_error() {
        let handle = tokio::spawn(async { panic!("boom") });
        let join_error = handle.await.unwrap_err();
        let err = join_err(join_error);
        assert!(matches!(
            err,
            ManagerError::X509(crate::ca::x509::X509Error::Internal(_))
        ));
    }

    #[test]
    fn manager_error_converts_to_api_error() {
        let db_err: ApiError = ManagerError::Db(sqlx::Error::RowNotFound).into();
        assert!(matches!(db_err, ApiError::Internal(_)));

        let x509_bad: ApiError =
            ManagerError::X509(crate::ca::x509::X509Error::BadRequest("bad".into())).into();
        assert!(matches!(x509_bad, ApiError::BadRequest(_)));

        let ssh_bad: ApiError =
            ManagerError::Ssh(crate::ca::ssh::SshError::BadRequest("bad".into())).into();
        assert!(matches!(ssh_bad, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn audit_swallows_db_errors_instead_of_propagating() {
        let manager = test_manager();
        // The unreachable pool means the INSERT fails; `audit()` returns `()`
        // regardless — it must log and return, never panic or block forever.
        manager
            .audit(
                "certificate_issued",
                "x509",
                Some(Uuid::new_v4()),
                Some("1"),
                Some("CN=test"),
                "issue",
                "success",
                Some("actor-1"),
            )
            .await;
    }

    #[tokio::test]
    async fn count_fails_against_unreachable_db_for_both_clause_shapes() {
        let manager = test_manager();
        assert!(manager.count("x509_certificates", "").await.is_err());
        assert!(
            manager
                .count("x509_certificates", "WHERE status='active'")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn issue_x509_runs_real_crypto_then_fails_on_db_insert() {
        let manager = test_manager();
        // Real RSA issuance happens (spawn_blocking) before the DB write is
        // attempted, so this exercises manager.issue_x509's full parameter
        // marshalling + bind chain, only failing at the final `.execute()`.
        let err = manager
            .issue_x509(x509_params("CN=manager-test.example.com"), Some("req-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, ManagerError::Db(_)));
    }

    #[tokio::test]
    async fn get_x509_resolves_none_without_db_when_identifier_is_unusable() {
        let manager = test_manager();
        // Neither a valid UUID nor a serial supplied -> Ok(None) with zero
        // DB access (the `(None, None)` early-return arm).
        assert_eq!(manager.get_x509(None, None, false).await.unwrap(), None);
        assert_eq!(
            manager
                .get_x509(Some("not-a-uuid"), None, false)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn get_x509_touches_db_for_valid_uuid_or_serial() {
        let manager = test_manager();
        let id = Uuid::new_v4().to_string();
        assert!(manager.get_x509(Some(&id), None, false).await.is_err());
        assert!(
            manager
                .get_x509(None, Some("deadbeef"), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn revoke_x509_resolves_false_without_db_when_identifier_is_unusable() {
        let manager = test_manager();
        assert!(
            !manager
                .revoke_x509(None, None, "unspecified", None)
                .await
                .unwrap()
        );
        assert!(
            !manager
                .revoke_x509(Some("not-a-uuid"), None, "unspecified", None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn revoke_x509_touches_db_for_valid_uuid_or_serial() {
        let manager = test_manager();
        let id = Uuid::new_v4().to_string();
        assert!(
            manager
                .revoke_x509(Some(&id), None, "unspecified", Some("actor"))
                .await
                .is_err()
        );
        assert!(
            manager
                .revoke_x509(None, Some("deadbeef"), "unspecified", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn list_x509_always_touches_db() {
        let manager = test_manager();
        assert!(
            manager
                .list_x509(
                    Some("active"),
                    Some("CN=x"),
                    Some(Utc::now().naive_utc()),
                    1,
                    50
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn generate_x509_crl_fails_reading_entries_from_db() {
        let manager = test_manager();
        assert!(manager.generate_x509_crl().await.is_err());
    }

    #[tokio::test]
    async fn get_ssh_resolves_none_without_db_when_identifier_is_unusable() {
        let manager = test_manager();
        assert_eq!(manager.get_ssh(None, None, false).await.unwrap(), None);
        assert_eq!(
            manager
                .get_ssh(Some("not-a-uuid"), None, false)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn get_ssh_touches_db_for_valid_uuid_or_serial() {
        let manager = test_manager();
        let id = Uuid::new_v4().to_string();
        assert!(manager.get_ssh(Some(&id), None, false).await.is_err());
        assert!(manager.get_ssh(None, Some("1"), false).await.is_err());
    }

    #[tokio::test]
    async fn revoke_ssh_resolves_false_without_db_when_identifier_is_unusable() {
        let manager = test_manager();
        assert!(
            !manager
                .revoke_ssh(None, None, "unspecified", None)
                .await
                .unwrap()
        );
        assert!(
            !manager
                .revoke_ssh(Some("not-a-uuid"), None, "unspecified", None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn revoke_ssh_touches_db_for_valid_uuid_or_serial() {
        let manager = test_manager();
        let id = Uuid::new_v4().to_string();
        assert!(
            manager
                .revoke_ssh(Some(&id), None, "unspecified", None)
                .await
                .is_err()
        );
        assert!(
            manager
                .revoke_ssh(None, Some("1"), "unspecified", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn list_ssh_always_touches_db() {
        let manager = test_manager();
        assert!(
            manager
                .list_ssh(Some("active"), Some("user"), Some("alice"), 1, 50)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn generate_ssh_krl_fails_reading_entries_from_db() {
        let manager = test_manager();
        assert!(manager.generate_ssh_krl().await.is_err());
    }

    #[tokio::test]
    async fn statistics_fails_against_unreachable_db() {
        let manager = test_manager();
        assert!(manager.statistics().await.is_err());
    }

    #[tokio::test]
    async fn db_accessor_returns_the_configured_pool() {
        // `connect_lazy` requires an active Tokio context even just to
        // construct the pool, so this needs `#[tokio::test]` like every
        // other test here, despite not being `.await`-ing anything itself.
        let manager = test_manager();
        // Just confirms the accessor wires through; a real query against it
        // is exercised by every DB-touching test above.
        let _pool: &PgPool = manager.db();
    }

    // ===================== DB-backed success paths =====================
    //
    // A real, migrated Postgres schema (services/pki/migrations/) is now
    // available (see docs/v2-port/testing-pattern.md), so the "found"
    // branches this module's earlier tests explicitly couldn't reach —
    // row-to-dict conversion, revoke's real update, list/CRL/KRL/statistics
    // bodies, audit-log writes — are exercised here for real, against
    // `crate::routes::test_support::db_state()`'s real X.509/SSH CA engines
    // + real Postgres pool.

    async fn db_manager() -> std::sync::Arc<CertManager> {
        crate::routes::test_support::db_state()
            .await
            .manager
            .clone()
    }

    fn x509_req(subject: &str) -> crate::ca::x509::X509IssueParams {
        crate::ca::x509::X509IssueParams {
            subject: subject.into(),
            key_algorithm: "RSA".into(),
            key_size: 2048,
            validity_days: 365,
            san_dns: vec!["db-test.example.com".into()],
            san_ip: vec![],
            san_email: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            is_ca: false,
            path_length: None,
            csr_pem: None,
        }
    }

    fn ssh_req(pubkey: &str) -> crate::ca::ssh::SshIssueParams {
        crate::ca::ssh::SshIssueParams {
            public_key: pubkey.to_owned(),
            certificate_type: "user".into(),
            key_id: None,
            principals: vec!["alice".into()],
            validity_seconds: 3600,
            extensions: None,
            critical_options: None,
            source_addresses: vec![],
            force_command: None,
            hostname: None,
        }
    }

    fn gen_subject_pubkey() -> String {
        let path = std::env::temp_dir().join(format!(
            "skauswatch-pki-manager-dbtest-{}",
            uuid::Uuid::new_v4()
        ));
        let status = std::process::Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-f")
            .arg(&path)
            .arg("-N")
            .arg("")
            .arg("-q")
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read_to_string(format!("{}.pub", path.display()))
            .unwrap()
            .trim()
            .to_owned()
    }

    #[tokio::test]
    async fn issue_x509_persists_and_get_x509_finds_it_by_id_and_serial() {
        let manager = db_manager().await;
        let issued = manager
            .issue_x509(
                x509_req("CN=db-persist.example.com"),
                Some(&Uuid::new_v4().to_string()),
            )
            .await
            .unwrap();
        let id = issued["id"].as_str().unwrap();
        let serial = issued["serial_number"].as_str().unwrap();

        let by_id = manager
            .get_x509(Some(id), None, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id["subject"], "CN=db-persist.example.com");
        assert_eq!(by_id["san_dns"], serde_json::json!(["db-test.example.com"]));
        assert!(
            by_id["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("PRIVATE KEY")
        );

        let by_serial = manager
            .get_x509(None, Some(serial), false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_serial["serial_number"], serial);
        assert!(by_serial.get("certificate_pem").is_none());

        // Unknown-but-valid UUID -> Ok(None), real DB round trip (not the
        // fully-DB-free (None,None) shortcut tested elsewhere).
        assert_eq!(
            manager
                .get_x509(Some(&Uuid::new_v4().to_string()), None, false)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn issue_x509_duplicate_serial_is_a_real_db_conflict() {
        // Every fresh X509Ca's serial counter starts at 1, so the first
        // certificate this brand-new manager issues will collide with a
        // row seeded ahead of time carrying serial_number = "1" — proving
        // the schema's `UNIQUE (serial_number)` constraint on
        // x509_certificates is real, not just declared.
        let manager = db_manager().await;
        sqlx::query(
            "INSERT INTO x509_certificates \
             (id, serial_number, subject, issuer, not_before, not_after, key_algorithm, \
              signature_algorithm, fingerprint_sha256, certificate_pem, san_dns, san_ip, \
              san_email, key_usage, extended_key_usage, is_ca, status, metadata, \
              created_at, updated_at) \
             VALUES ($1,'1','CN=seed','CN=seed',now(),now(),'RSA','SHA256','deadbeef', \
              'PEM','{}','{}','{}','{}','{}',false,'active','{}'::jsonb,now(),now())",
        )
        .bind(Uuid::new_v4())
        .execute(manager.db())
        .await
        .unwrap();

        let err = manager
            .issue_x509(x509_req("CN=collides.example.com"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ManagerError::Db(_)));
    }

    #[tokio::test]
    async fn revoke_x509_marks_revoked_and_is_idempotent() {
        let manager = db_manager().await;
        let issued = manager
            .issue_x509(x509_req("CN=revoke-db.example.com"), None)
            .await
            .unwrap();
        let id = issued["id"].as_str().unwrap();

        assert!(
            manager
                .revoke_x509(Some(id), None, "key_compromise", Some("actor-1"))
                .await
                .unwrap()
        );
        let after = manager
            .get_x509(Some(id), None, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after["status"], "revoked");
        assert_eq!(after["revocation_reason"], "key_compromise");
        assert!(after["revoked_at"].is_string());

        // Idempotent: second revoke on an already-revoked cert still
        // returns true without erroring (short-circuits before re-writing).
        assert!(
            manager
                .revoke_x509(Some(id), None, "superseded", None)
                .await
                .unwrap()
        );
        let still = manager
            .get_x509(Some(id), None, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still["revocation_reason"], "key_compromise"); // unchanged

        // A genuinely nonexistent (but valid-format) id -> Ok(false).
        assert!(
            !manager
                .revoke_x509(Some(&Uuid::new_v4().to_string()), None, "unspecified", None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn list_x509_paginates_and_filters_real_rows() {
        let manager = db_manager().await;
        for i in 0..3 {
            manager
                .issue_x509(x509_req(&format!("CN=list-{i}.example.com")), None)
                .await
                .unwrap();
        }
        let (page1, total) = manager.list_x509(None, None, None, 1, 2).await.unwrap();
        assert_eq!(total, 3);
        assert_eq!(page1.len(), 2);
        let (page2, total2) = manager.list_x509(None, None, None, 2, 2).await.unwrap();
        assert_eq!(total2, 3);
        assert_eq!(page2.len(), 1);

        let (filtered, ftotal) = manager
            .list_x509(None, Some("list-1"), None, 1, 50)
            .await
            .unwrap();
        assert_eq!(ftotal, 1);
        assert_eq!(filtered[0]["subject"], "CN=list-1.example.com");
    }

    #[tokio::test]
    async fn generate_x509_crl_lists_real_revoked_serials() {
        let manager = db_manager().await;
        let issued = manager
            .issue_x509(x509_req("CN=crl-db.example.com"), None)
            .await
            .unwrap();
        let id = issued["id"].as_str().unwrap();
        let serial = issued["serial_number"].as_str().unwrap().to_owned();
        manager
            .revoke_x509(Some(id), None, "ca_compromise", None)
            .await
            .unwrap();

        let crl = manager.generate_x509_crl().await.unwrap();
        assert!(crl["crl_pem"].as_str().unwrap().contains("BEGIN X509 CRL"));
        let revoked = crl["revoked_certificates"].as_array().unwrap();
        assert!(revoked.iter().any(|e| e["serial_number"] == serial));
    }

    #[tokio::test]
    async fn statistics_reflects_real_row_counts() {
        let manager = db_manager().await;
        let a = manager
            .issue_x509(x509_req("CN=stat-a.example.com"), None)
            .await
            .unwrap();
        manager
            .issue_x509(x509_req("CN=stat-b.example.com"), None)
            .await
            .unwrap();
        manager
            .revoke_x509(Some(a["id"].as_str().unwrap()), None, "unspecified", None)
            .await
            .unwrap();

        let stats = manager.statistics().await.unwrap();
        assert_eq!(stats["x509"]["total"], 2);
        assert_eq!(stats["x509"]["active"], 1);
        assert_eq!(stats["x509"]["revoked"], 1);
    }

    #[tokio::test]
    async fn issue_ssh_persists_and_get_ssh_finds_it() {
        let manager = db_manager().await;
        let pubkey = gen_subject_pubkey();
        let issued = manager
            .issue_ssh(ssh_req(&pubkey), Some(&Uuid::new_v4().to_string()))
            .await
            .unwrap();
        let id = issued["id"].as_str().unwrap();
        let serial = issued["serial_number"].as_str().unwrap();

        let by_id = manager
            .get_ssh(Some(id), None, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id["principals"], serde_json::json!(["alice"]));
        assert!(
            by_id["certificate"]
                .as_str()
                .unwrap()
                .contains("cert-v01@openssh.com")
        );

        let by_serial = manager
            .get_ssh(None, Some(serial), false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_serial["serial_number"], serial);
        assert!(by_serial.get("certificate").is_none());
    }

    #[tokio::test]
    async fn revoke_ssh_marks_revoked_and_is_idempotent() {
        let manager = db_manager().await;
        let pubkey = gen_subject_pubkey();
        let issued = manager.issue_ssh(ssh_req(&pubkey), None).await.unwrap();
        let id = issued["id"].as_str().unwrap();

        assert!(
            manager
                .revoke_ssh(Some(id), None, "key_compromise", None)
                .await
                .unwrap()
        );
        let after = manager
            .get_ssh(Some(id), None, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after["status"], "revoked");

        assert!(
            manager
                .revoke_ssh(Some(id), None, "superseded", None)
                .await
                .unwrap()
        );
        let still = manager
            .get_ssh(Some(id), None, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still["revocation_reason"], "key_compromise"); // unchanged, idempotent
    }

    #[tokio::test]
    async fn list_ssh_paginates_and_filters_real_rows() {
        let manager = db_manager().await;
        for _ in 0..2 {
            let pubkey = gen_subject_pubkey();
            manager.issue_ssh(ssh_req(&pubkey), None).await.unwrap();
        }
        let (items, total) = manager.list_ssh(None, None, None, 1, 50).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(items.len(), 2);

        let (filtered, ftotal) = manager
            .list_ssh(None, None, Some("alice"), 1, 50)
            .await
            .unwrap();
        assert_eq!(ftotal, 2);
        assert_eq!(filtered.len(), 2);
    }

    #[tokio::test]
    async fn generate_ssh_krl_lists_real_revoked_serials() {
        let manager = db_manager().await;
        let pubkey = gen_subject_pubkey();
        let issued = manager.issue_ssh(ssh_req(&pubkey), None).await.unwrap();
        let id = issued["id"].as_str().unwrap();
        let serial = issued["serial_number"].as_str().unwrap().to_owned();
        manager
            .revoke_ssh(Some(id), None, "unspecified", None)
            .await
            .unwrap();

        let krl = manager.generate_ssh_krl().await.unwrap();
        assert!(!krl["krl_binary"].as_str().unwrap().is_empty());
        let revoked = krl["revoked_keys"].as_array().unwrap();
        assert!(revoked.iter().any(|e| e["serial_number"] == serial));
    }

    #[tokio::test]
    async fn audit_persists_a_real_row() {
        let manager = db_manager().await;
        // issue_x509's success path calls `audit()` internally — assert the
        // row actually landed instead of just that the call didn't panic.
        manager
            .issue_x509(x509_req("CN=audit-db.example.com"), Some("requester-xyz"))
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pki_audit_log WHERE event_type='certificate_issued' AND certificate_type='x509'",
        )
        .fetch_one(manager.db())
        .await
        .unwrap();
        assert!(count >= 1);
    }
}
