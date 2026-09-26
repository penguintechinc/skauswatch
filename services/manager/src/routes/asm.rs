//! /api/v1/asm — Attack Surface Management: manager owns the `asm_*` tables
//! and publishes scan work to `scanner:tasks`; `services/scanner` executes
//! the masscan → banner-grab → cert-fetch → diff pipeline and writes
//! results back into these same tables. Contract:
//! docs/v2-port/phase12-scope-scan-monitor.md §1.
//!
//! **Re-architected from v1, not a line-port.** v1's `services/manager/api/
//! v1/asm.py` was a pure authenticated HTTP proxy to `worker-scanner`'s own
//! Flask app + Celery task (`services/worker-scanner/api/routes/asm.py`).
//! v2 has no such upstream — `services/scanner` is a stream-driven worker
//! with no HTTP server beyond a telemetry health router, so proxying was
//! structurally impossible (every call 503'd). This module instead follows
//! the pattern already established by `routes/s3_scan.rs`/`services/s3scan`:
//! this service owns the tables, inserts the scan row, and publishes a
//! stream task; the worker consumes it and writes results directly into the
//! same tables (see `services/scanner/src/asm.rs`). GET routes here query
//! Postgres directly — there is no upstream response to proxy.
//!
//! **Scope note — `target` replaces v1's `target_id`.** v1's `asm_scans`
//! referenced a `scan_targets` table shared with the separate, out-of-scope
//! nuclei/zap/openvas job schema. Pulling that whole 4-table schema in just
//! to satisfy one FK would be scope creep (see migration module doc), so
//! `target` is a plain host/CIDR/domain string here.
//!
//! **Screenshot capture is deferred, not implemented.** v1's screenshot
//! stage shells out to `gowitness`/`xfreerdp`/`vncsnapshot` and uploads to
//! S3 — none of those binaries or the upload plumbing are wired in this
//! pass (see `services/scanner/src/asm.rs` module doc). `asm_screenshots`
//! exists and this router's screenshot/report routes work correctly against
//! it, but no scan populates any rows yet — both routes currently return an
//! empty list / a report with an empty `screenshots` array until that stage
//! lands.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::NaiveDateTime;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

const MODES: [&str; 3] = ["internal", "external", "both"];
const MODE_MSG: &str = "Input should be 'internal', 'external' or 'both'";
const DEFAULT_RATE: i64 = 1000;
const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

/// Router for /api/v1/asm.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/asm/scans", get(list_asm_scans).post(create_asm_scan))
        .route("/asm/scans/{scan_id}", get(get_asm_scan))
        .route("/asm/scans/{scan_id}/hosts", get(get_asm_scan_hosts))
        .route(
            "/asm/scans/{scan_id}/screenshots",
            get(get_asm_scan_screenshots),
        )
        .route("/asm/scans/{scan_id}/certs", get(get_asm_scan_certs))
        .route("/asm/scans/{scan_id}/diff", get(get_asm_scan_diff))
        .route("/asm/scans/{scan_id}/report", get(get_asm_scan_report))
        .route(
            "/asm/settings/ports",
            get(get_port_settings).put(update_port_settings),
        )
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

fn check_len(s: &str, field: &str, min: usize, max: usize) -> Result<(), ApiError> {
    let n = s.chars().count();
    if n < min {
        return Err(validation(field, "Field required"));
    }
    if n > max {
        return Err(validation(
            field,
            &format!("String should have at most {max} characters"),
        ));
    }
    Ok(())
}

// ============================================
// SSRF hardening (creation-time layer)
// ============================================
//
// **Regression coverage for a CONFIRMED HIGH security-review finding**:
// `target` previously reached the scanner (masscan → banner-grab →
// TLS-cert fetch → headless-Chromium screenshot) with only this file's
// empty/length check — no block on link-local (including
// `169.254.169.254`, the AWS IMDS well-known address), loopback, or
// RFC1918/CGNAT ranges. An ordinary tenant (`admin`/`maintainer` role)
// could scan the platform's own cloud metadata or internal services and
// have the results (including a Chromium-rendered screenshot) handed
// back. This is the lighter, creation-time half of the fix — the
// critical half lives in `services/scanner/src/target_safety.rs`
// (`resolve_target_for_masscan` + the per-masscan-discovered-IP re-check
// in `asm.rs::run_asm_scan`), since a domain accepted here can still
// resolve to a blocked address by the time the scanner dispatches (DNS
// rebinding) — this creation-time check alone would not catch that.
//
// Deliberately duplicated here rather than shared via a workspace crate:
// this fix is scoped to `services/scanner/**` +
// `services/manager/src/routes/asm.rs` only, so the blocklist logic is a
// small, self-contained, pure-`std` copy (no new dependency) rather than
// a shared crate this file isn't allowed to introduce.
//
// Asset-ownership verification (v1's `scan_targets` FK model) is
// intentionally **not** restored here — out of scope for this hotfix,
// which closes the SSRF path via IP-range validation only; see this
// module's doc comment's "Scope note" and
// `docs/v2-port/phase12-scope-scan-monitor.md` for the tracked follow-up
// to add a per-tenant target-allowlist/verification gate.

/// IPv4 ranges disallowed as scan destinations: "this network"/
/// unspecified, RFC1918 private space, CGNAT (RFC6598), loopback,
/// link-local (which includes the cloud IMDS well-known address
/// `169.254.169.254`), and multicast.
const BLOCKED_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
];

/// IPv6 ranges disallowed as scan destinations: loopback, unique-local
/// (ULA — the IPv6 analogue of RFC1918), link-local, and multicast.
const BLOCKED_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::LOCALHOST, 128),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];

/// Inclusive `[network, broadcast]` bounds of `addr/prefix`.
fn v4_bounds(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let addr = u32::from(addr);
    if prefix == 0 {
        (0, u32::MAX)
    } else if prefix >= 32 {
        (addr, addr)
    } else {
        let mask = !0u32 << (32 - prefix);
        let network = addr & mask;
        (network, network | !mask)
    }
}

/// Inclusive `[network, broadcast]` bounds of `addr/prefix` (IPv6
/// analogue of [`v4_bounds`]).
fn v6_bounds(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
    let addr = u128::from(addr);
    if prefix == 0 {
        (0, u128::MAX)
    } else if prefix >= 128 {
        (addr, addr)
    } else {
        let mask = !0u128 << (128 - prefix);
        let network = addr & mask;
        (network, network | !mask)
    }
}

fn point_in<T: PartialOrd>(point: T, bounds: (T, T)) -> bool {
    bounds.0 <= point && point <= bounds.1
}

fn ranges_overlap<T: PartialOrd>(a: (T, T), b: (T, T)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// True if `ip` falls within any disallowed range. IPv4-mapped IPv6
/// addresses (`::ffff:a.b.c.d`) are normalized to plain IPv4 first via
/// [`IpAddr::to_canonical`] — a well-known blocklist-bypass technique
/// otherwise.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let point = u32::from(v4);
            BLOCKED_V4
                .iter()
                .any(|&(net, prefix)| point_in(point, v4_bounds(net, prefix)))
        }
        IpAddr::V6(v6) => {
            let point = u128::from(v6);
            BLOCKED_V6
                .iter()
                .any(|&(net, prefix)| point_in(point, v6_bounds(net, prefix)))
        }
    }
}

/// True if `addr/prefix` overlaps any disallowed range in either
/// direction — the requested CIDR might itself sit inside a blocked range
/// (e.g. `169.254.1.0/24`), or be broad enough to swallow one (e.g.
/// `0.0.0.0/0`, `10.0.0.0/7`).
fn is_blocked_cidr(addr: IpAddr, prefix: u8) -> bool {
    match addr.to_canonical() {
        IpAddr::V4(v4) => {
            let req = v4_bounds(v4, prefix);
            BLOCKED_V4
                .iter()
                .any(|&(net, net_prefix)| ranges_overlap(req, v4_bounds(net, net_prefix)))
        }
        IpAddr::V6(v6) => {
            let req = v6_bounds(v6, prefix);
            BLOCKED_V6
                .iter()
                .any(|&(net, net_prefix)| ranges_overlap(req, v6_bounds(net, net_prefix)))
        }
    }
}

const TARGET_BLOCKED_MSG: &str = "Target resolves to a disallowed address range (link-local/metadata, loopback, private, \
     CGNAT, or multicast)";

/// Creation-time SSRF check for a scan `target`: a literal IP or CIDR is
/// validated directly against the same blocklist the scanner worker uses
/// (see this section's module doc). A domain name is *not* resolved
/// here — synchronous DNS resolution in a request handler is its own
/// SSRF-adjacent hazard, and would be vulnerable to rebinding between
/// this check and actual scan time regardless — so domain-form targets
/// are accepted here and re-checked after resolution by the scanner
/// worker immediately before dispatch (`services/scanner/src/
/// target_safety.rs::resolve_target_for_masscan`), which is the layer
/// that actually closes the SSRF path for domain targets.
fn validate_target_safety(target: &str) -> Result<(), ApiError> {
    if let Some((addr_part, prefix_part)) = target.split_once('/')
        && let (Ok(addr), Ok(prefix)) = (addr_part.parse::<IpAddr>(), prefix_part.parse::<u8>())
    {
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(validation("target", "Invalid CIDR prefix length"));
        }
        if is_blocked_cidr(addr, prefix) {
            return Err(validation("target", TARGET_BLOCKED_MSG));
        }
        return Ok(());
    }
    if let Ok(ip) = target.parse::<IpAddr>()
        && is_blocked_ip(ip)
    {
        return Err(validation("target", TARGET_BLOCKED_MSG));
    }
    Ok(())
}

fn total_pages(total: i64, per_page: i64) -> i64 {
    (total + per_page - 1) / per_page
}

fn parse_page_params(pairs: &[(String, String)]) -> (i64, i64) {
    let page = first(pairs, "page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = first(pairs, "per_page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_PER_PAGE)
        .clamp(1, MAX_PER_PAGE);
    (page, per_page)
}

fn first<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Validates `extra_ports` (each 1..=65535, capped at 1000 entries — v1 had
/// no explicit cap, but an unbounded list is a resource-exhaustion vector
/// for the masscan invocation it feeds) and `rate` (1..=1_000_000, matching
/// v1's `PortsConfigSchema`/`AsmScanCreateSchema` range).
fn validate_ports_config(
    extra_ports: &Option<Vec<i64>>,
    rate: Option<i64>,
) -> Result<(Vec<i64>, i64), ApiError> {
    let ports = extra_ports.clone().unwrap_or_default();
    if ports.len() > 1000 {
        return Err(validation(
            "extra_ports",
            "List should have at most 1000 items",
        ));
    }
    for p in &ports {
        if !(1..=65535).contains(p) {
            return Err(validation("extra_ports", &format!("Invalid port: {p}")));
        }
    }
    let rate = rate.unwrap_or(DEFAULT_RATE);
    if !(1..=1_000_000).contains(&rate) {
        return Err(validation("rate", "Input should be between 1 and 1000000"));
    }
    Ok((ports, rate))
}

// ============================================
// Scan endpoints
// ============================================

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AsmScanCreateBody {
    target: Option<String>,
    mode: Option<String>,
    extra_ports: Option<Vec<i64>>,
    rate: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct AsmScanRow {
    id: i64,
    target: String,
    mode: String,
    status: String,
    ports_config: Option<serde_json::Value>,
    error_message: Option<String>,
    created_at: Option<NaiveDateTime>,
    started_at: Option<NaiveDateTime>,
    completed_at: Option<NaiveDateTime>,
}

const SCAN_COLUMNS: &str = "SELECT id, target, mode, status, ports_config, error_message, \
     created_at, started_at, completed_at FROM asm_scans WHERE tenant_id = $1";

fn scan_json(s: &AsmScanRow) -> serde_json::Value {
    serde_json::json!({
        "id": s.id,
        "target": s.target,
        "mode": s.mode,
        "status": s.status,
        "ports_config": s.ports_config,
        "error_message": s.error_message,
        "created_at": skauswatch_streams::py_isoformat_opt(s.created_at),
        "started_at": skauswatch_streams::py_isoformat_opt(s.started_at),
        "completed_at": skauswatch_streams::py_isoformat_opt(s.completed_at),
    })
}

async fn fetch_scan(db: &PgPool, tenant: Uuid, scan_id: i64) -> Result<AsmScanRow, ApiError> {
    sqlx::query_as::<_, AsmScanRow>(sqlx::AssertSqlSafe(format!("{SCAN_COLUMNS} AND id = $2")))
        .bind(tenant)
        .bind(scan_id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Scan not found".to_owned()))
}

/// `scanner:tasks` message shape for `scan_type: "asm"` — parsed by
/// `services/scanner/src/handler.rs`; `params` additionally carries
/// `scan_id`/`mode`/`ports_config` for `services/scanner/src/asm.rs`.
#[allow(clippy::too_many_arguments)]
fn asm_task_fields(
    job_id: &str,
    target: &str,
    scan_id: i64,
    mode: &str,
    ports_config: &serde_json::Value,
    tenant_id: Uuid,
    submitted_at: &str,
) -> skauswatch_streams::EntryFields {
    let params = serde_json::json!({
        "scan_id": scan_id,
        "mode": mode,
        "ports_config": ports_config,
    });
    vec![
        ("job_id".to_owned(), job_id.to_owned()),
        ("scan_type".to_owned(), "asm".to_owned()),
        ("target".to_owned(), target.to_owned()),
        ("file_path".to_owned(), String::new()),
        (
            "params".to_owned(),
            serde_json::to_string(&params).unwrap_or_default(),
        ),
        ("tenant_id".to_owned(), tenant_id.to_string()),
        ("submitted_at".to_owned(), submitted_at.to_owned()),
    ]
}

/// POST /asm/scans — admin/maintainer. Inserts the `asm_scans` row and
/// publishes one `scanner:tasks` message (`scan_type: "asm"`); the scanner
/// worker picks it up, runs the pipeline, and writes hosts/services/certs/
/// diff rows back tenant-stamped.
#[utoipa::path(
    post,
    path = "/api/v1/asm/scans",
    tag = "asm",
    security(("bearer_jwt" = [])),
    request_body = AsmScanCreateBody,
    responses(
        (status = 201, description = "ASM scan created and queued", body = serde_json::Value),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_asm_scan(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<AsmScanCreateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_scope("asm:write")?;

    let target = match body.target.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return Err(validation("target", "Field required")),
    };
    check_len(target, "target", 1, 2048)?;
    validate_target_safety(target)?;
    let mode = body.mode.unwrap_or_else(|| "external".to_owned());
    if !MODES.contains(&mode.as_str()) {
        return Err(validation("mode", MODE_MSG));
    }
    let (extra_ports, rate) = validate_ports_config(&body.extra_ports, body.rate)?;
    let ports_config = serde_json::json!({"extra_ports": extra_ports, "rate": rate});

    let row = sqlx::query_as::<_, AsmScanRow>(
        "INSERT INTO asm_scans (tenant_id, target, mode, status, ports_config, created_by, \
         created_at) VALUES ($1, $2, $3, 'pending', $4, $5, now()) \
         RETURNING id, target, mode, status, ports_config, error_message, created_at, \
         started_at, completed_at",
    )
    .bind(user.tenant_id)
    .bind(target)
    .bind(&mode)
    .bind(&ports_config)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    let job_id = uuid::Uuid::new_v4().to_string();
    state
        .publish_stream(
            skauswatch_streams::STREAM_SCANNER_TASKS,
            asm_task_fields(
                &job_id,
                target,
                row.id,
                &mode,
                &ports_config,
                user.tenant_id,
                &skauswatch_streams::py_now_isoformat(),
            ),
        )
        .await;

    Ok((StatusCode::CREATED, Json(scan_json(&row))))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AsmScanListResponse {
    scans: Vec<serde_json::Value>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// GET /asm/scans — paginated, tenant-scoped; optional `target` filter.
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(
        ("page" = Option<i64>, Query, description = "1-based page number (default 1)"),
        ("per_page" = Option<i64>, Query, description = "Page size, capped at 100 (default 20)"),
        ("target" = Option<String>, Query, description = "Filter by exact target value"),
    ),
    responses(
        (status = 200, description = "Paginated ASM scan list", body = AsmScanListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_asm_scans(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (page, per_page) = parse_page_params(&params);
    let offset = (page - 1) * per_page;
    let target_filter = first(&params, "target");

    let (rows, total) = if let Some(t) = target_filter {
        let rows = sqlx::query_as::<_, AsmScanRow>(sqlx::AssertSqlSafe(format!(
            "{SCAN_COLUMNS} AND target = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4"
        )))
        .bind(user.tenant_id)
        .bind(t)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM asm_scans WHERE tenant_id = $1 AND target = $2",
        )
        .bind(user.tenant_id)
        .bind(t)
        .fetch_one(&state.db)
        .await?;
        (rows, total)
    } else {
        let rows = sqlx::query_as::<_, AsmScanRow>(sqlx::AssertSqlSafe(format!(
            "{SCAN_COLUMNS} ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )))
        .bind(user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asm_scans WHERE tenant_id = $1")
            .bind(user.tenant_id)
            .fetch_one(&state.db)
            .await?;
        (rows, total)
    };

    Ok(Json(serde_json::json!({
        "scans": rows.iter().map(scan_json).collect::<Vec<_>>(),
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages(total, per_page),
    })))
}

/// GET /asm/scans/{scan_id} — scan detail.
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "ASM scan detail", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scan = fetch_scan(&state.db, user.tenant_id, scan_id).await?;
    Ok(Json(scan_json(&scan)))
}

#[derive(sqlx::FromRow)]
struct HostRow {
    id: i64,
    ip_address: String,
    hostname: Option<String>,
    is_alive: bool,
    latency_ms: Option<f64>,
    os_guess: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ServiceRow {
    id: i64,
    port: i32,
    protocol: String,
    state: String,
    service_name: Option<String>,
    banner: Option<String>,
    version: Option<String>,
}

/// GET /asm/scans/{scan_id}/hosts — discovered hosts nested with services.
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/hosts",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Discovered hosts and services", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_hosts(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    fetch_scan(&state.db, user.tenant_id, scan_id).await?;
    let hosts = fetch_hosts(&state.db, user.tenant_id, scan_id).await?;
    let mut out = Vec::with_capacity(hosts.len());
    for h in hosts {
        let services = fetch_services(&state.db, user.tenant_id, h.id).await?;
        out.push(serde_json::json!({
            "id": h.id,
            "ip_address": h.ip_address,
            "hostname": h.hostname,
            "is_alive": h.is_alive,
            "latency_ms": h.latency_ms,
            "os_guess": h.os_guess,
            "services": services.iter().map(service_json).collect::<Vec<_>>(),
        }));
    }
    Ok(Json(serde_json::json!({ "hosts": out })))
}

async fn fetch_hosts(db: &PgPool, tenant: Uuid, scan_id: i64) -> Result<Vec<HostRow>, ApiError> {
    Ok(sqlx::query_as::<_, HostRow>(
        "SELECT id, ip_address, hostname, is_alive, latency_ms, os_guess FROM asm_hosts \
         WHERE tenant_id = $1 AND scan_id = $2 ORDER BY ip_address",
    )
    .bind(tenant)
    .bind(scan_id)
    .fetch_all(db)
    .await?)
}

async fn fetch_services(
    db: &PgPool,
    tenant: Uuid,
    host_id: i64,
) -> Result<Vec<ServiceRow>, ApiError> {
    Ok(sqlx::query_as::<_, ServiceRow>(
        "SELECT id, port, protocol, state, service_name, banner, version \
         FROM asm_services WHERE tenant_id = $1 AND host_id = $2 ORDER BY port",
    )
    .bind(tenant)
    .bind(host_id)
    .fetch_all(db)
    .await?)
}

fn service_json(s: &ServiceRow) -> serde_json::Value {
    serde_json::json!({
        "id": s.id,
        "port": s.port,
        "protocol": s.protocol,
        "state": s.state,
        "service_name": s.service_name,
        "banner": s.banner,
        "version": s.version,
    })
}

#[derive(sqlx::FromRow)]
struct ScreenshotRow {
    id: i64,
    service_id: i64,
    s3_key: String,
    url: Option<String>,
    tool: String,
    width: Option<i32>,
    height: Option<i32>,
    file_size_bytes: Option<i32>,
    captured_at: Option<NaiveDateTime>,
}

/// One screenshot reference, as returned by the standalone `/screenshots`
/// endpoint. Typed (rather than ad-hoc `serde_json::Value`, unlike the
/// aggregated `/report` endpoint below) so the response shape is explicit
/// in the OpenAPI spec — see `crate::asm` (scanner)'s screenshot-capture
/// stage, which is what populates `asm_screenshots` rows for this to read.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AsmScreenshotDto {
    id: i64,
    service_id: i64,
    s3_key: String,
    url: Option<String>,
    tool: String,
    width: Option<i32>,
    height: Option<i32>,
    file_size_bytes: Option<i32>,
    captured_at: Option<String>,
}

impl From<&ScreenshotRow> for AsmScreenshotDto {
    fn from(s: &ScreenshotRow) -> Self {
        Self {
            id: s.id,
            service_id: s.service_id,
            s3_key: s.s3_key.clone(),
            url: s.url.clone(),
            tool: s.tool.clone(),
            width: s.width,
            height: s.height,
            file_size_bytes: s.file_size_bytes,
            captured_at: skauswatch_streams::py_isoformat_opt(s.captured_at),
        }
    }
}

/// Response body for `GET /asm/scans/{scan_id}/screenshots`.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AsmScreenshotsResponse {
    screenshots: Vec<AsmScreenshotDto>,
}

/// GET /asm/scans/{scan_id}/screenshots — screenshots captured for this
/// scan's services, tenant-scoped (via `fetch_scan`'s ownership check plus
/// `fetch_screenshots`'s own `tenant_id` filter — defense in depth). Empty
/// until the scanner's screenshot-capture stage lands a matching scan; the
/// join/read path itself is real.
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/screenshots",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Screenshots for this scan's services", body = AsmScreenshotsResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_screenshots(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i64>,
) -> Result<Json<AsmScreenshotsResponse>, ApiError> {
    fetch_scan(&state.db, user.tenant_id, scan_id).await?;
    let rows = fetch_screenshots(&state.db, user.tenant_id, scan_id).await?;
    Ok(Json(AsmScreenshotsResponse {
        screenshots: rows.iter().map(AsmScreenshotDto::from).collect(),
    }))
}

async fn fetch_screenshots(
    db: &PgPool,
    tenant: Uuid,
    scan_id: i64,
) -> Result<Vec<ScreenshotRow>, ApiError> {
    Ok(sqlx::query_as::<_, ScreenshotRow>(
        "SELECT sc.id, sc.service_id, sc.s3_key, sc.url, sc.tool, sc.width, sc.height, \
         sc.file_size_bytes, sc.captured_at \
         FROM asm_screenshots sc \
         JOIN asm_services sv ON sv.id = sc.service_id \
         JOIN asm_hosts h ON h.id = sv.host_id \
         WHERE sc.tenant_id = $1 AND h.scan_id = $2 ORDER BY sc.id",
    )
    .bind(tenant)
    .bind(scan_id)
    .fetch_all(db)
    .await?)
}

fn screenshot_json(s: &ScreenshotRow) -> serde_json::Value {
    serde_json::json!({
        "id": s.id,
        "service_id": s.service_id,
        "s3_key": s.s3_key,
        "url": s.url,
        "tool": s.tool,
        "width": s.width,
        "height": s.height,
        "file_size_bytes": s.file_size_bytes,
        "captured_at": skauswatch_streams::py_isoformat_opt(s.captured_at),
    })
}

#[derive(sqlx::FromRow)]
struct CertRow {
    id: i64,
    service_id: i64,
    subject: Option<String>,
    issuer: Option<String>,
    not_before: Option<NaiveDateTime>,
    not_after: Option<NaiveDateTime>,
    is_expired: bool,
    days_until_expiry: Option<i32>,
    sans: Option<serde_json::Value>,
    fingerprint_sha256: Option<String>,
}

/// GET /asm/scans/{scan_id}/certs — TLS certificate findings.
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/certs",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "TLS certificate findings for this scan", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_certs(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    fetch_scan(&state.db, user.tenant_id, scan_id).await?;
    let rows = fetch_certs(&state.db, user.tenant_id, scan_id).await?;
    Ok(Json(serde_json::json!({
        "certs": rows.iter().map(cert_json).collect::<Vec<_>>(),
    })))
}

async fn fetch_certs(db: &PgPool, tenant: Uuid, scan_id: i64) -> Result<Vec<CertRow>, ApiError> {
    Ok(sqlx::query_as::<_, CertRow>(
        "SELECT c.id, c.service_id, c.subject, c.issuer, c.not_before, c.not_after, \
         c.is_expired, c.days_until_expiry, c.sans, c.fingerprint_sha256 \
         FROM asm_certs c \
         JOIN asm_services sv ON sv.id = c.service_id \
         JOIN asm_hosts h ON h.id = sv.host_id \
         WHERE c.tenant_id = $1 AND h.scan_id = $2 ORDER BY c.id",
    )
    .bind(tenant)
    .bind(scan_id)
    .fetch_all(db)
    .await?)
}

fn cert_json(c: &CertRow) -> serde_json::Value {
    serde_json::json!({
        "id": c.id,
        "service_id": c.service_id,
        "subject": c.subject,
        "issuer": c.issuer,
        "not_before": skauswatch_streams::py_isoformat_opt(c.not_before),
        "not_after": skauswatch_streams::py_isoformat_opt(c.not_after),
        "is_expired": c.is_expired,
        "days_until_expiry": c.days_until_expiry,
        "sans": c.sans,
        "fingerprint_sha256": c.fingerprint_sha256,
    })
}

#[derive(sqlx::FromRow)]
struct DiffRow {
    id: i64,
    scan_id: i64,
    prev_scan_id: Option<i64>,
    new_services: Option<serde_json::Value>,
    removed_services: Option<serde_json::Value>,
    new_certs: Option<serde_json::Value>,
    expired_certs: Option<serde_json::Value>,
}

/// GET /asm/scans/{scan_id}/diff — diff vs the previous completed scan for
/// the same target (written by `services/scanner/src/asm.rs`).
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/diff",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Diff vs the previous scan (null if none computed yet)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_diff(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    fetch_scan(&state.db, user.tenant_id, scan_id).await?;
    let row = sqlx::query_as::<_, DiffRow>(
        "SELECT id, scan_id, prev_scan_id, new_services, removed_services, new_certs, \
         expired_certs FROM asm_diffs WHERE tenant_id = $1 AND scan_id = $2",
    )
    .bind(user.tenant_id)
    .bind(scan_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(Json(match row {
        Some(d) => serde_json::json!({
            "id": d.id,
            "scan_id": d.scan_id,
            "prev_scan_id": d.prev_scan_id,
            "new_services": d.new_services,
            "removed_services": d.removed_services,
            "new_certs": d.new_certs,
            "expired_certs": d.expired_certs,
        }),
        None => serde_json::Value::Null,
    }))
}

/// GET /asm/scans/{scan_id}/report — on-the-fly summary (hosts, services,
/// certs, diff). v1 generated a presigned URL to an S3-uploaded report
/// artifact; this deviates deliberately (no report-generation/upload
/// pipeline exists in v2) and returns the equivalent data inline as JSON
/// instead of a document to fetch.
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/report",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Full scan report (hosts, certs, diff summary)", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Scan not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_report(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scan = fetch_scan(&state.db, user.tenant_id, scan_id).await?;
    let hosts = fetch_hosts(&state.db, user.tenant_id, scan_id).await?;
    let mut host_entries = Vec::with_capacity(hosts.len());
    for h in &hosts {
        let services = fetch_services(&state.db, user.tenant_id, h.id).await?;
        host_entries.push(serde_json::json!({
            "id": h.id,
            "ip_address": h.ip_address,
            "hostname": h.hostname,
            "services": services.iter().map(service_json).collect::<Vec<_>>(),
        }));
    }
    let certs = fetch_certs(&state.db, user.tenant_id, scan_id).await?;
    let screenshots = fetch_screenshots(&state.db, user.tenant_id, scan_id).await?;
    let diff = sqlx::query_as::<_, DiffRow>(
        "SELECT id, scan_id, prev_scan_id, new_services, removed_services, new_certs, \
         expired_certs FROM asm_diffs WHERE tenant_id = $1 AND scan_id = $2",
    )
    .bind(user.tenant_id)
    .bind(scan_id)
    .fetch_optional(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "scan": scan_json(&scan),
        "hosts": host_entries,
        "certs": certs.iter().map(cert_json).collect::<Vec<_>>(),
        "screenshots": screenshots.iter().map(screenshot_json).collect::<Vec<_>>(),
        "diff": diff.map(|d| serde_json::json!({
            "prev_scan_id": d.prev_scan_id,
            "new_services": d.new_services,
            "removed_services": d.removed_services,
            "new_certs": d.new_certs,
            "expired_certs": d.expired_certs,
        })),
    })))
}

// ============================================
// Settings endpoints
// ============================================

const PORTS_SETTINGS_KEY: &str = "ports";

fn default_ports_settings() -> serde_json::Value {
    serde_json::json!({"extra_ports": [], "masscan_rate": DEFAULT_RATE})
}

/// GET /asm/settings/ports — any authenticated role; per-tenant, defaults
/// to `{extra_ports: [], masscan_rate: 1000}` when unset.
#[utoipa::path(
    get,
    path = "/api/v1/asm/settings/ports",
    tag = "asm",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Port configuration settings", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_port_settings(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let value: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT value FROM asm_settings WHERE tenant_id = $1 AND key = $2")
            .bind(user.tenant_id)
            .bind(PORTS_SETTINGS_KEY)
            .fetch_optional(&state.db)
            .await?;
    Ok(Json(value.map_or_else(default_ports_settings, |(v,)| v)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PortSettingsBody {
    extra_ports: Option<Vec<i64>>,
    masscan_rate: Option<i64>,
}

/// PUT /asm/settings/ports — admin only.
#[utoipa::path(
    put,
    path = "/api/v1/asm/settings/ports",
    tag = "asm",
    security(("bearer_jwt" = [])),
    request_body = PortSettingsBody,
    responses(
        (status = 200, description = "Updated port configuration settings", body = serde_json::Value),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_port_settings(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<PortSettingsBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_scope("asm:admin")?;
    let (extra_ports, rate) = validate_ports_config(&body.extra_ports, body.masscan_rate)?;
    let value = serde_json::json!({"extra_ports": extra_ports, "masscan_rate": rate});

    sqlx::query(
        "INSERT INTO asm_settings (tenant_id, key, value, updated_at, updated_by) \
         VALUES ($1, $2, $3, now(), $4) \
         ON CONFLICT (tenant_id, key) DO UPDATE SET value = $3, updated_at = now(), updated_by = $4",
    )
    .bind(user.tenant_id)
    .bind(PORTS_SETTINGS_KEY)
    .bind(&value)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    Ok(Json(value))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use crate::routes::test_support;

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    async fn server_and_state() -> (axum_test::TestServer, AppState) {
        let state = test_support::db_state(dev_license()).await;
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state.clone());
        (axum_test::TestServer::new(app), state)
    }

    // ---------- pure validator unit tests (no DB/HTTP) — every required
    // blocked range, v4 + v6, plus representative allowed public targets ----------

    #[test]
    fn blocks_aws_imds_link_local() {
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn blocks_v4_loopback() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918_ranges() {
        assert!(is_blocked_ip("10.1.2.3".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.31.255.254".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn blocks_unspecified_cgnat_and_multicast() {
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("100.127.255.254".parse().unwrap()));
        assert!(is_blocked_ip("224.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_v6_loopback_ula_link_local_multicast() {
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fd12:3456:789a::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("ff02::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_bypass_attempt() {
        assert!(is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn allows_representative_public_targets() {
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("203.0.113.5".parse().unwrap()));
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn blocks_cidr_inside_and_broader_than_blocked_ranges() {
        assert!(is_blocked_cidr("169.254.1.0".parse().unwrap(), 24));
        assert!(is_blocked_cidr("0.0.0.0".parse().unwrap(), 0));
        assert!(is_blocked_cidr("10.0.0.0".parse().unwrap(), 7));
    }

    #[test]
    fn allows_public_cidr() {
        assert!(!is_blocked_cidr("203.0.113.0".parse().unwrap(), 24));
        assert!(!is_blocked_cidr("2606:4700::".parse().unwrap(), 32));
    }

    #[test]
    fn validate_target_safety_rejects_blocked_and_accepts_public_and_domain() {
        assert!(validate_target_safety("169.254.169.254").is_err());
        assert!(validate_target_safety("10.0.0.0/8").is_err());
        assert!(validate_target_safety("203.0.113.5").is_ok());
        assert!(validate_target_safety("203.0.113.0/24").is_ok());
        // Domain forms are deferred, not resolved here — see the fn doc.
        assert!(validate_target_safety("scan-target.example").is_ok());
    }

    #[tokio::test]
    async fn all_routes_require_auth() {
        let (server, _state) = server_and_state().await;
        let cases = [
            ("GET", "/api/v1/asm/scans"),
            ("POST", "/api/v1/asm/scans"),
            ("GET", "/api/v1/asm/scans/1"),
            ("GET", "/api/v1/asm/scans/1/hosts"),
            ("GET", "/api/v1/asm/scans/1/screenshots"),
            ("GET", "/api/v1/asm/scans/1/certs"),
            ("GET", "/api/v1/asm/scans/1/diff"),
            ("GET", "/api/v1/asm/scans/1/report"),
            ("GET", "/api/v1/asm/settings/ports"),
            ("PUT", "/api/v1/asm/settings/ports"),
        ];
        for (m, p) in cases {
            let res = match m {
                "GET" => server.get(p).await,
                "POST" => server.post(p).await,
                "PUT" => server.put(p).await,
                other => panic!("unhandled method {other}"),
            };
            assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED, "{m} {p}");
        }
    }

    #[tokio::test]
    async fn create_scan_requires_admin_or_maintainer() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "viewer@example.com", "viewer").await;
        let res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"target": "10.0.0.0/24"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_scan_validates_missing_target() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "admin1@example.com", "admin").await;
        let res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&token)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["details"][0]["loc"], serde_json::json!(["target"]));
    }

    #[tokio::test]
    async fn create_scan_validates_bad_mode() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "admin2@example.com", "admin").await;
        let res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"target": "example.com", "mode": "bogus"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_scan_validates_out_of_range_port() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "admin3@example.com", "admin").await;
        let res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"target": "example.com", "extra_ports": [70000]}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    // ---------- SSRF hardening regression coverage (security review
    // finding: `target` reached masscan + headless Chromium with no block
    // on link-local/IMDS/loopback/RFC1918; see `validate_target_safety`'s
    // module doc) ----------

    #[tokio::test]
    async fn create_scan_rejects_link_local_metadata_target() {
        let (server, state) = server_and_state().await;
        let (_, token) =
            test_support::authed_user(&state, "admin-ssrf1@example.com", "admin").await;
        let res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"target": "169.254.169.254"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["details"][0]["loc"], serde_json::json!(["target"]));
    }

    #[tokio::test]
    async fn create_scan_rejects_private_cidr_target() {
        let (server, state) = server_and_state().await;
        let (_, token) =
            test_support::authed_user(&state, "admin-ssrf2@example.com", "admin").await;
        for target in ["10.0.0.0/8", "192.168.0.0/16", "0.0.0.0/0"] {
            let res = server
                .post("/api/v1/asm/scans")
                .authorization_bearer(&token)
                .json(&serde_json::json!({"target": target}))
                .await;
            res.assert_status(StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn create_scan_rejects_loopback_and_v6_targets() {
        let (server, state) = server_and_state().await;
        let (_, token) =
            test_support::authed_user(&state, "admin-ssrf3@example.com", "admin").await;
        for target in ["127.0.0.1", "::1", "fe80::1"] {
            let res = server
                .post("/api/v1/asm/scans")
                .authorization_bearer(&token)
                .json(&serde_json::json!({"target": target}))
                .await;
            res.assert_status(StatusCode::BAD_REQUEST);
        }
    }

    /// A domain-form target is accepted here — creation-time validation
    /// can't safely resolve DNS, so this is deferred to the scanner
    /// worker's post-resolution check (`target_safety::
    /// resolve_target_for_masscan`), which is the layer that actually
    /// closes the SSRF path for domains (see this module's SSRF section
    /// doc comment).
    #[tokio::test]
    async fn create_scan_accepts_domain_target_deferred_to_scanner() {
        let (server, state) = server_and_state().await;
        let (_, token) =
            test_support::authed_user(&state, "admin-ssrf4@example.com", "admin").await;
        let res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"target": "scan-target.example"}))
            .await;
        res.assert_status(StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_scan_persists_row_defaults_and_is_readable() {
        let (server, state) = server_and_state().await;
        let (_, token) =
            test_support::authed_user(&state, "admin4@example.com", "maintainer").await;
        let res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"target": "203.0.113.0/24"}))
            .await;
        res.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["target"], "203.0.113.0/24");
        assert_eq!(body["mode"], "external");
        assert_eq!(body["status"], "pending");
        assert_eq!(body["ports_config"]["rate"], 1000);
        let id = body["id"].as_i64().expect("id present");

        let get_res = server
            .get(&format!("/api/v1/asm/scans/{id}"))
            .authorization_bearer(&token)
            .await;
        get_res.assert_status_ok();
        let get_body: serde_json::Value = get_res.json();
        assert_eq!(get_body["target"], "203.0.113.0/24");
    }

    #[tokio::test]
    async fn get_scan_not_found_is_404() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "admin5@example.com", "admin").await;
        let res = server
            .get("/api/v1/asm/scans/999999")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn scans_are_isolated_by_tenant() {
        let (server, state) = server_and_state().await;
        let (_, admin_a) = test_support::authed_user(&state, "tena@example.com", "admin").await;
        let tenant_b = test_support::seed_tenant(&state.db, "asm-tenant-b").await;
        let (_, admin_b) =
            test_support::authed_user_in_tenant(&state, "tenb@example.com", "admin", tenant_b)
                .await;

        let create_res = server
            .post("/api/v1/asm/scans")
            .authorization_bearer(&admin_a)
            .json(&serde_json::json!({"target": "tenant-a-target.example"}))
            .await;
        create_res.assert_status(StatusCode::CREATED);
        let id = create_res.json::<serde_json::Value>()["id"]
            .as_i64()
            .expect("id present");

        // Tenant B cannot read tenant A's scan.
        let cross_res = server
            .get(&format!("/api/v1/asm/scans/{id}"))
            .authorization_bearer(&admin_b)
            .await;
        cross_res.assert_status(StatusCode::NOT_FOUND);

        // Tenant B's own list is empty.
        let list_res = server
            .get("/api/v1/asm/scans")
            .authorization_bearer(&admin_b)
            .await;
        list_res.assert_status_ok();
        let body: serde_json::Value = list_res.json();
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn hosts_screenshots_certs_diff_404_for_unknown_scan() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "admin6@example.com", "admin").await;
        for path in [
            "/api/v1/asm/scans/999999/hosts",
            "/api/v1/asm/scans/999999/screenshots",
            "/api/v1/asm/scans/999999/certs",
            "/api/v1/asm/scans/999999/diff",
            "/api/v1/asm/scans/999999/report",
        ] {
            let res = server.get(path).authorization_bearer(&token).await;
            res.assert_status(StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn hosts_endpoint_nests_services() {
        let (server, state) = server_and_state().await;
        let (uid, token) = test_support::authed_user(&state, "admin7@example.com", "admin").await;
        let tenant = test_support::default_tenant_id();

        let scan_id: i64 = sqlx::query_scalar(
            "INSERT INTO asm_scans (tenant_id, target, mode, status, created_by, created_at) \
             VALUES ($1, 'example.com', 'external', 'completed', $2, now()) RETURNING id",
        )
        .bind(tenant)
        .bind(uid)
        .fetch_one(&state.db)
        .await
        .expect("insert scan");

        let host_id: i64 = sqlx::query_scalar(
            "INSERT INTO asm_hosts (scan_id, tenant_id, ip_address, is_alive) \
             VALUES ($1, $2, '203.0.113.5', TRUE) RETURNING id",
        )
        .bind(scan_id)
        .bind(tenant)
        .fetch_one(&state.db)
        .await
        .expect("insert host");

        sqlx::query(
            "INSERT INTO asm_services (host_id, tenant_id, port, protocol, state, service_name) \
             VALUES ($1, $2, 443, 'tcp', 'open', 'https')",
        )
        .bind(host_id)
        .bind(tenant)
        .execute(&state.db)
        .await
        .expect("insert service");

        let res = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/hosts"))
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["hosts"][0]["ip_address"], "203.0.113.5");
        assert_eq!(body["hosts"][0]["services"][0]["port"], 443);
    }

    /// Seeds a full scan tree (scan → host → service → screenshot/cert) for
    /// the given tenant, returning `(scan_id, service_id)`.
    async fn seed_full_scan_tree(
        db: &sqlx::PgPool,
        tenant: Uuid,
        uid: i32,
        target: &str,
    ) -> (i64, i64) {
        let scan_id: i64 = sqlx::query_scalar(
            "INSERT INTO asm_scans (tenant_id, target, mode, status, created_by, created_at, \
             completed_at) VALUES ($1, $2, 'external', 'completed', $3, now(), now()) \
             RETURNING id",
        )
        .bind(tenant)
        .bind(target)
        .bind(uid)
        .fetch_one(db)
        .await
        .expect("insert scan");

        let host_id: i64 = sqlx::query_scalar(
            "INSERT INTO asm_hosts (scan_id, tenant_id, ip_address, is_alive) \
             VALUES ($1, $2, '203.0.113.9', TRUE) RETURNING id",
        )
        .bind(scan_id)
        .bind(tenant)
        .fetch_one(db)
        .await
        .expect("insert host");

        let service_id: i64 = sqlx::query_scalar(
            "INSERT INTO asm_services (host_id, tenant_id, port, protocol, state, service_name) \
             VALUES ($1, $2, 443, 'tcp', 'open', 'https') RETURNING id",
        )
        .bind(host_id)
        .bind(tenant)
        .fetch_one(db)
        .await
        .expect("insert service");

        sqlx::query(
            "INSERT INTO asm_screenshots (service_id, tenant_id, s3_key, tool, url) \
             VALUES ($1, $2, 'asm/shot.png', 'gowitness', 'https://example.invalid/shot.png')",
        )
        .bind(service_id)
        .bind(tenant)
        .execute(db)
        .await
        .expect("insert screenshot");

        sqlx::query(
            "INSERT INTO asm_certs (service_id, tenant_id, subject, issuer, is_expired, \
             fingerprint_sha256) VALUES ($1, $2, 'CN=example.com', 'CN=Test CA', FALSE, 'abc123')",
        )
        .bind(service_id)
        .bind(tenant)
        .execute(db)
        .await
        .expect("insert cert");

        (scan_id, service_id)
    }

    #[tokio::test]
    async fn screenshots_endpoint_returns_seeded_rows() {
        let (server, state) = server_and_state().await;
        let (uid, token) = test_support::authed_user(&state, "admin10@example.com", "admin").await;
        let tenant = test_support::default_tenant_id();
        let (scan_id, _) =
            seed_full_scan_tree(&state.db, tenant, uid, "screenshot-target.example").await;

        let res = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/screenshots"))
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["screenshots"][0]["s3_key"], "asm/shot.png");
        assert_eq!(body["screenshots"][0]["tool"], "gowitness");
    }

    #[tokio::test]
    async fn screenshots_endpoint_isolated_by_tenant() {
        let (server, state) = server_and_state().await;
        let (uid, token_a) =
            test_support::authed_user(&state, "shot-tena@example.com", "admin").await;
        let tenant_a = test_support::default_tenant_id();
        let (scan_id, _) =
            seed_full_scan_tree(&state.db, tenant_a, uid, "screenshot-isolation.example").await;

        let tenant_b = test_support::seed_tenant(&state.db, "asm-screenshot-tenant-b").await;
        let (_, token_b) =
            test_support::authed_user_in_tenant(&state, "shot-tenb@example.com", "admin", tenant_b)
                .await;

        // Tenant B cannot see tenant A's screenshot through the dedicated
        // endpoint — `fetch_scan`'s ownership check 404s before the
        // screenshot query ever runs.
        let cross_res = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/screenshots"))
            .authorization_bearer(&token_b)
            .await;
        cross_res.assert_status(StatusCode::NOT_FOUND);

        // Tenant A still sees its own screenshot, unaffected by tenant B's
        // scan being seeded in the same server/table.
        let own_res = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/screenshots"))
            .authorization_bearer(&token_a)
            .await;
        own_res.assert_status_ok();
        let body: serde_json::Value = own_res.json();
        assert_eq!(body["screenshots"][0]["s3_key"], "asm/shot.png");
    }

    #[tokio::test]
    async fn certs_endpoint_returns_seeded_rows() {
        let (server, state) = server_and_state().await;
        let (uid, token) = test_support::authed_user(&state, "admin11@example.com", "admin").await;
        let tenant = test_support::default_tenant_id();
        let (scan_id, _) =
            seed_full_scan_tree(&state.db, tenant, uid, "certs-target.example").await;

        let res = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/certs"))
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["certs"][0]["subject"], "CN=example.com");
        assert_eq!(body["certs"][0]["fingerprint_sha256"], "abc123");
        assert_eq!(body["certs"][0]["is_expired"], false);
    }

    #[tokio::test]
    async fn diff_endpoint_returns_null_when_no_diff_computed_then_the_row_once_seeded() {
        let (server, state) = server_and_state().await;
        let (uid, token) = test_support::authed_user(&state, "admin12@example.com", "admin").await;
        let tenant = test_support::default_tenant_id();
        let (scan_id, _) = seed_full_scan_tree(&state.db, tenant, uid, "diff-target.example").await;

        let before = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/diff"))
            .authorization_bearer(&token)
            .await;
        before.assert_status_ok();
        assert_eq!(before.json::<serde_json::Value>(), serde_json::Value::Null);

        sqlx::query(
            "INSERT INTO asm_diffs (scan_id, tenant_id, new_services, removed_services) \
             VALUES ($1, $2, $3::jsonb, '[]'::jsonb)",
        )
        .bind(scan_id)
        .bind(tenant)
        .bind(serde_json::json!([{"ip": "203.0.113.9", "port": 443}]))
        .execute(&state.db)
        .await
        .expect("insert diff");

        let after = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/diff"))
            .authorization_bearer(&token)
            .await;
        after.assert_status_ok();
        let body: serde_json::Value = after.json();
        assert_eq!(body["scan_id"], scan_id);
        assert_eq!(body["new_services"][0]["port"], 443);
    }

    #[tokio::test]
    async fn report_endpoint_aggregates_hosts_certs_and_screenshots() {
        let (server, state) = server_and_state().await;
        let (uid, token) = test_support::authed_user(&state, "admin13@example.com", "admin").await;
        let tenant = test_support::default_tenant_id();
        let (scan_id, _) =
            seed_full_scan_tree(&state.db, tenant, uid, "report-target.example").await;

        let res = server
            .get(&format!("/api/v1/asm/scans/{scan_id}/report"))
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["scan"]["target"], "report-target.example");
        assert_eq!(body["hosts"][0]["ip_address"], "203.0.113.9");
        assert_eq!(body["hosts"][0]["services"][0]["port"], 443);
        assert_eq!(body["certs"][0]["fingerprint_sha256"], "abc123");
        assert_eq!(body["screenshots"][0]["s3_key"], "asm/shot.png");
        assert_eq!(body["diff"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn list_scans_filters_by_target() {
        let (server, state) = server_and_state().await;
        let (uid, token) = test_support::authed_user(&state, "admin14@example.com", "admin").await;
        let tenant = test_support::default_tenant_id();
        seed_full_scan_tree(&state.db, tenant, uid, "filter-a.example").await;
        seed_full_scan_tree(&state.db, tenant, uid, "filter-b.example").await;

        let res = server
            .get("/api/v1/asm/scans?target=filter-a.example")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["total"], 1);
        assert_eq!(body["scans"][0]["target"], "filter-a.example");
    }

    #[tokio::test]
    async fn list_scans_unfiltered_paginates_across_all_targets() {
        let (server, state) = server_and_state().await;
        let (uid, token) = test_support::authed_user(&state, "admin15@example.com", "admin").await;
        let tenant = test_support::default_tenant_id();
        seed_full_scan_tree(&state.db, tenant, uid, "unfiltered-a.example").await;
        seed_full_scan_tree(&state.db, tenant, uid, "unfiltered-b.example").await;

        let res = server
            .get("/api/v1/asm/scans?page=1&per_page=1")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["per_page"], 1);
        assert!(body["total"].as_i64().unwrap_or(0) >= 2);
        assert_eq!(body["scans"].as_array().expect("array").len(), 1);
    }

    #[tokio::test]
    async fn port_settings_default_when_unset_then_updatable() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "admin8@example.com", "admin").await;

        let get_res = server
            .get("/api/v1/asm/settings/ports")
            .authorization_bearer(&token)
            .await;
        get_res.assert_status_ok();
        let body: serde_json::Value = get_res.json();
        assert_eq!(body["extra_ports"], serde_json::json!([]));
        assert_eq!(body["masscan_rate"], 1000);

        let put_res = server
            .put("/api/v1/asm/settings/ports")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"extra_ports": [8080, 8443], "masscan_rate": 500}))
            .await;
        put_res.assert_status_ok();

        let get2 = server
            .get("/api/v1/asm/settings/ports")
            .authorization_bearer(&token)
            .await;
        let body2: serde_json::Value = get2.json();
        assert_eq!(body2["extra_ports"], serde_json::json!([8080, 8443]));
        assert_eq!(body2["masscan_rate"], 500);
    }

    #[tokio::test]
    async fn port_settings_update_requires_admin() {
        let (server, state) = server_and_state().await;
        let (_, token) =
            test_support::authed_user(&state, "maintainer1@example.com", "maintainer").await;
        let res = server
            .put("/api/v1/asm/settings/ports")
            .authorization_bearer(&token)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn port_settings_validates_masscan_rate_range() {
        let (server, state) = server_and_state().await;
        let (_, token) = test_support::authed_user(&state, "admin9@example.com", "admin").await;
        let res = server
            .put("/api/v1/asm/settings/ports")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"masscan_rate": 0}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_ports_config_rejects_too_many_ports() {
        let ports: Vec<i64> = (1..=1001).collect();
        let err = validate_ports_config(&Some(ports), None).expect_err("should reject");
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn validate_ports_config_defaults_rate() {
        let (ports, rate) = validate_ports_config(&None, None).expect("ok");
        assert!(ports.is_empty());
        assert_eq!(rate, DEFAULT_RATE);
    }
}
