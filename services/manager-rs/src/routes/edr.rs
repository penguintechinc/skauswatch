//! /api/v1/edr — EDR agent surface (register, heartbeat, event ingest,
//! config) authenticated via HMAC headers, plus JWT-gated operator endpoints
//! (agent list/get/events/deactivate, statistics). Contract:
//! docs/v2-port/manager-contract.md §edr; Python source of truth:
//! services/manager/api/v1/edr.py (+ validators/pydantic_models.py EDR*).
//!
//! Port decisions (same conventions as routes/users.rs and routes/alerts.rs):
//! v1's bare `{"error": ...}` bodies map onto the `ApiError` envelope;
//! `page`/`per_page` are clamped to ≥1 (v1 divides by zero on per_page=0);
//! per-event error strings in POST /events are concise one-line summaries
//! rather than pydantic's multi-line `str(e)` dumps (diagnostics only, v1
//! never machine-parses them).

use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::{Postgres, QueryBuilder};

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::AppState;

/// v1 `EDRAgentStatus` enum values (order matters for statistics buckets).
const AGENT_STATUSES: [&str; 3] = ["active", "inactive", "disconnected"];
/// v1 `ThreatLevel` enum values accepted as event severity.
const THREAT_LEVELS: [&str; 5] = ["critical", "high", "medium", "low", "info"];
const AGENT_STATUS_MSG: &str = "Input should be 'active', 'inactive' or 'disconnected'";
const SEVERITY_MSG: &str = "Input should be 'critical', 'high', 'medium', 'low' or 'info'";

/// v1 `EDRConfig.api_secret` default (env `EDR_API_SECRET` unset).
const DEFAULT_EDR_SECRET: &str = "change-me-edr-secret";
/// v1 hard cap on POST /events batch size.
const MAX_EVENTS_PER_REQUEST: usize = 100;
/// v1 default collectors — `EDRConfig.enabled_collectors` has no env
/// override in `load_config`, so the default factory always applies.
const DEFAULT_COLLECTORS: [&str; 3] = ["process", "network", "file"];

const AGENT_COLUMNS: &str = "SELECT id, agent_id, hostname, ip_address, os_type, os_version, \
     agent_version, status, last_heartbeat::text, metadata, created_at::text, updated_at::text \
     FROM edr_agents WHERE TRUE";

/// Router for /api/v1/edr.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/edr/register", post(register_agent))
        .route("/edr/heartbeat", post(heartbeat))
        .route("/edr/events", post(report_events))
        .route("/edr/config", get(agent_config))
        .route("/edr/agents", get(list_agents))
        .route("/edr/agents/{agent_id}", get(get_agent))
        .route("/edr/agents/{agent_id}/events", get(get_agent_events))
        .route("/edr/agents/{agent_id}/deactivate", post(deactivate_agent))
        .route("/edr/statistics", get(get_statistics))
}

type HmacSha256 = Hmac<Sha256>;

/// v1 `config.edr.api_secret`: env `EDR_API_SECRET` with the change-me default.
fn edr_api_secret() -> String {
    std::env::var("EDR_API_SECRET").unwrap_or_else(|_| DEFAULT_EDR_SECRET.to_owned())
}

/// Lowercase hex encoding — matches Python's `hexdigest()`.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The API key v1 expects: hex HMAC-SHA256(secret, agent_id).
fn expected_api_key(secret: &str, agent_id: &str) -> Result<String, ApiError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| ApiError::internal("edr hmac key", e))?;
    mac.update(agent_id.as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

/// Constant-time string equality — the Rust analogue of v1's
/// `hmac.compare_digest` over the two hex digests (case-sensitive, like v1).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Authenticated EDR agent identity, extracted from `X-API-Key` +
/// `X-Agent-ID`. Mirrors v1's `verify_api_key` decorator; failure messages
/// carry the exact v1 strings inside the shared 401 envelope.
struct EdrAgent {
    /// Verified `X-Agent-ID` header value (v1 `g.agent_id`).
    agent_id: String,
}

impl<S: Send + Sync> FromRequestParts<S> for EdrAgent {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        // v1 truthiness: an empty header value counts as missing.
        let api_key = parts
            .headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty());
        let agent_id = parts
            .headers
            .get("x-agent-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty());
        let (Some(api_key), Some(agent_id)) = (api_key, agent_id) else {
            return Err(ApiError::Unauthorized(
                "Missing API key or Agent ID".to_owned(),
            ));
        };
        let expected = expected_api_key(&edr_api_secret(), agent_id)?;
        if !ct_eq(api_key, &expected) {
            return Err(ApiError::Unauthorized("Invalid API key".to_owned()));
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
        })
    }
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// pydantic-style string length check (character count, not bytes).
fn check_len(s: &str, field: &str, min: usize, max: usize) -> Result<(), ApiError> {
    let n = s.chars().count();
    if n < min {
        let unit = if min == 1 { "character" } else { "characters" };
        return Err(validation(
            field,
            &format!("String should have at least {min} {unit}"),
        ));
    }
    if n > max {
        return Err(validation(
            field,
            &format!("String should have at most {max} characters"),
        ));
    }
    Ok(())
}

fn required_str(
    v: &Option<String>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<String, ApiError> {
    let Some(s) = v else {
        return Err(validation(field, "Field required"));
    };
    check_len(s, field, min, max)?;
    Ok(s.clone())
}

/// Optional string with a pydantic max_length; `default` fills absence
/// (EDRAgentRegisterRequest fields all default to fixed strings).
fn defaulted_str(
    v: &Option<String>,
    field: &str,
    max: usize,
    default: &str,
) -> Result<String, ApiError> {
    match v {
        None => Ok(default.to_owned()),
        Some(s) => {
            check_len(s, field, 0, max)?;
            Ok(s.clone())
        }
    }
}

/// Optional metadata object — pydantic `Dict[str, Any]` defaulting to `{}`.
fn defaulted_object(
    v: &Option<serde_json::Value>,
    field: &str,
) -> Result<serde_json::Value, ApiError> {
    match v {
        None => Ok(serde_json::json!({})),
        Some(val) if val.is_object() => Ok(val.clone()),
        Some(_) => Err(validation(field, "Input should be a valid dictionary")),
    }
}

/// v1 pages math: `(total + per_page - 1) // per_page` (per_page ≥ 1).
fn total_pages(total: i64, per_page: i64) -> i64 {
    (total + per_page - 1) / per_page
}

/// Quart `request.args` semantics for page/per_page: first value wins,
/// unparsable ints fall back to the default. Deviation: clamped ≥1 (v1
/// divides by zero on per_page=0).
fn parse_page_params(
    pairs: &[(String, String)],
    default_per_page: i64,
    max_per_page: i64,
) -> (i64, i64) {
    let first = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let page = first("page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = first("per_page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default_per_page)
        .clamp(1, max_per_page);
    (page, per_page)
}

/// Python `datetime.utcnow().isoformat()` — naive UTC with microseconds.
fn utcnow_isoformat() -> String {
    Utc::now()
        .naive_utc()
        .format("%Y-%m-%dT%H:%M:%S%.6f")
        .to_string()
}

/// EDRAgentRegisterRequest — fields optional here so missing ones map to the
/// validation envelope instead of an axum extractor rejection.
#[derive(Deserialize)]
struct RegisterBody {
    agent_id: Option<String>,
    hostname: Option<String>,
    ip_address: Option<String>,
    os_type: Option<String>,
    os_version: Option<String>,
    agent_version: Option<String>,
    metadata: Option<serde_json::Value>,
}

struct ValidRegister {
    agent_id: String,
    hostname: String,
    ip_address: String,
    os_type: String,
    os_version: String,
    agent_version: String,
    metadata: serde_json::Value,
}

/// Mirrors pydantic EDRAgentRegisterRequest: agent_id 1-128 and hostname /
/// agent_version required; ip_address/os_type/os_version default to
/// ""/"unknown"/""; metadata is an object defaulting to `{}`.
fn validate_register(b: &RegisterBody) -> Result<ValidRegister, ApiError> {
    Ok(ValidRegister {
        agent_id: required_str(&b.agent_id, "agent_id", 1, 128)?,
        hostname: required_str(&b.hostname, "hostname", 0, 255)?,
        ip_address: defaulted_str(&b.ip_address, "ip_address", 45, "")?,
        os_type: defaulted_str(&b.os_type, "os_type", 50, "unknown")?,
        os_version: defaulted_str(&b.os_version, "os_version", 100, "")?,
        agent_version: required_str(&b.agent_version, "agent_version", 0, 32)?,
        metadata: defaulted_object(&b.metadata, "metadata")?,
    })
}

/// POST /edr/register — HMAC agent auth. Re-registers (200) when the body's
/// agent_id already exists (full field overwrite, metadata replaced), else
/// inserts a new active agent (201). v1 keys off the BODY agent_id, which
/// need not match the authenticated X-Agent-ID — preserved as-is.
async fn register_agent(
    State(state): State<AppState>,
    _agent: EdrAgent,
    Json(body): Json<RegisterBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let v = validate_register(&body)?;

    let existing: Option<(i32,)> = sqlx::query_as("SELECT id FROM edr_agents WHERE agent_id = $1")
        .bind(&v.agent_id)
        .fetch_optional(&state.db)
        .await?;

    if existing.is_some() {
        // pyDAL sets updated_at automatically on every update (update=utcnow).
        sqlx::query(
            "UPDATE edr_agents SET hostname = $1, ip_address = $2, os_type = $3, \
             os_version = $4, agent_version = $5, status = 'active', \
             last_heartbeat = now(), metadata = $6, updated_at = now() \
             WHERE agent_id = $7",
        )
        .bind(&v.hostname)
        .bind(&v.ip_address)
        .bind(&v.os_type)
        .bind(&v.os_version)
        .bind(&v.agent_version)
        .bind(&v.metadata)
        .bind(&v.agent_id)
        .execute(&state.db)
        .await?;

        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "Agent re-registered",
                "agent_id": v.agent_id,
                "status": "active",
            })),
        ));
    }

    sqlx::query(
        "INSERT INTO edr_agents (agent_id, hostname, ip_address, os_type, os_version, \
         agent_version, status, last_heartbeat, metadata, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'active', now(), $7, now())",
    )
    .bind(&v.agent_id)
    .bind(&v.hostname)
    .bind(&v.ip_address)
    .bind(&v.os_type)
    .bind(&v.os_version)
    .bind(&v.agent_version)
    .bind(&v.metadata)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Agent registered successfully",
            "agent_id": v.agent_id,
            "status": "active",
        })),
    ))
}

/// EDRHeartbeatRequest — status defaults to "active", metadata to `{}`.
#[derive(Deserialize)]
struct HeartbeatBody {
    agent_id: Option<String>,
    status: Option<String>,
    metadata: Option<serde_json::Value>,
}

struct ValidHeartbeat {
    agent_id: String,
    status: String,
    metadata: serde_json::Value,
}

/// Mirrors pydantic EDRHeartbeatRequest validation.
fn validate_heartbeat(b: &HeartbeatBody) -> Result<ValidHeartbeat, ApiError> {
    let agent_id = required_str(&b.agent_id, "agent_id", 1, 128)?;
    let status = match b.status.as_deref() {
        None => "active".to_owned(),
        Some(s) if AGENT_STATUSES.contains(&s) => s.to_owned(),
        Some(_) => return Err(validation("status", AGENT_STATUS_MSG)),
    };
    Ok(ValidHeartbeat {
        agent_id,
        status,
        metadata: defaulted_object(&b.metadata, "metadata")?,
    })
}

/// POST /edr/heartbeat — HMAC agent auth. Updates status + last_heartbeat and
/// merges the payload metadata over the stored metadata (new keys win),
/// exactly like v1's `{**old, **new}`.
async fn heartbeat(
    State(state): State<AppState>,
    _agent: EdrAgent,
    Json(body): Json<HeartbeatBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let v = validate_heartbeat(&body)?;

    let existing: Option<(i32,)> = sqlx::query_as("SELECT id FROM edr_agents WHERE agent_id = $1")
        .bind(&v.agent_id)
        .fetch_optional(&state.db)
        .await?;
    if existing.is_none() {
        return Err(ApiError::NotFound("Agent not registered".to_owned()));
    }

    sqlx::query(
        "UPDATE edr_agents SET status = $1, last_heartbeat = now(), \
         metadata = COALESCE(metadata, '{}'::jsonb) || $2, updated_at = now() \
         WHERE agent_id = $3",
    )
    .bind(&v.status)
    .bind(&v.metadata)
    .bind(&v.agent_id)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "agent_id": v.agent_id,
        "timestamp": utcnow_isoformat(),
    })))
}

/// One parsed event from the POST /events payload, ready to insert.
struct EventInsert {
    agent_id: String,
    event_type: String,
    severity: Option<String>,
    process_name: Option<String>,
    process_path: Option<String>,
    process_hash: Option<String>,
    parent_process: Option<String>,
    command_line: Option<String>,
    network_connections: Option<serde_json::Value>,
    file_operations: Option<serde_json::Value>,
    registry_operations: Option<serde_json::Value>,
    details: serde_json::Value,
}

/// Optional string field lookup for event parsing — JSON null and absence
/// both mean None; non-string values are a type error.
fn event_str(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    max: Option<usize>,
) -> Result<Option<String>, String> {
    match obj.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            if let Some(max) = max
                && s.chars().count() > max
            {
                return Err(format!(
                    "{field}: String should have at most {max} characters"
                ));
            }
            Ok(Some(s.clone()))
        }
        Some(_) => Err(format!("{field}: Input should be a valid string")),
    }
}

/// Optional list-of-objects field (pydantic `List[Dict[str, Any]]`).
fn event_dict_list(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<serde_json::Value>, String> {
    match obj.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(items)) => {
            if items.iter().any(|i| !i.is_object()) {
                return Err(format!("{field}: Input should be a valid dictionary"));
            }
            Ok(Some(serde_json::Value::Array(items.clone())))
        }
        Some(_) => Err(format!("{field}: Input should be a valid list")),
    }
}

/// Validates one raw event against pydantic EDREventRequest. Error strings
/// are concise one-liners (documented deviation from pydantic's `str(e)`).
fn parse_event(raw: &serde_json::Value) -> Result<EventInsert, String> {
    let Some(obj) = raw.as_object() else {
        return Err("event must be a JSON object".to_owned());
    };
    let agent_id = match event_str(obj, "agent_id", Some(128))? {
        Some(s) if !s.is_empty() => s,
        Some(_) => return Err("agent_id: String should have at least 1 character".to_owned()),
        None => return Err("agent_id: Field required".to_owned()),
    };
    let event_type = match event_str(obj, "event_type", Some(64))? {
        Some(s) if !s.is_empty() => s,
        Some(_) => return Err("event_type: String should have at least 1 character".to_owned()),
        None => return Err("event_type: Field required".to_owned()),
    };
    let severity = match event_str(obj, "severity", None)? {
        None => None,
        Some(s) if THREAT_LEVELS.contains(&s.as_str()) => Some(s),
        Some(_) => return Err(format!("severity: {SEVERITY_MSG}")),
    };
    let details = match obj.get("details") {
        None | Some(serde_json::Value::Null) => serde_json::json!({}),
        Some(v) if v.is_object() => v.clone(),
        Some(_) => return Err("details: Input should be a valid dictionary".to_owned()),
    };
    Ok(EventInsert {
        agent_id,
        event_type,
        severity,
        process_name: event_str(obj, "process_name", Some(255))?,
        process_path: event_str(obj, "process_path", None)?,
        process_hash: event_str(obj, "process_hash", Some(128))?,
        parent_process: event_str(obj, "parent_process", Some(255))?,
        command_line: event_str(obj, "command_line", None)?,
        network_connections: event_dict_list(obj, "network_connections")?,
        file_operations: event_dict_list(obj, "file_operations")?,
        registry_operations: event_dict_list(obj, "registry_operations")?,
        details,
    })
}

/// Checks the event's agent exists then inserts it. `Ok(false)` = agent not
/// registered (v1 skips the event with an error entry, not a 404).
async fn store_event(db: &sqlx::PgPool, ev: &EventInsert) -> Result<bool, sqlx::Error> {
    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM edr_agents WHERE agent_id = $1")
        .bind(&ev.agent_id)
        .fetch_optional(db)
        .await?;
    if exists.is_none() {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO edr_events (agent_id, event_type, severity, process_name, process_path, \
         process_hash, parent_process, command_line, network_connections, file_operations, \
         registry_operations, details, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())",
    )
    .bind(&ev.agent_id)
    .bind(&ev.event_type)
    .bind(&ev.severity)
    .bind(&ev.process_name)
    .bind(&ev.process_path)
    .bind(&ev.process_hash)
    .bind(&ev.parent_process)
    .bind(&ev.command_line)
    .bind(&ev.network_connections)
    .bind(&ev.file_operations)
    .bind(&ev.registry_operations)
    .bind(&ev.details)
    .execute(db)
    .await?;
    Ok(true)
}

/// POST /edr/events — HMAC agent auth. Accepts a single event object or a
/// batch (≤100); always 202 with per-item errors capped at 10 — v1 swallows
/// per-event DB failures into the errors list too.
async fn report_events(
    State(state): State<AppState>,
    _agent: EdrAgent,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let data: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("Invalid JSON body".to_owned()))?;
    let events: Vec<serde_json::Value> = match data {
        serde_json::Value::Array(items) => items,
        other => vec![other],
    };
    if events.len() > MAX_EVENTS_PER_REQUEST {
        return Err(ApiError::BadRequest(
            "Maximum 100 events per request".to_owned(),
        ));
    }

    let mut stored: i64 = 0;
    let mut errors: Vec<serde_json::Value> = Vec::new();
    for (idx, raw) in events.iter().enumerate() {
        match parse_event(raw) {
            Err(msg) => errors.push(serde_json::json!({"index": idx, "error": msg})),
            Ok(ev) => match store_event(&state.db, &ev).await {
                Ok(true) => stored += 1,
                Ok(false) => {
                    errors.push(serde_json::json!({"index": idx, "error": "Agent not registered"}));
                }
                Err(e) => {
                    errors.push(serde_json::json!({"index": idx, "error": e.to_string()}));
                }
            },
        }
    }

    // TODO(streams): publish edr:events batch summary — wired with
    // skauswatch-streams integration. Fields per contract:
    // {agent_id, events_count, severity, submitted_at}. NB v1's max-severity
    // expression iterates raw dicts (no .severity attr) so it always
    // publishes "low" — replicate when wiring.

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "accepted",
            "events_received": events.len(),
            "events_stored": stored,
            "errors": errors.into_iter().take(10).collect::<Vec<_>>(),
        })),
    ))
}

/// Pure helper for env-int parsing (v1 `int(os.getenv(...))` defaults).
fn parse_env_i64(raw: Option<&str>, default: i64) -> i64 {
    raw.and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_i64(name: &str, default: i64) -> i64 {
    parse_env_i64(std::env::var(name).ok().as_deref(), default)
}

/// GET /edr/config — HMAC agent auth. Returns per-agent config: metadata
/// overrides layered over the env-derived EDRConfig defaults, mirroring v1's
/// `agent_config.get(key, config.edr.<key>)`.
async fn agent_config(
    State(state): State<AppState>,
    agent: EdrAgent,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row: Option<(Option<serde_json::Value>,)> =
        sqlx::query_as("SELECT metadata FROM edr_agents WHERE agent_id = $1")
            .bind(&agent.agent_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((metadata,)) = row else {
        return Err(ApiError::NotFound("Agent not registered".to_owned()));
    };
    let meta = metadata.unwrap_or_else(|| serde_json::json!({}));
    let over = |key: &str, default: serde_json::Value| meta.get(key).cloned().unwrap_or(default);
    let severity_threshold =
        std::env::var("EDR_SEVERITY_THRESHOLD").unwrap_or_else(|_| "low".to_owned());

    Ok(Json(serde_json::json!({
        "agent_id": agent.agent_id,
        "config": {
            "reporting_interval": over(
                "reporting_interval",
                env_i64("EDR_REPORTING_INTERVAL", 60).into(),
            ),
            "heartbeat_interval": over(
                "heartbeat_interval",
                env_i64("EDR_HEARTBEAT_INTERVAL", 30).into(),
            ),
            "event_batch_size": over(
                "event_batch_size",
                env_i64("EDR_EVENT_BATCH_SIZE", 50).into(),
            ),
            "enabled_collectors": over(
                "enabled_collectors",
                serde_json::json!(DEFAULT_COLLECTORS),
            ),
            "severity_threshold": over("severity_threshold", severity_threshold.into()),
        },
    })))
}

/// Full agent row (list/get endpoints) — jsonb metadata as
/// `serde_json::Value`, timestamps as Postgres text.
#[derive(sqlx::FromRow)]
struct AgentRow {
    id: i32,
    agent_id: String,
    hostname: Option<String>,
    ip_address: Option<String>,
    os_type: Option<String>,
    os_version: Option<String>,
    agent_version: Option<String>,
    status: Option<String>,
    last_heartbeat: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// v1 list-item shape (GET /edr/agents) — no metadata / updated_at.
fn agent_list_json(r: &AgentRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "agent_id": r.agent_id,
        "hostname": r.hostname,
        "ip_address": r.ip_address,
        "os_type": r.os_type,
        "os_version": r.os_version,
        "agent_version": r.agent_version,
        "status": r.status,
        "last_heartbeat": r.last_heartbeat,
        "created_at": r.created_at,
    })
}

/// GET /edr/agents — JWT, admin/maintainer. Filters: repeated `status` keys
/// and a single `os_type`; ordered by last_heartbeat DESC; standard
/// pagination envelope (per_page default 20, cap 100).
async fn list_agents(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;

    let (page, per_page) = parse_page_params(&params, 20, 100);
    let status: Vec<String> = params
        .iter()
        .filter(|(k, _)| k == "status")
        .map(|(_, v)| v.clone())
        .collect();
    let os_type = params
        .iter()
        .find(|(k, _)| k == "os_type")
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty());

    let push_filters = |qb: &mut QueryBuilder<Postgres>| {
        if !status.is_empty() {
            qb.push(" AND status = ANY(")
                .push_bind(status.clone())
                .push(")");
        }
        if let Some(os) = &os_type {
            qb.push(" AND os_type = ").push_bind(os.clone());
        }
    };

    let mut qb = QueryBuilder::new(AGENT_COLUMNS);
    push_filters(&mut qb);
    qb.push(" ORDER BY last_heartbeat DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind((page - 1) * per_page);
    let rows = qb.build_query_as::<AgentRow>().fetch_all(&state.db).await?;

    let mut cq = QueryBuilder::new("SELECT COUNT(*) FROM edr_agents WHERE TRUE");
    push_filters(&mut cq);
    let total: i64 = cq.build_query_scalar().fetch_one(&state.db).await?;

    let items: Vec<serde_json::Value> = rows.iter().map(agent_list_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages(total, per_page),
    })))
}

/// GET /edr/agents/{agent_id} — JWT (any role). Full agent detail including
/// metadata (`{}` for null, v1 `agent.metadata or {}`) and updated_at.
async fn get_agent(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut qb = QueryBuilder::new(AGENT_COLUMNS);
    qb.push(" AND agent_id = ").push_bind(&agent_id);
    let row = qb
        .build_query_as::<AgentRow>()
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Agent not found".to_owned()))?;

    let metadata = match &row.metadata {
        Some(v) if !v.is_null() => v.clone(),
        _ => serde_json::json!({}),
    };
    Ok(Json(serde_json::json!({
        "id": row.id,
        "agent_id": row.agent_id,
        "hostname": row.hostname,
        "ip_address": row.ip_address,
        "os_type": row.os_type,
        "os_version": row.os_version,
        "agent_version": row.agent_version,
        "status": row.status,
        "last_heartbeat": row.last_heartbeat,
        "metadata": metadata,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })))
}

/// Event row subset for GET /edr/agents/{id}/events.
#[derive(sqlx::FromRow)]
struct EventRow {
    id: i32,
    event_type: String,
    severity: Option<String>,
    process_name: Option<String>,
    process_path: Option<String>,
    command_line: Option<String>,
    created_at: Option<String>,
}

/// GET /edr/agents/{agent_id}/events — JWT (any role). Paginated events for
/// one agent, newest first (per_page default 50, cap 200).
async fn get_agent_events(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(agent_id): Path<String>,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM edr_agents WHERE agent_id = $1")
        .bind(&agent_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Agent not found".to_owned()));
    }

    let (page, per_page) = parse_page_params(&params, 50, 200);
    let rows = sqlx::query_as::<_, EventRow>(
        "SELECT id, event_type, severity, process_name, process_path, command_line, \
         created_at::text FROM edr_events WHERE agent_id = $1 \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&agent_id)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.db)
    .await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edr_events WHERE agent_id = $1")
        .bind(&agent_id)
        .fetch_one(&state.db)
        .await?;

    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "process_name": e.process_name,
                "process_path": e.process_path,
                "command_line": e.command_line,
                "created_at": e.created_at,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages(total, per_page),
    })))
}

/// POST /edr/agents/{agent_id}/deactivate — JWT, admin only. Sets the agent
/// status to inactive (pyDAL also bumps updated_at).
async fn deactivate_agent(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin"])?;

    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM edr_agents WHERE agent_id = $1")
        .bind(&agent_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Agent not found".to_owned()));
    }

    sqlx::query(
        "UPDATE edr_agents SET status = 'inactive', updated_at = now() WHERE agent_id = $1",
    )
    .bind(&agent_id)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "message": "Agent deactivated",
        "agent_id": agent_id,
    })))
}

/// Builds a `{value: count}` object covering every canonical key,
/// zero-filled — matches v1's per-status COUNT loop.
fn bucket_counts(keys: &[&str], rows: &[(Option<String>, i64)]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for k in keys {
        let n = rows
            .iter()
            .find(|(key, _)| key.as_deref() == Some(*k))
            .map_or(0, |(_, n)| *n);
        map.insert((*k).to_owned(), serde_json::Value::from(n));
    }
    serde_json::Value::Object(map)
}

/// GET /edr/statistics — JWT (any role). Agent counts by status/OS, stale
/// agents (active with no heartbeat for 5 min), and event totals. v1 skips
/// falsy os_type values (NULL and "") in agents_by_os.
async fn get_statistics(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let total_agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edr_agents")
        .fetch_one(&state.db)
        .await?;
    let status_rows: Vec<(Option<String>, i64)> =
        sqlx::query_as("SELECT status, COUNT(*) FROM edr_agents GROUP BY status")
            .fetch_all(&state.db)
            .await?;
    let os_rows: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT os_type, COUNT(*) FROM edr_agents \
         WHERE os_type IS NOT NULL AND os_type <> '' GROUP BY os_type",
    )
    .fetch_all(&state.db)
    .await?;
    let mut agents_by_os = serde_json::Map::new();
    for (os, n) in &os_rows {
        if let Some(os) = os {
            agents_by_os.insert(os.clone(), serde_json::Value::from(*n));
        }
    }

    let stale_cutoff = Utc::now().naive_utc() - chrono::Duration::minutes(5);
    let stale_agents: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edr_agents WHERE status = 'active' AND last_heartbeat < $1",
    )
    .bind(stale_cutoff)
    .fetch_one(&state.db)
    .await?;

    let total_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edr_events")
        .fetch_one(&state.db)
        .await?;
    let cutoff_24h = Utc::now().naive_utc() - chrono::Duration::days(1);
    let events_last_24h: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM edr_events WHERE created_at >= $1")
            .bind(cutoff_24h)
            .fetch_one(&state.db)
            .await?;

    Ok(Json(serde_json::json!({
        "total_agents": total_agents,
        "agents_by_status": bucket_counts(&AGENT_STATUSES, &status_rows),
        "agents_by_os": serde_json::Value::Object(agents_by_os),
        "stale_agents": stale_agents,
        "total_events": total_events,
        "events_last_24h": events_last_24h,
    })))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    /// Test server mounting only this router under /api/v1 (no live DB —
    /// handlers that reach the pool fail, auth/validation paths don't).
    fn test_server() -> axum_test::TestServer {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("client: {e}"),
        };
        let state = AppStateInner::for_tests(client);
        let app = axum::Router::new()
            .nest("/api/v1", super::router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    fn valid_key(agent_id: &str) -> String {
        match expected_api_key(DEFAULT_EDR_SECRET, agent_id) {
            Ok(k) => k,
            Err(e) => panic!("hmac: {e:?}"),
        }
    }

    #[test]
    fn hmac_matches_python_hexdigest_vector() {
        // hmac.new(b"change-me-edr-secret", b"agent-001", sha256).hexdigest()
        assert_eq!(
            valid_key("agent-001"),
            "2e3bdc4edea1fa9037414810457dcbf75fa025b654ceffcbc0cf2a98fcbb9e40"
        );
    }

    #[test]
    fn ct_eq_compares_like_compare_digest() {
        assert!(ct_eq("abc123", "abc123"));
        assert!(!ct_eq("abc123", "abc124"));
        assert!(!ct_eq("abc", "abc123")); // length mismatch
        assert!(!ct_eq("ABC123", "abc123")); // case-sensitive, like v1
    }

    #[tokio::test]
    async fn missing_hmac_headers_rejected_401() {
        let server = test_server();
        let res = server
            .post("/api/v1/edr/register")
            .json(&serde_json::json!({"agent_id": "a1"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Unauthorized");
        assert_eq!(body["detail"], "Missing API key or Agent ID");

        // One header present, the other missing — still the same rejection.
        let res = server
            .post("/api/v1/edr/heartbeat")
            .add_header("X-Agent-ID", "agent-001")
            .json(&serde_json::json!({"agent_id": "agent-001"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["detail"], "Missing API key or Agent ID");
    }

    #[tokio::test]
    async fn bad_hmac_key_rejected_401() {
        let server = test_server();
        let res = server
            .post("/api/v1/edr/events")
            .add_header("X-Agent-ID", "agent-001")
            .add_header("X-API-Key", "deadbeef")
            .json(&serde_json::json!([]))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Unauthorized");
        assert_eq!(body["detail"], "Invalid API key");
    }

    #[tokio::test]
    async fn valid_hmac_reaches_validation_layer() {
        let server = test_server();
        // Auth passes (no 401); body missing agent_id → pydantic-style 400.
        let res = server
            .post("/api/v1/edr/register")
            .add_header("X-Agent-ID", "agent-001")
            .add_header("X-API-Key", valid_key("agent-001"))
            .json(&serde_json::json!({"hostname": "h1", "agent_version": "1.0"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Validation error");
        assert_eq!(body["details"][0]["loc"], serde_json::json!(["agent_id"]));
        assert_eq!(body["details"][0]["msg"], "Field required");
    }

    #[tokio::test]
    async fn events_batch_over_100_rejected_400() {
        let server = test_server();
        let batch: Vec<serde_json::Value> = (0..101)
            .map(|i| serde_json::json!({"agent_id": "a", "event_type": format!("e{i}")}))
            .collect();
        let res = server
            .post("/api/v1/edr/events")
            .add_header("X-Agent-ID", "agent-001")
            .add_header("X-API-Key", valid_key("agent-001"))
            .json(&batch)
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Bad Request");
        assert_eq!(body["detail"], "Maximum 100 events per request");
    }

    #[tokio::test]
    async fn events_invalid_items_accepted_202_with_errors() {
        let server = test_server();
        // Single non-list object with a validation failure — 202 envelope,
        // stored=0, error entry indexed 0 (no DB touched on invalid items).
        let res = server
            .post("/api/v1/edr/events")
            .add_header("X-Agent-ID", "agent-001")
            .add_header("X-API-Key", valid_key("agent-001"))
            .json(&serde_json::json!({"agent_id": "agent-001"}))
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["status"], "accepted");
        assert_eq!(body["events_received"], 1);
        assert_eq!(body["events_stored"], 0);
        assert_eq!(body["errors"][0]["index"], 0);
        assert_eq!(body["errors"][0]["error"], "event_type: Field required");
    }

    #[tokio::test]
    async fn operator_endpoints_require_jwt() {
        let server = test_server();
        for path in [
            "/api/v1/edr/agents",
            "/api/v1/edr/agents/agent-001",
            "/api/v1/edr/agents/agent-001/events",
            "/api/v1/edr/statistics",
        ] {
            let res = server.get(path).await;
            res.assert_status(StatusCode::UNAUTHORIZED);
            let body: serde_json::Value = res.json();
            assert_eq!(body["error"], "Unauthorized");
            assert_eq!(body["detail"], "Missing authorization header");
        }
        let res = server.post("/api/v1/edr/agents/agent-001/deactivate").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn validate_register_applies_v1_defaults() {
        let body = RegisterBody {
            agent_id: Some("agent-001".to_owned()),
            hostname: Some("host-1".to_owned()),
            ip_address: None,
            os_type: None,
            os_version: None,
            agent_version: Some("1.2.3".to_owned()),
            metadata: None,
        };
        let v = match validate_register(&body) {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(v.ip_address, "");
        assert_eq!(v.os_type, "unknown");
        assert_eq!(v.os_version, "");
        assert_eq!(v.metadata, serde_json::json!({}));
    }

    #[test]
    fn validate_register_bounds_and_metadata_type() {
        let base = RegisterBody {
            agent_id: Some("agent-001".to_owned()),
            hostname: Some("host-1".to_owned()),
            ip_address: None,
            os_type: None,
            os_version: None,
            agent_version: Some("1.2.3".to_owned()),
            metadata: None,
        };
        let long_id = RegisterBody {
            agent_id: Some("x".repeat(129)),
            ..clone_register(&base)
        };
        assert!(matches!(
            validate_register(&long_id),
            Err(ApiError::Validation(_))
        ));
        let empty_id = RegisterBody {
            agent_id: Some(String::new()),
            ..clone_register(&base)
        };
        assert!(matches!(
            validate_register(&empty_id),
            Err(ApiError::Validation(_))
        ));
        let bad_meta = RegisterBody {
            metadata: Some(serde_json::json!([1, 2])),
            ..clone_register(&base)
        };
        assert!(matches!(
            validate_register(&bad_meta),
            Err(ApiError::Validation(_))
        ));
        let no_version = RegisterBody {
            agent_version: None,
            ..clone_register(&base)
        };
        assert!(matches!(
            validate_register(&no_version),
            Err(ApiError::Validation(_))
        ));
    }

    fn clone_register(b: &RegisterBody) -> RegisterBody {
        RegisterBody {
            agent_id: b.agent_id.clone(),
            hostname: b.hostname.clone(),
            ip_address: b.ip_address.clone(),
            os_type: b.os_type.clone(),
            os_version: b.os_version.clone(),
            agent_version: b.agent_version.clone(),
            metadata: b.metadata.clone(),
        }
    }

    #[test]
    fn validate_heartbeat_defaults_and_enum() {
        let ok = HeartbeatBody {
            agent_id: Some("agent-001".to_owned()),
            status: None,
            metadata: None,
        };
        match validate_heartbeat(&ok) {
            Ok(v) => {
                assert_eq!(v.status, "active");
                assert_eq!(v.metadata, serde_json::json!({}));
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        let bad = HeartbeatBody {
            agent_id: Some("agent-001".to_owned()),
            status: Some("rebooting".to_owned()),
            metadata: None,
        };
        match validate_heartbeat(&bad) {
            Err(ApiError::Validation(details)) => {
                assert_eq!(details[0]["msg"], AGENT_STATUS_MSG);
            }
            Err(e) => panic!("expected validation error, got {e:?}"),
            Ok(_) => panic!("expected validation error, got ok"),
        }
    }

    #[test]
    fn parse_event_happy_path_and_failures() {
        let full = serde_json::json!({
            "agent_id": "agent-001",
            "event_type": "process_start",
            "severity": "high",
            "process_name": "evil.exe",
            "network_connections": [{"dst": "1.2.3.4"}],
            "details": {"pid": 1234},
        });
        let ev = match parse_event(&full) {
            Ok(ev) => ev,
            Err(e) => panic!("expected ok, got {e}"),
        };
        assert_eq!(ev.severity.as_deref(), Some("high"));
        assert_eq!(ev.details, serde_json::json!({"pid": 1234}));
        assert!(ev.process_hash.is_none());

        let parse_err = |v: serde_json::Value| match parse_event(&v) {
            Err(e) => e,
            Ok(_) => panic!("expected error for {v}"),
        };
        assert_eq!(
            parse_err(serde_json::json!(5)),
            "event must be a JSON object"
        );
        assert_eq!(
            parse_err(serde_json::json!({"event_type": "x"})),
            "agent_id: Field required"
        );
        assert_eq!(
            parse_err(serde_json::json!({
                "agent_id": "a", "event_type": "x", "severity": "apocalyptic"
            })),
            format!("severity: {SEVERITY_MSG}")
        );
        assert_eq!(
            parse_err(serde_json::json!({
                "agent_id": "a", "event_type": "x", "network_connections": [1]
            })),
            "network_connections: Input should be a valid dictionary"
        );
        assert_eq!(
            parse_err(serde_json::json!({
                "agent_id": "a", "event_type": "x", "details": []
            })),
            "details: Input should be a valid dictionary"
        );
    }

    #[test]
    fn page_params_match_quart_semantics() {
        let pairs = vec![
            ("page".to_owned(), "2".to_owned()),
            ("page".to_owned(), "9".to_owned()),
            ("per_page".to_owned(), "500".to_owned()),
        ];
        assert_eq!(parse_page_params(&pairs, 20, 100), (2, 100));
        assert_eq!(parse_page_params(&pairs, 50, 200), (2, 200));
        let garbage = vec![("page".to_owned(), "abc".to_owned())];
        assert_eq!(parse_page_params(&garbage, 50, 200), (1, 50));
        assert_eq!(parse_page_params(&[], 20, 100), (1, 20));
    }

    #[test]
    fn misc_helpers_match_v1() {
        assert_eq!(total_pages(0, 20), 0);
        assert_eq!(total_pages(101, 20), 6);
        assert_eq!(parse_env_i64(None, 60), 60);
        assert_eq!(parse_env_i64(Some("45"), 60), 45);
        assert_eq!(parse_env_i64(Some("nope"), 60), 60);
        let rows = vec![(Some("active".to_owned()), 3_i64)];
        let v = bucket_counts(&AGENT_STATUSES, &rows);
        assert_eq!(v["active"], 3);
        assert_eq!(v["inactive"], 0);
        assert_eq!(v["disconnected"], 0);
    }
}
