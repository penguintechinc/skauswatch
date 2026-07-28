//! /api/v1/siem — log-pipeline health, ingest proxy to the logs,
//! OpenSearch search/stats, and configuration. Contract:
//! docs/v2-port/manager-contract.md §siem; Python source of truth:
//! services/manager/api/v1/siem.py.

use std::time::Duration;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson};
use crate::state::AppState;

/// Free-tier user cap (v1 `SIEMConfig.free_tier_user_cap` — default 5, never
/// overridden from env by v1 `load_config`).
const FREE_TIER_USER_CAP: i64 = 5;
/// v1 bare 400 body for PUT /config — note the en dash, copied byte-for-byte.
const RETENTION_MSG: &str = "retention_days must be an integer 1–400";
/// v1 OpenSearch index pattern for SIEM logs.
const LOG_INDEX: &str = "skauswatch-logs-*";

/// Router for /api/v1/siem.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/siem/health", get(siem_health))
        .route("/siem/ingest", post(proxy_ingest))
        .route("/siem/search", get(search_logs))
        .route("/siem/stats", get(siem_stats))
        .route("/siem/config", get(get_siem_config).put(update_siem_config))
}

/// Request-time SIEM settings — the v1 `SIEMConfig` fields these routes
/// consume. Env is read per request (house pattern: alerts.rs `AI_ENABLED`).
struct SiemSettings {
    /// SIEM pipeline toggle (`SIEM_ENABLED`, default true).
    enabled: bool,
    /// OpenSearch endpoint (`OPENSEARCH_URL`).
    opensearch_url: String,
    /// Log-receiver service base URL (`LOGS_URL`).
    logs_url: String,
    /// Retention window in days (`LOG_RETENTION_DAYS`, default 90).
    retention_days: i64,
}

impl SiemSettings {
    /// Reads the SIEM env vars — one call per request, mirroring how v1
    /// resolved `config.siem` fields from the environment at startup.
    fn from_env() -> Self {
        Self::from_values(
            std::env::var("SIEM_ENABLED").ok().as_deref(),
            std::env::var("OPENSEARCH_URL").ok().as_deref(),
            std::env::var("LOGS_URL").ok().as_deref(),
            std::env::var("LOG_RETENTION_DAYS").ok().as_deref(),
        )
    }

    /// Pure constructor mirroring v1 `load_config` semantics: `SIEM_ENABLED`
    /// is `lower() == "true"` with default "true"; URLs fall back to the v1
    /// service defaults. Deviation: an unparsable `LOG_RETENTION_DAYS`
    /// crashed v1 at startup — v2 falls back to the default 90 instead.
    fn from_values(
        enabled: Option<&str>,
        opensearch_url: Option<&str>,
        logs_url: Option<&str>,
        retention_days: Option<&str>,
    ) -> Self {
        Self {
            enabled: enabled.is_none_or(|v| v.eq_ignore_ascii_case("true")),
            opensearch_url: opensearch_url
                .unwrap_or("http://opensearch:9200")
                .to_owned(),
            logs_url: logs_url.unwrap_or("http://logs:5010").to_owned(),
            retention_days: retention_days.and_then(parse_py_int).unwrap_or(90),
        }
    }
}

/// Approximates Python `int(str)`: surrounding whitespace tolerated, optional
/// sign, base-10 only. (Python also accepts digit-group underscores — an edge
/// no real caller hits.)
fn parse_py_int(s: &str) -> Option<i64> {
    s.trim().parse::<i64>().ok()
}

/// v1 health payload: `logs` ok/unavailable and an overall status
/// that degrades with it.
fn health_json(receiver_ok: bool) -> serde_json::Value {
    serde_json::json!({
        "logs": if receiver_ok { "ok" } else { "unavailable" },
        "status": if receiver_ok { "ok" } else { "degraded" },
    })
}

/// Probes `{logs_url}/healthz` with the v1 5s timeout; only an exact
/// 200 counts as healthy (v1 `resp.status_code == 200`).
async fn probe_logs(base_url: &str) -> bool {
    let resp = reqwest::Client::new()
        .get(format!("{base_url}/healthz"))
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    matches!(resp, Ok(r) if r.status().as_u16() == 200)
}

/// GET /siem/health — unauthenticated logs liveness probe. Always
/// 200; the body carries ok/degraded, matching the v1 route.
async fn siem_health() -> Json<serde_json::Value> {
    let settings = SiemSettings::from_env();
    let receiver_ok = probe_logs(&settings.logs_url).await;
    Json(health_json(receiver_ok))
}

/// POST /siem/ingest — authenticated proxy to `{LOGS_URL}/ingest`
/// with the v1 10s timeout. The upstream status code and JSON body pass
/// through verbatim; transport/parse failures are 500 (v1 uncaught httpx).
async fn proxy_ingest(
    _user: CurrentUser,
    ApiJson(body): ApiJson<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let settings = SiemSettings::from_env();
    let resp = reqwest::Client::new()
        .post(format!("{}/ingest", settings.logs_url))
        .timeout(Duration::from_secs(10))
        .json(&body)
        .send()
        .await
        .map_err(|e| ApiError::internal("logs ingest", e))?;
    let status = StatusCode::from_u16(resp.status().as_u16())
        .map_err(|e| ApiError::internal("logs ingest status", e))?;
    let payload: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ApiError::internal("logs ingest response", e))?;
    Ok((status, Json(payload)))
}

/// Builds the v1 `_build_os_query` body from raw query pairs. Quart parity:
/// `MultiDict.get` first-value-wins; empty strings are Python-falsy and skip
/// their filter; unparsable ints raised uncaught `ValueError` in v1 → 500.
fn build_os_query(pairs: &[(String, String)]) -> Result<serde_json::Value, ApiError> {
    let first = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let bad_int = |field: &str, raw: &str| {
        // v1: int(...) ValueError propagated to the Quart 500 handler.
        ApiError::internal(
            "siem search params",
            format!("invalid integer for {field}: {raw:?}"),
        )
    };

    let mut must: Vec<serde_json::Value> = Vec::new();
    if let Some(q) = first("q").filter(|s| !s.is_empty()) {
        must.push(serde_json::json!({"match": {"message": q}}));
    }
    if let Some(cn) = first("class_name").filter(|s| !s.is_empty()) {
        must.push(serde_json::json!({"term": {"class_name.keyword": cn}}));
    }
    if let Some(sev) = first("severity").filter(|s| !s.is_empty()) {
        let sev_id = parse_py_int(sev).ok_or_else(|| bad_int("severity", sev))?;
        must.push(serde_json::json!({"term": {"severity_id": sev_id}}));
    }

    let mut date_filter = serde_json::Map::new();
    if let Some(fd) = first("from_date").filter(|s| !s.is_empty()) {
        date_filter.insert("gte".to_owned(), serde_json::Value::from(fd));
    }
    if let Some(td) = first("to_date").filter(|s| !s.is_empty()) {
        date_filter.insert("lte".to_owned(), serde_json::Value::from(td));
    }
    if !date_filter.is_empty() {
        must.push(serde_json::json!({"range": {"time": date_filter}}));
    }

    let page = match first("page") {
        None => 1,
        Some(raw) => parse_py_int(raw).ok_or_else(|| bad_int("page", raw))?,
    };
    let page_size = match first("page_size") {
        None => 50,
        Some(raw) => parse_py_int(raw).ok_or_else(|| bad_int("page_size", raw))?,
    }
    .min(500);

    let query = if must.is_empty() {
        serde_json::json!({"match_all": {}})
    } else {
        serde_json::json!({"bool": {"must": must}})
    };
    Ok(serde_json::json!({
        "query": query,
        "from": page.saturating_sub(1).saturating_mul(page_size),
        "size": page_size,
        "sort": [{"time": {"order": "desc"}}],
    }))
}

/// POSTs a search body to the v1 index pattern — the REST equivalent of
/// opensearch-py `client.search(index=..., body=...)` with its default 10s
/// timeout. Any transport error or non-2xx is 500 (opensearchpy raised).
async fn os_search(
    base_url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/{LOG_INDEX}/_search"))
        .timeout(Duration::from_secs(10))
        .json(body)
        .send()
        .await
        .map_err(|e| ApiError::internal("opensearch request", e))?
        .error_for_status()
        .map_err(|e| ApiError::internal("opensearch status", e))?;
    resp.json()
        .await
        .map_err(|e| ApiError::internal("opensearch response", e))
}

/// Shapes the v1 search response: `{total: hits.total.value, logs:
/// [hit._source]}`. Missing keys were KeyErrors in v1 → 500 here too.
fn shape_search_response(resp: &serde_json::Value) -> Result<serde_json::Value, ApiError> {
    let total = resp
        .pointer("/hits/total/value")
        .cloned()
        .ok_or_else(|| ApiError::internal("opensearch response", "missing hits.total.value"))?;
    let hits = resp
        .pointer("/hits/hits")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ApiError::internal("opensearch response", "missing hits.hits"))?;
    let mut logs = Vec::with_capacity(hits.len());
    for hit in hits {
        logs.push(
            hit.get("_source")
                .cloned()
                .ok_or_else(|| ApiError::internal("opensearch response", "hit missing _source"))?,
        );
    }
    Ok(serde_json::json!({"total": total, "logs": logs}))
}

/// GET /siem/search — authenticated OpenSearch log search over
/// `skauswatch-logs-*`. Query params: q, from_date, to_date, class_name,
/// severity, page, page_size (v1 caps page_size at 500).
async fn search_logs(
    _user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let settings = SiemSettings::from_env();
    let query = build_os_query(&params)?;
    let resp = os_search(&settings.opensearch_url, &query).await?;
    Ok(Json(shape_search_response(&resp)?))
}

/// The fixed v1 aggregation body for GET /siem/stats — terms aggs over
/// `class_name.keyword` (size 20) and `severity_id` (size 10), zero hits.
fn stats_agg_body() -> serde_json::Value {
    serde_json::json!({
        "size": 0,
        "aggs": {
            "by_class": {"terms": {"field": "class_name.keyword", "size": 20}},
            "by_severity": {"terms": {"field": "severity_id", "size": 10}},
        },
    })
}

/// Shapes the v1 stats response: total indexed plus the raw terms buckets
/// passed through verbatim (`{key, doc_count}` objects).
fn shape_stats_response(resp: &serde_json::Value) -> Result<serde_json::Value, ApiError> {
    let total = resp
        .pointer("/hits/total/value")
        .cloned()
        .ok_or_else(|| ApiError::internal("opensearch response", "missing hits.total.value"))?;
    let by_class = resp
        .pointer("/aggregations/by_class/buckets")
        .cloned()
        .ok_or_else(|| ApiError::internal("opensearch response", "missing by_class buckets"))?;
    let by_severity = resp
        .pointer("/aggregations/by_severity/buckets")
        .cloned()
        .ok_or_else(|| ApiError::internal("opensearch response", "missing by_severity buckets"))?;
    Ok(serde_json::json!({
        "total_indexed": total,
        "by_class": by_class,
        "by_severity": by_severity,
    }))
}

/// GET /siem/stats — authenticated ingest statistics: total indexed events
/// plus per-class and per-severity terms buckets.
async fn siem_stats(_user: CurrentUser) -> Result<Json<serde_json::Value>, ApiError> {
    let settings = SiemSettings::from_env();
    let resp = os_search(&settings.opensearch_url, &stats_agg_body()).await?;
    Ok(Json(shape_stats_response(&resp)?))
}

/// v1 GET /config payload — the non-sensitive `SIEMConfig` fields.
fn config_json(settings: &SiemSettings) -> serde_json::Value {
    serde_json::json!({
        "enabled": settings.enabled,
        "retention_days": settings.retention_days,
        "opensearch_url": settings.opensearch_url,
        "logs_url": settings.logs_url,
        "free_tier_user_cap": FREE_TIER_USER_CAP,
    })
}

/// GET /siem/config — authenticated view of the current SIEM configuration
/// (any role, matching v1's bare `@auth_required`).
async fn get_siem_config(_user: CurrentUser) -> Json<serde_json::Value> {
    Json(config_json(&SiemSettings::from_env()))
}

/// Outcome of the v1 PUT /config retention check (`body.get("retention_days")`).
#[derive(Debug, PartialEq, Eq)]
enum RetentionOutcome {
    /// Key absent or JSON null — v1 skips validation and echoes null.
    Absent,
    /// Integer in 1–400 — echoed back (contract defect #5: never persisted).
    Valid(i64),
    /// Present but not an integer in range — v1 bare 400 body.
    Invalid,
}

/// Mirrors the v1 check: integers 1–400 only. Deviation (Python quirk):
/// v1's `isinstance(x, int)` also admitted JSON booleans (`True == 1`);
/// v2 rejects them as non-integers.
fn check_retention(body: &serde_json::Map<String, serde_json::Value>) -> RetentionOutcome {
    match body.get("retention_days") {
        None | Some(serde_json::Value::Null) => RetentionOutcome::Absent,
        Some(v) => match v.as_i64() {
            Some(n) if (1..=400).contains(&n) => RetentionOutcome::Valid(n),
            _ => RetentionOutcome::Invalid,
        },
    }
}

/// PUT /siem/config — admin-only retention update. Contract defect #5:
/// v1 validates but never persists — replicated as a validate-only no-op.
/// Invalid values return the bare v1 400 body, not the shared envelope.
async fn update_siem_config(
    user: CurrentUser,
    ApiJson(body): ApiJson<serde_json::Value>,
) -> Result<Response, ApiError> {
    user.require_role(&["admin"])?;

    let empty = serde_json::Map::new();
    let map = match &body {
        serde_json::Value::Object(m) => m,
        // v1: `await request.get_json() or {}` — a null body becomes {}.
        serde_json::Value::Null => &empty,
        // v1: `.get(...)` on a non-dict raised AttributeError → 500.
        _ => {
            return Err(ApiError::internal(
                "siem config body",
                "non-object JSON body",
            ));
        }
    };

    let retention = match check_retention(map) {
        RetentionOutcome::Invalid => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": RETENTION_MSG})),
            )
                .into_response());
        }
        RetentionOutcome::Absent => None,
        RetentionOutcome::Valid(days) => {
            tracing::info!(days, "siem_retention_updated");
            Some(days)
        }
    };

    Ok(Json(serde_json::json!({
        "message": "SIEM config updated",
        "retention_days": retention,
    }))
    .into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    /// Boots a TestServer with only the siem router nested under /api/v1 —
    /// self-contained regardless of routes/mod.rs wiring.
    fn test_server() -> axum_test::TestServer {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let state = AppStateInner::for_tests(client);
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    fn user_with_role(role: &str) -> CurrentUser {
        CurrentUser {
            id: 1,
            email: "user@example.com".to_owned(),
            full_name: None,
            role: role.to_owned(),
            is_active: true,
            mfa_enabled: false,
            created_at: None,
        }
    }

    fn body_map(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        match v {
            serde_json::Value::Object(m) => m,
            other => panic!("expected object, got {other}"),
        }
    }

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[tokio::test]
    async fn health_is_public_and_degrades_without_receiver() {
        let server = test_server();
        let res = server.get("/api/v1/siem/health").await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(
            body,
            serde_json::json!({"logs": "unavailable", "status": "degraded"})
        );
    }

    #[tokio::test]
    async fn protected_endpoints_require_a_token() {
        let server = test_server();
        let responses = [
            server.post("/api/v1/siem/ingest").await,
            server.get("/api/v1/siem/search").await,
            server.get("/api/v1/siem/stats").await,
            server.get("/api/v1/siem/config").await,
            server.put("/api/v1/siem/config").await,
        ];
        for res in responses {
            res.assert_status(StatusCode::UNAUTHORIZED);
            let body: serde_json::Value = res.json();
            assert_eq!(body["error"], "Missing or invalid authorization header");
        }
    }

    #[tokio::test]
    async fn garbage_bearer_token_is_rejected() {
        let server = test_server();
        let res = server
            .get("/api/v1/siem/search")
            .authorization_bearer("not-a-jwt")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Invalid token");
    }

    #[test]
    fn config_put_role_gate_is_admin_only() {
        assert!(user_with_role("admin").require_role(&["admin"]).is_ok());
        for role in ["maintainer", "viewer"] {
            match user_with_role(role).require_role(&["admin"]) {
                Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
                other => panic!("expected 403 for {role}, got {other:?}"),
            }
        }
    }

    #[test]
    fn retention_validation_matches_v1() {
        assert_eq!(
            check_retention(&body_map(serde_json::json!({}))),
            RetentionOutcome::Absent
        );
        assert_eq!(
            check_retention(&body_map(serde_json::json!({"retention_days": null}))),
            RetentionOutcome::Absent
        );
        assert_eq!(
            check_retention(&body_map(serde_json::json!({"retention_days": 1}))),
            RetentionOutcome::Valid(1)
        );
        assert_eq!(
            check_retention(&body_map(serde_json::json!({"retention_days": 400}))),
            RetentionOutcome::Valid(400)
        );
        for bad in [
            serde_json::json!(0),
            serde_json::json!(401),
            serde_json::json!("30"),
            serde_json::json!(5.5),
            serde_json::json!(true),
        ] {
            assert_eq!(
                check_retention(&body_map(serde_json::json!({"retention_days": bad}))),
                RetentionOutcome::Invalid,
                "expected Invalid for {bad}",
            );
        }
    }

    #[test]
    fn retention_error_message_matches_v1_bytes() {
        // The v1 message uses an en dash (U+2013), not a hyphen.
        assert_eq!(
            RETENTION_MSG,
            "retention_days must be an integer 1\u{2013}400"
        );
    }

    #[test]
    fn settings_defaults_match_v1() {
        let s = SiemSettings::from_values(None, None, None, None);
        assert!(s.enabled);
        assert_eq!(s.opensearch_url, "http://opensearch:9200");
        assert_eq!(s.logs_url, "http://logs:5010");
        assert_eq!(s.retention_days, 90);
    }

    #[test]
    fn settings_env_semantics_match_python() {
        let s = SiemSettings::from_values(
            Some("FALSE"),
            Some("http://os:9200"),
            Some("http://lr:5010"),
            Some("30"),
        );
        assert!(!s.enabled);
        assert_eq!(s.opensearch_url, "http://os:9200");
        assert_eq!(s.logs_url, "http://lr:5010");
        assert_eq!(s.retention_days, 30);

        // Python: os.getenv("SIEM_ENABLED", "true").lower() == "true"
        assert!(SiemSettings::from_values(Some("TRUE"), None, None, None).enabled);
        assert!(!SiemSettings::from_values(Some("yes"), None, None, None).enabled);
        // Deviation: v1 crashed at startup on int("abc") — v2 defaults to 90.
        assert_eq!(
            SiemSettings::from_values(None, None, None, Some("abc")).retention_days,
            90
        );
    }

    #[test]
    fn config_json_matches_v1_shape() {
        let s = SiemSettings::from_values(None, None, None, None);
        assert_eq!(
            config_json(&s),
            serde_json::json!({
                "enabled": true,
                "retention_days": 90,
                "opensearch_url": "http://opensearch:9200",
                "logs_url": "http://logs:5010",
                "free_tier_user_cap": 5,
            })
        );
    }

    #[test]
    fn health_json_shapes_match_v1() {
        assert_eq!(
            health_json(true),
            serde_json::json!({"logs": "ok", "status": "ok"})
        );
        assert_eq!(
            health_json(false),
            serde_json::json!({"logs": "unavailable", "status": "degraded"})
        );
    }

    #[test]
    fn os_query_defaults_to_match_all_page_one() {
        let q = match build_os_query(&[]) {
            Ok(q) => q,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(
            q,
            serde_json::json!({
                "query": {"match_all": {}},
                "from": 0,
                "size": 50,
                "sort": [{"time": {"order": "desc"}}],
            })
        );
    }

    #[test]
    fn os_query_builds_filters_and_skips_empty_params() {
        let q = match build_os_query(&pairs(&[
            ("q", "login failed"),
            ("class_name", "authentication"),
            ("severity", "3"),
            ("from_date", "2026-07-01"),
            ("to_date", ""), // Python truthiness: empty string skips the filter
        ])) {
            Ok(q) => q,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(
            q["query"],
            serde_json::json!({"bool": {"must": [
                {"match": {"message": "login failed"}},
                {"term": {"class_name.keyword": "authentication"}},
                {"term": {"severity_id": 3}},
                {"range": {"time": {"gte": "2026-07-01"}}},
            ]}})
        );
        assert_eq!(q["from"], 0);
        assert_eq!(q["size"], 50);
    }

    #[test]
    fn os_query_pagination_first_value_wins_and_caps_at_500() {
        let q = match build_os_query(&pairs(&[
            ("page", "3"),
            ("page", "9"),
            ("page_size", "1000"),
        ])) {
            Ok(q) => q,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(q["from"], 1000); // (3 - 1) * 500
        assert_eq!(q["size"], 500); // v1: min(page_size, 500)
    }

    #[test]
    fn os_query_bad_ints_map_to_v1_500() {
        for kv in [("severity", "high"), ("page", "abc"), ("page_size", "")] {
            match build_os_query(&pairs(&[kv])) {
                Err(ApiError::Internal) => {}
                other => panic!("expected Internal for {kv:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn search_response_extracts_sources_and_total() {
        let os = serde_json::json!({
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {"_index": "skauswatch-logs-2026.07", "_source": {"message": "a"}},
                    {"_index": "skauswatch-logs-2026.07", "_source": {"message": "b"}},
                ],
            },
        });
        match shape_search_response(&os) {
            Ok(v) => assert_eq!(
                v,
                serde_json::json!({"total": 2, "logs": [{"message": "a"}, {"message": "b"}]})
            ),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        // Malformed upstream shapes were v1 KeyErrors → 500.
        assert!(matches!(
            shape_search_response(&serde_json::json!({})),
            Err(ApiError::Internal)
        ));
    }

    #[test]
    fn stats_response_passes_buckets_through() {
        let os = serde_json::json!({
            "hits": {"total": {"value": 7}},
            "aggregations": {
                "by_class": {"buckets": [{"key": "auth", "doc_count": 4}]},
                "by_severity": {"buckets": [{"key": 3, "doc_count": 7}]},
            },
        });
        match shape_stats_response(&os) {
            Ok(v) => assert_eq!(
                v,
                serde_json::json!({
                    "total_indexed": 7,
                    "by_class": [{"key": "auth", "doc_count": 4}],
                    "by_severity": [{"key": 3, "doc_count": 7}],
                })
            ),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        assert!(matches!(
            shape_stats_response(&serde_json::json!({"hits": {"total": {"value": 7}}})),
            Err(ApiError::Internal)
        ));
    }

    /// Authed coverage for every route that reaches past `CurrentUser` (real
    /// DB). The workspace forbids `unsafe`, so these tests cannot mutate
    /// `LOGS_URL`/`OPENSEARCH_URL` to point at a wiremock upstream — the
    /// upstream-reachable success shapes (`search_response_extracts_sources_and_total`,
    /// `stats_response_passes_buckets_through`) are already covered at the
    /// pure shaping-function level above. `get_siem_config`/
    /// `update_siem_config` never call an upstream at all, so those still
    /// exercise their full authed body here; `proxy_ingest`/`search_logs`/
    /// `siem_stats` still reach past auth into `reqwest`, which fails fast
    /// against the unreachable default hosts (500), still exercising the
    /// handler bodies up to the upstream call.
    #[tokio::test]
    async fn authed_routes_reach_past_the_auth_gate() {
        let state = crate::routes::test_support::db_state(
            skauswatch_testkit::license::dev_license("skauswatch"),
        )
        .await;
        let (_, viewer_tok) =
            crate::routes::test_support::authed_user(&state, "siem-viewer@example.com", "viewer")
                .await;
        let (_, admin_tok) =
            crate::routes::test_support::authed_user(&state, "siem-admin@example.com", "admin")
                .await;
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        let server = axum_test::TestServer::new(app);

        let ingest = server
            .post("/api/v1/siem/ingest")
            .authorization_bearer(&viewer_tok)
            .json(&serde_json::json!({"event": "x"}))
            .await;
        assert_eq!(ingest.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let search = server
            .get("/api/v1/siem/search?q=login")
            .authorization_bearer(&viewer_tok)
            .await;
        assert_eq!(search.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let stats = server
            .get("/api/v1/siem/stats")
            .authorization_bearer(&viewer_tok)
            .await;
        assert_eq!(stats.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let cfg = server
            .get("/api/v1/siem/config")
            .authorization_bearer(&viewer_tok)
            .await;
        cfg.assert_status_ok();
        let body: serde_json::Value = cfg.json();
        assert_eq!(body["free_tier_user_cap"], 5);

        // Non-admin PUT /config is forbidden; admin PUT succeeds.
        let forbidden = server
            .put("/api/v1/siem/config")
            .authorization_bearer(&viewer_tok)
            .json(&serde_json::json!({"retention_days": 30}))
            .await;
        forbidden.assert_status(StatusCode::FORBIDDEN);

        let put_ok = server
            .put("/api/v1/siem/config")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"retention_days": 30}))
            .await;
        put_ok.assert_status_ok();
        let body: serde_json::Value = put_ok.json();
        assert_eq!(body["retention_days"], 30);

        let bad_put = server
            .put("/api/v1/siem/config")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"retention_days": 999}))
            .await;
        bad_put.assert_status(StatusCode::BAD_REQUEST);

        let null_body = server
            .put("/api/v1/siem/config")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::Value::Null)
            .await;
        null_body.assert_status_ok();
        let body: serde_json::Value = null_body.json();
        assert_eq!(body["retention_days"], serde_json::Value::Null);
    }

    #[test]
    fn stats_agg_body_matches_v1() {
        assert_eq!(
            stats_agg_body(),
            serde_json::json!({
                "size": 0,
                "aggs": {
                    "by_class": {"terms": {"field": "class_name.keyword", "size": 20}},
                    "by_severity": {"terms": {"field": "severity_id", "size": 10}},
                },
            })
        );
    }
}
