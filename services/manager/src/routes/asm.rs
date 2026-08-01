//! /api/v1/asm — pure authenticated proxy to the scanner ASM API
//! (`SCANNER_URL`, default `http://scanner:5001`). Contract:
//! docs/v2-port/manager-contract.md §asm; Python source of truth:
//! services/manager/api/v1/asm.py.

use std::sync::OnceLock;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse};
use crate::state::AppState;

/// v1 upstream default when `SCANNER_URL` is unset.
const DEFAULT_SCANNER_URL: &str = "http://scanner:5001";
/// v1 httpx client timeout for scanner calls (`timeout=120.0`).
const SCANNER_TIMEOUT: Duration = Duration::from_secs(120);

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

/// Resolves `{SCANNER_URL}/api/v1/asm` — same env var and default as
/// the v1 module-level constant, read per request (house pattern: siem.rs).
fn scanner_base() -> String {
    scanner_base_from(std::env::var("SCANNER_URL").ok().as_deref())
}

/// Pure form of [`scanner_base`] for tests.
fn scanner_base_from(env: Option<&str>) -> String {
    format!("{}/api/v1/asm", env.unwrap_or(DEFAULT_SCANNER_URL))
}

/// Shared upstream HTTP client with the v1 120s timeout, built once. A
/// builder failure (TLS init — practically impossible) surfaces as a 500.
fn shared_client() -> Result<reqwest::Client, ApiError> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c.clone());
    }
    let built = reqwest::Client::builder()
        .timeout(SCANNER_TIMEOUT)
        .build()
        .map_err(|e| ApiError::internal("reqwest client", e))?;
    Ok(CLIENT.get_or_init(|| built).clone())
}

/// v1 exception mapping: httpx.TimeoutException → 504 (checked first —
/// connect timeouts count as timeouts, as in httpx), httpx.ConnectError →
/// 503, anything else → 500 with the error text (v1 returned `str(e)`).
fn upstream_error(e: &reqwest::Error) -> (StatusCode, serde_json::Value) {
    if e.is_timeout() {
        (
            StatusCode::GATEWAY_TIMEOUT,
            serde_json::json!({"error": "Worker scanner timeout"}),
        )
    } else if e.is_connect() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"error": "Cannot connect to scanner"}),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": e.to_string()}),
        )
    }
}

/// Forwards one request to the scanner ASM API, mapping the outcome
/// to the v1 wire shapes: upstream JSON (non-JSON bodies become
/// `{"raw": text}`) with the upstream status code, or the
/// [`upstream_error`] envelopes on transport failure.
async fn proxy(
    client: &reqwest::Client,
    base: &str,
    method: reqwest::Method,
    path: &str,
    auth: Option<&str>,
    query: Option<&[(String, String)]>,
    body: Option<&serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut url = format!("{base}{path}");
    if let Some(q) = query
        && !q.is_empty()
    {
        url.push('?');
        url.push_str(&encode_query(q));
    }
    let mut req = client.request(method, url);
    if let Some(a) = auth {
        req = req.header(reqwest::header::AUTHORIZATION, a);
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return upstream_error(&e),
    };
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return upstream_error(&e),
    };
    let data = serde_json::from_str::<serde_json::Value>(&text)
        .unwrap_or_else(|_| serde_json::json!({"raw": text}));
    (status, data)
}

/// Handler-side glue: forwards the incoming `Authorization` header verbatim
/// when present (v1 behavior) and proxies via the shared client against the
/// env-resolved base URL.
async fn forward(
    method: reqwest::Method,
    path: &str,
    headers: &HeaderMap,
    query: Option<&[(String, String)]>,
    body: Option<&serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let client = shared_client()?;
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let (status, data) = proxy(&client, &scanner_base(), method, path, auth, query, body).await;
    Ok((status, Json(data)))
}

/// Percent-encodes one query component, keeping the RFC 3986 unreserved set
/// (the reqwest build here omits its optional `query` feature).
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Builds a `k=v&k2=v2` query string from pairs, percent-encoding both sides
/// — the encoding httpx applied to the forwarded `params=` dict in v1.
fn encode_query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Quart parity for `dict(request.args)`: first value wins per key, in
/// first-appearance order (empirically verified against werkzeug MultiDict).
fn first_value_params(pairs: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        if !out.iter().any(|(seen, _)| seen == k) {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

/// Python truthiness for decoded JSON — v1 `body or {}` replaces every falsy
/// body (null/false/0/""/[]/{}) with `{}` before forwarding.
fn is_py_falsy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(b) => !b,
        serde_json::Value::Number(n) => n.as_f64() == Some(0.0),
        serde_json::Value::String(s) => s.is_empty(),
        serde_json::Value::Array(a) => a.is_empty(),
        serde_json::Value::Object(o) => o.is_empty(),
    }
}

/// v1 `await request.get_json()` then `json=body or {}` — absent/empty and
/// Python-falsy bodies forward as `{}`. Malformed JSON is a 400 (house
/// pattern per alerts.rs ai-review; v1's Quart 400 detail text differed).
fn parse_forward_body(raw: &Bytes) -> Result<serde_json::Value, ApiError> {
    if raw.is_empty() {
        return Ok(serde_json::json!({}));
    }
    let v: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|_| ApiError::BadRequest("Invalid JSON body".to_owned()))?;
    Ok(if is_py_falsy(&v) {
        serde_json::json!({})
    } else {
        v
    })
}

/// Shared GET proxy for the /scans/{id}/&lt;subresource&gt; routes.
async fn scan_subresource(
    scan_id: i64,
    sub: &str,
    headers: &HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    forward(
        reqwest::Method::GET,
        &format!("/scans/{scan_id}/{sub}"),
        headers,
        None,
        None,
    )
    .await
}

/// POST /asm/scans — trigger a new ASM scan (proxied; body forwarded).
///
/// This whole router is a thin authenticated proxy to the scanner service —
/// every response body below is documented as a generic JSON object
/// (`serde_json::Value`) rather than a fixed schema, since the wire shape is
/// whatever the upstream scanner returns, not something this service
/// defines. See `docs/v2-port/openapi-pattern.md`.
#[utoipa::path(
    post,
    path = "/api/v1/asm/scans",
    tag = "asm",
    security(("bearer_jwt" = [])),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 400, description = "Invalid JSON body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_asm_scan(
    _user: CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let json = parse_forward_body(&body)?;
    forward(reqwest::Method::POST, "/scans", &headers, None, Some(&json)).await
}

/// GET /asm/scans — list ASM scans; query params forward first-value-wins.
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans",
    tag = "asm",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_asm_scans(
    _user: CurrentUser,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let query = first_value_params(&params);
    forward(reqwest::Method::GET, "/scans", &headers, Some(&query), None).await
}

/// GET /asm/scans/{scan_id} — ASM scan detail (proxied).
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan(
    _user: CurrentUser,
    headers: HeaderMap,
    Path(scan_id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    forward(
        reqwest::Method::GET,
        &format!("/scans/{scan_id}"),
        &headers,
        None,
        None,
    )
    .await
}

/// GET /asm/scans/{scan_id}/hosts — discovered hosts and services (proxied).
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/hosts",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_hosts(
    _user: CurrentUser,
    headers: HeaderMap,
    Path(scan_id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    scan_subresource(scan_id, "hosts", &headers).await
}

/// GET /asm/scans/{scan_id}/screenshots — screenshots with presigned URLs
/// (proxied).
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/screenshots",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_screenshots(
    _user: CurrentUser,
    headers: HeaderMap,
    Path(scan_id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    scan_subresource(scan_id, "screenshots", &headers).await
}

/// GET /asm/scans/{scan_id}/certs — TLS certificate findings (proxied).
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/certs",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_certs(
    _user: CurrentUser,
    headers: HeaderMap,
    Path(scan_id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    scan_subresource(scan_id, "certs", &headers).await
}

/// GET /asm/scans/{scan_id}/diff — diff vs the previous scan (proxied).
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/diff",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_diff(
    _user: CurrentUser,
    headers: HeaderMap,
    Path(scan_id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    scan_subresource(scan_id, "diff", &headers).await
}

/// GET /asm/scans/{scan_id}/report — presigned URL for the full scan report
/// (proxied).
#[utoipa::path(
    get,
    path = "/api/v1/asm/scans/{scan_id}/report",
    tag = "asm",
    security(("bearer_jwt" = [])),
    params(("scan_id" = i64, Path, description = "ASM scan id")),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_asm_scan_report(
    _user: CurrentUser,
    headers: HeaderMap,
    Path(scan_id): Path<i64>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    scan_subresource(scan_id, "report", &headers).await
}

/// GET /asm/settings/ports — port configuration (proxied; any role).
#[utoipa::path(
    get,
    path = "/api/v1/asm/settings/ports",
    tag = "asm",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_port_settings(
    _user: CurrentUser,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    forward(
        reqwest::Method::GET,
        "/settings/ports",
        &headers,
        None,
        None,
    )
    .await
}

/// PUT /asm/settings/ports — update port settings (admin only; proxied).
#[utoipa::path(
    put,
    path = "/api/v1/asm/settings/ports",
    tag = "asm",
    security(("bearer_jwt" = [])),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Proxied scanner response", body = serde_json::Value),
        (status = 400, description = "Invalid JSON body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 503, description = "Cannot connect to scanner", body = ErrorResponse),
        (status = 504, description = "Scanner request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_port_settings(
    user: CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin"])?;
    let json = parse_forward_body(&body)?;
    forward(
        reqwest::Method::PUT,
        "/settings/ports",
        &headers,
        None,
        Some(&json),
    )
    .await
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_server() -> axum_test::TestServer {
        let cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("config: {e}"),
        };
        let client = match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("client: {e}"),
        };
        let state = crate::state::AppStateInner::for_tests(client);
        let app = axum::Router::new()
            .nest("/api/v1", super::router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    fn user(role: &str) -> CurrentUser {
        CurrentUser {
            id: 1,
            email: "user@example.com".to_owned(),
            full_name: None,
            role: role.to_owned(),
            is_active: true,
            mfa_enabled: false,
            created_at: None,
            tenant_id: uuid::Uuid::nil(),
        }
    }

    fn client_with_timeout(timeout: Duration) -> reqwest::Client {
        match reqwest::Client::builder().timeout(timeout).build() {
            Ok(c) => c,
            Err(e) => panic!("client: {e}"),
        }
    }

    #[tokio::test]
    async fn all_routes_require_auth() {
        let server = test_server();
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
            let body: serde_json::Value = res.json();
            assert_eq!(
                body["error"], "Missing or invalid authorization header",
                "{m} {p}"
            );
        }
    }

    #[tokio::test]
    async fn garbage_bearer_token_is_401_invalid_token() {
        let server = test_server();
        let res = server
            .get("/api/v1/asm/scans")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer not-a-jwt"),
            )
            .await;
        assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Invalid token");
    }

    #[tokio::test]
    async fn non_bearer_scheme_is_401_invalid_header() {
        let server = test_server();
        let res = server
            .get("/api/v1/asm/scans")
            .add_header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Token abc"),
            )
            .await;
        assert_eq!(res.status_code(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Missing or invalid authorization header");
    }

    #[tokio::test]
    async fn viewer_and_maintainer_cannot_update_port_settings() {
        for role in ["viewer", "maintainer"] {
            let res = update_port_settings(user(role), HeaderMap::new(), Bytes::new()).await;
            match res {
                Err(ApiError::Forbidden(msg)) => {
                    assert_eq!(msg, "Insufficient permissions", "{role}");
                }
                other => panic!("expected 403 for {role}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn get_port_settings_has_no_role_gate() {
        // Viewer passes the (nonexistent) gate and reaches the proxy; the
        // default upstream host is unresolvable here, so any proxy outcome
        // arrives as Ok((5xx, body)) — never Forbidden.
        let res = get_port_settings(user("viewer"), HeaderMap::new()).await;
        match res {
            Ok((status, _)) => assert!(status.is_server_error()),
            Err(e) => panic!("expected proxied response, got {e:?}"),
        }
    }

    #[tokio::test]
    async fn proxy_forwards_get_with_query_and_auth() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/asm/scans"))
            .and(query_param("page", "2"))
            .and(query_param("status", "running"))
            .and(query_param("q", "a b&c=d"))
            .and(header("authorization", "Bearer tok-123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"items": [], "total": 0})),
            )
            .mount(&upstream)
            .await;

        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => panic!("client: {e:?}"),
        };
        let base = format!("{}/api/v1/asm", upstream.uri());
        let query = vec![
            ("page".to_owned(), "2".to_owned()),
            ("status".to_owned(), "running".to_owned()),
            ("q".to_owned(), "a b&c=d".to_owned()),
        ];
        let (status, body) = proxy(
            &client,
            &base,
            reqwest::Method::GET,
            "/scans",
            Some("Bearer tok-123"),
            Some(&query),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"items": [], "total": 0}));
    }

    #[tokio::test]
    async fn proxy_forwards_post_json_body() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/asm/scans"))
            .and(body_json(serde_json::json!({"target": "example.com"})))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"scan_id": 7})),
            )
            .mount(&upstream)
            .await;

        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => panic!("client: {e:?}"),
        };
        let base = format!("{}/api/v1/asm", upstream.uri());
        let body_in = serde_json::json!({"target": "example.com"});
        let (status, body) = proxy(
            &client,
            &base,
            reqwest::Method::POST,
            "/scans",
            None,
            None,
            Some(&body_in),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body, serde_json::json!({"scan_id": 7}));
    }

    #[tokio::test]
    async fn proxy_passes_upstream_errors_through() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/asm/scans/9"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"error": "Scan not found"})),
            )
            .mount(&upstream)
            .await;

        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => panic!("client: {e:?}"),
        };
        let base = format!("{}/api/v1/asm", upstream.uri());
        let (status, body) = proxy(
            &client,
            &base,
            reqwest::Method::GET,
            "/scans/9",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, serde_json::json!({"error": "Scan not found"}));
    }

    #[tokio::test]
    async fn proxy_wraps_non_json_responses_as_raw() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/asm/settings/ports"))
            .respond_with(ResponseTemplate::new(200).set_body_string("plain text"))
            .mount(&upstream)
            .await;

        let client = match shared_client() {
            Ok(c) => c,
            Err(e) => panic!("client: {e:?}"),
        };
        let base = format!("{}/api/v1/asm", upstream.uri());
        let (status, body) = proxy(
            &client,
            &base,
            reqwest::Method::GET,
            "/settings/ports",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"raw": "plain text"}));
    }

    #[tokio::test]
    async fn proxy_maps_connect_failure_to_503() {
        let client = client_with_timeout(Duration::from_secs(5));
        let (status, body) = proxy(
            &client,
            "http://127.0.0.1:9/api/v1/asm",
            reqwest::Method::GET,
            "/scans",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            serde_json::json!({"error": "Cannot connect to scanner"})
        );
    }

    #[tokio::test]
    async fn proxy_maps_timeout_to_504() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/asm/scans"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&upstream)
            .await;

        let client = client_with_timeout(Duration::from_millis(200));
        let base = format!("{}/api/v1/asm", upstream.uri());
        let (status, body) = proxy(
            &client,
            &base,
            reqwest::Method::GET,
            "/scans",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body, serde_json::json!({"error": "Worker scanner timeout"}));
    }

    #[test]
    fn forward_body_applies_python_truthiness() {
        let empty = serde_json::json!({});
        for raw in ["", "null", "0", "0.0", "false", "\"\"", "[]", "{}"] {
            let parsed = match parse_forward_body(&Bytes::from(raw.to_owned())) {
                Ok(v) => v,
                Err(e) => panic!("{raw:?}: {e:?}"),
            };
            assert_eq!(parsed, empty, "{raw:?}");
        }
        let truthy = match parse_forward_body(&Bytes::from_static(b"{\"a\":1}")) {
            Ok(v) => v,
            Err(e) => panic!("truthy: {e:?}"),
        };
        assert_eq!(truthy, serde_json::json!({"a": 1}));
        assert!(matches!(
            parse_forward_body(&Bytes::from_static(b"not json")),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn first_value_params_matches_quart_dict_args() {
        let pairs = vec![
            ("b".to_owned(), "1".to_owned()),
            ("a".to_owned(), "2".to_owned()),
            ("b".to_owned(), "3".to_owned()),
        ];
        assert_eq!(
            first_value_params(&pairs),
            vec![
                ("b".to_owned(), "1".to_owned()),
                ("a".to_owned(), "2".to_owned()),
            ]
        );
    }

    #[test]
    fn encode_query_percent_encodes_reserved_chars() {
        let pairs = vec![
            ("q".to_owned(), "a b&c=d".to_owned()),
            ("ok".to_owned(), "A-z_0.9~".to_owned()),
        ];
        assert_eq!(encode_query(&pairs), "q=a%20b%26c%3Dd&ok=A-z_0.9~");
    }

    #[test]
    fn scanner_base_uses_env_or_v1_default() {
        assert_eq!(scanner_base_from(None), "http://scanner:5001/api/v1/asm");
        assert_eq!(
            scanner_base_from(Some("http://localhost:9999")),
            "http://localhost:9999/api/v1/asm"
        );
    }
}
