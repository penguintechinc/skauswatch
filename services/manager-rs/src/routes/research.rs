//! /api/v1/research — threat-research lookups (composite, whois, dns, asn,
//! shodan, maltego) plus the research configuration status. Contract:
//! docs/v2-port/manager-contract.md §research; Python source of truth:
//! services/manager/api/v1/research.py (+ validators/pydantic_models.py
//! Research* / Whois* / Dns* / Asn* models, config.py ThreatIntelConfig
//! research settings).
//!
//! Port decisions (see the module report for the full rationale):
//! v1's research routes are runtime-broken — every handler reads the
//! non-existent `config.research` attribute (AttributeError → 500), and the
//! lookup clients are wired with mismatched method/type names — so there is no
//! working v1 success path to copy byte-for-byte. Per the contract DECISION we
//! implement against a proper env-derived `ResearchConfig` and emit the shapes
//! the v1 blueprint *intends* to return. The fully deterministic, config-driven
//! surface is ported exactly: JWT auth on every route, request validation
//! (400 envelope), the shodan/maltego "not enabled" 503 gates, and the fixed
//! GET /config payload. The external data sources (WHOIS/DNS/ASN resolution,
//! Shodan + Maltego HTTP) are not performed in this port; those endpoints
//! return the intended empty-result envelope shapes. No role gates exist in
//! this router (v1 uses `@auth_required` only).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::AppState;

/// v1 `ResearchIndicatorType` enum values, in declaration order.
const INDICATOR_TYPES: [&str; 6] = ["ip", "domain", "asn", "email", "hash", "url"];
/// pydantic v2 enum message for an invalid `ResearchIndicatorType`.
const TYPE_MSG: &str = "Input should be 'ip', 'domain', 'asn', 'email', 'hash' or 'url'";

/// GET /config timeout fields. v1's `ResearchConfigResponse` requires all six;
/// only whois/dns/asn had defaults in v1 config (10/5/5). `default_timeout`
/// mirrors `ResearchLookupRequest.timeout` (30) and the shodan/maltego client
/// httpx timeout (30s) — v1 config never defined those three, so they are
/// fixed here.
const DEFAULT_TIMEOUT: i64 = 30;
const WHOIS_TIMEOUT: i64 = 10;
const DNS_TIMEOUT: i64 = 5;
const ASN_TIMEOUT: i64 = 5;
const SHODAN_TIMEOUT: i64 = 30;
const MALTEGO_TIMEOUT: i64 = 30;

/// Max query length shared by every research request model (pydantic
/// `max_length=500`).
const MAX_QUERY_LEN: usize = 500;
/// `ResearchLookupRequest.timeout` bounds (`ge=5`, `le=120`).
const TIMEOUT_MIN: i64 = 5;
const TIMEOUT_MAX: i64 = 120;

/// Router for /api/v1/research.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/research/lookup", post(lookup))
        .route("/research/whois", post(whois_lookup))
        .route("/research/dns", post(dns_lookup))
        .route("/research/asn", post(asn_lookup))
        .route("/research/shodan", post(shodan_lookup))
        .route("/research/maltego", post(maltego_lookup))
        .route("/research/config", get(get_config))
}

/// Research feature settings resolved from the environment — the "proper
/// ResearchConfig" the contract DECISION calls for. `shodan_enabled` /
/// `maltego_enabled` are the raw config flags reported by GET /config; the
/// per-request gates additionally require an API key for shodan (see
/// `shodan_effective`).
struct ResearchConfig {
    research_enabled: bool,
    shodan_enabled: bool,
    shodan_api_key: Option<String>,
    maltego_enabled: bool,
}

impl ResearchConfig {
    /// Reads the same env vars as v1 `load_config`: `RESEARCH_ENABLED`
    /// (default true), `SHODAN_ENABLED` (default false) + `SHODAN_API_KEY`,
    /// `MALTEGO_ENABLED` (default false).
    fn from_env() -> Self {
        Self {
            research_enabled: env_bool("RESEARCH_ENABLED", true),
            shodan_enabled: env_bool("SHODAN_ENABLED", false),
            shodan_api_key: std::env::var("SHODAN_API_KEY").ok(),
            maltego_enabled: env_bool("MALTEGO_ENABLED", false),
        }
    }

    /// v1 `ShodanClient.enabled = enabled and api_key is not None`: the flag
    /// alone is not enough; a key must be configured.
    fn shodan_effective(&self) -> bool {
        self.shodan_enabled && self.shodan_api_key.is_some()
    }

    /// v1 `MaltegoClient.enabled = enabled` — the TRX server is optional, so
    /// the flag alone governs.
    fn maltego_effective(&self) -> bool {
        self.maltego_enabled
    }
}

/// v1 parity: `os.getenv(key, default).lower() == "true"` — only the literal
/// "true" (case-insensitive) enables; anything else is false.
fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => v.eq_ignore_ascii_case("true"),
        Err(_) => default,
    }
}

/// GET /config body from a resolved config — mirrors v1's
/// `ResearchConfigResponse` field for field. whois/dns/asn are always
/// available in v1, hence hard-coded `true`.
fn config_json(cfg: &ResearchConfig) -> Value {
    json!({
        "research_enabled": cfg.research_enabled,
        "whois_enabled": true,
        "dns_enabled": true,
        "asn_enabled": true,
        "shodan_enabled": cfg.shodan_enabled,
        "maltego_enabled": cfg.maltego_enabled,
        "default_timeout": DEFAULT_TIMEOUT,
        "whois_timeout": WHOIS_TIMEOUT,
        "dns_timeout": DNS_TIMEOUT,
        "asn_timeout": ASN_TIMEOUT,
        "shodan_timeout": SHODAN_TIMEOUT,
        "maltego_timeout": MALTEGO_TIMEOUT,
    })
}

/// Single-field `{error: "Validation error", details: [...]}` matching the
/// house helper in routes/threat_intel.rs — pydantic-style `loc`/`msg`/`type`.
fn validation_at(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// Validates a `query` field: required (`min_length=1`) and `max_length=500`,
/// counted in characters like pydantic.
fn validate_query(raw: Option<&str>) -> Result<String, ApiError> {
    let Some(q) = raw else {
        return Err(validation_at("query", "Field required"));
    };
    let n = q.chars().count();
    if n < 1 {
        return Err(validation_at(
            "query",
            "String should have at least 1 character",
        ));
    }
    if n > MAX_QUERY_LEN {
        return Err(validation_at(
            "query",
            "String should have at most 500 characters",
        ));
    }
    Ok(q.to_owned())
}

/// Validates an optional `indicator_type` against the enum. `required` mirrors
/// the models where the field has no default (whois/asn require it; lookup/dns
/// do not).
fn validate_indicator_type(raw: Option<&str>, required: bool) -> Result<Option<String>, ApiError> {
    match raw {
        None if required => Err(validation_at("indicator_type", "Field required")),
        None => Ok(None),
        Some(t) if INDICATOR_TYPES.contains(&t) => Ok(Some(t.to_owned())),
        Some(_) => Err(validation_at("indicator_type", TYPE_MSG)),
    }
}

/// True when `s` is a dotted-decimal IPv4 (four octets 0..=255), no colon.
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.parse::<u32>().is_ok_and(|n| n <= 255))
}

/// Loose IPv6 check approximating v1's regex: at least two colons and only
/// hex digits or colons.
fn is_ipv6(s: &str) -> bool {
    s.matches(':').count() >= 2 && s.chars().all(|c| c == ':' || c.is_ascii_hexdigit())
}

/// True for `http://` or `https://` prefixed strings.
fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// True when `s` is exactly `len` hex characters (MD5/SHA1/SHA256 lengths).
fn is_hex_len(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// True for `AS<digits>` (case-insensitive), matching v1's `^AS\d+$`.
fn is_asn(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    match lower.strip_prefix("as") {
        Some(rest) => !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// Approximate email check: a non-empty local part, `@`, and a domain with a
/// dot; length capped at 254 like v1.
fn is_email(s: &str) -> bool {
    if s.len() > 254 {
        return false;
    }
    match s.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    }
}

/// Approximate domain check: not a URL, length capped at 253, dotted labels of
/// alphanumerics/hyphens.
fn is_domain(s: &str) -> bool {
    if s.len() > 253 || is_url(s) || !s.contains('.') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Classifies a query into a `ResearchIndicatorType` value (lowercased enum
/// string) or None for unknown input, following v1's classifier ordering
/// (IPv4, IPv6, URL, MD5, SHA1, SHA256, ASN, Email, Domain).
fn classify(query: &str) -> Option<String> {
    let q = query.trim();
    if q.is_empty() {
        return None;
    }
    if is_ipv4(q) || is_ipv6(q) {
        return Some("ip".to_owned());
    }
    if is_url(q) {
        return Some("url".to_owned());
    }
    if is_hex_len(q, 32) || is_hex_len(q, 40) || is_hex_len(q, 64) {
        return Some("hash".to_owned());
    }
    if is_asn(q) {
        return Some("asn".to_owned());
    }
    if is_email(q) {
        return Some("email".to_owned());
    }
    if is_domain(q) {
        return Some("domain".to_owned());
    }
    None
}

/// Empty WHOIS envelope (no external lookup performed in this port).
fn whois_empty() -> Value {
    json!({"success": false, "data": {}, "error": null})
}

/// Empty DNS envelope matching v1 `DnsResult.to_dict()` (uppercase record
/// keys, the shape the /dns route emits).
fn dns_empty() -> Value {
    json!({
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
        "CNAME": null, "SOA": null
    })
}

/// POST /research/lookup body — every field optional so a missing one maps to
/// the validation envelope rather than an extractor rejection.
#[derive(Deserialize)]
struct LookupBody {
    query: Option<String>,
    indicator_type: Option<String>,
    include_whois: Option<bool>,
    include_dns: Option<bool>,
    include_asn: Option<bool>,
    include_shodan: Option<bool>,
    include_maltego: Option<bool>,
    timeout: Option<i64>,
}

/// Composite research lookup. Validates the request, classifies the indicator
/// when omitted, then walks v1's control flow — including the shodan/maltego
/// "not enabled" 503 short-circuits — emitting empty per-source envelopes since
/// no external source is queried in this port.
async fn lookup(_user: CurrentUser, Json(body): Json<LookupBody>) -> Result<Response, ApiError> {
    let query = validate_query(body.query.as_deref())?;
    let indicator_type = validate_indicator_type(body.indicator_type.as_deref(), false)?;
    if let Some(t) = body.timeout {
        if t < TIMEOUT_MIN {
            return Err(validation_at(
                "timeout",
                "Input should be greater than or equal to 5",
            ));
        }
        if t > TIMEOUT_MAX {
            return Err(validation_at(
                "timeout",
                "Input should be less than or equal to 120",
            ));
        }
    }

    let cfg = ResearchConfig::from_env();
    let itype = indicator_type.or_else(|| classify(&query));

    let include_whois = body.include_whois.unwrap_or(true);
    let include_dns = body.include_dns.unwrap_or(true);
    let include_asn = body.include_asn.unwrap_or(true);
    let include_shodan = body.include_shodan.unwrap_or(false);
    let include_maltego = body.include_maltego.unwrap_or(false);

    let mut result = serde_json::Map::new();
    result.insert("query".to_owned(), json!(query));
    result.insert("indicator_type".to_owned(), json!(itype));
    // Python datetime.utcnow().isoformat() shape via the shared helper
    // (v2-designed surface — the v1 research routes were runtime-broken).
    result.insert(
        "timestamp".to_owned(),
        json!(skauswatch_streams::py_now_isoformat()),
    );

    let is = |v: &str| itype.as_deref() == Some(v);

    if include_whois && (is("domain") || is("ip")) {
        result.insert("whois".to_owned(), whois_empty());
    }
    if include_dns && is("domain") {
        result.insert("dns".to_owned(), dns_empty());
    }
    if include_asn && (is("ip") || is("asn")) {
        result.insert("asn".to_owned(), json!({"error": "No results"}));
    }
    if include_shodan {
        if !cfg.shodan_effective() {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Shodan not enabled"})),
            )
                .into_response());
        }
        result.insert("shodan".to_owned(), json!({"error": "No results"}));
    }
    if include_maltego {
        if !cfg.maltego_effective() {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Maltego not enabled"})),
            )
                .into_response());
        }
        result.insert("maltego".to_owned(), json!({"error": "No results"}));
    }

    Ok(Json(Value::Object(result)).into_response())
}

/// POST /research/whois + /research/asn body — `query` and `indicator_type`.
#[derive(Deserialize)]
struct QueryTypeBody {
    query: Option<String>,
    indicator_type: Option<String>,
}

/// WHOIS-only lookup. `indicator_type` is required (v1 `WhoisLookupRequest`);
/// returns the empty WHOIS envelope since no external lookup is performed.
async fn whois_lookup(
    _user: CurrentUser,
    Json(body): Json<QueryTypeBody>,
) -> Result<Json<Value>, ApiError> {
    validate_query(body.query.as_deref())?;
    validate_indicator_type(body.indicator_type.as_deref(), true)?;
    Ok(Json(whois_empty()))
}

/// POST /research/dns body — `query` plus optional `indicator_type`
/// (defaults to domain in v1).
#[derive(Deserialize)]
struct DnsBody {
    query: Option<String>,
    indicator_type: Option<String>,
}

/// DNS-only lookup. Returns v1's `DnsResult.to_dict()` shape with empty records
/// since no resolver is queried in this port.
async fn dns_lookup(
    _user: CurrentUser,
    Json(body): Json<DnsBody>,
) -> Result<Json<Value>, ApiError> {
    validate_query(body.query.as_deref())?;
    validate_indicator_type(body.indicator_type.as_deref(), false)?;
    Ok(Json(dns_empty()))
}

/// ASN-only lookup. `indicator_type` is required (v1 `AsnLookupRequest`);
/// returns v1's no-data body since Team Cymru is not queried in this port.
async fn asn_lookup(
    _user: CurrentUser,
    Json(body): Json<QueryTypeBody>,
) -> Result<Json<Value>, ApiError> {
    validate_query(body.query.as_deref())?;
    validate_indicator_type(body.indicator_type.as_deref(), true)?;
    Ok(Json(json!({"error": "No ASN data found"})))
}

/// Parses the raw body of the shodan/maltego routes exactly like v1's
/// `request.get_json()` + `"query" in data` guard: invalid JSON →
/// `Err("Invalid request format")`, missing/absent `query` key →
/// `Err("Query field required")`. On success returns the whole object so the
/// maltego route can also read `indicator_type`; the caller renders the error
/// message as a bare `400 {"error": <msg>}` body (v1 shape).
fn parse_query_body(body: &[u8]) -> Result<serde_json::Map<String, Value>, &'static str> {
    if body.is_empty() {
        // v1: get_json() → None → "not data" branch.
        return Err("Query field required");
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| "Invalid request format")?;
    let Value::Object(map) = value else {
        return Err("Query field required");
    };
    if !map.contains_key("query") {
        return Err("Query field required");
    }
    Ok(map)
}

/// Renders a `parse_query_body` error message as v1's bare
/// `400 {"error": <msg>}` body.
fn bad_query(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
}

/// Shodan-only lookup. The "not enabled" 503 gate is checked before the body,
/// exactly as v1 does; when enabled it returns v1's no-data body (no live
/// Shodan call in this port).
async fn shodan_lookup(_user: CurrentUser, body: axum::body::Bytes) -> Response {
    let cfg = ResearchConfig::from_env();
    if !cfg.shodan_effective() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Shodan integration not enabled",
                "details": "Please configure Shodan API key and enable integration",
            })),
        )
            .into_response();
    }
    match parse_query_body(&body) {
        Err(msg) => bad_query(msg),
        Ok(_) => Json(json!({"error": "No Shodan data found"})).into_response(),
    }
}

/// Maltego transforms. The "not enabled" 503 gate precedes the body, matching
/// v1; when enabled it returns v1's no-data body (no live transform in this
/// port). `indicator_type` defaults to "domain" like v1 but does not change the
/// empty response.
async fn maltego_lookup(_user: CurrentUser, body: axum::body::Bytes) -> Response {
    let cfg = ResearchConfig::from_env();
    if !cfg.maltego_effective() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Maltego integration not enabled",
                "details": "Please configure Maltego and enable integration",
            })),
        )
            .into_response();
    }
    match parse_query_body(&body) {
        Err(msg) => bad_query(msg),
        Ok(_) => Json(json!({"error": "No Maltego data found"})).into_response(),
    }
}

/// GET /research/config — research source status and timeouts. Config is read
/// from the environment at request time (same pattern as alerts.rs `AI_ENABLED`
/// and threat_intel.rs feed keys).
async fn get_config(_user: CurrentUser) -> Result<Json<Value>, ApiError> {
    let cfg = ResearchConfig::from_env();
    Ok(Json(config_json(&cfg)))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    /// Boots a TestServer with only the research router nested under /api/v1 —
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

    fn disabled_config() -> ResearchConfig {
        ResearchConfig {
            research_enabled: true,
            shodan_enabled: false,
            shodan_api_key: None,
            maltego_enabled: false,
        }
    }

    #[test]
    fn config_json_matches_v1_shape_and_defaults() {
        let v = config_json(&disabled_config());
        assert_eq!(
            v,
            json!({
                "research_enabled": true,
                "whois_enabled": true,
                "dns_enabled": true,
                "asn_enabled": true,
                "shodan_enabled": false,
                "maltego_enabled": false,
                "default_timeout": 30,
                "whois_timeout": 10,
                "dns_timeout": 5,
                "asn_timeout": 5,
                "shodan_timeout": 30,
                "maltego_timeout": 30,
            })
        );
    }

    #[test]
    fn config_json_reflects_raw_flags() {
        let cfg = ResearchConfig {
            research_enabled: false,
            shodan_enabled: true,
            shodan_api_key: Some("k".to_owned()),
            maltego_enabled: true,
        };
        let v = config_json(&cfg);
        assert_eq!(v["research_enabled"], false);
        assert_eq!(v["shodan_enabled"], true);
        assert_eq!(v["maltego_enabled"], true);
    }

    #[test]
    fn shodan_gate_requires_flag_and_key() {
        // flag on, no key → disabled (v1: `enabled and api_key is not None`).
        let mut cfg = disabled_config();
        cfg.shodan_enabled = true;
        assert!(!cfg.shodan_effective());
        cfg.shodan_api_key = Some(String::new()); // present (even empty) → on
        assert!(cfg.shodan_effective());
        cfg.shodan_enabled = false;
        assert!(!cfg.shodan_effective());
    }

    #[test]
    fn maltego_gate_is_flag_only() {
        let mut cfg = disabled_config();
        assert!(!cfg.maltego_effective());
        cfg.maltego_enabled = true;
        assert!(cfg.maltego_effective());
    }

    #[test]
    fn env_bool_matches_python_truthiness() {
        assert!(env_bool("SKAUS_RESEARCH_TEST_UNSET_XYZ", true));
        assert!(!env_bool("SKAUS_RESEARCH_TEST_UNSET_XYZ", false));
    }

    #[test]
    fn classify_covers_each_type() {
        assert_eq!(classify("1.2.3.4").as_deref(), Some("ip"));
        assert_eq!(classify("fe80::1").as_deref(), Some("ip"));
        assert_eq!(classify("::1").as_deref(), Some("ip"));
        assert_eq!(classify("https://evil.example/x").as_deref(), Some("url"));
        assert_eq!(classify(&"a".repeat(32)).as_deref(), Some("hash"));
        assert_eq!(classify(&"b".repeat(64)).as_deref(), Some("hash"));
        assert_eq!(classify("AS15169").as_deref(), Some("asn"));
        assert_eq!(classify("user@example.com").as_deref(), Some("email"));
        assert_eq!(classify("evil.example.com").as_deref(), Some("domain"));
        assert_eq!(classify("!!!"), None);
        assert_eq!(classify("   "), None);
    }

    #[test]
    fn validate_query_bounds() {
        assert!(matches!(validate_query(None), Err(ApiError::Validation(_))));
        assert!(matches!(
            validate_query(Some("")),
            Err(ApiError::Validation(_))
        ));
        let long = "x".repeat(501);
        assert!(matches!(
            validate_query(Some(&long)),
            Err(ApiError::Validation(_))
        ));
        match validate_query(Some("evil.example.com")) {
            Ok(q) => assert_eq!(q, "evil.example.com"),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
    }

    #[test]
    fn validate_indicator_type_required_and_enum() {
        assert!(matches!(
            validate_indicator_type(None, true),
            Err(ApiError::Validation(_))
        ));
        match validate_indicator_type(None, false) {
            Ok(None) => {}
            other => panic!("expected Ok(None), got {other:?}"),
        }
        match validate_indicator_type(Some("ip"), true) {
            Ok(Some(t)) => assert_eq!(t, "ip"),
            other => panic!("expected Ok(Some(ip)), got {other:?}"),
        }
        let d = match validate_indicator_type(Some("mac"), false) {
            Err(ApiError::Validation(details)) => details.first().cloned().unwrap_or(Value::Null),
            other => panic!("expected validation error, got {other:?}"),
        };
        assert_eq!(d["msg"], TYPE_MSG);
    }

    #[test]
    fn parse_query_body_matches_v1_guards() {
        assert!(parse_query_body(b"").is_err()); // empty → Query field required
        assert!(parse_query_body(b"not json").is_err()); // invalid → Invalid request format
        assert!(parse_query_body(b"[1,2]").is_err()); // non-object → Query field required
        assert!(parse_query_body(br#"{"foo":1}"#).is_err()); // no query key
        match parse_query_body(br#"{"query":"1.2.3.4"}"#) {
            Ok(map) => assert_eq!(map["query"], json!("1.2.3.4")),
            Err(_) => panic!("expected ok"),
        }
    }

    #[test]
    fn is_ipv4_edge_cases() {
        assert!(is_ipv4("0.0.0.0"));
        assert!(is_ipv4("255.255.255.255"));
        assert!(!is_ipv4("256.1.1.1"));
        assert!(!is_ipv4("1.2.3"));
        assert!(!is_ipv4("1.2.3.4.5"));
        assert!(!is_ipv4("fe80::1"));
    }

    #[tokio::test]
    async fn all_routes_require_auth() {
        let server = test_server();
        let responses = [
            server.post("/api/v1/research/lookup").await,
            server.post("/api/v1/research/whois").await,
            server.post("/api/v1/research/dns").await,
            server.post("/api/v1/research/asn").await,
            server.post("/api/v1/research/shodan").await,
            server.post("/api/v1/research/maltego").await,
            server.get("/api/v1/research/config").await,
        ];
        for res in responses {
            res.assert_status(StatusCode::UNAUTHORIZED);
            let body: Value = res.json();
            assert_eq!(body["error"], "Unauthorized");
            assert_eq!(body["detail"], "Missing authorization header");
        }
    }

    #[tokio::test]
    async fn garbage_bearer_token_is_rejected() {
        let server = test_server();
        let res = server
            .get("/api/v1/research/config")
            .authorization_bearer("not-a-jwt")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: Value = res.json();
        assert_eq!(body["error"], "Unauthorized");
        assert_eq!(body["detail"], "Invalid token");
    }
}
