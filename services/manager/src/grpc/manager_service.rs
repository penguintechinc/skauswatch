//! `skauswatch.manager.ManagerService` — the 7 RPCs live in v1
//! (HealthCheck, CreateAlert, GetAlert, UpdateAlertStatus, CreateIOC,
//! LookupIndicator, LogAuditEvent) ported field-for-field from
//! services/manager/grpc/server.py; every other RPC answers UNIMPLEMENTED
//! "Method not implemented!" exactly like v1's unregistered base methods.

use std::pin::Pin;

use chrono::NaiveDateTime;
use sqlx::{Postgres, QueryBuilder};
use tonic::{Request, Response, Status};

use skauswatch_proto::manager::manager_service_server::ManagerService;
use skauswatch_proto::manager::{
    AiReviewQuery, AiReviewRequest, AiReviewResponse, AiReviewResult, AlertEvent, AlertFilter,
    AlertQuery, AlertRequest, AlertResponse, AlertSeverity, AlertStatus, AlertStatusUpdate,
    ApprovalDecision, ApprovalQuery, ApprovalRequest, ApprovalResponse, AuditEvent, AuditResponse,
    EnrichRequest, EnrichResponse, HealthResponse, IndicatorLookup, IndicatorMatch, IndicatorType,
    IocListResponse, IocQuery, IocRequest, IocResponse, ThreatLevel,
};

use super::{
    check_api_version, db_err, method_not_implemented, now_ts, require_jwt, ts_from_naive,
};
use crate::state::AppState;

/// v1 `HealthResponse.version` — the Python servicer hardcoded "1.0.0"
/// (it never read the .version file on the gRPC path). Kept for parity;
/// the REST /healthz reports the real version.
const V1_GRPC_VERSION: &str = "1.0.0";

/// ManagerService servicer backed by the shared AppState (DB pool).
pub struct ManagerGrpc {
    state: AppState,
}

impl ManagerGrpc {
    /// Wraps the shared state for the tonic service registration.
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Fetches an alert row and renders the v1 AlertResponse, or NOT_FOUND
    /// "Alert not found" — shared by GetAlert and UpdateAlertStatus.
    async fn fetch_alert(&self, alert_id: i64) -> Result<AlertResponse, Status> {
        // v1 compared the raw int against the integer PK; out-of-range ids
        // simply never match a row.
        let Ok(pk) = i32::try_from(alert_id) else {
            return Err(Status::not_found("Alert not found"));
        };
        let row: Option<AlertRow> = sqlx::query_as(
            "SELECT id, title, description, severity, status, source, indicators, \
             created_at, updated_at FROM alerts WHERE id = $1",
        )
        .bind(pk)
        .fetch_optional(&self.state.db)
        .await
        .map_err(db_err)?;
        row.map(alert_response)
            .ok_or_else(|| Status::not_found("Alert not found"))
    }
}

/// Alert row selected for gRPC responses (timestamps kept native for
/// protobuf Timestamp conversion, unlike the REST `::text` convention).
#[derive(sqlx::FromRow)]
struct AlertRow {
    id: i32,
    title: String,
    description: Option<String>,
    severity: String,
    status: String,
    source: Option<String>,
    indicators: Option<serde_json::Value>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

/// v1 GetAlert field population: `or ""` string defaults, enum maps with
/// medium/pending fallbacks, updated_at only when set.
fn alert_response(row: AlertRow) -> AlertResponse {
    AlertResponse {
        id: i64::from(row.id),
        title: row.title,
        description: row.description.unwrap_or_default(),
        severity: db_severity(&row.severity),
        status: db_status(&row.status),
        source: row.source.unwrap_or_default(),
        indicators: json_string_vec(row.indicators.as_ref()),
        ai_review: None,
        created_at: row.created_at.map(ts_from_naive),
        updated_at: row.updated_at.map(ts_from_naive),
    }
}

/// jsonb array → Vec<String> (v1 `alert.indicators or []`); non-string
/// entries are skipped — v1 rows only ever hold string arrays.
fn json_string_vec(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|j| j.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// protobuf map<string,string> → jsonb object (v1 `dict(request.details)`).
fn map_to_json(m: &std::collections::HashMap<String, String>) -> serde_json::Value {
    serde_json::Value::Object(
        m.iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect(),
    )
}

/// v1 `severity_map.get(request.severity, "medium")` — enum → DB string.
fn severity_to_db(v: i32) -> &'static str {
    match AlertSeverity::try_from(v) {
        Ok(AlertSeverity::SeverityInfo) => "info",
        Ok(AlertSeverity::SeverityLow) => "low",
        Ok(AlertSeverity::SeverityMedium) => "medium",
        Ok(AlertSeverity::SeverityHigh) => "high",
        Ok(AlertSeverity::SeverityCritical) => "critical",
        _ => "medium",
    }
}

/// v1 GetAlert `severity_map.get(..., SEVERITY_MEDIUM)` — DB string → enum.
fn db_severity(s: &str) -> i32 {
    (match s {
        "info" => AlertSeverity::SeverityInfo,
        "low" => AlertSeverity::SeverityLow,
        "high" => AlertSeverity::SeverityHigh,
        "critical" => AlertSeverity::SeverityCritical,
        _ => AlertSeverity::SeverityMedium,
    }) as i32
}

/// v1 UpdateAlertStatus `status_map.get(..., "pending")` — enum → DB string.
fn status_to_db(v: i32) -> &'static str {
    match AlertStatus::try_from(v) {
        Ok(AlertStatus::StatusPending) => "pending",
        Ok(AlertStatus::StatusInProgress) => "in_progress",
        Ok(AlertStatus::StatusResolved) => "resolved",
        Ok(AlertStatus::StatusFalsePositive) => "false_positive",
        Ok(AlertStatus::StatusEscalated) => "escalated",
        _ => "pending",
    }
}

/// v1 GetAlert `status_map.get(..., STATUS_PENDING)` — DB string → enum.
fn db_status(s: &str) -> i32 {
    (match s {
        "in_progress" => AlertStatus::StatusInProgress,
        "resolved" => AlertStatus::StatusResolved,
        "false_positive" => AlertStatus::StatusFalsePositive,
        "escalated" => AlertStatus::StatusEscalated,
        _ => AlertStatus::StatusPending,
    }) as i32
}

/// v1 `type_map.get(request.indicator_type, "ip")` — enum → DB string.
fn indicator_to_db(v: i32) -> &'static str {
    match IndicatorType::try_from(v) {
        Ok(IndicatorType::IndicatorIp) => "ip",
        Ok(IndicatorType::IndicatorDomain) => "domain",
        Ok(IndicatorType::IndicatorHash) => "hash",
        Ok(IndicatorType::IndicatorUrl) => "url",
        Ok(IndicatorType::IndicatorEmail) => "email",
        Ok(IndicatorType::IndicatorFile) => "file",
        _ => "ip",
    }
}

/// v1 LookupIndicator reverse type map (default INDICATOR_IP).
fn db_indicator(s: &str) -> i32 {
    (match s {
        "domain" => IndicatorType::IndicatorDomain,
        "hash" => IndicatorType::IndicatorHash,
        "url" => IndicatorType::IndicatorUrl,
        "email" => IndicatorType::IndicatorEmail,
        "file" => IndicatorType::IndicatorFile,
        _ => IndicatorType::IndicatorIp,
    }) as i32
}

/// v1 `level_map.get(request.threat_level, "medium")` — enum → DB string.
fn threat_to_db(v: i32) -> &'static str {
    match ThreatLevel::try_from(v) {
        Ok(ThreatLevel::ThreatInfo) => "info",
        Ok(ThreatLevel::ThreatLow) => "low",
        Ok(ThreatLevel::ThreatMedium) => "medium",
        Ok(ThreatLevel::ThreatHigh) => "high",
        Ok(ThreatLevel::ThreatCritical) => "critical",
        _ => "medium",
    }
}

/// v1 LookupIndicator reverse level map (default THREAT_MEDIUM).
fn db_threat(s: &str) -> i32 {
    (match s {
        "info" => ThreatLevel::ThreatInfo,
        "low" => ThreatLevel::ThreatLow,
        "high" => ThreatLevel::ThreatHigh,
        "critical" => ThreatLevel::ThreatCritical,
        _ => ThreatLevel::ThreatMedium,
    }) as i32
}

/// v1 `ioc.confidence or 0.5` — Python falsiness: NULL **and 0.0** both
/// fall back to 0.5. Replicated exactly for wire parity.
fn lookup_confidence(c: Option<f64>) -> f32 {
    let c = c.unwrap_or(0.0);
    if c == 0.0_f64 { 0.5 } else { c as f32 }
}

#[tonic::async_trait]
impl ManagerService for ManagerGrpc {
    /// HealthCheck — v1 parity: `status` depends only on the DB probe;
    /// `redis` is hardcoded "connected" and `version` "1.0.0" exactly as
    /// the Python servicer did (it had no stream-manager handle).
    async fn health_check(
        &self,
        _request: Request<()>,
    ) -> Result<Response<HealthResponse>, Status> {
        let database = match sqlx::query("SELECT 1").execute(&self.state.db).await {
            Ok(_) => "connected".to_owned(),
            Err(e) => format!("error: {e}"),
        };
        let status = if database == "connected" {
            "healthy"
        } else {
            "unhealthy"
        };
        Ok(Response::new(HealthResponse {
            status: status.to_owned(),
            version: V1_GRPC_VERSION.to_owned(),
            database,
            redis: "connected".to_owned(),
            timestamp: Some(now_ts()),
        }))
    }

    /// CreateAlert — insert status "pending"; the response echoes the
    /// request severity enum untouched (v1 behavior) and, unlike the REST
    /// route, publishes nothing to alerts:pending (v1 gRPC never did).
    async fn create_alert(
        &self,
        request: Request<AlertRequest>,
    ) -> Result<Response<AlertResponse>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        // v1 ignored request.metadata entirely; proto3 unset strings insert
        // as "" (not NULL), matching the Python servicer.
        let indicators = serde_json::Value::from(req.indicators.clone());
        let row: (i32, Option<NaiveDateTime>) = sqlx::query_as(
            "INSERT INTO alerts (title, description, severity, status, source, indicators, \
             created_at) VALUES ($1, $2, $3, 'pending', $4, $5, now()) \
             RETURNING id, created_at",
        )
        .bind(&req.title)
        .bind(&req.description)
        .bind(severity_to_db(req.severity))
        .bind(&req.source)
        .bind(&indicators)
        .fetch_one(&self.state.db)
        .await
        .map_err(db_err)?;

        Ok(Response::new(AlertResponse {
            id: i64::from(row.0),
            title: req.title,
            description: req.description,
            severity: req.severity,
            status: AlertStatus::StatusPending as i32,
            source: req.source,
            indicators: req.indicators,
            ai_review: None,
            created_at: row.1.map(ts_from_naive),
            updated_at: None,
        }))
    }

    /// GetAlert — NOT_FOUND "Alert not found" when missing; enum fallbacks
    /// medium/pending, `or ""` strings, updated_at only when set.
    async fn get_alert(
        &self,
        request: Request<AlertQuery>,
    ) -> Result<Response<AlertResponse>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;
        Ok(Response::new(self.fetch_alert(req.alert_id).await?))
    }

    /// UpdateAlertStatus — maps the enum (unknown → "pending"), sets
    /// resolution_notes only when non-empty, resolved_at when RESOLVED,
    /// updated_at always (v1 pydal `update=utcnow`), then returns GetAlert.
    async fn update_alert_status(
        &self,
        request: Request<AlertStatusUpdate>,
    ) -> Result<Response<AlertResponse>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;
        let Ok(pk) = i32::try_from(req.alert_id) else {
            return Err(Status::not_found("Alert not found"));
        };

        let mut qb =
            QueryBuilder::<Postgres>::new("UPDATE alerts SET updated_at = now(), status = ");
        qb.push_bind(status_to_db(req.new_status));
        if !req.resolution_notes.is_empty() {
            qb.push(", resolution_notes = ")
                .push_bind(req.resolution_notes.clone());
        }
        if req.new_status == AlertStatus::StatusResolved as i32 {
            qb.push(", resolved_at = now()");
        }
        qb.push(" WHERE id = ").push_bind(pk);
        let result = qb.build().execute(&self.state.db).await.map_err(db_err)?;
        if result.rows_affected() == 0 {
            return Err(Status::not_found("Alert not found"));
        }
        Ok(Response::new(self.fetch_alert(req.alert_id).await?))
    }

    /// Server streaming response type for the StreamAlerts method.
    type StreamAlertsStream = Pin<
        Box<dyn tonic::codegen::tokio_stream::Stream<Item = Result<AlertEvent, Status>> + Send>,
    >;

    /// StreamAlerts — declared in the proto, never implemented in v1.
    async fn stream_alerts(
        &self,
        _request: Request<AlertFilter>,
    ) -> Result<Response<Self::StreamAlertsStream>, Status> {
        Err(method_not_implemented())
    }

    /// RequestAIReview — declared in the proto, never implemented in v1.
    async fn request_ai_review(
        &self,
        _request: Request<AiReviewRequest>,
    ) -> Result<Response<AiReviewResponse>, Status> {
        Err(method_not_implemented())
    }

    /// GetAIReviewResult — declared in the proto, never implemented in v1.
    async fn get_ai_review_result(
        &self,
        _request: Request<AiReviewQuery>,
    ) -> Result<Response<AiReviewResult>, Status> {
        Err(method_not_implemented())
    }

    /// CreateIOC — insert with medium/ip fallbacks; request.expires_at is
    /// ignored (v1 never inserted it); response echoes the request enums.
    async fn create_ioc(
        &self,
        request: Request<IocRequest>,
    ) -> Result<Response<IocResponse>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let tags = serde_json::Value::from(req.tags.clone());
        let metadata = map_to_json(&req.metadata);
        let row: (i32, Option<NaiveDateTime>) = sqlx::query_as(
            "INSERT INTO threat_indicators (indicator_type, value, threat_level, confidence, \
             source, tags, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now()) \
             RETURNING id, created_at",
        )
        .bind(indicator_to_db(req.indicator_type))
        .bind(&req.value)
        .bind(threat_to_db(req.threat_level))
        .bind(f64::from(req.confidence))
        .bind(&req.source)
        .bind(&tags)
        .bind(&metadata)
        .fetch_one(&self.state.db)
        .await
        .map_err(db_err)?;

        Ok(Response::new(IocResponse {
            id: i64::from(row.0),
            indicator_type: req.indicator_type,
            value: req.value,
            threat_level: req.threat_level,
            confidence: req.confidence,
            source: req.source,
            tags: req.tags,
            created_at: row.1.map(ts_from_naive),
        }))
    }

    /// QueryIOCs — declared in the proto, never implemented in v1.
    async fn query_io_cs(
        &self,
        _request: Request<IocQuery>,
    ) -> Result<Response<IocListResponse>, Status> {
        Err(method_not_implemented())
    }

    /// LookupIndicator — first row matching type+value; found:false when
    /// absent. Confidence falls back to 0.5 on NULL **or 0.0** (v1 `or`).
    async fn lookup_indicator(
        &self,
        request: Request<IndicatorLookup>,
    ) -> Result<Response<IndicatorMatch>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let row: Option<IocRow> = sqlx::query_as(
            "SELECT id, indicator_type, value, threat_level, confidence, source, tags, \
             created_at FROM threat_indicators WHERE indicator_type = $1 AND value = $2 LIMIT 1",
        )
        .bind(indicator_to_db(req.r#type))
        .bind(&req.value)
        .fetch_optional(&self.state.db)
        .await
        .map_err(db_err)?;

        let Some(ioc) = row else {
            return Ok(Response::new(IndicatorMatch {
                found: false,
                ioc: None,
            }));
        };
        Ok(Response::new(IndicatorMatch {
            found: true,
            ioc: Some(IocResponse {
                id: i64::from(ioc.id),
                indicator_type: db_indicator(&ioc.indicator_type),
                value: ioc.value,
                threat_level: db_threat(ioc.threat_level.as_deref().unwrap_or_default()),
                confidence: lookup_confidence(ioc.confidence),
                source: ioc.source.unwrap_or_default(),
                tags: json_string_vec(ioc.tags.as_ref()),
                created_at: ioc.created_at.map(ts_from_naive),
            }),
        }))
    }

    /// EnrichIndicator — declared in the proto, never implemented in v1.
    async fn enrich_indicator(
        &self,
        _request: Request<EnrichRequest>,
    ) -> Result<Response<EnrichResponse>, Status> {
        Err(method_not_implemented())
    }

    /// CreateApprovalRequest — declared in the proto, never implemented in v1.
    async fn create_approval_request(
        &self,
        _request: Request<ApprovalRequest>,
    ) -> Result<Response<ApprovalResponse>, Status> {
        Err(method_not_implemented())
    }

    /// ProcessApproval — declared in the proto, never implemented in v1.
    async fn process_approval(
        &self,
        _request: Request<ApprovalDecision>,
    ) -> Result<Response<ApprovalResponse>, Status> {
        Err(method_not_implemented())
    }

    /// GetApprovalStatus — declared in the proto, never implemented in v1.
    async fn get_approval_status(
        &self,
        _request: Request<ApprovalQuery>,
    ) -> Result<Response<ApprovalResponse>, Status> {
        Err(method_not_implemented())
    }

    /// LogAuditEvent — insert audit_logs (user_id 0 → NULL, severity "" →
    /// "info"); response event_id "audit-{unix_ts}", success true.
    async fn log_audit_event(
        &self,
        request: Request<AuditEvent>,
    ) -> Result<Response<AuditResponse>, Status> {
        require_jwt(request.metadata(), &self.state.auth.jwt_secret)?;
        let req = request.into_inner();
        check_api_version(&req.api_version)?;

        let user_id: Option<i32> = i32::try_from(req.user_id).ok().filter(|id| *id != 0);
        let severity = if req.severity.is_empty() {
            "info"
        } else {
            req.severity.as_str()
        };
        let details = map_to_json(&req.details);
        sqlx::query(
            "INSERT INTO audit_logs (event_type, action, resource_type, resource_id, user_id, \
             ip_address, success, details, severity, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())",
        )
        .bind(&req.event_type)
        .bind(&req.action)
        .bind(&req.resource_type)
        .bind(&req.resource_id)
        .bind(user_id)
        .bind(&req.ip_address)
        .bind(req.success)
        .bind(&details)
        .bind(severity)
        .execute(&self.state.db)
        .await
        .map_err(db_err)?;

        // v1: f"audit-{datetime.utcnow().timestamp()}" — informational id;
        // Rust renders a fixed six fractional digits.
        let now = chrono::Utc::now();
        Ok(Response::new(AuditResponse {
            event_id: format!(
                "audit-{}.{:06}",
                now.timestamp(),
                now.timestamp_subsec_micros()
            ),
            success: true,
            timestamp: Some(now_ts()),
        }))
    }
}

/// IOC row selected for LookupIndicator responses.
#[derive(sqlx::FromRow)]
struct IocRow {
    id: i32,
    indicator_type: String,
    value: String,
    threat_level: Option<String>,
    confidence: Option<f64>,
    source: Option<String>,
    tags: Option<serde_json::Value>,
    created_at: Option<NaiveDateTime>,
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use crate::grpc::test_util::test_state;
    use tonic::Code;

    fn svc() -> ManagerGrpc {
        ManagerGrpc::new(test_state())
    }

    /// Wraps `msg` in a `Request` carrying a valid `test-secret`-signed
    /// bearer token, matching `test_state()`'s `AuthSettings::jwt_secret`.
    fn authed<T>(msg: T) -> Request<T> {
        let token = match skauswatch_auth::issue_service_token(
            "test-caller",
            "admin",
            "test-secret",
            300,
        ) {
            Ok(t) => t,
            Err(e) => panic!("issue test token: {e}"),
        };
        let mut req = Request::new(msg);
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("authorization", value);
        req
    }

    #[tokio::test]
    async fn create_alert_without_jwt_is_unauthenticated() {
        let err = match svc()
            .create_alert(Request::new(AlertRequest {
                title: "t".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("missing bearer token must be rejected"),
        };
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn get_alert_with_wrong_secret_is_unauthenticated() {
        let bad_token =
            match skauswatch_auth::issue_service_token("x", "admin", "wrong-secret", 300) {
                Ok(t) => t,
                Err(e) => panic!("issue token: {e}"),
            };
        let mut req = Request::new(AlertQuery {
            alert_id: 1,
            api_version: "v1".to_owned(),
        });
        let value = match format!("Bearer {bad_token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("authorization", value);
        let err = match svc().get_alert(req).await {
            Err(e) => e,
            Ok(_) => panic!("wrong-secret token must be rejected"),
        };
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn health_check_requires_no_jwt() {
        // HealthCheck is intentionally left open (liveness/readiness probe,
        // not in the audit's gated-method list) — must succeed with no
        // authorization metadata at all.
        assert!(svc().health_check(Request::new(())).await.is_ok());
    }

    #[tokio::test]
    async fn health_check_reports_v1_hardcoded_fields_and_db_error() {
        let resp = match svc().health_check(Request::new(())).await {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("health_check must not error: {e}"),
        };
        // Test pool is unreachable → DB probe fails → unhealthy.
        assert_eq!(resp.status, "unhealthy");
        assert!(
            resp.database.starts_with("error: "),
            "db: {}",
            resp.database
        );
        // v1 hardcodes: redis "connected", version "1.0.0".
        assert_eq!(resp.redis, "connected");
        assert_eq!(resp.version, "1.0.0");
        assert!(resp.timestamp.is_some());
    }

    #[tokio::test]
    async fn get_alert_empty_api_version_routes_like_old_v1_agents() {
        // Fielded v1 agents send no api_version (proto3 → ""): must route
        // past the gate and hit the handler (which fails on the test DB).
        let err = match svc()
            .get_alert(authed(AlertQuery {
                alert_id: 1,
                api_version: String::new(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("test DB is unreachable — handler must error"),
        };
        assert_eq!(err.code(), Code::Internal);
    }

    #[tokio::test]
    async fn get_alert_explicit_v1_routes_to_handler() {
        let err = match svc()
            .get_alert(authed(AlertQuery {
                alert_id: 1,
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("test DB is unreachable — handler must error"),
        };
        assert_eq!(err.code(), Code::Internal);
    }

    #[tokio::test]
    async fn get_alert_unknown_api_version_is_unimplemented() {
        let err = match svc()
            .get_alert(authed(AlertQuery {
                alert_id: 1,
                api_version: "v9".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), Code::Unimplemented);
        assert_eq!(err.message(), "api_version v9 not supported");
    }

    #[tokio::test]
    async fn create_alert_unknown_api_version_is_unimplemented() {
        let err = match svc()
            .create_alert(authed(AlertRequest {
                title: "t".to_owned(),
                api_version: "v9".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), Code::Unimplemented);
        assert_eq!(err.message(), "api_version v9 not supported");
    }

    #[tokio::test]
    async fn update_alert_status_unknown_api_version_is_unimplemented() {
        let err = match svc()
            .update_alert_status(authed(AlertStatusUpdate {
                alert_id: 1,
                new_status: AlertStatus::StatusResolved as i32,
                resolution_notes: String::new(),
                api_version: "v2".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v2 must be rejected"),
        };
        assert_eq!(err.code(), Code::Unimplemented);
        assert_eq!(err.message(), "api_version v2 not supported");
    }

    #[tokio::test]
    async fn create_ioc_and_lookup_gate_api_version() {
        let e1 = match svc()
            .create_ioc(authed(IocRequest {
                value: "1.2.3.4".to_owned(),
                api_version: "v9".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(e1.code(), Code::Unimplemented);

        let e2 = match svc()
            .lookup_indicator(authed(IndicatorLookup {
                r#type: IndicatorType::IndicatorIp as i32,
                value: "1.2.3.4".to_owned(),
                api_version: "v9".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(e2.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn log_audit_event_unknown_api_version_is_unimplemented() {
        let err = match svc()
            .log_audit_event(authed(AuditEvent {
                event_type: "endpoint".to_owned(),
                action: "test".to_owned(),
                api_version: "v9".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn dead_rpcs_answer_method_not_implemented() {
        let s = svc();
        let checks: Vec<(&str, Status)> = vec![
            (
                "query_io_cs",
                match s.query_io_cs(Request::new(IocQuery::default())).await {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
            (
                "enrich_indicator",
                match s
                    .enrich_indicator(Request::new(EnrichRequest::default()))
                    .await
                {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
            (
                "request_ai_review",
                match s
                    .request_ai_review(Request::new(AiReviewRequest::default()))
                    .await
                {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
            (
                "get_ai_review_result",
                match s
                    .get_ai_review_result(Request::new(AiReviewQuery::default()))
                    .await
                {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
            (
                "create_approval_request",
                match s
                    .create_approval_request(Request::new(ApprovalRequest::default()))
                    .await
                {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
            (
                "process_approval",
                match s
                    .process_approval(Request::new(ApprovalDecision::default()))
                    .await
                {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
            (
                "get_approval_status",
                match s
                    .get_approval_status(Request::new(ApprovalQuery::default()))
                    .await
                {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
            (
                "stream_alerts",
                match s.stream_alerts(Request::new(AlertFilter::default())).await {
                    Err(e) => e,
                    Ok(_) => panic!("dead RPC must be unimplemented"),
                },
            ),
        ];
        for (name, err) in checks {
            assert_eq!(err.code(), Code::Unimplemented, "{name}");
            assert_eq!(err.message(), "Method not implemented!", "{name}");
        }
    }

    #[test]
    fn enum_maps_match_v1_defaults() {
        // Enum → DB with v1 fallbacks.
        assert_eq!(
            severity_to_db(AlertSeverity::SeverityCritical as i32),
            "critical"
        );
        assert_eq!(
            severity_to_db(AlertSeverity::SeverityUnspecified as i32),
            "medium"
        );
        assert_eq!(severity_to_db(99), "medium");
        assert_eq!(
            status_to_db(AlertStatus::StatusFalsePositive as i32),
            "false_positive"
        );
        assert_eq!(status_to_db(0), "pending");
        assert_eq!(
            indicator_to_db(IndicatorType::IndicatorDomain as i32),
            "domain"
        );
        assert_eq!(indicator_to_db(0), "ip");
        assert_eq!(threat_to_db(ThreatLevel::ThreatHigh as i32), "high");
        assert_eq!(threat_to_db(42), "medium");
        // DB → enum with v1 fallbacks.
        assert_eq!(db_severity("info"), AlertSeverity::SeverityInfo as i32);
        assert_eq!(db_severity("bogus"), AlertSeverity::SeverityMedium as i32);
        assert_eq!(db_status("escalated"), AlertStatus::StatusEscalated as i32);
        assert_eq!(db_status("bogus"), AlertStatus::StatusPending as i32);
        assert_eq!(db_indicator("email"), IndicatorType::IndicatorEmail as i32);
        assert_eq!(db_indicator("bogus"), IndicatorType::IndicatorIp as i32);
        assert_eq!(db_threat("critical"), ThreatLevel::ThreatCritical as i32);
        assert_eq!(db_threat("bogus"), ThreatLevel::ThreatMedium as i32);
    }

    #[test]
    fn lookup_confidence_replicates_python_falsiness() {
        // NULL → 0.5, 0.0 → 0.5 (Python `ioc.confidence or 0.5`).
        assert_eq!(lookup_confidence(None), 0.5);
        assert_eq!(lookup_confidence(Some(0.0)), 0.5);
        assert_eq!(lookup_confidence(Some(0.9)), 0.9_f32);
    }

    #[tokio::test]
    async fn create_get_and_update_alert_round_trip_against_real_db() {
        let state = crate::grpc::test_util::db_state().await;
        let svc = ManagerGrpc::new(state);

        let created = match svc
            .create_alert(authed(AlertRequest {
                title: "gRPC alert".to_owned(),
                description: "d".to_owned(),
                severity: AlertSeverity::SeverityHigh as i32,
                source: "grpc".to_owned(),
                indicators: vec!["1.2.3.4".to_owned()],
                api_version: "v1".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("create_alert: {e:?}"),
        };
        assert_eq!(created.title, "gRPC alert");
        assert_eq!(created.status, AlertStatus::StatusPending as i32);
        assert!(created.created_at.is_some());

        let fetched = match svc
            .get_alert(authed(AlertQuery {
                alert_id: created.id,
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("get_alert: {e:?}"),
        };
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.severity, AlertSeverity::SeverityHigh as i32);
        assert_eq!(fetched.indicators, vec!["1.2.3.4".to_owned()]);

        let updated = match svc
            .update_alert_status(authed(AlertStatusUpdate {
                alert_id: created.id,
                new_status: AlertStatus::StatusResolved as i32,
                resolution_notes: "handled".to_owned(),
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("update_alert_status: {e:?}"),
        };
        assert_eq!(updated.status, AlertStatus::StatusResolved as i32);
        assert!(updated.updated_at.is_some());

        let not_found = match svc
            .get_alert(authed(AlertQuery {
                alert_id: 999_999_999,
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("expected not found"),
        };
        assert_eq!(not_found.code(), Code::NotFound);

        let update_missing = match svc
            .update_alert_status(authed(AlertStatusUpdate {
                alert_id: 999_999_999,
                new_status: AlertStatus::StatusResolved as i32,
                resolution_notes: String::new(),
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("expected not found"),
        };
        assert_eq!(update_missing.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn create_ioc_and_lookup_indicator_round_trip_against_real_db() {
        let state = crate::grpc::test_util::db_state().await;
        let svc = ManagerGrpc::new(state);

        let created = match svc
            .create_ioc(authed(IocRequest {
                indicator_type: IndicatorType::IndicatorDomain as i32,
                value: "grpc-evil.example.com".to_owned(),
                threat_level: ThreatLevel::ThreatCritical as i32,
                confidence: 0.9,
                source: "grpc-test".to_owned(),
                tags: vec!["c2".to_owned()],
                metadata: std::collections::HashMap::from([("k".to_owned(), "v".to_owned())]),
                api_version: "v1".to_owned(),
                ..Default::default()
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("create_ioc: {e:?}"),
        };
        assert_eq!(created.value, "grpc-evil.example.com");
        assert_eq!(created.threat_level, ThreatLevel::ThreatCritical as i32);

        let found = match svc
            .lookup_indicator(authed(IndicatorLookup {
                r#type: IndicatorType::IndicatorDomain as i32,
                value: "grpc-evil.example.com".to_owned(),
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("lookup_indicator: {e:?}"),
        };
        assert!(found.found);
        let ioc = found.ioc.unwrap_or_else(|| panic!("expected ioc in match"));
        assert_eq!(ioc.value, "grpc-evil.example.com");
        assert_eq!(ioc.threat_level, ThreatLevel::ThreatCritical as i32);

        let not_found = match svc
            .lookup_indicator(authed(IndicatorLookup {
                r#type: IndicatorType::IndicatorIp as i32,
                value: "203.0.113.250".to_owned(),
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("lookup_indicator: {e:?}"),
        };
        assert!(!not_found.found);
        assert!(not_found.ioc.is_none());
    }

    #[tokio::test]
    async fn log_audit_event_inserts_a_row_against_real_db() {
        let state = crate::grpc::test_util::db_state().await;
        let svc = ManagerGrpc::new(state);
        let resp = match svc
            .log_audit_event(authed(AuditEvent {
                event_type: "endpoint".to_owned(),
                action: "agent_registered".to_owned(),
                resource_type: "agent".to_owned(),
                resource_id: "agent-1".to_owned(),
                user_id: 0,
                ip_address: "10.0.0.5".to_owned(),
                success: true,
                details: std::collections::HashMap::new(),
                severity: String::new(),
                api_version: "v1".to_owned(),
            }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => panic!("log_audit_event: {e:?}"),
        };
        assert!(resp.success);
        assert!(resp.event_id.starts_with("audit-"));
        assert!(resp.timestamp.is_some());
    }

    #[test]
    fn json_string_vec_skips_nulls_and_non_strings() {
        assert_eq!(
            json_string_vec(Some(&serde_json::json!(["a", 1, "b", null]))),
            vec!["a".to_owned(), "b".to_owned()]
        );
        assert!(json_string_vec(Some(&serde_json::Value::Null)).is_empty());
        assert!(json_string_vec(None).is_empty());
    }
}
