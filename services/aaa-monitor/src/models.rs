//! Wire/data models for the AAA monitor service. Rust port of the v1
//! `services/aaa-monitor/models.py` dataclasses/pydantic models.
//!
//! Deviations from v1 (documented, not silent):
//! - `EventSearchRequest` in v1 only declared `query/event_type/severity/
//!   source/limit/offset`, but `log_processor.py`'s `_search_elasticsearch`/
//!   `_search_mongodb` read `request.sources`, `request.event_types`,
//!   `request.severities`, `request.start_time`, `request.end_time`,
//!   `request.sort_by`, `request.sort_order` — none of which exist on the
//!   real model. Every call to `POST /events/search` in v1 therefore raises
//!   `AttributeError` and 500s unconditionally; there is no working request
//!   shape to preserve byte-for-byte. This port defines the fields the query
//!   builders actually need (plural filters + time range + sort) so the
//!   endpoint works.
//! - `EventSearchResponse` in v1 declared `total` (not `total_count`), but
//!   `log_processor.py` constructed it with `total_count=...` — a field
//!   Pydantic v2 silently drops (`extra="ignore"` default), so `total`
//!   stayed 0 on every real response even had the AttributeError above not
//!   fired first. This port populates `total` correctly.
//! - v1's `BaseEvent` dataclass has no `processed_data` field, yet
//!   `log_processor.py`'s entire enrichment pipeline
//!   (`_enrich_event`/`_match_threat_intelligence`/`_classify_and_normalize`/
//!   `_add_geolocation`) unconditionally calls `event.processed_data.update(
//!   ...)` inside a try/except that logs and swallows the resulting
//!   `AttributeError`. That pipeline is unreachable from any HTTP route in
//!   v1 anyway (events are only ever produced by the log collectors, which
//!   are a tracked follow-up — see crate root docs), so it is not ported.
//!   `processed_data` is still modeled here (as a real, working field) so
//!   documents written by a future collector port deserialize cleanly.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Alert lifecycle status. v1 `AlertStatus`. Not constructed by any route
/// yet — `alerts.rs` faithfully ports v1's unbacked stub behavior (search
/// always empty, get always 404), so no real `Alert` ever carries a status.
/// Kept for wire-contract completeness and for when alert storage lands.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    /// Newly raised, not yet triaged.
    Open,
    /// A human has seen it.
    Acknowledged,
    /// Actively being worked.
    InProgress,
    /// Confirmed and resolved.
    Resolved,
    /// Closed without further action.
    Closed,
    /// Triaged and determined not to be a real issue.
    FalsePositive,
}

/// Supported AI provider types. v1 `AIProvider`. Kept for the deferred
/// AI-integration surface (`/ai/*`) — see crate root docs.
#[allow(dead_code)] // wired up once the AI-integration follow-up lands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProvider {
    /// OpenAI-hosted models.
    Openai,
    /// Anthropic-hosted models.
    Anthropic,
    /// Self-hosted Ollama.
    Ollama,
}

/// Event/alert severity levels. v1 `Severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Requires immediate action.
    Critical,
    /// High priority.
    High,
    /// Medium priority.
    Medium,
    /// Low priority.
    Low,
    /// Informational only.
    Info,
}

/// Threat intelligence confidence/impact level. v1 `ThreatLevel`. Wired up
/// once the threat-intel follow-up lands (see crate root docs) — not
/// constructed by any ported route today.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatLevel {
    /// Confirmed, severe threat.
    Critical,
    /// High-confidence threat.
    High,
    /// Medium-confidence threat.
    Medium,
    /// Low-confidence threat.
    Low,
    /// Threat level could not be determined.
    Unknown,
}

/// Security event categories. v1 `EventType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Login/logout/credential check.
    Authentication,
    /// Access-control decision.
    Authorization,
    /// Privilege escalation attempt or success.
    PrivilegeEscalation,
    /// Raw syscall audit record.
    SystemCall,
    /// Network connection/activity.
    Network,
    /// Network event (v1 kept both `network` and `network_event` variants).
    NetworkEvent,
    /// File read/write/delete.
    FileAccess,
    /// Process creation/termination.
    Process,
    /// Accounting record.
    Accounting,
    /// Generic access event.
    Access,
    /// Detected security violation.
    SecurityViolation,
    /// Generic system event.
    SystemEvent,
    /// Container lifecycle event.
    ContainerEvent,
    /// Application-level event.
    ApplicationEvent,
}

/// Origin of a collected log/event. v1 `LogSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    /// Linux audit subsystem.
    Auditd,
    /// Plain log file.
    File,
    /// Kubernetes API/events.
    Kubernetes,
    /// LXC/LXD container host.
    LxcLxd,
    /// Generic system source.
    System,
}

/// Base security event shared by every collector and returned by the
/// search/get/stream endpoints. v1 `BaseEvent` dataclass, `processed_data`
/// added as a real field (see module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseEvent {
    /// Unique event id (UUIDv4 when newly created).
    #[serde(default = "new_uuid")]
    pub id: String,
    /// Where the event originated.
    pub source: LogSource,
    /// Event category.
    pub event_type: EventType,
    /// Severity assigned at collection time.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
    /// Collection timestamp.
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,
    /// Unmodified source payload.
    #[serde(default)]
    pub raw_data: serde_json::Value,
    /// Free-form classification tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Originating host.
    #[serde(default)]
    pub host: String,
    /// Associated username, if any.
    #[serde(default)]
    pub user: Option<String>,
    /// Associated process name, if any.
    #[serde(default)]
    pub process: Option<String>,
    /// Associated process id, if any.
    #[serde(default)]
    pub pid: Option<i64>,
    /// Enrichment metadata (geo, hostnames, ...). Real field, currently
    /// populated only once a collector/enrichment port lands.
    #[serde(default)]
    pub enrichments: serde_json::Value,
    /// Threat-intel matches recorded against this event.
    #[serde(default)]
    pub threat_matches: Vec<serde_json::Value>,
    /// AI analysis result, if any was attached.
    #[serde(default)]
    pub ai_analysis: Option<serde_json::Value>,
    /// Working enrichment scratch space (see module docs: real field, v1
    /// lacked it and enrichment silently no-op'd).
    #[serde(default)]
    pub processed_data: serde_json::Value,
    /// Any additional fields present on a stored document that this struct
    /// doesn't model explicitly — preserved instead of failing
    /// deserialization (v1's `BaseEvent(**doc)` raised `TypeError` on any
    /// unexpected key).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Indicator of Compromise. v1 `IOC`. Modeled for contract completeness;
/// wired up once the threat-intel subsystem port lands (tracked follow-up).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// IOC id.
    #[serde(default = "new_uuid")]
    pub id: String,
    /// Indicator type (ip, domain, hash, ...).
    #[serde(rename = "type")]
    pub kind: String,
    /// Indicator value.
    #[serde(default)]
    pub value: String,
    /// Human description.
    #[serde(default)]
    pub description: String,
    /// Assessed threat level.
    #[serde(default = "unknown_threat_level")]
    pub threat_level: ThreatLevel,
    /// Confidence score (0.0-1.0).
    #[serde(default)]
    pub confidence: f64,
    /// Free-form tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Associated malware family names.
    #[serde(default)]
    pub malware_families: Vec<String>,
    /// MITRE-style kill-chain phases.
    #[serde(default)]
    pub kill_chain_phases: Vec<String>,
    /// Creation time.
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    /// Last update time.
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
    /// Optional expiration.
    #[serde(default)]
    pub expiration: Option<DateTime<Utc>>,
    /// Source feed id/name.
    #[serde(default)]
    pub source_feed: Option<String>,
    /// Free-form metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[allow(dead_code)] // referenced by the deferred Ioc/ThreatMatch models
fn unknown_threat_level() -> ThreatLevel {
    ThreatLevel::Unknown
}

/// Result of matching an event against threat intelligence. v1
/// `ThreatMatch`. Follow-up group (see [`Ioc`]).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    /// Matched event id.
    pub event_id: String,
    /// Matched IOC id.
    pub ioc_id: String,
    /// The value that matched.
    pub matched_value: String,
    /// The event field the match was found in.
    pub field_name: String,
    /// Match confidence.
    pub confidence: f64,
    /// Threat level of the matched IOC.
    #[serde(default = "unknown_threat_level")]
    pub threat_level: ThreatLevel,
    /// Match record id.
    #[serde(default = "new_uuid")]
    pub id: String,
    /// When the match was recorded.
    #[serde(default = "Utc::now")]
    pub matched_at: DateTime<Utc>,
    /// Free-form metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Threat intelligence feed configuration. v1 `ThreatFeed`. Follow-up group.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    /// Feed id.
    #[serde(default = "new_uuid")]
    pub id: String,
    /// Display name.
    pub name: String,
    /// Feed URL.
    pub url: String,
    /// Feed protocol (taxii, csv, stix, ...).
    #[serde(default = "default_feed_type")]
    pub feed_type: String,
    /// Whether the feed is actively polled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Poll frequency in seconds.
    #[serde(default = "default_update_frequency")]
    pub update_frequency: i64,
    /// Optional auth credentials.
    #[serde(default)]
    pub credentials: Option<serde_json::Value>,
    /// Optional extra HTTP headers.
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    /// Whether TLS certificates are verified.
    #[serde(default = "default_true")]
    pub certificate_verification: bool,
    /// Optional outbound proxy.
    #[serde(default)]
    pub proxy_url: Option<String>,
    /// Last successful update time.
    #[serde(default)]
    pub last_updated: Option<DateTime<Utc>>,
    /// Number of IOCs currently sourced from this feed.
    #[serde(default)]
    pub ioc_count: i64,
    /// Feed status string.
    #[serde(default = "default_unknown_status")]
    pub status: String,
    /// Free-form metadata.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[allow(dead_code)] // referenced by the deferred ThreatFeed model
fn default_feed_type() -> String {
    "taxii".to_owned()
}
#[allow(dead_code)] // referenced by the deferred ThreatFeed model
fn default_true() -> bool {
    true
}
#[allow(dead_code)] // referenced by the deferred ThreatFeed model
fn default_update_frequency() -> i64 {
    3600
}
#[allow(dead_code)] // referenced by the deferred ThreatFeed model
fn default_unknown_status() -> String {
    "unknown".to_owned()
}

/// Alert model for API responses. v1 `Alert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert id.
    pub id: String,
    /// Short title.
    pub title: String,
    /// Severity string.
    pub severity: String,
    /// Lifecycle status string.
    pub status: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Request body for `POST /alerts/search`. v1 `AlertSearchRequest`.
///
/// `Default` is implemented by hand for the same reason as
/// [`EventSearchRequest`]: a derived impl would give `limit: 0` instead of
/// the intended 50.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertSearchRequest {
    /// Free-text query.
    pub query: String,
    /// Optional severity filter.
    pub severity: Option<String>,
    /// Page size.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Page offset.
    pub offset: i64,
}

impl Default for AlertSearchRequest {
    fn default() -> Self {
        Self {
            query: String::new(),
            severity: None,
            limit: default_limit(),
            offset: 0,
        }
    }
}

fn default_limit() -> i64 {
    50
}

/// Response for `POST /alerts/search`. v1 `AlertSearchResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSearchResponse {
    /// Matching alerts.
    pub alerts: Vec<Alert>,
    /// Total match count.
    pub total: i64,
    /// Echoed page size.
    pub limit: i64,
    /// Echoed page offset.
    pub offset: i64,
}

/// Dashboard summary metrics. v1 `DashboardMetrics`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardMetrics {
    /// Total events processed.
    pub total_events: i64,
    /// Rolling events-per-hour rate.
    pub events_per_hour: f64,
    /// Open critical-severity alerts.
    pub critical_alerts: i64,
    /// Open high-severity alerts.
    pub high_alerts: i64,
    /// Open medium-severity alerts.
    pub medium_alerts: i64,
    /// Open low-severity alerts.
    pub low_alerts: i64,
    /// Threat-intel matches detected.
    pub threats_detected: i64,
    /// AI analyses run.
    pub ai_analyses: i64,
}

/// Request body for `POST /events/search`. See module docs for how this
/// differs from (and fixes) the v1 model.
///
/// `Default` is implemented by hand (not derived) so that
/// `EventSearchRequest::default()` in Rust code and `{}` over the wire
/// produce the identical, fully-defaulted request — a derived `Default`
/// would silently diverge from the `#[serde(default = "...")]` values below
/// (empty `sort_by`/`sort_order`/`limit` instead of `timestamp`/`desc`/50).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventSearchRequest {
    /// Free-text query matched against `message`/`processed_data`.
    pub query: String,
    /// Restrict to these sources (empty = no filter).
    pub sources: Vec<LogSource>,
    /// Restrict to these event types (empty = no filter).
    pub event_types: Vec<EventType>,
    /// Restrict to these severities (empty = no filter).
    pub severities: Vec<Severity>,
    /// Inclusive lower timestamp bound.
    pub start_time: Option<DateTime<Utc>>,
    /// Inclusive upper timestamp bound.
    pub end_time: Option<DateTime<Utc>>,
    /// Sort field (defaults to `timestamp`).
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    /// Sort order: `asc` or `desc`.
    #[serde(default = "default_sort_order")]
    pub sort_order: String,
    /// Page size.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Page offset.
    pub offset: i64,
}

impl Default for EventSearchRequest {
    fn default() -> Self {
        Self {
            query: String::new(),
            sources: Vec::new(),
            event_types: Vec::new(),
            severities: Vec::new(),
            start_time: None,
            end_time: None,
            sort_by: default_sort_by(),
            sort_order: default_sort_order(),
            limit: default_limit(),
            offset: 0,
        }
    }
}

fn default_sort_by() -> String {
    "timestamp".to_owned()
}
fn default_sort_order() -> String {
    "desc".to_owned()
}

/// Response for `POST /events/search`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSearchResponse {
    /// Matching events.
    pub events: Vec<BaseEvent>,
    /// Total match count (correctly populated — see module docs).
    pub total: i64,
    /// Echoed page size.
    pub limit: i64,
    /// Echoed page offset.
    pub offset: i64,
    /// Backend query latency in milliseconds.
    pub query_time_ms: f64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn severity_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(Severity::Critical).unwrap(),
            serde_json::json!("critical")
        );
        assert_eq!(
            serde_json::to_value(EventType::PrivilegeEscalation).unwrap(),
            serde_json::json!("privilege_escalation")
        );
        assert_eq!(
            serde_json::to_value(LogSource::LxcLxd).unwrap(),
            serde_json::json!("lxc_lxd")
        );
        assert_eq!(
            serde_json::to_value(AlertStatus::InProgress).unwrap(),
            serde_json::json!("in_progress")
        );
    }

    #[test]
    fn base_event_defaults_and_extra_fields_round_trip() {
        let doc = serde_json::json!({
            "source": "kubernetes",
            "event_type": "authentication",
            "severity": "high",
            "message": "login failed",
            "future_collector_field": "kept",
        });
        let event: BaseEvent = match serde_json::from_value(doc) {
            Ok(e) => e,
            Err(e) => panic!("expected ok, got {e}"),
        };
        assert_eq!(event.source, LogSource::Kubernetes);
        assert!(!event.id.is_empty());
        assert_eq!(
            event.extra.get("future_collector_field"),
            Some(&serde_json::json!("kept"))
        );
    }

    #[test]
    fn event_search_request_defaults_match_no_filter() {
        let req: EventSearchRequest = match serde_json::from_value(serde_json::json!({})) {
            Ok(r) => r,
            Err(e) => panic!("expected ok, got {e}"),
        };
        assert_eq!(req.limit, 50);
        assert_eq!(req.sort_by, "timestamp");
        assert_eq!(req.sort_order, "desc");
        assert!(req.sources.is_empty());
    }

    /// Threat-intel model shapes (`Ioc`/`ThreatMatch`/`ThreatFeed`/
    /// `AiProvider`) aren't wired to any route yet — see crate root docs for
    /// the tracked threat-intel/AI follow-up — but the wire shapes are
    /// exercised here so the contract is verified even before that lands.
    #[test]
    fn threat_intel_and_ai_models_round_trip_with_defaults() {
        let ioc: Ioc = match serde_json::from_value(serde_json::json!({
            "type": "ip",
            "value": "203.0.113.5",
        })) {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got {e}"),
        };
        assert_eq!(ioc.threat_level, ThreatLevel::Unknown);
        assert!(!ioc.id.is_empty());

        let feed: ThreatFeed = match serde_json::from_value(serde_json::json!({
            "name": "test-feed",
            "url": "https://example.test/taxii",
        })) {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got {e}"),
        };
        assert!(feed.enabled);
        assert_eq!(feed.feed_type, "taxii");

        let tm: ThreatMatch = match serde_json::from_value(serde_json::json!({
            "event_id": "e1",
            "ioc_id": "i1",
            "matched_value": "203.0.113.5",
            "field_name": "source_ip",
            "confidence": 0.9,
        })) {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got {e}"),
        };
        assert_eq!(tm.threat_level, ThreatLevel::Unknown);

        assert_eq!(
            serde_json::to_value(AiProvider::Anthropic).unwrap(),
            serde_json::json!("anthropic")
        );
    }
}
