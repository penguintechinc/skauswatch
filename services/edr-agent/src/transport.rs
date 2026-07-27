//! REST client that speaks the manager's `/api/v1/edr/*` HMAC-authenticated
//! protocol — Rust port of v1 `internal/reporters/rest_reporter.go`.
//!
//! Critical wire-compat fixes (not stubs — v1's Go client could never have
//! successfully talked to its own manager):
//!
//! 1. **Auth scheme.** v1's Go agent sent its static `api_key` config value
//!    verbatim as `X-API-Key`. Both the v1 Python manager and this port's
//!    `services/manager/src/routes/edr.rs` require
//!    `X-API-Key = hex(HMAC-SHA256(EDR_API_SECRET, agent_id))`, computed
//!    fresh per agent — a static token can never match, so v1's agent would
//!    have received 401 Unauthorized on every request. This client treats
//!    `config.api_key` as the shared HMAC secret and computes the header
//!    correctly (see `compute_api_key`, known-answer tested against the
//!    manager's own test vector).
//! 2. **Heartbeat body.** v1 sent no request body at all; the manager's
//!    `EDRHeartbeatRequest`/`HeartbeatBody` requires `agent_id`, so v1's
//!    heartbeat would 400/500. This client sends `{agent_id, status,
//!    metadata}`.
//! 3. **Event shape.** v1 sent `{type, timestamp, severity, data}` with no
//!    `agent_id` field. The manager's `EDREventRequest`/`parse_event`
//!    requires `agent_id` and `event_type` on every event object. This
//!    client sends the contract's actual shape (see `EventPayload`).
//!
//! Never logs `config.api_key` (the shared secret) or any computed
//! `X-API-Key` value.

use std::path::Path;
use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::{Certificate, Client, Identity, StatusCode};
use serde::Serialize;
use sha2::Sha256;
use tracing::warn;

use skauswatch_common::Error;

use crate::collectors::CollectedEvent;
use crate::config::TlsConfig;

type HmacSha256 = Hmac<Sha256>;

/// Manager REST request timeout — matches v1's `http.Client{Timeout: 30 *
/// time.Second}`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on events per report request — mirrors the manager's
/// `MAX_EVENTS_PER_REQUEST` (services/manager/src/routes/edr.rs); the agent
/// batches before this limit is ever reached (see `crate::agent`).
pub const MAX_EVENTS_PER_REQUEST: usize = 100;

/// Computes the `X-API-Key` header value the manager expects:
/// `hex(HMAC-SHA256(secret, agent_id))`. Byte-identical to the manager's
/// `expected_api_key` (services/manager/src/routes/edr.rs) and v1 Python's
/// `hmac.new(secret, agent_id, sha256).hexdigest()`.
pub fn compute_api_key(secret: &str, agent_id: &str) -> Result<String, Error> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| Error::Config(format!("invalid HMAC key length: {e}")))?;
    mac.update(agent_id.as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// `POST /api/v1/edr/register` body — field set matches the manager's
/// `RegisterBody` exactly.
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    /// This agent's stable identifier.
    pub agent_id: String,
    /// Local hostname.
    pub hostname: String,
    /// Local IP address; empty string when undetermined (v1 never
    /// determined one either — the manager defaults this to `""`).
    pub ip_address: String,
    /// `std::env::consts::OS` (`"linux"`/`"windows"`/`"macos"`).
    pub os_type: String,
    /// OS version string from `sysinfo::System::os_version()`.
    pub os_version: String,
    /// This binary's version (`CARGO_PKG_VERSION`).
    pub agent_version: String,
    /// Free-form metadata; carries the enabled collector names.
    pub metadata: serde_json::Value,
}

/// `POST /api/v1/edr/heartbeat` body — matches the manager's
/// `HeartbeatBody`.
#[derive(Debug, Serialize)]
struct HeartbeatRequest<'a> {
    agent_id: &'a str,
    status: &'a str,
    metadata: serde_json::Value,
}

/// One event in a `POST /api/v1/edr/events` batch — matches the fields
/// `parse_event` (services/manager/src/routes/edr.rs) reads.
#[derive(Debug, Serialize)]
pub struct EventPayload {
    /// The reporting agent's stable identifier.
    pub agent_id: String,
    /// `"process"` / `"file"` / `"network"`.
    pub event_type: String,
    /// One of critical/high/medium/low/info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Populated for process events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Populated for process events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Populated for network events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_connections: Option<Vec<serde_json::Value>>,
    /// Populated for file events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_operations: Option<Vec<serde_json::Value>>,
    /// The raw collector payload, always present.
    pub details: serde_json::Value,
}

impl EventPayload {
    /// Maps a collected event onto the manager's wire shape. The raw
    /// collector output always rides along in `details` (the manager's
    /// catch-all `Dict[str, Any]`); `process_name`/`command_line`/
    /// `network_connections`/`file_operations` are populated when the
    /// source collector naturally provides them, giving the manager
    /// queryable columns in addition to the full raw payload.
    pub fn from_collected(agent_id: &str, event: &CollectedEvent) -> Self {
        let data = &event.data;
        let process_name = data.get("name").and_then(|v| v.as_str()).map(str::to_owned);
        let command_line = data
            .get("cmdline")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let network_connections =
            (event.event_type == crate::collectors::EVENT_TYPE_NETWORK).then(|| vec![data.clone()]);
        let file_operations =
            (event.event_type == crate::collectors::EVENT_TYPE_FILE).then(|| vec![data.clone()]);

        Self {
            agent_id: agent_id.to_owned(),
            event_type: event.event_type.to_owned(),
            severity: Some(event.severity.as_str().to_owned()),
            process_name,
            command_line,
            network_connections,
            file_operations,
            details: data.clone(),
        }
    }
}

/// Talks the manager's HMAC-authenticated EDR protocol over HTTPS.
pub struct Reporter {
    client: Client,
    manager_url: String,
    api_secret: String,
    agent_id: String,
    agent_version: &'static str,
}

impl Reporter {
    /// Builds the HTTPS client for the manager connection, applying
    /// `TlsConfig` when `tls.enabled` (custom CA / client cert / dev-only
    /// cert-validation bypass — see `config::TlsConfig` docs).
    pub fn new(
        manager_url: String,
        api_secret: String,
        agent_id: String,
        tls: &TlsConfig,
    ) -> Result<Self, Error> {
        let mut builder = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(format!(
                "SkausWatch-EDR-Agent-Rust/{}",
                env!("CARGO_PKG_VERSION")
            ));

        if tls.enabled {
            if !tls.ca_file.is_empty() {
                let pem = std::fs::read(Path::new(&tls.ca_file))
                    .map_err(|e| Error::Config(format!("reading tls.ca_file: {e}")))?;
                let cert = Certificate::from_pem(&pem)
                    .map_err(|e| Error::Config(format!("parsing tls.ca_file: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }
            if !tls.cert_file.is_empty() && !tls.key_file.is_empty() {
                let mut pem = std::fs::read(Path::new(&tls.cert_file))
                    .map_err(|e| Error::Config(format!("reading tls.cert_file: {e}")))?;
                let mut key = std::fs::read(Path::new(&tls.key_file))
                    .map_err(|e| Error::Config(format!("reading tls.key_file: {e}")))?;
                pem.append(&mut key);
                let identity = Identity::from_pem(&pem)
                    .map_err(|e| Error::Config(format!("parsing tls client identity: {e}")))?;
                builder = builder.identity(identity);
            }
            if tls.skip_verify {
                warn!(
                    "tls.skip_verify is enabled — manager certificate validation is DISABLED; \
                     never use this outside development"
                );
                builder = builder.danger_accept_invalid_certs(true);
            }
        }

        let client = builder
            .build()
            .map_err(|e| Error::Config(format!("building HTTPS client: {e}")))?;

        Ok(Self {
            client,
            manager_url,
            api_secret,
            agent_id,
            agent_version: env!("CARGO_PKG_VERSION"),
        })
    }

    /// Computes the current `X-API-Key` for this agent — never logged.
    fn api_key(&self) -> Result<String, Error> {
        compute_api_key(&self.api_secret, &self.agent_id)
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/api/v1/edr/{path}",
            self.manager_url.trim_end_matches('/')
        )
    }

    async fn error_body(resp: reqwest::Response) -> String {
        resp.text()
            .await
            .unwrap_or_default()
            .chars()
            .take(500)
            .collect()
    }

    /// `POST /api/v1/edr/register`. Accepts manager status 200 (re-register)
    /// or 201 (new agent).
    pub async fn register(&self, req: &RegisterRequest) -> Result<(), Error> {
        let resp = self
            .client
            .post(self.endpoint("register"))
            .header("X-API-Key", self.api_key()?)
            .header("X-Agent-ID", &self.agent_id)
            .json(req)
            .send()
            .await
            .map_err(|e| Error::Dependency(format!("register request failed: {e}")))?;

        match resp.status() {
            StatusCode::OK | StatusCode::CREATED => Ok(()),
            status => Err(Error::Dependency(format!(
                "register failed: {status} {}",
                Self::error_body(resp).await
            ))),
        }
    }

    /// `POST /api/v1/edr/heartbeat`. `Ok(false)` signals a 404 ("Agent not
    /// registered") so the caller can re-register and retry — v1 never
    /// self-healed here, but doing so is a low-risk resilience
    /// improvement given the agent already has everything it needs to
    /// re-register.
    pub async fn heartbeat(&self, status: &str) -> Result<bool, Error> {
        let body = HeartbeatRequest {
            agent_id: &self.agent_id,
            status,
            metadata: serde_json::json!({}),
        };
        let resp = self
            .client
            .post(self.endpoint("heartbeat"))
            .header("X-API-Key", self.api_key()?)
            .header("X-Agent-ID", &self.agent_id)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Dependency(format!("heartbeat request failed: {e}")))?;

        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => Err(Error::Dependency(format!(
                "heartbeat failed: {status} {}",
                Self::error_body(resp).await
            ))),
        }
    }

    /// `POST /api/v1/edr/events` for a batch of at most
    /// `MAX_EVENTS_PER_REQUEST` events. Returns the manager's
    /// `events_stored` count for logging.
    pub async fn report_events(&self, events: &[EventPayload]) -> Result<i64, Error> {
        if events.is_empty() {
            return Ok(0);
        }
        if events.len() > MAX_EVENTS_PER_REQUEST {
            return Err(Error::Validation(format!(
                "batch of {} exceeds manager limit of {MAX_EVENTS_PER_REQUEST}",
                events.len()
            )));
        }

        let resp = self
            .client
            .post(self.endpoint("events"))
            .header("X-API-Key", self.api_key()?)
            .header("X-Agent-ID", &self.agent_id)
            .json(events)
            .send()
            .await
            .map_err(|e| Error::Dependency(format!("event report request failed: {e}")))?;

        if resp.status() != StatusCode::ACCEPTED {
            let status = resp.status();
            return Err(Error::Dependency(format!(
                "event report failed: {status} {}",
                Self::error_body(resp).await
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Dependency(format!("invalid event report response: {e}")))?;
        Ok(body
            .get("events_stored")
            .and_then(|v| v.as_i64())
            .unwrap_or(0))
    }

    /// `GET /api/v1/edr/config`. Implemented for wire-protocol completeness
    /// (the manager exposes it and v1 declared a client method for it) but,
    /// matching v1's own behavior, not invoked by the agent's run loop —
    /// local config remains authoritative.
    pub async fn get_config(&self) -> Result<serde_json::Value, Error> {
        let resp = self
            .client
            .get(self.endpoint("config"))
            .header("X-API-Key", self.api_key()?)
            .header("X-Agent-ID", &self.agent_id)
            .send()
            .await
            .map_err(|e| Error::Dependency(format!("config request failed: {e}")))?;

        if resp.status() != StatusCode::OK {
            let status = resp.status();
            return Err(Error::Dependency(format!(
                "config request failed: {status} {}",
                Self::error_body(resp).await
            )));
        }
        resp.json()
            .await
            .map_err(|e| Error::Dependency(format!("invalid config response: {e}")))
    }

    /// Agent version string sent in `RegisterRequest.agent_version`.
    pub fn agent_version(&self) -> &'static str {
        self.agent_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{must, must_err};

    /// Cross-checked against the manager's own test vector
    /// (services/manager/src/routes/edr.rs `hmac_matches_python_hexdigest_vector`):
    /// `hmac.new(b"change-me-edr-secret", b"agent-001", sha256).hexdigest()`.
    #[test]
    fn hmac_known_answer_vector_matches_manager() {
        let key = must(compute_api_key("change-me-edr-secret", "agent-001"), "hmac");
        assert_eq!(
            key,
            "2e3bdc4edea1fa9037414810457dcbf75fa025b654ceffcbc0cf2a98fcbb9e40"
        );
    }

    #[test]
    fn hmac_is_deterministic_and_agent_id_sensitive() {
        let a = must(compute_api_key("secret", "agent-a"), "hmac");
        let b = must(compute_api_key("secret", "agent-a"), "hmac");
        let c = must(compute_api_key("secret", "agent-b"), "hmac");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64, "hex-encoded SHA-256 HMAC must be 64 chars");
        assert!(
            a.chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
    }

    #[test]
    fn event_payload_maps_process_fields() {
        let event = CollectedEvent {
            event_type: crate::collectors::EVENT_TYPE_PROCESS,
            timestamp: std::time::SystemTime::now(),
            severity: crate::collectors::Severity::High,
            data: serde_json::json!({"action": "created", "name": "nc", "cmdline": "nc -l 4444", "pid": 123}),
        };
        let payload = EventPayload::from_collected("agent-1", &event);
        assert_eq!(payload.agent_id, "agent-1");
        assert_eq!(payload.event_type, "process");
        assert_eq!(payload.severity.as_deref(), Some("high"));
        assert_eq!(payload.process_name.as_deref(), Some("nc"));
        assert_eq!(payload.command_line.as_deref(), Some("nc -l 4444"));
        assert!(payload.network_connections.is_none());
        assert!(payload.file_operations.is_none());
        assert_eq!(payload.details["pid"], 123);
    }

    #[test]
    fn event_payload_maps_network_and_file_fields() {
        let net_event = CollectedEvent {
            event_type: crate::collectors::EVENT_TYPE_NETWORK,
            timestamp: std::time::SystemTime::now(),
            severity: crate::collectors::Severity::Medium,
            data: serde_json::json!({"action": "connected", "remote_addr": "8.8.8.8"}),
        };
        let payload = EventPayload::from_collected("agent-1", &net_event);
        assert!(payload.network_connections.is_some());
        assert!(payload.file_operations.is_none());

        let file_event = CollectedEvent {
            event_type: crate::collectors::EVENT_TYPE_FILE,
            timestamp: std::time::SystemTime::now(),
            severity: crate::collectors::Severity::Low,
            data: serde_json::json!({"action": "modified", "path": "/etc/hosts"}),
        };
        let payload = EventPayload::from_collected("agent-1", &file_event);
        assert!(payload.file_operations.is_some());
        assert!(payload.network_connections.is_none());
    }

    #[tokio::test]
    async fn batch_over_manager_limit_is_rejected_before_any_request() {
        let reporter = must(
            Reporter::new(
                "https://manager.invalid".to_owned(),
                "secret".to_owned(),
                "agent-001".to_owned(),
                &crate::config::TlsConfig::default(),
            ),
            "client build",
        );
        let events: Vec<EventPayload> = (0..MAX_EVENTS_PER_REQUEST + 1)
            .map(|i| EventPayload {
                agent_id: "a".to_owned(),
                event_type: format!("e{i}"),
                severity: None,
                process_name: None,
                command_line: None,
                network_connections: None,
                file_operations: None,
                details: serde_json::json!({}),
            })
            .collect();
        // Never touches the network — the >100 check runs first, so an
        // unreachable manager_url proves this is a pure client-side guard.
        let err = must_err(reporter.report_events(&events).await, "must reject");
        assert!(matches!(err, Error::Validation(_)));
    }

    #[tokio::test]
    async fn empty_batch_is_a_cheap_noop() {
        let reporter = must(
            Reporter::new(
                "https://manager.invalid".to_owned(),
                "secret".to_owned(),
                "agent-001".to_owned(),
                &crate::config::TlsConfig::default(),
            ),
            "client build",
        );
        let stored = must(reporter.report_events(&[]).await, "empty batch is ok");
        assert_eq!(stored, 0);
    }
}
