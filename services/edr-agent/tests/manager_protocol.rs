//! Integration tests: the agent's `Reporter` against a mocked manager
//! (`wiremock`), verifying the actual wire protocol — headers, HMAC
//! computation, and request/response body shapes — matches
//! `services/manager/src/routes/edr.rs` exactly. Complements the pure unit
//! tests in `src/transport.rs` with full HTTP-round-trip coverage.

use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use skauswatch_edr_agent::config::TlsConfig;
use skauswatch_edr_agent::transport::{EventPayload, RegisterRequest, Reporter, compute_api_key};

const SECRET: &str = "integration-test-secret";
const AGENT_ID: &str = "agent-integration-001";

fn expect_ok<T, E: std::fmt::Display>(result: Result<T, E>, ctx: &str) -> T {
    match result {
        Ok(v) => v,
        Err(e) => unreachable!("{ctx}: {e}"),
    }
}

async fn reporter_against(server: &MockServer) -> Reporter {
    expect_ok(
        Reporter::new(
            server.uri(),
            SECRET.to_owned(),
            AGENT_ID.to_owned(),
            &TlsConfig::default(),
        ),
        "reporter build",
    )
}

/// The `X-API-Key` header on every request must be exactly
/// `hex(HMAC-SHA256(secret, agent_id))` — the manager's `expected_api_key`.
/// This is asserted as an exact-match request matcher, not just "some
/// header present", so a regression back to v1's static-token bug would
/// fail every test in this file.
fn expected_api_key() -> String {
    expect_ok(compute_api_key(SECRET, AGENT_ID), "compute expected key")
}

#[tokio::test]
async fn register_sends_hmac_header_and_manager_contract_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/edr/register"))
        .and(header("X-API-Key", expected_api_key().as_str()))
        .and(header("X-Agent-ID", AGENT_ID))
        .and(body_json(json!({
            "agent_id": AGENT_ID,
            "hostname": "test-host",
            "ip_address": "",
            "os_type": "linux",
            "os_version": "6.8.0",
            "agent_version": "2.0.0",
            "metadata": {"collectors": ["process", "file", "network"]},
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "message": "Agent registered successfully",
            "agent_id": AGENT_ID,
            "status": "active",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let req = RegisterRequest {
        agent_id: AGENT_ID.to_owned(),
        hostname: "test-host".to_owned(),
        ip_address: String::new(),
        os_type: "linux".to_owned(),
        os_version: "6.8.0".to_owned(),
        agent_version: "2.0.0".to_owned(),
        metadata: json!({"collectors": ["process", "file", "network"]}),
    };

    let result = reporter.register(&req).await;
    assert!(
        result.is_ok(),
        "register must succeed against a contract-shaped 201: {result:?}"
    );
}

#[tokio::test]
async fn register_accepts_200_for_re_registration() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/edr/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "Agent re-registered", "agent_id": AGENT_ID, "status": "active",
        })))
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let req = RegisterRequest {
        agent_id: AGENT_ID.to_owned(),
        hostname: "h".to_owned(),
        ip_address: String::new(),
        os_type: "linux".to_owned(),
        os_version: String::new(),
        agent_version: "2.0.0".to_owned(),
        metadata: json!({}),
    };
    assert!(reporter.register(&req).await.is_ok());
}

#[tokio::test]
async fn register_surfaces_401_as_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/edr/register"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "Invalid API key"})))
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let req = RegisterRequest {
        agent_id: AGENT_ID.to_owned(),
        hostname: "h".to_owned(),
        ip_address: String::new(),
        os_type: "linux".to_owned(),
        os_version: String::new(),
        agent_version: "2.0.0".to_owned(),
        metadata: json!({}),
    };
    let result = reporter.register(&req).await;
    assert!(
        result.is_err(),
        "a 401 must surface as an error, never be swallowed"
    );
}

/// Wire-compat fix regression test: the heartbeat body must carry
/// `agent_id` (v1's Go agent sent no body at all, which 400s/500s against
/// the manager's `HeartbeatBody`, which requires it).
#[tokio::test]
async fn heartbeat_sends_agent_id_in_body_not_just_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/edr/heartbeat"))
        .and(header("X-API-Key", expected_api_key().as_str()))
        .and(header("X-Agent-ID", AGENT_ID))
        .and(body_json(
            json!({"agent_id": AGENT_ID, "status": "active", "metadata": {}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok", "agent_id": AGENT_ID, "timestamp": "2026-01-01T00:00:00",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let ok = expect_ok(reporter.heartbeat("active").await, "heartbeat");
    assert!(ok, "200 must map to Ok(true)");
}

#[tokio::test]
async fn heartbeat_404_reports_not_registered_without_erroring() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/edr/heartbeat"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"error": "Agent not registered"})),
        )
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let ok = expect_ok(reporter.heartbeat("active").await, "heartbeat");
    assert!(
        !ok,
        "404 must map to Ok(false) so the caller can re-register"
    );
}

/// Wire-compat fix regression test: each event must carry `agent_id` and
/// `event_type` (v1's Go agent sent `{type, timestamp, severity, data}`
/// with no `agent_id`, which the manager's `parse_event` rejects).
#[tokio::test]
async fn report_events_sends_manager_contract_event_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/edr/events"))
        .and(header("X-API-Key", expected_api_key().as_str()))
        .and(body_json(json!([
            {
                "agent_id": AGENT_ID,
                "event_type": "process",
                "severity": "high",
                "process_name": "nc",
                "command_line": "nc -l 4444",
                "details": {"action": "created", "name": "nc", "cmdline": "nc -l 4444", "pid": 1234},
            }
        ])))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "status": "accepted", "events_received": 1, "events_stored": 1, "errors": [],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let payload = EventPayload {
        agent_id: AGENT_ID.to_owned(),
        event_type: "process".to_owned(),
        severity: Some("high".to_owned()),
        process_name: Some("nc".to_owned()),
        command_line: Some("nc -l 4444".to_owned()),
        network_connections: None,
        file_operations: None,
        details: json!({"action": "created", "name": "nc", "cmdline": "nc -l 4444", "pid": 1234}),
    };
    let stored = expect_ok(reporter.report_events(&[payload]).await, "report_events");
    assert_eq!(stored, 1);
}

#[tokio::test]
async fn report_events_500_surfaces_as_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/edr/events"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let payload = EventPayload {
        agent_id: AGENT_ID.to_owned(),
        event_type: "process".to_owned(),
        severity: None,
        process_name: None,
        command_line: None,
        network_connections: None,
        file_operations: None,
        details: json!({}),
    };
    assert!(reporter.report_events(&[payload]).await.is_err());
}

#[tokio::test]
async fn get_config_parses_manager_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/edr/config"))
        .and(header("X-Agent-ID", AGENT_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "agent_id": AGENT_ID,
            "config": {
                "reporting_interval": 60,
                "heartbeat_interval": 30,
                "event_batch_size": 50,
                "enabled_collectors": ["process", "network", "file"],
                "severity_threshold": "low",
            },
        })))
        .mount(&server)
        .await;

    let reporter = reporter_against(&server).await;
    let body = expect_ok(reporter.get_config().await, "get_config");
    assert_eq!(body["config"]["heartbeat_interval"], 30);
}
