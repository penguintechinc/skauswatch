//! Socket.dev optional threat-intel tie-in (`docs/v2-port/v2.1-depgate.md`
//! §5): premium enrichment layered on top of the OSS scan-core floor, never
//! a replacement for it. Per §5/§10 this is DepGate's *complement, not
//! duplicate* to Socket's own firewall product — self-hosting + caching +
//! the OSS floor is DepGate's lane, Socket is opt-in intel on top.
//!
//! **Every gate fails toward "skip silently, never block":**
//! - No API key configured (`DEPGATE_SOCKET_API_KEY` unset) -> [`SocketClient::evaluate`]
//!   returns immediately with zero HTTP requests, no log line — this is the
//!   default, common state and must not be noisy.
//! - A key is configured but the tenant isn't Enterprise-tier or the
//!   `skauswatch.depgate.socket` flag is off -> same silent, zero-request
//!   skip (checked before any network call).
//! - The Socket API is unreachable, rate-limited, or errors -> logged once
//!   at `warn`, then skipped; the local (scan-core + heuristics) verdict is
//!   always sufficient to serve or block on its own.
//!
//! Findings are emitted as ordinary [`crate::heuristics::RiskFinding`]s —
//! `check` names prefixed `socket_` — so `crate::scanpipe::ScanPipeline::ingest`
//! folds them into the exact same findings vector heuristics populates and
//! `crate::policy::evaluate` consumes. There is no separate Socket decision
//! path: a Socket-sourced finding can influence `allow`/`warn`/`block`/
//! `quarantine` only through the one existing policy engine, exactly like a
//! local heuristic hit.
//!
//! Endpoint shape assumption (documented, not verified against a live
//! Socket account — no test in this module talks to the real service):
//! `POST {base_url}/v0/purl?alerts=true` with HTTP Basic auth (API key as
//! username, empty password) and a JSON body `{"components":[{"purl":"pkg:{eco}/{name}@{version}"}]}`,
//! answering with one JSON object (this module reads only the first) with an
//! `alerts: [{type, severity, description}]` array — Socket's actual public
//! API (package-report-by-PURL, batch `/v0/purl` endpoint) as documented at
//! the time this was written. Revisit against a real Socket account/key
//! before depending on this in production; `evaluate`'s fail-open-to-empty
//! posture means a shape mismatch degrades to "no Socket signal", never a
//! crash or a false verdict.

use std::sync::Arc;
#[cfg(test)]
use std::sync::OnceLock;

use penguin_licensing::{LicenseClient, Tier};
use serde::Deserialize;

use crate::heuristics::{RiskFinding, Severity};

/// PostHog flag gating the Socket.dev tie-in specifically, on top of the
/// whole-surface `crate::routes::DEPGATE_FLAG` — see §10: "Policy engine,
/// Socket tie-in, provenance enforcement, AI triage: Enterprise."
pub const SOCKET_FLAG: &str = "skauswatch.depgate.socket";

/// Socket.dev upstream settings (`DEPGATE_SOCKET_API_KEY`/`DEPGATE_SOCKET_BASE_URL`).
#[derive(Debug, Clone, Default)]
pub struct SocketConfig {
    /// Customer's Socket.dev API key. Belongs in IceBox, never committed —
    /// see `docs/v2-port/v2.1-depgate.md` §5. `None`/empty disables the
    /// integration entirely.
    pub api_key: Option<String>,
    /// Socket API base URL (default `https://api.socket.dev`).
    pub base_url: String,
}

fn resolve_socket(api_key: Option<&str>, base_url: Option<&str>) -> SocketConfig {
    SocketConfig {
        api_key: api_key.filter(|s| !s.is_empty()).map(str::to_owned),
        base_url: base_url
            .filter(|s| !s.is_empty())
            .unwrap_or("https://api.socket.dev")
            .to_owned(),
    }
}

impl SocketConfig {
    /// Loads Socket.dev settings from the environment.
    #[must_use]
    pub fn from_env() -> Self {
        resolve_socket(
            std::env::var("DEPGATE_SOCKET_API_KEY").ok().as_deref(),
            std::env::var("DEPGATE_SOCKET_BASE_URL").ok().as_deref(),
        )
    }
}

#[derive(Debug, Deserialize)]
struct SocketAlert {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SocketPurlResponse {
    #[serde(default)]
    alerts: Vec<SocketAlert>,
}

/// Optional Socket.dev enrichment client. A client with no API key
/// configured (`SocketClient::disabled`) is a complete no-op — the standard
/// value every `ScanPipeline` construction site that isn't specifically
/// exercising Socket enrichment uses.
#[derive(Clone)]
pub struct SocketClient {
    http: reqwest::Client,
    cfg: SocketConfig,
    license: Option<Arc<LicenseClient>>,
}

impl std::fmt::Debug for SocketClient {
    // `LicenseClient` (penguin-libs) doesn't implement `Debug` — mirrors
    // `crate::state::AppStateInner` (also holds an `Arc<LicenseClient>`),
    // which sidesteps this by not deriving `Debug` at all; `SocketClient` is
    // small enough to hand-write instead.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketClient")
            .field("cfg", &self.cfg)
            .field("license_configured", &self.license.is_some())
            .finish()
    }
}

/// Maps a DepGate ecosystem discriminator to a Package URL (PURL) type
/// Socket understands. `None` for ecosystems Socket has no concept of
/// scoring (OCI container images) — `evaluate` skips entirely rather than
/// send a request Socket can't answer meaningfully.
fn purl_type(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "npm" => Some("npm"),
        "pypi" => Some("pypi"),
        "crates" => Some("cargo"),
        "go" => Some("golang"),
        _ => None,
    }
}

fn map_severity(s: Option<&str>) -> Severity {
    s.and_then(|s| s.parse().ok()).unwrap_or(Severity::Medium)
}

impl SocketClient {
    /// Builds a client. `license` gates the Enterprise-tier + flag check
    /// (§10) — `None` skips that check entirely (used by [`Self::disabled`],
    /// which never reaches it anyway since the API-key check short-circuits
    /// first).
    #[must_use]
    pub fn new(
        http: reqwest::Client,
        cfg: SocketConfig,
        license: Option<Arc<LicenseClient>>,
    ) -> Self {
        Self { http, cfg, license }
    }

    /// A client with no API key configured — Socket integration fully
    /// disabled, zero requests ever sent. Test-only: production always
    /// builds a real (configured-or-not) client via [`Self::new`] in
    /// `crate::state::AppStateInner::from_env`.
    #[cfg(test)]
    #[must_use]
    pub fn disabled() -> Self {
        Self::new(reqwest::Client::new(), SocketConfig::default(), None)
    }

    /// A process-wide shared [`Self::disabled`] instance — lets every
    /// `ScanPipeline` test construction site that doesn't specifically
    /// exercise Socket enrichment pass a `&'static` reference without a
    /// local `let` binding per call site.
    #[cfg(test)]
    #[must_use]
    pub fn disabled_ref() -> &'static SocketClient {
        static DISABLED: OnceLock<SocketClient> = OnceLock::new();
        DISABLED.get_or_init(SocketClient::disabled)
    }

    /// Whether an API key is configured at all — the first, cheapest gate.
    /// Test-only helper; [`Self::evaluate`] checks the same condition
    /// inline rather than calling this.
    #[cfg(test)]
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.cfg.api_key.is_some()
    }

    /// Enterprise tier + `SOCKET_FLAG` gate, checked only once a key is
    /// configured (defense in depth: a key alone is not entitlement).
    async fn entitled(&self) -> bool {
        let Some(license) = &self.license else {
            // No license client wired at all (e.g. a raw `SocketClient::new`
            // with `license: None` but a key configured, used by this
            // module's own unit tests to exercise the HTTP path without a
            // license fixture) — treat as entitled so the key alone governs.
            return true;
        };
        license.check_tier(Tier::Enterprise).await && license.flag_enabled(SOCKET_FLAG).await
    }

    /// Fetches Socket's package-risk signal for `(ecosystem, name, version)`
    /// and maps it to zero or more [`RiskFinding`]s. Infallible from the
    /// caller's perspective: every failure mode (unconfigured, not
    /// entitled, unsupported ecosystem, network error, non-2xx, malformed
    /// response) degrades to an empty vec, never blocking the local scan
    /// verdict — see module docs.
    pub async fn evaluate(&self, ecosystem: &str, name: &str, version: &str) -> Vec<RiskFinding> {
        let Some(api_key) = &self.cfg.api_key else {
            return Vec::new();
        };
        let Some(purl_eco) = purl_type(ecosystem) else {
            return Vec::new();
        };
        if !self.entitled().await {
            return Vec::new();
        }

        let purl = format!("pkg:{purl_eco}/{name}@{version}");
        match self.fetch_alerts(api_key, &purl).await {
            Ok(alerts) => alerts
                .into_iter()
                .map(|a| RiskFinding {
                    check: format!("socket_{}", a.kind),
                    severity: map_severity(a.severity.as_deref()),
                    detail: a
                        .description
                        .unwrap_or_else(|| format!("Socket.dev alert: {}", a.kind)),
                })
                .collect(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    purl,
                    "socket.dev enrichment request failed; continuing with local verdict only"
                );
                Vec::new()
            }
        }
    }

    async fn fetch_alerts(&self, api_key: &str, purl: &str) -> Result<Vec<SocketAlert>, String> {
        let url = format!("{}/v0/purl?alerts=true", self.cfg.base_url);
        let resp = self
            .http
            .post(&url)
            .basic_auth(api_key, Some(""))
            .timeout(std::time::Duration::from_secs(5))
            .json(&serde_json::json!({ "components": [{ "purl": purl }] }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("socket.dev returned {}", resp.status()));
        }
        let body = resp.text().await.map_err(|e| e.to_string())?;
        // Socket's batch endpoint answers newline-delimited JSON, one object
        // per requested component — a single-PURL request gets (at most) one
        // line back.
        let first_line = body.lines().next().unwrap_or_default();
        if first_line.trim().is_empty() {
            return Ok(Vec::new());
        }
        let parsed: SocketPurlResponse =
            serde_json::from_str(first_line).map_err(|e| format!("malformed response: {e}"))?;
        Ok(parsed.alerts)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn resolve_socket_defaults_to_the_public_api_with_no_key() {
        let cfg = resolve_socket(None, None);
        assert_eq!(cfg.api_key, None);
        assert_eq!(cfg.base_url, "https://api.socket.dev");
    }

    #[test]
    fn resolve_socket_blank_values_fall_back_to_defaults() {
        let cfg = resolve_socket(Some(""), Some(""));
        assert_eq!(cfg.api_key, None);
        assert_eq!(cfg.base_url, "https://api.socket.dev");
    }

    #[test]
    fn resolve_socket_honors_overrides() {
        let cfg = resolve_socket(Some("sk-test"), Some("https://socket.internal"));
        assert_eq!(cfg.api_key.as_deref(), Some("sk-test"));
        assert_eq!(cfg.base_url, "https://socket.internal");
    }

    #[test]
    fn purl_type_covers_supported_ecosystems_and_excludes_oci() {
        assert_eq!(purl_type("npm"), Some("npm"));
        assert_eq!(purl_type("pypi"), Some("pypi"));
        assert_eq!(purl_type("crates"), Some("cargo"));
        assert_eq!(purl_type("go"), Some("golang"));
        assert_eq!(purl_type("oci"), None);
    }

    #[tokio::test]
    async fn evaluate_sends_zero_requests_when_unconfigured() {
        let server = MockServer::start().await;
        // No mocks mounted — any request would 404 from wiremock's default
        // "no matching stub" behavior. We additionally confirm below that no
        // request was ever sent at all.
        let client = SocketClient::new(
            reqwest::Client::new(),
            SocketConfig {
                api_key: None,
                base_url: server.uri(),
            },
            None,
        );
        let findings = client.evaluate("npm", "left-pad", "1.3.0").await;
        assert!(findings.is_empty());
        let received = server
            .received_requests()
            .await
            .expect("wiremock request recording is enabled by default");
        assert!(
            received.is_empty(),
            "unconfigured SocketClient must never send a request, saw: {received:?}"
        );
    }

    #[tokio::test]
    async fn evaluate_skips_unsupported_ecosystems_without_a_request() {
        let server = MockServer::start().await;
        let client = SocketClient::new(
            reqwest::Client::new(),
            SocketConfig {
                api_key: Some("sk-test".to_owned()),
                base_url: server.uri(),
            },
            None,
        );
        let findings = client.evaluate("oci", "library/nginx", "latest").await;
        assert!(findings.is_empty());
        let received = server.received_requests().await.expect("recording");
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn evaluate_maps_alerts_to_risk_findings() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/purl"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::json!({
                    "alerts": [
                        {"type": "installScripts", "severity": "high", "description": "runs a postinstall script"},
                    ]
                })
                .to_string(),
                "application/json",
            ))
            .mount(&server)
            .await;

        let client = SocketClient::new(
            reqwest::Client::new(),
            SocketConfig {
                api_key: Some("sk-test".to_owned()),
                base_url: server.uri(),
            },
            None,
        );
        let findings = client.evaluate("npm", "left-pad", "1.3.0").await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "socket_installScripts");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn evaluate_returns_empty_on_upstream_error_without_blocking() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/purl"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = SocketClient::new(
            reqwest::Client::new(),
            SocketConfig {
                api_key: Some("sk-test".to_owned()),
                base_url: server.uri(),
            },
            None,
        );
        let findings = client.evaluate("npm", "left-pad", "1.3.0").await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_on_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/purl"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("not json", "application/json"))
            .mount(&server)
            .await;

        let client = SocketClient::new(
            reqwest::Client::new(),
            SocketConfig {
                api_key: Some("sk-test".to_owned()),
                base_url: server.uri(),
            },
            None,
        );
        let findings = client.evaluate("npm", "left-pad", "1.3.0").await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn disabled_client_never_sends_a_request() {
        let server = MockServer::start().await;
        let client = SocketClient::disabled();
        // `disabled()` ignores `server` entirely (empty base URL default) —
        // just confirming the public constructor produces an unconfigured
        // client, mirroring `evaluate_sends_zero_requests_when_unconfigured`.
        assert!(!client.is_configured());
        let findings = client.evaluate("npm", "left-pad", "1.3.0").await;
        assert!(findings.is_empty());
        let received = server.received_requests().await.expect("recording");
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn disabled_ref_is_a_shared_singleton() {
        let a = SocketClient::disabled_ref();
        let b = SocketClient::disabled_ref();
        assert!(std::ptr::eq(a, b));
    }

    #[tokio::test]
    async fn evaluate_skips_when_not_entitled() {
        let server = MockServer::start().await;
        // No mock mounted for the alerts endpoint — a gated (non-Enterprise
        // or flag-off) license must prevent the request entirely.
        let license = skauswatch_testkit::license::gated_license("skauswatch");
        let client = SocketClient::new(
            reqwest::Client::new(),
            SocketConfig {
                api_key: Some("sk-test".to_owned()),
                base_url: server.uri(),
            },
            Some(license),
        );
        let findings = client.evaluate("npm", "left-pad", "1.3.0").await;
        assert!(findings.is_empty());
        let received = server.received_requests().await.expect("recording");
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn evaluate_proceeds_when_entitled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/purl"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::json!({"alerts": []}).to_string(),
                "application/json",
            ))
            .mount(&server)
            .await;

        let license = skauswatch_testkit::license::dev_license("skauswatch");
        let client = SocketClient::new(
            reqwest::Client::new(),
            SocketConfig {
                api_key: Some("sk-test".to_owned()),
                base_url: server.uri(),
            },
            Some(license),
        );
        let findings = client.evaluate("npm", "left-pad", "1.3.0").await;
        assert!(findings.is_empty());
        let received = server.received_requests().await.expect("recording");
        assert_eq!(received.len(), 1, "an entitled caller must reach Socket");
    }
}
