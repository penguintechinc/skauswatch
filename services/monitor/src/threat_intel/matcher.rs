//! Matches ingested events against the IOC store. Rust port of v1
//! `threat_intel/indicator_matcher.py::IndicatorMatcher`'s core behavior —
//! extract candidate values (IPs, hostnames/domains, usernames) from an
//! event's structured fields and check each against the threat-intel store.
//! Deliberately narrower than v1's elaborate multi-strategy scoring
//! (fuzzy/partial matching, allow-listing, confidence decay curves): this
//! implements exact `(kind, value)` lookups, which is the actual match
//! primitive both v1 and this port ultimately reduce to before scoring —
//! full-fidelity scoring is a documented follow-up, not silently dropped.

use std::sync::Arc;

use regex::Regex;
use std::sync::LazyLock;

use crate::models::{BaseEvent, ThreatMatch};
use crate::threat_intel::store::ThreatStore;

/// Matches an event against the configured threat-intel store, returning
/// zero or more [`ThreatMatch`]es. A trait (not a concrete type) so
/// `ingest.rs` doesn't need to depend on `ThreatStore`/sqlx directly, and so
/// tests can substitute a fake without a database.
#[async_trait::async_trait]
pub trait EventMatcher: Send + Sync {
    /// Returns every IOC match found in `event`'s fields.
    async fn match_event(&self, event: &BaseEvent) -> Vec<ThreatMatch>;
}

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)] // compile-time-constant pattern, provably valid
    Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap()
});
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)] // compile-time-constant pattern, provably valid
    Regex::new(r"\b([a-zA-Z0-9][a-zA-Z0-9-]{0,62}(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,62})+)\b").unwrap()
});

/// One candidate value pulled from an event, tagged with the IOC `kind`
/// it should be checked against and the event field it came from.
struct Candidate {
    kind: &'static str,
    value: String,
    field: &'static str,
}

/// Extracts IOC candidates from an event's structured fields plus a light
/// regex scan of `message` — v1 scanned `raw_data`/`message`/`processed_data`
/// similarly. Pure and unit-tested directly (the store round-trip is
/// exercised separately in `store.rs`'s DB-backed tests).
fn extract_candidates(event: &BaseEvent) -> Vec<Candidate> {
    let mut out = Vec::new();

    if let Some(user) = &event.user
        && !user.is_empty()
    {
        out.push(Candidate {
            kind: "username",
            value: user.clone(),
            field: "user",
        });
    }
    if !event.host.is_empty() {
        if IPV4_RE.is_match(&event.host) {
            out.push(Candidate {
                kind: "ip",
                value: event.host.clone(),
                field: "host",
            });
        } else {
            out.push(Candidate {
                kind: "domain",
                value: event.host.clone(),
                field: "host",
            });
        }
    }

    for m in IPV4_RE.find_iter(&event.message) {
        out.push(Candidate {
            kind: "ip",
            value: m.as_str().to_owned(),
            field: "message",
        });
    }
    // Domain extraction runs after IP extraction and only over text that
    // didn't already match an IPv4 literal — an IPv4 address also matches
    // the loose `DOMAIN_RE` shape (dotted alphanumeric labels).
    for m in DOMAIN_RE.find_iter(&event.message) {
        let candidate = m.as_str();
        if IPV4_RE.is_match(candidate) {
            continue;
        }
        out.push(Candidate {
            kind: "domain",
            value: candidate.to_owned(),
            field: "message",
        });
    }

    out
}

/// [`EventMatcher`] backed by [`ThreatStore`] — real, working exact-match
/// lookups against the Postgres IOC table.
pub struct IndicatorMatcher {
    store: Arc<ThreatStore>,
}

impl IndicatorMatcher {
    /// Builds a matcher over `store`.
    pub fn new(store: Arc<ThreatStore>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl EventMatcher for IndicatorMatcher {
    async fn match_event(&self, event: &BaseEvent) -> Vec<ThreatMatch> {
        let mut matches = Vec::new();
        for candidate in extract_candidates(event) {
            let found = match self
                .store
                .find_by_kind_value(candidate.kind, &candidate.value)
                .await
            {
                Ok(found) => found,
                Err(e) => {
                    tracing::error!(error = %e, "threat-intel lookup failed");
                    continue;
                }
            };
            let Some(ioc) = found else { continue };
            match self
                .store
                .record_match(
                    &event.id,
                    &ioc.id,
                    &candidate.value,
                    candidate.field,
                    ioc.confidence,
                    ioc.threat_level,
                    &event.tenant_id,
                )
                .await
            {
                Ok(m) => matches.push(m),
                Err(e) => tracing::error!(error = %e, "failed to record threat match"),
            }
        }
        matches
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::models::{EventType, LogSource, Severity};
    use chrono::Utc;

    fn sample_event(host: &str, user: Option<&str>, message: &str) -> BaseEvent {
        BaseEvent {
            id: "e1".to_owned(),
            source: LogSource::System,
            event_type: EventType::Network,
            severity: Severity::Info,
            message: message.to_owned(),
            timestamp: Utc::now(),
            raw_data: serde_json::Value::Null,
            tags: vec![],
            host: host.to_owned(),
            user: user.map(str::to_owned),
            process: None,
            pid: None,
            enrichments: serde_json::Value::Null,
            threat_matches: vec![],
            ai_analysis: None,
            processed_data: serde_json::Value::Null,
            tenant_id: "tenant-a".to_owned(),
            extra: Default::default(),
        }
    }

    #[test]
    fn extracts_ip_from_host_field() {
        let event = sample_event("203.0.113.5", None, "connection established");
        let candidates = extract_candidates(&event);
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == "ip" && c.value == "203.0.113.5" && c.field == "host")
        );
    }

    #[test]
    fn extracts_domain_from_host_field() {
        let event = sample_event("evil.example.test", None, "dns lookup");
        let candidates = extract_candidates(&event);
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == "domain" && c.value == "evil.example.test")
        );
    }

    #[test]
    fn extracts_ip_from_message_but_not_as_a_domain() {
        let event = sample_event("", None, "connect to 198.51.100.9 refused");
        let candidates = extract_candidates(&event);
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == "ip" && c.value == "198.51.100.9")
        );
        assert!(
            !candidates
                .iter()
                .any(|c| c.kind == "domain" && c.value.contains("198.51.100.9"))
        );
    }

    #[test]
    fn extracts_domain_from_message() {
        let event = sample_event("", None, "beaconing to c2.evil.example detected");
        let candidates = extract_candidates(&event);
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == "domain" && c.value == "c2.evil.example")
        );
    }

    #[test]
    fn extracts_username_field() {
        let event = sample_event("", Some("attacker"), "login attempt");
        let candidates = extract_candidates(&event);
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == "username" && c.value == "attacker")
        );
    }

    #[test]
    fn empty_event_yields_no_candidates() {
        let event = sample_event("", None, "");
        assert!(extract_candidates(&event).is_empty());
    }

    #[tokio::test]
    async fn indicator_matcher_finds_and_records_a_real_ioc_match() {
        use crate::models::ThreatLevel;
        use crate::threat_intel::store::ThreatStore;

        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        let store = Arc::new(ThreatStore::new(pool));
        store
            .store_indicator(&crate::models::Ioc {
                id: String::new(),
                kind: "ip".to_owned(),
                value: "203.0.113.77".to_owned(),
                description: "c2 node".to_owned(),
                threat_level: ThreatLevel::Critical,
                confidence: 0.99,
                tags: vec![],
                malware_families: vec![],
                kill_chain_phases: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                expiration: None,
                source_feed: None,
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap_or_else(|e| panic!("seed ioc: {e}"));

        let matcher = IndicatorMatcher::new(store);
        let event = sample_event("203.0.113.77", None, "connection from host");
        let matches = matcher.match_event(&event).await;

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_value, "203.0.113.77");
        assert_eq!(matches[0].field_name, "host");
        assert_eq!(matches[0].threat_level, ThreatLevel::Critical);
    }

    #[tokio::test]
    async fn indicator_matcher_returns_no_matches_for_unknown_values() {
        use crate::threat_intel::store::ThreatStore;

        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        let matcher = IndicatorMatcher::new(Arc::new(ThreatStore::new(pool)));
        let event = sample_event("198.51.100.200", None, "benign traffic");
        assert!(matcher.match_event(&event).await.is_empty());
    }
}
