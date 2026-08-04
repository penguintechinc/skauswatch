//! Minimal STIX 2.x `indicator` object parsing. Rust port of the working
//! subset of v1 `threat_intel/stix_parser.py`: extracting `(kind, value)`
//! pairs out of an indicator's STIX pattern string
//! (`[ipv4-addr:value = '203.0.113.5']`) plus the surrounding object's
//! `labels`/`description`/`confidence`/`valid_until`. Full STIX 2.1 pattern
//! grammar (boolean operators, comparison operators beyond `=`, cyber
//! observable qualifiers) is not implemented — v1's own parser was also a
//! regex-based approximation of the common single-comparison case, not a
//! full grammar implementation; this documents the same, narrower scope
//! rather than claiming full STIX pattern-language support.

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;

use crate::models::{Ioc, ThreatLevel};

/// Matches the common single-comparison STIX pattern shape:
/// `[object-type:property = 'value']` (also accepts double quotes). STIX
/// object-type prefixes map to this crate's IOC `kind` via [`stix_type_to_kind`].
static PATTERN_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)] // compile-time-constant pattern, provably valid
    Regex::new(r#"\[\s*([a-zA-Z0-9_-]+):([a-zA-Z0-9_.'"-]+)\s*=\s*['"]([^'"]+)['"]\s*\]"#).unwrap()
});

/// Maps a STIX cyber-observable object type (as it appears before the `:`
/// in a pattern) to this crate's IOC `kind` string. Unrecognized types pass
/// through unchanged so a feed using a type this parser doesn't special-case
/// still stores *something* usable rather than being silently dropped.
fn stix_type_to_kind(stix_type: &str) -> String {
    match stix_type {
        "ipv4-addr" | "ipv6-addr" => "ip".to_owned(),
        "domain-name" => "domain".to_owned(),
        "url" => "url".to_owned(),
        "file" => "hash".to_owned(),
        "email-addr" => "email".to_owned(),
        "windows-registry-key" => "registry".to_owned(),
        other => other.to_owned(),
    }
}

/// One `(kind, value)` extracted from a STIX pattern's single comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// This crate's IOC `kind` (see [`stix_type_to_kind`]).
    pub kind: String,
    /// The literal value being compared against.
    pub value: String,
}

/// Extracts every `[type:property = 'value']` comparison found in `pattern`
/// — a STIX indicator combining multiple observables via `AND`/`OR`
/// produces one [`PatternMatch`] per comparison (v1's parser also flattened
/// compound patterns this way rather than modeling the boolean structure).
pub fn parse_pattern(pattern: &str) -> Vec<PatternMatch> {
    PATTERN_RE
        .captures_iter(pattern)
        .map(|c| PatternMatch {
            kind: stix_type_to_kind(&c[1]),
            value: c[3].to_owned(),
        })
        .collect()
}

/// v1 `stix_parser.py`'s STIX `indicator` → v1 `IOC` mapping, adapted to
/// this crate's [`Ioc`] model. One STIX indicator with a compound pattern
/// yields one [`Ioc`] per extracted comparison — each stored independently
/// (matches `ThreatStore::store_indicator`'s `(kind, value)` identity).
pub fn indicator_object_to_iocs(obj: &Value, source_feed: &str) -> Vec<Ioc> {
    let Some(pattern) = obj.get("pattern").and_then(Value::as_str) else {
        return Vec::new();
    };
    let matches = parse_pattern(pattern);
    if matches.is_empty() {
        return Vec::new();
    }

    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let confidence = obj
        .get("confidence")
        .and_then(Value::as_f64)
        .map(|c| c / 100.0) // STIX confidence is 0-100; this crate uses 0.0-1.0
        .unwrap_or(0.0);
    let threat_level = labels_to_threat_level(obj.get("labels"));
    let tags: Vec<String> = obj
        .get("labels")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let expiration = obj
        .get("valid_until")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let now = Utc::now();

    matches
        .into_iter()
        .map(|m| Ioc {
            id: String::new(),
            kind: m.kind,
            value: m.value,
            description: description.clone(),
            threat_level,
            confidence,
            tags: tags.clone(),
            malware_families: Vec::new(),
            kill_chain_phases: Vec::new(),
            created_at: now,
            updated_at: now,
            expiration,
            source_feed: Some(source_feed.to_owned()),
            metadata: obj.clone(),
        })
        .collect()
}

/// STIX `labels` commonly carry a coarse severity hint
/// (`malicious-activity`, `benign`, ...) — maps the ones that map cleanly
/// to this crate's [`ThreatLevel`]; anything else (including no labels at
/// all) is [`ThreatLevel::Unknown`], matching `Ioc`'s own model default.
fn labels_to_threat_level(labels: Option<&Value>) -> ThreatLevel {
    let Some(labels) = labels.and_then(Value::as_array) else {
        return ThreatLevel::Unknown;
    };
    let has = |needle: &str| {
        labels
            .iter()
            .any(|l| l.as_str().is_some_and(|s| s.eq_ignore_ascii_case(needle)))
    };
    if has("malicious-activity") || has("attribution") {
        ThreatLevel::High
    } else if has("anomalous-activity") {
        ThreatLevel::Medium
    } else if has("benign") {
        ThreatLevel::Low
    } else {
        ThreatLevel::Unknown
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ipv4_comparison() {
        let matches = parse_pattern("[ipv4-addr:value = '203.0.113.5']");
        assert_eq!(
            matches,
            vec![PatternMatch {
                kind: "ip".to_owned(),
                value: "203.0.113.5".to_owned(),
            }]
        );
    }

    #[test]
    fn parses_domain_comparison_with_double_quotes() {
        let matches = parse_pattern(r#"[domain-name:value = "evil.example.test"]"#);
        assert_eq!(matches[0].kind, "domain");
        assert_eq!(matches[0].value, "evil.example.test");
    }

    #[test]
    fn parses_compound_pattern_into_multiple_matches() {
        let matches = parse_pattern(
            "[ipv4-addr:value = '203.0.113.5'] AND [domain-name:value = 'evil.example.test']",
        );
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|m| m.kind == "ip"));
        assert!(matches.iter().any(|m| m.kind == "domain"));
    }

    #[test]
    fn file_hash_property_maps_to_hash_kind() {
        let matches = parse_pattern(
            "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
        );
        assert_eq!(matches[0].kind, "hash");
    }

    #[test]
    fn unmatched_pattern_yields_no_matches() {
        assert!(parse_pattern("not a stix pattern").is_empty());
    }

    #[test]
    fn indicator_object_maps_fields_and_scales_confidence() {
        let obj = serde_json::json!({
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '203.0.113.5']",
            "description": "known C2 node",
            "confidence": 90,
            "labels": ["malicious-activity"],
            "valid_until": "2030-01-01T00:00:00Z",
        });
        let iocs = indicator_object_to_iocs(&obj, "test-feed");
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].kind, "ip");
        assert_eq!(iocs[0].value, "203.0.113.5");
        assert_eq!(iocs[0].description, "known C2 node");
        assert!((iocs[0].confidence - 0.9).abs() < f64::EPSILON);
        assert_eq!(iocs[0].threat_level, ThreatLevel::High);
        assert_eq!(iocs[0].source_feed, Some("test-feed".to_owned()));
        assert!(iocs[0].expiration.is_some());
    }

    #[test]
    fn indicator_object_without_pattern_yields_nothing() {
        let obj = serde_json::json!({"type": "indicator", "description": "no pattern here"});
        assert!(indicator_object_to_iocs(&obj, "test-feed").is_empty());
    }

    #[test]
    fn indicator_object_with_an_unmatchable_pattern_yields_nothing() {
        let obj = serde_json::json!({"type": "indicator", "pattern": "not a stix pattern"});
        assert!(indicator_object_to_iocs(&obj, "test-feed").is_empty());
    }

    #[test]
    fn stix_type_to_kind_covers_email_registry_and_unknown_types() {
        assert_eq!(stix_type_to_kind("email-addr"), "email");
        assert_eq!(stix_type_to_kind("windows-registry-key"), "registry");
        assert_eq!(stix_type_to_kind("mutex"), "mutex");
    }

    #[test]
    fn labels_map_to_threat_levels() {
        assert_eq!(
            labels_to_threat_level(Some(&serde_json::json!(["malicious-activity"]))),
            ThreatLevel::High
        );
        assert_eq!(
            labels_to_threat_level(Some(&serde_json::json!(["anomalous-activity"]))),
            ThreatLevel::Medium
        );
        assert_eq!(
            labels_to_threat_level(Some(&serde_json::json!(["benign"]))),
            ThreatLevel::Low
        );
        assert_eq!(
            labels_to_threat_level(Some(&serde_json::json!([]))),
            ThreatLevel::Unknown
        );
        assert_eq!(labels_to_threat_level(None), ThreatLevel::Unknown);
    }
}
