//! Syslog RFC 3164 + RFC 5424 parsing (`docs/v2-port/ingest-module-spec.md`
//! §4a). [`detect_and_parse`] tries the higher-fidelity, structurally
//! stricter RFC 5424 shape first, falling back to RFC 3164 when the input
//! doesn't match it — both formats always start with a `<PRI>` header, so
//! the leading `<` alone only rules out non-syslog input, not which RFC
//! applies. [`ParsedSyslog`] (re-exported from `skauswatch-ocsf`, which
//! also owns [`skauswatch_ocsf::mappings::syslog::to_ocsf_fields`]) is the
//! single normalized shape both RFCs parse into.
//!
//! RFC 3164 parsing (regex + best-effort "assume this year" timestamp) is
//! a direct port of `services/monitor/src/collectors/syslog.rs`'s
//! `RFC3164_RE`/`parse_rfc3164_timestamp`.

// `crate::listeners::syslog` (this file's sibling `mod.rs`) is the only
// caller of `detect_and_parse`, and its own `run_udp`/`run_tcp`/`run_tls`
// aren't wired into `main.rs`'s `serve()` until the Wave-1 integration
// gate — until then, `cargo build`'s reachability analysis (this crate has
// no `[lib]` target, only a `[[bin]]`) sees this whole file as unused.
// Same pattern as `crate::auth`/`crate::buffer`.
#![allow(dead_code)]

use std::sync::LazyLock;

use chrono::{DateTime, Datelike, TimeZone, Utc};
use regex::Regex;

/// The normalized RFC 3164/RFC 5424 syslog tuple. Defined in
/// `skauswatch-ocsf` (which also owns
/// `skauswatch_ocsf::mappings::syslog::to_ocsf_fields`) rather than here,
/// since that crate is the dependency-direction owner both this parser and
/// the OCSF mapping need to share.
pub use skauswatch_ocsf::mappings::syslog::ParsedSyslog;

/// RFC 3164: `<PRI>MMM DD HH:MM:SS HOSTNAME MESSAGE` — identical to
/// `services/monitor/src/collectors/syslog.rs`'s `RFC3164_RE`.
static RFC3164_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)] // compile-time-constant pattern, provably infallible
    Regex::new(r"^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$").unwrap()
});

/// Auto-detects and parses one syslog line: tries RFC 5424 first (Spec
/// §4a), falling back to RFC 3164 when the input doesn't have RFC 5424's
/// `VERSION ISOTIMESTAMP ...` shape immediately after `<PRI>`. Returns
/// `None` for anything with no leading `<PRI>` header at all, or that
/// matches neither format — the caller (a listener) drops these silently
/// rather than crashing (mirrors
/// `services/monitor/src/collectors/syslog.rs::parse_rfc3164`'s "no match,
/// no panic" contract).
/// Span name: `receiver_parse` (Spec §11a "per-event processing: parse,
/// normalize, enqueue, ack" — this covers the "parse" leg; `mod.rs::enqueue`
/// covers normalize+enqueue+ack).
#[must_use]
#[tracing::instrument(name = "receiver_parse", skip(raw), fields(otel.kind = "internal"))]
pub fn detect_and_parse(raw: &str) -> Option<ParsedSyslog> {
    let started = std::time::Instant::now();
    let result = detect_and_parse_inner(raw);
    metrics::histogram!(
        crate::otel::metric_names::RECEIVER_PARSE_DURATION_MS,
        "parser" => "syslog"
    )
    .record(started.elapsed().as_secs_f64() * 1000.0);
    result
}

fn detect_and_parse_inner(raw: &str) -> Option<ParsedSyslog> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('<') {
        return None;
    }
    parse_rfc5424(trimmed).or_else(|| parse_rfc3164(trimmed))
}

/// Splits the next whitespace-delimited token off the front of `s`,
/// skipping any leading whitespace first. `None` once nothing but
/// whitespace remains.
fn next_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(i) => Some((&s[..i], &s[i..])),
        None => Some((s, "")),
    }
}

/// RFC 5424's `-` NILVALUE sentinel means "field absent" — mapped to
/// `None` rather than the literal string.
fn nil_dash(s: &str) -> Option<String> {
    if s == "-" { None } else { Some(s.to_owned()) }
}

/// Splits RFC 5424's STRUCTURED-DATA field off the front of `s`, returning
/// `(structured_data, message)`. Handles the common `-` (no SD) case and
/// one-or-more bracketed `[id ...]` elements by bracket-depth scanning; an
/// unterminated `[` is treated as "no SD" and the whole remainder becomes
/// the message. Escaped `]` inside a parameter value (`\]`, permitted by
/// RFC 5424) is not specially handled — documented P1 limitation, same
/// "acceptable for P1" tone as the other syslog edge cases Spec §4a calls
/// out.
fn split_structured_data(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('-') {
        return ("-", rest.trim_start());
    }
    if s.starts_with('[') {
        let bytes = s.as_bytes();
        let mut depth = 0i32;
        let mut end = None;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 && bytes.get(i + 1) != Some(&b'[') {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(end) = end {
            let (sd, rest) = s.split_at(end);
            return (sd, rest.trim_start());
        }
    }
    ("-", s)
}

/// Parses one RFC 5424 line: `<PRI>VERSION ISOTIMESTAMP HOSTNAME APP-NAME
/// PROCID MSGID STRUCTURED-DATA MESSAGE`. `VERSION` is consumed but not
/// surfaced (always `"1"` in practice). `TIMESTAMP` must parse as RFC 3339
/// or the whole line fails to parse as RFC 5424 — [`detect_and_parse`]
/// then falls back to [`parse_rfc3164`].
fn parse_rfc5424(raw: &str) -> Option<ParsedSyslog> {
    let rest = raw.strip_prefix('<')?;
    let (pri_str, rest) = rest.split_once('>')?;
    let pri: u32 = pri_str.parse().ok()?;

    let (_version, rest) = next_token(rest)?;
    let (timestamp_str, rest) = next_token(rest)?;
    let (hostname, rest) = next_token(rest)?;
    let (app_name, rest) = next_token(rest)?;
    let (proc_id, rest) = next_token(rest)?;
    let (msg_id, rest) = next_token(rest)?;
    let (_structured_data, message) = split_structured_data(rest);

    let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
        .ok()?
        .with_timezone(&Utc);

    Some(ParsedSyslog {
        severity: (pri % 8) as u8,
        facility: (pri / 8) as u8,
        hostname: hostname.to_owned(),
        message: message.to_owned(),
        timestamp,
        app_name: nil_dash(app_name),
        proc_id: nil_dash(proc_id),
        msg_id: nil_dash(msg_id),
    })
}

/// Parses an RFC 3164 line. Returns `None` for anything that doesn't match
/// the `<PRI>MMM DD HH:MM:SS HOSTNAME MESSAGE` shape (mirrors
/// `services/monitor/src/collectors/syslog.rs::parse_rfc3164`).
fn parse_rfc3164(raw: &str) -> Option<ParsedSyslog> {
    let caps = RFC3164_RE.captures(raw)?;
    let pri: u32 = caps.get(1)?.as_str().parse().ok()?;
    let timestamp = parse_rfc3164_timestamp(caps.get(2)?.as_str());
    Some(ParsedSyslog {
        severity: (pri % 8) as u8,
        facility: (pri / 8) as u8,
        hostname: caps.get(3)?.as_str().to_owned(),
        message: caps.get(4)?.as_str().to_owned(),
        timestamp,
        app_name: None,
        proc_id: None,
        msg_id: None,
    })
}

/// Best-effort "MMM DD HH:MM:SS" (no year in RFC 3164) → this year's
/// `DateTime<Utc>`; falls back to "now" on any parse failure. Documented
/// limitation (Spec §4a): a message that actually originated in a
/// different year than "now" (replayed/backfilled logs, or received right
/// at a year boundary) is silently assigned the wrong year — RFC 3164
/// fundamentally cannot disambiguate, so this is the same best-effort
/// behavior `services/monitor/src/collectors/syslog.rs` (and v1 before it)
/// both accepted.
fn parse_rfc3164_timestamp(raw: &str) -> DateTime<Utc> {
    let now = Utc::now();
    let with_year = format!("{} {}", now.year(), raw);
    chrono::NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")
        .ok()
        .and_then(|naive| Utc.from_local_datetime(&naive).single())
        .unwrap_or(now)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rfc3164_and_rfc5424_auto_detected_by_leading_angle_bracket() {
        let rfc3164 = detect_and_parse("<34>Oct 11 22:14:15 host msg")
            .unwrap_or_else(|| panic!("expected RFC 3164 parse"));
        assert_eq!(rfc3164.facility, 4);
        assert_eq!(rfc3164.severity, 2);
        assert_eq!(rfc3164.hostname, "host");
        assert_eq!(rfc3164.message, "msg");
        assert_eq!(rfc3164.app_name, None);

        let rfc5424 = detect_and_parse("<34>1 2025-01-15T12:30:00Z host app - - - msg")
            .unwrap_or_else(|| panic!("expected RFC 5424 parse"));
        // Same PRI (34) in both fixtures — proves both branches decode the
        // header into the exact same `(severity, facility, ...)` shape
        // (Spec §4a: "Both emit a normalized tuple").
        assert_eq!(rfc5424.facility, rfc3164.facility);
        assert_eq!(rfc5424.severity, rfc3164.severity);
        assert_eq!(rfc5424.hostname, "host");
        assert_eq!(rfc5424.message, "msg");
        assert_eq!(rfc5424.app_name, Some("app".to_owned()));
        assert_eq!(rfc5424.proc_id, None);
        assert_eq!(rfc5424.msg_id, None);
    }

    #[test]
    fn year_wrap_timestamp_documented_limitation() {
        // RFC 3164 has no year field at all — `parse_rfc3164_timestamp`
        // always assumes the current year, a documented limitation (Spec
        // §4a) rather than a bug: there is no way to recover the true
        // year from the wire format alone.
        let now = Utc::now();
        let parsed = detect_and_parse("<34>Oct 11 22:14:15 host msg")
            .unwrap_or_else(|| panic!("expected a parse"));
        assert_eq!(parsed.timestamp.year(), now.year());
    }

    #[test]
    fn rfc5424_full_iso8601_timestamp_with_offset_is_preserved() {
        let parsed = detect_and_parse("<165>1 2026-02-03T10:11:12.500-05:00 h a - - - hi")
            .unwrap_or_else(|| panic!("expected a parse"));
        let expected = DateTime::parse_from_rfc3339("2026-02-03T10:11:12.500-05:00")
            .unwrap_or_else(|e| panic!("fixture timestamp: {e}"));
        assert_eq!(parsed.timestamp.timestamp(), expected.timestamp());
        assert_eq!(parsed.message, "hi");
    }

    #[test]
    fn rfc5424_structured_data_bracket_is_skipped_not_included_in_message() {
        let parsed = detect_and_parse(
            r#"<34>1 2025-01-15T12:30:00Z host app 123 msg1 [exampleSDID@32473 iut="3"] hello"#,
        )
        .unwrap_or_else(|| panic!("expected a parse"));
        assert_eq!(parsed.proc_id, Some("123".to_owned()));
        assert_eq!(parsed.msg_id, Some("msg1".to_owned()));
        assert_eq!(parsed.message, "hello");
    }

    #[test]
    fn rfc5424_multiple_structured_data_elements_are_both_skipped() {
        let parsed = detect_and_parse(
            r#"<34>1 2025-01-15T12:30:00Z host app - - [a@1 x="1"][b@2 y="2"] hello"#,
        )
        .unwrap_or_else(|| panic!("expected a parse"));
        assert_eq!(parsed.message, "hello");
    }

    #[test]
    fn rfc5424_empty_message_after_sd_is_empty_string() {
        let parsed = detect_and_parse("<34>1 2025-01-15T12:30:00Z host app - - -")
            .unwrap_or_else(|| panic!("expected a parse"));
        assert_eq!(parsed.message, "");
    }

    #[test]
    fn malformed_pri_is_not_parsed() {
        assert!(detect_and_parse("<not-a-number>Oct 11 22:14:15 host msg").is_none());
    }

    #[test]
    fn no_leading_angle_bracket_is_not_parsed() {
        assert!(detect_and_parse("not a syslog message").is_none());
    }

    #[test]
    fn rfc5424_invalid_timestamp_falls_back_to_rfc3164_and_fails_there_too() {
        // Not a valid RFC 3339 timestamp AND not RFC-3164-shaped either —
        // exercises the fallback-then-fail path in `detect_and_parse`.
        assert!(detect_and_parse("<34>1 not-a-timestamp host app - - - msg").is_none());
    }

    #[test]
    fn unterminated_structured_data_bracket_falls_back_to_whole_remainder_as_message() {
        let (sd, message) = split_structured_data("[unterminated forever");
        assert_eq!(sd, "-");
        assert_eq!(message, "[unterminated forever");
    }
}
