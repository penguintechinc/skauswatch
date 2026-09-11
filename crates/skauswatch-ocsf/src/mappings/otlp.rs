//! OpenTelemetry (OTLP logs) → OCSF field mapping (Task 1.2, see
//! `docs/v2-port/ingest-module-spec.md` §4b/§5).
//!
//! [`LogRecordFields`] is a plain struct — deliberately NOT the
//! prost-generated `opentelemetry::proto::logs::v1::LogRecord` type — so
//! this crate never depends on `skauswatch-proto`/`prost`. The OTLP gRPC
//! (`:4317`) and HTTP (`:4318`) listeners in `services/svc-ingest`
//! (consumers of the generated prost types) convert a real `LogRecord`
//! into this shape before calling [`log_record_to_ocsf`].

use crate::jsonord::JsonVal;
use crate::schema::OCSF_VERSION;

/// A decoded OTLP `LogRecord`, stripped of its prost/protobuf origin — see
/// the module doc comment. `attributes` preserves insertion order and each
/// value's original JSON type (string/bool/number), so an OTLP attribute
/// map that is itself already a complete OCSF document (see
/// [`log_record_to_ocsf`]'s "native passthrough" behavior) survives
/// round-trip unmodified rather than being stringified.
#[derive(Debug, Clone, PartialEq)]
pub struct LogRecordFields {
    /// `LogRecord.time_unix_nano` — nanoseconds since the Unix epoch. `0`
    /// means "unknown/missing" per the OTLP spec.
    pub time_unix_nano: u64,
    /// `LogRecord.severity_number` (`SeverityNumber` enum's integer value,
    /// 0-24). Mapped to an OCSF severity id by [`severity_number_to_ocsf`].
    pub severity_number: i32,
    /// `LogRecord.body`, already reduced to its string form (OTLP's `body`
    /// is technically an `AnyValue`; the listener extracts `string_value`
    /// or a best-effort string rendering before constructing this struct).
    pub body: String,
    /// `LogRecord.attributes`, in original order. Security-relevant keys
    /// are aliased onto top-level OCSF fields by [`log_record_to_ocsf`];
    /// everything else lands in `metadata.custom_attributes`.
    pub attributes: Vec<(String, JsonVal)>,
}

/// Maps an OTLP `SeverityNumber` (Spec §4b: "0-5 range, same as RFC 5424
/// levels") to this crate's OCSF severity id scale (see
/// `crate::detect_severity`'s string-keyed equivalent: 0=Unknown,
/// 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical). `TRACE` (1-4) has
/// no direct OCSF equivalent in that scale and maps to `0` (Unknown), same
/// as any out-of-range or unset (`0`) value.
#[must_use]
pub fn severity_number_to_ocsf(severity_number: i32) -> i64 {
    match severity_number {
        5..=8 => 1,   // DEBUG -> Informational
        9..=12 => 1,  // INFO -> Informational
        13..=16 => 2, // WARN -> Low
        17..=20 => 4, // ERROR -> High
        21..=24 => 5, // FATAL -> Critical
        _ => 0,       // TRACE (1-4), UNSPECIFIED (0), or out of range
    }
}

/// Attribute key recognized as an alias for OCSF's `user_name` — see
/// [`resolve_user_name`].
const ATTR_USER_ID: &str = "user_id";
/// Generic-username alias, lower precedence than [`ATTR_USER_ID`] on
/// collision (Spec §15 open question #8's recommended resolution).
const ATTR_USER: &str = "user";
/// Attribute key recognized as an alias for OCSF's `src_ip_addr`.
const ATTR_SRC_IP: &str = "src_ip";
/// Attribute key this crate treats as signaling a complete, already OCSF-shaped
/// document (Spec §4b "Native OTLP passthrough") — see [`passthrough_ocsf_doc`].
const ATTR_CLASS_UID: &str = "class_uid";

/// If `record.attributes` already carries a `class_uid` entry, the source
/// is treated as having sent a complete, pre-normalized OCSF document as
/// its OTLP attribute map (Spec §4b: "if the LogRecord already carries a
/// complete OCSF-shaped attribute dict ... skip normalization and pass it
/// through validated"). The attributes are returned exactly as given, in
/// their original order and with their original JSON types — `body`,
/// `severity_number`, `time_unix_nano`, and `resource_attrs` are all
/// ignored in this path, per "pass it through" (not merged/augmented).
fn passthrough_ocsf_doc(record: &LogRecordFields) -> Option<JsonVal> {
    let has_class_uid = record
        .attributes
        .iter()
        .any(|(key, _)| key == ATTR_CLASS_UID);
    if !has_class_uid {
        return None;
    }
    Some(JsonVal::Obj(record.attributes.clone()))
}

/// Resolves the `user_id`/`user` attribute-key collision per Spec §15 open
/// question #8: "log a warning, use `user_id`" — `user_id` always wins
/// when both are present, regardless of which appears first in
/// `attributes` (a plain single-pass `match` would let *iteration order*
/// decide the winner instead of the field name, which is wrong).
///
/// This is a pure mapping function with no `tracing`/logging dependency
/// (this crate — `skauswatch-ocsf` — intentionally carries none, so
/// `skauswatch-svc-ingest` can be normalization's only side-effecting
/// caller); the caller is expected to log the collision itself if it
/// wants operator-visible evidence, using this function's return value to
/// decide whether one occurred.
fn resolve_user_name(attributes: &[(String, JsonVal)]) -> Option<JsonVal> {
    let user_id = attributes
        .iter()
        .find(|(k, _)| k == ATTR_USER_ID)
        .map(|(_, v)| v);
    let user = attributes
        .iter()
        .find(|(k, _)| k == ATTR_USER)
        .map(|(_, v)| v);
    match (user_id, user) {
        (Some(uid), _) => Some(uid.clone()),
        (None, Some(user)) => Some(user.clone()),
        (None, None) => None,
    }
}

/// Maps a decoded OTLP `LogRecord` (plus its resource-level attributes) to
/// an OCSF event document (Spec §4b/§5): `body` → `message`,
/// `severity_number` → `severity_id`, `time_unix_nano` → `time`,
/// security-relevant attributes aliased onto top-level OCSF fields
/// (`user_id`/`user` → `user_name`, `src_ip` → `src_ip_addr`), everything
/// else into `metadata.custom_attributes`. See [`passthrough_ocsf_doc`] for
/// the native-OCSF-shaped-attributes short-circuit this checks first.
#[must_use]
pub fn log_record_to_ocsf(
    record: &LogRecordFields,
    resource_attrs: &[(String, String)],
) -> JsonVal {
    if let Some(doc) = passthrough_ocsf_doc(record) {
        return doc;
    }

    let user_name = resolve_user_name(&record.attributes);
    let src_ip_addr = record
        .attributes
        .iter()
        .find(|(k, _)| k == ATTR_SRC_IP)
        .map(|(_, v)| v.clone());

    let custom_attributes: Vec<(String, JsonVal)> = record
        .attributes
        .iter()
        .filter(|(k, _)| ![ATTR_USER_ID, ATTR_USER, ATTR_SRC_IP].contains(&k.as_str()))
        .cloned()
        .collect();

    // Self-contained classification (deliberately not reusing
    // `crate::detect_class`/`crate::detect_status`, which are shaped
    // around string-keyed JSON records from syslog/generic-JSON sources,
    // not an OTLP attribute list): a `src_ip` attribute signals a network
    // event; otherwise this is a generic security finding, matching
    // `crate::schema`'s existing class registry.
    let class_uid: i64 = if src_ip_addr.is_some() { 4001 } else { 2001 };

    let mut metadata_entries = vec![
        ("version".to_owned(), JsonVal::Str(OCSF_VERSION.to_owned())),
        (
            "product".to_owned(),
            JsonVal::Obj(vec![
                ("name".to_owned(), JsonVal::Str("SkausWatch".to_owned())),
                (
                    "vendor_name".to_owned(),
                    JsonVal::Str("PenguinTech".to_owned()),
                ),
            ]),
        ),
    ];
    if !resource_attrs.is_empty() {
        metadata_entries.push((
            "resource_attributes".to_owned(),
            JsonVal::Obj(
                resource_attrs
                    .iter()
                    .map(|(k, v)| (k.clone(), JsonVal::Str(v.clone())))
                    .collect(),
            ),
        ));
    }
    if !custom_attributes.is_empty() {
        metadata_entries.push((
            "custom_attributes".to_owned(),
            JsonVal::Obj(custom_attributes),
        ));
    }

    let mut doc = vec![
        ("class_uid".to_owned(), JsonVal::Num(class_uid.into())),
        (
            "class_name".to_owned(),
            JsonVal::Str(crate::schema::class_name(class_uid).to_owned()),
        ),
        (
            "time".to_owned(),
            JsonVal::Str(render_time(record.time_unix_nano)),
        ),
        (
            "severity_id".to_owned(),
            JsonVal::Num(severity_number_to_ocsf(record.severity_number).into()),
        ),
        ("status_id".to_owned(), JsonVal::Num(99.into())),
        ("message".to_owned(), JsonVal::Str(record.body.clone())),
    ];
    if let Some(user_name) = user_name {
        doc.push(("user_name".to_owned(), user_name));
    }
    if let Some(src_ip_addr) = src_ip_addr {
        doc.push(("src_ip_addr".to_owned(), src_ip_addr));
    }
    doc.push(("metadata".to_owned(), JsonVal::Obj(metadata_entries)));

    JsonVal::Obj(doc)
}

/// Renders `time_unix_nano` as an RFC 3339 timestamp with a `+00:00` UTC
/// offset and microsecond fraction (`chrono`'s `SecondsFormat::Micros`,
/// matching this crate's other ISO-8601 rendering style). `0` or an
/// out-of-chrono-range value (Spec's timestamp fields are attacker/
/// instrumentation-controlled, never assumed valid) falls back to "now" —
/// same fail-open behavior as `crate::detect_time`'s unparsable-timestamp
/// fallback, never a hard error for a log ingest path.
fn render_time(time_unix_nano: u64) -> String {
    use chrono::{DateTime, SecondsFormat, Utc};

    let secs = i64::try_from(time_unix_nano / 1_000_000_000).unwrap_or(i64::MAX);
    let subsec_nanos = u32::try_from(time_unix_nano % 1_000_000_000).unwrap_or(0);
    let dt = DateTime::<Utc>::from_timestamp(secs, subsec_nanos).unwrap_or_else(Utc::now);
    dt.to_rfc3339_opts(SecondsFormat::Micros, false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fields(
        time_unix_nano: u64,
        severity_number: i32,
        body: &str,
        attributes: Vec<(&str, JsonVal)>,
    ) -> LogRecordFields {
        LogRecordFields {
            time_unix_nano,
            severity_number,
            body: body.to_owned(),
            attributes: attributes
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        }
    }

    #[test]
    fn severity_number_mapping_matches_v1_scale() {
        assert_eq!(severity_number_to_ocsf(0), 0); // UNSPECIFIED
        assert_eq!(severity_number_to_ocsf(1), 0); // TRACE
        assert_eq!(severity_number_to_ocsf(4), 0); // TRACE4
        assert_eq!(severity_number_to_ocsf(5), 1); // DEBUG
        assert_eq!(severity_number_to_ocsf(9), 1); // INFO
        assert_eq!(severity_number_to_ocsf(13), 2); // WARN
        assert_eq!(severity_number_to_ocsf(17), 4); // ERROR
        assert_eq!(severity_number_to_ocsf(21), 5); // FATAL
        assert_eq!(severity_number_to_ocsf(999), 0); // out of range
    }

    #[test]
    fn native_ocsf_shaped_otlp_attributes_pass_through_unmodified() {
        // A source that already speaks OCSF sends a complete document as
        // the OTLP attribute map — Spec §4b: skip normalization entirely.
        let ocsf_shaped = vec![
            ("class_uid".to_owned(), JsonVal::Num(3002.into())),
            (
                "class_name".to_owned(),
                JsonVal::Str("authentication".to_owned()),
            ),
            ("severity_id".to_owned(), JsonVal::Num(2.into())),
            (
                "message".to_owned(),
                JsonVal::Str("login failed".to_owned()),
            ),
        ];
        let record = LogRecordFields {
            time_unix_nano: 1_705_312_200_000_000_000,
            severity_number: 17, // would map to severity_id 4 if normalized
            body: "this body must be ignored".to_owned(),
            attributes: ocsf_shaped.clone(),
        };
        let resource_attrs = vec![("service.name".to_owned(), "should-be-ignored".to_owned())];

        let doc = log_record_to_ocsf(&record, &resource_attrs);

        // Exactly the attribute set, unmodified — same order, same values,
        // nothing added (no `metadata`/`time` synthesized) and nothing
        // dropped.
        assert_eq!(doc, JsonVal::Obj(ocsf_shaped));
    }

    #[test]
    fn otlp_attribute_collision_user_id_wins_over_user() {
        let record = fields(
            0,
            9,
            "hello",
            vec![
                ("user", JsonVal::Str("alice-generic".to_owned())),
                ("user_id", JsonVal::Str("alice-explicit".to_owned())),
            ],
        );
        let doc = log_record_to_ocsf(&record, &[]);
        assert_eq!(
            doc.get("user_name"),
            Some(&JsonVal::Str("alice-explicit".to_owned()))
        );

        // Order-independence: `user_id` still wins even when it appears
        // first in the attribute list (iteration order must never decide).
        let record_reordered = fields(
            0,
            9,
            "hello",
            vec![
                ("user_id", JsonVal::Str("alice-explicit".to_owned())),
                ("user", JsonVal::Str("alice-generic".to_owned())),
            ],
        );
        let doc_reordered = log_record_to_ocsf(&record_reordered, &[]);
        assert_eq!(
            doc_reordered.get("user_name"),
            Some(&JsonVal::Str("alice-explicit".to_owned()))
        );
    }

    #[test]
    fn user_alone_or_user_id_alone_both_map_to_user_name() {
        let only_user = fields(0, 9, "m", vec![("user", JsonVal::Str("bob".to_owned()))]);
        assert_eq!(
            log_record_to_ocsf(&only_user, &[]).get("user_name"),
            Some(&JsonVal::Str("bob".to_owned()))
        );

        let only_user_id = fields(
            0,
            9,
            "m",
            vec![("user_id", JsonVal::Str("carol".to_owned()))],
        );
        assert_eq!(
            log_record_to_ocsf(&only_user_id, &[]).get("user_name"),
            Some(&JsonVal::Str("carol".to_owned()))
        );

        let neither = fields(0, 9, "m", vec![]);
        assert_eq!(log_record_to_ocsf(&neither, &[]).get("user_name"), None);
    }

    #[test]
    fn src_ip_attribute_aliases_to_src_ip_addr_and_classifies_network_activity() {
        let record = fields(
            0,
            9,
            "conn",
            vec![("src_ip", JsonVal::Str("10.1.2.3".to_owned()))],
        );
        let doc = log_record_to_ocsf(&record, &[]);
        assert_eq!(
            doc.get("src_ip_addr"),
            Some(&JsonVal::Str("10.1.2.3".to_owned()))
        );
        assert_eq!(doc.get("class_uid"), Some(&JsonVal::Num(4001.into())));
        assert_eq!(
            doc.get("class_name"),
            Some(&JsonVal::Str("network_activity".to_owned()))
        );
    }

    #[test]
    fn record_without_recognized_attributes_defaults_to_security_finding() {
        let record = fields(0, 0, "generic event", vec![]);
        let doc = log_record_to_ocsf(&record, &[]);
        assert_eq!(doc.get("class_uid"), Some(&JsonVal::Num(2001.into())));
        assert_eq!(
            doc.get("class_name"),
            Some(&JsonVal::Str("security_finding".to_owned()))
        );
        assert_eq!(doc.get("status_id"), Some(&JsonVal::Num(99.into())));
    }

    #[test]
    fn unknown_attributes_land_in_metadata_custom_attributes_not_rejected() {
        let record = fields(
            0,
            9,
            "m",
            vec![
                ("action", JsonVal::Str("blocked".to_owned())),
                ("retry_count", JsonVal::Num(3.into())),
            ],
        );
        let doc = log_record_to_ocsf(&record, &[]);
        let custom = doc
            .get("metadata")
            .and_then(|m| m.get("custom_attributes"))
            .expect("custom_attributes present");
        assert_eq!(
            custom.get("action"),
            Some(&JsonVal::Str("blocked".to_owned()))
        );
        assert_eq!(custom.get("retry_count"), Some(&JsonVal::Num(3.into())));
    }

    #[test]
    fn resource_attributes_land_in_metadata_resource_attributes() {
        let record = fields(0, 9, "m", vec![]);
        let resource_attrs = vec![("service.name".to_owned(), "svc-ingest".to_owned())];
        let doc = log_record_to_ocsf(&record, &resource_attrs);
        let resource = doc
            .get("metadata")
            .and_then(|m| m.get("resource_attributes"))
            .expect("resource_attributes present");
        assert_eq!(
            resource.get("service.name"),
            Some(&JsonVal::Str("svc-ingest".to_owned()))
        );
    }

    #[test]
    fn body_maps_to_message_and_time_unix_nano_maps_to_time() {
        let record = fields(1_705_312_200_000_000_000, 9, "hello world", vec![]);
        let doc = log_record_to_ocsf(&record, &[]);
        assert_eq!(
            doc.get("message"),
            Some(&JsonVal::Str("hello world".to_owned()))
        );
        assert_eq!(
            doc.get("time"),
            Some(&JsonVal::Str("2024-01-15T09:50:00.000000+00:00".to_owned()))
        );
    }

    #[test]
    fn zero_time_unix_nano_is_still_a_valid_renderable_epoch_timestamp() {
        let record = fields(0, 9, "m", vec![]);
        let doc = log_record_to_ocsf(&record, &[]);
        // time_unix_nano=0 is a valid (epoch) timestamp per the OTLP spec's
        // "0 indicates unknown or missing" note -- either way it must
        // render deterministically, not panic or omit the field.
        assert_eq!(
            doc.get("time"),
            Some(&JsonVal::Str("1970-01-01T00:00:00.000000+00:00".to_owned()))
        );
    }

    #[test]
    fn passthrough_requires_class_uid_specifically() {
        // Attributes that merely *resemble* OCSF fields (e.g. "message")
        // without a `class_uid` do NOT trigger passthrough -- otherwise
        // almost any OTLP log record would accidentally bypass mapping.
        let record = fields(
            1_705_312_200_000_000_000,
            9,
            "normalize me",
            vec![("message", JsonVal::Str("should not win".to_owned()))],
        );
        let doc = log_record_to_ocsf(&record, &[]);
        assert_eq!(
            doc.get("message"),
            Some(&JsonVal::Str("normalize me".to_owned()))
        );
    }
}
