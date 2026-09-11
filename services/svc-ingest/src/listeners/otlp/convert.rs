//! Converts the generated prost `opentelemetry::proto::{...}` types (gRPC
//! path) and OTLP's proto3-JSON wire encoding (HTTP `application/json`
//! path) into the transport-agnostic
//! [`skauswatch_ocsf::mappings::otlp::LogRecordFields`] shape, so both
//! `:4317` and `:4318` funnel through the exact same
//! [`skauswatch_ocsf::mappings::otlp::log_record_to_ocsf`] call — see
//! `otlp_http_json_and_protobuf_variants_both_parse_to_the_same_ocsf_doc`
//! in `super::tests`.
//!
//! JSON decoding covers the field shapes real OTLP/HTTP JSON producers
//! emit (`stringValue`/`boolValue`/`intValue`/`doubleValue` `AnyValue`
//! variants, `timeUnixNano` as either a JSON string or number per
//! proto3's int64-as-string convention, `severityNumber` as either the
//! numeric value or one of the six severity-family enum names). Nested
//! `arrayValue`/`kvlistValue`/`bytesValue` `AnyValue` variants are not
//! decoded from JSON (documented limitation, Spec §14d: "dead code...
//! must be documented" — these are unreachable, not merely untested, from
//! the JSON path); the protobuf path decodes all seven `AnyValue`
//! variants via [`any_value_to_json`].

use skauswatch_ocsf::JsonVal;
use skauswatch_ocsf::mappings::otlp::LogRecordFields;
use skauswatch_proto::opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest;
use skauswatch_proto::opentelemetry::proto::common::v1::AnyValue;
use skauswatch_proto::opentelemetry::proto::common::v1::any_value::Value as AnyValueKind;
use skauswatch_proto::opentelemetry::proto::logs::v1::LogRecord;
use skauswatch_proto::opentelemetry::proto::resource::v1::Resource;

/// One decoded log record paired with its resource-level attributes —
/// exactly the two arguments
/// `skauswatch_ocsf::mappings::otlp::log_record_to_ocsf` takes.
pub(super) struct DecodedRecord {
    pub(super) fields: LogRecordFields,
    pub(super) resource_attrs: Vec<(String, String)>,
}

// ---------------------------------------------------------------------
// Protobuf (gRPC + HTTP `application/x-protobuf`) path
// ---------------------------------------------------------------------

/// Flattens every `ResourceLogs` -> `ScopeLogs` -> `LogRecord` in `req`
/// into a flat list of [`DecodedRecord`]s, in wire order.
pub(super) fn decode_proto_request(req: &ExportLogsServiceRequest) -> Vec<DecodedRecord> {
    let started = std::time::Instant::now();
    let out = decode_proto_request_inner(req);
    metrics::histogram!(
        crate::otel::metric_names::RECEIVER_PARSE_DURATION_MS,
        "parser" => "otlp"
    )
    .record(started.elapsed().as_secs_f64() * 1000.0);
    out
}

fn decode_proto_request_inner(req: &ExportLogsServiceRequest) -> Vec<DecodedRecord> {
    let mut out = Vec::new();
    for resource_logs in &req.resource_logs {
        let resource_attrs = resource_logs
            .resource
            .as_ref()
            .map(resource_attrs_from_proto)
            .unwrap_or_default();
        for scope_logs in &resource_logs.scope_logs {
            for record in &scope_logs.log_records {
                out.push(DecodedRecord {
                    fields: log_record_fields_from_proto(record),
                    resource_attrs: resource_attrs.clone(),
                });
            }
        }
    }
    out
}

fn resource_attrs_from_proto(resource: &Resource) -> Vec<(String, String)> {
    resource
        .attributes
        .iter()
        .map(|kv| (kv.key.clone(), any_value_to_plain_string(kv.value.as_ref())))
        .collect()
}

fn log_record_fields_from_proto(record: &LogRecord) -> LogRecordFields {
    LogRecordFields {
        time_unix_nano: record.time_unix_nano,
        severity_number: record.severity_number,
        body: any_value_to_plain_string(record.body.as_ref()),
        attributes: record
            .attributes
            .iter()
            .map(|kv| (kv.key.clone(), any_value_to_json(kv.value.as_ref())))
            .collect(),
    }
}

/// Converts a protobuf `AnyValue` oneof into this crate's order-preserving
/// [`JsonVal`], recursing through `ArrayValue`/`KeyValueList`. `bytes` has
/// no native JSON representation here (this codebase has no base64
/// dependency to add — out of this task's file scope); it is hex-encoded,
/// same style as `crate::auth::hash_token`'s hex rendering.
fn any_value_to_json(v: Option<&AnyValue>) -> JsonVal {
    match v.and_then(|v| v.value.as_ref()) {
        Some(AnyValueKind::StringValue(s)) => JsonVal::Str(s.clone()),
        Some(AnyValueKind::BoolValue(b)) => JsonVal::Bool(*b),
        Some(AnyValueKind::IntValue(i)) => JsonVal::Num((*i).into()),
        Some(AnyValueKind::DoubleValue(d)) => {
            serde_json::Number::from_f64(*d).map_or(JsonVal::Null, JsonVal::Num)
        }
        Some(AnyValueKind::BytesValue(bytes)) => JsonVal::Str(hex_encode(bytes)),
        Some(AnyValueKind::ArrayValue(arr)) => JsonVal::Arr(
            arr.values
                .iter()
                .map(|v| any_value_to_json(Some(v)))
                .collect(),
        ),
        Some(AnyValueKind::KvlistValue(kv)) => JsonVal::Obj(
            kv.values
                .iter()
                .map(|kv| (kv.key.clone(), any_value_to_json(kv.value.as_ref())))
                .collect(),
        ),
        None => JsonVal::Null,
    }
}

fn any_value_to_plain_string(v: Option<&AnyValue>) -> String {
    match any_value_to_json(v) {
        JsonVal::Str(s) => s,
        JsonVal::Null => String::new(),
        other => other.to_compact_string(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------
// proto3-JSON (HTTP `application/json`) path
// ---------------------------------------------------------------------

/// Decodes an OTLP/HTTP JSON-encoded `ExportLogsServiceRequest` body
/// (`resourceLogs[].resource.attributes[]`,
/// `resourceLogs[].scopeLogs[].logRecords[]` — proto3 JSON's camelCase
/// field names and array-of-`{key,value}` encoding for `repeated
/// KeyValue`, never a JSON map). Malformed/missing fields degrade to
/// empty defaults rather than erroring — an ingest listener must not 500
/// on a shape it doesn't fully understand (Spec's general fail-open
/// posture for best-effort normalization paths).
pub(super) fn decode_json_request(root: &serde_json::Value) -> Vec<DecodedRecord> {
    let started = std::time::Instant::now();
    let out = decode_json_request_inner(root);
    metrics::histogram!(
        crate::otel::metric_names::RECEIVER_PARSE_DURATION_MS,
        "parser" => "otlp"
    )
    .record(started.elapsed().as_secs_f64() * 1000.0);
    out
}

fn decode_json_request_inner(root: &serde_json::Value) -> Vec<DecodedRecord> {
    let mut out = Vec::new();
    let Some(resource_logs) = root
        .get("resourceLogs")
        .and_then(serde_json::Value::as_array)
    else {
        return out;
    };
    for resource_log in resource_logs {
        let resource_attrs = resource_log
            .get("resource")
            .map(resource_attrs_from_json)
            .unwrap_or_default();
        let Some(scope_logs) = resource_log
            .get("scopeLogs")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for scope_log in scope_logs {
            let Some(log_records) = scope_log
                .get("logRecords")
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for record in log_records {
                out.push(DecodedRecord {
                    fields: log_record_fields_from_json(record),
                    resource_attrs: resource_attrs.clone(),
                });
            }
        }
    }
    out
}

fn resource_attrs_from_json(resource: &serde_json::Value) -> Vec<(String, String)> {
    key_value_array_to_string_pairs(resource.get("attributes"))
}

fn key_value_array_to_string_pairs(attrs: Option<&serde_json::Value>) -> Vec<(String, String)> {
    let Some(arr) = attrs.and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|kv| {
            let key = kv.get("key")?.as_str()?.to_owned();
            Some((key, any_value_json_to_plain_string(kv.get("value"))))
        })
        .collect()
}

fn log_record_fields_from_json(record: &serde_json::Value) -> LogRecordFields {
    let time_unix_nano = record.get("timeUnixNano").and_then(json_u64).unwrap_or(0);
    let severity_number = record
        .get("severityNumber")
        .and_then(json_severity_number)
        .unwrap_or(0);
    let body = any_value_json_to_plain_string(record.get("body"));
    let attributes = record
        .get("attributes")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|kv| {
                    let key = kv.get("key")?.as_str()?.to_owned();
                    Some((key, any_value_json_to_ocsf_json(kv.get("value"))))
                })
                .collect()
        })
        .unwrap_or_default();
    LogRecordFields {
        time_unix_nano,
        severity_number,
        body,
        attributes,
    }
}

/// `fixed64`/`int64` fields render as a JSON string in canonical proto3
/// JSON (avoids precision loss in JS number parsing); a bare JSON number
/// is also accepted defensively.
fn json_u64(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::String(s) => s.parse().ok(),
        serde_json::Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// Accepts either the enum's numeric value or one of the six
/// severity-family names (`SEVERITY_NUMBER_{TRACE,DEBUG,INFO,WARN,ERROR,
/// FATAL}`, mapped to that family's base value — the `2`/`3`/`4` numbered
/// variants have no distinct name-based entry point here since a real
/// producer emitting the string form invariably uses the base name).
fn json_severity_number(v: &serde_json::Value) -> Option<i32> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().and_then(|i| i32::try_from(i).ok()),
        serde_json::Value::String(s) => match s.as_str() {
            "SEVERITY_NUMBER_TRACE" => Some(1),
            "SEVERITY_NUMBER_DEBUG" => Some(5),
            "SEVERITY_NUMBER_INFO" => Some(9),
            "SEVERITY_NUMBER_WARN" => Some(13),
            "SEVERITY_NUMBER_ERROR" => Some(17),
            "SEVERITY_NUMBER_FATAL" => Some(21),
            _ => None,
        },
        _ => None,
    }
}

/// JSON encoding of an `AnyValue` oneof (`{"stringValue": "..."}`, etc.).
/// `int64` renders as a JSON string in canonical proto3 JSON; a bare
/// number is accepted defensively. `arrayValue`/`kvlistValue`/
/// `bytesValue` are not decoded here — see the module doc comment.
fn any_value_json_to_ocsf_json(v: Option<&serde_json::Value>) -> JsonVal {
    let Some(v) = v else {
        return JsonVal::Null;
    };
    if let Some(s) = v.get("stringValue").and_then(|s| s.as_str()) {
        return JsonVal::Str(s.to_owned());
    }
    if let Some(b) = v.get("boolValue").and_then(serde_json::Value::as_bool) {
        return JsonVal::Bool(b);
    }
    if let Some(i) = v.get("intValue") {
        let parsed = match i {
            serde_json::Value::String(s) => s.parse::<i64>().ok(),
            serde_json::Value::Number(n) => n.as_i64(),
            _ => None,
        };
        if let Some(n) = parsed {
            return JsonVal::Num(n.into());
        }
    }
    if let Some(d) = v.get("doubleValue").and_then(serde_json::Value::as_f64)
        && let Some(n) = serde_json::Number::from_f64(d)
    {
        return JsonVal::Num(n);
    }
    JsonVal::Null
}

fn any_value_json_to_plain_string(v: Option<&serde_json::Value>) -> String {
    match any_value_json_to_ocsf_json(v) {
        JsonVal::Str(s) => s,
        JsonVal::Null => String::new(),
        other => other.to_compact_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use skauswatch_proto::opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest;
    use skauswatch_proto::opentelemetry::proto::common::v1::{InstrumentationScope, KeyValue};
    use skauswatch_proto::opentelemetry::proto::logs::v1::{ResourceLogs, ScopeLogs};

    fn any_str(s: &str) -> AnyValue {
        AnyValue {
            value: Some(AnyValueKind::StringValue(s.to_owned())),
        }
    }

    fn sample_proto_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_owned(),
                        value: Some(any_str("svc-ingest")),
                    }],
                    dropped_attributes_count: 0,
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope::default()),
                    log_records: vec![LogRecord {
                        time_unix_nano: 1_705_312_200_000_000_000,
                        severity_number: 9,
                        body: Some(any_str("hello from otlp")),
                        attributes: vec![KeyValue {
                            key: "user_id".to_owned(),
                            value: Some(any_str("alice")),
                        }],
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    /// The equivalent OTLP/HTTP JSON body for [`sample_proto_request`] —
    /// same resource/log-record shape, proto3-JSON encoded by hand.
    fn sample_json_request() -> serde_json::Value {
        serde_json::json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "svc-ingest"}}
                    ]
                },
                "scopeLogs": [{
                    "logRecords": [{
                        "timeUnixNano": "1705312200000000000",
                        "severityNumber": 9,
                        "body": {"stringValue": "hello from otlp"},
                        "attributes": [
                            {"key": "user_id", "value": {"stringValue": "alice"}}
                        ]
                    }]
                }]
            }]
        })
    }

    #[test]
    fn otlp_http_json_and_protobuf_variants_both_parse_to_the_same_ocsf_doc() {
        let from_proto = decode_proto_request(&sample_proto_request());
        let json_body = sample_json_request();
        let from_json = decode_json_request(&json_body);

        assert_eq!(from_proto.len(), 1);
        assert_eq!(from_json.len(), 1);

        let doc_from_proto = skauswatch_ocsf::mappings::otlp::log_record_to_ocsf(
            &from_proto[0].fields,
            &from_proto[0].resource_attrs,
        );
        let doc_from_json = skauswatch_ocsf::mappings::otlp::log_record_to_ocsf(
            &from_json[0].fields,
            &from_json[0].resource_attrs,
        );

        assert_eq!(doc_from_proto, doc_from_json);
        assert_eq!(
            doc_from_proto.get("message"),
            Some(&JsonVal::Str("hello from otlp".to_owned()))
        );
        assert_eq!(
            doc_from_proto.get("user_name"),
            Some(&JsonVal::Str("alice".to_owned()))
        );
    }

    #[test]
    fn any_value_to_json_covers_every_protobuf_variant() {
        assert_eq!(
            any_value_to_json(Some(&AnyValue {
                value: Some(AnyValueKind::BoolValue(true))
            })),
            JsonVal::Bool(true)
        );
        assert_eq!(
            any_value_to_json(Some(&AnyValue {
                value: Some(AnyValueKind::IntValue(42))
            })),
            JsonVal::Num(42.into())
        );
        assert_eq!(
            any_value_to_json(Some(&AnyValue {
                value: Some(AnyValueKind::DoubleValue(1.5))
            })),
            JsonVal::Num(serde_json::Number::from_f64(1.5).unwrap())
        );
        assert_eq!(
            any_value_to_json(Some(&AnyValue {
                value: Some(AnyValueKind::BytesValue(vec![0xde, 0xad]))
            })),
            JsonVal::Str("dead".to_owned())
        );
        assert_eq!(any_value_to_json(None), JsonVal::Null);
        assert_eq!(
            any_value_to_json(Some(&AnyValue { value: None })),
            JsonVal::Null
        );
    }

    #[test]
    fn any_value_to_json_recurses_through_array_and_kvlist() {
        use skauswatch_proto::opentelemetry::proto::common::v1::{ArrayValue, KeyValueList};

        let arr = AnyValue {
            value: Some(AnyValueKind::ArrayValue(ArrayValue {
                values: vec![any_str("a"), any_str("b")],
            })),
        };
        assert_eq!(
            any_value_to_json(Some(&arr)),
            JsonVal::Arr(vec![
                JsonVal::Str("a".to_owned()),
                JsonVal::Str("b".to_owned())
            ])
        );

        let kvlist = AnyValue {
            value: Some(AnyValueKind::KvlistValue(KeyValueList {
                values: vec![KeyValue {
                    key: "nested".to_owned(),
                    value: Some(any_str("v")),
                }],
            })),
        };
        assert_eq!(
            any_value_to_json(Some(&kvlist)),
            JsonVal::Obj(vec![("nested".to_owned(), JsonVal::Str("v".to_owned()))])
        );
    }

    #[test]
    fn json_severity_number_accepts_numeric_and_named_forms() {
        assert_eq!(json_severity_number(&serde_json::json!(17)), Some(17));
        assert_eq!(
            json_severity_number(&serde_json::json!("SEVERITY_NUMBER_ERROR")),
            Some(17)
        );
        assert_eq!(
            json_severity_number(&serde_json::json!("not-a-severity")),
            None
        );
        assert_eq!(json_severity_number(&serde_json::json!(null)), None);
    }

    #[test]
    fn json_u64_accepts_string_and_number_forms() {
        assert_eq!(json_u64(&serde_json::json!("123")), Some(123));
        assert_eq!(json_u64(&serde_json::json!(123)), Some(123));
        assert_eq!(json_u64(&serde_json::json!("not-a-number")), None);
        assert_eq!(json_u64(&serde_json::json!(null)), None);
    }

    #[test]
    fn decode_json_request_degrades_gracefully_on_missing_fields() {
        assert!(decode_json_request(&serde_json::json!({})).is_empty());
        assert!(decode_json_request(&serde_json::json!({"resourceLogs": [{}]})).is_empty());
        assert!(
            decode_json_request(&serde_json::json!({"resourceLogs": [{"scopeLogs": [{}]}]}))
                .is_empty()
        );
    }

    #[test]
    fn any_value_json_double_and_missing_int_value_variants() {
        assert_eq!(
            any_value_json_to_ocsf_json(Some(&serde_json::json!({"doubleValue": 2.5}))),
            JsonVal::Num(serde_json::Number::from_f64(2.5).unwrap())
        );
        assert_eq!(
            any_value_json_to_ocsf_json(Some(&serde_json::json!({"intValue": "7"}))),
            JsonVal::Num(7.into())
        );
        assert_eq!(any_value_json_to_ocsf_json(None), JsonVal::Null);
        assert_eq!(
            any_value_json_to_ocsf_json(Some(&serde_json::json!({}))),
            JsonVal::Null
        );
    }

    #[test]
    fn any_value_json_bool_and_numeric_int_value_variants() {
        assert_eq!(
            any_value_json_to_ocsf_json(Some(&serde_json::json!({"boolValue": true}))),
            JsonVal::Bool(true)
        );
        // Bare numeric `intValue` (not the canonical proto3-JSON string
        // form) is accepted defensively.
        assert_eq!(
            any_value_json_to_ocsf_json(Some(&serde_json::json!({"intValue": 9}))),
            JsonVal::Num(9.into())
        );
    }

    #[test]
    fn any_value_json_to_plain_string_renders_null_and_non_string_values() {
        assert_eq!(any_value_json_to_plain_string(None), String::new());
        assert_eq!(
            any_value_json_to_plain_string(Some(&serde_json::json!({"boolValue": true}))),
            "true"
        );
    }

    #[test]
    fn any_value_to_plain_string_renders_null_and_non_string_values() {
        assert_eq!(any_value_to_plain_string(None), String::new());
        assert_eq!(
            any_value_to_plain_string(Some(&AnyValue {
                value: Some(AnyValueKind::IntValue(5))
            })),
            "5"
        );
    }

    #[test]
    fn key_value_array_to_string_pairs_skips_malformed_entries() {
        let attrs = serde_json::json!([
            {"key": "ok", "value": {"stringValue": "v"}},
            {"value": {"stringValue": "missing key"}},
            "not-an-object"
        ]);
        let pairs = key_value_array_to_string_pairs(Some(&attrs));
        assert_eq!(pairs, vec![("ok".to_owned(), "v".to_owned())]);
        assert_eq!(key_value_array_to_string_pairs(None), Vec::new());
    }
}
