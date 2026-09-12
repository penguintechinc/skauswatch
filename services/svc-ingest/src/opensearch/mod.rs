//! OpenSearch `_bulk` write path for the unified `skauswatch-logs-*` lake —
//! `daily_index`/`build_bulk_body`/`write_bulk` are ported byte-for-byte
//! from `services/logs/src/opensearch.rs` (same NDJSON framing, now
//! operating on `skauswatch_ocsf::JsonVal`). [`build_bulk_body_with_ids`]
//! is new for this task: `crate::writer` needs an explicit, deterministic
//! `_id` per document (derived from the buffered event's `dedup_key`) so a
//! JetStream-redelivered event overwrites the same OpenSearch document on
//! rewrite instead of creating a duplicate (Spec §7a at-least-once,
//! §14b `writer_crash_mid_batch_causes_at_least_once_redelivery`) —
//! `build_bulk_body` itself stays untouched for v1 framing parity. Task 2.1
//! adds a sibling `ism.rs` for hot/warm/cold tiering; that lifecycle policy
//! is out of scope here.
//!
use chrono::{DateTime, Utc};
use skauswatch_ocsf::JsonVal;

/// v1 `INDEX_PATTERN` — the daily index gets a `-YYYY.MM.DD` suffix. No
/// per-tenant segment: the Spec's unified index scheme (§8a) keeps a single
/// `skauswatch-logs-YYYY.MM.DD` pattern per day, with tenant isolation
/// enforced via the `tenant_id` document field + query-time filtering
/// (matching how `services/logs` already indexes) rather than a
/// per-tenant index split.
const INDEX_PATTERN: &str = "skauswatch-logs";

/// Daily index name for `now`: `skauswatch-logs-YYYY.MM.DD` (v1
/// `f"{INDEX_PATTERN}-{now.strftime('%Y.%m.%d')}"`).
pub fn daily_index(now: DateTime<Utc>) -> String {
    format!("{INDEX_PATTERN}-{}", now.format("%Y.%m.%d"))
}

/// Builds the `_bulk` NDJSON body for a batch: for each document, an index
/// action line `{"index":{"_index":"<index>"}}` followed by the compact
/// document, each terminated by `\n` (opensearch-py `helpers.bulk` framing).
/// Byte-identical port of `services/logs/src/opensearch.rs`'s function of
/// the same name — kept without an `_id` field so the v1 framing parity
/// test (`bulk_body_frames_action_and_document_lines_matches_v1_framing`)
/// stays meaningful; `crate::writer` uses [`build_bulk_body_with_ids`]
/// instead when it needs redelivery-safe deterministic document ids.
pub fn build_bulk_body(index: &str, docs: &[JsonVal]) -> String {
    let mut out = String::new();
    for doc in docs {
        let action = JsonVal::Obj(vec![(
            "index".to_owned(),
            JsonVal::Obj(vec![("_index".to_owned(), JsonVal::Str(index.to_owned()))]),
        )]);
        action.write_compact(&mut out);
        out.push('\n');
        doc.write_compact(&mut out);
        out.push('\n');
    }
    out
}

/// Same NDJSON `_bulk` framing as [`build_bulk_body`], but every action line
/// also carries an explicit `_id` (`{"index":{"_index":"<index>","_id":"<id>"}}`) —
/// `crate::writer` passes each event's `dedup_key` as `id`, so a
/// JetStream-redelivered event (the same `dedup_key`, at-least-once) writes
/// to the same OpenSearch document on retry instead of creating a
/// duplicate. `docs` pairs each document with its id, in the order they
/// should appear in the batch.
pub fn build_bulk_body_with_ids(index: &str, docs: &[(String, JsonVal)]) -> String {
    let mut out = String::new();
    for (id, doc) in docs {
        let action = JsonVal::Obj(vec![(
            "index".to_owned(),
            JsonVal::Obj(vec![
                ("_index".to_owned(), JsonVal::Str(index.to_owned())),
                ("_id".to_owned(), JsonVal::Str(id.clone())),
            ]),
        )]);
        action.write_compact(&mut out);
        out.push('\n');
        doc.write_compact(&mut out);
        out.push('\n');
    }
    out
}

/// One per-item rejection from a `_bulk` response's `items[].index.error`
/// object — `_id`, `_index`, the OpenSearch-reported error `type`, and
/// `reason`. Previously this detail was discarded entirely (only the bare
/// `_id` survived into [`BulkOutcome::failed_ids`]), so a rejection like a
/// dynamic-mapping conflict was logged as the opaque, undiagnosable
/// "opensearch bulk response reported per-item errors" with no indication
/// of which field or why. `crate::writer` logs this via `tracing::error!`
/// and folds it into the failure reason threaded through to the DLQ
/// envelope's `dlq_reason`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkItemError {
    /// The document `_id` (see [`build_bulk_body_with_ids`]) OpenSearch
    /// rejected.
    pub id: String,
    /// The target index for the rejected item, when present.
    pub index: Option<String>,
    /// OpenSearch's `error.type` (e.g. `mapper_parsing_exception`).
    pub error_type: Option<String>,
    /// OpenSearch's `error.reason` — the human-readable rejection cause.
    pub reason: Option<String>,
}

impl std::fmt::Display for BulkItemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id={} index={} type={} reason={}",
            self.id,
            self.index.as_deref().unwrap_or("?"),
            self.error_type.as_deref().unwrap_or("?"),
            self.reason.as_deref().unwrap_or("?")
        )
    }
}

/// Outcome of a `_bulk` request that completed at the HTTP level (2xx) —
/// OpenSearch can still report per-document failures inside that
/// otherwise-successful response (`"errors": true` plus a per-item
/// `error` object), so a status-code-only check would treat those
/// documents as written when they were not. `failed_ids` holds the `_id`
/// (see [`build_bulk_body_with_ids`]) of every document the response
/// reported as failed — `crate::writer` nacks/DLQs exactly those, and
/// acks the rest as normal. `item_errors` carries the full detail behind
/// each of those `failed_ids`, in the same order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkOutcome {
    /// `_id`s the bulk response reported as failed.
    pub failed_ids: Vec<String>,
    /// Full per-item error detail (index/type/reason) for each entry in
    /// [`Self::failed_ids`], same order.
    pub item_errors: Vec<BulkItemError>,
}

impl BulkOutcome {
    /// Whether every document in the batch was indexed successfully.
    pub fn all_succeeded(&self) -> bool {
        self.failed_ids.is_empty()
    }
}

/// POSTs the batch to `{base_url}/_bulk` and parses the response for
/// per-item failures. Mirrors v1 `helpers.async_bulk(..., raise_on_error=
/// False)`: a transport failure or non-2xx status propagates as `Err` (the
/// caller treats the whole batch as failed — nacks/DLQs on this, never
/// acks), but a 200 response is inspected for `"errors": true` — those
/// specific documents are reported via [`BulkOutcome::failed_ids`] rather
/// than silently treated as written.
///
/// # Errors
/// Returns the reqwest error on transport failure, a non-2xx bulk
/// response, or a response body that isn't valid JSON.
pub async fn write_bulk(
    client: &reqwest::Client,
    base_url: &str,
    body: String,
) -> Result<BulkOutcome, reqwest::Error> {
    let response = client
        .post(format!("{base_url}/_bulk"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    let payload: serde_json::Value = response.json().await?;
    Ok(parse_bulk_response(&payload))
}

/// Extracts the `_id`s of any per-item bulk failures from a parsed `_bulk`
/// response body. A response that doesn't have the expected `items` array
/// (missing or malformed) is treated as fully successful — matching v1's
/// `raise_on_error=False` forgiving behavior for anything short of a hard
/// transport/status failure, which `write_bulk` already handles before
/// this function ever runs.
fn parse_bulk_response(payload: &serde_json::Value) -> BulkOutcome {
    let Some(items) = payload.get("items").and_then(serde_json::Value::as_array) else {
        return BulkOutcome::default();
    };
    let item_errors: Vec<BulkItemError> = items
        .iter()
        .filter_map(|item| {
            // Each item is `{"<action>": {...}}` — "index" for every
            // write this service performs, but read whichever single key
            // is present rather than hardcoding "index" in case a future
            // action type is ever added.
            let action_result = item.as_object()?.values().next()?;
            let error = action_result.get("error")?;
            Some(BulkItemError {
                id: action_result
                    .get("_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                index: action_result
                    .get("_index")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                error_type: error
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                reason: error
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect();
    let failed_ids = item_errors.iter().map(|e| e.id.clone()).collect();
    BulkOutcome {
        failed_ids,
        item_errors,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn daily_index_uses_dotted_date() {
        let now = match Utc.with_ymd_and_hms(2026, 7, 25, 1, 2, 3) {
            chrono::LocalResult::Single(dt) => dt,
            _ => panic!("valid now"),
        };
        assert_eq!(daily_index(now), "skauswatch-logs-2026.07.25");
    }

    /// Parity with `services/logs/src/opensearch.rs`'s
    /// `bulk_body_frames_action_and_document_lines` test — same input,
    /// same byte-for-byte output.
    #[test]
    fn bulk_body_frames_action_and_document_lines_matches_v1_framing() {
        let doc = skauswatch_ocsf::jsonord::from_slice(br#"{"a":1}"#).unwrap();
        let body = build_bulk_body("skauswatch-logs-2026.07.25", std::slice::from_ref(&doc));
        assert_eq!(
            body,
            "{\"index\":{\"_index\":\"skauswatch-logs-2026.07.25\"}}\n{\"a\":1}\n"
        );
    }

    #[test]
    fn empty_batch_produces_empty_body() {
        assert_eq!(build_bulk_body("i", &[]), "");
    }

    /// [`build_bulk_body_with_ids`] must add `_id` to the action line
    /// without disturbing the rest of the v1 framing — same separators,
    /// same document encoding.
    #[test]
    fn build_bulk_body_with_ids_includes_deterministic_id() {
        let doc = skauswatch_ocsf::jsonord::from_slice(br#"{"a":1}"#).unwrap();
        let body = build_bulk_body_with_ids(
            "skauswatch-logs-2026.07.25",
            &[("dedup-key-a".to_owned(), doc)],
        );
        assert_eq!(
            body,
            "{\"index\":{\"_index\":\"skauswatch-logs-2026.07.25\",\"_id\":\"dedup-key-a\"}}\n{\"a\":1}\n"
        );
    }

    /// Redelivering the same event twice must produce the same `_id` both
    /// times — the property `crate::writer` relies on to make a
    /// JetStream-redelivered rewrite an overwrite, not a duplicate.
    #[test]
    fn build_bulk_body_with_ids_same_dedup_key_yields_same_id() {
        let doc_a = skauswatch_ocsf::jsonord::from_slice(br#"{"a":1}"#).unwrap();
        let doc_b = doc_a.clone();
        let first = build_bulk_body_with_ids("i", &[("k".to_owned(), doc_a)]);
        let second = build_bulk_body_with_ids("i", &[("k".to_owned(), doc_b)]);
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn write_bulk_succeeds_on_200() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"errors": false})),
            )
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let result = write_bulk(&client, &mock.uri(), "{}\n".to_owned()).await;

        assert!(result.as_ref().unwrap().all_succeeded());
        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "exactly one POST to /_bulk");
        assert_eq!(
            requests[0]
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/x-ndjson")
        );
    }

    #[tokio::test]
    async fn write_bulk_propagates_non_2xx_status() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let result = write_bulk(&client, &mock.uri(), "{}\n".to_owned()).await;

        assert!(result.is_err(), "a 503 bulk response must propagate as Err");
    }

    #[tokio::test]
    async fn write_bulk_propagates_transport_failure() {
        let client = reqwest::Client::new();
        // Nothing listens on this port — connection refused.
        let result = write_bulk(&client, "http://127.0.0.1:1", "{}\n".to_owned()).await;
        assert!(result.is_err());
    }

    /// A 200 response with `"errors": true` and a per-item `error` object
    /// must NOT be treated as fully successful — OpenSearch accepted the
    /// HTTP request but rejected specific documents, and silently acking
    /// those away would be a silent evidence loss in a SIEM.
    #[tokio::test]
    async fn write_bulk_reports_per_item_failures_on_200_with_errors_true() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errors": true,
                "items": [
                    {"index": {"_index": "i", "_id": "evt-ok", "status": 201}},
                    {"index": {"_index": "i", "_id": "evt-bad", "status": 400, "error": {"type": "mapper_parsing_exception", "reason": "boom"}}}
                ]
            })))
            .mount(&mock)
            .await;

        let client = reqwest::Client::new();
        let outcome = write_bulk(&client, &mock.uri(), "{}\n".to_owned())
            .await
            .unwrap();

        assert!(
            !outcome.all_succeeded(),
            "batch must not be treated as fully successful"
        );
        assert_eq!(outcome.failed_ids, vec!["evt-bad".to_owned()]);
        assert_eq!(
            outcome.item_errors,
            vec![BulkItemError {
                id: "evt-bad".to_owned(),
                index: Some("i".to_owned()),
                error_type: Some("mapper_parsing_exception".to_owned()),
                reason: Some("boom".to_owned()),
            }],
            "the full per-item error detail (index/type/reason) must survive parsing, \
             not just the bare _id — this is what makes the real OpenSearch rejection \
             reason visible instead of a generic message"
        );
    }

    #[test]
    fn parse_bulk_response_missing_items_is_treated_as_fully_successful() {
        let outcome = parse_bulk_response(&serde_json::json!({"errors": false}));
        assert!(outcome.all_succeeded());
    }

    #[test]
    fn parse_bulk_response_with_no_errors_reports_no_failed_ids() {
        let outcome = parse_bulk_response(&serde_json::json!({
            "errors": false,
            "items": [{"index": {"_index": "i", "_id": "evt-ok", "status": 201}}]
        }));
        assert!(outcome.all_succeeded());
    }
}
