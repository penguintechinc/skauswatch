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
//! Dead-code note: every item below is exercised by `crate::writer`, but
//! `writer::run` itself is not yet called from `main.rs::serve()` — that
//! wiring lands at the Wave-1 integration gate once every module it
//! references exists (see `writer.rs`'s own doc comment). Until then a
//! plain (non-test) `cargo build`/`clippy` sees this whole module as
//! unreachable, matching `buffer/mod.rs`'s same interim `#![allow(dead_code)]`.
#![allow(dead_code)]

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

/// POSTs the batch to `{base_url}/_bulk`. Mirrors v1 `helpers.async_bulk(...,
/// raise_on_error=False)`: per-document item errors in a 200 response are
/// ignored, but a transport failure or non-2xx status propagates (v1 raised →
/// the caller treats it as a failed batch — `crate::writer` nacks/DLQs on
/// this `Err`, never acks).
///
/// # Errors
/// Returns the reqwest error on transport failure or a non-2xx bulk response.
pub async fn write_bulk(
    client: &reqwest::Client,
    base_url: &str,
    body: String,
) -> Result<(), reqwest::Error> {
    client
        .post(format!("{base_url}/_bulk"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
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

        assert!(result.is_ok());
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
}
