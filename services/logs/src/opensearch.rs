//! OpenSearch write path — the `_bulk` document writer and the ISM lifecycle
//! policy, ported from v1 `writers/opensearch_writer.py` + `ism/policy.py`.
//! v1 used the opensearch-py client; there is no OpenSearch client crate, so
//! (matching the manager's siem router) these talk raw REST over reqwest. The
//! `_bulk` request body is emitted byte-for-byte identically to opensearch-py's
//! `helpers.async_bulk` output.

use chrono::{DateTime, Utc};

use crate::jsonord::JsonVal;

/// v1 `INDEX_PATTERN` — the daily index gets a `-YYYY.MM.DD` suffix.
const INDEX_PATTERN: &str = "skauswatch-logs";
/// v1 ISM policy id (`put_policy(policy="skauswatch-logs-policy", ...)`).
const ISM_POLICY_ID: &str = "skauswatch-logs-policy";

/// Daily index name for `now`: `skauswatch-logs-YYYY.MM.DD` (v1
/// `f"{INDEX_PATTERN}-{now.strftime('%Y.%m.%d')}"`).
pub fn daily_index(now: DateTime<Utc>) -> String {
    format!("{INDEX_PATTERN}-{}", now.format("%Y.%m.%d"))
}

/// Builds the `_bulk` NDJSON body for a batch: for each document, an index
/// action line `{"index":{"_index":"<index>"}}` followed by the compact
/// document, each terminated by `\n` (opensearch-py `helpers.bulk` framing).
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

/// POSTs the batch to `{base_url}/_bulk`. Mirrors v1 `helpers.async_bulk(...,
/// raise_on_error=False)`: per-document item errors in a 200 response are
/// ignored, but a transport failure or non-2xx status propagates (v1 raised →
/// the handler answers 500).
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

/// Builds the OpenSearch ISM hot→warm→delete policy (v1 `build_ism_policy`):
/// 30d hot, then read-only + force-merge, then delete at `retention_days`.
pub fn build_ism_policy(retention_days: i64) -> serde_json::Value {
    let warm_after_days = 30;
    serde_json::json!({
        "policy": {
            "description": format!(
                "SkausWatch SIEM log lifecycle: 30d hot, delete at {retention_days}d"
            ),
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [
                        {"rollover": {"min_index_age": "1d", "min_doc_count": 10_000_000}}
                    ],
                    "transitions": [
                        {"state_name": "warm", "conditions": {"min_index_age": format!("{warm_after_days}d")}}
                    ]
                },
                {
                    "name": "warm",
                    "actions": [
                        {"read_only": {}},
                        {"force_merge": {"max_num_segments": 1}}
                    ],
                    "transitions": [
                        {"state_name": "delete", "conditions": {"min_index_age": format!("{retention_days}d")}}
                    ]
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": []
                }
            ]
        }
    })
}

/// Applies the ISM policy at startup, idempotently. Like v1 `ensure_ism_policy`,
/// any error (e.g. OpenSearch unreachable) is logged and swallowed — startup
/// continues regardless.
pub async fn ensure_ism_policy(client: &reqwest::Client, base_url: &str, retention_days: i64) {
    let policy = build_ism_policy(retention_days);
    let url = format!("{base_url}/_plugins/_ism/policies/{ISM_POLICY_ID}");
    match client.put(url).json(&policy).send().await {
        Ok(resp) => match resp.error_for_status() {
            Ok(_) => tracing::info!(retention_days, "ism_policy_applied"),
            Err(e) => tracing::warn!(error = %e, "ism_policy_error"),
        },
        Err(e) => tracing::warn!(error = %e, "ism_policy_error"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn daily_index_uses_dotted_date() {
        let now = match Utc.with_ymd_and_hms(2026, 7, 25, 1, 2, 3) {
            chrono::LocalResult::Single(dt) => dt,
            _ => panic!("valid now"),
        };
        assert_eq!(daily_index(now), "skauswatch-logs-2026.07.25");
    }

    #[test]
    fn bulk_body_frames_action_and_document_lines() {
        let doc = crate::jsonord::from_slice(br#"{"a":1}"#).unwrap();
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

    #[test]
    fn ism_policy_matches_v1_structure() {
        let policy = build_ism_policy(90);
        assert_eq!(policy["policy"]["default_state"], "hot");
        assert_eq!(
            policy["policy"]["description"],
            "SkausWatch SIEM log lifecycle: 30d hot, delete at 90d"
        );
        let states = policy["policy"]["states"].as_array().unwrap();
        assert_eq!(states.len(), 3);
        assert_eq!(states[0]["name"], "hot");
        assert_eq!(
            states[0]["transitions"][0]["conditions"]["min_index_age"],
            "30d"
        );
        assert_eq!(
            states[1]["transitions"][0]["conditions"]["min_index_age"],
            "90d"
        );
        assert_eq!(states[2]["name"], "delete");
    }
}
