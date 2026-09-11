//! Legacy `aaa-events-*` → unified `skauswatch-logs-*` backfill job. Invoked
//! via `Command::Backfill` in `main.rs`; scrolls through `aaa-events-*` indices
//! by date range, maps each document to OCSF via
//! `skauswatch_ocsf::mappings::legacy_aaa_events::legacy_aaa_event_to_ocsf`,
//! batches by size, and bulk-writes to `skauswatch-logs-*` (or just maps and
//! prints if `--dry-run` is set). The backfill is a one-time administrative
//! operation; see the Task 2.3 brief for full context.

use chrono::{Duration, NaiveDate, Utc};
use skauswatch_ocsf::JsonVal;

use crate::config::Config;
use crate::opensearch;

/// Configuration for a backfill operation.
#[derive(Debug, Clone)]
pub struct BackfillConfig {
    /// Start date (inclusive) for the backfill range.
    pub start_date: NaiveDate,
    /// End date (inclusive) for the backfill range.
    pub end_date: NaiveDate,
    /// Number of documents per batch before posting to `_bulk`.
    pub batch_size: usize,
    /// If true, map documents but do not post to `_bulk`.
    pub dry_run: bool,
}

/// Result of a backfill operation.
#[derive(Debug)]
pub struct BackfillResult {
    /// Total documents mapped.
    pub total_mapped: usize,
    /// Total documents written (0 if dry_run).
    pub total_written: usize,
    /// Total documents that failed mapping.
    pub total_failed: usize,
}

/// Executes the backfill: scrolls `aaa-events-*` indices for the given date
/// range, maps each document to OCSF, batches, and bulk-writes to
/// `skauswatch-logs-*`. Returns a summary of the operation.
///
/// # Errors
///
/// Returns an error if OpenSearch communication fails, DB config is invalid,
/// or mapping fails unexpectedly.
pub async fn run_backfill(
    cfg: &Config,
    backfill_cfg: BackfillConfig,
) -> anyhow::Result<BackfillResult> {
    tracing::info!(
        start_date = %backfill_cfg.start_date,
        end_date = %backfill_cfg.end_date,
        batch_size = backfill_cfg.batch_size,
        dry_run = backfill_cfg.dry_run,
        "backfill starting"
    );

    let mut result = BackfillResult {
        total_mapped: 0,
        total_written: 0,
        total_failed: 0,
    };

    // Initialize OpenSearch client.
    let client = reqwest::Client::new();

    // Iterate through each day in the date range.
    let mut current_date = backfill_cfg.start_date;
    while current_date <= backfill_cfg.end_date {
        let index_name = format!("aaa-events-{}", current_date.format("%Y.%m.%d"));
        tracing::info!(index = %index_name, "scrolling index");

        // Scroll through the index, fetching documents in batches.
        let (daily_mapped, daily_written, daily_failed) =
            scroll_and_write_index(&client, cfg, &index_name, &backfill_cfg).await?;

        result.total_mapped += daily_mapped;
        result.total_written += daily_written;
        result.total_failed += daily_failed;

        current_date += Duration::days(1);
    }

    tracing::info!(
        total_mapped = result.total_mapped,
        total_written = result.total_written,
        total_failed = result.total_failed,
        "backfill completed"
    );

    Ok(result)
}

/// Scrolls through a single index and writes its documents in batches.
async fn scroll_and_write_index(
    client: &reqwest::Client,
    cfg: &Config,
    index_name: &str,
    backfill_cfg: &BackfillConfig,
) -> anyhow::Result<(usize, usize, usize)> {
    let mut total_mapped = 0;
    let mut total_written = 0;
    let mut total_failed = 0;
    let mut batch: Vec<JsonVal> = Vec::new();

    // Initial scroll request.
    let mut scroll_id: Option<String> = None;

    loop {
        let request_body = if let Some(ref sid) = scroll_id {
            // Subsequent scroll request.
            serde_json::json!({
                "scroll": "5m",
                "scroll_id": sid
            })
        } else {
            // Initial search request.
            serde_json::json!({
                "size": backfill_cfg.batch_size,
                "scroll": "5m",
                "query": {
                    "match_all": {}
                }
            })
        };

        let url = if scroll_id.is_some() {
            format!("{}/_search/scroll", cfg.opensearch_url)
        } else {
            format!("{}/{}/_search", cfg.opensearch_url, index_name)
        };

        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                index = index_name,
                "scroll request failed"
            );
            break;
        }

        let body: serde_json::Value = response.json().await?;

        // Extract scroll_id for the next request.
        if let Some(new_scroll_id) = body.get("_scroll_id").and_then(|v| v.as_str()) {
            scroll_id = Some(new_scroll_id.to_string());
        }

        // Extract hits array from the response.
        let hits_opt = body
            .get("hits")
            .and_then(|h| h.get("hits"))
            .and_then(|h| h.as_array());

        let hits = match hits_opt {
            Some(h) => h,
            None => break,
        };

        if hits.is_empty() {
            break;
        }

        // Process each hit: map to OCSF and add to batch.
        for hit in hits {
            if let Some(source) = hit.get("_source") {
                match serde_json::from_value::<JsonVal>(source.clone()) {
                    Ok(raw) => {
                        match skauswatch_ocsf::mappings::legacy_aaa_events::legacy_aaa_event_to_ocsf(
                            &raw,
                        ) {
                            Ok(mapped) => {
                                total_mapped += 1;
                                batch.push(mapped);

                                // Flush batch if it reaches the configured size.
                                if batch.len() >= backfill_cfg.batch_size {
                                    let written =
                                        flush_batch(client, cfg, &batch, backfill_cfg).await?;
                                    total_written += written;
                                    batch.clear();
                                }
                            }
                            Err(_) => {
                                total_failed += 1;
                                tracing::warn!("failed to map document");
                            }
                        }
                    }
                    Err(e) => {
                        total_failed += 1;
                        tracing::warn!(error = %e, "failed to deserialize source");
                    }
                }
            }
        }
    }

    // Flush any remaining documents in the batch.
    if !batch.is_empty() {
        let written = flush_batch(client, cfg, &batch, backfill_cfg).await?;
        total_written += written;
    }

    Ok((total_mapped, total_written, total_failed))
}

/// Flushes a batch of mapped documents to OpenSearch `_bulk` endpoint
/// (or just counts them if dry_run is true). Fails on any write error:
/// network failure, non-2xx status, or per-document errors all propagate.
async fn flush_batch(
    client: &reqwest::Client,
    cfg: &Config,
    batch: &[JsonVal],
    backfill_cfg: &BackfillConfig,
) -> anyhow::Result<usize> {
    let now = Utc::now();
    let index = opensearch::daily_index(now);
    let bulk_body = opensearch::build_bulk_body(&index, batch);

    if backfill_cfg.dry_run {
        // Just count the documents; don't POST.
        tracing::debug!(count = batch.len(), "dry_run: skipping _bulk POST");
        Ok(batch.len())
    } else {
        // POST to _bulk endpoint.
        let url = format!("{}/_bulk", cfg.opensearch_url);
        let response = client
            .post(&url)
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_body)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "bulk write failed: {} ({})",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }

        let body: serde_json::Value = response.json().await?;
        let errors = body
            .get("errors")
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        if errors {
            // Per-document failures are failures for a migration context.
            anyhow::bail!("bulk write reported per-document errors: {}", body);
        }

        Ok(batch.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn backfill_config_date_range_validation() {
        let start = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let end = NaiveDate::from_ymd_opt(2025, 1, 10).unwrap();
        let cfg = BackfillConfig {
            start_date: start,
            end_date: end,
            batch_size: 100,
            dry_run: false,
        };

        assert_eq!(cfg.start_date, start);
        assert_eq!(cfg.end_date, end);
    }

    /// Builds a [`Config`] pointed at a wiremock server for tests that drive
    /// the real [`run_backfill`]/[`scroll_and_write_index`] code path. All
    /// [`Config`] fields are `pub`, so this constructs the struct literal
    /// directly rather than going through `Config::from_values` (private to
    /// `config.rs`).
    fn test_config(opensearch_url: String) -> Config {
        Config {
            http_port: 8443,
            syslog_port: 5140,
            syslog_tls_port: 6514,
            otlp_grpc_port: 4317,
            otlp_http_port: 4318,
            opensearch_url,
            nats_url: "nats://localhost:4222".to_owned(),
            nats_jetstream_subject_prefix: "svc-ingest.logs".to_owned(),
            snapshot_repo: "skauswatch-snapshots".to_owned(),
            syslog_udp_enabled: false,
            syslog_trusted_cidrs: Vec::new(),
            syslog_udp_tenant_id: None,
        }
    }

    /// One `_source` hit document for a mocked scroll response.
    fn hit(id: &str, severity: i64) -> serde_json::Value {
        serde_json::json!({
            "_id": id,
            "_source": {
                "severity": severity,
                "facility": 4,
                "message": format!("Event {id}")
            }
        })
    }

    /// Drives the real [`run_backfill`] over a 3-day range against a
    /// wiremock OpenSearch and asserts the number of *distinct* per-day
    /// `aaa-events-*` search requests it issues, plus that `batch_size`
    /// controls how many `_bulk` flushes happen per day — replacing the
    /// prior version of this test, which only asserted local string
    /// arithmetic on index names and never called [`run_backfill`] at all.
    #[tokio::test]
    async fn backfill_batches_by_start_end_date_and_batch_size() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Each day's initial search returns 4 hits. With batch_size=2 this
        // must flush _bulk exactly twice per day (2 docs each).
        for day in ["2025.01.01", "2025.01.02", "2025.01.03"] {
            Mock::given(method("POST"))
                .and(path(format!("/aaa-events-{day}/_search")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "_scroll_id": format!("scroll_{day}"),
                    "hits": {
                        "hits": [hit("1", 3), hit("2", 4), hit("3", 5), hit("4", 6)]
                    }
                })))
                .expect(1)
                .named(format!("initial search for {day}"))
                .mount(&mock_server)
                .await;
        }

        // Scroll continuation always ends the loop for whichever day called
        // it — same endpoint is reused across all three days.
        Mock::given(method("POST"))
            .and(path("/_search/scroll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_scroll_id": "scroll_done",
                "hits": { "hits": [] }
            })))
            .expect(3)
            .named("scroll continuation")
            .mount(&mock_server)
            .await;

        // 3 days * 2 flushes/day (4 hits, batch_size=2) = 6 _bulk POSTs.
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"errors": false})),
            )
            .expect(6)
            .named("_bulk flush")
            .mount(&mock_server)
            .await;

        let cfg = test_config(mock_server.uri());
        let backfill_cfg = BackfillConfig {
            start_date: NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            end_date: NaiveDate::from_ymd_opt(2025, 1, 3).unwrap(),
            batch_size: 2,
            dry_run: false,
        };

        let result = run_backfill(&cfg, backfill_cfg)
            .await
            .expect("backfill against mocked OpenSearch must succeed");

        assert_eq!(result.total_mapped, 12, "4 docs/day * 3 days");
        assert_eq!(
            result.total_written, 12,
            "batch_size=2 flushes must cover every doc"
        );
        assert_eq!(result.total_failed, 0);

        // Assert on the ACTUAL request count the mock received, not local
        // index-name string arithmetic: exactly one search per day against
        // aaa-events-*, driven by the start/end date range.
        let received = mock_server.received_requests().await.unwrap();
        let aaa_events_requests = received
            .iter()
            .filter(|r| r.url.path().starts_with("/aaa-events-"))
            .count();
        assert_eq!(
            aaa_events_requests, 3,
            "one initial search per day in the start..=end date range"
        );

        // Confirm batch_size was actually sent as the page size on each
        // initial per-day search, tying the assertion to batch_size (not
        // just the date range).
        for r in received
            .iter()
            .filter(|r| r.url.path().starts_with("/aaa-events-"))
        {
            let body: serde_json::Value = r.body_json().unwrap();
            assert_eq!(body["size"], 2, "initial search size must equal batch_size");
        }

        let bulk_requests = received.iter().filter(|r| r.url.path() == "/_bulk").count();
        assert_eq!(
            bulk_requests, 6,
            "batch_size=2 over 4 docs/day must flush twice/day"
        );

        // expect(1)/expect(3)/expect(6) above are the primary gate — this
        // additionally fails loudly with the actual request set if it ever
        // regresses back to not calling run_backfill at all.
        mock_server.verify().await;
    }

    /// Drives the real [`run_backfill`] with `dry_run=true` against a
    /// wiremock OpenSearch and asserts it never POSTs to `_bulk` while still
    /// reporting a non-zero mapped/would-write count — replacing the prior
    /// version of this test, which only asserted [`BackfillConfig`] field
    /// values locally and never called [`run_backfill`] at all.
    #[tokio::test]
    async fn backfill_dry_run_maps_without_writing() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/aaa-events-2025.01.01/_search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_scroll_id": "scroll_1",
                "hits": { "hits": [hit("1", 3), hit("2", 4)] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/_search/scroll"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_scroll_id": "scroll_done",
                "hits": { "hits": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // The critical assertion: dry_run must NEVER issue a _bulk POST.
        // expect(0) fails the test the moment this mock is asked to match
        // a request that shouldn't exist.
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"errors": false})),
            )
            .expect(0)
            .named("_bulk (must never be called in dry_run)")
            .mount(&mock_server)
            .await;

        let cfg = test_config(mock_server.uri());
        let start = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let backfill_cfg = BackfillConfig {
            start_date: start,
            end_date: start,
            batch_size: 100,
            dry_run: true,
        };

        let result = run_backfill(&cfg, backfill_cfg)
            .await
            .expect("dry_run backfill against mocked OpenSearch must succeed");

        assert!(result.total_mapped > 0, "dry_run must still map documents");
        assert_eq!(result.total_mapped, 2);
        assert_eq!(
            result.total_written, 2,
            "dry_run reports would-write count without POSTing"
        );
        assert_eq!(result.total_failed, 0);

        let bulk_requests = mock_server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == "/_bulk")
            .count();
        assert_eq!(bulk_requests, 0, "dry_run must never POST to _bulk");

        // expect(0) above is the primary gate; verify() makes the failure
        // explicit rather than relying on Drop's implicit panic.
        mock_server.verify().await;
    }

    #[test]
    fn backfill_dry_run_configuration() {
        let start = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let end = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let cfg = BackfillConfig {
            start_date: start,
            end_date: end,
            batch_size: 100,
            dry_run: true,
        };

        assert!(cfg.dry_run);
    }
}
