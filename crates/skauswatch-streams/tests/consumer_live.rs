//! Live-Valkey integration tests for the consumer-group harness. Gated with
//! `#[ignore]`; run explicitly against a real broker:
//!
//! ```bash
//! docker run -d --rm -p 6379:6379 valkey/valkey:8-bookworm
//! SKAUSWATCH_TEST_REDIS_URL=redis://127.0.0.1:6379 \
//!   cargo test -p skauswatch-streams --test consumer_live -- --ignored
//! ```
//!
//! Coverage: producer→consumer roundtrip with the manager's exact
//! `s3scan:tasks` field shape, per-message ack, retry after a handler failure,
//! DLQ after the delivery limit, and `XAUTOCLAIM` recovery of a pending entry
//! abandoned by another (crashed) consumer.

#![allow(clippy::expect_used, clippy::panic)] // integration tests fail loudly

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fred::interfaces::{ClientLike, StreamsInterface};
use skauswatch_streams::{
    ConsumerConfig, EntryFields, HandlerError, StreamConsumer, StreamEntry, StreamHandler,
    StreamProducer, py_bool,
};
use tokio::sync::{Mutex, watch};

fn redis_url() -> String {
    std::env::var("SKAUSWATCH_TEST_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

/// A unique key prefix per test so runs never collide on a shared broker.
fn unique_prefix() -> String {
    format!("swtest:{}", uuid::Uuid::new_v4().simple())
}

/// The manager's `scan_task_fields` job-level enumerate shape.
fn manager_enumerate_fields(job_id: &str, bucket_config_id: i32) -> EntryFields {
    vec![
        ("job_id".to_owned(), job_id.to_owned()),
        ("bucket_config_id".to_owned(), bucket_config_id.to_string()),
        ("object_key".to_owned(), String::new()),
        ("object_size".to_owned(), "0".to_owned()),
        ("object_etag".to_owned(), String::new()),
        ("scan_enabled".to_owned(), py_bool(true).to_owned()),
        ("yara_enabled".to_owned(), py_bool(false).to_owned()),
        ("submitted_at".to_owned(), "2026-07-22T09:30:00".to_owned()),
    ]
}

/// Handler that records what it saw and fails its first `fail_first` deliveries.
struct RecordingHandler {
    seen: Arc<Mutex<Vec<StreamEntry>>>,
    attempts: AtomicUsize,
    fail_first: usize,
    always_fail: bool,
}

impl RecordingHandler {
    fn new(fail_first: usize, always_fail: bool) -> Arc<Self> {
        Arc::new(Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            attempts: AtomicUsize::new(0),
            fail_first,
            always_fail,
        })
    }
}

#[async_trait::async_trait]
impl StreamHandler for RecordingHandler {
    async fn handle(&self, entry: &StreamEntry) -> Result<(), HandlerError> {
        let n = self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.always_fail || n < self.fail_first {
            return Err(format!("intentional failure #{n}").into());
        }
        self.seen.lock().await.push(entry.clone());
        Ok(())
    }
}

async fn raw_client(url: &str) -> fred::clients::Client {
    let config = fred::types::config::Config::from_url(url).expect("valid url");
    let client = fred::types::Builder::from_config(config)
        .build()
        .expect("build client");
    client.init().await.expect("connect");
    client
}

/// Polls `f` until it returns true or the deadline elapses.
async fn wait_until<F, Fut>(timeout: Duration, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    loop {
        if f().await {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "condition not met within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Pending-entry count for a group (extended XPENDING).
async fn pending_count(client: &fred::clients::Client, key: &str, group: &str) -> usize {
    let rows: Vec<(String, String, u64, u64)> = client
        .xpending(key, group, (0u64, "-", "+", 100u64))
        .await
        .expect("xpending");
    rows.len()
}

fn test_config(prefix: &str, stream: &str, max_deliveries: u64) -> ConsumerConfig {
    let mut c = ConsumerConfig::new(stream, format!("{prefix}:grp"), "worker-1");
    c.block_ms = 100;
    c.min_idle_ms = 0;
    c.max_deliveries = max_deliveries;
    c
}

#[tokio::test]
#[ignore = "requires a live Valkey/Redis (SKAUSWATCH_TEST_REDIS_URL)"]
async fn roundtrip_publish_consume_ack() {
    let url = redis_url();
    let prefix = unique_prefix();
    let stream = "s3scan:tasks";
    let producer = StreamProducer::connect(&url, None, &prefix)
        .await
        .expect("producer");
    let consumer = StreamConsumer::connect(&url, None, &prefix)
        .await
        .expect("consumer");
    let cfg = test_config(&prefix, stream, 5);
    let handler = RecordingHandler::new(0, false);

    consumer
        .ensure_group(stream, &cfg.group)
        .await
        .expect("group");
    producer
        .publish(stream, manager_enumerate_fields("job-1", 7))
        .await
        .expect("publish");

    let (tx, rx) = watch::channel(false);
    let h = handler.clone();
    let run = tokio::spawn(async move { consumer.run(&cfg, h.as_ref(), rx).await });

    let seen = handler.seen.clone();
    wait_until(Duration::from_secs(10), || {
        let seen = seen.clone();
        async move { seen.lock().await.len() == 1 }
    })
    .await;

    // The handler received the exact manager field shape.
    let got = handler.seen.lock().await;
    assert_eq!(got[0].get("job_id"), Some("job-1"));
    assert_eq!(got[0].get("bucket_config_id"), Some("7"));
    assert_eq!(got[0].get("object_key"), Some(""));
    assert_eq!(got[0].get("scan_enabled"), Some("True"));
    drop(got);

    // And it was acked (no pending entries remain).
    let client = raw_client(&url).await;
    let key = format!("{prefix}:{stream}");
    wait_until(Duration::from_secs(5), || {
        let client = client.clone();
        let key = key.clone();
        let group = format!("{prefix}:grp");
        async move { pending_count(&client, &key, &group).await == 0 }
    })
    .await;

    let _ = tx.send(true);
    let _ = run.await;
}

#[tokio::test]
#[ignore = "requires a live Valkey/Redis (SKAUSWATCH_TEST_REDIS_URL)"]
async fn failed_delivery_is_retried_then_acked() {
    let url = redis_url();
    let prefix = unique_prefix();
    let stream = "s3scan:tasks";
    let producer = StreamProducer::connect(&url, None, &prefix)
        .await
        .expect("producer");
    let consumer = StreamConsumer::connect(&url, None, &prefix)
        .await
        .expect("consumer");
    let cfg = test_config(&prefix, stream, 5);
    let handler = RecordingHandler::new(1, false); // fail once, then succeed

    consumer
        .ensure_group(stream, &cfg.group)
        .await
        .expect("group");
    producer
        .publish(stream, manager_enumerate_fields("job-retry", 3))
        .await
        .expect("publish");

    let (tx, rx) = watch::channel(false);
    let h = handler.clone();
    let run = tokio::spawn(async move { consumer.run(&cfg, h.as_ref(), rx).await });

    // Eventually the retry succeeds (recovered via XAUTOCLAIM) and is acked.
    let seen = handler.seen.clone();
    wait_until(Duration::from_secs(10), || {
        let seen = seen.clone();
        async move { seen.lock().await.len() == 1 }
    })
    .await;
    assert!(
        handler.attempts.load(Ordering::SeqCst) >= 2,
        "should have retried"
    );

    let client = raw_client(&url).await;
    let key = format!("{prefix}:{stream}");
    let group = cfg_group(&prefix);
    wait_until(Duration::from_secs(5), || {
        let client = client.clone();
        let key = key.clone();
        let group = group.clone();
        async move { pending_count(&client, &key, &group).await == 0 }
    })
    .await;

    let _ = tx.send(true);
    let _ = run.await;
}

#[tokio::test]
#[ignore = "requires a live Valkey/Redis (SKAUSWATCH_TEST_REDIS_URL)"]
async fn poison_entry_routed_to_dlq() {
    let url = redis_url();
    let prefix = unique_prefix();
    let stream = "s3scan:tasks";
    let producer = StreamProducer::connect(&url, None, &prefix)
        .await
        .expect("producer");
    let consumer = StreamConsumer::connect(&url, None, &prefix)
        .await
        .expect("consumer");
    let cfg = test_config(&prefix, stream, 2); // DLQ after 2 deliveries
    let handler = RecordingHandler::new(0, true); // always fails

    consumer
        .ensure_group(stream, &cfg.group)
        .await
        .expect("group");
    producer
        .publish(stream, manager_enumerate_fields("job-poison", 9))
        .await
        .expect("publish");

    let (tx, rx) = watch::channel(false);
    let h = handler.clone();
    let run = tokio::spawn(async move { consumer.run(&cfg, h.as_ref(), rx).await });

    let client = raw_client(&url).await;
    let dlq_key = format!("{prefix}:{stream}:dlq");
    let key = format!("{prefix}:{stream}");
    let group = cfg_group(&prefix);

    // The entry ends up in the DLQ and is drained from the main group's PEL.
    wait_until(Duration::from_secs(15), || {
        let client = client.clone();
        let dlq_key = dlq_key.clone();
        async move {
            let len: u64 = client.xlen(dlq_key).await.unwrap_or(0);
            len == 1
        }
    })
    .await;
    wait_until(Duration::from_secs(5), || {
        let client = client.clone();
        let key = key.clone();
        let group = group.clone();
        async move { pending_count(&client, &key, &group).await == 0 }
    })
    .await;

    // The DLQ copy carries the provenance metadata.
    let entries: fred::types::streams::XReadResponse<String, String, String, String> = client
        .xread_map(Some(1), None, format!("{prefix}:{stream}:dlq"), "0")
        .await
        .expect("xread dlq");
    let rows = entries.get(&dlq_key).expect("dlq rows");
    let (_id, fields) = &rows[0];
    assert_eq!(fields.get("job_id").map(String::as_str), Some("job-poison"));
    assert!(fields.contains_key("_dlq_original_id"));
    assert!(fields.contains_key("_dlq_delivery_count"));

    let _ = tx.send(true);
    let _ = run.await;
}

#[tokio::test]
#[ignore = "requires a live Valkey/Redis (SKAUSWATCH_TEST_REDIS_URL)"]
async fn xautoclaim_recovers_abandoned_entry() {
    let url = redis_url();
    let prefix = unique_prefix();
    let stream = "s3scan:tasks";
    let producer = StreamProducer::connect(&url, None, &prefix)
        .await
        .expect("producer");
    let consumer = StreamConsumer::connect(&url, None, &prefix)
        .await
        .expect("consumer");
    let cfg = test_config(&prefix, stream, 5);
    let group = cfg_group(&prefix);

    consumer
        .ensure_group(stream, &cfg.group)
        .await
        .expect("group");
    producer
        .publish(stream, manager_enumerate_fields("job-ghost", 4))
        .await
        .expect("publish");

    // A "crashed" consumer reads the entry into its PEL but never acks it.
    let ghost = raw_client(&url).await;
    let key = format!("{prefix}:{stream}");
    let _: fred::types::streams::XReadResponse<String, String, String, String> = ghost
        .xreadgroup_map(&group, "ghost", Some(10), None, false, key.clone(), ">")
        .await
        .expect("ghost read");
    assert_eq!(pending_count(&ghost, &key, &group).await, 1);

    // Our live consumer must reclaim (XAUTOCLAIM) and process the orphan.
    let handler = RecordingHandler::new(0, false);
    let (tx, rx) = watch::channel(false);
    let h = handler.clone();
    let run = tokio::spawn(async move { consumer.run(&cfg, h.as_ref(), rx).await });

    let seen = handler.seen.clone();
    wait_until(Duration::from_secs(10), || {
        let seen = seen.clone();
        async move { seen.lock().await.len() == 1 }
    })
    .await;
    assert_eq!(
        handler.seen.lock().await[0].get("job_id"),
        Some("job-ghost")
    );
    wait_until(Duration::from_secs(5), || {
        let ghost = ghost.clone();
        let key = key.clone();
        let group = group.clone();
        async move { pending_count(&ghost, &key, &group).await == 0 }
    })
    .await;

    let _ = tx.send(true);
    let _ = run.await;
}

fn cfg_group(prefix: &str) -> String {
    format!("{prefix}:grp")
}
