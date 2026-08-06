//! Consumer-group worker harness — the reusable half of the Celery
//! replacement, landing with the first worker port (s3scan) and reused by
//! scanner / worker-codescan. Wraps a fred client with the full
//! at-least-once delivery lifecycle a v1 Celery worker had: consumer-group
//! reads (`XREADGROUP`), per-message ack (`XACK`), stale-message recovery
//! (`XAUTOCLAIM`), bounded retries, a dead-letter queue after N failed
//! deliveries, and cooperative graceful shutdown.
//!
//! The producer side (`StreamProducer`) publishes the flat, redis-py-encoded
//! field maps the manager writes; this consumer delivers those same field
//! maps to a [`StreamHandler`] unchanged (fields are looked up by name, so the
//! wire order the producer preserves is irrelevant on the read path).

use std::collections::HashMap;

use fred::interfaces::{ClientLike, StreamsInterface};
use fred::types::streams::{XReadResponse, XReadValue};
use tokio::sync::watch;

use crate::{DEFAULT_MAXLEN, EntryFields, StreamError, prefixed_key, redis_url_with_password};

/// Error surfaced by a [`StreamHandler`]. `Ok(())` from a handler acks the
/// message (success **or** a permanent, non-retryable outcome the handler has
/// already recorded); `Err(_)` leaves the message pending so it is retried and
/// eventually dead-lettered.
pub type HandlerError = Box<dyn std::error::Error + Send + Sync>;

/// One delivered stream entry: the Redis entry id plus its flat field map.
/// Field access is by name — the harness never depends on field order.
#[derive(Debug, Clone)]
pub struct StreamEntry {
    /// Redis stream entry id (e.g. `1700000000000-0`).
    pub id: String,
    /// Flattened field map exactly as XADD stored it (all values are strings,
    /// matching redis-py's stringification on the producer side).
    pub fields: HashMap<String, String>,
}

impl StreamEntry {
    /// Borrows a field value by name, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

/// Business logic invoked for each delivered entry. Implementors must be
/// cheap to share across the consumer loop (`Send + Sync`). Return `Ok(())` to
/// ack; return `Err(_)` only for transient failures that should be retried.
#[async_trait::async_trait]
pub trait StreamHandler: Send + Sync {
    /// Processes a single delivered entry.
    async fn handle(&self, entry: &StreamEntry) -> Result<(), HandlerError>;
}

/// Tuning for one consumer loop, mirroring v1 `RedisStreamManager` consume
/// defaults (count 10, block 5000ms) plus the retry/DLQ knobs the v1 Celery
/// broker provided implicitly.
#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    /// Unprefixed stream name (e.g. [`crate::STREAM_S3_SCAN_TASKS`]).
    pub stream: String,
    /// Consumer group name (v1 `CONSUMER_GROUP`).
    pub group: String,
    /// Unique consumer name within the group (v1 `CONSUMER_NAME`).
    pub consumer: String,
    /// Max entries per `XREADGROUP` (v1 count=10).
    pub batch: u64,
    /// Block timeout in ms per read (v1 block=5000); bounds shutdown latency.
    pub block_ms: u64,
    /// Minimum idle time (ms) before a pending entry owned by another consumer
    /// is eligible for `XAUTOCLAIM` recovery.
    pub min_idle_ms: u64,
    /// Deliveries permitted before an entry is routed to the DLQ. A delivery
    /// count strictly greater than this sends the entry to `{stream}:dlq`.
    pub max_deliveries: u64,
}

impl ConsumerConfig {
    /// Builds a config with the v1-parity defaults (batch 10, block 5s, idle
    /// 60s, 5 deliveries) for `stream`/`group`/`consumer`.
    pub fn new(
        stream: impl Into<String>,
        group: impl Into<String>,
        consumer: impl Into<String>,
    ) -> Self {
        Self {
            stream: stream.into(),
            group: group.into(),
            consumer: consumer.into(),
            batch: 10,
            block_ms: 5_000,
            min_idle_ms: 60_000,
            max_deliveries: 5,
        }
    }
}

/// Consumer-group reader with ack/retry/DLQ/stale-recovery. Cheap to clone
/// (wraps a fred client handle); one instance can run multiple stream loops.
#[derive(Clone)]
pub struct StreamConsumer {
    client: fred::clients::Client,
    prefix: String,
}

impl std::fmt::Debug for StreamConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamConsumer")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl StreamConsumer {
    /// Connects to Valkey/Redis and waits for the first handshake, using the
    /// same password-injection and reconnect policy as [`crate::StreamProducer`].
    pub async fn connect(
        url: &str,
        password: Option<&str>,
        prefix: &str,
    ) -> Result<Self, StreamError> {
        let effective = redis_url_with_password(url, password);
        let config = fred::types::config::Config::from_url(&effective)?;
        let mut builder = fred::types::Builder::from_config(config);
        builder.set_policy(fred::types::config::ReconnectPolicy::new_exponential(
            0, 100, 30_000, 2,
        ));
        let client = builder.build()?;
        let _connect_task = client.init().await?;
        Ok(Self {
            client,
            prefix: prefix.to_owned(),
        })
    }

    /// Wraps an already-connected fred client (used by services that share one
    /// client between the producer and consumer, and by tests).
    pub fn from_client(client: fred::clients::Client, prefix: &str) -> Self {
        Self {
            client,
            prefix: prefix.to_owned(),
        }
    }

    /// Fully-prefixed stream key for an unprefixed stream name.
    pub fn key(&self, stream: &str) -> String {
        prefixed_key(&self.prefix, stream)
    }

    /// DLQ key for an unprefixed stream name: `{prefix}:{stream}:dlq`.
    pub fn dlq_key(&self, stream: &str) -> String {
        format!("{}:dlq", self.key(stream))
    }

    /// Creates the consumer group (idempotent). `MKSTREAM` creates the stream
    /// if the producer has not written to it yet; a `BUSYGROUP` reply (group
    /// already exists) is treated as success — v1 `_ensure_group` parity.
    pub async fn ensure_group(&self, stream: &str, group: &str) -> Result<(), StreamError> {
        let key = self.key(stream);
        let res: Result<(), fred::error::Error> =
            self.client.xgroup_create(key, group, "0", true).await;
        match res {
            Ok(()) => Ok(()),
            Err(e) if e.to_string().contains("BUSYGROUP") => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Acknowledges a single entry, removing it from the group's pending list.
    async fn ack(&self, stream: &str, group: &str, id: &str) -> Result<(), StreamError> {
        let _: i64 = self.client.xack(self.key(stream), group, id).await?;
        Ok(())
    }

    /// Runs the consume loop until `shutdown` flips to `true`. Each iteration
    /// first recovers stale pending entries (`XAUTOCLAIM`) then blocks for new
    /// entries (`XREADGROUP`); the block is bounded by `block_ms` so shutdown
    /// is observed promptly. Transport errors are logged and retried after the
    /// block interval rather than aborting the worker.
    pub async fn run<H: StreamHandler>(
        &self,
        cfg: &ConsumerConfig,
        handler: &H,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), StreamError> {
        self.ensure_group(&cfg.stream, &cfg.group).await?;
        tracing::info!(
            stream = %cfg.stream, group = %cfg.group, consumer = %cfg.consumer,
            "stream consumer started"
        );

        while !*shutdown.borrow() {
            if let Err(e) = self.recover_stale(cfg, handler).await {
                tracing::warn!(stream = %cfg.stream, error = %e, "stale recovery failed");
            }

            tokio::select! {
                _ = shutdown.changed() => break,
                res = self.read_new(cfg, handler) => {
                    if let Err(e) = res {
                        tracing::warn!(stream = %cfg.stream, error = %e, "read batch failed");
                        // Avoid a hot error loop when the broker is unhealthy.
                        tokio::time::sleep(std::time::Duration::from_millis(cfg.block_ms)).await;
                    }
                }
            }
        }

        tracing::info!(stream = %cfg.stream, consumer = %cfg.consumer, "stream consumer stopped");
        Ok(())
    }

    /// Reads and dispatches one batch of never-before-delivered entries.
    async fn read_new<H: StreamHandler>(
        &self,
        cfg: &ConsumerConfig,
        handler: &H,
    ) -> Result<(), StreamError> {
        let key = self.key(&cfg.stream);
        let resp: XReadResponse<String, String, String, String> = self
            .client
            .xreadgroup_map(
                &cfg.group,
                &cfg.consumer,
                Some(cfg.batch),
                Some(cfg.block_ms),
                false,
                key.clone(),
                ">",
            )
            .await?;

        let Some(entries) = resp.get(&key) else {
            return Ok(());
        };
        for (id, fields) in entries {
            self.dispatch(cfg, handler, id, fields.clone()).await?;
        }
        Ok(())
    }

    /// Reclaims entries idle longer than `min_idle_ms` from any consumer in the
    /// group and either dead-letters them (delivery count past the limit) or
    /// re-dispatches them to this consumer.
    async fn recover_stale<H: StreamHandler>(
        &self,
        cfg: &ConsumerConfig,
        handler: &H,
    ) -> Result<(), StreamError> {
        let key = self.key(&cfg.stream);
        // XAUTOCLAIM takes ownership of stale entries and returns their fields;
        // the trailing deleted-ids element (Redis 7+) is handled by fred.
        let (_cursor, claimed): (String, Vec<XReadValue<String, String, String>>) = self
            .client
            .xautoclaim_values(
                key.clone(),
                &cfg.group,
                &cfg.consumer,
                cfg.min_idle_ms,
                "0",
                Some(cfg.batch),
                false,
            )
            .await?;
        if claimed.is_empty() {
            return Ok(());
        }

        // XAUTOCLAIM does not report delivery counts; XPENDING (extended) does.
        let counts = self.pending_counts(cfg).await?;
        for (id, fields) in claimed {
            let deliveries = counts.get(&id).copied().unwrap_or(1);
            if deliveries > cfg.max_deliveries {
                tracing::warn!(
                    stream = %cfg.stream, id = %id, deliveries,
                    "entry exceeded max deliveries — routing to DLQ"
                );
                self.dead_letter(cfg, &id, &fields, deliveries).await?;
                self.ack(&cfg.stream, &cfg.group, &id).await?;
            } else {
                self.dispatch(cfg, handler, &id, fields).await?;
            }
        }
        Ok(())
    }

    /// Delivery-count map for the group's pending entries idle ≥ `min_idle_ms`.
    async fn pending_counts(
        &self,
        cfg: &ConsumerConfig,
    ) -> Result<HashMap<String, u64>, StreamError> {
        // Extended XPENDING: [[id, consumer, idle_ms, delivery_count], ...].
        let rows: Vec<(String, String, u64, u64)> = self
            .client
            .xpending(
                self.key(&cfg.stream),
                &cfg.group,
                (cfg.min_idle_ms, "-", "+", cfg.batch),
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|(id, _consumer, _idle, count)| (id, count))
            .collect())
    }

    /// Runs the handler for one entry and acks on success; a handler error
    /// leaves the entry pending for later `XAUTOCLAIM` recovery.
    async fn dispatch<H: StreamHandler>(
        &self,
        cfg: &ConsumerConfig,
        handler: &H,
        id: &str,
        fields: HashMap<String, String>,
    ) -> Result<(), StreamError> {
        let entry = StreamEntry {
            id: id.to_owned(),
            fields,
        };
        match handler.handle(&entry).await {
            Ok(()) => {
                self.ack(&cfg.stream, &cfg.group, id).await?;
                tracing::debug!(stream = %cfg.stream, id = %id, "entry acked");
            }
            Err(e) => {
                tracing::warn!(
                    stream = %cfg.stream, id = %id, error = %e,
                    "handler failed — entry left pending for retry"
                );
            }
        }
        Ok(())
    }

    /// Copies a poison entry to the DLQ stream with provenance metadata, then
    /// the caller acks the original so it stops being redelivered.
    async fn dead_letter(
        &self,
        cfg: &ConsumerConfig,
        id: &str,
        fields: &HashMap<String, String>,
        deliveries: u64,
    ) -> Result<(), StreamError> {
        let mut dlq: EntryFields = fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        dlq.push(("_dlq_original_id".to_owned(), id.to_owned()));
        dlq.push(("_dlq_source_stream".to_owned(), self.key(&cfg.stream)));
        dlq.push(("_dlq_delivery_count".to_owned(), deliveries.to_string()));
        let _: String = self
            .client
            .xadd(
                self.dlq_key(&cfg.stream),
                false,
                ("MAXLEN", "~", DEFAULT_MAXLEN),
                "*",
                dlq,
            )
            .await?;
        Ok(())
    }
}

/// Real-Valkey integration tests for the consumer-group harness — mirrors
/// this workspace's "do not mock the DB layer, test against a real Postgres"
/// convention (`docs/v2-port/testing-pattern.md`) applied to the Streams
/// broker: every test here talks to a real Valkey/Redis instance
/// (`REDIS_URL`, defaulting to `redis://127.0.0.1:6379/0` for local runs
/// outside the CI service-container network) rather than mocking `fred`.
/// Each test uses a UUID-suffixed stream name so parallel test threads never
/// collide on the same consumer group.
#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::Mutex as AsyncMutex;
    use uuid::Uuid;

    use super::*;
    use crate::StreamProducer;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_owned())
    }

    /// A bare, unshared fred client used only to inspect broker state
    /// directly (e.g. DLQ stream length) that `StreamConsumer`'s API
    /// deliberately doesn't expose.
    async fn raw_client(url: &str) -> fred::clients::Client {
        let config =
            fred::types::config::Config::from_url(url).unwrap_or_else(|e| panic!("config: {e}"));
        let client = fred::types::Builder::from_config(config)
            .build()
            .unwrap_or_else(|e| panic!("build: {e}"));
        client.init().await.unwrap_or_else(|e| panic!("init: {e}"));
        client
    }

    /// Records every delivered entry and returns a caller-controlled
    /// success/failure outcome — lets a single handler type stand in for
    /// both the happy path and the retry/DLQ paths across these tests.
    struct RecordingHandler {
        calls: Arc<AsyncMutex<Vec<StreamEntry>>>,
        fail: Arc<AtomicBool>,
    }

    impl RecordingHandler {
        fn new(fail: bool) -> Self {
            Self {
                calls: Arc::new(AsyncMutex::new(Vec::new())),
                fail: Arc::new(AtomicBool::new(fail)),
            }
        }
    }

    #[async_trait::async_trait]
    impl StreamHandler for RecordingHandler {
        async fn handle(&self, entry: &StreamEntry) -> Result<(), HandlerError> {
            self.calls.lock().await.push(entry.clone());
            if self.fail.load(Ordering::SeqCst) {
                Err("simulated handler failure".into())
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn ensure_group_is_idempotent_and_a_second_create_hits_busygroup() {
        let stream = format!("streams-test-{}", Uuid::new_v4());
        let prefix = "skauswatch-test".to_owned();
        // Exercises `from_client` (as opposed to `connect`, covered by the
        // other tests below) — both must build an equally usable consumer.
        let client = raw_client(&redis_url()).await;
        let consumer = StreamConsumer::from_client(client, &prefix);

        consumer
            .ensure_group(&stream, "group-a")
            .await
            .unwrap_or_else(|e| panic!("first ensure_group: {e}"));
        // Second call hits Valkey's BUSYGROUP reply for an already-existing
        // group — v1 `_ensure_group` parity requires this still return Ok.
        consumer
            .ensure_group(&stream, "group-a")
            .await
            .unwrap_or_else(|e| panic!("second ensure_group (BUSYGROUP): {e}"));
    }

    /// Documents a real gap found while writing this suite (2026-08-06), not
    /// the intended behavior: when `XREADGROUP` genuinely has nothing to
    /// deliver (block times out with zero new entries), Valkey/Redis replies
    /// with a bare nil. `fred`'s generic map decode only treats nil as an
    /// empty map when the crate's `default-nil-types` feature is enabled —
    /// this workspace's `fred = "=10.1.0"` dependency (`Cargo.toml`) does not
    /// enable it, so `read_new` currently surfaces this as a transport error
    /// instead of a clean `Ok(())`. In production this routes through
    /// `run()`'s `Err(e) => { warn!(...); sleep(block_ms) }` arm, so a worker
    /// never crashes, but every idle poll cycle logs a spurious warning and
    /// sleeps an extra `block_ms` — this is a real behavior gap, not a test
    /// bug, and out of scope for this test-coverage pass to fix (a
    /// `default-nil-types` feature flip is a workspace-wide `fred` behavior
    /// change, not a test-only tweak). Tracked as a follow-up rather than
    /// silently fixed or silently ignored.
    #[tokio::test]
    async fn read_new_currently_errors_when_no_new_entries_are_pending() {
        let stream = format!("streams-test-{}", Uuid::new_v4());
        let prefix = "skauswatch-test".to_owned();
        let consumer = StreamConsumer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        consumer
            .ensure_group(&stream, "empty-group")
            .await
            .unwrap_or_else(|e| panic!("ensure_group: {e}"));

        let mut cfg =
            ConsumerConfig::new(stream, "empty-group".to_owned(), "consumer-a".to_owned());
        cfg.block_ms = 50; // keep the XREADGROUP block short — nothing will arrive

        let handler = RecordingHandler::new(false);
        let result = consumer.read_new(&cfg, &handler).await;
        assert!(
            result.is_err(),
            "expected the known nil-decode gap (see doc comment); read_new returned {result:?} — \
             if this now passes, fred's default-nil-types behavior changed and this test (and its \
             doc comment) should be updated to assert Ok(()) instead"
        );
        assert!(handler.calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn run_dispatches_a_published_entry_acks_it_then_stops_on_shutdown() {
        let stream = format!("streams-test-{}", Uuid::new_v4());
        let prefix = "skauswatch-test".to_owned();
        let group = "run-group".to_owned();

        let producer = StreamProducer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("producer connect: {e}"));
        producer
            .publish(&stream, vec![("kind".to_owned(), "unit-test".to_owned())])
            .await
            .unwrap_or_else(|e| panic!("publish: {e}"));

        let consumer = StreamConsumer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("consumer connect: {e}"));
        let mut cfg = ConsumerConfig::new(stream, group, "consumer-a".to_owned());
        cfg.block_ms = 200;

        let handler = RecordingHandler::new(false);
        let calls = handler.calls.clone();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let run_consumer = consumer.clone();
        let run_cfg = cfg.clone();
        let join = tokio::spawn(async move { run_consumer.run(&run_cfg, &handler, rx).await });

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if !calls.lock().await.is_empty() {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("handler was never invoked within the timeout");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        tx.send(true)
            .unwrap_or_else(|e| panic!("shutdown send: {e}"));
        let run_result = tokio::time::timeout(std::time::Duration::from_secs(10), join)
            .await
            .unwrap_or_else(|_| panic!("consumer task did not stop after shutdown"))
            .unwrap_or_else(|e| panic!("consumer task panicked: {e}"));
        assert!(
            run_result.is_ok(),
            "run() must exit cleanly: {run_result:?}"
        );

        let recorded = calls.lock().await;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].get("kind"), Some("unit-test"));
        drop(recorded);

        let pending = consumer
            .pending_counts(&cfg)
            .await
            .unwrap_or_else(|e| panic!("pending_counts: {e}"));
        assert!(
            pending.is_empty(),
            "acked entry must not remain pending: {pending:?}"
        );
    }

    #[tokio::test]
    async fn recover_stale_redispatches_a_failed_entry_within_the_delivery_limit() {
        let stream = format!("streams-test-{}", Uuid::new_v4());
        let prefix = "skauswatch-test".to_owned();
        let group = "recover-group".to_owned();

        let producer = StreamProducer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("producer connect: {e}"));
        producer
            .publish(&stream, vec![("k".to_owned(), "v".to_owned())])
            .await
            .unwrap_or_else(|e| panic!("publish: {e}"));

        let consumer = StreamConsumer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("consumer connect: {e}"));
        consumer
            .ensure_group(&stream, &group)
            .await
            .unwrap_or_else(|e| panic!("ensure_group: {e}"));
        let mut cfg = ConsumerConfig::new(stream, group, "consumer-a".to_owned());
        cfg.block_ms = 100;
        cfg.min_idle_ms = 0; // reclaim immediately — no need to wait out a real idle window

        // First delivery: the handler fails, so the entry stays pending
        // (dispatch's Err branch — never acked).
        let failing = RecordingHandler::new(true);
        consumer
            .read_new(&cfg, &failing)
            .await
            .unwrap_or_else(|e| panic!("read_new: {e}"));
        assert_eq!(failing.calls.lock().await.len(), 1);

        // A second consumer in the same group reclaims the stale entry via
        // XAUTOCLAIM; this time the handler succeeds and it gets acked.
        let mut cfg2 = cfg.clone();
        cfg2.consumer = "consumer-b".to_owned();
        let succeeding = RecordingHandler::new(false);
        consumer
            .recover_stale(&cfg2, &succeeding)
            .await
            .unwrap_or_else(|e| panic!("recover_stale: {e}"));
        assert_eq!(
            succeeding.calls.lock().await.len(),
            1,
            "recover_stale must redispatch the stale entry to the new consumer"
        );

        let pending = consumer
            .pending_counts(&cfg)
            .await
            .unwrap_or_else(|e| panic!("pending_counts: {e}"));
        assert!(
            pending.is_empty(),
            "entry must be acked after a successful redispatch: {pending:?}"
        );
    }

    #[tokio::test]
    async fn recover_stale_dead_letters_an_entry_past_the_delivery_limit() {
        let stream = format!("streams-test-{}", Uuid::new_v4());
        let prefix = "skauswatch-test".to_owned();
        let group = "dlq-group".to_owned();

        let producer = StreamProducer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("producer connect: {e}"));
        producer
            .publish(&stream, vec![("k".to_owned(), "v".to_owned())])
            .await
            .unwrap_or_else(|e| panic!("publish: {e}"));

        let consumer = StreamConsumer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("consumer connect: {e}"));
        consumer
            .ensure_group(&stream, &group)
            .await
            .unwrap_or_else(|e| panic!("ensure_group: {e}"));
        let mut cfg = ConsumerConfig::new(stream.clone(), group, "consumer-a".to_owned());
        cfg.block_ms = 100;
        cfg.min_idle_ms = 0;
        cfg.max_deliveries = 0; // any single delivery already exceeds the limit

        let failing = RecordingHandler::new(true);
        consumer
            .read_new(&cfg, &failing)
            .await
            .unwrap_or_else(|e| panic!("read_new: {e}"));

        let never_called = RecordingHandler::new(false);
        consumer
            .recover_stale(&cfg, &never_called)
            .await
            .unwrap_or_else(|e| panic!("recover_stale: {e}"));
        assert!(
            never_called.calls.lock().await.is_empty(),
            "an over-limit entry must be dead-lettered, not redispatched to the handler"
        );

        let pending = consumer
            .pending_counts(&cfg)
            .await
            .unwrap_or_else(|e| panic!("pending_counts: {e}"));
        assert!(
            pending.is_empty(),
            "dead-lettered entry must be acked off the original PEL: {pending:?}"
        );

        let raw = raw_client(&redis_url()).await;
        let dlq_len: i64 = raw
            .xlen(consumer.dlq_key(&stream))
            .await
            .unwrap_or_else(|e| panic!("xlen: {e}"));
        assert_eq!(dlq_len, 1, "entry must land on the DLQ stream exactly once");
    }
}
