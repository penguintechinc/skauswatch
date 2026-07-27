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
