//! Ingest pipeline: the glue between log collectors (`crate::collectors`)
//! and the event store, restoring the producer side of the event pipeline
//! that `src/main.rs`'s original module docs tracked as a follow-up. Rust
//! port of the *behavioral core* of v1 `log_processor.py::process_event` +
//! `buffer_manager.py::BufferManager` — batching, backpressure, and
//! never-dropping critical events — reimplemented with idiomatic Tokio
//! primitives (a bounded `mpsc` channel is itself backpressure; a
//! `tokio::time::interval` is the flush timer) rather than a line-for-line
//! port of v1's `deque`/`asyncio.Lock`/Redis-persisted-critical-event
//! machinery. Deliberately narrower than v1, documented rather than silent:
//! no Redis-backed critical-event backup, no gzip batch compression, no
//! per-buffer-key partitioning (v1's `{source}:{event_type}:{severity}` key)
//! — a single bounded channel already gives FIFO ordering and backpressure
//! without that partitioning, and AI-triggered analysis
//! (`_handle_ai_analysis`) is out of scope per `src/main.rs`'s AI-integration
//! follow-up note.
//!
//! **Tenant provenance (closes the gap flagged in `crate::es`'s
//! `index_event` doc comment):** every event reaching [`IngestPipeline::ingest`]
//! must already carry a non-empty `tenant_id`, stamped by the calling
//! collector from `Config::tenancy` (server-side deployment config — see
//! `config.rs::TenancyConfig` doc comment for why that is the correct trust
//! boundary here, not anything derived from collected log content). An
//! event arriving with an empty tenant is dropped and logged as an error
//! rather than indexed — the same "empty tenant is unreachable, never
//! silently exposed" invariant `BaseEvent::tenant_id` documents.

use std::sync::Arc;
use std::time::Duration;

use penguin_licensing::LicenseClient;
use tokio::sync::{broadcast, mpsc};

use crate::es::EventStore;
use crate::models::{BaseEvent, Severity};
use crate::threat_intel::matcher::EventMatcher;

/// PostHog flag gating collector ingest — `skauswatch.log-ingest` in
/// `services/manager/src/flags.rs::MODULE_FLAGS` (already reserved there,
/// unused until this port). Checked dynamically per-event (not once at
/// collector startup) so operators can kill ingest live without a redeploy,
/// per `general.md`'s "graceful degradation" flag philosophy — collectors
/// keep reading their sources (harmless) but the pipeline no-ops.
pub const LOG_INGEST_FLAG: &str = "skauswatch.log-ingest";

/// Default channel capacity — generous enough that a short collector burst
/// doesn't immediately trip backpressure under normal load.
const DEFAULT_CHANNEL_CAPACITY: usize = 2048;
/// Default batch size before an immediate flush (v1 `batch_size` default 100).
const DEFAULT_BATCH_SIZE: usize = 100;
/// Default flush timer (v1 `flush_interval_seconds` default 60; shortened
/// here so a live event stream/store doesn't sit idle for a full minute
/// under light load — configurable via [`IngestConfig`] for tests).
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// Tunables for [`IngestPipeline::spawn`]. Exists mainly so tests can shrink
/// `flush_interval`/`batch_size` instead of waiting on production defaults.
#[derive(Debug, Clone, Copy)]
pub struct IngestConfig {
    /// Bounded channel capacity — the backpressure limit.
    pub channel_capacity: usize,
    /// Events per batch before an immediate flush.
    pub batch_size: usize,
    /// Maximum time a partial batch waits before being flushed anyway.
    pub flush_interval: Duration,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
        }
    }
}

/// Entry point collectors hold onto — cheap to clone (wraps an `mpsc::Sender`
/// internally), one instance shared across every spawned collector task.
pub struct IngestPipeline {
    tx: mpsc::Sender<BaseEvent>,
    license: Arc<LicenseClient>,
}

/// Shared handle type collectors receive.
pub type IngestHandle = Arc<IngestPipeline>;

impl IngestPipeline {
    /// Spawns the background batching/flush task and returns a handle
    /// collectors call [`IngestPipeline::ingest`] on. `store`/`matcher` are
    /// both optional so the pipeline still runs (accepting and broadcasting
    /// events on `event_bus`) even when the ES backend or the threat-intel
    /// engine is disabled/unreachable — same graceful-degradation policy as
    /// `state.rs::build_event_store`.
    pub fn spawn(
        store: Option<Arc<dyn EventStore>>,
        event_bus: broadcast::Sender<BaseEvent>,
        matcher: Option<Arc<dyn EventMatcher>>,
        license: Arc<LicenseClient>,
        cfg: IngestConfig,
    ) -> IngestHandle {
        let (tx, rx) = mpsc::channel(cfg.channel_capacity);
        tokio::spawn(flush_loop(rx, store, event_bus, matcher, cfg));
        Arc::new(Self { tx, license })
    }

    /// Accepts one collector-produced event. Never blocks indefinitely
    /// except for [`Severity::Critical`] events under backpressure — v1's
    /// `_should_drop_event` also special-cased "never drop critical events".
    /// Returns once the event has been (a) rejected [no tenant / flag off],
    /// (b) queued, or (c) dropped for backpressure — the actual index write
    /// happens later, asynchronously, in [`flush_loop`].
    pub async fn ingest(&self, event: BaseEvent) {
        if event.tenant_id.trim().is_empty() {
            tracing::error!(
                event_id = %event.id,
                "dropping collector event with no tenant_id stamped — see ingest.rs module docs"
            );
            metrics::counter!("monitor_events_dropped_total", "reason" => "no_tenant").increment(1);
            return;
        }
        if !self.license.flag_enabled(LOG_INGEST_FLAG).await {
            metrics::counter!("monitor_events_dropped_total", "reason" => "flag_disabled")
                .increment(1);
            return;
        }

        let critical = event.severity == Severity::Critical;
        match self.tx.try_send(event) {
            Ok(()) => {
                metrics::counter!("monitor_events_ingested_total").increment(1);
            }
            Err(mpsc::error::TrySendError::Full(event)) if critical => {
                // Never drop critical events (v1 `_should_drop_event`): block
                // until a slot frees up rather than discarding.
                metrics::counter!("monitor_events_backpressure_blocked_total").increment(1);
                if self.tx.send(event).await.is_err() {
                    tracing::error!("ingest channel closed while blocking on a critical event");
                }
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("dropping event: ingest buffer full (backpressure)");
                metrics::counter!("monitor_events_dropped_total", "reason" => "backpressure")
                    .increment(1);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("ingest channel closed — flush task must have exited");
            }
        }
    }
}

/// Background batcher/flusher: drains `rx` into batches of up to
/// `cfg.batch_size`, flushing early on that threshold or on `cfg
/// .flush_interval` elapsing, whichever comes first (`tokio::select!`
/// between the channel and an interval timer — the Tokio-idiomatic
/// equivalent of v1's separate `_flush_timer` task racing `add_event`'s
/// immediate-flush check). Exits (after a final flush) once every
/// [`IngestHandle`] has been dropped and the channel closes.
async fn flush_loop(
    mut rx: mpsc::Receiver<BaseEvent>,
    store: Option<Arc<dyn EventStore>>,
    event_bus: broadcast::Sender<BaseEvent>,
    matcher: Option<Arc<dyn EventMatcher>>,
    cfg: IngestConfig,
) {
    let mut batch: Vec<BaseEvent> = Vec::with_capacity(cfg.batch_size);
    let mut ticker = tokio::time::interval(cfg.flush_interval);
    // The first tick fires immediately; skip it so an empty pipeline doesn't
    // busy-loop flushing nothing every tick right after startup.
    ticker.tick().await;

    loop {
        tokio::select! {
            received = rx.recv() => {
                match received {
                    Some(event) => {
                        batch.push(event);
                        if batch.len() >= cfg.batch_size {
                            flush_batch(&mut batch, &store, &event_bus, &matcher).await;
                        }
                    }
                    None => {
                        flush_batch(&mut batch, &store, &event_bus, &matcher).await;
                        tracing::info!("ingest pipeline shut down (all handles dropped)");
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                flush_batch(&mut batch, &store, &event_bus, &matcher).await;
            }
        }
    }
}

/// Flushes `batch` (draining it): runs threat-intel matching (if enabled),
/// broadcasts every event on `event_bus` for `GET /events/stream`
/// subscribers, and — if a store is configured — indexes it. A store write
/// failure is logged and counted, never panics and never blocks the rest of
/// the batch (matches v1's per-event try/except in `_process_batch`).
async fn flush_batch(
    batch: &mut Vec<BaseEvent>,
    store: &Option<Arc<dyn EventStore>>,
    event_bus: &broadcast::Sender<BaseEvent>,
    matcher: &Option<Arc<dyn EventMatcher>>,
) {
    if batch.is_empty() {
        return;
    }
    for mut event in batch.drain(..) {
        if let Some(matcher) = matcher {
            let matches = matcher.match_event(&event).await;
            if !matches.is_empty() {
                metrics::counter!("monitor_threat_matches_total").increment(matches.len() as u64);
                event.threat_matches = matches
                    .into_iter()
                    .filter_map(|m| serde_json::to_value(m).ok())
                    .collect();
            }
        }

        // Broadcast before the (possibly slower) store write so live
        // subscribers see the event without waiting on ES/OpenSearch.
        let _ = event_bus.send(event.clone());

        if let Some(store) = store {
            match store.index_event(&event).await {
                Ok(()) => {
                    metrics::counter!("monitor_events_indexed_total").increment(1);
                }
                Err(e) => {
                    tracing::error!(event_id = %event.id, error = ?e, "failed to index event");
                    metrics::counter!("monitor_events_index_errors_total").increment(1);
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::error::ApiError;
    use crate::models::{EventSearchRequest, EventSearchResponse, EventType, LogSource};
    use std::sync::Mutex;

    /// In-memory [`EventStore`] test double — the trait's own doc comment
    /// invites exactly this ("routes can be tested against a fake without a
    /// live ES/Mongo instance").
    #[derive(Default)]
    struct FakeStore {
        indexed: Mutex<Vec<BaseEvent>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl EventStore for FakeStore {
        async fn search(
            &self,
            _req: &EventSearchRequest,
            _tenant: &str,
        ) -> Result<EventSearchResponse, ApiError> {
            unimplemented!("not exercised by ingest tests")
        }

        async fn get_by_id(&self, _id: &str, _tenant: &str) -> Result<Option<BaseEvent>, ApiError> {
            unimplemented!("not exercised by ingest tests")
        }

        async fn index_event(&self, event: &BaseEvent) -> Result<(), ApiError> {
            if self.fail {
                return Err(ApiError::internal("fake store", "forced failure"));
            }
            self.indexed.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    fn sample_event(tenant: &str, severity: Severity) -> BaseEvent {
        BaseEvent {
            id: uuid::Uuid::new_v4().to_string(),
            source: LogSource::System,
            event_type: EventType::Process,
            severity,
            message: "m".to_owned(),
            timestamp: chrono::Utc::now(),
            raw_data: serde_json::Value::Null,
            tags: vec![],
            host: String::new(),
            user: None,
            process: None,
            pid: None,
            enrichments: serde_json::Value::Null,
            threat_matches: vec![],
            ai_analysis: None,
            processed_data: serde_json::Value::Null,
            tenant_id: tenant.to_owned(),
            extra: Default::default(),
        }
    }

    fn enabled_license() -> Arc<LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    fn test_cfg() -> IngestConfig {
        IngestConfig {
            channel_capacity: 16,
            batch_size: 4,
            flush_interval: Duration::from_millis(50),
        }
    }

    #[tokio::test]
    async fn events_with_no_tenant_are_dropped_before_reaching_the_store() {
        let store = Arc::new(FakeStore::default());
        let store_dyn: Arc<dyn EventStore> = store.clone();
        let (bus, _rx) = broadcast::channel(16);
        let pipeline =
            IngestPipeline::spawn(Some(store_dyn), bus, None, enabled_license(), test_cfg());

        pipeline.ingest(sample_event("", Severity::Low)).await;
        // Drop the handle and give the flush loop a moment — nothing should
        // have been queued at all, so this settles almost immediately.
        drop(pipeline);
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(store.indexed.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn ingest_flushes_a_full_batch_immediately_and_indexes_every_event() {
        let store = Arc::new(FakeStore::default());
        let store_dyn: Arc<dyn EventStore> = store.clone();
        let (bus, mut rx) = broadcast::channel(16);
        let pipeline = IngestPipeline::spawn(
            Some(store_dyn),
            bus,
            None,
            enabled_license(),
            test_cfg(), // batch_size = 4
        );

        for _ in 0..4 {
            pipeline
                .ingest(sample_event("tenant-a", Severity::Info))
                .await;
        }

        // Batch-size flush is immediate — no need to wait for the timer.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if store.indexed.lock().unwrap().len() == 4 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected 4 indexed events within timeout"));

        // Every flushed event is also broadcast for live SSE subscribers.
        let broadcasted = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected a broadcast event"));
        assert!(broadcasted.is_ok());
    }

    #[tokio::test]
    async fn partial_batch_flushes_on_the_timer_not_just_on_size() {
        let store = Arc::new(FakeStore::default());
        let store_dyn: Arc<dyn EventStore> = store.clone();
        let (bus, _rx) = broadcast::channel(16);
        let pipeline = IngestPipeline::spawn(
            Some(store_dyn),
            bus,
            None,
            enabled_license(),
            test_cfg(), // flush_interval = 50ms, batch_size = 4
        );

        // Below the batch-size threshold — must wait on the timer.
        pipeline
            .ingest(sample_event("tenant-a", Severity::Info))
            .await;

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !store.indexed.lock().unwrap().is_empty() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected the timer to flush the partial batch"));
    }

    #[tokio::test]
    async fn critical_events_are_never_dropped_under_backpressure() {
        // Channel capacity 1 + no receiver draining fast enough forces the
        // full-channel path; a Critical event must still make it through via
        // the blocking send fallback rather than being dropped.
        let store = Arc::new(FakeStore::default());
        let store_dyn: Arc<dyn EventStore> = store.clone();
        let (bus, _rx) = broadcast::channel(16);
        let cfg = IngestConfig {
            channel_capacity: 1,
            batch_size: 100, // large enough that the timer, not size, drives flushing
            flush_interval: Duration::from_millis(30),
        };
        let pipeline = IngestPipeline::spawn(Some(store_dyn), bus, None, enabled_license(), cfg);

        // Fire several critical events concurrently — with capacity 1 this
        // guarantees at least one hits the "channel full" branch.
        let mut handles = Vec::new();
        for _ in 0..5 {
            let p = pipeline.clone();
            handles.push(tokio::spawn(async move {
                p.ingest(sample_event("tenant-a", Severity::Critical)).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if store.indexed.lock().unwrap().len() == 5 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected all 5 critical events to be indexed, none dropped"));
    }

    #[tokio::test]
    async fn a_store_index_failure_does_not_stop_the_rest_of_the_batch() {
        let failing = Arc::new(FakeStore {
            indexed: Mutex::new(vec![]),
            fail: true,
        });
        let store_dyn: Arc<dyn EventStore> = failing;
        let (bus, mut rx) = broadcast::channel(16);
        let pipeline =
            IngestPipeline::spawn(Some(store_dyn), bus, None, enabled_license(), test_cfg());

        for _ in 0..4 {
            pipeline
                .ingest(sample_event("tenant-a", Severity::Info))
                .await;
        }

        // The store always errors, but the batch is still drained and every
        // event still reaches the broadcast bus.
        for _ in 0..4 {
            let got = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
            assert!(got.is_ok(), "expected broadcast despite store failures");
        }
    }

    #[tokio::test]
    async fn ingest_without_a_store_still_broadcasts_live_events() {
        let (bus, mut rx) = broadcast::channel(16);
        let pipeline = IngestPipeline::spawn(None, bus, None, enabled_license(), test_cfg());

        pipeline
            .ingest(sample_event("tenant-a", Severity::Info))
            .await;

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        assert!(got.is_ok(), "expected the event to be broadcast live");
    }

    #[tokio::test]
    async fn ingest_is_dropped_when_the_log_ingest_flag_is_disabled() {
        let store = Arc::new(FakeStore::default());
        let store_dyn: Arc<dyn EventStore> = store.clone();
        let (bus, _rx) = broadcast::channel(16);
        let gated = skauswatch_testkit::license::gated_license("skauswatch");
        let pipeline = IngestPipeline::spawn(Some(store_dyn), bus, None, gated, test_cfg());

        pipeline
            .ingest(sample_event("tenant-a", Severity::Critical))
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(store.indexed.lock().unwrap().is_empty());
    }
}
