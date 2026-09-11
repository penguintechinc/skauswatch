//! Production [`EventBuffer`]: NATS JetStream, server-side deduped via a
//! `Nats-Msg-Id` header. See the module-level durability contract in
//! [`super`] — `push` never returns before the `PublishAck` resolves, and
//! never wraps the publish in `tokio::time::timeout()` (a timed-out
//! client can still have a durably-written message sitting on the
//! broker; racing a retry on top of that would duplicate it).

use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
use opentelemetry::propagation::{Extractor, Injector};
use tokio::sync::OnceCell;

use super::{AckHandle, AckHandleInner, BufferError, DeliveredEvent, EventBuffer, NormalizedEvent};

/// Header carrying the server-validated tenant, so `consume` can rebuild
/// a [`NormalizedEvent`] without trusting anything read back off the wire
/// payload — the tenant travels alongside the payload the same way it was
/// stamped by the handler, never inside it.
const TENANT_HEADER: &str = "Skauswatch-Tenant";

/// How long a single `fetch` pull request waits for at least one message
/// before returning empty-handed. Keeps the writer loop responsive
/// without hot-looping the pull request when the stream is idle.
const FETCH_EXPIRES: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------
// Trace context propagation (`critical-rules.md` Observability:
// "propagate trace context across every service boundary ... queue
// hops"). Bridges `async_nats::HeaderMap` to OpenTelemetry's
// `Injector`/`Extractor` traits so the active span's W3C `traceparent`
// (+ `tracestate`, if any) travels alongside the existing `Nats-Msg-Id`/
// `Skauswatch-Tenant` headers. Both directions are infallible by the
// propagator API's own design (`Injector::set`/`Extractor::get` return no
// `Result`) — a missing/malformed header can never fail a `push` or
// `consume`, only degrade to "no parent linkage".
// ---------------------------------------------------------------------

struct HeaderInjector<'a>(&'a mut async_nats::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key, value.as_str());
    }
}

struct HeaderExtractor<'a>(&'a async_nats::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(async_nats::HeaderValue::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.iter().map(|(name, _)| name.as_ref()).collect()
    }
}

/// Injects the currently active `tracing` span's OpenTelemetry context
/// into `headers` as a W3C `traceparent` (+ `tracestate`) header pair —
/// called from [`JetStreamBuffer::push`]. A silent no-op when no
/// OTel-bridged span is active (e.g. OTLP export disabled — see
/// `crate::otel::init`) or the global propagator has nothing to inject;
/// never panics, never errors.
fn inject_trace_context(headers: &mut async_nats::HeaderMap) {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    let cx = tracing::Span::current().context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(headers));
    });
}

/// Extracts a W3C `traceparent`/`tracestate` pair from `headers` (the
/// inverse of [`inject_trace_context`]) into an OpenTelemetry
/// [`opentelemetry::Context`] — called from [`JetStreamBuffer::consume`].
/// Returns an empty (non-remote) context when `headers` carries no valid
/// `traceparent`, never an error — a malformed/absent header degrades to
/// "no parent linkage" rather than failing the consume.
pub(super) fn extract_trace_context(headers: &async_nats::HeaderMap) -> opentelemetry::Context {
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(headers))
    })
}

/// The seam [`JetStreamBuffer::push`] calls through. The only production
/// implementor is `async_nats::jetstream::Context` below — an ordinary
/// two-await forward to the SDK. Existing as a trait (rather than calling
/// `Context::publish_with_headers` inline) lets the durability-critical
/// "does not return before the ack resolves" behavior (both awaits
/// mandatory, never `tokio::time::timeout()`-wrapped) be proven against a
/// fake broker in `push_awaits_publish_ack_before_returning`, since
/// `async_nats::jetstream::context::PublishAckFuture` has no public
/// constructor and can't otherwise be faked from outside the crate.
#[async_trait::async_trait]
trait PublishAcker: Send + Sync {
    async fn publish_and_ack(
        &self,
        subject: String,
        headers: async_nats::HeaderMap,
        payload: Bytes,
    ) -> Result<(), BufferError>;
}

#[async_trait::async_trait]
impl PublishAcker for async_nats::jetstream::Context {
    async fn publish_and_ack(
        &self,
        subject: String,
        headers: async_nats::HeaderMap,
        payload: Bytes,
    ) -> Result<(), BufferError> {
        // BOTH awaits are mandatory (Global Constraint #3). The first
        // resolves once the message has been handed to the connection;
        // the second — the `PublishAckFuture` it returns — resolves only
        // once JetStream has durably stored the message and replied with
        // a `PublishAck`. Dropping the second future without awaiting it
        // would make this a fire-and-forget publish. Neither await is
        // wrapped in `tokio::time::timeout()` (Global Constraint #5).
        self.publish_with_headers(subject, headers, payload)
            .await
            .map_err(|e| BufferError::Transport(e.to_string()))?
            .await
            .map_err(|e| BufferError::Transport(e.to_string()))?;
        Ok(())
    }
}

/// NATS JetStream-backed [`EventBuffer`] — the production implementation.
/// `subject_prefix` is combined with the event's tenant to form the
/// publish subject (`{subject_prefix}.{tenant}`), so the stream stays
/// filterable per tenant even though today a single wildcard durable
/// consumer drains all tenants.
///
/// `push` is routed through `acker` (the [`PublishAcker`] seam) rather
/// than a concrete `Context` field directly, so tests can exercise the
/// real `push()` method end to end (subject/header construction, body
/// encoding, and the ack-blocking behavior) against a fake broker —
/// see `with_acker` and the `push_*` tests below. `context` backs
/// `consume`'s pull-consumer binding only; it is `None` for buffers built
/// via `with_acker`, which never call `consume`/`ack`/`nack` in tests
/// (that path needs a live broker — deferred to Task 1.5).
pub struct JetStreamBuffer {
    acker: Box<dyn PublishAcker>,
    subject_prefix: String,
    context: Option<async_nats::jetstream::Context>,
    consumer: OnceCell<async_nats::jetstream::consumer::PullConsumer>,
}

impl JetStreamBuffer {
    /// Builds a buffer publishing under `{subject_prefix}.{tenant}`.
    /// Performs no I/O — the backing stream/durable consumer are created
    /// lazily on first [`EventBuffer::consume`] call, so `new()` can
    /// never fail on broker connectivity.
    pub fn new(
        client: async_nats::jetstream::Context,
        subject_prefix: &str,
    ) -> Result<Self, BufferError> {
        validate_subject_prefix(subject_prefix)?;
        Ok(Self {
            acker: Box::new(client.clone()),
            subject_prefix: subject_prefix.to_owned(),
            context: Some(client),
            consumer: OnceCell::new(),
        })
    }

    /// Test-only constructor: builds a buffer whose `push` is routed
    /// through `acker` (a fake) instead of a real JetStream `Context` —
    /// lets `push_awaits_publish_ack_before_returning` and
    /// `push_sets_nats_msg_id_header_deterministically` drive the real
    /// `EventBuffer::push` implementation without a live NATS broker.
    /// `consume`/`ack`/`nack` on a buffer built this way always fail
    /// (`context` is `None`) — those paths need a live/dockerized broker
    /// and are exercised in Task 1.5 instead.
    #[cfg(test)]
    fn with_acker(acker: impl PublishAcker + 'static, subject_prefix: &str) -> Self {
        Self {
            acker: Box::new(acker),
            subject_prefix: subject_prefix.to_owned(),
            context: None,
            consumer: OnceCell::new(),
        }
    }

    /// Stream name derived from `subject_prefix` — JetStream stream names
    /// may not contain `.`, so dots become underscores.
    fn stream_name(&self) -> String {
        self.subject_prefix.replace('.', "_")
    }

    /// This buffer's backing JetStream stream config — a single wildcard
    /// subject (`{subject_prefix}.>`) capturing every tenant's traffic
    /// under this prefix. Shared by [`Self::consumer`] and
    /// [`Self::ensure_stream`] so both create (or idempotently fetch) the
    /// exact same stream definition.
    fn stream_config(&self) -> async_nats::jetstream::stream::Config {
        async_nats::jetstream::stream::Config {
            name: self.stream_name(),
            subjects: vec![format!("{}.>", self.subject_prefix)],
            ..Default::default()
        }
    }

    /// Explicitly creates (idempotently — safe to call from multiple
    /// processes/replicas concurrently) this buffer's backing JetStream
    /// stream, without needing to bind a pull consumer.
    ///
    /// [`Self::consumer`] already creates the stream as a side effect of
    /// lazily binding its consumer on first [`EventBuffer::consume`] call,
    /// which is sufficient for the *main* ingest buffer (the writer's own
    /// `run_loop` calls `consume()` continuously, so the stream exists
    /// before any producer's first `push`). A buffer that is only ever
    /// `push`ed to and never `consume`d — exactly the writer's
    /// dead-letter sink, see `crate::writer::build_dlq_buffer` — never
    /// takes that path, so its stream would otherwise never exist and
    /// every `push` would fail with JetStream's "no stream found for
    /// given subject". Callers of a push-only buffer must call this once
    /// after construction, before the first `push`.
    ///
    /// # Errors
    /// Returns an error if this buffer has no bound JetStream context (a
    /// test-only instance built via `with_acker`), or the stream cannot
    /// be created/fetched.
    pub async fn ensure_stream(&self) -> Result<(), BufferError> {
        let context = self.context.as_ref().ok_or_else(|| {
            BufferError::Transport(
                "JetStreamBuffer has no bound JetStream context (test-only instance built via \
                 with_acker) — ensure_stream requires a real broker connection"
                    .to_owned(),
            )
        })?;
        context
            .get_or_create_stream(self.stream_config())
            .await
            .map_err(|e| BufferError::Transport(e.to_string()))?;
        Ok(())
    }

    /// Lazily binds (creating on first use) the durable, explicit-ack
    /// pull consumer every `consume()` call fetches from.
    async fn consumer(
        &self,
    ) -> Result<&async_nats::jetstream::consumer::PullConsumer, BufferError> {
        let context = self.context.as_ref().ok_or_else(|| {
            BufferError::Transport(
                "JetStreamBuffer has no bound JetStream context (test-only instance built via \
                 with_acker) — consume/ack/nack require a real broker connection"
                    .to_owned(),
            )
        })?;
        self.consumer
            .get_or_try_init(|| async {
                let stream_name = self.stream_name();
                let stream = context
                    .get_or_create_stream(self.stream_config())
                    .await
                    .map_err(|e| BufferError::Transport(e.to_string()))?;
                let durable_name = format!("{stream_name}-consumer");
                stream
                    .get_or_create_consumer(
                        &durable_name,
                        async_nats::jetstream::consumer::pull::Config {
                            durable_name: Some(durable_name.clone()),
                            ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|e| BufferError::Transport(e.to_string()))
            })
            .await
    }
}

#[async_trait::async_trait]
impl EventBuffer for JetStreamBuffer {
    #[tracing::instrument(
        name = "buffer_push",
        skip(self, event),
        fields(tenant = %event.tenant.as_str())
    )]
    async fn push(&self, event: NormalizedEvent) -> Result<(), BufferError> {
        let subject = format!("{}.{}", self.subject_prefix, event.tenant.as_str());
        let mut headers = async_nats::HeaderMap::new();
        // Server-side dedup (Global Constraint #4): a redelivered/retried
        // publish of the same event becomes a broker-side no-op instead
        // of a duplicate document.
        headers.insert("Nats-Msg-Id", event.dedup_key.as_str());
        headers.insert(TENANT_HEADER, event.tenant.as_str());
        inject_trace_context(&mut headers);
        let mut body = String::new();
        event.doc.write_compact(&mut body);
        self.acker
            .publish_and_ack(subject, headers, Bytes::from(body.into_bytes()))
            .await
    }

    #[tracing::instrument(name = "buffer_consume", skip(self), fields(batch_size))]
    async fn consume(&self, batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError> {
        let consumer = self.consumer().await?;
        let mut messages = consumer
            .fetch()
            .max_messages(batch_size)
            .expires(FETCH_EXPIRES)
            .messages()
            .await
            .map_err(|e| BufferError::Transport(e.to_string()))?;

        let mut delivered = Vec::with_capacity(batch_size);
        while let Some(msg) = messages.next().await {
            let msg = msg.map_err(|e| BufferError::Transport(e.to_string()))?;
            let event = normalized_event_from_message(&msg)?;
            // Propagate the producer's trace context across the queue hop
            // (see `extract_trace_context`'s doc comment) -- infallible,
            // `None` only when the message genuinely carries no headers.
            let trace_context = msg.headers.as_ref().map(extract_trace_context);
            delivered.push(DeliveredEvent {
                event,
                handle: AckHandle(AckHandleInner::JetStream(Box::new(msg))),
                trace_context,
            });
        }
        // Proxy for "current buffer depth" (Spec §11a
        // `svc_ingest_receiver_queue_depth`): the size of the batch this
        // call just pulled off the stream. A literal server-side stream
        // byte/message count (`Stream::info()`) would need an extra
        // JetStream round trip on every `consume()` call -- this is
        // real, already-available data (no added I/O) that still tracks
        // ingest backlog/throughput for an operator watching the gauge,
        // documented here rather than silently approximated.
        metrics::gauge!(crate::otel::metric_names::RECEIVER_QUEUE_DEPTH)
            .set(delivered.len() as f64);
        Ok(delivered)
    }

    #[tracing::instrument(name = "buffer_ack", skip(self, handle))]
    async fn ack(&self, handle: AckHandle) -> Result<(), BufferError> {
        match handle.0 {
            AckHandleInner::JetStream(msg) => msg
                .ack()
                .await
                .map_err(|e| BufferError::Transport(e.to_string())),
            AckHandleInner::InMemory(_) => Err(BufferError::Transport(
                "in-memory ack handle used against JetStreamBuffer".to_owned(),
            )),
        }
    }

    #[tracing::instrument(name = "buffer_nack", skip(self, handle))]
    async fn nack(&self, handle: AckHandle) -> Result<(), BufferError> {
        match handle.0 {
            AckHandleInner::JetStream(msg) => msg
                .ack_with(async_nats::jetstream::AckKind::Nak(None))
                .await
                .map_err(|e| BufferError::Transport(e.to_string())),
            AckHandleInner::InMemory(_) => Err(BufferError::Transport(
                "in-memory ack handle used against JetStreamBuffer".to_owned(),
            )),
        }
    }
}

/// Validates a `subject_prefix` before it is ever used to build a NATS
/// subject or stream name — a pure, I/O-free check so `JetStreamBuffer::
/// new` can never fail on broker connectivity.
fn validate_subject_prefix(subject_prefix: &str) -> Result<(), BufferError> {
    if subject_prefix.trim().is_empty() {
        return Err(BufferError::Transport(
            "subject_prefix must not be empty".to_owned(),
        ));
    }
    Ok(())
}

/// Rebuilds a [`NormalizedEvent`] from a delivered message's headers and
/// payload — the inverse of `push`'s header + `write_compact` body
/// encoding. Takes the core `async_nats::Message` (all fields public,
/// constructable without a live broker) rather than the JetStream wrapper
/// so this decode step is independently testable; a
/// `&async_nats::jetstream::Message` deref-coerces to this at the
/// `consume()` call site.
fn normalized_event_from_message(
    msg: &async_nats::Message,
) -> Result<NormalizedEvent, BufferError> {
    let headers = msg
        .headers
        .as_ref()
        .ok_or_else(|| BufferError::Serialize("delivered message has no headers".to_owned()))?;
    let dedup_key = headers
        .get("Nats-Msg-Id")
        .map(std::string::ToString::to_string)
        .ok_or_else(|| {
            BufferError::Serialize("delivered message missing Nats-Msg-Id".to_owned())
        })?;
    let tenant = headers
        .get(TENANT_HEADER)
        .map(std::string::ToString::to_string)
        .ok_or_else(|| {
            BufferError::Serialize(format!("delivered message missing {TENANT_HEADER}"))
        })?;
    let doc =
        serde_json::from_slice(&msg.payload).map_err(|e| BufferError::Serialize(e.to_string()))?;
    Ok(NormalizedEvent {
        tenant: skauswatch_auth::Tenant(tenant),
        doc,
        dedup_key,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use opentelemetry::trace::{TraceContextExt as _, TracerProvider as _};
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    /// A fake [`PublishAcker`] that records every `(subject, headers,
    /// payload)` it's called with (so tests can inspect exactly what the
    /// REAL `JetStreamBuffer::push` sent) and can optionally delay its ack
    /// resolution (so tests can prove `push` genuinely waits for it,
    /// rather than spawning it in the background and returning early —
    /// the fire-and-forget bug Global Constraint #3 forbids). Cloning
    /// shares the same underlying state, so a test can hand one clone to
    /// `JetStreamBuffer::with_acker` and keep another to inspect.
    #[derive(Clone)]
    struct FakeAcker {
        ack_delay: Duration,
        ack_completed: Arc<AtomicBool>,
        calls: Arc<Mutex<Vec<(String, async_nats::HeaderMap, Bytes)>>>,
    }

    impl FakeAcker {
        fn new(ack_delay: Duration) -> Self {
            Self {
                ack_delay,
                ack_completed: Arc::new(AtomicBool::new(false)),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Headers from the most recent `publish_and_ack` call.
        fn last_headers(&self) -> async_nats::HeaderMap {
            self.calls
                .lock()
                .unwrap()
                .last()
                .expect("publish_and_ack was never called")
                .1
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl PublishAcker for FakeAcker {
        async fn publish_and_ack(
            &self,
            subject: String,
            headers: async_nats::HeaderMap,
            payload: Bytes,
        ) -> Result<(), BufferError> {
            self.calls.lock().unwrap().push((subject, headers, payload));
            tokio::time::sleep(self.ack_delay).await;
            self.ack_completed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn sample_event(dedup_key: &str) -> NormalizedEvent {
        NormalizedEvent {
            tenant: skauswatch_auth::Tenant("tenant-a".to_owned()),
            doc: skauswatch_ocsf::JsonVal::Obj(vec![(
                "message".to_owned(),
                skauswatch_ocsf::JsonVal::Str("hello".to_owned()),
            )]),
            dedup_key: dedup_key.to_owned(),
        }
    }

    /// Regression test for Spec §14b's "PublishAck synchronous blocking"
    /// durability test (Global Constraint #3): the REAL
    /// `JetStreamBuffer::push` (not the fake acker directly) must not
    /// return until the publish ack future has actually resolved. Fails
    /// if `push` were ever changed to `tokio::spawn` the ack await and
    /// return early, or to drop the second future without awaiting it.
    #[tokio::test]
    async fn push_awaits_publish_ack_before_returning() {
        let acker = FakeAcker::new(Duration::from_millis(50));
        let ack_completed = acker.ack_completed.clone();
        let buffer = JetStreamBuffer::with_acker(acker, "logs");

        let result = buffer.push(sample_event("dedup-key-a")).await;

        assert!(result.is_ok());
        assert!(
            ack_completed.load(Ordering::SeqCst),
            "JetStreamBuffer::push returned before the delayed ack resolved — fire-and-forget regression"
        );
    }

    /// Same content (dedup key) twice must yield an identical
    /// `Nats-Msg-Id`; different content must yield a different one —
    /// Global Constraint #4's server-side dedup only works if the header
    /// is a deterministic function of the event. Drives the REAL `push`
    /// and inspects what it actually sent via the recording fake, rather
    /// than re-implementing the header-derivation logic in the test.
    #[tokio::test]
    async fn push_sets_nats_msg_id_header_deterministically() {
        let acker = FakeAcker::new(Duration::from_millis(0));
        let buffer = JetStreamBuffer::with_acker(acker.clone(), "logs");

        buffer.push(sample_event("dedup-key-a")).await.unwrap();
        let msg_id_a1 = acker.last_headers().get("Nats-Msg-Id").unwrap().to_string();

        buffer.push(sample_event("dedup-key-a")).await.unwrap();
        let msg_id_a2 = acker.last_headers().get("Nats-Msg-Id").unwrap().to_string();
        assert_eq!(
            msg_id_a1, msg_id_a2,
            "same dedup_key must yield the same Nats-Msg-Id"
        );

        buffer.push(sample_event("dedup-key-b")).await.unwrap();
        let msg_id_b = acker.last_headers().get("Nats-Msg-Id").unwrap().to_string();
        assert_ne!(
            msg_id_a1, msg_id_b,
            "different dedup_key must yield a different Nats-Msg-Id"
        );
    }

    /// Installs a real (in-memory-exported) OTel tracer as the process's
    /// tracing subscriber for the duration of the test, via
    /// `tracing::subscriber::set_default` (thread-scoped, not the global
    /// default `tracing_subscriber::registry().init()` uses elsewhere in
    /// this crate -- safe to call from more than one test without
    /// conflicting). Returns the guard the caller must keep alive.
    fn install_test_otel_subscriber() -> tracing::subscriber::DefaultGuard {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let exporter =
            opentelemetry_sdk::trace::in_memory_exporter::InMemorySpanExporter::default();
        let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")));
        tracing::subscriber::set_default(subscriber)
    }

    /// Spec fix-round finding: `push` must inject the active span's W3C
    /// trace context as a `traceparent` header alongside the existing
    /// `Nats-Msg-Id`/`Skauswatch-Tenant` headers (`critical-rules.md`
    /// Observability: propagate trace context across every service
    /// boundary, including queue hops). Drives the REAL `push` (via
    /// `#[tracing::instrument]`'s own `buffer_push` span, not a
    /// hand-rolled injection) and asserts the resulting header is present
    /// and W3C-shaped (`{version}-{trace-id:32hex}-{span-id:16hex}-{flags}`).
    #[tokio::test]
    async fn push_injects_well_formed_traceparent_header_when_span_is_active() {
        let _guard = install_test_otel_subscriber();

        let acker = FakeAcker::new(Duration::ZERO);
        let buffer = JetStreamBuffer::with_acker(acker.clone(), "logs");
        buffer.push(sample_event("dedup-key-trace")).await.unwrap();

        let headers = acker.last_headers();
        let traceparent = headers
            .get("traceparent")
            .expect("push must inject a traceparent header when a span is active")
            .to_string();
        let parts: Vec<&str> = traceparent.split('-').collect();
        assert_eq!(
            parts.len(),
            4,
            "traceparent must be 4 dash-separated fields (version-traceid-spanid-flags): \
             {traceparent:?}"
        );
        assert_eq!(parts[0].len(), 2, "version field must be 2 hex chars");
        assert_eq!(parts[1].len(), 32, "trace-id field must be 32 hex chars");
        assert_eq!(parts[2].len(), 16, "span-id field must be 16 hex chars");
        assert_eq!(parts[3].len(), 2, "flags field must be 2 hex chars");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()) && parts[1] != "0".repeat(32),
            "trace-id must be non-zero hex: {traceparent:?}"
        );
    }

    /// Spec fix-round finding: `consume` must extract a delivered
    /// message's `traceparent` header back into an OpenTelemetry
    /// `Context`, and that context must be usable to parent a writer-side
    /// span -- the exact mechanism `writer::process_batch` uses to link
    /// its `writer_consume_and_bulk_write` span to the producer's trace
    /// across the NATS queue hop. Round-trips a known, fabricated
    /// `SpanContext` (never a live broker -- `extract_trace_context` is a
    /// pure function of a `HeaderMap`) through inject -> extract -> parent
    /// a fresh span, and asserts the trace_id survives every step.
    #[test]
    fn extract_trace_context_round_trips_and_can_parent_a_writer_span() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let known_trace_id =
            opentelemetry::trace::TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736")
                .expect("valid fixture trace id");
        let known_span_id = opentelemetry::trace::SpanId::from_hex("00f067aa0ba902b7")
            .expect("valid fixture span id");
        let span_context = opentelemetry::trace::SpanContext::new(
            known_trace_id,
            known_span_id,
            opentelemetry::trace::TraceFlags::SAMPLED,
            true, // remote -- W3C propagation always yields a remote span context
            opentelemetry::trace::TraceState::default(),
        );
        let known_cx = opentelemetry::Context::new().with_remote_span_context(span_context);

        // Inject the known context (mirrors `push`'s own
        // `inject_trace_context`, driven directly against a known Context
        // rather than a live span).
        let mut headers = async_nats::HeaderMap::new();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&known_cx, &mut HeaderInjector(&mut headers));
        });

        // Extract it back -- the exact function `consume()` calls.
        let extracted_cx = extract_trace_context(&headers);
        let extracted_trace_id = opentelemetry::trace::TraceContextExt::span(&extracted_cx)
            .span_context()
            .trace_id();
        assert_eq!(
            extracted_trace_id, known_trace_id,
            "round-tripped context must carry the same trace_id"
        );

        // Parent a fresh tracing span from the extracted context -- the
        // same `OpenTelemetrySpanExt::set_parent` call
        // `writer::process_batch` makes for its `writer_consume_and_bulk_write`
        // span -- and confirm the RESULTING span reports the identical
        // trace_id, proving the receiver's trace genuinely links to the
        // writer-side span rather than just the raw `Context` value
        // round-tripping in isolation.
        let _guard = install_test_otel_subscriber();
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        let span = tracing::info_span!("writer_consume_and_bulk_write_test");
        span.set_parent(extracted_cx)
            .expect("set_parent must succeed on a freshly created span");
        let span_trace_id = opentelemetry::trace::TraceContextExt::span(&span.context())
            .span_context()
            .trace_id();
        assert_eq!(
            span_trace_id, known_trace_id,
            "the writer span's parent trace_id must match the injected context's trace_id"
        );
    }

    /// `JetStreamBuffer::new` performs no I/O and rejects an obviously
    /// invalid (empty/whitespace-only) subject prefix synchronously,
    /// before it could ever be used to build a NATS subject.
    #[test]
    fn new_rejects_empty_subject_prefix() {
        assert!(matches!(
            validate_subject_prefix("   "),
            Err(BufferError::Transport(_))
        ));
        assert!(validate_subject_prefix("svc-ingest.logs").is_ok());
    }

    /// Pure, I/O-free: JetStream stream names may not contain `.`, so
    /// `stream_name` derives one from `subject_prefix` by substitution.
    #[test]
    fn stream_name_replaces_dots_with_underscores() {
        let buffer = JetStreamBuffer::with_acker(FakeAcker::new(Duration::ZERO), "svc-ingest.logs");
        assert_eq!(buffer.stream_name(), "svc-ingest_logs");
    }

    /// `ack`/`nack` reject a handle minted by the *other* `EventBuffer`
    /// implementation cleanly — no I/O, so this doesn't need a broker
    /// (unlike the `AckHandleInner::JetStream` arm, which does and is
    /// deferred to Task 1.5).
    #[tokio::test]
    async fn ack_rejects_inmemory_handle() {
        let buffer = JetStreamBuffer::with_acker(FakeAcker::new(Duration::ZERO), "logs");
        let result = buffer.ack(AckHandle(AckHandleInner::InMemory(0))).await;
        assert!(matches!(result, Err(BufferError::Transport(_))));
    }

    /// See `ack_rejects_inmemory_handle` — same mismatch guard on `nack`.
    #[tokio::test]
    async fn nack_rejects_inmemory_handle() {
        let buffer = JetStreamBuffer::with_acker(FakeAcker::new(Duration::ZERO), "logs");
        let result = buffer.nack(AckHandle(AckHandleInner::InMemory(0))).await;
        assert!(matches!(result, Err(BufferError::Transport(_))));
    }

    /// A buffer built via `with_acker` (test-only, no bound broker
    /// context) must fail `consume` cleanly rather than panicking —
    /// `consume`/`ack`/`nack` against a real broker are covered in Task
    /// 1.5, not here.
    #[tokio::test]
    async fn consume_without_bound_context_errors_cleanly() {
        let buffer = JetStreamBuffer::with_acker(FakeAcker::new(Duration::ZERO), "logs");
        let result = buffer.consume(10).await;
        assert!(matches!(result, Err(BufferError::Transport(_))));
    }

    /// Same mismatch guard as `consume_without_bound_context_errors_cleanly`,
    /// for `ensure_stream` — a buffer built via `with_acker` has no bound
    /// broker context and must fail cleanly rather than panicking.
    #[tokio::test]
    async fn ensure_stream_without_bound_context_errors_cleanly() {
        let buffer = JetStreamBuffer::with_acker(FakeAcker::new(Duration::ZERO), "logs");
        let result = buffer.ensure_stream().await;
        assert!(matches!(result, Err(BufferError::Transport(_))));
    }

    /// Builds the exact wire body/headers `push` would produce for
    /// `event`, without going through a live broker — `async_nats::
    /// Message`'s fields are all public, so a real message can be
    /// constructed directly for the decode-side test below.
    fn encode_as_wire_message(event: &NormalizedEvent, subject: &str) -> async_nats::Message {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", event.dedup_key.as_str());
        headers.insert(TENANT_HEADER, event.tenant.as_str());
        let mut body = String::new();
        event.doc.write_compact(&mut body);
        async_nats::Message {
            subject: subject.into(),
            reply: None,
            payload: Bytes::from(body.into_bytes()),
            headers: Some(headers),
            status: None,
            description: None,
            length: 0,
        }
    }

    /// Proves the push -> consume serialization boundary is symmetric: an
    /// event encoded the same way `push` encodes it decodes back via
    /// `normalized_event_from_message` into an equal event.
    #[test]
    fn push_encoding_round_trips_through_consume_decoding() {
        let event = sample_event("dedup-key-roundtrip");
        let message = encode_as_wire_message(&event, "logs.tenant-a");

        let rebuilt = normalized_event_from_message(&message).unwrap();

        assert_eq!(rebuilt.tenant, event.tenant);
        assert_eq!(rebuilt.dedup_key, event.dedup_key);
        assert_eq!(rebuilt.doc, event.doc);
    }

    /// Builds a wire message with exactly the given headers (no `Nats-
    /// Msg-Id`/tenant defaults), for tests exercising a message missing
    /// one of them — `HeaderMap` has no `remove`, so the negative cases
    /// build their headers directly instead of stripping one out.
    fn wire_message_with_headers(headers: async_nats::HeaderMap) -> async_nats::Message {
        async_nats::Message {
            subject: "logs.tenant-a".into(),
            reply: None,
            payload: Bytes::from_static(b"{}"),
            headers: Some(headers),
            status: None,
            description: None,
            length: 0,
        }
    }

    /// A delivered message missing the tenant header must error cleanly
    /// — never silently produce a `NormalizedEvent` with a fabricated or
    /// empty tenant (that would be an un-tenanted event slipping past the
    /// tenant-isolation boundary).
    #[test]
    fn normalized_event_from_message_missing_tenant_header_errors_cleanly() {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", "dedup-key-no-tenant");
        // Deliberately no TENANT_HEADER.
        let message = wire_message_with_headers(headers);

        let result = normalized_event_from_message(&message);

        assert!(
            matches!(result, Err(BufferError::Serialize(_))),
            "missing tenant header must be a clean Serialize error, never a silently-untenanted event"
        );
    }

    /// Same as above, for the `Nats-Msg-Id` header — a message JetStream
    /// somehow delivered without it must not decode into an event with a
    /// fabricated dedup key.
    #[test]
    fn normalized_event_from_message_missing_dedup_key_header_errors_cleanly() {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(TENANT_HEADER, "tenant-a");
        // Deliberately no Nats-Msg-Id.
        let message = wire_message_with_headers(headers);

        let result = normalized_event_from_message(&message);

        assert!(matches!(result, Err(BufferError::Serialize(_))));
    }

    /// Starts a minimal real NATS 2.14+ JetStream container for
    /// [`ensure_stream_lets_a_push_only_buffer_publish_successfully`] — a
    /// bare `-js` flag is sufficient here (unlike `tests/common::
    /// start_nats`'s `sync_interval: always` durability config, which is
    /// production-fidelity concerned; this test only needs a stream to
    /// exist).
    async fn start_test_nats() -> (
        testcontainers::ContainerAsync<testcontainers::GenericImage>,
        String,
    ) {
        use testcontainers::core::{IntoContainerPort, WaitFor};
        use testcontainers::runners::AsyncRunner;
        use testcontainers::{GenericImage, ImageExt};

        let image = GenericImage::new("nats", "2.14-alpine")
            .with_exposed_port(4222.tcp())
            .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
            .with_cmd(["-js"])
            .with_startup_timeout(Duration::from_secs(180));
        let container = image.start().await.expect("start nats container");
        let host = container.get_host().await.expect("nats container host");
        let port = container
            .get_host_port_ipv4(4222)
            .await
            .expect("nats container mapped port");
        (container, format!("nats://{host}:{port}"))
    }

    /// Regression test for the production DLQ durability bug fixed
    /// alongside this test (Task 3.0c): a [`JetStreamBuffer`] that is only
    /// ever `push`ed to and never `consume`d — exactly
    /// `crate::writer::build_dlq_buffer`'s dead-letter sink — previously
    /// had no path that ever created its backing JetStream stream, so
    /// every dead-letter `push` failed against a real broker with "no
    /// stream found for given subject". Proves the fix against a real
    /// (Docker, `testcontainers`) NATS JetStream broker, not a fake: after
    /// `ensure_stream()`, a push-only buffer's `push` must succeed.
    #[tokio::test]
    async fn ensure_stream_lets_a_push_only_buffer_publish_successfully() {
        let (_container, url) = start_test_nats().await;
        let client = async_nats::connect(&url)
            .await
            .expect("connect to test nats");
        let context = async_nats::jetstream::new(client);
        let buffer =
            JetStreamBuffer::new(context, "svc-ingest-dlq-test").expect("build dlq test buffer");

        buffer
            .ensure_stream()
            .await
            .expect("ensure_stream must provision the DLQ stream");

        let result = buffer.push(sample_event("dedup-key-dlq-real")).await;

        assert!(
            result.is_ok(),
            "push against an ensure_stream-provisioned stream must succeed: {result:?}"
        );
    }
}
