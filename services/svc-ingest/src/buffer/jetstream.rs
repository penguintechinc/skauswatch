//! Production [`EventBuffer`]: NATS JetStream, server-side deduped via a
//! `Nats-Msg-Id` header. See the module-level durability contract in
//! [`super`] — `push` never returns before the `PublishAck` resolves, and
//! never wraps the publish in `tokio::time::timeout()` (a timed-out
//! client can still have a durably-written message sitting on the
//! broker; racing a retry on top of that would duplicate it).

use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
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
            delivered.push(DeliveredEvent {
                event,
                handle: AckHandle(AckHandleInner::JetStream(Box::new(msg))),
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
