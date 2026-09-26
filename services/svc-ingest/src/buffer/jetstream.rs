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
use crate::config::NatsAuthConfig;

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

// ---------------------------------------------------------------------
// NATS client auth hardening (Spec §7a / P2). Before this, every NATS
// connection this crate opened was unauthenticated and plaintext — no
// creds/nkeys/TLS at all. `connect_options` is optional and back-compatible
// by construction: a default (all-`None`/`false`) `NatsAuthConfig`
// produces the exact same unauthenticated `ConnectOptions::default()`
// behavior every connection used before this hardening, so a local/dev
// deployment that sets none of the `NATS_*` auth env vars is unaffected —
// never fails startup for missing NATS auth.
// ---------------------------------------------------------------------

/// Which NATS auth mechanism [`connect_options`] applies for a given
/// [`NatsAuthConfig`] — factored out as a pure, synchronous decision (no
/// `async_nats` type touched yet) so the precedence rule itself (`.creds`
/// file > NKey seed > user/password > none) is unit-testable without
/// needing to inspect `async_nats::ConnectOptions`'s internal auth state,
/// which has no public accessors. Carries the selected credential(s)
/// directly (rather than a bare enum discriminant + a second lookup back
/// into `auth`) so callers never need an `.unwrap()`/`.expect()` to
/// re-extract an `Option` this function already proved is `Some`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatsAuthMode<'a> {
    /// No `NATS_*` auth env var set — today's unauthenticated behavior,
    /// preserved for local/dev.
    None,
    CredsFile(&'a str),
    Nkey(&'a str),
    UserPassword(&'a str, &'a str),
}

/// Selects a [`NatsAuthMode`] from `auth`'s precedence order. Exposed only
/// within this module — see [`connect_options`], the sole caller, and the
/// `nats_auth_mode_*` tests exercising this precedence directly.
fn select_nats_auth_mode(auth: &NatsAuthConfig) -> NatsAuthMode<'_> {
    if let Some(path) = auth.creds_file.as_deref() {
        NatsAuthMode::CredsFile(path)
    } else if let Some(seed) = auth.nkey.as_deref() {
        NatsAuthMode::Nkey(seed)
    } else if let (Some(user), Some(password)) = (auth.user.as_deref(), auth.password.as_deref()) {
        NatsAuthMode::UserPassword(user, password)
    } else {
        NatsAuthMode::None
    }
}

/// Installs `aws-lc-rs` as the process-wide default `rustls` crypto
/// provider, exactly once — required before `async_nats`'s own TLS
/// handshake code (`ClientConfig::builder()`, using the same vendored
/// `rustls` this crate pins via `Cargo.toml`) can select a default
/// provider. This workspace resolves both `ring` and `aws-lc-rs` into the
/// dependency graph, so `rustls` can't auto-select one on its own and
/// errors instead of connecting. Mirrors the identical, already-established
/// `ensure_default_crypto_provider` in
/// `services/worker-vault-sync/src/providers/mod.rs` — same problem
/// (`rcgen` pins `aws_lc_rs` explicitly while other crates default to
/// `ring`), same fix, same backend choice, kept as its own copy here per
/// that module's own doc comment ("to avoid touching already-stable,
/// already-tested code") rather than a shared helper neither crate
/// currently exposes to the other.
fn ensure_default_crypto_provider() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        // Ignore the `Err` (returns the already-installed provider) — a
        // race with another caller installing first is fine, we only care
        // that *some* default ends up installed before first use.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Builds the [`async_nats::ConnectOptions`] every NATS connection in this
/// crate should use, applying whichever [`NatsAuthMode`] `auth` selects
/// plus TLS if `auth.tls` is set. See this section's module comment for the
/// back-compat guarantee.
///
/// # Errors
/// Returns [`BufferError::Transport`] only if `NATS_CREDS_FILE` is set but
/// the file cannot be read or parsed (`async_nats`'s own `.creds`-format
/// parse) — never fails for absent auth.
pub(crate) async fn connect_options(
    auth: &NatsAuthConfig,
) -> Result<async_nats::ConnectOptions, BufferError> {
    let options = async_nats::ConnectOptions::new();
    let mut options = match select_nats_auth_mode(auth) {
        NatsAuthMode::None => options,
        NatsAuthMode::CredsFile(path) => options
            .credentials_file(path)
            .await
            .map_err(|e| BufferError::Transport(format!("NATS_CREDS_FILE {path:?}: {e}")))?,
        NatsAuthMode::Nkey(seed) => options.nkey(seed.to_owned()),
        NatsAuthMode::UserPassword(user, password) => {
            options.user_and_password(user.to_owned(), password.to_owned())
        }
    };
    if auth.tls {
        ensure_default_crypto_provider();
        options = options.require_tls(true);
    }
    Ok(options)
}

/// Connects to `url` applying `auth` (see [`connect_options`]) and builds a
/// [`JetStreamBuffer`] publishing/consuming under `subject_prefix` — the
/// auth-hardened counterpart to hand-rolling `async_nats::connect(url)` +
/// `async_nats::jetstream::new(client)` + [`JetStreamBuffer::new`]. Used by
/// `crate::writer::build_dlq_buffer`'s dead-letter-sink connection.
/// `crate::bootstrap::build_event_buffer` (the shared main ingest buffer —
/// out of this task's file scope) still connects unauthenticated pending
/// its own adoption of this helper.
///
/// # Errors
/// Returns an error if `auth` cannot be turned into `ConnectOptions` (see
/// [`connect_options`]), the NATS server is unreachable, or `subject_prefix`
/// is invalid (see [`JetStreamBuffer::new`]).
pub async fn connect(
    url: &str,
    auth: &NatsAuthConfig,
    subject_prefix: &str,
) -> Result<JetStreamBuffer, BufferError> {
    let options = connect_options(auth).await?;
    let client = options
        .connect(url)
        .await
        .map_err(|e| BufferError::Transport(format!("connect nats: {e}")))?;
    let context = async_nats::jetstream::new(client);
    JetStreamBuffer::new(context, subject_prefix)
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
    /// Backing stream retention (Spec §15 open question #6), applied via
    /// [`Self::with_max_age`] — `None` (the default) preserves the exact
    /// unlimited-retention behavior every stream had before this
    /// hardening. Only `crate::writer::build_dlq_buffer`'s dead-letter
    /// sink sets this; the main ingest buffer is left at `None`.
    max_age: Option<Duration>,
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
            max_age: None,
        })
    }

    /// Sets this buffer's backing stream `max_age` (Spec §15 open question
    /// #6, `DLQ_RETENTION_DAYS`) — a builder-style setter so
    /// `JetStreamBuffer::new(..)?.with_max_age(retention)` composes at the
    /// call site rather than needing a second constructor. Only takes
    /// effect the next time [`Self::stream_config`] is read
    /// ([`Self::ensure_stream`]/[`Self::consumer`]'s lazy stream creation);
    /// see [`Self::ensure_stream`]'s doc comment for how an
    /// already-existing stream converges to a changed value.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
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
            max_age: None,
        }
    }

    /// Stream name derived from `subject_prefix` — JetStream stream names
    /// may not contain `.`, so dots become underscores.
    fn stream_name(&self) -> String {
        self.subject_prefix.replace('.', "_")
    }

    /// This buffer's backing JetStream stream config — a single wildcard
    /// subject (`{subject_prefix}.>`) capturing every tenant's traffic
    /// under this prefix, retained for `self.max_age` (`Duration::ZERO` —
    /// JetStream's "unlimited" sentinel — when unset, i.e. every buffer
    /// except a DLQ sink built via [`Self::with_max_age`]). Shared by
    /// [`Self::consumer`] and [`Self::ensure_stream`] so both create (or
    /// idempotently fetch) the exact same stream definition.
    fn stream_config(&self) -> async_nats::jetstream::stream::Config {
        async_nats::jetstream::stream::Config {
            name: self.stream_name(),
            subjects: vec![format!("{}.>", self.subject_prefix)],
            max_age: self.max_age.unwrap_or_default(),
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
    /// When `self.max_age` is set (the DLQ sink), also `update_stream`s an
    /// already-existing stream to the currently configured retention —
    /// `get_or_create_stream` only creates when absent, it does not
    /// retroactively change an existing stream's config, so a DLQ stream
    /// created before an operator changed `DLQ_RETENTION_DAYS` (or before
    /// this hardening added retention at all) would otherwise keep
    /// whatever policy it happened to be created with forever. Skipped
    /// entirely for the main ingest buffer (`max_age: None`) — no extra
    /// round trip added to its existing behavior.
    ///
    /// # Errors
    /// Returns an error if this buffer has no bound JetStream context (a
    /// test-only instance built via `with_acker`), or the stream cannot
    /// be created/fetched/updated.
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
        if self.max_age.is_some() {
            context
                .update_stream(self.stream_config())
                .await
                .map_err(|e| BufferError::Transport(e.to_string()))?;
        }
        Ok(())
    }

    /// Lazily binds (creating on first use) the durable, explicit-ack pull
    /// consumer every `consume()` call fetches from.
    ///
    /// Resolves Spec §15 open question #1 ("is a single shared durable
    /// consumer safe when multiple writer replicas run, or does it
    /// duplicate-process?"): **yes, safe, kept as-is.** This is a JetStream
    /// *pull* consumer (`consumer::pull::Config`, not a push/ordered
    /// consumer) with `AckPolicy::Explicit` — pull consumers are
    /// explicitly designed for exactly this multi-subscriber "queue group"
    /// shape: each replica's own `stream.get_or_create_consumer(durable_name,
    /// ..)` call idempotently binds to the *same* server-side durable
    /// (identical name + config), and each replica's own `fetch()` request
    /// registers independent pull interest against it. The broker hands
    /// out *disjoint* batches of unacked messages per pull request — never
    /// the same message to two concurrent pulls — and only redelivers a
    /// given message if its `ack_wait` elapses or it's explicitly `Nak`ed
    /// (see `EventBuffer::ack`/`nack`), not because a second replica also
    /// asked for messages. There is no server-side or client-side
    /// duplication risk from running N writer replicas against one durable
    /// name; see
    /// `tests::two_concurrent_consumers_on_shared_durable_process_every_message_exactly_once`
    /// for the proof against a real broker, which *is* this open
    /// question's resolution rather than just documentation of an
    /// assumption. A per-replica durable name (keyed off `POD_NAME`/
    /// `HOSTNAME`) was the spec's fallback recommendation if this turned
    /// out unsafe — not needed.
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

    // -- NATS client auth hardening (Spec §7a / P2) ------------------------

    #[test]
    fn nats_auth_mode_prefers_creds_file_over_everything_else() {
        let auth = NatsAuthConfig {
            creds_file: Some("/etc/nats/user.creds".to_owned()),
            nkey: Some("seed".to_owned()),
            user: Some("u".to_owned()),
            password: Some("p".to_owned()),
            tls: false,
        };
        assert_eq!(
            select_nats_auth_mode(&auth),
            NatsAuthMode::CredsFile("/etc/nats/user.creds")
        );
    }

    #[test]
    fn nats_auth_mode_prefers_nkey_over_user_password() {
        let auth = NatsAuthConfig {
            creds_file: None,
            nkey: Some("SUANQ...seed".to_owned()),
            user: Some("u".to_owned()),
            password: Some("p".to_owned()),
            tls: false,
        };
        assert_eq!(
            select_nats_auth_mode(&auth),
            NatsAuthMode::Nkey("SUANQ...seed")
        );
    }

    #[test]
    fn nats_auth_mode_falls_back_to_user_password() {
        let auth = NatsAuthConfig {
            user: Some("derek".to_owned()),
            password: Some("s3cr3t".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            select_nats_auth_mode(&auth),
            NatsAuthMode::UserPassword("derek", "s3cr3t")
        );
    }

    #[test]
    fn nats_auth_mode_is_none_when_nothing_set() {
        assert_eq!(
            select_nats_auth_mode(&NatsAuthConfig::default()),
            NatsAuthMode::None
        );
    }

    /// Back-compat guarantee (this section's module doc comment): a default
    /// `NatsAuthConfig` must produce a `ConnectOptions` that behaves exactly
    /// like the unauthenticated default every NATS connection used before
    /// this hardening — proven end to end against a real broker rather than
    /// just asserted from `select_nats_auth_mode` alone, since
    /// `ConnectOptions`'s internal auth state has no public accessors to
    /// inspect directly.
    #[tokio::test]
    async fn connect_options_with_no_auth_set_connects_successfully() {
        let (_container, url) = start_test_nats().await;
        let options = connect_options(&NatsAuthConfig::default())
            .await
            .expect("build connect options");
        let result = options.connect(&url).await;
        assert!(
            result.is_ok(),
            "default NatsAuthConfig must connect exactly like unauthenticated \
             async_nats::connect: {result:?}"
        );
    }

    /// `NATS_CREDS_FILE` pointing at a nonexistent path must surface as a
    /// clean [`BufferError::Transport`], never a panic — no live broker
    /// needed, since the failure happens at the file-read step before any
    /// network I/O.
    #[tokio::test]
    async fn connect_options_surfaces_a_missing_creds_file_cleanly() {
        let auth = NatsAuthConfig {
            creds_file: Some("/nonexistent/path/does-not-exist.creds".to_owned()),
            ..Default::default()
        };
        let result = connect_options(&auth).await;
        assert!(
            matches!(result, Err(BufferError::Transport(_))),
            "a missing creds file must be a clean BufferError, got {result:?}"
        );
    }

    // -- DLQ retention (Spec §15 open question #6) -------------------------

    /// Proves [`JetStreamBuffer::with_max_age`] + [`JetStreamBuffer::
    /// ensure_stream`] actually set the DLQ stream's server-side `max_age`
    /// to the configured retention — against a real (Docker,
    /// `testcontainers`) broker, not just asserting `stream_config()`'s
    /// in-memory shape.
    #[tokio::test]
    async fn ensure_stream_sets_configured_max_age_on_the_dlq_stream() {
        let (_container, url) = start_test_nats().await;
        let client = async_nats::connect(&url)
            .await
            .expect("connect to test nats");
        let context = async_nats::jetstream::new(client);
        let retention = Duration::from_secs(30 * 24 * 60 * 60);
        let buffer = JetStreamBuffer::new(context.clone(), "svc-ingest-dlq-retention-test")
            .expect("build dlq test buffer")
            .with_max_age(retention);

        buffer
            .ensure_stream()
            .await
            .expect("ensure_stream must provision the DLQ stream");

        let mut stream = context
            .get_stream(buffer.stream_name())
            .await
            .expect("fetch provisioned dlq stream");
        let info = stream.info().await.expect("fetch dlq stream info");
        assert_eq!(
            info.config.max_age, retention,
            "DLQ stream max_age must match the configured 30-day retention"
        );
    }

    // -- Shared durable pull consumer, multi-replica (Spec §15 open
    // question #1) ----------------------------------------------------

    /// Drains `buffer` in batches of `batch` until `seen` (shared across
    /// both concurrently-running replicas in
    /// [`two_concurrent_consumers_on_shared_durable_process_every_message_exactly_once`])
    /// has collected `total` dedup keys, acking every delivered event as it
    /// goes. Rechecks `seen`'s length before every `consume()` call so both
    /// replicas stop promptly once every published event has been claimed
    /// by either one of them.
    async fn drain_until_total(
        buffer: &JetStreamBuffer,
        seen: &Arc<std::sync::Mutex<Vec<String>>>,
        total: usize,
        batch: usize,
    ) {
        loop {
            if seen.lock().expect("seen mutex poisoned").len() >= total {
                return;
            }
            let Ok(delivered) = buffer.consume(batch).await else {
                continue;
            };
            for d in delivered {
                seen.lock()
                    .expect("seen mutex poisoned")
                    .push(d.event.dedup_key.clone());
                buffer
                    .ack(d.handle)
                    .await
                    .expect("ack a fanout-test delivered event");
            }
        }
    }

    /// Resolves Spec §15 open question #1 WITH EVIDENCE (this test *is* the
    /// resolution, not just documentation of an assumption — see
    /// [`JetStreamBuffer::consumer`]'s doc comment): two independent
    /// [`JetStreamBuffer`]s, each its own NATS connection simulating a
    /// separate writer replica process, bind to the *same* durable pull
    /// consumer (deterministic `{stream_name}-consumer` name, derived from
    /// the shared `subject_prefix` both buffers are built with) and pull
    /// concurrently. Asserts every published event is delivered exactly
    /// once across the two replicas combined — no duplicate processing, no
    /// loss — the exact question raised for running the writer with
    /// multiple pods.
    #[tokio::test]
    async fn two_concurrent_consumers_on_shared_durable_process_every_message_exactly_once() {
        const TOTAL_EVENTS: usize = 40;
        const PULL_BATCH: usize = 5;
        let prefix = "svc-ingest-consumer-fanout-test";

        let (_container, url) = start_test_nats().await;

        let publisher_client = async_nats::connect(&url).await.expect("connect publisher");
        let publisher = JetStreamBuffer::new(async_nats::jetstream::new(publisher_client), prefix)
            .expect("build publisher buffer");
        // `push` alone never creates the backing stream (see
        // `JetStreamBuffer::ensure_stream`'s doc comment) — provision it
        // explicitly before publishing, same as the DLQ sink does.
        publisher
            .ensure_stream()
            .await
            .expect("provision the fanout-test stream");
        for i in 0..TOTAL_EVENTS {
            publisher
                .push(sample_event(&format!("dedup-fanout-{i}")))
                .await
                .expect("publish fanout event");
        }

        // Two independent connections/buffers simulate two separate writer
        // replica pods, both binding to the SAME durable name.
        let client_a = async_nats::connect(&url).await.expect("connect replica a");
        let replica_a = JetStreamBuffer::new(async_nats::jetstream::new(client_a), prefix)
            .expect("build replica a buffer");
        let client_b = async_nats::connect(&url).await.expect("connect replica b");
        let replica_b = JetStreamBuffer::new(async_nats::jetstream::new(client_b), prefix)
            .expect("build replica b buffer");

        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

        let drained = tokio::time::timeout(
            Duration::from_secs(30),
            futures::future::join(
                drain_until_total(&replica_a, &seen, TOTAL_EVENTS, PULL_BATCH),
                drain_until_total(&replica_b, &seen, TOTAL_EVENTS, PULL_BATCH),
            ),
        )
        .await;
        assert!(
            drained.is_ok(),
            "both replicas did not finish draining all {TOTAL_EVENTS} events within 30s — \
             possible message loss/stall"
        );

        let collected = seen.lock().expect("seen mutex poisoned").clone();
        assert_eq!(
            collected.len(),
            TOTAL_EVENTS,
            "expected exactly {TOTAL_EVENTS} deliveries across both replicas combined, got {} — \
             a shared durable pull consumer must never lose a message",
            collected.len()
        );
        let unique: std::collections::HashSet<&String> = collected.iter().collect();
        assert_eq!(
            unique.len(),
            TOTAL_EVENTS,
            "expected {TOTAL_EVENTS} DISTINCT dedup keys across both replicas, got {} unique out \
             of {} deliveries — a shared durable pull consumer must never double-deliver the same \
             message to two concurrent pullers",
            unique.len(),
            collected.len()
        );
    }
}
