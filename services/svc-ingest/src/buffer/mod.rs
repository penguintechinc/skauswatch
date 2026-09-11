//! Durable event buffer abstraction sitting between the receiver-mode
//! listeners and the writer. [`EventBuffer`] is the single seam every
//! listener (`Arc<dyn EventBuffer>`) publishes through and the writer
//! consumes from — [`jetstream::JetStreamBuffer`] is the production
//! implementation (NATS JetStream, server-side deduped via a
//! `Nats-Msg-Id` header); [`inmemory::InMemoryBuffer`] is a bounded
//! in-process fallback for tests only.
//!
//! # Durability contract (Spec §7a, non-negotiable)
//!
//! `push` MUST NOT return `Ok` until the event is confirmed durably
//! persisted (JetStream's `PublishAck` has resolved) — never
//! fire-and-forget a publish, and never wrap the publish (or its ack
//! future) in `tokio::time::timeout()`: the TCP write can persist on the
//! broker while the client sees a timeout, and racing a retry would
//! duplicate the message. Server-side dedup via `Nats-Msg-Id` plus
//! connection-level timeout config is the only sanctioned defense against
//! a stuck publish. See [`jetstream::JetStreamBuffer::push`] and its
//! `push_awaits_publish_ack_before_returning` regression test.

// Wave 1 (not this task) wires `Arc<dyn EventBuffer>` into `main.rs`'s
// `serve()` and every listener/writer — until then, `cargo build`'s
// reachability analysis (this crate has no `[lib]` target, only a
// `[[bin]]`, so nothing outside `buffer` can be an external consumer)
// sees this whole module tree as unused. Same pattern as the other
// Task-0.2 stub modules' per-item `#[allow(dead_code)]` (see
// `admin.rs`/`writer.rs`/etc.), broadened here to the module level
// because this task lands the full trait + two implementations, not one
// placeholder struct.
#![allow(dead_code, unused_imports)]

// Test-only (or `testutil`-feature-gated) in-process fallback — never
// compiled into a production `serve` build. `cfg(test)` is crate-wide
// during `cargo test`, so any other module's own `#[cfg(test)] mod
// tests` (listeners, writer) can `use crate::buffer::InMemoryBuffer`
// without the `testutil` feature.
#[cfg(any(test, feature = "testutil"))]
pub mod inmemory;
pub mod jetstream;

#[cfg(any(test, feature = "testutil"))]
pub use inmemory::InMemoryBuffer;
pub use jetstream::JetStreamBuffer;

/// A normalized OCSF event ready to be durably buffered — already stamped
/// with the caller's server-validated tenant (never a payload/param
/// tenant, per the house tenant-isolation rule) and carrying a
/// deterministic dedup key the buffer uses for at-least-once-safe
/// redelivery dedup.
#[derive(Debug, Clone)]
pub struct NormalizedEvent {
    /// The server-validated tenant this event belongs to.
    pub tenant: skauswatch_auth::Tenant,
    /// The OCSF-normalized document body.
    pub doc: skauswatch_ocsf::JsonVal,
    /// Deterministic dedup key (e.g. a content hash of the normalized
    /// document). Becomes the `Nats-Msg-Id` header on JetStream publish,
    /// so a retried publish of the same event is a server-side no-op
    /// instead of a duplicate document; the in-memory buffer enforces the
    /// same uniqueness locally for tests that don't run a broker.
    pub dedup_key: String,
}

/// A [`NormalizedEvent`] delivered back out of the buffer for processing,
/// paired with the opaque handle the consumer must `ack`/`nack` exactly
/// once.
#[derive(Debug)]
pub struct DeliveredEvent {
    /// The delivered event.
    pub event: NormalizedEvent,
    /// The handle to `ack`/`nack` once downstream processing of `event`
    /// has succeeded or failed.
    pub handle: AckHandle,
    /// The OpenTelemetry trace context extracted from this message's W3C
    /// `traceparent` header, if the receiver-side push had an active span
    /// to inject (`crate::buffer::jetstream::inject_trace_context`) — lets
    /// the writer reparent its own processing span to the producer's
    /// trace, propagating trace context across the receiver -> NATS ->
    /// writer queue hop (`critical-rules.md` Observability: "propagate
    /// trace context across every service boundary ... queue hops").
    /// `None` for the in-memory fallback (no header transport) or when no
    /// span was active at push time — never treated as an error either
    /// way (extraction is infallible; see
    /// `crate::buffer::jetstream::extract_trace_context`'s doc comment).
    pub trace_context: Option<opentelemetry::Context>,
}

/// Opaque redelivery handle — either a JetStream message (explicit-ack
/// pull consumer) or an in-memory queue index, depending on which
/// [`EventBuffer`] impl produced it. Only ever constructed by this
/// module; `ack`/`nack` reject a handle minted by the other
/// implementation.
#[derive(Debug)]
pub struct AckHandle(AckHandleInner);

#[derive(Debug)]
enum AckHandleInner {
    JetStream(Box<async_nats::jetstream::Message>),
    InMemory(usize),
}

impl AckHandle {
    /// The number of times this message has been delivered, as tracked
    /// server-side by JetStream (`Info::delivered`, parsed from the
    /// per-redelivery ack-reply subject) — `None` for the in-memory
    /// fallback (no server-side delivery tracking) or if the metadata
    /// can't be parsed. `crate::writer` uses this in preference to a
    /// process-local failure counter for its DLQ threshold: unlike a
    /// counter held in this process's memory, the JetStream delivery
    /// count survives a writer restart — it travels with the message
    /// itself, not with any one writer process.
    pub fn delivery_count(&self) -> Option<u64> {
        match &self.0 {
            AckHandleInner::JetStream(msg) => msg
                .info()
                .ok()
                .and_then(|info| u64::try_from(info.delivered).ok()),
            AckHandleInner::InMemory(_) => None,
        }
    }
}

/// Failure modes any `EventBuffer` impl can surface — never leaks a
/// transport-specific error type across the trait boundary.
#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    /// The buffer has no more capacity (the bounded in-memory fallback
    /// only — JetStream applies its own configured stream limits/discard
    /// policy server-side instead of surfacing this variant).
    #[error("event buffer is full")]
    Full,
    /// The underlying transport (NATS JetStream) rejected or failed to
    /// complete the operation.
    #[error("buffer transport error: {0}")]
    Transport(String),
    /// The event could not be serialized to, or deserialized from, the
    /// wire format the transport requires.
    #[error("buffer serialize error: {0}")]
    Serialize(String),
}

/// Durable event buffer sitting between the receiver-mode listeners and
/// the writer. Every listener publishes through `Arc<dyn EventBuffer>`;
/// the writer drains it via `consume`/`ack`/`nack`. Implementations must
/// uphold the module-level durability contract above exactly — this is
/// the single most safety-critical seam in the service.
#[async_trait::async_trait]
pub trait EventBuffer: Send + Sync {
    /// Durably buffers `event`. MUST NOT return `Ok` until the event is
    /// confirmed persisted — see the module-level durability contract.
    async fn push(&self, event: NormalizedEvent) -> Result<(), BufferError>;

    /// Pulls up to `batch_size` not-yet-acknowledged events for
    /// processing. May return fewer than `batch_size` (including zero)
    /// when the buffer is currently empty.
    async fn consume(&self, batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError>;

    /// Acknowledges a [`DeliveredEvent`] as durably processed — the
    /// buffer will not redeliver it.
    async fn ack(&self, handle: AckHandle) -> Result<(), BufferError>;

    /// Signals that processing failed — the buffer redelivers the event
    /// (at-least-once semantics).
    async fn nack(&self, handle: AckHandle) -> Result<(), BufferError>;
}
