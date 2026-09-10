//! Durable event buffer abstraction sitting between the receiver-mode
//! listeners and the writer — stub until Task 0.3 replaces this file with
//! the real `EventBuffer` trait (`push`/`consume`/`ack`/`nack`) plus the
//! `NormalizedEvent`/`DeliveredEvent`/`AckHandle`/`BufferError` types and
//! the `jetstream`/`inmemory` submodules (see
//! `docs/v2-port/ingest-module-spec.md` §7b).

/// Placeholder for the future `Arc<dyn EventBuffer>` every listener and the
/// writer will hold. Intentionally empty until Task 0.3 lands the real
/// trait.
// dead_code: this whole file is replaced by Task 0.3, which is the first
// consumer.
#[allow(dead_code)]
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingEventBuffer;
