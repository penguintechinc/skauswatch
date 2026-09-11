//! Bounded in-process [`EventBuffer`] fallback — test-only (or
//! `testutil`-feature-gated). Reproduces the two guarantees JetStream
//! itself provides server-side — bounded retention (oldest dropped on
//! overflow) and `Nats-Msg-Id`-style dedup — entirely in-process, so
//! listener/writer unit tests elsewhere in this crate can exercise the
//! full `EventBuffer` contract without a live NATS broker.

use std::collections::{HashMap, HashSet, VecDeque};

use tokio::sync::Mutex;

use super::{AckHandle, AckHandleInner, BufferError, DeliveredEvent, EventBuffer, NormalizedEvent};

struct Inner {
    queue: VecDeque<NormalizedEvent>,
    dedup_keys: HashSet<String>,
    in_flight: HashMap<usize, NormalizedEvent>,
    next_handle_id: usize,
}

/// Bounded `VecDeque<NormalizedEvent>` + `HashSet<String>` (dedup_key)
/// in-process buffer. `push` drops the oldest buffered event once
/// `capacity` is reached, and silently no-ops a `push` whose `dedup_key`
/// is already present (buffered or in-flight) — simulating JetStream's
/// server-side dedup for tests that use this fallback instead of a real
/// broker.
pub struct InMemoryBuffer {
    capacity: usize,
    inner: Mutex<Inner>,
}

impl InMemoryBuffer {
    /// Builds an empty buffer holding at most `capacity` events at once.
    /// A `capacity` of `0` accepts no events (every `push` returns
    /// [`BufferError::Full`]) rather than silently growing unbounded.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                dedup_keys: HashSet::new(),
                in_flight: HashMap::new(),
                next_handle_id: 0,
            }),
        }
    }
}

#[async_trait::async_trait]
impl EventBuffer for InMemoryBuffer {
    async fn push(&self, event: NormalizedEvent) -> Result<(), BufferError> {
        if self.capacity == 0 {
            return Err(BufferError::Full);
        }
        let mut inner = self.inner.lock().await;
        if inner.dedup_keys.contains(&event.dedup_key) {
            // Same dedup_key already buffered or in flight — a no-op,
            // mirroring JetStream's server-side `Nats-Msg-Id` dedup
            // (Global Constraint #4): a repeat publish of an
            // already-seen event is silently absorbed, not an error.
            return Ok(());
        }
        if inner.queue.len() >= self.capacity
            && let Some(evicted) = inner.queue.pop_front()
        {
            inner.dedup_keys.remove(&evicted.dedup_key);
        }
        inner.dedup_keys.insert(event.dedup_key.clone());
        inner.queue.push_back(event);
        Ok(())
    }

    async fn consume(&self, batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError> {
        let mut inner = self.inner.lock().await;
        let mut delivered = Vec::with_capacity(batch_size.min(inner.queue.len()));
        for _ in 0..batch_size {
            let Some(event) = inner.queue.pop_front() else {
                break;
            };
            let handle_id = inner.next_handle_id;
            inner.next_handle_id += 1;
            inner.in_flight.insert(handle_id, event.clone());
            delivered.push(DeliveredEvent {
                event,
                handle: AckHandle(AckHandleInner::InMemory(handle_id)),
            });
        }
        Ok(delivered)
    }

    async fn ack(&self, handle: AckHandle) -> Result<(), BufferError> {
        let AckHandleInner::InMemory(handle_id) = handle.0 else {
            return Err(BufferError::Transport(
                "JetStream ack handle used against InMemoryBuffer".to_owned(),
            ));
        };
        let mut inner = self.inner.lock().await;
        if let Some(event) = inner.in_flight.remove(&handle_id) {
            inner.dedup_keys.remove(&event.dedup_key);
        }
        Ok(())
    }

    async fn nack(&self, handle: AckHandle) -> Result<(), BufferError> {
        let AckHandleInner::InMemory(handle_id) = handle.0 else {
            return Err(BufferError::Transport(
                "JetStream ack handle used against InMemoryBuffer".to_owned(),
            ));
        };
        let mut inner = self.inner.lock().await;
        if let Some(event) = inner.in_flight.remove(&handle_id) {
            // Redeliver at the front (at-least-once semantics, mirroring
            // JetStream's Nak-then-redeliver). `dedup_keys` still
            // contains the key — it is only freed on `ack` — so a fresh
            // external push of the same key is correctly rejected as a
            // duplicate while redelivery is pending.
            inner.queue.push_front(event);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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

    /// Pushing capacity+1 events must cap the buffer's length at
    /// `capacity`, retaining the newest N (oldest dropped first).
    #[tokio::test]
    async fn inmemory_buffer_drops_oldest_on_overflow() {
        let buffer = InMemoryBuffer::new(3);
        for i in 0..4 {
            buffer
                .push(sample_event(&format!("key-{i}")))
                .await
                .unwrap();
        }

        let delivered = buffer.consume(10).await.unwrap();
        let dedup_keys: Vec<_> = delivered
            .iter()
            .map(|d| d.event.dedup_key.clone())
            .collect();
        assert_eq!(
            dedup_keys,
            vec!["key-1".to_owned(), "key-2".to_owned(), "key-3".to_owned()],
            "buffer must cap at capacity and retain the newest N events"
        );
    }

    /// Pushing two events with the same `dedup_key` must be a no-op on
    /// the second — simulating JetStream server-side dedup.
    #[tokio::test]
    async fn inmemory_buffer_dedup_key_collision_rejected() {
        let buffer = InMemoryBuffer::new(5);
        buffer.push(sample_event("duplicate")).await.unwrap();
        buffer.push(sample_event("duplicate")).await.unwrap();

        let delivered = buffer.consume(10).await.unwrap();
        assert_eq!(
            delivered.len(),
            1,
            "a second push with a colliding dedup_key must be a silent no-op"
        );
    }

    /// A zero-capacity buffer accepts nothing rather than growing
    /// unbounded.
    #[tokio::test]
    async fn inmemory_buffer_zero_capacity_rejects_push() {
        let buffer = InMemoryBuffer::new(0);
        let result = buffer.push(sample_event("key")).await;
        assert!(matches!(result, Err(BufferError::Full)));
    }

    /// `nack` redelivers the event at the front of the queue rather than
    /// dropping it — at-least-once semantics.
    #[tokio::test]
    async fn inmemory_buffer_nack_redelivers_event() {
        let buffer = InMemoryBuffer::new(5);
        buffer.push(sample_event("key-1")).await.unwrap();

        let mut delivered = buffer.consume(1).await.unwrap();
        assert_eq!(delivered.len(), 1);
        let handle = delivered.pop().unwrap().handle;
        buffer.nack(handle).await.unwrap();

        let redelivered = buffer.consume(1).await.unwrap();
        assert_eq!(redelivered.len(), 1, "nacked event must be redelivered");
        assert_eq!(redelivered[0].event.dedup_key, "key-1");
    }

    /// `ack` permanently removes the event and frees its `dedup_key` for
    /// reuse.
    #[tokio::test]
    async fn inmemory_buffer_ack_frees_dedup_key() {
        let buffer = InMemoryBuffer::new(5);
        buffer.push(sample_event("key-1")).await.unwrap();

        let mut delivered = buffer.consume(1).await.unwrap();
        let handle = delivered.pop().unwrap().handle;
        buffer.ack(handle).await.unwrap();

        buffer.push(sample_event("key-1")).await.unwrap();
        let redelivered = buffer.consume(1).await.unwrap();
        assert_eq!(
            redelivered.len(),
            1,
            "dedup_key must be reusable once the original event is acked"
        );
    }
}
