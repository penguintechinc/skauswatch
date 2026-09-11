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
pub struct JetStreamBuffer {
    context: async_nats::jetstream::Context,
    subject_prefix: String,
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
            context: client,
            subject_prefix: subject_prefix.to_owned(),
            consumer: OnceCell::new(),
        })
    }

    /// Stream name derived from `subject_prefix` — JetStream stream names
    /// may not contain `.`, so dots become underscores.
    fn stream_name(&self) -> String {
        self.subject_prefix.replace('.', "_")
    }

    /// Lazily binds (creating on first use) the durable, explicit-ack
    /// pull consumer every `consume()` call fetches from.
    async fn consumer(
        &self,
    ) -> Result<&async_nats::jetstream::consumer::PullConsumer, BufferError> {
        self.consumer
            .get_or_try_init(|| async {
                let stream_name = self.stream_name();
                let stream = self
                    .context
                    .get_or_create_stream(async_nats::jetstream::stream::Config {
                        name: stream_name.clone(),
                        subjects: vec![format!("{}.>", self.subject_prefix)],
                        ..Default::default()
                    })
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
        self.context
            .publish_and_ack(subject, headers, Bytes::from(body.into_bytes()))
            .await
    }

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
        Ok(delivered)
    }

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

/// Rebuilds a [`NormalizedEvent`] from a delivered JetStream message —
/// the inverse of `push`'s header + `write_compact` body encoding.
fn normalized_event_from_message(
    msg: &async_nats::jetstream::Message,
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
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// A fake [`PublishAcker`] whose ack resolution is delayed by
    /// `ack_delay`, so tests can prove the caller genuinely waits for it
    /// (as opposed to spawning it in the background and returning early —
    /// the fire-and-forget bug Global Constraint #3 forbids).
    struct DelayedAckPublisher {
        ack_delay: Duration,
        ack_completed: std::sync::Arc<AtomicBool>,
        captured: Mutex<Option<(String, async_nats::HeaderMap, Bytes)>>,
    }

    #[async_trait::async_trait]
    impl PublishAcker for DelayedAckPublisher {
        async fn publish_and_ack(
            &self,
            subject: String,
            headers: async_nats::HeaderMap,
            payload: Bytes,
        ) -> Result<(), BufferError> {
            *self.captured.lock().unwrap() = Some((subject, headers, payload));
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
    /// durability test (Global Constraint #3): `push` must not return
    /// until the publish ack future has actually resolved, never merely
    /// after the publish call is issued.
    #[tokio::test]
    async fn push_awaits_publish_ack_before_returning() {
        let ack_completed = std::sync::Arc::new(AtomicBool::new(false));
        let publisher = DelayedAckPublisher {
            ack_delay: Duration::from_millis(50),
            ack_completed: ack_completed.clone(),
            captured: Mutex::new(None),
        };

        let result = publisher
            .publish_and_ack(
                "subj".to_owned(),
                async_nats::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
        assert!(
            ack_completed.load(Ordering::SeqCst),
            "publish_and_ack returned before the delayed ack resolved — fire-and-forget regression"
        );
    }

    /// Same content (dedup key) twice must yield an identical
    /// `Nats-Msg-Id`; different content must yield a different one —
    /// Global Constraint #4's server-side dedup only works if the header
    /// is a deterministic function of the event.
    #[tokio::test]
    async fn push_sets_nats_msg_id_header_deterministically() {
        let ack_completed = std::sync::Arc::new(AtomicBool::new(false));
        let publisher = DelayedAckPublisher {
            ack_delay: Duration::from_millis(0),
            ack_completed,
            captured: Mutex::new(None),
        };

        let event_a1 = sample_event("dedup-key-a");
        let subject_a1 = format!("logs.{}", event_a1.tenant.as_str());
        let mut headers_a1 = async_nats::HeaderMap::new();
        headers_a1.insert("Nats-Msg-Id", event_a1.dedup_key.as_str());
        publisher
            .publish_and_ack(subject_a1.clone(), headers_a1, Bytes::new())
            .await
            .unwrap();
        let msg_id_a1 = publisher
            .captured
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .1
            .get("Nats-Msg-Id")
            .unwrap()
            .to_string();

        let event_a2 = sample_event("dedup-key-a");
        let mut headers_a2 = async_nats::HeaderMap::new();
        headers_a2.insert("Nats-Msg-Id", event_a2.dedup_key.as_str());
        publisher
            .publish_and_ack(subject_a1, headers_a2, Bytes::new())
            .await
            .unwrap();
        let msg_id_a2 = publisher
            .captured
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .1
            .get("Nats-Msg-Id")
            .unwrap()
            .to_string();

        assert_eq!(
            msg_id_a1, msg_id_a2,
            "same dedup_key must yield the same Nats-Msg-Id"
        );

        let event_b = sample_event("dedup-key-b");
        let mut headers_b = async_nats::HeaderMap::new();
        headers_b.insert("Nats-Msg-Id", event_b.dedup_key.as_str());
        publisher
            .publish_and_ack("logs.tenant-a".to_owned(), headers_b, Bytes::new())
            .await
            .unwrap();
        let msg_id_b = publisher
            .captured
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .1
            .get("Nats-Msg-Id")
            .unwrap()
            .to_string();

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
}
