//! Valkey/Redis Streams job model shared by every skauswatch worker — the
//! Celery replacement. Producers append `JobMessage` envelopes to
//! `skauswatch:*` topics; workers consume via consumer groups with
//! ack/retry/DLQ semantics (harness lands with the first worker port).
//!
//! Topic name constants are added per-service during Phase 3, copied
//! verbatim from the v1 producers so the wire contract is preserved.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stream key prefix shared with the v1 stack — do not change.
pub const TOPIC_PREFIX: &str = "skauswatch";

/// Builds a fully-qualified stream key: `skauswatch:{service}:{queue}`.
pub fn topic(service: &str, queue: &str) -> String {
    format!("{TOPIC_PREFIX}:{service}:{queue}")
}

/// Envelope for one queued job. Serialized as JSON into a single stream
/// field so payload schemas can evolve without stream-level migrations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobMessage {
    /// Unique job id, used for idempotency and audit.
    pub id: Uuid,
    /// Job kind discriminator (e.g. `scan_bucket`, `enrich_ioc`).
    pub kind: String,
    /// Tenant the job belongs to — every job is tenant-scoped.
    pub tenant: String,
    /// Job-kind-specific payload.
    pub payload: serde_json::Value,
    /// Delivery attempt count, incremented on retry.
    pub attempt: u32,
    /// When the producer enqueued the job.
    pub enqueued_at: DateTime<Utc>,
}

impl JobMessage {
    /// Creates a first-attempt job envelope stamped now.
    pub fn new(
        kind: impl Into<String>,
        tenant: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind: kind.into(),
            tenant: tenant.into(),
            payload,
            attempt: 1,
            enqueued_at: Utc::now(),
        }
    }
}

/// Errors surfaced by stream producers/consumers.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// The envelope could not be (de)serialized.
    #[error("job envelope serialization error: {0}")]
    Codec(#[from] serde_json::Error),
    /// The underlying Valkey/Redis operation failed.
    #[error("stream transport error: {0}")]
    Transport(String),
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn topic_uses_shared_prefix() {
        assert_eq!(topic("s3scan", "jobs"), "skauswatch:s3scan:jobs");
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let msg = JobMessage::new("scan_bucket", "t1", serde_json::json!({"bucket": "b"}));
        let encoded = serde_json::to_string(&msg).map_err(StreamError::Codec);
        let encoded = match encoded {
            Ok(s) => s,
            Err(e) => panic!("encode: {e}"),
        };
        let decoded: JobMessage = match serde_json::from_str(&encoded) {
            Ok(m) => m,
            Err(e) => panic!("decode: {e}"),
        };
        assert_eq!(decoded.id, msg.id);
        assert_eq!(decoded.kind, "scan_bucket");
        assert_eq!(decoded.attempt, 1);
    }
}
