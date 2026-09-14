//! Valkey/Redis Streams job model shared by every skauswatch worker — the
//! Celery replacement. Producers append `JobMessage` envelopes to
//! `skauswatch:*` topics; workers consume via consumer groups with
//! ack/retry/DLQ semantics (harness lands with the first worker port).
//!
//! Topic name constants are added per-service during Phase 3, copied
//! verbatim from the v1 producers so the wire contract is preserved.

use chrono::{DateTime, NaiveDateTime, Utc};
use fred::interfaces::{ClientLike, StreamsInterface};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod consumer;
pub use consumer::{ConsumerConfig, HandlerError, StreamConsumer, StreamEntry, StreamHandler};

/// Stream key prefix shared with the v1 stack — do not change.
pub const TOPIC_PREFIX: &str = "skauswatch";

/// Builds a fully-qualified stream key: `skauswatch:{service}:{queue}`.
pub fn topic(service: &str, queue: &str) -> String {
    format!("{TOPIC_PREFIX}:{service}:{queue}")
}

// v1 stream names (RedisStreamManager constants) — unprefixed; the producer
// prepends the configured key prefix (`REDIS_KEY_PREFIX`, default
// `skauswatch`) exactly like v1's `_key()`.

/// ENDPOINT event pipeline stream (v1 `STREAM_ENDPOINT_EVENTS`).
pub const STREAM_ENDPOINT_EVENTS: &str = "endpoint:events";
/// Pending-alert processing stream (v1 `STREAM_ALERTS_PENDING`).
pub const STREAM_ALERTS_PENDING: &str = "alerts:pending";
/// AI task queue stream (v1 `STREAM_AI_TASKS`).
pub const STREAM_AI_TASKS: &str = "ai:tasks";
/// Threat-intel update stream (v1 `STREAM_THREAT_UPDATES`).
pub const STREAM_THREAT_UPDATES: &str = "threatintel:updates";
/// Approval workflow stream (v1 `STREAM_APPROVALS`).
pub const STREAM_APPROVALS: &str = "approvals:pending";
/// Audit log stream (v1 `STREAM_AUDIT_LOG`).
pub const STREAM_AUDIT_LOG: &str = "audit:log";
/// S3 scan task stream (v1 `STREAM_S3_SCAN_TASKS`).
pub const STREAM_S3_SCAN_TASKS: &str = "s3scan:tasks";
/// S3 scan result stream (v1 `STREAM_S3_SCAN_RESULTS`).
pub const STREAM_S3_SCAN_RESULTS: &str = "s3scan:results";
/// CodeScan code review task stream.
pub const STREAM_CODESCAN_TASKS: &str = "codescan:tasks";

/// ASM (YARA/ClamAV/Nuclei/ZAP/OpenVAS) scan task stream.
pub const STREAM_SCANNER_TASKS: &str = "scanner:tasks";
/// ASM scan result stream.
pub const STREAM_SCANNER_RESULTS: &str = "scanner:results";

/// Approximate stream cap applied on publish — v1 `publish_event` default
/// (`maxlen=10000, approximate=True`).
pub const DEFAULT_MAXLEN: i64 = 10_000;

// v1 wire-encoding helpers. redis-py xadd stringifies every field value:
// dict/list → json.dumps, datetime → isoformat, bool → str(bool), None → "".
// Field maps built for publishing must reproduce those bytes exactly.

/// Python `str(bool)` — `"True"` / `"False"` (capitalized, unlike Rust).
pub fn py_bool(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

/// Python `datetime.isoformat()` for a naive UTC timestamp, byte-for-byte:
/// `YYYY-MM-DDTHH:MM:SS` when `microsecond == 0`, otherwise
/// `YYYY-MM-DDTHH:MM:SS.ffffff` (exactly six zero-padded digits).
pub fn py_isoformat(t: NaiveDateTime) -> String {
    use chrono::Timelike as _;
    if t.nanosecond() == 0 {
        t.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

/// `py_isoformat` lifted over `Option` — `None` stays `None` so JSON
/// rendering emits `null` exactly where v1's `x.isoformat() if x else None`
/// did.
pub fn py_isoformat_opt(t: Option<NaiveDateTime>) -> Option<String> {
    t.map(py_isoformat)
}

/// Serde `serialize_with` adapter for `Option<NaiveDateTime>` struct fields:
/// renders Python isoformat, or JSON null for `None`.
pub fn serde_py_isoformat_opt<S: serde::Serializer>(
    t: &Option<NaiveDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match t {
        Some(v) => serializer.serialize_str(&py_isoformat(*v)),
        None => serializer.serialize_none(),
    }
}

/// Python `datetime.utcnow().isoformat()` — the stamp v1 producers attach as
/// `submitted_at` / `timestamp` fields.
pub fn py_now_isoformat() -> String {
    py_isoformat(Utc::now().naive_utc())
}

/// Reproduces v1 `RedisConfig.full_url`: injects `default:{password}@` after
/// the scheme when a password is configured and the URL has no userinfo.
pub fn redis_url_with_password(url: &str, password: Option<&str>) -> String {
    match password {
        Some(pass) if !url.contains('@') => match url.split_once("://") {
            Some((scheme, rest)) => format!("{scheme}://default:{pass}@{rest}"),
            None => url.to_owned(),
        },
        _ => url.to_owned(),
    }
}

/// Fully-prefixed stream key (v1 `RedisStreamManager._key`):
/// `{prefix}:{stream}`, e.g. `skauswatch:alerts:pending`.
pub fn prefixed_key(prefix: &str, stream: &str) -> String {
    format!("{prefix}:{stream}")
}

/// Ordered field list for one stream entry. Order is preserved on XADD,
/// matching redis-py's dict insertion order — required for wire parity.
pub type EntryFields = Vec<(String, String)>;

/// Publisher for `skauswatch:*` streams — the v1 `RedisStreamManager`
/// producer side. Wraps a fred client with auto-reconnect; every publish is
/// an `XADD` with the v1 approximate MAXLEN cap.
#[derive(Clone)]
pub struct StreamProducer {
    client: fred::clients::Client,
    prefix: String,
}

impl std::fmt::Debug for StreamProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamProducer")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl StreamProducer {
    /// Connects to Valkey/Redis and verifies the connection (v1
    /// `RedisStreamManager.connect` pings on connect; startup fails if the
    /// broker is unreachable). `prefix` namespaces every stream key.
    pub async fn connect(
        url: &str,
        password: Option<&str>,
        prefix: &str,
    ) -> Result<Self, StreamError> {
        let effective = redis_url_with_password(url, password);
        let config = fred::types::config::Config::from_url(&effective)?;
        let mut builder = fred::types::Builder::from_config(config);
        // Retry forever with capped exponential backoff — parity with
        // redis-py's per-command reconnect behavior.
        builder.set_policy(fred::types::config::ReconnectPolicy::new_exponential(
            0, 100, 30_000, 2,
        ));
        let client = builder.build()?;
        // init() connects and waits for the first successful handshake; the
        // returned join handle is detached (the reconnect task runs for the
        // client's lifetime).
        let _connect_task = client.init().await?;
        Ok(Self {
            client,
            prefix: prefix.to_owned(),
        })
    }

    /// Fully-prefixed stream key for an unprefixed stream name (v1 `_key`).
    pub fn key(&self, stream: &str) -> String {
        prefixed_key(&self.prefix, stream)
    }

    /// XADDs the ordered fields to `{prefix}:{stream}` with the v1 cap
    /// (`MAXLEN ~ 10000`). Returns the generated entry id.
    pub async fn publish(&self, stream: &str, fields: EntryFields) -> Result<String, StreamError> {
        let id: String = self
            .client
            .xadd(
                self.key(stream),
                false,
                ("MAXLEN", "~", DEFAULT_MAXLEN),
                "*",
                fields,
            )
            .await?;
        Ok(id)
    }

    /// PINGs the broker — the v1 `/healthz` Redis probe.
    pub async fn ping(&self) -> Result<(), StreamError> {
        let _: String = self.client.ping(None).await?;
        Ok(())
    }
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

impl From<fred::error::Error> for StreamError {
    fn from(e: fred::error::Error) -> Self {
        StreamError::Transport(e.to_string())
    }
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
    fn stream_names_match_v1_manager_constants() {
        assert_eq!(STREAM_ENDPOINT_EVENTS, "endpoint:events");
        assert_eq!(STREAM_ALERTS_PENDING, "alerts:pending");
        assert_eq!(STREAM_AI_TASKS, "ai:tasks");
        assert_eq!(STREAM_THREAT_UPDATES, "threatintel:updates");
        assert_eq!(STREAM_APPROVALS, "approvals:pending");
        assert_eq!(STREAM_AUDIT_LOG, "audit:log");
        assert_eq!(STREAM_S3_SCAN_TASKS, "s3scan:tasks");
        assert_eq!(STREAM_S3_SCAN_RESULTS, "s3scan:results");
    }

    #[test]
    fn py_bool_matches_python_str_bool() {
        assert_eq!(py_bool(true), "True");
        assert_eq!(py_bool(false), "False");
    }

    fn micro_dt(micro: u32) -> NaiveDateTime {
        match chrono::NaiveDate::from_ymd_opt(2026, 7, 22)
            .and_then(|d| d.and_hms_micro_opt(10, 3, 7, micro))
        {
            Some(v) => v,
            None => panic!("valid test datetime"),
        }
    }

    #[test]
    fn py_isoformat_renders_six_zero_padded_fraction_digits() {
        assert_eq!(py_isoformat(micro_dt(123456)), "2026-07-22T10:03:07.123456");
        // Zero-padding: small microsecond values keep exactly six digits.
        assert_eq!(py_isoformat(micro_dt(42)), "2026-07-22T10:03:07.000042");
        assert_eq!(py_isoformat(micro_dt(120000)), "2026-07-22T10:03:07.120000");
    }

    #[test]
    fn py_isoformat_omits_fraction_at_zero_microseconds() {
        // Python datetime.isoformat() drops the fraction entirely when
        // microsecond == 0 — v1 wire parity depends on this.
        assert_eq!(py_isoformat(micro_dt(0)), "2026-07-22T10:03:07");
    }

    #[test]
    fn py_isoformat_opt_passes_null_through() {
        assert_eq!(py_isoformat_opt(None), None);
        assert_eq!(
            py_isoformat_opt(Some(micro_dt(1))),
            Some("2026-07-22T10:03:07.000001".to_owned())
        );
    }

    #[test]
    fn serde_adapter_matches_python_isoformat_and_null() {
        #[derive(Serialize)]
        struct Row {
            #[serde(serialize_with = "crate::serde_py_isoformat_opt")]
            at: Option<NaiveDateTime>,
        }
        let some = serde_json::to_value(Row {
            at: Some(micro_dt(0)),
        });
        match some {
            Ok(v) => assert_eq!(v, serde_json::json!({"at": "2026-07-22T10:03:07"})),
            Err(e) => panic!("serialize: {e}"),
        }
        let none = serde_json::to_value(Row { at: None });
        match none {
            Ok(v) => assert_eq!(v, serde_json::json!({"at": null})),
            Err(e) => panic!("serialize: {e}"),
        }
    }

    #[test]
    fn prefixed_key_matches_v1_key_builder() {
        assert_eq!(
            prefixed_key("skauswatch", STREAM_ALERTS_PENDING),
            "skauswatch:alerts:pending"
        );
        assert_eq!(prefixed_key("custom", STREAM_AI_TASKS), "custom:ai:tasks");
    }

    /// Real-Valkey coverage for `StreamProducer::connect`/`publish`/`ping` —
    /// same "test against the real broker, don't mock it" convention as
    /// `consumer::tests` (see that module's doc comment). `REDIS_URL`
    /// defaults to `redis://127.0.0.1:6379/0` for local runs outside the
    /// CI/dev-container network.
    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_owned())
    }

    #[tokio::test]
    async fn producer_connects_publishes_and_pings_a_real_broker() {
        let producer = StreamProducer::connect(&redis_url(), None, "skauswatch-test")
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));

        producer
            .ping()
            .await
            .unwrap_or_else(|e| panic!("ping: {e}"));

        let stream = format!("lib-test-{}", Uuid::new_v4());
        let id = producer
            .publish(&stream, vec![("k".to_owned(), "v".to_owned())])
            .await
            .unwrap_or_else(|e| panic!("publish: {e}"));
        assert!(!id.is_empty(), "XADD must return a non-empty entry id");
        assert_eq!(producer.key(&stream), format!("skauswatch-test:{stream}"));
    }

    #[test]
    fn redis_url_password_injection_matches_v1_full_url() {
        // Password set, no userinfo → inject `default:{pass}@`.
        assert_eq!(
            redis_url_with_password("redis://redis:6379/0", Some("s3cr3t")),
            "redis://default:s3cr3t@redis:6379/0"
        );
        // URL already carries userinfo → untouched.
        assert_eq!(
            redis_url_with_password("redis://user:pw@redis:6379/0", Some("s3cr3t")),
            "redis://user:pw@redis:6379/0"
        );
        // No password → untouched.
        assert_eq!(
            redis_url_with_password("redis://redis:6379/0", None),
            "redis://redis:6379/0"
        );
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
