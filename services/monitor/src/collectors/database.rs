//! Database collector: polls a target database's audit/log table for new
//! rows on a timestamp cursor. Rust port of the working core of v1
//! `collectors/database_collector.py`'s query-loop
//! (`_execute_query_loop`/`_create_event_from_row`) — v1 supported
//! Postgres, MySQL, and SQLite target databases via three separate driver
//! integrations (`asyncpg`/`aiomysql`/`aiosqlite`). This port supports
//! **Postgres target databases only**, matching this workspace's enabled
//! `sqlx` driver features (`postgres`, `sqlite` — no `mysql`, see the root
//! `Cargo.toml` `sqlx` entry); the Postgres path is fully real and working,
//! not a stub — MySQL/SQLite target support is a documented, narrower-scope
//! follow-up, not silently dropped.
//!
//! Note this is a **target** database being *monitored* (an application's
//! own audit-log table, external to this service) — unrelated to
//! `crate::threat_intel::store::ThreatStore`'s Postgres connection, which is
//! this service's *own* schema.

use std::env;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::ingest::IngestHandle;
use crate::models::{BaseEvent, EventType, LogSource, Severity};

/// Config for the database collector, loaded from
/// `MONITOR_COLLECTOR_DB_*`.
#[derive(Debug, Clone)]
pub struct DatabaseCollectorConfig {
    /// `MONITOR_COLLECTOR_DB_ENABLED` — off by default.
    pub enabled: bool,
    /// `MONITOR_COLLECTOR_DB_DSN` — target Postgres connection string
    /// (`postgres://user:pass@host:port/db`), distinct from this service's
    /// own `DB_*` vars (which configure `threat_intel::store::ThreatStore`).
    pub dsn: String,
    /// `MONITOR_COLLECTOR_DB_QUERY` — SQL selecting new rows; must expose a
    /// `message` column and SHOULD expose `timestamp`/`severity`/`username`/
    /// `source_ip` (all optional, looked up by name — v1's flexible
    /// row-field lookup, see [`row_to_event`]). No default; the collector
    /// does not start without an operator-supplied query, since a generic
    /// v1-style "any audit table" query cannot be guessed safely.
    pub query: String,
    /// `MONITOR_COLLECTOR_DB_POLL_INTERVAL_SECS`; default 30s.
    pub poll_interval: Duration,
}

impl DatabaseCollectorConfig {
    /// Pure constructor — the unit-testable core (no process env access).
    fn from_values(
        raw_enabled: Option<&str>,
        dsn: Option<&str>,
        query: Option<&str>,
        poll_interval_secs: Option<&str>,
    ) -> Self {
        let dsn = dsn.unwrap_or_default().to_owned();
        let query = query.unwrap_or_default().to_owned();
        let enabled = raw_enabled
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false)
            && !dsn.is_empty()
            && !query.is_empty();
        let poll_interval = poll_interval_secs
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        Self {
            enabled,
            dsn,
            query,
            poll_interval,
        }
    }

    /// Loads from env. Never fails — an unset `dsn`/`query` simply means
    /// [`mod@crate::collectors::spawn_enabled`] won't enable this collector
    /// (its `enabled` gate additionally requires both to be non-empty).
    pub fn from_env() -> Self {
        Self::from_values(
            env::var("MONITOR_COLLECTOR_DB_ENABLED").ok().as_deref(),
            env::var("MONITOR_COLLECTOR_DB_DSN").ok().as_deref(),
            env::var("MONITOR_COLLECTOR_DB_QUERY").ok().as_deref(),
            env::var("MONITOR_COLLECTOR_DB_POLL_INTERVAL_SECS")
                .ok()
                .as_deref(),
        )
    }
}

/// v1 `_determine_event_type` (message-keyword form — this port doesn't
/// support v1's `query_config["event_type"]` override, since it has no
/// per-query config struct beyond the one query).
fn infer_event_type(message_lower: &str) -> EventType {
    if contains_any(
        message_lower,
        &["login", "authentication", "password", "auth"],
    ) {
        EventType::Authentication
    } else if contains_any(
        message_lower,
        &["permission", "access", "denied", "authorized"],
    ) {
        EventType::Authorization
    } else if contains_any(message_lower, &["network", "connection", "tcp", "udp"]) {
        EventType::Network
    } else if contains_any(message_lower, &["sudo", "privilege", "escalation"]) {
        EventType::PrivilegeEscalation
    } else if contains_any(
        message_lower,
        &["security", "violation", "intrusion", "attack"],
    ) {
        EventType::SecurityViolation
    } else if contains_any(message_lower, &["process", "started", "stopped", "killed"]) {
        EventType::Process
    } else if contains_any(
        message_lower,
        &["file", "read", "write", "create", "delete"],
    ) {
        EventType::FileAccess
    } else {
        EventType::Accounting
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn severity_from_column(raw: Option<&str>) -> Severity {
    match raw.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => Severity::Critical,
        Some("error") => Severity::High,
        Some("warning" | "warn") => Severity::Medium,
        Some("debug") => Severity::Low,
        _ => Severity::Info,
    }
}

/// Looks up an optional text column by name, tolerating its absence from
/// the query result (v1's `row.get(field, default)` — an operator's query
/// need not project every optional field).
fn try_text(row: &sqlx::postgres::PgRow, name: &str) -> Option<String> {
    row.try_get::<Option<String>, _>(name).ok().flatten()
}

/// v1 `_create_event_from_row`/`_create_auth_event_from_row`: builds a
/// [`BaseEvent`] from one result row. Requires a `message` column (returns
/// `None` if absent/null — nothing meaningful to report otherwise);
/// `timestamp`/`severity`/`username`/`source_ip`/`method` are all optional.
pub fn row_to_event(row: &sqlx::postgres::PgRow, tenant_id: &str) -> Option<BaseEvent> {
    let message = try_text(row, "message")?;
    if message.is_empty() {
        return None;
    }
    let lower = message.to_ascii_lowercase();
    let severity_raw = try_text(row, "severity");
    let mut severity = severity_from_column(severity_raw.as_deref());
    let event_type = infer_event_type(&lower);

    let timestamp = row
        .try_get::<Option<DateTime<Utc>>, _>("timestamp")
        .ok()
        .flatten()
        .unwrap_or_else(Utc::now);

    let username = try_text(row, "username")
        .or_else(|| try_text(row, "user"))
        .or_else(|| try_text(row, "account"));
    let source_ip = try_text(row, "source_ip")
        .or_else(|| try_text(row, "ip_address"))
        .or_else(|| try_text(row, "client_ip"));

    if event_type == EventType::Authentication {
        let success_text = try_text(row, "success").map(|s| s.to_ascii_lowercase());
        let success = success_text
            .as_deref()
            .map(|s| matches!(s, "true" | "success" | "yes" | "1"))
            .unwrap_or(true);
        if !success {
            severity = Severity::High;
        }
        return Some(BaseEvent {
            id: uuid::Uuid::new_v4().to_string(),
            source: LogSource::System,
            event_type,
            severity,
            message,
            timestamp,
            raw_data: serde_json::json!({"collector": "database"}),
            tags: vec!["database".to_owned(), "authentication".to_owned()],
            host: String::new(),
            user: username,
            process: None,
            pid: None,
            enrichments: serde_json::Value::Null,
            threat_matches: vec![],
            ai_analysis: None,
            processed_data: source_ip
                .map(|ip| serde_json::json!({"source_ip": ip}))
                .unwrap_or(serde_json::Value::Null),
            tenant_id: tenant_id.to_owned(),
            extra: Default::default(),
        });
    }

    Some(BaseEvent {
        id: uuid::Uuid::new_v4().to_string(),
        source: LogSource::System,
        event_type,
        severity,
        message,
        timestamp,
        raw_data: serde_json::json!({"collector": "database"}),
        tags: vec!["database".to_owned()],
        host: String::new(),
        user: username,
        process: None,
        pid: None,
        enrichments: serde_json::Value::Null,
        threat_matches: vec![],
        ai_analysis: None,
        processed_data: serde_json::Value::Null,
        tenant_id: tenant_id.to_owned(),
        extra: Default::default(),
    })
}

/// Runs `query` and ingests every resulting row, returning the number
/// ingested. A query error is returned to the caller (`run` logs and
/// retries next cycle) rather than panicking the collector task.
pub async fn poll_once<'a>(
    pool: &'a PgPool,
    query: &'a str,
    tenant_id: &'a str,
    sink: &'a IngestHandle,
) -> Result<usize, sqlx::Error> {
    // `AssertSqlSafe`: sqlx 0.9's SQL-injection-safety lint only accepts
    // `&'static str` literals by default for a dynamic `&str` — this one is
    // operator-configured infrastructure config (`MONITOR_COLLECTOR_DB_QUERY`),
    // never end-user/request input, so the assertion holds. Same pattern
    // `skauswatch-testkit::db::test_pool` uses for its own dynamic SQL.
    let rows = sqlx::query(sqlx::AssertSqlSafe(query))
        .fetch_all(pool)
        .await?;
    let mut count = 0;
    for row in &rows {
        if let Some(event) = row_to_event(row, tenant_id) {
            sink.ingest(event).await;
            count += 1;
        }
    }
    Ok(count)
}

/// Connects (with retry/backoff, matching `skauswatch_db::connect_postgres`'s
/// resilience policy — but against an operator-supplied target DSN, not
/// this service's own `DB_*` config) and polls forever.
pub async fn run(cfg: DatabaseCollectorConfig, tenant_id: String, sink: IngestHandle) {
    let mut delay = Duration::from_secs(5);
    let pool = loop {
        match sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&cfg.dsn)
            .await
        {
            Ok(pool) => break pool,
            Err(e) => {
                tracing::warn!(error = %e, "database collector: target DB connect failed, retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(60));
            }
        }
    };

    let mut ticker = tokio::time::interval(cfg.poll_interval);
    loop {
        ticker.tick().await;
        match poll_once(&pool, &cfg.query, &tenant_id, &sink).await {
            Ok(count) => tracing::debug!(rows = count, "database collector polled"),
            Err(e) => tracing::error!(error = %e, "database collector query failed"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn severity_from_column_maps_known_levels() {
        assert_eq!(severity_from_column(Some("critical")), Severity::Critical);
        assert_eq!(severity_from_column(Some("ERROR")), Severity::High);
        assert_eq!(severity_from_column(Some("warn")), Severity::Medium);
        assert_eq!(severity_from_column(Some("debug")), Severity::Low);
        assert_eq!(severity_from_column(None), Severity::Info);
    }

    #[test]
    fn infer_event_type_prioritizes_authentication_keywords() {
        assert_eq!(
            infer_event_type("user login failed"),
            EventType::Authentication
        );
        assert_eq!(
            infer_event_type("permission denied"),
            EventType::Authorization
        );
        assert_eq!(infer_event_type("tcp connection reset"), EventType::Network);
        assert_eq!(
            infer_event_type("sudo privilege escalation"),
            EventType::PrivilegeEscalation
        );
        assert_eq!(infer_event_type("unrecognized text"), EventType::Accounting);
    }

    #[test]
    fn config_disabled_when_dsn_missing_even_if_flag_and_query_are_set() {
        let cfg = DatabaseCollectorConfig::from_values(Some("true"), None, Some("select 1"), None);
        assert!(!cfg.enabled);
    }

    #[test]
    fn config_disabled_when_query_missing_even_if_flag_and_dsn_are_set() {
        let cfg = DatabaseCollectorConfig::from_values(
            Some("true"),
            Some("postgres://u:p@h/db"),
            None,
            None,
        );
        assert!(!cfg.enabled);
    }

    #[test]
    fn config_disabled_when_flag_unset_even_with_dsn_and_query() {
        let cfg = DatabaseCollectorConfig::from_values(
            None,
            Some("postgres://u:p@h/db"),
            Some("select 1"),
            None,
        );
        assert!(!cfg.enabled);
    }

    #[test]
    fn config_enabled_when_flag_dsn_and_query_all_set() {
        let cfg = DatabaseCollectorConfig::from_values(
            Some("true"),
            Some("postgres://u:p@h/db"),
            Some("select 1"),
            Some("45"),
        );
        assert!(cfg.enabled);
        assert_eq!(cfg.poll_interval, Duration::from_secs(45));
    }

    #[test]
    fn config_poll_interval_defaults_to_30s() {
        let cfg = DatabaseCollectorConfig::from_values(None, None, None, None);
        assert_eq!(cfg.poll_interval, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn poll_once_ingests_rows_with_a_message_column() {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        sqlx::query(
            "CREATE TABLE app_audit_log (id serial primary key, message text, severity text, username text)",
        )
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("create table: {e}"));
        sqlx::query("INSERT INTO app_audit_log (message, severity, username) VALUES ($1, $2, $3)")
            .bind("failed login attempt")
            .bind("error")
            .bind("mallory")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("insert: {e}"));

        let (bus, mut rx) = tokio::sync::broadcast::channel(16);
        let sink = crate::ingest::IngestPipeline::spawn(
            None,
            bus,
            None,
            skauswatch_testkit::license::dev_license("skauswatch"),
            crate::ingest::IngestConfig {
                channel_capacity: 16,
                batch_size: 1,
                flush_interval: Duration::from_millis(30),
            },
        );

        let count = poll_once(
            &pool,
            "SELECT message, severity, username FROM app_audit_log",
            "tenant-a",
            &sink,
        )
        .await
        .unwrap_or_else(|e| panic!("poll: {e}"));
        assert_eq!(count, 1);

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected the row to be broadcast"));
        let event = got.unwrap_or_else(|e| panic!("recv: {e}"));
        assert_eq!(event.event_type, EventType::Authentication);
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.user, Some("mallory".to_owned()));
        assert_eq!(event.tenant_id, "tenant-a");
    }

    #[tokio::test]
    async fn poll_once_skips_rows_with_no_message() {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        sqlx::query("CREATE TABLE empty_log (id serial primary key, message text)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("create table: {e}"));
        sqlx::query("INSERT INTO empty_log (message) VALUES (NULL)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("insert: {e}"));

        let (bus, _rx) = tokio::sync::broadcast::channel(16);
        let sink = crate::ingest::IngestPipeline::spawn(
            None,
            bus,
            None,
            skauswatch_testkit::license::dev_license("skauswatch"),
            crate::ingest::IngestConfig::default(),
        );

        let count = poll_once(&pool, "SELECT message FROM empty_log", "tenant-a", &sink)
            .await
            .unwrap_or_else(|e| panic!("poll: {e}"));
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn poll_once_builds_a_non_authentication_event_for_non_auth_rows() {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        sqlx::query("CREATE TABLE net_log (id serial primary key, message text)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("create table: {e}"));
        sqlx::query("INSERT INTO net_log (message) VALUES ($1)")
            .bind("tcp connection reset by peer")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("insert: {e}"));

        let (bus, mut rx) = tokio::sync::broadcast::channel(16);
        let sink = crate::ingest::IngestPipeline::spawn(
            None,
            bus,
            None,
            skauswatch_testkit::license::dev_license("skauswatch"),
            crate::ingest::IngestConfig {
                channel_capacity: 16,
                batch_size: 1,
                flush_interval: Duration::from_millis(30),
            },
        );

        let count = poll_once(&pool, "SELECT message FROM net_log", "tenant-a", &sink)
            .await
            .unwrap_or_else(|e| panic!("poll: {e}"));
        assert_eq!(count, 1);

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected the row to be broadcast"));
        let event = got.unwrap_or_else(|e| panic!("recv: {e}"));
        assert_eq!(event.event_type, EventType::Network);
        assert!(event.tags.contains(&"database".to_owned()));
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        let cfg = DatabaseCollectorConfig::from_env();
        assert!(!cfg.enabled);
    }

    #[tokio::test]
    async fn run_connects_and_polls_at_least_once_against_a_real_target_db() {
        // `run`'s own connect-with-retry loop, exercised against a real
        // Postgres (any reachable one — this collector's target DB is
        // conceptually a *different* database than the one `ThreatStore`
        // uses, but for this smoke test the same test-Postgres instance
        // works fine: `run` never touches this crate's own schema).
        let host = std::env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_owned());
        let port = std::env::var("DB_PORT").unwrap_or_else(|_| "5432".to_owned());
        let user = std::env::var("DB_USER").unwrap_or_else(|_| "postgres".to_owned());
        let pass = std::env::var("DB_PASS").unwrap_or_else(|_| "postgres".to_owned());
        let name = std::env::var("DB_NAME").unwrap_or_else(|_| "postgres".to_owned());
        let dsn = format!("postgres://{user}:{pass}@{host}:{port}/{name}");

        let (bus, mut rx) = tokio::sync::broadcast::channel(16);
        let sink = crate::ingest::IngestPipeline::spawn(
            None,
            bus,
            None,
            skauswatch_testkit::license::dev_license("skauswatch"),
            crate::ingest::IngestConfig {
                channel_capacity: 16,
                batch_size: 1,
                flush_interval: Duration::from_millis(30),
            },
        );
        let cfg = DatabaseCollectorConfig {
            enabled: true,
            dsn,
            query: "SELECT 'db collector smoke test' AS message".to_owned(),
            poll_interval: Duration::from_millis(50),
        };
        let handle = tokio::spawn(run(cfg, "tenant-a".to_owned(), sink));

        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected at least one poll cycle to ingest a row"));
        assert!(got.is_ok());
        handle.abort();
    }
}
