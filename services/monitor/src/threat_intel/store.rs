//! Postgres-backed IOC/feed/match store. Rust port of v1
//! `threat_intel/threat_database.py::ThreatDatabase` (aiosqlite there,
//! Postgres here — see `migrations/0001_threat_intel.sql`'s doc comment)
//! covering the methods v1's *working* code paths actually call:
//! `store_indicator`, `search_indicators`, `get_iocs`, `get_ioc_by_id`,
//! `record_match`, `get_feed_status`/`list_feeds`. The ~15 v1 REST routes
//! that called methods with no implementation anywhere
//! (`get_iocs_advanced`, `add_ioc`, `bulk_add_iocs`, ...) are not
//! reproduced — see `threat_intel/mod.rs` module docs.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{Ioc, ThreatFeed, ThreatLevel, ThreatMatch};

/// Errors from the threat-intel store — deliberately a distinct type from
/// [`crate::error::ApiError`] so this module stays testable/usable outside
/// an HTTP handler context (the TAXII feed poller in `taxii.rs` is not a
/// request handler); `routes.rs` maps this to `ApiError::Internal`.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Underlying database error.
    #[error("threat-intel store: {0}")]
    Db(#[from] sqlx::Error),
    /// A stored `threat_level`/enum column held a value that no longer
    /// round-trips through the wire enum — a corrupt row, not a query bug.
    #[error("threat-intel store: invalid stored value: {0}")]
    InvalidData(String),
}

fn threat_level_to_str(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Critical => "critical",
        ThreatLevel::High => "high",
        ThreatLevel::Medium => "medium",
        ThreatLevel::Low => "low",
        ThreatLevel::Unknown => "unknown",
    }
}

fn threat_level_from_str(s: &str) -> ThreatLevel {
    match s {
        "critical" => ThreatLevel::Critical,
        "high" => ThreatLevel::High,
        "medium" => ThreatLevel::Medium,
        "low" => ThreatLevel::Low,
        _ => ThreatLevel::Unknown,
    }
}

fn string_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(sqlx::FromRow)]
struct IocRow {
    id: Uuid,
    kind: String,
    value: String,
    description: String,
    threat_level: String,
    confidence: f64,
    tags: Value,
    malware_families: Value,
    kill_chain_phases: Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expiration: Option<DateTime<Utc>>,
    source_feed: Option<String>,
    metadata: Value,
}

impl From<IocRow> for Ioc {
    fn from(r: IocRow) -> Self {
        Ioc {
            id: r.id.to_string(),
            kind: r.kind,
            value: r.value,
            description: r.description,
            threat_level: threat_level_from_str(&r.threat_level),
            confidence: r.confidence,
            tags: string_list(&r.tags),
            malware_families: string_list(&r.malware_families),
            kill_chain_phases: string_list(&r.kill_chain_phases),
            created_at: r.created_at,
            updated_at: r.updated_at,
            expiration: r.expiration,
            source_feed: r.source_feed,
            metadata: r.metadata,
        }
    }
}

#[derive(sqlx::FromRow)]
struct FeedRow {
    id: Uuid,
    name: String,
    url: String,
    feed_type: String,
    enabled: bool,
    update_frequency: i64,
    credentials: Option<Value>,
    headers: Option<Value>,
    certificate_verification: bool,
    proxy_url: Option<String>,
    last_updated: Option<DateTime<Utc>>,
    ioc_count: i64,
    status: String,
    metadata: Value,
}

impl From<FeedRow> for ThreatFeed {
    fn from(r: FeedRow) -> Self {
        ThreatFeed {
            id: r.id.to_string(),
            name: r.name,
            url: r.url,
            feed_type: r.feed_type,
            enabled: r.enabled,
            update_frequency: r.update_frequency,
            credentials: r.credentials,
            headers: r.headers,
            certificate_verification: r.certificate_verification,
            proxy_url: r.proxy_url,
            last_updated: r.last_updated,
            ioc_count: r.ioc_count,
            status: r.status,
            metadata: r.metadata,
        }
    }
}

/// Postgres-backed threat-intel store, shared (via `Arc`) between the TAXII
/// feed poller (`taxii.rs`, writes) and the event matcher (`matcher.rs`,
/// reads) and the REST routes (`routes.rs`, reads + feed status).
pub struct ThreatStore {
    pool: PgPool,
}

impl ThreatStore {
    /// Wraps an already-connected pool (see `state.rs` for graceful-
    /// degradation connection logic — this constructor itself never fails).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Inserts a new IOC, or refreshes an existing one with the same
    /// `(kind, value)` — v1's TAXII poller re-fetches the same indicators on
    /// every poll cycle, so this must be idempotent rather than erroring on
    /// a duplicate. Returns the stored/updated row.
    pub async fn store_indicator(&self, ioc: &Ioc) -> Result<Ioc, StoreError> {
        let row: IocRow = sqlx::query_as(
            r#"
            INSERT INTO threat_iocs
                (kind, value, description, threat_level, confidence, tags,
                 malware_families, kill_chain_phases, expiration, source_feed, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (kind, value) DO UPDATE SET
                description = EXCLUDED.description,
                threat_level = EXCLUDED.threat_level,
                confidence = EXCLUDED.confidence,
                tags = EXCLUDED.tags,
                malware_families = EXCLUDED.malware_families,
                kill_chain_phases = EXCLUDED.kill_chain_phases,
                expiration = EXCLUDED.expiration,
                source_feed = EXCLUDED.source_feed,
                metadata = EXCLUDED.metadata,
                updated_at = now()
            RETURNING id, kind, value, description, threat_level, confidence,
                      tags, malware_families, kill_chain_phases, created_at,
                      updated_at, expiration, source_feed, metadata
            "#,
        )
        .bind(&ioc.kind)
        .bind(&ioc.value)
        .bind(&ioc.description)
        .bind(threat_level_to_str(ioc.threat_level))
        .bind(ioc.confidence)
        .bind(serde_json::json!(ioc.tags))
        .bind(serde_json::json!(ioc.malware_families))
        .bind(serde_json::json!(ioc.kill_chain_phases))
        .bind(ioc.expiration)
        .bind(&ioc.source_feed)
        .bind(&ioc.metadata)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    /// Exact `(kind, value)` lookup — the primitive [`crate::threat_intel::
    /// matcher::IndicatorMatcher`] calls per candidate field value.
    pub async fn find_by_kind_value(
        &self,
        kind: &str,
        value: &str,
    ) -> Result<Option<Ioc>, StoreError> {
        let row: Option<IocRow> = sqlx::query_as(
            r#"SELECT id, kind, value, description, threat_level, confidence,
                      tags, malware_families, kill_chain_phases, created_at,
                      updated_at, expiration, source_feed, metadata
               FROM threat_iocs WHERE kind = $1 AND value = $2"#,
        )
        .bind(kind)
        .bind(value)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// v1 `search_indicators`: free-text match over `value`/`description`,
    /// optional `kind`/`threat_level` filters, paginated.
    pub async fn search_indicators(
        &self,
        query: &str,
        kind: Option<&str>,
        threat_level: Option<ThreatLevel>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Ioc>, i64), StoreError> {
        let level_str = threat_level.map(threat_level_to_str);
        let rows: Vec<IocRow> = sqlx::query_as(
            r#"SELECT id, kind, value, description, threat_level, confidence,
                      tags, malware_families, kill_chain_phases, created_at,
                      updated_at, expiration, source_feed, metadata
               FROM threat_iocs
               WHERE ($1 = '' OR value ILIKE '%' || $1 || '%' OR description ILIKE '%' || $1 || '%')
                 AND ($2::text IS NULL OR kind = $2)
                 AND ($3::text IS NULL OR threat_level = $3)
               ORDER BY updated_at DESC
               LIMIT $4 OFFSET $5"#,
        )
        .bind(query)
        .bind(kind)
        .bind(level_str)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM threat_iocs
               WHERE ($1 = '' OR value ILIKE '%' || $1 || '%' OR description ILIKE '%' || $1 || '%')
                 AND ($2::text IS NULL OR kind = $2)
                 AND ($3::text IS NULL OR threat_level = $3)"#,
        )
        .bind(query)
        .bind(kind)
        .bind(level_str)
        .fetch_one(&self.pool)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total))
    }

    /// v1 `get_iocs` / `get_ioc_by_id` (id form) — direct lookup by primary
    /// key. Bad-uuid input maps to `Ok(None)` (not-found), not an error.
    pub async fn get_ioc_by_id(&self, id: &str) -> Result<Option<Ioc>, StoreError> {
        let Ok(uuid) = Uuid::parse_str(id) else {
            return Ok(None);
        };
        let row: Option<IocRow> = sqlx::query_as(
            r#"SELECT id, kind, value, description, threat_level, confidence,
                      tags, malware_families, kill_chain_phases, created_at,
                      updated_at, expiration, source_feed, metadata
               FROM threat_iocs WHERE id = $1"#,
        )
        .bind(uuid)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Records a match, denormalizing `tenant_id` from the matched event so
    /// per-tenant match history never requires joining back through
    /// monitor's own tenant-scoped event store (see migration doc comment).
    #[allow(clippy::too_many_arguments)] // one row's worth of scalar columns — a params struct would just move the same fields, see config.rs::Config::from_values for the same house precedent
    pub async fn record_match(
        &self,
        event_id: &str,
        ioc_id: &str,
        matched_value: &str,
        field_name: &str,
        confidence: f64,
        threat_level: ThreatLevel,
        tenant_id: &str,
    ) -> Result<ThreatMatch, StoreError> {
        let ioc_uuid = Uuid::parse_str(ioc_id)
            .map_err(|_| StoreError::InvalidData(format!("invalid ioc id: {ioc_id}")))?;
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            matched_at: DateTime<Utc>,
        }
        let row: Row = sqlx::query_as(
            r#"INSERT INTO threat_matches
                (event_id, ioc_id, matched_value, field_name, confidence, threat_level, tenant_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, matched_at"#,
        )
        .bind(event_id)
        .bind(ioc_uuid)
        .bind(matched_value)
        .bind(field_name)
        .bind(confidence)
        .bind(threat_level_to_str(threat_level))
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ThreatMatch {
            event_id: event_id.to_owned(),
            ioc_id: ioc_id.to_owned(),
            matched_value: matched_value.to_owned(),
            field_name: field_name.to_owned(),
            confidence,
            threat_level,
            id: row.id.to_string(),
            matched_at: row.matched_at,
            metadata: Value::Null,
        })
    }

    /// Upserts a feed definition — `taxii.rs` seeds configured feeds at
    /// startup from `MONITOR_TAXII_FEED_URLS` (see that module).
    pub async fn upsert_feed(&self, feed: &ThreatFeed) -> Result<ThreatFeed, StoreError> {
        let row: FeedRow = sqlx::query_as(
            r#"INSERT INTO threat_feeds
                (name, url, feed_type, enabled, update_frequency, certificate_verification, status)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (url) DO UPDATE SET name = EXCLUDED.name, enabled = EXCLUDED.enabled
               RETURNING id, name, url, feed_type, enabled, update_frequency, credentials,
                         headers, certificate_verification, proxy_url, last_updated, ioc_count,
                         status, metadata"#,
        )
        .bind(&feed.name)
        .bind(&feed.url)
        .bind(&feed.feed_type)
        .bind(feed.enabled)
        .bind(feed.update_frequency)
        .bind(feed.certificate_verification)
        .bind(&feed.status)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    /// Records the outcome of a poll cycle: status string (`"ok"`/`"error"`),
    /// the IOC count sourced from this feed as of this cycle, and the poll
    /// timestamp — v1 `get_feed_status`'s per-feed fields.
    pub async fn record_feed_poll(
        &self,
        feed_id: &str,
        status: &str,
        ioc_count: i64,
    ) -> Result<(), StoreError> {
        let Ok(uuid) = Uuid::parse_str(feed_id) else {
            return Err(StoreError::InvalidData(format!(
                "invalid feed id: {feed_id}"
            )));
        };
        sqlx::query(
            r#"UPDATE threat_feeds SET status = $1, ioc_count = $2, last_updated = now(), updated_at = now()
               WHERE id = $3"#,
        )
        .bind(status)
        .bind(ioc_count)
        .bind(uuid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// v1 `get_feed_status` (list form, `GET /threat-intel/feeds`).
    pub async fn list_feeds(&self) -> Result<Vec<ThreatFeed>, StoreError> {
        let rows: Vec<FeedRow> = sqlx::query_as(
            r#"SELECT id, name, url, feed_type, enabled, update_frequency, credentials,
                      headers, certificate_verification, proxy_url, last_updated, ioc_count,
                      status, metadata
               FROM threat_feeds ORDER BY name"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Enabled feeds only — what `taxii.rs`'s poll loop iterates.
    pub async fn list_enabled_feeds(&self) -> Result<Vec<ThreatFeed>, StoreError> {
        let rows: Vec<FeedRow> = sqlx::query_as(
            r#"SELECT id, name, url, feed_type, enabled, update_frequency, credentials,
                      headers, certificate_verification, proxy_url, last_updated, ioc_count,
                      status, metadata
               FROM threat_feeds WHERE enabled = true ORDER BY name"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    async fn pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    fn sample_ioc(value: &str) -> Ioc {
        Ioc {
            id: String::new(),
            kind: "ip".to_owned(),
            value: value.to_owned(),
            description: "known bad actor".to_owned(),
            threat_level: ThreatLevel::High,
            confidence: 0.9,
            tags: vec!["botnet".to_owned()],
            malware_families: vec![],
            kill_chain_phases: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expiration: None,
            source_feed: Some("test-feed".to_owned()),
            metadata: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn store_indicator_then_find_by_kind_value_round_trips() {
        let store = ThreatStore::new(pool().await);
        let stored = store
            .store_indicator(&sample_ioc("203.0.113.5"))
            .await
            .unwrap_or_else(|e| panic!("store: {e}"));
        assert_eq!(stored.value, "203.0.113.5");
        assert!(!stored.id.is_empty());

        let found = store
            .find_by_kind_value("ip", "203.0.113.5")
            .await
            .unwrap_or_else(|e| panic!("find: {e}"));
        assert_eq!(found.map(|i| i.id), Some(stored.id));
    }

    #[tokio::test]
    async fn store_indicator_upserts_on_conflict() {
        let store = ThreatStore::new(pool().await);
        let first = store
            .store_indicator(&sample_ioc("198.51.100.9"))
            .await
            .unwrap_or_else(|e| panic!("store: {e}"));

        let mut updated = sample_ioc("198.51.100.9");
        updated.threat_level = ThreatLevel::Critical;
        updated.confidence = 0.99;
        let second = store
            .store_indicator(&updated)
            .await
            .unwrap_or_else(|e| panic!("re-store: {e}"));

        assert_eq!(first.id, second.id, "same (kind, value) must reuse the row");
        assert_eq!(second.threat_level, ThreatLevel::Critical);
        assert!((second.confidence - 0.99).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn search_indicators_filters_by_kind_and_query() {
        let store = ThreatStore::new(pool().await);
        store
            .store_indicator(&sample_ioc("203.0.113.10"))
            .await
            .unwrap_or_else(|e| panic!("store: {e}"));
        let mut domain = sample_ioc("evil.example.test");
        domain.kind = "domain".to_owned();
        store
            .store_indicator(&domain)
            .await
            .unwrap_or_else(|e| panic!("store: {e}"));

        let (ip_only, total) = store
            .search_indicators("", Some("ip"), None, 50, 0)
            .await
            .unwrap_or_else(|e| panic!("search: {e}"));
        assert_eq!(total, 1);
        assert_eq!(ip_only.len(), 1);
        assert_eq!(ip_only[0].kind, "ip");

        let (by_text, _) = store
            .search_indicators("evil", None, None, 50, 0)
            .await
            .unwrap_or_else(|e| panic!("search: {e}"));
        assert_eq!(by_text.len(), 1);
        assert_eq!(by_text[0].value, "evil.example.test");
    }

    #[tokio::test]
    async fn get_ioc_by_id_returns_none_for_malformed_id() {
        let store = ThreatStore::new(pool().await);
        let found = store
            .get_ioc_by_id("not-a-uuid")
            .await
            .unwrap_or_else(|e| panic!("get: {e}"));
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn record_match_persists_and_denormalizes_tenant() {
        let store = ThreatStore::new(pool().await);
        let ioc = store
            .store_indicator(&sample_ioc("203.0.113.20"))
            .await
            .unwrap_or_else(|e| panic!("store: {e}"));

        let m = store
            .record_match(
                "event-1",
                &ioc.id,
                "203.0.113.20",
                "source_ip",
                0.95,
                ThreatLevel::High,
                "tenant-a",
            )
            .await
            .unwrap_or_else(|e| panic!("record_match: {e}"));
        assert_eq!(m.event_id, "event-1");
        assert_eq!(m.ioc_id, ioc.id);
        assert!(!m.id.is_empty());
    }

    #[tokio::test]
    async fn feed_upsert_and_poll_recording_round_trip() {
        let store = ThreatStore::new(pool().await);
        let feed = ThreatFeed {
            id: String::new(),
            name: "Test TAXII feed".to_owned(),
            url: "https://taxii.example.test/".to_owned(),
            feed_type: "taxii".to_owned(),
            enabled: true,
            update_frequency: 3600,
            credentials: None,
            headers: None,
            certificate_verification: true,
            proxy_url: None,
            last_updated: None,
            ioc_count: 0,
            status: "unknown".to_owned(),
            metadata: serde_json::json!({}),
        };
        let stored = store
            .upsert_feed(&feed)
            .await
            .unwrap_or_else(|e| panic!("upsert: {e}"));
        assert_eq!(stored.status, "unknown");

        store
            .record_feed_poll(&stored.id, "ok", 12)
            .await
            .unwrap_or_else(|e| panic!("record_feed_poll: {e}"));

        let feeds = store
            .list_feeds()
            .await
            .unwrap_or_else(|e| panic!("list_feeds: {e}"));
        let updated = feeds.iter().find(|f| f.id == stored.id);
        assert!(updated.is_some());
        let updated = updated.unwrap_or_else(|| panic!("expected feed present"));
        assert_eq!(updated.status, "ok");
        assert_eq!(updated.ioc_count, 12);
        assert!(updated.last_updated.is_some());
    }

    #[tokio::test]
    async fn list_enabled_feeds_excludes_disabled() {
        let store = ThreatStore::new(pool().await);
        store
            .upsert_feed(&ThreatFeed {
                id: String::new(),
                name: "enabled".to_owned(),
                url: "https://a.example.test/".to_owned(),
                feed_type: "taxii".to_owned(),
                enabled: true,
                update_frequency: 3600,
                credentials: None,
                headers: None,
                certificate_verification: true,
                proxy_url: None,
                last_updated: None,
                ioc_count: 0,
                status: "unknown".to_owned(),
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap_or_else(|e| panic!("upsert: {e}"));
        store
            .upsert_feed(&ThreatFeed {
                id: String::new(),
                name: "disabled".to_owned(),
                url: "https://b.example.test/".to_owned(),
                feed_type: "taxii".to_owned(),
                enabled: false,
                update_frequency: 3600,
                credentials: None,
                headers: None,
                certificate_verification: true,
                proxy_url: None,
                last_updated: None,
                ioc_count: 0,
                status: "unknown".to_owned(),
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap_or_else(|e| panic!("upsert: {e}"));

        let enabled = store
            .list_enabled_feeds()
            .await
            .unwrap_or_else(|e| panic!("list_enabled_feeds: {e}"));
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "enabled");
    }

    #[test]
    fn threat_level_str_round_trips_every_variant() {
        for level in [
            ThreatLevel::Critical,
            ThreatLevel::High,
            ThreatLevel::Medium,
            ThreatLevel::Low,
            ThreatLevel::Unknown,
        ] {
            assert_eq!(threat_level_from_str(threat_level_to_str(level)), level);
        }
        assert_eq!(threat_level_from_str("not-a-level"), ThreatLevel::Unknown);
    }

    #[tokio::test]
    async fn record_feed_poll_rejects_a_malformed_feed_id() {
        let store = ThreatStore::new(pool().await);
        let result = store.record_feed_poll("not-a-uuid", "ok", 1).await;
        assert!(matches!(result, Err(StoreError::InvalidData(_))));
    }
}
