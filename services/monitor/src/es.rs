//! Elasticsearch/OpenSearch access for the event store. Rust port of the ES
//! half of v1 `services/monitor/log_processor.py`.
//!
//! There is no ES client crate in this workspace (house pattern, see
//! `services/manager/src/routes/siem.rs` and `services/logs`):
//! access goes over the plain REST API via `reqwest`. Query bodies are
//! built by pure functions ([`build_search_body`]) so the query shape is
//! unit-tested directly, without any HTTP mocking; the thin I/O methods on
//! [`ElasticsearchStore`] are exercised against a `wiremock` server.

use serde_json::{Value, json};

use crate::error::ApiError;
use crate::models::{BaseEvent, EventSearchRequest, EventSearchResponse};

/// Trait over the event-search backend so routes can be tested against a
/// fake without a live ES/Mongo instance. [`ElasticsearchStore`] and
/// [`crate::mongo::MongoStore`] both implement it.
///
/// **Tenant isolation (finding — no tenant filter on search/get):** every
/// implementation MUST scope `search`/`get_by_id` to `tenant` — never
/// return, and never let a caller distinguish "exists in another tenant"
/// from "doesn't exist" (`get_by_id` answers `None` for both, see
/// [`ElasticsearchStore::get_by_id`]). `tenant` is always the caller's
/// `skauswatch_auth::TenantContext` value, decoded from a validated JWT by
/// the router-wide `tenant_middleware` layer (`routes::events::router`) —
/// never a client-supplied path/body/query value.
#[async_trait::async_trait]
pub trait EventStore: Send + Sync {
    /// Runs a search scoped to `tenant` and returns matching events plus
    /// paging metadata.
    async fn search(
        &self,
        req: &EventSearchRequest,
        tenant: &str,
    ) -> Result<EventSearchResponse, ApiError>;

    /// Fetches a single event by id, scoped to `tenant`: `None` both when no
    /// document with `id` exists at all and when it exists but belongs to a
    /// different tenant (see trait docs — this must not become a
    /// cross-tenant existence oracle).
    async fn get_by_id(&self, id: &str, tenant: &str) -> Result<Option<BaseEvent>, ApiError>;

    /// Indexes/stores an event. Not reachable from any HTTP route today
    /// (v1 only ever populated events via the log collectors, which are a
    /// tracked follow-up — see `src/main.rs` module docs); kept so the
    /// store is ready for that port and so the write path has real,
    /// tested query construction now rather than later.
    ///
    /// **Tenant provenance flag (see `docs/v2-port/tenancy-model.md` §3):**
    /// this method does not stamp `event.tenant_id` itself — there is no
    /// active caller today to derive a trusted tenant from (no ingest
    /// route exists in this service; events are only ever produced by the
    /// not-yet-ported log collectors). Whichever future caller wires this
    /// up MUST set `event.tenant_id` from a trusted, server-side source
    /// (matching the collector's authenticated identity) before calling —
    /// never from a field the collector's own client input controls. This
    /// is intentionally left as an open item for that follow-up rather than
    /// guessed at here.
    #[allow(dead_code)] // no ingest route calls this yet — see doc comment
    async fn index_event(&self, event: &BaseEvent) -> Result<(), ApiError>;
}

/// Builds the ES/OpenSearch `_search` request body for an
/// [`EventSearchRequest`], scoped to `tenant`. v1 `LogProcessor
/// ._search_elasticsearch` — see `models.rs` module docs for why the v1
/// field names couldn't be preserved (they didn't exist on the real
/// request model).
///
/// The `tenant_id` term filter is always present (not conditional on any
/// other filter being set) — `tenant` is required non-empty upstream by
/// `skauswatch_auth::Claims::require_tenant`/`tenant_middleware`, so an
/// unfiltered "match everything" query would mean "match everything across
/// every tenant", which is exactly the isolation boundary this filter
/// exists to close. A request with no other filters therefore still
/// narrows to "every event belonging to the caller's tenant", not the v1
/// behavior of every event in the index.
pub fn build_search_body(req: &EventSearchRequest, tenant: &str) -> Value {
    let mut must: Vec<Value> = vec![json!({"term": {"tenant_id": tenant}})];

    if !req.sources.is_empty() {
        must.push(json!({"terms": {"source": req.sources}}));
    }
    if !req.event_types.is_empty() {
        must.push(json!({"terms": {"event_type": req.event_types}}));
    }
    if !req.severities.is_empty() {
        must.push(json!({"terms": {"severity": req.severities}}));
    }
    if req.start_time.is_some() || req.end_time.is_some() {
        let mut range = serde_json::Map::new();
        if let Some(start) = req.start_time {
            range.insert("gte".to_owned(), Value::from(start.to_rfc3339()));
        }
        if let Some(end) = req.end_time {
            range.insert("lte".to_owned(), Value::from(end.to_rfc3339()));
        }
        must.push(json!({"range": {"timestamp": range}}));
    }
    if !req.query.is_empty() {
        must.push(json!({
            "multi_match": {
                "query": req.query,
                "fields": ["message", "processed_data.*"],
            }
        }));
    }

    // `must` always carries at least the tenant term (seeded above), so the
    // v1-derived `match_all` fallback for "no filters at all" no longer
    // applies — see the doc comment above.
    let query = json!({"bool": {"must": must}});

    let mut sort_field = serde_json::Map::new();
    sort_field.insert(
        req.sort_by.clone(),
        json!({"order": req.sort_order.clone()}),
    );

    json!({
        "query": query,
        "from": req.offset,
        "size": req.limit,
        "sort": [Value::Object(sort_field)],
    })
}

/// Shapes a `_search` response into [`EventSearchResponse`], correctly
/// populating `total` (v1 bug fixed — see `models.rs` module docs).
fn shape_search_response(
    resp: &Value,
    limit: i64,
    offset: i64,
    query_time_ms: f64,
) -> Result<EventSearchResponse, ApiError> {
    let total = resp
        .pointer("/hits/total/value")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::internal("elasticsearch response", "missing hits.total.value"))?;
    let hits = resp
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::internal("elasticsearch response", "missing hits.hits"))?;

    let mut events = Vec::with_capacity(hits.len());
    for hit in hits {
        let source = hit
            .get("_source")
            .cloned()
            .ok_or_else(|| ApiError::internal("elasticsearch response", "hit missing _source"))?;
        let event: BaseEvent = serde_json::from_value(source)
            .map_err(|e| ApiError::internal("elasticsearch response", e))?;
        events.push(event);
    }

    Ok(EventSearchResponse {
        events,
        total,
        limit,
        offset,
        query_time_ms,
    })
}

/// Elasticsearch/OpenSearch-backed [`EventStore`], talking to the REST API
/// directly (house pattern — no ES client crate).
pub struct ElasticsearchStore {
    client: reqwest::Client,
    base_url: String,
    index_pattern: String,
    auth: Option<(String, String)>,
}

impl ElasticsearchStore {
    /// Builds a store against `base_url` (e.g. `http://elasticsearch:9200`)
    /// searching over `index_pattern` (v1 default `aaa-events-*`).
    pub fn new(
        base_url: impl Into<String>,
        index_pattern: impl Into<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            index_pattern: index_pattern.into(),
            auth: username.zip(password),
        }
    }

    fn request(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            Some((user, pass)) => builder.basic_auth(user, Some(pass)),
            None => builder,
        }
    }

    /// Date-rotated index name for a write, matching v1's
    /// `aaa-events-{YYYY-MM}` scheme.
    #[allow(dead_code)] // only called from index_event, itself unreached — see trait doc comment
    fn write_index_for(event: &BaseEvent) -> String {
        format!("aaa-events-{}", event.timestamp.format("%Y-%m"))
    }
}

#[async_trait::async_trait]
impl EventStore for ElasticsearchStore {
    async fn search(
        &self,
        req: &EventSearchRequest,
        tenant: &str,
    ) -> Result<EventSearchResponse, ApiError> {
        let body = build_search_body(req, tenant);
        let start = std::time::Instant::now();
        let resp = self
            .request(
                self.client
                    .post(format!("{}/{}/_search", self.base_url, self.index_pattern)),
            )
            .json(&body)
            .send()
            .await
            .map_err(|e| ApiError::internal("elasticsearch request", e))?
            .error_for_status()
            .map_err(|e| ApiError::internal("elasticsearch status", e))?;
        let json: Value = resp
            .json()
            .await
            .map_err(|e| ApiError::internal("elasticsearch response", e))?;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        shape_search_response(&json, req.limit, req.offset, elapsed_ms)
    }

    async fn get_by_id(&self, id: &str, tenant: &str) -> Result<Option<BaseEvent>, ApiError> {
        let resp = self
            .request(self.client.get(format!(
                "{}/{}/_doc/{}",
                self.base_url, self.index_pattern, id
            )))
            .send()
            .await
            .map_err(|e| ApiError::internal("elasticsearch request", e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp
            .error_for_status()
            .map_err(|e| ApiError::internal("elasticsearch status", e))?;
        let json: Value = resp
            .json()
            .await
            .map_err(|e| ApiError::internal("elasticsearch response", e))?;
        let source = json
            .get("_source")
            .cloned()
            .ok_or_else(|| ApiError::internal("elasticsearch response", "missing _source"))?;
        let event: BaseEvent = serde_json::from_value(source)
            .map_err(|e| ApiError::internal("elasticsearch response", e))?;
        // Tenant isolation (trait docs): a document belonging to another
        // tenant answers exactly like a missing one — never distinguish
        // "exists elsewhere" from "doesn't exist" for the caller.
        if event.tenant_id != tenant {
            return Ok(None);
        }
        Ok(Some(event))
    }

    async fn index_event(&self, event: &BaseEvent) -> Result<(), ApiError> {
        let index = Self::write_index_for(event);
        self.request(
            self.client
                .put(format!("{}/{}/_doc/{}", self.base_url, index, event.id)),
        )
        .json(event)
        .send()
        .await
        .map_err(|e| ApiError::internal("elasticsearch request", e))?
        .error_for_status()
        .map_err(|e| ApiError::internal("elasticsearch status", e))?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::models::{EventType, LogSource, Severity};
    use chrono::{TimeZone, Utc};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn search_body_with_no_filters_still_scopes_to_tenant() {
        // v1 (and this code, pre-tenancy) treated an unfiltered request as
        // `match_all` — every event in the index. Post-tenancy, "no filters"
        // must still mean "every event belonging to my tenant", never the
        // whole index (finding: no tenant filter on ES queries).
        let req = EventSearchRequest::default();
        let body = build_search_body(&req, "tenant-a");
        assert_eq!(
            body["query"],
            json!({"bool": {"must": [{"term": {"tenant_id": "tenant-a"}}]}})
        );
        assert_eq!(body["from"], 0);
        assert_eq!(body["size"], 50);
        assert_eq!(body["sort"][0]["timestamp"]["order"], "desc");
    }

    #[test]
    fn search_body_tenant_filter_is_scoped_to_the_calling_tenant() {
        let req = EventSearchRequest::default();
        let body_a = build_search_body(&req, "tenant-a");
        let body_b = build_search_body(&req, "tenant-b");
        assert_eq!(
            body_a["query"]["bool"]["must"][0],
            json!({"term": {"tenant_id": "tenant-a"}})
        );
        assert_eq!(
            body_b["query"]["bool"]["must"][0],
            json!({"term": {"tenant_id": "tenant-b"}})
        );
        assert_ne!(body_a, body_b);
    }

    #[test]
    fn search_body_builds_filters_and_time_range() {
        let req = EventSearchRequest {
            query: "login failed".to_owned(),
            sources: vec![LogSource::Kubernetes],
            event_types: vec![EventType::Authentication],
            severities: vec![Severity::High, Severity::Critical],
            start_time: Some(Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap()),
            end_time: Some(Utc.with_ymd_and_hms(2026, 7, 2, 0, 0, 0).unwrap()),
            sort_by: "timestamp".to_owned(),
            sort_order: "asc".to_owned(),
            limit: 25,
            offset: 10,
        };
        let body = build_search_body(&req, "tenant-a");
        let must = body["query"]["bool"]["must"].as_array().unwrap();
        assert_eq!(must.len(), 6);
        assert_eq!(must[0], json!({"term": {"tenant_id": "tenant-a"}}));
        assert_eq!(must[1], json!({"terms": {"source": ["kubernetes"]}}));
        assert_eq!(
            must[2],
            json!({"terms": {"event_type": ["authentication"]}})
        );
        assert_eq!(
            must[3],
            json!({"terms": {"severity": ["high", "critical"]}})
        );
        assert_eq!(
            must[4],
            json!({"range": {"timestamp": {"gte": "2026-07-01T00:00:00+00:00", "lte": "2026-07-02T00:00:00+00:00"}}})
        );
        assert_eq!(
            must[5],
            json!({"multi_match": {"query": "login failed", "fields": ["message", "processed_data.*"]}})
        );
        assert_eq!(body["from"], 10);
        assert_eq!(body["size"], 25);
        assert_eq!(body["sort"][0]["timestamp"]["order"], "asc");
    }

    #[test]
    fn shape_search_response_populates_total_correctly() {
        let raw = json!({
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_source": {"id": "e1", "source": "auditd", "event_type": "process", "severity": "low", "message": "m1"}},
                    {"_source": {"id": "e2", "source": "auditd", "event_type": "process", "severity": "low", "message": "m2"}},
                ],
            },
        });
        let resp = match shape_search_response(&raw, 50, 0, 3.5) {
            Ok(r) => r,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(resp.total, 2);
        assert_eq!(resp.events.len(), 2);
        assert_eq!(resp.events[0].id, "e1");
        assert_eq!(resp.query_time_ms, 3.5);
    }

    #[test]
    fn shape_search_response_rejects_malformed_upstream_shape() {
        assert!(matches!(
            shape_search_response(&json!({}), 50, 0, 0.0),
            Err(ApiError::Internal)
        ));
    }

    #[tokio::test]
    async fn store_search_sends_body_to_search_endpoint_and_parses_hits() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aaa-events-*/_search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hits": {"total": {"value": 1}, "hits": [
                    {"_source": {"id": "e1", "source": "system", "event_type": "process", "severity": "info", "message": "hi", "tenant_id": "tenant-a"}}
                ]},
            })))
            .mount(&server)
            .await;

        let store = ElasticsearchStore::new(server.uri(), "aaa-events-*", None, None);
        let req = EventSearchRequest {
            limit: 50,
            ..Default::default()
        };
        let resp = match store.search(&req, "tenant-a").await {
            Ok(r) => r,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(resp.total, 1);
        assert_eq!(resp.events[0].id, "e1");
    }

    /// End-to-end wiring check (not just the pure `build_search_body` unit
    /// tests above): the HTTP request this store actually sends to
    /// Elasticsearch carries the caller's tenant filter.
    #[tokio::test]
    async fn store_search_sends_the_tenant_filter_to_elasticsearch() {
        use wiremock::matchers::body_json;

        let server = MockServer::start().await;
        let req = EventSearchRequest::default();
        Mock::given(method("POST"))
            .and(path("/aaa-events-*/_search"))
            .and(body_json(build_search_body(&req, "tenant-a")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hits": {"total": {"value": 0}, "hits": []},
            })))
            .mount(&server)
            .await;

        let store = ElasticsearchStore::new(server.uri(), "aaa-events-*", None, None);
        // Wiremock rejects with a 404 (no matching mock) if the sent body
        // doesn't equal the `tenant-a`-scoped body above, so a passing
        // `Ok` here already proves the tenant filter went out on the wire;
        // the explicit total==0 assertion also rules out a stray match on
        // some other, unscoped mock.
        let resp = match store.search(&req, "tenant-a").await {
            Ok(r) => r,
            Err(e) => panic!("expected ok (tenant filter must be present), got {e:?}"),
        };
        assert_eq!(resp.total, 0);
    }

    #[tokio::test]
    async fn store_get_by_id_returns_none_on_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/aaa-events-*/_doc/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let store = ElasticsearchStore::new(server.uri(), "aaa-events-*", None, None);
        let found = match store.get_by_id("missing", "tenant-a").await {
            Ok(f) => f,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert!(found.is_none());
    }

    /// Cross-tenant isolation regression: a document that genuinely exists
    /// but belongs to a different tenant must answer identically to a
    /// missing document — never leak "it exists, just not for you".
    #[tokio::test]
    async fn store_get_by_id_hides_a_document_owned_by_another_tenant() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/aaa-events-*/_doc/e1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "_source": {"id": "e1", "source": "system", "event_type": "process", "severity": "info", "message": "hi", "tenant_id": "tenant-b"},
            })))
            .mount(&server)
            .await;

        let store = ElasticsearchStore::new(server.uri(), "aaa-events-*", None, None);
        let found = match store.get_by_id("e1", "tenant-a").await {
            Ok(f) => f,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert!(found.is_none(), "tenant-a must not see tenant-b's event");
    }

    #[tokio::test]
    async fn store_get_by_id_returns_a_document_owned_by_the_caller() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/aaa-events-*/_doc/e1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "_source": {"id": "e1", "source": "system", "event_type": "process", "severity": "info", "message": "hi", "tenant_id": "tenant-a"},
            })))
            .mount(&server)
            .await;

        let store = ElasticsearchStore::new(server.uri(), "aaa-events-*", None, None);
        let found = match store.get_by_id("e1", "tenant-a").await {
            Ok(f) => f,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(found.map(|e| e.id), Some("e1".to_owned()));
    }

    #[tokio::test]
    async fn store_index_event_puts_to_date_rotated_index() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/aaa-events-2026-07/_doc/e1"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let store = ElasticsearchStore::new(server.uri(), "aaa-events-*", None, None);
        let event = BaseEvent {
            id: "e1".to_owned(),
            source: LogSource::System,
            event_type: EventType::Process,
            severity: Severity::Info,
            message: "hi".to_owned(),
            timestamp: Utc.with_ymd_and_hms(2026, 7, 15, 0, 0, 0).unwrap(),
            raw_data: Value::Null,
            tags: vec![],
            host: String::new(),
            user: None,
            process: None,
            pid: None,
            enrichments: Value::Null,
            threat_matches: vec![],
            ai_analysis: None,
            processed_data: Value::Null,
            tenant_id: "tenant-a".to_owned(),
            extra: Default::default(),
        };
        if let Err(e) = store.index_event(&event).await {
            panic!("expected ok, got {e:?}");
        }
    }
}
