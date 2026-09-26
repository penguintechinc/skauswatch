//! Threat intelligence: aaa-monitor's own TAXII 2.x feed-polling engine.
//!
//! **Disambiguation (read this before touching either subsystem):** this
//! module and `services/manager/src/routes/threat_intel.rs` are two
//! unrelated v1 subsystems that happen to share the phrase "threat intel".
//! Manager's module is IOC CRUD + bulk upsert + search + a *static* feed
//! catalog backed by Postgres `threat_indicators`, a faithful, already-
//! shipped port of v1 `services/manager/api/v1/threat_intel.py`. This
//! module is aaa-monitor's real-time TAXII 2.x feed poller (v1
//! `threat_intel/taxii_client.py` + `stix_parser.py` +
//! `indicator_matcher.py` + `threat_database.py`), which automatically
//! discovers TAXII collections, fetches STIX indicator objects, stores them,
//! and matches them against ingested events (`crate::ingest`). Neither
//! subsystem's schema, routes, or code should be merged into the other —
//! see `docs/v2-port/phase12-scope-scan-monitor.md` §2 for the full
//! grep-verified history of why v1 ended up with two.
//!
//! v1's `main.py` mounted ~15 REST routes on top of the TAXII engine that
//! called `ThreatDatabase` methods existing nowhere in the v1 codebase
//! (`get_iocs_advanced`, `add_ioc`, `bulk_add_iocs`, `get_matches_by_event`,
//! `get_feed_status_enhanced`, `add_feed`, `get_feed_by_id`, `update_feed`,
//! `get_health_status`, ...) — every one 500s unconditionally in v1. Those
//! routes are not restored. [`routes`] is a small, new, read-only surface
//! (search indicators, get indicator, list feed status) designed against
//! what [`store::ThreatStore`] actually implements — admin feed CRUD over
//! REST is deferred; feeds are configured via `MONITOR_TAXII_FEED_URLS`
//! (`taxii::TaxiiConfig`) and seeded at startup.

pub mod matcher;
pub mod routes;
pub mod stix;
pub mod store;
pub mod taxii;
