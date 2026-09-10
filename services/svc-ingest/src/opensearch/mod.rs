//! OpenSearch `_bulk` write + index lifecycle for the unified
//! `skauswatch-logs-*` lake — stub until Task 1.5 fills in `daily_index`/
//! `write_bulk` (ported from `services/logs/src/opensearch.rs`; see
//! `docs/v2-port/ingest-module-spec.md` §8). Task 2.1 adds a sibling
//! `ism.rs` for hot/warm/cold tiering.

/// Placeholder — Task 1.5 replaces this with the real bulk-write client.
// dead_code: unreferenced until Task 1.5 wires this into `crate::writer`.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct OpenSearchWriter;
