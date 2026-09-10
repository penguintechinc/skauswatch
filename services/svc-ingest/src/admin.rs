//! Admin settings API — ISM hot/warm/cold tiering configuration + restore
//! trigger — stub until Task 2.1 fills this in (see
//! `docs/v2-port/ingest-module-spec.md` §8a1).

/// Placeholder admin router — Task 2.1 replaces this with the real `PUT
/// /api/v1/admin/ingest/lifecycle` / `POST
/// /api/v1/admin/ingest/restore` routes.
// dead_code: unwired until the Wave-1 integration gate merges every
// listener/writer module into `main.rs::serve()` (see that file's doc
// comment) — this stub is legitimately unreferenced until then.
#[allow(dead_code)]
pub fn router() -> axum::Router {
    axum::Router::new()
}
