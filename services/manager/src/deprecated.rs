//! Shared middleware for the module-rename deprecated REST aliases
//! (`/api/v1/{edr,vault,darwin,aaa}/*` — see docs/MIGRATION.md). Every
//! response served through a legacy alias sub-router carries `Deprecation`
//! and `Sunset` headers so clients can detect and migrate off the old paths;
//! the alias forwards to the exact same handlers as the canonical route, so
//! behavior is unaffected — only the headers differ.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// RFC 8594 `Sunset` date for the deprecated module-rename REST aliases —
/// ~12 months out per `backend.md` API versioning notice policy.
const SUNSET_DATE: &str = "Thu, 01 Jul 2027 00:00:00 GMT";

/// Tags every response from a legacy alias sub-router as deprecated.
pub async fn deprecated_alias(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("deprecation", HeaderValue::from_static("true"));
    headers.insert("sunset", HeaderValue::from_static(SUNSET_DATE));
    response
}
