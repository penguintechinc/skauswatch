//! Common error taxonomy shared across skauswatch services.
//! Service crates wrap these in their own error types where they need more
//! context; handlers map them onto HTTP/gRPC status codes at the edge.

/// Cross-cutting error type for shared infrastructure crates.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration was missing or malformed at startup.
    #[error("configuration error: {0}")]
    Config(String),

    /// A downstream dependency (DB, cache, HTTP API) failed.
    #[error("dependency error: {0}")]
    Dependency(String),

    /// Input failed validation before processing.
    #[error("validation error: {0}")]
    Validation(String),

    /// The caller is not authorized for the operation.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}
