//! SkausWatch EDR endpoint agent library — process/file/network collectors
//! reporting security events to the SkausWatch manager over its
//! HMAC-authenticated `/api/v1/edr/*` REST protocol.
//!
//! Split into a library + thin binary (`src/main.rs`) so integration tests
//! under `tests/` can exercise config loading, HMAC computation, and
//! request construction directly, and so `wiremock`-backed tests can drive
//! `transport::Reporter` without a real manager.

pub mod agent;
pub mod collectors;
pub mod config;
#[cfg(test)]
pub(crate) mod test_support;
pub mod transport;
