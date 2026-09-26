//! Shared test harness for skauswatch services: isolated-schema Postgres
//! pools ([`db::test_pool`]), manager-shaped JWT minting ([`jwt`]), and
//! dev/gated `LicenseClient` builders ([`license`]). See
//! `docs/v2-port/testing-pattern.md` for the full pattern (how to wire this
//! into a service's `AppStateInner::for_tests_with_db`, how to write an
//! authed/unauthed handler test, and how to run coverage locally against a
//! real database).
//!
//! Dev-only by construction: every function here either panics loudly on
//! infrastructure failure or is `#[cfg(test)]`-only within its own module —
//! nothing in this crate is meant to run in a production binary.

pub mod db;
pub mod jwt;
pub mod license;
