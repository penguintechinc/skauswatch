//! Per-IP request-rate limiting env knobs for `crate::routes::router`'s
//! `tower_governor::GovernorLayer` wiring (security audit finding: rate
//! limiting — sshca's REST surface, including certificate issuance and
//! revocation for an SSH CA signing key, previously had no request-rate
//! defense at all).
//!
//! See `services/pki/src/ratelimit.rs` for the full design rationale
//! (deliberately plain-primitive-returning, testable-without-env-mutation
//! `*_from` functions, and the custom `KeyExtractor` below) — this module
//! mirrors it exactly for sshca.

use std::net::{IpAddr, Ipv4Addr};

use axum::extract::ConnectInfo;
use axum::http::Request;
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

/// Rate-limits per source IP when one is available
/// (`ConnectInfo<SocketAddr>`, present on every real connection once the
/// listener is served via `.into_make_service_with_connect_info` — see
/// `main.rs`), and falls back to a single shared bucket rather than
/// erroring when it isn't (in-process test harnesses have no real socket).
/// The stock `PeerIpKeyExtractor` returns
/// `GovernorError::UnableToExtractKey` (→ 500) in that case, which would
/// turn every test request into a false rate-limit failure.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerIpOrGlobalKeyExtractor;

impl KeyExtractor for PeerIpOrGlobalKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        Ok(req
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
    }
}

/// Sustained requests/second allowed per source IP.
fn per_second_from(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(10)
}

/// Burst capacity above the sustained rate.
fn burst_size_from(raw: Option<&str>) -> u32 {
    raw.and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(20)
}

/// Resolves `RATE_LIMIT_PER_SECOND` (default 10). Unset, unparseable, or
/// non-positive values fall back to the default rather than disabling the
/// limit.
pub fn per_second() -> u64 {
    per_second_from(std::env::var("RATE_LIMIT_PER_SECOND").ok().as_deref())
}

/// Resolves `RATE_LIMIT_BURST` (default 20). Same fallback behavior as
/// [`per_second`].
pub fn burst_size() -> u32 {
    burst_size_from(std::env::var("RATE_LIMIT_BURST").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_second_defaults_when_unset_or_invalid() {
        assert_eq!(per_second_from(None), 10);
        assert_eq!(per_second_from(Some("")), 10);
        assert_eq!(per_second_from(Some("not-a-number")), 10);
        assert_eq!(per_second_from(Some("0")), 10);
        assert_eq!(per_second_from(Some("-5")), 10);
    }

    #[test]
    fn per_second_honors_a_valid_override() {
        assert_eq!(per_second_from(Some("50")), 50);
    }

    #[test]
    fn burst_size_defaults_when_unset_or_invalid() {
        assert_eq!(burst_size_from(None), 20);
        assert_eq!(burst_size_from(Some("")), 20);
        assert_eq!(burst_size_from(Some("not-a-number")), 20);
        assert_eq!(burst_size_from(Some("0")), 20);
    }

    #[test]
    fn burst_size_honors_a_valid_override() {
        assert_eq!(burst_size_from(Some("100")), 100);
    }

    #[test]
    fn key_extractor_falls_back_to_unspecified_without_connect_info() {
        let req = Request::builder()
            .body(())
            .unwrap_or_else(|e| unreachable!("bodyless request builder is infallible: {e}"));
        let key = PeerIpOrGlobalKeyExtractor
            .extract(&req)
            .unwrap_or_else(|e| unreachable!("this extractor never errors: {e}"));
        assert_eq!(key, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn key_extractor_reads_the_real_peer_ip_when_present() {
        let mut req = Request::builder()
            .body(())
            .unwrap_or_else(|e| unreachable!("bodyless request builder is infallible: {e}"));
        let addr: std::net::SocketAddr = "203.0.113.7:4242"
            .parse()
            .unwrap_or_else(|e| unreachable!("fixed literal socket addr always parses: {e}"));
        req.extensions_mut().insert(ConnectInfo(addr));
        let key = PeerIpOrGlobalKeyExtractor
            .extract(&req)
            .unwrap_or_else(|e| unreachable!("this extractor never errors: {e}"));
        assert_eq!(key, addr.ip());
    }
}
