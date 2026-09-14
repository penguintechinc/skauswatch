//! SSRF hardening for ASM scan targets.
//!
//! **Regression coverage for a CONFIRMED HIGH security-review finding**:
//! `asm_scans.target` previously reached `masscan` and, for every open
//! HTTP(S) port, headless Chromium (`crate::asm::capture_screenshot`) with
//! only an empty/length check — no block on link-local (including
//! `169.254.169.254`, the AWS IMDS well-known address), loopback, or
//! RFC1918/CGNAT ranges, and no asset-ownership check. An ordinary tenant
//! (`admin`/`maintainer` role) could point the platform's own scanner at
//! cloud metadata or internal services and have the screenshot/banner/cert
//! results handed back to them. See
//! `services/manager/src/routes/asm.rs`'s `validate_target_safety` for the
//! lighter creation-time layer this module's checks are mirrored from.
//!
//! Two checks live here, both required — creation-time validation alone is
//! bypassable via DNS rebinding (a domain resolves to a public IP when the
//! manager checks it, then to a private/metadata IP by the time this
//! worker actually connects):
//!
//! 1. [`resolve_target_for_masscan`] — called once per scan, before
//!    `masscan` ever runs. A literal IP/CIDR target is checked directly;
//!    a domain name is resolved *here* (masscan is never handed a
//!    hostname, closing off any question of whether masscan's own
//!    resolver might disagree with ours) and every resolved address is
//!    checked, with only the safe subset passed on.
//! 2. [`is_blocked_ip`] — called again by `crate::asm::run_asm_scan` for
//!    every individual IP masscan reports as open, immediately before the
//!    banner-grab/cert-fetch/screenshot stages act on it. This is the
//!    layer that actually stops rebinding: it re-checks the address
//!    masscan *actually* connected to, not the one resolved a scan-length
//!    duration earlier.
//!
//! Ownership/asset-verification (v1's `scan_targets` FK model) is
//! intentionally **not** restored here — out of scope for this hotfix,
//! which closes the SSRF path via IP-range validation; see
//! `docs/v2-port/phase12-scope-scan-monitor.md` for the tracked follow-up
//! to add a per-tenant target-allowlist/verification gate.
//!
//! No `ipnet`-style crate dependency: the blocked-range list is small and
//! fixed, so plain `u32`/`u128` mask arithmetic (tested below) keeps this
//! a pure-`std` addition rather than a new workspace dependency.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// How long a domain-name resolution may take before the scan fails
/// closed rather than hanging the worker on a slow or unresponsive
/// resolver.
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// IPv4 ranges disallowed as scan destinations: "this network"/
/// unspecified, RFC1918 private space, CGNAT (RFC6598), loopback,
/// link-local (which includes the cloud IMDS well-known address
/// `169.254.169.254`), and multicast.
const BLOCKED_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
];

/// IPv6 ranges disallowed as scan destinations: loopback, unique-local
/// (ULA — the IPv6 analogue of RFC1918), link-local, and multicast.
const BLOCKED_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::LOCALHOST, 128),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];

/// Inclusive `[network, broadcast]` bounds of `addr/prefix`. `prefix` is
/// clamped to 32 (a caller-supplied prefix wider than that is already
/// rejected by [`classify`] before this runs).
fn v4_bounds(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let addr = u32::from(addr);
    if prefix == 0 {
        (0, u32::MAX)
    } else if prefix >= 32 {
        (addr, addr)
    } else {
        let mask = !0u32 << (32 - prefix);
        let network = addr & mask;
        (network, network | !mask)
    }
}

/// Inclusive `[network, broadcast]` bounds of `addr/prefix` (IPv6 analogue
/// of [`v4_bounds`]).
fn v6_bounds(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
    let addr = u128::from(addr);
    if prefix == 0 {
        (0, u128::MAX)
    } else if prefix >= 128 {
        (addr, addr)
    } else {
        let mask = !0u128 << (128 - prefix);
        let network = addr & mask;
        (network, network | !mask)
    }
}

/// True if `ip` falls within any disallowed range. IPv4-mapped IPv6
/// addresses (`::ffff:a.b.c.d`) are normalized to plain IPv4 first via
/// [`IpAddr::to_canonical`] — a well-known blocklist-bypass technique
/// otherwise (an attacker supplying the mapped form to dodge a v4-only
/// check).
#[must_use]
pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let point = u32::from(v4);
            BLOCKED_V4
                .iter()
                .any(|&(net, prefix)| point_in(point, v4_bounds(net, prefix)))
        }
        IpAddr::V6(v6) => {
            let point = u128::from(v6);
            BLOCKED_V6
                .iter()
                .any(|&(net, prefix)| point_in(point, v6_bounds(net, prefix)))
        }
    }
}

fn point_in<T: PartialOrd>(point: T, bounds: (T, T)) -> bool {
    bounds.0 <= point && point <= bounds.1
}

/// True if `addr/prefix` overlaps any disallowed range in either
/// direction — the requested CIDR might itself sit inside a blocked range
/// (e.g. `169.254.1.0/24`), or be broad enough to swallow one (e.g.
/// `0.0.0.0/0`, `10.0.0.0/7`).
#[must_use]
fn is_blocked_cidr(addr: IpAddr, prefix: u8) -> bool {
    match addr.to_canonical() {
        IpAddr::V4(v4) => {
            let req = v4_bounds(v4, prefix);
            BLOCKED_V4
                .iter()
                .any(|&(net, net_prefix)| ranges_overlap(req, v4_bounds(net, net_prefix)))
        }
        IpAddr::V6(v6) => {
            let req = v6_bounds(v6, prefix);
            BLOCKED_V6
                .iter()
                .any(|&(net, net_prefix)| ranges_overlap(req, v6_bounds(net, net_prefix)))
        }
    }
}

fn ranges_overlap<T: PartialOrd>(a: (T, T), b: (T, T)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// How a raw scan `target` string parses: a literal address, a CIDR
/// block, or (falling through both) a domain name pending DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetKind {
    /// A literal IPv4 or IPv6 address.
    Ip(IpAddr),
    /// A literal CIDR block (`addr/prefix`).
    Cidr(IpAddr, u8),
    /// Anything else — treated as a hostname to resolve.
    Domain(String),
}

/// Classifies a raw `target` string with no I/O: literal IP/CIDR forms
/// are recognized syntactically; anything else is a domain name.
#[must_use]
pub(crate) fn classify(target: &str) -> TargetKind {
    if let Some((addr_part, prefix_part)) = target.split_once('/')
        && let (Ok(addr), Ok(prefix)) = (addr_part.parse::<IpAddr>(), prefix_part.parse::<u8>())
    {
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix <= max_prefix {
            return TargetKind::Cidr(addr, prefix);
        }
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return TargetKind::Ip(ip);
    }
    TargetKind::Domain(target.to_owned())
}

/// Reason a target was rejected before reaching `masscan` — safe to store
/// verbatim in `asm_scans.error_message` and to log.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(crate) enum TargetSafetyError {
    /// The literal target, or every address a domain resolved to, falls
    /// within a disallowed range.
    #[error(
        "target '{0}' resolves to a disallowed address range (link-local/metadata, loopback, \
         private, CGNAT, or multicast)"
    )]
    Blocked(String),
    /// DNS resolution of a domain-form target failed or timed out.
    #[error("target '{host}' could not be resolved: {reason}")]
    ResolutionFailed {
        /// The domain name that failed to resolve.
        host: String,
        /// Why resolution failed (I/O error message or timeout).
        reason: String,
    },
}

/// DNS-resolves `host` (bounded by [`DNS_RESOLVE_TIMEOUT`]) and returns
/// every resolved address. Only called for domain-form targets — literal
/// IP/CIDR targets never reach this.
async fn resolve_domain(host: &str) -> Result<Vec<IpAddr>, TargetSafetyError> {
    let lookup =
        tokio::time::timeout(DNS_RESOLVE_TIMEOUT, tokio::net::lookup_host((host, 0))).await;
    match lookup {
        Ok(Ok(addrs)) => {
            let ips: Vec<IpAddr> = addrs.map(|sock| sock.ip()).collect();
            if ips.is_empty() {
                Err(TargetSafetyError::ResolutionFailed {
                    host: host.to_owned(),
                    reason: "resolver returned no addresses".to_owned(),
                })
            } else {
                Ok(ips)
            }
        }
        Ok(Err(e)) => Err(TargetSafetyError::ResolutionFailed {
            host: host.to_owned(),
            reason: e.to_string(),
        }),
        Err(_) => Err(TargetSafetyError::ResolutionFailed {
            host: host.to_owned(),
            reason: format!("timed out after {DNS_RESOLVE_TIMEOUT:?}"),
        }),
    }
}

/// Resolves `target` to the exact address(es) `masscan` should scan,
/// enforcing the SSRF blocklist immediately before dispatch — see the
/// module doc for why this is the critical anti-rebinding layer. A
/// literal IP/CIDR target is checked directly and returned unchanged; a
/// domain name is resolved here and every resolved address checked
/// individually, with only the safe subset (comma-joined, masscan's
/// multi-target syntax) passed on. Never returns a target string that
/// would let `masscan` (or anything downstream of it) reach a blocked
/// address.
pub(crate) async fn resolve_target_for_masscan(target: &str) -> Result<String, TargetSafetyError> {
    match classify(target) {
        TargetKind::Ip(ip) => {
            if is_blocked_ip(ip) {
                return Err(TargetSafetyError::Blocked(target.to_owned()));
            }
            Ok(target.to_owned())
        }
        TargetKind::Cidr(addr, prefix) => {
            if is_blocked_cidr(addr, prefix) {
                return Err(TargetSafetyError::Blocked(target.to_owned()));
            }
            Ok(target.to_owned())
        }
        TargetKind::Domain(host) => {
            let resolved = resolve_domain(&host).await?;
            let safe: Vec<String> = resolved
                .into_iter()
                .filter(|ip| !is_blocked_ip(*ip))
                .map(|ip| ip.to_string())
                .collect();
            if safe.is_empty() {
                return Err(TargetSafetyError::Blocked(host));
            }
            Ok(safe.join(","))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    // ---------- is_blocked_ip: every required v4 range ----------

    #[test]
    fn blocks_aws_imds_link_local() {
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn blocks_v4_loopback() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918_ranges() {
        assert!(is_blocked_ip("10.1.2.3".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.31.255.254".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn blocks_unspecified_and_cgnat_and_multicast() {
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("100.127.255.254".parse().unwrap()));
        assert!(is_blocked_ip("224.0.0.1".parse().unwrap()));
    }

    // ---------- is_blocked_ip: every required v6 range ----------

    #[test]
    fn blocks_v6_loopback() {
        assert!(is_blocked_ip("::1".parse().unwrap()));
    }

    #[test]
    fn blocks_v6_ula_and_link_local_and_multicast() {
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fd12:3456:789a::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("ff02::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_bypass_attempt() {
        // `::ffff:169.254.169.254` — a classic blocklist-bypass encoding
        // of the AWS IMDS address; must normalize to v4 and still block.
        assert!(is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    // ---------- representative allowed public targets ----------

    #[test]
    fn allows_public_v4_addresses() {
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn allows_public_v6_addresses() {
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    // ---------- CIDR overlap, both directions ----------

    #[test]
    fn cidr_inside_a_blocked_range_is_blocked() {
        assert!(is_blocked_cidr("169.254.1.0".parse().unwrap(), 24));
        assert!(is_blocked_cidr("192.168.1.0".parse().unwrap(), 24));
    }

    #[test]
    fn cidr_broader_than_a_blocked_range_is_blocked() {
        // 0.0.0.0/0 and 10.0.0.0/7 both swallow whole blocked ranges even
        // though their own network address isn't itself inside one.
        assert!(is_blocked_cidr("0.0.0.0".parse().unwrap(), 0));
        assert!(is_blocked_cidr("10.0.0.0".parse().unwrap(), 7));
    }

    #[test]
    fn cidr_v6_ula_supernet_is_blocked() {
        assert!(is_blocked_cidr("fc00::".parse().unwrap(), 6));
    }

    #[test]
    fn public_cidr_is_allowed() {
        assert!(!is_blocked_cidr("203.0.113.0".parse().unwrap(), 24));
        assert!(!is_blocked_cidr("2606:4700::".parse().unwrap(), 32));
    }

    // ---------- classify ----------

    #[test]
    fn classify_recognizes_ip_cidr_and_domain() {
        assert_eq!(
            classify("203.0.113.5"),
            TargetKind::Ip("203.0.113.5".parse().unwrap())
        );
        assert_eq!(
            classify("203.0.113.0/24"),
            TargetKind::Cidr("203.0.113.0".parse().unwrap(), 24)
        );
        assert_eq!(
            classify("scan-target.example"),
            TargetKind::Domain("scan-target.example".to_owned())
        );
    }

    #[test]
    fn classify_rejects_cidr_prefix_wider_than_address_family_max() {
        // Not valid CIDR (prefix > 32 for v4) — falls through to domain
        // classification rather than panicking on bad shift math later.
        assert_eq!(
            classify("203.0.113.5/99"),
            TargetKind::Domain("203.0.113.5/99".to_owned())
        );
    }

    // ---------- resolve_target_for_masscan ----------

    #[tokio::test]
    async fn resolve_rejects_literal_blocked_ip() {
        let err = resolve_target_for_masscan("169.254.169.254")
            .await
            .unwrap_err();
        assert!(matches!(err, TargetSafetyError::Blocked(_)));
    }

    #[tokio::test]
    async fn resolve_rejects_literal_blocked_cidr() {
        let err = resolve_target_for_masscan("10.0.0.0/8").await.unwrap_err();
        assert!(matches!(err, TargetSafetyError::Blocked(_)));
    }

    #[tokio::test]
    async fn resolve_passes_through_literal_public_ip_and_cidr() {
        assert_eq!(
            resolve_target_for_masscan("203.0.113.5").await.unwrap(),
            "203.0.113.5"
        );
        assert_eq!(
            resolve_target_for_masscan("203.0.113.0/24").await.unwrap(),
            "203.0.113.0/24"
        );
    }

    /// The critical anti-rebinding regression case: a domain name that
    /// resolves to a loopback/private address must be dropped, never
    /// handed to masscan. `localhost` is used because it resolves via
    /// `/etc/hosts` (or the platform equivalent) on every environment,
    /// including one with no outbound DNS/network egress — so this test
    /// exercises real resolution without depending on network access.
    #[tokio::test]
    async fn resolve_drops_domain_resolving_to_loopback() {
        let err = resolve_target_for_masscan("localhost").await.unwrap_err();
        assert!(matches!(err, TargetSafetyError::Blocked(_)));
    }
}
