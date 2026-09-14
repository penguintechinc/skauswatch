//! Network connection collector — Rust port of v1
//! `internal/collectors/network.go`, using `netstat2` in place of
//! `gopsutil/v4/net` (both wrap the same per-OS socket tables: `/proc/net/*`
//! or netlink on Linux, `GetExtendedTcpTable` on Windows, `sysctl` on
//! macOS).
//!
//! Simplification vs v1 (same observable output): v1 queried both TCP and
//! UDP sockets, but its emit condition (`status == "ESTABLISHED" ||
//! status == "LISTEN"`) can never be true for a UDP socket (gopsutil never
//! reports a TCP-style status for UDP), so v1's UDP sockets were tracked in
//! `knownConns` but never produced an event. This port queries TCP sockets
//! only via `ProtocolFlags::TCP` — identical observable behavior, less
//! syscall overhead every poll.
//!
//! `established_only` (config field v1 declared but never read) is wired up
//! for real: `false` (the default, matching v1's hardcoded behavior)
//! reports both LISTEN and ESTABLISHED; `true` narrows to ESTABLISHED only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};
use tokio::sync::mpsc::Sender;
use tracing::warn;

use crate::collectors::{
    CollectedEvent, EVENT_TYPE_NETWORK, Severity, ShutdownFlag, emit, sleep_responsive,
};
use crate::config::NetworkCollectorConfig;

/// v1 hardcoded suspicious-port map (`name -> reason`) — the authoritative
/// floor; `config.suspicious_ports` can only add ports, never remove these.
pub const BUILTIN_SUSPICIOUS_PORTS: &[(u16, &str)] = &[
    (4444, "Metasploit default"),
    (5555, "Android ADB"),
    (6666, "IRC backdoor"),
    (6667, "IRC"),
    (31337, "Back Orifice"),
    (12345, "NetBus"),
    (1234, "Common RAT"),
    (8080, "HTTP proxy"),
    (3389, "RDP"),
    (5900, "VNC"),
    (22, "SSH"),
    (23, "Telnet"),
];

/// v1 hardcoded private/loopback/link-local ranges considered "not
/// external" — the authoritative floor; `config.trusted_ranges` only adds
/// ranges, consistent with the field's evident purpose (user-declared
/// additional trusted networks).
const BUILTIN_TRUSTED_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fe80::/10",
];

#[derive(Clone, Debug, PartialEq)]
struct ConnInfo {
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    state: TcpState,
    pid: u32,
}

fn is_suspicious_port(port: u16, extra: &[u16]) -> Option<&'static str> {
    BUILTIN_SUSPICIOUS_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, reason)| *reason)
        .or_else(|| {
            extra
                .contains(&port)
                .then_some("configured suspicious port")
        })
}

fn is_trusted(ip: IpAddr, extra_ranges: &[String]) -> bool {
    let parse_range = |s: &str| -> Option<ipnet_range::Net> { ipnet_range::Net::parse(s) };
    BUILTIN_TRUSTED_RANGES
        .iter()
        .copied()
        .chain(extra_ranges.iter().map(String::as_str))
        .filter_map(parse_range)
        .any(|net| net.contains(ip))
}

fn determine_severity(info: &ConnInfo, cfg: &NetworkCollectorConfig) -> Severity {
    if let Some(reason) = is_suspicious_port(info.remote_port, &cfg.suspicious_ports) {
        warn!(
            port = info.remote_port,
            reason, "suspicious remote port connection"
        );
        return Severity::High;
    }
    if info.state == TcpState::Listen
        && let Some(reason) = is_suspicious_port(info.local_port, &cfg.suspicious_ports)
    {
        warn!(port = info.local_port, reason, "suspicious listening port");
        return Severity::High;
    }
    if !info.remote_addr.is_unspecified() && !is_trusted(info.remote_addr, &cfg.trusted_ranges) {
        return Severity::Medium;
    }
    Severity::Low
}

fn is_interesting(state: TcpState, established_only: bool) -> bool {
    if established_only {
        state == TcpState::Established
    } else {
        matches!(state, TcpState::Established | TcpState::Listen)
    }
}

fn snapshot() -> HashMap<String, ConnInfo> {
    let sockets = match get_sockets_info(AddressFamilyFlags::all(), ProtocolFlags::TCP) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to list network connections");
            return HashMap::new();
        }
    };
    let mut out = HashMap::new();
    for sock in sockets {
        let ProtocolSocketInfo::Tcp(tcp) = sock.protocol_socket_info else {
            continue;
        };
        let pid = sock.associated_pids.first().copied().unwrap_or(0);
        let key = format!(
            "{}:{}-{}:{}-{}",
            tcp.local_addr, tcp.local_port, tcp.remote_addr, tcp.remote_port, pid
        );
        out.insert(
            key,
            ConnInfo {
                local_addr: tcp.local_addr,
                local_port: tcp.local_port,
                remote_addr: tcp.remote_addr,
                remote_port: tcp.remote_port,
                state: tcp.state,
                pid,
            },
        );
    }
    out
}

/// Runs the network collector loop until `shutdown` is set. Spawned via
/// `tokio::task::spawn_blocking` — socket table enumeration is a blocking
/// syscall.
pub fn run(cfg: NetworkCollectorConfig, tx: Sender<CollectedEvent>, shutdown: ShutdownFlag) {
    let poll = cfg.poll_duration();
    let mut known = snapshot();

    while !shutdown.load(Ordering::Relaxed) {
        sleep_responsive(poll, &shutdown);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let current = snapshot();

        for (key, info) in &current {
            if known.contains_key(key) {
                continue;
            }
            if is_interesting(info.state, cfg.established_only) {
                emit(
                    &tx,
                    EVENT_TYPE_NETWORK,
                    determine_severity(info, &cfg),
                    serde_json::json!({
                        "action": "connected",
                        "local_addr": info.local_addr.to_string(),
                        "local_port": info.local_port,
                        "remote_addr": info.remote_addr.to_string(),
                        "remote_port": info.remote_port,
                        "status": info.state.to_string(),
                        "pid": info.pid,
                    }),
                );
            }
        }

        for (key, info) in &known {
            if current.contains_key(key) {
                continue;
            }
            if info.state == TcpState::Established {
                emit(
                    &tx,
                    EVENT_TYPE_NETWORK,
                    Severity::Info,
                    serde_json::json!({
                        "action": "disconnected",
                        "local_addr": info.local_addr.to_string(),
                        "local_port": info.local_port,
                        "remote_addr": info.remote_addr.to_string(),
                        "remote_port": info.remote_port,
                        "pid": info.pid,
                    }),
                );
            }
        }

        known = current;
    }
}

/// Minimal CIDR containment check — v1's `net.ParseCIDR` equivalent, kept
/// dependency-free since this is the only place the agent needs it.
mod ipnet_range {
    use std::net::IpAddr;

    pub struct Net {
        base: IpAddr,
        prefix: u8,
    }

    impl Net {
        pub fn parse(s: &str) -> Option<Self> {
            let (addr, prefix) = s.split_once('/')?;
            let base: IpAddr = addr.parse().ok()?;
            let prefix: u8 = prefix.parse().ok()?;
            Some(Self { base, prefix })
        }

        pub fn contains(&self, ip: IpAddr) -> bool {
            match (self.base, ip) {
                (IpAddr::V4(base), IpAddr::V4(ip)) => {
                    if self.prefix > 32 {
                        return false;
                    }
                    let mask = if self.prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - self.prefix)
                    };
                    (u32::from(base) & mask) == (u32::from(ip) & mask)
                }
                (IpAddr::V6(base), IpAddr::V6(ip)) => {
                    if self.prefix > 128 {
                        return false;
                    }
                    let mask = if self.prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - self.prefix)
                    };
                    (u128::from(base) & mask) == (u128::from(ip) & mask)
                }
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::must;

    fn conn(remote_addr: &str, remote_port: u16, local_port: u16, state: TcpState) -> ConnInfo {
        ConnInfo {
            local_addr: must("0.0.0.0".parse(), "parse local addr"),
            local_port,
            remote_addr: must(remote_addr.parse(), "parse remote addr"),
            remote_port,
            state,
            pid: 100,
        }
    }

    fn default_cfg() -> NetworkCollectorConfig {
        NetworkCollectorConfig::default()
    }

    #[test]
    fn builtin_suspicious_remote_port_is_high() {
        let c = conn("8.8.8.8", 4444, 55000, TcpState::Established);
        assert_eq!(determine_severity(&c, &default_cfg()), Severity::High);
    }

    #[test]
    fn configured_suspicious_port_adds_without_replacing_builtin() {
        let mut cfg = default_cfg();
        cfg.suspicious_ports = vec![9999];
        let c = conn("8.8.8.8", 9999, 55000, TcpState::Established);
        assert_eq!(determine_severity(&c, &cfg), Severity::High);
        // Builtin port still flags High with a custom (unrelated) port list.
        let c2 = conn("8.8.8.8", 4444, 55000, TcpState::Established);
        assert_eq!(determine_severity(&c2, &cfg), Severity::High);
    }

    #[test]
    fn suspicious_listen_port_is_high_only_when_listening() {
        let c = conn("0.0.0.0", 0, 3389, TcpState::Listen);
        assert_eq!(determine_severity(&c, &default_cfg()), Severity::High);
    }

    #[test]
    fn external_ip_is_medium_private_is_low() {
        let external = conn("8.8.8.8", 443, 55000, TcpState::Established);
        assert_eq!(
            determine_severity(&external, &default_cfg()),
            Severity::Medium
        );
        let private = conn("192.168.1.5", 443, 55000, TcpState::Established);
        assert_eq!(determine_severity(&private, &default_cfg()), Severity::Low);
        let loopback = conn("127.0.0.1", 443, 55000, TcpState::Established);
        assert_eq!(determine_severity(&loopback, &default_cfg()), Severity::Low);
    }

    #[test]
    fn configured_trusted_range_is_additive() {
        let mut cfg = default_cfg();
        let candidate = conn("203.0.113.5", 443, 55000, TcpState::Established);
        assert_eq!(determine_severity(&candidate, &cfg), Severity::Medium);
        cfg.trusted_ranges = vec!["203.0.113.0/24".to_owned()];
        assert_eq!(determine_severity(&candidate, &cfg), Severity::Low);
    }

    #[test]
    fn established_only_excludes_listen() {
        assert!(is_interesting(TcpState::Established, true));
        assert!(!is_interesting(TcpState::Listen, true));
        assert!(is_interesting(TcpState::Listen, false));
        assert!(is_interesting(TcpState::Established, false));
        assert!(!is_interesting(TcpState::CloseWait, false));
    }

    #[test]
    fn cidr_v4_and_v6_containment() {
        let net = must(
            ipnet_range::Net::parse("10.0.0.0/8").ok_or("no parse"),
            "parse cidr",
        );
        assert!(net.contains(must("10.1.2.3".parse(), "parse ip")));
        assert!(!net.contains(must("11.1.2.3".parse(), "parse ip")));

        let net6 = must(
            ipnet_range::Net::parse("fe80::/10").ok_or("no parse"),
            "parse cidr",
        );
        assert!(net6.contains(must("fe80::1".parse(), "parse ip")));
        assert!(!net6.contains(must("2001::1".parse(), "parse ip")));
    }
}
