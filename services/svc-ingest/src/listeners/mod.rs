//! Ingest listeners: syslog (UDP/TCP/TLS), OTLP (gRPC/HTTP), and HTTPS
//! (OCSF/JSON) — see `docs/v2-port/ingest-module-spec.md` §3b for the full
//! port/transport/auth table. Every submodule below is a compiling stub
//! filled in by its own Wave 1 task, without editing this file again.

/// HTTPS OCSF/JSON listener (`:8443`) — filled in by Task 1.3.
pub mod http;
/// OTLP gRPC (`:4317`) + HTTP (`:4318`) listener — filled in by Task 1.2.
pub mod otlp;
/// Syslog RFC 3164/5424 UDP/TCP/TLS listener — filled in by Task 1.1.
pub mod syslog;
