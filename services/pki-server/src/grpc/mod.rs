//! gRPC control plane (tonic). Serves `skauswatch.pki` `PKIService` on
//! `GRPC_PORT` (default 50052, `GRPC_ENABLED` default true) — the same 16
//! RPCs the v1 servicer implemented (`grpc/server.py`).
//!
//! AUTH PARITY: v1 bound to an insecure port with no authentication —
//! replicated exactly (internal cluster port, no interceptor). Flagged for
//! GA hardening. Every request carries `api_version`; unknown values return
//! UNIMPLEMENTED per the backend API standard.

mod pki_service;

use std::net::SocketAddr;

use crate::state::AppState;

/// Default gRPC port — parity with v1 (`GRPC_PORT`, default 50052).
const DEFAULT_GRPC_PORT: u16 = 50_052;

/// Whether the gRPC server should run — enabled unless `GRPC_ENABLED`
/// (lowercased) is anything other than "true".
pub fn enabled() -> bool {
    std::env::var("GRPC_ENABLED")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true)
}

/// Resolves the gRPC listen port from `GRPC_PORT` (default 50052).
pub fn port() -> u16 {
    std::env::var("GRPC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_GRPC_PORT)
}

/// Runs the tonic `PKIService` server on 0.0.0.0:{port} until `shutdown`
/// resolves — wired into the same signal as the REST server.
pub async fn serve(
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    use skauswatch_proto::pki::pki_service_server::PkiServiceServer;

    let addr: SocketAddr = ([0, 0, 0, 0], port()).into();
    tracing::info!(%addr, "pki gRPC listening");
    tonic::transport::Server::builder()
        .add_service(PkiServiceServer::new(pki_service::PkiGrpc::new(state)))
        .serve_with_shutdown(addr, shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_port_defaults_to_v1_50052() {
        assert_eq!(DEFAULT_GRPC_PORT, 50_052);
    }
}
