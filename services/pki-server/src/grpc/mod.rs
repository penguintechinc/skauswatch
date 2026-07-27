//! gRPC control plane (tonic). Serves `skauswatch.pki` `PKIService` on
//! `GRPC_PORT` (default 50052, `GRPC_ENABLED` default true) — the same 16
//! RPCs the v1 servicer implemented (`grpc/server.py`).
//!
//! AUTH (hardened, finding #1): every RPC — including `HealthCheck` — now
//! requires `authorization: Bearer <jwt>` metadata, verified against the
//! shared `JWT_SECRET_KEY` (`skauswatch_auth::verify_grpc_bearer`). Before
//! this pass the port was completely open: anyone on the network could mint
//! CA certificates and download private keys via gRPC with zero auth. No
//! in-repo caller exists today (confirmed by repo-wide grep for this
//! service's RPC names / port) — gating introduces no breakage; a future
//! caller must present a machine JWT minted with
//! `skauswatch_auth::issue_service_token`. Every request carries
//! `api_version`; unknown values return UNIMPLEMENTED per the backend API
//! standard.

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

/// Tonic interceptor requiring `authorization: Bearer <jwt>` on every RPC of
/// the service it's attached to (finding #1 — see module docs).
fn auth_interceptor(
    secret: String,
) -> impl FnMut(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> + Clone {
    move |req: tonic::Request<()>| {
        skauswatch_auth::verify_grpc_bearer(req.metadata(), &secret)?;
        Ok(req)
    }
}

/// Runs the tonic `PKIService` server on 0.0.0.0:{port} until `shutdown`
/// resolves — wired into the same signal as the REST server. Every RPC is
/// gated by `auth_interceptor` (finding #1).
pub async fn serve(
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    use skauswatch_proto::pki::pki_service_server::PkiServiceServer;

    let addr: SocketAddr = ([0, 0, 0, 0], port()).into();
    tracing::info!(%addr, "pki gRPC listening");
    let interceptor = auth_interceptor(state.jwt_secret.clone());
    tonic::transport::Server::builder()
        .add_service(PkiServiceServer::with_interceptor(
            pki_service::PkiGrpc::new(state),
            interceptor,
        ))
        .serve_with_shutdown(addr, shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn grpc_port_defaults_to_v1_50052() {
        assert_eq!(DEFAULT_GRPC_PORT, 50_052);
    }

    #[test]
    fn auth_interceptor_rejects_missing_and_wrong_secret() {
        let mut auth = auth_interceptor("real-secret".to_owned());
        assert!(auth(tonic::Request::new(())).is_err());

        let token = match skauswatch_auth::issue_service_token("x", "admin", "wrong-secret", 300) {
            Ok(t) => t,
            Err(e) => panic!("issue token: {e}"),
        };
        let mut req = tonic::Request::new(());
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("authorization", value);
        assert!(auth(req).is_err());
    }

    #[test]
    fn auth_interceptor_accepts_valid_token() {
        let mut auth = auth_interceptor("real-secret".to_owned());
        let token = match skauswatch_auth::issue_service_token("x", "admin", "real-secret", 300) {
            Ok(t) => t,
            Err(e) => panic!("issue token: {e}"),
        };
        let mut req = tonic::Request::new(());
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("authorization", value);
        assert!(auth(req).is_ok());
    }
}
