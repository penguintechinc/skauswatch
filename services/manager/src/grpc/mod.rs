//! v1-parity gRPC control plane (tonic). Serves `skauswatch.manager`
//! (7 live RPCs + UNIMPLEMENTED stubs) and `skauswatch.s3scan` on
//! `GRPC_PORT` (default 50051, `GRPC_ENABLED` default true). Contract:
//! docs/v2-port/manager-contract.md §gRPC; Python source of truth:
//! services/manager/grpc/{server,s3_scan_server}.py.
//!
//! AUTH (hardened, finding #3): every implemented business RPC now requires
//! `authorization: Bearer <jwt>` metadata — an HS256 access token signed
//! with the shared `JWT_SECRET_KEY` (`skauswatch_auth::verify_grpc_bearer`).
//! `HealthCheck` stays open (liveness/readiness probes, no sensitive data,
//! not in the audit's gated-method list). Dead/UNIMPLEMENTED stub RPCs are
//! unauthenticated too — they do no work regardless of the caller. No
//! in-repo caller exists for either service today (confirmed by repo-wide
//! grep: ENDPOINT agents authenticate via the REST HMAC gate only, and workers
//! consume `s3scan:tasks`/publish results over Redis Streams, never gRPC) —
//! gating introduces no breakage; any future caller must present a machine
//! JWT minted with `skauswatch_auth::issue_service_token`.
//!
//! API VERSIONING: every request message (except HealthCheck's
//! `google.protobuf.Empty`) carries `api_version`. Fielded v1 Go agents
//! predate the field and send nothing — proto3 decodes that as `""` —
//! so `skauswatch_proto::is_v1` accepts both `""` and `"v1"`; anything
//! else gets UNIMPLEMENTED `api_version {v} not supported`.

mod manager_service;
mod s3_scan_service;

use std::net::SocketAddr;

use tonic::Status;

use crate::state::AppState;

/// Default gRPC port — parity with v1 (`GRPC_PORT`, default 50051).
const DEFAULT_GRPC_PORT: u16 = 50051;

/// Whether the gRPC server should run — v1 `GRPC_ENABLED` semantics:
/// enabled unless the env var (lowercased) is anything other than "true".
pub fn enabled() -> bool {
    enabled_from(std::env::var("GRPC_ENABLED").ok().as_deref())
}

/// Pure form of [`enabled`] for tests.
fn enabled_from(raw: Option<&str>) -> bool {
    raw.map(|v| v.to_lowercase() == "true").unwrap_or(true)
}

/// Resolves the gRPC listen port from `GRPC_PORT` (default 50051).
pub fn port() -> u16 {
    port_from(std::env::var("GRPC_PORT").ok().as_deref())
}

/// Pure form of [`port`] for tests.
fn port_from(raw: Option<&str>) -> u16 {
    raw.and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_GRPC_PORT)
}

/// Runs the tonic server (ManagerService + S3ScanService) on 0.0.0.0:{port}
/// until `shutdown` resolves — wired into the same signal as the REST server.
pub async fn serve(
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    use skauswatch_proto::manager::manager_service_server::ManagerServiceServer;
    use skauswatch_proto::s3scan::s3_scan_service_server::S3ScanServiceServer;

    let addr: SocketAddr = ([0, 0, 0, 0], port()).into();
    tracing::info!(%addr, "manager gRPC listening");
    tonic::transport::Server::builder()
        .add_service(ManagerServiceServer::new(
            manager_service::ManagerGrpc::new(state.clone()),
        ))
        .add_service(S3ScanServiceServer::new(s3_scan_service::S3ScanGrpc::new(
            state,
        )))
        .serve_with_shutdown(addr, shutdown)
        .await?;
    Ok(())
}

/// Requires a valid `authorization: Bearer <jwt>` gRPC metadata entry,
/// signed with the shared `JWT_SECRET_KEY` (finding #3). Maps verification
/// failure onto `UNAUTHENTICATED` via `skauswatch_auth::ServiceTokenError`'s
/// `From<_> for tonic::Status` impl.
fn require_jwt(metadata: &tonic::metadata::MetadataMap, secret: &str) -> Result<(), Status> {
    skauswatch_auth::verify_grpc_bearer(metadata, secret)?;
    Ok(())
}

/// Routes a request-carried `api_version` per the backend API standard:
/// `""`/`"v1"` → v1 handler; anything else → UNIMPLEMENTED with message
/// exactly `api_version {v} not supported`.
fn check_api_version(v: &str) -> Result<(), Status> {
    if skauswatch_proto::is_v1(v) {
        Ok(())
    } else {
        Err(Status::unimplemented(format!(
            "api_version {v} not supported"
        )))
    }
}

/// Dead-RPC response — v1's grpcio servicer base class answered every
/// unimplemented method with UNIMPLEMENTED "Method not implemented!"
/// before parsing the request, so no api_version routing applies here.
fn method_not_implemented() -> Status {
    Status::unimplemented("Method not implemented!")
}

/// Converts a Postgres naive-UTC timestamp into the protobuf Timestamp the
/// v1 servicer produced via `Timestamp.FromDatetime` (naive treated as UTC).
fn ts_from_naive(t: chrono::NaiveDateTime) -> prost_types::Timestamp {
    let utc = t.and_utc();
    prost_types::Timestamp {
        seconds: utc.timestamp(),
        nanos: utc.timestamp_subsec_nanos() as i32,
    }
}

/// Protobuf Timestamp for "now" (v1 `FromDatetime(datetime.utcnow())`).
fn now_ts() -> prost_types::Timestamp {
    ts_from_naive(chrono::Utc::now().naive_utc())
}

/// Maps a DB failure onto INTERNAL. v1's grpc.aio surfaced unhandled DB
/// exceptions as non-OK statuses too; the exact code was never contractual.
/// The real cause is logged server-side; the caller gets a generic message
/// so sqlx internals (constraint/column names, query context) never leak.
fn db_err(e: sqlx::Error) -> Status {
    tracing::error!(error = %e, "manager gRPC database error");
    Status::internal("Internal Server Error")
}

#[cfg(test)]
#[allow(clippy::panic)] // test helpers fail loudly by design
pub(crate) mod test_util {
    use std::path::Path;
    use std::sync::Arc;

    use penguin_licensing::{LicenseClient, LicenseConfig};

    use crate::state::{AppState, AppStateInner};

    /// Test AppState: unreachable lazy DB pool, no stream producer —
    /// exercises validation/routing/status layers without infrastructure.
    pub(crate) fn test_state() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        AppStateInner::for_tests(client)
    }

    /// Test AppState backed by a real, migrated Postgres pool holding this
    /// service's own tables — for RPC success paths that issue real queries
    /// (`ManagerService`: alerts/threat_indicators/audit_logs).
    pub(crate) async fn db_state() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client: Arc<LicenseClient> = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        AppStateInner::for_tests_with_db(client, pool)
    }

    /// Like [`db_state`] but also layers in `services/s3scan`'s migrations —
    /// `S3ScanService` RPCs query `s3_scan_jobs`/`s3_scan_results`/
    /// `adhoc_scan_results`, tables owned by the s3scan worker.
    pub(crate) async fn db_state_with_s3scan() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client: Arc<LicenseClient> = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let pool = skauswatch_testkit::db::test_pool_multi(&[
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")),
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../s3scan/migrations")),
        ])
        .await;
        AppStateInner::for_tests_with_db(client, pool)
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn api_version_gate_accepts_v1_and_empty() {
        assert!(check_api_version("").is_ok());
        assert!(check_api_version("v1").is_ok());
    }

    #[test]
    fn api_version_gate_rejects_unknown_with_exact_message() {
        let err = match check_api_version("v9") {
            Err(e) => e,
            Ok(()) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert_eq!(err.message(), "api_version v9 not supported");
    }

    #[test]
    fn ts_from_naive_converts_utc_epoch_fields() {
        let dt = chrono::NaiveDate::from_ymd_opt(2026, 7, 22)
            .and_then(|d| d.and_hms_micro_opt(10, 3, 7, 123456));
        let dt = match dt {
            Some(v) => v,
            None => panic!("valid test datetime"),
        };
        let ts = ts_from_naive(dt);
        assert_eq!(ts.seconds, dt.and_utc().timestamp());
        assert_eq!(ts.nanos, 123_456_000);
    }

    #[test]
    fn grpc_port_defaults_to_v1_50051() {
        // Env-free default; deployments override via GRPC_PORT.
        assert_eq!(DEFAULT_GRPC_PORT, 50051);
    }

    #[test]
    fn enabled_from_matches_v1_semantics() {
        assert!(enabled_from(None)); // default true
        assert!(enabled_from(Some("true")));
        assert!(enabled_from(Some("TRUE")));
        assert!(!enabled_from(Some("false")));
        assert!(!enabled_from(Some("nope")));
    }

    #[test]
    fn port_from_parses_or_falls_back() {
        assert_eq!(port_from(None), DEFAULT_GRPC_PORT);
        assert_eq!(port_from(Some("9000")), 9000);
        assert_eq!(port_from(Some("not-a-port")), DEFAULT_GRPC_PORT);
    }

    #[test]
    fn require_jwt_accepts_valid_and_rejects_missing() {
        let empty = tonic::metadata::MetadataMap::new();
        assert!(require_jwt(&empty, "s3cret").is_err());

        let token = match skauswatch_auth::issue_service_token("1", "admin", "s3cret", 300) {
            Ok(t) => t,
            Err(e) => panic!("issue token: {e}"),
        };
        let mut md = tonic::metadata::MetadataMap::new();
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        md.insert("authorization", value);
        assert!(require_jwt(&md, "s3cret").is_ok());
    }

    #[test]
    fn method_not_implemented_matches_v1_grpcio_message() {
        let s = method_not_implemented();
        assert_eq!(s.code(), tonic::Code::Unimplemented);
        assert_eq!(s.message(), "Method not implemented!");
    }

    #[test]
    fn db_err_maps_to_internal_without_leaking_detail() {
        let e = sqlx::Error::RowNotFound;
        let s = db_err(e);
        assert_eq!(s.code(), tonic::Code::Internal);
        assert_eq!(s.message(), "Internal Server Error");
    }

    #[tokio::test]
    async fn serve_binds_and_shuts_down_cleanly() {
        // No env override: `port()` resolves the fixed default 50051 — this
        // is the only test in the crate that ever binds a socket, so there
        // is no port-conflict risk. An already-resolved shutdown future
        // makes `serve_with_shutdown` return almost immediately after
        // binding (workspace policy forbids `unsafe`, so this deliberately
        // avoids mutating `GRPC_PORT` to pick an ephemeral port instead).
        let state = test_util::test_state();
        let result = serve(state, async {}).await;
        assert!(result.is_ok());
    }
}
