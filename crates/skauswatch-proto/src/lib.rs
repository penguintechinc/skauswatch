//! Generated gRPC types for the skauswatch wire contracts, compiled from
//! the canonical protos in `{repo}/proto/{manager,s3scan,pki}/v1/`.
//!
//! WIRE-COMPAT POLICY: proto **package names stay unchanged**
//! (`skauswatch.manager`, `skauswatch.s3scan`, `skauswatch.pki`) — the
//! package is part of the gRPC method path and fielded v1 ENDPOINT agents must
//! keep working against the v2 manager. A `buf breaking` CI gate guards
//! these contracts.
//!
//! Every request message carries `api_version` ("" or "v1" → v1 handler;
//! anything else → UNIMPLEMENTED per the backend API standard).

#![allow(missing_docs)] // generated code carries proto comments instead

/// Manager service contract (`skauswatch.manager`).
pub mod manager {
    tonic::include_proto!("skauswatch.manager");
}

/// S3 scan pipeline contract (`skauswatch.s3scan`).
pub mod s3scan {
    tonic::include_proto!("skauswatch.s3scan");
}

/// PKI contract (`skauswatch.pki`).
pub mod pki {
    tonic::include_proto!("skauswatch.pki");
}

/// Returns whether a request-carried `api_version` value routes to the v1
/// handlers. Empty is accepted for backward compatibility with fielded v1
/// clients that predate the field.
pub fn is_v1(api_version: &str) -> bool {
    api_version.is_empty() || api_version == "v1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_version_v1_and_empty_are_accepted() {
        assert!(is_v1(""));
        assert!(is_v1("v1"));
        assert!(!is_v1("v2"));
    }

    #[test]
    fn generated_types_exist() {
        let task = s3scan::ScanTask::default();
        assert_eq!(task.api_version, "");
        let health = manager::HealthResponse::default();
        assert_eq!(health.status, "");
        let q = pki::CertQuery::default();
        assert!(q.identifier.is_none());
    }
}
