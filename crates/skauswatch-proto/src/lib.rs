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

/// OpenTelemetry OTLP logs contract, vendored from
/// `open-telemetry/opentelemetry-proto` (Apache-2.0) — see
/// `proto/otel/opentelemetry/proto/{common,resource,logs}/v1/*.proto` and
/// `proto/otel/opentelemetry/proto/collector/logs/v1/logs_service.proto`
/// for the pinned upstream commit, recorded in each file's header comment
/// per Dependency Pinning discipline. `svc-ingest`'s OTLP gRPC (`:4317`)
/// and HTTP (`:4318`) listeners (Task 1.2) are the sole consumers.
///
/// Nested to mirror the upstream proto package hierarchy exactly
/// (`opentelemetry.proto.{common,resource,logs}.v1`,
/// `opentelemetry.proto.collector.logs.v1`) rather than flattened like
/// `manager`/`s3scan`/`pki` above — prost's generated cross-package field
/// types (e.g. `Resource::attributes: Vec<KeyValue>`,
/// `ExportLogsServiceRequest::resource_logs: Vec<ResourceLogs>`) reference
/// sibling packages via `super::`-relative paths computed from however
/// deep this module nesting is, so flattening it would produce
/// non-compiling generated code.
pub mod opentelemetry {
    #![allow(clippy::doc_markdown)] // generated code carries proto comments verbatim
    pub mod proto {
        pub mod common {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.common.v1");
            }
        }
        pub mod resource {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.resource.v1");
            }
        }
        pub mod logs {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.logs.v1");
            }
        }
        pub mod collector {
            pub mod logs {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.collector.logs.v1");
                }
            }
        }
    }
}

/// Returns whether a request-carried `api_version` value routes to the v1
/// handlers. Empty is accepted for backward compatibility with fielded v1
/// clients that predate the field.
pub fn is_v1(api_version: &str) -> bool {
    api_version.is_empty() || api_version == "v1"
}

#[cfg(test)]
#[allow(clippy::expect_used)]
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

    #[test]
    fn otlp_generated_types_exist_and_cross_package_refs_compile() {
        use opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest;
        use opentelemetry::proto::common::v1::{AnyValue, KeyValue};
        use opentelemetry::proto::logs::v1::{LogRecord, ResourceLogs};
        use opentelemetry::proto::resource::v1::Resource;

        // Exercises the cross-package `super::`-relative field types
        // (`ResourceLogs.resource: Option<Resource>`,
        // `Resource.attributes: Vec<KeyValue>`,
        // `LogRecord.body: Option<AnyValue>`) this module's nesting exists
        // to make resolvable — a flattened module layout would fail to
        // compile before this test could ever run.
        let req = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_owned(),
                        value: Some(AnyValue {
                            value: Some(
                                opentelemetry::proto::common::v1::any_value::Value::StringValue(
                                    "svc-ingest".to_owned(),
                                ),
                            ),
                        }),
                    }],
                    ..Default::default()
                }),
                scope_logs: vec![],
                schema_url: String::new(),
            }],
        };
        assert_eq!(req.resource_logs.len(), 1);
        let resource = req.resource_logs[0]
            .resource
            .as_ref()
            .expect("resource set above");
        assert_eq!(resource.attributes[0].key, "service.name");
        assert_eq!(LogRecord::default().severity_number, 0);
    }
}
