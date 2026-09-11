//! Compiles the canonical protos in `{repo}/proto/` with protox (pure Rust,
//! no protoc binary) and generates tonic server/client code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../proto";
    // Vendored OTLP protos live under their own `otel/` subtree, mirroring
    // upstream open-telemetry/opentelemetry-proto's own repo layout (its
    // root contains `opentelemetry/proto/...` directly) — see
    // `proto/otel/opentelemetry/proto/{common,resource,logs}/v1/*.proto`'s
    // header comments for the exact vendored commit. A second include root
    // is required (rather than reusing `proto_root` alone) because those
    // files' own `import "opentelemetry/proto/..."` statements resolve
    // relative to `otel_root`, not `proto_root`.
    let otel_root = "../../proto/otel";
    let files = [
        "../../proto/manager/v1/manager.proto",
        "../../proto/s3scan/v1/s3_scan.proto",
        "../../proto/pki/v1/pki.proto",
        "../../proto/otel/opentelemetry/proto/common/v1/common.proto",
        "../../proto/otel/opentelemetry/proto/resource/v1/resource.proto",
        "../../proto/otel/opentelemetry/proto/logs/v1/logs.proto",
        "../../proto/otel/opentelemetry/proto/collector/logs/v1/logs_service.proto",
    ];
    for f in &files {
        println!("cargo:rerun-if-changed={f}");
    }
    println!("cargo:rerun-if-changed={proto_root}");

    // `otel_root` MUST be searched before `proto_root`: protox resolves
    // each include-root-relative logical file name via the first matching
    // root (`ChainFileResolver` — first match wins), and `otel_root` is
    // nested inside `proto_root`. Trying `proto_root` first would resolve
    // the vendored files' *explicit* `files`-list entries to the logical
    // name `otel/opentelemetry/proto/...` while their sibling files'
    // `import "opentelemetry/proto/...";` statements resolve via
    // `otel_root` to `opentelemetry/proto/...` instead — two different
    // logical names for the same physical file, which protox then treats
    // as two separate files each declaring the same proto package
    // ("already defined" error).
    let fds = protox::compile(files, [otel_root, proto_root])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    Ok(())
}
