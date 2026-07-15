//! Compiles the canonical protos in `{repo}/proto/` with protox (pure Rust,
//! no protoc binary) and generates tonic server/client code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../proto";
    let files = [
        "../../proto/manager/v1/manager.proto",
        "../../proto/s3scan/v1/s3_scan.proto",
        "../../proto/pki/v1/pki.proto",
    ];
    for f in &files {
        println!("cargo:rerun-if-changed={f}");
    }
    println!("cargo:rerun-if-changed={proto_root}");

    let fds = protox::compile(files, [proto_root])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    Ok(())
}
