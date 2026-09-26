//! Compiles the vendored, trimmed SPIRE Server Entry API proto
//! (`proto/entry.proto`) with protox (pure Rust, no protoc binary) and
//! generates a tonic client — mirrors `crates/skauswatch-proto/build.rs`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "proto";
    let files = ["proto/entry.proto"];
    for f in &files {
        println!("cargo:rerun-if-changed={f}");
    }
    println!("cargo:rerun-if-changed={proto_root}");

    let fds = protox::compile(files, [proto_root])?;
    tonic_prost_build::configure()
        // Server side is generated only so this crate's own tests can spin
        // up a real in-process tonic server implementing the trimmed `Entry`
        // service — production code (services/manager) only ever uses the
        // client.
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    Ok(())
}
