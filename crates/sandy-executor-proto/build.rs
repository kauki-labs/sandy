//! Compile the executor-contract `.proto` into Rust at build time.
//!
//! Codegen uses `protox` (a pure-Rust protobuf compiler) to parse the schema
//! and `prost-build` to emit the types, so no external `protoc` is needed in
//! the dev shell or the hermetic crane build. Mirrors `sandy-control-proto`'s
//! build script.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Anchor on CARGO_MANIFEST_DIR rather than a path relative to the build
    // script's working directory: cargo happens to run build scripts from the
    // package dir today, but the manifest dir is the documented, stable anchor.
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("proto");
    let proto = proto_dir.join("executor.proto");

    // crane's `buildDepsOnly` layer compiles against a stub source tree that
    // has no `proto/` dir; skip codegen there so the dependency layer still
    // builds. The real build has `proto/` present and runs codegen.
    if !proto.exists() {
        println!("cargo:warning=sandy-executor-proto: proto/executor.proto not found; skipping codegen");
        return Ok(());
    }

    println!("cargo:rerun-if-changed={}", proto.display());

    let file_descriptors = protox::compile([&proto], [&proto_dir])?;
    // Dispatch.link_token is a bearer secret (INV-1); prost's derived Debug
    // would print its raw bytes. Skip it here; src/lib.rs hand-writes a
    // redacting Debug instead, mirroring sandy-control-proto's AttachResponse.
    prost_build::Config::new()
        .skip_debug(["sandy.executor.v1.Dispatch"])
        .compile_fds(file_descriptors)?;

    Ok(())
}
