//! Compile the control-RPC `.proto` into Rust at build time.
//!
//! Codegen uses `protox` (a pure-Rust protobuf compiler) to parse the schema and
//! `prost-build` to emit the types, so no external `protoc` is needed in the dev
//! shell or the hermetic crane build. Mirrors `sandy-proto`'s build script.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Anchor on CARGO_MANIFEST_DIR rather than a path relative to the build
    // script's working directory: cargo happens to run build scripts from the
    // package dir today, but the manifest dir is the documented, stable anchor.
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("proto");
    let proto = proto_dir.join("control.proto");

    // crane's `buildDepsOnly` layer compiles against a stub source tree that has
    // no `proto/` dir (and a stub lib.rs that includes nothing); skip codegen
    // there so the dependency layer still builds. The real build has `proto/`
    // present and runs codegen. Warn rather than stay silent: a genuinely
    // missing proto file in a real build would otherwise surface only as a
    // confusing missing-file error from `include!` in src/lib.rs.
    if !proto.exists() {
        println!("cargo:warning=sandy-control-proto: proto/control.proto not found; skipping codegen");
        return Ok(());
    }

    println!("cargo:rerun-if-changed={}", proto.display());

    let file_descriptors = protox::compile([&proto], [&proto_dir])?;
    prost_build::Config::new().compile_fds(file_descriptors)?;

    Ok(())
}
