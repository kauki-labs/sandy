//! Compile the channel-envelope `.proto` into Rust at build time.
//!
//! Codegen uses `protox` (a pure-Rust protobuf compiler) to parse the schema and
//! `prost-build` to emit the types, so no external `protoc` is needed in the dev
//! shell or the hermetic crane build.

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const PROTO: &str = "proto/envelope.proto";

    // crane's `buildDepsOnly` layer compiles against a stub source tree that has
    // no `proto/` dir (and a stub lib.rs that includes nothing); skip codegen
    // there so the dependency layer still builds. The real build has `proto/`
    // present and runs codegen.
    if !Path::new(PROTO).exists() {
        return Ok(());
    }

    println!("cargo:rerun-if-changed={PROTO}");

    let file_descriptors = protox::compile([PROTO], ["proto"])?;
    prost_build::Config::new().compile_fds(file_descriptors)?;

    Ok(())
}
