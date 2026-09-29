//! End-to-end integration test.
//!
//! A placeholder that does nothing meaningful yet — it exists so the
//! integration-test wiring (nextest, run by `nix flake check` and CI) is in
//! place from the start. Replace with a real end-to-end flow as the crate grows.

use anyhow::Context;

#[test]
fn end_to_end_smoke() -> anyhow::Result<()> {
    let greeting = sandy_core::greet("sandy").context("greeting a non-empty name")?;
    assert!(greeting.contains("sandy"));
    Ok(())
}
