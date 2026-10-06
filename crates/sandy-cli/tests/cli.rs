//! Binary smoke test: `sandy ls` on an empty `$SANDY_HOME` exits 0.
//!
//! Mirrors `tests/doctor.rs` — drives the real built binary via `CARGO_BIN_EXE_sandy`.
//! `run` is intentionally NOT exercised through the binary: it would select the
//! native backend and try to boot (tier-3 / #26).
//!
//! Stays red until `main` wires the `Ls` subcommand to `supervisor::ls`; the
//! implementer makes it green.

use std::process::Command;

use anyhow::Context;

#[test]
fn ls_exits_0_on_an_empty_temp_sandy_home() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;

    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .arg("ls")
        .env("SANDY_HOME", home.path())
        .output()
        .context("running `sandy ls`")?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}
