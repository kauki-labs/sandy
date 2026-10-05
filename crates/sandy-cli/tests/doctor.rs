//! Integration test for `sandy doctor` against a real built binary.
//!
//! Sandbox-safe positive path only: a `tempfile::TempDir` is always backed by a local
//! filesystem, so this covers the "local FS → exit 0" row. The adversarial "share
//! filesystem → exit 2, names INV-5" row needs a real networked mount and is covered
//! instead by the `classify_fs` / `doctor_result_for` unit tests in `src/doctor.rs`.

use std::process::Command;

use anyhow::Context;

#[test]
fn doctor_exits_0_for_a_local_temp_dir_sandy_home() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;

    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .arg("doctor")
        .env("SANDY_HOME", home.path())
        .output()
        .context("running `sandy doctor`")?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}
