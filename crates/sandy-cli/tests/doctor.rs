//! Integration test for `sandy doctor` against a real built binary.
//!
//! The local-fs-only positive row runs on every platform: a `tempfile::TempDir`
//! is always backed by a local filesystem, so this covers "local FS → exit 0".
//! On macOS the binary also gates on the vfkit prerequisites (`nix` on `PATH`
//! plus a matching remote builder); that check is injected with host facts
//! (fake `nix`, a temp machines file) rather than left to whatever the test
//! host happens to have installed, so the positive row is deterministic in the
//! `nix flake check` sandbox too, and the macOS-only `missing_nix`/
//! `missing_builder` tests below pin the adversarial rows as regressions (#163).
//! The networked-filesystem row needs a real share mount and is covered instead
//! by the `classify_fs` / `doctor_result_for` unit tests in `src/doctor.rs`.

use std::{io::Write as _, process::Command};

use anyhow::Context;

/// Strip any `PATH` entry containing a real `nix` binary, then prepend a fresh
/// temp dir holding a placeholder `nix` file. `nix_on_path` (src/doctor.rs)
/// only checks `is_file()`, so this flips the probe to "present" without
/// actually invoking `nix`. The rest of the real `PATH` is kept, rather than
/// replaced outright, so other tools doctor shells out to (`mount`, for
/// filesystem-type detection) have their best chance of still resolving —
/// though a stripped-down sandbox PATH can still lack `mount`, in which case
/// doctor falls back to its own "filesystem type is undetectable; proceeding"
/// path, which is also exit 0.
fn fake_nix_path() -> anyhow::Result<(std::ffi::OsString, tempfile::TempDir)> {
    let dir = tempfile::tempdir().context("temp PATH dir for a fake nix")?;
    std::fs::write(dir.path().join("nix"), b"").context("writing a placeholder nix file")?;
    let real = std::env::var_os("PATH").unwrap_or_default();
    let without_real_nix = std::env::split_paths(&real).filter(|entry| !entry.join("nix").is_file());
    let joined = std::env::join_paths(std::iter::once(dir.path().to_path_buf()).chain(without_real_nix))
        .context("joining the fake-nix PATH")?;
    Ok((joined, dir))
}

/// The real `PATH` with every entry containing a `nix` binary removed, and no
/// fake one added back — simulates the macOS build sandbox, where `nix` is
/// genuinely absent. Only used by the macOS-only regression test below; `cfg`
/// the function itself so a non-macOS build doesn't flag it as dead code
/// under `--deny warnings`.
#[cfg(target_os = "macos")]
fn nix_free_path() -> anyhow::Result<std::ffi::OsString> {
    let real = std::env::var_os("PATH").unwrap_or_default();
    let without_nix: Vec<_> = std::env::split_paths(&real)
        .filter(|entry| !entry.join("nix").is_file())
        .collect();
    std::env::join_paths(without_nix).context("joining the nix-free PATH")
}

/// A temp `/etc/nix/machines`-shaped file listing a builder for this host's own
/// guest system (`<arch>-linux`), so the macOS vfkit-prereq check's builder
/// lookup resolves regardless of what the real host has configured.
fn machines_file_for_this_arch() -> anyhow::Result<tempfile::NamedTempFile> {
    let guest = format!("{}-linux", std::env::consts::ARCH);
    let mut file = tempfile::NamedTempFile::new().context("temp nix machines file")?;
    writeln!(file, "ssh://builder@example {guest} /dev/null 1 1 - -").context("writing the machines file")?;
    Ok(file)
}

#[test]
fn doctor_exits_0_for_a_local_temp_dir_sandy_home() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;

    let mut command = Command::new(env!("CARGO_BIN_EXE_sandy"));
    command.arg("doctor").env("SANDY_HOME", home.path());

    // macOS additionally gates on nix + a matching remote builder; inject both
    // so this fs-locality test doesn't depend on the sandbox's real nix
    // install (#163). The guards keep the temp files alive through `.output()`.
    let _path_guard;
    let _machines_guard;
    if cfg!(target_os = "macos") {
        let (path, path_dir) = fake_nix_path()?;
        let machines = machines_file_for_this_arch()?;
        command
            .env("PATH", path)
            .env("SANDY_NIX_MACHINES_FILE", machines.path());
        _path_guard = path_dir;
        _machines_guard = machines;
    }

    let output = command.output().context("running `sandy doctor`")?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

/// Regression for #163: with `nix` genuinely absent from `PATH`, macOS `sandy
/// doctor` refuses (exit 2) naming the missing prerequisite, rather than the
/// sandboxed-build failure mode where the *positive* test above mistakenly
/// depended on this same condition.
#[test]
#[cfg(target_os = "macos")]
fn missing_nix_on_path_refuses_with_exit_2() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let path = nix_free_path()?;

    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .arg("doctor")
        .env("SANDY_HOME", home.path())
        .env("PATH", &path)
        .output()
        .context("running `sandy doctor`")?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("nix") && stderr.contains("PATH"), "stderr: {stderr}");
    Ok(())
}

/// `nix` present but no remote builder configured for this host's guest
/// system refuses (exit 2) naming the missing builder.
#[test]
#[cfg(target_os = "macos")]
fn missing_builder_refuses_with_exit_2() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let (path, _path_guard) = fake_nix_path()?;
    // An empty machines file: `nix` is present but no builder is configured.
    let machines = tempfile::NamedTempFile::new().context("temp empty machines file")?;

    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .arg("doctor")
        .env("SANDY_HOME", home.path())
        .env("PATH", &path)
        .env("SANDY_NIX_MACHINES_FILE", machines.path())
        .output()
        .context("running `sandy doctor`")?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("remote builder"), "stderr: {stderr}");
    Ok(())
}
