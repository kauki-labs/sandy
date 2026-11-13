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
use sandy_control_proto::{
    ControlRequest, ControlResponse, HostSummary, IsolationClass, ListHostsResponse, control_response, read_frame,
    write_frame,
};

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

/// A fake `sandyd` that answers every `ListHosts` with `hosts`, on a socket under `dir`. Serves from its own thread
/// until the test process ends.
fn fake_sandyd(dir: &std::path::Path, hosts: Vec<HostSummary>) -> anyhow::Result<std::path::PathBuf> {
    let sock = dir.join("sandyd.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).context("bind the fake sandyd")?;
    listener.set_nonblocking(true).context("nonblocking")?;
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
            return;
        };
        rt.block_on(async move {
            let Ok(listener) = tokio::net::UnixListener::from_std(listener) else {
                return;
            };
            while let Ok((mut stream, _)) = listener.accept().await {
                let hosts = hosts.clone();
                tokio::spawn(async move {
                    while let Ok(Some(request)) = read_frame::<ControlRequest>(&mut stream).await {
                        let reply = ControlResponse {
                            request_id: request.request_id,
                            result: Some(control_response::Result::Hosts(ListHostsResponse {
                                hosts: hosts.clone(),
                            })),
                        };
                        if write_frame(&mut stream, &reply).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    });
    Ok(sock)
}

fn executor(id: &str) -> HostSummary {
    HostSummary {
        host_id: id.to_owned(),
        sandbox_kinds: vec!["vm".to_owned()],
        isolation_classes: vec![i32::from(IsolationClass::Untrusted)],
        arch: std::env::consts::ARCH.to_owned(),
    }
}

/// `sandy doctor` against `$SANDY_HOME` `home` and the control socket `sock`. On macOS it also injects a fake `nix` and
/// a matching remote builder, so the host-prerequisite half does not depend on the sandbox's real nix install (#163).
/// The guards keep those temp files alive through the run.
fn run_doctor(
    home: &std::path::Path,
    sock: &std::path::Path,
) -> anyhow::Result<(std::process::Output, Vec<Box<dyn std::any::Any>>)> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandy"));
    // `$HOME` too: doctor stages a probe credential under `~/.config/sandy`, which a developer host may not allow.
    command
        .arg("doctor")
        .env("SANDY_HOME", home)
        .env("SANDY_SOCK", sock)
        .env("HOME", home);
    let mut guards: Vec<Box<dyn std::any::Any>> = Vec::new();
    if cfg!(target_os = "macos") {
        let (path, path_dir) = fake_nix_path()?;
        let machines = machines_file_for_this_arch()?;
        command
            .env("PATH", path)
            .env("SANDY_NIX_MACHINES_FILE", machines.path());
        guards.push(Box::new(path_dir));
        guards.push(Box::new(machines));
    }
    let output = command.output().context("running `sandy doctor`")?;
    Ok((output, guards))
}

#[test]
fn doctor_exits_0_for_a_local_temp_dir_sandy_home() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let sock = fake_sandyd(home.path(), vec![executor("exec-1")])?;

    let (output, _guards) = run_doctor(home.path(), &sock)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("exec-1"), "the registered executor is listed: {stdout}");
    Ok(())
}

/// With no `sandyd` on the control socket, doctor refuses (exit 2): the verbs are the daemon's, so a missing daemon is
/// a failed precondition, named with the socket and the fix (#483).
#[test]
fn doctor_refuses_when_no_daemon_answers() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let sock = home.path().join("nobody-home.sock");

    let (output, _guards) = run_doctor(home.path(), &sock)?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("nobody-home.sock"), "names the socket: {stderr}");
    assert!(stderr.contains("start `sandyd`"), "names the fix: {stderr}");
    Ok(())
}

/// A daemon with no executor registered is up but cannot place a job: refused (exit 2), naming the executor to start.
#[test]
fn doctor_refuses_a_daemon_with_no_executor() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("creating a temp SANDY_HOME")?;
    let sock = fake_sandyd(home.path(), Vec::new())?;

    let (output, _guards) = run_doctor(home.path(), &sock)?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("sandy-host-executor"), "names the fix: {stderr}");
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
