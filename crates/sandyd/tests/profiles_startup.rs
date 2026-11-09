//! The daemon refuses to start on a registry it cannot trust (#704), and says so without echoing the file.

use std::{
    io::Read,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

const SECRET: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

/// Run sandyd with `SANDY_PROFILES` at `registry` and return its exit code and log. A daemon that does not exit
/// within the bound is killed and the test fails.
fn run_with_registry(dir: &std::path::Path, registry: &std::path::Path) -> Result<(Option<i32>, String)> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sandyd"))
        .env("SANDY_PROFILES", registry)
        .env("SANDY_SOCK", dir.join("sandyd.sock"))
        .env("SANDY_DB", dir.join("sandyd.db"))
        .env_remove("SANDY_ENV_BACKEND")
        .env_remove("SANDY_AUDIT_LOG")
        .env_remove("SANDY_MAX_JOBS")
        .env_remove("SANDY_MAX_ENVIRONMENTS")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn sandyd")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().context("wait for sandyd")? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().context("kill a daemon that did not exit")?;
            child.wait().context("reap sandyd")?;
            anyhow::bail!("sandyd kept running on an untrusted registry");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // tracing's default writer is stdout; stderr is read too in case that changes.
    let mut log = String::new();
    child
        .stdout
        .take()
        .context("stdout")?
        .read_to_string(&mut log)
        .context("read sandyd log")?;
    child
        .stderr
        .take()
        .context("stderr")?
        .read_to_string(&mut log)
        .context("read sandyd log")?;
    Ok((status.code(), log))
}

#[test]
fn a_registry_open_to_others_stops_the_daemon_without_echoing_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("profiles.json");
    std::fs::write(
        &registry,
        format!(r#"{{"profiles":[{{"name":"{SECRET}","credential":"c"}}]}}"#),
    )?;
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o644))?;
    let (code, log) = run_with_registry(dir.path(), &registry)?;
    ensure!(code == Some(1), "exit {code:?}: {log}");
    ensure!(log.contains("could not load SANDY_PROFILES"), "{log}");
    ensure!(!log.contains(SECRET), "the log repeated the file: {log}");
    Ok(())
}

#[test]
fn a_malformed_private_registry_stops_the_daemon_without_echoing_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("profiles.json");
    std::fs::write(
        &registry,
        format!(r#"{{"profiles":[{{"name":"{SECRET}","credential":"c"}}]}}"#),
    )?;
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o600))?;
    let (code, log) = run_with_registry(dir.path(), &registry)?;
    ensure!(code == Some(1), "exit {code:?}: {log}");
    ensure!(log.contains("could not load SANDY_PROFILES"), "{log}");
    ensure!(!log.contains(SECRET), "the log repeated the file: {log}");
    Ok(())
}
