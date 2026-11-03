//! Acceptance tests for the process-backed environment backend, over real
//! processes (`fake-t3`, a stand-in for `t3 serve` and `t3 pair`).

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use sandy_api::{
    backend::BackendError,
    environment::{EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};
use sandy_environment::{ProcessConfig, ProcessConfigError, ProcessEnvironmentBackend};

const FAKE: &str = env!("CARGO_BIN_EXE_fake-t3");

fn spec(id: &str) -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: id.to_owned(),
        template: "process".to_owned(),
        size: None,
        env: Vec::new(),
        service_port: None,
    }
}

fn config(state: &Path, serve_args: &[&str]) -> ProcessConfig {
    let mut command = vec![FAKE.to_owned(), "serve".to_owned()];
    command.extend(["--port", "{port}", "--base-dir", "{base_dir}"].map(str::to_owned));
    command.extend(serve_args.iter().map(|s| (*s).to_owned()));
    ProcessConfig {
        command,
        pair_command: None,
        state_dir: state.to_owned(),
        path: std::env::var("PATH").unwrap_or_default(),
        pass_env: Vec::new(),
        pair_timeout: Duration::from_secs(10),
    }
}

fn backend(state: &Path, serve_args: &[&str]) -> Result<ProcessEnvironmentBackend> {
    Ok(ProcessEnvironmentBackend::new(config(state, serve_args))?)
}

/// Polls `probe` until `done` says so or 10 s pass; returns the last probe.
fn wait_for(b: &ProcessEnvironmentBackend, id: &str, done: impl Fn(&Probe) -> bool) -> Result<Probe> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let p = b.probe(id)?;
        if done(&p) {
            return Ok(p);
        }
        if Instant::now() > deadline {
            bail!("timed out; last probe {p:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn env_dir(state: &Path, id: &str) -> PathBuf {
    state.join(id)
}

#[test]
fn an_environment_is_starting_while_the_service_answers_503_then_ready_at_its_endpoint() -> Result<()> {
    let state = tempfile::tempdir()?;
    let b = backend(state.path(), &["--ready-after-ms", "600"])?;
    assert_eq!(b.launch(&spec("env-1"))?, Launch::Started);
    assert!(
        matches!(b.probe("env-1")?, Probe::Starting { .. }),
        "503 or no listener yet is Starting"
    );
    let ready = wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    let Probe::Ready { endpoint } = ready else {
        bail!("not ready")
    };
    assert_eq!(endpoint.host, "127.0.0.1");
    assert!(endpoint.port > 1023);
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn launching_a_running_id_again_starts_no_second_process() -> Result<()> {
    let state = tempfile::tempdir()?;
    let b = backend(state.path(), &[])?;
    assert_eq!(b.launch(&spec("env-1"))?, Launch::Started);
    assert_eq!(b.launch(&spec("env-1"))?, Launch::AlreadyRunning);
    let ids: Vec<_> = b.boxes()?.into_iter().map(|s| s.box_id).collect();
    assert_eq!(ids, ["env-1"]);
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn two_environments_get_their_own_ports_and_directories() -> Result<()> {
    let state = tempfile::tempdir()?;
    let b = backend(state.path(), &[])?;
    b.launch(&spec("env-1"))?;
    b.launch(&spec("env-2"))?;
    let port = |id| -> Result<u16> {
        match wait_for(&b, id, |p| matches!(p, Probe::Ready { .. }))? {
            Probe::Ready { endpoint } => Ok(endpoint.port),
            other => bail!("{other:?}"),
        }
    };
    assert_ne!(port("env-1")?, port("env-2")?);
    assert!(env_dir(state.path(), "env-1").is_dir() && env_dir(state.path(), "env-2").is_dir());
    b.kill("env-1")?;
    b.kill("env-2")?;
    Ok(())
}

#[test]
fn a_service_that_exits_early_is_failed_with_its_exit_status() -> Result<()> {
    let state = tempfile::tempdir()?;
    let b = backend(state.path(), &["--exit-after-ms", "100"])?;
    b.launch(&spec("env-1"))?;
    let p = wait_for(&b, "env-1", |p| matches!(p, Probe::Failed { .. }))?;
    let Probe::Failed { step, reason } = p else {
        bail!("not failed")
    };
    assert_eq!(step, "process");
    assert!(reason.contains('7'), "the exit status must be named: {reason}");
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn a_missing_program_is_a_spawn_error_and_leaves_no_box_or_directory() -> Result<()> {
    let state = tempfile::tempdir()?;
    let mut c = config(state.path(), &[]);
    c.command = vec!["/nonexistent/sandy-no-such-program".to_owned()];
    let b = ProcessEnvironmentBackend::new(c)?;
    assert!(matches!(b.launch(&spec("env-1")), Err(BackendError::Spawn(_))));
    assert!(b.boxes()?.is_empty());
    assert!(
        !env_dir(state.path(), "env-1").exists(),
        "a failed launch must not leave its directory"
    );
    Ok(())
}

#[test]
fn an_unknown_or_killed_environment_is_not_running_and_kill_is_idempotent() -> Result<()> {
    let state = tempfile::tempdir()?;
    let b = backend(state.path(), &[])?;
    assert_eq!(b.probe("env-nope")?, Probe::NotRunning);
    b.launch(&spec("env-1"))?;
    b.kill("env-1")?;
    b.kill("env-1")?;
    b.kill("env-never")?;
    assert_eq!(b.probe("env-1")?, Probe::NotRunning);
    assert!(b.boxes()?.is_empty());
    assert!(
        !env_dir(state.path(), "env-1").exists(),
        "kill removes the environment's directory"
    );
    Ok(())
}

#[test]
fn kill_ends_the_whole_process_group_including_children() -> Result<()> {
    let state = tempfile::tempdir()?;
    let b = backend(state.path(), &["--spawn-child"])?;
    b.launch(&spec("env-1"))?;
    wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    let beat = env_dir(state.path(), "env-1").join("child.beat");
    let read = || std::fs::read_to_string(&beat).unwrap_or_default();
    // The child is alive: its counter advances.
    let first = read();
    std::thread::sleep(Duration::from_millis(200));
    assert_ne!(first, read(), "the child must be beating before the kill");
    // Copy the file's path out: the directory is removed by kill, so read before.
    b.kill("env-1")?;
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !beat.exists() || read() == read(),
        "the child must have stopped beating"
    );
    // A beat file that reappears would mean a surviving writer.
    std::thread::sleep(Duration::from_millis(200));
    assert!(!beat.exists(), "no process may still write into the removed directory");
    Ok(())
}

#[test]
fn the_service_sees_a_clean_environment_with_only_the_passed_variables() -> Result<()> {
    let state = tempfile::tempdir()?;
    // SAFETY-free way to set a variable for this test process: pass it via the config's pass_env
    // by name only if it exists in the daemon's own environment, so use a name no test sets.
    let mut c = config(state.path(), &["--dump-env"]);
    c.pass_env = vec!["SANDY_ENV_TEST_PASSED".to_owned()];
    let b = ProcessEnvironmentBackend::new(c)?;
    b.launch(&spec("env-1"))?;
    wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    let dir = env_dir(state.path(), "env-1");
    let dumped = std::fs::read_to_string(dir.join("env.txt")).context("env.txt")?;
    let keys: Vec<&str> = dumped.lines().filter_map(|l| l.split('=').next()).collect();
    for key in &keys {
        assert!(
            ["PATH", "HOME", "LANG", "TMPDIR"].contains(key),
            "unexpected variable {key} reached the service"
        );
    }
    assert!(
        dumped.lines().any(|l| l == format!("HOME={}", dir.display())),
        "HOME must be the environment directory"
    );
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn the_pair_command_output_goes_to_a_0600_file_and_nowhere_else() -> Result<()> {
    let state = tempfile::tempdir()?;
    let mut c = config(state.path(), &[]);
    c.pair_command = Some([FAKE, "pair", "--base-dir", "{base_dir}"].map(str::to_owned).to_vec());
    let b = ProcessEnvironmentBackend::new(c)?;
    b.launch(&spec("env-1"))?;
    let ready = wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    let dir = env_dir(state.path(), "env-1");
    let pairing = dir.join("pairing");
    let code = std::fs::read_to_string(&pairing).context("pairing file")?;
    assert!(code.contains("PAIRCANARY-7d3f9a1c"));
    assert_eq!(std::fs::metadata(&pairing)?.permissions().mode() & 0o777, 0o600);
    assert!(
        !format!("{ready:?}").contains("PAIRCANARY"),
        "the code must not appear in the probe result"
    );
    assert!(!format!("{:?}", b.boxes()?).contains("PAIRCANARY"));
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn a_failing_pair_command_fails_the_environment_without_leaking_its_output() -> Result<()> {
    let state = tempfile::tempdir()?;
    let mut c = config(state.path(), &[]);
    c.pair_command = Some(
        [FAKE, "pair", "--fail", "--base-dir", "{base_dir}"]
            .map(str::to_owned)
            .to_vec(),
    );
    let b = ProcessEnvironmentBackend::new(c)?;
    b.launch(&spec("env-1"))?;
    let p = wait_for(&b, "env-1", |p| matches!(p, Probe::Failed { .. }))?;
    let Probe::Failed { step, reason } = p else {
        bail!("not failed")
    };
    assert_eq!(step, "pair");
    assert!(
        !reason.contains("PAIRCANARY"),
        "the pair command's output must not reach the reason: {reason}"
    );
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn the_state_and_environment_directories_are_private() -> Result<()> {
    let state = tempfile::tempdir()?;
    let root = state.path().join("environments");
    let b = backend(&root, &[])?;
    b.launch(&spec("env-1"))?;
    assert_eq!(std::fs::metadata(&root)?.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::metadata(root.join("env-1"))?.permissions().mode() & 0o777,
        0o700
    );
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn an_environment_id_that_could_escape_the_state_dir_is_refused() -> Result<()> {
    let state = tempfile::tempdir()?;
    let b = backend(state.path(), &[])?;
    for id in ["../x", "a/b", "", ".", "..", "a b", "x\0y"] {
        assert!(matches!(b.launch(&spec(id)), Err(BackendError::Spawn(_))), "id {id:?}");
    }
    assert!(b.boxes()?.is_empty());
    assert_eq!(
        std::fs::read_dir(state.path())?.count(),
        0,
        "nothing may be created for a refused id"
    );
    Ok(())
}

#[test]
fn an_empty_command_is_refused_at_construction() {
    let state = tempfile::tempdir().expect("tempdir");
    for command in [vec![], vec![String::new()]] {
        let mut c = config(state.path(), &[]);
        c.command = command;
        assert_eq!(c.validate(), Err(ProcessConfigError::Empty));
        assert!(ProcessEnvironmentBackend::new(c).is_err());
    }
}

#[test]
fn a_new_backend_removes_a_stale_directory_left_by_an_earlier_daemon() -> Result<()> {
    let state = tempfile::tempdir()?;
    let stale = env_dir(state.path(), "env-old");
    std::fs::create_dir_all(&stale)?;
    std::fs::write(stale.join("pid"), "999999999")?; // no such process
    std::fs::write(state.path().join("not-a-dir"), "keep")?;
    let b = backend(state.path(), &[])?;
    assert!(!stale.exists(), "a stale environment directory is removed");
    assert!(
        state.path().join("not-a-dir").exists(),
        "unrelated files are left alone"
    );
    assert!(b.boxes()?.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn a_new_backend_kills_the_orphan_process_group_of_a_stale_environment() -> Result<()> {
    let state = tempfile::tempdir()?;
    let first = backend(state.path(), &["--spawn-child"])?;
    first.launch(&spec("env-1"))?;
    wait_for(&first, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    let dir = env_dir(state.path(), "env-1");
    let beat = dir.join("child.beat");
    // The daemon dies without cleanup: forget the backend without dropping it.
    std::mem::forget(first);
    let second = backend(state.path(), &[])?;
    std::thread::sleep(Duration::from_millis(300));
    assert!(!dir.exists(), "the stale directory is removed");
    assert!(
        !beat.exists(),
        "the orphan's child must be dead, or it would rewrite its beat file"
    );
    assert!(second.boxes()?.is_empty());
    Ok(())
}
