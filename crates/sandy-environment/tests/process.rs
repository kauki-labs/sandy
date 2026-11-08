//! Acceptance tests for the process-backed environment backend, over real
//! processes (`fake-t3`, a stand-in for `t3 serve` and `t3 pair`).

use std::{
    io::Write,
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

/// A temp dir the backend accepts as a state dir: `tempfile` makes 0755 ones here.
fn private_tempdir() -> Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

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
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
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

/// The counter in `beat` changes within `window`, once the writer has written at all.
fn advances_within(beat: &Path, window: Duration) -> bool {
    let read = || std::fs::read_to_string(beat).unwrap_or_default();
    // A freshly started writer may not have written yet, most of all on a loaded host.
    let deadline = Instant::now() + Duration::from_secs(3);
    while read().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let first = read();
    let deadline = Instant::now() + window;
    while !first.is_empty() && Instant::now() < deadline {
        if read() != first {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// The counter in `beat` advances while its writer lives. A starved writer gets 3 s, not one tick.
fn is_beating(beat: &Path) -> bool {
    advances_within(beat, Duration::from_secs(3))
}

/// The counter in `beat` stays put for a short window. A live writer ticks well inside it.
fn has_stopped(beat: &Path) -> bool {
    !advances_within(beat, Duration::from_millis(250))
}

#[test]
fn a_writer_starved_past_the_poll_window_still_reads_as_beating() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let beat = dir.path().join("slow.beat");
    std::fs::write(&beat, "1")?;
    let writer = {
        let beat = beat.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(700));
            std::fs::write(&beat, "2")
        })
    };
    assert!(
        is_beating(&beat),
        "a live writer starved for 700 ms must still read as beating"
    );
    writer.join().ok().context("the writer thread panicked")??;
    Ok(())
}

#[test]
fn kill_ends_the_whole_process_group_including_children() -> Result<()> {
    let state = private_tempdir()?;
    let outside = tempfile::tempdir()?; // not removed by kill, so a live child can still write here
    let beat = outside.path().join("child.beat");
    let b = backend(state.path(), &["--child-beat-file", beat.to_str().context("utf8")?])?;
    b.launch(&spec("env-1"))?;
    wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    assert!(is_beating(&beat), "the child must be beating before the kill");
    b.kill("env-1")?;
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        has_stopped(&beat),
        "the child must stop beating once its group is killed"
    );
    Ok(())
}

#[test]
fn dropping_the_backend_kills_every_environment() -> Result<()> {
    let state = private_tempdir()?;
    let outside = tempfile::tempdir()?;
    let beat = outside.path().join("child.beat");
    let b = backend(state.path(), &["--child-beat-file", beat.to_str().context("utf8")?])?;
    b.launch(&spec("env-1"))?;
    wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    assert!(is_beating(&beat));
    drop(b);
    std::thread::sleep(Duration::from_millis(300));
    assert!(has_stopped(&beat), "a graceful exit must not leave the service running");
    assert!(!env_dir(state.path(), "env-1").exists());
    Ok(())
}

#[test]
fn the_service_sees_a_clean_environment_with_only_the_passed_variables() -> Result<()> {
    let state = private_tempdir()?;
    // Cargo (and nextest) set this for every test run, so it is a real variable to pass through.
    let passed_value = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR")?;
    let mut c = config(state.path(), &["--dump-env"]);
    c.pass_env = vec!["CARGO_MANIFEST_DIR".to_owned(), "SANDY_ENV_TEST_UNSET".to_owned()];
    let b = ProcessEnvironmentBackend::new(c)?;
    b.launch(&spec("env-1"))?;
    wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    let dir = env_dir(state.path(), "env-1");
    let dumped = std::fs::read_to_string(dir.join("env.txt")).context("env.txt")?;
    let keys: Vec<&str> = dumped.lines().filter_map(|l| l.split('=').next()).collect();
    for key in &keys {
        assert!(
            ["PATH", "HOME", "LANG", "TMPDIR", "CARGO_MANIFEST_DIR"].contains(key),
            "unexpected variable {key} reached the service"
        );
    }
    assert!(
        dumped
            .lines()
            .any(|l| l == format!("CARGO_MANIFEST_DIR={passed_value}")),
        "the named variable passes through"
    );
    assert!(
        dumped.lines().any(|l| l == format!("HOME={}", dir.display())),
        "HOME must be the environment directory"
    );
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn the_pair_command_output_goes_to_a_0600_file_and_nowhere_else() -> Result<()> {
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
    let b = backend(state.path(), &[])?;
    for id in ["../x", "a/b", "", ".", "..", "a b", "x\0y"] {
        assert!(matches!(b.launch(&spec(id)), Err(BackendError::Spawn(_))), "id {id:?}");
    }
    assert!(b.boxes()?.is_empty());
    assert_eq!(
        std::fs::read_dir(state.path())?
            .filter_map(Result::ok)
            .filter(|e| e.file_name() != ".lock")
            .count(),
        0,
        "nothing may be created for a refused id"
    );
    Ok(())
}

#[test]
fn an_empty_command_is_refused_at_construction() {
    let state = private_tempdir().expect("tempdir");
    for command in [vec![], vec![String::new()]] {
        let mut c = config(state.path(), &[]);
        c.command = command;
        assert_eq!(c.validate(), Err(ProcessConfigError::Empty));
        assert!(ProcessEnvironmentBackend::new(c).is_err());
    }
}

#[test]
fn a_new_backend_removes_a_stale_directory_left_by_an_earlier_daemon() -> Result<()> {
    let state = private_tempdir()?;
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
    let state = private_tempdir()?;
    let outside = tempfile::tempdir()?;
    let beat = outside.path().join("child.beat");
    let first = backend(state.path(), &["--child-beat-file", beat.to_str().context("utf8")?])?;
    first.launch(&spec("env-1"))?;
    wait_for(&first, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    assert!(is_beating(&beat));
    let dir = env_dir(state.path(), "env-1");
    // The daemon dies without cleanup: forget the backend and release its lock, as a dead process would.
    let lock_path = state.path().join(".lock");
    std::mem::forget(first);
    release_lock(&lock_path)?;
    let second = backend(state.path(), &[])?;
    std::thread::sleep(Duration::from_millis(300));
    assert!(!dir.exists(), "the stale directory is removed");
    assert!(
        has_stopped(&beat),
        "the orphan's child must be dead: only a group kill stops it"
    );
    assert!(second.boxes()?.is_empty());
    Ok(())
}

/// Stand-in for a crashed daemon dropping its flock: the forgotten backend still holds the
/// descriptor in this process, so take the lock over by unlinking the file; a new one is created.
#[cfg(target_os = "linux")]
fn release_lock(path: &Path) -> Result<()> {
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn an_unrelated_process_named_by_a_stale_pid_file_is_never_killed() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let state = private_tempdir()?;
    let outside = tempfile::tempdir()?;
    let beat = outside.path().join("other.beat");
    let mut other = std::process::Command::new(FAKE)
        .args(["beat", "--file"])
        .arg(&beat)
        .process_group(0)
        .spawn()?;
    let pid = other.id();
    for (name, contents) in [
        ("env-a", format!("{pid}")),   // no start time recorded
        ("env-b", format!("{pid} 1")), // a start time that is not this process's
        ("env-c", "-1".to_owned()),    // not a pid
        ("env-d", "0".to_owned()),
        ("env-e", "1 1".to_owned()), // init
        ("env-f", "not a pid".to_owned()),
        ("env-g", String::new()),
    ] {
        let dir = state.path().join(name);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("pid"), contents)?;
    }
    let b = backend(state.path(), &[])?;
    assert!(
        is_beating(&beat),
        "a process the pid file does not truly identify must survive the sweep"
    );
    for name in ["env-a", "env-b", "env-c", "env-d", "env-e", "env-f", "env-g"] {
        assert!(!state.path().join(name).exists(), "{name} is stale and must be removed");
    }
    drop(b);
    other.kill()?;
    other.wait()?;
    Ok(())
}

#[test]
fn a_second_backend_on_the_same_state_dir_is_refused_until_the_first_is_gone() -> Result<()> {
    let state = private_tempdir()?;
    let first = backend(state.path(), &[])?;
    assert!(
        backend(state.path(), &[]).is_err(),
        "two daemons must not sweep each other's live directories"
    );
    drop(first);
    assert!(backend(state.path(), &[]).is_ok());
    Ok(())
}

#[test]
fn a_state_dir_that_is_a_symlink_or_writable_by_others_is_refused() -> Result<()> {
    use std::os::unix::fs::symlink;
    let root = private_tempdir()?;
    let real = root.path().join("real");
    std::fs::create_dir(&real)?;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700))?;
    let link = root.path().join("link");
    symlink(&real, &link)?;
    assert!(
        ProcessEnvironmentBackend::new(config(&link, &[])).is_err(),
        "a symlinked state dir"
    );
    let open = root.path().join("open");
    std::fs::create_dir(&open)?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))?;
    assert!(
        ProcessEnvironmentBackend::new(config(&open, &[])).is_err(),
        "a world-writable state dir"
    );
    Ok(())
}

#[test]
fn a_pair_command_that_hangs_is_killed_with_its_children_and_fails_the_environment() -> Result<()> {
    let state = private_tempdir()?;
    let outside = tempfile::tempdir()?;
    let beat = outside.path().join("pair.beat");
    let mut c = config(state.path(), &[]);
    c.pair_command = Some(
        [FAKE, "pair-hang", "--beat-file", beat.to_str().context("utf8")?]
            .map(str::to_owned)
            .to_vec(),
    );
    c.pair_timeout = Duration::from_millis(600);
    let b = ProcessEnvironmentBackend::new(c)?;
    b.launch(&spec("env-1"))?;
    let p = wait_for(&b, "env-1", |p| matches!(p, Probe::Failed { .. }))?;
    let Probe::Failed { step, reason } = p else {
        bail!("not failed")
    };
    assert_eq!(step, "pair");
    assert!(reason.contains("timed out"), "{reason}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(has_stopped(&beat), "the hung pair command's children must die with it");
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn a_pair_command_that_cannot_start_leaves_no_pairing_file() -> Result<()> {
    let state = private_tempdir()?;
    let mut c = config(state.path(), &[]);
    c.pair_command = Some(vec!["/nonexistent/sandy-no-such-pair".to_owned()]);
    let b = ProcessEnvironmentBackend::new(c)?;
    b.launch(&spec("env-1"))?;
    let p = wait_for(&b, "env-1", |p| matches!(p, Probe::Failed { .. }))?;
    assert!(matches!(p, Probe::Failed { ref step, .. } if step == "pair"));
    assert!(!env_dir(state.path(), "env-1").join("pairing").exists());
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn reserved_variable_names_cannot_be_passed_through() -> Result<()> {
    let state = private_tempdir()?;
    for name in ["HOME", "PATH", "TMPDIR", "LANG"] {
        let mut c = config(state.path(), &[]);
        c.pass_env = vec![name.to_owned()];
        assert_eq!(c.validate(), Err(ProcessConfigError::ReservedEnv(name.to_owned())));
        assert!(ProcessEnvironmentBackend::new(c).is_err());
    }
    Ok(())
}

#[test]
fn a_status_line_split_across_tcp_segments_is_still_read() -> Result<()> {
    let state = private_tempdir()?;
    let b = backend(state.path(), &["--split-status"])?;
    b.launch(&spec("env-1"))?;
    wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))?;
    b.kill("env-1")?;
    Ok(())
}

#[test]
fn a_second_kill_removes_a_directory_the_first_could_not() -> Result<()> {
    let state = private_tempdir()?;
    let b = backend(state.path(), &[])?;
    b.launch(&spec("env-1"))?;
    b.kill("env-1")?;
    // A leftover directory for an id the backend no longer tracks.
    let leftover = env_dir(state.path(), "env-1");
    std::fs::create_dir(&leftover)?;
    std::fs::write(leftover.join("pairing"), "stale")?;
    b.kill("env-1")?;
    assert!(!leftover.exists(), "a retried kill must clear a leftover directory");
    Ok(())
}

#[test]
fn a_client_connected_to_the_service_makes_the_environment_active_until_it_disconnects() -> Result<()> {
    let state = private_tempdir()?;
    let b = backend(state.path(), &[])?;
    b.launch(&spec("env-1"))?;
    let Probe::Ready { endpoint } = wait_for(&b, "env-1", |p| matches!(p, Probe::Ready { .. }))? else {
        bail!("not ready")
    };
    assert!(!b.active("env-1")?, "no client is connected yet");
    let mut client = std::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port))?;
    client.write_all(b"HOLD")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !b.active("env-1")? {
        assert!(
            Instant::now() < deadline,
            "a connected client was never seen as activity"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(5);
    while b.active("env-1")? {
        assert!(Instant::now() < deadline, "a closed connection still reads as activity");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!b.active("no-such-env")?, "an unknown environment is not active");
    b.kill("env-1")?;
    Ok(())
}

/// Another local process takes the port between `free_port` and the service's bind (#637): the service stays up
/// without listening, and a stranger answers `200` on its port. That must not read as Ready.
#[test]
fn a_listener_that_is_not_the_service_never_reads_as_ready() -> Result<()> {
    let state = private_tempdir()?;
    let port_file = state.path().join("port.txt");
    let b = backend(
        state.path(),
        &["--no-bind", "--port-file", port_file.to_str().context("utf8 path")?],
    )?;
    b.launch(&spec("env-1"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let port: u16 = loop {
        if let Some(port) = std::fs::read_to_string(&port_file)
            .ok()
            .and_then(|t| t.trim().parse().ok())
        {
            break port;
        }
        if Instant::now() > deadline {
            bail!("the service never reported its port");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // This test process is not in the service's process group.
    let squatter = std::net::TcpListener::bind(("127.0.0.1", port)).context("take the service's port")?;
    std::thread::spawn(move || {
        for stream in squatter.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 512];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    let p = wait_for(&b, "env-1", |p| !matches!(p, Probe::Starting { .. }))?;
    let Probe::Failed { step, reason } = p else {
        bail!("a stranger's listener read as {p:?}")
    };
    assert_eq!(step, "port");
    assert!(reason.contains(&port.to_string()), "name the port: {reason}");
    b.kill("env-1")?;
    Ok(())
}
