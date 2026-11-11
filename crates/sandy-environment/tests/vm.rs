//! Acceptance tests for the VM-backed environment backend, over a hypervisor
//! double whose `run` holds until its control is cancelled.

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use sandy_api::{
    backend::{BackendError, BoxState, DirFingerprint, Outcome, RunSpec, VmBackend},
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};
use sandy_environment::{ConsoleSink, ConsoleTaps, ServiceProbe, VmEnvironmentBackend, VmEnvironmentConfig};

/// A run's secret share and whether it carried the `secrets` grant.
type SecretShare = (Option<(PathBuf, DirFingerprint)>, bool);

#[derive(Default)]
struct Seen {
    runs: AtomicUsize,
    commands: Mutex<Vec<Vec<String>>>,
    deadline_suspended: Mutex<Vec<bool>>,
    timeouts: Mutex<Vec<u32>>,
    agent_grant: Mutex<Vec<bool>>,
    envs: Mutex<Vec<Vec<(String, String)>>>,
    /// The secret share each run was given, and whether it carried the `secrets` grant.
    secret_dirs: Mutex<Vec<SecretShare>>,
}

/// Holds `run` until cancelled, like a booted VM; `die_after` makes it return by itself.
struct Holding {
    seen: Arc<Seen>,
    die_after: Option<Duration>,
    teardown: Duration,
    /// While set, `run` ignores cancel, like a hung hypervisor.
    stubborn: Option<Arc<AtomicBool>>,
}

impl VmBackend for Holding {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        self.seen.commands.lock().unwrap().push(spec.command.to_vec());
        self.seen
            .deadline_suspended
            .lock()
            .unwrap()
            .push(spec.control.deadline().is_none());
        self.seen
            .agent_grant
            .lock()
            .unwrap()
            .push(spec.grants.agent && !spec.grants.secrets);
        self.seen.envs.lock().unwrap().push(spec.env.to_vec());
        self.seen.secret_dirs.lock().unwrap().push((
            spec.secret_dir.map(|(dir, fp)| (dir.to_path_buf(), fp)),
            spec.grants.secrets,
        ));
        self.seen.timeouts.lock().unwrap().push(spec.timeout_secs);
        // Last, so a test that waits for the count reads every record below.
        self.seen.runs.fetch_add(1, Ordering::SeqCst);
        let start = Instant::now();
        while let Some(stuck) = self.stubborn.as_ref().filter(|s| s.load(Ordering::SeqCst)) {
            let _ = stuck;
            std::thread::sleep(Duration::from_millis(5));
        }
        while !spec.control.is_cancelled() {
            if self.die_after.is_some_and(|d| start.elapsed() >= d) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(self.teardown);
        Ok(Outcome {
            booted: true,
            guest_exit: None,
            transport_error: None,
            timed_out: false,
            console: String::new(),
            digests: None,
        })
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(Vec::new())
    }
}

fn spec(id: &str) -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: id.to_owned(),
        template: "service".to_owned(),
        size: None,
        env: vec![("K".to_owned(), "V".to_owned())],
        service_port: Some(3773),
        secret_dir: None,
    }
}

fn backend(die_after: Option<Duration>, teardown: Duration) -> (VmEnvironmentBackend, Arc<Seen>) {
    stubborn_backend(die_after, teardown, None)
}

fn stubborn_backend(
    die_after: Option<Duration>,
    teardown: Duration,
    stubborn: Option<Arc<AtomicBool>>,
) -> (VmEnvironmentBackend, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let s = Arc::clone(&seen);
    let b = VmEnvironmentBackend::new(
        Box::new(move |_| {
            Ok(Box::new(Holding {
                seen: Arc::clone(&s),
                die_after,
                teardown,
                stubborn: stubborn.clone(),
            }))
        }),
        VmEnvironmentConfig::new(vec!["service".to_owned(), "serve".to_owned()]),
    );
    (b, seen)
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) -> Result<()> {
    let start = Instant::now();
    while !ok() {
        anyhow::ensure!(start.elapsed() < Duration::from_secs(5), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[test]
fn launch_returns_before_the_run_ends_and_the_box_is_listed() -> Result<()> {
    let (b, seen) = backend(None, Duration::ZERO);
    assert_eq!(b.launch(&spec("env-a"))?, Launch::Started);
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    let boxes = b.boxes()?;
    assert_eq!(boxes.len(), 1);
    assert_eq!(boxes[0].box_id, "env-a");
    assert!(matches!(b.probe("env-a")?, Probe::Starting { .. }));
    Ok(())
}

#[test]
fn the_run_gets_the_service_command_and_no_deadline() -> Result<()> {
    let (b, seen) = backend(None, Duration::ZERO);
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    assert_eq!(seen.commands.lock().unwrap()[0], ["service", "serve"]);
    assert!(
        seen.agent_grant.lock().unwrap()[0],
        "agent mode: the agent grant on, secrets off"
    );
    assert_eq!(seen.envs.lock().unwrap()[0], [("K".to_owned(), "V".to_owned())]);
    assert!(
        seen.deadline_suspended.lock().unwrap()[0],
        "an environment must not time out"
    );
    Ok(())
}

#[test]
fn launching_a_running_id_starts_no_second_vm() -> Result<()> {
    let (b, seen) = backend(None, Duration::ZERO);
    assert_eq!(b.launch(&spec("env-a"))?, Launch::Started);
    assert_eq!(b.launch(&spec("env-a"))?, Launch::AlreadyRunning);
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) >= 1)?;
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(seen.runs.load(Ordering::SeqCst), 1, "one VM per environment");
    Ok(())
}

#[test]
fn kill_ends_the_run_clears_the_box_and_is_idempotent() -> Result<()> {
    let (b, seen) = backend(None, Duration::from_millis(50));
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    b.kill("env-a")?;
    assert!(b.boxes()?.is_empty());
    assert_eq!(b.probe("env-a")?, Probe::NotRunning);
    b.kill("env-a")?;
    b.kill("never-launched")?;
    Ok(())
}

#[test]
fn a_run_that_returns_by_itself_is_not_running_and_can_be_launched_again() -> Result<()> {
    let (b, seen) = backend(Some(Duration::from_millis(30)), Duration::ZERO);
    b.launch(&spec("env-a"))?;
    wait_for("the VM to exit", || matches!(b.probe("env-a"), Ok(Probe::NotRunning)))?;
    assert!(b.boxes()?.is_empty(), "a dead box must not be listed");
    assert_eq!(b.launch(&spec("env-a"))?, Launch::Started, "a dead box is replaced");
    wait_for("the second run", || seen.runs.load(Ordering::SeqCst) == 2)?;
    Ok(())
}

#[test]
fn a_factory_failure_is_a_spawn_error_and_leaves_no_box() -> Result<()> {
    let b = VmEnvironmentBackend::new(
        Box::new(|_| Err(BackendError::Spawn("no qemu".to_owned()))),
        VmEnvironmentConfig::new(vec![]),
    );
    let err = b.launch(&spec("env-a")).err().context("expected an error")?;
    assert!(matches!(err, BackendError::Spawn(_)));
    assert!(b.boxes()?.is_empty());
    assert_eq!(b.probe("env-a")?, Probe::NotRunning);
    Ok(())
}

struct ReadyAt;
impl ServiceProbe for ReadyAt {
    fn probe(&self, _id: &str) -> Result<Probe, BackendError> {
        Ok(Probe::Ready {
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 40000,
            },
        })
    }
}

#[test]
fn the_service_probe_decides_readiness_only_while_the_run_is_up() -> Result<()> {
    let (b, seen) = backend(None, Duration::ZERO);
    let b = b.with_service_probe(Arc::new(ReadyAt));
    assert_eq!(
        b.probe("env-a")?,
        Probe::NotRunning,
        "a probe never reports Ready for an id with no run"
    );
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    assert!(matches!(b.probe("env-a")?, Probe::Ready { .. }));
    b.kill("env-a")?;
    assert_eq!(b.probe("env-a")?, Probe::NotRunning);
    Ok(())
}

#[test]
fn a_slow_teardown_blocks_one_kill_not_another_environment() -> Result<()> {
    let (b, seen) = backend(None, Duration::from_millis(400));
    let b = Arc::new(b);
    b.launch(&spec("env-a"))?;
    b.launch(&spec("env-b"))?;
    wait_for("both runs", || seen.runs.load(Ordering::SeqCst) == 2)?;
    let slow = Arc::clone(&b);
    let t = std::thread::spawn(move || slow.kill("env-a"));
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    assert_eq!(b.boxes()?.iter().filter(|x| x.box_id == "env-b").count(), 1);
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "boxes() must not wait for another kill"
    );
    t.join().map_err(|_| anyhow::anyhow!("kill thread panicked"))??;
    Ok(())
}

#[test]
fn dropping_the_backend_cancels_every_run() -> Result<()> {
    let (b, seen) = backend(None, Duration::ZERO);
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    drop(b); // joins the run thread: it returns only because it was cancelled
    Ok(())
}

#[test]
fn a_launch_during_a_slow_kill_is_refused_and_starts_no_second_vm() -> Result<()> {
    let (b, seen) = backend(None, Duration::from_millis(500));
    let b = Arc::new(b);
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    let killer = Arc::clone(&b);
    let t = std::thread::spawn(move || killer.kill("env-a"));
    // The box is still alive while it tears down, so it stays listed and the id is not free.
    wait_for("the kill to mark the entry", || {
        matches!(b.probe("env-a"), Ok(Probe::NotRunning))
    })?;
    assert_eq!(b.boxes()?.len(), 1, "a box that is tearing down is still a box");
    let err = b
        .launch(&spec("env-a"))
        .err()
        .context("a launch during a kill must be refused")?;
    assert!(matches!(err, BackendError::Spawn(_)));
    t.join().map_err(|_| anyhow::anyhow!("kill thread panicked"))??;
    assert_eq!(
        seen.runs.load(Ordering::SeqCst),
        1,
        "no second VM while the first tears down"
    );
    assert_eq!(
        b.launch(&spec("env-a"))?,
        Launch::Started,
        "the id is free after the kill"
    );
    wait_for("the second run", || seen.runs.load(Ordering::SeqCst) == 2)?;
    Ok(())
}

#[test]
fn two_concurrent_kills_both_return_only_after_the_run_ended() -> Result<()> {
    let (b, seen) = backend(None, Duration::from_millis(300));
    let b = Arc::new(b);
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    let (k1, k2) = (Arc::clone(&b), Arc::clone(&b));
    let t1 = std::thread::spawn(move || k1.kill("env-a"));
    std::thread::sleep(Duration::from_millis(50));
    let t2 = std::thread::spawn(move || k2.kill("env-a"));
    t1.join().map_err(|_| anyhow::anyhow!("kill 1 panicked"))??;
    t2.join().map_err(|_| anyhow::anyhow!("kill 2 panicked"))??;
    assert!(b.boxes()?.is_empty());
    Ok(())
}

#[test]
fn a_kill_that_times_out_keeps_the_box_so_a_retry_ends_it() -> Result<()> {
    let stuck = Arc::new(AtomicBool::new(true));
    let (b, seen) = stubborn_backend(None, Duration::ZERO, Some(Arc::clone(&stuck)));
    let b = b.with_kill_wait(Duration::from_millis(150));
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    assert!(matches!(b.kill("env-a"), Err(BackendError::Transport(_))));
    assert_eq!(b.boxes()?.len(), 1, "a VM that did not stop must stay listed");
    assert_eq!(
        b.launch(&spec("env-a"))?,
        Launch::AlreadyRunning,
        "and must not be replaced"
    );
    stuck.store(false, Ordering::SeqCst);
    b.kill("env-a")?;
    assert!(b.boxes()?.is_empty());
    Ok(())
}

#[test]
fn dropping_the_backend_does_not_hang_on_a_run_that_ignores_cancel() -> Result<()> {
    let stuck = Arc::new(AtomicBool::new(true));
    let (b, seen) = stubborn_backend(None, Duration::ZERO, Some(Arc::clone(&stuck)));
    let b = b.with_kill_wait(Duration::from_millis(150));
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    let start = Instant::now();
    drop(b);
    assert!(start.elapsed() < Duration::from_secs(3), "drop must give up, not hang");
    stuck.store(false, Ordering::SeqCst);
    Ok(())
}

#[test]
fn the_config_env_follows_the_spec_env_and_the_boot_budget_reaches_the_run() -> Result<()> {
    let seen = Arc::new(Seen::default());
    let s = Arc::clone(&seen);
    let mut config = VmEnvironmentConfig::new(vec!["service".to_owned()]);
    config.env = vec![
        ("SANDY_SERVICE".to_owned(), "{}".to_owned()),
        ("K".to_owned(), "config-wins".to_owned()),
    ];
    config.boot_timeout_secs = 321;
    let b = VmEnvironmentBackend::new(
        Box::new(move |_| {
            Ok(Box::new(Holding {
                seen: Arc::clone(&s),
                die_after: None,
                teardown: Duration::ZERO,
                stubborn: None,
            }))
        }),
        config,
    );
    b.launch(&spec("env-a"))?;
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    let env = seen.envs.lock().unwrap()[0].clone();
    assert_eq!(
        env,
        [
            ("K".to_owned(), "V".to_owned()),
            ("SANDY_SERVICE".to_owned(), "{}".to_owned()),
            ("K".to_owned(), "config-wins".to_owned()),
        ],
        "the config env comes last, so a consumer reading the last entry sees it win"
    );
    assert_eq!(seen.timeouts.lock().unwrap()[0], 321, "a real boot budget, not zero");
    Ok(())
}

/// A hypervisor backend whose run panics at once.
struct Panicking;
impl VmBackend for Panicking {
    fn run(&self, _spec: &RunSpec) -> Result<Outcome, BackendError> {
        panic!("the hypervisor backend panicked");
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(Vec::new())
    }
}

#[test]
fn a_run_that_panics_is_not_running_and_does_not_make_drop_wait() -> Result<()> {
    let b = VmEnvironmentBackend::new(Box::new(|_| Ok(Box::new(Panicking))), VmEnvironmentConfig::new(vec![]))
        .with_kill_wait(Duration::from_secs(20));
    b.launch(&spec("env-a"))?;
    wait_for("the dead box to read as not running", || {
        matches!(b.probe("env-a"), Ok(Probe::NotRunning))
    })?;
    assert!(b.boxes()?.is_empty(), "a panicked run must not stay listed");
    let start = Instant::now();
    drop(b);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "drop waited {:?} on a dead thread",
        start.elapsed()
    );
    Ok(())
}

/// Prints `lines` on its console sink, then holds until cancelled, like a booted guest whose service never starts.
struct Printing {
    sink: ConsoleSink,
    lines: &'static str,
    printed: Arc<AtomicBool>,
}

impl VmBackend for Printing {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        (self.sink)(self.lines.as_bytes());
        self.printed.store(true, Ordering::SeqCst);
        while !spec.control.is_cancelled() {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Outcome {
            booted: true,
            guest_exit: None,
            transport_error: None,
            timed_out: false,
            console: String::new(),
            digests: None,
        })
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(Vec::new())
    }
}

/// Each launch prints the next of `launches`.
fn printing_backend(launches: &[&'static str], printed: Arc<AtomicBool>, with_taps: bool) -> VmEnvironmentBackend {
    let taps = Arc::new(ConsoleTaps::new());
    let factory_taps = Arc::clone(&taps);
    let queue = Mutex::new(launches.iter().copied().collect::<std::collections::VecDeque<_>>());
    let b = VmEnvironmentBackend::new(
        Box::new(move |spec| {
            let lines = queue.lock().unwrap().pop_front().unwrap_or("");
            Ok(Box::new(Printing {
                sink: factory_taps.sink_for(&spec.environment_id),
                lines,
                printed: Arc::clone(&printed),
            }))
        }),
        VmEnvironmentConfig::new(vec!["service".to_owned()]),
    );
    if with_taps { b.with_console_taps(taps) } else { b }
}

/// #727: the console is what a failed provision has to show, and the driver asks only after it has killed the box.
#[test]
fn the_console_tail_survives_the_kill_and_is_handed_over_once() -> Result<()> {
    let printed = Arc::new(AtomicBool::new(false));
    let b = printing_backend(
        &["Booting\n\x1b[31msocat: bind failed\x1b[0m\n"],
        Arc::clone(&printed),
        true,
    );
    assert_eq!(b.launch(&spec("env-a"))?, Launch::Started);
    wait_for("the console output", || printed.load(Ordering::SeqCst))?;
    b.kill("env-a")?;
    assert_eq!(b.console_tail("env-a").as_deref(), Some("Booting\nsocat: bind failed"));
    assert_eq!(b.console_tail("env-a"), None, "the tail is handed over once");
    Ok(())
}

/// A relaunch of the same id must not inherit the first run's console.
#[test]
fn a_relaunch_does_not_report_the_earlier_runs_console() -> Result<()> {
    let printed = Arc::new(AtomicBool::new(false));
    let b = printing_backend(&["first boot\n", "second boot\n"], Arc::clone(&printed), true);
    b.launch(&spec("env-a"))?;
    wait_for("the first console output", || printed.load(Ordering::SeqCst))?;
    b.kill("env-a")?;
    printed.store(false, Ordering::SeqCst);
    b.launch(&spec("env-a"))?;
    wait_for("the second console output", || printed.load(Ordering::SeqCst))?;
    b.kill("env-a")?;
    assert_eq!(
        b.console_tail("env-a").as_deref(),
        Some("second boot"),
        "only the new run's own print"
    );
    assert_eq!(b.console_tail("env-a"), None);
    Ok(())
}

/// Without taps (every other composition) there is no tail, and nothing fails.
#[test]
fn a_backend_without_console_taps_has_no_tail() -> Result<()> {
    let printed = Arc::new(AtomicBool::new(false));
    let b = printing_backend(&["boot\n"], Arc::clone(&printed), false);
    b.launch(&spec("env-a"))?;
    wait_for("the console output", || printed.load(Ordering::SeqCst))?;
    b.kill("env-a")?;
    assert_eq!(b.console_tail("env-a"), None);
    Ok(())
}

#[test]
fn a_secret_dir_is_forwarded_to_the_run_with_the_secrets_grant() -> Result<()> {
    let (b, seen) = backend(None, Duration::ZERO);
    let fingerprint = DirFingerprint { dev: 7, ino: 11 };
    let mut with_secrets = spec("env-s");
    with_secrets.secret_dir = Some((PathBuf::from("/run/sandy/env-s"), fingerprint));
    assert_eq!(b.launch(&with_secrets)?, Launch::Started);
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    let dirs = seen.secret_dirs.lock().unwrap().clone();
    assert_eq!(
        dirs,
        vec![(Some((PathBuf::from("/run/sandy/env-s"), fingerprint)), true)]
    );
    Ok(())
}

#[test]
fn a_spec_without_a_secret_dir_mounts_no_secret_share() -> Result<()> {
    let (b, seen) = backend(None, Duration::ZERO);
    assert_eq!(b.launch(&spec("env-n"))?, Launch::Started);
    wait_for("the run to start", || seen.runs.load(Ordering::SeqCst) == 1)?;
    let dirs = seen.secret_dirs.lock().unwrap().clone();
    assert_eq!(dirs, vec![(None, false)]);
    Ok(())
}
