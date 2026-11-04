//! Acceptance tests for the VM-backed environment backend, over a hypervisor
//! double whose `run` holds until its control is cancelled.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use sandy_api::{
    backend::{BackendError, BoxState, Outcome, RunSpec, VmBackend},
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};
use sandy_environment::{ServiceProbe, VmEnvironmentBackend, VmEnvironmentConfig};

#[derive(Default)]
struct Seen {
    runs: AtomicUsize,
    commands: Mutex<Vec<Vec<String>>>,
    deadline_suspended: Mutex<Vec<bool>>,
    agent_grant: Mutex<Vec<bool>>,
    envs: Mutex<Vec<Vec<(String, String)>>>,
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
        self.seen.runs.fetch_add(1, Ordering::SeqCst);
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
        template: "t3".to_owned(),
        size: None,
        env: vec![("K".to_owned(), "V".to_owned())],
        service_port: Some(3773),
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
        VmEnvironmentConfig {
            command: vec!["t3".to_owned(), "serve".to_owned()],
        },
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
    assert_eq!(seen.commands.lock().unwrap()[0], ["t3", "serve"]);
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
        VmEnvironmentConfig { command: vec![] },
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
