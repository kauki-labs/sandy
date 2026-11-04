//! Acceptance tests for the VM-backed environment backend, over a hypervisor
//! double whose `run` holds until its control is cancelled.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
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
}

/// Holds `run` until cancelled, like a booted VM; `die_after` makes it return by itself.
struct Holding {
    seen: Arc<Seen>,
    die_after: Option<Duration>,
    teardown: Duration,
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
        let start = Instant::now();
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
    let seen = Arc::new(Seen::default());
    let s = Arc::clone(&seen);
    let b = VmEnvironmentBackend::new(
        Box::new(move |_| {
            Ok(Box::new(Holding {
                seen: Arc::clone(&s),
                die_after,
                teardown,
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
