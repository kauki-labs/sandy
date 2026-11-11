//! Acceptance tests for the graceful stop (#670): `kill` asks the guest to stop first, waits out the grace, and
//! only then cancels the run, over a hypervisor double.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use sandy_api::{
    backend::{BackendError, BoxState, Outcome, RunSpec, VmBackend},
    environment::{EnvironmentBackend, EnvironmentSpec},
};
use sandy_environment::{StopRequest, VmEnvironmentBackend, VmEnvironmentConfig};

/// Whole seconds, since the wire carries a `u32`; a smaller value would be rounded up to it.
const GRACE: Duration = Duration::from_secs(1);
const MARGIN: Duration = Duration::from_millis(300);

/// A run held until it is cancelled or the guest "stops": it records whether its control had been cancelled when
/// it returned, which tells a guest-driven exit from a forced one.
struct Vm {
    stopped: Arc<AtomicBool>,
    cancelled_at_exit: Arc<Mutex<Option<bool>>>,
}

impl VmBackend for Vm {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        while !spec.control.is_cancelled() && !self.stopped.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        *self
            .cancelled_at_exit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(spec.control.is_cancelled());
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

/// Stands for the guest agent: `obeys` says whether the stop makes the run return, `fails` that the request
/// itself could not be sent.
struct Stopper {
    stopped: Arc<AtomicBool>,
    obeys: bool,
    fails: bool,
    asked: Arc<Mutex<Vec<(String, Duration)>>>,
}

impl StopRequest for Stopper {
    fn request_stop(&self, environment_id: &str, grace: Duration) -> Result<(), BackendError> {
        self.asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((environment_id.to_owned(), grace));
        if self.fails {
            return Err(BackendError::Transport("the link is gone".to_owned()));
        }
        if self.obeys {
            self.stopped.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

struct Fixture {
    backend: VmEnvironmentBackend,
    cancelled_at_exit: Arc<Mutex<Option<bool>>>,
    asked: Arc<Mutex<Vec<(String, Duration)>>>,
}

fn fixture(obeys: bool, fails: bool) -> Fixture {
    let stopped = Arc::new(AtomicBool::new(false));
    let cancelled_at_exit = Arc::new(Mutex::new(None));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let (vm_stopped, vm_cancelled) = (Arc::clone(&stopped), Arc::clone(&cancelled_at_exit));
    let backend = VmEnvironmentBackend::new(
        Box::new(move |_| {
            Ok(Box::new(Vm {
                stopped: Arc::clone(&vm_stopped),
                cancelled_at_exit: Arc::clone(&vm_cancelled),
            }))
        }),
        VmEnvironmentConfig::new(vec![]),
    )
    .with_stop_margin(MARGIN)
    .with_graceful_stop(
        Arc::new(Stopper {
            stopped,
            obeys,
            fails,
            asked: Arc::clone(&asked),
        }),
        GRACE,
    );
    Fixture {
        backend,
        cancelled_at_exit,
        asked,
    }
}

fn spec() -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: "env-a".to_owned(),
        template: "service".to_owned(),
        size: None,
        env: vec![],
        service_port: None,
        secret_dir: None,
    }
}

fn wait_until_up(backend: &VmEnvironmentBackend) -> Result<()> {
    let start = Instant::now();
    while backend.boxes()?.is_empty() {
        if start.elapsed() > Duration::from_secs(5) {
            bail!("the environment never came up");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn exit_state(fixture: &Fixture) -> Option<bool> {
    *fixture
        .cancelled_at_exit
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn a_guest_that_obeys_the_stop_ends_the_run_without_a_cancel() -> Result<()> {
    let fixture = fixture(true, false);
    fixture.backend.launch(&spec())?;
    wait_until_up(&fixture.backend)?;

    let start = Instant::now();
    fixture.backend.kill("env-a")?;

    assert!(start.elapsed() < GRACE, "an obeyed stop must not wait the whole grace");
    assert_eq!(exit_state(&fixture), Some(false), "the run ended before any cancel");
    let asked = fixture
        .asked
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(asked, vec![("env-a".to_owned(), GRACE)]);
    Ok(())
}

#[test]
fn a_guest_that_ignores_the_stop_is_cancelled_after_the_grace() -> Result<()> {
    let fixture = fixture(false, false);
    fixture.backend.launch(&spec())?;
    wait_until_up(&fixture.backend)?;

    let start = Instant::now();
    fixture.backend.kill("env-a")?;

    assert!(
        start.elapsed() >= GRACE,
        "the guest gets its whole grace first: {:?}",
        start.elapsed()
    );
    assert_eq!(
        exit_state(&fixture),
        Some(true),
        "then the run is cancelled, today's kill"
    );
    Ok(())
}

#[test]
fn a_stop_that_cannot_be_sent_falls_back_to_the_cancel_at_once() -> Result<()> {
    let fixture = fixture(false, true);
    fixture.backend.launch(&spec())?;
    wait_until_up(&fixture.backend)?;

    let start = Instant::now();
    fixture.backend.kill("env-a")?;

    assert!(
        start.elapsed() < GRACE,
        "there is nothing to wait for: {:?}",
        start.elapsed()
    );
    assert_eq!(exit_state(&fixture), Some(true));
    Ok(())
}

#[test]
fn a_sub_second_grace_is_asked_as_whole_seconds() -> Result<()> {
    let stopped = Arc::new(AtomicBool::new(false));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let (vm_stopped, cancelled) = (Arc::clone(&stopped), Arc::new(Mutex::new(None)));
    let backend = VmEnvironmentBackend::new(
        Box::new(move |_| {
            Ok(Box::new(Vm {
                stopped: Arc::clone(&vm_stopped),
                cancelled_at_exit: Arc::clone(&cancelled),
            }))
        }),
        VmEnvironmentConfig::new(vec![]),
    )
    .with_graceful_stop(
        Arc::new(Stopper {
            stopped,
            obeys: true,
            fails: false,
            asked: Arc::clone(&asked),
        }),
        Duration::from_millis(1),
    );
    backend.launch(&spec())?;
    wait_until_up(&backend)?;
    backend.kill("env-a")?;
    let asked = asked.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(
        asked,
        vec![("env-a".to_owned(), Duration::from_secs(1))],
        "1 ms asks for 1 s, not 0"
    );
    Ok(())
}
