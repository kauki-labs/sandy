//! Acceptance tests for tying a hook's guard to the run, over a hypervisor double.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use sandy_api::{
    backend::{BackendError, BoxState, Outcome, RunControl, RunSpec, VmBackend},
    environment::{EnvironmentBackend, EnvironmentSpec},
};
use sandy_environment::{RunGuards, VmEnvironmentBackend, VmEnvironmentConfig, guarded};

/// Drops a flag when released: stands for a bridge plus its probe registration.
struct Bridge(Arc<AtomicBool>);
impl Drop for Bridge {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn outcome() -> Outcome {
    Outcome {
        booted: true,
        guest_exit: None,
        transport_error: None,
        timed_out: false,
        console: String::new(),
        digests: None,
    }
}

/// A run that "boots" (calls the hook), then holds until cancelled. `panic_after_hook` makes it panic instead.
struct Vm {
    hook: Arc<dyn Fn() + Send + Sync>,
    panic_after_hook: bool,
    fail: bool,
}

impl VmBackend for Vm {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        (self.hook)();
        assert!(!self.panic_after_hook, "the hypervisor backend panicked");
        if self.fail {
            return Err(BackendError::Spawn("boom".to_owned()));
        }
        wait_cancel(spec.control);
        Ok(outcome())
    }

    fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(Vec::new())
    }
}

fn wait_cancel(control: &RunControl) {
    while !control.is_cancelled() {
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) -> Result<()> {
    let start = Instant::now();
    while !ok() {
        if start.elapsed() > Duration::from_secs(5) {
            bail!("timed out waiting for {what}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn spec() -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: "env-a".to_owned(),
        template: "t3".to_owned(),
        size: None,
        env: vec![],
        service_port: None,
    }
}

fn backend(
    panic_after_hook: bool,
    fail: bool,
    released: &Arc<AtomicBool>,
    hooks: &Arc<AtomicUsize>,
) -> VmEnvironmentBackend {
    let (released, hooks) = (Arc::clone(released), Arc::clone(hooks));
    VmEnvironmentBackend::new(
        Box::new(move |_| {
            let guards = RunGuards::new();
            let (g, r, h) = (guards.clone(), Arc::clone(&released), Arc::clone(&hooks));
            let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                h.fetch_add(1, Ordering::SeqCst);
                g.hold(Box::new(Bridge(Arc::clone(&r))));
            });
            Ok(Box::new(guarded(
                Vm {
                    hook,
                    panic_after_hook,
                    fail,
                },
                &guards,
            )))
        }),
        VmEnvironmentConfig::new(vec![]),
    )
}

#[test]
fn what_the_hook_started_is_released_when_the_run_is_cancelled() -> Result<()> {
    let (released, hooks) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
    let b = backend(false, false, &released, &hooks);
    b.launch(&spec())?;
    wait_for("the hook", || hooks.load(Ordering::SeqCst) == 1)?;
    assert!(
        !released.load(Ordering::SeqCst),
        "the bridge must live while the run is up"
    );
    b.kill("env-a")?;
    assert!(
        released.load(Ordering::SeqCst),
        "the bridge must be gone once the run ended"
    );
    Ok(())
}

#[test]
fn a_run_that_fails_or_panics_still_releases_it() -> Result<()> {
    for (panic, fail) in [(false, true), (true, false)] {
        let (released, hooks) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
        let b = backend(panic, fail, &released, &hooks);
        b.launch(&spec())?;
        wait_for("the bridge to be released", || released.load(Ordering::SeqCst))?;
    }
    Ok(())
}

#[test]
fn a_hook_that_fires_after_the_run_ended_has_its_guard_dropped_at_once() {
    let guards = RunGuards::new();
    struct Inner;
    impl VmBackend for Inner {
        fn run(&self, _spec: &RunSpec) -> Result<Outcome, BackendError> {
            Ok(outcome())
        }

        fn kill(&self, _box_id: &str) -> Result<(), BackendError> {
            Ok(())
        }

        fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
            Ok(Vec::new())
        }
    }
    let released = Arc::new(AtomicBool::new(false));
    let backend = guarded(Inner, &guards);
    drop(backend); // the run is over
    guards.hold(Box::new(Bridge(Arc::clone(&released))));
    assert!(
        released.load(Ordering::SeqCst),
        "a late hook must not leave a bridge behind"
    );
}

#[test]
fn a_second_guard_replaces_the_first_and_drops_it() {
    let guards = RunGuards::new();
    let (first, second) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    guards.hold(Box::new(Bridge(Arc::clone(&first))));
    guards.hold(Box::new(Bridge(Arc::clone(&second))));
    assert!(first.load(Ordering::SeqCst), "the replaced guard is dropped");
    assert!(!second.load(Ordering::SeqCst));
    let _ = Mutex::new(());
}
