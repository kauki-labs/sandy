//! The VM-backed [`EnvironmentBackend`] (#587 slice C3a): one held, agent-mode
//! [`VmBackend::run`] per environment.
//!
//! The box is the run. `launch` starts `run()` on its own thread and returns
//! at once; the run stays up until `kill` cancels its [`RunControl`], which
//! tears the box down through the hypervisor backend's own teardown. Boot,
//! shares, the egress proxy and the agent launch are reused as they are, on
//! qemu and on vfkit.
//!
//! Readiness is not decided here. While the run is up, `probe` asks the
//! [`ServiceProbe`] (the host bridge, slice C3b) and reports `Starting` until
//! one is set. A run that returned is `NotRunning`: the VM exited on its own.
//!
//! One hypervisor backend serves one environment (agent mode runs one job per
//! backend), so the caller supplies a factory.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};

use sandy_api::{
    backend::{BackendError, BoxState, Grants, RunControl, RunSpec, VmBackend},
    environment::{EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};

/// How long `kill` waits for a cancelled run to return before it reports a
/// teardown fault and keeps the entry for a retry.
const KILL_WAIT: Duration = Duration::from_secs(30);

/// How long past the grace `kill` keeps waiting for a stopped guest, before it cancels: the stop reaches the agent
/// after the host starts counting, and the agent needs a few seconds after forcing the job to notice and exit.
const STOP_MARGIN: Duration = Duration::from_secs(5);

/// A hypervisor backend an environment's run is held on.
pub type HeldBackend = Box<dyn VmBackend + Send>;

/// Builds the hypervisor backend for one environment.
pub type BackendFactory = Box<dyn Fn(&EnvironmentSpec) -> Result<HeldBackend, BackendError> + Send + Sync>;

/// Decides readiness for a box whose run is up (the host bridge dials the
/// service, slice C3b).
pub trait ServiceProbe: Send + Sync {
    /// One probe of environment `environment_id`'s service.
    ///
    /// # Errors
    /// [`BackendError::Transport`] or [`BackendError::Protocol`] if the probe itself could not run.
    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError>;
}

/// Asks a running guest to stop its job gracefully (#670): the agent interrupts it, gives it the grace, then ends
/// it. Implemented by whoever holds the environment's agent link and can post the stop on its channel.
pub trait StopRequest: Send + Sync {
    /// Ask environment `environment_id`'s guest to stop, with `grace` for the job to exit on its own. Returns once
    /// the request is sent, not once the guest has stopped. `grace` is whole seconds: the wire carries a `u32`.
    ///
    /// The request must reach this launch's agent only. A stop is a stored channel message that a late subscriber
    /// replays, so an implementation posts it on a channel that belongs to one launch, never one a relaunch
    /// reuses, or the new guest would stop at once.
    ///
    /// # Errors
    /// [`BackendError::Transport`] if the request could not be sent; `kill` then cancels the run at once.
    fn request_stop(&self, environment_id: &str, grace: Duration) -> Result<(), BackendError>;
}

/// What the held run is told about every environment.
#[derive(Debug, Clone)]
pub struct VmEnvironmentConfig {
    /// The guest command the agent runs as its job: the service.
    pub command: Vec<String>,
    /// Guest environment added after the environment spec's own, so a repeated key here wins. In agent mode only
    /// `SANDY_SERVICE` and `SANDY_HISTORY_LINES` reach the guest (`impls/vm`'s `agent_command_argv`); every other key
    /// is dropped there. The service spec (`SANDY_SERVICE`) goes here: without it the agent runs `command` as a
    /// plain job and never probes.
    pub env: Vec<(String, String)>,
    /// Sizes the hypervisor backend's connect budgets (the serial connect, capped at 10 s, and the vsock link
    /// connector, twice this plus 120 s), so zero would give a real qemu one second. It is not a boot timeout: the
    /// run's deadline is suspended, and the driver's provision timeout bounds a boot that never gets Ready.
    pub boot_timeout_secs: u32,
}

impl VmEnvironmentConfig {
    /// A config that runs `command`, with no extra environment and a ten-minute boot budget.
    #[must_use]
    pub fn new(command: Vec<String>) -> Self {
        Self {
            command,
            env: Vec::new(),
            boot_timeout_secs: 600,
        }
    }
}

struct Held {
    control: RunControl,
    /// Set by the run thread when `run()` returns, however it ends.
    done: Arc<AtomicBool>,
    /// Taken by the kill that owns the teardown.
    thread: Option<JoinHandle<()>>,
    /// A kill is tearing the box down: the id is not free until it finishes.
    killing: bool,
    generation: u64,
    started: SystemTime,
}

impl Held {
    fn up(&self) -> bool {
        !self.done.load(Ordering::SeqCst)
    }
}

/// An [`EnvironmentBackend`] over a hypervisor [`VmBackend`].
pub struct VmEnvironmentBackend {
    factory: BackendFactory,
    config: VmEnvironmentConfig,
    service: Option<Arc<dyn ServiceProbe>>,
    /// Asked to stop the guest before `kill` cancels the run, with the grace it gets (#670).
    graceful_stop: Option<(Arc<dyn StopRequest>, Duration)>,
    stop_margin: Duration,
    kill_wait: Duration,
    next_generation: AtomicU64,
    held: Mutex<BTreeMap<String, Held>>,
}

impl VmEnvironmentBackend {
    /// A backend that builds each environment's hypervisor backend with `factory`.
    #[must_use]
    pub fn new(factory: BackendFactory, config: VmEnvironmentConfig) -> Self {
        Self {
            factory,
            config,
            service: None,
            graceful_stop: None,
            stop_margin: STOP_MARGIN,
            kill_wait: KILL_WAIT,
            next_generation: AtomicU64::new(0),
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// Decide readiness with `service` once a run is up.
    #[must_use]
    pub fn with_service_probe(mut self, service: Arc<dyn ServiceProbe>) -> Self {
        self.service = Some(service);
        self
    }

    /// Have `kill` ask the guest to stop through `stop` and wait for the run to return before it cancels (#670):
    /// `grace` rounded up to whole seconds, plus a margin for the request to arrive and the agent to exit after it
    /// forces the job. Without this, `kill` cancels at once: the guest never gets to run its teardown.
    #[must_use]
    pub fn with_graceful_stop(mut self, stop: Arc<dyn StopRequest>, grace: Duration) -> Self {
        self.graceful_stop = Some((stop, grace));
        self
    }

    /// The time past the grace `kill` keeps waiting for a stopped guest. Five seconds by default.
    #[must_use]
    pub fn with_stop_margin(mut self, margin: Duration) -> Self {
        self.stop_margin = margin;
        self
    }

    /// How long `kill` and drop wait for a cancelled run to return.
    #[must_use]
    pub fn with_kill_wait(mut self, wait: Duration) -> Self {
        self.kill_wait = wait;
        self
    }

    /// Ask the guest to stop and give the run up to the grace (whole seconds, rounded up) plus the margin to return
    /// on its own. A run that already ended needs no stop, and a request that cannot be sent ends the wait at once:
    /// nothing is going to stop the guest.
    fn stop_gracefully(&self, stop: &dyn StopRequest, environment_id: &str, grace: Duration, done: &AtomicBool) {
        if done.load(Ordering::SeqCst) {
            return;
        }
        let grace = Duration::from_secs(grace.as_secs() + u64::from(grace.subsec_nanos() > 0));
        if let Err(e) = stop.request_stop(environment_id, grace) {
            tracing::warn!(environment = %environment_id, error = %e, "asking the guest to stop failed; cancelling the run");
            return;
        }
        let wait = grace + self.stop_margin;
        let start = Instant::now();
        while !done.load(Ordering::SeqCst) && start.elapsed() < wait {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Held>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The held run: no deadline, since an environment lives until it is killed.
fn hold(
    backend: &HeldBackend,
    spec: &EnvironmentSpec,
    config: &VmEnvironmentConfig,
    control: &RunControl,
) -> Result<(), BackendError> {
    control.suspend_deadline();
    let env: Vec<(String, String)> = spec.env.iter().chain(&config.env).cloned().collect();
    let run = RunSpec {
        digests: false,
        template: &spec.template,
        command: &config.command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &env,
        cpu: None,
        mem: None,
        timeout_secs: config.boot_timeout_secs,
        control,
        grants: &Grants {
            secrets: spec.secret_dir.is_some(),
            agent: true,
            shares: false,
        },
        outcome_file: None,
        // The caller owns this dir and may rewrite a staged file while the guest runs (#706).
        secret_dir: spec
            .secret_dir
            .as_ref()
            .map(|(dir, fingerprint)| (dir.as_path(), *fingerprint)),
        egress: None,
    };
    let outcome = backend.run(&run)?;
    tracing::info!(
        booted = outcome.booted,
        guest_exit = ?outcome.guest_exit,
        transport_error = ?outcome.transport_error,
        "an environment's held run returned"
    );
    Ok(())
}

/// Sets its flag when dropped, so the flag is set on a panic unwind too.
struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl EnvironmentBackend for VmEnvironmentBackend {
    fn launch(&self, spec: &EnvironmentSpec) -> Result<Launch, BackendError> {
        if let Some(outcome) = self.existing(&spec.environment_id)? {
            return Ok(outcome);
        }
        // Built outside the lock: a slow factory must not block other environments.
        let backend = (self.factory)(spec)?;
        let mut held = self.lock();
        // Another launch may have won the id while the factory ran.
        if let Some(entry) = held.get(&spec.environment_id) {
            if entry.up() {
                return if entry.killing {
                    Err(still_stopping(&spec.environment_id))
                } else {
                    Ok(Launch::AlreadyRunning)
                };
            }
            held.remove(&spec.environment_id);
        }
        let control = RunControl::new(Instant::now());
        let done = Arc::new(AtomicBool::new(false));
        let (thread_control, thread_done, thread_spec, config) =
            (control.clone(), Arc::clone(&done), spec.clone(), self.config.clone());
        let thread = std::thread::Builder::new()
            .name(format!("env-run-{}", spec.environment_id))
            .spawn(move || {
                // Set on every exit, a panic included: a box whose thread died must not look up forever.
                let _done = SetOnDrop(thread_done);
                // Declared after `_done`, so it drops first: what the backend's guards hold (a bridge, a probe
                // registration) is released before the id reads as free and a relaunch can register again.
                let backend = backend;
                if let Err(e) = hold(&backend, &thread_spec, &config, &thread_control) {
                    tracing::warn!(environment = %thread_spec.environment_id, error = %e, "an environment's held run failed");
                }
            })
            .map_err(|e| BackendError::Spawn(format!("start the run thread: {e}")))?;
        held.insert(
            spec.environment_id.clone(),
            Held {
                control,
                done,
                thread: Some(thread),
                killing: false,
                generation: self.next_generation.fetch_add(1, Ordering::SeqCst),
                started: SystemTime::now(),
            },
        );
        Ok(Launch::Started)
    }

    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        let up = self.lock().get(environment_id).is_some_and(|h| h.up() && !h.killing);
        if !up {
            return Ok(Probe::NotRunning);
        }
        match &self.service {
            Some(service) => service.probe(environment_id),
            None => Ok(Probe::Starting {
                step: "boot".to_owned(),
            }),
        }
    }

    fn kill(&self, environment_id: &str) -> Result<(), BackendError> {
        // Mark the entry and take the thread under the lock; wait without it, so a slow teardown blocks only this id.
        let (control, done, generation, thread) = {
            let mut held = self.lock();
            let Some(h) = held.get_mut(environment_id) else {
                return Ok(());
            };
            h.killing = true;
            (h.control.clone(), Arc::clone(&h.done), h.generation, h.thread.take())
        };
        if let Some((stop, grace)) = &self.graceful_stop {
            self.stop_gracefully(stop.as_ref(), environment_id, *grace, &done);
        }
        control.cancel();
        let start = Instant::now();
        while !done.load(Ordering::SeqCst) {
            if start.elapsed() >= self.kill_wait {
                // Keep the entry, still marked up, so a later kill retries and no launch starts a second VM.
                let mut held = self.lock();
                if let Some(h) = held.get_mut(environment_id).filter(|h| h.generation == generation) {
                    h.killing = false;
                    if h.thread.is_none() {
                        h.thread = thread;
                    }
                }
                return Err(BackendError::Transport(format!(
                    "the run of {environment_id} did not return after cancel"
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(thread) = thread {
            let _ = thread.join();
        }
        let mut held = self.lock();
        // Only this generation's entry: a launch that replaced it must stay.
        if held.get(environment_id).is_some_and(|h| h.generation == generation) {
            held.remove(environment_id);
        }
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        // A box that is mid-kill is still alive, so it is still listed.
        Ok(self
            .lock()
            .iter()
            .filter(|(_, h)| h.up())
            .map(|(id, h)| BoxState {
                box_id: id.clone(),
                box_name: id.clone(),
                pid: std::process::id(),
                started: h.started,
                rvport: None,
            })
            .collect())
    }
}

fn still_stopping(id: &str) -> BackendError {
    BackendError::Spawn(format!("the previous box of {id} is still stopping"))
}

impl VmEnvironmentBackend {
    /// `Some` when the id already decides a launch: a run that is up, or one being torn down.
    fn existing(&self, id: &str) -> Result<Option<Launch>, BackendError> {
        let mut held = self.lock();
        match held.get(id) {
            Some(h) if h.up() && h.killing => Err(still_stopping(id)),
            Some(h) if h.up() => Ok(Some(Launch::AlreadyRunning)),
            Some(_) => {
                // The run returned on its own: the box is gone, so this launch starts a fresh one.
                held.remove(id);
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

impl Drop for VmEnvironmentBackend {
    fn drop(&mut self) {
        // A dropped backend must not leave a VM running with nobody to kill it, and must not hang shutdown.
        let held = std::mem::take(&mut *self.lock());
        for h in held.values() {
            h.control.cancel();
        }
        let start = Instant::now();
        for (id, mut h) in held {
            while h.up() && start.elapsed() < self.kill_wait {
                std::thread::sleep(Duration::from_millis(20));
            }
            match h.thread.take() {
                Some(thread) if !h.up() => {
                    let _ = thread.join();
                }
                _ => {
                    tracing::error!(environment = %id, "a run did not return after cancel; its VM may outlive the daemon")
                }
            }
        }
    }
}
