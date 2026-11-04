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
    sync::{Arc, Mutex, MutexGuard, PoisonError},
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

/// What the held run is told about every environment.
#[derive(Debug, Clone)]
pub struct VmEnvironmentConfig {
    /// The guest command the agent runs as its job: the service.
    pub command: Vec<String>,
}

struct Held {
    control: RunControl,
    thread: Option<JoinHandle<()>>,
    started: SystemTime,
}

/// An [`EnvironmentBackend`] over a hypervisor [`VmBackend`].
pub struct VmEnvironmentBackend {
    factory: BackendFactory,
    config: VmEnvironmentConfig,
    service: Option<Arc<dyn ServiceProbe>>,
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
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// Decide readiness with `service` once a run is up.
    #[must_use]
    pub fn with_service_probe(mut self, service: Arc<dyn ServiceProbe>) -> Self {
        self.service = Some(service);
        self
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Held>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The held run: no deadline, since an environment lives until it is killed.
fn hold(
    backend: &HeldBackend,
    spec: &EnvironmentSpec,
    command: &[String],
    control: &RunControl,
) -> Result<(), BackendError> {
    control.suspend_deadline();
    let run = RunSpec {
        digests: false,
        template: &spec.template,
        command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &spec.env,
        cpu: None,
        mem: None,
        timeout_secs: 0,
        control,
        grants: &Grants {
            secrets: false,
            agent: true,
            shares: false,
        },
        outcome_file: None,
        secret_dir: None,
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

impl EnvironmentBackend for VmEnvironmentBackend {
    fn launch(&self, spec: &EnvironmentSpec) -> Result<Launch, BackendError> {
        let mut held = self.lock();
        if let Some(entry) = held.get(&spec.environment_id) {
            if entry.thread.as_ref().is_some_and(|t| !t.is_finished()) {
                return Ok(Launch::AlreadyRunning);
            }
            // The run returned on its own: the box is gone, so this launch starts a fresh one.
            held.remove(&spec.environment_id);
        }
        let backend = (self.factory)(spec)?;
        let control = RunControl::new(Instant::now());
        let (thread_control, thread_spec, command) = (control.clone(), spec.clone(), self.config.command.clone());
        let id = spec.environment_id.clone();
        let thread = std::thread::Builder::new()
            .name(format!("env-run-{id}"))
            .spawn(move || {
                if let Err(e) = hold(&backend, &thread_spec, &command, &thread_control) {
                    tracing::warn!(environment = %thread_spec.environment_id, error = %e, "an environment's held run failed");
                }
            })
            .map_err(|e| BackendError::Spawn(format!("start the run thread: {e}")))?;
        held.insert(
            id,
            Held {
                control,
                thread: Some(thread),
                started: SystemTime::now(),
            },
        );
        Ok(Launch::Started)
    }

    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        let up = self
            .lock()
            .get(environment_id)
            .is_some_and(|h| h.thread.as_ref().is_some_and(|t| !t.is_finished()));
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
        // Take the thread out under the lock and wait without it, so a slow teardown does not block other environments.
        let (control, thread) = {
            let mut held = self.lock();
            match held.get_mut(environment_id) {
                None => return Ok(()),
                Some(h) => (h.control.clone(), h.thread.take()),
            }
        };
        control.cancel();
        if let Some(thread) = thread {
            let start = Instant::now();
            while !thread.is_finished() {
                if start.elapsed() >= KILL_WAIT {
                    // Keep the entry and the thread, so a later kill retries instead of orphaning the VM.
                    if let Some(h) = self.lock().get_mut(environment_id) {
                        h.thread = Some(thread);
                    }
                    return Err(BackendError::Transport(format!(
                        "the run of {environment_id} did not return after cancel"
                    )));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = thread.join();
        }
        self.lock().remove(environment_id);
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self
            .lock()
            .iter()
            .filter(|(_, h)| h.thread.as_ref().is_some_and(|t| !t.is_finished()))
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

impl Drop for VmEnvironmentBackend {
    fn drop(&mut self) {
        // A dropped backend must not leave a VM running with nobody to kill it.
        let held = std::mem::take(&mut *self.lock());
        for h in held.values() {
            h.control.cancel();
        }
        for (_, mut h) in held {
            if let Some(thread) = h.thread.take() {
                let _ = thread.join();
            }
        }
    }
}
