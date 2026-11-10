//! [`FakeEnvironmentBackend`]: an in-memory [`EnvironmentBackend`] test double.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::SystemTime,
};

use sandy_api::{
    backend::{BackendError, BoxState},
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};

/// A callback run at the start of every probe, so a test can change the world
/// (delete a row, say) between a pass's launch and its probe's result.
struct ProbeHook(Box<dyn Fn(&str) + Send + Sync>);

impl std::fmt::Debug for ProbeHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProbeHook")
    }
}

/// What a launched box does when probed.
#[derive(Debug, Clone)]
enum Script {
    /// `polls` probes say `Starting`, then every probe says `Ready`.
    Ready { polls: usize },
    /// `polls` probes say `Starting`, then every probe says `Failed`.
    Fail { polls: usize, step: String, reason: String },
}

#[derive(Debug)]
struct RunningBox {
    started: SystemTime,
    polls: usize,
}

#[derive(Debug, Default)]
struct State {
    running: BTreeMap<String, RunningBox>,
    overrides: BTreeMap<String, Probe>,
    active: BTreeSet<String>,
    launched: Vec<EnvironmentSpec>,
    killed: Vec<String>,
}

/// An in-memory [`EnvironmentBackend`] test double.
///
/// Script how a box behaves with [`FakeEnvironmentBackend::starting_polls`],
/// [`FakeEnvironmentBackend::failing_at`] and
/// [`FakeEnvironmentBackend::with_endpoint`], make a launch fail with
/// [`FakeEnvironmentBackend::failing_launch`], kill a box behind the caller's
/// back with [`FakeEnvironmentBackend::die`], and inspect calls with
/// [`FakeEnvironmentBackend::launched`] and [`FakeEnvironmentBackend::killed`].
#[derive(Debug)]
pub struct FakeEnvironmentBackend {
    script: Script,
    endpoint: Endpoint,
    launch_error: Option<String>,
    kill_failing: AtomicBool,
    probe_failing: AtomicBool,
    launch_calls: AtomicUsize,
    probe_hook: Option<ProbeHook>,
    state: Mutex<State>,
}

impl Default for FakeEnvironmentBackend {
    fn default() -> Self {
        Self {
            script: Script::Ready { polls: 0 },
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 3773,
            },
            launch_error: None,
            kill_failing: AtomicBool::new(false),
            probe_failing: AtomicBool::new(false),
            launch_calls: AtomicUsize::new(0),
            probe_hook: None,
            state: Mutex::new(State::default()),
        }
    }
}

impl FakeEnvironmentBackend {
    /// A backend whose boxes are Ready at the first probe.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Probes report `Starting` this many times before `Ready`.
    #[must_use]
    pub fn starting_polls(mut self, polls: usize) -> Self {
        self.script = Script::Ready { polls };
        self
    }

    /// Probes report `Starting` `polls` times, then `Failed` for good.
    #[must_use]
    pub fn failing_at(mut self, polls: usize, step: &str, reason: &str) -> Self {
        self.script = Script::Fail {
            polls,
            step: step.to_owned(),
            reason: reason.to_owned(),
        };
        self
    }

    /// The endpoint a Ready probe reports.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: Endpoint) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Run `hook` with the environment id at the start of every probe.
    #[must_use]
    pub fn on_probe(mut self, hook: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.probe_hook = Some(ProbeHook(Box::new(hook)));
        self
    }

    /// Every launch fails with [`BackendError::Spawn`] carrying `message`.
    #[must_use]
    pub fn failing_launch(mut self, message: &str) -> Self {
        self.launch_error = Some(message.to_owned());
        self
    }

    /// Remove box `environment_id` as if its VM died on its own: nothing is
    /// recorded in [`FakeEnvironmentBackend::killed`].
    pub fn die(&self, environment_id: &str) {
        let mut state = self.lock();
        state.running.remove(environment_id);
        state.overrides.remove(environment_id);
    }

    /// Make every probe of box `environment_id` return `result`, whatever the
    /// script says, for as long as the box runs. Lets a test turn a Ready box
    /// into a failing one, or make a launched box report `NotRunning`.
    pub fn set_probe_result(&self, environment_id: &str, result: Probe) {
        self.lock().overrides.insert(environment_id.to_owned(), result);
    }

    /// Make [`EnvironmentBackend::active`] report `active` for box `environment_id`.
    pub fn set_active(&self, environment_id: &str, active: bool) {
        let mut state = self.lock();
        if active {
            state.active.insert(environment_id.to_owned());
        } else {
            state.active.remove(environment_id);
        }
    }

    /// While `failing`, [`EnvironmentBackend::kill`] fails with
    /// [`BackendError::Transport`] and leaves the box running.
    pub fn set_kill_failing(&self, failing: bool) {
        self.kill_failing.store(failing, Ordering::SeqCst);
    }

    /// While `failing`, [`EnvironmentBackend::probe`] fails with
    /// [`BackendError::Transport`], as if the probe itself could not run.
    pub fn set_probe_failing(&self, failing: bool) {
        self.probe_failing.store(failing, Ordering::SeqCst);
    }

    /// How many times [`EnvironmentBackend::launch`] was called, including the
    /// calls that found a box already running or failed.
    pub fn launch_calls(&self) -> usize {
        self.launch_calls.load(Ordering::SeqCst)
    }

    /// Every spec passed to a successful [`EnvironmentBackend::launch`] that
    /// started a box, in call order.
    pub fn launched(&self) -> Vec<EnvironmentSpec> {
        self.lock().launched.clone()
    }

    /// Every id passed to [`EnvironmentBackend::kill`], in call order.
    pub fn killed(&self) -> Vec<String> {
        self.lock().killed.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl EnvironmentBackend for FakeEnvironmentBackend {
    fn launch(&self, spec: &EnvironmentSpec) -> Result<Launch, BackendError> {
        self.launch_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = &self.launch_error {
            return Err(BackendError::Spawn(message.clone()));
        }
        let mut state = self.lock();
        if state.running.contains_key(&spec.environment_id) {
            return Ok(Launch::AlreadyRunning);
        }
        state.running.insert(
            spec.environment_id.clone(),
            RunningBox {
                started: SystemTime::now(),
                polls: 0,
            },
        );
        state.launched.push(spec.clone());
        Ok(Launch::Started)
    }

    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        if let Some(hook) = &self.probe_hook {
            (hook.0)(environment_id);
        }
        if self.probe_failing.load(Ordering::SeqCst) {
            return Err(BackendError::Transport("probe could not run".to_owned()));
        }
        let mut state = self.lock();
        if let Some(result) = state.overrides.get(environment_id) {
            return Ok(result.clone());
        }
        let Some(running) = state.running.get_mut(environment_id) else {
            return Ok(Probe::NotRunning);
        };
        let seen = running.polls;
        running.polls += 1;
        Ok(match &self.script {
            Script::Ready { polls } if seen < *polls => Probe::Starting {
                step: "boot".to_owned(),
            },
            Script::Ready { .. } => Probe::Ready {
                endpoint: self.endpoint.clone(),
            },
            Script::Fail { polls, .. } if seen < *polls => Probe::Starting {
                step: "boot".to_owned(),
            },
            Script::Fail { step, reason, .. } => Probe::Failed {
                step: step.clone(),
                reason: reason.clone(),
            },
        })
    }

    fn active(&self, environment_id: &str) -> Result<bool, BackendError> {
        Ok(self.lock().active.contains(environment_id))
    }

    fn kill(&self, environment_id: &str) -> Result<(), BackendError> {
        if self.kill_failing.load(Ordering::SeqCst) {
            return Err(BackendError::Transport("kill failed".to_owned()));
        }
        let mut state = self.lock();
        state.running.remove(environment_id);
        state.overrides.remove(environment_id);
        state.killed.push(environment_id.to_owned());
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self
            .lock()
            .running
            .iter()
            .map(|(id, b)| BoxState {
                box_id: id.clone(),
                box_name: id.clone(),
                pid: 0,
                started: b.started,
                rvport: None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    fn spec(id: &str) -> EnvironmentSpec {
        EnvironmentSpec {
            environment_id: id.to_owned(),
            template: "t3".to_owned(),
            size: None,
            env: Vec::new(),
            service_port: Some(3773),
            secret_dir: None,
        }
    }

    #[test]
    fn a_launched_box_is_listed_by_its_environment_id() -> Result<()> {
        let b = FakeEnvironmentBackend::new();
        assert_eq!(b.launch(&spec("env-1"))?, Launch::Started);
        let ids: Vec<_> = b.boxes()?.into_iter().map(|s| s.box_id).collect();
        assert_eq!(ids, ["env-1"]);
        assert_eq!(b.launched(), vec![spec("env-1")]);
        Ok(())
    }

    #[test]
    fn launching_a_running_id_again_starts_no_second_box() -> Result<()> {
        let b = FakeEnvironmentBackend::new();
        b.launch(&spec("env-1"))?;
        assert_eq!(b.launch(&spec("env-1"))?, Launch::AlreadyRunning);
        assert_eq!(b.boxes()?.len(), 1);
        assert_eq!(b.launched().len(), 1, "a retry must not count as a launch");
        Ok(())
    }

    #[test]
    fn a_box_is_starting_for_the_scripted_polls_then_ready_for_good() -> Result<()> {
        let b = FakeEnvironmentBackend::new().starting_polls(2).with_endpoint(Endpoint {
            host: "127.0.0.1".to_owned(),
            port: 41000,
        });
        b.launch(&spec("env-1"))?;
        let starting = Probe::Starting {
            step: "boot".to_owned(),
        };
        assert_eq!(b.probe("env-1")?, starting);
        assert_eq!(b.probe("env-1")?, starting);
        let ready = Probe::Ready {
            endpoint: Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 41000,
            },
        };
        assert_eq!(b.probe("env-1")?, ready);
        assert_eq!(b.probe("env-1")?, ready, "Ready is sticky");
        Ok(())
    }

    #[test]
    fn a_failing_box_names_the_step_and_reason_and_stays_failed() -> Result<()> {
        let b = FakeEnvironmentBackend::new().failing_at(1, "probe", "connection refused");
        b.launch(&spec("env-1"))?;
        assert!(matches!(b.probe("env-1")?, Probe::Starting { .. }));
        let failed = Probe::Failed {
            step: "probe".to_owned(),
            reason: "connection refused".to_owned(),
        };
        assert_eq!(b.probe("env-1")?, failed);
        assert_eq!(b.probe("env-1")?, failed);
        Ok(())
    }

    #[test]
    fn an_unknown_dead_or_killed_box_is_not_running() -> Result<()> {
        let b = FakeEnvironmentBackend::new();
        assert_eq!(b.probe("env-nope")?, Probe::NotRunning);
        b.launch(&spec("env-1"))?;
        b.die("env-1");
        assert_eq!(b.probe("env-1")?, Probe::NotRunning);
        assert!(b.boxes()?.is_empty());
        assert!(b.killed().is_empty(), "a death is not a kill");
        b.launch(&spec("env-2"))?;
        b.kill("env-2")?;
        assert_eq!(b.probe("env-2")?, Probe::NotRunning);
        Ok(())
    }

    #[test]
    fn kill_is_idempotent_and_recorded_each_time() -> Result<()> {
        let b = FakeEnvironmentBackend::new();
        b.launch(&spec("env-1"))?;
        b.kill("env-1")?;
        b.kill("env-1")?;
        b.kill("env-never")?;
        assert_eq!(b.killed(), ["env-1", "env-1", "env-never"]);
        assert!(b.boxes()?.is_empty());
        Ok(())
    }

    #[test]
    fn a_failing_launch_is_a_spawn_error_and_starts_no_box() -> Result<()> {
        let b = FakeEnvironmentBackend::new().failing_launch("no kvm");
        assert_eq!(b.launch(&spec("env-1")), Err(BackendError::Spawn("no kvm".to_owned())));
        assert!(b.boxes()?.is_empty());
        assert!(b.launched().is_empty());
        Ok(())
    }

    #[test]
    fn a_relaunch_after_a_kill_starts_a_fresh_box_that_polls_from_the_start() -> Result<()> {
        let b = FakeEnvironmentBackend::new().starting_polls(1);
        b.launch(&spec("env-1"))?;
        b.probe("env-1")?;
        assert!(matches!(b.probe("env-1")?, Probe::Ready { .. }));
        b.kill("env-1")?;
        assert_eq!(b.launch(&spec("env-1"))?, Launch::Started);
        assert!(
            matches!(b.probe("env-1")?, Probe::Starting { .. }),
            "a fresh box starts again"
        );
        assert_eq!(b.launched().len(), 2);
        Ok(())
    }

    #[test]
    fn a_failing_kill_leaves_the_box_and_a_failing_probe_is_a_transport_error() -> Result<()> {
        let b = FakeEnvironmentBackend::new();
        b.launch(&spec("env-1"))?;
        b.set_kill_failing(true);
        assert_eq!(b.kill("env-1"), Err(BackendError::Transport("kill failed".to_owned())));
        assert_eq!(b.boxes()?.len(), 1, "a failed kill leaves the box");
        assert!(b.killed().is_empty(), "a failed kill is not recorded as a kill");
        b.set_kill_failing(false);
        b.kill("env-1")?;
        assert!(b.boxes()?.is_empty());

        b.launch(&spec("env-2"))?;
        b.set_probe_failing(true);
        assert!(matches!(b.probe("env-2"), Err(BackendError::Transport(_))));
        b.set_probe_failing(false);
        assert!(matches!(b.probe("env-2")?, Probe::Ready { .. }));
        Ok(())
    }

    #[test]
    fn launch_calls_count_every_call_including_the_idempotent_ones() -> Result<()> {
        let b = FakeEnvironmentBackend::new();
        b.launch(&spec("env-1"))?;
        b.launch(&spec("env-1"))?;
        assert_eq!(b.launch_calls(), 2);
        assert_eq!(b.launched().len(), 1);
        Ok(())
    }
}
