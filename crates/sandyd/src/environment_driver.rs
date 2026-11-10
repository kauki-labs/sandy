//! The environment launch driver (#587, slices B and C2): converges the boxes an
//! [`EnvironmentBackend`] runs to the environments the store says should exist.
//!
//! It is level-triggered, not event-triggered. Every pass reads the backend's
//! boxes and then the whole store and fixes each difference, so the same pass
//! is the reconciler after a `sandyd` restart: nothing is remembered in memory.
//!
//! - `Provisioning`: launch a box unless one already runs, then probe it. Ready records the endpoint and marks the row
//!   `Ready`; Failed records the step and reason and kills the box. A probe that is not Ready after the provision
//!   timeout fails the row (step `provision`) and kills the box. The probe comes first, so a long daemon downtime never
//!   fails a row that can still become Ready.
//! - `Ready` whose box is gone or failing: marked lost (`Failed`), box killed.
//! - `Stopped`, `Failed`, `Deleted`: no box may run, so any box is killed.
//! - A box with no environment row is an orphan and is killed.
//!
//! A store fault on one row, or a row that cannot be read, is logged and skipped
//! so it cannot stop the rest of the pass. The backend calls block, so a pass
//! runs under `spawn_blocking`. The probes of `Provisioning` rows run together
//! (at most eight at once) once the row loop has launched them, so slow probes do
//! not add up and the other rows' steps do not wait behind them.

use std::{
    collections::BTreeSet,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use prost::Message;
use sandy_api::{
    backend::BackendError,
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};
use sandy_control_proto::v1::EnvironmentSpec as WireSpec;

use crate::{
    environment_credential::EnvironmentCredentials,
    environment_store::{EnvTransition, EnvironmentRecord, EnvironmentState, EnvironmentStore, EnvironmentStoreError},
};

/// The most probes of `Provisioning` rows that run at once in one pass. Each probe
/// is bounded by the backend's own timeout, so a pass takes about one probe budget
/// per eight rows, not one per row.
const MAX_PROBES_IN_FLIGHT: usize = 8;

/// A launched `Provisioning` row whose probe is yet to run.
struct PendingProbe {
    id: String,
    waited: i64,
    timed_out: bool,
    hard_timed_out: bool,
}

/// What the driver launches and how long it waits.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// The guest flake attr every environment boots.
    pub template: String,
    /// The TCP port the guest's service listens on, passed to the backend so it
    /// can bridge the port.
    pub service_port: Option<u16>,
    /// How long a row may stay `Provisioning` without a passing probe before it
    /// is failed.
    pub provision_timeout: Duration,
    /// Stop a `Ready` environment with no owner-visible use for this long. `None`
    /// never stops one. The environment is stopped, not deleted, and resumes under
    /// the same id.
    pub idle_timeout: Option<Duration>,
}

/// A failure that stops a whole pass.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The environment store could not be read at all.
    #[error(transparent)]
    Store(#[from] EnvironmentStoreError),
    /// The backend could not list its boxes.
    #[error("listing boxes: {0}")]
    Backend(#[from] BackendError),
}

/// What one pass did, for logs and tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Environment ids a new box was started for.
    pub launched: Vec<String>,
    /// Environment ids that became `Ready`.
    pub readied: Vec<String>,
    /// Environment ids that became `Failed`.
    pub failed: Vec<String>,
    /// Box ids that were killed.
    pub killed: Vec<String>,
    /// Environment ids stopped because their idle-stop lease ran out.
    pub idle_stopped: Vec<String>,
}

impl Report {
    fn is_empty(&self) -> bool {
        self.launched.is_empty()
            && self.readied.is_empty()
            && self.failed.is_empty()
            && self.killed.is_empty()
            && self.idle_stopped.is_empty()
    }
}

/// Converges backend boxes to store rows.
pub struct EnvironmentDriver {
    store: Arc<EnvironmentStore>,
    backend: Arc<dyn EnvironmentBackend + Send + Sync>,
    config: DriverConfig,
    /// The per-environment forge credentials (#706). `None` launches every environment without one.
    credentials: Option<Arc<EnvironmentCredentials>>,
}

impl EnvironmentDriver {
    /// A driver over `store` and `backend`.
    pub fn new(
        store: Arc<EnvironmentStore>,
        backend: Arc<dyn EnvironmentBackend + Send + Sync>,
        config: DriverConfig,
    ) -> Self {
        Self {
            store,
            backend,
            config,
            credentials: None,
        }
    }

    /// Mint a forge credential for every environment before its guest boots, renew it while the environment is
    /// `Ready`, and revoke it when the environment stops, is deleted or fails (#706).
    #[must_use]
    pub fn with_credentials(mut self, credentials: Arc<EnvironmentCredentials>) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// One converge pass at unix time `now`. Blocks on the store and backend.
    ///
    /// # Errors
    /// [`DriverError`] when the store cannot be read at all or the backend
    /// cannot list boxes. A fault on one environment fails or skips that
    /// environment, not the pass.
    pub fn reconcile_once(&self, now: i64) -> Result<Report, DriverError> {
        let mut report = Report::default();
        // Boxes first: a box can only exist for a row that already existed, so a
        // row created after this snapshot has no box in it, and a box in it
        // always has its row in the listing below.
        let mut running: BTreeSet<String> = self.backend.boxes()?.into_iter().map(|b| b.box_id).collect();
        let mut known: BTreeSet<String> = BTreeSet::new();
        // Provisioning rows are launched in the row loop; their probes wait for the end of it and run together.
        let mut probes: Vec<PendingProbe> = Vec::new();
        for row in self.store.list_each()? {
            match row {
                Ok(row) => {
                    known.insert(row.environment_id.clone());
                    if let Err(e) = self.converge(&row, now, &mut running, &mut report, &mut probes) {
                        tracing::warn!(environment = %row.environment_id, error = %e, "could not converge an environment");
                    }
                }
                // An unreadable row still owns its box: skip it, never kill its box as an orphan.
                Err(EnvironmentStoreError::CorruptState { environment_id, raw }) => {
                    tracing::warn!(environment = %environment_id, state = %raw, "skipping an environment with an unreadable state");
                    known.insert(environment_id);
                }
                Err(e) => return Err(e.into()),
            }
        }
        self.finish_probes(probes, &mut running, &mut report);
        // A box no environment row names is an orphan: the row was never written or is gone.
        let orphans: Vec<String> = running
            .iter()
            .filter(|id| !known.contains(id.as_str()))
            .cloned()
            .collect();
        for id in orphans {
            self.kill(&id, &mut running, &mut report);
            // A box that survived the kill still mounts its share: keep the token until a later pass kills it.
            if !running.contains(&id) {
                self.release_credential(&id);
            }
        }
        Ok(report)
    }

    fn converge(
        &self,
        row: &EnvironmentRecord,
        now: i64,
        running: &mut BTreeSet<String>,
        report: &mut Report,
        probes: &mut Vec<PendingProbe>,
    ) -> Result<(), EnvironmentStoreError> {
        match row.state {
            EnvironmentState::Provisioning => {
                probes.extend(self.provision(row, now, running, report)?);
                Ok(())
            }
            EnvironmentState::Ready => self.check_ready(row, now, running, report),
            EnvironmentState::Stopped | EnvironmentState::Failed | EnvironmentState::Deleted => {
                if running.contains(&row.environment_id) {
                    self.kill(&row.environment_id, running, report);
                    // No failure will ask for this run's console: drop it so a later failure of the id cannot show it.
                    // Only once the box is gone: a box that survived the kill keeps writing to its ring, and a resume
                    // may adopt it.
                    if !running.contains(&row.environment_id) {
                        let _ = self.backend.console_tail(&row.environment_id);
                    }
                }
                // A box that survived the kill still mounts its share, and a resume would reuse the guest: release
                // only once no box runs, so the share and the lease stay in step with the guest.
                if !running.contains(&row.environment_id) {
                    self.release_credential(&row.environment_id);
                }
                Ok(())
            }
        }
    }

    fn kill(&self, id: &str, running: &mut BTreeSet<String>, report: &mut Report) {
        match self.backend.kill(id) {
            Ok(()) => {
                running.remove(id);
                report.killed.push(id.to_owned());
            }
            // Left in `running`; the next pass tries again.
            Err(e) => tracing::warn!(environment = id, error = %e, "could not kill a box"),
        }
    }

    fn fail(&self, id: &str, step: &str, reason: &str, report: &mut Report) -> Result<(), EnvironmentStoreError> {
        self.fail_with(id, step, reason, true, report)
    }

    /// Fail a row whose box never started in this attempt (admission, spec, credential, launch). Any console the
    /// backend still holds for the id belongs to an earlier run, so it is dropped, not reported (#727).
    fn fail_before_boot(
        &self,
        id: &str,
        step: &str,
        reason: &str,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        self.fail_with(id, step, reason, false, report)
    }

    fn fail_with(
        &self,
        id: &str,
        step: &str,
        reason: &str,
        had_box: bool,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        // Every caller with a box has already killed it, so the console is complete. The backend hands the tail over
        // once, so it cannot land on a later failure of the same id (#727).
        let tail = self.backend.console_tail(id).filter(|tail| !tail.is_empty());
        let reason = match tail.filter(|_| had_box) {
            // The staged token is not a shape a mask knows: it is scrubbed by value, before the credential is revoked
            // below. A tail that cannot be checked against the token is dropped, never stored raw.
            Some(tail) => match self.scrub_staged_token(id, tail) {
                Some(tail) => format!("{reason}\nconsole tail:\n{tail}"),
                None => format!("{reason}\nconsole tail dropped: the staged token could not be scrubbed from it"),
            },
            None => reason.to_owned(),
        };
        if self.store.mark_lost(id, step, &reason)? == EnvTransition::Applied {
            report.failed.push(id.to_owned());
        }
        // A failed environment keeps no token: revoke now, not at the next pass.
        self.release_credential(id);
        Ok(())
    }

    fn scrub_staged_token(&self, id: &str, tail: String) -> Option<String> {
        match &self.credentials {
            Some(credentials) => credentials.redact_text(id, tail),
            None => Some(tail),
        }
    }

    fn to_spec(&self, row: &EnvironmentRecord) -> Option<EnvironmentSpec> {
        let wire = WireSpec::decode(row.spec.as_slice()).ok()?;
        Some(EnvironmentSpec {
            environment_id: row.environment_id.clone(),
            template: self.config.template.clone(),
            size: (!wire.size.is_empty()).then_some(wire.size),
            env: Vec::new(),
            service_port: self.config.service_port,
            secret_dir: None,
        })
    }

    /// Launch the box of a `Provisioning` row unless one runs, and note when its
    /// attempt began. Returns the probe to run, or `None` when the row failed.
    fn provision(
        &self,
        row: &EnvironmentRecord,
        now: i64,
        running: &mut BTreeSet<String>,
        report: &mut Report,
    ) -> Result<Option<PendingProbe>, EnvironmentStoreError> {
        let id = row.environment_id.as_str();
        if !running.contains(id) {
            // Covers a row made while the gate was off, and a resume: the create gate alone does not.
            if self.store.trusted_submitter_required() && !row.submitter_trusted {
                self.fail_before_boot(
                    id,
                    "admission",
                    "the backend serves trusted submitters only and this environment was not created by one",
                    report,
                )?;
                return Ok(None);
            }
            let Some(mut spec) = self.to_spec(row) else {
                self.fail_before_boot(id, "spec", "the stored spec does not decode", report)?;
                return Ok(None);
            };
            // Before the guest boots: with a credential component (the VM backends), a guest never starts without the
            // token its profile promises. The process backend has none: it runs tokenless by design (decision 38).
            if self.credentials.is_some() {
                match self.mint_credential(row) {
                    Ok(share) => spec.secret_dir = Some((share.dir, share.fingerprint)),
                    Err(reason) => {
                        self.fail_before_boot(id, "credential", &reason, report)?;
                        return Ok(None);
                    }
                }
            }
            match self.backend.launch(&spec) {
                Ok(Launch::Started) => {
                    running.insert(id.to_owned());
                    report.launched.push(id.to_owned());
                }
                Ok(Launch::AlreadyRunning) => {
                    running.insert(id.to_owned());
                }
                Err(e) => {
                    self.fail_before_boot(id, "launch", &e.to_string(), report)?;
                    return Ok(None);
                }
            }
        } else if self.credentials.as_ref().is_some_and(|c| !c.holds(id)) {
            // A guest the previous daemon launched is still running: the new token goes into its share.
            if let Err(reason) = self.mint_credential(row) {
                self.fail_before_boot(id, "credential", &reason, report)?;
                return Ok(None);
            }
        }
        // The provision timeout runs from the moment a box exists for this
        // attempt, recorded once and kept across passes and restarts, not from
        // the row's last write: a row found after a long downtime must get its
        // full boot time.
        if row.launched_at.is_none() {
            self.store.mark_launched(id, now)?;
        }
        let waited = now.saturating_sub(row.launched_at.unwrap_or(now));
        let limit = i64::try_from(self.config.provision_timeout.as_secs()).unwrap_or(i64::MAX);
        let timed_out = waited > limit;
        // A probe that cannot run is retried, so one transport fault cannot end a
        // healthy environment; only a probe that stays broken for twice the
        // timeout fails the row.
        let hard_timed_out = waited > limit.saturating_mul(2);
        Ok(Some(PendingProbe {
            id: id.to_owned(),
            waited,
            timed_out,
            hard_timed_out,
        }))
    }

    /// Probe every pending row, at most [`MAX_PROBES_IN_FLIGHT`] at a time, then
    /// apply each result in row order. A probe that panics counts as a probe
    /// that could not run: only that row's pass is lost.
    fn finish_probes(&self, pending: Vec<PendingProbe>, running: &mut BTreeSet<String>, report: &mut Report) {
        let results = self.probe_concurrently(&pending);
        for (probe, result) in pending.into_iter().zip(results) {
            if let Err(e) = self.apply_probe(&probe, result, running, report) {
                tracing::warn!(environment = %probe.id, error = %e, "could not converge an environment");
            }
        }
    }

    fn probe_concurrently(&self, pending: &[PendingProbe]) -> Vec<Result<Probe, BackendError>> {
        let next = AtomicUsize::new(0);
        let slots: Mutex<Vec<Option<Result<Probe, BackendError>>>> =
            Mutex::new(std::iter::repeat_with(|| None).take(pending.len()).collect());
        let work = || {
            loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(probe) = pending.get(i) else { break };
                let result = catch_unwind(AssertUnwindSafe(|| self.backend.probe(&probe.id))).unwrap_or_else(|payload| {
                    tracing::warn!(environment = %probe.id, panic = panic_text(payload.as_ref()), "a probe panicked");
                    Err(BackendError::Transport("the probe panicked".to_owned()))
                });
                slots.lock().unwrap_or_else(PoisonError::into_inner)[i] = Some(result);
            }
        };
        std::thread::scope(|scope| {
            let mut spawned = 0;
            for _ in 0..MAX_PROBES_IN_FLIGHT.min(pending.len()) {
                // `Scope::spawn` would panic if the OS refuses a thread and lose the whole pass; probe inline instead.
                match std::thread::Builder::new().spawn_scoped(scope, work) {
                    Ok(_) => spawned += 1,
                    Err(e) => {
                        tracing::warn!(error = %e, "could not start a probe thread");
                        break;
                    }
                }
            }
            if spawned == 0 {
                work();
            }
        });
        // A worker panic outside `catch_unwind` would already have unwound out of the scope; the fallbacks
        // below only keep this function total.
        slots
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .into_iter()
            .map(|slot| slot.unwrap_or_else(|| Err(BackendError::Transport("the probe did not run".to_owned()))))
            .collect()
    }

    fn apply_probe(
        &self,
        pending: &PendingProbe,
        result: Result<Probe, BackendError>,
        running: &mut BTreeSet<String>,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        let PendingProbe {
            id,
            waited,
            timed_out,
            hard_timed_out,
        } = pending;
        let (id, waited, timed_out, hard_timed_out) = (id.as_str(), *waited, *timed_out, *hard_timed_out);
        match result {
            Ok(Probe::Ready { endpoint }) => match endpoint_string(&endpoint) {
                Some(address) => match self.store.mark_ready_with_endpoint(id, &address)? {
                    EnvTransition::Applied => report.readied.push(id.to_owned()),
                    // A delete (or a failure written by another driver) landed during the
                    // launch: the box must not outlive it (decision 26).
                    EnvTransition::Refused(EnvironmentState::Deleted | EnvironmentState::Failed) => {
                        self.kill(id, running, report);
                    }
                    EnvTransition::Unchanged | EnvTransition::NotFound | EnvTransition::Refused(_) => {}
                },
                None => {
                    self.kill(id, running, report);
                    self.fail(
                        id,
                        "probe",
                        "the backend reported an endpoint that is not a plain host and port",
                        report,
                    )?;
                }
            },
            Ok(Probe::Failed { step, reason }) => {
                self.kill(id, running, report);
                self.fail(id, &step, &reason, report)?;
            }
            Ok(Probe::NotRunning) => self.fail(id, "launch", "the box is not running after launch", report)?,
            Ok(Probe::Starting { .. }) if timed_out => self.time_out(id, waited, running, report)?,
            Ok(Probe::Starting { .. }) => {}
            // The probe itself could not run: not the environment's fault, unless it never recovers.
            Err(e) if hard_timed_out => {
                tracing::warn!(environment = id, error = %e, "probe could not run past twice the provision timeout");
                self.time_out(id, waited, running, report)?;
            }
            Err(e) => tracing::warn!(environment = id, error = %e, "probe could not run"),
        }
        Ok(())
    }

    /// Mint (or find) the credential `row`'s profile names, and clear any earlier degraded or revoke-failure mark.
    /// Blocking. The reason never carries a token or the profile name.
    fn mint_credential(&self, row: &EnvironmentRecord) -> Result<crate::environment_credential::SecretShare, String> {
        let credentials = self
            .credentials
            .as_ref()
            .ok_or("no credential component is configured")?;
        let wire = WireSpec::decode(row.spec.as_slice()).map_err(|_| "the stored spec does not decode".to_owned())?;
        let profile = self
            .store
            .profiles()
            .ok_or("no identity profile registry is configured")?
            .resolve(&wire.profile)
            .map_err(|_| "the environment's profile is not in the registry".to_owned())?;
        let share = credentials.ensure(&row.environment_id, profile.credential(), profile.scope())?;
        if (row.credential_degraded || row.credential_error.is_some())
            && let Err(e) = self.store.set_credential_state(&row.environment_id, false, None)
        {
            tracing::warn!(environment = %row.environment_id, error = %e, "could not clear the credential mark");
        }
        Ok(share)
    }

    /// Renew a `Ready` environment's credential before it expires, or mint one when this daemon holds none (it
    /// restarted). A failure leaves the environment running and marks it `degraded` (#706).
    fn keep_credential_fresh(&self, row: &EnvironmentRecord) {
        let Some(credentials) = &self.credentials else { return };
        let id = row.environment_id.as_str();
        let outcome = if credentials.holds(id) {
            credentials.renew(id, std::time::SystemTime::now()).map(|_| ())
        } else {
            self.mint_credential(row).map(|_| ())
        };
        match outcome {
            Ok(()) if row.credential_degraded => {
                if let Err(e) = self
                    .store
                    .set_credential_state(id, false, row.credential_error.as_deref())
                {
                    tracing::warn!(environment = id, error = %e, "could not clear the degraded mark");
                }
            }
            Ok(()) => {}
            Err(reason) => {
                tracing::warn!(environment = id, error = %reason, "the environment's credential could not be renewed");
                if !row.credential_degraded
                    && let Err(e) = self
                        .store
                        .set_credential_state(id, true, row.credential_error.as_deref())
                {
                    tracing::warn!(environment = id, error = %e, "could not record the degraded mark");
                }
            }
        }
    }

    /// Revoke `id`'s credential and remove its staged files. A failure is recorded on the row and never stops the
    /// pass. Idempotent: a pass over a stopped environment finds nothing to do.
    fn release_credential(&self, id: &str) {
        let Some(credentials) = &self.credentials else { return };
        if let Err(reason) = credentials.release(id) {
            tracing::warn!(environment = id, error = %reason, "could not revoke an environment's credential");
            if let Err(e) = self.store.set_credential_state(id, false, Some(&reason)) {
                tracing::warn!(environment = id, error = %e, "could not record the revoke failure");
            }
        }
    }

    fn time_out(
        &self,
        id: &str,
        waited: i64,
        running: &mut BTreeSet<String>,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        self.kill(id, running, report);
        self.fail(id, "provision", &format!("not ready after {waited}s"), report)
    }

    fn check_ready(
        &self,
        row: &EnvironmentRecord,
        now: i64,
        running: &mut BTreeSet<String>,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        let id = row.environment_id.as_str();
        match self.backend.probe(id) {
            Ok(Probe::Ready { .. } | Probe::Starting { .. }) => {
                self.keep_credential_fresh(row);
                self.stop_if_idle(row, now, report)?;
            }
            Ok(Probe::Failed { step, reason }) => {
                self.kill(id, running, report);
                self.fail(id, &step, &reason, report)?;
            }
            Ok(Probe::NotRunning) => self.fail(id, "reconcile", "the box is not running", report)?,
            Err(e) => tracing::warn!(environment = id, error = %e, "probe could not run"),
        }
        Ok(())
    }

    /// Stop `row` once its lease has run out. The next pass sees `Stopped` and
    /// kills the box, the same path as an owner's stop.
    fn stop_if_idle(
        &self,
        row: &EnvironmentRecord,
        now: i64,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        let Some(limit) = self.config.idle_timeout else {
            return Ok(());
        };
        // A client connected straight to the service is invisible to the RPC surface.
        match self.backend.active(&row.environment_id) {
            Ok(true) => {
                if let Err(e) = self.store.touch(&row.environment_id, now) {
                    tracing::warn!(environment = %row.environment_id, error = %e, "could not renew an idle-stop lease");
                }
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(environment = %row.environment_id, error = %e, "activity check could not run"),
        }
        // Conditional in the store: `row` is a snapshot, and a renewal that landed after
        // it (the probe can be slow) must win.
        if self.store.stop_if_idle(
            &row.environment_id,
            now,
            i64::try_from(limit.as_secs()).unwrap_or(i64::MAX),
        )? {
            report.idle_stopped.push(row.environment_id.clone());
        }
        Ok(())
    }

    /// Run [`EnvironmentDriver::reconcile_once`] every `interval` until the task
    /// is aborted. A pass already running when the task is aborted finishes; a
    /// failed pass is logged and retried at the next tick.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let me = Arc::clone(&self);
            match tokio::task::spawn_blocking(move || me.reconcile_once(now_unix())).await {
                Ok(Ok(report)) if !report.is_empty() => tracing::info!(?report, "environment driver pass"),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::error!(error = %e, "environment driver pass failed"),
                Err(e) => tracing::error!(error = %e, "environment driver pass panicked"),
            }
        }
    }
}

/// The message of a caught panic, for the log.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("a non-text panic payload")
}

/// `host:port` for a backend endpoint, with brackets around an IPv6 address, or
/// `None` when the host is not an IP address or a plain DNS name. The string
/// becomes part of a URL, so a host with a scheme, path, userinfo or space is
/// refused instead of passed through.
fn endpoint_string(endpoint: &Endpoint) -> Option<String> {
    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        return Some(match ip {
            IpAddr::V4(v4) => format!("{v4}:{}", endpoint.port),
            IpAddr::V6(v6) => format!("[{v6}]:{}", endpoint.port),
        });
    }
    let plain = !endpoint.host.is_empty()
        && endpoint.host.len() <= 253
        && endpoint.host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    plain.then(|| format!("{}:{}", endpoint.host, endpoint.port))
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use prost::Message;
    use sandy_api::environment::{Endpoint, Probe};
    use sandy_control_proto::v1::{EnvironmentLifetime, EnvironmentLifetimeKind};
    use sandy_test_support::FakeEnvironmentBackend;

    use super::*;

    fn config() -> DriverConfig {
        DriverConfig {
            template: "t3".to_owned(),
            service_port: Some(3773),
            provision_timeout: Duration::from_secs(600),
            idle_timeout: None,
        }
    }

    fn idle_config(secs: u64) -> DriverConfig {
        DriverConfig {
            idle_timeout: Some(Duration::from_secs(secs)),
            ..config()
        }
    }

    fn spec_bytes(size: &str) -> Vec<u8> {
        WireSpec {
            profile: "harness".to_owned(),
            size: size.to_owned(),
            lifetime: Some(EnvironmentLifetime {
                kind: EnvironmentLifetimeKind::Ephemeral.into(),
                ttl_secs: 600,
            }),
            task_ref: "task-1".to_owned(),
        }
        .encode_to_vec()
    }

    struct Rig {
        store: Arc<EnvironmentStore>,
        backend: Arc<FakeEnvironmentBackend>,
        driver: EnvironmentDriver,
    }

    fn rig(backend: FakeEnvironmentBackend) -> Result<Rig> {
        let store = Arc::new(EnvironmentStore::open_in_memory()?);
        let backend = Arc::new(backend);
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, config());
        Ok(Rig { store, backend, driver })
    }

    fn add(store: &EnvironmentStore, n: u32) -> Result<String> {
        let id = format!("env-{n}");
        store.create(
            &format!("r{n}"),
            &id,
            &spec_bytes("small"),
            "sandy.control.v1.EnvironmentSpec",
        )?;
        Ok(id)
    }

    fn state(store: &EnvironmentStore, id: &str) -> Result<EnvironmentRecord> {
        store.get(id)?.with_context(|| format!("{id} missing"))
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    #[test]
    fn a_trusted_only_driver_fails_a_row_that_was_not_created_by_a_trusted_submitter() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        // The untrusted row predates the trusted-only backend, so the store accepts it.
        let untrusted = add(&r.store, 1)?;
        r.store.require_trusted_submitter();
        let trusted = "env-2";
        r.store.create_for(
            "r2",
            trusted,
            &spec_bytes("small"),
            "sandy.control.v1.EnvironmentSpec",
            true,
        )?;

        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.failed, std::slice::from_ref(&untrusted));
        assert_eq!(report.launched, [trusted.to_owned()], "only the trusted row launches");
        let rec = state(&r.store, &untrusted)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        assert_eq!(rec.failure.map(|f| f.step).as_deref(), Some("admission"));
        assert_eq!(r.backend.launched().len(), 1, "the backend never saw the untrusted row");
        Ok(())
    }

    #[test]
    fn a_provisioning_environment_is_launched_then_ready_with_its_endpoint() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(1).with_endpoint(Endpoint {
            host: "127.0.0.1".to_owned(),
            port: 41000,
        }))?;
        let id = add(&r.store, 1)?;

        let first = r.driver.reconcile_once(now())?;
        assert_eq!(first.launched, std::slice::from_ref(&id));
        assert!(first.readied.is_empty(), "the first probe still says Starting");
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Provisioning);

        let second = r.driver.reconcile_once(now())?;
        assert_eq!(second.readied, std::slice::from_ref(&id));
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Ready);
        assert_eq!(rec.endpoint.as_deref(), Some("127.0.0.1:41000"));

        let launched = r.backend.launched();
        assert_eq!(launched.len(), 1);
        assert_eq!(launched[0].environment_id, id);
        assert_eq!(launched[0].template, "t3");
        assert_eq!(launched[0].size.as_deref(), Some("small"));
        assert_eq!(launched[0].service_port, Some(3773));
        Ok(())
    }

    #[test]
    fn passes_are_idempotent_one_launch_however_many_passes() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(5))?;
        add(&r.store, 1)?;
        for _ in 0..4 {
            r.driver.reconcile_once(now())?;
        }
        assert_eq!(r.backend.launched().len(), 1);
        assert!(r.backend.killed().is_empty());
        Ok(())
    }

    #[test]
    fn a_failing_probe_fails_the_environment_with_step_and_reason_and_kills_the_box() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().failing_at(0, "probe", "connection refused"))?;
        let id = add(&r.store, 1)?;
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.failed, std::slice::from_ref(&id));
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        let failure = rec.failure.context("a failure must be recorded")?;
        assert_eq!(
            (failure.step.as_str(), failure.reason.as_str()),
            ("probe", "connection refused")
        );
        assert!(r.backend.boxes()?.is_empty(), "a failed environment keeps no box");
        Ok(())
    }

    #[test]
    fn a_launch_error_fails_the_environment_naming_the_launch_step() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().failing_launch("no kvm"))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        let failure = rec.failure.context("a failure must be recorded")?;
        assert_eq!(failure.step, "launch");
        assert!(failure.reason.contains("no kvm"), "{}", failure.reason);
        Ok(())
    }

    #[test]
    fn a_provisioning_environment_past_the_timeout_fails_and_its_box_is_killed() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(usize::MAX))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        assert!(!r.backend.boxes()?.is_empty());
        // 601 s later the environment is still Provisioning.
        let report = r.driver.reconcile_once(now() + 601)?;
        assert_eq!(report.failed, std::slice::from_ref(&id));
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        assert_eq!(rec.failure.context("failure")?.step, "provision");
        assert!(r.backend.boxes()?.is_empty());
        Ok(())
    }

    #[test]
    fn deleting_or_cancelling_an_environment_kills_its_box() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(usize::MAX))?;
        let a = add(&r.store, 1)?;
        let b = add(&r.store, 2)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(r.backend.boxes()?.len(), 2);
        r.store.cancel(&a)?;
        r.store.delete(&b)?;
        let report = r.driver.reconcile_once(now())?;
        let mut killed = report.killed.clone();
        killed.sort();
        assert_eq!(killed, [a, b]);
        assert!(r.backend.boxes()?.is_empty());
        Ok(())
    }

    #[test]
    fn a_box_with_no_environment_row_is_an_orphan_and_is_killed() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        // The row was never written (or was lost) but a box runs under its id.
        r.backend.launch(&EnvironmentSpec {
            environment_id: "env-orphan".to_owned(),
            template: "t3".to_owned(),
            size: None,
            env: Vec::new(),
            service_port: None,
            secret_dir: None,
        })?;
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.killed, ["env-orphan"]);
        assert!(r.backend.boxes()?.is_empty());
        Ok(())
    }

    #[test]
    fn a_row_written_before_a_crash_but_never_launched_is_launched_on_the_next_pass() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?; // the store write happened; the process died before launch
        assert!(r.backend.boxes()?.is_empty());
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        assert_eq!(r.backend.launched().len(), 1);
        Ok(())
    }

    #[test]
    fn a_restart_mid_provision_continues_the_existing_box_and_launches_no_second() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(2))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?; // the box is up and still Starting
        // sandyd restarts: a new driver over the same store and the same running box.
        let restarted = EnvironmentDriver::new(Arc::clone(&r.store), Arc::clone(&r.backend) as _, config());
        restarted.reconcile_once(now())?;
        restarted.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        assert_eq!(r.backend.launched().len(), 1, "the restart must not start a second VM");
        Ok(())
    }

    #[test]
    fn an_idle_ready_environment_is_stopped_then_its_box_killed_and_the_row_survives() -> Result<()> {
        let store = Arc::new(EnvironmentStore::open_in_memory()?);
        let backend = Arc::new(FakeEnvironmentBackend::new());
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, idle_config(300));
        let id = add(&store, 1)?;
        driver.reconcile_once(now())?;
        assert_eq!(state(&store, &id)?.state, EnvironmentState::Ready);
        let report = driver.reconcile_once(now() + 301)?;
        assert_eq!(report.idle_stopped, std::slice::from_ref(&id));
        assert_eq!(
            state(&store, &id)?.state,
            EnvironmentState::Stopped,
            "stopped, not deleted"
        );
        driver.reconcile_once(now() + 302)?;
        assert!(backend.boxes()?.is_empty(), "the stop must end the box");
        Ok(())
    }

    #[test]
    fn use_renews_the_lease_and_inactivity_alone_does_not() -> Result<()> {
        let store = Arc::new(EnvironmentStore::open_in_memory()?);
        let backend = Arc::new(FakeEnvironmentBackend::new());
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, idle_config(300));
        let id = add(&store, 1)?;
        driver.reconcile_once(now())?;
        assert!(store.touch(&id, now() + 250)?);
        let report = driver.reconcile_once(now() + 400)?; // 150 s after the touch
        assert!(report.idle_stopped.is_empty(), "a renewed lease must hold");
        assert_eq!(state(&store, &id)?.state, EnvironmentState::Ready);
        let report = driver.reconcile_once(now() + 560)?; // 310 s after the touch
        assert_eq!(report.idle_stopped, std::slice::from_ref(&id));
        Ok(())
    }

    #[test]
    fn a_backend_reported_connection_renews_the_lease_and_its_absence_does_not() -> Result<()> {
        let store = Arc::new(EnvironmentStore::open_in_memory()?);
        let backend = Arc::new(FakeEnvironmentBackend::new());
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, idle_config(300));
        let id = add(&store, 1)?;
        driver.reconcile_once(now())?;
        // A client connected straight to the service the whole time: no GetEnvironment, no touch.
        backend.set_active(&id, true);
        let report = driver.reconcile_once(now() + 250)?;
        assert!(report.idle_stopped.is_empty());
        let report = driver.reconcile_once(now() + 400)?; // 400 s after Ready, 150 s after the last use
        assert!(report.idle_stopped.is_empty(), "a connected client must hold the lease");
        // The client disconnects; the lease runs from the last observed use.
        backend.set_active(&id, false);
        let report = driver.reconcile_once(now() + 650)?; // 250 s after the last use
        assert!(report.idle_stopped.is_empty(), "inside the lease after disconnect");
        let report = driver.reconcile_once(now() + 710)?; // 310 s after the last use
        assert_eq!(report.idle_stopped, std::slice::from_ref(&id));
        Ok(())
    }

    #[test]
    fn no_idle_timeout_never_stops_an_environment() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let report = r.driver.reconcile_once(now() + 10_000_000)?;
        assert!(report.idle_stopped.is_empty());
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        Ok(())
    }

    #[test]
    fn a_resumed_environment_starts_a_fresh_lease() -> Result<()> {
        let store = Arc::new(EnvironmentStore::open_in_memory()?);
        let backend = Arc::new(FakeEnvironmentBackend::new());
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, idle_config(300));
        let id = add(&store, 1)?;
        driver.reconcile_once(now())?;
        store.touch(&id, now() + 10)?;
        let stopped = driver.reconcile_once(now() + 400)?;
        assert_eq!(stopped.idle_stopped, std::slice::from_ref(&id));
        driver.reconcile_once(now())?; // box killed
        assert!(
            matches!(store.resume(&id)?, EnvTransition::Applied),
            "resume must apply"
        );
        driver.reconcile_once(now())?; // relaunch to Ready (the store stamps real time, so no offset)
        assert_eq!(state(&store, &id)?.state, EnvironmentState::Ready);
        let rec = state(&store, &id)?;
        assert_eq!(rec.last_activity_at, None, "the old lease must not carry over");
        let report = driver.reconcile_once(now())?;
        assert!(
            report.idle_stopped.is_empty(),
            "a resumed environment must not start idle"
        );
        Ok(())
    }

    #[test]
    fn a_ready_environment_whose_box_died_is_marked_lost() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        r.backend.die(&id);
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.failed, std::slice::from_ref(&id));
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        assert_eq!(rec.failure.context("failure")?.step, "reconcile");
        Ok(())
    }

    #[test]
    fn a_stopped_environment_keeps_no_box() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        r.store.stop(&id)?;
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.killed, std::slice::from_ref(&id));
        assert!(r.backend.boxes()?.is_empty());
        // Resuming sends it back through Provisioning and a fresh box.
        r.store.resume(&id)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        assert_eq!(r.backend.launched().len(), 2);
        Ok(())
    }

    #[test]
    fn environments_are_converged_independently() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let a = add(&r.store, 1)?;
        let b = add(&r.store, 2)?;
        r.store.delete(&b)?;
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(
            report.launched,
            std::slice::from_ref(&a),
            "a deleted row is never launched"
        );
        assert_eq!(state(&r.store, &a)?.state, EnvironmentState::Ready);
        assert_eq!(state(&r.store, &b)?.state, EnvironmentState::Deleted);
        Ok(())
    }

    #[tokio::test]
    async fn the_run_loop_converges_without_being_called_per_environment() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(2))?;
        let id = add(&r.store, 1)?;
        let driver = Arc::new(r.driver);
        let looping = tokio::spawn(Arc::clone(&driver).run(Duration::from_millis(20)));
        let ready = async {
            loop {
                if state(&r.store, &id)?.state == EnvironmentState::Ready {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), ready)
            .await
            .context("never Ready")??;
        looping.abort();
        Ok(())
    }

    #[test]
    fn a_long_downtime_does_not_fail_a_row_that_can_still_become_ready() -> Result<()> {
        // A row nobody launched, found 601 s late: launched and Ready, not failed.
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now() + 601)?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);

        // A box that was still starting, found Ready 601 s later: Ready, not killed.
        let r = rig(FakeEnvironmentBackend::new().starting_polls(1))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        r.driver.reconcile_once(now() + 601)?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        assert!(r.backend.killed().is_empty());
        Ok(())
    }

    #[test]
    fn the_driver_itself_calls_launch_once_while_a_box_runs() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(5))?;
        add(&r.store, 1)?;
        for _ in 0..4 {
            r.driver.reconcile_once(now())?;
        }
        assert_eq!(
            r.backend.launch_calls(),
            1,
            "the fake's idempotence must not be what saves us"
        );
        Ok(())
    }

    #[test]
    fn a_kill_that_fails_is_retried_on_the_next_pass() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(usize::MAX))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        r.store.delete(&id)?;
        r.backend.set_kill_failing(true);
        let stuck = r.driver.reconcile_once(now())?;
        assert!(stuck.killed.is_empty());
        assert_eq!(r.backend.boxes()?.len(), 1, "the box survived the failed kill");
        r.backend.set_kill_failing(false);
        let retried = r.driver.reconcile_once(now())?;
        assert_eq!(retried.killed, [id]);
        assert!(r.backend.boxes()?.is_empty());
        Ok(())
    }

    #[test]
    fn a_probe_that_cannot_run_is_retried_and_does_not_fail_the_environment() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.backend.set_probe_failing(true);
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Provisioning);
        r.backend.set_probe_failing(false);
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        Ok(())
    }

    #[test]
    fn a_ready_environment_whose_probe_fails_is_lost_with_the_probes_step() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        r.backend.set_probe_result(
            &id,
            Probe::Failed {
                step: "service".to_owned(),
                reason: "exited 1".to_owned(),
            },
        );
        r.driver.reconcile_once(now())?;
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        let failure = rec.failure.context("failure")?;
        assert_eq!(
            (failure.step.as_str(), failure.reason.as_str()),
            ("service", "exited 1")
        );
        assert!(r.backend.boxes()?.is_empty(), "a lost environment keeps no box");
        Ok(())
    }

    #[test]
    fn a_launched_box_that_reports_not_running_fails_the_environment_at_launch() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.backend.set_probe_result(&id, Probe::NotRunning);
        r.driver.reconcile_once(now())?;
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        assert_eq!(rec.failure.context("failure")?.step, "launch");
        Ok(())
    }

    #[test]
    fn one_environments_failure_leaves_the_others_alone() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let bad = add(&r.store, 1)?;
        let good = add(&r.store, 2)?;
        r.backend.set_probe_result(
            &bad,
            Probe::Failed {
                step: "boot".to_owned(),
                reason: "no".to_owned(),
            },
        );
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &bad)?.state, EnvironmentState::Failed);
        assert_eq!(state(&r.store, &good)?.state, EnvironmentState::Ready);
        assert_eq!(r.backend.boxes()?.len(), 1, "only the good environment keeps a box");
        Ok(())
    }

    #[test]
    fn a_corrupt_row_does_not_stop_the_pass_and_its_box_is_not_killed_as_an_orphan() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("env.db");
        let store = Arc::new(EnvironmentStore::open(&path)?);
        let backend = Arc::new(FakeEnvironmentBackend::new().starting_polls(usize::MAX));
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, config());
        let corrupt = add(&store, 1)?;
        driver.reconcile_once(now())?; // env-1 is launched and still starting
        let healthy = add(&store, 2)?;
        rusqlite::Connection::open(&path)?.execute(
            "UPDATE environments SET state = 'bogus' WHERE environment_id = ?1",
            [&corrupt],
        )?;
        let report = driver.reconcile_once(now())?;
        assert_eq!(
            report.launched,
            std::slice::from_ref(&healthy),
            "the healthy row is still launched"
        );
        assert!(
            report.killed.is_empty(),
            "the corrupt row's box must not be killed as an orphan"
        );
        let ids: Vec<_> = backend.boxes()?.into_iter().map(|b| b.box_id).collect();
        assert_eq!(ids, [corrupt, healthy]);
        Ok(())
    }

    #[test]
    fn a_second_driver_over_the_same_store_and_backend_kills_nothing_the_first_one_launched() -> Result<()> {
        // The box snapshot is taken before the row listing, so a row created
        // (and its box launched by another driver) between the two reads is
        // either seen with its row or not seen at all, never seen as a box alone.
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let other = EnvironmentDriver::new(Arc::clone(&r.store), Arc::clone(&r.backend) as _, config());
        let second = other.reconcile_once(now())?;
        assert!(
            second.killed.is_empty(),
            "a second driver must not kill the first one's box"
        );
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        Ok(())
    }

    #[test]
    fn the_endpoint_is_recorded_as_host_port_with_brackets_for_ipv6() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().with_endpoint(Endpoint {
            host: "::1".to_owned(),
            port: 41000,
        }))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.endpoint.as_deref(), Some("[::1]:41000"));
        Ok(())
    }

    #[test]
    fn an_endpoint_that_is_not_a_plain_host_fails_the_environment_instead_of_becoming_a_url() -> Result<()> {
        for host in ["a@b/x", "http://evil", "host name", "", "bad_host"] {
            let r = rig(FakeEnvironmentBackend::new().with_endpoint(Endpoint {
                host: host.to_owned(),
                port: 1,
            }))?;
            let id = add(&r.store, 1)?;
            r.driver.reconcile_once(now())?;
            let rec = state(&r.store, &id)?;
            assert_eq!(rec.state, EnvironmentState::Failed, "host {host:?}");
            assert_eq!(rec.failure.context("failure")?.step, "probe");
            assert_eq!(rec.endpoint, None);
            assert!(r.backend.boxes()?.is_empty());
        }
        Ok(())
    }

    #[test]
    fn a_row_older_than_the_timeout_gets_its_full_boot_time_after_its_first_launch() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(1))?;
        let id = add(&r.store, 1)?;
        let late = now() + 601; // the daemon was down for longer than the timeout
        let first = r.driver.reconcile_once(late)?;
        assert_eq!(first.launched, std::slice::from_ref(&id));
        assert!(
            first.failed.is_empty(),
            "the first Starting probe must not fail a row launched just now"
        );
        assert_eq!(r.backend.boxes()?.len(), 1, "the box must not be killed");
        r.driver.reconcile_once(late + 1)?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);

        // The clock still runs from the launch: a box that never gets ready is failed, later.
        let r = rig(FakeEnvironmentBackend::new().starting_polls(usize::MAX))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(late)?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Provisioning);
        let report = r.driver.reconcile_once(late + 601)?;
        assert_eq!(report.failed, std::slice::from_ref(&id));
        assert_eq!(state(&r.store, &id)?.failure.context("failure")?.step, "provision");
        Ok(())
    }

    #[test]
    fn a_delete_that_lands_during_the_launch_kills_the_box_in_the_same_pass() -> Result<()> {
        let store = Arc::new(EnvironmentStore::open_in_memory()?);
        let hook_store = Arc::clone(&store);
        let backend = Arc::new(FakeEnvironmentBackend::new().on_probe(move |id| {
            let _ = hook_store.delete(id);
        }));
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, config());
        let id = add(&store, 1)?;
        let report = driver.reconcile_once(now())?;
        assert!(report.readied.is_empty());
        assert_eq!(
            report.killed,
            std::slice::from_ref(&id),
            "the box must be torn down at once, not on a later pass"
        );
        assert!(backend.boxes()?.is_empty());
        assert_eq!(state(&store, &id)?.state, EnvironmentState::Deleted);
        Ok(())
    }

    #[test]
    fn a_probe_that_cannot_run_is_retried_past_the_timeout_and_fails_only_after_twice_of_it() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.backend.set_probe_failing(true);
        let base = now();
        r.driver.reconcile_once(base)?;
        let past_timeout = r.driver.reconcile_once(base + 601)?;
        assert!(
            past_timeout.failed.is_empty(),
            "one transport fault past the timeout must not end the environment"
        );
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Provisioning);
        r.backend.set_probe_failing(false);
        r.driver.reconcile_once(base + 602)?;
        assert_eq!(
            state(&r.store, &id)?.state,
            EnvironmentState::Ready,
            "a recovered probe still readies it"
        );

        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.backend.set_probe_failing(true);
        r.driver.reconcile_once(base)?;
        let report = r.driver.reconcile_once(base + 1201)?;
        assert_eq!(
            report.failed,
            std::slice::from_ref(&id),
            "a probe broken for twice the timeout fails the row"
        );
        assert_eq!(state(&r.store, &id)?.failure.context("failure")?.step, "provision");
        assert!(r.backend.boxes()?.is_empty());
        Ok(())
    }

    // ---- #706: the per-environment forge credential ----

    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::atomic::Ordering,
    };

    use crate::{
        environment_credential::fakes::{Resolver, Rotating},
        test_support::test_profiles,
    };

    struct CredRig {
        store: Arc<EnvironmentStore>,
        backend: Arc<FakeEnvironmentBackend>,
        provider: Arc<Rotating>,
        base: std::path::PathBuf,
        driver: EnvironmentDriver,
        _tmp: tempfile::TempDir,
    }

    fn creds_over(provider: &Arc<Rotating>, base: &std::path::Path) -> Arc<EnvironmentCredentials> {
        Arc::new(
            EnvironmentCredentials::new(Arc::new(Resolver(Arc::clone(provider))), base.to_owned())
                // Always due, so every pass over a Ready environment renews.
                .with_margin(Duration::from_secs(100_000)),
        )
    }

    fn cred_rig(backend: FakeEnvironmentBackend) -> Result<CredRig> {
        let tmp = tempfile::tempdir()?;
        let base = tmp.path().join("staging");
        std::fs::create_dir(&base)?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
        let store = Arc::new(EnvironmentStore::open_in_memory()?.with_profiles(test_profiles()));
        let backend = Arc::new(backend);
        let provider = Arc::new(Rotating::default());
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, config())
            .with_credentials(creds_over(&provider, &base));
        Ok(CredRig {
            store,
            backend,
            provider,
            base,
            driver,
            _tmp: tmp,
        })
    }

    fn staged(r: &CredRig, id: &str) -> std::path::PathBuf {
        r.base.join(format!("env-cred-{id}")).join("GITHUB_TOKEN")
    }

    #[test]
    fn the_credential_is_minted_before_the_launch_and_the_spec_carries_its_share() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let launched = r.backend.launched();
        let spec = launched.first().context("the environment launched")?;
        let (dir, _) = spec.secret_dir.clone().context("the spec carries a secret share")?;
        assert_eq!(dir, r.base.join(format!("env-cred-{id}")));
        assert_eq!(std::fs::read_to_string(staged(&r, &id))?, "tok-1");
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        Ok(())
    }

    #[test]
    fn a_mint_failure_fails_the_environment_closed_and_nothing_launches() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        r.provider.fail_mint.store(true, Ordering::SeqCst);
        let id = add(&r.store, 1)?;
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.failed, std::slice::from_ref(&id));
        assert!(
            r.backend.launched().is_empty(),
            "a guest must never boot without its token"
        );
        let rec = state(&r.store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Failed);
        let failure = rec.failure.context("a failure is recorded")?;
        assert_eq!(failure.step, "credential");
        assert!(failure.reason.contains("the forge refused"), "{}", failure.reason);
        assert!(!staged(&r, &id).exists());
        Ok(())
    }

    #[test]
    fn a_profile_outside_the_registry_fails_the_credential_step_without_naming_it() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = "env-9";
        let spec = WireSpec {
            profile: "stranger-profile".to_owned(),
            size: "small".to_owned(),
            lifetime: Some(EnvironmentLifetime {
                kind: EnvironmentLifetimeKind::Ephemeral.into(),
                ttl_secs: 600,
            }),
            task_ref: String::new(),
        };
        // Written straight to the store: the create path would refuse it first.
        let bare = EnvironmentStore::open_in_memory()?;
        bare.create("r9", id, &spec.encode_to_vec(), "sandy.control.v1.EnvironmentSpec")?;
        let driver = EnvironmentDriver::new(Arc::new(bare), Arc::clone(&r.backend) as _, config())
            .with_credentials(creds_over(&r.provider, &r.base));
        driver.reconcile_once(now())?;
        assert!(r.backend.launched().is_empty());
        let rec = driver.store.get(id)?.context("row")?;
        let failure = rec.failure.context("a failure is recorded")?;
        assert_eq!(failure.step, "credential");
        assert!(!failure.reason.contains("stranger-profile"), "{}", failure.reason);
        Ok(())
    }

    #[test]
    fn stop_delete_and_a_lost_box_each_revoke_and_remove_the_token() -> Result<()> {
        for how in ["stop", "delete", "lost"] {
            let r = cred_rig(FakeEnvironmentBackend::new())?;
            let id = add(&r.store, 1)?;
            r.driver.reconcile_once(now())?;
            assert!(staged(&r, &id).exists(), "{how}: staged while ready");
            match how {
                "stop" => assert!(matches!(r.store.stop(&id)?, EnvTransition::Applied)),
                "delete" => assert!(matches!(r.store.delete(&id)?, EnvTransition::Applied)),
                _ => r.backend.die(&id),
            }
            r.driver.reconcile_once(now())?;
            assert_eq!(r.provider.revoked(), ["h1"], "{how}: the lease is revoked");
            assert!(!staged(&r, &id).exists(), "{how}: the token file is gone");
            assert!(
                !r.base.join(format!("env-cred-{id}")).exists(),
                "{how}: the dir is gone"
            );
            r.driver.reconcile_once(now())?;
            assert_eq!(
                r.provider.revoked().len(),
                1,
                "{how}: a later pass revokes nothing more"
            );
        }
        Ok(())
    }

    #[test]
    fn an_orphan_boxs_credential_is_released_too() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        // The row disappears while the box and the lease stay: a fresh store models a lost row.
        let empty = Arc::new(EnvironmentStore::open_in_memory()?.with_profiles(test_profiles()));
        let driver = EnvironmentDriver::new(empty, Arc::clone(&r.backend) as _, config())
            .with_credentials(creds_over(&r.provider, &r.base));
        let report = driver.reconcile_once(now())?;
        assert_eq!(report.killed, std::slice::from_ref(&id));
        assert!(!staged(&r, &id).exists(), "no token file may outlive its environment");
        Ok(())
    }

    #[test]
    fn a_revoke_failure_is_recorded_on_the_row_and_the_stop_still_happens() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let secret = std::fs::read_to_string(staged(&r, &id))?;
        r.provider.fail_revoke.store(true, Ordering::SeqCst);
        r.store.stop(&id)?;
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.killed, std::slice::from_ref(&id), "the box is killed regardless");
        let rec = state(&r.store, &id)?;
        let error = rec.credential_error.context("the revoke failure is on the row")?;
        assert!(error.contains("the forge refused"), "{error}");
        assert!(!error.contains(&secret), "the token must never reach the row");
        assert!(
            !staged(&r, &id).exists(),
            "the file is removed even when the revoke fails"
        );
        Ok(())
    }

    #[test]
    fn a_resume_mints_a_fresh_token_and_clears_the_revoke_failure() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        r.provider.fail_revoke.store(true, Ordering::SeqCst);
        r.store.stop(&id)?;
        r.driver.reconcile_once(now())?; // stopped: box killed, revoke fails
        assert!(state(&r.store, &id)?.credential_error.is_some());
        r.provider.fail_revoke.store(false, Ordering::SeqCst);
        assert!(matches!(r.store.resume(&id)?, EnvTransition::Applied));
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        assert_eq!(
            std::fs::read_to_string(staged(&r, &id))?,
            "tok-2",
            "a resume mints anew"
        );
        assert_eq!(
            state(&r.store, &id)?.credential_error,
            None,
            "the old failure is cleared"
        );
        Ok(())
    }

    #[test]
    fn a_ready_environment_renews_and_a_failed_renewal_marks_it_degraded_until_one_works() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?; // launch and ready, tok-1
        r.driver.reconcile_once(now())?; // renewal: tok-2, h1 revoked
        assert_eq!(std::fs::read_to_string(staged(&r, &id))?, "tok-2");
        assert_eq!(
            r.provider.revoked(),
            ["h1"],
            "the old lease is revoked after the new token is staged"
        );
        assert!(!state(&r.store, &id)?.credential_degraded);

        r.provider.fail_refresh.store(true, Ordering::SeqCst);
        r.driver.reconcile_once(now())?;
        let rec = state(&r.store, &id)?;
        assert_eq!(
            rec.state,
            EnvironmentState::Ready,
            "a failed renewal leaves the environment running"
        );
        assert!(rec.credential_degraded);
        assert_eq!(
            std::fs::read_to_string(staged(&r, &id))?,
            "tok-2",
            "the held token stays staged"
        );

        r.provider.fail_refresh.store(false, Ordering::SeqCst);
        r.driver.reconcile_once(now())?;
        assert!(
            !state(&r.store, &id)?.credential_degraded,
            "a later renewal clears the mark"
        );
        Ok(())
    }

    #[test]
    fn a_restarted_daemon_mints_into_the_share_the_running_guest_mounted() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let (dir, _) = r.backend.launched()[0].secret_dir.clone().context("share")?;
        // A restart: a new driver and registry over the same store, box and staging base.
        let restarted = EnvironmentDriver::new(Arc::clone(&r.store), Arc::clone(&r.backend) as _, config())
            .with_credentials(Arc::new(
                EnvironmentCredentials::new(Arc::new(Resolver(Arc::clone(&r.provider))), r.base.clone())
                    .with_margin(Duration::from_secs(1)),
            ));
        restarted.reconcile_once(now())?;
        assert_eq!(r.backend.launched().len(), 1, "the running guest is not relaunched");
        assert_eq!(std::fs::read_to_string(dir.join("GITHUB_TOKEN"))?, "tok-2");
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        Ok(())
    }

    #[test]
    fn a_driver_without_credentials_launches_with_no_share() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(r.backend.launched().first().map(|s| s.secret_dir.clone()), Some(None));
        Ok(())
    }

    #[test]
    fn a_driver_without_a_credential_component_launches_a_profile_that_names_a_trust_root_tokenless() -> Result<()> {
        // The process backend has no secret channel, so main wires no credential component for it: the environment
        // runs with no token and no mark. Failing closed would make the backend unusable, since every profile names
        // a trust root and a create needs a registry.
        let store = Arc::new(EnvironmentStore::open_in_memory()?.with_profiles(test_profiles()));
        let backend = Arc::new(FakeEnvironmentBackend::new());
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&backend) as _, config());
        let id = add(&store, 1)?;
        driver.reconcile_once(now())?;
        assert_eq!(backend.launched().first().map(|s| s.secret_dir.clone()), Some(None));
        let rec = state(&store, &id)?;
        assert_eq!(rec.state, EnvironmentState::Ready);
        assert!(!rec.credential_degraded && rec.credential_error.is_none());
        Ok(())
    }

    #[test]
    fn a_kill_that_fails_keeps_the_share_and_the_lease_and_a_resume_reuses_the_running_guest() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let share = r.base.join(format!("env-cred-{id}"));
        let inode = std::fs::metadata(&share)?.ino();
        r.backend.set_kill_failing(true);
        r.store.stop(&id)?;
        r.driver.reconcile_once(now())?;
        assert!(r.provider.revoked().is_empty(), "the guest still runs: the lease stays");
        assert!(share.exists(), "the share the guest mounts is not removed");
        // The owner resumes before the box died: the same guest is adopted, nothing is minted into a new dir.
        assert!(matches!(r.store.resume(&id)?, EnvTransition::Applied));
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        assert_eq!(std::fs::metadata(&share)?.ino(), inode, "the guest's mount stays valid");
        assert_eq!(r.provider.next.load(Ordering::SeqCst), 1, "no second mint");
        // Once the box can be killed, the stop releases for real.
        r.backend.set_kill_failing(false);
        r.store.stop(&id)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(r.provider.revoked(), ["h1"]);
        assert!(!share.exists());
        Ok(())
    }

    /// Launch, boxes and kill come from the fake; the probe sleeps, may panic for
    /// one environment, and records how many probes run at once (#709).
    struct ProbeLab {
        inner: FakeEnvironmentBackend,
        delay: Duration,
        panic_on: Option<String>,
        inside: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        /// Probe calls per environment id, counted before the probe can panic.
        calls: Mutex<std::collections::BTreeMap<String, usize>>,
    }

    impl ProbeLab {
        fn new(delay: Duration, panic_on: Option<&str>) -> Self {
            Self {
                inner: FakeEnvironmentBackend::new(),
                delay,
                panic_on: panic_on.map(str::to_owned),
                inside: std::sync::atomic::AtomicUsize::default(),
                peak: std::sync::atomic::AtomicUsize::default(),
                calls: Mutex::default(),
            }
        }

        fn calls_for(&self, id: &str) -> usize {
            let calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
            calls.get(id).copied().unwrap_or(0)
        }
    }

    impl EnvironmentBackend for ProbeLab {
        fn launch(&self, spec: &EnvironmentSpec) -> Result<Launch, BackendError> {
            self.inner.launch(spec)
        }

        fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
            use std::sync::atomic::Ordering::SeqCst;
            *self
                .calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(environment_id.to_owned())
                .or_default() += 1;
            let now = self.inside.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            if self.panic_on.as_deref() == Some(environment_id) {
                self.inside.fetch_sub(1, SeqCst);
                panic!("probe of {environment_id} panicked");
            }
            std::thread::sleep(self.delay);
            self.inside.fetch_sub(1, SeqCst);
            Ok(Probe::Ready {
                endpoint: Endpoint {
                    host: "127.0.0.1".to_owned(),
                    port: 41000,
                },
            })
        }

        fn kill(&self, environment_id: &str) -> Result<(), BackendError> {
            self.inner.kill(environment_id)
        }

        fn boxes(&self) -> Result<Vec<sandy_api::backend::BoxState>, BackendError> {
            self.inner.boxes()
        }
    }

    fn lab_rig(lab: ProbeLab) -> Result<(Rig2, Arc<ProbeLab>)> {
        let store = Arc::new(EnvironmentStore::open_in_memory()?);
        let lab = Arc::new(lab);
        let driver = EnvironmentDriver::new(Arc::clone(&store), Arc::clone(&lab) as _, config());
        Ok((Rig2 { store, driver }, lab))
    }

    struct Rig2 {
        store: Arc<EnvironmentStore>,
        driver: EnvironmentDriver,
    }

    /// #709: N Provisioning environments whose probes each take a second must
    /// not make a pass take N seconds.
    #[test]
    fn eight_slow_probes_finish_one_pass_in_about_one_probe_budget() -> Result<()> {
        let (r, _lab) = lab_rig(ProbeLab::new(Duration::from_secs(1), None))?;
        for n in 1..=8 {
            add(&r.store, n)?;
        }
        let started = std::time::Instant::now();
        let report = r.driver.reconcile_once(now())?;
        let took = started.elapsed();
        assert!(took < Duration::from_secs(3), "one pass took {took:?}");
        assert_eq!(report.readied.len(), 8, "{report:?}");
        for n in 1..=8 {
            assert_eq!(state(&r.store, &format!("env-{n}"))?.state, EnvironmentState::Ready);
        }
        Ok(())
    }

    /// #709: a probe that panics fails only that environment's pass. The others
    /// keep their results, and the panicked one is probed again next pass.
    #[test]
    fn a_panicking_probe_leaves_the_other_environments_results_intact() -> Result<()> {
        let (r, lab) = lab_rig(ProbeLab::new(Duration::from_millis(50), Some("env-2")))?;
        for n in 1..=4 {
            add(&r.store, n)?;
        }
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(lab.calls_for("env-2"), 1, "the panicking probe did run");
        assert_eq!(report.readied.len(), 3, "{report:?}");
        assert!(
            report.failed.is_empty(),
            "a panic is a probe fault, not a failure: {report:?}"
        );
        assert_eq!(state(&r.store, "env-2")?.state, EnvironmentState::Provisioning);
        for n in [1, 3, 4] {
            assert_eq!(state(&r.store, &format!("env-{n}"))?.state, EnvironmentState::Ready);
        }
        // The panicked row is probed again next pass, not skipped for good.
        r.driver.reconcile_once(now())?;
        assert_eq!(lab.calls_for("env-2"), 2, "the next pass probes it again");
        Ok(())
    }

    /// #709: at most eight probes are in flight, however many environments.
    #[test]
    fn no_more_than_eight_probes_run_at_once() -> Result<()> {
        let (r, lab) = lab_rig(ProbeLab::new(Duration::from_millis(100), None))?;
        for n in 1..=20 {
            add(&r.store, n)?;
        }
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.readied.len(), 20, "{report:?}");
        let peak = lab.peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(peak > 1, "probes must overlap, peak was {peak}");
        assert!(peak <= 8, "at most 8 probes in flight, peak was {peak}");
        Ok(())
    }

    /// #727: a provision that never gets Ready says what the guest console showed,
    /// since `sandyd` keeps no console log of its own.
    #[test]
    fn a_provision_timeout_carries_the_console_tail_in_its_reason() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().starting_polls(1000))?;
        let id = add(&r.store, 1)?;
        r.backend.set_console_tail(&id, "socat: bind failed\nlogin:");
        let base = now();
        r.driver.reconcile_once(base)?;
        let report = r.driver.reconcile_once(base + 601)?;
        assert_eq!(report.failed, std::slice::from_ref(&id));
        let failure = state(&r.store, &id)?.failure.context("failure")?;
        assert_eq!(failure.step, "provision");
        assert!(
            failure.reason.contains("console tail:\nsocat: bind failed\nlogin:"),
            "{}",
            failure.reason
        );
        assert!(failure.reason.starts_with("not ready after"), "{}", failure.reason);
        Ok(())
    }

    #[test]
    fn a_probe_that_reports_failed_carries_the_console_tail_in_its_reason() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().failing_at(0, "probe", "connection refused"))?;
        let id = add(&r.store, 1)?;
        r.backend.set_console_tail(&id, "kernel panic");
        r.driver.reconcile_once(now())?;
        let failure = state(&r.store, &id)?.failure.context("failure")?;
        assert_eq!(failure.step, "probe");
        assert_eq!(failure.reason, "connection refused\nconsole tail:\nkernel panic");
        Ok(())
    }

    /// The tail must survive a kill that fails: the box may be wedged, which is when the console matters most.
    #[test]
    fn the_console_tail_is_carried_when_the_kill_fails_too() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().failing_at(0, "probe", "connection refused"))?;
        let id = add(&r.store, 1)?;
        r.backend.set_kill_failing(true);
        r.backend.set_console_tail(&id, "hung task");
        r.driver.reconcile_once(now())?;
        let failure = state(&r.store, &id)?.failure.context("failure")?;
        assert!(
            failure.reason.ends_with("console tail:\nhung task"),
            "{}",
            failure.reason
        );
        Ok(())
    }

    /// No console (a process backend, a launch that failed before a box existed): the reason is unchanged.
    #[test]
    fn a_failure_without_a_console_tail_keeps_its_reason() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new().failing_at(0, "probe", "connection refused"))?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        let failure = state(&r.store, &id)?.failure.context("failure")?;
        assert_eq!(failure.reason, "connection refused");
        Ok(())
    }
    /// #727: a stop leaves the old run's console behind, and a later failure before a box boots must not show it as
    /// its own.
    #[test]
    fn a_failure_before_boot_never_shows_an_earlier_runs_console() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let untrusted = add(&r.store, 1)?;
        r.store.require_trusted_submitter();
        r.backend.set_console_tail(&untrusted, "output of an earlier run");
        r.driver.reconcile_once(now())?;
        let failure = state(&r.store, &untrusted)?.failure.context("failure")?;
        assert_eq!(failure.step, "admission");
        assert!(!failure.reason.contains("console tail"), "{}", failure.reason);
        assert!(!failure.reason.contains("earlier run"), "{}", failure.reason);
        Ok(())
    }

    /// The console of a box that ended without a failure is dropped when the driver kills it, so it cannot wait for a
    /// later failure of the same id.
    #[test]
    fn killing_a_stopped_environments_box_drops_its_console() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        r.backend.set_console_tail(&id, "output of the run that just stopped");
        assert!(matches!(r.store.stop(&id)?, EnvTransition::Applied));
        r.driver.reconcile_once(now())?;
        assert_eq!(r.backend.killed(), std::slice::from_ref(&id));
        assert_eq!(
            r.backend.console_tail(&id),
            None,
            "the stopped run's console must be gone"
        );
        Ok(())
    }

    /// A held guest has a staged token since #706, and the agent prints the job's transcript on the console when the
    /// service exits: the exact token must not reach the stored reason. The test provider mints `tok-1` first.
    #[test]
    fn the_staged_token_is_scrubbed_from_the_console_tail() -> Result<()> {
        let r = cred_rig(FakeEnvironmentBackend::new().failing_at(0, "probe", "connection refused"))?;
        let id = add(&r.store, 1)?;
        r.backend
            .set_console_tail(&id, "service said: auth failed with tok-1 for the repo");
        r.driver.reconcile_once(now())?;
        let failure = state(&r.store, &id)?.failure.context("failure")?;
        assert!(
            !failure.reason.contains("tok-1"),
            "the token reached the reason: {}",
            failure.reason
        );
        assert!(
            failure.reason.contains("auth failed with [redacted] for the repo"),
            "{}",
            failure.reason
        );
        Ok(())
    }

    /// A tail that cannot be checked against the staged token is not stored.
    #[test]
    fn a_console_tail_is_dropped_when_the_staged_token_cannot_be_read() -> Result<()> {
        let target = Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
        let hook_target = Arc::clone(&target);
        let backend = FakeEnvironmentBackend::new()
            .failing_at(0, "probe", "connection refused")
            .on_probe(move |_| {
                // The token file goes away between the mint and the failure.
                if let Some(path) = hook_target.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
                    let _ = std::fs::remove_file(path);
                }
            });
        let r = cred_rig(backend)?;
        let id = add(&r.store, 1)?;
        *target.lock().unwrap_or_else(PoisonError::into_inner) = Some(staged(&r, &id));
        r.backend.set_console_tail(&id, "something unscrubbed");
        r.driver.reconcile_once(now())?;
        let failure = state(&r.store, &id)?.failure.context("failure")?;
        assert!(!failure.reason.contains("something unscrubbed"), "{}", failure.reason);
        assert!(failure.reason.contains("console tail dropped"), "{}", failure.reason);
        Ok(())
    }

    /// A box that survives its kill keeps writing to its ring, and a resume may adopt it: the console stays.
    #[test]
    fn a_failed_kill_keeps_the_console_of_the_box_that_is_still_running() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        r.backend.set_console_tail(&id, "still running");
        r.backend.set_kill_failing(true);
        assert!(matches!(r.store.stop(&id)?, EnvTransition::Applied));
        r.driver.reconcile_once(now())?;
        assert_eq!(r.backend.console_tail(&id).as_deref(), Some("still running"));
        Ok(())
    }
}
