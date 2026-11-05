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
//! runs under `spawn_blocking`.

use std::{collections::BTreeSet, net::IpAddr, sync::Arc, time::Duration};

use prost::Message;
use sandy_api::{
    backend::BackendError,
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};
use sandy_control_proto::v1::EnvironmentSpec as WireSpec;

use crate::environment_store::{
    EnvTransition, EnvironmentRecord, EnvironmentState, EnvironmentStore, EnvironmentStoreError,
};

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
}

impl EnvironmentDriver {
    /// A driver over `store` and `backend`.
    pub fn new(
        store: Arc<EnvironmentStore>,
        backend: Arc<dyn EnvironmentBackend + Send + Sync>,
        config: DriverConfig,
    ) -> Self {
        Self { store, backend, config }
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
        for row in self.store.list_each()? {
            match row {
                Ok(row) => {
                    known.insert(row.environment_id.clone());
                    if let Err(e) = self.converge(&row, now, &mut running, &mut report) {
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
        // A box no environment row names is an orphan: the row was never written or is gone.
        let orphans: Vec<String> = running
            .iter()
            .filter(|id| !known.contains(id.as_str()))
            .cloned()
            .collect();
        for id in orphans {
            self.kill(&id, &mut running, &mut report);
        }
        Ok(report)
    }

    fn converge(
        &self,
        row: &EnvironmentRecord,
        now: i64,
        running: &mut BTreeSet<String>,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        match row.state {
            EnvironmentState::Provisioning => self.provision(row, now, running, report),
            EnvironmentState::Ready => self.check_ready(row, now, running, report),
            EnvironmentState::Stopped | EnvironmentState::Failed | EnvironmentState::Deleted => {
                if running.contains(&row.environment_id) {
                    self.kill(&row.environment_id, running, report);
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
        if self.store.mark_lost(id, step, reason)? == EnvTransition::Applied {
            report.failed.push(id.to_owned());
        }
        Ok(())
    }

    fn to_spec(&self, row: &EnvironmentRecord) -> Option<EnvironmentSpec> {
        let wire = WireSpec::decode(row.spec.as_slice()).ok()?;
        Some(EnvironmentSpec {
            environment_id: row.environment_id.clone(),
            template: self.config.template.clone(),
            size: (!wire.size.is_empty()).then_some(wire.size),
            env: Vec::new(),
            service_port: self.config.service_port,
        })
    }

    fn provision(
        &self,
        row: &EnvironmentRecord,
        now: i64,
        running: &mut BTreeSet<String>,
        report: &mut Report,
    ) -> Result<(), EnvironmentStoreError> {
        let id = row.environment_id.as_str();
        if !running.contains(id) {
            let Some(spec) = self.to_spec(row) else {
                return self.fail(id, "spec", "the stored spec does not decode", report);
            };
            match self.backend.launch(&spec) {
                Ok(Launch::Started) => {
                    running.insert(id.to_owned());
                    report.launched.push(id.to_owned());
                }
                Ok(Launch::AlreadyRunning) => {
                    running.insert(id.to_owned());
                }
                Err(e) => return self.fail(id, "launch", &e.to_string(), report),
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
        match self.backend.probe(id) {
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
            Ok(Probe::Ready { .. } | Probe::Starting { .. }) => self.stop_if_idle(row, now, report)?,
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
}
