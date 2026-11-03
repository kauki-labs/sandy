//! The environment launch driver (#587, slices B and C2): converges the boxes an
//! [`EnvironmentBackend`] runs to the environments the store says should exist.
//!
//! It is level-triggered, not event-triggered. Every pass reads the whole store
//! and the backend's box list and fixes each difference, so the same pass is
//! the reconciler after a `sandyd` restart: nothing is remembered in memory.
//!
//! - `Provisioning` with no box: launch one (idempotent per environment id). Probe it: still starting leaves the row
//!   alone; Ready records the endpoint and marks it `Ready`; Failed records the step and reason and kills the box. A
//!   row that stays `Provisioning` past the timeout is failed and its box killed.
//! - `Ready` whose box is gone or failing: marked lost (`Failed`), box killed.
//! - `Stopped`, `Failed`, `Deleted`: no box may run, so any box is killed.
//! - A box with no environment row is an orphan and is killed.
//!
//! The backend calls block, so a pass runs under `spawn_blocking`.

use std::{sync::Arc, time::Duration};

use sandy_api::{
    backend::BackendError,
    environment::{Endpoint, EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};
use sandy_control_proto::v1::EnvironmentSpec as WireSpec;

use crate::environment_store::{EnvironmentRecord, EnvironmentState, EnvironmentStore, EnvironmentStoreError};

/// What the driver launches and how long it waits.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// The guest flake attr every environment boots.
    pub template: String,
    /// The TCP port the guest's service listens on, passed to the backend so it
    /// can bridge the port.
    pub service_port: Option<u16>,
    /// How long a row may stay `Provisioning` before it is failed.
    pub provision_timeout: Duration,
}

/// A failure the driver cannot turn into an environment state.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The environment store faulted.
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
    /// [`DriverError`] when the store faults or the backend cannot list boxes.
    /// A failure of one environment's backend call fails that environment, not
    /// the pass.
    pub fn reconcile_once(&self, now: i64) -> Result<Report, DriverError> {
        let _ = (
            now,
            &self.store,
            &self.backend,
            &self.config,
            Report::default(),
            Endpoint {
                host: String::new(),
                port: 0,
            },
            Launch::Started,
            Probe::NotRunning,
            EnvironmentState::Ready,
        );
        let _: Option<(EnvironmentRecord, EnvironmentSpec, WireSpec)> = None;
        unimplemented!("#587 slice C2: red")
    }

    /// Run [`EnvironmentDriver::reconcile_once`] every `interval` until the
    /// returned future is dropped. A failed pass is logged and retried.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        let _ = (self, interval);
        unimplemented!("#587 slice C2: red")
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};
    use prost::Message;
    use sandy_api::environment::Endpoint;
    use sandy_control_proto::v1::{EnvironmentLifetime, EnvironmentLifetimeKind};
    use sandy_test_support::FakeEnvironmentBackend;

    use super::*;

    fn config() -> DriverConfig {
        DriverConfig {
            template: "t3".to_owned(),
            service_port: Some(3773),
            provision_timeout: Duration::from_secs(600),
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
        assert_eq!(first.launched, [id.clone()]);
        assert!(first.readied.is_empty(), "the first probe still says Starting");
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Provisioning);

        let second = r.driver.reconcile_once(now())?;
        assert_eq!(second.readied, [id.clone()]);
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
        assert_eq!(report.failed, [id.clone()]);
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
        assert_eq!(report.failed, [id.clone()]);
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
    fn a_ready_environment_whose_box_died_is_marked_lost() -> Result<()> {
        let r = rig(FakeEnvironmentBackend::new())?;
        let id = add(&r.store, 1)?;
        r.driver.reconcile_once(now())?;
        assert_eq!(state(&r.store, &id)?.state, EnvironmentState::Ready);
        r.backend.die(&id);
        let report = r.driver.reconcile_once(now())?;
        assert_eq!(report.failed, [id.clone()]);
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
        assert_eq!(report.killed, [id.clone()]);
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
        assert_eq!(report.launched, [a.clone()], "a deleted row is never launched");
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
}
