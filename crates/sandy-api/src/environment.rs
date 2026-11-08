//! The long-lived sandbox seam (#587, slice C): [`EnvironmentBackend`].
//!
//! A sibling of [`crate::backend::VmBackend`], which runs one job to completion.
//! An environment is launched once, probed until its service answers, and killed
//! when it is deleted. Nothing here runs a job; a launched box stays up until
//! [`EnvironmentBackend::kill`].
//!
//! Two choices carry the design:
//!
//! - **A box is keyed by `environment_id`, not by an in-memory handle.** The id survives a `sandyd` restart, so the
//!   reconciler can find a box with [`EnvironmentBackend::boxes`] and no orphan can hide behind a lost handle.
//! - **`launch` returns before Ready.** Ready means [`EnvironmentBackend::probe`] reported [`Probe::Ready`], never
//!   console text (#585 O2, #589).
//!
//! `stop` and `resume` are not part of the seam yet: an ephemeral environment
//! cannot be stopped, and a real resume needs persistent guest state (#588).

use crate::backend::{BackendError, BoxState};

/// What to launch: one environment, one box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentSpec {
    /// The environment's id, also the box's id.
    pub environment_id: String,
    /// The guest flake attr to boot.
    pub template: String,
    /// A size class name; `None` is the backend's default.
    pub size: Option<String>,
    /// Non-secret environment variables for the guest. Secrets never travel
    /// here: they go through the secret channel.
    pub env: Vec<(String, String)>,
    /// The TCP port the guest's service listens on, when it declares one. A
    /// backend that bridges the port (#590) needs it before boot, since a vfkit
    /// vsock device must be declared at launch.
    pub service_port: Option<u16>,
}

/// Where a client reaches a Ready environment's service, from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// A host-reachable address, normally the bridge's loopback address.
    pub host: String,
    /// The port on `host`.
    pub port: u16,
}

/// What [`EnvironmentBackend::launch`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// A new box was started.
    Started,
    /// The id already has a running box; nothing was started, so a retry never
    /// makes a second VM.
    AlreadyRunning,
}

/// One health probe of an environment's box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// Booting or waiting for the service. `step` names where it is.
    Starting {
        /// The provisioning step in progress.
        step: String,
    },
    /// The probe passed; the service answers at `endpoint`.
    Ready {
        /// Where a client reaches the service.
        endpoint: Endpoint,
    },
    /// Provisioning failed; the box will not become Ready.
    Failed {
        /// The step that failed.
        step: String,
        /// Why, for example the last probe output.
        reason: String,
    },
    /// No box runs under this id: it was never launched, was killed, or died.
    NotRunning,
}

/// A long-lived sandbox: launched once, probed until Ready, killed on delete.
pub trait EnvironmentBackend {
    /// Start the box for `spec` and return once the hypervisor process runs,
    /// not once it is Ready. Launching an id that already has a box is
    /// [`Launch::AlreadyRunning`], not a second VM.
    ///
    /// # Errors
    /// [`BackendError::Spawn`] if the box cannot be started.
    fn launch(&self, spec: &EnvironmentSpec) -> Result<Launch, BackendError>;

    /// One health probe of box `environment_id`. Readiness comes from the
    /// probe, never from console text.
    ///
    /// # Errors
    /// [`BackendError::Transport`] or [`BackendError::Protocol`] if the probe
    /// itself could not run; a box that is not up is [`Probe::NotRunning`].
    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError>;

    /// Kill box `environment_id` and release everything it holds. Idempotent:
    /// killing an id with no box succeeds.
    ///
    /// # Errors
    /// [`BackendError::Transport`] if teardown faulted.
    fn kill(&self, environment_id: &str) -> Result<(), BackendError>;

    /// The environment boxes this backend launched and still runs, keyed by
    /// environment id in [`BoxState::box_id`]. It must not list boxes of other
    /// kinds (a `VmBackend` job VM): the reconciler kills any box it lists that
    /// no environment row names.
    ///
    /// The reconciler uses it to find a box with no live environment.
    ///
    /// # Errors
    /// [`BackendError::Transport`] if the backend cannot list its boxes.
    fn boxes(&self) -> Result<Vec<BoxState>, BackendError>;

    /// Whether a client uses the service of `environment_id` right now, for
    /// example through an established connection to its endpoint. The driver
    /// renews the idle-stop lease while this is true, so a client that connects
    /// straight to the service (invisible to `sandyd`) keeps its box up. The
    /// default is `false`: a backend that cannot tell leaves renewal to owner-visible
    /// calls.
    ///
    /// # Errors
    /// [`BackendError::Transport`] if the check could not run. The driver logs it and
    /// treats the box as not active.
    fn active(&self, _environment_id: &str) -> Result<bool, BackendError> {
        Ok(false)
    }
}
