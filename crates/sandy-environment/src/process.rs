//! The process-backed, trusted-only [`EnvironmentBackend`].

use std::{path::PathBuf, time::Duration};

use sandy_api::{
    backend::{BackendError, BoxState},
    environment::{EnvironmentBackend, EnvironmentSpec, Launch, Probe},
};

/// Why a [`ProcessConfig`] is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcessConfigError {
    /// No service command was given, or its program is blank.
    #[error("the service command is empty")]
    Empty,
}

/// How to run the service.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// The service argv. `{port}`, `{base_dir}` and `{environment_id}` are
    /// replaced in every element.
    pub command: Vec<String>,
    /// An optional argv run once after the service first answers; its stdout
    /// is written to `<base_dir>/pairing` (mode 0600) and never logged.
    pub pair_command: Option<Vec<String>>,
    /// Where each environment gets its own directory.
    pub state_dir: PathBuf,
    /// The `PATH` the service sees.
    pub path: String,
    /// Names of daemon environment variables passed through to the service.
    pub pass_env: Vec<String>,
    /// How long the pair command may run.
    pub pair_timeout: Duration,
}

impl ProcessConfig {
    /// Checks the config.
    ///
    /// # Errors
    /// [`ProcessConfigError::Empty`] when `command` is empty or its program is blank.
    pub fn validate(&self) -> Result<(), ProcessConfigError> {
        let _ = (
            &self.command,
            &self.pair_command,
            &self.state_dir,
            &self.path,
            &self.pass_env,
            self.pair_timeout,
        );
        unimplemented!("#587 process backend: red")
    }
}

/// Runs each environment as a host process group.
#[derive(Debug)]
pub struct ProcessEnvironmentBackend {
    config: ProcessConfig,
}

impl ProcessEnvironmentBackend {
    /// A backend over `config`. Removes stale environment directories left by
    /// an earlier daemon (and kills their process groups where it can tell
    /// they are ours).
    ///
    /// # Errors
    /// [`BackendError::Spawn`] if the config is invalid or the state dir cannot be prepared.
    pub fn new(config: ProcessConfig) -> Result<Self, BackendError> {
        let _ = config.validate();
        unimplemented!("#587 process backend: red")
    }
}

impl EnvironmentBackend for ProcessEnvironmentBackend {
    fn launch(&self, spec: &EnvironmentSpec) -> Result<Launch, BackendError> {
        let _ = (&self.config, spec);
        unimplemented!("#587 process backend: red")
    }

    fn probe(&self, environment_id: &str) -> Result<Probe, BackendError> {
        let _ = environment_id;
        unimplemented!("#587 process backend: red")
    }

    fn kill(&self, environment_id: &str) -> Result<(), BackendError> {
        let _ = environment_id;
        unimplemented!("#587 process backend: red")
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        unimplemented!("#587 process backend: red")
    }
}
