//! The provisioning seams: the HostNix router seam and the remote-build seam,
//! plus their data/error types. The routing and orchestration logic lives in the
//! core crate.

use std::fmt;

use crate::result::ResultEnvelope;

/// A minimal stand-in for Phase A's fully-desugared run request (`RunSpec`),
/// kept tiny for Phase B routing. The implementer expands or replaces this when
/// wiring the real `LauncherBackend` path; it exists so the router has a job to
/// forward unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The template (flake attr / image) to boot.
    pub template: String,
    /// The guest command and its arguments.
    pub command: Vec<String>,
}

/// The Phase A provisioning seam the router drives for a `HostNix` strategy.
///
/// The real path (`LauncherBackend` + the `vm run` CLI) is deferred, so the
/// router depends only on this trait and tests inject a fake. An implementation
/// runs `job` natively at `arch` and returns Phase A's result envelope
/// unchanged.
pub trait HostNixProvisioner {
    /// Provision and run `job` at `arch`, returning the Phase A result envelope.
    fn provision_host_nix(&self, job: &Job, arch: &str) -> ResultEnvelope;
}

/// The result of routing a provisioning strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// `HostNix` ran via Phase A's backend; carries the result envelope unchanged.
    Provisioned(ResultEnvelope),
    /// The strategy could not run at stage B; `reason` names the blocker — an
    /// axis propagated from `ProvisioningStrategy::Refuse`, or a "requires
    /// stage C/D" pointer (B-REQ-7).
    Refused {
        /// Why the run was refused.
        reason: String,
    },
}

/// The store artifacts a remote NixOS builder produced and copied back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteArtifacts {
    /// The Nix store path of the built output, now present in the local store.
    pub output_store_path: String,
}

/// A fault from the remote build path.
///
/// Both variants are infra faults (INV-7 → `retryable: true`). An arch mismatch is
/// not modelled here: the orchestration confirms the remote's arch via
/// [`RemoteBuilder::probe_arch`] *before* delegating a build and refuses directly,
/// so `build_remote` only ever reports unreachable / build faults.
///
/// Implemented by hand rather than via `thiserror`, matching the original seam's
/// hand-written error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    /// The remote builder host could not be reached (infra fault, INV-7).
    Unreachable(String),
    /// The remote build itself failed (infra fault, INV-7).
    Build(String),
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteError::Unreachable(host) => write!(f, "remote builder `{host}` is unreachable"),
            RemoteError::Build(msg) => write!(f, "remote build failed: {msg}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// A faked-remote seam over the eval-local / build-remote / copy-back path.
///
/// Two operations so the orchestration can confirm the remote's arch *before*
/// delegating a build (D-REQ-1: "confirm the remote builder's arch/reachability").
/// An arch mismatch must refuse with **no build attempted**, which a single
/// build-only method could not express — hence [`probe_arch`](RemoteBuilder::probe_arch).
/// The real seam drives `nix build --builders ssh://…` + `nix copy`; tests inject
/// a fake.
pub trait RemoteBuilder {
    /// Probe the remote builder's advertised system arch (cheap; no build).
    ///
    /// Returns [`RemoteError::Unreachable`] when the host cannot be reached.
    fn probe_arch(&self, host: &str) -> Result<String, RemoteError>;

    /// Build `derivation` on `host` for `arch` and copy the artifacts back.
    fn build_remote(&self, derivation: &str, host: &str, arch: &str) -> Result<RemoteArtifacts, RemoteError>;
}
