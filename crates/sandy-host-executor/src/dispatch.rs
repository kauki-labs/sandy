//! Receive-dispatch handling (#263, #269, #283, M2 stage 1; the
//! `SandboxKind::Vm` branch since #332): turning an orchestrator's
//! `Dispatch` into a running sandbox whose agent link forwards back over the
//! mesh.
//!
//! Built against the real `sandy-executor-proto` contract (#277), not a
//! guessed shape: [`decode_argv_manifest`] (pinned down with sandy-d1:
//! `manifest_encoding = "argv/v1"`, `manifest` a JSON array of the command
//! and its arguments), [`check_isolation_class`] (the executor-side half of
//! #269's two-sided isolation gate, decision 6/#279/#280 is the other
//! half), and [`handle_dispatch`] (the full composition: decode, re-check,
//! launch via `ProcessBackend::with_agent` or `QemuBackend::with_agent`,
//! forward the agent's link back via
//! `sandy_fabric_local::mesh_link::relay_agent_link`). `RunSpec`'s fields
//! with no `Dispatch` wire shape yet (timeout, grants, inputs/outputs) are
//! architect-ruled stage-1 constants — see [`handle_dispatch`]'s own doc for
//! the exact values and why. The run-id + link-token prefix is encoded via
//! `sandy_executor_proto::encode_remote_link_prefix`, not duplicated here
//! (#279).
//!
//! `SandboxKind::Vm` (#332) decodes a `flake/v1` manifest (a flake reference,
//! never a prebuilt topology — ground truth confirmed on #332: a topology
//! built on the submitter's own host is useless on this one) and resolves it
//! via `sandy_guest_template::resolve_flake_template` against THIS host's own
//! `host_target()` pairing, the identical logic `sandy run --flake` runs
//! locally. Refused outright (`UnsupportedBackend`) unless
//! [`crate::capability::detect_vm_capability`] freshly re-confirms this host
//! can actually run it (defense in depth, same discipline as
//! [`check_isolation_class`]'s re-probe — never trust the orchestrator's
//! placement decision, or this host's own earlier `Register`, alone).

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use sandy::admits_untrusted;
use sandy_api::{
    agent::{AgentLaunch, OnLink},
    backend::{
        BackendError, Grants, Input, Outcome, Output, RunControl, RunSpec, SandboxKind as ApiSandboxKind, SecretRef,
        SecretSource, VmBackend,
    },
    containment::{Containment, ContainmentStatus},
};
use sandy_executor_proto::{Dispatch, IsolationClass, REMOTE_LINK_TOKEN_LEN, SandboxKind as ProtoSandboxKind};
use sandy_fabric_local::mesh_link::relay_agent_link;
use sandy_guest_template::manifest::MANIFEST_ENCODING_FLAKE_V1;
use sandy_impls_local::ProcessBackend;
use sandy_impls_vm::QemuBackend;
use serde::Deserialize;

use crate::{
    input_pull::PullLimits,
    input_stage::{INPUT_PULL_TOTAL_SECS, StagedInputs, dial_data_link, stage_remote_inputs},
    output_stage::{OUTPUT_SEND_TOTAL_SECS, OutputStaging, send_staged_outputs},
};

/// The `Dispatch.manifest_encoding` tag stage 1 understands for a
/// `SandboxKind::Process` dispatch: the manifest is a JSON array of strings,
/// `argv[0]` first (the command and its arguments, nothing else).
/// Submitter-bounded capability derivation already happened
/// orchestrator-side before `Dispatch` is ever sent (decision C), so the
/// executor needs only argv — not a full `sandy_orchestrator::JobManifest`,
/// which deliberately carries no wire encoding of its own yet (confirmed
/// with sandy-d1: nothing serializes it today, so inventing one here would
/// be guessing a shape no real sender produces).
pub const MANIFEST_ENCODING_ARGV_V1: &str = "argv/v1";

/// A dispatch that cannot be honored, refused before anything runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DispatchError {
    /// This host's declared backend cannot provide the job's required
    /// isolation class. Fail-closed, never a silent downgrade onto
    /// trusted-process (#269's isolation-class gate, D5).
    #[error("required isolation class {required:?} is not satisfied by this host")]
    IsolationClassNotSatisfied {
        /// The class the dispatch required.
        required: IsolationClass,
    },
    /// `manifest_encoding` was not a tag this host understands for the
    /// dispatch's declared `backend`. Per `sandy-control-proto`'s own
    /// `SubmitRequest.manifest_encoding` precedent, empty/unrecognized means
    /// "undefined, reject" — never a silent default encoding.
    #[error("unrecognized manifest_encoding {0:?}")]
    UnrecognizedManifestEncoding(String),
    /// `manifest_encoding` was recognized, but the bytes did not decode as
    /// that encoding's expected shape (a JSON array of strings for
    /// `argv/v1`; a `sandy_guest_template::manifest::FlakeManifestV1` for
    /// `flake/v1`).
    #[error("malformed manifest: {0}")]
    MalformedManifest(String),
    /// An `argv/v1` manifest decoded but named no command at all —
    /// `argv[0]` is required; nothing can run without it.
    #[error("manifest names no command (empty argv)")]
    EmptyCommand,
    /// A `flake/v1` manifest declares a `service` (#589), but this executor cannot run one yet: running it as
    /// an ordinary job would start the declared service as the default account instead of its own non-root
    /// user. Refused rather than run wrong; removed once the guest agent supervises services.
    #[error("this executor cannot run a service manifest yet")]
    ServiceNotSupported,
    /// Resolving a `flake/v1` manifest's flake reference against this host
    /// failed — a `nix build`/`nix eval` fault, an unresolvable flake ref, or
    /// a template kind this host could not detect. Carries
    /// `sandy_guest_template::resolve_flake_template`'s own message, which
    /// already names what was checked.
    #[error("resolving the flake template: {0}")]
    FlakeResolve(String),
    /// Resolving the flake template passed [`FLAKE_RESOLVE_TIMEOUT_SECS`]
    /// without finishing — a distinct variant from [`Self::FlakeResolve`]
    /// (#332, CodeRabbit finding on PR #333) so the orchestrator-facing
    /// reason names a bounded, expected outcome ("timed out after Ns")
    /// rather than reading like a generic `nix` spawn/build failure.
    #[error("resolving the flake template timed out after {0}s")]
    FlakeResolveTimedOut(u64),
    /// `SANDY_NETWORK` asks for a guest NIC (or holds a value that is not `none`). Only `sandy run` applies the
    /// nftables boundary a NIC needs, so a dispatched VM never gets one (#602).
    #[error("SANDY_NETWORK is set to a guest NIC on this host, but a dispatched VM has no egress boundary: {0}")]
    NetworkProfileUnsupported(String),
}

/// Refuse a guest NIC for a dispatched VM (#602).
///
/// The qemu backend reads `SANDY_NETWORK` and `SANDY_TAP` from its own environment, and nothing in this dispatch path
/// applies the nftables ruleset on the tap, so a host started with them set would boot a NIC with no filter.
/// Anything but an unset or `none` profile is refused, a malformed value included.
///
/// # Errors
///
/// Returns [`DispatchError::NetworkProfileUnsupported`] for any profile other than `none`.
fn refuse_guest_nic(var: Result<String, std::env::VarError>) -> Result<(), DispatchError> {
    match sandy_api::egress::NetworkMode::from_var(var) {
        Ok(sandy_api::egress::NetworkMode::None) => Ok(()),
        Ok(mode) => Err(DispatchError::NetworkProfileUnsupported(format!("{mode:?}"))),
        Err(why) => Err(DispatchError::NetworkProfileUnsupported(why)),
    }
}

/// Whether `err`'s anyhow chain carries an [`std::io::Error`] of kind
/// [`std::io::ErrorKind::TimedOut`] — `run_with_deadline`'s own signal
/// (`sandy_guest_template::flake_wrap`) for a `nix` child killed at its
/// deadline, surfaced through `with_context` wrapping on its way back up
/// through `resolve_flake_template`.
fn is_timeout(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io_err| io_err.kind() == std::io::ErrorKind::TimedOut)
}

/// `timeout_secs`'s default AND ceiling (manifest-parity #480, `sandyd.md`
/// §19): a manifest requesting more than [`STAGE1_TIMEOUT_SECS`] is clamped
/// to it, never honored past the host's own bound; a manifest requesting
/// none gets the ceiling itself as the default (today's unchanged behavior).
fn clamp_timeout_secs(requested: Option<u32>) -> u32 {
    requested.map_or(STAGE1_TIMEOUT_SECS, |t| t.min(STAGE1_TIMEOUT_SECS))
}

/// Convert `Dispatch.inputs` into the backend's own `Input` shape (#496,
/// decision 21). A pure field copy: the orchestrator only ever forwards a
/// non-empty list to a host that declared `shares_submitter_filesystem`, so
/// `host` names a path that's valid right here.
fn to_run_inputs(inputs: &[sandy_executor_proto::Input]) -> Vec<Input> {
    inputs
        .iter()
        .map(|i| Input {
            host: PathBuf::from(&i.host),
            name: i.name.clone(),
            guest_path: i.guest_path.as_deref().map(PathBuf::from),
        })
        .collect()
}

/// Convert `Dispatch.outputs` into the backend's own `Output` shape.
fn to_run_outputs(outputs: &[sandy_executor_proto::Output]) -> Vec<Output> {
    outputs
        .iter()
        .map(|o| Output {
            name: o.name.clone(),
            dest: PathBuf::from(&o.dest),
        })
        .collect()
}

/// Convert `Dispatch.secrets` into the backend's own `SecretRef` shape. Always
/// a file source — the only shape a `SecretRef` ever crosses this wire as
/// (`SecretSource::Fd` has no wire representation, same as the CLI's own
/// `--secret NAME=@PATH` grammar).
fn to_run_secrets(secrets: &[sandy_executor_proto::SecretRef]) -> Vec<SecretRef> {
    secrets
        .iter()
        .map(|s| SecretRef {
            name: s.name.clone(),
            source: SecretSource::File(PathBuf::from(&s.host_path)),
        })
        .collect()
}

/// Set `control`'s deadline to a fresh `timeout_secs`-second budget from now.
/// `RunSpec.timeout_secs` only seeds a *newly constructed* `RunControl`
/// (`impls/local/src/process.rs`'s own doc) — every backend actually
/// enforces the budget by reading `spec.control` live, so a manifest's
/// clamped request has to reach the ALREADY-CONSTRUCTED `control`
/// `handle_dispatch`'s caller passed in, not merely `RunSpec.timeout_secs`
/// itself. Used right after decode (both branches), and again after a VM
/// dispatch's flake resolution (up to `FLAKE_RESOLVE_TIMEOUT_SECS`, longer
/// than `STAGE1_TIMEOUT_SECS`) to undo however much of the original budget
/// that resolution step ate into (CodeRabbit on #344). Delegates to
/// [`RunControl::set_deadline_if_finite`] for the check-then-set as ONE
/// locked operation: a suspended (attached) control is left alone, since
/// "unlimited while attached" already covers it, and doing the check and the
/// set as two separate calls would race a concurrent `suspend_deadline()`
/// landing in between them, silently reinstating a deadline attach just
/// lifted (CodeRabbit on #487).
fn set_deadline_from_timeout_secs(control: &RunControl, timeout_secs: u32) {
    control.set_deadline_if_finite(std::time::Instant::now() + std::time::Duration::from_secs(u64::from(timeout_secs)));
}

/// The `SANDY_HISTORY_LINES` env entry for a flake/v1 dispatch's
/// `RunSpec.env` (epic #340, phase 6): names, for whichever guest-agent code
/// wraps the job in tmux (phase 1), the scrollback/transcript line bound the
/// submitter asked for (or
/// [`sandy_guest_template::manifest::default_history_lines`] if they didn't).
///
/// `impls/vm` forwards this one entry to the guest agent (#398); no other `RunSpec.env` entry crosses.
fn history_lines_env(history_lines: u32) -> [(String, String); 1] {
    [("SANDY_HISTORY_LINES".to_owned(), history_lines.to_string())]
}

/// The env an argv/v1 run carries: the submitter's entries without `SANDY_SERVICE`. The argv manifest has no
/// service, so a submitter-set key would reach the agent's probe and port relay unvalidated (#589 review).
fn process_run_env(env: &[(String, String)]) -> Vec<(String, String)> {
    env.iter()
        .filter(|(key, _)| key != sandy_api::agent::SERVICE_ENV)
        .cloned()
        .collect()
}

/// The longest `SANDY_SERVICE` value the executor sends. The guest console takes the agent's command as one
/// line, shell-quoted and base64-encoded (about 4095 bytes in canonical mode), and quoting and encoding grow a
/// value by up to a factor of 4, so a larger spec plus the job's own argv could be cut mid-argument. A typical
/// spec is a few hundred bytes.
const MAX_SERVICE_ENV_BYTES: usize = 1024;

/// The env a flake/v1 run carries: the submitter's own entries, then the plumbing entries the executor owns.
///
/// The executor's keys (`SANDY_HISTORY_LINES`, `SANDY_SERVICE`) are removed from the submitter's entries first:
/// without that, a manifest with `service: None` could set `SANDY_SERVICE` itself and reach the agent's probe
/// with a spec `validate_service` never saw (#589 review).
///
/// # Errors
/// [`DispatchError::MalformedManifest`] if the service spec cannot be encoded or exceeds
/// [`MAX_SERVICE_ENV_BYTES`].
fn flake_run_env(
    decoded: &sandy_guest_template::manifest::FlakeManifestV1,
) -> Result<Vec<(String, String)>, DispatchError> {
    let mut env: Vec<(String, String)> = decoded
        .env
        .iter()
        .filter(|(key, _)| key != "SANDY_HISTORY_LINES" && key != sandy_api::agent::SERVICE_ENV)
        .cloned()
        .collect();
    env.extend(history_lines_env(decoded.history_lines));
    if let Some(service) = &decoded.service
        && service.restart != sandy_guest_template::manifest::RestartPolicy::Never
    {
        return Err(DispatchError::MalformedManifest(format!(
            "service restart policy {:?} is not implemented yet; refused rather than ignored",
            service.restart
        )));
    }
    let service = service_env(decoded.service.as_ref())
        .map_err(|e| DispatchError::MalformedManifest(format!("the service spec: {e}")))?;
    if let Some((_, value)) = &service
        && value.len() > MAX_SERVICE_ENV_BYTES
    {
        return Err(DispatchError::MalformedManifest(format!(
            "the service spec is {} bytes, over the {MAX_SERVICE_ENV_BYTES} byte limit",
            value.len()
        )));
    }
    env.extend(service);
    Ok(env)
}

/// The `SANDY_SERVICE` env entry for a flake/v1 dispatch that declares a service (#589): the spec as JSON for
/// the guest agent's probe loop. `None` for a plain job. `impls/vm` forwards this entry like the history bound.
///
/// # Errors
/// `serde_json`'s error if the spec cannot be serialized (it cannot in practice).
fn service_env(
    service: Option<&sandy_guest_template::manifest::ServiceSpec>,
) -> Result<Option<(String, String)>, serde_json::Error> {
    service
        .map(|spec| Ok((sandy_api::agent::SERVICE_ENV.to_owned(), serde_json::to_string(spec)?)))
        .transpose()
}

/// An `argv/v1` manifest's decoded shape (manifest-parity #480, `sandyd.md`
/// §19): a bare `["cmd", "arg", ...]` array still decodes, with every field
/// but `command` absent — the backward-compat form `scripts/cross-machine-
/// smoke.sh`, the host-executor manual smoke test, and `README.md`'s own
/// usage example all construct by hand against a real remote host-executor.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgvManifestV1Fields {
    command: Vec<String>,
    #[serde(default)]
    env: Vec<(String, String)>,
    #[serde(default)]
    cpu: Option<u32>,
    #[serde(default)]
    mem: Option<u32>,
    #[serde(default)]
    timeout_secs: Option<u32>,
}

/// The wire shape `argv/v1` accepts: the historical bare array, or the
/// object form carrying the manifest-parity fields. `untagged` tries each
/// variant in order; a JSON array only ever matches [`Self::Bare`], a JSON
/// object only ever matches [`Self::Full`] — the two shapes never collide.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
enum ArgvManifestV1Wire {
    Bare(Vec<String>),
    Full(ArgvManifestV1Fields),
}

/// An `argv/v1` manifest, normalized to one shape regardless of which wire
/// form it decoded from.
#[derive(Debug, Clone, PartialEq)]
pub struct ArgvManifest {
    /// The command and its arguments, `argv[0]` first.
    pub command: Vec<String>,
    /// Extra environment entries for the job (manifest-parity #480). Merged
    /// ahead of the plumbing env `ProcessBackend` itself sets (share dirs,
    /// the containment passthrough list), which always applies last and
    /// wins a key collision.
    pub env: Vec<(String, String)>,
    /// A request for vCPUs; `None` keeps the backend's own default.
    pub cpu: Option<u32>,
    /// A request for memory in MiB; `None` keeps the backend's own default.
    pub mem: Option<u32>,
    /// A request for the run's wall-clock budget in seconds, clamped to the
    /// host's ceiling ([`STAGE1_TIMEOUT_SECS`]). `None` keeps the host's
    /// default.
    pub timeout_secs: Option<u32>,
}

/// Decode `Dispatch.manifest` into the argv (plus manifest-parity fields)
/// this host will run, per `manifest_encoding`. The only encoding stage 1
/// understands is [`MANIFEST_ENCODING_ARGV_V1`]; anything else — including
/// an empty tag — is refused rather than guessed at.
///
/// # Errors
/// See [`DispatchError`]'s `UnrecognizedManifestEncoding`,
/// `MalformedManifest`, and `EmptyCommand` variants.
pub fn decode_argv_manifest(manifest_encoding: &str, manifest: &[u8]) -> Result<ArgvManifest, DispatchError> {
    if manifest_encoding != MANIFEST_ENCODING_ARGV_V1 {
        return Err(DispatchError::UnrecognizedManifestEncoding(
            manifest_encoding.to_owned(),
        ));
    }
    let wire: ArgvManifestV1Wire =
        serde_json::from_slice(manifest).map_err(|e| DispatchError::MalformedManifest(e.to_string()))?;
    let decoded = match wire {
        ArgvManifestV1Wire::Bare(command) => ArgvManifest {
            command,
            env: Vec::new(),
            cpu: None,
            mem: None,
            timeout_secs: None,
        },
        ArgvManifestV1Wire::Full(fields) => ArgvManifest {
            command: fields.command,
            env: fields.env,
            cpu: fields.cpu,
            mem: fields.mem,
            timeout_secs: fields.timeout_secs,
        },
    };
    if decoded.command.is_empty() {
        return Err(DispatchError::EmptyCommand);
    }
    Ok(decoded)
}

/// Decode `Dispatch.manifest` into a
/// [`sandy_guest_template::manifest::FlakeManifestV1`], per
/// `manifest_encoding`. The only encoding this branch understands is
/// [`MANIFEST_ENCODING_FLAKE_V1`]; anything else — including an empty tag —
/// is refused rather than guessed at. Unlike [`decode_argv_manifest`], an
/// empty `command` is valid here (it means "boot the template's default
/// command", the same convention `sandy run --flake` itself uses).
///
/// # Errors
/// See [`DispatchError`]'s `UnrecognizedManifestEncoding` and
/// `MalformedManifest` variants.
fn decode_flake_dispatch_manifest(
    manifest_encoding: &str,
    manifest: &[u8],
) -> Result<sandy_guest_template::manifest::FlakeManifestV1, DispatchError> {
    if manifest_encoding != MANIFEST_ENCODING_FLAKE_V1 {
        return Err(DispatchError::UnrecognizedManifestEncoding(
            manifest_encoding.to_owned(),
        ));
    }
    let decoded = sandy_guest_template::manifest::decode_flake_manifest(manifest)
        .map_err(|e| DispatchError::MalformedManifest(e.to_string()))?;
    if decoded.service.is_some() {
        return Err(DispatchError::ServiceNotSupported);
    }
    Ok(decoded)
}

/// Re-check the dispatch's required isolation class against this host's
/// actual, freshly probed containment — independent of whatever placement
/// decision the orchestrator already made. #269's spec is explicit that this
/// is defense in depth: "the executor re-checks it independently before
/// running anything ... never trust the orchestrator's placement decision
/// alone for a fail-closed security gate." Reuses
/// [`sandy::admits_untrusted`], the same gate `ProcessBackend` itself relies
/// on, rather than a second, narrower or broader copy of the same decision.
///
/// `kind` is the sandbox kind the dispatch runs on. Untrusted jobs are VM-only
/// (#150), so an untrusted job passes only with `Vm`.
///
/// # Errors
/// [`DispatchError::IsolationClassNotSatisfied`] if `required` is
/// `Untrusted` and [`admits_untrusted`] refuses `kind`, or if `required` is
/// the zero/unspecified value — an unspecified class is never treated as the
/// weaker "trusted".
pub fn check_isolation_class(
    required: IsolationClass,
    kind: ApiSandboxKind,
    containment_status: &ContainmentStatus,
) -> Result<(), DispatchError> {
    let satisfied = match required {
        IsolationClass::Trusted => true,
        IsolationClass::Untrusted => admits_untrusted(kind, containment_status),
        IsolationClass::Unspecified => false,
    };
    if satisfied {
        Ok(())
    } else {
        Err(DispatchError::IsolationClassNotSatisfied { required })
    }
}

// The run-id + link-token prefix encoding (decision 6's mesh-accept-loop
// demux) is a shared wire seam between this crate and sandyd's accept loop
// (#279) — per infra-f3's ruling, it lives in sandy-executor-proto (both
// sides already depend on it) as encode_remote_link_prefix/
// decode_remote_link_prefix, with its own round-trip test there.

/// Stage 1's fixed per-run timeout (#269, D4). With the orchestrator→host
/// `Cancel` message deferred (no mid-run teardown in M2), this default is
/// the ONLY teardown trigger a dispatched job gets: a hung job without it
/// would wedge the host indefinitely. Matches `sandy-cli`'s own local-run
/// default (not imported — that's a CLI-local constant, this is the
/// dispatch path's own; they simply agree today, by architect ruling, not
/// by sharing a constant).
pub(crate) const STAGE1_TIMEOUT_SECS: u32 = 300;

/// Budget for resolving a `flake/v1` job's guest template on THIS host
/// (#332, CodeRabbit finding on PR #333): kind-detection probes plus the
/// guest-wrapper's `nix build`/`nix eval`, all as one shared deadline (see
/// `sandy_guest_template::resolve_flake_template`'s own doc). Deliberately
/// NOT [`STAGE1_TIMEOUT_SECS`] — a cold Nix store has to fetch the flake and
/// its inputs and build the wrapper's runner derivation before the guest
/// even boots, which can legitimately take longer than one sandbox run, and
/// a successful resolve should still leave the full run timeout available to
/// the job it then boots, not a budget already partly spent resolving it.
/// Without this (the unpatched behavior this finding describes): an
/// unresponsive git remote or a stalled substituter blocks
/// `run_dispatch_loop`'s sequential processing indefinitely — no
/// `JobResult` is ever sent, so the job stays `Running` forever and every
/// later dispatch to this host (including unrelated `argv/v1` jobs) queues
/// behind it.
const FLAKE_RESOLVE_TIMEOUT_SECS: u64 = 600;

/// A full dispatch-handling failure, refused before or during the run.
#[derive(Debug, thiserror::Error)]
pub enum HandleDispatchError {
    /// The manifest didn't decode, or the isolation class isn't satisfied —
    /// refused before a [`ProcessBackend`] is ever constructed.
    #[error(transparent)]
    Dispatch(#[from] DispatchError),
    /// `Dispatch.backend` named a sandbox kind this host-executor cannot
    /// actually run: `Unspecified`/an unrecognized value always; `Vm` when
    /// [`crate::capability::detect_vm_capability`]'s fresh re-probe says this
    /// host cannot (#332 — never silently run it through `ProcessBackend`,
    /// or `QemuBackend` without a real qemu/kvm/vsock boundary, anyway).
    #[error("backend {0:?} is not supported by this host-executor")]
    UnsupportedBackend(i32),
    /// `Dispatch.link_token` was not exactly
    /// `sandy_executor_proto::REMOTE_LINK_TOKEN_LEN` bytes — refused here
    /// rather than silently truncated or zero-padded into a prefix the
    /// orchestrator's accept loop would then decode wrong.
    #[error("link_token is {0} bytes, expected {REMOTE_LINK_TOKEN_LEN}")]
    InvalidLinkTokenLength(usize),
    /// `Dispatch.forward_back` was not a parseable socket address.
    #[error("forward_back {0:?} is not a valid socket address")]
    InvalidForwardBack(String),
    /// The run id was implausibly large to prefix (see
    /// `sandy_executor_proto::encode_remote_link_prefix`).
    #[error("encoding the run-id+token prefix: {0}")]
    PrefixEncoding(#[from] sandy_executor_proto::EncodeRemoteLinkPrefixError),
    /// Launching or running the sandbox failed.
    #[error("running the sandbox: {0}")]
    Backend(#[from] BackendError),
    /// `Dispatch.data_link_token` was neither empty nor exactly `REMOTE_LINK_TOKEN_LEN` bytes.
    #[error("data_link_token is {0} bytes, expected {REMOTE_LINK_TOKEN_LEN} or none")]
    InvalidDataLinkTokenLength(usize),
    /// The inputs could not be pulled over the data link (#482). The job never booted: this is a transfer failure,
    /// a cancel or a deadline during the pull, never a guest failure.
    #[error("staging the inputs from the data link: {0}")]
    DataLink(#[from] crate::input_stage::StageError),
    /// The staging root for the job's outputs could not be created (#482). The job never ran.
    #[error("staging the outputs: {0}")]
    OutputStaging(#[source] std::io::Error),
}

impl HandleDispatchError {
    /// The `JobResult` message that reports this failure for `job_id` (#762). A deadline or the total cap passing
    /// during the input pull is a timeout; every other failure is a plain one, and a cancel keeps its own stable text
    /// (sandyd already knows it cancelled).
    #[must_use]
    pub fn result_message(&self, job_id: String) -> sandy_executor_proto::HostExecutorMessage {
        let mut message = crate::run::failure_result_message(job_id, self.to_string());
        if matches!(
            self,
            Self::DataLink(
                crate::input_stage::StageError::DeadlinePassed | crate::input_stage::StageError::TotalCapExceeded
            )
        ) && let Some(sandy_executor_proto::host_executor_message::Op::Result(result)) = &mut message.op
        {
            result.timed_out = true;
        }
        message
    }
}

/// What a dispatch produced: the physical outcome, and whether the job's outputs went back over the data link.
#[derive(Debug)]
pub struct Dispatched {
    /// The physical outcome of the run.
    pub outcome: Outcome,
    /// True when the outputs were sent over the data link (even if the send failed), so the orchestrator must wait
    /// for them before it records the job as finished (#482).
    pub outputs_follow: bool,
}

/// Plan where a remote job's outputs are collected: `None` for a local dispatch (no data link) or a job with no
/// outputs, otherwise a private staging root.
fn stage_outputs(
    declared: &[sandy_executor_proto::Output],
    staged: Option<&StagedInputs>,
) -> Result<Option<OutputStaging>, HandleDispatchError> {
    if staged.is_none() || declared.is_empty() {
        return Ok(None);
    }
    OutputStaging::new(&std::env::temp_dir(), declared)
        .map(Some)
        .map_err(HandleDispatchError::OutputStaging)
}

/// After the run: send the staged outputs over the retained data link and say whether they follow. The staging root
/// and the link go away when this returns, on every path.
fn dispatched(
    outcome: Outcome,
    staged: Option<StagedInputs>,
    staging: Option<OutputStaging>,
    rt: &tokio::runtime::Handle,
    control: &RunControl,
) -> Dispatched {
    let outputs_follow = match (staged, &staging) {
        (Some(mut staged), Some(staging)) => send_staged_outputs(
            &mut staged.link,
            staging,
            rt,
            control,
            std::time::Duration::from_secs(OUTPUT_SEND_TOTAL_SECS),
        ),
        _ => false,
    };
    Dispatched {
        outcome,
        outputs_follow,
    }
}

/// Pull the dispatch's inputs over the data link, if it has one (#482, sandyd.md decision 22). `None` when the token
/// is absent. Blocks on `rt`, so it runs on the blocking thread that runs the dispatch. The returned value owns the
/// staging root and the link: keep it alive across the run and drop it after, on every path.
fn stage_data_link_inputs(
    dispatch: &Dispatch,
    data_link_token: Option<&[u8; REMOTE_LINK_TOKEN_LEN]>,
    forward_back: SocketAddr,
    rt: &tokio::runtime::Handle,
    mesh_tls: &sandy_fabric_local::mesh_link::MeshTlsIdentity,
    control: &RunControl,
) -> Result<Option<StagedInputs>, HandleDispatchError> {
    let Some(token) = data_link_token else {
        return Ok(None);
    };
    let staged = rt.block_on(async {
        let link = dial_data_link(forward_back, &dispatch.job_id, token, mesh_tls, control).await?;
        stage_remote_inputs(
            link,
            &dispatch.inputs,
            &std::env::temp_dir(),
            control,
            std::time::Duration::from_secs(INPUT_PULL_TOTAL_SECS),
            PullLimits::default(),
        )
        .await
    })?;
    Ok(Some(staged))
}

/// Handle one [`Dispatch`]: decode its manifest, independently re-check the
/// isolation class (defense in depth, #269 — never trust the orchestrator's
/// placement decision alone), launch the sandbox (a trusted process, or
/// since #332 a flake-templated VM), and forward its agent's link back to
/// the orchestrator via [`relay_agent_link`].
///
/// Blocks the calling thread for the run's whole duration —
/// [`ProcessBackend::run`]/`QemuBackend::run`'s own contract, same as
/// [`AgentLaunch::on_link`]'s "no ambient async runtime" one. Callers run
/// this on a blocking thread (`tokio::task::spawn_blocking`), never on an
/// async task directly.
///
/// `rt` is the runtime [`relay_agent_link`]'s spawned forwarding task runs
/// on; capture it with `Handle::current()` in the async context that reads
/// `Dispatch` messages off the Register connection, before calling this
/// function.
///
/// `containment` is consumed into a constructed [`ProcessBackend`] for a
/// `SandboxKind::Process` dispatch (unused for `Vm`, whose isolation comes
/// from the hypervisor itself, not host containment); its freshly probed
/// [`Containment::status`] is also what [`check_isolation_class`] re-checks
/// `dispatch.required_isolation_class` against — one probe, not two
/// independently-timed ones that could drift.
///
/// `agent_program` is the in-process `$SANDY_AGENT_PATH` this host launches
/// for a `Process` dispatch; a `Vm` dispatch ignores it (the booted guest
/// names its OWN in-guest agent path via `Topology::agent_program`, baked in
/// by the same `mkGuest` overlay every VM boot path already uses — see
/// `impls/vm/src/qemu.rs`'s own `agent.program is not used` note).
///
/// `vm_available` is [`crate::capability::detect_vm_capability`]'s verdict,
/// probed by the CALLER immediately before this call (same freshness
/// discipline as `containment`, probed fresh per dispatch by `main.rs` too)
/// — passed in rather than probed internally so this function stays a pure,
/// deterministic unit under test: a test fixes the verdict explicitly
/// instead of depending on whatever qemu/kvm/vsock/nix the test-running host
/// happens to have.
///
/// # Errors
/// See [`HandleDispatchError`].
pub fn handle_dispatch(
    dispatch: &Dispatch,
    containment: Box<dyn Containment>,
    agent_program: PathBuf,
    rt: tokio::runtime::Handle,
    vm_available: bool,
    control: RunControl,
    mesh_tls: sandy_fabric_local::mesh_link::MeshTlsIdentity,
) -> Result<Dispatched, HandleDispatchError> {
    let status = containment.status();
    let required = IsolationClass::try_from(dispatch.required_isolation_class).unwrap_or(IsolationClass::Unspecified);
    // An unknown or unset backend is checked as `Process`, the weaker kind, so
    // an untrusted job with no usable backend is refused here, first.
    let kind = match ProtoSandboxKind::try_from(dispatch.backend) {
        Ok(ProtoSandboxKind::Vm) => ApiSandboxKind::Vm,
        _ => ApiSandboxKind::Process,
    };
    check_isolation_class(required, kind, &status)?;

    let forward_back: SocketAddr = dispatch
        .forward_back
        .parse()
        .map_err(|_| HandleDispatchError::InvalidForwardBack(dispatch.forward_back.clone()))?;
    let link_token: [u8; REMOTE_LINK_TOKEN_LEN] = dispatch
        .link_token
        .clone()
        .try_into()
        .map_err(|token: Vec<u8>| HandleDispatchError::InvalidLinkTokenLength(token.len()))?;
    let prefix = sandy_executor_proto::encode_remote_link_prefix(&dispatch.job_id, &link_token)?;
    // Empty means no data link: the inputs, if any, are local paths (decision 21). Otherwise the host pulls them over
    // the data link before the run (decision 22), and never reads `Input.host`.
    let data_link_token: Option<[u8; REMOTE_LINK_TOKEN_LEN]> = if dispatch.data_link_token.is_empty() {
        None
    } else {
        Some(
            dispatch
                .data_link_token
                .clone()
                .try_into()
                .map_err(|token: Vec<u8>| HandleDispatchError::InvalidDataLinkTokenLength(token.len()))?,
        )
    };
    // `rt` and `mesh_tls` move into `on_link` below; the data link dial needs its own.
    let data_link_rt = rt.clone();
    let data_link_tls = mesh_tls.clone();

    // A clone kept for the closure below: `control` itself is still needed
    // by reference for both `RunSpec` literals further down.
    let control_for_relay = control.clone();
    let on_link: OnLink = Arc::new(move |_box_id, host_end, report| {
        relay_agent_link(
            &rt,
            forward_back,
            host_end,
            prefix.clone(),
            report,
            control_for_relay.clone(),
            mesh_tls.clone(),
        );
    });

    // Path fields (#496, sandyd.md decision 21): the orchestrator only ever
    // forwards these non-empty when it placed this job on a host that
    // declared `shares_submitter_filesystem` — this host IS that host, so
    // the names are valid on its own filesystem. `agent` stays the one
    // always-on grant from Stage 1 (#269, D4: cross-machine communication
    // through the agent channel, not sandbox IO); `secrets` turns on
    // precisely when a secret was actually forwarded, never unconditionally.
    let path_inputs = to_run_inputs(&dispatch.inputs);
    let path_outputs = to_run_outputs(&dispatch.outputs);
    let path_secrets = to_run_secrets(&dispatch.secrets);
    let grants = Grants {
        secrets: !path_secrets.is_empty(),
        agent: true,
        shares: false,
    };

    match ProtoSandboxKind::try_from(dispatch.backend).ok() {
        Some(ProtoSandboxKind::Process) => {
            let decoded = decode_argv_manifest(&dispatch.manifest_encoding, &dispatch.manifest)?;
            let timeout_secs = clamp_timeout_secs(decoded.timeout_secs);
            set_deadline_from_timeout_secs(&control, timeout_secs);
            let staged = stage_data_link_inputs(
                dispatch,
                data_link_token.as_ref(),
                forward_back,
                &data_link_rt,
                &data_link_tls,
                &control,
            )?;
            let run_inputs: &[Input] = staged.as_ref().map_or(&path_inputs[..], |s| &s.inputs[..]);
            let staging = stage_outputs(&dispatch.outputs, staged.as_ref())?;
            let run_outputs: &[Output] = staging.as_ref().map_or(&path_outputs[..], OutputStaging::run_outputs);
            let backend = ProcessBackend::with_containment(containment).with_agent(AgentLaunch {
                program: agent_program,
                on_link,
            });
            let spec = RunSpec {
                digests: false,
                egress: None,
                template: &dispatch.job_id,
                command: &decoded.command,
                inputs: run_inputs,
                outputs: run_outputs,
                secrets: &path_secrets,
                env: &process_run_env(&decoded.env),
                cpu: decoded.cpu,
                mem: decoded.mem,
                timeout_secs,
                grants: &grants,
                // Exit comes from the agent's own report (INV-11), never an
                // outcome file; `ProcessBackend` doesn't read this field at
                // all.
                outcome_file: None,
                secret_dir: None,
                control: &control,
            };
            let outcome = backend.run(&spec)?;
            Ok(dispatched(outcome, staged, staging, &data_link_rt, &control))
        }
        // Defense in depth (#332, mirroring `check_isolation_class`'s own
        // re-probe discipline): `vm_available` is the caller's own fresh
        // re-probe, never trusting this host's earlier `Register` or the
        // orchestrator's placement decision alone. A host that lost
        // qemu/kvm/vsock access since registering (or was never redeployed
        // with VM support at all) falls through to the catch-all refusal
        // below, exactly like an unrecognized backend value.
        Some(ProtoSandboxKind::Vm) if vm_available => {
            refuse_guest_nic(std::env::var(sandy_api::egress::NETWORK_ENV))?;
            let decoded = decode_flake_dispatch_manifest(&dispatch.manifest_encoding, &dispatch.manifest)?;
            // Before flake resolution: an oversized or unencodable spec is refused at once, not after the
            // sequential dispatch loop spent up to FLAKE_RESOLVE_TIMEOUT_SECS on it (CodeRabbit on #632).
            // The manifest's own env first, the plumbing entries last so they always win a key collision
            // (see `flake_run_env`) — the same precedence `impls/local/src/process.rs` already establishes for
            // the process backend's share-dir/passthrough overlays (manifest-parity #480, `sandyd.md` §19).
            let env = flake_run_env(&decoded)?;
            let resolved = sandy_guest_template::resolve_flake_template(
                &decoded.flake,
                decoded.kind.as_deref(),
                decoded.attr.as_deref(),
                // `--from-devshell` rides the manifest (A3, #483); an executor that predates the field refuses the
                // manifest.
                decoded.from_devshell,
                // The macOS vfkit-prereq check: dead code on this host's
                // Linux build target (`cfg!(target_os = "macos")` is false
                // there), so a callback that never fires is correct, not a
                // stub standing in for missing behavior.
                || None,
                // #332, CodeRabbit finding on PR #333: bound this REMOTE
                // call — unlike `sandy run --flake`'s local, interactive,
                // unbounded path, an unresponsive git remote or a stalled
                // substituter here would otherwise wedge this host's whole
                // sequential dispatch loop with no terminal result ever
                // reaching the orchestrator.
                Some(std::time::Instant::now() + std::time::Duration::from_secs(FLAKE_RESOLVE_TIMEOUT_SECS)),
            )
            .map_err(|e| {
                if is_timeout(&e) {
                    DispatchError::FlakeResolveTimedOut(FLAKE_RESOLVE_TIMEOUT_SECS)
                } else {
                    DispatchError::FlakeResolve(e.to_string())
                }
            })?;
            // Flake resolution can take up to FLAKE_RESOLVE_TIMEOUT_SECS (600s),
            // longer than control's own budget set when the worker popped this
            // dispatch — without this, the VM's run and its agent-link relay
            // could start already past their own deadline (CodeRabbit on #344).
            let timeout_secs = clamp_timeout_secs(decoded.timeout_secs);
            set_deadline_from_timeout_secs(&control, timeout_secs);
            let (template, _kept_topology_file) = match resolved {
                sandy_guest_template::ResolvedTemplate::Direct(t) => (t, None),
                sandy_guest_template::ResolvedTemplate::Prebuilt { path, _kept } => (path, Some(_kept)),
            };

            // After flake resolution, so the pull starts when the run is about to: the sender's first frame is due
            // within `PullLimits::idle` of the dial.
            let staged = stage_data_link_inputs(
                dispatch,
                data_link_token.as_ref(),
                forward_back,
                &data_link_rt,
                &data_link_tls,
                &control,
            )?;
            let run_inputs: &[Input] = staged.as_ref().map_or(&path_inputs[..], |s| &s.inputs[..]);
            let staging = stage_outputs(&dispatch.outputs, staged.as_ref())?;
            let run_outputs: &[Output] = staging.as_ref().map_or(&path_outputs[..], OutputStaging::run_outputs);
            let backend = QemuBackend::new().with_agent(AgentLaunch {
                program: agent_program,
                on_link,
            });
            let spec = RunSpec {
                digests: false,
                egress: None,
                template: &template,
                command: &decoded.command,
                inputs: run_inputs,
                outputs: run_outputs,
                secrets: &path_secrets,
                env: &env,
                cpu: decoded.cpu,
                mem: decoded.mem,
                timeout_secs,
                grants: &grants,
                outcome_file: None,
                secret_dir: None,
                control: &control,
            };
            // `_kept_topology_file` (the temp JSON file, for a Prebuilt
            // template) must outlive `backend.run`'s own read of `template`
            // — held in scope here, across the call, not dropped before it.
            let outcome = backend.run(&spec)?;
            drop(_kept_topology_file);
            Ok(dispatched(outcome, staged, staging, &data_link_rt, &control))
        }
        _ => Err(HandleDispatchError::UnsupportedBackend(dispatch.backend)),
    }
}

#[cfg(test)]
mod tests {

    /// The `JobResult` a failed dispatch reports, as the orchestrator will read it.
    fn reported(error: &HandleDispatchError) -> anyhow::Result<sandy_executor_proto::JobResult> {
        match error.result_message("job-1".to_owned()).op {
            Some(sandy_executor_proto::host_executor_message::Op::Result(result)) => Ok(result),
            other => anyhow::bail!("expected a JobResult, got {other:?}"),
        }
    }

    /// A deadline that passes during the input pull is a timeout, not a plain failure (#762).
    #[test]
    fn a_deadline_during_the_input_pull_is_reported_as_timed_out() -> anyhow::Result<()> {
        use crate::input_stage::StageError;
        for stage in [StageError::DeadlinePassed, StageError::TotalCapExceeded] {
            let result = reported(&HandleDispatchError::DataLink(stage))?;
            assert!(result.timed_out, "the job timed out during its input pull");
            assert!(!result.booted, "it never booted");
            assert!(result.transport_error.is_some(), "the reason is kept");
            assert!(!result.outputs_follow);
        }
        Ok(())
    }

    /// A cancel during the pull keeps a stable text and is not a timeout: sandyd already knows it cancelled, and a
    /// transfer failure must read differently (#762).
    #[test]
    fn a_cancel_during_the_input_pull_is_a_stable_non_timeout_failure() -> anyhow::Result<()> {
        use crate::input_stage::StageError;
        let cancelled = reported(&HandleDispatchError::DataLink(StageError::Cancelled))?;
        assert!(!cancelled.timed_out);
        assert!(!cancelled.booted);
        assert_eq!(
            cancelled.transport_error.as_deref(),
            Some("staging the inputs from the data link: the job was cancelled while its inputs were being pulled")
        );
        let failed = reported(&HandleDispatchError::DataLink(StageError::Dial("x".to_owned())))?;
        assert!(!failed.timed_out);
        assert_ne!(failed.transport_error, cancelled.transport_error);
        Ok(())
    }
    use anyhow::Context;

    use super::*;

    fn available(isolates_untrusted: bool) -> ContainmentStatus {
        ContainmentStatus::Available { isolates_untrusted }
    }

    /// A throwaway mesh TLS config for `handle_dispatch` tests that never
    /// actually reach `relay_agent_link`'s dial (every test here fails before
    /// `on_link` is ever invoked) — a fresh, unpersisted identity is fine.
    fn test_mesh_tls_config() -> sandy_fabric_local::mesh_link::MeshTlsIdentity {
        sandy_fabric_local::mesh_link::MeshTlsIdentity {
            identity: Arc::new(sandy_conn::TlsIdentity::generate().expect("generate a throwaway test identity")),
            orchestrator_fingerprint: sandy_conn::TlsIdentity::generate()
                .expect("generate a throwaway test identity")
                .fingerprint(),
        }
    }

    /// Regression (#332, CodeRabbit finding on PR #333): a timed-out `nix`
    /// call (`run_with_deadline`'s `ErrorKind::TimedOut`, wrapped by
    /// `resolve_flake_template`'s own `with_context` chain) must map to the
    /// distinct `FlakeResolveTimedOut` reason, not the generic
    /// `FlakeResolve(String)` — the orchestrator-facing message should read
    /// "timed out after Ns", not look like an ordinary build failure.
    #[test]
    fn is_timeout_recognizes_a_wrapped_timed_out_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "nix timed out and was killed");
        let wrapped = anyhow::Error::new(io_err).context("spawn `nix build ...`");
        assert!(is_timeout(&wrapped));
    }

    /// Adversarial: an ordinary build failure (not a timeout) must NOT be
    /// misreported as one.
    #[test]
    fn is_timeout_is_false_for_an_unrelated_failure() {
        let err = anyhow::anyhow!("could not build the --flake guest: some other nix error");
        assert!(!is_timeout(&err));

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "nix: command not found");
        let wrapped = anyhow::Error::new(io_err).context("spawn `nix build ...`");
        assert!(!is_timeout(&wrapped));
    }

    /// Regression (CodeRabbit on #344): a finite deadline already eaten into
    /// by slow flake resolution must be realigned forward, not left expired
    /// before the VM run (and its agent-link relay) has even started.
    #[test]
    fn set_deadline_from_timeout_secs_bumps_an_already_passed_finite_deadline_forward() {
        let control =
            sandy_api::backend::RunControl::new(std::time::Instant::now() - std::time::Duration::from_secs(1));
        assert!(
            control.timed_out(),
            "the deadline must already be in the past for this test to be meaningful"
        );

        set_deadline_from_timeout_secs(&control, STAGE1_TIMEOUT_SECS);

        assert!(
            !control.timed_out(),
            "the deadline must be realigned to the future, not left in the past"
        );
    }

    /// Regression (CodeRabbit on #344): an attached (suspended) job's
    /// deadline must stay suspended — a fresh timeout is not a reason to
    /// reinstate a bound "unlimited while attached" already lifted.
    #[test]
    fn set_deadline_from_timeout_secs_leaves_a_suspended_control_alone() {
        let control = sandy_api::backend::RunControl::with_timeout_secs(60);
        control.suspend_deadline();
        assert_eq!(control.deadline(), None);

        set_deadline_from_timeout_secs(&control, STAGE1_TIMEOUT_SECS);

        assert_eq!(
            control.deadline(),
            None,
            "a suspended control must stay suspended, not be given a new finite deadline"
        );
    }

    #[test]
    fn clamp_timeout_secs_keeps_a_request_under_the_ceiling() {
        assert_eq!(clamp_timeout_secs(Some(60)), 60);
    }

    #[test]
    fn clamp_timeout_secs_clamps_a_request_over_the_ceiling() {
        assert_eq!(clamp_timeout_secs(Some(STAGE1_TIMEOUT_SECS + 1)), STAGE1_TIMEOUT_SECS);
    }

    #[test]
    fn clamp_timeout_secs_defaults_to_the_ceiling_when_unrequested() {
        assert_eq!(clamp_timeout_secs(None), STAGE1_TIMEOUT_SECS);
    }

    /// #589 review: until the agent runs the service (its own non-root user, its probe), an executor must not
    /// run a `service` manifest as an ordinary job: that would run the declared service as the default
    /// account, failing open on the non-root promise.
    #[test]
    fn a_service_manifest_is_refused_until_the_runtime_supports_it() -> Result<(), serde_json::Error> {
        use sandy_guest_template::manifest::{
            HealthProbe, MANIFEST_ENCODING_FLAKE_V1, ProbeCheck, RestartPolicy, ServiceSpec, encode_flake_manifest,
        };

        let manifest = |service| sandy_guest_template::manifest::FlakeManifestV1 {
            flake: ".".to_owned(),
            kind: None,
            attr: None,
            command: vec!["service".to_owned(), "serve".to_owned()],
            history_lines: 5_000,
            env: Vec::new(),
            cpu: None,
            mem: None,
            timeout_secs: None,
            from_devshell: false,
            service,
        };
        let spec = ServiceSpec {
            user: "dev".to_owned(),
            probe: HealthProbe {
                check: ProbeCheck::Tcp { port: 3773 },
                interval_secs: 2,
                timeout_secs: 1,
                max_attempts: 30,
            },
            restart: RestartPolicy::Never,
            port: None,
        };
        let with = encode_flake_manifest(&manifest(Some(spec)))?;
        let err = decode_flake_dispatch_manifest(MANIFEST_ENCODING_FLAKE_V1, &with).expect_err("must be refused");
        assert!(matches!(err, DispatchError::ServiceNotSupported), "{err:?}");
        let without = encode_flake_manifest(&manifest(None))?;
        decode_flake_dispatch_manifest(MANIFEST_ENCODING_FLAKE_V1, &without).expect("a plain job still decodes");
        Ok(())
    }

    #[test]
    fn history_lines_env_carries_the_submitter_requested_bound() {
        assert_eq!(
            history_lines_env(5_000),
            [("SANDY_HISTORY_LINES".to_owned(), "5000".to_owned())]
        );
    }

    /// #589: a service manifest reaches the guest agent as one JSON env entry; a plain job adds none.
    #[test]
    fn service_env_carries_the_spec_and_is_absent_for_a_plain_job() -> Result<(), serde_json::Error> {
        use sandy_guest_template::manifest::{HealthProbe, ProbeCheck, RestartPolicy, ServiceSpec};

        assert_eq!(service_env(None)?, None);
        let spec = ServiceSpec {
            user: "dev".to_owned(),
            probe: HealthProbe {
                check: ProbeCheck::Tcp { port: 3773 },
                interval_secs: 2,
                timeout_secs: 1,
                max_attempts: 30,
            },
            restart: RestartPolicy::Never,
            port: Some(3773),
        };
        let (key, value) = service_env(Some(&spec))?.expect("a service sets the env entry");
        assert_eq!(key, sandy_api::agent::SERVICE_ENV);
        assert_eq!(serde_json::from_str::<ServiceSpec>(&value)?, spec);
        Ok(())
    }

    fn flake_manifest(
        env: Vec<(String, String)>,
        service: Option<sandy_guest_template::manifest::ServiceSpec>,
    ) -> sandy_guest_template::manifest::FlakeManifestV1 {
        sandy_guest_template::manifest::FlakeManifestV1 {
            flake: ".".to_owned(),
            kind: None,
            attr: None,
            command: vec!["service".to_owned(), "serve".to_owned()],
            history_lines: 5_000,
            env,
            cpu: None,
            mem: None,
            timeout_secs: None,
            from_devshell: false,
            service,
        }
    }

    fn example_spec() -> sandy_guest_template::manifest::ServiceSpec {
        use sandy_guest_template::manifest::{HealthProbe, ProbeCheck, RestartPolicy, ServiceSpec};
        ServiceSpec {
            user: "dev".to_owned(),
            probe: HealthProbe {
                check: ProbeCheck::Tcp { port: 3773 },
                interval_secs: 2,
                timeout_secs: 1,
                max_attempts: 30,
            },
            restart: RestartPolicy::Never,
            port: None,
        }
    }

    /// #589 review: a submitter's own `SANDY_SERVICE` (or history bound) never reaches the agent. A plain job
    /// gets no service entry at all, and a service job gets only the executor's.
    #[test]
    fn a_submitter_cannot_set_the_executors_plumbing_env() -> Result<(), DispatchError> {
        let forged = r#"{"user":"x","probe":{"check":{"type":"tcp","port":1},"interval_secs":0}}"#;
        let env = vec![
            ("KEEP".to_owned(), "yes".to_owned()),
            ("SANDY_SERVICE".to_owned(), forged.to_owned()),
            ("SANDY_HISTORY_LINES".to_owned(), "1".to_owned()),
        ];

        let plain = flake_run_env(&flake_manifest(env.clone(), None))?;
        assert_eq!(
            plain,
            [
                ("KEEP".to_owned(), "yes".to_owned()),
                ("SANDY_HISTORY_LINES".to_owned(), "5000".to_owned())
            ],
            "a plain job carries no SANDY_SERVICE and the executor's history bound"
        );

        let service = flake_run_env(&flake_manifest(env, Some(example_spec())))?;
        let services: Vec<_> = service.iter().filter(|(key, _)| key == "SANDY_SERVICE").collect();
        assert_eq!(services.len(), 1, "exactly the executor's entry: {service:?}");
        assert_ne!(services[0].1, forged);
        Ok(())
    }

    /// A restart policy the agent cannot honour is refused at dispatch, not accepted and ignored.
    #[test]
    fn a_restart_policy_is_refused_until_it_is_implemented() {
        for policy in [
            sandy_guest_template::manifest::RestartPolicy::OnFailure,
            sandy_guest_template::manifest::RestartPolicy::Always,
        ] {
            let mut spec = example_spec();
            spec.restart = policy;
            let err = flake_run_env(&flake_manifest(Vec::new(), Some(spec))).expect_err("must be refused");
            assert!(
                matches!(err, DispatchError::MalformedManifest(ref m) if m.contains("restart")),
                "{err:?}"
            );
        }
        assert!(flake_run_env(&flake_manifest(Vec::new(), Some(example_spec()))).is_ok());
    }

    /// A spec too large for one console line is refused, not sent to be cut mid-argument.
    #[test]
    fn an_oversized_service_spec_is_refused() {
        let mut spec = example_spec();
        spec.probe.check = sandy_guest_template::manifest::ProbeCheck::Command {
            argv: vec!["x".repeat(MAX_SERVICE_ENV_BYTES)],
        };
        let err = flake_run_env(&flake_manifest(Vec::new(), Some(spec))).expect_err("must be refused");
        assert!(
            matches!(err, DispatchError::MalformedManifest(ref m) if m.contains("byte limit")),
            "{err:?}"
        );
    }

    #[test]
    fn an_argv_run_drops_a_submitter_set_service_env_and_keeps_the_rest() {
        let env = vec![
            ("FOO".to_owned(), "bar".to_owned()),
            (sandy_api::agent::SERVICE_ENV.to_owned(), "{}".to_owned()),
        ];
        assert_eq!(process_run_env(&env), [("FOO".to_owned(), "bar".to_owned())]);
    }

    #[test]
    fn history_lines_env_carries_the_default_when_unset() {
        assert_eq!(
            history_lines_env(sandy_guest_template::manifest::default_history_lines()),
            [("SANDY_HISTORY_LINES".to_owned(), "10000".to_owned())]
        );
    }

    #[test]
    fn a_trusted_requirement_is_always_satisfied() {
        assert_eq!(
            check_isolation_class(IsolationClass::Trusted, ApiSandboxKind::Process, &available(false)),
            Ok(())
        );
        assert_eq!(
            check_isolation_class(
                IsolationClass::Trusted,
                ApiSandboxKind::Process,
                &ContainmentStatus::Unavailable("no systemd".to_owned())
            ),
            Ok(())
        );
    }

    #[test]
    fn to_run_inputs_copies_every_field_including_guest_path() {
        let converted = to_run_inputs(&[
            sandy_executor_proto::Input {
                host: "/submitter/data".to_owned(),
                name: "in0".to_owned(),
                guest_path: Some("/workspace".to_owned()),
            },
            sandy_executor_proto::Input {
                host: "/submitter/plain".to_owned(),
                name: "plain".to_owned(),
                guest_path: None,
            },
        ]);
        assert_eq!(converted[0].host, PathBuf::from("/submitter/data"));
        assert_eq!(converted[0].name, "in0");
        assert_eq!(converted[0].guest_path, Some(PathBuf::from("/workspace")));
        assert_eq!(converted[1].guest_path, None);
    }

    #[test]
    fn to_run_outputs_copies_name_and_dest() {
        let converted = to_run_outputs(&[
            sandy_executor_proto::Output {
                name: Some("out0".to_owned()),
                dest: "/submitter/dest".to_owned(),
            },
            sandy_executor_proto::Output {
                name: None,
                dest: "/submitter/catchall".to_owned(),
            },
        ]);
        assert_eq!(converted[0].name, Some("out0".to_owned()));
        assert_eq!(converted[0].dest, PathBuf::from("/submitter/dest"));
        assert_eq!(converted[1].name, None);
    }

    #[test]
    fn to_run_secrets_always_produces_a_file_source() {
        let converted = to_run_secrets(&[sandy_executor_proto::SecretRef {
            name: "token".to_owned(),
            host_path: "/submitter/secret.txt".to_owned(),
        }]);
        assert_eq!(converted[0].name, "token");
        match &converted[0].source {
            sandy_api::backend::SecretSource::File(path) => assert_eq!(path, &PathBuf::from("/submitter/secret.txt")),
            other => panic!("expected a File source, got {other:?}"),
        }
    }

    /// The hard case: stage-1's bwrap backend (reaping only, no bus/mount
    /// isolation) must REFUSE an untrusted job, never silently accept it as
    /// if it were trusted-process-shaped.
    #[test]
    fn an_untrusted_requirement_is_refused_by_a_reaping_only_host() {
        let err = check_isolation_class(IsolationClass::Untrusted, ApiSandboxKind::Process, &available(false))
            .expect_err("a plain reaper must not admit an untrusted job");
        assert_eq!(
            err,
            DispatchError::IsolationClassNotSatisfied {
                required: IsolationClass::Untrusted
            }
        );
    }

    /// Untrusted is VM-only (process-containment.md §6, #150): an isolating
    /// process containment still refuses an untrusted job.
    #[test]
    fn an_untrusted_requirement_is_refused_even_by_an_isolating_process_host() {
        assert_eq!(
            check_isolation_class(IsolationClass::Untrusted, ApiSandboxKind::Process, &available(true)),
            Err(DispatchError::IsolationClassNotSatisfied {
                required: IsolationClass::Untrusted
            })
        );
    }

    #[test]
    fn an_unspecified_requirement_is_refused_not_treated_as_trusted() {
        let err = check_isolation_class(IsolationClass::Unspecified, ApiSandboxKind::Process, &available(true))
            .expect_err("an unspecified isolation class must never default to the weaker trusted path");
        assert_eq!(
            err,
            DispatchError::IsolationClassNotSatisfied {
                required: IsolationClass::Unspecified
            }
        );
    }

    /// The historical bare-array shape (`scripts/cross-machine-smoke.sh`,
    /// `docs/design/host-executor/spec.md`'s manual smoke test, and
    /// `README.md`'s own usage example all construct this by hand) must keep
    /// decoding unchanged, with every manifest-parity field absent.
    #[test]
    fn a_bare_array_manifest_decodes_to_its_command_with_no_parity_fields() -> anyhow::Result<()> {
        let manifest = serde_json::to_vec(&["echo", "hello"])?;
        let decoded = decode_argv_manifest(MANIFEST_ENCODING_ARGV_V1, &manifest)?;
        assert_eq!(decoded.command, vec!["echo".to_string(), "hello".to_string()]);
        assert_eq!(decoded.env, Vec::<(String, String)>::new());
        assert_eq!(decoded.cpu, None);
        assert_eq!(decoded.mem, None);
        assert_eq!(decoded.timeout_secs, None);
        Ok(())
    }

    /// The object shape (manifest-parity #480) decodes every field.
    #[test]
    fn an_object_manifest_decodes_its_parity_fields() -> anyhow::Result<()> {
        let manifest = serde_json::json!({
            "command": ["echo", "hello"],
            "env": [["FOO", "bar"]],
            "cpu": 4,
            "mem": 2048,
            "timeout_secs": 120,
        });
        let decoded = decode_argv_manifest(MANIFEST_ENCODING_ARGV_V1, &serde_json::to_vec(&manifest)?)?;
        assert_eq!(decoded.command, vec!["echo".to_string(), "hello".to_string()]);
        assert_eq!(decoded.env, vec![("FOO".to_string(), "bar".to_string())]);
        assert_eq!(decoded.cpu, Some(4));
        assert_eq!(decoded.mem, Some(2048));
        assert_eq!(decoded.timeout_secs, Some(120));
        Ok(())
    }

    /// Object-shape fields besides `command` are each optional, same
    /// forward-compat contract `flake/v1`'s own `history_lines` established.
    #[test]
    fn an_object_manifest_with_only_command_defaults_the_rest() -> anyhow::Result<()> {
        let manifest = serde_json::json!({ "command": ["echo"] });
        let decoded = decode_argv_manifest(MANIFEST_ENCODING_ARGV_V1, &serde_json::to_vec(&manifest)?)?;
        assert_eq!(decoded.env, Vec::<(String, String)>::new());
        assert_eq!(decoded.cpu, None);
        assert_eq!(decoded.mem, None);
        assert_eq!(decoded.timeout_secs, None);
        Ok(())
    }

    /// An unrecognized field is refused, not silently dropped (manifest-parity
    /// spec #459 item 1).
    #[test]
    fn an_object_manifest_with_an_unknown_field_is_refused() -> anyhow::Result<()> {
        let manifest = serde_json::json!({ "command": ["echo"], "bogus": 1 });
        let err = decode_argv_manifest(MANIFEST_ENCODING_ARGV_V1, &serde_json::to_vec(&manifest)?)
            .expect_err("an unknown field must be refused, not dropped");
        assert!(matches!(err, DispatchError::MalformedManifest(_)));
        Ok(())
    }

    #[test]
    fn an_unrecognized_encoding_is_refused_not_guessed_at() -> anyhow::Result<()> {
        let manifest = serde_json::to_vec(&["echo"])?;
        let err = decode_argv_manifest("", &manifest).expect_err("empty encoding must be refused");
        assert_eq!(err, DispatchError::UnrecognizedManifestEncoding(String::new()));

        let err = decode_argv_manifest("shell/v1", &manifest)
            .expect_err("an encoding this host doesn't understand must be refused");
        assert_eq!(err, DispatchError::UnrecognizedManifestEncoding("shell/v1".to_string()));
        Ok(())
    }

    #[test]
    fn malformed_json_is_refused() {
        let err = decode_argv_manifest(MANIFEST_ENCODING_ARGV_V1, b"not json")
            .expect_err("malformed manifest bytes must be refused, not panic");
        assert!(matches!(err, DispatchError::MalformedManifest(_)));
    }

    #[test]
    fn an_empty_argv_is_refused() -> anyhow::Result<()> {
        let manifest = serde_json::to_vec(&Vec::<String>::new())?;
        let err = decode_argv_manifest(MANIFEST_ENCODING_ARGV_V1, &manifest).expect_err("empty argv names no command");
        assert_eq!(err, DispatchError::EmptyCommand);
        Ok(())
    }

    /// The acceptance requirement #283/#269 call out explicitly: a job
    /// declaring an isolation class this host's trusted-process backend
    /// can't satisfy is refused before any `ProcessBackend` is constructed
    /// or launched — fail-closed, asserting the bad behavior, not just the
    /// happy path. The manifest here is deliberately malformed (not valid
    /// JSON): if the isolation check ran anywhere but first, this test
    /// would see `MalformedManifest` instead, proving the ordering, not
    /// just asserting a single error variant in isolation.
    #[tokio::test]
    async fn handle_dispatch_refuses_an_untrusted_job_before_touching_the_backend() {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: b"not valid json".to_vec(),
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Process.into(),
            link_token: vec![0u8; 32],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Untrusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        // A plain reaper (no bus/mount isolation): the exact host state this
        // gate exists to refuse an untrusted job on.
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            false,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("an untrusted job on a reaping-only host must be refused, never run");
        assert!(
            matches!(
                err,
                HandleDispatchError::Dispatch(DispatchError::IsolationClassNotSatisfied {
                    required: IsolationClass::Untrusted
                })
            ),
            "expected IsolationClassNotSatisfied, got {err:?} — if this is a manifest error instead, the isolation \
             check ran after the manifest decode, not before it"
        );
    }

    /// Adversarial: a `Dispatch` naming `Vm` on a host whose fresh capability
    /// re-probe says it cannot actually run one (`vm_available: false`,
    /// injected here rather than probed for real so this test is
    /// deterministic regardless of the test-running host's own qemu/kvm —
    /// see `handle_dispatch`'s own doc) must be refused, never silently run
    /// through `QemuBackend` anyway (CodeRabbit finding on #284, extended by
    /// #332: the field was decoded but never checked).
    #[tokio::test]
    async fn handle_dispatch_refuses_a_vm_backend_this_host_cannot_run() -> anyhow::Result<()> {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["echo"]).context("encoding the static test manifest")?,
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Vm.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            false,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("a Vm dispatch must be refused when this host cannot actually run one");
        assert!(
            matches!(err, HandleDispatchError::UnsupportedBackend(backend)
                if backend == i32::from(sandy_executor_proto::SandboxKind::Vm)),
            "expected UnsupportedBackend, got {err:?}"
        );
        Ok(())
    }

    /// A `Process` dispatch whose manifest names a command that cannot start, so a run that is wrongly reached fails
    /// at spawn at once and touches nothing. `data_token` is the dispatch's data link token.
    fn process_dispatch_with_data_token(data_token: Vec<u8>, forward_back: &str) -> anyhow::Result<Dispatch> {
        Ok(Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["/nonexistent/sandy-test-command"]).context("encoding the test manifest")?,
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Process.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: forward_back.to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: vec![sandy_executor_proto::Input {
                host: "/submitter/path".to_string(),
                name: "data".to_string(),
                guest_path: None,
            }],
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: data_token,
            egress: None,
        })
    }

    /// `handle_dispatch` blocks (it is called from `spawn_blocking` in production), so a test that reaches the data
    /// link's `block_on` must run it on a blocking thread too.
    async fn run_blocking(dispatch: Dispatch) -> anyhow::Result<Result<Dispatched, HandleDispatchError>> {
        let rt = tokio::runtime::Handle::current();
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        tokio::task::spawn_blocking(move || {
            handle_dispatch(
                &dispatch,
                containment,
                PathBuf::from("/nonexistent/sandy-agent"),
                rt,
                false,
                sandy_api::backend::RunControl::with_timeout_secs(60),
                test_mesh_tls_config(),
            )
        })
        .await
        .context("the blocking dispatch task")
    }

    /// A data link token that is not 32 bytes is refused up front, like a bad agent link token.
    #[tokio::test]
    async fn handle_dispatch_refuses_a_data_link_token_of_the_wrong_length() -> anyhow::Result<()> {
        let dispatch = process_dispatch_with_data_token(vec![7u8; 5], "127.0.0.1:9000")?;
        let err = run_blocking(dispatch)
            .await?
            .expect_err("a short data link token must be refused");
        assert!(
            matches!(err, HandleDispatchError::InvalidDataLinkTokenLength(5)),
            "expected InvalidDataLinkTokenLength(5), got {err:?}"
        );
        Ok(())
    }

    /// A non-empty data link token makes the host dial the data link BEFORE it runs anything: with nothing
    /// listening, the dispatch fails as a data link error, not as a sandbox failure. The job never boots.
    #[tokio::test]
    async fn handle_dispatch_dials_the_data_link_before_it_runs() -> anyhow::Result<()> {
        // A port that was just free and is now closed, so the dial is refused at once.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").context("bind")?;
        let addr = closed.local_addr().context("local_addr")?;
        drop(closed);

        let dispatch = process_dispatch_with_data_token(vec![7u8; REMOTE_LINK_TOKEN_LEN], &addr.to_string())?;
        let err = run_blocking(dispatch).await?.expect_err("the dial must fail");
        assert!(
            matches!(
                err,
                HandleDispatchError::DataLink(crate::input_stage::StageError::Dial(_))
            ),
            "expected a data link dial error, got {err:?}"
        );
        Ok(())
    }

    fn an_outcome() -> Outcome {
        Outcome {
            digests: None,
            booted: true,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: String::new(),
        }
    }

    /// `dispatched` is the one place the flag is decided: outputs follow exactly when the job has a data link AND
    /// staged outputs. A job with a link but no outputs, and a local job, send nothing and say nothing follows.
    #[tokio::test]
    async fn dispatched_says_outputs_follow_only_for_a_link_with_staged_outputs() -> anyhow::Result<()> {
        use tokio::io::AsyncReadExt as _;

        let rt = tokio::runtime::Handle::current();
        let control = sandy_api::backend::RunControl::with_timeout_secs(60);
        let declared = [sandy_executor_proto::Output {
            name: None,
            dest: "/submitter/all".to_owned(),
        }];

        // A local job: no link, no staging.
        let local = {
            let (rt, control) = (rt.clone(), control.clone());
            tokio::task::spawn_blocking(move || dispatched(an_outcome(), None, None, &rt, &control)).await?
        };
        assert!(!local.outputs_follow, "a local job has nothing following");

        // A link and no declared outputs: the link is dropped unused, nothing is written to it.
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let staged = StagedInputs::for_test(near).context("staged inputs")?;
        let linked = {
            let (rt, control) = (rt.clone(), control.clone());
            tokio::task::spawn_blocking(move || dispatched(an_outcome(), Some(staged), None, &rt, &control)).await?
        };
        assert!(!linked.outputs_follow, "no outputs declared: nothing follows");
        let mut rest = Vec::new();
        far.read_to_end(&mut rest).await.context("read the link")?;
        assert!(rest.is_empty(), "nothing may be written to a link with no outputs");

        // A link and staged outputs: they are sent, the flag is set, and the link ends after them.
        let parent = tempfile::tempdir().context("parent")?;
        let staging = OutputStaging::new(parent.path(), &declared).context("stage")?;
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let staged = StagedInputs::for_test(near).context("staged inputs")?;
        let sent = {
            let (rt, control) = (rt.clone(), control.clone());
            tokio::task::spawn_blocking(move || dispatched(an_outcome(), Some(staged), Some(staging), &rt, &control))
                .await?
        };
        assert!(sent.outputs_follow, "staged outputs over a link follow");
        let mut frames = Vec::new();
        far.read_to_end(&mut frames).await.context("read the link")?;
        assert!(!frames.is_empty(), "the transfer must at least end with OutputEnd");
        Ok(())
    }

    /// An empty data link token means no dial and today's behaviour: the dispatch goes straight to the run.
    #[tokio::test]
    async fn handle_dispatch_without_a_data_link_token_runs_as_before() -> anyhow::Result<()> {
        let dispatch = process_dispatch_with_data_token(Vec::new(), "127.0.0.1:9000")?;
        let err = run_blocking(dispatch)
            .await?
            .expect_err("the nonexistent command cannot run");
        assert!(
            matches!(err, HandleDispatchError::Backend(_)),
            "expected a backend error, got {err:?}"
        );
        Ok(())
    }

    /// Adversarial (#332): an unrecognized/unspecified `backend` value is
    /// refused the same way, regardless of `vm_available` — the catch-all
    /// never silently defaults to either real backend.
    #[tokio::test]
    async fn handle_dispatch_refuses_an_unspecified_backend_even_when_vm_capable() -> anyhow::Result<()> {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["echo"]).context("encoding the static test manifest")?,
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Unspecified.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            true,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("an unspecified backend must never be silently accepted");
        assert!(
            matches!(err, HandleDispatchError::UnsupportedBackend(backend)
                if backend == i32::from(sandy_executor_proto::SandboxKind::Unspecified)),
            "expected UnsupportedBackend, got {err:?}"
        );
        Ok(())
    }

    /// Positive (#332): a `Vm` dispatch on a capable host (`vm_available:
    /// true`, injected) reaches the flake-manifest decode — proven without a
    /// real `nix` invocation by giving it a manifest_encoding the flake
    /// branch does not understand, which fails fast at decode, before any
    /// `resolve_flake_template` call. This is the unit-level proof that the
    /// `Vm` arm is actually reachable and decodes with
    /// [`MANIFEST_ENCODING_FLAKE_V1`], not that a real flake resolves (the
    /// `live_remote_host_*` tests own that).
    #[tokio::test]
    async fn handle_dispatch_reaches_the_vm_branch_and_decodes_flake_v1() -> anyhow::Result<()> {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: b"irrelevant".to_vec(),
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(), // not flake/v1
            backend: sandy_executor_proto::SandboxKind::Vm.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            true,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("a non-flake/v1 encoding on the Vm branch must be refused, never guessed at");
        assert!(
            matches!(
                &err,
                HandleDispatchError::Dispatch(DispatchError::UnrecognizedManifestEncoding(encoding))
                    if encoding == MANIFEST_ENCODING_ARGV_V1
            ),
            "expected UnrecognizedManifestEncoding, got {err:?} — if this is UnsupportedBackend instead, the Vm \
             branch was never reached"
        );
        Ok(())
    }

    /// A `flake/v1` manifest that asks for `--from-devshell` reaches `resolve_flake_template` with the flag set (A3,
    /// #483): combined with a `kind` the resolver refuses it before any `nix` call, which a dropped flag would not.
    #[tokio::test]
    async fn a_from_devshell_manifest_reaches_the_resolver_with_the_flag() -> anyhow::Result<()> {
        let manifest =
            sandy_guest_template::manifest::encode_flake_manifest(&sandy_guest_template::manifest::FlakeManifestV1 {
                flake: ".".to_owned(),
                kind: Some("topology".to_owned()),
                attr: None,
                command: Vec::new(),
                history_lines: 5_000,
                env: Vec::new(),
                cpu: None,
                mem: None,
                timeout_secs: None,
                from_devshell: true,
                service: None,
            })?;
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest,
            manifest_encoding: MANIFEST_ENCODING_FLAKE_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Vm.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();
        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            true,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("--from-devshell with --kind is refused by the resolver");
        assert!(
            err.to_string()
                .contains("--from-devshell cannot be combined with --kind"),
            "the flag must reach the resolver: {err}"
        );
        Ok(())
    }

    /// Untrusted is VM-only (#150): an untrusted `Vm` dispatch on a VM-capable
    /// host passes the isolation gate and reaches the `Vm` branch. Host
    /// containment is reaping-only here, because the hypervisor is the boundary
    /// for a VM job. The non-flake encoding makes the `Vm` branch fail at decode,
    /// which proves the gate let it through.
    #[tokio::test]
    async fn handle_dispatch_admits_an_untrusted_vm_dispatch_past_the_isolation_gate() -> anyhow::Result<()> {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: b"irrelevant".to_vec(),
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(), // not flake/v1
            backend: sandy_executor_proto::SandboxKind::Vm.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Untrusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            true,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("the non-flake encoding must be refused on the Vm branch");
        assert!(
            matches!(
                &err,
                HandleDispatchError::Dispatch(DispatchError::UnrecognizedManifestEncoding(encoding))
                    if encoding == MANIFEST_ENCODING_ARGV_V1
            ),
            "expected UnrecognizedManifestEncoding from the Vm branch, got {err:?}. IsolationClassNotSatisfied means \
             the gate checked the Vm dispatch as a Process job"
        );
        Ok(())
    }

    /// #602: a dispatched VM never boots a guest NIC, because this path applies no egress boundary.
    #[test]
    fn a_dispatched_vm_refuses_a_guest_nic() {
        use std::{env::VarError, ffi::OsString};
        assert_eq!(refuse_guest_nic(Err(VarError::NotPresent)), Ok(()));
        assert_eq!(refuse_guest_nic(Ok(String::new())), Ok(()));
        assert_eq!(refuse_guest_nic(Ok("none".to_string())), Ok(()));
        for bad in [
            Ok("nic".to_string()),
            Ok("NIC".to_string()),
            Err(VarError::NotUnicode(OsString::new())),
        ] {
            assert!(
                matches!(refuse_guest_nic(bad), Err(DispatchError::NetworkProfileUnsupported(_))),
                "a NIC or malformed profile must be refused"
            );
        }
    }

    /// An untrusted dispatch with an unset backend is checked as the weaker
    /// `Process` kind, so the isolation gate refuses it before anything else.
    #[tokio::test]
    async fn handle_dispatch_refuses_an_untrusted_job_with_an_unspecified_backend() -> anyhow::Result<()> {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["echo"]).context("encoding the static test manifest")?,
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Unspecified.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Untrusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            true,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("an untrusted job with no backend must be refused");
        assert!(
            matches!(
                err,
                HandleDispatchError::Dispatch(DispatchError::IsolationClassNotSatisfied {
                    required: IsolationClass::Untrusted
                })
            ),
            "expected IsolationClassNotSatisfied, got {err:?}"
        );
        Ok(())
    }

    /// Adversarial: a `link_token` that isn't exactly `REMOTE_LINK_TOKEN_LEN`
    /// bytes must be refused, never silently truncated or padded into a
    /// prefix the orchestrator's accept loop would then decode wrong — and
    /// (INV-1, issue #159's residual item) the refusal's error `Display`/
    /// `Debug` must not carry the bytes that were presented, even though
    /// `HandleDispatchError::InvalidLinkTokenLength` only carries a length by
    /// construction: a marker-containing token proves that, rather than
    /// assuming it from reading the enum definition.
    #[tokio::test]
    async fn handle_dispatch_refuses_a_malformed_link_token_length() -> anyhow::Result<()> {
        let marker = b"sandy-leak-marker-short-by-one!".to_vec();
        assert_eq!(
            marker.len(),
            REMOTE_LINK_TOKEN_LEN - 1,
            "test fixture must stay one byte short"
        );
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["echo"]).context("encoding the static test manifest")?,
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Process.into(),
            link_token: marker.clone(),
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            false,
            sandy_api::backend::RunControl::with_timeout_secs(60),
            test_mesh_tls_config(),
        )
        .expect_err("a wrong-length link_token must be refused, never silently reshaped");
        assert!(
            matches!(err, HandleDispatchError::InvalidLinkTokenLength(len) if len == REMOTE_LINK_TOKEN_LEN - 1),
            "expected InvalidLinkTokenLength, got {err:?}"
        );
        let display = err.to_string();
        let debug = format!("{err:?}");
        let marker_text = String::from_utf8_lossy(&marker).into_owned();
        let marker_hex: String = marker.iter().map(|b| format!("{b:02x}")).collect();
        for rendered in [&display, &debug] {
            assert!(
                !rendered.contains(&marker_text),
                "the presented token's decoded text leaked into the error: {rendered}"
            );
            assert!(
                !rendered.contains(&marker_hex),
                "the presented token's hex encoding leaked into the error: {rendered}"
            );
            assert!(
                !rendered.contains(&format!("{marker:?}")),
                "the presented token's raw bytes leaked into the error: {rendered}"
            );
        }
        Ok(())
    }
}
