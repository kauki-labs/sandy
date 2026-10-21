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
    backend::{BackendError, Grants, Outcome, RunSpec, SandboxKind as ApiSandboxKind, VmBackend},
    containment::{Containment, ContainmentStatus},
};
use sandy_executor_proto::{Dispatch, IsolationClass, REMOTE_LINK_TOKEN_LEN, SandboxKind as ProtoSandboxKind};
use sandy_fabric_local::mesh_link::relay_agent_link;
use sandy_guest_template::manifest::MANIFEST_ENCODING_FLAKE_V1;
use sandy_impls_local::ProcessBackend;
use sandy_impls_vm::QemuBackend;

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

/// Decode `Dispatch.manifest` into the argv this host will run, per
/// `manifest_encoding`. The only encoding stage 1 understands is
/// [`MANIFEST_ENCODING_ARGV_V1`]; anything else — including an empty tag —
/// is refused rather than guessed at.
///
/// # Errors
/// See [`DispatchError`]'s `UnrecognizedManifestEncoding`,
/// `MalformedManifest`, and `EmptyCommand` variants.
pub fn decode_argv_manifest(manifest_encoding: &str, manifest: &[u8]) -> Result<Vec<String>, DispatchError> {
    if manifest_encoding != MANIFEST_ENCODING_ARGV_V1 {
        return Err(DispatchError::UnrecognizedManifestEncoding(
            manifest_encoding.to_owned(),
        ));
    }
    let argv: Vec<String> =
        serde_json::from_slice(manifest).map_err(|e| DispatchError::MalformedManifest(e.to_string()))?;
    if argv.is_empty() {
        return Err(DispatchError::EmptyCommand);
    }
    Ok(argv)
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
    sandy_guest_template::manifest::decode_flake_manifest(manifest)
        .map_err(|e| DispatchError::MalformedManifest(e.to_string()))
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
/// # Errors
/// [`DispatchError::IsolationClassNotSatisfied`] if `required` is
/// `Untrusted` and this host's containment does not clear
/// [`admits_untrusted`]'s bar, or if `required` is the zero/unspecified
/// value — an unspecified class is never treated as the weaker "trusted".
pub fn check_isolation_class(
    required: IsolationClass,
    containment_status: &ContainmentStatus,
) -> Result<(), DispatchError> {
    let satisfied = match required {
        IsolationClass::Trusted => true,
        IsolationClass::Untrusted => admits_untrusted(ApiSandboxKind::Process, containment_status),
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
const STAGE1_TIMEOUT_SECS: u32 = 300;

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
) -> Result<Outcome, HandleDispatchError> {
    let status = containment.status();
    let required = IsolationClass::try_from(dispatch.required_isolation_class).unwrap_or(IsolationClass::Unspecified);
    check_isolation_class(required, &status)?;

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

    let on_link: OnLink = Arc::new(move |_box_id, host_end, report| {
        relay_agent_link(
            &rt,
            forward_back,
            host_end,
            prefix.clone(),
            report,
            std::time::Duration::from_secs(u64::from(STAGE1_TIMEOUT_SECS)),
        );
    });

    // Stage 1 (#269, D4): no inputs/outputs/secrets (M2 is cross-machine
    // communication through the agent channel, not sandbox IO — the IO
    // roadmap is separate, post-#34); no cpu/mem bound; the agent channel is
    // the whole point of M2, so it's the only grant. Shared by both
    // branches below.
    let grants = Grants {
        secrets: false,
        agent: true,
        shares: false,
    };

    match ProtoSandboxKind::try_from(dispatch.backend).ok() {
        Some(ProtoSandboxKind::Process) => {
            let argv = decode_argv_manifest(&dispatch.manifest_encoding, &dispatch.manifest)?;
            let backend = ProcessBackend::with_containment(containment).with_agent(AgentLaunch {
                program: agent_program,
                on_link,
            });
            let spec = RunSpec {
                template: &dispatch.job_id,
                command: &argv,
                inputs: &[],
                outputs: &[],
                secrets: &[],
                env: &[],
                cpu: None,
                mem: None,
                timeout_secs: STAGE1_TIMEOUT_SECS,
                grants: &grants,
                // Exit comes from the agent's own report (INV-11), never an
                // outcome file; `ProcessBackend` doesn't read this field at
                // all.
                outcome_file: None,
                secret_dir: None,
            };
            Ok(backend.run(&spec)?)
        }
        // Defense in depth (#332, mirroring `check_isolation_class`'s own
        // re-probe discipline): `vm_available` is the caller's own fresh
        // re-probe, never trusting this host's earlier `Register` or the
        // orchestrator's placement decision alone. A host that lost
        // qemu/kvm/vsock access since registering (or was never redeployed
        // with VM support at all) falls through to the catch-all refusal
        // below, exactly like an unrecognized backend value.
        Some(ProtoSandboxKind::Vm) if vm_available => {
            let decoded = decode_flake_dispatch_manifest(&dispatch.manifest_encoding, &dispatch.manifest)?;
            let resolved = sandy_guest_template::resolve_flake_template(
                &decoded.flake,
                decoded.kind.as_deref(),
                decoded.attr.as_deref(),
                // `--from-devshell` over M2: non-goal (#332) — not worth
                // forcing in without it falling out for free.
                false,
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
            let (template, _kept_topology_file) = match resolved {
                sandy_guest_template::ResolvedTemplate::Direct(t) => (t, None),
                sandy_guest_template::ResolvedTemplate::Prebuilt { path, _kept } => (path, Some(_kept)),
            };

            let backend = QemuBackend::new().with_agent(AgentLaunch {
                program: agent_program,
                on_link,
            });
            let spec = RunSpec {
                template: &template,
                command: &decoded.command,
                inputs: &[],
                outputs: &[],
                secrets: &[],
                env: &[],
                cpu: None,
                mem: None,
                timeout_secs: STAGE1_TIMEOUT_SECS,
                grants: &grants,
                outcome_file: None,
                secret_dir: None,
            };
            // `_kept_topology_file` (the temp JSON file, for a Prebuilt
            // template) must outlive `backend.run`'s own read of `template`
            // — held in scope here, across the call, not dropped before it.
            let outcome = backend.run(&spec)?;
            drop(_kept_topology_file);
            Ok(outcome)
        }
        _ => Err(HandleDispatchError::UnsupportedBackend(dispatch.backend)),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;

    fn available(isolates_untrusted: bool) -> ContainmentStatus {
        ContainmentStatus::Available { isolates_untrusted }
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

    #[test]
    fn a_trusted_requirement_is_always_satisfied() {
        assert_eq!(
            check_isolation_class(IsolationClass::Trusted, &available(false)),
            Ok(())
        );
        assert_eq!(
            check_isolation_class(
                IsolationClass::Trusted,
                &ContainmentStatus::Unavailable("no systemd".to_owned())
            ),
            Ok(())
        );
    }

    /// The hard case: stage-1's bwrap backend (reaping only, no bus/mount
    /// isolation) must REFUSE an untrusted job, never silently accept it as
    /// if it were trusted-process-shaped.
    #[test]
    fn an_untrusted_requirement_is_refused_by_a_reaping_only_host() {
        let err = check_isolation_class(IsolationClass::Untrusted, &available(false))
            .expect_err("a plain reaper must not admit an untrusted job");
        assert_eq!(
            err,
            DispatchError::IsolationClassNotSatisfied {
                required: IsolationClass::Untrusted
            }
        );
    }

    #[test]
    fn an_untrusted_requirement_is_satisfied_by_a_genuine_untrusted_boundary() {
        assert_eq!(
            check_isolation_class(IsolationClass::Untrusted, &available(true)),
            Ok(())
        );
    }

    #[test]
    fn an_unspecified_requirement_is_refused_not_treated_as_trusted() {
        let err = check_isolation_class(IsolationClass::Unspecified, &available(true))
            .expect_err("an unspecified isolation class must never default to the weaker trusted path");
        assert_eq!(
            err,
            DispatchError::IsolationClassNotSatisfied {
                required: IsolationClass::Unspecified
            }
        );
    }

    #[test]
    fn an_argv_v1_manifest_decodes_to_its_command_and_args() -> anyhow::Result<()> {
        let manifest = serde_json::to_vec(&["echo", "hello"])?;
        let argv = decode_argv_manifest(MANIFEST_ENCODING_ARGV_V1, &manifest)?;
        assert_eq!(argv, vec!["echo".to_string(), "hello".to_string()]);
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
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            false,
        )
        .expect_err("a Vm dispatch must be refused when this host cannot actually run one");
        assert!(
            matches!(err, HandleDispatchError::UnsupportedBackend(backend)
                if backend == i32::from(sandy_executor_proto::SandboxKind::Vm)),
            "expected UnsupportedBackend, got {err:?}"
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
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            true,
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
    /// `live_ws01_*` tests own that).
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
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            true,
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

    /// Adversarial: a `link_token` that isn't exactly `REMOTE_LINK_TOKEN_LEN`
    /// bytes must be refused, never silently truncated or padded into a
    /// prefix the orchestrator's accept loop would then decode wrong.
    #[tokio::test]
    async fn handle_dispatch_refuses_a_malformed_link_token_length() -> anyhow::Result<()> {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["echo"]).context("encoding the static test manifest")?,
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Process.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN - 1],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(
            &dispatch,
            containment,
            PathBuf::from("/nonexistent/sandy-agent"),
            rt,
            false,
        )
        .expect_err("a wrong-length link_token must be refused, never silently reshaped");
        assert!(
            matches!(err, HandleDispatchError::InvalidLinkTokenLength(len) if len == REMOTE_LINK_TOKEN_LEN - 1),
            "expected InvalidLinkTokenLength, got {err:?}"
        );
        Ok(())
    }
}
