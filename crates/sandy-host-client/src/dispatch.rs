//! Receive-dispatch handling (#263, #269, #283, M2 stage 1): turning an
//! orchestrator's `Dispatch` into a running trusted-process sandbox whose
//! agent link forwards back over the mesh.
//!
//! Built against the real `sandy-executor-proto` contract (#277), not a
//! guessed shape: [`decode_argv_manifest`] (pinned down with sandy-d1:
//! `manifest_encoding = "argv/v1"`, `manifest` a JSON array of the command
//! and its arguments), [`check_isolation_class`] (the executor-side half of
//! #269's two-sided isolation gate, decision 6/#279/#280 is the other
//! half), and [`handle_dispatch`] (the full composition: decode, re-check,
//! launch via `ProcessBackend::with_agent`, forward the agent's link back
//! via `sandy_fabric_local::mesh_link::relay_agent_link`). `RunSpec`'s
//! fields with no `Dispatch` wire shape yet (timeout, grants,
//! inputs/outputs) are architect-ruled stage-1 constants — see
//! [`handle_dispatch`]'s own doc for the exact values and why. The run-id +
//! link-token prefix is encoded via
//! `sandy_executor_proto::encode_remote_link_prefix`, not duplicated here
//! (#279).

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use sandy::admits_untrusted;
use sandy_api::{
    agent::{AgentLaunch, OnLink},
    backend::{BackendError, Grants, Outcome, RunSpec, SandboxKind as ApiSandboxKind, VmBackend},
    containment::{Containment, ContainmentStatus},
};
use sandy_executor_proto::{Dispatch, IsolationClass, REMOTE_LINK_TOKEN_LEN, SandboxKind as ProtoSandboxKind};
use sandy_fabric_local::mesh_link::relay_agent_link;
use sandy_impls_local::ProcessBackend;

/// The `Dispatch.manifest_encoding` tag stage 1 understands: the manifest is
/// a JSON array of strings, `argv[0]` first (the command and its arguments,
/// nothing else). Submitter-bounded capability derivation already happened
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
    /// `manifest_encoding` was not a tag this host understands. Per
    /// `sandy-control-proto`'s own `SubmitRequest.manifest_encoding`
    /// precedent, empty/unrecognized means "undefined, reject" — never a
    /// silent default encoding.
    #[error("unrecognized manifest_encoding {0:?}")]
    UnrecognizedManifestEncoding(String),
    /// `manifest_encoding` was [`MANIFEST_ENCODING_ARGV_V1`] but the bytes
    /// did not decode as a JSON array of strings.
    #[error("malformed argv/v1 manifest: {0}")]
    MalformedManifest(String),
    /// An `argv/v1` manifest decoded but named no command at all —
    /// `argv[0]` is required; nothing can run without it.
    #[error("manifest names no command (empty argv)")]
    EmptyCommand,
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

/// A full dispatch-handling failure, refused before or during the run.
#[derive(Debug, thiserror::Error)]
pub enum HandleDispatchError {
    /// The manifest didn't decode, or the isolation class isn't satisfied —
    /// refused before a [`ProcessBackend`] is ever constructed.
    #[error(transparent)]
    Dispatch(#[from] DispatchError),
    /// `Dispatch.backend` named a sandbox kind this host-client build does not
    /// run — stage 1 only ever runs `Process`, so `Vm` or `Unspecified` must
    /// be refused rather than silently run through `ProcessBackend` anyway.
    #[error("backend {0:?} is not supported by this host-client (stage 1 runs Process only)")]
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
/// placement decision alone), launch the trusted-process sandbox, and
/// forward its agent's link back to the orchestrator via
/// [`relay_agent_link`].
///
/// Blocks the calling thread for the run's whole duration —
/// [`ProcessBackend::run`]'s own contract, same as
/// [`AgentLaunch::on_link`]'s "no ambient async runtime" one. Callers run
/// this on a blocking thread (`tokio::task::spawn_blocking`), never on an
/// async task directly.
///
/// `rt` is the runtime [`relay_agent_link`]'s spawned forwarding task runs
/// on; capture it with `Handle::current()` in the async context that reads
/// `Dispatch` messages off the Register connection, before calling this
/// function.
///
/// `containment` is consumed into the constructed [`ProcessBackend`]; its
/// freshly probed [`Containment::status`] is also what
/// [`check_isolation_class`] re-checks `dispatch.required_isolation_class`
/// against — one probe, not two independently-timed ones that could drift.
///
/// # Errors
/// See [`HandleDispatchError`].
pub fn handle_dispatch(
    dispatch: &Dispatch,
    containment: Box<dyn Containment>,
    agent_program: PathBuf,
    rt: tokio::runtime::Handle,
) -> Result<Outcome, HandleDispatchError> {
    let status = containment.status();
    let required = IsolationClass::try_from(dispatch.required_isolation_class).unwrap_or(IsolationClass::Unspecified);
    check_isolation_class(required, &status)?;

    if ProtoSandboxKind::try_from(dispatch.backend) != Ok(ProtoSandboxKind::Process) {
        return Err(HandleDispatchError::UnsupportedBackend(dispatch.backend));
    }

    let argv = decode_argv_manifest(&dispatch.manifest_encoding, &dispatch.manifest)?;

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
        relay_agent_link(&rt, forward_back, host_end, prefix.clone(), report);
    });

    let backend = ProcessBackend::with_containment(containment).with_agent(AgentLaunch {
        program: agent_program,
        on_link,
    });

    // Stage 1 (#269, D4): no inputs/outputs/secrets (M2 is cross-machine
    // communication through the agent channel, not sandbox IO — the IO
    // roadmap is separate, post-#34); no cpu/mem bound; the agent channel is
    // the whole point of M2, so it's the only grant.
    let grants = Grants {
        secrets: false,
        agent: true,
        shares: false,
    };
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
        // Exit comes from the agent's own report (INV-11), never an outcome
        // file; `ProcessBackend` doesn't read this field at all.
        outcome_file: None,
        secret_dir: None,
    };

    Ok(backend.run(&spec)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available(isolates_untrusted: bool) -> ContainmentStatus {
        ContainmentStatus::Available { isolates_untrusted }
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

        let err = handle_dispatch(&dispatch, containment, PathBuf::from("/nonexistent/sandy-agent"), rt)
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

    /// Adversarial: a `Dispatch` naming `Vm` (or an unrecognized/unspecified
    /// value) must be refused, never silently run through `ProcessBackend`
    /// anyway — stage 1 only ever runs `Process` (CodeRabbit finding on
    /// #284: the field was decoded but never checked).
    #[tokio::test]
    async fn handle_dispatch_refuses_a_backend_this_host_does_not_run() {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["echo"]).expect("static manifest always encodes"),
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Vm.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(&dispatch, containment, PathBuf::from("/nonexistent/sandy-agent"), rt)
            .expect_err("a Vm dispatch must be refused by a host-client that only runs Process");
        assert!(
            matches!(err, HandleDispatchError::UnsupportedBackend(backend)
                if backend == i32::from(sandy_executor_proto::SandboxKind::Vm)),
            "expected UnsupportedBackend, got {err:?}"
        );
    }

    /// Adversarial: a `link_token` that isn't exactly `REMOTE_LINK_TOKEN_LEN`
    /// bytes must be refused, never silently truncated or padded into a
    /// prefix the orchestrator's accept loop would then decode wrong.
    #[tokio::test]
    async fn handle_dispatch_refuses_a_malformed_link_token_length() {
        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_string(),
            manifest: serde_json::to_vec(&["echo"]).expect("static manifest always encodes"),
            manifest_encoding: MANIFEST_ENCODING_ARGV_V1.to_string(),
            backend: sandy_executor_proto::SandboxKind::Process.into(),
            link_token: vec![0u8; REMOTE_LINK_TOKEN_LEN - 1],
            forward_back: "127.0.0.1:9000".to_string(),
            required_isolation_class: IsolationClass::Trusted.into(),
        };
        let containment = Box::new(sandy_test_support::FakeContainment::available());
        let rt = tokio::runtime::Handle::current();

        let err = handle_dispatch(&dispatch, containment, PathBuf::from("/nonexistent/sandy-agent"), rt)
            .expect_err("a wrong-length link_token must be refused, never silently reshaped");
        assert!(
            matches!(err, HandleDispatchError::InvalidLinkTokenLength(len) if len == REMOTE_LINK_TOKEN_LEN - 1),
            "expected InvalidLinkTokenLength, got {err:?}"
        );
    }
}
