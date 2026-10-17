//! Receive-dispatch handling (#263, #269, M2 stage 1): the pieces of turning
//! an orchestrator's `Dispatch` into a running trusted-process sandbox whose
//! agent link forwards back over the mesh.
//!
//! Built incrementally against the real `sandy-executor-proto` contract
//! (#277), not a guessed shape. This module holds the two pieces that are
//! independently testable and fully specified today: [`decode_argv_manifest`]
//! (pinned down with sandy-d1: `manifest_encoding = "argv/v1"`, `manifest` a
//! JSON array of the command and its arguments) and
//! [`check_isolation_class`] (the executor-side half of #269's two-sided
//! isolation gate). The run-id+link-token prefix is encoded via
//! `sandy_executor_proto::encode_remote_link_prefix`, not duplicated here
//! (#279). The full composition — turning the decoded argv into a
//! `RunSpec`, wiring `ProcessBackend::with_agent` with
//! `sandy_fabric_local::mesh_link::relay_agent_link` as the `on_link` — is
//! tracked as its own follow-on (#283): `RunSpec` carries fields (timeout,
//! grants, inputs/outputs) `Dispatch` doesn't define a wire shape for yet,
//! and that's a real design decision, not a wiring exercise.

use sandy::admits_untrusted;
use sandy_api::{backend::SandboxKind as ApiSandboxKind, containment::ContainmentStatus};
use sandy_executor_proto::IsolationClass;

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
// decode_remote_link_prefix, with its own round-trip test there. This
// module calls the encode side once it lands; not duplicated here.

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
    fn an_unrecognized_encoding_is_refused_not_guessed_at() {
        let manifest = serde_json::to_vec(&["echo"]).unwrap();
        let err = decode_argv_manifest("", &manifest).expect_err("empty encoding must be refused");
        assert_eq!(err, DispatchError::UnrecognizedManifestEncoding(String::new()));

        let err = decode_argv_manifest("shell/v1", &manifest)
            .expect_err("an encoding this host doesn't understand must be refused");
        assert_eq!(err, DispatchError::UnrecognizedManifestEncoding("shell/v1".to_string()));
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
}
