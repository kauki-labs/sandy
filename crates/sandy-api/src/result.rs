//! The LOCKED result envelope and classification types (INV-6, INV-7, INV-11).
//!
//! The envelope is `snake_case` on the wire and in Rust, with no serde rename
//! layer. These are the data types only; the classification *functions* that map
//! a physical `Outcome` (or a backend / plan error) into a [`Classification`]
//! live in the core crate that depends on this one.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::{cred::Scope, egress::AllowList};

/// The schema version stamped into every envelope (INV-6/INV-11).
///
/// Bumped to `3` for the audit receipt (#361): `receipt` is a new
/// `Option<Receipt>` field, `None` on a pre-`3` record (`#[serde(default)]`),
/// matching the `2`/`warnings` precedent (L-12).
pub const RESULT_SCHEMA_VERSION: u32 = 3;

/// Terminal status of a job on the wire. The lowercase values are part of the
/// LOCKED schema; `rename_all` selects them without renaming any field key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Guest exited 0 and all required outputs were collected.
    Succeeded,
    /// A task/contract fault, or an infra fault that aborted the run.
    Failed,
    /// The job was cancelled before a terminal guest result.
    Cancelled,
}

/// sandy's own *process* exit band (INV-11) — never conflated with the guest's
/// `exit_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExit {
    /// `0` — succeeded.
    Succeeded,
    /// `1` — task failure (guest-nonzero / timeout / missing-required /
    /// cancelled); `retryable: false`.
    TaskFailure,
    /// `2` — invalid plan / usage; `retryable: false`; no boot.
    InvalidPlan,
    /// `3` — infra fault (boot / transport / unreachable / host-IO);
    /// `retryable: true`.
    InfraFault,
}

impl ProcessExit {
    /// The numeric process exit code for this band (`0`/`1`/`2`/`3`).
    #[must_use]
    pub fn code(self) -> i32 {
        match self {
            ProcessExit::Succeeded => 0,
            ProcessExit::TaskFailure => 1,
            ProcessExit::InvalidPlan => 2,
            ProcessExit::InfraFault => 3,
        }
    }
}

/// How a job's declared outputs resolved, fed into the core's `classify_outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStatus {
    /// Every required output was collected.
    Complete,
    /// A required output was absent after a clean exit.
    RequiredMissing,
    /// Collection exceeded the per-job cap.
    OverQuota,
}

/// The terminal classification of a job: the three values that MUST stay
/// consistent (INV-11 cross-checks). The core builds these; this crate only
/// defines the shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    /// The envelope status.
    pub status: Status,
    /// Whether the platform may retry (true only for infra faults, INV-7).
    pub retryable: bool,
    /// sandy's process exit band.
    pub process_exit: ProcessExit,
}

/// One collected output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputRef {
    /// Path of the collected output, relative to the job's `out/`.
    pub path: String,
}

/// A side effect produced by the job (e.g. a GitHub PR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The receipt kind, e.g. `"github-pr"`.
    pub kind: String,
    /// A reference for the receipt, e.g. a PR URL. Serializes as the `ref` key.
    pub r#ref: String,
}

/// Provenance of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The Nix store path of the template that was booted.
    pub template_store_path: String,
}

/// Captured guest logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logs {
    /// The tail of the guest's combined output.
    pub tail: String,
}

/// Who ran or authorized the job (#361). Host-observed: the guest cannot
/// influence this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Who {
    /// The local uid (direct `sandy run`, or a sandyd job with no verified
    /// submitter cap) or the verified submitter cap's `scope.peer`
    /// (`docs/decisions/sandyd.md` section 11).
    pub identity: String,
    /// `true` only for a submitter cap `CapAuthority::verify`d against its
    /// issuing authority; `false` for the local-uid fallback.
    pub authenticated: bool,
}

/// What ran (#361). Host-observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct What {
    /// The job id.
    pub job_id: String,
    /// The template or flake ref that was booted (as given on the command
    /// line or manifest), e.g. `demo` or a `--flake` ref.
    pub template: String,
    /// The template's resolved Nix store path, when the run path resolved
    /// one. `None` today: no sandy run path threads a resolved store path
    /// this far yet (a separate, not-yet-filed gap from the digests in
    /// #373/#374/#375).
    pub template_store_path: Option<String>,
    /// A digest of the job manifest, when one exists. `None` for a direct
    /// `sandy run` (there is no manifest object on that path, only a
    /// `JobPlan`); populated once a manifest-carrying path builds a receipt.
    pub manifest_digest: Option<String>,
}

/// Where the job ran (#361). Host-observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// The backend kind: `"qemu"`, `"vfkit"`, or `"process"`.
    pub backend: String,
    /// The dispatching executor's host id, for a sandyd-dispatched job
    /// (`docs/decisions/sandyd.md` decision 12). `None` for a direct
    /// `sandy run`, and for a sandyd job today — dispatch-core does not yet
    /// persist a receipt at all (tracked in the follow-up filed with #361).
    pub executor_host_id: Option<String>,
    /// The executor's mesh IP, same conditions as `executor_host_id`.
    pub executor_mesh_ip: Option<String>,
}

/// The credential lease a job ran with (#361). Host-observed. Never the token
/// itself (INV-1) — only `sandy::Scope`'s targets/capabilities and lifecycle
/// timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReceipt {
    /// The credential provider, e.g. `"github"`.
    pub provider: String,
    /// The minted lease's scope (repos/targets and capabilities granted).
    pub scope: Scope,
    /// When the credential was minted, before the boot.
    pub minted_at: SystemTime,
    /// When each mid-run refresh re-minted a token (empty if none fired).
    pub refreshed_at: Vec<SystemTime>,
    /// When the credential was revoked at teardown.
    pub revoked_at: SystemTime,
    /// Whether the revoke call succeeded; `false` means the warning in
    /// `ResultEnvelope::warnings` names the same failure (L-12).
    pub revoke_succeeded: bool,
}

/// Egress enforcement state at boot (#361), the structured form of the
/// warning #358 surfaces for an unenforced boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressEnforcement {
    /// The allow-list was applied as the per-VM boundary.
    Enforced,
    /// No boundary was applied, or applying one failed; `reason` on
    /// [`EgressReceipt`] says why.
    Unenforced,
}

/// One egress attempt the guest made. Reserved and always empty until the
/// #360 proxy can observe them (#375).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAttempt {
    /// The destination the guest attempted to reach.
    pub target: String,
    /// Whether the allow-list permitted it.
    pub allowed: bool,
}

/// The egress boundary's state around the boot (#361). Host-observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressReceipt {
    /// Whether the boundary was enforced.
    pub status: EgressEnforcement,
    /// Why, when `status` is [`EgressEnforcement::Unenforced`] (a platform
    /// with no boundary, or a failed apply); `None` when enforced.
    pub reason: Option<String>,
    /// The allow-list that was actually applied; `None` when nothing was
    /// (unenforced) — never present labeled "applied" with nothing behind it.
    pub allow_list: Option<AllowList>,
    /// Attempts the guest made against the boundary. Reserved, always empty
    /// (#375).
    #[serde(default)]
    pub attempts: Vec<EgressAttempt>,
}

/// Lifecycle timestamps for the run (#361). Host-observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    /// When the boot began (the `Running` record's `started`).
    pub boot_started_at: SystemTime,
    /// When the guest's command phase began, distinct from boot. `None`
    /// today: no backend reports this moment back to the supervisor (a
    /// separate, not-yet-filed gap — `Outcome` carries no timestamp).
    pub job_started_at: Option<SystemTime>,
    /// When teardown completed (egress reverted, credential revoked if any).
    pub teardown_at: SystemTime,
}

/// One collected output's name and size (#361). Guest-reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSizeRef {
    /// Logical path, same convention as [`OutputRef::path`].
    pub path: String,
    /// Size in bytes on the host after collection.
    pub size_bytes: u64,
}

/// Values a hostile guest could shape (#361, `docs/architecture/spec.md`'s
/// attacker model): never trusted as a host fact on their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestReported {
    /// The guest's exit code, mirroring [`ResultEnvelope::exit_code`] under
    /// its provenance classification.
    pub exit_code: Option<i32>,
    /// Collected output names and sizes.
    pub outputs: Vec<OutputSizeRef>,
}

/// Facts the host supervisor or executor recorded directly; the guest cannot
/// influence these (#361).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostObserved {
    /// Who ran or authorized the job.
    pub who: Who,
    /// What ran.
    pub what: What,
    /// Where it ran.
    #[serde(rename = "where")]
    pub location: Location,
    /// The credential lease the job ran with, if any.
    pub credential: Option<CredentialReceipt>,
    /// The egress boundary's state.
    pub egress: EgressReceipt,
    /// Lifecycle timestamps.
    pub timing: Timing,
}

/// The envelope receipt v1 (#361): audit lineage split by who observed each
/// field, so an auditor never takes the guest's claim as a host fact. Named
/// `Receipt` for the wire shape the issue specifies; distinct from the
/// side-effect [`Receipt`] already on [`ResultEnvelope::receipts`] (e.g. a
/// GitHub PR a job opened) — an unrelated, older concept this type does not
/// replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReceipt {
    /// Facts the host observed directly.
    pub host_observed: HostObserved,
    /// Values reported by the (possibly hostile) guest.
    pub guest_reported: GuestReported,
}

/// The LOCKED result envelope (INV-11). Written to the journal at the terminal
/// transition (INV-6) and printed by foreground `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultEnvelope {
    /// Schema version of this envelope.
    pub result_schema_version: u32,
    /// The job id.
    pub job_id: String,
    /// The box the job ran in, if one booted.
    pub box_id: Option<String>,
    /// Terminal status.
    pub status: Status,
    /// Whether the platform may retry (INV-7).
    pub retryable: bool,
    /// A human-readable message.
    pub message: String,
    /// The GUEST's exit code (never sandy's process band — INV-11).
    pub exit_code: Option<i32>,
    /// Collected outputs.
    pub outputs: Vec<OutputRef>,
    /// Side-effect receipts.
    pub receipts: Vec<Receipt>,
    /// Run provenance.
    pub provenance: Provenance,
    /// Captured logs.
    pub logs: Logs,
    /// Non-fatal faults folded into the run rather than failing it (L-12), e.g. a
    /// credential revoke that failed at teardown. Empty on every ordinary run.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The audit receipt (#361), schema `3`. `None` on a pre-`3` record
    /// (`#[serde(default)]`), on an invalid-plan run (no `Running` record was
    /// ever written, no backend observation to report), and on `kill`'s
    /// synthetic cancellation (no backend run to observe either).
    #[serde(default)]
    pub receipt: Option<AuditReceipt>,
}
