//! Dispatch one [`ControlRequest`] to a [`ControlResponse`] against the
//! [`JobStore`] and the [`JobRegistry`] (#212, B1 + B2's dispatch slice).
//! `Submit` persists the job AND mints its dedicated channel + caps (see
//! [`crate::dispatch`]); `Attach` returns that real channel id + a cap once
//! minted — a post-capable one when the requesting session is the one that
//! submitted the job (#327, "my own job I can log into"), the existing
//! observer-only `job.observer_cap` otherwise ("someone else's, I can only
//! watch"). No agent or executor wiring yet: a submitted job stays `Pending`
//! forever, since nothing joins its channel or runs it — see `dispatch`'s
//! module doc for why that's an honest gap, not a fake.

use std::{net::SocketAddr, sync::Arc};

use sandy_control_proto::{
    AttachResponse, CancelResponse, ControlError, ControlRequest, ControlResponse, JobStatus,
    JobSummary as WireJobSummary, ListResponse, StatusResponse, SubmitRequest, SubmitResponse, control_request,
    control_response,
};
use sandy_executor_proto::{Dispatch, IsolationClass, SandboxKind};
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapCodecError, CapRights, CapScope, decode_cap, encode_cap},
    types::{ChannelId, PeerId},
};
use sandy_guest_template::manifest::MANIFEST_ENCODING_FLAKE_V1;
use sandy_orchestrator::{JobManifest, MANIFEST_ENCODING_JSON, derive_job_caps};
use uuid::Uuid;

use crate::{
    credential::CREDENTIAL_SECRET_NAME,
    dispatch::{self, JobRegistry},
    host_registry::HostRegistry,
    link_auth::RemoteLink,
    store::{CancelOutcome, InsertOutcome, JobStore, StoreError, Transition},
};

/// The reason a `flake/v1` manifest fails `decode_flake_manifest`, `None` for any other encoding or a manifest
/// that decodes (#589). Run at Submit so a malformed manifest or an invalid `service` (root user, zero port,
/// unrunnable probe) fails in the reply, not after placement as a `MalformedManifest`. It does not mirror the
/// executor's temporary `ServiceNotSupported` guard: a valid service still reaches the executor. Only `flake/v1`
/// is checked: this daemon still resolves and builds nothing. The error text can echo submitter bytes (an unknown
/// field name), so control characters are replaced before it is returned or logged.
fn flake_manifest_refusal(manifest_encoding: &str, manifest: &[u8]) -> Option<String> {
    (manifest_encoding == MANIFEST_ENCODING_FLAKE_V1)
        .then(|| sandy_guest_template::manifest::decode_flake_manifest(manifest).err())
        .flatten()
        .map(|e| {
            format!("the flake/v1 manifest is refused: {e}")
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect()
        })
}

/// The one refusal text for a `Cancel` that is not authorized (#540): it must not say whether the job
/// exists, what state it is in, or which part of the credential was wrong.
const CANCEL_REFUSED: &str = "cancel refused: a valid attach token for this job is required";

/// Derive the `Dispatch.backend` a submitted manifest requires, purely from
/// its `manifest_encoding` (#332): `flake/v1` requires `Vm` (a remote
/// host-executor resolves+boots the guest; this daemon has no local VM
/// execution path at all). Every other encoding — `argv/v1`, the JSON
/// `JobManifest` encoding, an opaque/unrecognized tag — requires `Process`,
/// exactly today's only backend. A submitter never states the backend
/// directly; it follows from the manifest shape it chose.
fn required_sandbox_kind_for(manifest_encoding: &str) -> SandboxKind {
    if manifest_encoding == MANIFEST_ENCODING_FLAKE_V1 {
        SandboxKind::Vm
    } else {
        SandboxKind::Process
    }
}

/// Refuses a submit this daemon cannot place when placement is mandatory for
/// it, with `reason` as the explanation; `None` for anything else (a placed
/// job, or an `argv/v1`+`Trusted` job, which keeps its existing "falls back
/// to local" behavior unchanged). Placement is mandatory for a `SandboxKind::Vm`
/// requirement (a `flake/v1` job has no local execution path at all) and,
/// independently, for an `IsolationClass::Untrusted` requirement (#381: the
/// process backend never admits an untrusted job, so an unplaced one has no
/// local fallback either, whatever sandbox kind it named). Shared by the two
/// placement checks in `handle`'s `Submit` arm: the early one (before any
/// side effect) and the one right after `dispatch_plan` is computed, which
/// closes a narrow TOCTOU the early check alone cannot — a host disconnecting
/// between the two `pick_host_for` calls, or `RemoteLink::new`'s RNG failing,
/// can make the second placement attempt come back empty even though the
/// first one found a host. Leaving either kind of mandatory-placement job
/// `Pending` forever with no distinct status would be exactly the silent gap
/// decision 18 rules out.
fn placement_required_error(
    required_isolation_class: IsolationClass,
    required_sandbox_kind: SandboxKind,
    require_local: bool,
    placed: bool,
    reason: &str,
) -> Option<ControlError> {
    let placement_mandatory = required_sandbox_kind == SandboxKind::Vm
        || required_isolation_class == IsolationClass::Untrusted
        || require_local;
    (placement_mandatory && !placed).then(|| ControlError {
        message: reason.to_owned(),
    })
}

/// Whether `submit` names any path field (#496, decision 21) — `inputs`,
/// `outputs`, or `secrets`. Non-empty here means placement must land on a
/// host-executor that declared `shares_submitter_filesystem`; a path is only
/// ever meaningful on the filesystem the submitter itself is on. A
/// `credential` (#481, decision 37) requires the same: the minted token is a
/// file on this machine, and no encrypted mesh transport carries it to a
/// remote host yet (#495).
fn submit_requires_local_dispatch(submit: &SubmitRequest) -> bool {
    !submit.inputs.is_empty() || !submit.outputs.is_empty() || !submit.secrets.is_empty() || submit.credential.is_some()
}

/// The refusal for a credentialed Submit with no local host to place on (#481).
fn credential_placement_refusal() -> String {
    "no registered host both declares shares_submitter_filesystem and offers the required isolation class and sandbox \
     kind; this Submit names a `credential`, and a daemon-minted token is only handed to a host-executor on this \
     machine: carrying it to a remote host needs the encrypted mesh transport (#495), which is not wired yet"
        .to_owned()
}

/// Refuse a Submit whose credential request this daemon cannot honor (#481), before
/// any side effect: `cred_capabilities` with no `credential`, a credential name
/// that is not a single file name, a credential on a daemon with no credential
/// support, or a `secrets` entry already using the name the minted token is
/// staged under.
fn credential_request_refusal(submit: &SubmitRequest, registry: &JobRegistry) -> Option<String> {
    let Some(name) = &submit.credential else {
        return (!submit.cred_capabilities.is_empty()).then(|| {
            "cred_capabilities names capabilities but the Submit names no credential to mint them for".to_owned()
        });
    };
    // The name becomes `<trust-roots dir>/<name>.json`: refuse anything but one file name.
    if let Err(e) = sandy::validate_trust_root_name(name) {
        return Some(format!("credential {name:?} is refused: {e}"));
    }
    if registry.credentials().is_none() {
        return Some(format!(
            "this daemon has no credential support configured; the Submit naming credential {name:?} is refused"
        ));
    }
    submit
        .secrets
        .iter()
        .any(|s| s.name == CREDENTIAL_SECRET_NAME)
        .then(|| {
            format!(
                "secrets already names {CREDENTIAL_SECRET_NAME}, the name the minted credential is staged under; \
                 rename that secret or drop the credential"
            )
        })
}

/// Name the path field that made [`submit_requires_local_dispatch`] true, for
/// a refusal message — `control.proto`'s own doc on these fields and the
/// manifest-parity spec both require naming the field, never a generic "a
/// path field" (CodeRabbit on #508). Checked in the same order the proto
/// declares them; a Submit naming more than one still gets a single,
/// representative name rather than every one of them.
fn first_path_field_name(submit: &SubmitRequest) -> &'static str {
    if !submit.inputs.is_empty() {
        "inputs"
    } else if !submit.outputs.is_empty() {
        "outputs"
    } else {
        "secrets"
    }
}

/// Convert `SubmitRequest`'s client-facing path fields (`sandy_control_proto`)
/// into their `Dispatch` wire shape (`sandy_executor_proto`) — two structurally
/// identical but separately-defined proto messages (this crate's existing
/// stance of no cross-proto-package dependency between the two contracts,
/// matching `IsolationClass`'s own duplication). A pure field-by-field copy,
/// never touching the paths' bytes — the daemon forwards names, it does not
/// read them (that's the host-executor's job, once placed on a host that
/// declared it shares the submitter's filesystem).
fn to_dispatch_path_fields(
    submit: &SubmitRequest,
) -> (
    Vec<sandy_executor_proto::Input>,
    Vec<sandy_executor_proto::Output>,
    Vec<sandy_executor_proto::SecretRef>,
) {
    let inputs = submit
        .inputs
        .iter()
        .map(|i| sandy_executor_proto::Input {
            host: i.host.clone(),
            name: i.name.clone(),
            guest_path: i.guest_path.clone(),
        })
        .collect();
    let outputs = submit
        .outputs
        .iter()
        .map(|o| sandy_executor_proto::Output {
            name: o.name.clone(),
            dest: o.dest.clone(),
        })
        .collect();
    let secrets = submit
        .secrets
        .iter()
        .map(|s| sandy_executor_proto::SecretRef {
            name: s.name.clone(),
            host_path: s.host_path.clone(),
        })
        .collect();
    (inputs, outputs, secrets)
}

/// Parse `SubmitRequest.required_isolation_class`'s wire value (the
/// client-facing `sandy_control_proto::IsolationClass`) into the internal
/// `sandy_executor_proto::IsolationClass` placement/dispatch uses. `None` for
/// `Unspecified` or an unrecognized value — #381's contract is that an unset
/// or invalid class is refused at Submit, never defaulted to `Trusted`.
fn parse_required_isolation_class(wire_value: i32) -> Option<IsolationClass> {
    match sandy_control_proto::IsolationClass::try_from(wire_value) {
        Ok(sandy_control_proto::IsolationClass::Trusted) => Some(IsolationClass::Trusted),
        Ok(sandy_control_proto::IsolationClass::Untrusted) => Some(IsolationClass::Untrusted),
        Ok(sandy_control_proto::IsolationClass::Unspecified) | Err(_) => None,
    }
}

/// The length, in bytes, of a job's durable attach token (#327) —
/// `SubmitResponse.attach_token`/`AttachRequest.attach_token`. Same length as
/// `link_auth::LINK_TOKEN_LEN`, a distinct value (a different bearer
/// credential, minted independently): not shared with or derived from it.
const ATTACH_TOKEN_LEN: usize = 32;

/// A failure handling a [`ControlRequest`]: the job store or the dispatch
/// layer faulted, or the `spawn_blocking` task running a store call panicked
/// or was cancelled. None of these is a job-level refusal (an unknown job
/// id, an already-terminal cancel) — those are [`ControlError`] responses,
/// not `Err`s, since the request was understood and the daemon answered it.
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    /// The job store faulted.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The `spawn_blocking` task running a store call panicked or was
    /// cancelled. Propagated, not `.expect()`'d: a failed store task must
    /// close the one connection that asked for it, never panic the whole
    /// connection-handling task.
    #[error("store task: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// Minting the job's channel/caps faulted.
    #[error("dispatch: {0}")]
    Dispatch(#[from] dispatch::DispatchError),
    /// Encoding a cap for the wire faulted.
    #[error("cap encoding: {0}")]
    Cap(#[from] CapCodecError),
}

/// Decode `submit.submitter_caps` and, if the manifest requests anything
/// beyond the job's own dedicated channel, bound it against what the
/// submitter holds (decision C-at-Submit, #226). Returns the caps to attach
/// to the job (empty for a direct-mint submission), or a [`ControlError`]
/// naming the refusal — never silently grants more than this function itself
/// verified.
///
/// **Policy: trust comes from the connection, not from whether
/// `submitter_caps` is present.** In the local-UDS MVP, the 0700 socket IS
/// the trust boundary — only the local operator reaches it — so an empty
/// `submitter_caps` is the direct-mint path, exactly as before this block,
/// and is *not* a silent way to skip bounding: there is nothing to bound,
/// since the job gets only its own dedicated channel either way. The one
/// case this function refuses outright is a submitter presenting caps for a
/// manifest it cannot decode (an unrecognized `manifest_encoding`) — never
/// silently ignoring caps the submitter explicitly went to the trouble of
/// presenting. Once an untrusted submitter reaches Submit (cross-machine via
/// B6, or a sub-agent submitting a sub-job), THAT connection must always
/// carry `submitter_caps` and go through this path — gating on the
/// connection's own trust level is a future block's job, not this
/// function's; this function only decides what a given `SubmitRequest`'s
/// frame is allowed to grant.
fn resolve_granted_caps(
    manifest: &[u8],
    manifest_encoding: &str,
    submitter_caps: &[Vec<u8>],
    authority: &sandy_fabric_local::SharedCapAuthority,
) -> Result<Vec<Cap>, ControlError> {
    if submitter_caps.is_empty() {
        return Ok(Vec::new());
    }

    let submitter_caps: Vec<Cap> = submitter_caps
        .iter()
        .map(|bytes| decode_cap(bytes))
        .collect::<Result<_, _>>()
        .map_err(|e| ControlError {
            message: format!("could not decode a submitter capability: {e}"),
        })?;

    if manifest_encoding != MANIFEST_ENCODING_JSON {
        return Err(ControlError {
            message: format!(
                "submitter presented capabilities but manifest_encoding {manifest_encoding:?} is not understood; \
                 cannot bound this request"
            ),
        });
    }
    let parsed: JobManifest = serde_json::from_slice(manifest).map_err(|e| ControlError {
        message: format!("manifest did not decode as a JobManifest: {e}"),
    })?;

    derive_job_caps(authority, &submitter_caps, &parsed).map_err(|e| ControlError {
        message: format!("capability request refused: {e}"),
    })
}

/// Handle `request` against `store` and `registry`, blocking on the store's
/// synchronous connection via `spawn_blocking` so the connection's async
/// read/write loop is never held up by it. Takes `store` by `&Arc`, cloning
/// it (a refcount bump, not a deep copy) into each `spawn_blocking` closure
/// that needs a `'static` capture — never leaks an allocation per call.
///
/// `session` (CF-H-1) is the calling connection's own id, minted once by
/// `serve_connection` and threaded through here in-process (never on the
/// wire): `Submit` records it on the new job, and a later `Cancel`/`Attach`
/// compares against it to log — never refuse — a request arriving from a
/// different connection than the one that submitted the job.
///
/// # Errors
/// See [`HandlerError`].
pub async fn handle(
    store: &Arc<JobStore>,
    registry: &Arc<JobRegistry>,
    host_registry: &Arc<HostRegistry>,
    forward_back_addr: Option<SocketAddr>,
    session: Uuid,
    request: ControlRequest,
) -> Result<ControlResponse, HandlerError> {
    let result = match request.op {
        Some(control_request::Op::Submit(submit)) => {
            // CF-M-1: reject an oversized manifest before anything else —
            // even before decision C-at-Submit's own cap-bounding below, which
            // itself has to deserialize the manifest to do its job.
            if submit.manifest.len() > sandy_control_proto::MAX_MANIFEST_LEN as usize {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(ControlError {
                        message: format!(
                            "manifest of {} bytes exceeds the {}-byte limit",
                            submit.manifest.len(),
                            sandy_control_proto::MAX_MANIFEST_LEN
                        ),
                    })),
                });
            }

            // #381: every submitter must state its job's required isolation
            // class explicitly. Checked before anything else below (even
            // decision C-at-Submit's cap-bounding), same "no trace" bar as
            // every other Submit-time refusal in this function — an
            // unspecified or unrecognized class is never silently treated as
            // `Trusted`, which would breach isolation for a client that meant
            // to ask for `Untrusted`.
            let required_isolation_class = match parse_required_isolation_class(submit.required_isolation_class) {
                Some(class) => class,
                None => {
                    return Ok(ControlResponse {
                        request_id: request.request_id,
                        result: Some(control_response::Result::Error(ControlError {
                            message: "required_isolation_class must be TRUSTED or UNTRUSTED; UNSPECIFIED is refused, \
                                      never defaulted"
                                .to_owned(),
                        })),
                    });
                }
            };

            // Decision C-at-Submit (#226): bound before anything else is
            // created. A refusal here must leave no trace — no channel, no
            // store row — the same "fail before any side effect" shape the
            // existing mint-then-persist ordering below already follows.
            let granted_caps = match resolve_granted_caps(
                &submit.manifest,
                &submit.manifest_encoding,
                &submit.submitter_caps,
                registry.authority(),
            ) {
                Ok(granted) => granted,
                Err(control_error) => {
                    return Ok(ControlResponse {
                        request_id: request.request_id,
                        result: Some(control_response::Result::Error(control_error)),
                    });
                }
            };

            // #332: a required `SandboxKind` this daemon cannot place at all
            // must refuse the whole Submit now, before any side effect —
            // unlike `argv/v1`'s existing "no registered host → silently
            // stays Pending forever" gap (an already-accepted, pre-#332
            // honest limitation of the process-backend path, unchanged
            // here), a `flake/v1` VM job has NO local execution fallback in
            // this daemon at all: accepting it anyway would create a job
            // that can never run, with no distinct status a caller could
            // ever notice (item 5's "never silently" bar).
            let required_sandbox_kind = required_sandbox_kind_for(&submit.manifest_encoding);

            if let Some(message) = flake_manifest_refusal(&submit.manifest_encoding, &submit.manifest) {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(ControlError { message })),
                });
            }

            // #381 (CodeRabbit on this PR): the process kind never admits an
            // untrusted job (`process-containment.md` decision 6) — refuse
            // here, before `pick_host_for` or any persistence, rather than
            // letting an Untrusted+non-Vm submission reach placement. Without
            // this, a host that declares BOTH `Untrusted` and `Process`
            // (every `Vm`-capable host does — `Process` stays additive, see
            // `to_wire_capabilities`) would satisfy `pick_host_for`, and the
            // job would be placed and dispatched with `backend == Process`
            // only to be refused by the host-executor's own re-check —
            // technically fail-closed, but a wasted dispatch round trip
            // instead of a clean Submit-time refusal.
            if required_isolation_class == IsolationClass::Untrusted && required_sandbox_kind != SandboxKind::Vm {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(ControlError {
                        message: format!(
                            "an Untrusted job requires a Vm-backed manifest encoding (e.g. flake/v1); \
                             manifest_encoding {:?} resolves to SandboxKind::{required_sandbox_kind:?}, which can \
                             never satisfy Untrusted",
                            submit.manifest_encoding
                        ),
                    })),
                });
            }

            // #481: a credential request this daemon cannot honor is refused
            // before placement and before any mint.
            if let Some(message) = credential_request_refusal(&submit, registry) {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(ControlError { message })),
                });
            }
            let credential_request = submit
                .credential
                .clone()
                .map(|name| (name, submit.cred_capabilities.clone()));

            // Named apart from `placeable` itself (CodeRabbit on this PR): the
            // original message always blamed "no Vm-capable host," even when
            // the real cause was this orchestrator's own configuration
            // (`SANDY_MESH_AGENT_LINK_LISTEN` unset, so `forward_back_addr` is
            // `None` and no remote placement is reachable at all, regardless
            // of what's registered) — an operator misreads that as "go
            // register a host" when the actual fix is on this box.
            // #496, decision 21: a path field is only ever meaningful on the
            // submitter's own filesystem — require a host-executor that
            // declared `shares_submitter_filesystem`, same fail-closed
            // treatment as an Untrusted or Vm requirement with no qualifying
            // host (never a silent `Pending` forever, never a silent place-
            // anywhere).
            let require_local = submit_requires_local_dispatch(&submit);
            // Cached before `submit.manifest`/`manifest_encoding` are moved
            // out below: a partial move of one field makes rustc refuse any
            // later `&submit` borrow, even to read a different field.
            let path_field_name = first_path_field_name(&submit);
            let (path_inputs, path_outputs, path_secrets) = to_dispatch_path_fields(&submit);
            let placeable = if forward_back_addr.is_none() {
                false
            } else {
                host_registry
                    .pick_host_for(
                        required_isolation_class.into(),
                        required_sandbox_kind.into(),
                        require_local,
                    )
                    .is_some()
            };
            let placement_reason = if forward_back_addr.is_none() {
                "this orchestrator has no agent-link listen address configured (SANDY_MESH_AGENT_LINK_LISTEN is unset) \
                 — no remote placement is reachable at all, regardless of what hosts are registered"
                    .to_owned()
            } else if credential_request.is_some() {
                credential_placement_refusal()
            } else if require_local {
                format!(
                    "no registered host declares shares_submitter_filesystem; this Submit names a `{path_field_name}` \
                     path, which is only ever valid on the submitter's own filesystem"
                )
            } else {
                "no registered host declares the required isolation class and sandbox kind; this job cannot be placed \
                 (this daemon has no local fallback for a Vm-backend or Untrusted-class job)"
                    .to_owned()
            };
            if let Some(control_error) = placement_required_error(
                required_isolation_class,
                required_sandbox_kind,
                require_local,
                placeable,
                &placement_reason,
            ) {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(control_error)),
                });
            }

            let job_id = Uuid::new_v4().to_string();
            let manifest = submit.manifest;
            let encoding = submit.manifest_encoding;
            let inserted_id = job_id.clone();
            let store_for_token = Arc::clone(store);
            // Cloned before `store` itself is moved into the `insert_pending`
            // spawn_blocking below (#292's silent-Pending family): if the
            // placed dispatch can't actually be delivered, the failure branch
            // near the end of this arm needs its own store handle to fail the
            // job terminally instead of leaving it silently `Pending`.
            let store_for_dispatch_failure = Arc::clone(store);
            let store_for_archive = Arc::clone(store);
            let store = Arc::clone(store);

            // #327: a durable, re-presentable credential — independent of
            // CF-H-1's per-connection `session` below — so a LATER `sandy
            // daemon attach` invocation (a fresh connection, the realistic
            // "log back into my own job" case) can still prove it's the
            // submitter; `session_matches` alone never recognizes that case,
            // since a fresh connection always mints a fresh session.
            // Since #540 the token is also the only way to cancel the job, so an RNG failure refuses the
            // whole Submit (below) rather than leaving an uncancellable job.
            let attach_token = {
                let mut bytes = [0u8; ATTACH_TOKEN_LEN];
                match getrandom::fill(&mut bytes) {
                    Ok(()) => bytes.to_vec(),
                    Err(e) => {
                        // Cancel needs this token (#540), so a job without one could never be cancelled:
                        // refuse the Submit instead, before any side effect.
                        tracing::warn!(error = %e, job_id, "could not mint a durable attach token; refusing the submit");
                        return Ok(ControlResponse {
                            request_id: request.request_id,
                            result: Some(control_response::Result::Error(ControlError {
                                message: "could not mint a durable attach token; submit refused".to_owned(),
                            })),
                        });
                    }
                }
            };

            // Mint the job's dedicated channel + caps BEFORE the row is
            // persisted (#212 B2, adversarial): if minting faulted after the
            // row was already written, the row would be stranded `Pending`
            // with no channel, and `Attach` would misreport it as
            // "restarted since submit?" instead of surfacing the real fault.
            let mut job_channel = dispatch::mint_job_channel(&job_id, registry.authority()).await?;
            job_channel.granted_caps = granted_caps;
            job_channel.session = session; // CF-H-1

            // Placement (#298, #381): dispatch to a registered remote host
            // whose declared capabilities satisfy this job's OWN required
            // isolation class, if the orchestrator's own agent-link accept
            // address is configured (no address means no remote run is even
            // reachable, regardless of what's registered) and such a host
            // exists; run locally otherwise — today's unchanged behavior for
            // a `Trusted`+`Process` job (an `Untrusted` job with no host is
            // refused outright instead, see `placement_required_error`
            // below). Binding the remote link (decision 6) happens BEFORE the
            // job is persisted/registered, so a placed job's `remote_link` is
            // set from the moment anyone can observe it; the actual
            // `send_dispatch` call happens after, once the job is durably
            // recorded.
            let dispatch_plan = forward_back_addr.and_then(|forward_back| {
                let candidate = host_registry.pick_host_for(
                    required_isolation_class.into(),
                    required_sandbox_kind.into(),
                    require_local,
                )?;
                // The data link exists only for a host that declared `transfer`
                // and a job that names inputs or outputs (#482 decision 22): an
                // executor that dials on a non-empty token would otherwise
                // connect and wait for a transfer that never comes.
                let wants_data_link =
                    candidate.capabilities.transfer && (!path_inputs.is_empty() || !path_outputs.is_empty());
                let minted = RemoteLink::new(candidate.peer_ip).and_then(|link| {
                    let data_link = wants_data_link
                        .then(|| RemoteLink::new(candidate.peer_ip))
                        .transpose()?;
                    Ok((link, data_link))
                });
                match minted {
                    Ok((link, data_link)) => {
                        let link_token = link.token().as_bytes().to_vec();
                        let data_link_token = data_link
                            .as_ref()
                            .map(|l| l.token().as_bytes().to_vec())
                            .unwrap_or_default();
                        job_channel.remote_link = Some(link);
                        job_channel.data_inputs = if data_link.is_some() {
                            path_inputs.clone()
                        } else {
                            Vec::new()
                        };
                        job_channel.data_outputs = if data_link.is_some() {
                            path_outputs.clone()
                        } else {
                            Vec::new()
                        };
                        job_channel.data_link = data_link;
                        job_channel.host_id = Some(candidate.host_id.clone());
                        let dispatch = Dispatch {
                            job_id: job_id.clone(),
                            manifest: manifest.clone(),
                            manifest_encoding: encoding.clone(),
                            // The submission's OWN required kind (#332), not
                            // merely whatever the picked host happens to
                            // support: `supported_sandbox_kinds` is a SET, so
                            // a host can qualify for a placement by
                            // supporting MORE than the one kind this specific
                            // job actually needs.
                            backend: required_sandbox_kind.into(),
                            link_token,
                            forward_back: forward_back.to_string(),
                            required_isolation_class: required_isolation_class.into(),
                            // Safe to forward unconditionally (#496): `candidate`
                            // only exists because `pick_host_for` was called with
                            // `require_local`, which already filtered on
                            // `shares_submitter_filesystem` for a Submit that
                            // actually carries any of these — a non-local pick
                            // only ever happens when all three were empty to
                            // begin with.
                            inputs: path_inputs.clone(),
                            outputs: path_outputs.clone(),
                            secrets: path_secrets.clone(),
                            data_link_token,
                            egress: None,
                        };
                        Some((candidate.host_id, candidate.registration, dispatch))
                    }
                    Err(e) => {
                        // The OS RNG is unavailable — vanishingly rare.
                        // Placement is best-effort for `argv/v1`: that job
                        // still submits and runs locally. A `flake/v1` job
                        // has no local fallback, so the check right after
                        // this closure refuses the whole Submit instead —
                        // never claim "running locally" here, since that is
                        // only true for one of the two kinds.
                        tracing::warn!(error = %e, job_id, "could not mint a remote link token");
                        None
                    }
                }
            });

            // #332, closing CodeRabbit's finding on this PR: the early check
            // above is necessarily a pre-check against the SAME registry
            // state `dispatch_plan` itself then re-reads — a host
            // disconnecting between the two `pick_host_for` calls, or
            // `RemoteLink::new`'s RNG failing just above, can still leave a
            // `Vm` job's `dispatch_plan` empty here. Refuse before
            // `insert_pending`, same "no trace" bar as every other Submit-time
            // refusal in this function (CF-M-2's `CapExceeded` below discards
            // a minted link exactly this way) — never insert a `flake/v1` job
            // that would then sit `Pending` forever with no local fallback
            // and no distinct status a caller could ever notice.
            let dispatch_plan_reason = if credential_request.is_some() {
                credential_placement_refusal()
            } else if require_local {
                format!(
                    "no registered host declaring shares_submitter_filesystem could be bound for this job's \
                     `{path_field_name}` path"
                )
            } else {
                "no registered host could be bound for this job's required isolation class and sandbox kind; it cannot \
                 be placed (this daemon has no local fallback for a Vm-backend or Untrusted-class job)"
                    .to_owned()
            };
            if let Some(control_error) = placement_required_error(
                required_isolation_class,
                required_sandbox_kind,
                require_local,
                dispatch_plan.is_some(),
                &dispatch_plan_reason,
            ) {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(control_error)),
                });
            }

            // #481: mint the job's credential last among the Submit-time steps that
            // can refuse, and before anything is persisted or dispatched. A mint
            // failure refuses the Submit: no host ever runs this job without its
            // token. The bracket revokes on drop, so any early return below
            // before `adopt` still cannot leak the token.
            let mut dispatch_plan = dispatch_plan;
            let job_credential = match (&credential_request, registry.credentials()) {
                (Some((name, capabilities)), Some(credentials)) => {
                    let (credentials, name_for_mint, capabilities) =
                        (Arc::clone(credentials), name.clone(), capabilities.clone());
                    match tokio::task::spawn_blocking(move || credentials.mint(&name_for_mint, &capabilities)).await? {
                        Ok(bracket) => Some(bracket),
                        Err(reason) => {
                            tracing::warn!(job_id, credential = ?name, error = %reason, "credential mint failed; refusing the submit");
                            return Ok(ControlResponse {
                                request_id: request.request_id,
                                result: Some(control_response::Result::Error(ControlError {
                                    message: format!(
                                        "credential {name:?} mint failed, so the Submit is refused and nothing was \
                                         dispatched: {reason}"
                                    ),
                                })),
                            });
                        }
                    }
                }
                _ => None,
            };
            if let (Some(bracket), Some((_, _, dispatch))) = (&job_credential, dispatch_plan.as_mut()) {
                // The path only: the token stays in the file (decision 37).
                if let sandy::SecretSource::File(path) = bracket.secret_ref().source {
                    dispatch.secrets.push(sandy_executor_proto::SecretRef {
                        name: CREDENTIAL_SECRET_NAME.to_owned(),
                        host_path: path.display().to_string(),
                    });
                }
            }

            let insert_outcome =
                tokio::task::spawn_blocking(move || store.insert_pending(&inserted_id, &manifest, &encoding)).await??;
            // CF-M-2: a capacity refusal must leave no trace, same as every
            // other Submit-time refusal above — never registered, never
            // dispatched, even though `dispatch_plan` may already have minted
            // a remote link above (cheap to discard, nothing observed it).
            if let InsertOutcome::CapExceeded { max } = insert_outcome {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(ControlError {
                        message: format!(
                            "the job store is at its {max}-row capacity (SANDY_MAX_JOBS); terminal jobs are not \
                             pruned, so an operator must clear old rows before new submits can succeed"
                        ),
                    })),
                });
            }
            // The job now exists: it owns the credential until a terminal path
            // releases it.
            // Whether this job's archive needs redacting is decided now, not when the
            // archive arrives: it can arrive after a terminal path released the credential.
            let credentialed = job_credential.is_some();
            if let (Some(bracket), Some(credentials)) = (job_credential, registry.credentials()) {
                credentials.adopt(&job_id, bracket);
            }

            // Best-effort: the job is already durably submitted, so a faulted write here is logged, not a
            // reason to fail the Submit. KNOWN GAP (#540): such a job has no stored token, so it can never
            // be cancelled through this RPC (decision 23). Rare: it needs the store write to fail right
            // after the job insert succeeded.
            if !attach_token.is_empty() {
                let token_job_id = job_id.clone();
                let token = attach_token.clone();
                match tokio::task::spawn_blocking(move || store_for_token.set_attach_token(&token_job_id, &token)).await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, job_id, "could not persist the durable attach token for this job");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, job_id, "the attach-token persistence task panicked");
                    }
                }
            }

            // #340 item 4: persist the agent's eventual archived transcript
            // into the durable job store, independent of whether anyone ever
            // attaches to see it live (see `dispatch::persist_archive_when_posted`'s
            // own doc for why the in-memory channel/registry alone isn't
            // enough). Best-effort and fire-and-forget: its own failure
            // paths are all silent-and-logged, never a reason to fail this
            // Submit.
            tokio::spawn(dispatch::persist_archive_when_posted(
                Arc::clone(&job_channel.channel),
                job_channel.archiver_cap.clone(),
                job_id.clone(),
                store_for_archive,
                dispatch::ARCHIVE_WAIT_BOUND,
                registry.credentials().filter(|_| credentialed).cloned(),
            ));

            registry.insert(job_id.clone(), job_channel);

            if let Some((host_id, registration, dispatch)) = dispatch_plan {
                // Best-effort: the job is already durably submitted above,
                // so a failed dispatch (e.g. the host disconnected between
                // being picked and this send — a narrow TOCTOU) leaves it
                // Pending rather than failing Submit for a placement
                // decision the caller never asked to observe directly.
                // `send_dispatch_if_current` (not plain `send_dispatch`)
                // refuses if `host_id` has since been reclaimed by a
                // different connection than the one actually picked.
                //
                // CAUTION (#289): this `.await` is undeadlined — it blocks
                // on the host's bounded (capacity 8) dispatch channel, which
                // backs up exactly when `host_conn`'s own `write_frame` to
                // that host stalls (a registered-but-not-reading peer). A
                // slow/hung host can therefore delay THIS Submit response
                // indefinitely, one layer above the write itself. #289 item
                // 2 (the write-frame deadline, same owner) bounds this
                // transitively: once that write times out and closes the
                // connection, this channel's receiver drops and a blocked
                // send here fails fast instead of hanging. Deferred to #289,
                // not fixed here.
                //
                // #292 item 3 (also closes #303 item 4, the same strand in a
                // different milestone): a failure here — `RegistrationChanged`
                // or any other `DispatchSendError` — used to leave the job
                // silently `Pending` forever, with no re-placement attempt
                // and no distinct terminal status a caller could poll for.
                // Re-placement is set aside (it would need a fresh
                // `RemoteLink` bound to whatever host is current, not just a
                // resend): failing the job terminally instead is the
                // minimal fix that removes the silent-no-op, matching the
                // same "never silently" bar `host_conn`'s own
                // `fail_disconnected_job` already holds for a dispatch lost
                // after delivery.
                if let Err(e) = host_registry
                    .send_dispatch_if_current(&host_id, registration, dispatch)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        job_id,
                        host_id,
                        "could not dispatch the placed job to its host; failing it rather than leaving it silently Pending"
                    );
                    let reason = format!("could not dispatch to the placed host-executor: {e}");
                    let fail_job_id = job_id.clone();
                    let store = Arc::clone(&store_for_dispatch_failure);
                    match tokio::task::spawn_blocking(move || {
                        store.finish(&fail_job_id, JobStatus::Failed, None, &reason)
                    })
                    .await
                    {
                        Ok(Ok(Transition::Applied)) => registry.mark_terminal(&job_id),
                        Ok(Ok(other)) => {
                            tracing::warn!(
                                job_id,
                                ?other,
                                "could not fail the undelivered job: unexpected transition"
                            )
                        }
                        Ok(Err(e)) => tracing::warn!(job_id, error = %e, "could not fail the undelivered job"),
                        Err(e) => tracing::warn!(job_id, error = %e, "the fail-undelivered-job store task panicked"),
                    }
                    // #481: the dispatch never reached a host, so nothing will
                    // ever use this job's credential.
                    registry.release_credential(&job_id);
                    // The dispatch never reached the host either way (the
                    // send itself failed), so the job's RemoteLink was never
                    // presented on the wire and must not stay claimable —
                    // job status alone doesn't gate authentication (#269).
                    registry.invalidate_remote_link(&job_id);
                }
            }

            control_response::Result::Submit(SubmitResponse { job_id, attach_token })
        }
        Some(control_request::Op::Cancel(cancel)) => {
            // #540 (owner decision on audit #391, 2026-10-29): Cancel is gated per job by the job's
            // `attach_token`, from any session. CF-H-1's old "audit trail, not a gate" no longer holds
            // for Cancel (Attach still uses `session_matches` as a hint, see below). Every refusal (no
            // token, a wrong one, another job's, a job with none stored, an unknown job id) returns the
            // one message, so a caller cannot probe which job ids exist or why it was refused. The
            // token is never logged.
            let authorized = match &cancel.attach_token {
                Some(presented) => {
                    let store = Arc::clone(store);
                    let job_id = cancel.job_id.clone();
                    // A store fault refuses like any other failure, with the one message.
                    let stored = match tokio::task::spawn_blocking(move || store.attach_token(&job_id)).await {
                        Ok(Ok(stored)) => stored,
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "cancel: reading the attach token failed");
                            None
                        }
                        Err(error) => {
                            tracing::warn!(%error, "cancel: the attach token read task failed");
                            None
                        }
                    };
                    stored.is_some_and(|stored| attach_tokens_match(&stored, presented))
                }
                None => false,
            };
            if !authorized {
                // The id is caller-supplied and unbounded: log a short escaped prefix only.
                let shown: String = cancel.job_id.chars().take(64).collect();
                tracing::info!(
                    job_id = ?shown,
                    token_presented = cancel.attach_token.is_some(),
                    "cancel refused: no matching attach token"
                );
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(ControlError {
                        message: CANCEL_REFUSED.to_owned(),
                    })),
                });
            }
            let job_id = cancel.job_id.clone();
            // Captured before mark_terminal/invalidate below, which touch
            // this same registry entry: read the placement while it's
            // certainly still there, rather than racing its own cleanup.
            let placed_host = registry.get(&cancel.job_id).and_then(|job| job.host_id.clone());
            let store = Arc::clone(store);
            let outcome = tokio::task::spawn_blocking(move || store.cancel(&job_id)).await??;
            match outcome {
                CancelOutcome::Cancelled => {
                    // #269 token-lifecycle: an unclaimed remote link must not
                    // outlive the job it was minted for. Logged distinctly
                    // from an ordinary already-claimed refusal so a reader
                    // sees "cancelled" here, not "double-claim attempted",
                    // if a late stream later presents this job's token.
                    tracing::info!(job_id = %cancel.job_id, "cancel: invalidating any unclaimed remote link");
                    registry.invalidate_remote_link(&cancel.job_id);
                    registry.mark_terminal(&cancel.job_id);
                    // #481: revoke the job's credential now, not when the host
                    // gets around to reporting.
                    registry.release_credential(&cancel.job_id);
                    // #477: the local store-cancel above only stops a late
                    // agent-link stream from claiming the run (decision 12's
                    // own residual-gap note). If the job was placed on a
                    // remote host, also reach its live RunControl there —
                    // best-effort, fire-and-forget: the local cancel already
                    // took effect regardless of whether this send succeeds,
                    // so a send failure (host disconnected, queue full) is
                    // logged, never surfaced as this RPC's own failure.
                    if let Some(host_id) = placed_host {
                        let host_registry = Arc::clone(host_registry);
                        let job_id = cancel.job_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = host_registry
                                .send_cancel(&host_id, sandy_executor_proto::Cancel { job_id: job_id.clone() })
                                .await
                            {
                                tracing::debug!(host_id, job_id, error = %e, "could not deliver Cancel to the host-executor");
                            }
                        });
                    }
                    control_response::Result::Cancel(CancelResponse {})
                }
                CancelOutcome::NotFound => control_response::Result::Error(ControlError {
                    message: format!("no such job: {}", cancel.job_id),
                }),
                CancelOutcome::AlreadyTerminal(status) => control_response::Result::Error(ControlError {
                    message: format!(
                        "job {} is already {}, cannot cancel",
                        cancel.job_id,
                        status.as_str_name()
                    ),
                }),
            }
        }
        Some(control_request::Op::Attach(attach)) => match registry.get(&attach.job_id) {
            Some(job) => {
                // CF-H-1, extended by #327: `session_matches` alone only ever
                // recognizes the submitter on the SAME connection Submit used
                // — the realistic case (`daemon submit` now, `daemon attach`
                // later from a fresh terminal) always mints a fresh session,
                // so it would never match there. The durable `attach_token`
                // `Submit` minted closes that: present it (from a fresh
                // connection/process, read back from wherever the CLI
                // persisted it) and it proves the same submitter regardless
                // of session. Either one is sufficient; the log line below is
                // still just an audit trail, never a refusal, on the one case
                // neither recognizes.
                let session_match = job.session_matches(session);
                let token_match = match &attach.attach_token {
                    Some(presented) => {
                        let stored = {
                            let store = Arc::clone(store);
                            let job_id = attach.job_id.clone();
                            tokio::task::spawn_blocking(move || store.attach_token(&job_id)).await??
                        };
                        stored.is_some_and(|stored| attach_tokens_match(&stored, presented))
                    }
                    None => false,
                };
                let is_submitter = session_match || token_match;
                if !is_submitter {
                    tracing::info!(
                        job_id = %attach.job_id,
                        submitted_session = %job.session,
                        requesting_session = %session,
                        token_presented = attach.attach_token.is_some(),
                        "attach from neither the submitting session nor a matching attach token"
                    );
                }
                // The submitter gets a freshly minted post-capable cap, never
                // the stored `job.agent_cap`: that cap's principal is the
                // real in-guest/host agent, and presenting the identical cap
                // bytes here would join as the SAME membership (membership is
                // keyed by the cap's own proof digest, `Channel::join`) —
                // sharing one cursor between the agent and an attaching
                // operator instead of two independent ones. A different
                // session still gets the existing observer-only cap minted
                // at Submit.
                // The broker's output collector (#643) gets a read-only cap of its own, one
                // that attach counting ignores. Only the token proves the submitter here: a
                // matching session alone does not.
                if attach.collector && !token_match {
                    return Ok(ControlResponse {
                        request_id: request.request_id,
                        result: Some(control_response::Result::Error(ControlError {
                            message: format!("job {}: a collector attach needs the attach token", attach.job_id),
                        })),
                    });
                }
                let attach_cap = if attach.collector {
                    registry
                        .authority()
                        .mint(CapScope {
                            peer: PeerId::from(dispatch::COLLECTOR_PEER),
                            channel: ChannelId::from(attach.job_id.as_str()),
                            rights: CapRights {
                                post: false,
                                read: true,
                                invite: false,
                            },
                            expires_at: None,
                        })
                        .map_err(dispatch::DispatchError::Cap)?
                } else if is_submitter {
                    registry
                        .authority()
                        .mint(CapScope {
                            peer: PeerId::from("operator"),
                            channel: ChannelId::from(attach.job_id.as_str()),
                            rights: CapRights {
                                post: true,
                                read: true,
                                invite: false,
                            },
                            expires_at: None,
                        })
                        .map_err(dispatch::DispatchError::Cap)?
                } else {
                    job.observer_cap.clone()
                };
                if cap_has_expired(&attach_cap) {
                    control_response::Result::Error(ControlError {
                        message: format!(
                            "job {}'s attach cap has expired; re-submit to get a new one",
                            attach.job_id
                        ),
                    })
                } else {
                    control_response::Result::Attach(AttachResponse {
                        channel_id: attach.job_id.clone(),
                        cap: encode_cap(&attach_cap)?,
                    })
                }
            }
            None => {
                // No live channel for this id. Distinguish "never existed"
                // from "existed but this daemon process doesn't hold its
                // channel anymore" (channels are process-local, never
                // persisted — a restart since submit loses them) rather than
                // reporting the same unhelpful message for both.
                let job_id = attach.job_id.clone();
                let store = Arc::clone(store);
                let known = tokio::task::spawn_blocking(move || store.status(&job_id)).await??;
                let message = match known {
                    Some(_) => format!(
                        "job {} has no live channel on this daemon (restarted since submit, or past its terminal \
                         retention window); re-submit to get a new one",
                        attach.job_id
                    ),
                    None => format!("no such job: {}", attach.job_id),
                };
                control_response::Result::Error(ControlError { message })
            }
        },
        Some(control_request::Op::Status(status_req)) => {
            let job_id = status_req.job_id.clone();
            let store = Arc::clone(store);
            // `detail`, not `status`: a terminal job now also carries the exit
            // code and console tail a remote run reported back (#292), surfaced
            // so `status` returns the terminal state AND the exit, not just the
            // lifecycle band.
            let detail = tokio::task::spawn_blocking(move || store.detail(&job_id)).await??;
            match detail {
                Some(detail) => control_response::Result::Status(StatusResponse {
                    job_id: status_req.job_id,
                    status: i32::from(detail.status),
                    exit_code: detail.exit_code,
                    console_tail: detail.console,
                }),
                None => control_response::Result::Error(ControlError {
                    message: format!("no such job: {}", status_req.job_id),
                }),
            }
        }
        Some(control_request::Op::List(_)) => {
            let store = Arc::clone(store);
            let summaries = tokio::task::spawn_blocking(move || store.list()).await??;
            control_response::Result::List(ListResponse {
                jobs: summaries
                    .into_iter()
                    .map(|s| WireJobSummary {
                        job_id: s.job_id,
                        status: s.status.into(),
                    })
                    .collect(),
            })
        }
        // Environment operations are routed to `crate::environment` by
        // `serve_connection` before this function is called.
        Some(
            control_request::Op::CreateEnvironment(_)
            | control_request::Op::GetEnvironment(_)
            | control_request::Op::ListEnvironments(_)
            | control_request::Op::StopEnvironment(_)
            | control_request::Op::ResumeEnvironment(_)
            | control_request::Op::CancelEnvironment(_)
            | control_request::Op::DeleteEnvironment(_),
        ) => control_response::Result::Error(ControlError {
            message: "environment operations are served by the environment handler, not the job handler".to_owned(),
        }),
        None => control_response::Result::Error(ControlError {
            message: "request carried no operation".to_owned(),
        }),
    };

    Ok(ControlResponse {
        request_id: request.request_id,
        result: Some(result),
    })
}

/// Whether `cap`'s expiry has passed. `Attach` must never hand back a cap the
/// client can't actually join with (#227 adversarial): `encode_cap` has no
/// way to know that, so the check lives here, at the one place that decides
/// whether to return the cap at all.
fn cap_has_expired(cap: &sandy_fabric::capauth::Cap) -> bool {
    let Some(expires_at) = cap.scope().expires_at else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    expires_at <= now
}

/// Constant-time comparison of a stored and a presented attach token (#327):
/// a wrong guess must not be narrowable byte-by-byte via response timing.
/// Mirrors `link_auth::LinkToken::matches`'s discipline; not shared code
/// since that type is fixed-size and specific to the remote-link seam, while
/// this compares plain, store-read `Vec<u8>`s.
fn attach_tokens_match(stored: &[u8], presented: &[u8]) -> bool {
    // An empty token is "no token": two empty slices must never count as a match (#540).
    if stored.is_empty() || stored.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in stored.iter().zip(presented.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::{AttachRequest, CancelRequest, JobStatus, ListRequest, StatusRequest, SubmitRequest};
    use sandy_fabric::{
        capauth::{CapAuthority, CapRights, CapScope},
        types::{ChannelId, PeerId},
    };
    use sandy_orchestrator::{CapRequest, JobEntrypoint};

    use super::*;

    fn full_rights() -> CapRights {
        CapRights {
            post: true,
            read: true,
            invite: true,
        }
    }

    fn read_only() -> CapRights {
        CapRights {
            read: true,
            ..CapRights::default()
        }
    }

    fn entrypoint() -> JobEntrypoint {
        JobEntrypoint {
            command: vec!["true".to_owned()],
        }
    }

    fn manifest_json(requested_caps: Vec<CapRequest>) -> Vec<u8> {
        serde_json::to_vec(&JobManifest {
            entrypoint: entrypoint(),
            requested_caps,
        })
        .expect("encode JobManifest")
    }

    fn submit_req_with_caps(id: u64, manifest: Vec<u8>, submitter_caps: Vec<Cap>) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest,
                manifest_encoding: MANIFEST_ENCODING_JSON.to_owned(),
                submitter_caps: submitter_caps
                    .iter()
                    .map(|c| encode_cap(c).expect("encode cap"))
                    .collect(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    fn new_store() -> Arc<JobStore> {
        Arc::new(JobStore::open_in_memory().expect("in-memory store"))
    }

    fn new_registry() -> Arc<JobRegistry> {
        Arc::new(JobRegistry::new().expect("getrandom for a test registry"))
    }

    /// A deterministic test fingerprint, not a real certificate digest.
    fn test_fp() -> sandy_conn::Fingerprint {
        sandy_conn::Fingerprint::from_hex(&"aa".repeat(32)).expect("64-char hex literal")
    }

    /// A registry whose terminal-retention sweep (#270) fires immediately,
    /// for tests that need to observe a job being reaped rather than wait
    /// out the real production default.
    fn new_registry_with_zero_retention() -> Arc<JobRegistry> {
        Arc::new(
            JobRegistry::new()
                .expect("getrandom for a test registry")
                .with_retention(std::time::Duration::ZERO),
        )
    }

    fn new_host_registry() -> Arc<HostRegistry> {
        Arc::new(HostRegistry::default())
    }

    /// A fresh per-call session id (CF-H-1), standing in for a distinct
    /// connection — most tests here don't care which session an op runs
    /// under, only that it doesn't change `handle`'s outcome, so each one
    /// gets its own rather than a single shared constant (incidentally
    /// realistic: `serve_connection` mints one per real connection too). The
    /// two tests that specifically cover same-/cross-session behavior pin
    /// their own `Uuid` instead of calling this.
    fn test_session() -> Uuid {
        Uuid::new_v4()
    }

    fn req(id: u64, op: control_request::Op) -> ControlRequest {
        ControlRequest {
            request_id: id,
            op: Some(op),
        }
    }

    fn submit_req(id: u64) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest: b"m".to_vec(),
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    #[tokio::test]
    async fn submit_persists_and_returns_a_job_id() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let response = handle(&store, &registry, &host_registry, None, test_session(), submit_req(1)).await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        assert_eq!(response.request_id, 1);
        assert_eq!(store.status(&job_id)?, Some(JobStatus::Pending));
        Ok(())
    }

    #[tokio::test]
    async fn status_of_an_unknown_job_is_a_control_error_not_a_default() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(
                1,
                control_request::Op::Status(StatusRequest {
                    job_id: "ghost".to_owned(),
                }),
            ),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Error(_))),
            "got {:?}",
            response.result
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancel_on_an_unknown_job_is_refused() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(
                1,
                control_request::Op::Cancel(CancelRequest {
                    job_id: "ghost".to_owned(),
                    attach_token: None,
                }),
            ),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Error(_))),
            "got {:?}",
            response.result
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_reflects_submitted_jobs() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        handle(&store, &registry, &host_registry, None, test_session(), submit_req(1)).await?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(2, control_request::Op::List(ListRequest {})),
        )
        .await?;
        let jobs = match response.result {
            Some(control_response::Result::List(ListResponse { jobs })) => jobs,
            other => anyhow::bail!("expected a List response, got {other:?}"),
        };
        assert_eq!(jobs.len(), 1);
        Ok(())
    }

    /// Positive (#212 B2): `Attach` on a job submitted in this same daemon
    /// process returns a real channel id and a cap that actually decodes.
    #[tokio::test]
    async fn attach_on_a_submitted_job_returns_a_real_channel_and_cap() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, test_session(), submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(
                2,
                control_request::Op::Attach(AttachRequest {
                    job_id: job_id.clone(),
                    attach_token: None,
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Attach(AttachResponse { channel_id, cap })) => {
                assert_eq!(channel_id, job_id);
                decode_cap(&cap).context("the attach cap must decode")?;
            }
            other => anyhow::bail!("expected an Attach response, got {other:?}"),
        }
        Ok(())
    }

    /// Positive (#327): `Attach` from the SAME session that submitted the job
    /// gets a post-capable cap back — "my own job, I can log into".
    #[tokio::test]
    async fn attach_from_the_submitting_session_gets_a_post_capable_cap() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let session = Uuid::new_v4();
        let submitted = handle(&store, &registry, &host_registry, None, session, submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            session,
            req(
                2,
                control_request::Op::Attach(AttachRequest {
                    job_id,
                    attach_token: None,
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Attach(AttachResponse { cap, .. })) => {
                let decoded = decode_cap(&cap).context("the attach cap must decode")?;
                let rights = decoded.scope().rights;
                assert!(
                    rights.post,
                    "the submitter's own attach must be post-capable, got {rights:?}"
                );
                assert!(
                    rights.read,
                    "the submitter's own attach must still be read-capable, got {rights:?}"
                );
            }
            other => anyhow::bail!("expected an Attach response, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial (#327): `Attach` from a DIFFERENT session than the one
    /// that submitted the job gets the existing observer-only cap back — read
    /// succeeds, post would be refused (proven at the channel level by
    /// `dispatch::tests::the_observer_cap_cannot_post`) — "someone else's job,
    /// I can only watch".
    #[tokio::test]
    async fn attach_from_a_different_session_gets_observer_rights_only() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, Uuid::new_v4(), submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            Uuid::new_v4(), // a different session than the one that submitted
            req(
                2,
                control_request::Op::Attach(AttachRequest {
                    job_id,
                    attach_token: None,
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Attach(AttachResponse { cap, .. })) => {
                let decoded = decode_cap(&cap).context("the attach cap must decode")?;
                assert_eq!(
                    decoded.scope().rights,
                    read_only(),
                    "a cross-session attach must be observer-only (read, no post), got {:?}",
                    decoded.scope().rights
                );
            }
            other => anyhow::bail!("expected an Attach response, got {other:?}"),
        }
        Ok(())
    }

    /// Positive (#327, the realistic acceptance case): a DIFFERENT session
    /// presenting the durable `attach_token` `Submit` handed back is STILL
    /// post-capable — this is what closes the gap a plain cross-session
    /// attach (the test above, presenting no token) leaves open: `daemon
    /// submit` now, `daemon attach` later from a fresh terminal, is exactly
    /// "a different session presenting the right token."
    #[tokio::test]
    async fn attach_from_a_different_session_with_the_right_token_is_still_post_capable() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, Uuid::new_v4(), submit_req(1)).await?;
        let (job_id, attach_token) = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, attach_token })) => (job_id, attach_token),
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        assert!(
            !attach_token.is_empty(),
            "Submit must mint a durable attach token for this test to mean anything"
        );

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            Uuid::new_v4(), // a different session than the one that submitted
            req(
                2,
                control_request::Op::Attach(AttachRequest {
                    job_id,
                    attach_token: Some(attach_token),
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Attach(AttachResponse { cap, .. })) => {
                let decoded = decode_cap(&cap).context("the attach cap must decode")?;
                let rights = decoded.scope().rights;
                assert!(
                    rights.post,
                    "a different session presenting the right attach token must still be post-capable, got {rights:?}"
                );
            }
            other => anyhow::bail!("expected an Attach response, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial (#327): a DIFFERENT session presenting a WRONG token (not
    /// merely an absent one) still gets observer-only rights, not refused
    /// outright — a guessed/forged token is simply not recognized, same as
    /// presenting none at all.
    #[tokio::test]
    async fn attach_from_a_different_session_with_a_wrong_token_is_still_observer_only() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, Uuid::new_v4(), submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            Uuid::new_v4(),
            req(
                2,
                control_request::Op::Attach(AttachRequest {
                    job_id,
                    attach_token: Some(vec![0xAA; 32]),
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Attach(AttachResponse { cap, .. })) => {
                let decoded = decode_cap(&cap).context("the attach cap must decode")?;
                assert_eq!(
                    decoded.scope().rights,
                    read_only(),
                    "a wrong token must not grant post rights, got {:?}",
                    decoded.scope().rights
                );
            }
            other => anyhow::bail!("expected an Attach response, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial (#212): `Attach` on a job id that was never submitted is
    /// refused by name, never a fabricated channel.
    #[tokio::test]
    async fn attach_on_an_unknown_job_is_refused_not_fabricated() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(
                1,
                control_request::Op::Attach(AttachRequest {
                    job_id: "never-submitted".to_owned(),
                    attach_token: None,
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("no such job"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial: a job that exists in the durable store but whose channel
    /// isn't in THIS registry (simulating a daemon restart, since channels
    /// are process-local and never persisted) is refused with a message
    /// distinguishing it from a truly unknown job — never a fabricated
    /// channel for a job this process can no longer actually serve.
    #[tokio::test]
    async fn attach_on_a_known_job_with_no_live_channel_names_the_gap() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        store.insert_pending("job-from-before-restart", b"m", "test/v1")?;

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(
                1,
                control_request::Op::Attach(AttachRequest {
                    job_id: "job-from-before-restart".to_owned(),
                    attach_token: None,
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("no live channel"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// Submits a job from `session` and returns its id and attach token.
    async fn submit_with_token(
        store: &Arc<crate::store::JobStore>,
        registry: &Arc<JobRegistry>,
        host_registry: &Arc<HostRegistry>,
        session: Uuid,
    ) -> anyhow::Result<(String, Vec<u8>)> {
        let submitted = handle(store, registry, host_registry, None, session, submit_req(1)).await?;
        match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse {
                job_id, attach_token, ..
            })) => Ok((job_id, attach_token)),
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        }
    }

    /// The broker's output collector (#643) asks for a cap of its own: read-only, a peer name no
    /// client holds, so attach counting and cursors never mix with a client's.
    #[tokio::test]
    async fn a_collector_attach_with_the_token_gets_the_dedicated_read_only_cap() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let (job_id, token) = submit_with_token(&store, &registry, &host_registry, Uuid::new_v4()).await?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            Uuid::new_v4(),
            req(
                2,
                control_request::Op::Attach(AttachRequest {
                    job_id,
                    attach_token: Some(token),
                    collector: true,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Attach(AttachResponse { cap, .. })) => {
                let decoded = decode_cap(&cap).context("the cap must decode")?;
                assert_eq!(decoded.scope().peer.0, dispatch::COLLECTOR_PEER);
                assert!(decoded.scope().rights.read && !decoded.scope().rights.post);
            }
            other => anyhow::bail!("expected an Attach response, got {other:?}"),
        }
        Ok(())
    }

    /// The collector cap needs proof of the submitter: no token, a wrong token, or the session
    /// alone is refused.
    #[tokio::test]
    async fn a_collector_attach_without_a_matching_token_is_refused() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let session = Uuid::new_v4();
        let (job_id, _token) = submit_with_token(&store, &registry, &host_registry, session).await?;
        for (session, token) in [(session, None), (Uuid::new_v4(), Some(b"wrong".to_vec()))] {
            let response = handle(
                &store,
                &registry,
                &host_registry,
                None,
                session,
                req(
                    2,
                    control_request::Op::Attach(AttachRequest {
                        job_id: job_id.clone(),
                        attach_token: token,
                        collector: true,
                    }),
                ),
            )
            .await?;
            assert!(
                matches!(response.result, Some(control_response::Result::Error(_))),
                "got {:?}",
                response.result
            );
        }
        Ok(())
    }

    /// Adversarial (#227): `Attach` must never hand back a cap the client
    /// can't actually join with — an expired observer cap is refused by
    /// name, not encoded and returned as if it still worked.
    #[tokio::test]
    async fn attach_refuses_an_expired_observer_cap() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, test_session(), submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let job = registry.get(&job_id).context("the submitted job must be registered")?;
        let mut expired_cap = job.observer_cap.clone();
        expired_cap.scope_mut().expires_at = Some(0); // the distant past
        registry.insert(
            job_id.clone(),
            dispatch::JobChannel {
                channel: Arc::clone(&job.channel),
                agent_cap: job.agent_cap.clone(),
                observer_cap: expired_cap,
                archiver_cap: job.archiver_cap.clone(),
                remote_link: None,
                data_link: None,
                data_inputs: Vec::new(),
                data_outputs: Vec::new(),
                outputs: crate::output_slot::OutputsSlot::new(),
                granted_caps: job.granted_caps.clone(),
                session: job.session,
                host_id: job.host_id.clone(),
                attach_tracking: std::sync::Mutex::new(dispatch::AttachTracking::default()),
            },
        );

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(
                2,
                control_request::Op::Attach(AttachRequest {
                    job_id: job_id.clone(),
                    attach_token: None,
                    collector: false,
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("expired"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// Regression (#269 token-lifecycle): cancelling a job through the
    /// control-request path, not just through `JobRegistry` directly, must
    /// invalidate its remote link so a late-arriving stream can never claim
    /// it afterward.
    #[tokio::test]
    async fn cancel_invalidates_the_jobs_remote_link() -> anyhow::Result<()> {
        use crate::link_auth::{LinkAuthError, RemoteLink};

        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, test_session(), submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let job = registry.get(&job_id).context("the submitted job must be registered")?;
        let executor_ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let link = RemoteLink::new(executor_ip)?;
        let token = *link.token().as_bytes();
        registry.insert(
            job_id.clone(),
            dispatch::JobChannel {
                channel: Arc::clone(&job.channel),
                agent_cap: job.agent_cap.clone(),
                observer_cap: job.observer_cap.clone(),
                archiver_cap: job.archiver_cap.clone(),
                remote_link: Some(link),
                data_link: None,
                data_inputs: Vec::new(),
                data_outputs: Vec::new(),
                outputs: crate::output_slot::OutputsSlot::new(),
                granted_caps: job.granted_caps.clone(),
                session: job.session,
                host_id: job.host_id.clone(),
                attach_tracking: std::sync::Mutex::new(dispatch::AttachTracking::default()),
            },
        );

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(2, cancel_authed(&store, &job_id)),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Cancel(_))),
            "got {:?}",
            response.result
        );

        match registry.authenticate_remote_link(&job_id, executor_ip, &token) {
            Err(e) => assert_eq!(e, LinkAuthError::AlreadyClaimed),
            Ok(_) => panic!("a cancelled job's remote link must not authenticate a late-arriving stream"),
        }
        Ok(())
    }

    /// #477: a Cancel for a job already placed on a remote host reaches that
    /// host's own connection — not just the local store/registry bookkeeping
    /// `cancel_invalidates_the_jobs_remote_link` above already covers.
    #[tokio::test]
    async fn cancel_reaches_a_registered_remote_hosts_connection() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let allowlist = crate::host_registry::ExecutorAllowlist::new([(peer_ip, test_fp())]);
        // Keep the whole `Registration` alive, not just `cancel_rx`: dropping
        // `dispatch_rx` would close that channel immediately, failing the
        // Submit's own dispatch send before this test ever gets to Cancel.
        let registration = host_registry
            .register(
                &allowlist,
                peer_ip,
                test_fp(),
                "remote-host".to_owned(),
                trusted_host_capabilities(),
            )
            .expect("register a test host");
        let mut cancel_rx = registration.cancel_rx;
        let _dispatch_rx = registration.dispatch_rx;

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let submitted = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        let job = registry.get(&job_id).context("the submitted job must be registered")?;
        assert_eq!(
            job.host_id.as_deref(),
            Some("remote-host"),
            "the job must actually be placed on the registered host for this test to mean anything"
        );

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(2, cancel_authed(&store, &job_id)),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Cancel(_))),
            "got {:?}",
            response.result
        );

        let cancel = tokio::time::timeout(std::time::Duration::from_secs(5), cancel_rx.recv())
            .await
            .context("timed out waiting for the Cancel to reach the host")?
            .context("the host's cancel channel closed before receiving anything")?;
        assert_eq!(cancel.job_id, job_id);
        Ok(())
    }

    /// #270: Cancel must call `JobRegistry::mark_terminal`, not just
    /// invalidate the remote link above — otherwise a cancelled job's
    /// channel would never be reaped by the registry's retention sweep.
    #[tokio::test]
    async fn cancel_marks_the_job_terminal_for_the_registrys_retention_sweep() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry_with_zero_retention(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, test_session(), submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(2, cancel_authed(&store, &job_id)),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Cancel(_))),
            "got {:?}",
            response.result
        );

        // A second Submit's insert is what the sweep is tied to (#270).
        handle(&store, &registry, &host_registry, None, test_session(), submit_req(3)).await?;

        assert!(
            registry.get(&job_id).is_none(),
            "a cancelled job's channel must be reaped once retention elapses"
        );
        Ok(())
    }

    // ---- CF-H-1 (session audit trail) ----

    /// A Cancel on the SAME session that submitted the job succeeds, exactly
    /// as it always did — and `handle`'s Submit arm really did record that
    /// session on the job, not leave `session` at its `Uuid::nil()` default
    /// (the one thing none of this section's other tests, which all use a
    /// fresh `test_session()` per call, would ever catch).
    #[tokio::test]
    async fn a_same_session_submit_then_cancel_succeeds_and_session_is_recorded() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let session = Uuid::new_v4();
        let submitted = handle(&store, &registry, &host_registry, None, session, submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let job = registry.get(&job_id).context("the submitted job must be registered")?;
        assert!(
            job.session_matches(session),
            "Submit must record the submitting session"
        );
        assert!(!job.session_matches(Uuid::new_v4()), "a fresh session must not match");

        let cancelled = handle(
            &store,
            &registry,
            &host_registry,
            None,
            session,
            req(2, cancel_authed(&store, &job_id)),
        )
        .await?;
        assert!(
            matches!(cancelled.result, Some(control_response::Result::Cancel(_))),
            "got {:?}",
            cancelled.result
        );
        Ok(())
    }

    /// A Cancel on a DIFFERENT session than the one that submitted the job
    /// still succeeds — this is an audit trail, not an access-control gate
    /// (see `handle`'s own doc on `session`; the real gate is the separate B6
    /// work). The mismatch itself is proven directly via
    /// `JobChannel::session_matches` in `dispatch.rs`; this only proves
    /// `handle` doesn't let it change the outcome.
    /// A `Cancel` carrying the job's own stored attach token: what a client that kept the token from
    /// `Submit` sends (#540).
    fn cancel_authed(store: &JobStore, job_id: &str) -> control_request::Op {
        let attach_token = store.attach_token(job_id).ok().flatten();
        control_request::Op::Cancel(CancelRequest {
            job_id: job_id.to_owned(),
            attach_token,
        })
    }

    fn cancel_with(job_id: &str, attach_token: Option<Vec<u8>>) -> control_request::Op {
        control_request::Op::Cancel(CancelRequest {
            job_id: job_id.to_owned(),
            attach_token,
        })
    }

    /// Submit one job; return its id and the attach token `Submit` handed back.
    async fn submit_job(
        store: &Arc<JobStore>,
        registry: &Arc<JobRegistry>,
        host_registry: &Arc<HostRegistry>,
    ) -> anyhow::Result<(String, Vec<u8>)> {
        let submitted = handle(store, registry, host_registry, None, Uuid::new_v4(), submit_req(1)).await?;
        match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse {
                job_id, attach_token, ..
            })) => Ok((job_id, attach_token)),
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        }
    }

    async fn cancel_message(
        deps: (&Arc<JobStore>, &Arc<JobRegistry>, &Arc<HostRegistry>),
        op: control_request::Op,
    ) -> anyhow::Result<Result<(), String>> {
        let response = handle(deps.0, deps.1, deps.2, None, Uuid::new_v4(), req(2, op)).await?;
        match response.result {
            Some(control_response::Result::Cancel(_)) => Ok(Ok(())),
            Some(control_response::Result::Error(e)) => Ok(Err(e.message)),
            other => anyhow::bail!("unexpected Cancel response {other:?}"),
        }
    }

    /// #540 (owner decision on audit #391): Cancel is gated by the job's attach token, from any session.
    #[tokio::test]
    async fn a_cancel_with_the_jobs_attach_token_succeeds_from_any_session() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let (job_id, token) = submit_job(&store, &registry, &host_registry).await?;
        let outcome = cancel_message((&store, &registry, &host_registry), cancel_with(&job_id, Some(token))).await?;
        assert_eq!(outcome, Ok(()));
        Ok(())
    }

    /// The refusal cases all answer with one message, and each leaves the job cancellable: a refused
    /// cancel must change nothing.
    #[tokio::test]
    async fn a_cancel_without_a_valid_token_is_refused_the_same_way_and_changes_nothing() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let (job_id, token) = submit_job(&store, &registry, &host_registry).await?;
        let (other_id, other_token) = submit_job(&store, &registry, &host_registry).await?;
        let deps = (&store, &registry, &host_registry);

        let mut wrong = token.clone();
        wrong[0] ^= 0xff;
        let refusals = [
            cancel_message(deps, cancel_with(&job_id, None)).await?,
            cancel_message(deps, cancel_with(&job_id, Some(wrong))).await?,
            cancel_message(deps, cancel_with(&job_id, Some(Vec::new()))).await?,
            cancel_message(deps, cancel_with(&job_id, Some(other_token))).await?,
            cancel_message(deps, cancel_with("ghost", Some(token.clone()))).await?,
            cancel_message(deps, cancel_with("ghost", None)).await?,
        ];
        let first = refusals[0].clone().expect_err("a cancel with no token must be refused");
        for refusal in &refusals {
            assert_eq!(refusal.as_ref().expect_err("must be refused"), &first);
        }
        // The message names neither the job, its state, nor any token.
        assert!(
            !first.contains(&job_id) && !first.contains("ghost") && !first.contains("PENDING"),
            "{first}"
        );

        // Nothing changed: both jobs still cancel with their own tokens.
        assert_eq!(cancel_message(deps, cancel_with(&job_id, Some(token))).await?, Ok(()));
        let (_, other_token) = (
            other_id.clone(),
            store.attach_token(&other_id)?.context("stored token")?,
        );
        assert_eq!(
            cancel_message(deps, cancel_with(&other_id, Some(other_token))).await?,
            Ok(())
        );
        Ok(())
    }

    /// An empty stored token (a hand-edited row, a legacy migration) must never match an empty presented
    /// one: that would let any caller cancel the job.
    #[test]
    fn two_empty_tokens_never_match() {
        assert!(!attach_tokens_match(&[], &[]));
        assert!(!attach_tokens_match(&[], &[1]));
        assert!(attach_tokens_match(&[1, 2], &[1, 2]));
        assert!(!attach_tokens_match(&[1, 2], &[1, 3]));
    }

    #[tokio::test]
    async fn a_job_whose_stored_token_is_empty_cannot_be_cancelled_with_an_empty_token() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let (job_id, token) = submit_job(&store, &registry, &host_registry).await?;
        store.set_attach_token(&job_id, &[])?;
        let deps = (&store, &registry, &host_registry);
        for presented in [Some(Vec::new()), Some(token), None] {
            let outcome = cancel_message(deps, cancel_with(&job_id, presented)).await?;
            assert!(
                outcome.is_err(),
                "a job with no usable stored token must refuse every cancel"
            );
        }
        Ok(())
    }

    /// A refused cancel must not reach the host-executor either.
    #[tokio::test]
    async fn a_refused_cancel_sends_nothing_to_the_host() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.9".parse().context("peer ip literal")?;
        let allowlist = crate::host_registry::ExecutorAllowlist::new([(peer_ip, test_fp())]);
        let registration = host_registry
            .register(
                &allowlist,
                peer_ip,
                test_fp(),
                "remote-host".to_owned(),
                trusted_host_capabilities(),
            )
            .expect("register a test host");
        let mut cancel_rx = registration.cancel_rx;
        let _dispatch_rx = registration.dispatch_rx;
        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let submitted = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            Uuid::new_v4(),
            submit_req(1),
        )
        .await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        anyhow::ensure!(
            registry.get(&job_id).and_then(|j| j.host_id.clone()).as_deref() == Some("remote-host"),
            "the job must be placed on the host for this test to mean anything"
        );
        let refused = cancel_message((&store, &registry, &host_registry), cancel_with(&job_id, None)).await?;
        assert!(refused.is_err());
        let sent = tokio::time::timeout(std::time::Duration::from_millis(300), cancel_rx.recv()).await;
        assert!(
            sent.is_err(),
            "a refused cancel must not send a Cancel to the host, got {sent:?}"
        );
        Ok(())
    }

    // ---- Decision C-at-Submit (#226) ----

    /// Positive: a submitter holding `full_rights` on a channel can submit a
    /// job requesting a strictly narrower right there; the job is accepted.
    #[tokio::test]
    async fn a_submitter_holding_a_cap_can_submit_a_job_requesting_a_narrower_right() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitter_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: full_rights(),
            expires_at: None,
        })?;
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: read_only(),
        }]);

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_with_caps(1, manifest, vec![submitter_cap]),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );
        Ok(())
    }

    /// Positive: requesting EXACTLY what the submitter holds (not just
    /// strictly narrower) is also accepted — decision C bounds at-or-below,
    /// not strictly-below.
    #[tokio::test]
    async fn a_submitter_can_submit_a_job_requesting_exactly_what_they_hold() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitter_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: read_only(),
            expires_at: None,
        })?;
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: read_only(),
        }]);

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_with_caps(1, manifest, vec![submitter_cap]),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );
        Ok(())
    }

    /// Adversarial: a manifest requesting MORE than the submitter holds is
    /// refused outright — never a silent narrowing to what it held, and no
    /// job is created (checked via `list` staying empty).
    #[tokio::test]
    async fn a_request_exceeding_the_submitters_held_rights_refuses_the_whole_submit() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitter_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: read_only(),
            expires_at: None,
        })?;
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: full_rights(),
        }]);

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_with_caps(1, manifest, vec![submitter_cap]),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("refused"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }

        let list = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(2, control_request::Op::List(ListRequest {})),
        )
        .await?;
        match list.result {
            Some(control_response::Result::List(ListResponse { jobs })) => {
                assert!(jobs.is_empty(), "a refused submit must create no job: {jobs:?}");
            }
            other => anyhow::bail!("expected a List response, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial: a submitter with no cap at all for the requested channel
    /// is refused that capability, not granted one anyway.
    #[tokio::test]
    async fn a_submitter_with_no_cap_on_the_requested_channel_is_refused() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitter_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("some-other-channel"),
            rights: full_rights(),
            expires_at: None,
        })?;
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: read_only(),
        }]);

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_with_caps(1, manifest, vec![submitter_cap]),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("refused"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial: a forged submitter cap (tampered proof) refuses the whole
    /// submit — `attenuate`'s own re-verify catches it, not trusted blind
    /// because it arrived in `submitter_caps`.
    #[tokio::test]
    async fn a_forged_submitter_cap_refuses_the_whole_submit() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let mut forged_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: full_rights(),
            expires_at: None,
        })?;
        forged_cap.proof_mut()[0] ^= 0xFF; // tamper the proof
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: read_only(),
        }]);

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_with_caps(1, manifest, vec![forged_cap]),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("refused"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial: an expired submitter cap refuses the whole submit, the
    /// same as a forged one — `attenuate` re-verifies expiry too.
    #[tokio::test]
    async fn an_expired_submitter_cap_refuses_the_whole_submit() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let expired_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: full_rights(),
            expires_at: Some(0), // the distant past
        })?;
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: read_only(),
        }]);

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_with_caps(1, manifest, vec![expired_cap]),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("refused"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial: a revoked submitter cap refuses the whole submit — the
    /// same `attenuate` re-verify that catches forged/expired caps also
    /// catches revocation.
    #[tokio::test]
    async fn a_revoked_submitter_cap_refuses_the_whole_submit() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: full_rights(),
            expires_at: None,
        })?;
        registry.authority().revoke(&cap);
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: read_only(),
        }]);

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_with_caps(1, manifest, vec![cap]),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("refused"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial: a submitter presents caps, but the manifest's
    /// `manifest_encoding` is one `sandyd` doesn't understand — the caps must
    /// never be silently ignored (which would waive the bounding the
    /// submitter explicitly opted into); the whole submit is refused instead.
    #[tokio::test]
    async fn presented_caps_with_an_unrecognized_manifest_encoding_refuse_the_submit() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitter_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: full_rights(),
            expires_at: None,
        })?;
        let request = req(
            1,
            control_request::Op::Submit(SubmitRequest {
                manifest: b"opaque".to_vec(),
                manifest_encoding: "application/octet-stream".to_owned(),
                submitter_caps: vec![encode_cap(&submitter_cap)?],
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        );

        let response = handle(&store, &registry, &host_registry, None, test_session(), request).await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("not understood"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// A direct-mint submit (no `submitter_caps`, the trusted-local-operator
    /// path, #226's policy: trust from the connection, not the frame) is
    /// completely unaffected by any of the above — unchanged from before this
    /// block, including an opaque, undecodable manifest.
    #[tokio::test]
    async fn a_direct_mint_submit_with_no_submitter_caps_is_unaffected() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let response = handle(&store, &registry, &host_registry, None, test_session(), submit_req(1)).await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );
        Ok(())
    }

    // ---- CF-M-1 (oversized manifest) ----

    /// Adversarial: a manifest over the size cap is refused outright, before
    /// decision C-at-Submit even runs — and, like that refusal, leaves no
    /// trace (checked via `list` staying empty).
    #[tokio::test]
    async fn an_oversized_manifest_refuses_the_submit_and_creates_no_job() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let oversized = vec![0u8; sandy_control_proto::MAX_MANIFEST_LEN as usize + 1];
        let request = req(
            1,
            control_request::Op::Submit(SubmitRequest {
                manifest: oversized,
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        );

        let response = handle(&store, &registry, &host_registry, None, test_session(), request).await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("exceeds"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }

        let list = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(2, control_request::Op::List(ListRequest {})),
        )
        .await?;
        match list.result {
            Some(control_response::Result::List(ListResponse { jobs })) => {
                assert!(jobs.is_empty(), "an oversized manifest must create no job: {jobs:?}");
            }
            other => anyhow::bail!("expected a List response, got {other:?}"),
        }
        Ok(())
    }

    /// Positive: a manifest at EXACTLY the cap is accepted — the limit is
    /// over, not at-or-over.
    #[tokio::test]
    async fn a_manifest_at_exactly_the_cap_succeeds() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let at_cap = vec![0u8; sandy_control_proto::MAX_MANIFEST_LEN as usize];
        let request = req(
            1,
            control_request::Op::Submit(SubmitRequest {
                manifest: at_cap,
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        );

        let response = handle(&store, &registry, &host_registry, None, test_session(), request).await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );
        Ok(())
    }

    // ---- Placement (#298) ----

    fn trusted_host_capabilities() -> sandy_executor_proto::Capabilities {
        sandy_executor_proto::Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
            shares_submitter_filesystem: false,
            transfer: false,
            egress_proxy: false,
        }
    }

    fn register_test_host(
        host_registry: &HostRegistry,
        host_id: &str,
        peer_ip: std::net::IpAddr,
        capabilities: sandy_executor_proto::Capabilities,
    ) -> tokio::sync::mpsc::Receiver<Dispatch> {
        let allowlist = crate::host_registry::ExecutorAllowlist::new([(peer_ip, test_fp())]);
        host_registry
            .register(&allowlist, peer_ip, test_fp(), host_id.to_owned(), capabilities)
            .expect("register a test host")
            .dispatch_rx
    }

    /// Integration (#298 acceptance): a submitted job is actually dispatched
    /// to a registered remote host through the REAL control/submit path —
    /// `handle` itself, not a unit harness calling `send_dispatch` directly.
    /// Proves the whole placement chain end to end: `pick_host_for` ->
    /// `RemoteLink::new` -> a `Dispatch` built -> `send_dispatch` -> the
    /// host's own dispatch channel actually receiving it.
    #[tokio::test]
    async fn a_submitted_job_is_dispatched_to_a_registered_remote_host() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, trusted_host_capabilities());

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("the host's dispatch channel closed before receiving anything")?;
        assert_eq!(dispatch.job_id, job_id);
        assert_eq!(dispatch.forward_back, forward_back.to_string());
        assert_eq!(dispatch.required_isolation_class, i32::from(IsolationClass::Trusted));
        assert_eq!(dispatch.link_token.len(), crate::link_auth::LINK_TOKEN_LEN);

        // The job's own channel must carry the remote_link binding too, not
        // just the Dispatch message handed to the host — decision 6's accept
        // loop authenticates against JobRegistry, not against the Dispatch.
        let job = registry.get(&job_id).context("the job must be registered")?;
        assert!(
            job.remote_link.is_some(),
            "a placed job must have its remote_link bound"
        );

        Ok(())
    }

    fn submit_req_with_input(id: u64) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest: b"m".to_vec(),
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: vec![sandy_control_proto::Input {
                    host: "/src".to_owned(),
                    name: "src".to_owned(),
                    guest_path: Some("/work/src".to_owned()),
                }],
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    /// Place `request` on one registered host and return its `Dispatch` and
    /// the job, for the #482 data-link gating tests.
    async fn place_and_read(
        request: ControlRequest,
        capabilities: sandy_executor_proto::Capabilities,
        peer_ip: std::net::IpAddr,
    ) -> anyhow::Result<(Dispatch, Arc<crate::dispatch::JobChannel>, Arc<JobRegistry>)> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, capabilities);
        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            request,
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("the host's dispatch channel closed before receiving anything")?;
        let job = registry.get(&job_id).context("the job must be registered")?;
        Ok((dispatch, job, registry))
    }

    /// #482: a job naming no inputs or outputs gets no data link, even on a
    /// host that declared `transfer`. A host-executor that dials on a
    /// non-empty token would otherwise connect and wait for a transfer that
    /// never comes.
    #[tokio::test]
    async fn a_job_without_inputs_or_outputs_gets_no_data_link() -> anyhow::Result<()> {
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let capabilities = sandy_executor_proto::Capabilities {
            transfer: true,
            egress_proxy: false,
            ..trusted_host_capabilities()
        };
        let (dispatch, job, _registry) = place_and_read(submit_req(1), capabilities, peer_ip).await?;
        assert!(dispatch.data_link_token.is_empty(), "no inputs or outputs: no token");
        assert!(job.data_link.is_none(), "no inputs or outputs: no data link bound");
        Ok(())
    }

    /// #482: a job with inputs on a host that did not declare `transfer`
    /// gets no data link: the host cannot take one.
    #[tokio::test]
    async fn a_host_without_transfer_gets_no_data_link() -> anyhow::Result<()> {
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let capabilities = sandy_executor_proto::Capabilities {
            shares_submitter_filesystem: true,
            transfer: false,
            egress_proxy: false,
            ..trusted_host_capabilities()
        };
        let (dispatch, job, _registry) = place_and_read(submit_req_with_input(1), capabilities, peer_ip).await?;
        assert!(dispatch.data_link_token.is_empty(), "no transfer capability: no token");
        assert!(job.data_link.is_none(), "no transfer capability: no data link bound");
        Ok(())
    }

    /// #482: outputs alone also earn a data link on a transfer host (the
    /// gate is inputs OR outputs, not inputs only).
    #[tokio::test]
    async fn an_outputs_only_job_gets_a_data_link_on_a_transfer_host() -> anyhow::Result<()> {
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let capabilities = sandy_executor_proto::Capabilities {
            shares_submitter_filesystem: true,
            transfer: true,
            egress_proxy: false,
            ..trusted_host_capabilities()
        };
        let request = req(
            1,
            control_request::Op::Submit(SubmitRequest {
                manifest: b"m".to_vec(),
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: vec![sandy_control_proto::Output {
                    name: Some("result".to_owned()),
                    dest: "/out".to_owned(),
                }],
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        );
        let (dispatch, job, _registry) = place_and_read(request, capabilities, peer_ip).await?;
        assert_eq!(dispatch.data_link_token.len(), crate::link_auth::LINK_TOKEN_LEN);
        assert!(job.data_link.is_some(), "outputs alone must bind a data link");
        Ok(())
    }

    /// #482: the handler-minted data link is bound to the placed host's IP,
    /// carries the token the Dispatch sent, and differs from the agent
    /// link's token; a stream from any other peer is refused.
    #[tokio::test]
    async fn a_transfer_job_gets_a_data_link_bound_to_the_placed_host() -> anyhow::Result<()> {
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let other_ip: std::net::IpAddr = "100.64.0.9".parse().context("other ip literal")?;
        let capabilities = sandy_executor_proto::Capabilities {
            shares_submitter_filesystem: true,
            transfer: true,
            egress_proxy: false,
            ..trusted_host_capabilities()
        };
        let (dispatch, job, registry) = place_and_read(submit_req_with_input(1), capabilities, peer_ip).await?;
        let token: [u8; crate::link_auth::LINK_TOKEN_LEN] = dispatch
            .data_link_token
            .as_slice()
            .try_into()
            .context("the data link token must be LINK_TOKEN_LEN bytes")?;
        assert_ne!(dispatch.data_link_token, dispatch.link_token);

        let job_id = &dispatch.job_id;
        match registry.authenticate_incoming_link(job_id, other_ip, &token) {
            Err(e) => assert_eq!(e, crate::link_auth::LinkAuthError::WrongPeer),
            Ok(_) => anyhow::bail!("a data token from a peer other than the placed host must be refused"),
        }
        let (_, kind) = registry.authenticate_incoming_link(job_id, peer_ip, &token)?;
        assert_eq!(kind, crate::link_auth::LinkKind::Data);
        assert!(job.data_link.is_some());
        assert_eq!(
            job.data_inputs, dispatch.inputs,
            "the data link sends the dispatched path inputs"
        );
        Ok(())
    }

    /// Regression (live M2 cross-machine run, infra-f3): the test above
    /// registers its host via `register_test_host`, a hand-built
    /// `Capabilities` fed directly to `HostRegistry::register` — it never
    /// exercises `host_conn::serve_host_executor`'s real wire decode. This
    /// drives that part of the path for real: a REAL wire `Register` frame
    /// through `serve_host_executor`, then `handle(Submit)`, reading the
    /// resulting `Dispatch` back off the host's actual connection (not a
    /// bare channel recv) — the same observable the host-executor itself
    /// would see.
    ///
    /// CAUTION (CodeRabbit, #313): `forward_back_addr` is passed to `handle`
    /// directly here, a value this test picked — it does NOT exercise
    /// `main.rs`'s own threading of that address from `$SANDY_MESH_AGENT_LINK_LISTEN`
    /// through `setup_mesh_agent_link_listener` and `serve_connection` into
    /// `handle`. A regression that broke THAT wiring (e.g. `main.rs` stops
    /// passing the bound address through) would not be caught here — this
    /// test only proves the handler/registry/wire path once `forward_back_addr`
    /// is already correct, not that `main.rs` supplies it correctly. No test
    /// in this crate currently covers that seam; it would need a real bound
    /// listener and a `main`-level integration test, out of scope for this
    /// PR's coverage-only aim.
    #[tokio::test]
    async fn a_submit_reaches_a_real_wire_registered_host_end_to_end() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let allowlist = crate::host_registry::ExecutorAllowlist::new([(peer_ip, test_fp())]);
        let (mut client, server) = tokio::io::duplex(4096);

        sandy_control_proto::write_frame(
            &mut client,
            &sandy_executor_proto::HostExecutorMessage {
                op: Some(sandy_executor_proto::host_executor_message::Op::Register(
                    sandy_executor_proto::Register {
                        host_id: "remote-host".to_owned(),
                        capabilities: Some(trusted_host_capabilities()),
                    },
                )),
            },
        )
        .await?;

        let host_registry_for_conn = Arc::clone(&host_registry);
        let store_for_conn = Arc::clone(&store);
        let registry_for_conn = Arc::clone(&registry);
        let serve = tokio::spawn(async move {
            crate::host_conn::serve_host_executor(
                Box::new(server),
                sandy_conn::PeerAddr::TcpTls(std::net::SocketAddr::new(peer_ip, 9000), test_fp()),
                &allowlist,
                &host_registry_for_conn,
                &store_for_conn,
                &registry_for_conn,
            )
            .await;
        });

        let registered: sandy_executor_proto::OrchestratorMessage = sandy_control_proto::read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;
        assert!(matches!(
            registered.op,
            Some(sandy_executor_proto::orchestrator_message::Op::Registered(_))
        ));

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let pushed: sandy_executor_proto::OrchestratorMessage = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sandy_control_proto::read_frame(&mut client),
        )
        .await
        .context("timed out waiting for the Dispatch push")?
        .context("read_frame faulted")?
        .context("the connection closed before a Dispatch arrived")?;
        match pushed.op {
            Some(sandy_executor_proto::orchestrator_message::Op::Dispatch(dispatch)) => {
                assert_eq!(dispatch.job_id, job_id);
                assert_eq!(dispatch.forward_back, forward_back.to_string());
                assert_eq!(dispatch.required_isolation_class, i32::from(IsolationClass::Trusted));
            }
            other => anyhow::bail!("expected a Dispatch push, got {other:?}"),
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;
        Ok(())
    }

    /// Adversarial (CodeRabbit on #301, infra-f3's safety-floor check): this
    /// test uses `register_test_host`, which discards the host's own
    /// `cancel_rx` (#477's own Cancel delivery is a separate, best-effort
    /// send that this test never observes) — the exact "Cancel never
    /// reaches the host" case: the host never ran, a stale connection, an
    /// older host-executor build. A cancelled job's already-delivered
    /// Dispatch cannot be retracted from the host side in that case, so the
    /// independent safety floor still has to hold: a cancelled job must
    /// still be unable to DELIVER a result, meaning the host eventually
    /// running the stale Dispatch and dialing back with the EXACT
    /// `link_token` it was given must still be refused by decision 6's
    /// accept path. Proven through the real placement flow, not a manually
    /// constructed `RemoteLink` (that's `cancel_invalidates_the_jobs_remote_link`
    /// above) — this test captures the token from the real `Dispatch` a
    /// registered host actually received, cancels the job, then
    /// authenticates with that exact token.
    #[tokio::test]
    async fn a_cancelled_jobs_dispatched_token_cannot_authenticate_afterward() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, trusted_host_capabilities());
        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;

        let submitted = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        // The exact token the (simulated) host now holds, from the real
        // Dispatch it received — not a token this test minted itself.
        let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("the host's dispatch channel closed before receiving anything")?;
        let token: [u8; crate::link_auth::LINK_TOKEN_LEN] = dispatch
            .link_token
            .try_into()
            .map_err(|_| anyhow::anyhow!("link_token was not LINK_TOKEN_LEN bytes"))?;

        let cancelled = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            req(2, cancel_authed(&store, &job_id)),
        )
        .await?;
        assert!(
            matches!(cancelled.result, Some(control_response::Result::Cancel(_))),
            "got {:?}",
            cancelled.result
        );

        // The host "runs" the stale Dispatch and dials back with the token
        // it was actually given — must still be refused, not authenticate.
        match registry.authenticate_remote_link(&job_id, peer_ip, &token) {
            Err(e) => assert_eq!(e, crate::link_auth::LinkAuthError::AlreadyClaimed),
            Ok(_) => panic!(
                "a cancelled job's dispatched token must never authenticate afterward — that would let a cancelled \
                 job's result reach the orchestrator"
            ),
        }
        Ok(())
    }

    /// Adversarial (INV-1, issue #159's residual item): across the real
    /// Submit -> placement -> Dispatch-construction -> delivery path, no
    /// `tracing` event or error `Display` carries the genuine per-run link
    /// token. Exercises a successful delivery (the real token is read back
    /// off the host's own dispatch channel, same as
    /// `a_submitted_job_is_dispatched_to_a_registered_remote_host` above)
    /// and an undeliverable one (the host's receiver is dropped before
    /// Submit, so `send_dispatch_if_current` fails and `handle`'s own
    /// "could not dispatch the placed job to its host" warning fires,
    /// carrying the real `DispatchSendError`'s `Display` — the genuine
    /// token for that job sits in its `remote_link` the whole time).
    /// Complements `mesh_accept`'s
    /// `no_tracing_event_carries_the_raw_link_token`, which covers the
    /// accept-loop side of the same token's lifetime; this covers the
    /// orchestrator's own construction and delivery of it.
    #[tokio::test]
    async fn no_tracing_event_carries_the_real_dispatch_token() -> anyhow::Result<()> {
        let buf = crate::test_support::SharedBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // A successful delivery: the real token travels from RemoteLink::new
        // into the Dispatch the host's channel actually receives.
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, trusted_host_capabilities());
        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;

        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );
        let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("the host's dispatch channel closed before receiving anything")?;
        let token1: [u8; crate::link_auth::LINK_TOKEN_LEN] = dispatch
            .link_token
            .try_into()
            .map_err(|_| anyhow::anyhow!("link_token was not LINK_TOKEN_LEN bytes"))?;

        // An undeliverable dispatch, in a fresh registry so host placement
        // can't ambiguously fall back to the first host above: the second
        // host's receiver is dropped before Submit, so the send fails and
        // handle logs the failure, but the job's own genuine token (never
        // sent anywhere) still sits in its remote_link.
        let (store2, registry2, host_registry2) = (new_store(), new_registry(), new_host_registry());
        let dispatch_rx2 = register_test_host(&host_registry2, "remote-host-2", peer_ip, trusted_host_capabilities());
        drop(dispatch_rx2);
        let response2 = handle(
            &store2,
            &registry2,
            &host_registry2,
            Some(forward_back),
            test_session(),
            submit_req(2),
        )
        .await?;
        let job_id2 = match response2.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        let token2 = *registry2
            .get(&job_id2)
            .context("the undeliverable job must still be registered")?
            .remote_link
            .as_ref()
            .context("the undeliverable job must still have a remote_link bound")?
            .token()
            .as_bytes();

        let logged = buf.contents()?;
        assert!(
            logged.contains("could not dispatch the placed job to its host"),
            "positive control: the undeliverable dispatch must have logged its failure: {logged}"
        );

        for marker in [token1, token2] {
            let text_marker = String::from_utf8_lossy(&marker).into_owned();
            let hex_marker: String = marker.iter().map(|b| format!("{b:02x}")).collect();
            let decimal_debug_marker = format!("{marker:?}");
            let hex_debug_marker = format!("{marker:x?}");
            assert!(
                !logged.contains(&text_marker),
                "a genuine dispatch token's decoded text leaked into tracing output: {logged}"
            );
            assert!(
                !logged.contains(&hex_marker),
                "a genuine dispatch token's hex encoding leaked into tracing output: {logged}"
            );
            assert!(
                !logged.contains(&decimal_debug_marker),
                "a genuine dispatch token's decimal byte-array Debug leaked into tracing output: {logged}"
            );
            assert!(
                !logged.contains(&hex_debug_marker),
                "a genuine dispatch token's hex byte-array Debug leaked into tracing output: {logged}"
            );
        }
        Ok(())
    }

    /// Adversarial, through the real path (belt-and-suspenders with
    /// `host_registry`'s own `pick_host_for_skips_a_host_that_does_not_support_the_required_class`
    /// unit test — this is the integration-level copy proving the fail-closed
    /// gate actually applies at the real placement point, not only in
    /// isolation): a registered host that does NOT declare the required
    /// isolation class is never placed on, even though it's the only host
    /// registered. `submit_req` always requests `Trusted` (see #381's own
    /// Untrusted-specific tests below for the other direction), so this
    /// simulates the mismatch with a host that declares Untrusted but not
    /// Trusted.
    #[tokio::test]
    async fn a_submit_never_places_on_a_host_lacking_the_required_isolation_class() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let untrusted_only = sandy_executor_proto::Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Untrusted.into()],
            shares_submitter_filesystem: false,
            transfer: false,
            egress_proxy: false,
        };
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, untrusted_only);

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => {
                anyhow::bail!("the submit itself must still succeed even when placement finds no match, got {other:?}")
            }
        };

        assert!(
            dispatch_rx.try_recv().is_err(),
            "a host lacking the required isolation class must never receive a dispatch"
        );
        let job = registry.get(&job_id).context("the job must be registered")?;
        assert!(
            job.remote_link.is_none(),
            "a job that failed placement must stay local, not carry a remote_link to nowhere"
        );
        Ok(())
    }

    /// Regression (#292 item 3, also closes #303 item 4 — the same strand):
    /// when the placed dispatch cannot actually be delivered —
    /// `send_dispatch_if_current` refuses because the connection it was
    /// placed on already ended — the job must be failed terminally, not left
    /// silently `Pending` forever with no distinct status a caller could
    /// poll for. Forces the failure deterministically (dropping the host's
    /// `dispatch_rx` before `handle` runs, so the internal send hits
    /// `ConnectionClosing`) rather than racing a real reconnect — the same
    /// underlying `DispatchSendError` family `RegistrationChanged` belongs
    /// to; the handler's fix applies uniformly to any error from this call,
    /// not just that one variant.
    #[tokio::test]
    async fn a_submit_fails_the_job_when_the_placed_dispatch_cannot_be_delivered() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        // Register the host, then immediately drop its dispatch_rx: the
        // registry entry (and `pick_host_for`'s view of it) stays live, but
        // any `send_dispatch`/`send_dispatch_if_current` against it now
        // fails with `ConnectionClosing` — standing in for "the connection
        // this dispatch was placed on already ended."
        drop(register_test_host(
            &host_registry,
            "remote-host",
            peer_ip,
            trusted_host_capabilities(),
        ));

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!(
                "Submit must still succeed even when the placed dispatch can't be delivered, got {other:?}"
            ),
        };

        assert_eq!(
            store.status(&job_id)?,
            Some(JobStatus::Failed),
            "an undeliverable dispatch must fail the job terminally, not leave it silently Pending forever"
        );

        // Regression (#368): job status alone must not be the only thing
        // gating agent-link authentication — the link itself must be
        // invalidated too, or a late stream could still present the
        // genuine, never-delivered token and get admitted.
        let job = registry
            .get(&job_id)
            .context("the failed job must still be in the registry")?;
        let link = job
            .remote_link
            .as_ref()
            .context("the placed job must have a remote link")?;
        let token = *link.token().as_bytes();
        let auth = registry.authenticate_remote_link(&job_id, peer_ip, &token).map(drop);
        assert!(
            matches!(auth, Err(crate::link_auth::LinkAuthError::AlreadyClaimed)),
            "the genuine token must be refused once the job it was minted for has failed: {auth:?}"
        );
        Ok(())
    }

    /// #270: the undelivered-dispatch failure path above must call
    /// `JobRegistry::mark_terminal` too, not just fail the job in the store
    /// — otherwise a job that failed this way would sit in the registry
    /// forever, never reached by the retention sweep.
    #[tokio::test]
    async fn an_undelivered_dispatch_marks_the_job_terminal_for_the_registrys_retention_sweep() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry_with_zero_retention(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        drop(register_test_host(
            &host_registry,
            "remote-host",
            peer_ip,
            trusted_host_capabilities(),
        ));

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        assert_eq!(store.status(&job_id)?, Some(JobStatus::Failed));

        // A second Submit's insert is what the sweep is tied to (#270). No
        // host registered for this one — it just needs to be AN insert.
        handle(&store, &registry, &host_registry, None, test_session(), submit_req(2)).await?;

        assert!(
            registry.get(&job_id).is_none(),
            "an undelivered-dispatch job's channel must be reaped once retention elapses"
        );
        Ok(())
    }

    /// Adversarial: with no host registered at all, Submit still succeeds
    /// and the job simply runs local (today's unchanged behavior) — a
    /// configured `forward_back_addr` alone must never be mistaken for "a
    /// host is available."
    #[tokio::test]
    async fn a_submit_with_no_registered_host_stays_local() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;

        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req(1),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let job = registry.get(&job_id).context("the job must be registered")?;
        assert!(
            job.remote_link.is_none(),
            "with no registered host, the job must stay local"
        );
        Ok(())
    }

    // ---- Sandbox-kind placement dimension (#332) ----

    /// A `flake/v1` manifest as a submitter sends it, with `service` as given.
    fn flake_manifest_bytes(service: Option<sandy_guest_template::manifest::ServiceSpec>) -> Vec<u8> {
        sandy_guest_template::manifest::encode_flake_manifest(&sandy_guest_template::manifest::FlakeManifestV1 {
            flake: "github:example/guest".to_owned(),
            kind: None,
            attr: None,
            command: vec!["serve".to_owned()],
            history_lines: sandy_guest_template::manifest::default_history_lines(),
            env: Vec::new(),
            cpu: None,
            mem: None,
            timeout_secs: None,
            service,
        })
        .expect("a flake manifest encodes")
    }

    fn service_spec(user: &str) -> sandy_guest_template::manifest::ServiceSpec {
        sandy_guest_template::manifest::ServiceSpec {
            user: user.to_owned(),
            probe: sandy_guest_template::manifest::HealthProbe {
                check: sandy_guest_template::manifest::ProbeCheck::Tcp { port: 8080 },
                interval_secs: 1,
                timeout_secs: 1,
                max_attempts: 5,
            },
            restart: sandy_guest_template::manifest::RestartPolicy::Never,
            port: Some(8080),
        }
    }

    fn submit_req_flake(id: u64) -> ControlRequest {
        submit_req_flake_with(id, flake_manifest_bytes(None))
    }

    fn submit_req_flake_with(id: u64, manifest: Vec<u8>) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest,
                manifest_encoding: "flake/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    fn vm_host_capabilities() -> sandy_executor_proto::Capabilities {
        sandy_executor_proto::Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into(), SandboxKind::Vm.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
            shares_submitter_filesystem: false,
            transfer: false,
            egress_proxy: false,
        }
    }

    /// `required_sandbox_kind_for` is a pure function of the encoding tag
    /// alone: `flake/v1` requires `Vm`, everything else (including an opaque
    /// or test-only tag) requires `Process` — the existing, unchanged
    /// default.
    #[test]
    fn required_sandbox_kind_for_maps_flake_v1_to_vm_and_everything_else_to_process() {
        assert_eq!(required_sandbox_kind_for("flake/v1"), SandboxKind::Vm);
        assert_eq!(required_sandbox_kind_for("argv/v1"), SandboxKind::Process);
        assert_eq!(required_sandbox_kind_for("test/v1"), SandboxKind::Process);
        assert_eq!(required_sandbox_kind_for(""), SandboxKind::Process);
    }

    /// Regression for CodeRabbit's finding on #332's PR, extended by #381:
    /// `handle`'s early placeability check and its post-`dispatch_plan` check
    /// call this same function, so proving its cases here proves both call
    /// sites refuse (or don't) correctly — including the narrow TOCTOU case
    /// (a `Vm` job, placeable at the early check, unplaceable by the time
    /// `dispatch_plan` is computed) the full async race itself can't be
    /// reproduced deterministically in a unit test (it needs a real
    /// concurrent host disconnect, or `RemoteLink::new`'s RNG failing,
    /// between two reads of `host_registry`'s internal lock). Placement is
    /// mandatory along TWO independent dimensions: `SandboxKind::Vm`
    /// (unchanged since #332) and, as of #381, `IsolationClass::Untrusted` —
    /// a `Process`+`Untrusted` combination (inexpressible as a real
    /// dispatch, since the process backend never admits an untrusted job)
    /// must still be refused on failed placement, not silently kept Pending.
    #[test]
    fn placement_required_error_refuses_an_unplaced_vm_or_untrusted_requirement() {
        assert!(
            placement_required_error(IsolationClass::Trusted, SandboxKind::Vm, false, false, "unplaced").is_some(),
            "a Vm job with no placement must be refused"
        );
        assert!(
            placement_required_error(IsolationClass::Trusted, SandboxKind::Vm, false, true, "unplaced").is_none(),
            "a Vm job that IS placed must not be refused"
        );
        assert!(
            placement_required_error(IsolationClass::Trusted, SandboxKind::Process, false, false, "unplaced").is_none(),
            "an unplaced Trusted+Process job keeps its existing silent local-fallback behavior"
        );
        assert!(
            placement_required_error(
                IsolationClass::Untrusted,
                SandboxKind::Process,
                false,
                false,
                "unplaced"
            )
            .is_some(),
            "an unplaced Untrusted job must be refused even when its sandbox kind alone wouldn't require placement"
        );
        assert!(
            placement_required_error(IsolationClass::Untrusted, SandboxKind::Vm, false, true, "unplaced").is_none(),
            "an Untrusted job that IS placed must not be refused"
        );
    }

    /// Positive (#332 acceptance): a `flake/v1` submit placed on a host that
    /// declared BOTH `Process` and `Vm` dispatches with `backend == Vm` —
    /// the submission's own required kind, not merely whatever the picked
    /// host happens to support.
    #[tokio::test]
    async fn a_flake_submit_dispatches_as_vm_to_a_vm_capable_host() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, vm_host_capabilities());

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_flake(1),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );

        let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("the host's dispatch channel closed before receiving anything")?;
        assert_eq!(dispatch.backend, i32::from(SandboxKind::Vm));
        assert_eq!(dispatch.manifest_encoding, "flake/v1");
        Ok(())
    }

    /// Adversarial (#332, the issue's own acceptance bar — "never silently
    /// fall back"): a `flake/v1` submit with only a Process-only host
    /// registered is refused OUTRIGHT, creating no job at all — never a
    /// silently un-run `Pending` row, which this daemon can never advance
    /// (no local VM execution path exists).
    #[tokio::test]
    async fn a_flake_submit_with_only_a_process_only_host_is_refused_and_creates_no_job() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let _dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, trusted_host_capabilities()); // Process only

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_flake(1),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("Vm"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }

        let list = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            req(2, control_request::Op::List(ListRequest {})),
        )
        .await?;
        match list.result {
            Some(control_response::Result::List(ListResponse { jobs })) => {
                assert!(jobs.is_empty(), "a refused flake submit must create no job: {jobs:?}");
            }
            other => anyhow::bail!("expected a List response, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial (#332): a `flake/v1` submit with NO remote-dispatch
    /// address configured at all (`forward_back_addr: None`) is refused the
    /// same way — a Vm-capable host existing somewhere is irrelevant if this
    /// daemon can't reach it back.
    #[tokio::test]
    async fn a_flake_submit_with_no_forward_back_configured_is_refused() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let _dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, vm_host_capabilities());

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_flake(1),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                // CodeRabbit on this PR: this is specifically the
                // forward_back-unconfigured case, not the no-Vm-host case —
                // the message must name THIS orchestrator's own missing
                // config, not point the operator at registering a host that
                // wouldn't help.
                assert!(message.contains("SANDY_MESH_AGENT_LINK_LISTEN"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    /// #589: a `flake/v1` service the executor would refuse (a root user) is refused at Submit, before placement,
    /// so the caller sees the reason in the Submit reply and no dispatch is sent.
    #[tokio::test]
    async fn a_flake_submit_naming_a_root_service_is_refused_at_submit() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, vm_host_capabilities());
        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;

        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_flake_with(1, flake_manifest_bytes(Some(service_spec("root")))),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("non-root"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        assert!(dispatch_rx.try_recv().is_err(), "a refused submit must not dispatch");
        let list = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            req(2, control_request::Op::List(ListRequest {})),
        )
        .await?;
        match list.result {
            Some(control_response::Result::List(ListResponse { jobs })) => {
                assert!(jobs.is_empty(), "a refused submit must create no job: {jobs:?}");
            }
            other => anyhow::bail!("expected a List response, got {other:?}"),
        }
        Ok(())
    }

    /// #589: the refusal covers the rest of decode too, and a submitter-chosen field name cannot carry a newline
    /// into the reply (and so into the broker's log).
    #[tokio::test]
    async fn a_malformed_flake_manifest_is_refused_without_control_characters() -> anyhow::Result<()> {
        let malformed: [&[u8]; 2] = [b"not json", br#"{"flake":"x","command":[],"\n2026 INFO forged":1}"#];
        for manifest in malformed {
            let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
            let response = handle(
                &store,
                &registry,
                &host_registry,
                None,
                test_session(),
                submit_req_flake_with(1, manifest.to_vec()),
            )
            .await?;
            match response.result {
                Some(control_response::Result::Error(ControlError { message })) => {
                    assert!(message.contains("flake/v1 manifest is refused"), "got {message:?}");
                    assert!(!message.chars().any(char::is_control), "got {message:?}");
                }
                other => anyhow::bail!("expected a refusal, got {other:?}"),
            }
        }
        Ok(())
    }

    /// #589: a well-formed service manifest passes the Submit check and is placed.
    #[tokio::test]
    async fn a_flake_submit_naming_a_valid_service_passes_the_submit_check() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, vm_host_capabilities());
        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;

        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_flake_with(1, flake_manifest_bytes(Some(service_spec("svc")))),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("the dispatch channel closed")?;
        Ok(())
    }

    // ---- Isolation-class placement dimension (#381) ----

    fn submit_req_untrusted_flake(id: u64) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest: flake_manifest_bytes(None),
                manifest_encoding: "flake/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Untrusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    fn submit_req_untrusted_argv(id: u64) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest: b"m".to_vec(),
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Untrusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    fn submit_req_unspecified_class(id: u64) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest: b"m".to_vec(),
                manifest_encoding: "test/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Unspecified.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    fn vm_untrusted_host_capabilities() -> sandy_executor_proto::Capabilities {
        sandy_executor_proto::Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into(), SandboxKind::Vm.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into(), IsolationClass::Untrusted.into()],
            shares_submitter_filesystem: false,
            transfer: false,
            egress_proxy: false,
        }
    }

    /// Positive (#381 acceptance): an `Untrusted`-required submit is placed
    /// on a host that declares BOTH `Untrusted` and `Vm`, and the resulting
    /// `Dispatch` carries `backend == Vm` and `required_isolation_class ==
    /// Untrusted` — the process kind never satisfies `Untrusted` (spec item
    /// 3), so a Vm-capable host is the only combination that can ever place
    /// one.
    #[tokio::test]
    async fn an_untrusted_submit_is_placed_on_a_vm_and_untrusted_capable_host_and_dispatches_as_vm()
    -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx =
            register_test_host(&host_registry, "remote-host", peer_ip, vm_untrusted_host_capabilities());

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_untrusted_flake(1),
        )
        .await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );

        let dispatch = tokio::time::timeout(std::time::Duration::from_secs(5), dispatch_rx.recv())
            .await
            .context("timed out waiting for the dispatch")?
            .context("the host's dispatch channel closed before receiving anything")?;
        assert_eq!(dispatch.backend, i32::from(SandboxKind::Vm));
        assert_eq!(dispatch.required_isolation_class, i32::from(IsolationClass::Untrusted));
        Ok(())
    }

    /// Adversarial (#381 acceptance): a Vm-encoded `Untrusted`-required submit
    /// with only a plain process-capable host registered (no `Vm`, no
    /// `Untrusted`) is refused OUTRIGHT at placement, creating no job — same
    /// "never silently stay Pending" bar decision 18 already holds for an
    /// unplaced `flake/v1` job, now extended to the isolation-class
    /// dimension: the process backend never admits an untrusted job, so this
    /// job has no local fallback either.
    #[tokio::test]
    async fn an_untrusted_submit_with_only_a_process_capable_host_is_refused_and_creates_no_job() -> anyhow::Result<()>
    {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let _dispatch_rx = register_test_host(&host_registry, "remote-host", peer_ip, trusted_host_capabilities());

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_untrusted_flake(1),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("Untrusted"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }

        let list = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            req(2, control_request::Op::List(ListRequest {})),
        )
        .await?;
        match list.result {
            Some(control_response::Result::List(ListResponse { jobs })) => {
                assert!(
                    jobs.is_empty(),
                    "a refused untrusted submit must create no job: {jobs:?}"
                );
            }
            other => anyhow::bail!("expected a List response, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial (CodeRabbit on this PR): an `Untrusted`-required submit
    /// whose `manifest_encoding` resolves to `SandboxKind::Process` (the
    /// `argv/v1`/`test/v1` default, never `Vm`) is refused BEFORE
    /// `pick_host_for` or any persistence — even with a host registered that
    /// declares both `Untrusted` and `Process` (every `Vm`-capable host does,
    /// since `Process` stays additive). Without this guard, such a host would
    /// satisfy `pick_host_for(Untrusted, Process)` and the job would be
    /// placed and dispatched with `backend == Process`, only to be refused by
    /// the host-executor's own re-check later — a wasted round trip instead
    /// of a clean Submit-time refusal.
    #[tokio::test]
    async fn an_untrusted_submit_with_a_non_vm_encoding_is_refused_before_placement_and_creates_no_job()
    -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx =
            register_test_host(&host_registry, "remote-host", peer_ip, vm_untrusted_host_capabilities());

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_untrusted_argv(1),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("Untrusted"), "got {message:?}");
                assert!(message.contains("Vm"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        assert!(
            dispatch_rx.try_recv().is_err(),
            "a Process-encoded Untrusted submit must never reach dispatch, even on a Vm+Untrusted-capable host"
        );

        let list = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            req(2, control_request::Op::List(ListRequest {})),
        )
        .await?;
        match list.result {
            Some(control_response::Result::List(ListResponse { jobs })) => {
                assert!(
                    jobs.is_empty(),
                    "a refused untrusted submit must create no job: {jobs:?}"
                );
            }
            other => anyhow::bail!("expected a List response, got {other:?}"),
        }
        Ok(())
    }

    /// Adversarial (#381 acceptance): an unset/`Unspecified`
    /// `required_isolation_class` is refused at Submit, never silently
    /// defaulted to `Trusted` — defaulting it would breach isolation for a
    /// client that forgot to state its job's class.
    #[tokio::test]
    async fn a_submit_with_an_unspecified_isolation_class_is_refused() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            submit_req_unspecified_class(1),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("required_isolation_class"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    // ---- Result propagation (#292) ----

    fn submit_req_argv(id: u64, argv: &[&str]) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest: serde_json::to_vec(argv).expect("encode argv manifest"),
                manifest_encoding: "argv/v1".to_owned(),
                submitter_caps: Vec::new(),
                required_isolation_class: sandy_control_proto::IsolationClass::Trusted.into(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                secrets: Vec::new(),
                credential: None,
                cred_capabilities: Vec::new(),
                egress: None,
            }),
        )
    }

    /// Poll the store until `job_id` leaves PENDING/RUNNING, so a test can wait
    /// for `serve_host_executor`'s own (spawn_blocking) terminal write to land
    /// without reaching into its internals. Bounded, so a regression that never
    /// transitions fails loudly instead of hanging.
    async fn wait_for_terminal(store: &JobStore, job_id: &str) -> anyhow::Result<crate::store::JobDetail> {
        for _ in 0..200 {
            if let Some(detail) = store.detail(job_id)?
                && !matches!(
                    detail.status,
                    sandy_control_proto::JobStatus::Pending | sandy_control_proto::JobStatus::Running
                )
            {
                return Ok(detail);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        anyhow::bail!("job {job_id} never reached a terminal status")
    }

    /// The acceptance bar (#292): a job submitted as `["echo","hi"]` with
    /// `argv/v1`, dispatched to a real-wire-registered host that reports back a
    /// clean `exit 0` with `hi` on its console, transitions OFF `Pending` and
    /// ends `Succeeded` with the real exit code and `hi` reachable in the
    /// output tail — through the whole real path: `serve_host_executor`
    /// decoding the registration, `handle(Submit)` placing + dispatching, the
    /// Dispatch read off the host's own connection, a `JobResult` frame sent
    /// back over that same connection, and `handle(Status)`/`handle(List)`
    /// reflecting the stored terminal result. Fails under the pre-#292
    /// behavior, where the outcome was only logged and the job stayed
    /// `Pending` forever.
    #[tokio::test]
    async fn a_completed_remote_job_ends_succeeded_with_its_exit_and_output() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let allowlist = crate::host_registry::ExecutorAllowlist::new([(peer_ip, test_fp())]);
        let (mut client, server) = tokio::io::duplex(8192);

        sandy_control_proto::write_frame(
            &mut client,
            &sandy_executor_proto::HostExecutorMessage {
                op: Some(sandy_executor_proto::host_executor_message::Op::Register(
                    sandy_executor_proto::Register {
                        host_id: "remote-host".to_owned(),
                        capabilities: Some(trusted_host_capabilities()),
                    },
                )),
            },
        )
        .await?;

        let host_registry_for_conn = Arc::clone(&host_registry);
        let store_for_conn = Arc::clone(&store);
        let registry_for_conn = Arc::clone(&registry);
        let serve = tokio::spawn(async move {
            crate::host_conn::serve_host_executor(
                Box::new(server),
                sandy_conn::PeerAddr::TcpTls(std::net::SocketAddr::new(peer_ip, 9000), test_fp()),
                &allowlist,
                &host_registry_for_conn,
                &store_for_conn,
                &registry_for_conn,
            )
            .await;
        });

        let registered: sandy_executor_proto::OrchestratorMessage = sandy_control_proto::read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;
        assert!(matches!(
            registered.op,
            Some(sandy_executor_proto::orchestrator_message::Op::Registered(_))
        ));

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_argv(1, &["echo", "hi"]),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        // The Dispatch the host-executor would receive, read off its own wire.
        let pushed: sandy_executor_proto::OrchestratorMessage = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sandy_control_proto::read_frame(&mut client),
        )
        .await
        .context("timed out waiting for the Dispatch push")?
        .context("read_frame faulted")?
        .context("the connection closed before a Dispatch arrived")?;
        let dispatch = match pushed.op {
            Some(sandy_executor_proto::orchestrator_message::Op::Dispatch(dispatch)) => dispatch,
            other => anyhow::bail!("expected a Dispatch push, got {other:?}"),
        };
        assert_eq!(dispatch.job_id, job_id);
        assert_eq!(dispatch.manifest_encoding, "argv/v1");

        // The host-executor "runs echo hi" and reports a clean exit 0 back over
        // the same management connection.
        sandy_control_proto::write_frame(
            &mut client,
            &sandy_executor_proto::HostExecutorMessage {
                op: Some(sandy_executor_proto::host_executor_message::Op::Result(
                    sandy_executor_proto::JobResult {
                        job_id: job_id.clone(),
                        booted: true,
                        exit_code: Some(0),
                        timed_out: false,
                        transport_error: None,
                        console: "hi\n".to_owned(),
                        outputs_follow: false,
                    },
                )),
            },
        )
        .await?;

        let detail = wait_for_terminal(&store, &job_id).await?;
        assert_eq!(detail.status, sandy_control_proto::JobStatus::Succeeded);
        assert_eq!(detail.exit_code, Some(0));
        assert!(
            detail.console.contains("hi"),
            "the output tail must carry `hi`: {:?}",
            detail.console
        );

        // `handle(Status)` surfaces the same off the real control path.
        let status = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            req(2, control_request::Op::Status(StatusRequest { job_id: job_id.clone() })),
        )
        .await?;
        match status.result {
            Some(control_response::Result::Status(sandy_control_proto::StatusResponse {
                status,
                exit_code,
                console_tail,
                ..
            })) => {
                assert_eq!(status, i32::from(sandy_control_proto::JobStatus::Succeeded));
                assert_eq!(exit_code, Some(0));
                assert!(
                    console_tail.contains("hi"),
                    "status must surface the output tail: {console_tail:?}"
                );
            }
            other => anyhow::bail!("expected a Status response, got {other:?}"),
        }

        // `list` reflects the terminal status too.
        let list = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            req(3, control_request::Op::List(ListRequest {})),
        )
        .await?;
        match list.result {
            Some(control_response::Result::List(ListResponse { jobs })) => {
                let job = jobs
                    .iter()
                    .find(|j| j.job_id == job_id)
                    .context("the job must be listed")?;
                assert_eq!(job.status, i32::from(sandy_control_proto::JobStatus::Succeeded));
            }
            other => anyhow::bail!("expected a List response, got {other:?}"),
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;
        Ok(())
    }

    /// Regression (#292, failure path): a job dispatched to a host that then
    /// disconnects mid-run — without ever reporting a result — must go to a
    /// terminal FAILED state, never stay stuck `Pending`/`Running` forever.
    /// Fails under the pre-#292 behavior (no result path, no disconnect
    /// handling: the job stayed `Pending`).
    #[tokio::test]
    async fn a_remote_job_whose_host_disconnects_mid_run_goes_failed() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let allowlist = crate::host_registry::ExecutorAllowlist::new([(peer_ip, test_fp())]);
        let (mut client, server) = tokio::io::duplex(8192);

        sandy_control_proto::write_frame(
            &mut client,
            &sandy_executor_proto::HostExecutorMessage {
                op: Some(sandy_executor_proto::host_executor_message::Op::Register(
                    sandy_executor_proto::Register {
                        host_id: "remote-host".to_owned(),
                        capabilities: Some(trusted_host_capabilities()),
                    },
                )),
            },
        )
        .await?;

        let host_registry_for_conn = Arc::clone(&host_registry);
        let store_for_conn = Arc::clone(&store);
        let registry_for_conn = Arc::clone(&registry);
        let serve = tokio::spawn(async move {
            crate::host_conn::serve_host_executor(
                Box::new(server),
                sandy_conn::PeerAddr::TcpTls(std::net::SocketAddr::new(peer_ip, 9000), test_fp()),
                &allowlist,
                &host_registry_for_conn,
                &store_for_conn,
                &registry_for_conn,
            )
            .await;
        });

        let _registered: sandy_executor_proto::OrchestratorMessage = sandy_control_proto::read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;

        let forward_back: std::net::SocketAddr = "100.64.0.1:9000".parse().context("forward_back literal")?;
        let response = handle(
            &store,
            &registry,
            &host_registry,
            Some(forward_back),
            test_session(),
            submit_req_argv(1, &["echo", "hi"]),
        )
        .await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        // Drain the Dispatch so the job is genuinely in flight on the
        // connection before the host vanishes (this is also what drives the
        // Pending -> Running mark on the orchestrator side).
        let _pushed: sandy_executor_proto::OrchestratorMessage = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sandy_control_proto::read_frame(&mut client),
        )
        .await
        .context("timed out waiting for the Dispatch push")?
        .context("read_frame faulted")?
        .context("the connection closed before a Dispatch arrived")?;

        // The host disconnects mid-run, never reporting a result.
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;

        let detail = wait_for_terminal(&store, &job_id).await?;
        assert_eq!(
            detail.status,
            sandy_control_proto::JobStatus::Failed,
            "a job whose host disconnected mid-run must be FAILED, never stuck Pending/Running"
        );
        Ok(())
    }
}
