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
    AttachResponse, CancelResponse, ControlError, ControlRequest, ControlResponse, JobSummary as WireJobSummary,
    ListResponse, StatusResponse, SubmitResponse, control_request, control_response,
};
use sandy_executor_proto::{Dispatch, IsolationClass, SandboxKind};
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapCodecError, CapRights, CapScope, decode_cap, encode_cap},
    types::{ChannelId, PeerId},
};
use sandy_orchestrator::{JobManifest, MANIFEST_ENCODING_JSON, derive_job_caps};
use uuid::Uuid;

use crate::{
    dispatch::{self, JobRegistry},
    host_registry::HostRegistry,
    link_auth::RemoteLink,
    store::{CancelOutcome, InsertOutcome, JobStore, StoreError},
};

/// STAGE-1: untrusted jobs are inexpressible (no VM/untrusted backend yet,
/// #269 D4), so every submitted job's required isolation class is `Trusted`
/// — this is accurate for stage-1, not a shortcut. When #150 (VM/untrusted
/// isolation) lands, replace this default with a real per-job requirement on
/// the submit path (a `SubmitRequest` field) — otherwise an untrusted job
/// would silently default to `Trusted` and breach isolation. See #298, #269,
/// #150.
const STAGE1_REQUIRED_ISOLATION_CLASS: IsolationClass = IsolationClass::Trusted;

/// The `manifest_encoding` tag a flake-templated VM job uses (#332) —
/// `sandy_host_executor::dispatch`/`sandy_guest_template::manifest`'s own
/// `MANIFEST_ENCODING_FLAKE_V1`, duplicated here (not imported) for the same
/// reason `link_auth::LINK_TOKEN_LEN` duplicates
/// `sandy_executor_proto::REMOTE_LINK_TOKEN_LEN`: this daemon never resolves
/// or decodes a flake manifest itself, only classifies the tag, so it has no
/// real need for that crate's `nix`-shelling resolution logic as a
/// dependency. The two constants name the same wire tag and must stay in
/// sync if either changes.
const MANIFEST_ENCODING_FLAKE_V1: &str = "flake/v1";

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

/// Refuses a `SandboxKind::Vm` submit this daemon cannot place, with `reason`
/// as the explanation; `None` for anything else (a placed `Vm` job, or any
/// `argv/v1` `Process` job, which keeps its existing "falls back to local"
/// behavior unchanged). Shared by the two placement checks in `handle`'s
/// `Submit` arm: the early one (before any side effect) and the one right
/// after `dispatch_plan` is computed, which closes a narrow TOCTOU the early
/// check alone cannot — a host disconnecting between the two `pick_host_for`
/// calls, or `RemoteLink::new`'s RNG failing, can make the second placement
/// attempt come back empty even though the first one found a host. `flake/v1`
/// has no local execution fallback, so leaving that job `Pending` forever
/// with no distinct status would be exactly the silent gap decision 18 rules
/// out.
fn vm_placement_error(required_sandbox_kind: SandboxKind, placed: bool, reason: &str) -> Option<ControlError> {
    (required_sandbox_kind == SandboxKind::Vm && !placed).then(|| ControlError {
        message: reason.to_owned(),
    })
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
            // Named apart from `placeable` itself (CodeRabbit on this PR): the
            // original message always blamed "no Vm-capable host," even when
            // the real cause was this orchestrator's own configuration
            // (`SANDY_MESH_AGENT_LINK_LISTEN` unset, so `forward_back_addr` is
            // `None` and no remote placement is reachable at all, regardless
            // of what's registered) — an operator misreads that as "go
            // register a host" when the actual fix is on this box.
            let placeable = if forward_back_addr.is_none() {
                false
            } else {
                host_registry
                    .pick_host_for(STAGE1_REQUIRED_ISOLATION_CLASS.into(), required_sandbox_kind.into())
                    .is_some()
            };
            if let Some(control_error) = vm_placement_error(
                required_sandbox_kind,
                placeable,
                if forward_back_addr.is_none() {
                    "this orchestrator has no agent-link listen address configured (SANDY_MESH_AGENT_LINK_LISTEN is \
                     unset) — no remote placement is reachable at all, regardless of what hosts are registered"
                } else {
                    "no registered host declares SandboxKind::Vm capability; a flake-templated job cannot be placed \
                     (this daemon has no local VM execution path)"
                },
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
            let store = Arc::clone(store);

            // #327: a durable, re-presentable credential — independent of
            // CF-H-1's per-connection `session` below — so a LATER `sandy
            // daemon attach` invocation (a fresh connection, the realistic
            // "log back into my own job" case) can still prove it's the
            // submitter; `session_matches` alone never recognizes that case,
            // since a fresh connection always mints a fresh session. Minted
            // best-effort, same shape as `RemoteLink::new`'s own RNG-failure
            // handling just below: a vanishingly rare RNG failure degrades
            // this one job to session-only gating rather than failing the
            // whole Submit.
            let attach_token = {
                let mut bytes = [0u8; ATTACH_TOKEN_LEN];
                match getrandom::fill(&mut bytes) {
                    Ok(()) => bytes.to_vec(),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            job_id,
                            "could not mint a durable attach token; this job falls back to session-only attach gating"
                        );
                        Vec::new()
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

            // Placement (#298): stage-1 policy. Dispatch to a registered
            // remote host whose declared capabilities satisfy
            // STAGE1_REQUIRED_ISOLATION_CLASS, if the orchestrator's own
            // agent-link accept address is configured (no address means no
            // remote run is even reachable, regardless of what's
            // registered) and such a host exists; run locally otherwise —
            // today's unchanged behavior. Binding the remote link (decision
            // 6) happens BEFORE the job is persisted/registered, so a
            // placed job's `remote_link` is set from the moment anyone can
            // observe it; the actual `send_dispatch` call happens after,
            // once the job is durably recorded.
            let dispatch_plan = forward_back_addr.and_then(|forward_back| {
                let candidate = host_registry
                    .pick_host_for(STAGE1_REQUIRED_ISOLATION_CLASS.into(), required_sandbox_kind.into())?;
                match RemoteLink::new(candidate.peer_ip) {
                    Ok(link) => {
                        let link_token = link.token().as_bytes().to_vec();
                        job_channel.remote_link = Some(link);
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
                            required_isolation_class: STAGE1_REQUIRED_ISOLATION_CLASS.into(),
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
            if let Some(control_error) = vm_placement_error(
                required_sandbox_kind,
                dispatch_plan.is_some(),
                "no registered host could be bound for SandboxKind::Vm placement; a flake-templated job cannot be \
                 placed (this daemon has no local VM execution path)",
            ) {
                return Ok(ControlResponse {
                    request_id: request.request_id,
                    result: Some(control_response::Result::Error(control_error)),
                });
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

            // Best-effort, same reasoning as the mint step above: a faulted
            // write here leaves this one job without a durable attach
            // token (degrading to session-only gating for it), never a
            // reason to fail an otherwise-successful Submit.
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
                // KNOWN GAP (#292's reconnect-dispatch-preservation class):
                // on any failure here — including `RegistrationChanged` —
                // the job stays silently `Pending` with no re-placement
                // attempt and no distinct terminal status a caller could
                // poll for; this only moves the existing "a placed job can
                // silently never run" strand earlier (to send time) rather
                // than eliminating it. Stage-1 accepts this as the same
                // honest gap every other un-run `Pending` job already has in
                // this module (no retry, no scheduler) — #292 tracks closing
                // it for good (re-queue on reconnect, or a distinct status).
                if let Err(e) = host_registry
                    .send_dispatch_if_current(&host_id, registration, dispatch)
                    .await
                {
                    tracing::warn!(error = %e, job_id, host_id, "could not dispatch the placed job to its host");
                }
            }

            control_response::Result::Submit(SubmitResponse { job_id, attach_token })
        }
        Some(control_request::Op::Cancel(cancel)) => {
            // CF-H-1: an audit trail, not a gate — a mismatch is logged, never
            // refused (see `handle`'s own doc on `session`). `info`, not
            // `warn`: the CLI opens a fresh connection per invocation, so a
            // later `cancel` from a separate `sandy daemon` call is the
            // ordinary case, not an anomaly — this is a correlation trail,
            // not an alert.
            if let Some(job) = registry.get(&cancel.job_id)
                && !job.session_matches(session)
            {
                tracing::info!(
                    job_id = %cancel.job_id,
                    submitted_session = %job.session,
                    requesting_session = %session,
                    "cancel from a different session than the one that submitted this job"
                );
            }
            let job_id = cancel.job_id.clone();
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
                    // CAUTION (decision 12, reachable since #298/#301 - #298
                    // is the first real send_dispatch caller): this only
                    // stops a late agent-link stream from claiming the run.
                    // If the job's Dispatch already reached the host-executor
                    // (running, or still queued behind another job under
                    // decision 14's sequential processing), nothing retracts
                    // it - there is no Cancel/Stop OrchestratorMessage. The
                    // host-side process starts or keeps running regardless.
                    // Confirmed intentionally deferred past M2 (decision 12):
                    // a future Cancel/Stop message is an additive oneof
                    // variant.
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
                let attach_cap = if is_submitter {
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
                        "job {} has no live channel on this daemon (restarted since submit?); re-submit to get a new \
                         one",
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
    if stored.len() != presented.len() {
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
            }),
        )
    }

    fn new_store() -> Arc<JobStore> {
        Arc::new(JobStore::open_in_memory().expect("in-memory store"))
    }

    fn new_registry() -> Arc<JobRegistry> {
        Arc::new(JobRegistry::new().expect("getrandom for a test registry"))
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
                remote_link: None,
                granted_caps: job.granted_caps.clone(),
                session: job.session,
                host_id: job.host_id.clone(),
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
                remote_link: Some(link),
                granted_caps: job.granted_caps.clone(),
                session: job.session,
                host_id: job.host_id.clone(),
            },
        );

        let response = handle(
            &store,
            &registry,
            &host_registry,
            None,
            test_session(),
            req(2, control_request::Op::Cancel(CancelRequest { job_id: job_id.clone() })),
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
            req(2, control_request::Op::Cancel(CancelRequest { job_id: job_id.clone() })),
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
    #[tokio::test]
    async fn a_cross_session_cancel_still_succeeds() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let submitted = handle(&store, &registry, &host_registry, None, Uuid::new_v4(), submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id, .. })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let cancelled = handle(
            &store,
            &registry,
            &host_registry,
            None,
            Uuid::new_v4(), // a different session than the one that submitted
            req(2, control_request::Op::Cancel(CancelRequest { job_id: job_id.clone() })),
        )
        .await?;
        assert!(
            matches!(cancelled.result, Some(control_response::Result::Cancel(_))),
            "got {:?}",
            cancelled.result
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
        }
    }

    fn register_test_host(
        host_registry: &HostRegistry,
        host_id: &str,
        peer_ip: std::net::IpAddr,
        capabilities: sandy_executor_proto::Capabilities,
    ) -> tokio::sync::mpsc::Receiver<Dispatch> {
        let allowlist = crate::host_registry::ExecutorAllowlist::new([peer_ip]);
        host_registry
            .register(&allowlist, peer_ip, host_id.to_owned(), capabilities)
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
        let mut dispatch_rx = register_test_host(&host_registry, "ws01", peer_ip, trusted_host_capabilities());

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
        let allowlist = crate::host_registry::ExecutorAllowlist::new([peer_ip]);
        let (mut client, server) = tokio::io::duplex(4096);

        sandy_control_proto::write_frame(
            &mut client,
            &sandy_executor_proto::HostExecutorMessage {
                op: Some(sandy_executor_proto::host_executor_message::Op::Register(
                    sandy_executor_proto::Register {
                        host_id: "ws01".to_owned(),
                        capabilities: Some(trusted_host_capabilities()),
                    },
                )),
            },
        )
        .await?;

        let host_registry_for_conn = Arc::clone(&host_registry);
        let store_for_conn = Arc::clone(&store);
        let serve = tokio::spawn(async move {
            crate::host_conn::serve_host_executor(
                Box::new(server),
                sandy_conn::PeerAddr::Tcp(std::net::SocketAddr::new(peer_ip, 9000)),
                &allowlist,
                &host_registry_for_conn,
                &store_for_conn,
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

    /// Adversarial (CodeRabbit on #301, infra-f3's safety-floor check): a
    /// cancelled job's Dispatch, once delivered to a host, cannot be
    /// retracted — there is no Cancel/Stop `OrchestratorMessage` (decision
    /// 12). Deferring that is only acceptable if a cancelled job still
    /// cannot DELIVER a result: the host eventually running the stale
    /// Dispatch and dialing back with the EXACT `link_token` it was given
    /// must still be refused by decision 6's accept path. Proven through
    /// the real placement flow, not a manually constructed `RemoteLink`
    /// (that's `cancel_invalidates_the_jobs_remote_link` above) — this test
    /// captures the token from the real `Dispatch` a registered host
    /// actually received, cancels the job, then authenticates with that
    /// exact token.
    #[tokio::test]
    async fn a_cancelled_jobs_dispatched_token_cannot_authenticate_afterward() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut dispatch_rx = register_test_host(&host_registry, "ws01", peer_ip, trusted_host_capabilities());
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
            req(2, control_request::Op::Cancel(CancelRequest { job_id: job_id.clone() })),
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

    /// Adversarial, through the real path (belt-and-suspenders with
    /// `host_registry`'s own `pick_host_for_skips_a_host_that_does_not_support_the_required_class`
    /// unit test — this is the integration-level copy proving the fail-closed
    /// gate actually applies at the real placement point, not only in
    /// isolation): a registered host that does NOT declare the required
    /// isolation class is never placed on, even though it's the only host
    /// registered. Nothing can submit an Untrusted-required job today
    /// (#298's stage-1 tripwire — every job's required class is the
    /// `STAGE1_REQUIRED_ISOLATION_CLASS` constant, `Trusted`), so this
    /// simulates the mismatch the only way currently possible: a host that
    /// declares support for Untrusted but not Trusted.
    #[tokio::test]
    async fn a_submit_never_places_on_a_host_lacking_the_required_isolation_class() -> anyhow::Result<()> {
        let (store, registry, host_registry) = (new_store(), new_registry(), new_host_registry());
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let untrusted_only = sandy_executor_proto::Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Untrusted.into()],
        };
        let mut dispatch_rx = register_test_host(&host_registry, "ws01", peer_ip, untrusted_only);

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

    fn submit_req_flake(id: u64) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                // Opaque to `handle` at placement time — it never decodes a
                // flake manifest itself, only classifies the encoding tag.
                manifest: b"irrelevant-to-placement".to_vec(),
                manifest_encoding: "flake/v1".to_owned(),
                submitter_caps: Vec::new(),
            }),
        )
    }

    fn vm_host_capabilities() -> sandy_executor_proto::Capabilities {
        sandy_executor_proto::Capabilities {
            supported_sandbox_kinds: vec![SandboxKind::Process.into(), SandboxKind::Vm.into()],
            arch: sandy_executor_proto::Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
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

    /// Regression for CodeRabbit's finding on this PR: `handle`'s early
    /// placeability check and its post-`dispatch_plan` check call this same
    /// function, so proving the function's three cases here proves both call
    /// sites refuse (or don't) correctly — including the narrow TOCTOU case
    /// (a `Vm` job, placeable at the early check, unplaceable by the time
    /// `dispatch_plan` is computed) the full async race itself can't be
    /// reproduced deterministically in a unit test (it needs a real
    /// concurrent host disconnect, or `RemoteLink::new`'s RNG failing,
    /// between two reads of `host_registry`'s internal lock).
    #[test]
    fn vm_placement_error_refuses_only_an_unplaced_vm_requirement() {
        assert!(
            vm_placement_error(SandboxKind::Vm, false, "unplaced").is_some(),
            "a Vm job with no placement must be refused"
        );
        assert!(
            vm_placement_error(SandboxKind::Vm, true, "unplaced").is_none(),
            "a Vm job that IS placed must not be refused"
        );
        assert!(
            vm_placement_error(SandboxKind::Process, false, "unplaced").is_none(),
            "an unplaced Process job keeps its existing silent local-fallback behavior"
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
        let mut dispatch_rx = register_test_host(&host_registry, "ws01", peer_ip, vm_host_capabilities());

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
        let _dispatch_rx = register_test_host(&host_registry, "ws01", peer_ip, trusted_host_capabilities()); // Process only

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
        let _dispatch_rx = register_test_host(&host_registry, "ws01", peer_ip, vm_host_capabilities());

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

    // ---- Result propagation (#292) ----

    fn submit_req_argv(id: u64, argv: &[&str]) -> ControlRequest {
        req(
            id,
            control_request::Op::Submit(SubmitRequest {
                manifest: serde_json::to_vec(argv).expect("encode argv manifest"),
                manifest_encoding: "argv/v1".to_owned(),
                submitter_caps: Vec::new(),
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
        let allowlist = crate::host_registry::ExecutorAllowlist::new([peer_ip]);
        let (mut client, server) = tokio::io::duplex(8192);

        sandy_control_proto::write_frame(
            &mut client,
            &sandy_executor_proto::HostExecutorMessage {
                op: Some(sandy_executor_proto::host_executor_message::Op::Register(
                    sandy_executor_proto::Register {
                        host_id: "ws01".to_owned(),
                        capabilities: Some(trusted_host_capabilities()),
                    },
                )),
            },
        )
        .await?;

        let host_registry_for_conn = Arc::clone(&host_registry);
        let store_for_conn = Arc::clone(&store);
        let serve = tokio::spawn(async move {
            crate::host_conn::serve_host_executor(
                Box::new(server),
                sandy_conn::PeerAddr::Tcp(std::net::SocketAddr::new(peer_ip, 9000)),
                &allowlist,
                &host_registry_for_conn,
                &store_for_conn,
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
        let allowlist = crate::host_registry::ExecutorAllowlist::new([peer_ip]);
        let (mut client, server) = tokio::io::duplex(8192);

        sandy_control_proto::write_frame(
            &mut client,
            &sandy_executor_proto::HostExecutorMessage {
                op: Some(sandy_executor_proto::host_executor_message::Op::Register(
                    sandy_executor_proto::Register {
                        host_id: "ws01".to_owned(),
                        capabilities: Some(trusted_host_capabilities()),
                    },
                )),
            },
        )
        .await?;

        let host_registry_for_conn = Arc::clone(&host_registry);
        let store_for_conn = Arc::clone(&store);
        let serve = tokio::spawn(async move {
            crate::host_conn::serve_host_executor(
                Box::new(server),
                sandy_conn::PeerAddr::Tcp(std::net::SocketAddr::new(peer_ip, 9000)),
                &allowlist,
                &host_registry_for_conn,
                &store_for_conn,
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
