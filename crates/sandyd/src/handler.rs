//! Dispatch one [`ControlRequest`] to a [`ControlResponse`] against the
//! [`JobStore`] and the [`JobRegistry`] (#212, B1 + B2's dispatch slice).
//! `Submit` persists the job AND mints its dedicated channel + caps (see
//! [`crate::dispatch`]); `Attach` returns that real channel id + an observer
//! cap once minted. No agent or executor wiring yet: a submitted job stays
//! `Pending` forever, since nothing joins its channel or runs it — see
//! `dispatch`'s module doc for why that's an honest gap, not a fake.

use std::sync::Arc;

use sandy_control_proto::{
    AttachResponse, CancelResponse, ControlError, ControlRequest, ControlResponse, JobSummary as WireJobSummary,
    ListResponse, StatusResponse, SubmitResponse, control_request, control_response,
};
use sandy_fabric::capauth::{Cap, CapCodecError, decode_cap, encode_cap};
use sandy_orchestrator::{JobManifest, MANIFEST_ENCODING_JSON, derive_job_caps};
use uuid::Uuid;

use crate::{
    dispatch::{self, JobRegistry},
    store::{CancelOutcome, JobStore, StoreError},
};

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
/// # Errors
/// See [`HandlerError`].
pub async fn handle(
    store: &Arc<JobStore>,
    registry: &Arc<JobRegistry>,
    request: ControlRequest,
) -> Result<ControlResponse, HandlerError> {
    let result = match request.op {
        Some(control_request::Op::Submit(submit)) => {
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

            let job_id = Uuid::new_v4().to_string();
            let manifest = submit.manifest;
            let encoding = submit.manifest_encoding;
            let inserted_id = job_id.clone();
            let store = Arc::clone(store);

            // Mint the job's dedicated channel + caps BEFORE the row is
            // persisted (#212 B2, adversarial): if minting faulted after the
            // row was already written, the row would be stranded `Pending`
            // with no channel, and `Attach` would misreport it as
            // "restarted since submit?" instead of surfacing the real fault.
            let mut job_channel = dispatch::mint_job_channel(&job_id, registry.authority()).await?;
            job_channel.granted_caps = granted_caps;
            tokio::task::spawn_blocking(move || store.insert_pending(&inserted_id, &manifest, &encoding)).await??;
            registry.insert(job_id.clone(), job_channel);

            control_response::Result::Submit(SubmitResponse { job_id })
        }
        Some(control_request::Op::Cancel(cancel)) => {
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
            Some(job) if cap_has_expired(&job.observer_cap) => control_response::Result::Error(ControlError {
                message: format!(
                    "job {}'s attach cap has expired; re-submit to get a new one",
                    attach.job_id
                ),
            }),
            Some(job) => control_response::Result::Attach(AttachResponse {
                channel_id: attach.job_id.clone(),
                cap: encode_cap(&job.observer_cap)?,
            }),
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
            let status = tokio::task::spawn_blocking(move || store.status(&job_id)).await??;
            match status {
                Some(status) => control_response::Result::Status(StatusResponse {
                    job_id: status_req.job_id,
                    status: status.into(),
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
    let Some(expires_at) = cap.scope.expires_at else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    expires_at <= now
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
        let (store, registry) = (new_store(), new_registry());
        let response = handle(&store, &registry, submit_req(1)).await?;
        let job_id = match response.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };
        assert_eq!(response.request_id, 1);
        assert_eq!(store.status(&job_id)?, Some(JobStatus::Pending));
        Ok(())
    }

    #[tokio::test]
    async fn status_of_an_unknown_job_is_a_control_error_not_a_default() -> anyhow::Result<()> {
        let (store, registry) = (new_store(), new_registry());
        let response = handle(
            &store,
            &registry,
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
        let (store, registry) = (new_store(), new_registry());
        let response = handle(
            &store,
            &registry,
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
        let (store, registry) = (new_store(), new_registry());
        handle(&store, &registry, submit_req(1)).await?;
        let response = handle(&store, &registry, req(2, control_request::Op::List(ListRequest {}))).await?;
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
        let (store, registry) = (new_store(), new_registry());
        let submitted = handle(&store, &registry, submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let response = handle(
            &store,
            &registry,
            req(2, control_request::Op::Attach(AttachRequest { job_id: job_id.clone() })),
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

    /// Adversarial (#212): `Attach` on a job id that was never submitted is
    /// refused by name, never a fabricated channel.
    #[tokio::test]
    async fn attach_on_an_unknown_job_is_refused_not_fabricated() -> anyhow::Result<()> {
        let (store, registry) = (new_store(), new_registry());
        let response = handle(
            &store,
            &registry,
            req(
                1,
                control_request::Op::Attach(AttachRequest {
                    job_id: "never-submitted".to_owned(),
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
        let (store, registry) = (new_store(), new_registry());
        store.insert_pending("job-from-before-restart", b"m", "test/v1")?;

        let response = handle(
            &store,
            &registry,
            req(
                1,
                control_request::Op::Attach(AttachRequest {
                    job_id: "job-from-before-restart".to_owned(),
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
        let (store, registry) = (new_store(), new_registry());
        let submitted = handle(&store, &registry, submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id })) => job_id,
            other => anyhow::bail!("expected a Submit response, got {other:?}"),
        };

        let job = registry.get(&job_id).context("the submitted job must be registered")?;
        let mut expired_cap = job.observer_cap.clone();
        expired_cap.scope.expires_at = Some(0); // the distant past
        registry.insert(
            job_id.clone(),
            dispatch::JobChannel {
                channel: Arc::clone(&job.channel),
                agent_cap: job.agent_cap.clone(),
                observer_cap: expired_cap,
                remote_link: None,
                granted_caps: job.granted_caps.clone(),
            },
        );

        let response = handle(
            &store,
            &registry,
            req(2, control_request::Op::Attach(AttachRequest { job_id: job_id.clone() })),
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

        let (store, registry) = (new_store(), new_registry());
        let submitted = handle(&store, &registry, submit_req(1)).await?;
        let job_id = match submitted.result {
            Some(control_response::Result::Submit(SubmitResponse { job_id })) => job_id,
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
            },
        );

        let response = handle(
            &store,
            &registry,
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

    // ---- Decision C-at-Submit (#226) ----

    /// Positive: a submitter holding `full_rights` on a channel can submit a
    /// job requesting a strictly narrower right there; the job is accepted.
    #[tokio::test]
    async fn a_submitter_holding_a_cap_can_submit_a_job_requesting_a_narrower_right() -> anyhow::Result<()> {
        let (store, registry) = (new_store(), new_registry());
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
        let (store, registry) = (new_store(), new_registry());
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
        let (store, registry) = (new_store(), new_registry());
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
            submit_req_with_caps(1, manifest, vec![submitter_cap]),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("refused"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }

        let list = handle(&store, &registry, req(2, control_request::Op::List(ListRequest {}))).await?;
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
        let (store, registry) = (new_store(), new_registry());
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
        let (store, registry) = (new_store(), new_registry());
        let mut forged_cap = registry.authority().mint(CapScope {
            peer: PeerId::from("operator"),
            channel: ChannelId::from("peer-group-1"),
            rights: full_rights(),
            expires_at: None,
        })?;
        forged_cap.proof[0] ^= 0xFF; // tamper the proof
        let manifest = manifest_json(vec![CapRequest {
            channel_id: ChannelId::from("peer-group-1"),
            rights: read_only(),
        }]);

        let response = handle(&store, &registry, submit_req_with_caps(1, manifest, vec![forged_cap])).await?;
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
        let (store, registry) = (new_store(), new_registry());
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

        let response = handle(&store, &registry, submit_req_with_caps(1, manifest, vec![expired_cap])).await?;
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
        let (store, registry) = (new_store(), new_registry());
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

        let response = handle(&store, &registry, submit_req_with_caps(1, manifest, vec![cap])).await?;
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
        let (store, registry) = (new_store(), new_registry());
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

        let response = handle(&store, &registry, request).await?;
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
        let (store, registry) = (new_store(), new_registry());
        let response = handle(&store, &registry, submit_req(1)).await?;
        assert!(
            matches!(response.result, Some(control_response::Result::Submit(_))),
            "got {:?}",
            response.result
        );
        Ok(())
    }
}
