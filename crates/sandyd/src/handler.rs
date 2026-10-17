//! Dispatch one [`ControlRequest`] to a [`ControlResponse`] against the
//! [`JobStore`] (#212, B1). No real dispatch into the fabric: `Submit`/
//! `Cancel`/`Status`/`List` only persist/read state; `Attach` refuses with a
//! named error rather than a fabricated channel id, since no real channel
//! exists to attach to until B2 (`sandy-orchestrator`) lands.

use std::sync::Arc;

use sandy_control_proto::{
    CancelResponse, ControlError, ControlRequest, ControlResponse, JobSummary as WireJobSummary, ListResponse,
    StatusResponse, SubmitResponse, control_request, control_response,
};
use uuid::Uuid;

use crate::store::{CancelOutcome, JobStore, StoreError};

/// A failure handling a [`ControlRequest`]: either the job store itself
/// faulted, or the `spawn_blocking` task running a store call panicked or
/// was cancelled. Neither is a job-level refusal (an unknown job id, an
/// already-terminal cancel) — those are [`ControlError`] responses, not
/// `Err`s, since the request was understood and the daemon answered it.
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
}

/// Handle `request` against `store`, blocking on the store's synchronous
/// connection via `spawn_blocking` so the connection's async read/write loop
/// is never held up by it. Takes `store` by `&Arc`, cloning it (a refcount
/// bump, not a deep copy) into each `spawn_blocking` closure that needs a
/// `'static` capture — never leaks an allocation per call.
///
/// # Errors
/// See [`HandlerError`].
pub async fn handle(store: &Arc<JobStore>, request: ControlRequest) -> Result<ControlResponse, HandlerError> {
    let result = match request.op {
        Some(control_request::Op::Submit(submit)) => {
            let job_id = Uuid::new_v4().to_string();
            let manifest = submit.manifest;
            let encoding = submit.manifest_encoding;
            let inserted_id = job_id.clone();
            let store = Arc::clone(store);
            tokio::task::spawn_blocking(move || store.insert_pending(&inserted_id, &manifest, &encoding)).await??;
            control_response::Result::Submit(SubmitResponse { job_id })
        }
        Some(control_request::Op::Cancel(cancel)) => {
            let job_id = cancel.job_id.clone();
            let store = Arc::clone(store);
            let outcome = tokio::task::spawn_blocking(move || store.cancel(&job_id)).await??;
            match outcome {
                CancelOutcome::Cancelled => control_response::Result::Cancel(CancelResponse {}),
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
        Some(control_request::Op::Attach(attach)) => control_response::Result::Error(ControlError {
            message: format!(
                "job {} is not yet dispatchable: the orchestrator core (B2) is not wired up",
                attach.job_id
            ),
        }),
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

#[cfg(test)]
mod tests {
    use sandy_control_proto::{AttachRequest, CancelRequest, JobStatus, ListRequest, StatusRequest, SubmitRequest};

    use super::*;

    fn new_store() -> Arc<JobStore> {
        Arc::new(JobStore::open_in_memory().expect("in-memory store"))
    }

    fn req(id: u64, op: control_request::Op) -> ControlRequest {
        ControlRequest {
            request_id: id,
            op: Some(op),
        }
    }

    #[tokio::test]
    async fn submit_persists_and_returns_a_job_id() -> anyhow::Result<()> {
        let store = new_store();
        let response = handle(
            &store,
            req(
                1,
                control_request::Op::Submit(SubmitRequest {
                    manifest: b"m".to_vec(),
                    manifest_encoding: "test/v1".to_owned(),
                }),
            ),
        )
        .await?;
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
        let store = new_store();
        let response = handle(
            &store,
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
        let store = new_store();
        let response = handle(
            &store,
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
        let store = new_store();
        handle(
            &store,
            req(
                1,
                control_request::Op::Submit(SubmitRequest {
                    manifest: b"m".to_vec(),
                    manifest_encoding: "test/v1".to_owned(),
                }),
            ),
        )
        .await?;
        let response = handle(&store, req(2, control_request::Op::List(ListRequest {}))).await?;
        let jobs = match response.result {
            Some(control_response::Result::List(ListResponse { jobs })) => jobs,
            other => anyhow::bail!("expected a List response, got {other:?}"),
        };
        assert_eq!(jobs.len(), 1);
        Ok(())
    }

    /// Adversarial (#212): `Attach` must never fabricate a channel id before
    /// B2 actually provisions one — a plausible-looking fake would let a
    /// client act on a channel that doesn't exist.
    #[tokio::test]
    async fn attach_refuses_with_a_named_error_not_a_fake_channel() -> anyhow::Result<()> {
        let store = new_store();
        let response = handle(
            &store,
            req(
                1,
                control_request::Op::Attach(AttachRequest {
                    job_id: "job-1".to_owned(),
                }),
            ),
        )
        .await?;
        match response.result {
            Some(control_response::Result::Error(ControlError { message })) => {
                assert!(message.contains("not yet dispatchable"), "got {message:?}");
            }
            other => anyhow::bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }
}
