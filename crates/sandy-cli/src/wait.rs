//! Waiting for a daemon job to end, and the exit band its result gives (promote-and-remove prep, #483).
//!
//! The direct `sandy run` blocks until the job ends and exits `0`, `1`, `2` or `3` from its result. The daemon verbs
//! need the same: `sandyd` has no wait call, so the client polls `Status` until the job leaves `Pending` and
//! `Running`, within a bound it states.

use std::time::Duration;

use sandy::{ProcessExit, ResultEnvelope};
use sandy_control_proto::{JobStatus, StatusResponse};

/// Why a wait ended without a terminal status.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WaitError {
    /// The job was still not terminal when the bound passed.
    #[error("the job was still {0} after {1:?}")]
    TimedOut(String, Duration),
    /// A status call failed, or `sandyd` answered something other than a status.
    #[error("{0}")]
    Call(String),
}

/// The process exit band a terminal job gives, as the direct `sandy run` exits: `0` for a success, `3` for a failure
/// the platform may retry (an infra fault), `1` for any other failure and for a cancel (the direct classifier puts a
/// cancel with the task failures). A job that is not terminal has no band.
#[must_use]
pub fn exit_band(status: &StatusResponse) -> Option<ProcessExit> {
    if !is_terminal(status) {
        return None;
    }
    if status.status() == JobStatus::Succeeded {
        return Some(ProcessExit::Succeeded);
    }
    // A failure the platform may retry is the envelope's own `retryable` flag (the infra-fault band); a row recorded
    // before envelopes were stored has none, and reads as a task failure.
    let retryable = status
        .result_envelope
        .as_deref()
        .and_then(|bytes| serde_json::from_slice::<ResultEnvelope>(bytes).ok())
        .is_some_and(|envelope| envelope.retryable);
    Some(if status.status() == JobStatus::Failed && retryable {
        ProcessExit::InfraFault
    } else {
        ProcessExit::TaskFailure
    })
}

/// Whether `status` is a state a job can no longer leave.
#[must_use]
pub fn is_terminal(status: &StatusResponse) -> bool {
    matches!(
        status.status(),
        JobStatus::Succeeded | JobStatus::Failed | JobStatus::Cancelled
    )
}

/// Poll `fetch` every `poll` until the job is terminal or `bound` has passed.
///
/// # Errors
///
/// [`WaitError::TimedOut`] naming the last state seen; [`WaitError::Call`] when `fetch` fails.
pub async fn wait_until_terminal<F, Fut>(
    mut fetch: F,
    poll: Duration,
    bound: Duration,
) -> Result<StatusResponse, WaitError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<StatusResponse, String>>,
{
    let started = tokio::time::Instant::now();
    loop {
        let status = fetch().await.map_err(WaitError::Call)?;
        if is_terminal(&status) {
            return Ok(status);
        }
        if started.elapsed() >= bound {
            return Err(WaitError::TimedOut(status.status().as_str_name().to_owned(), bound));
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;

    fn response(status: JobStatus, envelope: Option<ResultEnvelope>) -> StatusResponse {
        StatusResponse {
            job_id: "job-1".to_owned(),
            status: status.into(),
            exit_code: None,
            console_tail: String::new(),
            result_envelope: envelope.map(|e| serde_json::to_vec(&e).unwrap_or_default()),
        }
    }

    fn envelope(status: sandy::Status, retryable: bool) -> ResultEnvelope {
        sandy::build_envelope(
            "job-1",
            None,
            sandy::Classification {
                status,
                retryable,
                process_exit: ProcessExit::TaskFailure,
            },
            None,
            String::new(),
            String::new(),
            Vec::new(),
            None,
        )
    }

    /// The band is the direct `run`'s: success 0, a retryable failure 3, any other failure and a cancel 1. A job that
    /// has not ended has none.
    #[test]
    fn the_exit_band_follows_the_direct_runs() {
        use sandy::Status;
        let rows: Vec<(&str, StatusResponse, Option<ProcessExit>)> = vec![
            (
                "succeeded",
                response(JobStatus::Succeeded, Some(envelope(Status::Succeeded, false))),
                Some(ProcessExit::Succeeded),
            ),
            (
                "task failure",
                response(JobStatus::Failed, Some(envelope(Status::Failed, false))),
                Some(ProcessExit::TaskFailure),
            ),
            (
                "infra fault",
                response(JobStatus::Failed, Some(envelope(Status::Failed, true))),
                Some(ProcessExit::InfraFault),
            ),
            (
                "cancelled",
                response(JobStatus::Cancelled, Some(envelope(Status::Cancelled, false))),
                Some(ProcessExit::TaskFailure),
            ),
            (
                "failed, no envelope (a row from before envelopes)",
                response(JobStatus::Failed, None),
                Some(ProcessExit::TaskFailure),
            ),
            ("pending", response(JobStatus::Pending, None), None),
            ("running", response(JobStatus::Running, None), None),
        ];
        for (name, status, want) in rows {
            assert_eq!(exit_band(&status), want, "{name}");
            assert_eq!(is_terminal(&status), want.is_some(), "{name}: is_terminal");
        }
    }

    /// A wait returns the first terminal status and polls until then, once per interval.
    #[tokio::test]
    async fn a_wait_polls_until_the_job_is_terminal() -> anyhow::Result<()> {
        let script = std::sync::Mutex::new(vec![
            response(JobStatus::Pending, None),
            response(JobStatus::Running, None),
            response(JobStatus::Succeeded, Some(envelope(sandy::Status::Succeeded, false))),
        ]);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let got = wait_until_terminal(
            || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let next = script.lock().map(|mut s| s.remove(0)).map_err(|e| e.to_string());
                async move { next }
            },
            Duration::from_millis(5),
            Duration::from_secs(30),
        )
        .await
        .context("the job ends")?;
        assert_eq!(got.status, i32::from(JobStatus::Succeeded));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        Ok(())
    }

    /// A job that never ends is reported after the bound, naming the state it was in.
    #[tokio::test]
    async fn a_wait_that_passes_its_bound_says_what_state_the_job_was_in() {
        let err = wait_until_terminal(
            || async { Ok(response(JobStatus::Running, None)) },
            Duration::from_millis(5),
            Duration::from_millis(60),
        )
        .await
        .expect_err("a running job never ends");
        let WaitError::TimedOut(state, bound) = err else {
            panic!("expected a timeout, got {err:?}");
        };
        assert!(state.contains("RUNNING"), "{state}");
        assert_eq!(bound, Duration::from_millis(60));
    }

    /// A failing status call ends the wait with that failure, not a hang.
    #[tokio::test]
    async fn a_failing_status_call_ends_the_wait() {
        let err = wait_until_terminal(
            || async { Err("the daemon closed the connection".to_owned()) },
            Duration::from_millis(5),
            Duration::from_millis(60),
        )
        .await
        .expect_err("the call fails");
        assert_eq!(err, WaitError::Call("the daemon closed the connection".to_owned()));
    }
}
