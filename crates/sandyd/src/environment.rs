//! The environment operations of the control RPC (#587, slice A2): create,
//! get, list, stop, resume, cancel and delete, served over an
//! [`EnvironmentStore`]. Separate from [`crate::handler`] so the job handler
//! stays untouched; `serve_connection` routes an environment op here first.
//!
//! This handler validates and records. It launches nothing: a driver (slice C)
//! turns `Provisioning` into a VM and reports `Ready` or `Failed` back to the
//! store. Until then a created environment stays `Provisioning`, and
//! `connection` is never set.
//!
//! The create payload is stored as the prost encoding of an
//! [`EnvironmentSpec`], so two retries with equal fields are byte-equal
//! whatever order a client wrote them in.

use std::sync::Arc;

use sandy_control_proto::{
    ControlRequest, ControlResponse, control_request,
    v1::{
        EnvironmentError, EnvironmentErrorCode, EnvironmentFailure, EnvironmentLifetimeKind, EnvironmentResponse,
        EnvironmentSpec, EnvironmentState as WireState, ListEnvironmentsResponse,
    },
};

use crate::environment_store::{EnvironmentStore, EnvironmentStoreError};

/// `EnvironmentStore::create`'s payload encoding name.
pub const SPEC_ENCODING: &str = "sandy.control.v1.EnvironmentSpec";

/// Whether `op` is an environment operation this module serves.
pub fn is_environment_op(op: &Option<control_request::Op>) -> bool {
    let _ = (
        op,
        EnvironmentErrorCode::NotFound,
        EnvironmentLifetimeKind::Ephemeral,
        WireState::Ready,
    );
    unimplemented!("#587 slice A2: red")
}

/// Serve one environment request against `store`.
///
/// # Errors
/// [`EnvironmentStoreError`] when the store itself faults; a refused request is
/// an [`EnvironmentError`] response, not an `Err`.
pub async fn handle(
    store: &Arc<EnvironmentStore>,
    request: ControlRequest,
) -> Result<ControlResponse, EnvironmentStoreError> {
    let _ = (
        store,
        request,
        EnvironmentError::default(),
        EnvironmentFailure::default(),
        EnvironmentResponse::default(),
        EnvironmentSpec::default(),
        ListEnvironmentsResponse::default(),
    );
    unimplemented!("#587 slice A2: red")
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result, bail};
    use sandy_control_proto::{
        control_response,
        v1::{
            CancelEnvironmentRequest, CreateEnvironmentRequest, DeleteEnvironmentRequest, EnvironmentLifetime,
            GetEnvironmentRequest, ListEnvironmentsRequest, ResumeEnvironmentRequest, StopEnvironmentRequest,
        },
    };

    use super::*;

    fn lifetime(kind: EnvironmentLifetimeKind, ttl_secs: u64) -> Option<EnvironmentLifetime> {
        Some(EnvironmentLifetime {
            kind: kind.into(),
            ttl_secs,
        })
    }

    fn spec(kind: EnvironmentLifetimeKind, ttl_secs: u64) -> EnvironmentSpec {
        EnvironmentSpec {
            profile: "harness".to_owned(),
            size: "small".to_owned(),
            lifetime: lifetime(kind, ttl_secs),
            task_ref: "owner/repo#12".to_owned(),
        }
    }

    fn ephemeral() -> EnvironmentSpec {
        spec(EnvironmentLifetimeKind::Ephemeral, 600)
    }

    fn persistent() -> EnvironmentSpec {
        spec(EnvironmentLifetimeKind::Persistent, 0)
    }

    fn store() -> Result<Arc<EnvironmentStore>> {
        Ok(Arc::new(EnvironmentStore::open_in_memory()?))
    }

    fn request(op: control_request::Op) -> ControlRequest {
        ControlRequest {
            request_id: 7,
            op: Some(op),
        }
    }

    /// The reply, or the typed refusal `(code, message)`.
    async fn call(
        store: &Arc<EnvironmentStore>,
        op: control_request::Op,
    ) -> Result<std::result::Result<control_response::Result, (EnvironmentErrorCode, String)>> {
        let response = handle(store, request(op)).await?;
        assert_eq!(response.request_id, 7, "the reply must echo the request id");
        match response.result.context("a reply must carry a result")? {
            control_response::Result::EnvironmentError(e) => {
                let code = EnvironmentErrorCode::try_from(e.code).context("known error code")?;
                Ok(Err((code, e.message)))
            }
            other => Ok(Ok(other)),
        }
    }

    async fn create(store: &Arc<EnvironmentStore>, key: &str, spec: EnvironmentSpec) -> Result<EnvironmentResponse> {
        let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: key.to_owned(),
            spec: Some(spec),
        });
        match call(store, op).await? {
            Ok(control_response::Result::Environment(env)) => Ok(env),
            other => bail!("expected an environment, got {other:?}"),
        }
    }

    async fn refused(store: &Arc<EnvironmentStore>, op: control_request::Op) -> Result<EnvironmentErrorCode> {
        match call(store, op).await? {
            Err((code, _)) => Ok(code),
            Ok(other) => bail!("expected a refusal, got {other:?}"),
        }
    }

    async fn state_after(store: &Arc<EnvironmentStore>, op: control_request::Op) -> Result<WireState> {
        match call(store, op).await? {
            Ok(control_response::Result::Environment(env)) => Ok(WireState::try_from(env.state)?),
            other => bail!("expected an environment, got {other:?}"),
        }
    }

    fn get(id: &str) -> control_request::Op {
        control_request::Op::GetEnvironment(GetEnvironmentRequest {
            environment_id: id.to_owned(),
        })
    }

    fn stop(id: &str) -> control_request::Op {
        control_request::Op::StopEnvironment(StopEnvironmentRequest {
            environment_id: id.to_owned(),
        })
    }

    fn resume(id: &str) -> control_request::Op {
        control_request::Op::ResumeEnvironment(ResumeEnvironmentRequest {
            environment_id: id.to_owned(),
        })
    }

    fn cancel(id: &str) -> control_request::Op {
        control_request::Op::CancelEnvironment(CancelEnvironmentRequest {
            environment_id: id.to_owned(),
        })
    }

    fn delete(id: &str) -> control_request::Op {
        control_request::Op::DeleteEnvironment(DeleteEnvironmentRequest {
            environment_id: id.to_owned(),
        })
    }

    #[test]
    fn only_environment_ops_are_environment_ops() {
        assert!(is_environment_op(&Some(get("x"))));
        assert!(is_environment_op(&Some(delete("x"))));
        assert!(!is_environment_op(&None));
        assert!(!is_environment_op(&Some(control_request::Op::List(
            sandy_control_proto::ListRequest {}
        ))));
    }

    #[tokio::test]
    async fn a_created_environment_is_provisioning_with_no_connection_or_failure() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", ephemeral()).await?;
        assert!(env.environment_id.starts_with("env-") && env.environment_id.len() > 8);
        assert_eq!(WireState::try_from(env.state)?, WireState::Provisioning);
        assert_eq!(env.connection, None, "no connection before Ready");
        assert_eq!(env.failure, None);
        assert_eq!(env.spec, Some(ephemeral()));
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_returns_the_same_environment_and_another_spec_is_a_conflict() -> Result<()> {
        let s = store()?;
        let first = create(&s, "k1", ephemeral()).await?;
        // Equal fields rebuilt from the wire bytes: still the same request.
        let rebuilt = prost_roundtrip(&ephemeral())?;
        let again = create(&s, "k1", rebuilt).await?;
        assert_eq!(again.environment_id, first.environment_id);

        let mut other = ephemeral();
        other.profile = "other".to_owned();
        let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k1".to_owned(),
            spec: Some(other),
        });
        assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::RequestIdConflict);
        assert_eq!(s.list()?.len(), 1, "a conflict must write nothing");
        Ok(())
    }

    fn prost_roundtrip(spec: &EnvironmentSpec) -> Result<EnvironmentSpec> {
        use prost::Message;
        Ok(EnvironmentSpec::decode(spec.encode_to_vec().as_slice())?)
    }

    #[tokio::test]
    async fn an_invalid_create_is_refused_and_writes_nothing() -> Result<()> {
        let s = store()?;
        let long = "a".repeat(129);
        let bad_keys = ["", "has space", "a/b", long.as_str(), "tab\there"];
        for key in bad_keys {
            let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
                idempotency_key: key.to_owned(),
                spec: Some(ephemeral()),
            });
            assert_eq!(
                refused(&s, op).await?,
                EnvironmentErrorCode::InvalidArgument,
                "key {key:?}"
            );
        }
        let mut cases: Vec<(&str, EnvironmentSpec)> = Vec::new();
        let mut c = ephemeral();
        c.profile = String::new();
        cases.push(("empty profile", c));
        let mut c = ephemeral();
        c.profile = "ghp_abcdefghijklmnopqrstuvwxyz0123456789".to_owned();
        cases.push(("token-shaped profile", c));
        let mut c = ephemeral();
        c.profile = "a b".to_owned();
        cases.push(("profile with a space", c));
        let mut c = ephemeral();
        c.size = "x".repeat(33);
        cases.push(("long size", c));
        let mut c = ephemeral();
        c.task_ref = "x".repeat(257);
        cases.push(("long task_ref", c));
        let mut c = ephemeral();
        c.task_ref = "bad\nref".to_owned();
        cases.push(("control char in task_ref", c));
        cases.push((
            "no lifetime",
            EnvironmentSpec {
                lifetime: None,
                ..ephemeral()
            },
        ));
        cases.push(("unspecified lifetime", spec(EnvironmentLifetimeKind::Unspecified, 0)));
        cases.push(("ephemeral without ttl", spec(EnvironmentLifetimeKind::Ephemeral, 0)));
        cases.push((
            "ephemeral ttl over 7 days",
            spec(EnvironmentLifetimeKind::Ephemeral, 604_801),
        ));
        cases.push(("persistent with ttl", spec(EnvironmentLifetimeKind::Persistent, 60)));
        for (what, bad) in cases {
            let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
                idempotency_key: "k".to_owned(),
                spec: Some(bad),
            });
            assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument, "{what}");
        }
        let no_spec = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k".to_owned(),
            spec: None,
        });
        assert_eq!(refused(&s, no_spec).await?, EnvironmentErrorCode::InvalidArgument);
        assert!(s.list()?.is_empty(), "a refused create must leave no row");
        Ok(())
    }

    #[tokio::test]
    async fn get_reports_the_environment_and_an_unknown_id_is_not_found() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", persistent()).await?;
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => assert_eq!(got, env),
            other => bail!("expected an environment, got {other:?}"),
        }
        assert_eq!(refused(&s, get("env-nope")).await?, EnvironmentErrorCode::NotFound);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_environment_reports_the_step_and_reason() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", ephemeral()).await?;
        s.mark_failed(&env.environment_id, "boot", "probe timed out")?;
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => {
                assert_eq!(WireState::try_from(got.state)?, WireState::Failed);
                assert_eq!(
                    got.failure,
                    Some(EnvironmentFailure {
                        step: "boot".to_owned(),
                        reason: "probe timed out".to_owned(),
                    })
                );
            }
            other => bail!("expected an environment, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn list_filters_by_state_and_task_ref() -> Result<()> {
        let s = store()?;
        let a = create(&s, "k1", ephemeral()).await?;
        let mut other = persistent();
        other.task_ref = "another-task".to_owned();
        let b = create(&s, "k2", other).await?;
        s.mark_ready(&b.environment_id)?;

        let list = |state: WireState, task_ref: &str| {
            control_request::Op::ListEnvironments(ListEnvironmentsRequest {
                state: state.into(),
                task_ref: task_ref.to_owned(),
            })
        };
        let ids = |reply: control_response::Result| -> Result<Vec<String>> {
            match reply {
                control_response::Result::Environments(l) => {
                    Ok(l.environments.into_iter().map(|e| e.environment_id).collect())
                }
                other => bail!("expected a list, got {other:?}"),
            }
        };
        let all = ids(call(&s, list(WireState::Unspecified, ""))
            .await?
            .map_err(|e| anyhow::anyhow!("{e:?}"))?)?;
        assert_eq!(all, [a.environment_id.clone(), b.environment_id.clone()]);
        let ready = ids(call(&s, list(WireState::Ready, ""))
            .await?
            .map_err(|e| anyhow::anyhow!("{e:?}"))?)?;
        assert_eq!(ready, [b.environment_id.clone()]);
        let by_task = ids(call(&s, list(WireState::Unspecified, "owner/repo#12"))
            .await?
            .map_err(|e| anyhow::anyhow!("{e:?}"))?)?;
        assert_eq!(by_task, [a.environment_id]);
        Ok(())
    }

    #[tokio::test]
    async fn stop_and_resume_keep_the_id_for_a_persistent_environment() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", persistent()).await?;
        assert_eq!(
            refused(&s, stop(&env.environment_id)).await?,
            EnvironmentErrorCode::InvalidState
        );
        s.mark_ready(&env.environment_id)?;
        assert_eq!(state_after(&s, stop(&env.environment_id)).await?, WireState::Stopped);
        assert_eq!(
            refused(&s, stop(&env.environment_id)).await?,
            EnvironmentErrorCode::InvalidState
        );
        assert_eq!(
            state_after(&s, resume(&env.environment_id)).await?,
            WireState::Provisioning
        );
        assert_eq!(
            refused(&s, resume(&env.environment_id)).await?,
            EnvironmentErrorCode::InvalidState
        );
        assert_eq!(refused(&s, stop("env-nope")).await?, EnvironmentErrorCode::NotFound);
        assert_eq!(refused(&s, resume("env-nope")).await?, EnvironmentErrorCode::NotFound);
        Ok(())
    }

    #[tokio::test]
    async fn an_ephemeral_environment_cannot_be_stopped_or_resumed() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", ephemeral()).await?;
        s.mark_ready(&env.environment_id)?;
        assert_eq!(
            refused(&s, stop(&env.environment_id)).await?,
            EnvironmentErrorCode::UnsupportedForLifetime,
            "even in Ready, where stop would otherwise apply"
        );
        assert_eq!(
            refused(&s, resume(&env.environment_id)).await?,
            EnvironmentErrorCode::UnsupportedForLifetime
        );
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => {
                assert_eq!(
                    WireState::try_from(got.state)?,
                    WireState::Ready,
                    "a refused stop changes nothing"
                );
            }
            other => bail!("expected an environment, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancel_applies_only_while_provisioning_and_ends_deleted() -> Result<()> {
        let s = store()?;
        let a = create(&s, "k1", ephemeral()).await?;
        assert_eq!(state_after(&s, cancel(&a.environment_id)).await?, WireState::Deleted);
        let b = create(&s, "k2", ephemeral()).await?;
        s.mark_ready(&b.environment_id)?;
        assert_eq!(
            refused(&s, cancel(&b.environment_id)).await?,
            EnvironmentErrorCode::InvalidState
        );
        assert_eq!(refused(&s, cancel("env-nope")).await?, EnvironmentErrorCode::NotFound);
        Ok(())
    }

    #[tokio::test]
    async fn delete_works_from_any_state_and_is_idempotent() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", persistent()).await?;
        s.mark_ready(&env.environment_id)?;
        assert_eq!(state_after(&s, delete(&env.environment_id)).await?, WireState::Deleted);
        assert_eq!(state_after(&s, delete(&env.environment_id)).await?, WireState::Deleted);
        assert_eq!(refused(&s, delete("env-nope")).await?, EnvironmentErrorCode::NotFound);
        // A retry of the create after delete returns the deleted environment, never a new one.
        let again = create(&s, "k1", persistent()).await?;
        assert_eq!(again.environment_id, env.environment_id);
        assert_eq!(WireState::try_from(again.state)?, WireState::Deleted);
        Ok(())
    }

    #[tokio::test]
    async fn the_row_cap_is_a_typed_quota_error_and_never_refuses_a_retry() -> Result<()> {
        let s = Arc::new(EnvironmentStore::open_in_memory()?.with_max_rows(Some(1)));
        create(&s, "k1", ephemeral()).await?;
        let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k2".to_owned(),
            spec: Some(ephemeral()),
        });
        assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::QuotaExceeded);
        create(&s, "k1", ephemeral()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_or_empty_environment_id_is_invalid_not_a_lookup() -> Result<()> {
        let s = store()?;
        for op in [get(""), stop(""), resume(""), cancel(""), delete("")] {
            assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument);
        }
        Ok(())
    }
}
