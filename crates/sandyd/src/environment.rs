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

use prost::Message;
use sandy_control_proto::{
    ControlRequest, ControlResponse, control_request, control_response,
    v1::{
        EnvironmentConnection, EnvironmentError, EnvironmentErrorCode, EnvironmentFailure, EnvironmentLifetimeKind,
        EnvironmentResponse, EnvironmentSpec, EnvironmentState as WireState, ListEnvironmentsResponse,
    },
};

use crate::environment_store::{
    CreateOutcome, EnvTransition, EnvironmentRecord, EnvironmentState, EnvironmentStore, EnvironmentStoreError,
};

/// The create payload's encoding name, stored beside the spec bytes.
pub const SPEC_ENCODING: &str = "sandy.control.v1.EnvironmentSpec";

const MAX_KEY: usize = 128;
const MAX_PROFILE: usize = 64;
const MAX_SIZE: usize = 32;
const MAX_TASK_REF: usize = 256;
/// The most environments one `ListEnvironments` reply may carry. A row is at
/// most about 415 bytes on the wire, so this stays under the control frame limit.
pub const MAX_LIST_ROWS: usize = 1000;
/// The longest ephemeral lifetime a client may ask for: seven days.
const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// A fault the handler cannot turn into a typed refusal. The connection is
/// closed and the fault logged, like a job-store fault.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentHandlerError {
    /// The environment store faulted.
    #[error(transparent)]
    Store(#[from] EnvironmentStoreError),
    /// A blocking store call panicked.
    #[error("environment store task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// A stored spec does not decode; a row this handler wrote always does.
    #[error("environment {0:?} holds a spec that does not decode")]
    CorruptSpec(String),
    /// A freshly minted id already names another environment.
    #[error("a freshly minted environment id collided with an existing one")]
    IdCollision,
}

/// Whether `op` is an environment operation this module serves.
pub fn is_environment_op(op: &Option<control_request::Op>) -> bool {
    matches!(
        op,
        Some(
            control_request::Op::CreateEnvironment(_)
                | control_request::Op::GetEnvironment(_)
                | control_request::Op::ListEnvironments(_)
                | control_request::Op::StopEnvironment(_)
                | control_request::Op::ResumeEnvironment(_)
                | control_request::Op::CancelEnvironment(_)
                | control_request::Op::DeleteEnvironment(_)
        )
    )
}

type Reply = Result<control_response::Result, EnvironmentHandlerError>;

fn refuse(code: EnvironmentErrorCode, message: impl Into<String>) -> Reply {
    Ok(control_response::Result::EnvironmentError(EnvironmentError {
        code: code.into(),
        message: message.into(),
    }))
}

/// Run a blocking store call off the async runtime.
async fn blocking<T: Send + 'static>(
    store: &Arc<EnvironmentStore>,
    f: impl FnOnce(&EnvironmentStore) -> Result<T, EnvironmentStoreError> + Send + 'static,
) -> Result<T, EnvironmentHandlerError> {
    let store = Arc::clone(store);
    Ok(tokio::task::spawn_blocking(move || f(&store)).await??)
}

/// Serve one environment request against `store`. A refused request is an
/// [`EnvironmentError`] reply, not an `Err`.
///
/// # Errors
/// [`EnvironmentHandlerError`] for a fault no client can act on.
pub async fn handle(
    store: &Arc<EnvironmentStore>,
    request: ControlRequest,
) -> Result<ControlResponse, EnvironmentHandlerError> {
    use control_request::Op;
    let result = match request.op {
        Some(Op::CreateEnvironment(r)) => create(store, r.idempotency_key, r.spec).await?,
        Some(Op::GetEnvironment(r)) => get(store, r.environment_id).await?,
        Some(Op::ListEnvironments(r)) => list(store, r.state, r.task_ref).await?,
        Some(Op::StopEnvironment(r)) => stop_or_resume(store, r.environment_id, true).await?,
        Some(Op::ResumeEnvironment(r)) => stop_or_resume(store, r.environment_id, false).await?,
        Some(Op::CancelEnvironment(r)) => cancel(store, r.environment_id).await?,
        Some(Op::DeleteEnvironment(r)) => delete(store, r.environment_id).await?,
        _ => refuse(EnvironmentErrorCode::InvalidArgument, "not an environment operation")?,
    };
    Ok(ControlResponse {
        request_id: request.request_id,
        result: Some(result),
    })
}

/// A key or name: 1 to `max` bytes of letters, digits, `-`, `_` and `.`.
fn token_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Prefixes of well-known credential formats. A profile names an identity; it
/// must never be, or carry, a credential.
const SECRET_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "glptt-",
    "sk-",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "AKIA",
    "ASIA",
    "AIza",
    "npm_",
];

fn looks_like_secret(s: &str) -> bool {
    SECRET_PREFIXES
        .iter()
        .any(|p| s.starts_with(p) && s.len() >= p.len() + 8)
}

/// Unicode direction marks and overrides: invisible, and they reorder text.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn validate_spec(spec: &EnvironmentSpec) -> Result<(), String> {
    if !token_ok(&spec.profile, MAX_PROFILE) {
        return Err(format!(
            "profile must be 1 to {MAX_PROFILE} letters, digits, '-', '_' or '.'"
        ));
    }
    if looks_like_secret(&spec.profile) {
        return Err("profile names an identity profile; it must not look like a credential".to_owned());
    }
    if !spec.size.is_empty() && !token_ok(&spec.size, MAX_SIZE) {
        return Err(format!(
            "size must be empty or 1 to {MAX_SIZE} letters, digits, '-', '_' or '.'"
        ));
    }
    if spec.task_ref.len() > MAX_TASK_REF || spec.task_ref.chars().any(|c| c.is_control() || is_bidi_control(c)) {
        return Err(format!(
            "task_ref must be at most {MAX_TASK_REF} bytes with no control or bidirectional-override characters"
        ));
    }
    let lifetime = spec.lifetime.as_ref().ok_or("lifetime is required")?;
    match EnvironmentLifetimeKind::try_from(lifetime.kind) {
        Ok(EnvironmentLifetimeKind::Ephemeral) if (1..=MAX_TTL_SECS).contains(&lifetime.ttl_secs) => Ok(()),
        Ok(EnvironmentLifetimeKind::Ephemeral) => Err(format!(
            "an ephemeral environment needs ttl_secs between 1 and {MAX_TTL_SECS}"
        )),
        Ok(EnvironmentLifetimeKind::Persistent) if lifetime.ttl_secs == 0 => Ok(()),
        Ok(EnvironmentLifetimeKind::Persistent) => Err("a persistent environment has no ttl_secs".to_owned()),
        _ => Err("lifetime.kind must be EPHEMERAL or PERSISTENT".to_owned()),
    }
}

fn to_wire_state(state: EnvironmentState) -> WireState {
    match state {
        EnvironmentState::Provisioning => WireState::Provisioning,
        EnvironmentState::Ready => WireState::Ready,
        EnvironmentState::Stopped => WireState::Stopped,
        EnvironmentState::Failed => WireState::Failed,
        EnvironmentState::Deleted => WireState::Deleted,
    }
}

fn from_wire_state(state: WireState) -> Option<EnvironmentState> {
    match state {
        WireState::Unspecified => None,
        WireState::Provisioning => Some(EnvironmentState::Provisioning),
        WireState::Ready => Some(EnvironmentState::Ready),
        WireState::Stopped => Some(EnvironmentState::Stopped),
        WireState::Failed => Some(EnvironmentState::Failed),
        WireState::Deleted => Some(EnvironmentState::Deleted),
    }
}

fn decode_spec(record: &EnvironmentRecord) -> Result<EnvironmentSpec, EnvironmentHandlerError> {
    EnvironmentSpec::decode(record.spec.as_slice())
        .map_err(|_| EnvironmentHandlerError::CorruptSpec(record.environment_id.clone()))
}

fn to_wire(record: EnvironmentRecord) -> Result<EnvironmentResponse, EnvironmentHandlerError> {
    let spec = decode_spec(&record)?;
    Ok(EnvironmentResponse {
        environment_id: record.environment_id,
        state: to_wire_state(record.state).into(),
        steps: Vec::new(),
        failure: record.failure.map(|f| EnvironmentFailure {
            step: f.step,
            reason: f.reason,
        }),
        // The launch driver records the endpoint when its probe passes. Shown
        // only while Ready: any other state has no service to reach.
        connection: record
            .endpoint
            .as_ref()
            .filter(|_| record.state == EnvironmentState::Ready)
            .map(|endpoint| EnvironmentConnection {
                url: format!("http://{endpoint}"),
            }),
        spec: Some(spec),
    })
}

fn reply(record: EnvironmentRecord) -> Reply {
    Ok(control_response::Result::Environment(to_wire(record)?))
}

async fn create(store: &Arc<EnvironmentStore>, key: String, spec: Option<EnvironmentSpec>) -> Reply {
    if !token_ok(&key, MAX_KEY) {
        return refuse(
            EnvironmentErrorCode::InvalidArgument,
            format!("idempotency_key must be 1 to {MAX_KEY} letters, digits, '-', '_' or '.'"),
        );
    }
    let Some(spec) = spec else {
        return refuse(EnvironmentErrorCode::InvalidArgument, "spec is required");
    };
    let bytes = spec.encode_to_vec();
    // A retry is answered from the stored row before any validation: a rule
    // tightened by a later daemon must not turn an accepted create's replay
    // into a refusal.
    let lookup = key.clone();
    if let Some(existing) = blocking(store, move |s| s.get_by_request_id(&lookup)).await? {
        return if existing.spec == bytes && existing.spec_encoding == SPEC_ENCODING {
            reply(existing)
        } else {
            refuse(
                EnvironmentErrorCode::RequestIdConflict,
                "this idempotency_key was used with a different spec",
            )
        };
    }
    if let Err(why) = validate_spec(&spec) {
        return refuse(EnvironmentErrorCode::InvalidArgument, why);
    }
    let new_id = format!("env-{}", uuid::Uuid::new_v4().simple());
    let outcome = blocking(store, move |s| s.create(&key, &new_id, &bytes, SPEC_ENCODING)).await?;
    match outcome {
        CreateOutcome::Created(record) | CreateOutcome::Existing(record) => reply(record),
        CreateOutcome::Conflict => refuse(
            EnvironmentErrorCode::RequestIdConflict,
            "this idempotency_key was used with a different spec",
        ),
        CreateOutcome::CapExceeded { max } => refuse(
            EnvironmentErrorCode::QuotaExceeded,
            format!("the daemon already holds {max} environments"),
        ),
        CreateOutcome::IdTaken => Err(EnvironmentHandlerError::IdCollision),
    }
}

fn id_ok(id: &str) -> bool {
    token_ok(id, MAX_KEY)
}

fn bad_id() -> Reply {
    refuse(
        EnvironmentErrorCode::InvalidArgument,
        "environment_id is missing or malformed",
    )
}

fn not_found(id: &str) -> Reply {
    refuse(EnvironmentErrorCode::NotFound, format!("no environment {id:?}"))
}

async fn fetch(store: &Arc<EnvironmentStore>, id: &str) -> Result<Option<EnvironmentRecord>, EnvironmentHandlerError> {
    let id = id.to_owned();
    blocking(store, move |s| s.get(&id)).await
}

async fn get(store: &Arc<EnvironmentStore>, id: String) -> Reply {
    if !id_ok(&id) {
        return bad_id();
    }
    match fetch(store, &id).await? {
        Some(record) => reply(record),
        None => not_found(&id),
    }
}

async fn list(store: &Arc<EnvironmentStore>, state: i32, task_ref: String) -> Reply {
    let Ok(wire) = WireState::try_from(state) else {
        return refuse(EnvironmentErrorCode::InvalidArgument, "unknown state filter");
    };
    let records = match from_wire_state(wire) {
        None => blocking(store, EnvironmentStore::list).await?,
        Some(s) => blocking(store, move |st| st.list_by_state(s)).await?,
    };
    // Without a state filter, deleted rows (kept for replay) stay out of the reply.
    let hide_deleted = wire == WireState::Unspecified;
    let mut environments = Vec::new();
    for record in records {
        if hide_deleted && record.state == EnvironmentState::Deleted {
            continue;
        }
        let wire = to_wire(record)?;
        if task_ref.is_empty() || wire.spec.as_ref().is_some_and(|s| s.task_ref == task_ref) {
            environments.push(wire);
        }
    }
    if environments.len() > MAX_LIST_ROWS {
        return refuse(
            EnvironmentErrorCode::InvalidArgument,
            format!(
                "{} environments match; narrow the list with a state or task_ref (at most {MAX_LIST_ROWS} per reply)",
                environments.len()
            ),
        );
    }
    Ok(control_response::Result::Environments(ListEnvironmentsResponse {
        environments,
    }))
}

/// Applies an [`EnvTransition`] to the reply a client sees.
async fn finish(store: &Arc<EnvironmentStore>, id: &str, moved: EnvTransition, needs: &str) -> Reply {
    match moved {
        EnvTransition::Applied | EnvTransition::Unchanged => match fetch(store, id).await? {
            Some(record) => reply(record),
            None => not_found(id),
        },
        EnvTransition::NotFound => not_found(id),
        EnvTransition::Refused(state) => refuse(
            EnvironmentErrorCode::InvalidState,
            format!("environment is {}; {needs}", state.as_str()),
        ),
    }
}

async fn stop_or_resume(store: &Arc<EnvironmentStore>, id: String, stop: bool) -> Reply {
    if !id_ok(&id) {
        return bad_id();
    }
    let Some(record) = fetch(store, &id).await? else {
        return not_found(&id);
    };
    let spec = decode_spec(&record)?;
    let ephemeral = spec
        .lifetime
        .as_ref()
        .is_some_and(|l| l.kind == i32::from(EnvironmentLifetimeKind::Ephemeral));
    if ephemeral {
        return refuse(
            EnvironmentErrorCode::UnsupportedForLifetime,
            "an ephemeral environment lives for one task and cannot be stopped or resumed",
        );
    }
    let key = id.clone();
    let (moved, needs) = if stop {
        (
            blocking(store, move |s| s.stop(&key)).await?,
            "only a ready environment can be stopped",
        )
    } else {
        (
            blocking(store, move |s| s.resume(&key)).await?,
            "only a stopped environment can be resumed",
        )
    };
    finish(store, &id, moved, needs).await
}

async fn cancel(store: &Arc<EnvironmentStore>, id: String) -> Reply {
    if !id_ok(&id) {
        return bad_id();
    }
    let key = id.clone();
    let moved = blocking(store, move |s| s.cancel(&key)).await?;
    finish(
        store,
        &id,
        moved,
        "only an environment still provisioning can be cancelled",
    )
    .await
}

async fn delete(store: &Arc<EnvironmentStore>, id: String) -> Reply {
    if !id_ok(&id) {
        return bad_id();
    }
    let key = id.clone();
    let moved = blocking(store, move |s| s.delete(&key)).await?;
    finish(store, &id, moved, "delete applies from every state").await
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
        assert_eq!(ready, [b.environment_id]);
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

    /// Hand-encoded `EnvironmentSpec` bytes: fields in a different order than
    /// prost writes them, an explicit empty `size`, and an unknown field.
    fn raw_spec(size: Option<&str>) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend([0x22, 13]); // task_ref (4), written first
        b.extend(b"owner/repo#12");
        b.extend([0x78, 0x01]); // unknown field 15
        b.extend([0x1A, 5, 0x08, 0x01, 0x10, 0xD8, 0x04]); // lifetime: ephemeral, ttl 600
        b.extend([0x0A, 7]); // profile (1)
        b.extend(b"harness");
        if let Some(size) = size {
            b.push(0x12);
            b.push(size.len() as u8);
            b.extend(size.as_bytes());
        }
        b
    }

    #[tokio::test]
    async fn equal_fields_in_another_wire_order_with_an_unknown_field_are_the_same_request() -> Result<()> {
        use prost::Message;
        let s = store()?;
        let first = create(&s, "k1", ephemeral()).await?;
        let decoded = EnvironmentSpec::decode(raw_spec(Some("small")).as_slice())?;
        assert_eq!(
            decoded,
            ephemeral(),
            "the hand-built bytes must decode to the same spec"
        );
        let again = create(&s, "k1", decoded).await?;
        assert_eq!(again.environment_id, first.environment_id);
        // An explicit empty size and an omitted size are the same request.
        let explicit = EnvironmentSpec::decode(raw_spec(Some("")).as_slice())?;
        let omitted = EnvironmentSpec::decode(raw_spec(None).as_slice())?;
        let a = create(&s, "k2", explicit).await?;
        let b = create(&s, "k2", omitted).await?;
        assert_eq!(a.environment_id, b.environment_id);
        Ok(())
    }

    #[tokio::test]
    async fn the_ttl_boundaries_are_accepted_and_unknown_enum_values_are_refused() -> Result<()> {
        let s = store()?;
        create(&s, "k1", spec(EnvironmentLifetimeKind::Ephemeral, 1)).await?;
        create(&s, "k2", spec(EnvironmentLifetimeKind::Ephemeral, 604_800)).await?;
        let mut unknown_kind = ephemeral();
        unknown_kind.lifetime = Some(EnvironmentLifetime {
            kind: 99,
            ttl_secs: 600,
        });
        let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k3".to_owned(),
            spec: Some(unknown_kind),
        });
        assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument);
        let op = control_request::Op::ListEnvironments(ListEnvironmentsRequest {
            state: 99,
            task_ref: String::new(),
        });
        assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument);
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_of_an_accepted_create_survives_tighter_validation() -> Result<()> {
        // A row an older daemon accepted: its profile now looks like a credential.
        let s = store()?;
        let mut old = ephemeral();
        old.profile = "AIzaSyA1234567890abcdefghijklmnopqrstuv".to_owned();
        {
            use prost::Message;
            s.create("k1", "env-old", &old.encode_to_vec(), SPEC_ENCODING)?;
        }
        let again = create(&s, "k1", old.clone()).await?;
        assert_eq!(
            again.environment_id, "env-old",
            "a retry must find its environment, not be re-validated"
        );
        // The same key with another spec is still a conflict, and a new key is validated.
        let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k2".to_owned(),
            spec: Some(old),
        });
        assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument);
        Ok(())
    }

    #[tokio::test]
    async fn more_credential_formats_are_refused_as_a_profile() -> Result<()> {
        let s = store()?;
        for profile in [
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
            "ghr_abcdefghijklmnopqrstuvwxyz0123456789",
            "ASIAABCDEFGHIJKLMNOP",
            "xoxp-1234567890-abcdefghij",
            "xapp-1-A0123456789-abcdefghij",
            "glptt-abcdefghijklmnopqrstuvwxyz",
            "npm_abcdefghijklmnopqrstuvwxyz0123456789",
        ] {
            let mut bad = ephemeral();
            bad.profile = profile.to_owned();
            let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
                idempotency_key: "k".to_owned(),
                spec: Some(bad),
            });
            assert_eq!(
                refused(&s, op).await?,
                EnvironmentErrorCode::InvalidArgument,
                "{profile}"
            );
        }
        let mut bidi = ephemeral();
        bidi.task_ref = "ref\u{202E}evil".to_owned();
        let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k".to_owned(),
            spec: Some(bidi),
        });
        assert_eq!(
            refused(&s, op).await?,
            EnvironmentErrorCode::InvalidArgument,
            "bidi override in task_ref"
        );
        assert!(s.list()?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn an_unfiltered_list_leaves_out_deleted_environments_unless_asked() -> Result<()> {
        let s = store()?;
        let a = create(&s, "k1", ephemeral()).await?;
        let b = create(&s, "k2", ephemeral()).await?;
        s.delete(&b.environment_id)?;
        let ids = |reply: control_response::Result| -> Result<Vec<String>> {
            match reply {
                control_response::Result::Environments(l) => {
                    Ok(l.environments.into_iter().map(|e| e.environment_id).collect())
                }
                other => bail!("expected a list, got {other:?}"),
            }
        };
        let list = |state: WireState| {
            control_request::Op::ListEnvironments(ListEnvironmentsRequest {
                state: state.into(),
                task_ref: String::new(),
            })
        };
        let live = ids(call(&s, list(WireState::Unspecified))
            .await?
            .map_err(|e| anyhow::anyhow!("{e:?}"))?)?;
        assert_eq!(live, [a.environment_id]);
        let deleted = ids(call(&s, list(WireState::Deleted))
            .await?
            .map_err(|e| anyhow::anyhow!("{e:?}"))?)?;
        assert_eq!(deleted, [b.environment_id]);
        Ok(())
    }

    #[tokio::test]
    async fn a_list_that_would_overflow_the_frame_is_refused_with_a_typed_error() -> Result<()> {
        let s = store()?;
        for n in 0..=MAX_LIST_ROWS {
            s.create(&format!("k{n}"), &format!("env-{n}"), &ephemeral_bytes(), SPEC_ENCODING)?;
        }
        let op = control_request::Op::ListEnvironments(ListEnvironmentsRequest {
            state: WireState::Unspecified.into(),
            task_ref: String::new(),
        });
        assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument);
        // A filter that narrows below the limit still works.
        let op = control_request::Op::ListEnvironments(ListEnvironmentsRequest {
            state: WireState::Unspecified.into(),
            task_ref: "nothing-matches".to_owned(),
        });
        assert!(
            matches!(call(&s, op).await?, Ok(control_response::Result::Environments(l)) if l.environments.is_empty())
        );
        Ok(())
    }

    fn ephemeral_bytes() -> Vec<u8> {
        use prost::Message;
        ephemeral().encode_to_vec()
    }

    #[tokio::test]
    async fn cancelling_a_deleted_environment_is_an_idempotent_success_and_a_failed_one_is_refused() -> Result<()> {
        let s = store()?;
        let a = create(&s, "k1", ephemeral()).await?;
        assert_eq!(state_after(&s, cancel(&a.environment_id)).await?, WireState::Deleted);
        assert_eq!(
            state_after(&s, cancel(&a.environment_id)).await?,
            WireState::Deleted,
            "a retried cancel"
        );
        let b = create(&s, "k2", ephemeral()).await?;
        s.mark_failed(&b.environment_id, "boot", "no")?;
        assert_eq!(
            refused(&s, cancel(&b.environment_id)).await?,
            EnvironmentErrorCode::InvalidState
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_malformed_environment_id_says_malformed_not_missing() -> Result<()> {
        let s = store()?;
        match call(&s, get("has space")).await? {
            Err((EnvironmentErrorCode::InvalidArgument, message)) => {
                assert!(message.contains("malformed"), "{message}")
            }
            other => bail!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_ready_environment_reports_its_connection_and_no_other_state_does() -> Result<()> {
        use sandy_control_proto::v1::EnvironmentConnection;
        let s = store()?;
        let env = create(&s, "k1", persistent()).await?;
        // An endpoint recorded while still Provisioning is not shown.
        s.set_endpoint(&env.environment_id, "127.0.0.1:41000")?;
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => assert_eq!(got.connection, None),
            other => bail!("expected an environment, got {other:?}"),
        }
        s.mark_ready(&env.environment_id)?;
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => assert_eq!(
                got.connection,
                Some(EnvironmentConnection {
                    url: "http://127.0.0.1:41000".to_owned()
                })
            ),
            other => bail!("expected an environment, got {other:?}"),
        }
        // A stopped environment shows no connection, even with an endpoint on the row.
        s.stop(&env.environment_id)?;
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => assert_eq!(got.connection, None),
            other => bail!("expected an environment, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_ready_environment_with_no_recorded_endpoint_reports_no_connection() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", persistent()).await?;
        s.mark_ready(&env.environment_id)?;
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => {
                assert_eq!(WireState::try_from(got.state)?, WireState::Ready);
                assert_eq!(got.connection, None, "never a made-up address");
            }
            other => bail!("expected an environment, got {other:?}"),
        }
        Ok(())
    }
}
