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
        EnvironmentResponse, EnvironmentSpec, EnvironmentState as WireState, IsolationClass, ListEnvironmentsRequest,
        ListEnvironmentsResponse,
    },
};

use crate::{
    environment_driver::now_unix,
    environment_store::{
        CreateOutcome, EnvTransition, EnvironmentRecord, EnvironmentState, EnvironmentStore, EnvironmentStoreError,
        GcReport, RetentionPolicy,
    },
};

/// The create payload's encoding name, stored beside the spec bytes.
pub const SPEC_ENCODING: &str = "sandy.control.v1.EnvironmentSpec";

const MAX_KEY: usize = 128;
const MAX_PROFILE: usize = 64;
const MAX_SIZE: usize = 32;
const MAX_TASK_REF: usize = 256;
/// Rows per `ListEnvironments` page when the request names none.
pub const DEFAULT_PAGE_SIZE: usize = 100;
/// The most rows one `ListEnvironments` page may carry, whatever the request asks.
pub const MAX_PAGE_SIZE: usize = 500;
/// The most encoded bytes of rows one page carries: half the control frame, so a
/// page always fits one.
pub const PAGE_BYTE_BUDGET: usize = 512 * 1024;
/// The longest ephemeral lifetime a client may ask for: seven days.
const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// How often [`run_retention`] sweeps in the daemon.
pub const RETENTION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

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

/// Sweep `Deleted` rows per `policy` once at once, then every `interval`, for the
/// life of the task (#633). `clock` supplies unix seconds, injected so tests
/// need no sleep. A faulting sweep is logged and retried on the next tick.
pub async fn run_retention(
    store: Arc<EnvironmentStore>,
    policy: RetentionPolicy,
    interval: std::time::Duration,
    clock: impl Fn() -> i64 + Send + 'static,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let now = clock();
        match blocking(&store, move |s| s.gc_deleted(now, &policy)).await {
            Ok(GcReport { expired: 0, evicted: 0 }) => {}
            Ok(GcReport { expired, evicted }) => {
                tracing::info!(expired, evicted, "removed deleted environment rows");
            }
            Err(e) => tracing::warn!(error = %e, "environment retention sweep failed"),
        }
    }
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
        Some(Op::CreateEnvironment(r)) => create(store, r.idempotency_key, r.spec, r.submitter_class).await?,
        Some(Op::GetEnvironment(r)) => get(store, r.environment_id).await?,
        Some(Op::ListEnvironments(r)) => list(store, r, PAGE_BYTE_BUDGET).await?,
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

/// Write the audit line for `operation` before it applies. `None` means go on; `Some` is the
/// refusal to return, because an operation that cannot be audited does not run (#596).
async fn audit(store: &Arc<EnvironmentStore>, operation: &'static str, id: &str, trusted: bool) -> Option<Reply> {
    let log = Arc::clone(store.audit()?);
    let id = id.to_owned();
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let submitter = if trusted { "trusted" } else { "untrusted" };
    let written = tokio::task::spawn_blocking(move || {
        log.record(&crate::audit::AuditEntry {
            at,
            operation,
            environment_id: &id,
            submitter_class: submitter,
        })
    })
    .await;
    match written {
        Ok(Ok(())) => None,
        Ok(Err(e)) => {
            tracing::error!(error = %e, operation, "the environment audit log could not be written; the operation was refused");
            Some(refuse(
                EnvironmentErrorCode::Unavailable,
                "the audit log cannot be written, so the operation did not run",
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, operation, "the environment audit task failed; the operation was refused");
            Some(refuse(
                EnvironmentErrorCode::Unavailable,
                "the audit log cannot be written, so the operation did not run",
            ))
        }
    }
}

async fn create(
    store: &Arc<EnvironmentStore>,
    key: String,
    spec: Option<EnvironmentSpec>,
    submitter_class: i32,
) -> Reply {
    let trusted = IsolationClass::try_from(submitter_class) == Ok(IsolationClass::Trusted);
    // Before the replay lookup: a client whose class was lowered must not reach its old row's
    // answer either. UNSPECIFIED and unknown values are not TRUSTED.
    if store.trusted_submitter_required() && !trusted {
        return refuse(
            EnvironmentErrorCode::Forbidden,
            "the environment backend runs without isolation and serves trusted submitters only",
        );
    }
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
    if let Some(refusal) = audit(store, "create", &new_id, trusted).await {
        return refusal;
    }
    let outcome = blocking(store, move |s| {
        s.create_for(&key, &new_id, &bytes, SPEC_ENCODING, trusted)
    })
    .await?;
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
        Some(record) => {
            // Reading an environment renews its idle-stop lease (decision 30). A failed
            // renewal must not fail the read.
            let (s, touched) = (Arc::clone(store), id.clone());
            if let Ok(Err(e)) = tokio::task::spawn_blocking(move || s.touch(&touched, now_unix())).await {
                tracing::warn!(environment = %id, error = %e, "could not renew an idle-stop lease");
            }
            reply(record)
        }
        None => not_found(&id),
    }
}

/// The page size a request asks for, made valid: 0 is the default, and anything
/// above the maximum is the maximum.
fn clamp_page_size(requested: u32) -> usize {
    match requested as usize {
        0 => DEFAULT_PAGE_SIZE,
        n => n.min(MAX_PAGE_SIZE),
    }
}

/// Rows read from the store per round while a page is filled; a `task_ref` filter
/// can skip rows, so one page may take several rounds.
const SCAN_CHUNK: usize = 200;

/// One page of `ListEnvironments`, in `environment_id` order. A page ends at the
/// page size or when the next row would push its encoded rows past `budget`
/// bytes (so a page always fits a control frame), and `next_page_token` is the
/// id of the last row scanned (it advances past rows a `task_ref` filter skipped),
/// or empty when no later row matches.
async fn list(store: &Arc<EnvironmentStore>, request: ListEnvironmentsRequest, budget: usize) -> Reply {
    let ListEnvironmentsRequest {
        state,
        task_ref,
        page_size,
        page_token,
    } = request;
    let Ok(wire) = WireState::try_from(state) else {
        return refuse(EnvironmentErrorCode::InvalidArgument, "unknown state filter");
    };
    if !page_token.is_empty() && !id_ok(&page_token) {
        return refuse(EnvironmentErrorCode::InvalidArgument, "page_token is malformed");
    }
    let limit = clamp_page_size(page_size);
    let filter = from_wire_state(wire);
    let mut after = page_token;
    let mut environments: Vec<EnvironmentResponse> = Vec::new();
    let mut bytes = 0;
    loop {
        let cursor = after.clone();
        let chunk = blocking(store, move |s| s.list_page(filter, Some(&cursor), SCAN_CHUNK)).await?;
        let exhausted = chunk.len() < SCAN_CHUNK;
        for record in chunk {
            let id = record.environment_id.clone();
            let row = to_wire(record)?;
            if task_ref.is_empty() || row.spec.as_ref().is_some_and(|s| s.task_ref == task_ref) {
                let size = row.encoded_len();
                if !environments.is_empty() && (environments.len() >= limit || bytes + size > budget) {
                    // A matching row is waiting, so there is a next page.
                    return Ok(page(environments, after));
                }
                bytes += size;
                environments.push(row);
            }
            after = id;
        }
        if exhausted {
            return Ok(page(environments, String::new()));
        }
    }
}

fn page(environments: Vec<EnvironmentResponse>, next_page_token: String) -> control_response::Result {
    control_response::Result::Environments(ListEnvironmentsResponse {
        environments,
        next_page_token,
    })
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
    // Only a Ready environment can be stopped: any other state is refused below, so it is not audited.
    if stop
        && record.state == EnvironmentState::Ready
        && let Some(refusal) = audit(store, "stop", &id, record.submitter_trusted).await
    {
        return refusal;
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
    let Some(record) = fetch(store, &id).await? else {
        return not_found(&id);
    };
    // Cancel ends a Provisioning environment in Deleted, so it is audited like a delete.
    if record.state == EnvironmentState::Provisioning
        && let Some(refusal) = audit(store, "cancel", &id, record.submitter_trusted).await
    {
        return refusal;
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
    let Some(record) = fetch(store, &id).await? else {
        return not_found(&id);
    };
    // Deleting a deleted environment changes nothing, so an idempotent retry is not audited.
    if record.state != EnvironmentState::Deleted
        && let Some(refusal) = audit(store, "delete", &id, record.submitter_trusted).await
    {
        return refusal;
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
            GetEnvironmentRequest, ResumeEnvironmentRequest, StopEnvironmentRequest,
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
            ..Default::default()
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
            ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
            });
            assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument, "{what}");
        }
        let no_spec = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k".to_owned(),
            spec: None,
            ..Default::default()
        });
        assert_eq!(refused(&s, no_spec).await?, EnvironmentErrorCode::InvalidArgument);
        assert!(s.list()?.is_empty(), "a refused create must leave no row");
        Ok(())
    }

    #[tokio::test]
    async fn reading_a_ready_environment_renews_its_idle_lease() -> Result<()> {
        let s = store()?;
        let env = create(&s, "k1", ephemeral()).await?;
        s.mark_ready(&env.environment_id)?;
        assert_eq!(s.get(&env.environment_id)?.context("row")?.last_activity_at, None);
        call(&s, get(&env.environment_id))
            .await?
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        assert!(s.get(&env.environment_id)?.context("row")?.last_activity_at.is_some());
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
                ..Default::default()
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
        // Pages are in id order, and ids are random.
        let mut both = [a.environment_id.clone(), b.environment_id.clone()];
        both.sort();
        assert_eq!(all, both);
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
            ..Default::default()
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
            ..Default::default()
        });
        assert_eq!(refused(&s, op).await?, EnvironmentErrorCode::InvalidArgument);
        let op = control_request::Op::ListEnvironments(ListEnvironmentsRequest {
            state: 99,
            ..Default::default()
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
            ..Default::default()
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
                ..Default::default()
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
            ..Default::default()
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
                ..Default::default()
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

    /// Inserts `n` live rows straight into the store, each with a 256-byte `task_ref`
    /// (the largest a row can carry), ids `env-00000`, `env-00001`, ...
    fn fill(s: &EnvironmentStore, n: usize) -> Result<Vec<String>> {
        let mut spec = ephemeral();
        spec.task_ref = "t".repeat(MAX_TASK_REF);
        let bytes = spec.encode_to_vec();
        (0..n)
            .map(|i| {
                let id = format!("env-{i:05}");
                match s.create(&format!("k{i}"), &id, &bytes, SPEC_ENCODING)? {
                    CreateOutcome::Created(_) => Ok(id),
                    other => bail!("row {i}: {other:?}"),
                }
            })
            .collect()
    }

    fn page_op(state: WireState, page_size: u32, page_token: &str) -> control_request::Op {
        control_request::Op::ListEnvironments(ListEnvironmentsRequest {
            state: state.into(),
            task_ref: String::new(),
            page_size,
            page_token: page_token.to_owned(),
        })
    }

    /// One page: its environment ids, its encoded reply size, and the next token.
    async fn page(s: &Arc<EnvironmentStore>, op: control_request::Op) -> Result<(Vec<String>, usize, String)> {
        match call(s, op).await {
            Ok(Ok(control_response::Result::Environments(l))) => {
                let size = l.encoded_len();
                let ids = l.environments.into_iter().map(|e| e.environment_id).collect();
                Ok((ids, size, l.next_page_token))
            }
            other => bail!("expected a list page, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_list_over_more_rows_than_one_frame_holds_comes_back_as_pages_covering_every_row_once() -> Result<()> {
        let s = store()?;
        let all = fill(&s, 5000)?;
        let mut seen = Vec::new();
        let mut token = String::new();
        let mut total_bytes = 0;
        let mut pages = 0;
        loop {
            let (ids, size, next) = page(&s, page_op(WireState::Unspecified, 0, &token)).await?;
            assert!(!ids.is_empty(), "a page must make progress");
            assert!(
                size <= sandy_control_proto::MAX_FRAME_LEN as usize,
                "a page must fit a frame"
            );
            assert!(ids.len() <= MAX_PAGE_SIZE);
            total_bytes += size;
            seen.extend(ids);
            pages += 1;
            if next.is_empty() {
                break;
            }
            token = next;
        }
        assert!(
            total_bytes > sandy_control_proto::MAX_FRAME_LEN as usize,
            "the premise: all rows together outgrow one frame"
        );
        assert!(pages > 1);
        let mut expected = all;
        expected.sort();
        assert_eq!(seen, expected, "every row exactly once, in environment id order");
        Ok(())
    }

    #[tokio::test]
    async fn a_page_stops_at_the_byte_budget_before_the_row_limit() -> Result<()> {
        let s = store()?;
        let all = fill(&s, 40)?;
        let mut seen = Vec::new();
        let mut token = String::new();
        loop {
            let request = ListEnvironmentsRequest {
                page_size: 500,
                page_token: token.clone(),
                ..Default::default()
            };
            let Ok(control_response::Result::Environments(l)) = list(&s, request, 2_000).await else {
                bail!("expected a list page");
            };
            assert!(l.environments.len() < 40, "a 2000-byte budget cannot hold 40 rows");
            assert!(!l.environments.is_empty());
            seen.extend(l.environments.into_iter().map(|e| e.environment_id));
            if l.next_page_token.is_empty() {
                break;
            }
            token = l.next_page_token;
        }
        assert_eq!(seen, all);
        Ok(())
    }

    #[test]
    fn a_requested_page_size_is_the_default_when_zero_and_never_above_the_maximum() {
        assert_eq!(clamp_page_size(0), DEFAULT_PAGE_SIZE);
        assert_eq!(clamp_page_size(1), 1);
        assert_eq!(clamp_page_size(MAX_PAGE_SIZE as u32), MAX_PAGE_SIZE);
        assert_eq!(clamp_page_size(MAX_PAGE_SIZE as u32 + 1), MAX_PAGE_SIZE);
        assert_eq!(clamp_page_size(u32::MAX), MAX_PAGE_SIZE);
    }

    #[tokio::test]
    async fn an_unset_page_size_returns_the_default_and_a_huge_one_the_maximum() -> Result<()> {
        let s = store()?;
        fill(&s, MAX_PAGE_SIZE + 50)?;
        let (first, _, next) = page(&s, page_op(WireState::Unspecified, 0, "")).await?;
        assert_eq!(first.len(), DEFAULT_PAGE_SIZE);
        assert!(!next.is_empty());
        let (big, _, next) = page(&s, page_op(WireState::Unspecified, u32::MAX, "")).await?;
        assert_eq!(big.len(), MAX_PAGE_SIZE);
        let (rest, _, last) = page(&s, page_op(WireState::Unspecified, u32::MAX, &next)).await?;
        assert_eq!(rest.len(), 50);
        assert_eq!(last, "", "the last page has no next token");
        Ok(())
    }

    #[tokio::test]
    async fn a_page_that_ends_exactly_on_the_last_row_has_no_next_token() -> Result<()> {
        let s = store()?;
        fill(&s, 4)?;
        let (ids, _, next) = page(&s, page_op(WireState::Unspecified, 4, "")).await?;
        assert_eq!((ids.len(), next.as_str()), (4, ""));
        Ok(())
    }

    #[tokio::test]
    async fn a_malformed_page_token_is_an_invalid_argument() -> Result<()> {
        let s = store()?;
        fill(&s, 3)?;
        for bad in ["has space", "a/b", "env-\u{0}", &"x".repeat(MAX_KEY + 1)] {
            assert_eq!(
                refused(&s, page_op(WireState::Unspecified, 0, bad)).await?,
                EnvironmentErrorCode::InvalidArgument,
                "{bad:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_page_token_whose_row_was_collected_still_continues_after_its_place() -> Result<()> {
        let s = store()?;
        let all = fill(&s, 6)?;
        let (first, _, token) = page(&s, page_op(WireState::Unspecified, 3, "")).await?;
        assert_eq!(first, all[..3]);
        s.delete(&first[2])?;
        s.gc_deleted(
            i64::MAX / 2,
            &RetentionPolicy {
                window_secs: 1,
                max_deleted: 10,
            },
        )?;
        assert_eq!(s.get(&first[2])?, None);
        let (rest, _, next) = page(&s, page_op(WireState::Unspecified, 3, &token)).await?;
        assert_eq!((rest, next.as_str()), (all[3..].to_vec(), ""));
        Ok(())
    }

    #[tokio::test]
    async fn the_deleted_filter_pages_deleted_rows_and_the_default_filter_skips_them() -> Result<()> {
        let s = store()?;
        let all = fill(&s, 6)?;
        for id in &all[..2] {
            s.delete(id)?;
        }
        let (live, ..) = page(&s, page_op(WireState::Unspecified, 0, "")).await?;
        assert_eq!(live, all[2..]);
        let (gone, ..) = page(&s, page_op(WireState::Deleted, 0, "")).await?;
        assert_eq!(gone, all[..2]);
        Ok(())
    }

    #[tokio::test]
    async fn create_and_delete_churn_past_the_row_cap_leaves_room_for_a_new_create() -> Result<()> {
        let s = Arc::new(EnvironmentStore::open_in_memory()?.with_max_rows(Some(2)));
        for n in 0..6 {
            let env = create(&s, &format!("churn-{n}"), ephemeral()).await?;
            assert_eq!(state_after(&s, delete(&env.environment_id)).await?, WireState::Deleted);
        }
        let live = create(&s, "live-1", ephemeral()).await?;
        create(&s, "live-2", ephemeral()).await?;
        let over = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "live-3".to_owned(),
            spec: Some(ephemeral()),
            ..Default::default()
        });
        assert_eq!(refused(&s, over).await?, EnvironmentErrorCode::QuotaExceeded);
        // Deleting a live row frees its slot at once, with no wait for the retention window.
        s.delete(&live.environment_id)?;
        create(&s, "live-3", ephemeral()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_replay_inside_the_retention_window_finds_the_deleted_environment_and_one_after_it_makes_a_new_one()
    -> Result<()> {
        let s = store()?;
        let policy = RetentionPolicy {
            window_secs: 3600,
            max_deleted: 100,
        };
        let first = create(&s, "replayed", ephemeral()).await?;
        s.delete(&first.environment_id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        s.gc_deleted(now + 60, &policy)?;
        let replay = create(&s, "replayed", ephemeral()).await?;
        assert_eq!(
            replay.environment_id, first.environment_id,
            "inside the window: the same environment"
        );
        assert_eq!(WireState::try_from(replay.state)?, WireState::Deleted);
        s.gc_deleted(now + 3600 + 60, &policy)?;
        let fresh = create(&s, "replayed", ephemeral()).await?;
        assert_ne!(
            fresh.environment_id, first.environment_id,
            "after gc: a new environment"
        );
        assert_eq!(WireState::try_from(fresh.state)?, WireState::Provisioning);
        Ok(())
    }

    /// 450 rows, of which only the ones at `300..305` carry the `task_ref` `needle`, so the
    /// first match lies beyond the first `SCAN_CHUNK` rows. Returns the matching ids.
    fn fill_with_needles(s: &EnvironmentStore) -> Result<Vec<String>> {
        let mut needles = Vec::new();
        for i in 0..450 {
            let mut spec = ephemeral();
            if (300..305).contains(&i) {
                spec.task_ref = "needle".to_owned();
            }
            let id = format!("env-{i:05}");
            match s.create(&format!("k{i}"), &id, &spec.encode_to_vec(), SPEC_ENCODING)? {
                CreateOutcome::Created(_) => {}
                other => bail!("row {i}: {other:?}"),
            }
            if spec.task_ref == "needle" {
                needles.push(id);
            }
        }
        Ok(needles)
    }

    fn needle_op(page_size: u32, page_token: &str) -> control_request::Op {
        control_request::Op::ListEnvironments(ListEnvironmentsRequest {
            task_ref: "needle".to_owned(),
            page_size,
            page_token: page_token.to_owned(),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn a_task_ref_filter_pages_over_matches_found_beyond_the_first_scan_chunk() -> Result<()> {
        let s = store()?;
        let needles = fill_with_needles(&s)?;
        let (first, _, token) = page(&s, needle_op(3, "")).await?;
        assert_eq!(
            first,
            needles[..3],
            "the first match is row 300, past the first 200 scanned"
        );
        assert_eq!(
            token, needles[2],
            "the token is the last row scanned, here the third match"
        );
        let (rest, _, last) = page(&s, needle_op(3, &token)).await?;
        assert_eq!((rest, last.as_str()), (needles[3..].to_vec(), ""));
        // A page that fills exactly with the last match has nothing after it, so no token.
        let (all, _, none) = page(&s, needle_op(5, "")).await?;
        assert_eq!((all, none.as_str()), (needles.clone(), ""));
        // A full page with matches still to come carries a token that skips the filtered rows.
        let (two, _, token) = page(&s, needle_op(2, "")).await?;
        assert_eq!(two, needles[..2]);
        let (next, ..) = page(&s, needle_op(2, &token)).await?;
        assert_eq!(next, needles[2..4]);
        Ok(())
    }

    #[tokio::test]
    async fn the_retention_task_sweeps_at_start_without_waiting_a_tick() -> Result<()> {
        let s = store()?;
        let env = create(&s, "old", ephemeral()).await?;
        s.delete(&env.environment_id)?;
        let policy = RetentionPolicy {
            window_secs: 60,
            max_deleted: 100,
        };
        let task = tokio::spawn(run_retention(
            Arc::clone(&s),
            policy,
            std::time::Duration::from_secs(3600),
            || i64::MAX / 2,
        ));
        let gone = async {
            while s.get(&env.environment_id)?.is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            anyhow::Ok(())
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), gone)
            .await
            .context("the first sweep must run at start")??;
        task.abort();
        Ok(())
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
        // Still Provisioning: no endpoint, no connection.
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => assert_eq!(got.connection, None),
            other => bail!("expected an environment, got {other:?}"),
        }
        s.mark_ready_with_endpoint(&env.environment_id, "127.0.0.1:41000")?;
        match call(&s, get(&env.environment_id)).await? {
            Ok(control_response::Result::Environment(got)) => assert_eq!(
                got.connection,
                Some(EnvironmentConnection {
                    url: "http://127.0.0.1:41000".to_owned()
                })
            ),
            other => bail!("expected an environment, got {other:?}"),
        }
        // A stopped environment shows no connection, even with an endpoint left on the row.
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

    fn create_as(key: &str, class: IsolationClass) -> control_request::Op {
        control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: key.to_owned(),
            spec: Some(persistent()),
            submitter_class: class.into(),
        })
    }

    #[tokio::test]
    async fn a_trusted_only_store_refuses_every_class_but_trusted_and_keeps_no_row() -> Result<()> {
        let store = store()?;
        store.require_trusted_submitter();
        for (key, class) in [("u", IsolationClass::Untrusted), ("x", IsolationClass::Unspecified)] {
            assert_eq!(
                refused(&store, create_as(key, class)).await?,
                EnvironmentErrorCode::Forbidden,
                "{class:?} must be refused"
            );
        }
        let unknown = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "n".to_owned(),
            spec: Some(persistent()),
            submitter_class: 99,
        });
        assert_eq!(refused(&store, unknown).await?, EnvironmentErrorCode::Forbidden);
        assert_eq!(store.list()?.len(), 0, "a refused create leaves no row");
        match call(&store, create_as("t", IsolationClass::Trusted)).await? {
            Ok(control_response::Result::Environment(_)) => {}
            other => bail!("a trusted create must succeed, got {other:?}"),
        }
        let row = store.get_by_request_id("t")?.context("the trusted row")?;
        assert!(row.submitter_trusted, "the row must record its trusted submitter");
        Ok(())
    }

    #[tokio::test]
    async fn a_client_lowered_to_untrusted_cannot_replay_its_old_create_under_a_trusted_only_store() -> Result<()> {
        let store = store()?;
        store.require_trusted_submitter();
        let first = call(&store, create_as("k", IsolationClass::Trusted)).await?;
        assert!(
            matches!(first, Ok(control_response::Result::Environment(_))),
            "{first:?}"
        );
        assert_eq!(
            refused(&store, create_as("k", IsolationClass::Untrusted)).await?,
            EnvironmentErrorCode::Forbidden
        );
        Ok(())
    }

    #[tokio::test]
    async fn without_a_trusted_only_backend_any_class_may_create() -> Result<()> {
        let store = store()?;
        for (key, class) in [
            ("u", IsolationClass::Untrusted),
            ("x", IsolationClass::Unspecified),
            ("t", IsolationClass::Trusted),
        ] {
            let reply = call(&store, create_as(key, class)).await?;
            assert!(
                matches!(reply, Ok(control_response::Result::Environment(_))),
                "{class:?}: {reply:?}"
            );
        }
        Ok(())
    }

    // ---- the audit log (#596) ----

    fn audited_store(dir: &std::path::Path) -> Result<(Arc<EnvironmentStore>, std::path::PathBuf)> {
        let path = dir.join("audit.jsonl");
        let log = crate::audit::AuditLog::open(&path)?;
        Ok((
            Arc::new(EnvironmentStore::open_in_memory()?.with_audit(Arc::new(log))),
            path,
        ))
    }

    fn lines(path: &std::path::Path) -> Result<Vec<serde_json::Value>> {
        std::fs::read_to_string(path)?
            .lines()
            .map(|l| serde_json::from_str(l).context("an audit line is JSON"))
            .collect()
    }

    fn trusted_create(key: &str) -> control_request::Op {
        control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: key.to_owned(),
            spec: Some(persistent()),
            submitter_class: IsolationClass::Trusted.into(),
        })
    }

    #[tokio::test]
    async fn create_stop_and_delete_each_leave_one_audit_line_naming_the_environment() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (s, path) = audited_store(dir.path())?;
        let Ok(control_response::Result::Environment(env)) = call(&s, trusted_create("k1")).await? else {
            bail!("create must succeed");
        };
        s.mark_ready(&env.environment_id)?;
        assert_eq!(state_after(&s, stop(&env.environment_id)).await?, WireState::Stopped);
        assert_eq!(state_after(&s, delete(&env.environment_id)).await?, WireState::Deleted);
        let entries = lines(&path)?;
        let ops: Vec<_> = entries.iter().map(|e| e["operation"].as_str().unwrap_or("")).collect();
        assert_eq!(ops, ["create", "stop", "delete"]);
        for e in &entries {
            assert_eq!(e["environment_id"], env.environment_id.as_str());
            assert_eq!(e["submitter_class"], "trusted");
            assert_eq!(e["outcome"], "attempted");
            assert!(e["at"].as_i64().unwrap_or(0) > 0, "the line carries a unix time");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_replayed_create_and_a_refused_one_write_no_audit_line() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (s, path) = audited_store(dir.path())?;
        call(&s, trusted_create("k1")).await?.ok();
        call(&s, trusted_create("k1")).await?.ok();
        let bad = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
            idempotency_key: "k2".to_owned(),
            spec: None,
            submitter_class: IsolationClass::Trusted.into(),
        });
        assert_eq!(refused(&s, bad).await?, EnvironmentErrorCode::InvalidArgument);
        assert_eq!(lines(&path)?.len(), 1, "only the first accepted create is audited");
        Ok(())
    }

    #[tokio::test]
    async fn an_unwritable_audit_log_refuses_every_audited_operation_and_changes_nothing() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "")?;
        let read_only = std::fs::File::open(&path)?;
        let log = crate::audit::AuditLog::from_file(path, read_only);
        let s = Arc::new(EnvironmentStore::open_in_memory()?.with_audit(Arc::new(log)));
        assert_eq!(
            refused(&s, trusted_create("k1")).await?,
            EnvironmentErrorCode::Unavailable
        );
        assert!(s.list()?.is_empty(), "a create whose audit failed leaves no row");
        let CreateOutcome::Created(row) =
            s.create_for("k2", "env-0001", &persistent().encode_to_vec(), SPEC_ENCODING, true)?
        else {
            bail!("seed row");
        };
        s.mark_ready(&row.environment_id)?;
        assert_eq!(
            refused(&s, stop(&row.environment_id)).await?,
            EnvironmentErrorCode::Unavailable
        );
        assert_eq!(
            s.get(&row.environment_id)?.map(|r| r.state),
            Some(EnvironmentState::Ready)
        );
        assert_eq!(
            refused(&s, delete(&row.environment_id)).await?,
            EnvironmentErrorCode::Unavailable
        );
        assert_eq!(
            s.get(&row.environment_id)?.map(|r| r.state),
            Some(EnvironmentState::Ready)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_stop_the_state_refuses_and_a_repeated_delete_write_no_audit_line() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (s, path) = audited_store(dir.path())?;
        let Ok(control_response::Result::Environment(env)) = call(&s, trusted_create("k1")).await? else {
            bail!("create must succeed");
        };
        // Still Provisioning: a stop is refused as an invalid state.
        assert_eq!(
            refused(&s, stop(&env.environment_id)).await?,
            EnvironmentErrorCode::InvalidState
        );
        assert_eq!(state_after(&s, delete(&env.environment_id)).await?, WireState::Deleted);
        assert_eq!(state_after(&s, delete(&env.environment_id)).await?, WireState::Deleted);
        let ops: Vec<_> = lines(&path)?
            .iter()
            .map(|e| e["operation"].as_str().unwrap_or("").to_owned())
            .collect();
        assert_eq!(
            ops,
            ["create", "delete"],
            "no line for the refused stop or the repeat delete"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_cancel_that_ends_a_provisioning_environment_is_audited_and_refused_when_unwritable() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (s, path) = audited_store(dir.path())?;
        let Ok(control_response::Result::Environment(env)) = call(&s, trusted_create("k1")).await? else {
            bail!("create must succeed");
        };
        assert_eq!(state_after(&s, cancel(&env.environment_id)).await?, WireState::Deleted);
        assert_eq!(state_after(&s, cancel(&env.environment_id)).await?, WireState::Deleted);
        let ops: Vec<_> = lines(&path)?
            .iter()
            .map(|e| e["operation"].as_str().unwrap_or("").to_owned())
            .collect();
        assert_eq!(ops, ["create", "cancel"], "one line for the cancel, none for its retry");

        let dir = tempfile::tempdir()?;
        let broken = dir.path().join("audit.jsonl");
        std::fs::write(&broken, "")?;
        let log = crate::audit::AuditLog::from_file(broken.clone(), std::fs::File::open(&broken)?);
        let s = Arc::new(EnvironmentStore::open_in_memory()?.with_audit(Arc::new(log)));
        let CreateOutcome::Created(row) =
            s.create_for("k2", "env-0002", &persistent().encode_to_vec(), SPEC_ENCODING, true)?
        else {
            bail!("seed row");
        };
        assert_eq!(
            refused(&s, cancel(&row.environment_id)).await?,
            EnvironmentErrorCode::Unavailable
        );
        assert_eq!(
            s.get(&row.environment_id)?.map(|r| r.state),
            Some(EnvironmentState::Provisioning)
        );
        Ok(())
    }
}
