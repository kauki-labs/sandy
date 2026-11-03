//! The environment endpoints: map the HTTP contract onto sandyd's typed
//! environment RPC (#587 A2), with per-client ownership, a per-client
//! idempotency namespace and a per-client quota.

use hyper::{Request, StatusCode, body::Incoming};
use sandy_control_proto::{
    control_request, control_response,
    v1::{
        CancelEnvironmentRequest, CreateEnvironmentRequest, DeleteEnvironmentRequest, EnvironmentErrorCode,
        EnvironmentLifetime, EnvironmentLifetimeKind, EnvironmentResponse, EnvironmentSpec, EnvironmentState,
        GetEnvironmentRequest, ListEnvironmentsRequest, ResumeEnvironmentRequest, StopEnvironmentRequest,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    Client,
    server::{ApiError, FORBIDDEN, INVALID, NOT_FOUND, Reply, State, UNAVAILABLE, read_body, rpc},
};

/// Longest `request_id` the broker accepts. sandyd allows 128 characters for its
/// key, and the broker prefixes 16 hex digits and a dot.
const MAX_REQUEST_ID: usize = 111;

const CONFLICT: ApiError = ApiError {
    status: StatusCode::CONFLICT,
    code: "request_id_conflict",
    message: "this request_id was used with a different payload",
};
const QUOTA: ApiError = ApiError {
    status: StatusCode::TOO_MANY_REQUESTS,
    code: "quota_exceeded",
    message: "too many environments",
};
const LIFETIME: ApiError = ApiError {
    status: StatusCode::CONFLICT,
    code: "unsupported_for_lifetime",
    message: "the environment's lifetime does not allow this operation",
};
const INVALID_STATE: ApiError = ApiError {
    status: StatusCode::CONFLICT,
    code: "invalid_request",
    message: "the environment is not in a state that allows this operation",
};
const REFUSED_FIELDS: ApiError = ApiError {
    status: StatusCode::BAD_REQUEST,
    code: "invalid_request",
    message: "sandyd refused the request's fields",
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpawnEnvironment {
    request_id: String,
    profile: String,
    #[serde(default)]
    size: String,
    lifetime: LifetimeBody,
    #[serde(default)]
    task_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LifetimeBody {
    kind: LifetimeKind,
    ttl_secs: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum LifetimeKind {
    Ephemeral,
    Persistent,
}

/// sandyd keys idempotency over all callers, so each client gets its own
/// namespace: a hash prefix of the client id, then the client's `request_id`.
fn namespaced(client: &Client, request_id: &str) -> String {
    let digest = hex::encode(Sha256::digest(client.id.as_bytes()));
    format!("{}.{request_id}", &digest[..16])
}

fn valid_request_id(id: &str) -> bool {
    (1..=MAX_REQUEST_ID).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn state_name(state: i32) -> &'static str {
    match EnvironmentState::try_from(state) {
        Ok(EnvironmentState::Provisioning) => "provisioning",
        Ok(EnvironmentState::Ready) => "ready",
        Ok(EnvironmentState::Stopped) => "stopped",
        Ok(EnvironmentState::Deleted) => "deleted",
        _ => "failed",
    }
}

fn is_live(state: i32) -> bool {
    matches!(
        EnvironmentState::try_from(state),
        Ok(EnvironmentState::Provisioning | EnvironmentState::Ready | EnvironmentState::Stopped)
    )
}

fn summary(e: &EnvironmentResponse) -> Value {
    json!({"environment_id": e.environment_id, "state": state_name(e.state)})
}

fn detail(e: &EnvironmentResponse) -> Value {
    let mut body = summary(e);
    // The step format is pinned when the launch driver (#587 slice C) reports
    // steps. Until then sandyd sends none.
    body["steps"] = e
        .steps
        .iter()
        .map(|name| json!({"name": name, "status": "pending"}))
        .collect();
    if let Some(f) = e
        .failure
        .as_ref()
        .filter(|f| !f.step.is_empty() || !f.reason.is_empty())
    {
        body["failure"] = json!({"step": f.step, "reason": f.reason});
    }
    if let Some(c) = e.connection.as_ref().filter(|c| !c.url.is_empty()) {
        body["connection"] = json!({"url": c.url});
    }
    body
}

/// sandyd's own refusal text is not relayed; each code has a fixed message.
fn environment_error(code: i32) -> ApiError {
    match EnvironmentErrorCode::try_from(code) {
        Ok(EnvironmentErrorCode::NotFound) => NOT_FOUND,
        Ok(EnvironmentErrorCode::RequestIdConflict) => CONFLICT,
        Ok(EnvironmentErrorCode::QuotaExceeded) => QUOTA,
        Ok(EnvironmentErrorCode::UnsupportedForLifetime) => LIFETIME,
        Ok(EnvironmentErrorCode::InvalidState) => INVALID_STATE,
        Ok(EnvironmentErrorCode::InvalidArgument) => REFUSED_FIELDS,
        _ => UNAVAILABLE,
    }
}

async fn call(state: &State, op: control_request::Op) -> Result<control_response::Result, ApiError> {
    match rpc(state, op).await? {
        control_response::Result::EnvironmentError(e) => {
            tracing::info!(code = e.code, "sandyd refused an environment request");
            Err(environment_error(e.code))
        }
        other => Ok(other),
    }
}

async fn one(state: &State, op: control_request::Op) -> Result<EnvironmentResponse, ApiError> {
    match call(state, op).await? {
        control_response::Result::Environment(e) => Ok(e),
        _ => Err(UNAVAILABLE),
    }
}

pub(crate) async fn spawn(state: &State, client: &Client, req: Request<Incoming>) -> Reply {
    let bytes = read_body(req).await?;
    let body: SpawnEnvironment = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    if !valid_request_id(&body.request_id) {
        return Err(INVALID);
    }
    let lifetime = match body.lifetime {
        LifetimeBody {
            kind: LifetimeKind::Ephemeral,
            ttl_secs: Some(ttl),
        } => EnvironmentLifetime {
            kind: EnvironmentLifetimeKind::Ephemeral.into(),
            ttl_secs: ttl,
        },
        LifetimeBody {
            kind: LifetimeKind::Persistent,
            ttl_secs: None,
        } => EnvironmentLifetime {
            kind: EnvironmentLifetimeKind::Persistent.into(),
            ttl_secs: 0,
        },
        _ => return Err(INVALID),
    };
    // One create at a time per broker, so the quota check and the create cannot
    // race another create of the same client.
    let _serial = state.env_create.lock().await;
    if !state.owners.has_request(&client.id, &body.request_id) {
        let live = live_owned(state, client).await?;
        if live >= client.max_environments {
            return Err(QUOTA);
        }
    }
    let op = control_request::Op::CreateEnvironment(CreateEnvironmentRequest {
        idempotency_key: namespaced(client, &body.request_id),
        spec: Some(EnvironmentSpec {
            profile: body.profile,
            size: body.size,
            lifetime: Some(lifetime),
            task_ref: body.task_ref,
        }),
    });
    let created = one(state, op).await?;
    // A failed save leaves the environment unowned for now. The client's retry
    // replays this create, gets the same environment back, and records it.
    if let Err(e) = state
        .owners
        .record_environment(&created.environment_id, &client.id, &body.request_id)
    {
        tracing::error!(error = %e, environment_id = %created.environment_id, "cannot record environment owner");
        return Err(UNAVAILABLE);
    }
    Ok((StatusCode::ACCEPTED, summary(&created)))
}

/// How many non-terminal environments `client` holds.
async fn live_owned(state: &State, client: &Client) -> Result<usize, ApiError> {
    let op = control_request::Op::ListEnvironments(ListEnvironmentsRequest::default());
    let control_response::Result::Environments(all) = call(state, op).await? else {
        return Err(UNAVAILABLE);
    };
    Ok(all
        .environments
        .iter()
        .filter(|e| is_live(e.state) && state.owners.owns_environment(&e.environment_id, &client.id))
        .count())
}

/// A query parameter, percent-decoded. `None` when absent.
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if bytes
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) =>
            {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) async fn list(state: &State, client: &Client, query: Option<&str>) -> Reply {
    let wanted = match query_param(query, "state").as_deref() {
        None | Some("") => EnvironmentState::Unspecified,
        Some("provisioning") => EnvironmentState::Provisioning,
        Some("ready") => EnvironmentState::Ready,
        Some("stopped") => EnvironmentState::Stopped,
        Some("failed") => EnvironmentState::Failed,
        Some("deleted") => EnvironmentState::Deleted,
        Some(_) => return Err(INVALID),
    };
    let op = control_request::Op::ListEnvironments(ListEnvironmentsRequest {
        state: wanted.into(),
        task_ref: query_param(query, "task_ref").unwrap_or_default(),
    });
    let control_response::Result::Environments(all) = call(state, op).await? else {
        return Err(UNAVAILABLE);
    };
    let environments: Vec<Value> = all
        .environments
        .iter()
        .filter(|e| state.owners.owns_environment(&e.environment_id, &client.id))
        .map(summary)
        .collect();
    Ok((StatusCode::OK, json!({"environments": environments})))
}

fn owned(state: &State, client: &Client, id: &str) -> Result<(), ApiError> {
    if state.owners.owns_environment(id, &client.id) {
        Ok(())
    } else {
        Err(NOT_FOUND)
    }
}

pub(crate) async fn get(state: &State, client: &Client, id: &str) -> Reply {
    owned(state, client, id)?;
    let op = control_request::Op::GetEnvironment(GetEnvironmentRequest {
        environment_id: id.to_owned(),
    });
    Ok((StatusCode::OK, detail(&one(state, op).await?)))
}

/// An operation on one of the caller's own environments, answered with its summary.
pub(crate) async fn act(state: &State, client: &Client, id: &str, action: &str) -> Reply {
    owned(state, client, id)?;
    let environment_id = id.to_owned();
    let op = match action {
        "stop" => control_request::Op::StopEnvironment(StopEnvironmentRequest { environment_id }),
        "resume" => control_request::Op::ResumeEnvironment(ResumeEnvironmentRequest { environment_id }),
        "cancel" => control_request::Op::CancelEnvironment(CancelEnvironmentRequest { environment_id }),
        "delete" => control_request::Op::DeleteEnvironment(DeleteEnvironmentRequest { environment_id }),
        _ => return Err(FORBIDDEN),
    };
    Ok((StatusCode::OK, summary(&one(state, op).await?)))
}
