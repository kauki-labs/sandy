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
    format!("{}.{request_id}", namespace_prefix(&client.id))
}

/// The 16 hex digits that start every idempotency key of `client_id`.
pub(crate) fn namespace_prefix(client_id: &str) -> String {
    hex::encode(Sha256::digest(client_id.as_bytes()))[..16].to_owned()
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

/// Everything but a known terminal state counts, so a state sandyd adds later
/// is counted against the quota until this code says otherwise.
fn is_live(state: i32) -> bool {
    !matches!(
        EnvironmentState::try_from(state),
        Ok(EnvironmentState::Failed | EnvironmentState::Deleted)
    )
}

const QUOTA_RECORDS: ApiError = ApiError {
    status: StatusCode::TOO_MANY_REQUESTS,
    code: "quota_exceeded",
    message: "too many environments created",
};

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
        // The reason is sandyd's own text and may name a path or a credential once the
        // launch driver writes it, so it is neither relayed nor logged here. sandyd's
        // store holds it for the operator. The step is relayed only if it is a plain name.
        let step = if safe_step(&f.step) { f.step.as_str() } else { "unknown" };
        body["failure"] = json!({"step": step, "reason": "the step failed; the operator has the details"});
    }
    // A stopped, failed or deleted environment has no reachable service, so a URL
    // sandyd still holds for one is not relayed: it could outlive the delete.
    if e.state == i32::from(EnvironmentState::Ready)
        && let Some(c) = e.connection.as_ref().filter(|c| !c.url.is_empty())
    {
        body["connection"] = json!({"url": c.url});
    }
    body
}

/// A provisioning step name the broker relays: at most 64 characters of letters,
/// digits, `-`, `_`, `.`.
fn safe_step(step: &str) -> bool {
    (1..=64).contains(&step.len())
        && step
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
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

/// sandyd refuses a list that matches too many rows with `INVALID_ARGUMENT`. The
/// caller's own arguments were already checked, so that refusal is the daemon's
/// limit, not a bad request.
fn list_refusal(e: ApiError) -> ApiError {
    if e.status == StatusCode::BAD_REQUEST && e.code == "invalid_request" {
        UNAVAILABLE
    } else {
        e
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
    // sandyd owns whether a profile exists (#592). The broker owns which client may
    // name it. An empty list allows none, so a client is useless until configured.
    if !client.profiles.contains(&body.profile) {
        return Err(FORBIDDEN);
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
    // One create at a time per client, so the quota check and the create cannot race
    // another create of the same client, and one client cannot hold up another.
    let _serial = state.env_create.get(&client.id).ok_or(UNAVAILABLE)?.lock().await;
    if !state.owners.has_request(&client.id, &body.request_id) {
        let live = live_owned(state, client).await?;
        if live >= client.max_environments {
            return Err(QUOTA);
        }
        if state.owners.environment_records(&client.id) >= client.max_environment_records {
            return Err(QUOTA_RECORDS);
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
    let control_response::Result::Environments(all) = call(state, op).await.map_err(list_refusal)? else {
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
    let task_ref = query_param(query, "task_ref").unwrap_or_default();
    if task_ref.len() > 256 || task_ref.chars().any(char::is_control) {
        return Err(INVALID);
    }
    let op = control_request::Op::ListEnvironments(ListEnvironmentsRequest {
        state: wanted.into(),
        task_ref,
    });
    let control_response::Result::Environments(all) = call(state, op).await.map_err(list_refusal)? else {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_id_must_be_1_to_111_characters_of_letters_digits_dash_underscore_dot() {
        assert!(valid_request_id("a"));
        assert!(valid_request_id("Task-1_2.x"));
        assert!(valid_request_id(&"x".repeat(111)));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id(&"x".repeat(112)));
        for bad in ["has space", "a\nb", "a/b", "a:b", "tab\t", "\u{e9}"] {
            assert!(!valid_request_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_list_the_daemon_refuses_is_unavailable_not_a_bad_request() {
        assert_eq!(list_refusal(REFUSED_FIELDS).code, "unavailable");
        assert_eq!(list_refusal(NOT_FOUND).code, "not_found");
        assert_eq!(list_refusal(QUOTA).code, "quota_exceeded");
    }

    fn response(state: EnvironmentState, url: &str) -> EnvironmentResponse {
        EnvironmentResponse {
            environment_id: "env-1".to_owned(),
            state: state.into(),
            connection: Some(sandy_control_proto::v1::EnvironmentConnection { url: url.to_owned() }),
            ..Default::default()
        }
    }

    #[test]
    fn a_connection_url_is_relayed_only_while_the_environment_is_ready() {
        let url = "http://127.0.0.1:9000";
        assert_eq!(
            detail(&response(EnvironmentState::Ready, url))["connection"]["url"],
            url
        );
        for state in [
            EnvironmentState::Provisioning,
            EnvironmentState::Stopped,
            EnvironmentState::Failed,
            EnvironmentState::Deleted,
        ] {
            let body = detail(&response(state, url));
            assert!(body.get("connection").is_none(), "{state:?} relayed {body}");
        }
    }

    #[test]
    fn a_failure_step_is_relayed_only_if_it_is_a_plain_name() {
        for (step, relayed) in [
            ("clone", "clone"),
            ("warm.deps-1", "warm.deps-1"),
            ("/home/daemon/.ssh", "unknown"),
            ("has space", "unknown"),
            ("token=ghp_x", "unknown"),
        ] {
            let e = EnvironmentResponse {
                state: EnvironmentState::Failed.into(),
                failure: Some(sandy_control_proto::v1::EnvironmentFailure {
                    step: step.to_owned(),
                    reason: "x".to_owned(),
                }),
                ..Default::default()
            };
            assert_eq!(detail(&e)["failure"]["step"], relayed, "{step}");
        }
        assert!(!safe_step(&"x".repeat(65)));
    }

    #[test]
    fn a_failure_reason_from_sandyd_is_not_relayed() {
        let e = EnvironmentResponse {
            environment_id: "env-1".to_owned(),
            state: EnvironmentState::Failed.into(),
            failure: Some(sandy_control_proto::v1::EnvironmentFailure {
                step: "clone".to_owned(),
                reason: "cannot read /home/daemon/.ssh/id_ed25519 token=ghp_secret".to_owned(),
            }),
            ..Default::default()
        };
        let body = detail(&e).to_string();
        assert!(body.contains("clone"), "the step is relayed: {body}");
        assert!(!body.contains("ghp_secret") && !body.contains("/home/daemon"), "{body}");
    }

    #[test]
    fn an_unknown_state_counts_as_live_and_only_failed_and_deleted_do_not() {
        assert!(is_live(EnvironmentState::Provisioning.into()));
        assert!(is_live(EnvironmentState::Ready.into()));
        assert!(is_live(EnvironmentState::Stopped.into()));
        assert!(is_live(99));
        assert!(!is_live(EnvironmentState::Failed.into()));
        assert!(!is_live(EnvironmentState::Deleted.into()));
    }

    #[test]
    fn the_namespace_prefix_is_16_lowercase_hex_digits_and_differs_per_client() {
        let (a, b) = (namespace_prefix("a"), namespace_prefix("b"));
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        assert_ne!(a, b);
    }
}
