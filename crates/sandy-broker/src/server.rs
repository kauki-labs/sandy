//! Request routing and the job handlers.

use std::{path::PathBuf, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use sandy_control_proto::{
    CancelRequest, Input, IsolationClass as WireClass, JobStatus, ListRequest, Output, SecretRef, StatusRequest,
    SubmitRequest, client, control_request, control_response,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::UnixStream;

use crate::{
    Client, IsolationClass, attach, auth::authenticate, body::Body, environments, output, output::Outputs,
    owners::Owners, paths::within_roots,
};

const MAX_BODY: usize = 1024 * 1024;

pub(crate) struct State {
    pub(crate) control_socket: PathBuf,
    pub(crate) rpc_deadline: std::time::Duration,
    pub(crate) clients: Vec<Client>,
    pub(crate) owners: Owners,
    pub(crate) tickets: attach::Tickets,
    /// Each accepted job's collected output.
    pub(crate) outputs: Outputs,
    /// How long one write to a stalled attach client may block.
    pub(crate) send_timeout: std::time::Duration,
    /// Serializes one client's environment creates, so a quota check and its create are one step.
    pub(crate) env_create: std::collections::HashMap<String, tokio::sync::Mutex<()>>,
}

/// A typed API error (the contract's `Error` schema).
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

const UNAUTHENTICATED: ApiError = ApiError {
    status: StatusCode::UNAUTHORIZED,
    code: "unauthenticated",
    message: "missing or unknown bearer token",
};
pub(crate) const NOT_FOUND: ApiError = ApiError {
    status: StatusCode::NOT_FOUND,
    code: "not_found",
    message: "no such resource",
};
pub(crate) const FORBIDDEN: ApiError = ApiError {
    status: StatusCode::FORBIDDEN,
    code: "forbidden",
    message: "the request exceeds what this client may do",
};
pub(crate) const INVALID: ApiError = ApiError {
    status: StatusCode::BAD_REQUEST,
    code: "invalid_request",
    message: "the request body is not valid",
};
const UNSUPPORTED: ApiError = ApiError {
    status: StatusCode::NOT_IMPLEMENTED,
    code: "unsupported",
    message: "not supported by this broker yet",
};
pub(crate) const UNAVAILABLE: ApiError = ApiError {
    status: StatusCode::SERVICE_UNAVAILABLE,
    code: "unavailable",
    message: "sandyd refused or could not be reached",
};

fn respond(status: StatusCode, body: &Value) -> Response<Body> {
    let mut response = Response::new(Body::Full(Full::new(Bytes::from(body.to_string()))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

pub(crate) fn error(e: &ApiError) -> Response<Body> {
    respond(e.status, &json!({"code": e.code, "message": e.message}))
}

pub(crate) fn busy() -> Response<Body> {
    error(&ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "unavailable",
        message: "too many requests in flight",
    })
}

pub(crate) fn internal_error() -> Response<Body> {
    respond(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({"code": "unavailable", "message": "internal error"}),
    )
}

pub(crate) async fn handle(state: Arc<State>, req: Request<Incoming>) -> Response<Body> {
    let authorization = req.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    let Some(client) = authenticate(&state.clients, authorization) else {
        return error(&UNAUTHENTICATED);
    };
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let result = match (&method, segments.as_slice()) {
        (&Method::POST, ["v1", "jobs"]) => submit(&state, client, req).await,
        (&Method::GET, ["v1", "jobs"]) => list(&state, client).await,
        (&Method::GET, ["v1", "jobs", id]) => get(&state, client, id).await,
        (&Method::GET, ["v1", "jobs", id, "output"]) => output::get(&state, client, id, req.uri().query()),
        (&Method::POST, ["v1", "jobs", id, "cancel"]) => cancel(&state, client, id).await,
        (&Method::POST, ["v1", "environments"]) => environments::spawn(&state, client, req).await,
        (&Method::GET, ["v1", "environments"]) => environments::list(&state, client, req.uri().query()).await,
        (&Method::GET, ["v1", "environments", id]) => environments::get(&state, client, id).await,
        (&Method::DELETE, ["v1", "environments", id]) => environments::act(&state, client, id, "delete").await,
        (&Method::POST, ["v1", "environments", id, action @ ("cancel" | "stop" | "resume")]) => {
            environments::act(&state, client, id, action).await
        }
        (&Method::POST, ["v1", "jobs", id, "attach"]) => attach::issue(&state, client, id).await,
        (&Method::GET, ["v1", "jobs", id, "stream", ticket]) => {
            return attach::stream(Arc::clone(&state), client, id, ticket).await;
        }
        (&Method::POST, ["v1", "environments", _, "link"]) => Err(UNSUPPORTED),
        _ => Err(NOT_FOUND),
    };
    match result {
        Ok((status, body)) => respond(status, &body),
        Err(e) => error(&e),
    }
}

pub(crate) type Reply = Result<(StatusCode, Value), ApiError>;

/// The request body, at most [`MAX_BODY`] bytes.
pub(crate) async fn read_body(req: Request<Incoming>) -> Result<Bytes, ApiError> {
    Ok(Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|_| INVALID)?
        .to_bytes())
}

/// One control-RPC call over a fresh UDS connection. Any transport fault or
/// `ControlError` becomes `unavailable`: sandyd's own message is not relayed.
pub(crate) async fn rpc(state: &State, op: control_request::Op) -> Result<control_response::Result, ApiError> {
    tokio::time::timeout(state.rpc_deadline, rpc_inner(state, op))
        .await
        .unwrap_or_else(|_| {
            tracing::warn!("control call timed out");
            Err(UNAVAILABLE)
        })
}

async fn rpc_inner(state: &State, op: control_request::Op) -> Result<control_response::Result, ApiError> {
    let mut stream = UnixStream::connect(&state.control_socket).await.map_err(|e| {
        tracing::warn!(error = %e, "cannot reach sandyd");
        UNAVAILABLE
    })?;
    let response = client::call(&mut stream, 1, op).await.map_err(|e| {
        tracing::warn!(error = %e, "control call failed");
        UNAVAILABLE
    })?;
    match response.result {
        Some(control_response::Result::Error(e)) => {
            tracing::warn!(message = %e.message, "sandyd refused a control request");
            Err(UNAVAILABLE)
        }
        Some(result) => Ok(result),
        None => Err(UNAVAILABLE),
    }
}

fn state_name(status: i32) -> &'static str {
    match JobStatus::try_from(status) {
        Ok(JobStatus::Pending) => "pending",
        Ok(JobStatus::Running) => "running",
        Ok(JobStatus::Succeeded) => "succeeded",
        Ok(JobStatus::Failed) => "failed",
        Ok(JobStatus::Cancelled) => "cancelled",
        _ => "failed",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitJob {
    manifest: String,
    manifest_encoding: String,
    required_isolation_class: IsolationClass,
    #[serde(default)]
    inputs: Vec<InputBody>,
    #[serde(default)]
    outputs: Vec<OutputBody>,
    #[serde(default)]
    secrets: Vec<SecretBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputBody {
    host: String,
    name: String,
    guest_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputBody {
    name: Option<String>,
    dest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretBody {
    name: String,
    host_path: String,
}

async fn submit(state: &Arc<State>, client: &Client, req: Request<Incoming>) -> Reply {
    let bytes = Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|_| INVALID)?
        .to_bytes();
    let body: SubmitJob = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    let manifest = STANDARD.decode(&body.manifest).map_err(|_| INVALID)?;
    if body.required_isolation_class > client.max_isolation_class {
        return Err(FORBIDDEN);
    }
    let paths = body
        .inputs
        .iter()
        .map(|i| &i.host)
        .chain(body.outputs.iter().map(|o| &o.dest))
        .chain(body.secrets.iter().map(|s| &s.host_path));
    if !paths.into_iter().all(|p| within_roots(p, &client.roots)) {
        return Err(FORBIDDEN);
    }
    let class = match body.required_isolation_class {
        IsolationClass::Trusted => WireClass::Trusted,
        IsolationClass::Untrusted => WireClass::Untrusted,
    };
    let submit = SubmitRequest {
        manifest,
        manifest_encoding: body.manifest_encoding,
        submitter_caps: Vec::new(),
        required_isolation_class: class.into(),
        inputs: body
            .inputs
            .into_iter()
            .map(|i| Input {
                host: i.host,
                name: i.name,
                guest_path: i.guest_path,
            })
            .collect(),
        outputs: body
            .outputs
            .into_iter()
            .map(|o| Output {
                name: o.name,
                dest: o.dest,
            })
            .collect(),
        secrets: body
            .secrets
            .into_iter()
            .map(|s| SecretRef {
                name: s.name,
                host_path: s.host_path,
            })
            .collect(),
    };
    let control_response::Result::Submit(done) = rpc(state, control_request::Op::Submit(submit)).await? else {
        return Err(UNAVAILABLE);
    };
    if let Err(e) = state.owners.insert(&done.job_id, &client.id, &done.attach_token) {
        // Without the token the job could never be cancelled through this API,
        // so cancel it now and report the fault.
        tracing::error!(error = %e, job_id = %done.job_id, "cannot record job owner; cancelling the job");
        let cancel = CancelRequest {
            job_id: done.job_id.clone(),
            attach_token: Some(done.attach_token.clone()),
        };
        match rpc(state, control_request::Op::Cancel(cancel)).await {
            Ok(control_response::Result::Cancel(_)) => {
                tracing::info!(job_id = %done.job_id, "cancelled the job that has no recorded owner");
            }
            other => tracing::error!(
                job_id = %done.job_id,
                cancelled = other.is_ok(),
                "the job has no recorded owner and was NOT cancelled; it runs until its deadline"
            ),
        }
        return Err(UNAVAILABLE);
    }
    state.outputs.register(&done.job_id);
    tokio::spawn(output::collect(Arc::clone(state), done.job_id.clone()));
    Ok((StatusCode::ACCEPTED, json!({"job_id": done.job_id, "state": "pending"})))
}

async fn list(state: &State, client: &Client) -> Reply {
    let control_response::Result::List(all) = rpc(state, control_request::Op::List(ListRequest {})).await? else {
        return Err(UNAVAILABLE);
    };
    let jobs: Vec<Value> = all
        .jobs
        .into_iter()
        .filter(|j| state.owners.owns(&j.job_id, &client.id))
        .map(|j| json!({"job_id": j.job_id, "state": state_name(j.status)}))
        .collect();
    Ok((StatusCode::OK, json!({"jobs": jobs})))
}

pub(crate) async fn status_of(state: &State, id: &str) -> Result<Value, ApiError> {
    let op = control_request::Op::Status(StatusRequest { job_id: id.to_owned() });
    let control_response::Result::Status(s) = rpc(state, op).await? else {
        return Err(UNAVAILABLE);
    };
    let mut body = json!({"job_id": s.job_id, "state": state_name(s.status)});
    if let Some(code) = s.exit_code {
        body["exit_code"] = json!(code);
    }
    if !s.console_tail.is_empty() {
        body["console_tail"] = json!(s.console_tail);
    }
    Ok(body)
}

async fn get(state: &State, client: &Client, id: &str) -> Reply {
    if !state.owners.owns(id, &client.id) {
        return Err(NOT_FOUND);
    }
    Ok((StatusCode::OK, status_of(state, id).await?))
}

async fn cancel(state: &State, client: &Client, id: &str) -> Reply {
    let token = state.owners.token_for(id, &client.id).ok_or(NOT_FOUND)?;
    let op = control_request::Op::Cancel(CancelRequest {
        job_id: id.to_owned(),
        attach_token: Some(token),
    });
    rpc(state, op).await?;
    // sandyd applied the cancel. Report that, whatever the status read says.
    Ok((StatusCode::OK, json!({"job_id": id, "state": "cancelled"})))
}
