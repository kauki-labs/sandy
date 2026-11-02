//! A stateful in-memory broker for the sandy-mcp tests: idempotent spawn by
//! `request_id`, a probe gate before Ready, quota, and a job table. It stands
//! in for the API tier; the conformance script must pass against it and,
//! later, against a real broker.
#![allow(dead_code, reason = "shared by several test binaries; each uses a subset")]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use serde_json::{Value, json};

pub struct Broker {
    pub by_request: HashMap<String, (Value, String)>,
    pub states: HashMap<String, String>,
    pub jobs: HashMap<String, String>,
    /// Every `METHOD URL` the broker saw.
    pub requests: Vec<(String, String)>,
    /// The `Authorization` header of every request.
    pub auth: Vec<Option<String>>,
    /// An environment turns Ready on the poll after this many polls. Never, by default.
    pub ready_after_polls: usize,
    /// A spawn with a repeated `request_id` returns the same environment.
    pub idempotent: bool,
    /// Concurrent non-terminal environments allowed.
    pub quota: usize,
    pub polls: HashMap<String, usize>,
}

impl Default for Broker {
    fn default() -> Self {
        Self {
            by_request: HashMap::new(),
            states: HashMap::new(),
            jobs: HashMap::new(),
            requests: Vec::new(),
            auth: Vec::new(),
            ready_after_polls: usize::MAX,
            idempotent: true,
            quota: 2,
            polls: HashMap::new(),
        }
    }
}

impl Broker {
    /// Environments and jobs the fake's own state table lists as non-terminal.
    /// This reads the fake's internals, so it is tier-2 only: a live target must
    /// check `sandy ls`, VM processes and credential leases instead.
    pub fn leftovers(&self) -> usize {
        let envs = self
            .states
            .values()
            .filter(|s| matches!(s.as_str(), "provisioning" | "ready" | "stopped"))
            .count();
        let jobs = self
            .jobs
            .values()
            .filter(|s| matches!(s.as_str(), "pending" | "running"))
            .count();
        envs + jobs
    }
}

pub fn broker() -> Result<(String, Arc<Mutex<Broker>>)> {
    start(Broker::default())
}

/// Serves `broker` on a loopback port; returns its base URL and the shared state.
pub fn start(broker: Broker) -> Result<(String, Arc<Mutex<Broker>>)> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| anyhow::anyhow!("{e}"))?;
    let url = format!("http://{}", server.server_addr());
    let state = Arc::new(Mutex::new(broker));
    let s = Arc::clone(&state);
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let method = req.method().to_string();
            let url = req.url().to_string();
            let auth = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("authorization"))
                .map(|h| h.value.to_string());
            let (status, out) = {
                let mut b = s.lock().unwrap();
                b.auth.push(auth);
                route(&mut b, &method, &url, &body)
            };
            let resp = tiny_http::Response::from_string(out.to_string())
                .with_status_code(status)
                .with_header(tiny_http::Header::from_bytes("content-type", "application/json").unwrap());
            let _ = req.respond(resp);
        }
    });
    Ok((url, state))
}

fn err(status: u16, code: &str) -> (u16, Value) {
    (status, json!({"code": code, "message": code}))
}

fn route(b: &mut Broker, method: &str, url: &str, body: &str) -> (u16, Value) {
    b.requests.push((method.to_owned(), url.to_owned()));
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    match (method, parts.as_slice()) {
        ("POST", ["v1", "environments"]) => spawn(b, body),
        ("GET", ["v1", "environments"]) => {
            let want = query.strip_prefix("state=");
            let envs: Vec<_> = b
                .states
                .iter()
                .filter(|(_, s)| want.is_none_or(|w| w == s.as_str()))
                .map(|(id, s)| json!({"environment_id": id, "state": s}))
                .collect();
            (200, json!({"environments": envs}))
        }
        ("GET", ["v1", "environments", id]) => get_environment(b, id),
        ("DELETE", ["v1", "environments", id]) | ("POST", ["v1", "environments", id, "cancel"]) => {
            if !b.states.contains_key(*id) {
                return err(404, "not_found");
            }
            b.states.insert((*id).to_owned(), "deleted".into());
            (200, json!({"environment_id": id, "state": "deleted"}))
        }
        ("POST", ["v1", "environments", _, "stop" | "resume"]) => err(409, "unsupported_for_lifetime"),
        ("POST", ["v1", "environments", _, "link"]) => (200, json!({"link_status": "unsupported"})),
        ("POST", ["v1", "jobs"]) => {
            let id = format!("j{}", b.jobs.len() + 1);
            b.jobs.insert(id.clone(), "pending".into());
            (202, json!({"job_id": id, "state": "pending"}))
        }
        ("GET", ["v1", "jobs"]) => {
            let jobs: Vec<_> = b.jobs.iter().map(|(id, s)| json!({"job_id": id, "state": s})).collect();
            (200, json!({"jobs": jobs}))
        }
        ("GET", ["v1", "jobs", id]) => match b.jobs.get(*id) {
            Some(s) => (200, json!({"job_id": id, "state": s})),
            None => err(404, "not_found"),
        },
        ("POST", ["v1", "jobs", id, "cancel"]) => match b.jobs.get_mut(*id) {
            Some(s) => {
                "cancelled".clone_into(s);
                (200, json!({"job_id": id, "state": "cancelled"}))
            }
            None => err(404, "not_found"),
        },
        ("POST", ["v1", "jobs", id, "attach"]) if b.jobs.contains_key(*id) => {
            (200, json!({"stream_url": format!("http://127.0.0.1/s/{id}")}))
        }
        _ => err(404, "not_found"),
    }
}

fn spawn(b: &mut Broker, body: &str) -> (u16, Value) {
    let payload: Value = serde_json::from_str(body).unwrap_or_default();
    let rid = payload["request_id"].as_str().unwrap_or_default().to_owned();
    if b.idempotent
        && let Some((first, id)) = b.by_request.get(&rid)
    {
        if *first != payload {
            return err(409, "request_id_conflict");
        }
        return (202, json!({"environment_id": id, "state": b.states[id]}));
    }
    if b.leftovers_envs() >= b.quota {
        return err(429, "quota_exceeded");
    }
    let id = format!("env{}", b.states.len() + 1);
    b.by_request.insert(rid, (payload, id.clone()));
    b.states.insert(id.clone(), "provisioning".into());
    (202, json!({"environment_id": id, "state": "provisioning"}))
}

impl Broker {
    fn leftovers_envs(&self) -> usize {
        self.states
            .values()
            .filter(|s| !matches!(s.as_str(), "deleted" | "failed"))
            .count()
    }
}

fn get_environment(b: &mut Broker, id: &str) -> (u16, Value) {
    let Some(state) = b.states.get(id).cloned() else {
        return err(404, "not_found");
    };
    if state == "provisioning" {
        let polls = b.polls.entry(id.to_owned()).or_default();
        *polls += 1;
        if *polls > b.ready_after_polls {
            b.states.insert(id.to_owned(), "ready".into());
            return get_environment(b, id);
        }
    }
    match state.as_str() {
        "ready" => (
            200,
            json!({"environment_id": id, "state": state, "steps": [],
                   "connection": {"url": "http://10.0.0.2:3773"}}),
        ),
        "failed" => (
            200,
            json!({"environment_id": id, "state": state, "steps": [],
                   "failure": {"step": "boot", "reason": "probe timed out"}}),
        ),
        _ => (200, json!({"environment_id": id, "state": state, "steps": []})),
    }
}
