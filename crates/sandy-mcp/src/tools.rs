//! The tool table: each tool is one API route. No logic lives here.

use serde_json::{Value, json};

/// How a tool maps onto one API request.
pub(crate) struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub method: &'static str,
    /// Path with `{arg}` placeholders filled from the tool arguments.
    pub path: &'static str,
    /// Arguments consumed by the path; the rest form the JSON body.
    pub path_args: &'static [&'static str],
    /// Arguments sent as query parameters instead of a body.
    pub query: &'static [&'static str],
    pub required: &'static [&'static str],
    pub properties: fn() -> Value,
}

impl Tool {
    /// The MCP `inputSchema`. Unknown arguments are refused.
    pub(crate) fn input_schema(&self) -> Value {
        json!({"type":"object","properties":(self.properties)(),
               "required":self.required,"additionalProperties":false})
    }
}

fn none() -> Value {
    json!({})
}

fn job_id() -> Value {
    json!({"job_id":{"type":"string"}})
}

fn environment_id() -> Value {
    json!({"environment_id":{"type":"string"}})
}

fn spawn_props() -> Value {
    json!({
        "request_id":{"type":"string","description":"Idempotency key: a retry never creates a second environment."},
        "profile":{"type":"string","description":"Credential identity profile name. Never a secret."},
        "size":{"type":"string"},
        "lifetime":{"type":"object","required":["kind"],"additionalProperties":false,"properties":{
            "kind":{"type":"string","enum":["ephemeral","persistent"]},
            "ttl_secs":{"type":"integer","minimum":1}}},
        "task_ref":{"type":"string"},
    })
}

fn link_props() -> Value {
    json!({"environment_id":{"type":"string"},"primary":{"type":"string"}})
}

fn list_env_props() -> Value {
    json!({"state":{"type":"string","enum":["provisioning","ready","stopped","failed","deleted"]},
           "task_ref":{"type":"string"}})
}

fn submit_props() -> Value {
    json!({
        "manifest":{"type":"string","description":"Base64 job manifest."},
        "manifest_encoding":{"type":"string"},
        "required_isolation_class":{"type":"string","enum":["trusted","untrusted"]},
        "inputs":{"type":"array","items":{"type":"object","required":["host","name"],
            "additionalProperties":false,"properties":{
            "host":{"type":"string"},"name":{"type":"string"},"guest_path":{"type":"string"}}}},
        "outputs":{"type":"array","items":{"type":"object","required":["dest"],
            "additionalProperties":false,"properties":{
            "name":{"type":"string"},"dest":{"type":"string"}}}},
        "secrets":{"type":"array","description":"File references only: name and host_path.",
            "items":{"type":"object","required":["name","host_path"],"additionalProperties":false,
            "properties":{"name":{"type":"string"},"host_path":{"type":"string"}}}},
    })
}

pub(crate) static TOOLS: &[Tool] = &[
    Tool {
        name: "submit",
        description: "Submit a job.",
        method: "POST",
        path: "/v1/jobs",
        path_args: &[],
        query: &[],
        required: &["manifest", "manifest_encoding", "required_isolation_class"],
        properties: submit_props,
    },
    Tool {
        name: "status",
        description: "Get a job's status.",
        method: "GET",
        path: "/v1/jobs/{job_id}",
        path_args: &["job_id"],
        query: &[],
        required: &["job_id"],
        properties: job_id,
    },
    Tool {
        name: "cancel",
        description: "Cancel a job.",
        method: "POST",
        path: "/v1/jobs/{job_id}/cancel",
        path_args: &["job_id"],
        query: &[],
        required: &["job_id"],
        properties: job_id,
    },
    Tool {
        name: "list",
        description: "List jobs.",
        method: "GET",
        path: "/v1/jobs",
        path_args: &[],
        query: &[],
        required: &[],
        properties: none,
    },
    Tool {
        name: "attach",
        description: "Open a job's output stream and return its location.",
        method: "POST",
        path: "/v1/jobs/{job_id}/attach",
        path_args: &["job_id"],
        query: &[],
        required: &["job_id"],
        properties: job_id,
    },
    Tool {
        name: "spawn_environment",
        description: "Create an environment. Idempotent by request_id.",
        method: "POST",
        path: "/v1/environments",
        path_args: &[],
        query: &[],
        required: &["request_id", "profile", "lifetime"],
        properties: spawn_props,
    },
    Tool {
        name: "get_environment",
        description: "Get an environment: state, ordered steps, failure, and the connection once Ready.",
        method: "GET",
        path: "/v1/environments/{environment_id}",
        path_args: &["environment_id"],
        query: &[],
        required: &["environment_id"],
        properties: environment_id,
    },
    Tool {
        name: "link_environment",
        description: "Pair the environment with a primary, server-side. No pairing code passes through this tool.",
        method: "POST",
        path: "/v1/environments/{environment_id}/link",
        path_args: &["environment_id"],
        query: &[],
        required: &["environment_id", "primary"],
        properties: link_props,
    },
    Tool {
        name: "cancel_environment",
        description: "Cancel provisioning.",
        method: "POST",
        path: "/v1/environments/{environment_id}/cancel",
        path_args: &["environment_id"],
        query: &[],
        required: &["environment_id"],
        properties: environment_id,
    },
    Tool {
        name: "delete_environment",
        description: "Delete an environment and revoke its credentials. Idempotent.",
        method: "DELETE",
        path: "/v1/environments/{environment_id}",
        path_args: &["environment_id"],
        query: &[],
        required: &["environment_id"],
        properties: environment_id,
    },
    Tool {
        name: "stop_environment",
        description: "Pause an environment. Unsupported for ephemeral environments.",
        method: "POST",
        path: "/v1/environments/{environment_id}/stop",
        path_args: &["environment_id"],
        query: &[],
        required: &["environment_id"],
        properties: environment_id,
    },
    Tool {
        name: "resume_environment",
        description: "Resume a stopped environment.",
        method: "POST",
        path: "/v1/environments/{environment_id}/resume",
        path_args: &["environment_id"],
        query: &[],
        required: &["environment_id"],
        properties: environment_id,
    },
    Tool {
        name: "list_environments",
        description: "List environments, filtered by state or task_ref.",
        method: "GET",
        path: "/v1/environments",
        path_args: &[],
        query: &["state", "task_ref"],
        required: &[],
        properties: list_env_props,
    },
];
