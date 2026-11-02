//! JSON-RPC 2.0 over newline-delimited stdio: the MCP subset a tool server needs.

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{
    api::{Api, ApiError},
    guard::find_secret,
    tools::{TOOLS, Tool},
};

const PROTOCOL_VERSION: &str = "2025-06-18";

/// The MCP server: a tool table over one [`Api`].
pub struct Server {
    api: Api,
}

impl Server {
    /// A server that serves its tools against `api`.
    pub fn new(api: Api) -> Self {
        Self { api }
    }

    /// Handles one JSON-RPC message. `None` for a notification.
    pub async fn handle(&self, msg: Value) -> Option<Value> {
        let id = msg.get("id").cloned()?;
        let method = msg["method"].as_str().unwrap_or_default();
        Some(match method {
            "initialize" => reply(
                id,
                json!({"protocolVersion": PROTOCOL_VERSION,
                       "capabilities": {"tools": {}},
                       "serverInfo": {"name": "sandy-mcp", "version": env!("CARGO_PKG_VERSION")}}),
            ),
            "ping" => reply(id, json!({})),
            "tools/list" => reply(id, json!({"tools": TOOLS.iter().map(describe).collect::<Vec<_>>()})),
            "tools/call" => self.call(id, &msg["params"]).await,
            _ => rpc_error(id, -32601, "method not found"),
        })
    }

    async fn call(&self, id: Value, params: &Value) -> Value {
        let name = params["name"].as_str().unwrap_or_default();
        let Some(tool) = TOOLS.iter().find(|t| t.name == name) else {
            return rpc_error(id, -32602, "unknown tool");
        };
        let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
        match self.run(tool, args).await {
            Ok(v) => reply(id, tool_result(&v, false)),
            Err(e) => reply(id, tool_result(&e.to_json(), true)),
        }
    }

    /// One tool call: validate, make exactly one API request, screen the result.
    async fn run(&self, tool: &Tool, args: Value) -> Result<Value, ApiError> {
        let Value::Object(mut args) = args else {
            return Err(ApiError::new("invalid_request", "arguments must be an object"));
        };
        let props = (tool.properties)();
        if let Some(extra) = args.keys().find(|k| props.get(k.as_str()).is_none()) {
            return Err(ApiError::new("invalid_request", format!("unknown argument `{extra}`")));
        }
        if let Some(missing) = tool.required.iter().find(|r| !args.contains_key(**r)) {
            return Err(ApiError::new(
                "invalid_request",
                format!("missing argument `{missing}`"),
            ));
        }
        if let Some(at) = find_secret(&Value::Object(args.clone())) {
            return Err(ApiError::new(
                "invalid_request",
                format!("a secret is not allowed in a tool argument (at {at})"),
            ));
        }
        let mut path = tool.path.to_owned();
        for name in tool.path_args {
            let value = args.remove(*name).and_then(|v| v.as_str().map(str::to_owned));
            let value = value.filter(|v| !v.is_empty() && !v.contains(['/', '?', '#']));
            let value = value.ok_or_else(|| ApiError::new("invalid_request", format!("invalid `{name}`")))?;
            path = path.replace(&format!("{{{name}}}"), &value);
        }
        let mut query = Vec::new();
        for name in tool.query {
            if let Some(v) = args.remove(*name) {
                let v = v
                    .as_str()
                    .filter(|v| v.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)));
                let v = v.ok_or_else(|| ApiError::new("invalid_request", format!("invalid `{name}`")))?;
                query.push(format!("{name}={v}"));
            }
        }
        if !query.is_empty() {
            path = format!("{path}?{}", query.join("&"));
        }
        let body = (!matches!(tool.method, "GET" | "DELETE") && !args.is_empty()).then_some(Value::Object(args));
        let out = self.api.request(tool.method, &path, body.as_ref()).await?;
        if find_secret(&out).is_some() {
            return Err(ApiError::new(
                "unavailable",
                "the API result was withheld: it held a secret",
            ));
        }
        Ok(out)
    }
}

fn describe(t: &Tool) -> Value {
    json!({"name": t.name, "description": t.description, "inputSchema": t.input_schema()})
}

fn tool_result(v: &Value, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": v.to_string()}], "isError": is_error})
}

fn reply(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Serves `server` on stdin/stdout until stdin closes.
pub async fn serve_stdio(server: &Server) -> std::io::Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => server.handle(msg).await,
            Err(_) => Some(rpc_error(Value::Null, -32700, "parse error")),
        };
        if let Some(resp) = resp {
            out.write_all(resp.to_string().as_bytes()).await?;
            out.write_all(b"\n").await?;
            out.flush().await?;
        }
    }
    Ok(())
}
