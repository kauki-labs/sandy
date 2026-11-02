//! JSON-RPC 2.0 over newline-delimited stdio: the MCP subset a tool server needs.

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::{
    api::{Api, ApiError},
    guard::find_secret,
    tools::{TOOLS, Tool},
    validate::validate,
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
        let Some(obj) = msg.as_object() else {
            return Some(rpc_error(Value::Null, -32600, "invalid request"));
        };
        let id = match obj.get("id") {
            None => return None,
            Some(Value::Null) => return Some(rpc_error(Value::Null, -32600, "invalid request: null id")),
            Some(id) => id.clone(),
        };
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
        validate(&tool.input_schema(), &args, "$").map_err(|m| ApiError::new("invalid_request", m))?;
        if let Some(at) = find_secret(&args) {
            return Err(ApiError::new(
                "invalid_request",
                format!("a secret is not allowed in a tool argument (at {at})"),
            ));
        }
        let Value::Object(mut args) = args else {
            return Err(ApiError::new("invalid_request", "arguments must be an object"));
        };
        let mut path = tool.path.to_owned();
        for name in tool.path_args {
            let value = args.remove(*name).and_then(|v| v.as_str().map(str::to_owned));
            let value = value.filter(|v| valid_segment(v));
            let value = value.ok_or_else(|| ApiError::new("invalid_request", format!("invalid `{name}`")))?;
            path = path.replace(&format!("{{{name}}}"), &value);
        }
        let mut query = Vec::new();
        for name in tool.query {
            if let Some(v) = args.remove(*name).and_then(|v| v.as_str().map(str::to_owned)) {
                query.push(format!("{name}={}", percent_encode(&v)));
            }
        }
        if !query.is_empty() {
            path = format!("{path}?{}", query.join("&"));
        }
        let body = (!matches!(tool.method, "GET" | "DELETE") && !args.is_empty()).then_some(Value::Object(args));
        match self.api.request(tool.method, &path, body.as_ref()).await {
            Ok(out) if find_secret(&out).is_some() => Err(ApiError::new(
                "withheld",
                "the operation ran; its result was withheld because it held a secret. Do not retry with a new \
                 request_id.",
            )),
            Err(e) if find_secret(&e.to_json()).is_some() => Err(ApiError::new(
                "withheld",
                "the broker answered with an error that held a secret; the error was withheld.",
            )),
            other => other,
        }
    }
}

/// A path segment: letters, digits, `_`, `-` and `.`, and not `.` or `..`.
fn valid_segment(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && !v.bytes().all(|b| b == b'.')
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Percent-encodes every byte outside the RFC 3986 unreserved set.
fn percent_encode(v: &str) -> String {
    v.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
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

/// Largest stdin message accepted.
const MAX_LINE: u64 = 1024 * 1024;

/// Serves `server` on stdin/stdout until stdin closes.
pub async fn serve_stdio(server: &Server) -> std::io::Result<()> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut out = tokio::io::stdout();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = (&mut input).take(MAX_LINE + 1).read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let too_long = buf.last() != Some(&b'\n') && buf.len() as u64 > MAX_LINE;
        let resp = if too_long {
            // Discard the rest of the oversized line, then refuse it.
            let mut sink = Vec::new();
            while input.read_until(b'\n', &mut sink).await? > 0 && sink.last() != Some(&b'\n') {
                sink.clear();
            }
            Some(rpc_error(Value::Null, -32600, "message too large"))
        } else if buf.iter().all(u8::is_ascii_whitespace) {
            continue;
        } else {
            match serde_json::from_slice::<Value>(&buf) {
                Ok(msg) => server.handle(msg).await,
                Err(_) => Some(rpc_error(Value::Null, -32700, "parse error")),
            }
        };
        if let Some(resp) = resp {
            out.write_all(resp.to_string().as_bytes()).await?;
            out.write_all(b"\n").await?;
            out.flush().await?;
        }
    }
}
