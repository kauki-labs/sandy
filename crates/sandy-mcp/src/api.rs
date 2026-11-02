//! The API client: one request per call, bearer credential, typed errors.

use std::{net::IpAddr, time::Duration};

use serde_json::{Value, json};

/// Largest API response body the client reads.
const MAX_BODY: usize = 1024 * 1024;

/// A typed failure, shaped like the API's `Error` schema.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub(crate) fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({"code": self.code, "message": self.message})
    }
}

/// Client for the sandyd broker API.
pub struct Api {
    base: String,
    credential: String,
    http: reqwest::Client,
}

impl Api {
    /// A client for `base` (no trailing slash needed) that sends `credential`
    /// as the bearer token. The credential never appears in `Debug` output.
    pub fn new(base: &str, credential: &str) -> Self {
        Self::with_timeout(base, credential, Duration::from_secs(30))
    }

    /// Like [`Api::new`] with a total request `timeout`. The client follows no
    /// redirect (a redirect would replay a request) and ignores proxy
    /// environment variables (the bearer credential must reach the broker only).
    pub fn with_timeout(base: &str, credential: &str, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap_or_default();
        Self {
            base: base.trim_end_matches('/').to_owned(),
            credential: credential.to_owned(),
            http,
        }
    }

    pub(crate) async fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, ApiError> {
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| ApiError::new("invalid_request", e.to_string()))?;
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.credential);
        if let Some(body) = body {
            req = req.json(body);
        }
        let unreachable = || ApiError::new("unavailable", "the broker API is unreachable");
        let mut resp = req.send().await.map_err(|_| unreachable())?;
        let status = resp.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|_| unreachable())? {
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err(ApiError::new("unavailable", "the broker API response is too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let parsed = serde_json::from_slice::<Value>(&bytes);
        if status.is_success() {
            return parsed.map_err(|_| ApiError::new("unavailable", "the broker API returned an invalid response"));
        }
        let payload = parsed.unwrap_or(Value::Null);
        let code = payload["code"].as_str().unwrap_or("unavailable");
        let message = payload["message"]
            .as_str()
            .unwrap_or("the broker API refused the request");
        Err(ApiError::new(code, message))
    }
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").field("base", &self.base).finish_non_exhaustive()
    }
}

/// Accepts a broker URL the client can use safely: plain `http` to a loopback
/// address only. The client has no TLS backend, so a remote broker would get
/// the bearer credential in cleartext; reach one through a local tunnel.
pub fn check_base_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid broker URL: {e}"))?;
    if parsed.scheme() != "http" {
        return Err("only an `http` broker URL is supported (this build has no TLS)".into());
    }
    let host = parsed.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let loopback = host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if loopback {
        Ok(())
    } else {
        Err("the broker URL must be loopback: this build sends the credential in cleartext (use a local tunnel)".into())
    }
}
