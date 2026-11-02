//! The API client: one request per call, bearer credential, typed errors.

use serde_json::{Value, json};

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
        Self {
            base: base.trim_end_matches('/').to_owned(),
            credential: credential.to_owned(),
            http: reqwest::Client::new(),
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
        let resp = req
            .send()
            .await
            .map_err(|_| ApiError::new("unavailable", "the broker API is unreachable"))?;
        let status = resp.status();
        let payload: Value = resp.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(payload);
        }
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
