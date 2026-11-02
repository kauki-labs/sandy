//! The secret guard (O8): no secret in a tool argument or result.

use serde_json::Value;

/// Field names that only ever carry a secret.
const SECRET_FIELDS: &[&str] = &[
    "secret",
    "token",
    "key",
    "password",
    "api_key",
    "apikey",
    "pairing_code",
    "authorization",
];

/// Value prefixes of well-known token formats.
const TOKEN_PREFIXES: &[&str] = &["ghp_", "gho_", "ghs_", "github_pat_", "sk-", "xoxb-", "AKIA"];

/// Returns the JSON path of the first secret-looking field or value in `v`.
pub(crate) fn find_secret(v: &Value) -> Option<String> {
    walk(v, "$")
}

fn walk(v: &Value, path: &str) -> Option<String> {
    match v {
        Value::Object(map) => map.iter().find_map(|(k, child)| {
            let here = format!("{path}.{k}");
            let lower = k.to_ascii_lowercase();
            if SECRET_FIELDS.contains(&lower.as_str()) {
                return Some(here);
            }
            walk(child, &here)
        }),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, child)| walk(child, &format!("{path}[{i}]"))),
        Value::String(s) => looks_like_token(s).then(|| path.to_owned()),
        _ => None,
    }
}

fn looks_like_token(s: &str) -> bool {
    s.contains("-----BEGIN")
        || s.split(|c: char| c.is_whitespace() || c == '"' || c == '\'').any(|w| {
            TOKEN_PREFIXES
                .iter()
                .any(|p| w.starts_with(p) && w.len() >= p.len() + 8)
                || is_jwt(w)
        })
}

fn is_jwt(w: &str) -> bool {
    let parts: Vec<_> = w.split('.').collect();
    parts.len() == 3 && parts[0].starts_with("eyJ") && parts.iter().all(|p| p.len() >= 8)
}
