//! The secret guard (O8): no secret in a tool argument or result.

use serde_json::Value;

/// A field name containing one of these (case-insensitive) is a secret.
const SECRET_FIELD_PARTS: &[&str] = &[
    "token",
    "secret",
    "key",
    "pass",
    "credential",
    "pairing",
    "authorization",
];

/// Field names that look secret but carry none: `submit`'s file references.
const FIELD_ALLOWLIST: &[&str] = &["secrets"];

/// Token formats: prefix and the minimum run of token characters after it.
const TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("ghp_", 20),
    ("gho_", 20),
    ("ghs_", 20),
    ("ghu_", 20),
    ("github_pat_", 20),
    ("sk-", 20),
    ("glpat-", 20),
    ("xoxb-", 10),
    ("AKIA", 16),
];

/// Returns the JSON path of the first secret-looking field or value in `v`.
pub(crate) fn find_secret(v: &Value) -> Option<String> {
    walk(v, "$")
}

fn walk(v: &Value, path: &str) -> Option<String> {
    match v {
        Value::Object(map) => map.iter().find_map(|(k, child)| {
            let here = format!("{path}.{k}");
            if secret_field(k) {
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

fn secret_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !FIELD_ALLOWLIST.contains(&lower.as_str()) && SECRET_FIELD_PARTS.iter().any(|p| lower.contains(p))
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Occurrences of `needle` in `s` that start a word: the previous byte is not
/// alphanumeric, so `task-` does not match `sk-`.
fn word_starts<'a>(s: &'a str, needle: &'a str) -> impl Iterator<Item = usize> + 'a {
    s.match_indices(needle)
        .map(|(i, _)| i)
        .filter(|&i| i == 0 || !s.as_bytes()[i - 1].is_ascii_alphanumeric())
}

fn looks_like_token(s: &str) -> bool {
    if s.contains("-----BEGIN") {
        return true;
    }
    let by_prefix = TOKEN_PREFIXES.iter().any(|(prefix, min)| {
        word_starts(s, prefix).any(|i| {
            s.as_bytes()[i + prefix.len()..]
                .iter()
                .take_while(|b| is_token_char(**b))
                .count()
                >= *min
        })
    });
    by_prefix
        || word_starts(s, "eyJ").any(|i| {
            let run = s[i..].bytes().take_while(|b| is_token_char(*b) || *b == b'.').count();
            is_jwt(&s[i..i + run])
        })
}

fn is_jwt(w: &str) -> bool {
    let parts: Vec<_> = w.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| p.len() >= 8)
}
