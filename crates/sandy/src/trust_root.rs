//! Trust-root installer: provisions the forge trust root the credential seam
//! consumes (`sandy app register`), as specified in
//! `docs/design/trust-root-installer/`.
//!
//! The pure, provider-neutral parts live here in the library; the network
//! provisioners (the GitHub manifest flow, REST calls) live in `sandy-cli`, so
//! the core crate carries no HTTP client. The one contract this module binds to
//! is [`crate::cred::render_github_permissions`]: the registered App's permission
//! ceiling is rendered by the SAME function a minted token is later scoped
//! through, so the two can never drift.

use serde_json::{Map, Value};

use crate::cred::{Capability, render_github_permissions};

/// Parse a [`Capability`] from its CLI spelling (`read-code`, `write-code`,
/// `read-pr`, `write-pr`).
///
/// # Errors
/// Returns the unrecognized token when it matches no capability.
pub fn parse_capability(token: &str) -> Result<Capability, String> {
    match token {
        "read-code" => Ok(Capability::ReadCode),
        "write-code" => Ok(Capability::WriteCode),
        "read-pr" => Ok(Capability::ReadPr),
        "write-pr" => Ok(Capability::WritePr),
        other => Err(other.to_string()),
    }
}

/// Build the GitHub App manifest for the manifest-registration flow, pre-filled
/// from the requested capabilities.
///
/// Permissions come from [`render_github_permissions`] so the registered App's
/// ceiling matches exactly what a minted token will later request. The webhook is
/// disabled (`hook_attributes.active = false`, sandy receives none) and the App is
/// private (`public = false`, "Only on this account"), per the spec's manifest.
#[must_use]
pub fn github_app_manifest(name: &str, url: &str, capabilities: &[Capability]) -> Value {
    let permissions: Map<String, Value> = render_github_permissions(capabilities)
        .into_iter()
        .map(|(key, level)| (key, Value::String(level)))
        .collect();

    let mut hook = Map::new();
    hook.insert("active".to_string(), Value::Bool(false));

    let mut manifest = Map::new();
    manifest.insert("name".to_string(), Value::String(name.to_string()));
    manifest.insert("url".to_string(), Value::String(url.to_string()));
    manifest.insert("public".to_string(), Value::Bool(false));
    manifest.insert("hook_attributes".to_string(), Value::Object(hook));
    manifest.insert("default_events".to_string(), Value::Array(Vec::new()));
    manifest.insert("default_permissions".to_string(), Value::Object(permissions));
    Value::Object(manifest)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn capability_tokens_parse() {
        assert_eq!(parse_capability("read-code"), Ok(Capability::ReadCode));
        assert_eq!(parse_capability("write-code"), Ok(Capability::WriteCode));
        assert_eq!(parse_capability("read-pr"), Ok(Capability::ReadPr));
        assert_eq!(parse_capability("write-pr"), Ok(Capability::WritePr));
    }

    #[test]
    fn an_unknown_capability_token_is_rejected_with_the_token() {
        assert_eq!(parse_capability("admin"), Err("admin".to_string()));
    }

    #[test]
    fn the_manifest_pins_the_webhook_off_and_keeps_the_app_private() {
        let manifest = github_app_manifest(
            "sandy-runner",
            "https://github.com/kauki-labs/sandy",
            &[Capability::WriteCode, Capability::WritePr],
        );
        assert_eq!(manifest["public"], json!(false));
        assert_eq!(manifest["hook_attributes"]["active"], json!(false));
        assert_eq!(manifest["default_events"], json!([]));
    }

    #[test]
    fn manifest_permissions_track_the_shared_renderer() {
        let manifest = github_app_manifest("n", "u", &[Capability::WriteCode, Capability::WritePr]);
        let permissions = &manifest["default_permissions"];
        assert_eq!(permissions["metadata"], json!("read"));
        assert_eq!(permissions["contents"], json!("write"));
        assert_eq!(permissions["pull_requests"], json!("write"));
    }

    #[test]
    fn a_read_only_request_renders_read_and_omits_unrequested_permissions() {
        let manifest = github_app_manifest("n", "u", &[Capability::ReadCode]);
        let permissions = &manifest["default_permissions"];
        assert_eq!(permissions["contents"], json!("read"));
        assert_eq!(permissions["metadata"], json!("read"));
        assert!(permissions.get("pull_requests").is_none());
    }
}
