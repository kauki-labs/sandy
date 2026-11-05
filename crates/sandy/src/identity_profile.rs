//! The identity profile registry (#592, epic #597): the operator's list of named identities an environment
//! request may pick. A profile holds names only, never a value: the trust root to mint from, the credential
//! [`Scope`], and the secret names the service may read. See `docs/design/credential-seam/identity-profiles.md`.

use std::collections::BTreeSet;

use sandy_api::cred::{Capability, Scope, Target};
use serde_json::Value;

/// The longest profile or trust root name. The same bound sandyd applies to a request's `profile` field.
const MAX_NAME: usize = 64;

/// The longest repository path.
const MAX_TARGET: usize = 256;

/// The keys of a profile entry.
const FIELDS: &[&str] = &["name", "credential", "targets", "capabilities", "service_secrets"];

/// Prefixes of well-known credential formats. A name must never be, or carry, a credential. Mirrors the list in
/// `crates/sandyd/src/environment.rs`, which checks a request's `profile`; one shared rule is a follow-up.
const SECRET_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "glptt-",
    "sk-",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "AKIA",
    "ASIA",
    "AIza",
    "npm_",
];

/// Why a registry or a profile lookup was refused. No variant carries a value read from the registry file:
/// the text is safe to log (INV-1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityProfileError {
    /// The registry is not valid JSON of the expected shape.
    #[error("the identity profile registry is malformed ({0})")]
    Malformed(String),
    /// A profile entry is refused; `at` is its position and, when it has a valid name, the name.
    #[error("identity profile {at}: {reason}")]
    Invalid {
        /// Where the entry sits in the file.
        at: String,
        /// What is wrong, without the offending value.
        reason: String,
    },
    /// Two entries share a name.
    #[error("identity profile {0:?} is defined twice")]
    Duplicate(String),
    /// A lookup named no profile in the registry.
    #[error("unknown identity profile {0:?}")]
    Unknown(String),
}

/// One named identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProfile {
    name: String,
    credential: String,
    scope: Scope,
    service_secrets: Vec<String>,
}

impl IdentityProfile {
    /// The profile's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The registered trust root to mint from.
    #[must_use]
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// The scope of the credential minted for this profile.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The secret names exported to the service process. Empty unless the profile lists some.
    #[must_use]
    pub fn service_secrets(&self) -> &[String] {
        &self.service_secrets
    }
}

/// The parsed registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityProfiles {
    profiles: Vec<IdentityProfile>,
}

impl IdentityProfiles {
    /// Parse the registry file's text.
    ///
    /// # Errors
    ///
    /// The first problem found, as an [`IdentityProfileError`].
    pub fn parse(text: &str) -> Result<Self, IdentityProfileError> {
        // Walk a `Value` by hand: serde's own messages repeat the offending value, and this text reaches logs.
        let value: Value = serde_json::from_str(text).map_err(|err| {
            let what = match err.classify() {
                serde_json::error::Category::Syntax => "syntax error",
                serde_json::error::Category::Eof => "unexpected end of input",
                serde_json::error::Category::Data => "unexpected data",
                serde_json::error::Category::Io => "read error",
            };
            IdentityProfileError::Malformed(format!("{what} at line {} column {}", err.line(), err.column()))
        })?;
        let Some(top) = value.as_object() else {
            return Err(IdentityProfileError::Malformed(
                "the top level must be an object".to_owned(),
            ));
        };
        if top.len() != 1 || !top.contains_key("profiles") {
            return Err(IdentityProfileError::Malformed(
                "the top level must hold only `profiles`".to_owned(),
            ));
        }
        let Some(entries) = top["profiles"].as_array() else {
            return Err(IdentityProfileError::Malformed(
                "`profiles` must be an array".to_owned(),
            ));
        };
        let mut seen = BTreeSet::new();
        let mut profiles = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let profile = parse_entry(index, entry)?;
            if !seen.insert(profile.name.clone()) {
                return Err(IdentityProfileError::Duplicate(profile.name));
            }
            profiles.push(profile);
        }
        Ok(Self { profiles })
    }

    /// The profile called `name`.
    ///
    /// # Errors
    ///
    /// [`IdentityProfileError::Unknown`] when the registry has no such profile.
    pub fn resolve(&self, name: &str) -> Result<&IdentityProfile, IdentityProfileError> {
        self.profiles
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| IdentityProfileError::Unknown(name.to_owned()))
    }
}

fn invalid(at: &str, reason: impl Into<String>) -> IdentityProfileError {
    IdentityProfileError::Invalid {
        at: at.to_owned(),
        reason: reason.into(),
    }
}

/// A name for a trust root or a profile: letters, digits, `-`, `_` and `.`.
fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn looks_like_secret(s: &str) -> bool {
    SECRET_PREFIXES
        .iter()
        .any(|p| s.starts_with(p) && s.len() >= p.len() + 8)
}

/// An environment variable name for a secret the service may read: upper case, digits and `_`.
fn secret_name_ok(s: &str) -> bool {
    let mut bytes = s.bytes();
    s.len() <= MAX_NAME
        && bytes.next().is_some_and(|b| b.is_ascii_uppercase())
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// A field name safe to show: short and name-shaped, so a pasted secret used as a key is not echoed.
fn field_label(key: &str) -> String {
    if key.len() <= 32 && name_ok(key) && !looks_like_secret(key) {
        format!("`{key}`")
    } else {
        "(name not shown)".to_owned()
    }
}

/// The strings of an array, or `None` when the value is not an array of strings.
fn strings(value: &Value) -> Option<Vec<&str>> {
    value.as_array()?.iter().map(Value::as_str).collect()
}

fn parse_entry(index: usize, entry: &Value) -> Result<IdentityProfile, IdentityProfileError> {
    let at = format!("#{index}");
    let Some(fields) = entry.as_object() else {
        return Err(invalid(&at, "an entry must be an object"));
    };
    for key in fields.keys() {
        if !FIELDS.contains(&key.as_str()) {
            return Err(invalid(&at, format!("unknown field {}", field_label(key))));
        }
    }
    let name = fields.get("name").and_then(Value::as_str).unwrap_or_default();
    if !name_ok(name) {
        return Err(invalid(
            &at,
            format!("name must be 1 to {MAX_NAME} letters, digits, '-', '_' or '.'"),
        ));
    }
    if looks_like_secret(name) {
        return Err(invalid(&at, "name must not look like a credential"));
    }
    let at = format!("#{index} ({name})");

    let credential = fields.get("credential").and_then(Value::as_str).unwrap_or_default();
    if !name_ok(credential) || looks_like_secret(credential) {
        return Err(invalid(
            &at,
            format!("credential must name a trust root: 1 to {MAX_NAME} letters, digits, '-', '_' or '.'"),
        ));
    }

    let targets = fields.get("targets").and_then(strings).unwrap_or_default();
    if targets.is_empty()
        || targets
            .iter()
            .any(|t| t.is_empty() || t.len() > MAX_TARGET || t.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        return Err(invalid(
            &at,
            "targets must be a non-empty list of repository paths without whitespace",
        ));
    }

    let capability_error = || {
        invalid(
            &at,
            "capabilities must be a non-empty list of read_code, write_code, read_pr, write_pr",
        )
    };
    let mut capabilities = Vec::new();
    for raw in fields.get("capabilities").and_then(strings).unwrap_or_default() {
        capabilities
            .push(serde_json::from_value::<Capability>(Value::String(raw.to_owned())).map_err(|_| capability_error())?);
    }
    if capabilities.is_empty() {
        return Err(capability_error());
    }
    capabilities.sort();
    capabilities.dedup();

    let mut service_secrets: Vec<String> = Vec::new();
    if let Some(raw) = fields.get("service_secrets") {
        let Some(names) = strings(raw) else {
            return Err(invalid(&at, "service_secrets must be a list of secret names"));
        };
        for secret in names {
            if !secret_name_ok(secret) {
                return Err(invalid(
                    &at,
                    format!("a service secret name must be upper case letters, digits and '_' (1 to {MAX_NAME})"),
                ));
            }
            if !service_secrets.iter().any(|s| s == secret) {
                service_secrets.push(secret.to_owned());
            }
        }
    }

    Ok(IdentityProfile {
        name: name.to_owned(),
        credential: credential.to_owned(),
        scope: Scope {
            targets: targets.into_iter().map(|t| Target(t.to_owned())).collect(),
            capabilities,
        },
        service_secrets,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_api::cred::{Capability, Target};

    use super::*;

    const VALID: &str = r#"{
        "profiles": [
            {
                "name": "dev",
                "credential": "github-main",
                "targets": ["owner/repo", "owner/other"],
                "capabilities": ["write_code", "read_code", "read_code"],
                "service_secrets": ["GITHUB_TOKEN", "ANTHROPIC_API_KEY"]
            },
            { "name": "readonly", "credential": "github-main", "targets": ["owner/repo"], "capabilities": ["read_code"] }
        ]
    }"#;

    /// A well-formed token-shaped value no error text may repeat.
    const SECRET: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

    fn refused(text: &str) -> anyhow::Result<IdentityProfileError> {
        IdentityProfiles::parse(text)
            .err()
            .context("the registry must be refused")
    }

    #[test]
    fn a_valid_registry_resolves_a_profile_to_its_scope_trust_root_and_service_secrets() -> anyhow::Result<()> {
        let profiles = IdentityProfiles::parse(VALID).context("parse")?;
        let dev = profiles.resolve("dev").context("resolve dev")?;
        assert_eq!(dev.name(), "dev");
        assert_eq!(dev.credential(), "github-main");
        assert_eq!(
            dev.scope().targets,
            vec![Target("owner/repo".to_owned()), Target("owner/other".to_owned())]
        );
        // Sorted and deduplicated, so the scope does not depend on the file's order.
        assert_eq!(
            dev.scope().capabilities,
            vec![Capability::ReadCode, Capability::WriteCode]
        );
        assert_eq!(dev.service_secrets(), ["GITHUB_TOKEN", "ANTHROPIC_API_KEY"]);
        Ok(())
    }

    #[test]
    fn service_secrets_default_to_none() -> anyhow::Result<()> {
        let profiles = IdentityProfiles::parse(VALID).context("parse")?;
        let readonly = profiles.resolve("readonly").context("resolve readonly")?;
        assert!(readonly.service_secrets().is_empty(), "{readonly:?}");
        Ok(())
    }

    #[test]
    fn an_unknown_profile_is_refused_without_listing_the_known_ones() -> anyhow::Result<()> {
        let profiles = IdentityProfiles::parse(VALID).context("parse")?;
        let err = profiles.resolve("prod").err().context("prod is not in the registry")?;
        assert_eq!(err, IdentityProfileError::Unknown("prod".to_owned()));
        let text = err.to_string();
        assert!(!text.contains("dev") && !text.contains("readonly"), "{text}");
        Ok(())
    }

    #[test]
    fn a_secret_in_the_registry_is_refused_and_never_echoed() -> anyhow::Result<()> {
        for key in ["token", "secret", "password", "anything_else"] {
            let text = format!(
                r#"{{"profiles":[{{"name":"dev","credential":"c","targets":["o/r"],"capabilities":["read_code"],"{key}":"{SECRET}"}}]}}"#
            );
            let err = refused(&text)?.to_string();
            assert!(!err.contains(SECRET), "{key}: {err}");
            assert!(err.contains("unknown field"), "{key}: {err}");
        }
        Ok(())
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_and_never_echoed() -> anyhow::Result<()> {
        let text = format!(
            r#"{{"profiles":[{{"name":"dev","credential":"c","targets":"{SECRET}","capabilities":["read_code"]}}]}}"#
        );
        let err = refused(&text)?.to_string();
        assert!(!err.contains(SECRET), "{err}");
        Ok(())
    }

    #[test]
    fn a_broken_entry_is_refused() {
        let entry = |fields: &str| format!(r#"{{"profiles":[{{"name":"dev",{fields}}}]}}"#);
        let cases = [
            (
                "empty targets",
                entry(r#""credential":"c","targets":[],"capabilities":["read_code"]"#),
            ),
            (
                "empty capabilities",
                entry(r#""credential":"c","targets":["o/r"],"capabilities":[]"#),
            ),
            (
                "unknown capability",
                entry(r#""credential":"c","targets":["o/r"],"capabilities":["root"]"#),
            ),
            (
                "blank target",
                entry(r#""credential":"c","targets":["o r"],"capabilities":["read_code"]"#),
            ),
            (
                "empty credential",
                entry(r#""credential":"","targets":["o/r"],"capabilities":["read_code"]"#),
            ),
            (
                "missing credential",
                entry(r#""targets":["o/r"],"capabilities":["read_code"]"#),
            ),
            (
                "lowercase secret name",
                entry(
                    r#""credential":"c","targets":["o/r"],"capabilities":["read_code"],"service_secrets":["github_token"]"#,
                ),
            ),
            (
                "secret name with a dash",
                entry(r#""credential":"c","targets":["o/r"],"capabilities":["read_code"],"service_secrets":["A-B"]"#),
            ),
        ];
        for (what, text) in cases {
            assert!(IdentityProfiles::parse(&text).is_err(), "{what} must be refused");
        }
    }

    #[test]
    fn a_duplicate_profile_name_is_refused() -> anyhow::Result<()> {
        let one = r#"{"name":"dev","credential":"c","targets":["o/r"],"capabilities":["read_code"]}"#;
        let err = refused(&format!(r#"{{"profiles":[{one},{one}]}}"#))?;
        assert_eq!(err, IdentityProfileError::Duplicate("dev".to_owned()));
        Ok(())
    }

    #[test]
    fn a_profile_name_that_looks_like_a_credential_is_refused_and_never_echoed() -> anyhow::Result<()> {
        let text = format!(
            r#"{{"profiles":[{{"name":"{SECRET}","credential":"c","targets":["o/r"],"capabilities":["read_code"]}}]}}"#
        );
        let err = refused(&text)?.to_string();
        assert!(!err.contains(SECRET), "{err}");
        Ok(())
    }

    #[test]
    fn a_malformed_file_is_refused_without_echoing_it() {
        for text in [
            String::new(),
            "not json".to_owned(),
            format!(r#"{{"profiles": [{{"name": "{SECRET}"#),
            format!(r#"{{"profiles": "{SECRET}"}}"#),
            format!(r#"{{"profiles": [], "{SECRET}": 1}}"#),
        ] {
            let err = IdentityProfiles::parse(&text);
            let message = match err {
                Ok(profiles) => panic!("{text:?} parsed as {profiles:?}"),
                Err(e) => e.to_string(),
            };
            assert!(!message.contains(SECRET), "{message}");
        }
    }

    #[test]
    fn an_empty_registry_is_valid_and_resolves_nothing() -> anyhow::Result<()> {
        let profiles = IdentityProfiles::parse(r#"{"profiles":[]}"#).context("parse")?;
        assert!(profiles.resolve("dev").is_err());
        Ok(())
    }
}
