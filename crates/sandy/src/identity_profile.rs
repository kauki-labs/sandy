//! The identity profile registry (#592, epic #597): the operator's list of named identities an environment
//! request may pick. A profile holds names only, never a value: the trust root to mint from, the credential
//! [`Scope`], and the secret names the service may read. See `docs/design/credential-seam/identity-profiles.md`.

use sandy_api::cred::Scope;

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
    pub fn parse(_text: &str) -> Result<Self, IdentityProfileError> {
        Ok(Self::default())
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
