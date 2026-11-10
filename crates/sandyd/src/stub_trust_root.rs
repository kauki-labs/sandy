//! A stub forge trust root for the live broker gate (#733, #727).
//!
//! Since #706 every vm environment mints a forge token from a registered trust root before it boots, and the only
//! provider is the real GitHub adapter. A host with no real App key cannot run a live scenario with a credential.
//! This module lets a test daemon register a trust root whose provider mints a recognisable fake token, never opens
//! a socket, and writes its calls to a log file so a live test can assert the bracket ran.
//!
//! It must not be selectable in a production binary, so there are two locks. The provider exists only when sandyd is
//! built with the `stub-trust-root` cargo feature, which is off by default and not enabled in the release build. And
//! the daemon uses it only when the operator sets [`STUB_ENV`]: with the variable set and the feature off, the daemon
//! refuses to start with a named error ([`StubError::FeatureOff`]), so a test configuration never silently runs
//! against the real adapter, and a stray variable never silently enables nothing.

/// The variable that names the stub trust root. Set only by a test harness.
pub const STUB_ENV: &str = "SANDYD_STUB_TRUST_ROOT";

/// Where the stub appends one line per `mint`, `refresh` and `revoke`, if set. Never holds a token.
pub const STUB_LOG_ENV: &str = "SANDYD_STUB_CALL_LOG";

use std::{path::PathBuf, sync::Arc};

use crate::credential::{CredentialResolver, TrustRootResolver};

/// What a test daemon's stub trust root is configured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubConfig {
    /// The trust root name the stub answers to, a valid trust root name.
    pub name: String,
    /// Where the stub appends its call log, if anywhere.
    pub call_log: Option<PathBuf>,
}

/// Why the stub configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StubError {
    /// [`STUB_ENV`] is set in a build without the `stub-trust-root` feature.
    #[error(
        "{STUB_ENV} is set, but this sandyd was built without the stub-trust-root cargo feature: refusing to start \
         rather than run a test configuration against the real forge adapter"
    )]
    FeatureOff,
    /// [`STUB_ENV`] holds a value that is not a valid trust root name.
    #[error("{STUB_ENV} is not a valid trust root name: {0}")]
    BadName(String),
}

/// Read the stub configuration through `get`. `Ok(None)` when [`STUB_ENV`] is unset. With it set and the
/// `stub-trust-root` feature off, [`StubError::FeatureOff`]: the check comes first, so a build without the feature
/// can never reach the stub whatever the value is.
///
/// # Errors
/// [`StubError`] as above, or [`StubError::BadName`] for a value that is not a valid trust root name.
pub fn stub_config_from(get: impl Fn(&str) -> Option<String>) -> Result<Option<StubConfig>, StubError> {
    let Some(name) = get(STUB_ENV) else {
        return Ok(None);
    };
    if !cfg!(feature = "stub-trust-root") {
        return Err(StubError::FeatureOff);
    }
    sandy::validate_trust_root_name(&name).map_err(|e| StubError::BadName(e.to_string()))?;
    Ok(Some(StubConfig {
        name,
        call_log: get(STUB_LOG_ENV).filter(|p| !p.is_empty()).map(PathBuf::from),
    }))
}

/// The resolver the daemon mints from: the real trust roots, or, in a test daemon that names the stub, the stub
/// for that one name and the real resolver for every other.
///
/// # Errors
/// [`StubError`] from [`stub_config_from`]: the daemon must not start.
pub fn credential_resolver() -> Result<Arc<dyn CredentialResolver>, StubError> {
    let config = stub_config_from(|key| std::env::var(key).ok())?;
    let real: Arc<dyn CredentialResolver> = Arc::new(TrustRootResolver);
    #[cfg(feature = "stub-trust-root")]
    if let Some(config) = config {
        tracing::warn!(
            trust_root = %config.name,
            "a STUB trust root is active (test configuration): this daemon mints fake tokens and must not serve users"
        );
        return Ok(Arc::new(StubResolver::new(config, real)));
    }
    #[cfg(not(feature = "stub-trust-root"))]
    // Without the feature `stub_config_from` has already refused a set variable, so there is nothing to select.
    let _ = config;
    Ok(real)
}

/// What every stub token starts with, so a leak is recognisable.
#[cfg(feature = "stub-trust-root")]
pub const STUB_TOKEN_PREFIX: &str = "stub-token-";

#[cfg(feature = "stub-trust-root")]
pub use provider::{StubProvider, StubResolver};

#[cfg(feature = "stub-trust-root")]
mod provider {
    use std::{
        io::Write as _,
        os::unix::fs::OpenOptionsExt as _,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, SystemTime},
    };

    use sandy::{CredError, CredentialHandle, CredentialProvider, Lease, Minted, Scope, SharedProvider};

    use super::{STUB_TOKEN_PREFIX, StubConfig};
    use crate::credential::CredentialResolver;

    /// A provider that mints a fake token and calls no network: no socket is ever opened here.
    pub struct StubProvider {
        next: AtomicU64,
        call_log: Option<PathBuf>,
    }

    impl StubProvider {
        /// A provider that appends to `call_log` when set.
        #[must_use]
        pub fn new(call_log: Option<PathBuf>) -> Self {
            Self {
                next: AtomicU64::new(0),
                call_log,
            }
        }

        /// One log line per call, never a token. A log that cannot be written fails the call, so a test that asserts on
        /// the log cannot pass because it silently stayed empty.
        fn log(&self, line: &str) -> std::io::Result<()> {
            let Some(path) = &self.call_log else { return Ok(()) };
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?;
            writeln!(file, "{line}")
        }

        /// A fresh fake token and handle. Logs nothing: the caller logs the call it serves.
        fn issue(&self) -> Result<Minted, CredError> {
            let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|e| CredError::Mint(format!("random bytes: {e}")))?;
            let token = format!("{STUB_TOKEN_PREFIX}{n}-{}", hex::encode(random));
            let handle = CredentialHandle {
                id: format!("stub-{n}"),
            };
            Ok(Minted::new(
                token,
                SystemTime::now() + Duration::from_secs(3000),
                handle,
            ))
        }
    }

    impl CredentialProvider for StubProvider {
        fn mint(&self, _scope: &Scope, _ttl_hint: Duration) -> Result<Minted, CredError> {
            let minted = self.issue()?;
            self.log(&format!("mint {}", minted.handle.id))
                .map_err(|e| CredError::Mint(format!("the stub call log cannot be written: {e}")))?;
            Ok(minted)
        }

        fn revoke(&self, lease: &Lease) -> Result<(), CredError> {
            self.log(&format!("revoke {}", lease.handle.id))
                .map_err(|e| CredError::Revoke(format!("the stub call log cannot be written: {e}")))
        }

        /// Logs the lease it replaces; the new handle shows when it is revoked.
        fn refresh(&self, lease: &Lease) -> Result<Minted, CredError> {
            let renewed = self.issue()?;
            self.log(&format!("refresh {}", lease.handle.id))
                .map_err(|e| CredError::Mint(format!("the stub call log cannot be written: {e}")))?;
            Ok(renewed)
        }
    }

    /// Answers to the stub's one name and hands every other name to the real resolver.
    pub struct StubResolver {
        config: StubConfig,
        provider: Arc<StubProvider>,
        real: Arc<dyn CredentialResolver>,
    }

    impl StubResolver {
        /// A resolver for `config`'s trust root name, with `real` for any other.
        #[must_use]
        pub fn new(config: StubConfig, real: Arc<dyn CredentialResolver>) -> Self {
            let provider = Arc::new(StubProvider::new(config.call_log.clone()));
            Self { config, provider, real }
        }
    }

    impl CredentialResolver for StubResolver {
        fn resolve(&self, name: &str, capabilities: &[String]) -> Result<(SharedProvider, Scope), String> {
            if name == self.config.name {
                return Err(format!(
                    "{name:?} is the stub trust root, which serves environment profiles only; a job's credential \
                     needs a registered trust root"
                ));
            }
            self.real.resolve(name, capabilities)
        }

        fn provider(&self, name: &str) -> Result<SharedProvider, String> {
            if name == self.config.name {
                return Ok(Arc::clone(&self.provider) as SharedProvider);
            }
            self.real.provider(name)
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "stub-trust-root")]
    use std::path::PathBuf;

    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| (*v).to_owned())
    }

    #[test]
    fn an_unset_variable_selects_no_stub() {
        assert_eq!(stub_config_from(env(&[])), Ok(None));
    }

    /// The feature is off in this build: naming the stub is a startup error that says what to do, never a silent no-op.
    #[cfg(not(feature = "stub-trust-root"))]
    #[test]
    fn naming_the_stub_without_the_feature_is_refused_by_name() {
        let err = stub_config_from(env(&[(STUB_ENV, "live")])).expect_err("must refuse");
        assert_eq!(err, StubError::FeatureOff);
        let text = err.to_string();
        assert!(text.contains(STUB_ENV), "{text}");
        assert!(text.contains("stub-trust-root"), "{text}");
    }

    #[cfg(feature = "stub-trust-root")]
    #[test]
    fn naming_the_stub_with_the_feature_selects_it() {
        let config = stub_config_from(env(&[(STUB_ENV, "live"), (STUB_LOG_ENV, "/tmp/stub.log")]))
            .expect("valid")
            .expect("selected");
        assert_eq!(config.name, "live");
        assert_eq!(config.call_log, Some(PathBuf::from("/tmp/stub.log")));
    }

    #[cfg(feature = "stub-trust-root")]
    #[test]
    fn the_stub_name_must_be_a_valid_trust_root_name() {
        for bad in ["", "../x", "a/b", ".", ".."] {
            let err = stub_config_from(env(&[(STUB_ENV, bad)])).expect_err(bad);
            assert!(matches!(err, StubError::BadName(_)), "{bad:?}: {err}");
        }
    }

    #[cfg(feature = "stub-trust-root")]
    mod provider {
        use std::{path::PathBuf, time::Duration};

        use sandy::{CredentialProvider, Scope};

        use super::super::*;

        fn scope() -> Scope {
            Scope {
                targets: Vec::new(),
                capabilities: Vec::new(),
            }
        }

        fn lease_of(minted: &sandy::Minted) -> sandy::Lease {
            sandy::Lease {
                secret_ref: sandy_api::backend::SecretRef {
                    name: "GITHUB_TOKEN".to_owned(),
                    source: sandy_api::backend::SecretSource::File(std::path::PathBuf::new()),
                },
                expires_at: minted.expires_at,
                handle: minted.handle.clone(),
            }
        }

        fn log_path() -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("calls.log");
            (dir, path)
        }

        #[test]
        fn each_mint_is_a_recognisable_unique_fake_token_and_is_logged_without_the_token() {
            let (_dir, path) = log_path();
            let provider = StubProvider::new(Some(path.clone()));
            let first = provider.mint(&scope(), Duration::from_secs(60)).expect("mint");
            let second = provider.mint(&scope(), Duration::from_secs(60)).expect("mint");
            let token = first.secret().to_owned();
            assert!(token.starts_with(STUB_TOKEN_PREFIX), "{token}");
            assert_ne!(token, second.secret(), "tokens are unique");
            assert_ne!(first.handle.id, second.handle.id, "handles are unique");
            let log = std::fs::read_to_string(&path).expect("log");
            assert_eq!(log.lines().count(), 2, "{log}");
            assert!(log.lines().all(|l| l.starts_with("mint stub-")), "{log}");
            assert!(!log.contains(STUB_TOKEN_PREFIX), "the log never holds a token: {log}");
        }

        #[test]
        fn revoke_and_refresh_are_logged_by_handle() {
            let (_dir, path) = log_path();
            let provider = StubProvider::new(Some(path.clone()));
            let minted = provider.mint(&scope(), Duration::from_secs(60)).expect("mint");
            let lease = lease_of(&minted);
            let renewed = provider.refresh(&lease).expect("refresh");
            provider.revoke(&lease).expect("revoke");
            let log = std::fs::read_to_string(&path).expect("log");
            let lines: Vec<&str> = log.lines().collect();
            assert_eq!(lines.len(), 3, "{log}");
            assert_eq!(lines[1], format!("refresh {}", lease.handle.id));
            assert_eq!(lines[2], format!("revoke {}", lease.handle.id));
            assert_ne!(renewed.handle.id, lease.handle.id);
        }

        /// A test that asserts on the log must not pass because the log silently failed.
        #[test]
        fn a_call_log_that_cannot_be_written_fails_the_call() {
            let provider = StubProvider::new(Some(PathBuf::from("/nonexistent-dir-733/calls.log")));
            let err = provider
                .mint(&scope(), Duration::from_secs(60))
                .expect_err("must fail, not pass silently");
            assert!(err.to_string().contains("call log"), "{err}");
        }

        #[test]
        fn the_call_log_is_private() {
            use std::os::unix::fs::PermissionsExt as _;
            let (_dir, path) = log_path();
            StubProvider::new(Some(path.clone()))
                .mint(&scope(), Duration::from_secs(60))
                .expect("mint");
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o077, 0, "mode {mode:o}");
        }
    }

    #[cfg(feature = "stub-trust-root")]
    mod resolver {
        use super::super::*;
        use crate::credential::CredentialResolver;

        struct Inner;

        impl CredentialResolver for Inner {
            fn resolve(&self, name: &str, _: &[String]) -> Result<(sandy::SharedProvider, sandy::Scope), String> {
                Err(format!("inner resolve {name}"))
            }

            fn provider(&self, name: &str) -> Result<sandy::SharedProvider, String> {
                Err(format!("inner provider {name}"))
            }
        }

        fn resolver() -> StubResolver {
            StubResolver::new(
                StubConfig {
                    name: "live".to_owned(),
                    call_log: None,
                },
                std::sync::Arc::new(Inner),
            )
        }

        #[test]
        fn the_stub_name_resolves_to_the_stub_provider_and_never_reaches_the_real_resolver() {
            assert!(resolver().provider("live").is_ok());
        }

        #[test]
        fn any_other_name_goes_to_the_real_resolver() {
            let err = resolver().provider("github-main").err().expect("delegated");
            assert_eq!(err, "inner provider github-main");
        }

        /// The stub serves environment profiles only; a job's `credential` keeps the real resolution.
        #[test]
        fn a_job_credential_naming_the_stub_is_refused_by_name() {
            let err = resolver().resolve("live", &[]).err().expect("refused");
            assert!(err.contains("stub trust root") && err.contains("environment"), "{err}");
        }
    }

    /// The acceptance the live gate relies on, through the real credential component: the stub's token is staged once
    /// at the guest secret path, the call log records the mint and then the revoke, the log never holds the token,
    /// and revoking removes the file.
    #[cfg(feature = "stub-trust-root")]
    #[test]
    fn the_credential_component_stages_the_stub_token_logs_the_bracket_and_revokes_it() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        use crate::{credential::CREDENTIAL_SECRET_NAME, environment_credential::EnvironmentCredentials};

        struct NoRealRoots;
        impl CredentialResolver for NoRealRoots {
            fn resolve(&self, _: &str, _: &[String]) -> Result<(sandy::SharedProvider, sandy::Scope), String> {
                Err("no real trust roots in this test".to_owned())
            }

            fn provider(&self, _: &str) -> Result<sandy::SharedProvider, String> {
                Err("no real trust roots in this test".to_owned())
            }
        }

        let tmp = tempfile::tempdir()?;
        let base = tmp.path().join("staging");
        std::fs::create_dir(&base)?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
        let log = tmp.path().join("calls.log");
        let resolver = StubResolver::new(
            StubConfig {
                name: "live".to_owned(),
                call_log: Some(log.clone()),
            },
            Arc::new(NoRealRoots),
        );
        let creds = EnvironmentCredentials::new(Arc::new(resolver), base);

        let share = creds
            .ensure("env-1", "live", &sandy::Scope::default())
            .map_err(anyhow::Error::msg)?;
        let staged = share.dir.join(CREDENTIAL_SECRET_NAME);
        let token = std::fs::read_to_string(&staged)?;
        assert!(token.trim().starts_with(STUB_TOKEN_PREFIX), "{token}");
        let calls = std::fs::read_to_string(&log)?;
        assert_eq!(calls, "mint stub-1\n");
        assert!(!calls.contains(token.trim()), "the log never holds the token");

        creds.release("env-1").map_err(anyhow::Error::msg)?;
        assert_eq!(std::fs::read_to_string(&log)?, "mint stub-1\nrevoke stub-1\n");
        assert!(!staged.exists(), "revoking removes the staged token");
        Ok(())
    }
}
