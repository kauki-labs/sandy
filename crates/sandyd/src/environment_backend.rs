//! Choosing the environment backend from the daemon's environment (#587).
//!
//! The launch driver runs only when a backend is configured. Today the one
//! backend is the process backend, which has NO isolation, so it is opt-in
//! under a name that says so: `SANDY_ENV_BACKEND=process-insecure`. An unknown
//! value is an error, never a silent "off", so a typo cannot hide a
//! misconfiguration.
//!
//! | variable | meaning |
//! | --- | --- |
//! | `SANDY_ENV_BACKEND` | unset or empty: no driver. `process-insecure`: host processes. |
//! | `SANDY_ENV_PROCESS_COMMAND` | the service argv, split on whitespace; must contain `{port}`; `{base_dir}` and `{environment_id}` also expand |
//! | `SANDY_ENV_PAIR_COMMAND` | optional argv run once after the service answers; stdout goes to `<base_dir>/pairing` (0600) |
//! | `SANDY_ENV_STATE_DIR` | where environment directories live; default `<runtime dir>/environments` |
//! | `SANDY_ENV_PASS_ENV` | comma-separated names of daemon variables passed to the service |
//! | `SANDY_ENV_PATH` | the service's `PATH`; default the daemon's |
//! | `SANDY_ENV_IDLE_TIMEOUT_SECS` | stop a Ready environment with no owner-visible use or service connection for this long; default off |
//! | `SANDY_ENV_PROVISION_TIMEOUT_SECS` | seconds before a probe that is not Ready fails the environment; default 120 |

use std::{path::PathBuf, time::Duration};

use sandy_environment::ProcessConfig;

use crate::environment_driver::DriverConfig;

/// The one backend name accepted today.
pub const PROCESS_INSECURE: &str = "process-insecure";

/// How often the driver converges.
pub const DRIVER_INTERVAL: Duration = Duration::from_secs(1);

/// A selected backend and the driver settings that go with it.
#[derive(Debug, Clone)]
pub struct EnvironmentBackendConfig {
    /// How to run the process backend.
    pub process: ProcessConfig,
    /// The launch driver's settings.
    pub driver: DriverConfig,
}

/// Why the backend settings are unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvironmentBackendConfigError {
    /// `SANDY_ENV_BACKEND` names no known backend.
    #[error("SANDY_ENV_BACKEND={0:?} is not a known backend (expected `{PROCESS_INSECURE}`)")]
    UnknownBackend(String),
    /// A required variable is unset or blank.
    #[error("{0} is required when SANDY_ENV_BACKEND={PROCESS_INSECURE}")]
    Missing(&'static str),
    /// The service command has no `{port}`, so the service could never be reached.
    #[error("SANDY_ENV_PROCESS_COMMAND must contain {{port}}")]
    MissingPort,
    /// A number could not be parsed or was zero.
    #[error("{name}={raw:?} is not a positive whole number")]
    InvalidNumber {
        /// The variable.
        name: &'static str,
        /// What it held.
        raw: String,
    },
    /// A passed-through variable name is not `[A-Z0-9_]+`.
    #[error("SANDY_ENV_PASS_ENV name {0:?} is not an upper-case variable name")]
    InvalidName(String),
    /// A passed-through variable name is one the backend sets itself.
    #[error("SANDY_ENV_PASS_ENV name {0:?} is set by the backend and cannot be passed through")]
    ReservedName(String),
    /// The default state dir could not be prepared.
    #[error("state dir: {0}")]
    StateDir(String),
}

/// Reads the backend settings through `get`. `default_state_dir` is called only
/// when a backend is on and `SANDY_ENV_STATE_DIR` is unset.
///
/// # Errors
/// [`EnvironmentBackendConfigError`] for an unknown backend or an unusable setting.
pub fn from_env(
    get: impl Fn(&str) -> Option<String>,
    default_state_dir: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<Option<EnvironmentBackendConfig>, EnvironmentBackendConfigError> {
    use EnvironmentBackendConfigError as E;
    let Some(backend) = get("SANDY_ENV_BACKEND").filter(|v| !v.trim().is_empty()) else {
        return Ok(None);
    };
    if backend != PROCESS_INSECURE {
        return Err(E::UnknownBackend(backend));
    }
    let argv = |name: &'static str| -> Vec<String> {
        get(name)
            .map(|raw| raw.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    };
    let command = argv("SANDY_ENV_PROCESS_COMMAND");
    if command.is_empty() {
        return Err(E::Missing("SANDY_ENV_PROCESS_COMMAND"));
    }
    if !command.iter().any(|a| a.contains("{port}")) {
        return Err(E::MissingPort);
    }
    let pair_command = Some(argv("SANDY_ENV_PAIR_COMMAND")).filter(|a| !a.is_empty());
    let mut pass_env = Vec::new();
    for name in get("SANDY_ENV_PASS_ENV").unwrap_or_default().split(',').map(str::trim) {
        if name.is_empty() {
            continue;
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(E::InvalidName(name.to_owned()));
        }
        if ["HOME", "PATH", "TMPDIR", "LANG"].contains(&name) {
            return Err(E::ReservedName(name.to_owned()));
        }
        pass_env.push(name.to_owned());
    }
    let provision_timeout = match get("SANDY_ENV_PROVISION_TIMEOUT_SECS") {
        None => Duration::from_secs(120),
        Some(raw) => match raw.parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => {
                return Err(E::InvalidNumber {
                    name: "SANDY_ENV_PROVISION_TIMEOUT_SECS",
                    raw,
                });
            }
        },
    };
    let idle_timeout = match get("SANDY_ENV_IDLE_TIMEOUT_SECS").filter(|v| !v.trim().is_empty()) {
        None => None,
        Some(raw) => match raw.parse::<u64>() {
            Ok(secs) if secs > 0 => Some(Duration::from_secs(secs)),
            _ => {
                return Err(E::InvalidNumber {
                    name: "SANDY_ENV_IDLE_TIMEOUT_SECS",
                    raw,
                });
            }
        },
    };
    let state_dir = match get("SANDY_ENV_STATE_DIR").filter(|v| !v.trim().is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => default_state_dir().map_err(E::StateDir)?,
    };
    let path = get("SANDY_ENV_PATH")
        .filter(|v| !v.trim().is_empty())
        .or_else(|| get("PATH"))
        .unwrap_or_else(|| "/usr/bin:/bin".to_owned());
    Ok(Some(EnvironmentBackendConfig {
        process: ProcessConfig {
            command,
            pair_command,
            state_dir,
            path,
            pass_env,
            pair_timeout: Duration::from_secs(30),
        },
        driver: DriverConfig {
            template: "process".to_owned(),
            service_port: None,
            provision_timeout,
            idle_timeout,
        },
    }))
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::HashMap};

    use super::*;

    fn getter(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        move |k| map.get(k).cloned()
    }

    fn base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("SANDY_ENV_BACKEND", "process-insecure"),
            (
                "SANDY_ENV_PROCESS_COMMAND",
                "t3 serve --port {port} --base-dir {base_dir}",
            ),
        ]
    }

    fn parse(pairs: &[(&str, &str)]) -> Result<Option<EnvironmentBackendConfig>, EnvironmentBackendConfigError> {
        from_env(getter(pairs), || Ok(PathBuf::from("/run/sandyd/environments")))
    }

    #[test]
    fn no_backend_variable_means_no_driver_and_never_asks_for_a_state_dir() {
        let asked = Cell::new(false);
        for pairs in [
            vec![],
            vec![("SANDY_ENV_BACKEND", "")],
            vec![("SANDY_ENV_BACKEND", "  ")],
        ] {
            let out = from_env(getter(&pairs), || {
                asked.set(true);
                Ok(PathBuf::new())
            });
            assert!(matches!(out, Ok(None)), "{pairs:?}");
        }
        assert!(!asked.get());
    }

    #[test]
    fn an_unknown_backend_is_an_error_not_a_silent_off() {
        for name in ["process", "vm", "PROCESS-INSECURE", "process-insecure "] {
            let out = parse(&[("SANDY_ENV_BACKEND", name), ("SANDY_ENV_PROCESS_COMMAND", "x {port}")]);
            assert!(
                matches!(out, Err(EnvironmentBackendConfigError::UnknownBackend(ref n)) if n == name.trim() || n == name),
                "{name:?}: {out:?}"
            );
        }
    }

    #[test]
    fn the_process_backend_needs_a_command_with_a_port() {
        assert_eq!(
            parse(&[("SANDY_ENV_BACKEND", "process-insecure")]).err(),
            Some(EnvironmentBackendConfigError::Missing("SANDY_ENV_PROCESS_COMMAND"))
        );
        for blank in ["", "   "] {
            let out = parse(&[
                ("SANDY_ENV_BACKEND", "process-insecure"),
                ("SANDY_ENV_PROCESS_COMMAND", blank),
            ]);
            assert_eq!(
                out.err(),
                Some(EnvironmentBackendConfigError::Missing("SANDY_ENV_PROCESS_COMMAND"))
            );
        }
        let no_port = parse(&[
            ("SANDY_ENV_BACKEND", "process-insecure"),
            ("SANDY_ENV_PROCESS_COMMAND", "t3 serve --base-dir {base_dir}"),
        ]);
        assert_eq!(no_port.err(), Some(EnvironmentBackendConfigError::MissingPort));
    }

    #[test]
    fn a_full_configuration_is_read_with_commands_split_on_whitespace() -> anyhow::Result<()> {
        let mut pairs = base();
        pairs.extend([
            (
                "SANDY_ENV_PROCESS_COMMAND",
                "  t3   serve --port {port}  --base-dir {base_dir} ",
            ),
            ("SANDY_ENV_PAIR_COMMAND", "t3 pair  --base-dir {base_dir}"),
            ("SANDY_ENV_STATE_DIR", "/var/lib/sandy/envs"),
            ("SANDY_ENV_PASS_ENV", "ANTHROPIC_API_KEY, OPENAI_API_KEY ,"),
            ("SANDY_ENV_PATH", "/opt/t3/bin:/usr/bin"),
            ("SANDY_ENV_PROVISION_TIMEOUT_SECS", "300"),
            ("SANDY_ENV_IDLE_TIMEOUT_SECS", "900"),
        ]);
        // The last entry for a key wins in the map.
        let cfg = parse(&pairs)?.ok_or_else(|| anyhow::anyhow!("expected a backend"))?;
        assert_eq!(
            cfg.process.command,
            ["t3", "serve", "--port", "{port}", "--base-dir", "{base_dir}"]
        );
        assert_eq!(
            cfg.process.pair_command.as_deref(),
            Some(&["t3", "pair", "--base-dir", "{base_dir}"].map(String::from)[..])
        );
        assert_eq!(cfg.process.state_dir, PathBuf::from("/var/lib/sandy/envs"));
        assert_eq!(cfg.process.pass_env, ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]);
        assert_eq!(cfg.process.path, "/opt/t3/bin:/usr/bin");
        assert_eq!(cfg.driver.provision_timeout, Duration::from_secs(300));
        assert_eq!(cfg.driver.idle_timeout, Some(Duration::from_secs(900)));
        Ok(())
    }

    #[test]
    fn defaults_come_from_the_runtime_dir_the_path_and_two_minutes() -> anyhow::Result<()> {
        let cfg = parse(&base())?.ok_or_else(|| anyhow::anyhow!("expected a backend"))?;
        assert_eq!(cfg.process.state_dir, PathBuf::from("/run/sandyd/environments"));
        assert_eq!(cfg.process.pair_command, None);
        assert!(cfg.process.pass_env.is_empty());
        assert_eq!(cfg.driver.provision_timeout, Duration::from_secs(120));
        assert_eq!(cfg.driver.idle_timeout, None, "idle stop is off by default");
        assert_eq!(cfg.driver.service_port, None);
        let with_path = parse(&[base(), vec![("PATH", "/usr/local/bin:/usr/bin")]].concat())?
            .ok_or_else(|| anyhow::anyhow!("expected a backend"))?;
        assert_eq!(with_path.process.path, "/usr/local/bin:/usr/bin");
        Ok(())
    }

    #[test]
    fn the_default_state_dir_is_not_asked_for_when_one_is_given() -> anyhow::Result<()> {
        let asked = Cell::new(false);
        let mut pairs = base();
        pairs.push(("SANDY_ENV_STATE_DIR", "/x"));
        from_env(getter(&pairs), || {
            asked.set(true);
            Ok(PathBuf::new())
        })?;
        assert!(!asked.get());
        Ok(())
    }

    #[test]
    fn a_failing_default_state_dir_is_a_state_dir_error() {
        let out = from_env(getter(&base()), || Err("no runtime dir".to_owned()));
        assert_eq!(
            out.err(),
            Some(EnvironmentBackendConfigError::StateDir("no runtime dir".to_owned()))
        );
    }

    #[test]
    fn a_zero_or_non_numeric_idle_timeout_is_refused() {
        for raw in ["0", "-5", "abc", "1.5"] {
            let mut pairs = base();
            pairs.push(("SANDY_ENV_IDLE_TIMEOUT_SECS", raw));
            let out = parse(&pairs);
            assert!(
                matches!(
                    out,
                    Err(EnvironmentBackendConfigError::InvalidNumber {
                        name: "SANDY_ENV_IDLE_TIMEOUT_SECS",
                        ..
                    })
                ),
                "{raw:?}: {out:?}"
            );
        }
    }

    #[test]
    fn a_zero_or_non_numeric_timeout_is_refused() {
        for raw in ["0", "-5", "abc", "1.5", ""] {
            let mut pairs = base();
            pairs.push(("SANDY_ENV_PROVISION_TIMEOUT_SECS", raw));
            let out = parse(&pairs);
            assert!(
                matches!(
                    out,
                    Err(EnvironmentBackendConfigError::InvalidNumber {
                        name: "SANDY_ENV_PROVISION_TIMEOUT_SECS",
                        ..
                    })
                ),
                "{raw:?}: {out:?}"
            );
        }
    }

    #[test]
    fn a_passed_variable_cannot_override_one_the_backend_sets() {
        for bad in ["HOME", "PATH", "TMPDIR", "LANG"] {
            let mut pairs = base();
            pairs.push(("SANDY_ENV_PASS_ENV", bad));
            let out = parse(&pairs);
            assert!(
                matches!(out, Err(EnvironmentBackendConfigError::ReservedName(_))),
                "{bad:?}: {out:?}"
            );
        }
    }

    #[test]
    fn a_passed_variable_name_must_be_an_upper_case_variable_name() {
        for bad in ["lower", "A-B", "A B", "A=B", "1;rm"] {
            let mut pairs = base();
            pairs.push(("SANDY_ENV_PASS_ENV", bad));
            let out = parse(&pairs);
            assert!(
                matches!(out, Err(EnvironmentBackendConfigError::InvalidName(_))),
                "{bad:?}: {out:?}"
            );
        }
    }
}
