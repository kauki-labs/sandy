//! Choosing the environment backend from the daemon's environment (#587).
//!
//! The launch driver runs only when a backend is configured. The process backend has NO isolation, so it is
//! opt-in under a name that says so: `SANDY_ENV_BACKEND=process-insecure`. `vm-qemu` runs each environment as a
//! qemu microVM (Linux only) and `vm-vfkit` as a vfkit microVM (macOS only); another platform is an error. An unknown
//! value is an error, never a silent "off", so a typo cannot hide a misconfiguration.
//!
//! | variable | meaning |
//! | --- | --- |
//! | `SANDY_ENV_BACKEND` | unset or empty: no driver. `process-insecure`: host processes. `vm-qemu`: qemu microVMs (Linux). `vm-vfkit`: vfkit microVMs (macOS). |
//! | `SANDY_ENV_PROCESS_COMMAND` | the service argv, split on whitespace; must contain `{port}`; `{base_dir}` and `{environment_id}` also expand |
//! | `SANDY_ENV_PAIR_COMMAND` | optional argv run once after the service answers; stdout goes to `<base_dir>/pairing` (0600) |
//! | `SANDY_ENV_STATE_DIR` | where environment directories live; default `<runtime dir>/environments` |
//! | `SANDY_ENV_PASS_ENV` | comma-separated names of daemon variables passed to the service |
//! | `SANDY_ENV_PATH` | the service's `PATH`; default the daemon's |
//! | `SANDY_ENV_IDLE_TIMEOUT_SECS` | stop a Ready environment with no owner-visible use or service connection for this long; default off |
//! | `SANDY_ENV_PROVISION_TIMEOUT_SECS` | seconds before a probe that is not Ready fails the environment; default 120; `vm-qemu` and `vm-vfkit`: its boot budget plus 300, and a value below the boot budget is refused |
//!
//! `vm-qemu` and `vm-vfkit` read these as well, and only the provision timeout of the settings above. They refuse
//! `SANDY_ENV_IDLE_TIMEOUT_SECS` and the process-only settings (`SANDY_ENV_PROCESS_COMMAND`, `SANDY_ENV_PAIR_COMMAND`,
//! `SANDY_ENV_STATE_DIR`, `SANDY_ENV_PASS_ENV`, `SANDY_ENV_PATH`) rather than ignore them:
//!
//! | variable | meaning |
//! | --- | --- |
//! | `SANDY_ENV_VM_TEMPLATE` | the guest topology: a flake attr such as `<flake>#topologies.x86_64-linux.qemu-t3`, or a prebuilt topology JSON file |
//! | `SANDY_ENV_VM_COMMAND` | the service argv in the guest, split on whitespace; must contain `{port}` |
//! | `SANDY_ENV_VM_SERVICE_PORT` | the guest loopback port the service listens on |
//! | `SANDY_ENV_VM_SERVICE_USER` | the guest account the service runs as; default `t3`, never root |
//! | `SANDY_ENV_VM_BOOT_TIMEOUT_SECS` | sizes the hypervisor's connect budgets (not a deadline); default 600 |
//! | `SANDY_ENV_VM_HOST_CHECK` | how the host decides the service is Ready: `http` (default: `GET /` answers below 500, as a typical service does) or `connect` (the service port accepted a connection through the bridge, for a service that does not speak HTTP); any other value is refused |

use std::{path::PathBuf, time::Duration};

use sandy_environment::ProcessConfig;

use crate::environment_driver::DriverConfig;

/// The host-process backend, with no isolation.
pub const PROCESS_INSECURE: &str = "process-insecure";

/// The qemu microVM backend, Linux only.
pub const VM_QEMU: &str = "vm-qemu";

/// The vfkit microVM backend, macOS only.
pub const VM_VFKIT: &str = "vm-vfkit";

/// Seconds added to the boot budget for a VM backend's provision timeout when none is set: the guest probe and the
/// host bridge need time after the guest has booted.
const VM_PROVISION_MARGIN_SECS: u64 = 300;

/// The longest `SANDY_SERVICE` value the guest console takes (the executor's bound; the agent command is one
/// shell-quoted, base64-encoded console line).
const MAX_SERVICE_ENV_BYTES: usize = 1024;

/// How often the driver converges.
pub const DRIVER_INTERVAL: Duration = Duration::from_secs(1);

/// A selected backend and the driver settings that go with it.
#[derive(Debug, Clone)]
pub struct EnvironmentBackendConfig {
    /// The selected backend and its settings.
    pub backend: BackendSettings,
    /// The launch driver's settings.
    pub driver: DriverConfig,
}

/// The backend `SANDY_ENV_BACKEND` selected.
#[derive(Debug, Clone)]
pub enum BackendSettings {
    /// Host processes, no isolation.
    Process(ProcessConfig),
    /// One qemu microVM per environment.
    VmQemu(VmSettings),
    /// One vfkit microVM per environment.
    VmVfkit(VmSettings),
}

/// How a VM backend (`vm-qemu`, `vm-vfkit`) runs a service. The guest topology is [`DriverConfig::template`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSettings {
    /// The service argv the guest agent runs, with `{port}` already expanded.
    pub command: Vec<String>,
    /// The `SANDY_SERVICE` value (JSON `ServiceSpec`) that makes the agent run `command` as a probed service.
    pub service_env: String,
    /// Seconds that size the hypervisor backend's connect budgets.
    pub boot_timeout_secs: u32,
    /// How the host decides the service is Ready (`SANDY_ENV_VM_HOST_CHECK`, #732).
    pub host_check: sandy_environment::HostCheck,
}

/// Why the backend settings are unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvironmentBackendConfigError {
    /// `SANDY_ENV_BACKEND` names no known backend.
    #[error(
        "SANDY_ENV_BACKEND={0:?} is not a known backend (expected `{PROCESS_INSECURE}`, `{VM_QEMU}` or `{VM_VFKIT}`)"
    )]
    UnknownBackend(String),
    /// The backend exists but not on this platform.
    #[error(
        "SANDY_ENV_BACKEND={backend} is not available on {os}: it needs {}",
        platform_needs(backend)
    )]
    UnsupportedPlatform {
        /// The selected backend.
        backend: &'static str,
        /// The platform sandyd runs on.
        os: String,
    },
    /// A required variable is unset or blank.
    #[error("{0} is required by the selected SANDY_ENV_BACKEND")]
    Missing(&'static str),
    /// The service command has no `{port}`, so the service could never be reached.
    #[error("{0} must contain {{port}}")]
    MissingPort(&'static str),
    /// The service spec the settings describe is not one the guest agent accepts.
    #[error("service settings: {0}")]
    Service(String),
    /// The provision timeout would fail a cold boot before the boot budget ends.
    #[error(
        "SANDY_ENV_PROVISION_TIMEOUT_SECS={provision} is below SANDY_ENV_VM_BOOT_TIMEOUT_SECS={boot}: a cold boot \
         would be failed before it can finish"
    )]
    ProvisionBelowBoot {
        /// The configured provision timeout.
        provision: u64,
        /// The boot budget.
        boot: u64,
    },
    /// A number could not be parsed or was zero.
    #[error("{name}={raw:?} is not a positive whole number")]
    InvalidNumber {
        /// The variable.
        name: &'static str,
        /// What it held.
        raw: String,
    },
    /// The host readiness check is neither `http` nor `connect`.
    #[error("SANDY_ENV_VM_HOST_CHECK={raw:?} is not a host check: use `http` (the default) or `connect`")]
    InvalidHostCheck {
        /// What the variable held.
        raw: String,
    },
    /// A passed-through variable name is not `[A-Z0-9_]+`.
    #[error("SANDY_ENV_PASS_ENV name {0:?} is not an upper-case variable name")]
    InvalidName(String),
    /// A passed-through variable name is one the backend sets itself.
    #[error("SANDY_ENV_PASS_ENV name {0:?} is set by the backend and cannot be passed through")]
    ReservedName(String),
    /// A setting the selected VM backend cannot honour.
    #[error("{0} is not supported with a VM environment backend; unset it")]
    UnsupportedWithVm(&'static str),
    /// The default state dir could not be prepared.
    #[error("state dir: {0}")]
    StateDir(String),
}

fn platform_needs(backend: &str) -> &'static str {
    if backend == VM_VFKIT {
        "macOS with vfkit"
    } else {
        "Linux with KVM and vhost-vsock"
    }
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
    from_env_on(std::env::consts::OS, get, default_state_dir)
}

/// [`from_env`] for a named platform, so the platform refusal is testable on any host.
fn from_env_on(
    os: &str,
    get: impl Fn(&str) -> Option<String>,
    default_state_dir: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<Option<EnvironmentBackendConfig>, EnvironmentBackendConfigError> {
    use EnvironmentBackendConfigError as E;
    let Some(backend) = get("SANDY_ENV_BACKEND").filter(|v| !v.trim().is_empty()) else {
        return Ok(None);
    };
    let vm: Option<fn(VmSettings) -> BackendSettings> = match backend.as_str() {
        PROCESS_INSECURE => None,
        VM_QEMU if os == "linux" => Some(BackendSettings::VmQemu),
        VM_VFKIT if os == "macos" => Some(BackendSettings::VmVfkit),
        VM_QEMU | VM_VFKIT => {
            return Err(E::UnsupportedPlatform {
                backend: if backend == VM_QEMU { VM_QEMU } else { VM_VFKIT },
                os: os.to_owned(),
            });
        }
        _ => return Err(E::UnknownBackend(backend)),
    };
    let explicit_provision = match get("SANDY_ENV_PROVISION_TIMEOUT_SECS") {
        None => None,
        Some(raw) => Some(positive_secs("SANDY_ENV_PROVISION_TIMEOUT_SECS", raw)?),
    };
    let idle_timeout = match get("SANDY_ENV_IDLE_TIMEOUT_SECS").filter(|v| !v.trim().is_empty()) {
        None => None,
        Some(raw) => Some(Duration::from_secs(positive_secs("SANDY_ENV_IDLE_TIMEOUT_SECS", raw)?)),
    };
    let mut provision_secs = explicit_provision.unwrap_or(120);
    if vm.is_some() {
        // The VM backend cannot see bridge clients, so an idle stop would end a Ready VM that is in use (#645), and
        // the process settings have no VM counterpart: refuse each rather than drop it silently.
        if idle_timeout.is_some() {
            return Err(E::UnsupportedWithVm("SANDY_ENV_IDLE_TIMEOUT_SECS"));
        }
        for name in [
            "SANDY_ENV_PASS_ENV",
            "SANDY_ENV_PAIR_COMMAND",
            "SANDY_ENV_PROCESS_COMMAND",
            "SANDY_ENV_STATE_DIR",
            "SANDY_ENV_PATH",
        ] {
            if get(name).is_some_and(|v| !v.trim().is_empty()) {
                return Err(E::UnsupportedWithVm(name));
            }
        }
    }
    let (backend, template, service_port) = if let Some(wrap) = vm {
        let (settings, template, port) = vm_settings(&get)?;
        let boot = u64::from(settings.boot_timeout_secs);
        match explicit_provision {
            Some(provision) if provision < boot => {
                return Err(E::ProvisionBelowBoot { provision, boot });
            }
            Some(_) => {}
            None => provision_secs = boot + VM_PROVISION_MARGIN_SECS,
        }
        (wrap(settings), template, Some(port))
    } else {
        (
            BackendSettings::Process(process_settings(&get, default_state_dir)?),
            "process".to_owned(),
            None,
        )
    };
    Ok(Some(EnvironmentBackendConfig {
        backend,
        driver: DriverConfig {
            template,
            service_port,
            provision_timeout: Duration::from_secs(provision_secs),
            idle_timeout,
        },
    }))
}

fn positive_secs(name: &'static str, raw: String) -> Result<u64, EnvironmentBackendConfigError> {
    match raw.parse::<u64>() {
        Ok(secs) if secs > 0 => Ok(secs),
        _ => Err(EnvironmentBackendConfigError::InvalidNumber { name, raw }),
    }
}

fn argv(get: &impl Fn(&str) -> Option<String>, name: &str) -> Vec<String> {
    get(name)
        .map(|raw| raw.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn process_settings(
    get: &impl Fn(&str) -> Option<String>,
    default_state_dir: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<ProcessConfig, EnvironmentBackendConfigError> {
    use EnvironmentBackendConfigError as E;
    let command = argv(get, "SANDY_ENV_PROCESS_COMMAND");
    if command.is_empty() {
        return Err(E::Missing("SANDY_ENV_PROCESS_COMMAND"));
    }
    if !command.iter().any(|a| a.contains("{port}")) {
        return Err(E::MissingPort("SANDY_ENV_PROCESS_COMMAND"));
    }
    let pair_command = Some(argv(get, "SANDY_ENV_PAIR_COMMAND")).filter(|a| !a.is_empty());
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
    let state_dir = match get("SANDY_ENV_STATE_DIR").filter(|v| !v.trim().is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => default_state_dir().map_err(E::StateDir)?,
    };
    let path = get("SANDY_ENV_PATH")
        .filter(|v| !v.trim().is_empty())
        .or_else(|| get("PATH"))
        .unwrap_or_else(|| "/usr/bin:/bin".to_owned());
    Ok(ProcessConfig {
        command,
        pair_command,
        state_dir,
        path,
        pass_env,
        pair_timeout: Duration::from_secs(30),
    })
}

/// The VM settings, the guest topology (the driver's template) and the service port.
fn vm_settings(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<(VmSettings, String, u16), EnvironmentBackendConfigError> {
    use EnvironmentBackendConfigError as E;
    use sandy_guest_template::manifest::{HealthProbe, ProbeCheck, RestartPolicy, ServiceSpec, validate_service_spec};
    let template = get("SANDY_ENV_VM_TEMPLATE")
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .ok_or(E::Missing("SANDY_ENV_VM_TEMPLATE"))?;
    let raw_port = get("SANDY_ENV_VM_SERVICE_PORT")
        .filter(|v| !v.trim().is_empty())
        .ok_or(E::Missing("SANDY_ENV_VM_SERVICE_PORT"))?;
    let port = match raw_port.parse::<u16>() {
        Ok(port) if port > 0 => port,
        _ => {
            return Err(E::InvalidNumber {
                name: "SANDY_ENV_VM_SERVICE_PORT",
                raw: raw_port,
            });
        }
    };
    let command: Vec<String> = argv(get, "SANDY_ENV_VM_COMMAND");
    if command.is_empty() {
        return Err(E::Missing("SANDY_ENV_VM_COMMAND"));
    }
    if !command.iter().any(|a| a.contains("{port}")) {
        return Err(E::MissingPort("SANDY_ENV_VM_COMMAND"));
    }
    let command = command.iter().map(|a| a.replace("{port}", &port.to_string())).collect();
    let boot_timeout_secs = match get("SANDY_ENV_VM_BOOT_TIMEOUT_SECS").filter(|v| !v.trim().is_empty()) {
        None => 600,
        Some(raw) => u32::try_from(positive_secs("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", raw.clone())?).map_err(|_| {
            E::InvalidNumber {
                name: "SANDY_ENV_VM_BOOT_TIMEOUT_SECS",
                raw,
            }
        })?,
    };
    let host_check = match get("SANDY_ENV_VM_HOST_CHECK").filter(|v| !v.trim().is_empty()) {
        None => sandy_environment::HostCheck::default(),
        Some(raw) => raw.parse().map_err(|_| E::InvalidHostCheck { raw })?,
    };
    let spec = ServiceSpec {
        user: get("SANDY_ENV_VM_SERVICE_USER")
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "t3".to_owned()),
        probe: HealthProbe {
            check: ProbeCheck::Tcp { port },
            interval_secs: 2,
            timeout_secs: 2,
            // Five minutes of guest-side probing; the driver's provision timeout bounds the whole boot.
            max_attempts: 150,
        },
        restart: RestartPolicy::Never,
        port: Some(port),
    };
    validate_service_spec(&spec).map_err(E::Service)?;
    let service_env = serde_json::to_string(&spec).map_err(|e| E::Service(e.to_string()))?;
    if service_env.len() > MAX_SERVICE_ENV_BYTES {
        return Err(E::Service(format!(
            "the service spec is {} bytes, over the {MAX_SERVICE_ENV_BYTES} the guest console takes",
            service_env.len()
        )));
    }
    Ok((
        VmSettings {
            command,
            service_env,
            boot_timeout_secs,
            host_check,
        },
        template,
        port,
    ))
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::HashMap};

    use super::*;

    fn getter(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
        move |k| map.get(k).cloned()
    }

    fn process_of(cfg: &EnvironmentBackendConfig) -> &ProcessConfig {
        match &cfg.backend {
            BackendSettings::Process(p) => p,
            BackendSettings::VmQemu(_) | BackendSettings::VmVfkit(_) => panic!("expected the process backend"),
        }
    }

    fn vm_base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("SANDY_ENV_BACKEND", "vm-qemu"),
            ("SANDY_ENV_VM_TEMPLATE", "/srv/guest#topologies.x86_64-linux.qemu-t3"),
            ("SANDY_ENV_VM_COMMAND", "service serve --port {port}"),
            ("SANDY_ENV_VM_SERVICE_PORT", "3773"),
        ]
    }

    fn parse_on(
        os: &str,
        pairs: &[(&str, &str)],
    ) -> Result<Option<EnvironmentBackendConfig>, EnvironmentBackendConfigError> {
        from_env_on(os, getter(pairs), || Ok(PathBuf::from("/run/sandyd/environments")))
    }

    fn base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("SANDY_ENV_BACKEND", "process-insecure"),
            (
                "SANDY_ENV_PROCESS_COMMAND",
                "service serve --port {port} --base-dir {base_dir}",
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
            ("SANDY_ENV_PROCESS_COMMAND", "service serve --base-dir {base_dir}"),
        ]);
        assert_eq!(
            no_port.err(),
            Some(EnvironmentBackendConfigError::MissingPort("SANDY_ENV_PROCESS_COMMAND"))
        );
    }

    #[test]
    fn a_full_configuration_is_read_with_commands_split_on_whitespace() -> anyhow::Result<()> {
        let mut pairs = base();
        pairs.extend([
            (
                "SANDY_ENV_PROCESS_COMMAND",
                "  service   serve --port {port}  --base-dir {base_dir} ",
            ),
            ("SANDY_ENV_PAIR_COMMAND", "service pair  --base-dir {base_dir}"),
            ("SANDY_ENV_STATE_DIR", "/var/lib/sandy/envs"),
            ("SANDY_ENV_PASS_ENV", "ANTHROPIC_API_KEY, OPENAI_API_KEY ,"),
            ("SANDY_ENV_PATH", "/opt/service/bin:/usr/bin"),
            ("SANDY_ENV_PROVISION_TIMEOUT_SECS", "300"),
            ("SANDY_ENV_IDLE_TIMEOUT_SECS", "900"),
        ]);
        // The last entry for a key wins in the map.
        let cfg = parse(&pairs)?.ok_or_else(|| anyhow::anyhow!("expected a backend"))?;
        assert_eq!(
            process_of(&cfg).command,
            ["service", "serve", "--port", "{port}", "--base-dir", "{base_dir}"]
        );
        assert_eq!(
            process_of(&cfg).pair_command.as_deref(),
            Some(&["service", "pair", "--base-dir", "{base_dir}"].map(String::from)[..])
        );
        assert_eq!(process_of(&cfg).state_dir, PathBuf::from("/var/lib/sandy/envs"));
        assert_eq!(process_of(&cfg).pass_env, ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]);
        assert_eq!(process_of(&cfg).path, "/opt/service/bin:/usr/bin");
        assert_eq!(cfg.driver.provision_timeout, Duration::from_secs(300));
        assert_eq!(cfg.driver.idle_timeout, Some(Duration::from_secs(900)));
        Ok(())
    }

    #[test]
    fn defaults_come_from_the_runtime_dir_the_path_and_two_minutes() -> anyhow::Result<()> {
        let cfg = parse(&base())?.ok_or_else(|| anyhow::anyhow!("expected a backend"))?;
        assert_eq!(process_of(&cfg).state_dir, PathBuf::from("/run/sandyd/environments"));
        assert_eq!(process_of(&cfg).pair_command, None);
        assert!(process_of(&cfg).pass_env.is_empty());
        assert_eq!(cfg.driver.provision_timeout, Duration::from_secs(120));
        assert_eq!(cfg.driver.idle_timeout, None, "idle stop is off by default");
        assert_eq!(cfg.driver.service_port, None);
        let with_path = parse(&[base(), vec![("PATH", "/usr/local/bin:/usr/bin")]].concat())?
            .ok_or_else(|| anyhow::anyhow!("expected a backend"))?;
        assert_eq!(process_of(&with_path).path, "/usr/local/bin:/usr/bin");
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
    #[test]
    fn vm_qemu_off_linux_is_a_typed_error_naming_the_platform() {
        for os in ["macos", "windows", "freebsd"] {
            let out = parse_on(os, &vm_base());
            assert_eq!(
                out.as_ref().err(),
                Some(&EnvironmentBackendConfigError::UnsupportedPlatform {
                    backend: "vm-qemu",
                    os: os.to_owned()
                }),
                "{os}: {out:?}"
            );
            assert!(out.err().is_some_and(|e| e.to_string().contains(os)));
        }
    }

    fn vfkit_base() -> Vec<(&'static str, &'static str)> {
        vm_base()
            .into_iter()
            .map(|(k, v)| {
                if k == "SANDY_ENV_BACKEND" {
                    (k, "vm-vfkit")
                } else {
                    (k, v)
                }
            })
            .collect()
    }

    #[test]
    fn vm_vfkit_off_macos_is_a_typed_error_naming_the_platform() {
        for os in ["linux", "windows", "freebsd"] {
            let out = parse_on(os, &vfkit_base());
            assert_eq!(
                out.as_ref().err(),
                Some(&EnvironmentBackendConfigError::UnsupportedPlatform {
                    backend: "vm-vfkit",
                    os: os.to_owned()
                }),
                "{os}: {out:?}"
            );
            assert!(out.err().is_some_and(|e| e.to_string().contains("macOS")));
        }
    }

    #[test]
    fn vm_vfkit_leaves_vm_qemu_on_macos_refused() {
        assert_eq!(
            parse_on("macos", &vm_base()).err(),
            Some(EnvironmentBackendConfigError::UnsupportedPlatform {
                backend: "vm-qemu",
                os: "macos".to_owned()
            })
        );
    }

    #[test]
    fn a_valid_vm_vfkit_configuration_reads_the_vm_settings_on_macos() -> anyhow::Result<()> {
        use anyhow::Context;
        let cfg = parse_on("macos", &vfkit_base())?.context("a backend")?;
        let BackendSettings::VmVfkit(vm) = &cfg.backend else {
            anyhow::bail!("expected the vfkit backend, got {:?}", cfg.backend);
        };
        assert_eq!(vm.command, ["service", "serve", "--port", "3773"]);
        assert_eq!(cfg.driver.service_port, Some(3773));
        // Same defaults as vm-qemu: the boot budget plus 300 s.
        assert_eq!(cfg.driver.provision_timeout, Duration::from_secs(900));
        let mut missing = vfkit_base();
        missing.retain(|(k, _)| *k != "SANDY_ENV_VM_TEMPLATE");
        assert_eq!(
            parse_on("macos", &missing).err(),
            Some(EnvironmentBackendConfigError::Missing("SANDY_ENV_VM_TEMPLATE"))
        );
        Ok(())
    }

    #[test]
    fn vm_an_unknown_backend_still_errors_on_linux_and_names_both_choices() {
        let out = parse_on("linux", &[("SANDY_ENV_BACKEND", "vm")]);
        let Err(e @ EnvironmentBackendConfigError::UnknownBackend(_)) = out else {
            panic!("expected UnknownBackend, got {out:?}");
        };
        assert!(
            e.to_string().contains("vm-qemu") && e.to_string().contains("process-insecure"),
            "{e}"
        );
    }

    #[test]
    fn a_vm_qemu_backend_needs_template_command_with_port_and_service_port() {
        use EnvironmentBackendConfigError as E;
        let without = |name: &str| -> Vec<(&'static str, &'static str)> {
            vm_base().into_iter().filter(|(k, _)| *k != name).collect()
        };
        for name in [
            "SANDY_ENV_VM_TEMPLATE",
            "SANDY_ENV_VM_COMMAND",
            "SANDY_ENV_VM_SERVICE_PORT",
        ] {
            let out = parse_on("linux", &without(name));
            assert!(matches!(out, Err(E::Missing(n)) if n == name), "{name}: {out:?}");
        }
        let mut blank = vm_base();
        blank.push(("SANDY_ENV_VM_TEMPLATE", "  "));
        assert!(matches!(
            parse_on("linux", &blank),
            Err(E::Missing("SANDY_ENV_VM_TEMPLATE"))
        ));
        let mut no_port = vm_base();
        no_port.push(("SANDY_ENV_VM_COMMAND", "service serve"));
        assert_eq!(
            parse_on("linux", &no_port).err(),
            Some(E::MissingPort("SANDY_ENV_VM_COMMAND"))
        );
    }

    #[test]
    fn a_zero_or_non_numeric_vm_number_is_refused() {
        for (name, raw) in [
            ("SANDY_ENV_VM_SERVICE_PORT", "0"),
            ("SANDY_ENV_VM_SERVICE_PORT", "70000"),
            ("SANDY_ENV_VM_SERVICE_PORT", "http"),
            ("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "0"),
            ("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "99999999999"),
            ("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "x"),
        ] {
            let mut pairs = vm_base();
            pairs.push((name, raw));
            let out = parse_on("linux", &pairs);
            assert!(
                matches!(out, Err(EnvironmentBackendConfigError::InvalidNumber { name: n, .. }) if n == name),
                "{name}={raw}: {out:?}"
            );
        }
    }

    fn host_check_of(extra: Option<(&'static str, &'static str)>) -> anyhow::Result<sandy_environment::HostCheck> {
        use anyhow::Context;
        let mut pairs = vm_base();
        pairs.extend(extra);
        let cfg = parse_on("linux", &pairs)?.context("expected a backend")?;
        let BackendSettings::VmQemu(vm) = &cfg.backend else {
            anyhow::bail!("expected the vm backend");
        };
        Ok(vm.host_check)
    }

    /// The default keeps a typical service's semantics (503 while starting, 401 with auth, below 500 is Ready) (#732).
    #[test]
    fn the_vm_host_check_defaults_to_http_when_unset_or_blank() -> anyhow::Result<()> {
        use sandy_environment::HostCheck;
        assert_eq!(host_check_of(None)?, HostCheck::Http);
        assert_eq!(host_check_of(Some(("SANDY_ENV_VM_HOST_CHECK", "")))?, HostCheck::Http);
        assert_eq!(host_check_of(Some(("SANDY_ENV_VM_HOST_CHECK", "  ")))?, HostCheck::Http);
        Ok(())
    }

    #[test]
    fn the_vm_host_check_can_be_http_or_connect() -> anyhow::Result<()> {
        use sandy_environment::HostCheck;
        assert_eq!(
            host_check_of(Some(("SANDY_ENV_VM_HOST_CHECK", "http")))?,
            HostCheck::Http
        );
        assert_eq!(
            host_check_of(Some(("SANDY_ENV_VM_HOST_CHECK", "connect")))?,
            HostCheck::Connect
        );
        Ok(())
    }

    /// Fail closed: a typo must not silently pick a mode, since either one changes what Ready means.
    #[test]
    fn an_unknown_vm_host_check_is_refused_and_names_the_choices() {
        for raw in ["tcp", "Connect", "HTTP", "connect,http", "1", "none"] {
            let mut pairs = vm_base();
            pairs.push(("SANDY_ENV_VM_HOST_CHECK", raw));
            let out = parse_on("linux", &pairs);
            let Err(e @ EnvironmentBackendConfigError::InvalidHostCheck { .. }) = out else {
                panic!("{raw}: expected InvalidHostCheck, got {out:?}");
            };
            let text = e.to_string();
            assert!(
                text.contains("SANDY_ENV_VM_HOST_CHECK") && text.contains("http") && text.contains("connect"),
                "{raw}: {text}"
            );
        }
    }

    #[test]
    fn vm_a_service_user_the_guest_agent_would_refuse_fails_at_startup() {
        for user in ["root", "Bad User", "1abc"] {
            let mut pairs = vm_base();
            pairs.push(("SANDY_ENV_VM_SERVICE_USER", user));
            let out = parse_on("linux", &pairs);
            assert!(
                matches!(out, Err(EnvironmentBackendConfigError::Service(_))),
                "{user}: {out:?}"
            );
        }
    }

    #[test]
    fn a_valid_vm_qemu_configuration_expands_the_port_and_encodes_the_service() -> anyhow::Result<()> {
        use anyhow::Context;
        let mut pairs = vm_base();
        pairs.extend([
            ("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "900"),
            ("SANDY_ENV_PROVISION_TIMEOUT_SECS", "1000"),
        ]);
        let cfg = parse_on("linux", &pairs)?.context("expected a backend")?;
        let BackendSettings::VmQemu(vm) = &cfg.backend else {
            anyhow::bail!("expected the vm backend");
        };
        assert_eq!(vm.command, ["service", "serve", "--port", "3773"]);
        assert_eq!(vm.boot_timeout_secs, 900);
        assert_eq!(cfg.driver.template, "/srv/guest#topologies.x86_64-linux.qemu-t3");
        assert_eq!(cfg.driver.service_port, Some(3773));
        assert_eq!(cfg.driver.provision_timeout, Duration::from_secs(1000));
        let spec: sandy_guest_template::manifest::ServiceSpec = serde_json::from_str(&vm.service_env)?;
        assert_eq!(spec.user, "t3", "the default service user is the image's t3 account");
        assert_eq!(spec.port, Some(3773));
        assert!(vm.service_env.len() <= MAX_SERVICE_ENV_BYTES);
        Ok(())
    }

    #[test]
    fn vm_qemu_defaults_and_never_asks_for_a_state_dir() -> anyhow::Result<()> {
        use anyhow::Context;
        let asked = Cell::new(false);
        let cfg = from_env_on("linux", getter(&vm_base()), || {
            asked.set(true);
            Ok(PathBuf::new())
        })?
        .context("expected a backend")?;
        assert!(!asked.get());
        let BackendSettings::VmQemu(vm) = &cfg.backend else {
            anyhow::bail!("expected the vm backend");
        };
        assert_eq!(vm.boot_timeout_secs, 600);
        assert_eq!(
            cfg.driver.provision_timeout,
            Duration::from_secs(900),
            "a cold boot gets its whole budget plus a margin, not the process backend's 120 s"
        );
        Ok(())
    }

    #[test]
    fn vm_a_provision_timeout_below_the_boot_budget_is_refused_and_one_at_it_is_not() -> anyhow::Result<()> {
        let mut low = vm_base();
        low.extend([
            ("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "600"),
            ("SANDY_ENV_PROVISION_TIMEOUT_SECS", "599"),
        ]);
        assert_eq!(
            parse_on("linux", &low).err(),
            Some(EnvironmentBackendConfigError::ProvisionBelowBoot {
                provision: 599,
                boot: 600
            })
        );
        let mut at = vm_base();
        at.extend([
            ("SANDY_ENV_VM_BOOT_TIMEOUT_SECS", "600"),
            ("SANDY_ENV_PROVISION_TIMEOUT_SECS", "600"),
        ]);
        assert!(parse_on("linux", &at)?.is_some());
        // The process backend keeps its own 120 s default.
        assert_eq!(
            parse(&base())?.map(|c| c.driver.provision_timeout),
            Some(Duration::from_secs(120))
        );
        Ok(())
    }

    #[test]
    fn vm_qemu_refuses_the_idle_timeout_it_cannot_honour() {
        let mut env = vm_base();
        env.push(("SANDY_ENV_IDLE_TIMEOUT_SECS", "600"));
        let err = parse_on("linux", &env).err();
        assert!(
            matches!(
                err,
                Some(EnvironmentBackendConfigError::UnsupportedWithVm(
                    "SANDY_ENV_IDLE_TIMEOUT_SECS"
                ))
            ),
            "{err:?}"
        );
        // Blank or unset stays off, as before.
        env.pop();
        env.push(("SANDY_ENV_IDLE_TIMEOUT_SECS", " "));
        assert!(parse_on("linux", &env).is_ok());
    }

    #[test]
    fn vm_qemu_refuses_process_only_settings_instead_of_dropping_them() {
        for name in [
            "SANDY_ENV_PASS_ENV",
            "SANDY_ENV_PAIR_COMMAND",
            "SANDY_ENV_PROCESS_COMMAND",
            "SANDY_ENV_STATE_DIR",
            "SANDY_ENV_PATH",
        ] {
            let mut env = vm_base();
            env.push((name, "X"));
            let err = parse_on("linux", &env).err();
            assert!(
                matches!(&err, Some(EnvironmentBackendConfigError::UnsupportedWithVm(n)) if *n == name),
                "{name}: {err:?}"
            );
        }
    }
}
