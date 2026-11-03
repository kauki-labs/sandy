//! The `flake/v1` dispatch manifest (#332): a flake-templated VM job's
//! `Dispatch.manifest` bytes, mirroring `sandy run --flake`'s own CLI shape
//! (`--flake`/`--attr`/`--kind`, a trailing `-- CMD ARGS...`) so
//! `sandy daemon submit --flake` encodes exactly what a remote host-executor's
//! `SandboxKind::Vm` branch decodes — ship the flake REFERENCE, never a
//! prebuilt topology: the executor resolves it against its OWN host (ground
//! truth confirmed on #332: a topology built on the submitting Mac is useless
//! on an x86_64-linux executor).

use serde::{Deserialize, Serialize};

/// The `Dispatch.manifest_encoding` tag a `flake/v1` manifest carries.
pub const MANIFEST_ENCODING_FLAKE_V1: &str = "flake/v1";

/// A `flake/v1` manifest's decoded shape: everything
/// [`crate::resolve_flake_template`] needs, plus the guest command.
///
/// `deny_unknown_fields`: an unrecognized field is refused, never silently
/// dropped (manifest-parity spec #459 item 1, decision `sandyd.md` §19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlakeManifestV1 {
    /// The flake reference `--flake` named (a path, `github:…`, or any other
    /// `nix` installable flake-ref syntax) — resolved by the EXECUTOR against
    /// its own host, never built here.
    pub flake: String,
    /// `--kind`'s override, if given; `None` auto-detects (mirrors `sandy run
    /// --flake`'s own default).
    pub kind: Option<String>,
    /// `--attr`'s override, if given; `None` uses `resolve_flake_template`'s
    /// own default (`"default"`).
    pub attr: Option<String>,
    /// The trailing `-- CMD ARGS...` guest command; empty means "boot the
    /// template's default command" (same convention as `JobPlan::command`).
    pub command: Vec<String>,
    /// The scrollback/transcript line bound for the job's interactive
    /// session (epic #340, phase 6): both tmux's own `history-limit` for
    /// live reattach and the cap on the archived transcript delivered back
    /// once the job ends use this same number. `#[serde(default)]` so a
    /// manifest encoded before this field existed still decodes — the
    /// default matches what a consumer should assume absent any override.
    #[serde(default = "default_history_lines")]
    pub history_lines: u32,
    /// Extra environment entries for the guest job (manifest-parity #480,
    /// `sandyd.md` §19). Merged ahead of the plumbing env this crate's own
    /// callers set (e.g. `SANDY_HISTORY_LINES`), which always applies last
    /// and wins a key collision.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// A request for vCPUs, clamped by `resolve_flake_template`'s caller
    /// against the executing host's own topology default. `None` keeps the
    /// template's own default.
    #[serde(default)]
    pub cpu: Option<u32>,
    /// A request for guest memory in MiB, same clamping rule as [`Self::cpu`].
    #[serde(default)]
    pub mem: Option<u32>,
    /// A request for the run's wall-clock budget in seconds, clamped to the
    /// host's ceiling (`STAGE1_TIMEOUT_SECS` today). `None` keeps the host's
    /// default.
    #[serde(default)]
    pub timeout_secs: Option<u32>,
    /// Declares `command` a long-running service (#589): it reaches Ready only once its health probe
    /// passes, instead of ending when the command exits. `None` is an ordinary job.
    #[serde(default)]
    pub service: Option<ServiceSpec>,
}

/// How a service runs and when it counts as Ready (#589).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    /// The account the service runs as. Required and never root, so a service cannot read the root-only
    /// secret share by default.
    pub user: String,
    /// The readiness check.
    pub probe: HealthProbe,
    /// What the agent does when the service exits.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// The guest loopback port the host-side bridge reaches (#590, #620): the agent starts the guest half of
    /// the bridge for it. `None` means the service has no host-reachable port. Separate from the probe because a
    /// command probe has no port.
    #[serde(default)]
    pub port: Option<u16>,
}

/// A readiness check, run by `sandy-agent` inside the guest every `interval_secs` until it passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthProbe {
    /// What to check.
    pub check: ProbeCheck,
    /// Seconds between attempts.
    #[serde(default = "default_probe_interval_secs")]
    pub interval_secs: u32,
    /// Seconds one attempt may take before it counts as failed.
    #[serde(default = "default_probe_timeout_secs")]
    pub timeout_secs: u32,
    /// Failed attempts in a row after which the service is Failed, with the last attempt's output.
    #[serde(default = "default_probe_max_attempts")]
    pub max_attempts: u32,
}

/// The two readiness checks a service can declare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeCheck {
    /// A TCP connect to `127.0.0.1:<port>` inside the guest succeeds.
    Tcp {
        /// The guest-local port.
        port: u16,
    },
    /// The command exits 0 (argv, no shell).
    Command {
        /// The program and its arguments.
        argv: Vec<String>,
    },
}

/// What `sandy-agent` does when a service exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Report the exit and stop.
    #[default]
    Never,
    /// Restart after a non-zero exit; a zero exit is reported and ends the service.
    OnFailure,
    /// Restart after any exit.
    Always,
}

const fn default_probe_interval_secs() -> u32 {
    2
}

const fn default_probe_timeout_secs() -> u32 {
    2
}

const fn default_probe_max_attempts() -> u32 {
    30
}

/// [`FlakeManifestV1::history_lines`]'s default (10,000) — also `sandy
/// daemon submit --flake`'s own `--history-lines` CLI default, so an
/// unencoded-field manifest and an explicit-default submission produce
/// identical bytes.
#[must_use]
pub fn default_history_lines() -> u32 {
    10_000
}

/// Encode a [`FlakeManifestV1`] as the JSON bytes `Dispatch.manifest` carries
/// under [`MANIFEST_ENCODING_FLAKE_V1`].
///
/// # Errors
/// Never fails in practice (every field is a plain string/`Vec<String>`), but
/// surfaces `serde_json`'s own error rather than panicking.
pub fn encode_flake_manifest(manifest: &FlakeManifestV1) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(manifest)
}

/// Decode a `flake/v1` manifest's bytes back into a [`FlakeManifestV1`].
///
/// # Errors
/// `serde_json`'s own error if the bytes are not valid JSON, not this
/// shape, or declare a [`ServiceSpec`] that cannot run (see [`validate_service`]).
pub fn decode_flake_manifest(bytes: &[u8]) -> Result<FlakeManifestV1, serde_json::Error> {
    let manifest: FlakeManifestV1 = serde_json::from_slice(bytes)?;
    validate_service(&manifest).map_err(serde::de::Error::custom)?;
    Ok(manifest)
}

/// The longest a service may take to become Ready: `interval_secs * max_attempts`, one hour.
pub const MAX_PROBE_BUDGET_SECS: u64 = 3_600;

/// Refuses a `service` that could never become Ready or would run as root. `decode_flake_manifest` calls it, so
/// the executor enforces it on every dispatch; a submitter that wants to fail early calls it too.
///
/// `user` is an account name (`[a-z_][a-z0-9_-]*`, at most 32 characters), never a uid, and never `root`. The
/// agent must still check the uid the name resolves to: another account can share uid 0.
///
/// # Errors
/// The first problem found, as a message.
pub fn validate_service(manifest: &FlakeManifestV1) -> Result<(), String> {
    let Some(service) = &manifest.service else {
        return Ok(());
    };
    if manifest.command.first().is_none_or(|program| program.trim().is_empty()) {
        return Err("a service needs a command to run, with a program name".to_owned());
    }
    validate_service_spec(service)
}

/// The part of [`validate_service`] that needs only the spec: the guest agent calls it on the spec it reads from
/// `SANDY_SERVICE`, so a spec that skipped the executor's decode (a submitter's own env entry) is checked too.
///
/// # Errors
/// The first problem found, as a message.
pub fn validate_service_spec(service: &ServiceSpec) -> Result<(), String> {
    if service.port == Some(0) {
        return Err("the service port must not be 0".to_owned());
    }
    if !is_service_account_name(&service.user) || service.user == "root" {
        return Err(format!(
            "a service must name a non-root user account ([a-z_][a-z0-9_-]*, at most 32 characters), got {:?}",
            service.user
        ));
    }
    let probe = &service.probe;
    match &probe.check {
        ProbeCheck::Tcp { port: 0 } => return Err("the probe port must not be 0".to_owned()),
        ProbeCheck::Command { argv }
            if argv
                .first()
                .is_none_or(|program| program.trim().is_empty() || argv.iter().any(|arg| arg.contains('\0'))) =>
        {
            return Err("the probe command needs a program and no NUL in its arguments".to_owned());
        }
        ProbeCheck::Tcp { .. } | ProbeCheck::Command { .. } => {}
    }
    if probe.interval_secs == 0 || probe.timeout_secs == 0 || probe.max_attempts == 0 {
        return Err("the probe interval, timeout and max attempts must be at least 1".to_owned());
    }
    if probe.timeout_secs > probe.interval_secs {
        return Err(format!(
            "the probe timeout ({}s) must not exceed its interval ({}s); both default to 2s",
            probe.timeout_secs, probe.interval_secs
        ));
    }
    if u64::from(probe.interval_secs) * u64::from(probe.max_attempts) > MAX_PROBE_BUDGET_SECS {
        return Err(format!(
            "the probe budget (interval * max attempts) must not exceed {MAX_PROBE_BUDGET_SECS}s"
        ));
    }
    Ok(())
}

/// A conservative POSIX account name: the shape every guest user the image defines will have.
fn is_service_account_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flake_manifest_round_trips_through_json() -> Result<(), serde_json::Error> {
        let manifest = FlakeManifestV1 {
            flake: "github:acme/guest".to_owned(),
            kind: Some("nixos-module".to_owned()),
            attr: Some("default".to_owned()),
            command: vec!["sh".to_owned()],
            history_lines: 5_000,
            env: vec![("FOO".to_owned(), "bar".to_owned())],
            cpu: Some(4),
            mem: Some(2_048),
            timeout_secs: Some(120),
            service: Some(t3_service()),
        };
        let bytes = encode_flake_manifest(&manifest)?;
        assert_eq!(decode_flake_manifest(&bytes)?, manifest);
        Ok(())
    }

    fn t3_service() -> ServiceSpec {
        ServiceSpec {
            user: "dev".to_owned(),
            probe: HealthProbe {
                check: ProbeCheck::Tcp { port: 3773 },
                interval_secs: 2,
                timeout_secs: 1,
                max_attempts: 60,
            },
            restart: RestartPolicy::OnFailure,
            port: Some(3773),
        }
    }

    /// A service manifest with `change` applied, encoded the way a submitter would send it.
    fn service_manifest_bytes(change: impl FnOnce(&mut ServiceSpec)) -> Result<Vec<u8>, serde_json::Error> {
        let mut service = t3_service();
        change(&mut service);
        encode_flake_manifest(&FlakeManifestV1 {
            flake: "./fixture".to_owned(),
            kind: None,
            attr: None,
            command: vec!["t3".to_owned(), "serve".to_owned()],
            history_lines: default_history_lines(),
            env: Vec::new(),
            cpu: None,
            mem: None,
            timeout_secs: None,
            service: Some(service),
        })
    }

    /// Decodes `bytes`, which must be refused, and returns the refusal's text.
    fn refusal(bytes: &[u8]) -> String {
        decode_flake_manifest(bytes)
            .expect_err("this manifest must be refused")
            .to_string()
    }

    /// Adversarial (#589): a service runs as a named, non-root account. Every spelling of uid 0, and any name
    /// that is not a plain account name, is refused.
    #[test]
    fn a_service_user_that_is_not_a_plain_non_root_account_is_refused() -> Result<(), serde_json::Error> {
        let too_long = "a".repeat(33);
        for user in [
            "root", "0", "00", "+0", "", " root", "root ", "root\0", "ROOT", "-x", "a/b", "1abc", "a b", &too_long,
        ] {
            let bytes = service_manifest_bytes(|s| s.user = user.to_owned())?;
            assert!(
                refusal(&bytes).contains("non-root user account"),
                "user {user:?} must be refused as a bad account"
            );
        }
        for user in ["dev", "_t3", "t3-user", "svc_1"] {
            decode_flake_manifest(&service_manifest_bytes(|s| s.user = user.to_owned())?)?;
        }
        Ok(())
    }

    /// Adversarial (#589): a probe that can never pass, or never time out, is refused at submit time instead of
    /// hanging the environment in Starting. Each case names the message it must produce.
    #[test]
    fn an_unrunnable_probe_is_refused_with_its_reason() -> Result<(), serde_json::Error> {
        // A case name, how it mutates the fixture, and the message its refusal must contain.
        type Case = (&'static str, fn(&mut ServiceSpec), &'static str);
        let cases: [Case; 8] = [
            (
                "port 0",
                |s| s.probe.check = ProbeCheck::Tcp { port: 0 },
                "port must not be 0",
            ),
            (
                "empty argv",
                |s| s.probe.check = ProbeCheck::Command { argv: Vec::new() },
                "needs a program",
            ),
            (
                "blank program",
                |s| {
                    s.probe.check = ProbeCheck::Command {
                        argv: vec!["  ".to_owned()],
                    }
                },
                "needs a program",
            ),
            (
                "NUL in an argument",
                |s| {
                    s.probe.check = ProbeCheck::Command {
                        argv: vec!["true".to_owned(), "a\0b".to_owned()],
                    }
                },
                "no NUL",
            ),
            ("zero interval", |s| s.probe.interval_secs = 0, "at least 1"),
            ("zero timeout", |s| s.probe.timeout_secs = 0, "at least 1"),
            ("zero attempts", |s| s.probe.max_attempts = 0, "at least 1"),
            (
                "an hour and a second of budget",
                |s| {
                    s.probe.interval_secs = 3_601;
                    s.probe.timeout_secs = 1;
                    s.probe.max_attempts = 1;
                },
                "probe budget",
            ),
        ];
        for (name, change, message) in cases {
            let text = refusal(&service_manifest_bytes(change)?);
            assert!(text.contains(message), "{name}: {text}");
        }
        Ok(())
    }

    /// The budget is checked in u64: a huge interval and attempt count is refused, not wrapped.
    #[test]
    fn a_probe_budget_that_overflows_u32_is_refused() -> Result<(), serde_json::Error> {
        let bytes = service_manifest_bytes(|s| {
            s.probe.interval_secs = u32::MAX;
            s.probe.max_attempts = u32::MAX;
        })?;
        assert!(refusal(&bytes).contains("probe budget"));
        Ok(())
    }

    /// Adversarial (#589): a probe timeout longer than its interval would overlap attempts, and the message
    /// names both values since either may come from a default.
    #[test]
    fn a_probe_timeout_beyond_its_interval_is_refused() -> Result<(), serde_json::Error> {
        let bytes = service_manifest_bytes(|s| {
            s.probe.interval_secs = 1;
            s.probe.timeout_secs = 5;
        })?;
        let text = refusal(&bytes);
        assert!(text.contains("(5s)") && text.contains("(1s)"), "{text}");
        Ok(())
    }

    /// A service needs a command to run: the template's default command is not a service.
    #[test]
    fn a_service_without_a_command_is_refused() -> Result<(), serde_json::Error> {
        let mut manifest = decode_flake_manifest(&service_manifest_bytes(|_| {})?)?;
        manifest.command.clear();
        let bytes = encode_flake_manifest(&manifest)?;
        assert!(refusal(&bytes).contains("needs a command"));
        Ok(())
    }

    /// Schema holes: an unknown field in `service`, `probe` or `check`, and an unknown check type, are refused
    /// like an unknown top-level field; `"service": null` is an ordinary job.
    #[test]
    fn the_service_schema_refuses_unknown_shapes() -> Result<(), serde_json::Error> {
        let base = |service: &str| {
            format!(r#"{{"flake":".","kind":null,"attr":null,"command":["t3","serve"],"service":{service}}}"#)
        };
        for service in [
            r#"{"user":"dev","probe":{"check":{"type":"tcp","port":1}},"extra":1}"#,
            r#"{"user":"dev","probe":{"check":{"type":"tcp","port":1},"extra":1}}"#,
            r#"{"user":"dev","probe":{"check":{"type":"tcp","port":1,"extra":1}}}"#,
            r#"{"user":"dev","probe":{"check":{"type":"http","port":1}}}"#,
            r#"{"user":"dev","probe":{"check":{"type":"tcp","port":1}},"restart":"sometimes"}"#,
        ] {
            assert!(
                decode_flake_manifest(base(service).as_bytes()).is_err(),
                "{service} must be refused"
            );
        }
        assert_eq!(decode_flake_manifest(base("null").as_bytes())?.service, None);
        Ok(())
    }

    /// #590: a service port of 0 cannot be reached, so it is refused; an absent port is fine.
    #[test]
    fn a_service_port_of_zero_is_refused_and_an_absent_one_is_allowed() -> Result<(), serde_json::Error> {
        let bytes = service_manifest_bytes(|s| s.port = Some(0))?;
        assert!(refusal(&bytes).contains("service port"));
        let bytes = service_manifest_bytes(|s| s.port = None)?;
        assert_eq!(decode_flake_manifest(&bytes)?.service.map(|s| s.port), Some(None));
        Ok(())
    }

    /// The bare-spec check the agent uses accepts the T3 shape and refuses what the manifest check refuses.
    #[test]
    fn validate_service_spec_checks_a_spec_without_a_manifest() {
        assert_eq!(validate_service_spec(&t3_service()), Ok(()));
        let mut zero_interval = t3_service();
        zero_interval.probe.interval_secs = 0;
        assert!(validate_service_spec(&zero_interval).is_err());
        let mut root = t3_service();
        root.user = "root".to_owned();
        assert!(validate_service_spec(&root).is_err());
    }

    /// CodeRabbit on #632: a service command whose program is empty or blank cannot start, so decode refuses it
    /// like a missing command.
    #[test]
    fn a_service_command_with_a_blank_program_is_refused() -> Result<(), serde_json::Error> {
        for program in ["", "   "] {
            let mut manifest = decode_flake_manifest(&service_manifest_bytes(|_| {})?)?;
            manifest.command = vec![program.to_owned(), "serve".to_owned()];
            let bytes = encode_flake_manifest(&manifest)?;
            assert!(refusal(&bytes).contains("needs a command"), "program {program:?}");
        }
        Ok(())
    }

    /// The T3 shape decodes, and an omitted restart policy and probe timing take their defaults.
    #[test]
    fn a_minimal_service_takes_the_defaults() -> Result<(), serde_json::Error> {
        let json = r#"{"flake":".","kind":null,"attr":null,"command":["t3","serve"],
            "service":{"user":"dev","probe":{"check":{"type":"tcp","port":3773}}}}"#;
        let service = decode_flake_manifest(json.as_bytes())?
            .service
            .expect("service present");
        assert_eq!(service.restart, RestartPolicy::Never);
        assert_eq!(
            (
                service.probe.interval_secs,
                service.probe.timeout_secs,
                service.probe.max_attempts
            ),
            (2, 2, 30)
        );
        Ok(())
    }

    /// `kind`/`attr` are optional and an empty command means "boot the
    /// template's default" — the minimal `--flake <ref>` invocation with no
    /// overrides and no trailing command.
    #[test]
    fn kind_attr_and_command_are_optional() -> Result<(), serde_json::Error> {
        let manifest = FlakeManifestV1 {
            flake: "./fixture".to_owned(),
            kind: None,
            attr: None,
            command: Vec::new(),
            history_lines: default_history_lines(),
            env: Vec::new(),
            cpu: None,
            mem: None,
            timeout_secs: None,
            service: None,
        };
        let bytes = encode_flake_manifest(&manifest)?;
        assert_eq!(decode_flake_manifest(&bytes)?, manifest);
        Ok(())
    }

    /// A manifest encoded before `env`/`cpu`/`mem`/`timeout_secs` existed (no
    /// fields in the JSON at all, same as a pre-#480 sender) must still
    /// decode, each field absent — the same forward-compat contract
    /// `history_lines` already established.
    #[test]
    fn a_manifest_with_no_parity_fields_defaults_them_absent() -> Result<(), serde_json::Error> {
        let legacy_json = br#"{"flake":"./fixture","kind":null,"attr":null,"command":[],"history_lines":10000}"#;
        let decoded = decode_flake_manifest(legacy_json)?;
        assert_eq!(decoded.env, Vec::<(String, String)>::new());
        assert_eq!(decoded.cpu, None);
        assert_eq!(decoded.mem, None);
        assert_eq!(decoded.timeout_secs, None);
        Ok(())
    }

    /// An unrecognized field is refused, not silently dropped (manifest-parity
    /// spec #459 item 1).
    #[test]
    fn an_unknown_field_is_refused() {
        let json = br#"{"flake":"./fixture","kind":null,"attr":null,"command":[],"history_lines":10000,"bogus":1}"#;
        assert!(decode_flake_manifest(json).is_err());
    }

    /// Malformed bytes are refused, not silently defaulted.
    #[test]
    fn malformed_bytes_are_refused() {
        assert!(decode_flake_manifest(b"not json").is_err());
    }

    /// A manifest encoded before `history_lines` existed (no field in the
    /// JSON at all) must still decode, defaulting to 10,000 — the whole
    /// point of `#[serde(default)]` here: a not-yet-redeployed host-executor
    /// or an older CLI must never fail to decode an otherwise-valid
    /// `flake/v1` manifest.
    #[test]
    fn a_manifest_with_no_history_lines_field_defaults_to_ten_thousand() -> Result<(), serde_json::Error> {
        let legacy_json = br#"{"flake":"./fixture","kind":null,"attr":null,"command":[]}"#;
        let decoded = decode_flake_manifest(legacy_json)?;
        assert_eq!(decoded.history_lines, 10_000);
        Ok(())
    }
}
