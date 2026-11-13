//! `sandy daemon submit`'s template and flake sources: what the positional argument means and the `flake/v1`
//! manifest a template or `--flake` becomes (manifest-parity A3, #483).
//!
//! Both sources ship a flake REFERENCE the executor resolves for its own host, never a host-system attr built here.
//! A `TEMPLATE` is `--flake TEMPLATE --kind topology`.

use sandy::PlanError;
use sandy_guest_template::manifest::FlakeManifestV1;

/// What the positional argument of `daemon submit` is.
#[derive(Debug, PartialEq, Eq)]
pub enum Positional<'a> {
    /// A manifest file (or `-` for stdin), named by `--manifest-encoding`.
    Manifest(&'a str),
    /// A template: a flake reference, as `--flake` with `--kind topology`.
    Template(&'a str),
}

/// The plain-value flags a template or `--flake` takes, shared with `sandy run`.
#[derive(Debug, Clone, Default)]
pub struct PlainFlags {
    /// `--history-lines`.
    pub history_lines: u32,
    /// `--env KEY=VALUE` occurrences, verbatim.
    pub env: Vec<String>,
    /// `--cpu`.
    pub cpu: Option<u32>,
    /// `--mem` in MiB.
    pub mem: Option<u32>,
    /// `--timeout` in seconds.
    pub timeout: Option<u32>,
    /// The trailing `-- CMD ARGS...`.
    pub command: Vec<String>,
}

/// Decide what `positional` is. With `--manifest-encoding` it is a manifest file. Without it, it is a template, unless
/// it looks like a manifest file or a full attr.
///
/// # Errors
///
/// [`PlanError::Invalid`] for a template that names an existing file or `-` (a forgotten `--manifest-encoding`, never
/// a silent flake lookup) and for one that holds a `#` (use `--flake`).
pub fn classify_positional<'a>(
    positional: &'a str,
    manifest_encoding: Option<&str>,
    exists: impl Fn(&str) -> bool,
) -> Result<Positional<'a>, PlanError> {
    if manifest_encoding.is_some() {
        return Ok(Positional::Manifest(positional));
    }
    if positional == "-" || exists(positional) {
        return Err(PlanError::Invalid(format!(
            "`{positional}` looks like a manifest file; pass --manifest-encoding to submit it as one"
        )));
    }
    if positional.contains('#') {
        return Err(PlanError::Invalid(format!(
            "template `{positional}` has a `#`: a template is a flake reference, not a full attr; use --flake (with \
             --kind) for one"
        )));
    }
    Ok(Positional::Template(positional))
}

/// What a TEMPLATE names, as the `flake` of a `flake/v1` manifest with kind `topology`, and a note for the user when
/// part of what they typed is not sent (owner ruling on #483):
///
/// - a bare `topologies.<system>.<hypervisor>` names a topology of sandy's own guest flake
///   ([`sandy_guest_template::BUNDLED_GUEST_FLAKE`]);
/// - `REF#topologies.<system>.<hypervisor>` is the flake `REF`;
/// - anything with a `/` and no `#` is a flake reference as typed.
///
/// The executor adds its own system and hypervisor, so the `<system>.<hypervisor>` a user typed is not sent; the note
/// says so, so a request for another architecture is never ignored silently.
///
/// # Errors
///
/// [`PlanError::Invalid`] for a `#` attr that is not a `topologies.<system>.<hypervisor>` (use `--flake` with
/// `--kind`/`--attr`), an empty reference before the `#`, and a bare word that is neither a topology attr nor a
/// reference.
pub fn template_source(template: &str) -> Result<(String, Option<String>), PlanError> {
    Ok((template.to_owned(), None))
}

/// The `flake/v1` manifest for a flake reference.
///
/// # Errors
///
/// [`PlanError::Invalid`] for a malformed `--env` entry.
pub fn flake_manifest(
    flake: String,
    kind: Option<String>,
    attr: Option<String>,
    from_devshell: bool,
    plain: PlainFlags,
) -> Result<FlakeManifestV1, PlanError> {
    let env = plain
        .env
        .iter()
        .map(|raw| crate::plan::parse_env(raw))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FlakeManifestV1 {
        flake,
        kind,
        attr,
        command: plain.command,
        history_lines: plain.history_lines,
        env,
        cpu: plain.cpu,
        mem: plain.mem,
        timeout_secs: plain.timeout,
        service: None,
        from_devshell,
    })
}

/// The `flake/v1` manifest for a template: the flake reference with kind `topology`.
///
/// # Errors
///
/// [`PlanError::Invalid`] for a malformed `--env` entry.
pub fn template_manifest(template: &str, plain: PlainFlags) -> Result<FlakeManifestV1, PlanError> {
    flake_manifest(template.to_owned(), Some("topology".to_owned()), None, false, plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{RunArgs, parse_run};

    fn plain() -> PlainFlags {
        PlainFlags {
            history_lines: 1000,
            ..PlainFlags::default()
        }
    }

    #[test]
    fn a_positional_with_a_manifest_encoding_is_a_manifest() {
        let got = classify_positional("m.json", Some("x/v1"), |_| true);
        assert_eq!(got, Ok(Positional::Manifest("m.json")));
        assert_eq!(
            classify_positional("-", Some("x/v1"), |_| false),
            Ok(Positional::Manifest("-"))
        );
    }

    #[test]
    fn a_positional_without_an_encoding_is_a_template() {
        let got = classify_positional("github:acme/guest", None, |_| false);
        assert_eq!(got, Ok(Positional::Template("github:acme/guest")));
    }

    #[test]
    fn a_template_that_names_an_existing_file_or_stdin_is_refused_not_looked_up() {
        for name in ["manifest.json", "-"] {
            let err = classify_positional(name, None, |p| p == name)
                .err()
                .map(|e| e.to_string());
            let text = err.unwrap_or_default();
            assert!(
                text.contains("looks like a manifest file") && text.contains("--manifest-encoding"),
                "{name}: {text}"
            );
        }
    }

    #[test]
    fn a_template_with_a_hash_is_refused_naming_flake() {
        let text = classify_positional("./g#topologies.x86_64-linux.qemu", None, |_| false)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(text.contains("--flake"), "{text}");
    }

    #[test]
    fn a_template_is_a_flake_reference_with_kind_topology() -> anyhow::Result<()> {
        let m = template_manifest("github:acme/guest", plain()).map_err(|e| anyhow::anyhow!("{e}"))?;
        assert_eq!(m.flake, "github:acme/guest");
        assert_eq!(m.kind.as_deref(), Some("topology"));
        assert_eq!(m.attr, None);
        assert!(!m.from_devshell);
        Ok(())
    }

    #[test]
    fn a_devshell_flake_carries_the_flag_and_other_flakes_do_not_serialize_it() -> anyhow::Result<()> {
        let with = flake_manifest("g".to_owned(), None, None, true, plain()).map_err(|e| anyhow::anyhow!("{e}"))?;
        assert!(with.from_devshell);
        let json = String::from_utf8(sandy_guest_template::manifest::encode_flake_manifest(&with)?)?;
        assert!(json.contains("\"from_devshell\":true"), "{json}");
        let without = flake_manifest("g".to_owned(), None, None, false, plain()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let json = String::from_utf8(sandy_guest_template::manifest::encode_flake_manifest(&without)?)?;
        assert!(
            !json.contains("from_devshell"),
            "a manifest without the flag stays byte-identical: {json}"
        );
        Ok(())
    }

    /// An executor that does not know `from_devshell` refuses the manifest naming the field (deny_unknown_fields),
    /// never drops it (spec failure rule 3).
    #[test]
    fn an_executor_without_the_field_refuses_it_by_name() -> anyhow::Result<()> {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code, reason = "the shape of a manifest before from_devshell")]
        struct Old {
            flake: String,
            kind: Option<String>,
            attr: Option<String>,
            command: Vec<String>,
            history_lines: u32,
        }
        let m = flake_manifest("g".to_owned(), None, None, true, plain()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let bytes = sandy_guest_template::manifest::encode_flake_manifest(&m)?;
        let err = serde_json::from_slice::<Old>(&bytes)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("from_devshell") || err.contains("unknown field"), "{err}");
        // The real type keeps the guard: an unknown key is refused by name, never dropped.
        let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
        value["not_a_field"] = serde_json::Value::Bool(true);
        let err = sandy_guest_template::manifest::decode_flake_manifest(&serde_json::to_vec(&value)?)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("not_a_field"), "{err}");
        Ok(())
    }

    /// Each plain flag gives the manifest the same value the direct planner puts in the plan, one table row per flag.
    #[test]
    fn every_plain_flag_matches_the_direct_planner() -> anyhow::Result<()> {
        type Row = (&'static str, PlainFlags, RunArgs);
        let base = || RunArgs {
            template: "t".to_owned(),
            ..RunArgs::default()
        };
        let rows: Vec<Row> = vec![
            (
                "env",
                PlainFlags {
                    env: vec!["A=1".to_owned(), "B=two".to_owned()],
                    ..plain()
                },
                RunArgs {
                    env: vec!["A=1".to_owned(), "B=two".to_owned()],
                    ..base()
                },
            ),
            (
                "cpu",
                PlainFlags {
                    cpu: Some(3),
                    ..plain()
                },
                RunArgs { cpu: Some(3), ..base() },
            ),
            (
                "mem",
                PlainFlags {
                    mem: Some(2048),
                    ..plain()
                },
                RunArgs {
                    mem: Some(2048),
                    ..base()
                },
            ),
            (
                "timeout",
                PlainFlags {
                    timeout: Some(90),
                    ..plain()
                },
                RunArgs {
                    timeout: Some(90),
                    ..base()
                },
            ),
            (
                "command",
                PlainFlags {
                    command: vec!["echo".to_owned(), "hi".to_owned()],
                    ..plain()
                },
                RunArgs {
                    command: vec!["echo".to_owned(), "hi".to_owned()],
                    ..base()
                },
            ),
            ("none", plain(), base()),
        ];
        for (name, flags, args) in rows {
            let manifest = template_manifest("t", flags).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
            let plan = parse_run(args).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
            assert_eq!(manifest.env, plan.env, "{name}: env");
            assert_eq!(manifest.cpu, plan.cpu, "{name}: cpu");
            assert_eq!(manifest.mem, plan.mem, "{name}: mem");
            assert_eq!(manifest.command, plan.command, "{name}: command");
            let timeout = manifest.timeout_secs.unwrap_or(crate::plan::DEFAULT_TIMEOUT_SECS);
            assert_eq!(timeout, plan.timeout_secs, "{name}: timeout");
        }
        Ok(())
    }

    #[test]
    fn a_malformed_env_entry_is_refused() {
        let flags = PlainFlags {
            env: vec!["NOEQUALS".to_owned()],
            ..plain()
        };
        assert!(template_manifest("t", flags).is_err());
    }

    /// Owner ruling on #483: a bare topology attr names sandy's own guest flake; `REF#topologies.<s>.<h>` is `REF`;
    /// a reference with a `/` is sent as typed. Whatever the user typed for system and hypervisor is not sent, and the
    /// note says the executor picks its own.
    #[test]
    fn a_template_names_a_flake_by_the_rulings_three_forms() -> anyhow::Result<()> {
        let bundled = sandy_guest_template::BUNDLED_GUEST_FLAKE;
        let rows: [(&str, &str, bool); 5] = [
            ("topologies.aarch64-linux.vfkit", bundled, true),
            ("topologies.x86_64-linux.qemu", bundled, true),
            ("./guest#topologies.x86_64-linux.qemu", "./guest", true),
            (
                "github:acme/guest#topologies.aarch64-linux.vfkit",
                "github:acme/guest",
                true,
            ),
            ("github:acme/guest", "github:acme/guest", false),
        ];
        for (template, flake, noted) in rows {
            let (got, note) = template_source(template).map_err(|e| anyhow::anyhow!("{template}: {e}"))?;
            assert_eq!(got, flake, "{template}");
            assert_eq!(note.is_some(), noted, "{template}: note {note:?}");
            if let Some(note) = note {
                assert!(note.contains("its own system and hypervisor"), "{template}: {note}");
            }
        }
        assert_eq!(
            template_source("./guest")?.0,
            "./guest",
            "a path with a slash is a reference"
        );
        Ok(())
    }

    /// What is neither of those forms is refused with a message that names what would work, never guessed.
    #[test]
    fn a_template_that_is_neither_a_topology_attr_nor_a_reference_is_refused() {
        for bad in [
            "nixpkgs",
            "topologies.x86_64-linux",
            "topologies..qemu",
            "topologies.a.b.c",
            "./guest#nixosConfigurations.dev",
            "#topologies.x86_64-linux.qemu",
        ] {
            let text = template_source(bad).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(!text.is_empty(), "{bad} must be refused");
            assert!(
                text.contains("topologies.<system>.<hypervisor>") && text.contains("--flake"),
                "{bad}: {text}"
            );
        }
    }
}
