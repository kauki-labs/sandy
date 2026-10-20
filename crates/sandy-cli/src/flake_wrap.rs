//! `sandy run --flake <ref>`: wrap an arbitrary flake with no sandy awareness
//! at all as a bootable guest (#325).
//!
//! Three template kinds, picked by what `<ref>` actually exposes (or named
//! with `--kind`), always printed once resolved — never silently guessed:
//!
//! - **`topology`**: `<ref>` already calls `lib.mkGuest`/`lib.mkTopology` itself and exposes
//!   `topologies.<system>.<hypervisor>` (#324). Unchanged from today's `sandy run <flake>#topologies…` path — `--flake`
//!   only auto-assembles that same attr string for this host.
//! - **`nixos-module`**: `<ref>` exposes `nixosModules.<attr>` (default `"default"`). Routed through
//!   `nix/guest-wrapper/flake.nix`'s `topologiesFromModule`/`guestRunnersFromModule`, which wrap it with `mkGuest`
//!   exactly as `nix/guest/flake.nix`'s own `extraModules` callers do.
//! - **`nixos-configuration`**: `<ref>` exposes a full `nixosConfigurations.<attr>`. Routed through the wrapper's
//!   `topologiesFromConfiguration`/`guestRunnersFromConfiguration`, which layer sandy's protocol wiring on with
//!   `extendModules`.
//!
//! The mechanism (kind 2/3): `<ref>` is wired into the wrapper flake as the
//! `target` input, overridden at invocation time
//! (`--override-input target <ref>`) rather than baked into the wrapper's own
//! lock — the one flake in the repo not meant to be evaluated with its own
//! locked default. sandy first `nix build`s the wrapper's runner attr (realising
//! the kernel/initrd/erofs store paths `mkTopology` only names, matching every
//! other boot path's build-then-eval order), then `nix eval --json`s the
//! topology attr and hands the resulting bytes to the EXISTING Nix-free file
//! branch in `crates/sandy/src/nix/topology.rs::topology` — via a temp file,
//! not a new code path there. That function stays byte-for-byte unchanged;
//! only the source this module feeds it (a prebuilt JSON file instead of a
//! live flake attr) is new.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result, bail};

use crate::host_target::{HostTarget, host_target};

/// Which of the three template kinds `--flake` resolved to (or was told to
/// force via `--kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    /// The flake already exposes `topologies.<system>.<hypervisor>` itself.
    Topology,
    /// The flake exposes `nixosModules.<attr>`.
    NixosModule,
    /// The flake exposes `nixosConfigurations.<attr>`.
    NixosConfiguration,
}

impl std::fmt::Display for TemplateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TemplateKind::Topology => "topology",
            TemplateKind::NixosModule => "nixos-module",
            TemplateKind::NixosConfiguration => "nixos-configuration",
        })
    }
}

/// Parse a `--kind` token. The CLI's only spelling for each kind — keep in
/// sync with the `Display` impl above (every valid input round-trips).
pub fn parse_kind(raw: &str) -> Result<TemplateKind, String> {
    match raw {
        "topology" => Ok(TemplateKind::Topology),
        "nixos-module" => Ok(TemplateKind::NixosModule),
        "nixos-configuration" => Ok(TemplateKind::NixosConfiguration),
        other => Err(format!(
            "unknown --kind `{other}` (expected topology | nixos-module | nixos-configuration)"
        )),
    }
}

/// `--attr`'s default when the flag is omitted: the conventional entry point
/// for both `nixosModules` and `nixosConfigurations`.
const DEFAULT_ATTR: &str = "default";

/// The result of resolving a `--flake` template: either the user's own
/// `topologies` attr passed straight through (kind `topology`, unchanged), or
/// a prebuilt topology JSON file sandy evaluated+built through its own
/// guest-wrapper flake (kinds `nixos-module`/`nixos-configuration`).
pub enum ResolvedTemplate {
    /// Hand straight to the existing flake-attr path
    /// (`crates/sandy/src/nix/topology.rs::topology`'s `nix eval` branch) —
    /// no wrapper, no prebuild, exactly today's behaviour.
    Direct(String),
    /// A prebuilt topology JSON file; `path` is what `JobPlan::template`
    /// becomes (the existing Nix-free file branch reads it). `_kept` holds
    /// the temp file open for the life of the run — it must outlive the
    /// backend's `topology()` read, so the caller keeps it in scope across
    /// the whole `sandy run` dispatch, not just this function.
    Prebuilt {
        /// The temp file path, as a `String` for `JobPlan::template`.
        path: String,
        /// Deletes the file on drop; keep this alive until the run completes.
        _kept: tempfile::TempPath,
    },
}

/// Resolve `--flake <flake_ref>` (with optional `--kind`/`--attr` overrides)
/// into a [`ResolvedTemplate`], printing the kind it picked (or was told) to
/// stderr before doing anything else — `--flake` never silently guesses.
///
/// # Errors
/// Returns an error naming what was checked when no kind is detected, when a
/// forced `--kind`/`--attr` names an attr the flake does not have, when the
/// macOS vfkit build prerequisites are missing, or when the wrapper's
/// `nix build`/`nix eval` fails (the module-system conflict case is
/// summarized, not dumped as a raw stack trace).
pub fn resolve_flake_template(flake_ref: &str, kind: Option<&str>, attr: Option<&str>) -> Result<ResolvedTemplate> {
    let forced = kind
        .map(|k| parse_kind(k).map_err(|e| anyhow::anyhow!(e)))
        .transpose()?;
    let host = host_target();
    let (kind, resolved_attr) = detect_kind(flake_ref, forced, attr, &host)?;
    eprintln!(
        "sandy: --flake {flake_ref} resolved to kind `{kind}`{}",
        if resolved_attr.is_empty() {
            String::new()
        } else {
            format!(" (attr `{resolved_attr}`)")
        }
    );

    match kind {
        TemplateKind::Topology => Ok(ResolvedTemplate::Direct(direct_topology_ref(flake_ref, &host))),
        TemplateKind::NixosModule | TemplateKind::NixosConfiguration => {
            if cfg!(target_os = "macos")
                && let Some(refusal) = crate::doctor::mac_prereq_result(crate::doctor::detect_mac_prereq())
            {
                bail!("{}", refusal.message);
            }
            let wrapper_dir = guest_wrapper_dir()?;
            let json = build_and_eval(flake_ref, kind, &resolved_attr, &host, &wrapper_dir)?;
            let mut file = tempfile::Builder::new()
                .suffix(".json")
                .tempfile()
                .context("create a temp file for the --flake topology JSON")?;
            file.write_all(&json).context("write topology JSON to temp file")?;
            let temp_path = file.into_temp_path();
            let path = temp_path
                .to_str()
                .context("temp topology file path is not valid UTF-8")?
                .to_string();
            Ok(ResolvedTemplate::Prebuilt { path, _kept: temp_path })
        }
    }
}

/// Detect (or confirm a forced) template kind, returning the kind and the
/// attr name resolved within it (empty for `topology`, which has none).
fn detect_kind(
    flake_ref: &str,
    forced: Option<TemplateKind>,
    attr_override: Option<&str>,
    host: &HostTarget,
) -> Result<(TemplateKind, String)> {
    let attr = attr_override.unwrap_or(DEFAULT_ATTR);
    match forced {
        Some(TemplateKind::Topology) => match detect_topology(flake_ref, host)? {
            true => Ok((TemplateKind::Topology, String::new())),
            false => bail!(
                "--kind topology forced, but `{flake_ref}` has no `topologies.{}.{}`",
                host.guest_system,
                host.hypervisor
            ),
        },
        Some(TemplateKind::NixosModule) => match probe_attr_present(flake_ref, "nixosModules", attr)? {
            true => Ok((TemplateKind::NixosModule, attr.to_string())),
            false => bail!("--kind nixos-module forced, but `{flake_ref}` has no `nixosModules.{attr}`"),
        },
        Some(TemplateKind::NixosConfiguration) => match probe_attr_present(flake_ref, "nixosConfigurations", attr)? {
            true => Ok((TemplateKind::NixosConfiguration, attr.to_string())),
            false => {
                bail!("--kind nixos-configuration forced, but `{flake_ref}` has no `nixosConfigurations.{attr}`")
            }
        },
        // Auto-detect, in the issue's own priority order. `detect_topology`
        // bails (rather than returning `false`) when `topologies` exists but
        // lacks this host's system/hypervisor row — a real match that just
        // can't boot here must refuse, not silently fall through to kind 2.
        None => {
            if detect_topology(flake_ref, host)? {
                return Ok((TemplateKind::Topology, String::new()));
            }
            if probe_attr_present(flake_ref, "nixosModules", attr)? {
                return Ok((TemplateKind::NixosModule, attr.to_string()));
            }
            if probe_attr_present(flake_ref, "nixosConfigurations", attr)? {
                return Ok((TemplateKind::NixosConfiguration, attr.to_string()));
            }
            bail!(
                "could not detect a sandy template kind for `--flake {flake_ref}`: checked `topologies.{}.{}`, \
                 `nixosModules.{attr}`, `nixosConfigurations.{attr}` — none present. Pass `--kind` to name one \
                 explicitly, or `--attr` if it lives under a different name.",
                host.guest_system,
                host.hypervisor
            )
        }
    }
}

/// Whether `flake_ref` exposes `topologies.<host.guest_system>.<host.hypervisor>`.
///
/// # Errors
/// Bails (rather than returning `false`) when `topologies` exists at all but
/// not for this host's system/hypervisor — that is a real kind-1 flake this
/// host simply cannot boot, not "try kind 2 instead".
fn detect_topology(flake_ref: &str, host: &HostTarget) -> Result<bool> {
    let Some(systems) = probe_attr_names(flake_ref, "topologies")? else {
        return Ok(false);
    };
    if !systems.iter().any(|s| s == &host.guest_system) {
        bail!(
            "`{flake_ref}` exposes `topologies` but not for this host's guest system `{}` (has: {})",
            host.guest_system,
            systems.join(", ")
        );
    }
    let hypervisors = probe_attr_names(flake_ref, &format!("topologies.{}", host.guest_system))?
        .with_context(|| format!("`{flake_ref}#topologies.{}` vanished between probes", host.guest_system))?;
    if !hypervisors.iter().any(|h| h == &host.hypervisor) {
        bail!(
            "`{flake_ref}` exposes `topologies.{}` but not for `{}` (has: {})",
            host.guest_system,
            host.hypervisor,
            hypervisors.join(", ")
        );
    }
    Ok(true)
}

/// Whether `flake_ref#<top>.<attr>` exists (`top` is `nixosModules` or
/// `nixosConfigurations`).
fn probe_attr_present(flake_ref: &str, top: &str, attr: &str) -> Result<bool> {
    Ok(probe_attr_names(flake_ref, top)?.is_some_and(|names| names.iter().any(|n| n == attr)))
}

/// List `flake_ref#<path>`'s attr names (lazy — forces no derivation,
/// matching the structure-only check `nix flake show` does, just scoped to
/// one subtree). `Ok(None)` means the attr itself does not exist (nix's own
/// "does not provide attribute" wording); any other failure (network, a real
/// eval error elsewhere in the flake, …) surfaces as `Err`, unclassified.
fn probe_attr_names(flake_ref: &str, path: &str) -> Result<Option<Vec<String>>> {
    let installable = format!("{flake_ref}#{path}");
    let output = run_nix(&[
        "eval",
        "--json",
        "--no-write-lock-file",
        &installable,
        "--apply",
        "builtins.attrNames",
    ])
    .with_context(|| format!("spawn `nix eval {installable}`"))?;
    if output.status.success() {
        let names: Vec<String> = serde_json::from_slice(&output.stdout)
            .with_context(|| format!("parse `nix eval {installable} --apply builtins.attrNames` output as JSON"))?;
        return Ok(Some(names));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if attribute_missing(&stderr) {
        return Ok(None);
    }
    bail!("`nix eval {installable}` failed: {}", summarize_nix_error(&stderr));
}

/// Whether `stderr` is nix's own "this attribute does not exist" wording
/// (confirmed verbatim against this nix version: `error: flake '…' does not
/// provide attribute '…'`), as opposed to any other eval failure.
fn attribute_missing(stderr: &str) -> bool {
    stderr.contains("does not provide attribute")
}

/// Pull the actionable line(s) out of a nix module-system error, dropping the
/// `… while evaluating …` stack trace nix prints above it. Recognizes the
/// "conflicting definition values" shape (#325's design note: an arbitrary
/// kind-2/3 module colliding with `commonModule`); anything else is returned
/// as nix's own final `error: …` block, trimmed — never swallowed, but never
/// the full trace either when nix already names the real cause at the end.
fn summarize_nix_error(stderr: &str) -> String {
    if let Some(idx) = stderr.find("error: The option") {
        return stderr[idx..].trim().to_string();
    }
    if let Some(idx) = stderr.rfind("\nerror:") {
        return stderr[idx + 1..].trim().to_string();
    }
    stderr.trim().to_string()
}

/// `nix <args>`, captured (not inherited) so stdout stays the pure data
/// channel (`sandy -o json run` parses it as the result envelope) and stderr
/// is ours to summarize on failure.
fn run_nix(args: &[&str]) -> std::io::Result<Output> {
    Command::new("nix").args(args).output()
}

/// The user's own flake attr, auto-assembled — kind `topology`'s only new
/// behaviour over today's `sandy run <flake>#topologies…`.
fn direct_topology_ref(flake_ref: &str, host: &HostTarget) -> String {
    format!("{flake_ref}#topologies.{}.{}", host.guest_system, host.hypervisor)
}

/// The wrapper's `topologiesFromModule`/`guestRunnersFromModule` attr paths
/// for one `nixosModules.<attr>`.
fn module_attrs(attr: &str, host: &HostTarget) -> (String, String) {
    (
        format!("topologiesFromModule.{attr}.{}.{}", host.guest_system, host.hypervisor),
        format!(
            "guestRunnersFromModule.{attr}.{}.{}",
            host.guest_system, host.hypervisor
        ),
    )
}

/// The wrapper's `topologiesFromConfiguration`/`guestRunnersFromConfiguration`
/// attr paths for one `nixosConfigurations.<attr>`. No system component: the
/// target's own `nixosConfigurations.<attr>` already fixes its system — the
/// wrapper's own `guestFromConfiguration` is what refuses a mismatched
/// hypervisor (a named `throw`, not a missing attr).
fn configuration_attrs(attr: &str, host: &HostTarget) -> (String, String) {
    (
        format!("topologiesFromConfiguration.{attr}.{}", host.hypervisor),
        format!("guestRunnersFromConfiguration.{attr}.{}", host.hypervisor),
    )
}

/// `nix build` the wrapper's runner attr (realising kernel/initrd/erofs),
/// then `nix eval --json` its topology attr, both with `<ref>` wired in as
/// the wrapper's `target` input override. Returns the topology JSON bytes.
fn build_and_eval(
    flake_ref: &str,
    kind: TemplateKind,
    attr: &str,
    host: &HostTarget,
    wrapper_dir: &Path,
) -> Result<Vec<u8>> {
    let (topology_attr, runner_attr) = match kind {
        TemplateKind::NixosModule => module_attrs(attr, host),
        TemplateKind::NixosConfiguration => configuration_attrs(attr, host),
        TemplateKind::Topology => bail!("internal: build_and_eval called for kind `topology`, which never wraps"),
    };
    let installable = |a: &str| format!("{}#{a}", wrapper_dir.display());
    let override_args = ["--override-input", "target", flake_ref];

    let build_target = installable(&runner_attr);
    let mut build_args = vec!["build", "--no-link", "--no-write-lock-file"];
    build_args.extend(override_args);
    build_args.push(&build_target);
    let build_output = run_nix(&build_args).with_context(|| format!("spawn `nix build {build_target}`"))?;
    if !build_output.status.success() {
        bail!(
            "could not build the --flake guest ({build_target}): {}",
            summarize_nix_error(&String::from_utf8_lossy(&build_output.stderr))
        );
    }

    let eval_target = installable(&topology_attr);
    let mut eval_args = vec!["eval", "--json", "--no-write-lock-file"];
    eval_args.extend(override_args);
    eval_args.push(&eval_target);
    let eval_output = run_nix(&eval_args).with_context(|| format!("spawn `nix eval {eval_target}`"))?;
    if !eval_output.status.success() {
        bail!(
            "could not evaluate the --flake guest topology ({eval_target}): {}",
            summarize_nix_error(&String::from_utf8_lossy(&eval_output.stderr))
        );
    }
    Ok(eval_output.stdout)
}

/// The guest-wrapper flake's directory: `$SANDY_GUEST_WRAPPER` if set, else
/// this crate's manifest-relative `../../nix/guest-wrapper` (the dev-tree
/// layout `live_target::guest_flake` also assumes). A crane-built `sandy`
/// binary carries no such relative tree, so an installed binary needs
/// `$SANDY_GUEST_WRAPPER` set — refusing with a named fix rather than a
/// confusing "flake.nix not found" deep in a `nix` error.
fn guest_wrapper_dir() -> Result<PathBuf> {
    let dir = std::env::var_os("SANDY_GUEST_WRAPPER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../nix/guest-wrapper"));
    if !dir.join("flake.nix").is_file() {
        bail!(
            "sandy's guest-wrapper flake was not found at {} — set $SANDY_GUEST_WRAPPER to its directory (an \
             installed `sandy` binary does not carry the dev-tree-relative default)",
            dir.display()
        );
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::{
        HostTarget, TemplateKind, attribute_missing, configuration_attrs, direct_topology_ref, module_attrs,
        parse_kind, summarize_nix_error,
    };

    fn vfkit_host() -> HostTarget {
        HostTarget {
            hypervisor: "vfkit".to_string(),
            guest_system: "aarch64-linux".to_string(),
        }
    }

    /// Every `Display` spelling round-trips through `parse_kind`.
    #[test]
    fn kind_spellings_round_trip() {
        for kind in [
            TemplateKind::Topology,
            TemplateKind::NixosModule,
            TemplateKind::NixosConfiguration,
        ] {
            assert_eq!(parse_kind(&kind.to_string()).unwrap(), kind);
        }
    }

    /// An unrecognized `--kind` token is rejected, naming the valid ones.
    #[test]
    fn unknown_kind_is_rejected() {
        let err = parse_kind("docker-image").unwrap_err();
        assert!(err.contains("docker-image"), "{err}");
        assert!(err.contains("topology"), "{err}");
    }

    /// The exact nix wording this module classifies as "attribute absent"
    /// (confirmed against a real nix invocation, not guessed).
    #[test]
    fn attribute_missing_matches_real_nix_wording() {
        let stderr = "error: flake 'git+file:///repo?dir=fixture' does not provide attribute \
                      'packages.aarch64-darwin.topologies', 'legacyPackages.aarch64-darwin.topologies' or 'topologies'";
        assert!(attribute_missing(stderr));
    }

    /// Any other eval failure is not misclassified as "attribute absent".
    #[test]
    fn unrelated_eval_failure_is_not_attribute_missing() {
        assert!(!attribute_missing("error: infinite recursion encountered"));
        assert!(!attribute_missing(
            "error: access to absolute path '/etc/passwd' is forbidden"
        ));
    }

    /// The module-system "conflicting definition values" block is extracted
    /// verbatim, dropping nix's `… while evaluating …` stack trace above it.
    /// This is real stderr captured from booting
    /// `nix/guest-wrapper/tests/fixtures/nixos-module-hostname` against
    /// `nix/lib/guest.nix` BEFORE #325's `lib.mkForce` fix (the red state the
    /// fix resolves).
    #[test]
    fn summarize_extracts_the_conflicting_definition_block() {
        let stderr = "warning: Git tree '/repo' is dirty\nerror:\n… while evaluating attribute 'initrd'\nat \
                      /repo/nix/lib/guest.nix:171:7:\n170|       kernel = \"...\";\n171|       initrd = \
                      \"${c.microvm.initrdPath}\";\n|       ^\n(stack trace truncated; use '--show-trace' to show the \
                      full, detailed trace)\nerror: The option `networking.hostName' has conflicting definition \
                      values:\n- In `/nix/store/xxx-source/flake.nix': \"totally-not-sandy\"\n- In \
                      `/nix/store/xxx-source/flake.nix': \"sandy\"\nUse `lib.mkForce value` or `lib.mkDefault value` \
                      to change the priority on any of these definitions.";
        let summary = summarize_nix_error(stderr);
        assert!(
            summary.starts_with("error: The option `networking.hostName'"),
            "{summary}"
        );
        assert!(summary.contains("lib.mkForce"), "{summary}");
        assert!(!summary.contains("while evaluating attribute 'initrd'"), "{summary}");
    }

    /// With no "conflicting definition values" block, the last `error: …` line
    /// nix prints is returned, not the whole trace above it.
    #[test]
    fn summarize_falls_back_to_the_last_error_line() {
        let stderr = "warning: Git tree is dirty\nerror:\n  … while evaluating foo\nerror: something else broke";
        assert_eq!(summarize_nix_error(stderr), "error: something else broke");
    }

    /// Kind 1's attr is the user's own flake, auto-assembled for this host.
    #[test]
    fn direct_topology_ref_builds_the_users_own_attr() {
        assert_eq!(
            direct_topology_ref("github:acme/guest", &vfkit_host()),
            "github:acme/guest#topologies.aarch64-linux.vfkit"
        );
    }

    /// Kind 2's topology/runner attrs are nested `<attr>.<system>.<hypervisor>`,
    /// matching `topologies.<system>.<hypervisor>`'s own shape (#324).
    #[test]
    fn module_attrs_nest_by_system_then_hypervisor() {
        let (topology, runner) = module_attrs("default", &vfkit_host());
        assert_eq!(topology, "topologiesFromModule.default.aarch64-linux.vfkit");
        assert_eq!(runner, "guestRunnersFromModule.default.aarch64-linux.vfkit");
    }

    /// Kind 3 has no system component: the target's own `nixosConfigurations`
    /// already fixed it.
    #[test]
    fn configuration_attrs_have_no_system_component() {
        let (topology, runner) = configuration_attrs("default", &vfkit_host());
        assert_eq!(topology, "topologiesFromConfiguration.default.vfkit");
        assert_eq!(runner, "guestRunnersFromConfiguration.default.vfkit");
    }
}
