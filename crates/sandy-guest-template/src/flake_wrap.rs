//! Resolve an arbitrary flake with no sandy awareness at all into a bootable
//! guest (#325), shared since #332 by `sandy-cli`'s `sandy run --flake`/
//! `sandy daemon submit --flake` and `sandy-host-executor`'s remote VM
//! dispatch (the `flake/v1` manifest, see [`crate::manifest`]) — each side
//! runs [`resolve_flake_template`] against ITS OWN host, never a
//! prebuilt artifact shipped from the other.
//!
//! Four template kinds. The first three are auto-detected (or named with
//! `--kind`), always printed once resolved — never silently guessed. The
//! fourth is always-explicit, never auto-detected:
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
//! - **`devshell`** (`--from-devshell`, #326, best-effort): `<ref>` exposes `devShells.<system>.<attr>` instead of any
//!   of the above. The wrapper synthesizes a throwaway `nixosModule` from it (`buildInputs`/`nativeBuildInputs` to
//!   `environment.systemPackages`, `shellHook` appended into the guest's login shell before the READY marker) and feeds
//!   it through the same `mkGuest` seam kind 2 uses. Lossy by construction — a devShell was never designed as a NixOS
//!   module — so this path is opt-in only and always prints a best-effort warning first.
//!
//! The mechanism (kind 2/3/4): `<ref>` is wired into the wrapper flake as the
//! `target` input, overridden at invocation time
//! (`--override-input target <ref>`) rather than baked into the wrapper's own
//! lock — the one flake in the repo not meant to be evaluated with its own
//! locked default. The caller first `nix build`s the wrapper's runner attr
//! (realising the kernel/initrd/erofs store paths `mkTopology` only names,
//! matching every other boot path's build-then-eval order), then `nix eval
//! --json`s the topology attr and hands the resulting bytes to the EXISTING
//! Nix-free file branch in `crates/sandy/src/nix/topology.rs::topology` — via
//! a temp file, not a new code path there. That function stays byte-for-byte
//! unchanged; only the source this module feeds it (a prebuilt JSON file
//! instead of a live flake attr) is new.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result, bail};

use crate::host_target::{HostTarget, host_target};

/// Which of the four template kinds `--flake` resolved to (or was told to
/// force via `--kind`). `DevShell` is never produced by [`parse_kind`] — it is
/// only ever selected by `--from-devshell`, never by `--kind` (#326).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    /// The flake already exposes `topologies.<system>.<hypervisor>` itself.
    Topology,
    /// The flake exposes `nixosModules.<attr>`.
    NixosModule,
    /// The flake exposes `nixosConfigurations.<attr>`.
    NixosConfiguration,
    /// `--from-devshell`: the flake exposes `devShells.<system>.<attr>`
    /// instead, synthesized into a throwaway nixos-module (best-effort,
    /// #326).
    DevShell,
}

impl std::fmt::Display for TemplateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TemplateKind::Topology => "topology",
            TemplateKind::NixosModule => "nixos-module",
            TemplateKind::NixosConfiguration => "nixos-configuration",
            TemplateKind::DevShell => "devshell",
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
/// for `nixosModules`, `nixosConfigurations`, and (`--from-devshell`, #326)
/// `devShells`.
const DEFAULT_ATTR: &str = "default";

/// The result of resolving a `--flake` template: either the user's own
/// `topologies` attr passed straight through (kind `topology`, unchanged), or
/// a prebuilt topology JSON file sandy evaluated+built through its own
/// guest-wrapper flake (kinds `nixos-module`/`nixos-configuration`/`devshell`).
pub enum ResolvedTemplate {
    /// Hand straight to the existing flake-attr path
    /// (`crates/sandy/src/nix/topology.rs::topology`'s `nix eval` branch) —
    /// no wrapper, no prebuild, exactly today's behaviour.
    Direct(String),
    /// A prebuilt topology JSON file; `path` is what `JobPlan::template`
    /// becomes (the existing Nix-free file branch reads it). `_kept` holds
    /// the temp file open for the life of the run — it must outlive the
    /// backend's `topology()` read, so the caller keeps it in scope across
    /// the whole dispatch, not just this function.
    Prebuilt {
        /// The temp file path, as a `String` for `JobPlan::template`.
        path: String,
        /// Deletes the file on drop; keep this alive until the run completes.
        _kept: tempfile::TempPath,
    },
}

/// Resolve `--flake <flake_ref>` (with optional `--kind`/`--attr` overrides,
/// or `--from-devshell` for kind `devshell`, #326) into a [`ResolvedTemplate`],
/// printing the kind it picked (or was told) to stderr before doing anything
/// else — `--flake` never silently guesses. When `from_devshell` is set, the
/// best-effort warning is printed first, before any `nix` call, so it is on
/// stderr even when the probe or build that follows fails.
///
/// `mac_prereq_check` is called (only on a macOS host, for kinds 2/3/4) to
/// decide whether this host's vfkit/linux-builder prerequisites are met;
/// `Some(message)` refuses with that message, `None` proceeds. Injected
/// rather than hardcoded so this crate never depends on a caller's own
/// `doctor` module: `sandy-cli` passes its real macOS prereq check,
/// `sandy-host-executor` passes a check that never fires (dead code on its
/// Linux build target, since `cfg!(target_os = "macos")` is false there).
///
/// `deadline` bounds every `nix` call this makes (kind-detection probes,
/// then the wrapper's build+eval) as ONE shared budget (#332, CodeRabbit
/// finding on PR #333) — `sandy-cli`'s local `--flake`/`daemon submit
/// --flake` pass `None`, preserving today's unbounded behavior exactly;
/// `sandy-host-executor`'s remote VM dispatch passes a real deadline, since
/// an unresponsive git remote or a stalled substituter would otherwise block
/// its sequential dispatch loop forever.
///
/// # Errors
/// Returns an error naming what was checked when no kind is detected, when a
/// forced `--kind`/`--attr` (or `--from-devshell`'s own attr) names an attr
/// the flake does not have, when `mac_prereq_check` refuses, when `deadline`
/// passes before a `nix` call finishes, or when the wrapper's `nix build`/
/// `nix eval` fails (the module-system conflict case is summarized, not
/// dumped as a raw stack trace).
pub fn resolve_flake_template(
    flake_ref: &str,
    kind: Option<&str>,
    attr: Option<&str>,
    from_devshell: bool,
    mac_prereq_check: impl FnOnce() -> Option<String>,
    deadline: Option<std::time::Instant>,
) -> Result<ResolvedTemplate> {
    let host = host_target();
    let (kind, resolved_attr) = if from_devshell {
        if kind.is_some() {
            bail!("--from-devshell cannot be combined with --kind");
        }
        // Printed before `detect_devshell`'s own `nix eval` probe, so it is
        // never silently skipped by an early failure (#326's own acceptance
        // bar: the warning fires on every invocation, not only a successful
        // one).
        eprintln!(
            "sandy: best-effort: synthesizing a nixos-module from --from-devshell — a devShell's shellHook assumes an \
             interactive shell, the host checkout's cwd, and inherited host env, none of which carry over identically \
             into the guest's login shell"
        );
        let resolved_attr = attr.unwrap_or(DEFAULT_ATTR).to_string();
        detect_devshell(flake_ref, &resolved_attr, &host, deadline)?;
        (TemplateKind::DevShell, resolved_attr)
    } else {
        let forced = kind
            .map(|k| parse_kind(k).map_err(|e| anyhow::anyhow!(e)))
            .transpose()?;
        detect_kind(flake_ref, forced, attr, &host, deadline)?
    };
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
        TemplateKind::NixosModule | TemplateKind::NixosConfiguration | TemplateKind::DevShell => {
            if cfg!(target_os = "macos")
                && let Some(message) = mac_prereq_check()
            {
                bail!("{message}");
            }
            let wrapper_root = guest_wrapper_root()?;
            let json = build_and_eval(flake_ref, kind, &resolved_attr, &host, &wrapper_root, deadline)?;
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
    deadline: Option<std::time::Instant>,
) -> Result<(TemplateKind, String)> {
    let attr = attr_override.unwrap_or(DEFAULT_ATTR);
    match forced {
        Some(TemplateKind::Topology) => match detect_topology(flake_ref, host, deadline)? {
            true => Ok((TemplateKind::Topology, String::new())),
            false => bail!(
                "--kind topology forced, but `{flake_ref}` has no `topologies.{}.{}`",
                host.guest_system,
                host.hypervisor
            ),
        },
        Some(TemplateKind::NixosModule) => match probe_attr_present(flake_ref, "nixosModules", attr, deadline)? {
            true => Ok((TemplateKind::NixosModule, attr.to_string())),
            false => bail!("--kind nixos-module forced, but `{flake_ref}` has no `nixosModules.{attr}`"),
        },
        Some(TemplateKind::NixosConfiguration) => {
            match probe_attr_present(flake_ref, "nixosConfigurations", attr, deadline)? {
                true => Ok((TemplateKind::NixosConfiguration, attr.to_string())),
                false => {
                    bail!("--kind nixos-configuration forced, but `{flake_ref}` has no `nixosConfigurations.{attr}`")
                }
            }
        }
        // `parse_kind` never returns `DevShell` (there is no `--kind devshell`
        // spelling; `--from-devshell` is the only way in, and it bypasses
        // this function entirely) — unreachable in practice, named rather
        // than panicked in case that ever changes.
        Some(TemplateKind::DevShell) => {
            bail!("--kind devshell is not a valid --kind value; pass --from-devshell instead")
        }
        // Auto-detect, in the issue's own priority order. `detect_topology`
        // bails (rather than returning `false`) when `topologies` exists but
        // lacks this host's system/hypervisor row — a real match that just
        // can't boot here must refuse, not silently fall through to kind 2.
        None => {
            if detect_topology(flake_ref, host, deadline)? {
                return Ok((TemplateKind::Topology, String::new()));
            }
            if probe_attr_present(flake_ref, "nixosModules", attr, deadline)? {
                return Ok((TemplateKind::NixosModule, attr.to_string()));
            }
            if probe_attr_present(flake_ref, "nixosConfigurations", attr, deadline)? {
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
fn detect_topology(flake_ref: &str, host: &HostTarget, deadline: Option<std::time::Instant>) -> Result<bool> {
    let Some(systems) = probe_attr_names(flake_ref, "topologies", deadline)? else {
        return Ok(false);
    };
    if !systems.iter().any(|s| s == &host.guest_system) {
        bail!(
            "`{flake_ref}` exposes `topologies` but not for this host's guest system `{}` (has: {})",
            host.guest_system,
            systems.join(", ")
        );
    }
    let hypervisors = probe_attr_names(flake_ref, &format!("topologies.{}", host.guest_system), deadline)?
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

/// `--from-devshell`'s own probe: whether `flake_ref` exposes
/// `devShells.<host.guest_system>.<attr>` — never part of auto-detection
/// (#326's flag is always-explicit), so this is only ever called from the
/// `from_devshell` branch of [`resolve_flake_template`], not from
/// [`detect_kind`].
///
/// # Errors
/// Bails naming what was checked: no `devShells` at all, `devShells` but not
/// for this host's guest system, or that system's `devShells` but not
/// `attr`.
fn detect_devshell(flake_ref: &str, attr: &str, host: &HostTarget, deadline: Option<std::time::Instant>) -> Result<()> {
    let Some(systems) = probe_attr_names(flake_ref, "devShells", deadline)? else {
        bail!("--from-devshell: `{flake_ref}` exposes no `devShells` at all");
    };
    if !systems.iter().any(|s| s == &host.guest_system) {
        bail!(
            "--from-devshell: `{flake_ref}` exposes `devShells` but not for this host's guest system `{}` (has: {})",
            host.guest_system,
            systems.join(", ")
        );
    }
    if !probe_attr_present(flake_ref, &format!("devShells.{}", host.guest_system), attr, deadline)? {
        bail!(
            "--from-devshell: `{flake_ref}` has no `devShells.{}.{attr}`",
            host.guest_system
        );
    }
    Ok(())
}

/// Whether `flake_ref#<top>.<attr>` exists (`top` is `nixosModules`,
/// `nixosConfigurations`, or (via [`detect_devshell`]) `devShells.<system>`).
fn probe_attr_present(flake_ref: &str, top: &str, attr: &str, deadline: Option<std::time::Instant>) -> Result<bool> {
    Ok(probe_attr_names(flake_ref, top, deadline)?.is_some_and(|names| names.iter().any(|n| n == attr)))
}

/// List `flake_ref#<path>`'s attr names (lazy — forces no derivation,
/// matching the structure-only check `nix flake show` does, just scoped to
/// one subtree). `Ok(None)` means the attr itself does not exist (nix's own
/// "does not provide attribute" wording); any other failure (network, a real
/// eval error elsewhere in the flake, …) surfaces as `Err`, unclassified.
fn probe_attr_names(flake_ref: &str, path: &str, deadline: Option<std::time::Instant>) -> Result<Option<Vec<String>>> {
    let installable = format!("{flake_ref}#{path}");
    let output = run_nix(
        &[
            "eval",
            "--json",
            "--no-write-lock-file",
            &installable,
            "--apply",
            "builtins.attrNames",
        ],
        deadline,
    )
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
    // Nix indents the final cause under a `--show-trace`-less trace (e.g.
    // `       error: sandy: …`), so a plain `rfind("\nerror:")` only catches
    // an unindented header line (typically the top-level one right after a
    // `warning:`) and returns the truncated trace above the real message.
    // Take the last line that is an `error:` carrying a message, plus
    // whatever nix printed after it.
    let lines: Vec<&str> = stderr.lines().collect();
    if let Some(pos) = lines.iter().rposition(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("error:") && trimmed.trim_end() != "error:"
    }) {
        return lines[pos..]
            .iter()
            .map(|line| line.trim())
            .collect::<Vec<_>>()
            .join("\n");
    }
    stderr.trim().to_string()
}

/// `nix <args>`, captured (not inherited) so stdout stays the pure data
/// channel (`sandy -o json run` parses it as the result envelope) and stderr
/// is ours to summarize on failure. `deadline` is an absolute instant, not a
/// per-call duration — a caller that makes several of these (kind-detection
/// probes, then build, then eval) shares ONE overall budget instead of
/// getting N times the timeout. `None` waits forever, `sandy run --flake`'s
/// existing unbounded behavior (#332, CodeRabbit finding on PR #333: an
/// unresponsive git remote or a stalled substituter used to block the
/// REMOTE host-executor's sequential dispatch loop indefinitely — no
/// `JobResult` ever sent, so the job stayed `Running` forever with no
/// terminal outcome).
///
/// # Errors
/// An I/O fault spawning or waiting on the child, or `ErrorKind::TimedOut` if
/// `deadline` passes before it exits (the child, and its whole process
/// group, are killed first).
fn run_nix(args: &[&str], deadline: Option<std::time::Instant>) -> std::io::Result<Output> {
    let mut command = Command::new(nix_bin());
    command.args(args);
    run_with_deadline(command, deadline)
}

/// `SANDY_NIX_BIN`, falling back to a bare `nix` (`PATH` lookup) — the same
/// escape hatch `impls/vm`'s `SANDY_QEMU_BIN`/`SANDY_VIRTIOFSD_BIN` give
/// their own subprocess spawns, needed on a host whose environment setup
/// (PAM, systemd session handling, etc.) does not reliably carry the unit's
/// own `Environment=PATH=` through to the spawned child — confirmed on ws01
/// (#335 follow-up). Exported so `sandy-host-executor`'s capability probe
/// checks the exact same override this call does, never a probe/dispatch-time
/// definition drift.
#[must_use]
pub fn nix_bin() -> String {
    std::env::var("SANDY_NIX_BIN").unwrap_or_else(|_| "nix".to_string())
}

/// Spawn `command` with piped stdout/stderr (drained on dedicated threads,
/// concurrently with waiting — never inherited, since callers need the
/// bytes captured for JSON parsing / error summaries), killing it if
/// `deadline` passes before it exits on its own. See [`run_nix`] for why
/// `deadline` is absolute.
///
/// Its own process group: a killed `nix` can leave a `sh -c`/
/// single-user-build grandchild alive, still holding the stdout/stderr pipe
/// write-ends open — draining those would otherwise block the caller
/// forever even though `nix` itself already exited. Killing the whole group
/// on timeout closes them too. On the timeout path, the drain threads are
/// deliberately NOT joined (nothing needs their output, and a grandchild
/// that somehow survives the group kill must never make this call itself
/// hang).
fn run_with_deadline(mut command: Command, deadline: Option<std::time::Instant>) -> std::io::Result<Output> {
    use std::{io::Read as _, os::unix::process::CommandExt as _, process::Stdio};

    // `Stdio::null()` for stdin, always: `Command::output()` (what this
    // replaces) defaults stdin to null, and a nix child silently inheriting
    // this process's own stdin could block waiting for input that will
    // never come, in the unbounded (`deadline: None`) local-run case where
    // nothing enforces a timeout to kill it. `process_group(0)` only when a
    // deadline is actually in play (CodeRabbit on this PR): it's the kill
    // path's own mechanism (the whole group, not just the direct child, so a
    // nix subprocess's own children are also reaped on expiry) and has no
    // reason to run for `sandy run --flake`'s unbounded local path, which
    // never calls the kill branch below at all.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if deadline.is_some() {
        command.process_group(0);
    }
    let mut child = command.spawn()?;

    // `child.stdout`/`child.stderr` are only ever `None` if a caller already
    // took them, or never requested `Stdio::piped()` — neither is possible
    // here (this function owns `child` exclusively and just set both above),
    // but a house rule (never `.expect()`/`.unwrap()` in library code) still
    // rules out treating that as unreachable.
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("child's stdout was not piped"))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("child's stderr was not piped"))?;
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            return Ok(Output { status, stdout, stderr });
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            let _ = child.wait(); // reap; the exit status itself is moot (killed)
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "nix timed out and was killed",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
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

/// The wrapper's `topologiesFromDevShell`/`guestRunnersFromDevShell` attr
/// paths for one `devShells.<attr>` (#326). Nested `<attr>.<system>.
/// <hypervisor>`, matching `topologiesFromModule`'s own shape — a devShell is
/// looked up by system like `nixosModules`/`topologies` are, unlike a
/// `nixosConfiguration` which already fixes its own system.
fn devshell_attrs(attr: &str, host: &HostTarget) -> (String, String) {
    (
        format!(
            "topologiesFromDevShell.{attr}.{}.{}",
            host.guest_system, host.hypervisor
        ),
        format!(
            "guestRunnersFromDevShell.{attr}.{}.{}",
            host.guest_system, host.hypervisor
        ),
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
    wrapper_root: &Path,
    deadline: Option<std::time::Instant>,
) -> Result<Vec<u8>> {
    let (topology_attr, runner_attr) = match kind {
        TemplateKind::NixosModule => module_attrs(attr, host),
        TemplateKind::NixosConfiguration => configuration_attrs(attr, host),
        TemplateKind::DevShell => devshell_attrs(attr, host),
        TemplateKind::Topology => bail!("internal: build_and_eval called for kind `topology`, which never wraps"),
    };
    // `?dir=nix/guest-wrapper`, not a plain `{wrapper_root}/nix/guest-wrapper`
    // path: see `guest_wrapper_root`'s doc for why the installable has to
    // name the ROOT nix walks its flake-source resolution from, not the
    // wrapper subdirectory directly.
    let installable = |a: &str| format!("{}?dir=nix/guest-wrapper#{a}", wrapper_root.display());
    let override_args = ["--override-input", "target", flake_ref];

    let build_target = installable(&runner_attr);
    let mut build_args = vec!["build", "--no-link", "--no-write-lock-file"];
    build_args.extend(override_args);
    build_args.push(&build_target);
    let build_output = run_nix(&build_args, deadline).with_context(|| format!("spawn `nix build {build_target}`"))?;
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
    let eval_output = run_nix(&eval_args, deadline).with_context(|| format!("spawn `nix eval {eval_target}`"))?;
    if !eval_output.status.success() {
        bail!(
            "could not evaluate the --flake guest topology ({eval_target}): {}",
            summarize_nix_error(&String::from_utf8_lossy(&eval_output.stderr))
        );
    }
    Ok(eval_output.stdout)
}

/// The root `$SANDY_GUEST_WRAPPER` names if set, else this crate's
/// manifest-relative `../..` (the dev-tree repo root). NOT the
/// `nix/guest-wrapper` directory itself (#332, CodeRabbit finding on PR
/// #333): `nix/guest-wrapper/flake.nix` imports `../lib/guest.nix` and
/// `../overlays/sandy-agent.nix` by plain relative path, and
/// `nix/overlays/lib.nix` in turn sources `Cargo.toml`/`Cargo.lock`/
/// `crates`/`impls` from two levels further up — packaging just the
/// `guest-wrapper` subdirectory on its own (no enclosing `.git`, so nix has
/// no wider tree to walk up to) leaves those imports unreachable
/// (`access to absolute path '…/lib/guest.nix' is forbidden in pure
/// evaluation mode`, confirmed empirically against a real packaged copy).
/// Naming the ROOT here, and building every installable as `{root}?dir=…`
/// (see [`build_and_eval`]), keeps the whole tree inside the one nix source
/// `path:` resolves, whether that root is this dev checkout's `.git` or a
/// packaged, git-less copy. A crane-built `sandy`/`sandy-host-executor`
/// binary carries no such relative tree at all, so an installed binary needs
/// `$SANDY_GUEST_WRAPPER` set — refusing with a named fix rather than a
/// confusing "flake.nix not found" deep in a `nix` error.
fn guest_wrapper_root() -> Result<PathBuf> {
    let root = std::env::var_os("SANDY_GUEST_WRAPPER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    if !root.join("nix/guest-wrapper/flake.nix").is_file() {
        bail!(
            "sandy's guest-wrapper flake was not found under {} (expected nix/guest-wrapper/flake.nix there) — set \
             $SANDY_GUEST_WRAPPER to the root that contains it (an installed binary does not carry the \
             dev-tree-relative default)",
            root.display()
        );
    }
    Ok(root)
}

/// Whether [`guest_wrapper_root`] resolves to a real, usable guest-wrapper
/// flake on this host (#332, CodeRabbit finding on PR #333) — the same "try
/// the real thing" discipline `sandy-host-executor::capability`'s own probes
/// apply to qemu/kvm/vhost-vsock. Public so `detect_vm_capability` can fold
/// it into its verdict: declaring `SandboxKind::Vm` on a host whose package
/// does not ship `nix/guest-wrapper` (or never set `$SANDY_GUEST_WRAPPER`)
/// would advertise a capability this host cannot actually service — a VM
/// dispatch would reach [`resolve_flake_template`], fall back to the
/// build-time `CARGO_MANIFEST_DIR` default, and fail there instead of at
/// placement.
#[must_use]
pub fn guest_wrapper_present() -> bool {
    guest_wrapper_root().is_ok()
}

#[cfg(test)]
mod tests {
    use super::{
        HostTarget, TemplateKind, attribute_missing, configuration_attrs, devshell_attrs, direct_topology_ref,
        module_attrs, parse_kind, summarize_nix_error,
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

    /// Real nix traces indent the final cause (`       error: …`), not column
    /// 0 — a plain `rfind("\nerror:")` only matches the empty top-level
    /// header right after the `warning:` line and returns the truncated
    /// trace above the real message. This is the kind-3 wrong-hypervisor
    /// `throw` (#325) as it actually appears under a trace.
    #[test]
    fn summarize_matches_an_indented_final_error_line() {
        let stderr = "warning: Git tree '/repo' is dirty\nerror:\n       … while evaluating the attribute 'x'\n       \
                      at /repo/flake.nix:10:5:\n\n       error: sandy: nixosConfigurations.default targets system \
                      aarch64-linux, but hypervisor qemu needs a x86_64-linux guest — pick a configuration that \
                      targets x86_64-linux, or a hypervisor matching aarch64-linux";
        let summary = summarize_nix_error(stderr);
        assert!(
            summary.starts_with("error: sandy: nixosConfigurations.default targets system aarch64-linux"),
            "{summary}"
        );
        assert!(summary.ends_with("hypervisor matching aarch64-linux"), "{summary}");
        assert!(!summary.contains("while evaluating"), "{summary}");
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

    /// Kind 4 (devshell, #326) is nested by system like kind 2, not
    /// system-free like kind 3.
    #[test]
    fn devshell_attrs_nest_by_system_then_hypervisor() {
        let (topology, runner) = devshell_attrs("default", &vfkit_host());
        assert_eq!(topology, "topologiesFromDevShell.default.aarch64-linux.vfkit");
        assert_eq!(runner, "guestRunnersFromDevShell.default.aarch64-linux.vfkit");
    }

    /// `devshell` is `TemplateKind::DevShell`'s `Display` spelling — it does
    /// NOT round-trip through `parse_kind` (`--kind devshell` is not a valid
    /// token; `--from-devshell` is the only way in, #326).
    #[test]
    fn devshell_display_does_not_round_trip_through_parse_kind() {
        assert_eq!(TemplateKind::DevShell.to_string(), "devshell");
        assert!(parse_kind("devshell").is_err());
    }

    // ---- `run_with_deadline` (#332, CodeRabbit finding on PR #333) ----

    use std::{
        process::Command,
        time::{Duration, Instant},
    };

    use super::run_with_deadline;

    /// `Command::new(..).args(..)` returns `&mut Command`, but
    /// `run_with_deadline` takes an owned one (it spawns from inside a
    /// `loop`, so it can't borrow) — this just builds it in two statements
    /// instead of making every call site do so.
    fn cmd(program: &str, args: &[&str]) -> Command {
        let mut command = Command::new(program);
        command.args(args);
        command
    }

    /// A `None` deadline preserves `sandy run --flake`'s existing unbounded
    /// behavior: a normal, fast command still returns its real output.
    #[test]
    fn no_deadline_still_returns_output() -> anyhow::Result<()> {
        let output = run_with_deadline(cmd("echo", &["hi"]), None)?;
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hi");
        Ok(())
    }

    /// The regression this finding is about: an unbounded `nix` call used to
    /// block forever. A command that would otherwise run far longer than its
    /// deadline is killed and reported as `ErrorKind::TimedOut`, promptly —
    /// not only eventually.
    #[test]
    fn a_hanging_command_is_killed_at_its_deadline() {
        let start = Instant::now();
        let err = run_with_deadline(cmd("sleep", &["30"]), Some(Instant::now() + Duration::from_millis(200)))
            .expect_err("a 30s sleep must not complete within a 200ms deadline");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "killing the child must not itself block for anywhere near the original 30s, took {:?}",
            start.elapsed()
        );
    }

    /// Proves the process-GROUP kill, not just the direct child: a shell
    /// grandchild that outlives its immediate parent (the classic `nix`
    /// single-user-build shape) must still be reaped by the deadline, rather
    /// than leaving the drain threads blocked on its still-open stdout/stderr
    /// pipe write-ends forever.
    #[test]
    fn a_grandchild_holding_the_pipes_is_also_killed() {
        let start = Instant::now();
        let err = run_with_deadline(
            cmd("sh", &["-c", "sleep 30 & wait"]),
            Some(Instant::now() + Duration::from_millis(200)),
        )
        .expect_err("a grandchild sleeping for 30s must not complete within a 200ms deadline");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "took {:?}, the grandchild must not have kept the drain threads blocked",
            start.elapsed()
        );
    }

    /// A generous deadline that the command finishes well within still
    /// drains and returns every byte — proves the concurrent drain threads
    /// (not just the timeout path) work correctly for real output volume.
    #[test]
    fn a_generous_deadline_still_drains_full_output() -> anyhow::Result<()> {
        let output = run_with_deadline(
            cmd("head", &["-c", "200000", "/dev/zero"]),
            Some(Instant::now() + Duration::from_secs(30)),
        )?;
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 200_000);
        Ok(())
    }
}
