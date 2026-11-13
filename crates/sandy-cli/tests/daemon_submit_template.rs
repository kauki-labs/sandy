//! `sandy daemon submit TEMPLATE` and its flags (manifest-parity A3, #483), at the process boundary. Every case is a
//! client-side decision made before a connection is opened, so no daemon runs: the socket path is a dead one.

use std::process::{Command, Output};

use anyhow::Context;

fn submit(home: &std::path::Path, args: &[&str]) -> anyhow::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_HOME", home)
        .env("SANDY_SOCK", home.join("no-daemon.sock"))
        .args(["daemon", "submit"])
        .args(args)
        .output()
        .context("running sandy daemon submit")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `REF#topologies.<system>.<hypervisor>` is the flake `REF` (owner ruling on #483): accepted client-side, with a note
/// that the executor picks its own system and hypervisor. Only the missing daemon fails.
#[test]
fn a_template_with_a_topology_attr_is_accepted_with_a_note() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let out = submit(
        home.path(),
        &["./guest#topologies.x86_64-linux.qemu", "--isolation-class", "trusted"],
    )?;
    let text = stderr(&out);
    assert_ne!(out.status.code(), Some(2), "not a usage error: {text}");
    assert!(text.contains("its own system and hypervisor"), "{text}");
    Ok(())
}

/// A `#` attr that is not a topology is refused, naming the template forms and `--flake`.
#[test]
fn a_template_with_another_attr_is_refused_naming_flake() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let out = submit(
        home.path(),
        &["./guest#nixosConfigurations.dev", "--isolation-class", "trusted"],
    )?;
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        text.contains("topologies.<system>.<hypervisor>") && text.contains("--flake"),
        "{text}"
    );
    Ok(())
}

/// A positional that names an existing file, without `--manifest-encoding`, is a forgotten flag, not a flake lookup.
#[test]
fn an_existing_file_without_a_manifest_encoding_is_refused_not_looked_up() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let manifest = home.path().join("manifest.bin");
    std::fs::write(&manifest, b"x").context("manifest")?;
    let out = submit(
        home.path(),
        &[manifest.to_str().context("utf8")?, "--isolation-class", "trusted"],
    )?;
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        text.contains("looks like a manifest file") && text.contains("--manifest-encoding"),
        "{text}"
    );
    Ok(())
}

/// A template with every plain flag is accepted client-side: the only failure is the missing daemon.
#[test]
fn a_template_with_the_plain_flags_is_accepted_and_only_the_daemon_is_missing() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let out = submit(
        home.path(),
        &[
            "github:acme/guest",
            "--isolation-class",
            "untrusted",
            "--env",
            "A=1",
            "--cpu",
            "2",
            "--mem",
            "1024",
            "--timeout",
            "60",
            "--",
            "echo",
            "hi",
        ],
    )?;
    let text = stderr(&out);
    assert_ne!(
        out.status.code(),
        Some(2),
        "a valid template is not a usage error: {text}"
    );
    assert!(!text.contains("required arguments"), "{text}");
    Ok(())
}

/// A malformed `--env` with a template is refused as an input error, before any connection.
#[test]
fn a_malformed_env_with_a_template_is_an_input_error() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let out = submit(
        home.path(),
        &["github:acme/guest", "--isolation-class", "trusted", "--env", "NOEQUALS"],
    )?;
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    Ok(())
}

/// The plain flags describe a template or `--flake` job. With a manifest file they would be dropped, so they are
/// refused.
#[test]
fn a_plain_flag_with_a_manifest_file_is_refused() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let manifest = home.path().join("manifest.bin");
    std::fs::write(&manifest, b"x").context("manifest")?;
    let out = submit(
        home.path(),
        &[
            manifest.to_str().context("utf8")?,
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "--cpu",
            "2",
        ],
    )?;
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("only apply to a template or --flake"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

/// `--from-devshell` is a flake kind: alone, or with a template, it is refused client-side, never ignored.
#[test]
fn from_devshell_without_a_flake_is_refused() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    for args in [
        vec!["--from-devshell", "--isolation-class", "trusted"],
        vec!["github:acme/guest", "--from-devshell", "--isolation-class", "trusted"],
    ] {
        let out = submit(home.path(), &args)?;
        assert_ne!(out.status.code(), Some(0), "{args:?}");
        let text = stderr(&out);
        assert!(
            text.contains("--flake") || text.contains("cannot be used with"),
            "{args:?}: {text}"
        );
    }
    Ok(())
}

/// `--from-devshell` with `--flake` is accepted client-side.
#[test]
fn from_devshell_with_a_flake_is_accepted() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let out = submit(
        home.path(),
        &[
            "--flake",
            "github:acme/guest",
            "--from-devshell",
            "--isolation-class",
            "trusted",
        ],
    )?;
    let text = stderr(&out);
    assert_ne!(out.status.code(), Some(2), "{text}");
    assert!(!text.contains("unexpected argument"), "{text}");
    Ok(())
}

/// A path flake (a directory) is the commonest local TEMPLATE: it is not a manifest file and must reach the daemon
/// step, not be refused as one.
#[test]
fn a_directory_template_is_not_taken_for_a_manifest_file() -> anyhow::Result<()> {
    let home = tempfile::tempdir().context("home")?;
    let flake = home.path().join("guest");
    std::fs::create_dir(&flake).context("flake dir")?;
    std::fs::write(flake.join("flake.nix"), b"{}").context("flake.nix")?;
    let out = submit(
        home.path(),
        &[flake.to_str().context("utf8")?, "--isolation-class", "trusted"],
    )?;
    let text = stderr(&out);
    assert!(!text.contains("looks like a manifest file"), "{text}");
    assert_ne!(
        out.status.code(),
        Some(2),
        "a directory template is not a usage error: {text}"
    );
    Ok(())
}
