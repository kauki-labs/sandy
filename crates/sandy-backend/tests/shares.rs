//! Integration tests for the input/output shares (#34): staging wired through to
//! the real hypervisor argv.
//!
//! Tier-2 (CI, no hypervisor, not behind the `live` feature). These sit between the
//! `sandy::stage::*` unit tests (each function alone) and the host-gated live
//! round-trips (`sandy-cli/tests/live_{inputs,outputs}.rs`, a real boot): they
//! stage real directories, build the `StagedArgs` the backend `run` would, and
//! assert the **read-only vs read-write distinction and the mount tags reach the
//! actual `qemu_args` / `vfkit_args` command** — the one thing neither the unit
//! tests nor a non-live CI run otherwise prove.

use anyhow::{Context, Result};
use sandy::{
    Grants, INPUT_MOUNT_TAG, Input, OUTPUT_MOUNT_TAG, Output, RunSpec, SECRET_MOUNT_TAG, Topology, collect_outputs,
    parse_topology, prepare_outputs, stage_inputs,
};
use sandy_backend::{QemuStagedArgs, VfkitStagedArgs, qemu_args, vfkit_args};

const QEMU_FIXTURE: &[u8] = include_bytes!("fixtures/topology-x86_64.json");
const VFKIT_FIXTURE: &[u8] = include_bytes!("fixtures/topology-aarch64.json");

const GRANTS: Grants = Grants {
    secrets: true,
    agent: false,
    shares: true,
};

/// A minimal spec: the assemblers read only `cpu`/`mem`/`command`/`template` from
/// it — the shares come from `StagedArgs`, so the spec's own input/output/secret
/// slices are empty here.
fn spec<'a>(command: &'a [String]) -> RunSpec<'a> {
    RunSpec {
        template: "demo",
        command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: &GRANTS,
        outcome_file: None,
        secret_dir: None,
    }
}

fn qemu_topo() -> Topology {
    parse_topology(QEMU_FIXTURE).expect("parse qemu fixture")
}

fn vfkit_topo() -> Topology {
    parse_topology(VFKIT_FIXTURE).expect("parse vfkit fixture")
}

/// The argv token carrying `needle` (e.g. a mount tag), or a panic naming the argv.
fn share_arg<'a>(args: &'a [String], needle: &str) -> &'a str {
    args.iter()
        .find(|a| a.contains(needle))
        .unwrap_or_else(|| panic!("no argv token contains {needle:?} in {args:?}"))
}

/// A share descriptor as the backend `run` builds it: read-only carries a trailing
/// `,ro`, writable does not.
fn descriptor(dir: &std::path::Path, tag: &str, ro: bool) -> String {
    let base = format!("sharedDir={},mountTag={tag}", dir.display());
    if ro { format!("{base},ro") } else { base }
}

// ---- inputs -------------------------------------------------------------------

/// I1 — qemu: a staged input is woven into the argv as a read-only virtio share
/// (`mount_tag=sandy-inputs` + `readonly=on`).
#[test]
fn qemu_input_share_is_read_only() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let inputs_dir = tmp.path().join("inputs");
    std::fs::write(tmp.path().join("f"), b"in")?;
    let n = stage_inputs(
        &[Input {
            host: tmp.path().join("f"),
            name: "data".to_string(),
        }],
        &inputs_dir,
    )?;
    assert_eq!(n, 1);
    assert_eq!(
        std::fs::read(inputs_dir.join("data"))?,
        b"in",
        "input staged under its name"
    );

    let staged = QemuStagedArgs {
        input_share: Some(descriptor(&inputs_dir, INPUT_MOUNT_TAG, true)),
        ..Default::default()
    };
    let args = qemu_args(&qemu_topo(), &spec(&["true".to_string()]), &staged).context("qemu_args")?;

    let arg = share_arg(&args, &format!("mount_tag={INPUT_MOUNT_TAG}"));
    assert!(arg.contains("readonly=on"), "qemu input share must be read-only: {arg}");
    Ok(())
}

/// I2 — vfkit: a staged input is a virtio-fs device at `mountTag=sandy-inputs`
/// with the `,ro` stripped (vfkit rejects it; the guest enforces RO).
#[test]
fn vfkit_input_share_strips_ro() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let inputs_dir = tmp.path().join("inputs");
    std::fs::write(tmp.path().join("f"), b"in")?;
    stage_inputs(
        &[Input {
            host: tmp.path().join("f"),
            name: "data".to_string(),
        }],
        &inputs_dir,
    )?;

    let staged = VfkitStagedArgs::new(vec![], vec![descriptor(&inputs_dir, INPUT_MOUNT_TAG, true)], vec![]);
    let args = vfkit_args(&vfkit_topo(), &spec(&["true".to_string()]), &staged).context("vfkit_args")?;

    let arg = share_arg(&args, &format!("mountTag={INPUT_MOUNT_TAG}"));
    assert!(arg.starts_with("virtio-fs,"), "input is a virtio-fs device: {arg}");
    assert!(!arg.ends_with(",ro"), "vfkit must strip the trailing ,ro: {arg}");
    Ok(())
}

/// I3 — a nonexistent host input path fails closed with a named error, never a
/// silent skip.
#[test]
fn missing_host_input_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let err = stage_inputs(
        &[Input {
            host: tmp.path().join("does-not-exist"),
            name: "data".to_string(),
        }],
        &tmp.path().join("inputs"),
    );
    assert!(err.is_err(), "a missing host input path must be a hard error");
}

// ---- outputs ------------------------------------------------------------------

/// O1 — qemu: a prepared output is woven in writable (`mount_tag=sandy-outputs`,
/// no `readonly=on`), unlike the inputs/secret shares.
#[test]
fn qemu_output_share_is_writable() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let outputs_dir = tmp.path().join("outputs");
    prepare_outputs(
        &[Output {
            name: Some("result".to_string()),
            dest: tmp.path().join("dest"),
        }],
        &outputs_dir,
    )?;

    let staged = QemuStagedArgs {
        output_share: Some(descriptor(&outputs_dir, OUTPUT_MOUNT_TAG, false)),
        ..Default::default()
    };
    let args = qemu_args(&qemu_topo(), &spec(&["true".to_string()]), &staged).context("qemu_args")?;

    let arg = share_arg(&args, &format!("mount_tag={OUTPUT_MOUNT_TAG}"));
    assert!(
        !arg.contains("readonly=on"),
        "qemu output share must be writable: {arg}"
    );
    Ok(())
}

/// O2 — vfkit: the output share is a virtio-fs device at `mountTag=sandy-outputs`
/// with no `,ro` (writable).
#[test]
fn vfkit_output_share_is_writable() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let outputs_dir = tmp.path().join("outputs");
    prepare_outputs(
        &[Output {
            name: Some("result".to_string()),
            dest: tmp.path().join("dest"),
        }],
        &outputs_dir,
    )?;

    let staged = VfkitStagedArgs::new(vec![], vec![], vec![descriptor(&outputs_dir, OUTPUT_MOUNT_TAG, false)]);
    let args = vfkit_args(&vfkit_topo(), &spec(&["true".to_string()]), &staged).context("vfkit_args")?;

    let arg = share_arg(&args, &format!("mountTag={OUTPUT_MOUNT_TAG}"));
    assert!(!arg.ends_with(",ro"), "vfkit output share is writable (no ,ro): {arg}");
    Ok(())
}

/// O3 — collection round-trip: both a named subtree and a catch-all (whole output
/// dir) are collected to their host dests, as the backend does after boot.
#[test]
fn outputs_collect_named_and_catch_all() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let outputs_dir = tmp.path().join("outputs");
    let named_dest = tmp.path().join("named-dest");
    let all_dest = tmp.path().join("all-dest");
    let outputs = [
        Output {
            name: Some("result".to_string()),
            dest: named_dest.clone(),
        },
        Output {
            name: None,
            dest: all_dest.clone(),
        },
    ];
    prepare_outputs(&outputs, &outputs_dir)?;

    // The "guest" writes a named subtree and a loose root file.
    std::fs::write(outputs_dir.join("result").join("r"), b"named")?;
    std::fs::write(outputs_dir.join("loose"), b"root")?;

    collect_outputs(&outputs, &outputs_dir)?;

    assert_eq!(
        std::fs::read(named_dest.join("r"))?,
        b"named",
        "named subtree collected"
    );
    // Catch-all sees both the named subtree and the loose file under the root.
    assert_eq!(
        std::fs::read(all_dest.join("loose"))?,
        b"root",
        "catch-all collected the loose file"
    );
    assert_eq!(
        std::fs::read(all_dest.join("result").join("r"))?,
        b"named",
        "catch-all also collected the named subtree"
    );
    Ok(())
}

/// O4 — a symlink the guest drops into the output share pointing at a host file is
/// skipped during collection: no bytes and no link reach the dest.
#[test]
fn output_symlink_escape_is_skipped() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let outputs_dir = tmp.path().join("outputs");
    let dest = tmp.path().join("dest");
    let secret = tmp.path().join("host-secret");
    std::fs::write(&secret, b"TOP-SECRET")?;
    let outputs = [Output {
        name: Some("o".to_string()),
        dest: dest.clone(),
    }];
    prepare_outputs(&outputs, &outputs_dir)?;
    std::os::unix::fs::symlink(&secret, outputs_dir.join("o").join("leak"))?;
    std::fs::write(outputs_dir.join("o").join("real"), b"ok")?;

    collect_outputs(&outputs, &outputs_dir)?;

    assert!(
        std::fs::symlink_metadata(dest.join("leak")).is_err(),
        "the escaping symlink must not be collected"
    );
    assert_eq!(
        std::fs::read(dest.join("real"))?,
        b"ok",
        "a real file beside it is still collected"
    );
    Ok(())
}

// ---- cross-cutting ------------------------------------------------------------

/// X1 — with an input, an output, and a secret all set, the qemu argv carries three
/// distinct shares with the right tags, and only the outputs share is writable
/// (inputs and secret are read-only; outputs never lands under the secret mount).
#[test]
fn three_shares_only_outputs_writable() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let inputs_dir = tmp.path().join("inputs");
    let outputs_dir = tmp.path().join("outputs");
    let secret_dir = tmp.path().join("secret");
    std::fs::create_dir_all(&secret_dir)?;
    std::fs::write(tmp.path().join("f"), b"in")?;
    stage_inputs(
        &[Input {
            host: tmp.path().join("f"),
            name: "data".to_string(),
        }],
        &inputs_dir,
    )?;
    prepare_outputs(
        &[Output {
            name: None,
            dest: tmp.path().join("dest"),
        }],
        &outputs_dir,
    )?;

    let staged = QemuStagedArgs {
        input_share: Some(descriptor(&inputs_dir, INPUT_MOUNT_TAG, true)),
        output_share: Some(descriptor(&outputs_dir, OUTPUT_MOUNT_TAG, false)),
        secret_share: Some(descriptor(&secret_dir, SECRET_MOUNT_TAG, true)),
        ..Default::default()
    };
    let args = qemu_args(&qemu_topo(), &spec(&["true".to_string()]), &staged).context("qemu_args")?;

    for (tag, writable) in [
        (INPUT_MOUNT_TAG, false),
        (OUTPUT_MOUNT_TAG, true),
        (SECRET_MOUNT_TAG, false),
    ] {
        let arg = share_arg(&args, &format!("mount_tag={tag}"));
        assert_eq!(
            !arg.contains("readonly=on"),
            writable,
            "share {tag} writable={writable}, got arg {arg}"
        );
    }
    Ok(())
}
