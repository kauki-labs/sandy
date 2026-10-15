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
use sandy_backend::{GuestShareTransport, Placement, Presentation, ShareSpec};
use sandy_impls_local::LocalDirTransport;
use sandy_impls_vm::{
    QemuStagedArgs, VfkitStagedArgs, VirtioFsTransport, VirtiofsdTransport, qemu_args, vfkit_args, virtiofsd_args,
};

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

/// A [`ShareSpec`] as the backend `run` builds it: the virtiofsd socket lives beside
/// the shared dir (qemu uses it; vfkit ignores it), and `ro` drives the read-only
/// boundary (`--readonly` on qemu, the guest mount on vfkit).
fn qshare(dir: &std::path::Path, tag: &str, ro: bool) -> ShareSpec {
    ShareSpec {
        host_dir: dir.to_path_buf(),
        tag: tag.to_string(),
        readonly: ro,
        socket: dir.join(format!("vfsd-{tag}.sock")),
    }
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
            guest_path: None,
        }],
        &inputs_dir,
    )?;
    assert_eq!(n, 1);
    assert_eq!(
        std::fs::read(inputs_dir.join("data"))?,
        b"in",
        "input staged under its name"
    );

    let share = qshare(&inputs_dir, INPUT_MOUNT_TAG, true);
    let staged = QemuStagedArgs {
        shares: vec![share.clone()],
        ..Default::default()
    };
    let args = qemu_args(&qemu_topo(), &spec(&["true".to_string()]), &staged).context("qemu_args")?;

    // The share is a virtio-fs device carrying the mount tag the guest keys on.
    let arg = share_arg(&args, &format!("tag={INPUT_MOUNT_TAG}"));
    assert!(
        arg.contains("vhost-user-fs-pci"),
        "qemu input share is a virtio-fs device: {arg}"
    );
    // Read-only is enforced at the virtiofsd boundary, not the argv (INV-1).
    assert!(
        virtiofsd_args(&share).iter().any(|a| a == "--readonly"),
        "qemu input share must be read-only (virtiofsd --readonly)"
    );
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
            guest_path: None,
        }],
        &inputs_dir,
    )?;

    let staged = VfkitStagedArgs::new(vec![qshare(&inputs_dir, INPUT_MOUNT_TAG, true)]);
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
            guest_path: None,
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

    let share = qshare(&outputs_dir, OUTPUT_MOUNT_TAG, false);
    let staged = QemuStagedArgs {
        shares: vec![share.clone()],
        ..Default::default()
    };
    let args = qemu_args(&qemu_topo(), &spec(&["true".to_string()]), &staged).context("qemu_args")?;

    let arg = share_arg(&args, &format!("tag={OUTPUT_MOUNT_TAG}"));
    assert!(
        arg.contains("vhost-user-fs-pci"),
        "qemu output share is a virtio-fs device: {arg}"
    );
    // Writable: no --readonly at the virtiofsd boundary, so the guest can write it.
    assert!(
        !virtiofsd_args(&share).iter().any(|a| a == "--readonly"),
        "qemu output share must be writable (no virtiofsd --readonly)"
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

    let staged = VfkitStagedArgs::new(vec![qshare(&outputs_dir, OUTPUT_MOUNT_TAG, false)]);
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
            guest_path: None,
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

    let shares = vec![
        qshare(&inputs_dir, INPUT_MOUNT_TAG, true),
        qshare(&outputs_dir, OUTPUT_MOUNT_TAG, false),
        qshare(&secret_dir, SECRET_MOUNT_TAG, true),
    ];
    let staged = QemuStagedArgs {
        shares: shares.clone(),
        ..Default::default()
    };
    let args = qemu_args(&qemu_topo(), &spec(&["true".to_string()]), &staged).context("qemu_args")?;

    for share in &shares {
        // Each share is wired as a virtio-fs device keyed on its tag...
        let arg = share_arg(&args, &format!("tag={}", share.tag));
        assert!(
            arg.contains("vhost-user-fs-pci"),
            "share {} is a virtio-fs device: {arg}",
            share.tag
        );
        // ...and only outputs are writable (no --readonly); inputs/secret are RO.
        let writable = !share.readonly;
        assert_eq!(
            !virtiofsd_args(share).iter().any(|a| a == "--readonly"),
            writable,
            "share {} writable={writable}",
            share.tag
        );
    }
    Ok(())
}

/// `plan_shares` is the single home for the share-staging policy both backends use.
/// Given a secret, an input, and an output it stages each and returns the shares in
/// secret → input → output order, with the right tags, the read-only flags (secret
/// and input read-only, output writable), and the virtiofsd socket beside inst_dir.
/// This is the policy qemu and vfkit previously open-coded in lockstep.
#[test]
fn plan_shares_stages_secret_input_output_with_the_right_flags() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    use sandy::{SecretRef, SecretSource};
    use sandy_backend::{ShareDirs, plan_shares};

    let tmp = tempfile::tempdir().context("tmp")?;
    let secret_src = tmp.path().join("tok");
    std::fs::write(&secret_src, b"S").context("write secret src")?;
    // Secret sources must be 0600 (INV-1); stage_secrets refuses a loose one.
    std::fs::set_permissions(&secret_src, std::fs::Permissions::from_mode(0o600)).context("chmod secret src")?;
    let in_src = tmp.path().join("in");
    std::fs::create_dir_all(&in_src).context("mk input src")?;
    std::fs::write(in_src.join("f"), b"I").context("write input")?;

    let inst = tmp.path().join("inst");
    let inputs = tmp.path().join("inputs");
    let outputs = tmp.path().join("outputs");

    let secrets = [SecretRef {
        name: "TOK".to_string(),
        source: SecretSource::File(secret_src),
    }];
    let in_specs = [Input {
        host: in_src,
        name: "data".to_string(),
        guest_path: None,
    }];
    let out_specs = [Output {
        name: Some("r".to_string()),
        dest: tmp.path().join("dest"),
    }];
    let spec = RunSpec {
        template: "demo",
        command: &[],
        inputs: &in_specs,
        outputs: &out_specs,
        secrets: &secrets,
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: &GRANTS,
        outcome_file: None,
        secret_dir: None,
    };

    let shares = plan_shares(
        &spec,
        &ShareDirs {
            inst_dir: &inst,
            inputs_dir: &inputs,
            outputs_dir: &outputs,
        },
    )
    .context("plan_shares")?;

    let tags: Vec<&str> = shares.iter().map(|s| s.tag.as_str()).collect();
    assert_eq!(
        tags,
        [SECRET_MOUNT_TAG, INPUT_MOUNT_TAG, OUTPUT_MOUNT_TAG],
        "shares come back in secret → input → output order"
    );
    let by_tag = |t: &str| shares.iter().find(|s| s.tag == t).expect("share present");
    assert!(by_tag(SECRET_MOUNT_TAG).readonly, "the secret share is read-only");
    assert!(by_tag(INPUT_MOUNT_TAG).readonly, "the input share is read-only");
    assert!(!by_tag(OUTPUT_MOUNT_TAG).readonly, "the output share is writable");
    assert_eq!(
        by_tag(SECRET_MOUNT_TAG).socket,
        inst.join(format!("vfsd-{SECRET_MOUNT_TAG}.sock")),
        "the virtiofsd socket lives beside inst_dir"
    );
    Ok(())
}

/// The #49 secret_dir rule: with a caller-owned `secret_dir` and no plan secrets,
/// the secret share is still attached (so a mid-run refresh into that dir reaches
/// the guest) and points at the caller's dir, not inst_dir.
#[test]
fn plan_shares_attaches_an_empty_secret_dir_for_refresh() -> Result<()> {
    use sandy_backend::{ShareDirs, plan_shares};

    let tmp = tempfile::tempdir().context("tmp")?;
    let inst = tmp.path().join("inst");
    let cred = tmp.path().join("cred");
    std::fs::create_dir_all(&cred).context("mk cred dir")?;
    let inputs = tmp.path().join("i");
    let outputs = tmp.path().join("o");

    let spec = RunSpec {
        template: "demo",
        command: &[],
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 60,
        grants: &GRANTS,
        outcome_file: None,
        secret_dir: Some(&cred),
    };

    let shares = plan_shares(
        &spec,
        &ShareDirs {
            inst_dir: &inst,
            inputs_dir: &inputs,
            outputs_dir: &outputs,
        },
    )
    .context("plan_shares")?;

    assert_eq!(shares.len(), 1, "only the secret share attaches");
    assert_eq!(shares[0].tag, SECRET_MOUNT_TAG);
    assert_eq!(
        shares[0].host_dir, cred,
        "the secret share points at the caller's cred_dir for refresh re-delivery"
    );
    Ok(())
}

/// The process profile's transport maps each staged share to a placement
/// (tag, dir, readonly) under the per-run root, which ProcessBackend exposes as
/// `SANDY_<TAG>_DIR` env. (Red first: the plan stub returns no placements.)
#[test]
fn local_dir_plan_maps_each_share_to_a_placement() {
    use std::path::PathBuf;

    let transport = LocalDirTransport::new(PathBuf::from("/run/inst"));
    let shares = [
        qshare(std::path::Path::new("/s/in"), "sandy-inputs", true),
        qshare(std::path::Path::new("/s/out"), "sandy-outputs", false),
    ];

    let Presentation::LocalDir { root, placements } = transport.plan(&shares, 0) else {
        panic!("the process transport yields a LocalDir presentation");
    };

    assert_eq!(root, PathBuf::from("/run/inst"), "root is the per-run inst dir");
    assert_eq!(placements.len(), 2, "one placement per share");
    assert_eq!(
        placements[0],
        Placement {
            tag: "sandy-inputs".to_string(),
            dir: PathBuf::from("/s/in"),
            readonly: true,
        }
    );
    assert_eq!(
        placements[1],
        Placement {
            tag: "sandy-outputs".to_string(),
            dir: PathBuf::from("/s/out"),
            readonly: false,
        }
    );
}

/// activate() strips write from a read-only share (cooperative RO) and leaves a
/// writable share alone. No daemons are returned.
#[test]
fn local_dir_activate_makes_readonly_shares_unwritable() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::TempDir::new()?;
    let inputs = tmp.path().join("inputs");
    std::fs::create_dir(&inputs)?;
    std::fs::write(inputs.join("f"), b"x")?;
    let outputs = tmp.path().join("outputs");
    std::fs::create_dir(&outputs)?;

    let shares = [
        qshare(&inputs, "sandy-inputs", true),
        qshare(&outputs, "sandy-outputs", false),
    ];
    let children = LocalDirTransport::new(tmp.path().to_path_buf()).activate(&shares)?;

    assert!(children.is_empty(), "the process transport launches no daemons");
    let write_bits =
        |p: &std::path::Path| -> Result<u32> { Ok(std::fs::metadata(p).context("stat")?.permissions().mode() & 0o222) };
    assert_eq!(
        write_bits(&inputs.join("f"))?,
        0,
        "read-only input FILE loses write (its bytes are protected)"
    );
    assert_ne!(
        write_bits(&inputs)? & 0o200,
        0,
        "the read-only input DIR keeps write, so teardown's remove_dir_all can unlink its entries"
    );
    assert_ne!(
        write_bits(&outputs)? & 0o200,
        0,
        "writable output dir keeps owner write"
    );
    Ok(())
}

/// activate() does NOT chmod the secret share read-only: secret files are already
/// 0600 (INV-1) and a caller-owned secret_dir supports in-place token refresh
/// (#49), which a `chmod a-w` would break (and would mutate caller-owned files).
#[test]
fn local_dir_activate_leaves_the_secret_share_writable() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::TempDir::new()?;
    let secret_dir = tmp.path().join("secrets");
    std::fs::create_dir(&secret_dir)?;
    let token = secret_dir.join("TOKEN");
    std::fs::write(&token, b"t")?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;

    LocalDirTransport::new(tmp.path().to_path_buf()).activate(&[qshare(&secret_dir, SECRET_MOUNT_TAG, true)])?;

    let mode = std::fs::metadata(&token)?.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "the secret file keeps 0600 (owner rw) — refresh-capable, not chmod'd read-only"
    );
    Ok(())
}

// ---- the GuestShareTransport contract, over all three transports --------------

/// The contract every [`GuestShareTransport`] upholds: `plan()` is PURE (no IO,
/// same shares yield the same `Presentation`) and an empty share set yields an
/// empty presentation (no argv / no placements). Run against all three impls;
/// `activate()` conformance is per-impl (virtiofsd spawns daemons, a live concern;
/// virtio-fs and local-dir are exercised directly elsewhere in this file).
fn share_transport_contract<T: GuestShareTransport>(label: &str, transport: &T) {
    let shares = [
        qshare(std::path::Path::new("/s/in"), "sandy-inputs", true),
        qshare(std::path::Path::new("/s/out"), "sandy-outputs", false),
    ];

    // Pure: no IO, and deterministic — the same shares yield the same Presentation.
    let first = transport.plan(&shares, 128);
    let second = transport.plan(&shares, 128);
    assert_eq!(
        first, second,
        "{label}: plan() is pure (same shares -> same Presentation)"
    );

    // An empty share set yields an empty presentation.
    match transport.plan(&[], 128) {
        Presentation::Vm { args } => assert!(args.is_empty(), "{label}: no shares -> no argv"),
        Presentation::LocalDir { placements, .. } => {
            assert!(placements.is_empty(), "{label}: no shares -> no placements");
        }
    }
}

#[test]
fn virtiofsd_transport_satisfies_the_share_contract() {
    share_transport_contract("virtiofsd", &VirtiofsdTransport);
}

#[test]
fn virtiofs_transport_satisfies_the_share_contract() {
    share_transport_contract("virtiofs", &VirtioFsTransport);
}

#[test]
fn local_dir_transport_satisfies_the_share_contract() {
    share_transport_contract(
        "local-dir",
        &LocalDirTransport::new(std::path::PathBuf::from("/run/inst")),
    );
}
