//! The live gate's process and staging helpers (`common/procs.rs`), pinned without a VM: they run in every
//! default `cargo nextest run -p sandy-mcp`.

mod common;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use common::procs::{
    descendants_in, foreign_new_entries, is_vm_part, parse_stat, run_dirs_left, sandy_entries, staging_base,
};

/// A `/proc/<pid>/stat` line: pid, comm, state, ppid and 17 more fields up to the start time (field 22).
fn stat_line(comm: &str, ppid: u32, start: u64) -> String {
    format!("4242 ({comm}) S {ppid} 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 50 18446744073709551615")
}

#[test]
fn a_stat_line_gives_its_parent_and_start_time() {
    assert_eq!(
        parse_stat(&stat_line("qemu-system-x86", 77, 987_654)),
        Some((77, 987_654))
    );
}

#[test]
fn a_command_name_with_spaces_and_parentheses_does_not_shift_the_fields() {
    assert_eq!(parse_stat(&stat_line("a) b (c d", 5, 31)), Some((5, 31)));
}

#[test]
fn a_truncated_or_malformed_stat_line_is_none() {
    for bad in [
        "",
        "1 (x)",
        "1 (x) S 2 3",
        "1 (x) S notanumber 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 5 1",
    ] {
        assert_eq!(parse_stat(bad), None, "{bad:?}");
    }
}

#[test]
fn the_descendant_walk_follows_children_of_children_and_nothing_else() {
    // 10 is the daemon; 11 and 12 are its children, 13 is a child of 11. 20 is another session's tree, and 30
    // is a re-parented orphan whose parent died, which the walk cannot reach (an inferred, accepted risk).
    let table = [
        (1, 0, 1),
        (10, 1, 100),
        (11, 10, 110),
        (12, 10, 120),
        (13, 11, 130),
        (20, 1, 200),
        (21, 20, 210),
        (30, 1, 300),
    ];
    let mut found = descendants_in(&table, 10);
    found.sort_unstable();
    assert_eq!(found, vec![(11, 110), (12, 120), (13, 130)]);
    assert!(
        descendants_in(&table, 99).is_empty(),
        "an unknown root has no descendants"
    );
    assert!(descendants_in(&table, 13).is_empty(), "a leaf has none");
}

#[test]
fn the_descendant_walk_ends_on_a_cyclic_table_and_never_lists_the_root() {
    let table = [(10, 11, 1), (11, 10, 2)];
    let found = descendants_in(&table, 10);
    assert_eq!(found, vec![(11, 2)]);
}

#[test]
fn vm_parts_are_qemu_virtiofsd_and_the_egress_proxy_only() {
    for yes in [
        "qemu-system-x86",
        ".qemu-system-x8",
        "virtiofsd",
        ".virtiofsd-wrap",
        "sandy-egress-pr",
    ] {
        assert!(is_vm_part(yes), "{yes}");
    }
    for no in ["sandyd", "sandy-broker", "socat", "nix", ""] {
        assert!(!is_vm_part(no), "{no}");
    }
}

/// The staging base is the backend's own: the name comes from `sandy-fsutil`, and `ensure_staging_base_in`
/// creates exactly the path the helper scans, so a rename of the constant cannot leave the gate scanning nothing.
#[test]
fn the_staging_base_is_the_one_the_backend_creates() -> Result<()> {
    assert_eq!(sandy_fsutil::STAGING_DIR_NAME, "sandy");
    let tmp = tempfile::tempdir()?;
    let made = sandy_fsutil::ensure_staging_base_in(tmp.path()).context("ensure the staging base")?;
    assert_eq!(made, staging_base(tmp.path()));
    assert!(
        run_dirs_left(tmp.path()).is_empty(),
        "a fresh base holds no run directory"
    );
    std::fs::create_dir(made.join("run-1"))?;
    assert_eq!(run_dirs_left(tmp.path()), vec![made.join("run-1")]);
    Ok(())
}

#[test]
fn the_stray_scan_sees_the_base_and_dashed_names_in_an_injected_root_only() -> Result<()> {
    let root = tempfile::tempdir()?;
    for dir in ["sandy/run-1", "sandy-job-1", "other/sandy", "unrelated"] {
        std::fs::create_dir_all(root.path().join(dir))?;
    }
    let found = sandy_entries(root.path());
    let want: BTreeSet<_> = ["sandy", "sandy/run-1", "sandy-job-1"]
        .iter()
        .map(|p| root.path().join(p))
        .collect();
    assert_eq!(found, want);
    assert!(sandy_entries(&root.path().join("missing")).is_empty());
    Ok(())
}

#[test]
fn a_new_entry_outside_this_runs_root_is_foreign_and_one_inside_it_is_not() -> Result<()> {
    let own = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    let before: BTreeSet<_> = [other.path().join("sandy-old")].into();
    let after: BTreeSet<_> = [
        other.path().join("sandy-old"),
        other.path().join("sandy-concurrent-agent"),
        own.path().join("sandy"),
        own.path().join("sandy/run-1"),
    ]
    .into();
    assert_eq!(
        foreign_new_entries(&before, &after, own.path()),
        vec![other.path().join("sandy-concurrent-agent")],
        "only the concurrent agent's new entry is foreign: it is reported, never removed"
    );
    Ok(())
}

/// The credential file holds the live broker's bearer token (INV-1: staged secrets are 0600 files).
#[test]
fn the_credential_file_is_private_to_its_owner() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().context("temp dir")?;
    let path = common::mcp_client::credential_file(dir.path(), "canary").context("write")?;
    let mode = std::fs::metadata(&path).context("stat")?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "credential file mode");
    Ok(())
}
