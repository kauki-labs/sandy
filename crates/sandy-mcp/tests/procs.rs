//! The live gate's process and staging helpers (`common/procs.rs`), pinned without a VM: they run in every
//! default `cargo nextest run -p sandy-mcp`.

mod common;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use common::procs::{
    descendants_in, file_holds, files_holding, foreign_new_entries, group_members_in, is_vm_part, parse_pgrp,
    parse_stat, run_dirs_left, sandy_entries, staging_base, stat_is_live,
};

/// A `/proc/<pid>/stat` line: pid, comm, state, ppid and 17 more fields up to the start time (field 22).
fn stat_line(comm: &str, ppid: u32, start: u64) -> String {
    format!("4242 ({comm}) S {ppid} 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 50 18446744073709551615")
}

#[test]
fn a_zombie_or_dead_or_unreadable_process_is_not_live() {
    let line = |state: &str| stat_line("sandyd", 1, 7).replacen(" S ", &format!(" {state} "), 1);
    for live in ["R", "S", "D", "T"] {
        assert!(stat_is_live(&line(live)), "{live} is live");
    }
    for dead in ["Z", "X"] {
        assert!(!stat_is_live(&line(dead)), "{dead} is not live");
    }
    // The state follows the last `)`, so a command name with parentheses cannot be read as it.
    let tricky = stat_line("sandyd) Z (x", 1, 7);
    assert!(
        stat_is_live(&tricky),
        "a `)` in the command name does not make the process a zombie"
    );
    assert!(
        !stat_is_live(&tricky.replacen(") S ", ") Z ", 1)),
        "the real state still decides"
    );
    assert!(!stat_is_live(""), "no stat text is not live");
    assert!(!stat_is_live("4242 (sandyd"), "a truncated line is not live");
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

/// The process group id is field 5 of `/proc/<pid>/stat`: the third after the command name.
#[test]
fn the_process_group_is_read_from_the_stat_line() {
    // stat_line puts ppid at field 4 and the group (pgrp) at field 5, which `stat_line` fixes at 1.
    assert_eq!(parse_pgrp(&stat_line("qemu-system-x86", 7, 9)), Some(1));
    let tricky = stat_line("a) S (b", 7, 9);
    assert_eq!(
        parse_pgrp(&tricky),
        Some(1),
        "a `)` in the command name does not shift the fields"
    );
    assert_eq!(parse_pgrp(""), None);
    assert_eq!(parse_pgrp("4242 (sandyd"), None);
}

/// A re-parented or double-forked descendant keeps the group of the daemon that started it, so the group finds what the
/// parent walk cannot; another session's processes have another group.
#[test]
fn a_group_lists_its_members_including_orphans_and_no_one_else() {
    // (pid, pgrp, start): 10 leads group 10; 11 is its child; 12 was re-parented to init but kept the group;
    // 20 and 21 belong to another session's group; 30 is a stray with no group relation.
    let table = [
        (1, 1, 1),
        (10, 10, 100),
        (11, 10, 110),
        (12, 10, 120),
        (20, 20, 200),
        (21, 20, 210),
        (30, 30, 300),
    ];
    let mut found = group_members_in(&table, 10);
    found.sort_unstable();
    assert_eq!(found, vec![(10, 100), (11, 110), (12, 120)]);
    assert!(
        group_members_in(&table, 99).is_empty(),
        "an unknown group has no members"
    );
    assert_eq!(group_members_in(&table, 30), vec![(30, 300)]);
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
        run_dirs_left(tmp.path())?.is_empty(),
        "a fresh base holds no run directory"
    );
    std::fs::create_dir(made.join("run-1"))?;
    assert_eq!(run_dirs_left(tmp.path())?, vec![made.join("run-1")]);
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

const CANARY: &str = "canary-0123456789abcdef";

fn no_skip() -> std::path::PathBuf {
    std::path::PathBuf::from("/nonexistent-skip")
}

/// True when `path` cannot be listed or read by this process (false for root, where mode bits do not bind).
fn is_blocked(path: &std::path::Path) -> bool {
    std::fs::read_dir(path).is_err() && std::fs::read(path).is_err()
}

/// The two tests that make a path unreadable need mode bits that bind the current user. Root is not bound, so
/// there the precondition fails loudly instead of the test passing without checking anything.
fn require_mode_bits_to_bind(blocked: bool) {
    assert!(
        blocked,
        "the path stayed readable after chmod 000: this process is not bound by mode bits (running as root?). Run the \
         test as a normal user; it cannot check the failure path otherwise"
    );
}

fn deny(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))?;
    Ok(())
}

fn allow(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn the_canary_scan_finds_a_file_that_holds_it_and_skips_the_named_credential_file() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::create_dir_all(root.path().join("a/b"))?;
    std::fs::write(root.path().join("a/b/log"), format!("x {CANARY} y"))?;
    std::fs::write(root.path().join("a/clean"), "nothing here")?;
    std::fs::write(root.path().join("credential"), CANARY)?;
    let hits = files_holding(root.path(), CANARY, &root.path().join("credential"))?;
    assert_eq!(hits, vec![root.path().join("a/b/log")]);
    Ok(())
}

#[test]
fn a_canary_beyond_the_old_64_mib_cap_is_found() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("console.log");
    let file = std::fs::File::create(&path)?;
    file.set_len(65 * 1024 * 1024)?;
    drop(file);
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new().write(true).open(&path)?;
        f.seek(SeekFrom::End(0))?;
        f.write_all(CANARY.as_bytes())?;
    }
    assert_eq!(files_holding(root.path(), CANARY, &no_skip())?, vec![path]);
    Ok(())
}

#[test]
fn a_canary_that_straddles_a_read_chunk_is_found() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("log");
    // The scan reads in 1 MiB chunks: put the canary across that boundary.
    let mut bytes = vec![b'.'; 1024 * 1024 - 5];
    bytes.extend_from_slice(CANARY.as_bytes());
    bytes.extend_from_slice(&[b'.'; 100]);
    std::fs::write(&path, bytes)?;
    assert_eq!(files_holding(root.path(), CANARY, &no_skip())?, vec![path]);
    Ok(())
}

#[test]
fn an_unreadable_directory_is_an_error_not_a_clean_scan() -> Result<()> {
    let root = tempfile::tempdir()?;
    let locked = root.path().join("locked");
    std::fs::create_dir(&locked)?;
    std::fs::write(locked.join("log"), CANARY)?;
    deny(&locked)?;
    let blocked = is_blocked(&locked);
    let result = files_holding(root.path(), CANARY, &no_skip());
    allow(&locked)?;
    require_mode_bits_to_bind(blocked);
    assert!(
        result.is_err(),
        "an unlistable directory must fail the scan: {result:?}"
    );
    Ok(())
}

#[test]
fn an_unreadable_file_is_an_error_not_a_clean_scan() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("log");
    std::fs::write(&path, CANARY)?;
    deny(&path)?;
    let blocked = is_blocked(&path);
    let result = files_holding(root.path(), CANARY, &no_skip());
    allow(&path)?;
    require_mode_bits_to_bind(blocked);
    assert!(result.is_err(), "an unreadable file must fail the scan: {result:?}");
    Ok(())
}

#[test]
fn a_missing_scan_root_is_an_error() {
    assert!(files_holding(&std::env::temp_dir().join("sandy-mcp-no-such-root"), CANARY, &no_skip()).is_err());
}

#[test]
fn a_symlink_or_fifo_is_an_error_because_the_scan_cannot_read_it() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::os::unix::fs::symlink("/etc/hostname", root.path().join("link"))?;
    assert!(files_holding(root.path(), CANARY, &no_skip()).is_err(), "a symlink");

    let fifo_root = tempfile::tempdir()?;
    let status = std::process::Command::new("mkfifo")
        .arg(fifo_root.path().join("pipe"))
        .status()?;
    anyhow::ensure!(status.success(), "mkfifo failed");
    assert!(files_holding(fifo_root.path(), CANARY, &no_skip()).is_err(), "a fifo");
    Ok(())
}

#[test]
fn a_unix_socket_is_exempt_because_it_stores_no_bytes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let _listener = std::os::unix::net::UnixListener::bind(root.path().join("serial.sock"))?;
    std::fs::write(root.path().join("log"), "clean")?;
    assert!(files_holding(root.path(), CANARY, &no_skip())?.is_empty());
    Ok(())
}

#[test]
fn a_missing_staging_base_is_clean_and_an_unreadable_one_is_an_error() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    assert!(run_dirs_left(tmp.path())?.is_empty(), "no base: nothing was staged");

    // The base is a file, not a directory: it cannot be listed, and that is not "clean".
    std::fs::write(staging_base(tmp.path()), "not a directory")?;
    assert!(run_dirs_left(tmp.path()).is_err(), "a base that is a file");
    std::fs::remove_file(staging_base(tmp.path()))?;

    std::fs::create_dir(staging_base(tmp.path()))?;
    deny(&staging_base(tmp.path()))?;
    let blocked = is_blocked(&staging_base(tmp.path()));
    let result = run_dirs_left(tmp.path());
    allow(&staging_base(tmp.path()))?;
    if blocked {
        assert!(
            result.is_err(),
            "an unlistable base must fail, not read as clean: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn the_credential_file_is_created_private_and_never_overwritten() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let path = common::mcp_client::credential_file(dir.path(), CANARY)?;
    assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read_to_string(&path)?, format!("{CANARY}\n"));
    assert!(
        common::mcp_client::credential_file(dir.path(), "other").is_err(),
        "an existing file is refused, so a loosely-moded one is never reused"
    );
    Ok(())
}

/// An empty needle matches every window of every file: it is a bug in the caller, and `windows(0)` panics, so it is
/// refused with an error before anything is read.
#[test]
fn an_empty_needle_is_an_error_not_a_panic() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("log"), "anything")?;
    let err = files_holding(root.path(), "", &no_skip()).expect_err("an empty needle must be refused");
    assert!(format!("{err:#}").contains("needle"), "{err:#}");
    Ok(())
}

/// A fifo swapped in for a regular file after the scan listed it must not hang the open: the file is opened
/// non-blocking and its type is checked on the open descriptor. The bound makes a hang a failure.
#[test]
fn a_fifo_in_place_of_a_file_is_refused_without_blocking() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fifo = root.path().join("pipe");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    anyhow::ensure!(status.success(), "mkfifo failed");
    let (tx, rx) = std::sync::mpsc::channel();
    // A blocked open leaves this thread behind; the test fails on the timeout and the process ends it.
    std::thread::spawn(move || {
        let _ = tx.send(file_holds(&fifo, CANARY.as_bytes()));
    });
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .context("file_holds blocked on a fifo for 10 s")?;
    assert!(result.is_err(), "a fifo is not a regular file: {result:?}");
    Ok(())
}

/// The canary can be in a name as well as in contents: a log line names a file, and a path can carry it.
#[test]
fn a_canary_in_a_file_or_directory_name_is_found() -> Result<()> {
    let root = tempfile::tempdir()?;
    let dir = root.path().join(format!("dir-{CANARY}"));
    std::fs::create_dir(&dir)?;
    let named_file = dir.join(format!("{CANARY}.log"));
    std::fs::write(&named_file, "clean contents")?;
    std::fs::write(root.path().join("clean"), "clean contents")?;
    let mut hits = files_holding(root.path(), CANARY, &no_skip())?;
    hits.sort();
    assert_eq!(hits, vec![dir, named_file]);
    Ok(())
}

/// A file whose name and contents both hold the canary is reported once.
#[test]
fn a_file_that_holds_the_canary_in_name_and_contents_is_reported_once() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join(format!("{CANARY}.log"));
    std::fs::write(&path, CANARY)?;
    assert_eq!(files_holding(root.path(), CANARY, &no_skip())?, vec![path]);
    Ok(())
}

/// Run `file_holds` on `path` with a bound, so a missing type check or flag shows up as a failure and not a hang.
fn file_holds_bounded(path: std::path::PathBuf, needle: &'static [u8]) -> Result<std::io::Result<bool>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(file_holds(&path, needle));
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .context("file_holds did not return within 10 s")
}

/// A symlink is refused at the open (`ELOOP`), whether it points at a file or at nothing, and the error is not
/// `NotFound`, which the scan skips as a file that vanished.
#[test]
fn a_symlink_is_an_error_that_the_scan_does_not_mistake_for_a_vanished_file() -> Result<()> {
    let root = tempfile::tempdir()?;
    let target = root.path().join("target");
    std::fs::write(&target, CANARY)?;
    let live = root.path().join("live-link");
    std::os::unix::fs::symlink(&target, &live)?;
    let dangling = root.path().join("dangling-link");
    std::os::unix::fs::symlink(root.path().join("nowhere"), &dangling)?;
    for link in [live, dangling] {
        let err = file_holds_bounded(link.clone(), CANARY.as_bytes())?.expect_err("a symlink must be refused");
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound, "{}: {err}", link.display());
    }
    Ok(())
}

/// The type is checked on the open descriptor before any read: a device that never ends must be refused at once,
/// not scanned for ever.
#[test]
fn a_device_is_refused_before_any_read() -> Result<()> {
    let err = file_holds_bounded(std::path::PathBuf::from("/dev/zero"), CANARY.as_bytes())?
        .expect_err("a device is not a regular file");
    assert!(err.to_string().contains("regular file"), "{err}");
    Ok(())
}

#[test]
fn file_holds_refuses_an_empty_needle_itself() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("log");
    std::fs::write(&path, "anything")?;
    assert!(file_holds(&path, b"").is_err());
    Ok(())
}

/// The skipped path is exempt from the name check as well as the content check.
#[test]
fn the_skipped_path_is_exempt_from_the_name_check_too() -> Result<()> {
    let root = tempfile::tempdir()?;
    let skipped = root.path().join(format!("{CANARY}.cred"));
    std::fs::write(&skipped, "clean")?;
    assert!(files_holding(root.path(), CANARY, &skipped)?.is_empty());
    Ok(())
}
