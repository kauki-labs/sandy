//! Finding and stopping the VM processes a killed host process left behind (#666).
//!
//! A VM backend keeps its running boxes in memory, so a `SIGKILL` of the host process (the `sandyd` daemon or a
//! `sandy run`) leaves the hypervisor, its virtiofsd daemons and its egress proxy running with no one to stop them.
//! Each box therefore writes a record, `<run dir>/box.json`, naming every process it started and the process that
//! owns them. [`sweep_orphans`] reads the records at start-up and stops only what a record proves is ours and
//! orphaned. See `docs/decisions/run-plane.md` decision 6.
//!
//! Safety rests on three rules. A process is stopped only when its pid, its start time and its executable all match
//! the record, so a reused pid is never hit. A box is swept only when its owner is verifiably gone, so a second
//! daemon or a running CLI is never touched. Nothing without a record is ever touched.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// The record's file name inside a box's run directory.
pub const RECORD_FILE: &str = "box.json";

/// The largest record the sweep reads, in bytes. A record is a few lines; a bigger file is not ours.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// What the sweep needs to know about the host's processes, and the one thing it does to them. A trait so tests
/// use a table of invented processes on any host; [`Procfs`] is the Linux implementation.
pub trait ProcessTable {
    /// When `pid` started, in the table's own units, or `None` when no such process exists.
    fn start_time(&self, pid: u32) -> Option<u64>;
    /// The path of `pid`'s executable, or `None` when it cannot be read.
    fn exe(&self, pid: u32) -> Option<String>;
    /// Send `pid` an unblockable kill. Best effort: the process may already be gone.
    fn kill(&self, pid: u32);
}

/// A process as a record names it. The three fields together tell it from a later process that reused its pid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcId {
    /// The process id.
    pub pid: u32,
    /// The start time, in the units of the [`ProcessTable`] that wrote it.
    pub start: u64,
    /// The executable path.
    pub exe: String,
}

/// The processes of one box and the process that owns them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoxRecord {
    /// The launching process. The sweep leaves the box alone while this process is alive.
    pub owner: ProcId,
    /// Every process the box started: the hypervisor, each virtiofsd, the egress proxy.
    pub procs: Vec<ProcId>,
}

/// Writes a box's record, rewriting it each time a process is added so that a kill between two spawns still leaves
/// a record of what already runs.
#[derive(Debug)]
pub struct RecordWriter {
    path: PathBuf,
    record: BoxRecord,
}

impl RecordWriter {
    /// Start the record for the box whose run directory is `dir`, owned by `owner_pid`, and write it.
    ///
    /// # Errors
    ///
    /// When `owner_pid` cannot be identified through `table`, or the record cannot be written.
    pub fn create(dir: &Path, table: &dyn ProcessTable, owner_pid: u32) -> io::Result<Self> {
        let _ = (dir, table, owner_pid);
        Err(io::Error::other("not implemented"))
    }

    /// Add a started process to the record and rewrite it.
    ///
    /// # Errors
    ///
    /// When `pid` cannot be identified through `table`, or the record cannot be written. The file keeps its
    /// previous content then.
    pub fn add(&mut self, table: &dyn ProcessTable, pid: u32) -> io::Result<()> {
        let _ = (table, pid);
        Err(io::Error::other("not implemented"))
    }
}

/// What one sweep did. Counts only: nothing here repeats text from a record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Processes stopped.
    pub killed: usize,
    /// Boxes whose run directories were removed.
    pub wiped: usize,
    /// Boxes left alone because their owner is alive.
    pub live_owner: usize,
    /// Directories whose record could not be read or understood, left untouched.
    pub unreadable: usize,
}

/// Stop the processes of every box under `base` whose owner is gone, and remove its run directories.
///
/// Only a directory that holds a [`RECORD_FILE`] is considered. A record that cannot be read leaves its directory
/// as it is. The sweep never follows a symlink.
pub fn sweep_orphans(base: &Path, table: &dyn ProcessTable) -> SweepReport {
    let _ = (base, table);
    SweepReport::default()
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use anyhow::Context;

    use super::*;

    /// A table of invented processes: pid to (start, exe). Records the kills it was asked for.
    #[derive(Default)]
    struct Fake {
        procs: BTreeMap<u32, (u64, String)>,
        killed: RefCell<Vec<u32>>,
    }

    impl Fake {
        fn with(mut self, pid: u32, start: u64, exe: &str) -> Self {
            self.procs.insert(pid, (start, exe.to_owned()));
            self
        }

        fn killed(&self) -> Vec<u32> {
            self.killed.borrow().clone()
        }
    }

    impl ProcessTable for Fake {
        fn start_time(&self, pid: u32) -> Option<u64> {
            self.procs.get(&pid).map(|p| p.0)
        }

        fn exe(&self, pid: u32) -> Option<String> {
            self.procs.get(&pid).map(|p| p.1.clone())
        }

        fn kill(&self, pid: u32) {
            self.killed.borrow_mut().push(pid);
        }
    }

    const QEMU: &str = "/nix/store/x-qemu/bin/qemu-system-x86_64";
    const VIRTIOFSD: &str = "/nix/store/x-virtiofsd/bin/virtiofsd";
    const DAEMON: &str = "/nix/store/x-sandyd/bin/sandyd";

    fn id(pid: u32, start: u64, exe: &str) -> ProcId {
        ProcId {
            pid,
            start,
            exe: exe.to_owned(),
        }
    }

    /// A box as the daemon (pid 100, start 1000) launched it: qemu 200, virtiofsd 201.
    fn record() -> BoxRecord {
        BoxRecord {
            owner: id(100, 1000, DAEMON),
            procs: vec![id(200, 2000, QEMU), id(201, 2001, VIRTIOFSD)],
        }
    }

    /// The table after the daemon died: its children still run.
    fn orphaned() -> Fake {
        Fake::default().with(200, 2000, QEMU).with(201, 2001, VIRTIOFSD)
    }

    /// Lay out `<base>/<name>` with the record and its two sibling dirs, as a run does.
    fn lay_out(base: &Path, name: &str, record: &BoxRecord) -> anyhow::Result<()> {
        for dir in [name.to_owned(), format!("{name}-inputs"), format!("{name}-outputs")] {
            fs::create_dir_all(base.join(&dir)).context("create dir")?;
            fs::write(base.join(&dir).join("data"), b"x").context("write data")?;
        }
        fs::write(
            base.join(name).join(RECORD_FILE),
            serde_json::to_vec(record).context("encode record")?,
        )
        .context("write record")?;
        Ok(())
    }

    fn exists(base: &Path, name: &str) -> bool {
        base.join(name).exists()
    }

    #[test]
    fn a_box_whose_owner_died_is_stopped_and_wiped() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![200, 201]);
        assert_eq!(
            report,
            SweepReport {
                killed: 2,
                wiped: 1,
                ..SweepReport::default()
            }
        );
        for name in ["run1", "run1-inputs", "run1-outputs"] {
            assert!(!exists(base.path(), name), "{name} must be removed");
        }
        Ok(())
    }

    #[test]
    fn a_box_with_a_live_owner_is_left_alone() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = orphaned().with(100, 1000, DAEMON);

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert_eq!(
            report,
            SweepReport {
                live_owner: 1,
                ..SweepReport::default()
            }
        );
        assert!(exists(base.path(), "run1") && exists(base.path(), "run1-inputs"));
        Ok(())
    }

    #[test]
    fn an_owner_pid_reused_by_another_process_does_not_protect_the_box() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        // Pid 100 now belongs to a different process that started later.
        let table = orphaned().with(100, 5000, "/usr/bin/bash");

        sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![200, 201]);
        assert!(!exists(base.path(), "run1"));
        Ok(())
    }

    #[test]
    fn a_pid_reused_by_another_process_is_not_killed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        // 200 now runs something that started later; 201 is the same executable but a later start.
        let table = Fake::default().with(200, 9000, QEMU).with(201, 9001, VIRTIOFSD);

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert_eq!(report.killed, 0);
        assert_eq!(report.wiped, 1, "the dead box's directories are still removed");
        assert!(!exists(base.path(), "run1"));
        Ok(())
    }

    #[test]
    fn a_pid_running_a_different_executable_is_not_killed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = Fake::default()
            .with(200, 2000, "/usr/bin/bash")
            .with(201, 2001, VIRTIOFSD);

        sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![201], "only the process that matches in full");
        Ok(())
    }

    #[test]
    fn a_process_that_already_exited_is_only_wiped() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = Fake::default();

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty());
        assert_eq!((report.killed, report.wiped), (0, 1));
        Ok(())
    }

    #[test]
    fn pid_zero_and_one_are_never_killed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let record = BoxRecord {
            owner: id(100, 1000, DAEMON),
            procs: vec![id(0, 1, "/sbin/init"), id(1, 1, "/sbin/init")],
        };
        lay_out(base.path(), "run1", &record)?;
        let table = Fake::default().with(0, 1, "/sbin/init").with(1, 1, "/sbin/init");

        sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        Ok(())
    }

    #[test]
    fn a_corrupt_record_leaves_its_directory_and_does_not_stop_the_pass() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join("bad")).context("bad dir")?;
        fs::write(base.path().join("bad").join(RECORD_FILE), b"{not json").context("bad record")?;
        fs::create_dir_all(base.path().join("unknown-field")).context("dir")?;
        fs::write(
            base.path().join("unknown-field").join(RECORD_FILE),
            br#"{"owner":{"pid":1,"start":1,"exe":"x"},"procs":[],"extra":1}"#,
        )
        .context("record")?;
        lay_out(base.path(), "good", &record())?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report.unreadable, 2);
        assert_eq!(report.wiped, 1);
        assert!(exists(base.path(), "bad") && exists(base.path(), "unknown-field"));
        assert!(!exists(base.path(), "good"));
        Ok(())
    }

    #[test]
    fn an_oversized_record_is_not_read() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join("big")).context("dir")?;
        let padding = " ".repeat(usize::try_from(MAX_RECORD_BYTES)? + 1);
        let json = serde_json::to_string(&record()).context("encode")?;
        fs::write(base.path().join("big").join(RECORD_FILE), format!("{json}{padding}")).context("write")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report.unreadable, 1);
        assert!(table.killed().is_empty());
        assert!(exists(base.path(), "big"));
        Ok(())
    }

    #[test]
    fn a_directory_without_a_record_is_never_touched() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join("cred-abc")).context("dir")?;
        fs::write(base.path().join("a-file"), b"x").context("file")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report, SweepReport::default());
        assert!(exists(base.path(), "cred-abc") && exists(base.path(), "a-file"));
        Ok(())
    }

    #[test]
    fn a_symlink_to_a_box_directory_is_not_followed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let elsewhere = tempfile::tempdir().context("tempdir")?;
        lay_out(elsewhere.path(), "real", &record())?;
        std::os::unix::fs::symlink(elsewhere.path().join("real"), base.path().join("link")).context("symlink")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report, SweepReport::default());
        assert!(table.killed().is_empty());
        assert!(exists(elsewhere.path(), "real"));
        Ok(())
    }

    #[test]
    fn a_missing_base_is_an_empty_sweep() {
        let table = orphaned();
        let report = sweep_orphans(Path::new("/nonexistent/sandy-orphan-sweep-test"), &table);
        assert_eq!(report, SweepReport::default());
    }

    #[test]
    fn a_record_round_trips_through_the_writer_one_process_at_a_time() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("tempdir")?;
        let table = Fake::default()
            .with(100, 1000, DAEMON)
            .with(200, 2000, QEMU)
            .with(201, 2001, VIRTIOFSD);

        let mut writer = RecordWriter::create(dir.path(), &table, 100).context("create")?;
        let read = |dir: &Path| -> anyhow::Result<BoxRecord> {
            serde_json::from_slice(&fs::read(dir.join(RECORD_FILE)).context("read")?).context("decode")
        };
        assert_eq!(
            read(dir.path())?,
            BoxRecord {
                owner: id(100, 1000, DAEMON),
                procs: vec![]
            }
        );
        writer.add(&table, 201).context("add virtiofsd")?;
        writer.add(&table, 200).context("add qemu")?;
        assert_eq!(
            read(dir.path())?.procs,
            vec![id(201, 2001, VIRTIOFSD), id(200, 2000, QEMU)]
        );
        Ok(())
    }

    #[test]
    fn a_process_that_cannot_be_identified_is_not_recorded() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("tempdir")?;
        let table = Fake::default().with(100, 1000, DAEMON);
        assert!(
            RecordWriter::create(dir.path(), &Fake::default(), 100).is_err(),
            "unknown owner"
        );

        let mut writer = RecordWriter::create(dir.path(), &table, 100).context("create")?;
        let before = fs::read(dir.path().join(RECORD_FILE)).context("read")?;
        assert!(writer.add(&table, 999).is_err(), "unknown process");
        assert_eq!(fs::read(dir.path().join(RECORD_FILE)).context("read")?, before);
        Ok(())
    }

    /// The real process table reads this very process: it is alive, started, and runs the test binary.
    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_identifies_the_running_process() -> anyhow::Result<()> {
        let pid = std::process::id();
        let table = Procfs;
        assert!(table.start_time(pid).is_some());
        let exe = table.exe(pid).context("exe")?;
        assert_eq!(Path::new(&exe), std::env::current_exe().context("current_exe")?);
        assert_eq!(table.start_time(u32::MAX - 1), None);
        Ok(())
    }
}
