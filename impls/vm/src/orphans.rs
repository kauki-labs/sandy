//! Finding and stopping the VM processes a killed host process left behind (#666).
//!
//! A VM backend keeps its running boxes in memory, so a `SIGKILL` of the host process (the `sandyd` daemon or a
//! `sandy run`) leaves the hypervisor, its virtiofsd daemons and its egress proxy running with no one to stop them.
//! Each box therefore writes a record, `<run dir>/box.json`, naming every process it started and the process that
//! owns them. [`sweep_orphans`] reads the records at start-up and stops only what a record proves is ours and
//! orphaned. See `docs/decisions/run-plane.md` decision 6.
//!
//! Safety rests on four rules. A process is stopped only when its pid and its start time both match the record, so a
//! reused pid is never hit. A box is swept only when its owner is verifiably gone, so a second daemon or a running CLI
//! is never touched. When the table cannot tell whether a process is there (a read failed), the box is left for the
//! next sweep: an unreadable owner never reads as a dead one. Nothing without a record is ever touched.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// The record's file name inside a box's run directory.
pub const RECORD_FILE: &str = "box.json";

/// The largest record the sweep reads, in bytes. A record is a few lines; a bigger file is not ours.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// What a [`ProcessTable`] knows about one pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    /// There is no such process.
    Gone,
    /// The table could not tell (a read failed for a reason other than "no such process"). Never read as gone.
    Unknown,
    /// The process exists and started at this time, in the table's own units.
    Started(u64),
}

/// What the sweep needs to know about the host's processes, and the one thing it does to them. A trait so tests
/// use a table of invented processes on any host; [`Procfs`] is the Linux implementation.
pub trait ProcessTable {
    /// Whether `pid` exists and when it started.
    fn state(&self, pid: u32) -> ProcState;
    /// The path of `pid`'s executable, or `None` when it cannot be read. Recorded for a human reading the record; the
    /// sweep never compares it, because a wrapper execs another binary after the process is recorded.
    fn exe(&self, pid: u32) -> Option<String>;
    /// Send `pid` an unblockable kill. `true` when the signal was delivered or the process was already gone, `false`
    /// when it could not be sent (no permission, an invalid pid).
    fn kill(&self, pid: u32) -> bool;
    /// An id of the current boot, or `None` when the host has none. Processes do not survive a reboot.
    fn boot_id(&self) -> Option<String>;
    /// An id of the pid namespace this process reads pids in, or `None` when the host has none. A pid means nothing
    /// in another namespace.
    fn pid_namespace(&self) -> Option<String>;
}

/// A process as a record names it. The pid and the start time together tell it from a later process that reused
/// its pid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcId {
    /// The process id.
    pub pid: u32,
    /// The start time, in the units of the [`ProcessTable`] that wrote it.
    pub start: u64,
    /// The executable path when the process was recorded, or empty when it could not be read. Informational: it can
    /// change by an `exec`.
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
    /// The boot this record was written in. A record from an earlier boot names no live process.
    #[serde(default)]
    pub boot_id: String,
    /// The pid namespace this record was written in. A sweep in another namespace cannot read its pids.
    #[serde(default)]
    pub pid_ns: String,
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
        let writer = Self {
            path: dir.join(RECORD_FILE),
            record: BoxRecord {
                owner: identify(table, owner_pid)?,
                procs: Vec::new(),
                boot_id: table.boot_id().unwrap_or_default(),
                pid_ns: table.pid_namespace().unwrap_or_default(),
            },
        };
        write_record(&writer.path, &writer.record)?;
        Ok(writer)
    }

    /// Add a started process to the record and rewrite it.
    ///
    /// # Errors
    ///
    /// When `pid` cannot be identified through `table`, or the record cannot be written. The file keeps its
    /// previous content then.
    pub fn add(&mut self, table: &dyn ProcessTable, pid: u32) -> io::Result<()> {
        let mut next = self.record.clone();
        next.procs.push(identify(table, pid)?);
        write_record(&self.path, &next)?;
        self.record = next;
        Ok(())
    }
}

/// Name `pid` as a record does, or fail when the table cannot give its start time: a process that cannot be told
/// apart from a later one with its pid must not be recorded, since the sweep could never kill it safely. The
/// executable is only for a human reader, so an unreadable one is recorded as empty.
fn identify(table: &dyn ProcessTable, pid: u32) -> io::Result<ProcId> {
    match table.state(pid) {
        ProcState::Started(start) => Ok(ProcId {
            pid,
            start,
            exe: table.exe(pid).unwrap_or_default(),
        }),
        ProcState::Gone | ProcState::Unknown => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the process is not visible in the process table",
        )),
    }
}

/// Replace the record file in one step: write a private temp file beside it, then rename over it. A failure leaves
/// the old file as it was.
fn write_record(path: &Path, record: &BoxRecord) -> io::Result<()> {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};

    let temp = path.with_extension("json.tmp");
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(record).map_err(io::Error::other)?)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Read a box's record. `Ok(None)` when the directory has none; `Err` when there is one that is not ours to trust: a
/// symlink, not a plain file, too large, or not the expected shape.
fn read_record(path: &Path) -> Result<Option<BoxRecord>, ()> {
    use std::io::Read as _;

    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if !meta.file_type().is_file() || meta.len() > MAX_RECORD_BYTES {
        return Err(());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| ())?;
    serde_json::from_slice(&bytes).map(Some).map_err(|_| ())
}

/// Remove a run directory, and the `-inputs` and `-outputs` directories beside it. A symlink is left alone.
fn wipe_box(base: &Path, name: &str) -> bool {
    let mut removed = true;
    for (dir, is_box) in [
        (name.to_owned(), true),
        (format!("{name}-inputs"), false),
        (format!("{name}-outputs"), false),
    ] {
        let path = base.join(dir);
        if !fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_dir()) {
            continue;
        }
        if let Err(err) = fs::remove_dir_all(&path)
            && err.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(dir = %path.display(), %err, "could not remove an orphaned box directory");
            removed &= !is_box;
        }
    }
    removed
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
    /// Boxes left for the next sweep: a process could not be read or killed, or the record is from another pid
    /// namespace.
    pub undecided: usize,
}

/// Stop the processes of every box under `base` whose owner is gone, and remove its run directories.
///
/// Only a directory that holds a [`RECORD_FILE`] is considered. A record that cannot be read leaves its directory
/// as it is. The sweep never follows a symlink.
pub fn sweep_orphans(base: &Path, table: &dyn ProcessTable) -> SweepReport {
    let mut report = SweepReport::default();
    let Ok(entries) = fs::read_dir(base) else {
        return report;
    };
    for entry in entries.flatten() {
        // `DirEntry::file_type` does not follow a symlink, so a link to a directory is skipped here.
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let record = match read_record(&entry.path().join(RECORD_FILE)) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(()) => {
                tracing::warn!(dir = %entry.path().display(), "a box record could not be read; leaving the directory");
                report.unreadable += 1;
                continue;
            }
        };
        // A reboot ends every process, so a record from an earlier boot names none that runs. Nothing is killed (a
        // pid and start time from that boot could match an unrelated process of this one); only the directories go.
        let rebooted = !record.boot_id.is_empty() && table.boot_id().is_some_and(|boot| boot != record.boot_id);
        if rebooted {
            if wipe_box(base, &name) {
                report.wiped += 1;
            }
            continue;
        }
        // Pids mean nothing in another pid namespace, so the box cannot be judged from here.
        if !record.pid_ns.is_empty() && table.pid_namespace().is_some_and(|ns| ns != record.pid_ns) {
            report.undecided += 1;
            continue;
        }
        match table.state(record.owner.pid) {
            ProcState::Started(start) if start == record.owner.start => {
                report.live_owner += 1;
                continue;
            }
            // Could not tell: never read a failed read as a dead owner, or a live box is wiped.
            ProcState::Unknown => {
                report.undecided += 1;
                continue;
            }
            ProcState::Gone | ProcState::Started(_) => {}
        }
        let mut undecided = false;
        for process in &record.procs {
            // Pid 0 and 1 are never ours, whatever a record says.
            if process.pid <= 1 {
                continue;
            }
            match table.state(process.pid) {
                ProcState::Started(start) if start == process.start => {
                    if table.kill(process.pid) {
                        report.killed += 1;
                    } else {
                        undecided = true;
                    }
                }
                ProcState::Unknown => undecided = true,
                ProcState::Gone | ProcState::Started(_) => {}
            }
        }
        // A process that could not be read or stopped keeps its box (and the secret share in it) for the next sweep.
        if undecided {
            report.undecided += 1;
        } else if wipe_box(base, &name) {
            report.wiped += 1;
        }
    }
    report
}

/// The process table of a Linux host, read from `/proc`.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Procfs;

#[cfg(target_os = "linux")]
impl ProcessTable for Procfs {
    fn state(&self, pid: u32) -> ProcState {
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            // No such process (ENOENT, or ESRCH when it exits mid-read).
            Err(err) if err.kind() == io::ErrorKind::NotFound || is_srch(&err) => return ProcState::Gone,
            // Anything else (no descriptors left, `hidepid`, `/proc` not mounted) says nothing about the process.
            Err(_) => return ProcState::Unknown,
        };
        // Field 2 (the command name) may hold spaces and parentheses; field 3 starts after the last `)`. Field 22,
        // the start time in clock ticks since boot, is the 20th after it.
        stat.rfind(')')
            .and_then(|end| stat[end + 1..].split_whitespace().nth(19)?.parse().ok())
            .map_or(ProcState::Unknown, ProcState::Started)
    }

    fn exe(&self, pid: u32) -> Option<String> {
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }

    fn kill(&self, pid: u32) -> bool {
        // `Pid::from_raw` refuses 0, and a pid above `i32::MAX` is refused here instead of wrapping negative, which
        // would signal a process group or every process.
        let Some(pid) = i32::try_from(pid).ok().and_then(rustix::process::Pid::from_raw) else {
            return false;
        };
        match rustix::process::kill_process(pid, rustix::process::Signal::KILL) {
            Ok(()) => true,
            Err(errno) => errno == rustix::io::Errno::SRCH,
        }
    }

    fn boot_id(&self) -> Option<String> {
        let id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        Some(id.trim().to_owned()).filter(|id| !id.is_empty())
    }

    fn pid_namespace(&self) -> Option<String> {
        fs::read_link("/proc/self/ns/pid")
            .ok()
            .map(|link| link.to_string_lossy().into_owned())
    }
}

/// Whether `err` is ESRCH, which a `/proc/<pid>` read returns when the process exits while it is read.
#[cfg(target_os = "linux")]
fn is_srch(err: &io::Error) -> bool {
    err.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
    };

    use anyhow::Context;

    use super::*;

    /// A table of invented processes: pid to (start, exe). Records the kills it was asked for.
    #[derive(Default)]
    struct Fake {
        procs: BTreeMap<u32, (u64, String)>,
        unreadable: BTreeSet<u32>,
        hidden_exe: BTreeSet<u32>,
        kill_fails: BTreeSet<u32>,
        boot: Option<String>,
        namespace: Option<String>,
        killed: RefCell<Vec<u32>>,
    }

    impl Fake {
        fn with(mut self, pid: u32, start: u64, exe: &str) -> Self {
            self.procs.insert(pid, (start, exe.to_owned()));
            self
        }

        /// `pid` exists but the table cannot read its state (a `/proc` read failed).
        fn unreadable(mut self, pid: u32) -> Self {
            self.unreadable.insert(pid);
            self
        }

        /// The table cannot read `pid`'s executable.
        fn hidden_exe(mut self, pid: u32) -> Self {
            self.hidden_exe.insert(pid);
            self
        }

        /// A kill signal to `pid` cannot be sent.
        fn kill_fails(mut self, pid: u32) -> Self {
            self.kill_fails.insert(pid);
            self
        }

        fn booted(mut self, boot: &str) -> Self {
            self.boot = Some(boot.to_owned());
            self
        }

        fn in_namespace(mut self, namespace: &str) -> Self {
            self.namespace = Some(namespace.to_owned());
            self
        }

        fn killed(&self) -> Vec<u32> {
            self.killed.borrow().clone()
        }
    }

    impl ProcessTable for Fake {
        fn state(&self, pid: u32) -> ProcState {
            if self.unreadable.contains(&pid) {
                return ProcState::Unknown;
            }
            self.procs
                .get(&pid)
                .map_or(ProcState::Gone, |p| ProcState::Started(p.0))
        }

        fn exe(&self, pid: u32) -> Option<String> {
            if self.hidden_exe.contains(&pid) {
                return None;
            }
            self.procs.get(&pid).map(|p| p.1.clone())
        }

        fn kill(&self, pid: u32) -> bool {
            self.killed.borrow_mut().push(pid);
            !self.kill_fails.contains(&pid)
        }

        fn boot_id(&self) -> Option<String> {
            self.boot.clone()
        }

        fn pid_namespace(&self) -> Option<String> {
            self.namespace.clone()
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

    /// A box as the daemon (pid 100, start 1000) launched it: qemu 200, virtiofsd 201. No boot or namespace is
    /// named, so the sweep takes the current ones to be the same.
    fn record() -> BoxRecord {
        BoxRecord {
            owner: id(100, 1000, DAEMON),
            procs: vec![id(200, 2000, QEMU), id(201, 2001, VIRTIOFSD)],
            boot_id: String::new(),
            pid_ns: String::new(),
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

    /// Found live (#666): nix's qemu is a wrapper that execs the real binary after `spawn` returns, so the executable
    /// recorded at launch is not the one the sweep sees. The start time survives an exec; the process must still be
    /// stopped.
    #[test]
    fn a_process_that_exec_d_another_binary_after_it_was_recorded_is_still_stopped() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = Fake::default()
            .with(200, 2000, "/nix/store/x-qemu/bin/.qemu-system-x86_64-wrapped")
            .with(201, 2001, VIRTIOFSD);

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![200, 201]);
        assert_eq!(report.killed, 2);
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
            procs: vec![id(0, 1, "/sbin/init"), id(1, 1, "/sbin/init")],
            ..record()
        };
        lay_out(base.path(), "run1", &record)?;
        let table = Fake::default().with(0, 1, "/sbin/init").with(1, 1, "/sbin/init");

        sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        Ok(())
    }

    /// Review of #666: a failed `/proc` read (no descriptors left, a `hidepid` mount) must not read as "the owner is
    /// gone", or a live box's secret directory is deleted under a running VM.
    #[test]
    fn an_owner_that_cannot_be_read_leaves_its_box_alone() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = orphaned().unreadable(100);

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert_eq!(
            report,
            SweepReport {
                undecided: 1,
                ..SweepReport::default()
            }
        );
        assert!(exists(base.path(), "run1") && exists(base.path(), "run1-inputs"));
        Ok(())
    }

    #[test]
    fn a_process_that_cannot_be_read_leaves_the_box_for_the_next_sweep() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = orphaned().unreadable(201);

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(
            table.killed(),
            vec![200],
            "the process that can be read is still stopped"
        );
        assert_eq!(
            report,
            SweepReport {
                killed: 1,
                undecided: 1,
                ..SweepReport::default()
            }
        );
        assert!(
            exists(base.path(), "run1"),
            "the box stays until every process is accounted for"
        );
        Ok(())
    }

    #[test]
    fn a_failed_kill_is_not_counted_and_leaves_the_box_for_the_next_sweep() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        let table = orphaned().kill_fails(200);

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(
            report,
            SweepReport {
                killed: 1,
                undecided: 1,
                ..SweepReport::default()
            }
        );
        assert!(exists(base.path(), "run1"));
        Ok(())
    }

    /// A reboot ends every recorded process, so nothing is killed; a pid and start time from an earlier boot could
    /// match an unrelated process of this one. The directories are only removed.
    #[test]
    fn a_box_from_an_earlier_boot_is_wiped_and_nothing_is_killed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let record = BoxRecord {
            boot_id: "boot-1".to_owned(),
            ..record()
        };
        lay_out(base.path(), "run1", &record)?;
        // Processes of this boot that happen to share the recorded pids and start times.
        let table = orphaned().booted("boot-2");

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert_eq!(
            report,
            SweepReport {
                wiped: 1,
                ..SweepReport::default()
            }
        );
        assert!(!exists(base.path(), "run1"));
        Ok(())
    }

    #[test]
    fn a_box_from_the_same_boot_is_swept_as_usual() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let record = BoxRecord {
            boot_id: "boot-1".to_owned(),
            ..record()
        };
        lay_out(base.path(), "run1", &record)?;
        let table = orphaned().booted("boot-1");

        sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![200, 201]);
        Ok(())
    }

    /// Pids mean nothing in another pid namespace (a container sharing the base): the sweep cannot judge the box.
    #[test]
    fn a_box_from_another_pid_namespace_is_left_alone() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let record = BoxRecord {
            pid_ns: "pid:[1]".to_owned(),
            ..record()
        };
        lay_out(base.path(), "run1", &record)?;
        let table = orphaned().in_namespace("pid:[2]");

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert_eq!(
            report,
            SweepReport {
                undecided: 1,
                ..SweepReport::default()
            }
        );
        assert!(exists(base.path(), "run1"));
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

    /// A record that is itself a symlink is not ours to trust, even when it points at a well-formed one.
    #[test]
    fn a_symlinked_record_is_not_read() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let elsewhere = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join("run1")).context("dir")?;
        fs::write(
            elsewhere.path().join("real.json"),
            serde_json::to_vec(&record()).context("encode")?,
        )
        .context("write")?;
        std::os::unix::fs::symlink(
            elsewhere.path().join("real.json"),
            base.path().join("run1").join(RECORD_FILE),
        )
        .context("symlink")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(
            report,
            SweepReport {
                unreadable: 1,
                ..SweepReport::default()
            }
        );
        assert!(table.killed().is_empty());
        assert!(exists(base.path(), "run1"));
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

    /// The `-inputs` and `-outputs` directories are removed with the box; a symlink standing in for one is not
    /// followed, and its target is untouched.
    #[test]
    fn a_symlinked_sibling_directory_is_not_followed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let elsewhere = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), "run1", &record())?;
        fs::remove_dir_all(base.path().join("run1-inputs")).context("remove")?;
        fs::write(elsewhere.path().join("precious"), b"keep").context("write")?;
        std::os::unix::fs::symlink(elsewhere.path(), base.path().join("run1-inputs")).context("symlink")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report.wiped, 1);
        assert!(!exists(base.path(), "run1") && !exists(base.path(), "run1-outputs"));
        assert!(
            fs::symlink_metadata(base.path().join("run1-inputs")).is_ok(),
            "the link is left in place"
        );
        assert!(elsewhere.path().join("precious").exists(), "its target is untouched");
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
            .with(201, 2001, VIRTIOFSD)
            .booted("boot-1")
            .in_namespace("pid:[1]");

        let mut writer = RecordWriter::create(dir.path(), &table, 100).context("create")?;
        let read = |dir: &Path| -> anyhow::Result<BoxRecord> {
            serde_json::from_slice(&fs::read(dir.join(RECORD_FILE)).context("read")?).context("decode")
        };
        assert_eq!(
            read(dir.path())?,
            BoxRecord {
                owner: id(100, 1000, DAEMON),
                procs: vec![],
                boot_id: "boot-1".to_owned(),
                pid_ns: "pid:[1]".to_owned(),
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
        let table = Fake::default().with(100, 1000, DAEMON).unreadable(300);
        assert!(
            RecordWriter::create(dir.path(), &Fake::default(), 100).is_err(),
            "unknown owner"
        );

        let mut writer = RecordWriter::create(dir.path(), &table, 100).context("create")?;
        let before = fs::read(dir.path().join(RECORD_FILE)).context("read")?;
        assert!(writer.add(&table, 999).is_err(), "unknown process");
        assert!(writer.add(&table, 300).is_err(), "a process whose state cannot be read");
        assert_eq!(fs::read(dir.path().join(RECORD_FILE)).context("read")?, before);
        Ok(())
    }

    /// The executable is only for a human reader and is never compared, so a process whose executable cannot be read
    /// is still recorded, and can still be stopped.
    #[test]
    fn a_process_whose_executable_cannot_be_read_is_still_recorded() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("tempdir")?;
        let table = Fake::default()
            .with(100, 1000, DAEMON)
            .with(200, 2000, QEMU)
            .hidden_exe(200);

        let mut writer = RecordWriter::create(dir.path(), &table, 100).context("create")?;
        writer
            .add(&table, 200)
            .context("a hidden executable must not stop the record")?;

        let record: BoxRecord =
            serde_json::from_slice(&fs::read(dir.path().join(RECORD_FILE)).context("read")?).context("decode")?;
        assert_eq!(record.procs, vec![id(200, 2000, "")]);
        Ok(())
    }

    /// The real process table reads this very process: it is alive, started, runs the test binary, and has a boot id
    /// and a pid namespace.
    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_identifies_the_running_process() -> anyhow::Result<()> {
        let pid = std::process::id();
        let table = Procfs;
        assert!(matches!(table.state(pid), ProcState::Started(_)));
        let exe = table.exe(pid).context("exe")?;
        assert_eq!(Path::new(&exe), std::env::current_exe().context("current_exe")?);
        assert_eq!(table.state(u32::MAX - 1), ProcState::Gone);
        assert!(
            table.boot_id().is_some_and(|id| !id.is_empty()),
            "a Linux host has a boot id"
        );
        assert!(
            table.pid_namespace().is_some_and(|ns| ns.starts_with("pid:[")),
            "and a pid namespace"
        );
        Ok(())
    }

    /// A pid that cannot be signalled is reported, not ignored: pid 1 is never ours, and a pid above `i32::MAX`
    /// would wrap to a negative one (a process group or every process) if it were not refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_refuses_a_pid_it_cannot_signal() {
        let table = Procfs;
        assert!(!table.kill(0), "pid 0 would signal this process's group");
        assert!(!table.kill(u32::MAX), "u32::MAX wraps to -1, every process");
        assert!(
            !table.kill(i32::MAX as u32 + 1),
            "above i32::MAX wraps negative, a process group"
        );
    }
}
