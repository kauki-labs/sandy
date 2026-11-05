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
    time::{Duration, Instant},
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

/// What [`ProcessTable::kill_started`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kill {
    /// The kill signal was sent to the process.
    Signalled,
    /// There is no such process, or the pid now belongs to a process that started at another time. Nothing was sent.
    Gone,
    /// The check or the signal could not be done (no permission, an unreadable process, an invalid pid). Nothing was
    /// sent that could be confirmed.
    Failed,
}

/// What the sweep needs to know about the host's processes, and the one thing it does to them. A trait so tests
/// use a table of invented processes on any host; [`Procfs`] is the Linux implementation.
pub trait ProcessTable {
    /// Whether `pid` exists and when it started.
    fn state(&self, pid: u32) -> ProcState;
    /// The path of `pid`'s executable, or `None` when it cannot be read. Recorded for a human reading the record; the
    /// sweep never compares it, because a wrapper execs another binary after the process is recorded.
    fn exe(&self, pid: u32) -> Option<String>;
    /// Send an unblockable kill to the process `pid` that started at `start`, and to that process only. The check and
    /// the signal are bound to one process, so a process that takes the pid after the check cannot receive the signal.
    fn kill_started(&self, pid: u32, start: u64) -> Kill;
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

    /// The writer for the box whose run directory is `dir`: the record already there when it names the same owner
    /// (it is adopted, with the processes it already lists), else a new one. Each stage of a launch opens the record
    /// this way, so a process recorded by an earlier stage is not lost.
    ///
    /// # Errors
    ///
    /// As [`create`](Self::create).
    pub fn open_or_create(dir: &Path, table: &dyn ProcessTable, owner_pid: u32) -> io::Result<Self> {
        let path = dir.join(RECORD_FILE);
        let owner = identify(table, owner_pid)?;
        if let Ok(Some(record)) = read_record(&path)
            && record.owner.pid == owner.pid
            && record.owner.start == owner.start
        {
            return Ok(Self { path, record });
        }
        Self::create(dir, table, owner_pid)
    }

    /// Add a started process to the record and rewrite it.
    ///
    /// # Errors
    ///
    /// When `pid` cannot be identified through `table`, or the record cannot be written. The file keeps its
    /// previous content then.
    pub fn add(&mut self, table: &dyn ProcessTable, pid: u32) -> io::Result<()> {
        let process = identify(table, pid)?;
        // A process the record already names (an earlier stage recorded it) is not listed again.
        if self
            .record
            .procs
            .iter()
            .any(|p| p.pid == process.pid && p.start == process.start)
        {
            return Ok(());
        }
        let mut next = self.record.clone();
        next.procs.push(process);
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
    // The record lives in the run directory, so it goes last: while any sibling is left, the next sweep still finds
    // the record and finishes the job.
    for dir in [format!("{name}-inputs"), format!("{name}-outputs")] {
        if !remove_orphan_dir(base, &dir) {
            return false;
        }
    }
    remove_orphan_dir(base, name)
}

/// Remove one directory of a box. A missing path or a non-directory (a symlink is left alone) counts as removed;
/// `false` means the directory is still there.
fn remove_orphan_dir(base: &Path, dir: &str) -> bool {
    let path = base.join(dir);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => return true,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return true,
        Err(err) => {
            tracing::warn!(dir = %path.display(), %err, "could not inspect an orphaned box directory");
            return false;
        }
    }
    match fs::remove_dir_all(&path) {
        Ok(()) => true,
        Err(err) if err.kind() == io::ErrorKind::NotFound => true,
        Err(err) => {
            tracing::warn!(dir = %path.display(), %err, "could not remove an orphaned box directory");
            false
        }
    }
}

/// What one sweep did. Counts only: nothing here repeats text from a record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Processes sent the kill signal. Whether each has exited decides `wiped` and `undecided`.
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
    sweep_within(base, table, STOP_WAIT)
}

/// How long the sweep waits for a killed process to exit before it leaves the box for the next sweep.
const STOP_WAIT: Duration = Duration::from_secs(3);

/// [`sweep_orphans`] with the exit wait given, so a test does not wait for seconds.
fn sweep_within(base: &Path, table: &dyn ProcessTable, wait: Duration) -> SweepReport {
    let mut report = SweepReport::default();
    let Ok(entries) = fs::read_dir(base) else {
        return report;
    };
    for entry in entries.flatten() {
        // `DirEntry::file_type` does not follow a symlink, so a link to a directory is skipped here.
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        // Only a directory a run creates holds a record. `<run>-outputs` is writable by the guest and the base holds
        // other directories, so a record found anywhere else could name a host process to kill.
        let Some(name) = entry
            .file_name()
            .to_str()
            .filter(|n| is_run_dir_name(n))
            .map(str::to_owned)
        else {
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
            } else {
                report.undecided += 1;
            }
            continue;
        }
        // Pids mean nothing in another pid namespace, so the box cannot be judged from here. A namespace that cannot
        // be read cannot be compared either, so it is not taken to match.
        if !record.pid_ns.is_empty() && table.pid_namespace().is_none_or(|ns| ns != record.pid_ns) {
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
        let mut signalled = Vec::new();
        for process in &record.procs {
            // Pid 0 and 1 are never ours, whatever a record says.
            if process.pid <= 1 {
                continue;
            }
            match table.kill_started(process.pid, process.start) {
                Kill::Signalled => {
                    report.killed += 1;
                    signalled.push(process);
                }
                Kill::Gone => {}
                Kill::Failed => undecided = true,
            }
        }
        // A signal that was sent is not an exit: a process stuck in uninterruptible I/O survives it. Its box, and the
        // secret share in it, stay until every signalled process is gone.
        if !signalled.is_empty() && !all_exited(table, &signalled, wait) {
            undecided = true;
        }
        // A process that could not be read or stopped, or a directory that could not be removed, leaves the box (and
        // its record) for the next sweep.
        if undecided || !wipe_box(base, &name) {
            report.undecided += 1;
        } else {
            report.wiped += 1;
        }
    }
    report
}

/// Whether every one of `processes` has exited, polling for up to `wait`. A process that cannot be read has not been
/// shown to have exited.
fn all_exited(table: &dyn ProcessTable, processes: &[&ProcId], wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        let exited = |p: &&ProcId| match table.state(p.pid) {
            ProcState::Gone => true,
            ProcState::Started(start) => start != p.start,
            ProcState::Unknown => false,
        };
        if processes.iter().all(exited) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Whether a directory name is one a run creates: a UUID, or `inst-` and a UUID.
fn is_run_dir_name(name: &str) -> bool {
    let id = name.strip_prefix("inst-").unwrap_or(name);
    // `parse_str` also takes the simple, braced and upper case forms; a run makes only the hyphenated lower case one.
    uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
}

/// What a `/proc/<pid>/stat` text says about the process, or `Unknown` when it does not parse.
#[cfg(any(target_os = "linux", test))]
fn parse_stat(stat: &str) -> ProcState {
    // Field 2 (the command name) may hold spaces and parentheses; field 3, the state, starts after the last `)`.
    let Some(end) = stat.rfind(')') else {
        return ProcState::Unknown;
    };
    let mut fields = stat[end + 1..].split_whitespace();
    // `Z` (zombie) and `X` (dead) have exited and only await reaping: a killed process whose parent has not reaped it
    // keeps its `/proc` entry, and must not read as running.
    if matches!(fields.next(), Some("Z" | "X")) {
        return ProcState::Gone;
    }
    // Field 22, the start time in clock ticks since boot, is the 19th after the state.
    fields
        .nth(18)
        .and_then(|start| start.parse().ok())
        .map_or(ProcState::Unknown, ProcState::Started)
}

/// What a failed `/proc/<pid>/stat` read says about the process.
#[cfg(any(target_os = "linux", test))]
fn classify_missing(not_found: bool, srch: bool, proc_mounted: bool) -> ProcState {
    // ESRCH: the process exited while it was read. ENOENT means "no such process" only while `/proc` is mounted:
    // without it every pid reads ENOENT, and every process would read as gone.
    if srch || (not_found && proc_mounted) {
        ProcState::Gone
    } else {
        ProcState::Unknown
    }
}

/// The process table of a Linux host, read from `/proc`.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Procfs;

#[cfg(target_os = "linux")]
impl ProcessTable for Procfs {
    fn state(&self, pid: u32) -> ProcState {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => parse_stat(&stat),
            Err(err) => classify_missing(
                err.kind() == io::ErrorKind::NotFound,
                is_srch(&err),
                Path::new("/proc/self/stat").exists(),
            ),
        }
    }

    fn exe(&self, pid: u32) -> Option<String> {
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }

    fn kill_started(&self, pid: u32, start: u64) -> Kill {
        use rustix::{
            io::Errno,
            process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal},
        };

        // `Pid::from_raw` refuses 0, and a pid above `i32::MAX` is refused here instead of wrapping negative, which
        // would signal a process group or every process.
        let Some(raw) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
            return Kill::Failed;
        };
        // A pidfd names one process for good. The start time is read after it is open and the signal goes through it,
        // so a process that takes the pid after the check cannot receive the kill. Never a fall back to the bare pid.
        let fd = match pidfd_open(raw, PidfdFlags::empty()) {
            Ok(fd) => fd,
            Err(errno) if errno == Errno::SRCH => return Kill::Gone,
            Err(_) => return Kill::Failed,
        };
        match self.state(pid) {
            ProcState::Started(found) if found == start => {}
            ProcState::Gone | ProcState::Started(_) => return Kill::Gone,
            ProcState::Unknown => return Kill::Failed,
        }
        match pidfd_send_signal(&fd, Signal::KILL) {
            Ok(()) => Kill::Signalled,
            Err(errno) if errno == Errno::SRCH => Kill::Gone,
            Err(_) => Kill::Failed,
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

/// What an answer of "no such process" is worth. `ps` prints nothing for a pid that does not exist, but it also prints
/// nothing when it is denied access to process information (a sandbox, a restricted launch context). So a "gone" is
/// believed only if `control`, the same question asked about this very process, saw it: a `ps` that cannot see the
/// process asking cannot say that another one is gone.
#[cfg(any(target_os = "macos", test))]
fn gone_or_blind(parsed: ProcState, _control: ProcState) -> ProcState {
    parsed
}

/// What `ps -o state=,lstart=` printed for one pid, as a [`ProcState`]. `ps` prints nothing for a pid that does not
/// exist. The state letter is only for telling a zombie (`Z`) or dead (`X`) process, which has exited, from a running
/// one. The start time is the five fields of `lstart` (`Wed Nov  5 10:23:45 2026`), hashed: it is only ever compared
/// for equality, and a process that took the pid later started later, so it never matches.
#[cfg(any(target_os = "macos", test))]
fn parse_ps_state(stdout: &str) -> ProcState {
    let line = stdout.trim();
    if line.is_empty() {
        return ProcState::Gone;
    }
    let mut fields = line.split_whitespace();
    let Some(state) = fields.next() else {
        return ProcState::Unknown;
    };
    if state.starts_with(['Z', 'X']) {
        return ProcState::Gone;
    }
    // `lstart` is five fields: a weekday, a month, a day, a time and a year. Anything else (an error line, a cut
    // answer) says nothing about the process.
    let started: Vec<&str> = fields.collect();
    if started.len() != 5 {
        return ProcState::Unknown;
    }
    ProcState::Started(fnv1a(&started.join(" ")))
}

/// FNV-1a over `text`: a stable 64 bit identity for a start time string.
#[cfg(any(target_os = "macos", test))]
fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The process table of a macOS host, read through `ps`. The crate forbids `unsafe`, so there is no `proc_pidinfo`.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Ps;

#[cfg(target_os = "macos")]
impl Ps {
    /// The command for `/bin/ps` and `/usr/sbin/sysctl`: a fixed locale, no input.
    fn command(program: &str, args: &[&str]) -> std::process::Command {
        let mut command = std::process::Command::new(program);
        command.env("LC_ALL", "C").args(args).stdin(std::process::Stdio::null());
        command
    }

    fn run(program: &str, args: &[&str]) -> Option<std::process::Output> {
        Self::command(program, args).output().ok()
    }
}

#[cfg(target_os = "macos")]
impl ProcessTable for Ps {
    fn state(&self, pid: u32) -> ProcState {
        let Some(out) = Self::run("/bin/ps", &["-o", "state=,lstart=", "-p", &pid.to_string()]) else {
            return ProcState::Unknown;
        };
        // `ps` exits 1 and prints nothing at all for a pid that does not exist. Any other failure, or a failure that
        // says something on stderr (a bad option, a refused call), tells nothing about the process.
        match out.status.code() {
            Some(0) => parse_ps_state(&String::from_utf8_lossy(&out.stdout)),
            Some(1) if out.stderr.is_empty() => parse_ps_state(&String::from_utf8_lossy(&out.stdout)),
            _ => ProcState::Unknown,
        }
    }

    fn exe(&self, pid: u32) -> Option<String> {
        let out = Self::run("/bin/ps", &["-o", "comm=", "-p", &pid.to_string()])?;
        let comm = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        (out.status.success() && !comm.is_empty()).then_some(comm)
    }

    fn kill_started(&self, pid: u32, start: u64) -> Kill {
        use rustix::{
            io::Errno,
            process::{Pid, Signal, kill_process},
        };

        let Some(raw) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
            return Kill::Failed;
        };
        // macOS has no pidfd, so this is check then kill: the window is one `ps` call. A process that took the pid in
        // it would also have to have started at exactly the recorded second, which a process that is not the recorded
        // one cannot (it started later).
        match self.state(pid) {
            ProcState::Started(found) if found == start => {}
            ProcState::Gone | ProcState::Started(_) => return Kill::Gone,
            ProcState::Unknown => return Kill::Failed,
        }
        match kill_process(raw, Signal::KILL) {
            Ok(()) => Kill::Signalled,
            Err(errno) if errno == Errno::SRCH => Kill::Gone,
            Err(_) => Kill::Failed,
        }
    }

    fn boot_id(&self) -> Option<String> {
        let out = Self::run("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"])?;
        let id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        (out.status.success() && !id.is_empty()).then_some(id)
    }

    /// macOS has no pid namespaces.
    fn pid_namespace(&self) -> Option<String> {
        None
    }
}

/// The process table of this host.
#[cfg(target_os = "linux")]
pub(crate) type Host = Procfs;

/// The process table of this host.
#[cfg(target_os = "macos")]
pub(crate) type Host = Ps;

/// The box's record of the processes it started (#666). Best effort: a run must not fail because its record could not
/// be written, so a failure is logged and the box simply goes unrecorded.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct BoxRecorder(Option<RecordWriter>);

/// A host with no process table to read records nothing.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) struct BoxRecorder;

impl BoxRecorder {
    /// Open the record in `dir`, adopting what an earlier stage of the launch wrote.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn open(dir: &Path) -> Self {
        match RecordWriter::open_or_create(dir, &Host::default(), std::process::id()) {
            Ok(writer) => Self(Some(writer)),
            Err(err) => {
                tracing::warn!(%err, "could not write the box record; a killed host would leave this VM behind");
                Self(None)
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn open(_dir: &Path) -> Self {
        Self
    }

    /// Add a process the launch just started.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn add(&mut self, pid: u32) {
        if let Some(writer) = &mut self.0
            && let Err(err) = writer.add(&Host::default(), pid)
        {
            tracing::warn!(pid, %err, "could not record a started process; it would outlive a killed host");
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn add(&mut self, _pid: u32) {}
}

/// Stop the VMs that a killed host process (`sandyd` or a `sandy run`) left behind, and remove their staging
/// directories (#666). It reads the records under the staging base, so it sweeps a box whichever hypervisor wrote it.
/// Call it once at start-up, before launching. It stops only a process that a box record proves is ours, and only for a
/// box whose owner is gone, so a running daemon or CLI is never touched. A no-op on a host with no process table.
#[must_use]
pub fn sweep_orphaned_vms() -> SweepReport {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match sandy::ensure_sandy_staging_base() {
        Ok(base) => {
            let report = sweep_orphans(&base, &Host::default());
            if report != SweepReport::default() {
                tracing::info!(?report, "swept the VMs a killed host left behind");
            }
            report
        }
        Err(err) => {
            tracing::warn!(%err, "could not open the staging base to sweep for orphaned VMs");
            SweepReport::default()
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    SweepReport::default()
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
    };

    use anyhow::Context;

    use super::*;

    /// A table of invented processes: pid to (start, exe). A kill removes the process, unless it is stubborn.
    #[derive(Default)]
    struct Fake {
        procs: RefCell<BTreeMap<u32, (u64, String)>>,
        unreadable: BTreeSet<u32>,
        hidden_exe: BTreeSet<u32>,
        kill_fails: BTreeSet<u32>,
        /// Survives the kill signal (stuck in uninterruptible I/O).
        stubborn: BTreeSet<u32>,
        /// A different process holds the pid by the time the kill is sent.
        replaced: BTreeSet<u32>,
        boot: Option<String>,
        namespace: Option<String>,
        killed: RefCell<Vec<u32>>,
    }

    impl Fake {
        fn with(self, pid: u32, start: u64, exe: &str) -> Self {
            self.procs.borrow_mut().insert(pid, (start, exe.to_owned()));
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

        fn stubborn(mut self, pid: u32) -> Self {
            self.stubborn.insert(pid);
            self
        }

        fn replaced(mut self, pid: u32) -> Self {
            self.replaced.insert(pid);
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

        fn running(&self, pid: u32) -> bool {
            self.procs.borrow().contains_key(&pid)
        }
    }

    impl ProcessTable for Fake {
        fn state(&self, pid: u32) -> ProcState {
            if self.unreadable.contains(&pid) {
                return ProcState::Unknown;
            }
            self.procs
                .borrow()
                .get(&pid)
                .map_or(ProcState::Gone, |p| ProcState::Started(p.0))
        }

        fn exe(&self, pid: u32) -> Option<String> {
            if self.hidden_exe.contains(&pid) {
                return None;
            }
            self.procs.borrow().get(&pid).map(|p| p.1.clone())
        }

        fn kill_started(&self, pid: u32, start: u64) -> Kill {
            if self.kill_fails.contains(&pid) || self.unreadable.contains(&pid) {
                return Kill::Failed;
            }
            if self.replaced.contains(&pid) {
                return Kill::Gone;
            }
            let matches = self.procs.borrow().get(&pid).is_some_and(|p| p.0 == start);
            if !matches {
                return Kill::Gone;
            }
            self.killed.borrow_mut().push(pid);
            if !self.stubborn.contains(&pid) {
                self.procs.borrow_mut().remove(&pid);
            }
            Kill::Signalled
        }

        fn boot_id(&self) -> Option<String> {
            self.boot.clone()
        }

        fn pid_namespace(&self) -> Option<String> {
            self.namespace.clone()
        }
    }

    /// The sweep with a short exit wait, so a stubborn process does not hold a test for seconds.
    fn sweep_orphans(base: &Path, table: &dyn ProcessTable) -> SweepReport {
        sweep_within(base, table, Duration::from_millis(40))
    }

    const QEMU: &str = "/nix/store/x-qemu/bin/qemu-system-x86_64";
    const VIRTIOFSD: &str = "/nix/store/x-virtiofsd/bin/virtiofsd";
    const DAEMON: &str = "/nix/store/x-sandyd/bin/sandyd";

    /// Run directory names, as a run makes them: a UUID.
    const RUN1: &str = "0f6c3a52-1b9d-4c43-8a3e-000000000001";
    const RUN2: &str = "0f6c3a52-1b9d-4c43-8a3e-000000000002";
    const RUN3: &str = "0f6c3a52-1b9d-4c43-8a3e-000000000003";

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

    /// A `/proc/<pid>/stat` line: pid, command, state, then fields 4 to 21 and the start time as field 22.
    fn stat_line(comm: &str, state: &str, start: u64) -> String {
        format!(
            "123 ({comm}) {state} 1 123 123 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 200 \
             18446744073709551615"
        )
    }

    #[test]
    fn a_box_whose_owner_died_is_stopped_and_wiped() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
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
        for name in [RUN1.to_owned(), format!("{RUN1}-inputs"), format!("{RUN1}-outputs")] {
            assert!(!exists(base.path(), &name), "{name} must be removed");
        }
        Ok(())
    }

    #[test]
    fn a_box_with_a_live_owner_is_left_alone() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
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
        assert!(exists(base.path(), RUN1) && exists(base.path(), &format!("{RUN1}-inputs")));
        Ok(())
    }

    #[test]
    fn an_owner_pid_reused_by_another_process_does_not_protect_the_box() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
        // Pid 100 now belongs to a different process that started later.
        let table = orphaned().with(100, 5000, "/usr/bin/bash");

        sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![200, 201]);
        assert!(!exists(base.path(), RUN1));
        Ok(())
    }

    #[test]
    fn a_pid_reused_by_another_process_is_not_killed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
        // 200 now runs something that started later; 201 is the same executable but a later start.
        let table = Fake::default().with(200, 9000, QEMU).with(201, 9001, VIRTIOFSD);

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert_eq!(report.killed, 0);
        assert_eq!(report.wiped, 1, "the dead box's directories are still removed");
        assert!(!exists(base.path(), RUN1));
        Ok(())
    }

    /// Found live (#666): nix's qemu is a wrapper that execs the real binary after `spawn` returns, so the executable
    /// recorded at launch is not the one the sweep sees. The start time survives an exec; the process must still be
    /// stopped.
    #[test]
    fn a_process_that_exec_d_another_binary_after_it_was_recorded_is_still_stopped() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
        let table = Fake::default()
            .with(200, 2000, "/nix/store/x-qemu/bin/.qemu-system-x86_64-wrapped")
            .with(201, 2001, VIRTIOFSD);

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![200, 201]);
        assert_eq!(report.killed, 2);
        Ok(())
    }

    /// Review of #666: the check and the kill are one step on one process. A process that takes the pid after the
    /// check must not receive the signal.
    #[test]
    fn a_process_replaced_between_the_check_and_the_kill_is_not_killed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
        let table = orphaned().replaced(200);

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(table.killed(), vec![201], "the replacement of 200 gets no signal");
        assert!(table.running(200), "and keeps running");
        assert_eq!((report.killed, report.wiped), (1, 1));
        Ok(())
    }

    /// Review of #666: a signal that was sent is not an exit. A process stuck in uninterruptible I/O survives it, and
    /// its secret share must not be deleted under it.
    #[test]
    fn a_process_that_survives_the_kill_keeps_its_box() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
        let table = orphaned().stubborn(200);

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(
            report,
            SweepReport {
                killed: 2,
                undecided: 1,
                ..SweepReport::default()
            }
        );
        assert!(exists(base.path(), RUN1) && exists(base.path(), &format!("{RUN1}-inputs")));
        Ok(())
    }

    #[test]
    fn a_process_that_already_exited_is_only_wiped() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
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
        lay_out(base.path(), RUN1, &record)?;
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
        lay_out(base.path(), RUN1, &record())?;
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
        assert!(exists(base.path(), RUN1) && exists(base.path(), &format!("{RUN1}-inputs")));
        Ok(())
    }

    #[test]
    fn a_process_that_cannot_be_read_leaves_the_box_for_the_next_sweep() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
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
            exists(base.path(), RUN1),
            "the box stays until every process is accounted for"
        );
        Ok(())
    }

    #[test]
    fn a_failed_kill_is_not_counted_and_leaves_the_box_for_the_next_sweep() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
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
        assert!(exists(base.path(), RUN1));
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
        lay_out(base.path(), RUN1, &record)?;
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
        assert!(!exists(base.path(), RUN1));
        Ok(())
    }

    #[test]
    fn a_box_from_the_same_boot_is_swept_as_usual() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let record = BoxRecord {
            boot_id: "boot-1".to_owned(),
            ..record()
        };
        lay_out(base.path(), RUN1, &record)?;
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
        lay_out(base.path(), RUN1, &record)?;
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
        assert!(exists(base.path(), RUN1));
        Ok(())
    }

    /// Review of #666: a sweep that cannot read its own namespace cannot compare it either, so the box is not judged.
    #[test]
    fn a_box_whose_namespace_cannot_be_compared_is_left_alone() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let record = BoxRecord {
            pid_ns: "pid:[1]".to_owned(),
            ..record()
        };
        lay_out(base.path(), RUN1, &record)?;
        // The table has no namespace to compare with.
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert_eq!(report.undecided, 1);
        assert!(exists(base.path(), RUN1));
        Ok(())
    }

    #[test]
    fn a_corrupt_record_leaves_its_directory_and_does_not_stop_the_pass() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join(RUN2)).context("bad dir")?;
        fs::write(base.path().join(RUN2).join(RECORD_FILE), b"{not json").context("bad record")?;
        fs::create_dir_all(base.path().join(RUN3)).context("dir")?;
        fs::write(
            base.path().join(RUN3).join(RECORD_FILE),
            br#"{"owner":{"pid":1,"start":1,"exe":"x"},"procs":[],"extra":1}"#,
        )
        .context("record")?;
        lay_out(base.path(), RUN1, &record())?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report.unreadable, 2);
        assert_eq!(report.wiped, 1);
        assert!(exists(base.path(), RUN2) && exists(base.path(), RUN3));
        assert!(!exists(base.path(), RUN1));
        Ok(())
    }

    #[test]
    fn an_oversized_record_is_not_read() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join(RUN2)).context("dir")?;
        let padding = " ".repeat(usize::try_from(MAX_RECORD_BYTES)? + 1);
        let json = serde_json::to_string(&record()).context("encode")?;
        fs::write(base.path().join(RUN2).join(RECORD_FILE), format!("{json}{padding}")).context("write")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report.unreadable, 1);
        assert!(table.killed().is_empty());
        assert!(exists(base.path(), RUN2));
        Ok(())
    }

    /// A record that is itself a symlink is not ours to trust, even when it points at a well-formed one.
    #[test]
    fn a_symlinked_record_is_not_read() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let elsewhere = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join(RUN1)).context("dir")?;
        fs::write(
            elsewhere.path().join("real.json"),
            serde_json::to_vec(&record()).context("encode")?,
        )
        .context("write")?;
        std::os::unix::fs::symlink(
            elsewhere.path().join("real.json"),
            base.path().join(RUN1).join(RECORD_FILE),
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
        assert!(exists(base.path(), RUN1));
        Ok(())
    }

    #[test]
    fn a_directory_without_a_record_is_never_touched() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        fs::create_dir_all(base.path().join("cred-abc")).context("dir")?;
        fs::create_dir_all(base.path().join(RUN2)).context("run dir without a record")?;
        fs::write(base.path().join("a-file"), b"x").context("file")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report, SweepReport::default());
        assert!(exists(base.path(), "cred-abc") && exists(base.path(), RUN2) && exists(base.path(), "a-file"));
        Ok(())
    }

    /// Review of #666 (a guest can write `<run>-outputs`, and the staging base holds other directories): only a
    /// directory a run creates is read for a record. A forged record elsewhere must not get a host process killed.
    #[test]
    fn a_record_in_a_directory_that_is_not_a_run_directory_is_ignored() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        // A record that names an unrelated host process (pid 300) as an orphan to kill.
        let forged = BoxRecord {
            owner: id(100, 1000, DAEMON),
            procs: vec![id(300, 3000, "/usr/bin/important")],
            boot_id: String::new(),
            pid_ns: String::new(),
        };
        for name in [
            format!("{RUN1}-outputs"),
            format!("{RUN1}-inputs"),
            "run1".to_owned(),
            "inst-not-a-uuid".to_owned(),
            RUN1.to_uppercase(),
        ] {
            fs::create_dir_all(base.path().join(&name)).context("dir")?;
            fs::write(
                base.path().join(&name).join(RECORD_FILE),
                serde_json::to_vec(&forged).context("encode")?,
            )
            .context("write")?;
        }
        let table = orphaned().with(300, 3000, "/usr/bin/important");

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report, SweepReport::default());
        assert!(table.killed().is_empty(), "{:?}", table.killed());
        assert!(table.running(300));
        Ok(())
    }

    #[test]
    fn a_vfkit_run_directory_name_is_a_run_directory() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), &format!("inst-{RUN1}"), &record())?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!((report.killed, report.wiped), (2, 1));
        Ok(())
    }

    #[test]
    fn run_directory_names_are_exactly_a_uuid_or_inst_and_a_uuid() {
        assert!(is_run_dir_name(RUN1));
        assert!(is_run_dir_name(&format!("inst-{RUN1}")));
        for not in [
            "",
            "inst-",
            "run1",
            "inst-run1",
            &format!("{RUN1}-inputs"),
            &format!("{RUN1}-outputs"),
            &RUN1.to_uppercase(),
            &RUN1.replace('-', ""),
            &format!("{{{RUN1}}}"),
        ] {
            assert!(!is_run_dir_name(not), "{not:?}");
        }
    }

    #[test]
    fn a_symlink_to_a_box_directory_is_not_followed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let elsewhere = tempfile::tempdir().context("tempdir")?;
        lay_out(elsewhere.path(), RUN2, &record())?;
        std::os::unix::fs::symlink(elsewhere.path().join(RUN2), base.path().join(RUN1)).context("symlink")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report, SweepReport::default());
        assert!(table.killed().is_empty());
        assert!(exists(elsewhere.path(), RUN2));
        Ok(())
    }

    /// The `-inputs` and `-outputs` directories are removed with the box; a symlink standing in for one is not
    /// followed, and its target is untouched.
    #[test]
    fn a_symlinked_sibling_directory_is_not_followed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("tempdir")?;
        let elsewhere = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
        fs::remove_dir_all(base.path().join(format!("{RUN1}-inputs"))).context("remove")?;
        fs::write(elsewhere.path().join("precious"), b"keep").context("write")?;
        std::os::unix::fs::symlink(elsewhere.path(), base.path().join(format!("{RUN1}-inputs"))).context("symlink")?;
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);

        assert_eq!(report.wiped, 1);
        assert!(!exists(base.path(), RUN1) && !exists(base.path(), &format!("{RUN1}-outputs")));
        assert!(
            fs::symlink_metadata(base.path().join(format!("{RUN1}-inputs"))).is_ok(),
            "the link is left in place"
        );
        assert!(elsewhere.path().join("precious").exists(), "its target is untouched");
        Ok(())
    }

    /// Review of #666: the record lives in the run directory, so the siblings go first. A sibling that cannot be
    /// removed must leave the run directory and its record for the next sweep, not strand a directory with no record.
    #[test]
    fn a_sibling_that_cannot_be_removed_keeps_the_record() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let base = tempfile::tempdir().context("tempdir")?;
        lay_out(base.path(), RUN1, &record())?;
        let locked = base.path().join(format!("{RUN1}-inputs")).join("locked");
        fs::create_dir_all(&locked).context("locked dir")?;
        fs::write(locked.join("file"), b"x").context("file")?;
        // A directory that cannot be written to cannot lose its entries.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).context("chmod")?;
        if fs::File::create(locked.join("probe")).is_ok() {
            // Running as root: permissions do not stop the removal, so there is nothing to test here.
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).context("restore")?;
            return Ok(());
        }
        let table = orphaned();

        let report = sweep_orphans(base.path(), &table);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).context("restore")?;

        assert_eq!(
            report,
            SweepReport {
                killed: 2,
                undecided: 1,
                ..SweepReport::default()
            }
        );
        assert!(
            base.path().join(RUN1).join(RECORD_FILE).exists(),
            "the record stays so the next sweep can finish"
        );
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

    #[test]
    fn a_stat_line_gives_the_start_time_whatever_the_command_name_holds() {
        assert_eq!(parse_stat(&stat_line("sleep", "S", 98765)), ProcState::Started(98765));
        // A command name with spaces and parentheses must not shift the fields.
        assert_eq!(parse_stat(&stat_line("a b) (c", "R", 4242)), ProcState::Started(4242));
    }

    /// Review of #666: a killed process whose parent has not reaped it keeps its `/proc` entry as a zombie. It has
    /// exited, so a zombie owner is a dead owner and a zombie child is already stopped.
    #[test]
    fn a_zombie_or_dead_process_reads_as_gone() {
        for state in ["Z", "X"] {
            assert_eq!(parse_stat(&stat_line("qemu", state, 98765)), ProcState::Gone, "{state}");
        }
        for state in ["R", "S", "D", "T", "I"] {
            assert_eq!(
                parse_stat(&stat_line("qemu", state, 98765)),
                ProcState::Started(98765),
                "{state}"
            );
        }
    }

    #[test]
    fn a_stat_text_that_does_not_parse_is_unknown() {
        for text in [
            "",
            "123 (qemu",
            "123 (qemu) S 1",
            "123 (qemu) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 x",
        ] {
            assert_eq!(parse_stat(text), ProcState::Unknown, "{text:?}");
        }
    }

    /// Review of #666: ENOENT means "no such process" only while `/proc` is mounted. Without it every pid reads
    /// ENOENT, and every process would read as gone.
    #[test]
    fn a_missing_stat_file_means_no_such_process_only_while_proc_is_mounted() {
        assert_eq!(
            classify_missing(true, false, true),
            ProcState::Gone,
            "ENOENT with /proc"
        );
        assert_eq!(
            classify_missing(true, false, false),
            ProcState::Unknown,
            "ENOENT without /proc"
        );
        assert_eq!(
            classify_missing(false, true, false),
            ProcState::Gone,
            "ESRCH: it exited mid-read"
        );
        assert_eq!(
            classify_missing(false, false, true),
            ProcState::Unknown,
            "any other error"
        );
    }

    /// Each stage of a launch opens the same record (the run writes the owner before staging, the share transport
    /// adds each daemon as it spawns, `launch` adds the proxy and qemu), so opening must keep what is already there.
    #[test]
    fn an_existing_record_of_the_same_owner_is_adopted_with_its_processes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("tempdir")?;
        let table = Fake::default()
            .with(100, 1000, DAEMON)
            .with(200, 2000, QEMU)
            .with(201, 2001, VIRTIOFSD);
        let mut first = RecordWriter::open_or_create(dir.path(), &table, 100).context("first")?;
        first.add(&table, 201).context("add virtiofsd")?;

        let mut second = RecordWriter::open_or_create(dir.path(), &table, 100).context("second")?;
        second.add(&table, 200).context("add qemu")?;

        let record: BoxRecord =
            serde_json::from_slice(&fs::read(dir.path().join(RECORD_FILE)).context("read")?).context("decode")?;
        assert_eq!(record.procs, vec![id(201, 2001, VIRTIOFSD), id(200, 2000, QEMU)]);
        Ok(())
    }

    /// A record of another owner is not ours to extend: it is replaced.
    #[test]
    fn a_record_of_another_owner_is_replaced() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("tempdir")?;
        let table = Fake::default()
            .with(100, 1000, DAEMON)
            .with(101, 1001, DAEMON)
            .with(200, 2000, QEMU);
        let mut other = RecordWriter::create(dir.path(), &table, 101).context("other owner")?;
        other.add(&table, 200).context("add")?;

        RecordWriter::open_or_create(dir.path(), &table, 100).context("open")?;

        let record: BoxRecord =
            serde_json::from_slice(&fs::read(dir.path().join(RECORD_FILE)).context("read")?).context("decode")?;
        assert_eq!(record.owner.pid, 100);
        assert!(record.procs.is_empty(), "{:?}", record.procs);
        Ok(())
    }

    #[test]
    fn a_process_recorded_twice_is_listed_once() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("tempdir")?;
        let table = Fake::default().with(100, 1000, DAEMON).with(200, 2000, QEMU);
        let mut writer = RecordWriter::create(dir.path(), &table, 100).context("create")?;

        writer.add(&table, 200).context("first")?;
        let once = fs::read(dir.path().join(RECORD_FILE)).context("read")?;
        writer.add(&table, 200).context("second")?;

        assert_eq!(fs::read(dir.path().join(RECORD_FILE)).context("read")?, once);
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

    /// A pid that cannot be signalled is reported, not ignored: pid 0 would signal this process's group, and a pid
    /// above `i32::MAX` would wrap to a negative one (a process group or every process) if it were not refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_refuses_a_pid_it_cannot_signal() {
        let table = Procfs;
        assert_eq!(table.kill_started(0, 1), Kill::Failed, "pid 0");
        assert_eq!(table.kill_started(u32::MAX, 1), Kill::Failed, "u32::MAX wraps to -1");
        assert_eq!(
            table.kill_started(i32::MAX as u32 + 1, 1),
            Kill::Failed,
            "above i32::MAX wraps negative"
        );
    }

    /// The kill is bound to the process that started at the recorded time: a live process with another start time
    /// gets no signal. A child `sleep` is the stand-in.
    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_signals_only_the_process_that_started_at_the_recorded_time() -> anyhow::Result<()> {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .context("spawn sleep")?;
        let pid = child.id();
        let table = Procfs;
        let ProcState::Started(start) = table.state(pid) else {
            anyhow::bail!("the child must be visible");
        };

        // The wrong start time: the pid is alive but is not the recorded process.
        assert_eq!(table.kill_started(pid, start + 1), Kill::Gone);
        assert!(
            child.try_wait().context("try_wait")?.is_none(),
            "the child must be untouched"
        );

        // The right one: it is killed.
        assert_eq!(table.kill_started(pid, start), Kill::Signalled);
        let status = child.wait().context("wait")?;
        assert!(!status.success(), "{status:?}");
        // Once reaped, the same pid and start reads as gone.
        assert_eq!(table.kill_started(pid, start), Kill::Gone);
        Ok(())
    }

    #[test]
    fn a_ps_line_gives_a_start_that_identifies_the_process() {
        let started = parse_ps_state("S    Wed Nov  5 10:23:45 2026\n");
        assert!(matches!(started, ProcState::Started(_)), "{started:?}");
        // The state letter is not part of the identity: a process changes state, never its start.
        assert_eq!(started, parse_ps_state("R+   Wed Nov  5 10:23:45 2026\n"));
        // Nor is the padding `ps` puts in the day.
        assert_eq!(started, parse_ps_state("S Wed Nov 5 10:23:45 2026"));
        // A different second, or a different day, is a different process.
        assert_ne!(started, parse_ps_state("S    Wed Nov  5 10:23:46 2026\n"));
        assert_ne!(started, parse_ps_state("S    Thu Nov  6 10:23:45 2026\n"));
    }

    /// A zombie or dead process has exited and only awaits reaping.
    #[test]
    fn a_zombie_or_dead_process_reads_as_gone_in_ps() {
        for line in [
            "Z    Wed Nov  5 10:23:45 2026",
            "Z+   Wed Nov  5 10:23:45 2026",
            "X    Wed Nov  5 10:23:45 2026",
        ] {
            assert_eq!(parse_ps_state(line), ProcState::Gone, "{line}");
        }
    }

    /// `ps` prints nothing for a pid that does not exist.
    #[test]
    fn an_empty_ps_answer_means_no_such_process() {
        assert_eq!(parse_ps_state(""), ProcState::Gone);
        assert_eq!(parse_ps_state("\n"), ProcState::Gone);
    }

    /// Anything that is not a state and a start time says nothing about the process, and must not read as one that is
    /// gone.
    #[test]
    fn a_ps_answer_that_does_not_parse_is_unknown() {
        for text in ["S", "S Wed Nov", "garbage", "ps: Invalid process id: 99999999999"] {
            assert_eq!(parse_ps_state(text), ProcState::Unknown, "{text:?}");
        }
    }

    /// Review of #666: a `ps` that cannot see this very process cannot say another one is gone, or every owner would
    /// read as dead and a live box would be wiped.
    #[test]
    fn a_ps_that_cannot_see_this_process_does_not_say_another_is_gone() {
        let seen = ProcState::Started(7);
        assert_eq!(
            gone_or_blind(ProcState::Gone, seen),
            ProcState::Gone,
            "a sighted ps is believed"
        );
        assert_eq!(
            gone_or_blind(ProcState::Gone, ProcState::Gone),
            ProcState::Unknown,
            "blind"
        );
        assert_eq!(
            gone_or_blind(ProcState::Gone, ProcState::Unknown),
            ProcState::Unknown,
            "unclear"
        );
        // Only a "gone" needs the control: a process that was seen is seen, and an unknown stays unknown.
        assert_eq!(
            gone_or_blind(ProcState::Started(1), ProcState::Gone),
            ProcState::Started(1)
        );
        assert_eq!(gone_or_blind(ProcState::Unknown, seen), ProcState::Unknown);
    }

    /// Review of #666: `ps -o lstart` prints LOCAL time. A different `TZ` in the recording process and the sweeping
    /// process, or a DST change between them, would print another string for the same process: a live owner would read
    /// as another process and its box would be wiped. Every `ps` call runs in a fixed time zone.
    #[cfg(target_os = "macos")]
    #[test]
    fn ps_runs_in_a_fixed_locale_and_time_zone() {
        let command = Ps::command("/bin/ps", &["-p", "1"]);
        let env = |key: &str| {
            command
                .get_envs()
                .find(|(name, _)| *name == key)
                .and_then(|(_, value)| value.map(|v| v.to_string_lossy().into_owned()))
        };
        assert_eq!(env("LC_ALL").as_deref(), Some("C"));
        assert_eq!(env("TZ").as_deref(), Some("UTC"));
    }

    /// The same, by outcome: the identity this table gives a process is the one `ps` prints in UTC, whatever zone the
    /// host is in, and a zone 14 hours ahead prints another time (so the pin matters).
    #[cfg(target_os = "macos")]
    #[test]
    fn the_start_identity_does_not_depend_on_the_hosts_time_zone() -> anyhow::Result<()> {
        let pid = std::process::id();
        let lstart = |tz: &str| -> anyhow::Result<String> {
            let out = std::process::Command::new("/bin/ps")
                .env("LC_ALL", "C")
                .env("TZ", tz)
                .args(["-o", "lstart=", "-p", &pid.to_string()])
                .output()
                .context("run ps")?;
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
        };
        assert_ne!(
            lstart("UTC")?,
            lstart("Pacific/Kiritimati")?,
            "a zone 14 hours ahead prints another time"
        );

        let in_utc = parse_ps_state(&format!("S {}", lstart("UTC")?));
        assert!(matches!(in_utc, ProcState::Started(_)), "{in_utc:?}");
        assert_eq!(
            Ps.state(pid),
            in_utc,
            "the table must identify the process by its UTC start"
        );
        Ok(())
    }

    /// The real macOS table reads this very process, a finished child, and a live one.
    #[cfg(target_os = "macos")]
    #[test]
    fn ps_identifies_the_running_process_and_a_finished_one() -> anyhow::Result<()> {
        let table = Ps;
        let pid = std::process::id();
        assert!(matches!(table.state(pid), ProcState::Started(_)));
        assert_eq!(table.state(pid), table.state(pid), "the start time is stable");
        assert!(table.exe(pid).is_some_and(|exe| !exe.is_empty()));
        assert!(
            table.boot_id().is_some_and(|id| !id.is_empty()),
            "a macOS host has a boot session id"
        );
        assert_eq!(table.pid_namespace(), None);

        let mut finished = std::process::Command::new("true").spawn().context("spawn true")?;
        let gone = finished.id();
        finished.wait().context("wait")?;
        assert_eq!(table.state(gone), ProcState::Gone);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ps_refuses_a_pid_it_cannot_signal() {
        let table = Ps;
        assert_eq!(table.kill_started(0, 1), Kill::Failed, "pid 0");
        assert_eq!(table.kill_started(u32::MAX, 1), Kill::Failed, "u32::MAX wraps to -1");
        assert_eq!(
            table.kill_started(i32::MAX as u32 + 1, 1),
            Kill::Failed,
            "above i32::MAX"
        );
    }

    /// The kill is bound to the process that started at the recorded time: a live process with another start time gets
    /// no signal. A child `sleep` is the stand-in.
    #[cfg(target_os = "macos")]
    #[test]
    fn ps_signals_only_the_process_that_started_at_the_recorded_time() -> anyhow::Result<()> {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .context("spawn sleep")?;
        let pid = child.id();
        let table = Ps;
        let ProcState::Started(start) = table.state(pid) else {
            anyhow::bail!("the child must be visible");
        };

        assert_eq!(table.kill_started(pid, start.wrapping_add(1)), Kill::Gone);
        assert!(
            child.try_wait().context("try_wait")?.is_none(),
            "the child must be untouched"
        );

        assert_eq!(table.kill_started(pid, start), Kill::Signalled);
        let status = child.wait().context("wait")?;
        assert!(!status.success(), "{status:?}");
        assert_eq!(table.kill_started(pid, start), Kill::Gone);
        Ok(())
    }
}
