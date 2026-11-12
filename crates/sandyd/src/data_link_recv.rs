//! The receiver half of the output transfer (#482 slice 6a, sandyd.md §22): read the `OutputChunk`s a host-executor
//! sends back over the data link and write them to the submitter's output destinations.
//!
//! The host-executor is untrusted on this boundary (§22: sandyd re-validates every name a host reports), and the
//! destinations are submitter-chosen host paths that other processes can write to. So every write goes through
//! `sandy_fsutil::Beneath`: each directory is opened once with `O_NOFOLLOW`, and a file is written under a temp name
//! in its final directory and renamed into place, so a reader never sees a partial file and a symlink at the final
//! name is replaced, never followed.
//!
//! Where a chunk goes is pinned to local `collect_outputs`: for the named output `N` with destination `D`, the chunk
//! `N/rel` is written to `D/rel`, and a bare `N` is a file written to `D` itself; for a catch-all, `rel` is written
//! to `D/rel`. `OutputChunk::output_index` says which declared output the file belongs to; a file several outputs
//! cover arrives once per output, as local collection writes it to each destination.
//!
//! Failure keeps the files that already completed (local collection is best-effort per file too) and removes only the
//! file in flight. Files get mode `0600`, not the umask default local collection gives them.
//!
//! What this does NOT do: hold the job non-terminal until `OutputEnd` (6c), or send anything from the host (6b).

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    time::Duration,
};

use sandy_control_proto::{FrameError, read_frame, write_frame};
use sandy_executor_proto::{
    DataLinkMessage, DataLinkViolation, MAX_TRANSFER_BYTES, MAX_TRANSFER_ENTRIES, OutputChunk, TransferError,
    data_link_message::Op,
};
use sandy_fsutil::beneath::Beneath;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

/// The default longest gap between frames.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(30);

/// The default longest a whole receive may take, however steadily frames arrive: the idle gap alone lets a peer that
/// sends one byte just under it hold the link, an open file and a worker for days (#781). The same 30 minutes as the
/// host's input pull.
pub const DEFAULT_TOTAL: Duration = Duration::from_secs(30 * 60);

/// The default most frames one receive reads. A full transfer is at most one chunk per `MAX_CHUNK_BYTES` of data
/// (16,384 for the byte cap) plus one frame per file, so a sender that fills its chunks never comes near twice that;
/// a peer sending tiny chunks does.
pub const DEFAULT_MAX_FRAMES: usize = 2 * (MAX_TRANSFER_ENTRIES + 16_384);

/// The caps one receive enforces. The default is the §22 pair and [`DEFAULT_IDLE`]; a test lowers them.
#[derive(Debug, Clone, Copy)]
pub struct ReceiveLimits {
    /// The most file bytes the receive writes.
    pub max_bytes: u64,
    /// The most entries the receive creates: files plus the directories below a destination.
    pub max_entries: usize,
    /// The longest gap between frames.
    pub idle: Duration,
    /// The longest the whole receive may take.
    pub total: Duration,
    /// The most frames the receive reads, `OutputEnd` included.
    pub max_frames: usize,
}

impl Default for ReceiveLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_TRANSFER_BYTES,
            max_entries: MAX_TRANSFER_ENTRIES,
            idle: DEFAULT_IDLE,
            total: DEFAULT_TOTAL,
            max_frames: DEFAULT_MAX_FRAMES,
        }
    }
}

/// What a finished receive wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Files written.
    pub files: usize,
    /// File bytes written.
    pub bytes: u64,
}

/// Why a receive failed. No variant carries a peer-chosen byte. A peer-chosen name or reason reaches a variant only
/// escaped (`Write`, `PeerError`). The peer is told a fixed text, never either.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    /// Reading from the link failed.
    #[error("reading from the data link: {0}")]
    Frame(#[from] FrameError),
    /// A message broke a size or path rule.
    #[error("a data-link message broke a rule: {0}")]
    Violation(#[from] DataLinkViolation),
    /// The peer sent a `TransferError`; the reason is escaped.
    #[error("the peer reported a transfer error: {0}")]
    PeerError(String),
    /// The link closed before `OutputEnd`.
    #[error("the link closed before OutputEnd")]
    Truncated,
    /// No frame arrived within the idle limit.
    #[error("no frame arrived within the idle limit")]
    Idle,
    /// A message that is not an output message.
    #[error("an unexpected message on the output transfer")]
    Unexpected,
    /// A chunk names an output that was not declared.
    #[error("a chunk names an output index that was not declared")]
    BadIndex,
    /// A chunk's name does not start with its output's declared name.
    #[error("a chunk's name is not under its declared output")]
    NameMismatch,
    /// An empty chunk that adds nothing: after data, or a repeat.
    #[error("an empty chunk made no progress")]
    NoProgress,
    /// A file that already completed arrived again.
    #[error("a file arrived twice")]
    Reopened,
    /// Two files of the transfer name the same destination file (two spellings on a case-insensitive filesystem).
    #[error("two files of the transfer name the same destination file")]
    Alias,
    /// The transfer is past its byte cap.
    #[error("the transfer is past its byte cap")]
    TooManyBytes,
    /// The transfer is past its entry cap.
    #[error("the transfer is past its entry cap")]
    TooManyEntries,
    /// The receive ran past its total time limit.
    #[error("the receive ran past its total time limit")]
    TotalDeadline,
    /// The peer sent more frames than a transfer needs.
    #[error("the peer sent more frames than a transfer needs")]
    TooManyFrames,
    /// A destination could not be written without following a link, or a write failed. The text is escaped: the
    /// path in the underlying error can hold a name the peer chose, and an error is logged.
    #[error("writing an output: {0}")]
    Write(String),
    /// A file write failed.
    #[error("writing an output file: {0}")]
    Io(#[source] std::io::Error),
}

impl From<sandy_fsutil::FsError> for ReceiveError {
    fn from(error: sandy_fsutil::FsError) -> Self {
        Self::Write(error.to_string().chars().flat_map(char::escape_default).collect())
    }
}

impl ReceiveError {
    /// The text sent to the peer in a `TransferError`: fixed per variant, never a path or a name.
    #[must_use]
    pub fn peer_reason(&self) -> &'static str {
        match self {
            Self::Frame(_) | Self::Truncated | Self::Idle | Self::PeerError(_) => "the receiver's link failed",
            Self::Violation(_) | Self::BadIndex | Self::NameMismatch | Self::Reopened => "an output chunk broke a rule",
            Self::Alias => "two output files name the same destination file",
            Self::Unexpected => "an unexpected message on the output transfer",
            Self::NoProgress => "an empty chunk made no progress",
            Self::TooManyBytes => "the transfer is past its byte cap",
            Self::TooManyEntries => "the transfer is past its entry cap",
            Self::TotalDeadline => "the transfer took too long",
            Self::TooManyFrames => "the transfer used too many frames",
            Self::Write(_) | Self::Io(_) => "an output could not be written",
        }
    }
}

/// How long the best-effort `TransferError` back to the peer may take.
const TELL_TIMEOUT: Duration = Duration::from_secs(5);

/// Receive the outputs of one job from `link` until `OutputEnd`, writing each file to its destination in `outputs`
/// (the job's `Dispatch.outputs`, in order). On a failure other than a dead link, the peer gets a `TransferError`.
///
/// The file in flight is removed on every exit, including the future being dropped (a cancelled job).
///
/// # Errors
/// See [`ReceiveError`].
pub async fn receive_outputs(
    link: &mut (impl AsyncRead + AsyncWrite + Unpin),
    outputs: &[sandy_executor_proto::Output],
    limits: ReceiveLimits,
) -> Result<Received, ReceiveError> {
    let mut receive = Receive::new(outputs, limits);
    // `receive` lives outside the timed future, so the file in flight is still removed when the deadline drops it.
    let result = match tokio::time::timeout(limits.total, pump(link, &mut receive)).await {
        Ok(result) => result,
        Err(_) => Err(ReceiveError::TotalDeadline),
    };
    let Err(error) = result else {
        return result;
    };
    // The partial file goes first, so the peer's view and the disk agree when it hears of the failure.
    if let Some(current) = receive.current.take() {
        current.discard().await;
    }
    if !matches!(
        error,
        ReceiveError::Frame(_) | ReceiveError::Truncated | ReceiveError::Idle | ReceiveError::PeerError(_)
    ) {
        let reason = DataLinkMessage {
            op: Some(Op::TransferError(TransferError {
                reason: error.peer_reason().to_owned(),
            })),
        };
        // Best effort: the peer may already be gone, and the original failure is what the caller needs.
        let _ = tokio::time::timeout(TELL_TIMEOUT, write_frame(link, &reason)).await;
    }
    Err(error)
}

async fn pump(
    link: &mut (impl AsyncRead + AsyncWrite + Unpin),
    receive: &mut Receive<'_>,
) -> Result<Received, ReceiveError> {
    let mut frames = 0usize;
    loop {
        let frame = tokio::time::timeout(receive.limits.idle, read_frame::<DataLinkMessage>(link))
            .await
            .map_err(|_| ReceiveError::Idle)??;
        let message = frame.ok_or(ReceiveError::Truncated)?;
        frames += 1;
        if frames > receive.limits.max_frames {
            return Err(ReceiveError::TooManyFrames);
        }
        message.validate()?;
        match message.op {
            Some(Op::OutputChunk(chunk)) => receive.chunk(chunk).await?,
            Some(Op::OutputEnd(_)) => {
                receive.finish_file().await?;
                return Ok(receive.received);
            }
            Some(Op::TransferError(error)) => {
                return Err(ReceiveError::PeerError(
                    error.reason.chars().flat_map(char::escape_default).collect(),
                ));
            }
            _ => return Err(ReceiveError::Unexpected),
        }
    }
}

/// The key under which a receive remembers a completed file or a created directory: a fixed-size digest of the output
/// index and the wire name, so memory per entry does not depend on the length of a name the peer chose (#780).
type EntryKey = [u8; 16];

/// The key of `name` under the output at `index`. The name is length-prefixed, so no two (index, name) pairs share
/// the bytes that are hashed.
fn entry_key(index: u32, name: &str) -> EntryKey {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::new()
        .chain_update(index.to_be_bytes())
        .chain_update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes())
        .chain_update(name.as_bytes())
        .finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// What one receive has done so far.
struct Receive<'a> {
    outputs: &'a [sandy_executor_proto::Output],
    limits: ReceiveLimits,
    received: Received,
    /// Files plus the distinct directories created below a destination: what `max_entries` caps.
    entries: usize,
    dirs: HashSet<EntryKey>,
    /// Files already completed, by output index and wire name.
    done: HashSet<EntryKey>,
    current: Option<InFlight>,
    temp_seq: u64,
    /// The identity of each file this receive completed, so a rename onto one of them is caught (#787).
    completed_ids: std::sync::Arc<std::sync::Mutex<HashSet<sandy_fsutil::FileId>>>,
}

/// The file being received: written under a temp name in its final directory, renamed into place on completion,
/// and removed if it never completed.
struct InFlight {
    key: (u32, String),
    name: OsString,
    file: tokio::fs::File,
    cleanup: Cleanup,
}

impl InFlight {
    /// Remove the temp file and wait for it, so the destination is clean when the caller goes on (a failed receive
    /// tells the peer after this).
    async fn discard(mut self) {
        let cleanup = self.cleanup.take();
        let _ = tokio::task::spawn_blocking(move || cleanup.remove_now()).await;
    }
}

/// The unlink of a temp file that never completed, through the directory handle it was created in, so nothing is
/// resolved again. Unlinking is blocking I/O (a hung destination stalls its thread), so dropping one queues the unlink
/// on the blocking pool instead of running it on the async worker (#779). The write that may still be in flight on
/// another blocking thread goes to the then unlinked file.
///
/// Queueing is not enough on its own: tokio cancels a `spawn_blocking` task that is still queued when the runtime shuts
/// down, and one spawned after, without running them. So the work travels as an [`UnlinkOnDrop`] guard that the queued
/// closure owns. The closure runs and drops it on a pool thread; a cancelled closure is dropped by tokio, and the
/// guard unlinks inline on the thread that cancels it. Neither path loses the unlink.
struct Cleanup(Option<(Beneath, OsString)>);

impl Cleanup {
    fn new(dir: Beneath, temp: OsString) -> Self {
        Self(Some((dir, temp)))
    }

    /// Take the work out, leaving a guard that does nothing.
    fn take(&mut self) -> Self {
        Self(self.0.take())
    }

    /// The file is in place under its final name: nothing to remove.
    fn disarm(&mut self) {
        self.0 = None;
    }

    /// Remove the file now, on the calling thread. Callers run it on the blocking pool.
    fn remove_now(mut self) {
        drop(UnlinkOnDrop(self.0.take()));
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let Some(target) = self.0.take() else {
            return;
        };
        let guard = UnlinkOnDrop(Some(target));
        match tokio::runtime::Handle::try_current() {
            // The closure owns the guard: run, it unlinks on a pool thread; cancelled at shutdown, it unlinks inline.
            Ok(handle) => drop(handle.spawn_blocking(move || drop(guard))),
            // No runtime on this thread: nothing to queue on.
            Err(_) => drop(guard),
        }
    }
}

/// Unlinks its temp file when dropped, wherever that happens.
struct UnlinkOnDrop(Option<(Beneath, OsString)>);

impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        if let Some((dir, temp)) = self.0.take() {
            let _ = dir.remove_file(&temp);
        }
    }
}

/// How many temp names one `open_temp` call tries before it gives up on a destination full of stale ones.
const MAX_TEMP_NAME_TRIES: u32 = 1000;

/// Rename the finished temp file onto its final name, unless that name is a file this receive already completed.
/// On a case-insensitive destination `a` then `A` name one file; case-folding the receive's keys would wrongly refuse
/// them on a case-sensitive one, where they are two files, so the target's identity decides (#787). Runs on the
/// blocking pool.
fn commit(current: &InFlight, completed: &std::sync::Mutex<HashSet<sandy_fsutil::FileId>>) -> Result<(), ReceiveError> {
    let poisoned = || ReceiveError::Io(std::io::Error::other("the completed-file set is poisoned"));
    let Some((dir, temp)) = current.cleanup.0.as_ref() else {
        return Err(sandy_fsutil::FsError::Unsafe {
            path: PathBuf::from(&current.name),
            reason: "the temp file was already removed".to_owned(),
        }
        .into());
    };
    let mine = dir.file_id(temp)?;
    if let Some(target) = dir.file_id(&current.name)?
        && completed.lock().map_err(|_| poisoned())?.contains(&target)
    {
        return Err(ReceiveError::Alias);
    }
    dir.rename(temp, &current.name)?;
    if let Some(id) = mine {
        completed.lock().map_err(|_| poisoned())?.insert(id);
    }
    Ok(())
}

/// Open the destination beneath `root`, create the directories in `parts`, and a new temp file in the last one.
/// Runs on the blocking pool. The returned guard removes the temp file if it is dropped before the file is renamed,
/// including when the receive that asked for it is gone by the time this ends.
fn open_temp(root: &Path, parts: &[String], mut seq: u64) -> Result<(Cleanup, std::fs::File, u64), ReceiveError> {
    let mut dir = Beneath::create_dir_at(root)?;
    for part in parts {
        dir = dir.create_dir(OsStr::new(part))?;
    }
    // `seq` runs across the whole receive so names stay unique; the retry bound is per call.
    for _ in 0..MAX_TEMP_NAME_TRIES {
        seq += 1;
        let temp = OsString::from(format!(".sandy-recv-{}-{seq}", std::process::id()));
        match dir.create_new_file(&temp) {
            Ok(file) => return Ok((Cleanup::new(dir, temp), file, seq)),
            // A stale name from a crashed receive: try the next one.
            Err(sandy_fsutil::FsError::Unsafe { .. }) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(ReceiveError::Write(
        "too many stale temp files in the destination".to_owned(),
    ))
}

impl<'a> Receive<'a> {
    fn new(outputs: &'a [sandy_executor_proto::Output], limits: ReceiveLimits) -> Self {
        Self {
            outputs,
            limits,
            received: Received { files: 0, bytes: 0 },
            entries: 0,
            dirs: HashSet::new(),
            done: HashSet::new(),
            current: None,
            temp_seq: 0,
            completed_ids: std::sync::Arc::default(),
        }
    }

    async fn chunk(&mut self, chunk: OutputChunk) -> Result<(), ReceiveError> {
        let key = (chunk.output_index, chunk.name);
        if self.current.as_ref().is_some_and(|c| c.key == key) {
            if chunk.bytes.is_empty() {
                return Err(ReceiveError::NoProgress);
            }
        } else {
            self.finish_file().await?;
            if self.done.contains(&entry_key(key.0, &key.1)) {
                return Err(ReceiveError::Reopened);
            }
            self.start_file(key).await?;
        }
        let len = u64::try_from(chunk.bytes.len()).unwrap_or(u64::MAX);
        let bytes = self.received.bytes.saturating_add(len);
        if bytes > self.limits.max_bytes {
            return Err(ReceiveError::TooManyBytes);
        }
        self.received.bytes = bytes;
        let current = self.current.as_mut().ok_or(ReceiveError::Unexpected)?;
        current.file.write_all(&chunk.bytes).await.map_err(ReceiveError::Io)?;
        Ok(())
    }

    /// Complete the file in flight, if any: flush it and rename it into place (on the blocking pool).
    async fn finish_file(&mut self) -> Result<(), ReceiveError> {
        let Some(mut current) = self.current.take() else {
            return Ok(());
        };
        if let Err(e) = current.file.flush().await {
            // `finish_file` took the file out of `receive.current`, so the error path cannot discard it: do it here,
            // before the error returns and the peer is told (decision 22).
            current.discard().await;
            return Err(ReceiveError::Io(e));
        }
        let completed = std::sync::Arc::clone(&self.completed_ids);
        let current = tokio::task::spawn_blocking(move || -> Result<InFlight, ReceiveError> {
            match commit(&current, &completed) {
                Ok(()) => {
                    current.cleanup.disarm();
                    Ok(current)
                }
                Err(e) => {
                    // Done here, before the peer hears of the failure.
                    current.cleanup.take().remove_now();
                    Err(e)
                }
            }
        })
        .await
        .map_err(|e| ReceiveError::Io(std::io::Error::other(e)))??;
        self.done.insert(entry_key(current.key.0, &current.key.1));
        self.received.files += 1;
        Ok(())
    }

    /// Open the destination directory beneath its root, creating what is missing, and a temp file in it. The caps are
    /// counted first; the directory work runs on the blocking pool.
    async fn start_file(&mut self, key: (u32, String)) -> Result<(), ReceiveError> {
        let (root, parts, name) = self.target(&key)?;
        let mut prefix = String::new();
        for part in &parts {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if self.dirs.insert(entry_key(key.0, &prefix)) {
                self.count_entry()?;
            }
        }
        self.count_entry()?;
        let seq = self.temp_seq;
        let (cleanup, file, seq) = tokio::task::spawn_blocking(move || open_temp(&root, &parts, seq))
            .await
            .map_err(|e| ReceiveError::Io(std::io::Error::other(e)))??;
        self.temp_seq = seq;
        self.current = Some(InFlight {
            key,
            name: OsString::from(name),
            file: tokio::fs::File::from_std(file),
            cleanup,
        });
        Ok(())
    }

    fn count_entry(&mut self) -> Result<(), ReceiveError> {
        self.entries += 1;
        if self.entries > self.limits.max_entries {
            return Err(ReceiveError::TooManyEntries);
        }
        Ok(())
    }

    /// Where a chunk goes, pinned to local `collect_outputs`: the directory to open, the directories below it, and
    /// the file name.
    fn target(&self, key: &(u32, String)) -> Result<(std::path::PathBuf, Vec<String>, String), ReceiveError> {
        let output = usize::try_from(key.0)
            .ok()
            .and_then(|i| self.outputs.get(i))
            .ok_or(ReceiveError::BadIndex)?;
        let dest = Path::new(&output.dest);
        let split = |rel: &str| -> (Vec<String>, String) {
            let mut parts: Vec<String> = rel.split('/').map(str::to_owned).collect();
            let name = parts.pop().unwrap_or_default();
            (parts, name)
        };
        match &output.name {
            Some(declared) if key.1 == *declared => {
                // The guest replaced the output directory with a file: it is the destination itself.
                let (Some(parent), Some(name)) = (dest.parent(), dest.file_name()) else {
                    return Err(sandy_fsutil::FsError::Unsafe {
                        path: dest.to_owned(),
                        reason: "a file output needs a destination with a file name".to_owned(),
                    }
                    .into());
                };
                Ok((parent.to_owned(), Vec::new(), name.to_string_lossy().into_owned()))
            }
            Some(declared) => {
                let rel = key
                    .1
                    .strip_prefix(declared.as_str())
                    .and_then(|rest| rest.strip_prefix('/'))
                    .ok_or(ReceiveError::NameMismatch)?;
                let (parts, name) = split(rel);
                Ok((dest.to_owned(), parts, name))
            }
            None => {
                let (parts, name) = split(&key.1);
                Ok((dest.to_owned(), parts, name))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, os::unix::fs::symlink, path::Path};

    use anyhow::Context;
    use sandy_control_proto::{read_frame, write_frame};
    use sandy_executor_proto::{MAX_CHUNK_BYTES, OutputChunk, OutputEnd};
    use tokio::io::DuplexStream;

    use super::*;

    fn out(name: Option<&str>, dest: &Path) -> sandy_executor_proto::Output {
        sandy_executor_proto::Output {
            name: name.map(str::to_owned),
            dest: dest.to_string_lossy().into_owned(),
        }
    }

    fn chunk(index: u32, name: &str, bytes: &[u8]) -> DataLinkMessage {
        DataLinkMessage {
            op: Some(Op::OutputChunk(OutputChunk {
                name: name.to_owned(),
                bytes: bytes.to_vec(),
                output_index: index,
            })),
        }
    }

    fn end() -> DataLinkMessage {
        DataLinkMessage {
            op: Some(Op::OutputEnd(OutputEnd {})),
        }
    }

    /// Write `messages` to the peer end, then run the receiver. `close` drops the peer after the writes (a link that
    /// goes away); otherwise the peer stays open and silent.
    async fn run(
        messages: &[DataLinkMessage],
        outputs: &[sandy_executor_proto::Output],
        limits: ReceiveLimits,
        close: bool,
    ) -> anyhow::Result<(Result<Received, ReceiveError>, DuplexStream)> {
        let (mut peer, mut local) = tokio::io::duplex(8 * 1024 * 1024);
        for message in messages {
            write_frame(&mut peer, message).await.context("peer write")?;
        }
        let peer = if close {
            drop(peer);
            tokio::io::duplex(1).0
        } else {
            peer
        };
        let received = tokio::time::timeout(Duration::from_secs(10), receive_outputs(&mut local, outputs, limits))
            .await
            .context("the receive hung")?;
        Ok((received, peer))
    }

    fn quick() -> ReceiveLimits {
        ReceiveLimits {
            idle: Duration::from_millis(300),
            ..ReceiveLimits::default()
        }
    }

    /// Every regular file below `root`, as relative path to bytes.
    fn tree(root: &Path) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
        fn walk(dir: &Path, root: &Path, into: &mut BTreeMap<String, Vec<u8>>) -> anyhow::Result<()> {
            for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
                let path = entry?.path();
                if path.is_dir() {
                    walk(&path, root, into)?;
                } else {
                    let rel = path.strip_prefix(root)?.to_string_lossy().into_owned();
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            into.insert(rel, bytes);
                        }
                        // A queued cleanup can remove a temp file between the listing and the read.
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Ok(())
        }
        let mut into = BTreeMap::new();
        if root.exists() {
            walk(root, root, &mut into)?;
        }
        Ok(into)
    }

    fn files(pairs: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), v.to_vec())).collect()
    }

    /// The fixed text the peer was sent, if any.
    async fn told(peer: &mut DuplexStream) -> Option<String> {
        let message = tokio::time::timeout(Duration::from_millis(500), read_frame::<DataLinkMessage>(peer))
            .await
            .ok()?
            .ok()??;
        match message.op? {
            Op::TransferError(e) => Some(e.reason),
            _ => None,
        }
    }

    /// A named output: `N/rel` lands at `dest/rel`, not `dest/N/rel`, and the receive reports what it wrote.
    #[tokio::test]
    async fn a_named_tree_lands_at_the_destination_not_under_its_name() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(Some("results"), dest.path())];
        let messages = [
            chunk(0, "results/a.txt", b"A"),
            chunk(0, "results/sub/b.txt", b"BB"),
            end(),
        ];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        assert_eq!(received.context("the receive")?, Received { files: 2, bytes: 3 });
        assert_eq!(tree(dest.path())?, files(&[("a.txt", b"A"), ("sub/b.txt", b"BB")]));
        Ok(())
    }

    /// A bare `N` chunk is a file: the guest replaced the output directory with a file, and local collection writes
    /// it to `dest` itself.
    #[tokio::test]
    async fn a_bare_named_chunk_is_a_file_written_to_the_destination() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let dest = parent.path().join("report.bin");
        let outputs = [out(Some("report"), &dest)];
        let (received, _peer) = run(&[chunk(0, "report", b"payload"), end()], &outputs, quick(), false).await?;
        received.context("the receive")?;
        assert_eq!(std::fs::read(&dest).context("dest")?, b"payload");
        Ok(())
    }

    /// A catch-all: `rel` lands at `dest/rel`.
    #[tokio::test]
    async fn a_catch_all_lands_at_the_destination() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let messages = [chunk(0, "x.txt", b"X"), chunk(0, "d/y.txt", b"Y"), end()];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        received.context("the receive")?;
        assert_eq!(tree(dest.path())?, files(&[("x.txt", b"X"), ("d/y.txt", b"Y")]));
        Ok(())
    }

    /// A zero-byte file is one empty chunk and is created, and a file of several chunks arrives whole.
    #[tokio::test]
    async fn a_zero_byte_file_and_a_multi_chunk_file_arrive() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let big = vec![7u8; MAX_CHUNK_BYTES];
        let messages = [
            chunk(0, "empty", b""),
            chunk(0, "big", &big),
            chunk(0, "big", b"tail"),
            end(),
        ];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        let received = received.context("the receive")?;
        let mut expected = big.clone();
        expected.extend_from_slice(b"tail");
        assert_eq!(tree(dest.path())?, files(&[("empty", b""), ("big", &expected)]));
        assert_eq!(received.files, 2);
        Ok(())
    }

    /// The acceptance test: the same output tree collected locally by `collect_outputs` and received over the link
    /// gives identical destination trees, including a named output and a catch-all that overlap, and two catch-alls.
    #[tokio::test]
    async fn the_remote_tree_equals_the_locally_collected_tree_including_overlap() -> anyhow::Result<()> {
        let src = tempfile::tempdir().context("src")?;
        for (rel, bytes) in [
            ("a/x.txt", &b"AX"[..]),
            ("a/deep/z.txt", b"AZ"),
            ("b/y.txt", b"BY"),
            ("top.txt", b"T"),
            ("empty", b""),
        ] {
            let path = src.path().join(rel);
            std::fs::create_dir_all(path.parent().context("parent")?).context("mkdir")?;
            std::fs::write(&path, bytes).context("write")?;
        }

        let roots: Vec<tempfile::TempDir> = (0..2)
            .map(|_| tempfile::tempdir().context("dest root"))
            .collect::<anyhow::Result<_>>()?;
        // Output 0: named `a`. Output 1: a catch-all (covers a/ too). Output 2: a second catch-all.
        let declared = |base: &Path| {
            [
                (Some("a"), base.join("named")),
                (None, base.join("all")),
                (None, base.join("all2")),
            ]
        };

        let local_outputs: Vec<sandy::Output> = declared(roots[0].path())
            .into_iter()
            .map(|(name, dest)| sandy::Output {
                name: name.map(str::to_owned),
                dest,
            })
            .collect();
        sandy::collect_outputs(&local_outputs, src.path(), false).context("local collection")?;

        // What the host would send: each file once per output that covers it.
        let remote_outputs: Vec<sandy_executor_proto::Output> = declared(roots[1].path())
            .into_iter()
            .map(|(name, dest)| out(name, &dest))
            .collect();
        let mut messages = Vec::new();
        for (index, (name, _)) in declared(roots[1].path()).into_iter().enumerate() {
            let base = match name {
                Some(n) => src.path().join(n),
                None => src.path().to_path_buf(),
            };
            for (rel, bytes) in tree(&base)? {
                let wire = match name {
                    Some(n) => format!("{n}/{rel}"),
                    None => rel,
                };
                messages.push(chunk(u32::try_from(index).context("index")?, &wire, &bytes));
            }
        }
        messages.push(end());
        let (received, _peer) = run(&messages, &remote_outputs, quick(), false).await?;
        received.context("the receive")?;

        assert_eq!(tree(roots[0].path())?, tree(roots[1].path())?);
        assert!(
            tree(roots[1].path())?.contains_key("all/a/x.txt"),
            "the catch-all must cover the named output's files too"
        );
        Ok(())
    }

    /// An index past `Dispatch.outputs` is refused: nothing is written, and the peer is told a fixed text.
    #[tokio::test]
    async fn an_index_past_the_declared_outputs_is_refused() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (received, mut peer) = run(&[chunk(1, "x", b"X"), end()], &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::BadIndex)), "got {received:?}");
        assert!(tree(dest.path())?.is_empty());
        assert_eq!(told(&mut peer).await.as_deref(), Some("an output chunk broke a rule"));
        Ok(())
    }

    /// A name that does not start with its named output's name is refused, so a host cannot write another output's
    /// files through the wrong index.
    #[tokio::test]
    async fn a_name_outside_its_named_output_is_refused() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(Some("results"), dest.path())];
        for wrong in ["other/x", "resultsx/x", "other"] {
            let (received, _peer) = run(&[chunk(0, wrong, b"X"), end()], &outputs, quick(), false).await?;
            assert!(
                matches!(received, Err(ReceiveError::NameMismatch)),
                "{wrong}: got {received:?}"
            );
        }
        assert!(tree(dest.path())?.is_empty());
        Ok(())
    }

    /// A message that breaks a path rule (`..`) is refused before anything is written.
    #[tokio::test]
    async fn a_dot_dot_name_is_refused() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&[chunk(0, "../escape", b"X"), end()], &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::Violation(_))), "got {received:?}");
        assert!(!dest.path().parent().context("parent")?.join("escape").exists());
        Ok(())
    }

    /// A name the peer chose reaches the error when the OS refuses it (a directory component past `NAME_MAX`), and
    /// an error is logged: it must not print the peer's newline or control characters raw.
    #[tokio::test]
    async fn a_write_error_does_not_print_the_peers_name_raw() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let name = format!("{}\nINJECTED\u{1b}[31m/f", "d".repeat(300));
        let (received, _peer) = run(&[chunk(0, &name, b"x"), end()], &outputs, quick(), false).await?;
        let Err(error @ ReceiveError::Write(_)) = received else {
            anyhow::bail!("expected a write error, got {received:?}");
        };
        let shown = error.to_string();
        assert!(
            !shown.chars().any(char::is_control),
            "a control character reached the error text: {shown:?}"
        );
        Ok(())
    }

    /// An input message on the output transfer is refused.
    #[tokio::test]
    async fn an_input_message_is_unexpected() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let input = DataLinkMessage {
            op: Some(Op::InputEnd(sandy_executor_proto::InputEnd {})),
        };
        let (received, _peer) = run(&[input], &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::Unexpected)), "got {received:?}");
        Ok(())
    }

    /// A symlink as the destination root is refused, and its target is not written.
    #[tokio::test]
    async fn a_symlinked_destination_is_refused() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("base")?;
        let victim = base.path().join("victim");
        std::fs::create_dir(&victim).context("victim")?;
        let dest = base.path().join("dest");
        symlink(&victim, &dest).context("link")?;
        let outputs = [out(None, &dest)];
        let (received, _peer) = run(&[chunk(0, "x", b"X"), end()], &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::Write(_))), "got {received:?}");
        assert!(tree(&victim)?.is_empty(), "nothing may be written through the link");
        Ok(())
    }

    /// A symlinked directory planted inside the destination is refused, and its target is not written.
    #[tokio::test]
    async fn a_symlinked_subdirectory_is_refused() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("base")?;
        let victim = base.path().join("victim");
        std::fs::create_dir(&victim).context("victim")?;
        let dest = base.path().join("dest");
        std::fs::create_dir(&dest).context("dest")?;
        symlink(&victim, dest.join("sub")).context("link")?;
        let outputs = [out(None, &dest)];
        let (received, _peer) = run(&[chunk(0, "sub/x", b"X"), end()], &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::Write(_))), "got {received:?}");
        assert!(tree(&victim)?.is_empty());
        Ok(())
    }

    /// A symlink at the final file name is replaced by the new file, and its target keeps its bytes.
    #[tokio::test]
    async fn a_symlink_at_the_final_name_is_replaced_not_followed() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("base")?;
        let victim = base.path().join("victim");
        std::fs::write(&victim, b"HOST-SECRET").context("victim")?;
        let dest = base.path().join("dest");
        std::fs::create_dir(&dest).context("dest")?;
        symlink(&victim, dest.join("x")).context("link")?;
        let outputs = [out(None, &dest)];
        let (received, _peer) = run(&[chunk(0, "x", b"new"), end()], &outputs, quick(), false).await?;
        received.context("the receive")?;
        assert_eq!(std::fs::read(&victim).context("victim")?, b"HOST-SECRET");
        assert_eq!(std::fs::read(dest.join("x")).context("x")?, b"new");
        assert!(!std::fs::symlink_metadata(dest.join("x"))?.file_type().is_symlink());
        Ok(())
    }

    /// An existing destination is merged into, as local collection does: a same-named file is overwritten and an
    /// unrelated one stays.
    #[tokio::test]
    async fn an_existing_destination_is_merged_into() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        std::fs::write(dest.path().join("keep"), b"old").context("keep")?;
        std::fs::write(dest.path().join("x"), b"old").context("x")?;
        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&[chunk(0, "x", b"new"), end()], &outputs, quick(), false).await?;
        received.context("the receive")?;
        assert_eq!(tree(dest.path())?, files(&[("keep", b"old"), ("x", b"new")]));
        Ok(())
    }

    /// A file is never visible half written, and a failure removes only the file in flight: the earlier completed
    /// file stays, the partial one is gone, no temp name is left, and an old file at the final name is untouched.
    #[tokio::test]
    async fn a_failure_removes_only_the_file_in_flight() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        std::fs::write(dest.path().join("partial"), b"old").context("old")?;
        let outputs = [out(None, dest.path())];
        let messages = [chunk(0, "done", b"D"), chunk(0, "partial", b"half")];
        let (received, _peer) = run(&messages, &outputs, quick(), true).await?;
        assert!(matches!(received, Err(ReceiveError::Truncated)), "got {received:?}");
        assert_eq!(
            tree(dest.path())?,
            files(&[("done", b"D"), ("partial", b"old")]),
            "the completed file stays, the old file is untouched, and no temp is left"
        );
        Ok(())
    }

    /// A receiver dropped mid-file (the job is cancelled) leaves no temp file.
    #[tokio::test]
    async fn a_dropped_receive_leaves_no_temp_file() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (mut peer, mut local) = tokio::io::duplex(1024 * 1024);
        write_frame(&mut peer, &chunk(0, "half", b"x")).await.context("write")?;
        let limits = ReceiveLimits {
            idle: Duration::from_secs(30),
            ..ReceiveLimits::default()
        };
        let stopped = tokio::time::timeout(
            Duration::from_millis(300),
            receive_outputs(&mut local, &outputs, limits),
        )
        .await;
        assert!(stopped.is_err(), "the receive must still be waiting");
        // The unlink is queued on the blocking pool by the drop, so it ends a moment later.
        let mut left = tree(dest.path())?;
        for _ in 0..40 {
            if left.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            left = tree(dest.path())?;
        }
        assert!(left.is_empty(), "no partial file may stay: {left:?}");
        drop(peer);
        Ok(())
    }

    /// Poll `receive` until a temp file is on disk (the file is in flight), failing if the receive ends first.
    async fn wait_until_a_file_is_in_flight(
        receive: &mut (impl std::future::Future<Output = Result<Received, ReceiveError>> + Unpin),
        dest: &Path,
    ) -> anyhow::Result<()> {
        for _ in 0..80 {
            tokio::select! {
                ended = &mut *receive => anyhow::bail!("the receive ended with the peer silent: {ended:?}"),
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
            if !tree(dest)?.is_empty() {
                return Ok(());
            }
        }
        anyhow::bail!("no file was ever in flight")
    }

    /// A flush that fails ends the receive with the file already removed: the error path tells the peer only after the
    /// unlink is done (decision 22), and it cannot await a file that `finish_file` has already taken. With the pool's
    /// only thread occupied, a drop-time unlink stays queued, so the file is still there when the error returns.
    #[test]
    fn a_failed_flush_removes_the_file_before_the_error_returns() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt as _;

        let rt = runtime_with_one_blocking_thread()?;
        let dest = tempfile::tempdir().context("dest")?;
        rt.block_on(async {
            let dir = Beneath::open_dir(dest.path()).context("open dest")?;
            let temp = OsString::from(".sandy-recv-flush-test");
            drop(dir.create_new_file(&temp).context("create temp")?);
            // A read-only descriptor: the buffered write is accepted and fails when it reaches the file.
            let read_only = std::fs::File::open(dest.path().join(&temp)).context("reopen")?;
            let mut file = tokio::fs::File::from_std(read_only);
            file.write_all(b"x").await.context("buffer a write")?;
            let mut receive = Receive::new(&[], quick());
            receive.current = Some(InFlight {
                key: (0, "f".to_owned()),
                name: OsString::from("f"),
                file,
                cleanup: Cleanup::new(dir, temp.clone()),
            });

            let (release, held) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = held.recv();
            });
            tokio::time::sleep(Duration::from_millis(150)).await;
            let releaser = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(400));
                let _ = release.send(());
            });

            let finished = receive.finish_file().await;
            let still_there = dest.path().join(&temp).exists();
            releaser.join().map_err(|_| anyhow::anyhow!("releaser panicked"))?;
            blocker.await.context("blocker")?;
            assert!(matches!(finished, Err(ReceiveError::Io(_))), "got {finished:?}");
            assert!(!still_there, "the file was still on disk when the flush error returned");
            Ok(())
        })
    }

    /// The temp-name retry counts collisions per file, not across the receive: after more than 1,000 files, one stale
    /// `.sandy-recv-*` name must not fail a transfer when the next name is free.
    #[test]
    fn a_stale_temp_name_does_not_fail_a_receive_that_has_written_many_files() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let pid = std::process::id();
        for n in 1001..=1005 {
            std::fs::write(dest.path().join(format!(".sandy-recv-{pid}-{n}")), b"").context("stale name")?;
        }
        let (cleanup, _file, seq) =
            open_temp(dest.path(), &[], 1000).map_err(|e| anyhow::anyhow!("open_temp failed: {e}"))?;
        assert_eq!(seq, 1006, "the first free name after the stale ones");
        drop(cleanup);
        Ok(())
    }

    /// A flood of stale names still ends the search: the retry is bounded, not endless.
    #[test]
    fn a_flood_of_stale_temp_names_ends_the_search() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let pid = std::process::id();
        for n in 1..=1000 {
            std::fs::write(dest.path().join(format!(".sandy-recv-{pid}-{n}")), b"").context("stale name")?;
        }
        let Err(error) = open_temp(dest.path(), &[], 0) else {
            anyhow::bail!("every name the search may try is taken, it must fail");
        };
        assert!(
            error.to_string().contains("too many stale temp files"),
            "wrong error: {error}"
        );
        Ok(())
    }

    /// The bound is exactly 1,000 name attempts per call: with 999 names taken the 1000th is found.
    #[test]
    fn the_thousandth_temp_name_is_still_tried() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let pid = std::process::id();
        for n in 1..=999 {
            std::fs::write(dest.path().join(format!(".sandy-recv-{pid}-{n}")), b"").context("stale name")?;
        }
        let (cleanup, _file, seq) =
            open_temp(dest.path(), &[], 0).map_err(|e| anyhow::anyhow!("open_temp failed: {e}"))?;
        assert_eq!(seq, 1000);
        drop(cleanup);
        Ok(())
    }

    /// A rename onto a file this transfer already completed is refused, not done: on a case-insensitive destination `a`
    /// then `A` name one file, and the second would replace the first while the receive counts two. The completed file
    /// stays as it was and the temp file goes.
    #[tokio::test]
    async fn a_target_that_is_a_file_of_this_transfer_is_refused_not_replaced() -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        use tokio::io::AsyncWriteExt as _;

        let dest = tempfile::tempdir().context("dest")?;
        std::fs::write(dest.path().join("a"), b"first").context("first file")?;
        let meta = std::fs::metadata(dest.path().join("a")).context("stat")?;
        let dir = Beneath::open_dir(dest.path()).context("open dest")?;
        let temp = OsString::from(".sandy-recv-alias-test");
        let mut file = tokio::fs::File::from_std(dir.create_new_file(&temp).context("temp file")?);
        file.write_all(b"second").await.context("write")?;

        let mut receive = Receive::new(&[], quick());
        receive
            .completed_ids
            .lock()
            .map_err(|_| anyhow::anyhow!("the id set is poisoned"))?
            .insert(sandy_fsutil::FileId {
                dev: meta.dev(),
                ino: meta.ino(),
            });
        receive.current = Some(InFlight {
            key: (0, "a".to_owned()),
            name: OsString::from("a"),
            file,
            cleanup: Cleanup::new(dir, temp.clone()),
        });

        let finished = receive.finish_file().await;
        assert!(matches!(finished, Err(ReceiveError::Alias)), "got {finished:?}");
        assert_eq!(
            std::fs::read(dest.path().join("a")).context("read a")?,
            b"first",
            "the completed file must not be replaced"
        );
        assert!(!dest.path().join(&temp).exists(), "the temp file is removed");
        Ok(())
    }

    /// A finished-looking file in flight: a temp file written in `dest`, held the way the receive holds one.
    async fn in_flight(dest: &Path, name: &str, temp: &str, body: &[u8]) -> anyhow::Result<InFlight> {
        use tokio::io::AsyncWriteExt as _;

        let dir = Beneath::open_dir(dest).context("open dest")?;
        let temp = OsString::from(temp);
        let mut file = tokio::fs::File::from_std(dir.create_new_file(&temp).context("temp file")?);
        file.write_all(body).await.context("write")?;
        Ok(InFlight {
            key: (0, name.to_owned()),
            name: OsString::from(name),
            file,
            cleanup: Cleanup::new(dir, temp),
        })
    }

    /// The record side of the check: a file the receive completes is remembered by identity, so a later file whose
    /// target is another name of it is refused. `a` is finished for real, a hard link `b` is made to it, and finishing
    /// `b` must be an `Alias`. Without the receive recording `a`'s id, the second rename goes through on any
    /// filesystem.
    #[tokio::test]
    async fn a_completed_file_is_remembered_so_a_hard_link_to_it_is_refused() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let mut receive = Receive::new(&[], quick());

        receive.current = Some(in_flight(dest.path(), "a", ".sandy-recv-t1", b"first").await?);
        receive.finish_file().await.context("finish a")?;
        std::fs::hard_link(dest.path().join("a"), dest.path().join("b")).context("hard link")?;

        receive.current = Some(in_flight(dest.path(), "b", ".sandy-recv-t2", b"second").await?);
        let finished = receive.finish_file().await;
        assert!(matches!(finished, Err(ReceiveError::Alias)), "got {finished:?}");
        assert_eq!(std::fs::read(dest.path().join("a")).context("read a")?, b"first");
        assert_eq!(
            std::fs::read(dest.path().join("b")).context("read b")?,
            b"first",
            "b is a hard link to a and must not have been replaced"
        );
        assert!(!dest.path().join(".sandy-recv-t2").exists(), "the temp file is removed");
        Ok(())
    }

    /// Names that differ only by case: on a case-insensitive destination they are one file and the second is refused,
    /// on a case-sensitive one they are two files and both arrive. The probe decides which this filesystem is, so the
    /// test holds on both.
    #[tokio::test]
    async fn names_differing_only_by_case_follow_the_destination_filesystem() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        std::fs::write(dest.path().join("probe-x"), b"").context("probe")?;
        let folds_case = dest.path().join("PROBE-X").exists();
        std::fs::remove_file(dest.path().join("probe-x")).context("remove probe")?;

        let outputs = [out(None, dest.path())];
        let messages = [chunk(0, "a", b"1"), chunk(0, "A", b"2"), end()];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        if folds_case {
            assert!(matches!(received, Err(ReceiveError::Alias)), "got {received:?}");
            assert_eq!(std::fs::read(dest.path().join("a")).context("read a")?, b"1");
        } else {
            assert_eq!(received.context("two distinct files")?.files, 2);
            assert_eq!(tree(dest.path())?, files(&[("a", b"1"), ("A", b"2")]));
        }
        Ok(())
    }

    /// The pid of a process that has exited: a short-lived child of this test binary, waited for.
    fn a_dead_pid() -> anyhow::Result<u32> {
        let mut child = std::process::Command::new(std::env::current_exe().context("current exe")?)
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("spawn a child")?;
        let pid = child.id();
        child.wait().context("wait for the child")?;
        Ok(pid)
    }

    /// A `.sandy-recv-*` temp file a crashed process left in a destination is removed before the receive makes its own
    /// temp file there (#782): the name says which process made it, and that process is gone. Files in a subdirectory
    /// are swept too, once per directory.
    #[tokio::test]
    async fn a_stale_temp_file_of_a_dead_process_is_removed_before_the_receive_writes_there() -> anyhow::Result<()> {
        let dead = a_dead_pid()?;
        let dest = tempfile::tempdir().context("dest")?;
        std::fs::create_dir(dest.path().join("sub")).context("sub")?;
        std::fs::write(dest.path().join(format!(".sandy-recv-{dead}-1")), b"stale").context("stale root")?;
        std::fs::write(dest.path().join(format!("sub/.sandy-recv-{dead}-9")), b"stale").context("stale sub")?;
        std::fs::write(dest.path().join("keep.txt"), b"mine").context("unrelated")?;

        let outputs = [out(None, dest.path())];
        let messages = [chunk(0, "x.txt", b"X"), chunk(0, "sub/y.txt", b"Y"), end()];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        received.context("the receive")?;

        assert_eq!(
            tree(dest.path())?,
            files(&[("keep.txt", b"mine"), ("x.txt", b"X"), ("sub/y.txt", b"Y")]),
            "the stale temp files must be gone, and nothing else"
        );
        Ok(())
    }

    /// What the sweep must not touch: a temp file of this process (another job's receive in this daemon may be writing
    /// it), one of a live process, names that are not temp names, and entries that are not regular files.
    #[tokio::test]
    async fn the_sweep_leaves_live_and_foreign_entries_alone() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let dead = a_dead_pid()?;
        let own = std::process::id();
        let parent = std::os::unix::process::parent_id();
        let dest = tempfile::tempdir().context("dest")?;
        let outside = tempfile::tempdir().context("outside")?;
        std::fs::write(outside.path().join("target"), b"TARGET").context("target")?;

        std::fs::write(dest.path().join(format!(".sandy-recv-{own}-5")), b"own").context("own")?;
        std::fs::write(dest.path().join(format!(".sandy-recv-{parent}-5")), b"live").context("live")?;
        std::fs::write(dest.path().join(".sandy-recv-notapid-1"), b"x").context("not a pid")?;
        std::fs::write(dest.path().join(".sandy-recv-1"), b"x").context("no counter")?;
        std::fs::write(dest.path().join(format!(".sandy-recv-{dead}-x")), b"x").context("bad counter")?;
        std::fs::create_dir(dest.path().join(format!(".sandy-recv-{dead}-2"))).context("a directory")?;
        symlink(
            outside.path().join("target"),
            dest.path().join(format!(".sandy-recv-{dead}-3")),
        )
        .context("a symlink")?;

        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&[chunk(0, "x.txt", b"X"), end()], &outputs, quick(), false).await?;
        received.context("the receive")?;

        for kept in [
            format!(".sandy-recv-{own}-5"),
            format!(".sandy-recv-{parent}-5"),
            ".sandy-recv-notapid-1".to_owned(),
            ".sandy-recv-1".to_owned(),
            format!(".sandy-recv-{dead}-x"),
        ] {
            assert!(dest.path().join(&kept).is_file(), "{kept} was removed");
        }
        assert!(
            dest.path().join(format!(".sandy-recv-{dead}-2")).is_dir(),
            "a directory was removed"
        );
        assert!(
            std::fs::symlink_metadata(dest.path().join(format!(".sandy-recv-{dead}-3")))?
                .file_type()
                .is_symlink(),
            "a symlink was removed"
        );
        assert_eq!(
            std::fs::read(outside.path().join("target")).context("target")?,
            b"TARGET"
        );
        Ok(())
    }

    /// A runtime with one blocking-pool thread, so a test can occupy it and see which work waits for the pool.
    fn runtime_with_one_blocking_thread() -> anyhow::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .context("build the runtime")
    }

    /// Directory work is blocking I/O (a slow or hung destination stalls its thread): it runs on the blocking pool,
    /// never inline on the async worker. With the pool's only thread occupied, the receive must not have created the
    /// directory yet; before the fix it created it at once, on the worker (#779).
    #[test]
    fn creating_directories_waits_for_the_blocking_pool() -> anyhow::Result<()> {
        let rt = runtime_with_one_blocking_thread()?;
        rt.block_on(async {
            let dest = tempfile::tempdir().context("dest")?;
            let outputs = [out(None, dest.path())];
            let (release, held) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = held.recv();
            });
            tokio::time::sleep(Duration::from_millis(150)).await;

            let (mut peer, mut local) = tokio::io::duplex(1024 * 1024);
            write_frame(&mut peer, &chunk(0, "sub/f", b"x"))
                .await
                .context("write")?;
            let stalled = tokio::time::timeout(
                Duration::from_millis(400),
                receive_outputs(&mut local, &outputs, quick()),
            )
            .await;
            assert!(stalled.is_err(), "the receive cannot finish while the pool is occupied");
            assert!(
                !dest.path().join("sub").exists(),
                "a directory was created on the async worker, not the blocking pool"
            );
            release.send(()).context("release")?;
            blocker.await.context("blocker")?;
            // The queued work of the dropped receive may still run; let it end before the directory goes.
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(())
        })
    }

    /// The unlink of a file in flight, when the receive is dropped (a cancelled job), is blocking I/O too: it is
    /// queued on the blocking pool, not run inside `Drop` on the async worker, and it still happens.
    #[test]
    fn a_dropped_receives_cleanup_runs_on_the_blocking_pool() -> anyhow::Result<()> {
        let rt = runtime_with_one_blocking_thread()?;
        rt.block_on(async {
            let dest = tempfile::tempdir().context("dest")?;
            let outputs = [out(None, dest.path())];
            let (mut peer, mut local) = tokio::io::duplex(1024 * 1024);
            write_frame(&mut peer, &chunk(0, "half", b"x")).await.context("write")?;

            let patient = ReceiveLimits {
                idle: Duration::from_secs(30),
                ..quick()
            };
            let mut receive = Box::pin(receive_outputs(&mut local, &outputs, patient));
            wait_until_a_file_is_in_flight(&mut receive, dest.path()).await?;

            let (release, held) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = held.recv();
            });
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(receive);
            assert!(
                !tree(dest.path())?.is_empty(),
                "the temp file was unlinked inside Drop, on the async worker"
            );

            release.send(()).context("release")?;
            blocker.await.context("blocker")?;
            let mut left = tree(dest.path())?;
            for _ in 0..40 {
                if left.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                left = tree(dest.path())?;
            }
            assert!(
                left.is_empty(),
                "the queued cleanup must still remove the temp file: {left:?}"
            );
            drop(peer);
            Ok(())
        })
    }

    /// A receive dropped after its runtime has shut down still removes its temp file. Tokio rejects a `spawn_blocking`
    /// made on a pool that has shut down, without running it, so a cleanup that only queues the unlink loses it. A task
    /// the runtime drops late is in this position: its `Drop` runs with the runtime's handle entered and the pool gone.
    #[test]
    fn a_receive_dropped_after_the_runtime_shut_down_still_removes_its_temp_file() -> anyhow::Result<()> {
        let rt = runtime_with_one_blocking_thread()?;
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = vec![out(None, dest.path())];
        let (mut peer, local) = tokio::io::duplex(1024 * 1024);
        let patient = ReceiveLimits {
            idle: Duration::from_secs(30),
            ..quick()
        };
        let mut receive = Box::pin(async move {
            let mut local = local;
            receive_outputs(&mut local, &outputs, patient).await
        });
        rt.block_on(async {
            write_frame(&mut peer, &chunk(0, "half", b"x")).await.context("write")?;
            wait_until_a_file_is_in_flight(&mut receive, dest.path()).await
        })?;

        let handle = rt.handle().clone();
        drop(rt);
        let _entered = handle.enter();
        drop(receive);

        let left = tree(dest.path())?;
        assert!(
            left.is_empty(),
            "the unlink was lost with the pool, the temp file stays: {left:?}"
        );
        drop(peer);
        Ok(())
    }

    /// The entry key tells every (output index, name) pair apart: the index counts, the name counts, and a name that
    /// ends where another starts cannot be confused with it (the name is length-prefixed).
    #[test]
    fn the_entry_key_tells_pairs_apart() {
        let keys = [
            entry_key(0, "a"),
            entry_key(1, "a"),
            entry_key(0, "b"),
            entry_key(0, "a/b"),
            entry_key(0, "ab"),
            entry_key(0, ""),
            entry_key(256, "a"),
            entry_key(0, &"a".repeat(4096)),
            entry_key(0, &"a".repeat(4095)),
        ];
        let distinct: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(distinct.len(), keys.len(), "two pairs share a key: {keys:?}");
    }

    /// The same pair always has the same key, or a completed file would never be recognised again.
    #[test]
    fn the_entry_key_is_stable() {
        assert_eq!(entry_key(3, "out/x.txt"), entry_key(3, "out/x.txt"));
    }

    /// The memory a receive holds per entry is the key, not the name: a key is 16 bytes however long the name.
    #[test]
    fn a_key_does_not_grow_with_the_name() {
        assert_eq!(std::mem::size_of_val(&entry_key(0, &"n".repeat(4096))), 16);
        assert_eq!(std::mem::size_of_val(&entry_key(0, "n")), 16);
    }

    /// A file that arrives twice is still refused with keys in place of names, and a different name is not mistaken
    /// for it, including one that shares a long prefix.
    #[tokio::test]
    async fn reopening_is_detected_by_key_and_near_names_are_not_confused() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let long = "d".repeat(200);
        let near = format!("{long}x");
        let messages = [
            chunk(0, &long, b"1"),
            chunk(0, &near, b"2"),
            chunk(0, "other", b"3"),
            end(),
        ];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        assert_eq!(received.context("three different files")?.files, 3);

        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let messages = [
            chunk(0, &long, b"1"),
            chunk(0, "other", b"2"),
            chunk(0, &long, b"3"),
            end(),
        ];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::Reopened)), "got {received:?}");
        Ok(())
    }

    /// The byte cap is counted as bytes arrive: exactly at it passes, one past it stops, and what was written
    /// before the stop is a prefix of complete files only.
    #[tokio::test]
    async fn the_byte_cap_stops_one_past() -> anyhow::Result<()> {
        let limits = |max_bytes| ReceiveLimits { max_bytes, ..quick() };
        let messages = [chunk(0, "f", b"12345"), chunk(0, "f", b"67890"), end()];

        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&messages, &outputs, limits(10), false).await?;
        assert_eq!(received.context("exactly at the cap")?.bytes, 10);

        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&messages, &outputs, limits(9), false).await?;
        assert!(matches!(received, Err(ReceiveError::TooManyBytes)), "got {received:?}");
        assert!(tree(dest.path())?.is_empty(), "the file in flight is removed");
        Ok(())
    }

    /// Entries are files plus the directories created below a destination: `a/b/c.txt` is 3 entries.
    #[tokio::test]
    async fn directories_count_against_the_entry_cap() -> anyhow::Result<()> {
        let limits = |max_entries| ReceiveLimits { max_entries, ..quick() };
        let messages = [chunk(0, "a/b/c.txt", b"x"), end()];

        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&messages, &outputs, limits(3), false).await?;
        received.context("exactly at the cap")?;

        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&messages, &outputs, limits(2), false).await?;
        assert!(
            matches!(received, Err(ReceiveError::TooManyEntries)),
            "got {received:?}"
        );
        Ok(())
    }

    /// An empty chunk is only the one chunk of a zero-byte file: after data, or repeated, it makes no progress, or a
    /// peer could trickle empty chunks under the idle limit for ever.
    #[tokio::test]
    async fn an_empty_chunk_after_data_or_a_repeat_makes_no_progress() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        for messages in [
            vec![chunk(0, "f", b"data"), chunk(0, "f", b""), end()],
            vec![chunk(0, "f", b""), chunk(0, "f", b""), end()],
        ] {
            let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
            assert!(matches!(received, Err(ReceiveError::NoProgress)), "got {received:?}");
        }
        Ok(())
    }

    /// A file that already completed arrives again: refused, since outputs carry no offset to say where it goes.
    #[tokio::test]
    async fn a_completed_file_arriving_again_is_refused() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let messages = [chunk(0, "a", b"1"), chunk(0, "b", b"2"), chunk(0, "a", b"3"), end()];
        let (received, _peer) = run(&messages, &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::Reopened)), "got {received:?}");
        assert_eq!(tree(dest.path())?, files(&[("a", b"1"), ("b", b"2")]));
        Ok(())
    }

    /// The peer's `TransferError` ends the receive with its reason escaped, and the peer is not told anything back.
    #[tokio::test]
    async fn a_peer_transfer_error_ends_the_receive_with_an_escaped_reason() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let message = DataLinkMessage {
            op: Some(Op::TransferError(TransferError {
                reason: "bad\u{1b}[31m\nthing".to_owned(),
            })),
        };
        let (received, _peer) = run(&[message], &outputs, quick(), false).await?;
        let Err(ReceiveError::PeerError(reason)) = received else {
            anyhow::bail!("expected PeerError, got {received:?}");
        };
        assert!(
            !reason.contains('\u{1b}') && !reason.contains('\n'),
            "unescaped: {reason:?}"
        );
        Ok(())
    }

    /// A peer that sends a frame inside every idle gap, for ever, is stopped by the total limit, and the file in
    /// flight is removed.
    #[tokio::test]
    async fn a_trickle_under_the_idle_limit_ends_at_the_total_deadline() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (mut peer, mut local) = tokio::io::duplex(1024 * 1024);
        let sender = tokio::spawn(async move {
            for _ in 0..60 {
                if write_frame(&mut peer, &chunk(0, "f", b"x")).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            peer
        });
        let limits = ReceiveLimits {
            idle: Duration::from_millis(400),
            total: Duration::from_millis(500),
            ..ReceiveLimits::default()
        };
        let received = tokio::time::timeout(Duration::from_secs(5), receive_outputs(&mut local, &outputs, limits))
            .await
            .context("the receive must end at its total deadline, not run on")?;
        assert!(matches!(received, Err(ReceiveError::TotalDeadline)), "got {received:?}");
        assert!(tree(dest.path())?.is_empty(), "the file in flight is removed");
        sender.abort();
        Ok(())
    }

    /// The frame cap counts every frame read, `OutputEnd` included: exactly at it passes, one past it stops.
    #[tokio::test]
    async fn the_frame_cap_stops_one_past() -> anyhow::Result<()> {
        let limits = ReceiveLimits {
            max_frames: 3,
            ..quick()
        };

        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let at_cap = [chunk(0, "f", b"1"), chunk(0, "f", b"2"), end()];
        let (received, _peer) = run(&at_cap, &outputs, limits, false).await?;
        received.context("exactly at the cap")?;

        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let past_cap = [chunk(0, "f", b"1"), chunk(0, "f", b"2"), chunk(0, "f", b"3"), end()];
        let (received, mut peer) = run(&past_cap, &outputs, limits, false).await?;
        assert!(matches!(received, Err(ReceiveError::TooManyFrames)), "got {received:?}");
        assert!(tree(dest.path())?.is_empty(), "the file in flight is removed");
        assert_eq!(
            told(&mut peer).await.as_deref(),
            Some("the transfer used too many frames")
        );
        Ok(())
    }

    /// The default frame cap leaves room for a full transfer a sender makes of full chunks: every entry, and one
    /// chunk per `MAX_CHUNK_BYTES` of the byte cap.
    #[test]
    fn the_default_frame_cap_fits_a_full_transfer() {
        let chunks = usize::try_from(MAX_TRANSFER_BYTES / u64::try_from(MAX_CHUNK_BYTES).unwrap_or(u64::MAX))
            .unwrap_or(usize::MAX);
        assert!(DEFAULT_MAX_FRAMES > MAX_TRANSFER_ENTRIES + chunks);
    }

    /// A silent peer ends the receive after the idle limit.
    #[tokio::test]
    async fn a_silent_peer_ends_the_receive_as_idle() -> anyhow::Result<()> {
        let dest = tempfile::tempdir().context("dest")?;
        let outputs = [out(None, dest.path())];
        let (received, _peer) = run(&[], &outputs, quick(), false).await?;
        assert!(matches!(received, Err(ReceiveError::Idle)), "got {received:?}");
        Ok(())
    }

    /// `OutputEnd` with no output is a clean, empty receive.
    #[tokio::test]
    async fn no_outputs_end_cleanly() -> anyhow::Result<()> {
        let (received, _peer) = run(&[end()], &[], quick(), false).await?;
        assert_eq!(received.context("the receive")?, Received { files: 0, bytes: 0 });
        Ok(())
    }
}
