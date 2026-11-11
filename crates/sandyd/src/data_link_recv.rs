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
    path::Path,
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

/// The caps one receive enforces. The default is the §22 pair and [`DEFAULT_IDLE`]; a test lowers them.
#[derive(Debug, Clone, Copy)]
pub struct ReceiveLimits {
    /// The most file bytes the receive writes.
    pub max_bytes: u64,
    /// The most entries the receive creates: files plus the directories below a destination.
    pub max_entries: usize,
    /// The longest gap between frames.
    pub idle: Duration,
}

impl Default for ReceiveLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_TRANSFER_BYTES,
            max_entries: MAX_TRANSFER_ENTRIES,
            idle: DEFAULT_IDLE,
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
    /// The transfer is past its byte cap.
    #[error("the transfer is past its byte cap")]
    TooManyBytes,
    /// The transfer is past its entry cap.
    #[error("the transfer is past its entry cap")]
    TooManyEntries,
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
            Self::Unexpected => "an unexpected message on the output transfer",
            Self::NoProgress => "an empty chunk made no progress",
            Self::TooManyBytes => "the transfer is past its byte cap",
            Self::TooManyEntries => "the transfer is past its entry cap",
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
    let result = pump(link, &mut receive).await;
    let Err(error) = result else {
        return result;
    };
    // The partial file goes first, so the peer's view and the disk agree when it hears of the failure.
    drop(receive.current.take());
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
    loop {
        let frame = tokio::time::timeout(receive.limits.idle, read_frame::<DataLinkMessage>(link))
            .await
            .map_err(|_| ReceiveError::Idle)??;
        let message = frame.ok_or(ReceiveError::Truncated)?;
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

/// What one receive has done so far.
struct Receive<'a> {
    outputs: &'a [sandy_executor_proto::Output],
    limits: ReceiveLimits,
    received: Received,
    /// Files plus the distinct directories created below a destination: what `max_entries` caps.
    entries: usize,
    dirs: HashSet<(u32, String)>,
    /// Files already completed, by output index and wire name.
    done: HashSet<(u32, String)>,
    current: Option<InFlight>,
    temp_seq: u64,
}

/// The file being received: written under a temp name in its final directory, renamed into place on completion,
/// and removed on drop if it never completed.
struct InFlight {
    key: (u32, String),
    dir: Beneath,
    temp: OsString,
    name: OsString,
    file: tokio::fs::File,
    committed: bool,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if !self.committed {
            // Through the held directory handle, so nothing is resolved again. The write that may still be in
            // flight on a blocking thread goes to the now unlinked file.
            let _ = self.dir.remove_file(&self.temp);
        }
    }
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
            if self.done.contains(&key) {
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

    /// Complete the file in flight, if any: flush it and rename it into place.
    async fn finish_file(&mut self) -> Result<(), ReceiveError> {
        let Some(mut current) = self.current.take() else {
            return Ok(());
        };
        current.file.flush().await.map_err(ReceiveError::Io)?;
        current.dir.rename(&current.temp, &current.name)?;
        current.committed = true;
        self.done.insert(current.key.clone());
        self.received.files += 1;
        Ok(())
    }

    /// Open the destination directory beneath its root, creating what is missing, and a temp file in it.
    async fn start_file(&mut self, key: (u32, String)) -> Result<(), ReceiveError> {
        let (root, parts, name) = self.target(&key)?;
        let mut dir = Beneath::create_dir_at(&root)?;
        let mut prefix = String::new();
        for part in &parts {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if self.dirs.insert((key.0, prefix.clone())) {
                self.count_entry()?;
            }
            dir = dir.create_dir(OsStr::new(part))?;
        }
        self.count_entry()?;
        let (temp, file) = loop {
            self.temp_seq += 1;
            let temp = OsString::from(format!(".sandy-recv-{}-{}", std::process::id(), self.temp_seq));
            match dir.create_new_file(&temp) {
                Ok(file) => break (temp, file),
                // A stale name from a crashed receive: try the next one.
                Err(sandy_fsutil::FsError::Unsafe { .. }) if self.temp_seq < 1000 => {}
                Err(e) => return Err(e.into()),
            }
        };
        self.current = Some(InFlight {
            key,
            dir,
            temp,
            name: OsString::from(name),
            file: tokio::fs::File::from_std(file),
            committed: false,
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
                    into.insert(rel, std::fs::read(&path)?);
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
        assert!(
            tree(dest.path())?.is_empty(),
            "no partial file may stay: {:?}",
            tree(dest.path())?
        );
        drop(peer);
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
