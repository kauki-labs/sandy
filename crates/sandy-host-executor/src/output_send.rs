//! The sender half of the output transfer (#482 slice 6b, sandyd.md §22): read the outputs the backend collected into
//! host-local staging directories and write them to the data link as `OutputChunk`s, then `OutputEnd`.
//!
//! The reads go through `sandy_fsutil::beneath`, as the input sender in sandyd does: each directory is opened once
//! with `O_NOFOLLOW` and everything below it is read through that handle. A symlink in a staged tree is skipped
//! (with a warning) and never opened, so never followed, as local collection skips it. Disk I/O runs on a blocking
//! thread behind a bounded channel.
//!
//! One [`OutputSource`] per declared output, in `Dispatch.outputs` order; its position is `output_index` on the wire.
//! A file several outputs cover is sent once per output, each from that output's own staged tree, as local
//! collection writes it to each destination. The wire name is `<declared name>/<rel>` for a named output, the bare
//! declared name for a file, and `<rel>` for a catch-all. A source with nothing staged (the guest declared an output
//! and never wrote it) sends nothing, as local collection collects nothing for it.
//!
//! The wire rules the receiver (`sandyd::data_link_recv`) holds this side to: a chunk is at most `MAX_CHUNK_BYTES`;
//! the chunks of one file are contiguous and in order; an empty chunk is only the one chunk of a zero-byte file; the
//! caps count files plus the directories below a root; and every frame passes `DataLinkMessage::validate`.
//!
//! What this does NOT do: stage the outputs or call this from `handle_dispatch` (6c), or set
//! `JobResult.outputs_follow` (6c).

use std::{collections::HashSet, ffi::OsStr, io::Read, path::PathBuf, time::Duration};

use sandy_control_proto::{FrameError, write_frame};
use sandy_executor_proto::{
    DataLinkMessage, DataLinkViolation, MAX_CHUNK_BYTES, MAX_TRANSFER_BYTES, MAX_TRANSFER_ENTRIES, OutputChunk,
    OutputEnd, TransferError, data_link_message::Op,
};
use sandy_fsutil::{
    FsError,
    beneath::{self, Beneath, EntryKind},
};
use tokio::io::AsyncWrite;

/// How long one frame may take to write. A peer that stops reading must not hold the sender for ever.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// One declared output and where its collected files are.
#[derive(Debug, Clone)]
pub struct OutputSource {
    /// The declared `Output.name`, or `None` for the catch-all.
    pub name: Option<String>,
    /// The host-local path the backend collected this output into: a directory, or a file when the guest replaced the
    /// named output directory with one. It may not exist.
    pub root: PathBuf,
}

/// The caps one send enforces. The default is the §22 pair; a test lowers them.
#[derive(Debug, Clone, Copy)]
pub struct SendLimits {
    /// The most file bytes the send reads.
    pub max_bytes: u64,
    /// The most entries the send counts: files plus the directories below a root.
    pub max_entries: usize,
}

impl Default for SendLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_TRANSFER_BYTES,
            max_entries: MAX_TRANSFER_ENTRIES,
        }
    }
}

/// What a finished send wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    /// Files sent, counting a file once per output that covers it.
    pub files: usize,
    /// File bytes sent.
    pub bytes: u64,
}

/// Why a send failed. The peer is told a fixed text ([`SendError::peer_reason`]), never a path.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Writing to the link failed: the peer is gone.
    #[error("writing to the data link: {0}")]
    Link(#[from] FrameError),
    /// The write of one frame took longer than [`WRITE_TIMEOUT`].
    #[error("the data link did not accept a frame within the write timeout")]
    WriteTimedOut,
    /// A staged path could not be opened or read without following a link.
    #[error("reading a staged output: {0}")]
    Source(#[from] sandy_fsutil::FsError),
    /// A staged file read failed.
    #[error("reading a staged output file: {0}")]
    Read(#[source] std::io::Error),
    /// A frame breaks a rule the receiver would refuse it for (a name too long, or not a plain relative path).
    #[error("a frame breaks a wire rule: {0}")]
    Violation(#[from] DataLinkViolation),
    /// The transfer is past its byte cap.
    #[error("the transfer is past its byte cap")]
    TooManyBytes,
    /// The transfer is past its entry cap.
    #[error("the transfer is past its entry cap")]
    TooManyEntries,
    /// The reader stopped before it finished (the link side went away).
    #[error("the output reader stopped early")]
    Stopped,
}

impl SendError {
    /// The text sent to the peer in a `TransferError`: fixed per variant, never a path or a name.
    #[must_use]
    pub fn peer_reason(&self) -> &'static str {
        match self {
            Self::Link(_) | Self::WriteTimedOut | Self::Stopped => "the sender's link failed",
            Self::Source(_) | Self::Read(_) => "an output could not be read",
            Self::Violation(_) => "an output name breaks a wire rule",
            Self::TooManyBytes => "the transfer is past its byte cap",
            Self::TooManyEntries => "the transfer is past its entry cap",
        }
    }
}

/// Messages buffered between the reader thread and the writer: enough to keep the link busy, little enough that a
/// slow peer holds a few MiB, not a file.
const QUEUE_DEPTH: usize = 4;

/// Send the staged `outputs` to `link`, then `OutputEnd`. On a failure other than a dead link, the peer gets a
/// `TransferError` first.
///
/// # Errors
/// See [`SendError`].
pub async fn send_outputs(
    link: &mut (impl AsyncWrite + Unpin),
    outputs: &[OutputSource],
    limits: SendLimits,
) -> Result<Sent, SendError> {
    let outputs = outputs.to_vec();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<DataLinkMessage>(QUEUE_DEPTH);
    let reader = tokio::task::spawn_blocking(move || read_outputs(&outputs, limits, &tx));
    while let Some(message) = rx.recv().await {
        if let Err(e) = write(link, &message).await {
            // Dropping the receiver stops the reader at its next hand-over.
            drop(rx);
            return Err(e);
        }
    }
    let sent = match reader.await {
        Ok(Ok(sent)) => sent,
        Ok(Err(e)) => {
            let reason = DataLinkMessage {
                op: Some(Op::TransferError(TransferError {
                    reason: e.peer_reason().to_owned(),
                })),
            };
            // Best effort: the peer may already be gone, and the original failure is what the caller needs.
            let _ = write(link, &reason).await;
            return Err(e);
        }
        Err(_) => return Err(SendError::Stopped),
    };
    write(
        link,
        &DataLinkMessage {
            op: Some(Op::OutputEnd(OutputEnd {})),
        },
    )
    .await?;
    Ok(sent)
}

async fn write(link: &mut (impl AsyncWrite + Unpin), message: &DataLinkMessage) -> Result<(), SendError> {
    match tokio::time::timeout(WRITE_TIMEOUT, write_frame(link, message)).await {
        Ok(written) => Ok(written?),
        Err(_) => Err(SendError::WriteTimedOut),
    }
}

/// What the reader thread has counted so far.
struct Walk<'a> {
    tx: &'a tokio::sync::mpsc::Sender<DataLinkMessage>,
    limits: SendLimits,
    sent: Sent,
    /// The position of the output being read, on the wire as `output_index`.
    index: u32,
    /// Files plus the distinct directories below a root, as the receiver counts them.
    entries: usize,
    dirs: HashSet<(u32, String)>,
}

/// Read every staged output on this thread and hand its frames to the writer.
fn read_outputs(
    outputs: &[OutputSource],
    limits: SendLimits,
    tx: &tokio::sync::mpsc::Sender<DataLinkMessage>,
) -> Result<Sent, SendError> {
    let mut walk = Walk {
        tx,
        limits,
        sent: Sent { files: 0, bytes: 0 },
        index: 0,
        entries: 0,
        dirs: HashSet::new(),
    };
    for (position, output) in outputs.iter().enumerate() {
        walk.index = u32::try_from(position).unwrap_or(u32::MAX);
        match beneath::open_file(&output.root) {
            // The guest replaced the named output directory with a file: the bare declared name.
            Ok(file) => match &output.name {
                Some(name) => walk.file(name, "", file)?,
                // A catch-all root is always a directory; a file there has no wire name.
                None => tracing::warn!(
                    index = walk.index,
                    "skipping a catch-all output whose staged root is a file"
                ),
            },
            Err(_) => match Beneath::open_dir(&output.root) {
                Ok(dir) => walk.tree(output.name.as_deref(), "", &dir)?,
                // Declared and never written: local collection collects nothing for it.
                Err(FsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {}
                // A symlink or a special file where the output should be: local collection skips it.
                Err(FsError::Unsafe { .. }) => {
                    tracing::warn!(
                        index = walk.index,
                        "skipping a staged output root that is a symlink or a special file"
                    );
                }
                Err(e) => return Err(e.into()),
            },
        }
    }
    Ok(walk.sent)
}

impl Walk<'_> {
    /// Send every file below `dir`. An empty subdirectory has no wire form and is skipped, as are a symlink, a
    /// special file and a name that is not UTF-8 (#756); local collection delivers the rest the same way. `wire` is the
    /// declared name prefix (none for a catch-all) and `rel` the path below the root, which is what the receiver counts
    /// directories by.
    fn tree(&mut self, wire: Option<&str>, rel: &str, dir: &Beneath) -> Result<(), SendError> {
        for entry in dir.entries()? {
            let (name, kind) = entry?;
            // A name that is not UTF-8 has no wire form: skipped, like the entries below.
            let Some(name) = name.to_str() else {
                tracing::warn!(index = self.index, "skipping a staged entry whose name is not UTF-8");
                continue;
            };
            let rel_path = if rel.is_empty() {
                name.to_owned()
            } else {
                format!("{rel}/{name}")
            };
            let wire_path = wire.map_or_else(|| rel_path.clone(), |prefix| format!("{prefix}/{rel_path}"));
            match kind {
                EntryKind::File => self.file(&wire_path, &rel_path, dir.open_file(OsStr::new(name))?)?,
                EntryKind::Dir => {
                    let sub = dir.open_subdir(OsStr::new(name))?;
                    self.tree(wire, &rel_path, &sub)?;
                }
                // Never opened, so never followed. Local collection skips both and delivers the rest.
                EntryKind::Symlink | EntryKind::Other => {
                    tracing::warn!(
                        index = self.index,
                        "skipping a symlink or special file in a staged output"
                    );
                }
            }
        }
        Ok(())
    }

    fn count_entry(&mut self) -> Result<(), SendError> {
        self.entries += 1;
        if self.entries > self.limits.max_entries {
            return Err(SendError::TooManyEntries);
        }
        Ok(())
    }

    /// Send one file as chunks in order. A zero-byte file is one empty chunk, and no empty chunk follows data.
    fn file(&mut self, wire: &str, rel: &str, mut file: std::fs::File) -> Result<(), SendError> {
        for (i, _) in rel.match_indices('/') {
            if self.dirs.insert((self.index, rel[..i].to_owned())) {
                self.count_entry()?;
            }
        }
        self.count_entry()?;
        let mut buf = vec![0u8; MAX_CHUNK_BYTES];
        let mut first = true;
        loop {
            let n = match file.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(SendError::Read(e)),
            };
            if n == 0 && !first {
                break;
            }
            let len = u64::try_from(n).unwrap_or(u64::MAX);
            self.sent.bytes += len;
            if self.sent.bytes > self.limits.max_bytes {
                return Err(SendError::TooManyBytes);
            }
            let message = DataLinkMessage {
                op: Some(Op::OutputChunk(OutputChunk {
                    name: wire.to_owned(),
                    bytes: buf[..n].to_vec(),
                    output_index: self.index,
                })),
            };
            message.validate()?;
            self.tx.blocking_send(message).map_err(|_| SendError::Stopped)?;
            first = false;
            if n == 0 {
                break;
            }
        }
        self.sent.files += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::{fs::symlink, net::UnixListener},
        path::Path,
    };

    use anyhow::Context;
    use sandy_control_proto::read_frame;
    use tokio::io::DuplexStream;

    use super::*;

    fn src(name: Option<&str>, root: &Path) -> OutputSource {
        OutputSource {
            name: name.map(str::to_owned),
            root: root.to_path_buf(),
        }
    }

    fn write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create parents")?;
        }
        std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
    }

    /// Every frame the sender wrote, up to `OutputEnd` or a `TransferError`, and the send's own result.
    async fn frames(
        outputs: &[OutputSource],
        limits: SendLimits,
    ) -> anyhow::Result<(Result<Sent, SendError>, Vec<DataLinkMessage>)> {
        let (mut sender_end, mut receiver_end) = tokio::io::duplex(16 * 1024 * 1024);
        let sent = send_outputs(&mut sender_end, outputs, limits).await;
        drop(sender_end);
        let mut out = Vec::new();
        while let Some(message) = read_frame::<DataLinkMessage>(&mut receiver_end)
            .await
            .context("read a frame")?
        {
            out.push(message);
        }
        Ok((sent, out))
    }

    /// The chunks as (output index, name, bytes), in order.
    fn chunks(messages: &[DataLinkMessage]) -> Vec<(u32, String, Vec<u8>)> {
        messages
            .iter()
            .filter_map(|m| match m.op.as_ref()? {
                Op::OutputChunk(c) => Some((c.output_index, c.name.clone(), c.bytes.clone())),
                _ => None,
            })
            .collect()
    }

    fn sorted(mut v: Vec<(u32, String, Vec<u8>)>) -> Vec<(u32, String, Vec<u8>)> {
        v.sort();
        v
    }

    fn ends_with_one_output_end(messages: &[DataLinkMessage]) -> bool {
        let ends = messages
            .iter()
            .filter(|m| matches!(m.op, Some(Op::OutputEnd(_))))
            .count();
        ends == 1 && matches!(messages.last().and_then(|m| m.op.as_ref()), Some(Op::OutputEnd(_)))
    }

    /// A named output: a tree is sent as `N/rel`, and a file the guest wrote in place of the directory as the bare `N`.
    #[tokio::test]
    async fn a_named_tree_and_a_named_file_are_sent_under_their_names() -> anyhow::Result<()> {
        let tree = tempfile::tempdir().context("tree")?;
        write(&tree.path().join("a.txt"), b"A")?;
        write(&tree.path().join("sub/b.txt"), b"BB")?;
        let parent = tempfile::tempdir().context("parent")?;
        let file = parent.path().join("report");
        write(&file, b"payload")?;

        let outputs = [src(Some("results"), tree.path()), src(Some("report"), &file)];
        let (sent, messages) = frames(&outputs, SendLimits::default()).await?;
        assert_eq!(sent.context("the send")?, Sent { files: 3, bytes: 10 });
        assert_eq!(
            sorted(chunks(&messages)),
            vec![
                (0, "results/a.txt".to_owned(), b"A".to_vec()),
                (0, "results/sub/b.txt".to_owned(), b"BB".to_vec()),
                (1, "report".to_owned(), b"payload".to_vec()),
            ]
        );
        assert!(ends_with_one_output_end(&messages));
        Ok(())
    }

    /// A catch-all sends the bare relative path, and a file two outputs cover is sent once per output with that
    /// output's index.
    #[tokio::test]
    async fn a_catch_all_and_an_overlap_are_sent_once_per_covering_output() -> anyhow::Result<()> {
        let named = tempfile::tempdir().context("named")?;
        write(&named.path().join("x.txt"), b"X")?;
        let all = tempfile::tempdir().context("all")?;
        write(&all.path().join("a/x.txt"), b"X")?;
        write(&all.path().join("top.txt"), b"T")?;
        let all2 = tempfile::tempdir().context("all2")?;
        write(&all2.path().join("top.txt"), b"T")?;

        let outputs = [
            src(Some("a"), named.path()),
            src(None, all.path()),
            src(None, all2.path()),
        ];
        let (sent, messages) = frames(&outputs, SendLimits::default()).await?;
        assert_eq!(sent.context("the send")?.files, 4);
        assert_eq!(
            sorted(chunks(&messages)),
            vec![
                (0, "a/x.txt".to_owned(), b"X".to_vec()),
                (1, "a/x.txt".to_owned(), b"X".to_vec()),
                (1, "top.txt".to_owned(), b"T".to_vec()),
                (2, "top.txt".to_owned(), b"T".to_vec()),
            ]
        );
        Ok(())
    }

    /// The receiver's rules hold on every frame: chunks under the cap and contiguous, an empty chunk only as a
    /// zero-byte file's one chunk, every frame valid, and exactly one `OutputEnd` last.
    #[tokio::test]
    async fn the_frames_obey_the_receivers_rules() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        let big = pattern(MAX_CHUNK_BYTES * 2 + 17);
        write(&root.path().join("big"), &big)?;
        write(&root.path().join("empty"), b"")?;

        let (sent, messages) = frames(&[src(None, root.path())], SendLimits::default()).await?;
        sent.context("the send")?;

        let mut joined: Vec<u8> = Vec::new();
        for message in &messages {
            message.validate().context("every frame must pass validate")?;
            if let Some(Op::OutputChunk(c)) = &message.op {
                assert!(c.bytes.len() <= MAX_CHUNK_BYTES, "a chunk over the cap");
                if c.bytes.is_empty() {
                    assert_eq!(c.name, "empty", "an empty chunk is only a zero-byte file's one chunk");
                }
                if c.name == "big" {
                    joined.extend_from_slice(&c.bytes);
                }
            }
        }
        assert_eq!(joined, big, "the chunks of one file, in order, make the file");
        let empties = chunks(&messages)
            .iter()
            .filter(|(_, n, b)| n == "empty" && b.is_empty())
            .count();
        assert_eq!(empties, 1, "a zero-byte file is exactly one empty chunk");
        assert!(ends_with_one_output_end(&messages));
        Ok(())
    }

    /// An output with nothing staged (never written, or an empty directory) sends nothing and is not an error, as
    /// local collection collects nothing for it. No outputs at all send only `OutputEnd`.
    #[tokio::test]
    async fn nothing_staged_sends_nothing() -> anyhow::Result<()> {
        let empty_dir = tempfile::tempdir().context("empty")?;
        let gone = empty_dir.path().join("never-written");
        let (sent, messages) = frames(
            &[src(None, empty_dir.path()), src(Some("x"), &gone)],
            SendLimits::default(),
        )
        .await?;
        assert_eq!(sent.context("the send")?, Sent { files: 0, bytes: 0 });
        assert!(chunks(&messages).is_empty());
        assert!(ends_with_one_output_end(&messages));

        let (sent, messages) = frames(&[], SendLimits::default()).await?;
        sent.context("no outputs")?;
        assert_eq!(messages.len(), 1);
        assert!(ends_with_one_output_end(&messages));
        Ok(())
    }

    /// Local collection skips a symlink and a special file and delivers the rest, so one in a guest's output must not
    /// abort the transfer: the entry is skipped, never opened (so never followed), and every other file arrives.
    #[tokio::test]
    async fn a_symlink_or_a_socket_in_a_staged_tree_is_skipped_and_the_rest_arrives() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("base")?;
        let victim = base.path().join("victim");
        write(&victim, b"HOST-SECRET")?;
        let victim_dir = base.path().join("victim-dir");
        write(&victim_dir.join("inside"), b"HOST-SECRET-TOO")?;
        let root = base.path().join("root");
        write(&root.join("ok.txt"), b"ok")?;
        write(&root.join("sub/also.txt"), b"also")?;
        symlink(&victim, root.join("file-link")).context("file link")?;
        symlink(&victim_dir, root.join("dir-link")).context("dir link")?;
        symlink(&victim, root.join("sub/nested-link")).context("nested link")?;
        let _listener = UnixListener::bind(root.join("sock")).context("bind")?;

        let (sent, messages) = frames(&[src(None, &root)], SendLimits::default()).await?;
        assert_eq!(sent.context("the send")?, Sent { files: 2, bytes: 6 });
        assert_eq!(
            sorted(chunks(&messages)),
            vec![
                (0, "ok.txt".to_owned(), b"ok".to_vec()),
                (0, "sub/also.txt".to_owned(), b"also".to_vec()),
            ]
        );
        assert!(
            ends_with_one_output_end(&messages),
            "a skipped entry must not end the transfer in an error: {messages:?}"
        );
        Ok(())
    }

    /// A staged root that is itself a symlink or a special file is skipped like any other entry: that output sends
    /// nothing and the other outputs still arrive.
    #[tokio::test]
    async fn a_symlinked_staged_root_is_skipped_and_the_other_outputs_arrive() -> anyhow::Result<()> {
        let base = tempfile::tempdir().context("base")?;
        let real = base.path().join("real");
        write(&real.join("x.txt"), b"HOST-SECRET")?;
        let root_link = base.path().join("root-link");
        symlink(&real, &root_link).context("root link")?;
        let good = base.path().join("good");
        write(&good.join("y.txt"), b"y")?;

        let (sent, messages) = frames(&[src(None, &root_link), src(None, &good)], SendLimits::default()).await?;
        assert_eq!(sent.context("the send")?.files, 1);
        assert_eq!(sorted(chunks(&messages)), vec![(1, "y.txt".to_owned(), b"y".to_vec())]);
        assert!(ends_with_one_output_end(&messages));
        Ok(())
    }

    /// A name the receiver would refuse is refused here, before it is sent: one past `MAX_CHUNK_NAME_BYTES`.
    #[tokio::test]
    async fn a_name_the_receiver_would_refuse_is_refused_at_the_source() -> anyhow::Result<()> {
        use std::io::Write as _;

        let root = tempfile::tempdir().context("root")?;
        // Built through directory handles: the path is longer than `PATH_MAX` where it is 1 KiB.
        let mut dir = Beneath::open_dir(root.path()).context("open root")?;
        for _ in 0..18 {
            dir = dir.create_dir(OsStr::new(&"d".repeat(250))).context("create dir")?;
        }
        dir.create_new_file(OsStr::new("f"))
            .context("create file")?
            .write_all(b"x")
            .context("write file")?;
        let (sent, messages) = frames(&[src(None, root.path())], SendLimits::default()).await?;
        assert!(matches!(sent, Err(SendError::Violation(_))), "got {sent:?}");
        assert!(chunks(&messages).is_empty());
        Ok(())
    }

    /// The byte cap is counted as bytes are read: exactly at it passes, one past it stops.
    #[tokio::test]
    async fn the_byte_cap_stops_the_send_one_past() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        write(&root.path().join("data"), b"1234567890")?;
        let outputs = [src(None, root.path())];
        let limits = |max_bytes| SendLimits {
            max_bytes,
            ..SendLimits::default()
        };
        let (sent, _) = frames(&outputs, limits(10)).await?;
        assert_eq!(sent.context("exactly at the cap")?.bytes, 10);
        let (sent, _) = frames(&outputs, limits(9)).await?;
        assert!(matches!(sent, Err(SendError::TooManyBytes)), "got {sent:?}");
        Ok(())
    }

    /// Entries are files plus the directories below a root, the count the receiver enforces: `a/b/c.txt` is three.
    #[tokio::test]
    async fn directories_count_against_the_entry_cap() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        write(&root.path().join("a/b/c.txt"), b"x")?;
        let outputs = [src(None, root.path())];
        let limits = |max_entries| SendLimits {
            max_entries,
            ..SendLimits::default()
        };
        let (sent, _) = frames(&outputs, limits(2)).await?;
        assert!(matches!(sent, Err(SendError::TooManyEntries)), "got {sent:?}");
        let (sent, _) = frames(&outputs, limits(3)).await?;
        assert_eq!(sent.context("exactly at the cap")?.files, 1);
        Ok(())
    }

    /// A link that goes away mid-send ends the send with a link error and stops the reader, instead of reading the
    /// rest of a large file.
    #[tokio::test]
    async fn a_link_that_goes_away_ends_the_send() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        write(&root.path().join("big"), &pattern(8 * 1024 * 1024))?;
        let outputs = [src(None, root.path())];

        let (mut sender_end, mut receiver_end): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
        let reader = tokio::spawn(async move {
            let _first =
                tokio::time::timeout(Duration::from_secs(5), read_frame::<DataLinkMessage>(&mut receiver_end)).await;
            // Dropping `receiver_end` here closes the link.
        });
        let sent = tokio::time::timeout(
            Duration::from_secs(10),
            send_outputs(&mut sender_end, &outputs, SendLimits::default()),
        )
        .await
        .context("the send must not hang on a dead link")?;
        reader.await.context("reader task")?;
        assert!(matches!(sent, Err(SendError::Link(_))), "got {sent:?}");
        Ok(())
    }
}
