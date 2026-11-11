//! The sender half of the input transfer (#482 slice 5c, sandyd.md §22): read the submitter's declared inputs and
//! write them to the data link as `InputChunk`s, then `InputEnd`.
//!
//! The reads go through `sandy_fsutil::beneath`: each directory is opened once with `O_NOFOLLOW` and everything
//! below it is read through that handle, so a symlink planted in an input tree is refused, never followed. Disk I/O
//! runs on a blocking thread and hands chunks over a bounded channel, so a slow disk never stalls the task that
//! drives the link, and a link that goes away stops the reader.
//!
//! The wire rules the receiver (`sandy_host_executor::input_pull`) holds this side to: a chunk is at most
//! `MAX_CHUNK_BYTES`; the chunks of one file are in order from offset 0; an empty chunk is only the one chunk of a
//! zero-byte file, never an empty read after data; the caps count files plus the directories the receiver creates;
//! and every declared input must carry at least one file, or the receiver ends the pull with `Missing`.
//!
//! What this does NOT do: the Submit-time `stat` check of the caps, or the placement rule (slice 7), or send
//! anything back over the link (slice 6).

use std::time::Duration;

use sandy_control_proto::FrameError;
#[allow(unused_imports, reason = "the stub sends nothing; the real sender uses them")]
use sandy_executor_proto::{
    DataLinkMessage, MAX_CHUNK_BYTES, MAX_TRANSFER_BYTES, MAX_TRANSFER_ENTRIES, data_link_message::Op,
};
use tokio::io::AsyncWrite;

/// How long one frame may take to write. A peer that stops reading must not hold the sender, or the daemon's
/// accept task, for ever.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The caps one send enforces. The default is the §22 pair; a test lowers them.
#[derive(Debug, Clone, Copy)]
pub struct SendLimits {
    /// The most file bytes the send reads.
    pub max_bytes: u64,
    /// The most entries the send counts: files plus the directories the receiver creates for their names.
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
    /// Files sent.
    pub files: usize,
    /// File bytes sent.
    pub bytes: u64,
}

/// Why a send failed. The peer is told a fixed text ([`SendError::peer_reason`]), never a path.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Writing to the link failed or timed out: the peer is gone or stopped reading.
    #[error("writing to the data link: {0}")]
    Link(#[from] FrameError),
    /// The write of one frame took longer than [`WRITE_TIMEOUT`].
    #[error("the data link did not accept a frame within the write timeout")]
    WriteTimedOut,
    /// A source path could not be opened or read without following a link, or vanished.
    #[error("reading an input: {0}")]
    Source(#[from] sandy_fsutil::FsError),
    /// A source read failed.
    #[error("reading an input file: {0}")]
    Read(#[source] std::io::Error),
    /// An entry inside an input is a symlink: it is refused, never followed, and it has no wire form (#756).
    #[error("an input holds a symlink")]
    Symlink,
    /// An entry in an input is a socket, a fifo or a device: it has no wire form.
    #[error("an input holds an entry that is not a file or a directory")]
    UnsupportedEntry,
    /// A declared input has no file to send (an empty directory), so the receiver would end with `Missing`.
    #[error("a declared input holds no file")]
    EmptyInput,
    /// A declared input has an empty name, so its chunks cannot be named.
    #[error("a declared input has no name")]
    UnnamedInput,
    /// The transfer is past its byte cap.
    #[error("the transfer is past its byte cap")]
    TooManyBytes,
    /// The transfer is past its entry cap.
    #[error("the transfer is past its entry cap")]
    TooManyEntries,
    /// The reader stopped before it finished (the link side went away).
    #[error("the input reader stopped early")]
    Stopped,
}

impl SendError {
    /// The text sent to the peer in a `TransferError`: fixed per variant, never a path or a name.
    #[must_use]
    pub fn peer_reason(&self) -> &'static str {
        match self {
            Self::Link(_) | Self::WriteTimedOut | Self::Stopped => "the sender's link failed",
            Self::Source(_) | Self::Read(_) => "an input could not be read",
            Self::Symlink => "an input holds a symlink",
            Self::UnsupportedEntry => "an input holds an entry that is not a file or a directory",
            Self::EmptyInput => "a declared input holds no file",
            Self::UnnamedInput => "a declared input has no name",
            Self::TooManyBytes => "the transfer is past its byte cap",
            Self::TooManyEntries => "the transfer is past its entry cap",
        }
    }
}

/// Send `inputs` to `link`, then `InputEnd`. On a failure other than a dead link, the peer gets a `TransferError`
/// first.
///
/// # Errors
/// See [`SendError`].
pub async fn send_inputs(
    _link: &mut (impl AsyncWrite + Unpin),
    _inputs: &[sandy_executor_proto::Input],
    _limits: SendLimits,
) -> Result<Sent, SendError> {
    Err(SendError::Stopped)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use anyhow::Context;
    use sandy_control_proto::read_frame;
    use sandy_host_executor::input_pull::{PullError, PullLimits, PulledInputs, pull_inputs};
    use tokio::io::DuplexStream;

    use super::*;

    fn input(dir: &Path, name: &str) -> sandy_executor_proto::Input {
        sandy_executor_proto::Input {
            host: dir.join(name).to_string_lossy().into_owned(),
            name: name.to_owned(),
            guest_path: None,
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

    /// Run the sender against the real receiver and return both results and the receiver's root.
    async fn round_trip(
        inputs: &[sandy_executor_proto::Input],
        limits: SendLimits,
    ) -> anyhow::Result<(
        Result<Sent, SendError>,
        Result<PulledInputs, PullError>,
        tempfile::TempDir,
    )> {
        let (mut sender_end, mut receiver_end) = tokio::io::duplex(256 * 1024);
        let root = tempfile::tempdir().context("receiver root")?;
        let names: Vec<String> = inputs.iter().map(|i| i.name.clone()).collect();
        let (sent, pulled) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(
                send_inputs(&mut sender_end, inputs, limits),
                pull_inputs(&mut receiver_end, &names, root.path(), PullLimits::default()),
            )
        })
        .await
        .context("the round trip hung")?;
        Ok((sent, pulled, root))
    }

    /// Every frame the sender wrote, up to `InputEnd` or a `TransferError`.
    async fn frames(
        inputs: &[sandy_executor_proto::Input],
        limits: SendLimits,
    ) -> anyhow::Result<(Result<Sent, SendError>, Vec<DataLinkMessage>)> {
        let (mut sender_end, mut receiver_end) = tokio::io::duplex(8 * 1024 * 1024);
        let sent = send_inputs(&mut sender_end, inputs, limits).await;
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

    /// A tree with a multi-chunk file, nested directories and a zero-byte file arrives byte for byte through the
    /// real receiver.
    #[tokio::test]
    async fn a_file_and_a_tree_round_trip_through_the_receiver() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        let big = pattern(MAX_CHUNK_BYTES * 2 + 1234);
        write(&source.path().join("data"), &big)?;
        write(&source.path().join("src/a.txt"), b"A")?;
        write(&source.path().join("src/sub/b.txt"), b"BB")?;
        write(&source.path().join("src/sub/empty"), b"")?;
        let inputs = [input(source.path(), "data"), input(source.path(), "src")];

        let (sent, pulled, root) = round_trip(&inputs, SendLimits::default()).await?;
        let sent = sent.context("the send")?;
        pulled.context("the pull")?;

        assert_eq!(std::fs::read(root.path().join("data")).context("data")?, big);
        assert_eq!(std::fs::read(root.path().join("src/a.txt")).context("a")?, b"A");
        assert_eq!(std::fs::read(root.path().join("src/sub/b.txt")).context("b")?, b"BB");
        assert_eq!(std::fs::read(root.path().join("src/sub/empty")).context("empty")?, b"");
        assert_eq!(sent.files, 4);
        assert_eq!(sent.bytes, u64::try_from(big.len() + 3).context("len")?);
        Ok(())
    }

    /// The wire rules the receiver enforces hold on every frame: chunks under the cap, in order from 0, and an
    /// empty chunk only as the one chunk of a zero-byte file; the stream ends with exactly one `InputEnd`.
    #[tokio::test]
    async fn the_frames_obey_the_receivers_rules() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        write(&source.path().join("data"), &pattern(MAX_CHUNK_BYTES * 2))?;
        write(&source.path().join("empty"), b"")?;
        let inputs = [input(source.path(), "data"), input(source.path(), "empty")];

        let (sent, messages) = frames(&inputs, SendLimits::default()).await?;
        sent.context("the send")?;

        let mut next_offset: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut ends = 0;
        for message in &messages {
            match message.op.as_ref().context("an empty message")? {
                Op::InputChunk(chunk) => {
                    assert!(chunk.bytes.len() <= MAX_CHUNK_BYTES, "a chunk over the cap");
                    let expected = next_offset.entry(chunk.name.clone()).or_insert(0);
                    assert_eq!(chunk.offset, *expected, "chunks of one file must be in order from 0");
                    if chunk.bytes.is_empty() {
                        assert_eq!(
                            chunk.name, "empty",
                            "an empty chunk is only a zero-byte file's one chunk"
                        );
                        assert_eq!(chunk.offset, 0);
                    }
                    *expected += u64::try_from(chunk.bytes.len()).context("len")?;
                }
                Op::InputEnd(_) => ends += 1,
                other => anyhow::bail!("unexpected frame {other:?}"),
            }
        }
        assert_eq!(ends, 1, "exactly one InputEnd");
        assert!(matches!(
            messages.last().and_then(|m| m.op.as_ref()),
            Some(Op::InputEnd(_))
        ));
        assert_eq!(
            next_offset.get("data").copied(),
            Some(u64::try_from(MAX_CHUNK_BYTES * 2).context("len")?)
        );
        Ok(())
    }

    /// No inputs (an outputs-only job) is just `InputEnd`.
    #[tokio::test]
    async fn no_inputs_send_only_input_end() -> anyhow::Result<()> {
        let (sent, messages) = frames(&[], SendLimits::default()).await?;
        assert_eq!(sent.context("the send")?, Sent { files: 0, bytes: 0 });
        assert!(
            matches!(messages.as_slice(), [m] if matches!(m.op, Some(Op::InputEnd(_)))),
            "got {messages:?}"
        );
        Ok(())
    }

    /// A symlink inside an input tree is refused, never followed, and the peer is told without the path.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_in_an_input_is_refused_and_not_followed() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        let outside = tempfile::tempdir().context("outside")?;
        write(&outside.path().join("secret"), b"top secret")?;
        write(&source.path().join("src/ok.txt"), b"ok")?;
        std::os::unix::fs::symlink(outside.path().join("secret"), source.path().join("src/link")).context("link")?;
        let inputs = [input(source.path(), "src")];

        let (sent, messages) = frames(&inputs, SendLimits::default()).await?;
        assert!(matches!(sent, Err(SendError::Symlink)), "got {sent:?}");
        let text = format!("{messages:?}");
        assert!(!text.contains("top secret"), "the target's bytes must never be sent");
        let reason = messages
            .iter()
            .find_map(|m| match &m.op {
                Some(Op::TransferError(e)) => Some(e.reason.clone()),
                _ => None,
            })
            .context("the peer must get a TransferError")?;
        assert!(
            !reason.contains(&*source.path().to_string_lossy()),
            "the reason must not carry a path: {reason}"
        );

        // An input whose root is itself a symlink is refused too.
        std::os::unix::fs::symlink(source.path().join("src"), source.path().join("alias")).context("alias")?;
        let (sent, _) = frames(&[input(source.path(), "alias")], SendLimits::default()).await?;
        assert!(matches!(sent, Err(SendError::Source(_))), "got {sent:?}");
        Ok(())
    }

    /// An entry that is neither a file nor a directory has no wire form.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_in_an_input_is_unsupported() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        write(&source.path().join("src/ok.txt"), b"ok")?;
        let _listener = std::os::unix::net::UnixListener::bind(source.path().join("src/sock")).context("socket")?;
        let (sent, _) = frames(&[input(source.path(), "src")], SendLimits::default()).await?;
        assert!(matches!(sent, Err(SendError::UnsupportedEntry)), "got {sent:?}");
        Ok(())
    }

    /// An input with no file would end the receiver's pull with `Missing`; the sender refuses it first, by name.
    #[tokio::test]
    async fn an_empty_directory_input_is_refused() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        std::fs::create_dir(source.path().join("src")).context("dir")?;
        let (sent, messages) = frames(&[input(source.path(), "src")], SendLimits::default()).await?;
        assert!(matches!(sent, Err(SendError::EmptyInput)), "got {sent:?}");
        assert!(
            messages.iter().any(|m| matches!(m.op, Some(Op::TransferError(_)))),
            "the peer must be told"
        );
        Ok(())
    }

    /// An input with an empty name cannot be named on the wire.
    #[tokio::test]
    async fn an_unnamed_input_is_refused() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        write(&source.path().join("f"), b"x")?;
        let mut unnamed = input(source.path(), "f");
        unnamed.name = String::new();
        let (sent, _) = frames(&[unnamed], SendLimits::default()).await?;
        assert!(matches!(sent, Err(SendError::UnnamedInput)), "got {sent:?}");
        Ok(())
    }

    /// The byte cap is counted as bytes are read: exactly at it passes, one past it stops the send.
    #[tokio::test]
    async fn the_byte_cap_stops_the_send_one_past() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        write(&source.path().join("data"), b"1234567890")?;
        let inputs = [input(source.path(), "data")];
        let limits = |max_bytes| SendLimits {
            max_bytes,
            ..SendLimits::default()
        };

        let (sent, _) = frames(&inputs, limits(10)).await?;
        assert_eq!(sent.context("exactly at the cap")?.bytes, 10);
        let (sent, _) = frames(&inputs, limits(9)).await?;
        assert!(matches!(sent, Err(SendError::TooManyBytes)), "got {sent:?}");
        Ok(())
    }

    /// Entries are files plus the directories the receiver creates, the count `input_pull` enforces: `src/a/b/c.txt`
    /// is one file and the directories `src`, `src/a`, `src/a/b`.
    #[tokio::test]
    async fn directories_count_against_the_entry_cap() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        write(&source.path().join("src/a/b/c.txt"), b"x")?;
        let inputs = [input(source.path(), "src")];
        let limits = |max_entries| SendLimits {
            max_entries,
            ..SendLimits::default()
        };

        let (sent, _) = frames(&inputs, limits(3)).await?;
        assert!(
            matches!(sent, Err(SendError::TooManyEntries)),
            "3 dirs and a file are 4 entries: {sent:?}"
        );
        let (sent, _) = frames(&inputs, limits(4)).await?;
        assert_eq!(sent.context("exactly at the cap")?.files, 1);

        // And the receiver agrees on the same boundary.
        let (sent, pulled, _root) = round_trip(&inputs, limits(4)).await?;
        sent.context("the send")?;
        pulled.context("the receiver accepts what the sender counted")?;
        Ok(())
    }

    /// A link that goes away mid-send ends the send with a link error, and the reader stops: the future returns
    /// instead of reading the rest of a large file.
    #[tokio::test]
    async fn a_link_that_goes_away_ends_the_send() -> anyhow::Result<()> {
        let source = tempfile::tempdir().context("source")?;
        write(&source.path().join("big"), &pattern(8 * 1024 * 1024))?;
        let inputs = [input(source.path(), "big")];

        let (mut sender_end, mut receiver_end): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
        let reader = tokio::spawn(async move {
            let _first =
                tokio::time::timeout(Duration::from_secs(5), read_frame::<DataLinkMessage>(&mut receiver_end)).await;
            // Dropping `receiver_end` here closes the link.
        });
        let sent = tokio::time::timeout(
            Duration::from_secs(10),
            send_inputs(&mut sender_end, &inputs, SendLimits::default()),
        )
        .await
        .context("the send must not hang on a dead link")?;
        reader.await.context("reader task")?;
        assert!(matches!(sent, Err(SendError::Link(_))), "got {sent:?}");
        Ok(())
    }
}
