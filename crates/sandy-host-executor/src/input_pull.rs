//! The host-executor's half of the input pull (#482, sandyd.md §22): read `InputChunk`s off the data link until
//! `InputEnd` and write them under a private staging root.
//!
//! The orchestrator is the trusted side for inputs, but the bytes still cross the mesh, so the receiver owns the
//! duties §22 lists: [`DataLinkMessage::validate`] on every message, a running offset per file, a per-transfer cap
//! counted as bytes arrive, a first name component that matches a declared `Input.name`, and a write that cannot
//! follow a symlink. A local failure goes back to the peer as a `TransferError` and ends the pull.
//!
//! What this does NOT do: dial the link, create the staging root, build the `Input` list for `stage_inputs`, or
//! remove the root on teardown. The caller (`handle_dispatch`, a later slice) owns all four.

use std::{collections::BTreeSet, path::Path};

use sandy_control_proto::{read_frame, write_frame};
use sandy_executor_proto::{
    DataLinkMessage, DataLinkViolation, InputChunk, MAX_TRANSFER_BYTES, MAX_TRANSFER_ENTRIES, TransferError,
    data_link_message::Op,
};
use tokio::io::AsyncWriteExt;

/// The caps one pull enforces. The default is the §22 pair; a test lowers them.
#[derive(Debug, Clone, Copy)]
pub struct PullLimits {
    /// The most file bytes the pull accepts.
    pub max_bytes: u64,
    /// The most files the pull accepts.
    pub max_entries: usize,
}

impl Default for PullLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_TRANSFER_BYTES,
            max_entries: MAX_TRANSFER_ENTRIES,
        }
    }
}

/// What a finished pull wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledInputs {
    /// Files written.
    pub files: usize,
    /// File bytes written.
    pub bytes: u64,
    /// The declared input names that received at least one file.
    pub names: BTreeSet<String>,
}

/// Why a pull failed. No variant carries a peer-chosen name or byte; the peer's `TransferError` reason is escaped.
#[derive(Debug, thiserror::Error)]
pub enum PullError {
    /// The link broke or sent a frame that does not decode.
    #[error("data link framing: {0}")]
    Frame(#[from] sandy_control_proto::FrameError),
    /// A message broke a limit in [`DataLinkMessage::validate`].
    #[error("data link message refused: {0}")]
    Violation(#[from] DataLinkViolation),
    /// The peer ended the transfer with a `TransferError`; the reason is escaped.
    #[error("the sender reported a transfer error: {reason}")]
    PeerError {
        /// The peer's reason, control characters escaped.
        reason: String,
    },
    /// The link closed before `InputEnd`.
    #[error("the link closed before InputEnd")]
    Truncated,
    /// A message that is not an input message arrived.
    #[error("an unexpected message arrived during the input pull")]
    Unexpected,
    /// A chunk's first name component is no declared `Input.name`.
    #[error("a chunk names an input that was not declared")]
    Undeclared,
    /// A chunk's offset is not the running byte count of its file.
    #[error("a chunk's offset is not the running byte count of its file")]
    OffsetMismatch,
    /// A file arrived twice, or a name is both a file and a directory.
    #[error("a name is sent twice or is both a file and a directory")]
    Clash,
    /// The transfer is past its byte cap.
    #[error("the transfer is past its byte cap")]
    TooManyBytes,
    /// The transfer is past its file cap.
    #[error("the transfer is past its file cap")]
    TooManyEntries,
    /// A local write failed.
    #[error("writing a staged input failed: {0}")]
    Write(#[source] std::io::Error),
}

/// Read the input transfer from `link` into `root` and return what was written.
///
/// `root` must be an empty directory this process created and nobody else can write. `declared` is the job's
/// `Input.name` set. On a local failure the function sends the peer a `TransferError` (best effort) before it
/// returns.
///
/// # Errors
/// See [`PullError`].
pub async fn pull_inputs(
    link: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    declared: &[String],
    root: &Path,
    limits: PullLimits,
) -> Result<PulledInputs, PullError> {
    let error = match pull(link, declared, root, limits).await {
        Ok(pulled) => return Ok(pulled),
        Err(error) => error,
    };
    // Tell the peer why, unless the failure is the peer's own report or a dead link. The reason is the error's fixed
    // text: it never carries a peer-chosen name.
    if !matches!(
        error,
        PullError::PeerError { .. } | PullError::Truncated | PullError::Frame(_)
    ) {
        let reason = DataLinkMessage {
            op: Some(Op::TransferError(TransferError {
                reason: error.to_string(),
            })),
        };
        let _ = tokio::time::timeout(REPORT_TIMEOUT, write_frame(link, &reason)).await;
    }
    Err(error)
}

/// How long the receiver waits to hand the peer a `TransferError` before it gives up and returns its own error.
const REPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

async fn pull(
    link: &mut (impl tokio::io::AsyncRead + Unpin),
    declared: &[String],
    root: &Path,
    limits: PullLimits,
) -> Result<PulledInputs, PullError> {
    let mut pull = Pull {
        root,
        declared,
        limits,
        files: 0,
        bytes: 0,
        names: BTreeSet::new(),
        current: None,
    };
    loop {
        let message: DataLinkMessage = read_frame(link).await?.ok_or(PullError::Truncated)?;
        message.validate()?;
        match message.op {
            Some(Op::InputChunk(chunk)) => pull.chunk(chunk).await?,
            Some(Op::InputEnd(_)) => {
                pull.finish_file().await?;
                return Ok(PulledInputs {
                    files: pull.files,
                    bytes: pull.bytes,
                    names: pull.names,
                });
            }
            Some(Op::TransferError(error)) => {
                return Err(PullError::PeerError {
                    reason: escape(&error.reason),
                });
            }
            _ => return Err(PullError::Unexpected),
        }
    }
}

/// The file being written: chunks of one file arrive in order, so one handle is open at a time.
struct OpenFile {
    name: String,
    file: tokio::fs::File,
    written: u64,
}

struct Pull<'a> {
    root: &'a Path,
    declared: &'a [String],
    limits: PullLimits,
    files: usize,
    bytes: u64,
    names: BTreeSet<String>,
    current: Option<OpenFile>,
}

impl Pull<'_> {
    async fn chunk(&mut self, chunk: InputChunk) -> Result<(), PullError> {
        let first = chunk.name.split('/').next().unwrap_or_default();
        if !self.declared.iter().any(|name| name == first) {
            return Err(PullError::Undeclared);
        }
        let len = u64::try_from(chunk.bytes.len()).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(len);
        if self.bytes > self.limits.max_bytes {
            return Err(PullError::TooManyBytes);
        }
        if self.current.as_ref().is_none_or(|open| open.name != chunk.name) {
            self.finish_file().await?;
            if chunk.offset != 0 {
                return Err(PullError::OffsetMismatch);
            }
            if self.files >= self.limits.max_entries {
                return Err(PullError::TooManyEntries);
            }
            let file = self.create(&chunk.name).await?;
            self.files += 1;
            self.names.insert(first.to_owned());
            self.current = Some(OpenFile {
                name: chunk.name.clone(),
                file,
                written: 0,
            });
        }
        let open = self.current.as_mut().ok_or(PullError::Unexpected)?;
        if chunk.offset != open.written {
            return Err(PullError::OffsetMismatch);
        }
        open.file.write_all(&chunk.bytes).await.map_err(PullError::Write)?;
        open.written += len;
        Ok(())
    }

    async fn finish_file(&mut self) -> Result<(), PullError> {
        if let Some(mut open) = self.current.take() {
            open.file.flush().await.map_err(PullError::Write)?;
        }
        Ok(())
    }

    /// Create the file for `name` under the root. The root is private and only this function writes it, so a
    /// directory component that exists is checked to be a real directory (a symlink or a file is refused), and the
    /// file itself is `create_new`, which fails on any existing entry and never follows a symlink.
    async fn create(&self, name: &str) -> Result<tokio::fs::File, PullError> {
        let mut path = self.root.to_path_buf();
        let mut parts = name.split('/').peekable();
        while let Some(part) = parts.next() {
            path.push(part);
            if parts.peek().is_some() {
                ensure_dir(&path).await?;
            }
        }
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => PullError::Clash,
                _ => PullError::Write(e),
            })
    }
}

async fn ensure_dir(path: &Path) -> Result<(), PullError> {
    match tokio::fs::create_dir(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = tokio::fs::symlink_metadata(path).await.map_err(PullError::Write)?;
            if metadata.is_dir() {
                Ok(())
            } else {
                Err(PullError::Clash)
            }
        }
        Err(e) => Err(PullError::Write(e)),
    }
}

/// A peer-chosen reason, with control characters (and anything non-ASCII) escaped, before it is logged or shown.
fn escape(reason: &str) -> String {
    reason.chars().flat_map(char::escape_default).collect()
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::{read_frame, write_frame};
    use sandy_executor_proto::{
        DataLinkMessage, InputChunk, InputEnd, OutputChunk, TransferError, data_link_message::Op,
    };
    use tokio::io::DuplexStream;

    use super::*;

    fn chunk(name: &str, offset: u64, bytes: &[u8]) -> DataLinkMessage {
        DataLinkMessage {
            op: Some(Op::InputChunk(InputChunk {
                name: name.to_owned(),
                offset,
                bytes: bytes.to_vec(),
            })),
        }
    }

    fn end() -> DataLinkMessage {
        DataLinkMessage {
            op: Some(Op::InputEnd(InputEnd {})),
        }
    }

    fn declared(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// Send `messages` from the peer side, then keep the peer end open (so a pull that waits for more would hang) or
    /// drop it when `close` is set. Returns the peer end so a test can read what the receiver answered.
    async fn run(
        messages: &[DataLinkMessage],
        close: bool,
        names: &[&str],
        limits: PullLimits,
        root: &Path,
    ) -> anyhow::Result<(Result<PulledInputs, PullError>, DuplexStream)> {
        let (mut peer, mut local) = tokio::io::duplex(4 * 1024 * 1024);
        for message in messages {
            write_frame(&mut peer, message).await.context("peer write")?;
        }
        if close {
            drop(peer);
            let result = pull_inputs(&mut local, &declared(names), root, limits).await;
            // `local` is the receiver's end; hand it back so the caller can read its answer.
            return Ok((result, local));
        }
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pull_inputs(&mut local, &declared(names), root, limits),
        )
        .await
        .context("the pull hung waiting for more frames")?;
        Ok((result, peer))
    }

    /// The `TransferError` the receiver wrote back to the peer, if any.
    async fn answered(peer: &mut DuplexStream) -> anyhow::Result<Option<String>> {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame::<DataLinkMessage>(peer))
            .await
            .context("timed out reading the receiver's answer")?
            .context("read the answer")?;
        Ok(match frame.and_then(|m| m.op) {
            Some(Op::TransferError(e)) => Some(e.reason),
            _ => None,
        })
    }

    fn read(path: impl AsRef<Path>) -> anyhow::Result<Vec<u8>> {
        std::fs::read(path.as_ref()).with_context(|| format!("read {}", path.as_ref().display()))
    }

    /// A file in two chunks and a directory input with a nested file land byte for byte under the root.
    #[tokio::test]
    async fn a_file_and_a_directory_input_are_staged_byte_for_byte() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        let messages = [
            chunk("data", 0, b"hello "),
            chunk("data", 6, b"world"),
            chunk("src/a.txt", 0, b"A"),
            chunk("src/sub/b.txt", 0, b"BB"),
            end(),
        ];
        let (pulled, _peer) = run(&messages, false, &["data", "src"], PullLimits::default(), root.path()).await?;
        let pulled = pulled.context("the pull")?;

        assert_eq!(read(root.path().join("data"))?, b"hello world");
        assert_eq!(read(root.path().join("src/a.txt"))?, b"A");
        assert_eq!(read(root.path().join("src/sub/b.txt"))?, b"BB");
        assert_eq!(pulled.files, 3);
        assert_eq!(pulled.bytes, 14);
        assert_eq!(pulled.names, ["data", "src"].map(str::to_owned).into_iter().collect());
        Ok(())
    }

    /// A link that closes before `InputEnd` is a truncated transfer, never a success.
    #[tokio::test]
    async fn a_link_that_closes_before_input_end_is_truncated() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        let (pulled, _peer) = run(
            &[chunk("data", 0, b"x")],
            true,
            &["data"],
            PullLimits::default(),
            root.path(),
        )
        .await?;
        assert!(matches!(pulled, Err(PullError::Truncated)), "got {pulled:?}");
        Ok(())
    }

    /// A `TransferError` from the sender ends the pull, and its reason is escaped before it is carried anywhere.
    #[tokio::test]
    async fn a_peer_transfer_error_ends_the_pull_with_an_escaped_reason() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        let error = DataLinkMessage {
            op: Some(Op::TransferError(TransferError {
                reason: "disk\u{1b}[31m full\n".to_owned(),
            })),
        };
        let (pulled, _peer) = run(&[error], false, &["data"], PullLimits::default(), root.path()).await?;
        match pulled {
            Err(PullError::PeerError { reason }) => {
                assert!(
                    !reason.contains('\u{1b}') && !reason.contains('\n'),
                    "unescaped: {reason:?}"
                );
                assert!(reason.contains("disk"), "the cause must survive: {reason:?}");
            }
            other => anyhow::bail!("expected PeerError, got {other:?}"),
        }
        Ok(())
    }

    /// A first component that is no declared `Input.name` is refused, nothing is written, and the peer is told.
    #[tokio::test]
    async fn an_undeclared_input_name_is_refused_and_reported() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        let (pulled, mut peer) = run(
            &[chunk("evil/x", 0, b"x"), end()],
            false,
            &["data"],
            PullLimits::default(),
            root.path(),
        )
        .await?;
        assert!(matches!(pulled, Err(PullError::Undeclared)), "got {pulled:?}");
        assert!(
            !root.path().join("evil").exists(),
            "nothing may be written for an undeclared name"
        );
        let reason = answered(&mut peer)
            .await?
            .context("the peer must get a TransferError")?;
        assert!(
            !reason.contains("evil"),
            "the reason must not echo the peer's name: {reason}"
        );
        Ok(())
    }

    /// An offset that is not the running count is refused: the first chunk must start at 0 (no sparse file from a
    /// huge first offset) and each next chunk continues where the last ended.
    #[tokio::test]
    async fn an_offset_that_is_not_the_running_count_is_refused() -> anyhow::Result<()> {
        for messages in [
            vec![chunk("data", 1 << 40, b"x"), end()],
            vec![chunk("data", 0, b"abc"), chunk("data", 5, b"d"), end()],
            vec![chunk("data", 0, b"abc"), chunk("data", 1, b"d"), end()],
        ] {
            let root = tempfile::tempdir().context("root")?;
            let (pulled, _peer) = run(&messages, false, &["data"], PullLimits::default(), root.path()).await?;
            assert!(matches!(pulled, Err(PullError::OffsetMismatch)), "got {pulled:?}");
        }
        Ok(())
    }

    /// A name that `validate` refuses never reaches the filesystem, and nothing lands outside the root.
    #[tokio::test]
    async fn a_name_that_escapes_the_root_is_refused() -> anyhow::Result<()> {
        let outer = tempfile::tempdir().context("outer")?;
        let root = outer.path().join("root");
        std::fs::create_dir(&root).context("root dir")?;
        let (pulled, _peer) = run(
            &[chunk("data/../../escape", 0, b"x"), end()],
            false,
            &["data"],
            PullLimits::default(),
            &root,
        )
        .await?;
        assert!(
            matches!(pulled, Err(PullError::Violation(DataLinkViolation::NameComponent))),
            "got {pulled:?}"
        );
        assert!(!outer.path().join("escape").exists());
        Ok(())
    }

    /// The byte cap and the file cap each stop the pull, counted as the bytes arrive.
    #[tokio::test]
    async fn the_byte_and_file_caps_stop_the_pull() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        let limits = PullLimits {
            max_bytes: 10,
            max_entries: 100,
        };
        let (pulled, _peer) = run(
            &[chunk("data", 0, b"123456"), chunk("data", 6, b"78901"), end()],
            false,
            &["data"],
            limits,
            root.path(),
        )
        .await?;
        assert!(matches!(pulled, Err(PullError::TooManyBytes)), "got {pulled:?}");

        let root = tempfile::tempdir().context("root")?;
        let limits = PullLimits {
            max_bytes: 100,
            max_entries: 1,
        };
        let (pulled, _peer) = run(
            &[chunk("a", 0, b"1"), chunk("b", 0, b"2"), end()],
            false,
            &["a", "b"],
            limits,
            root.path(),
        )
        .await?;
        assert!(matches!(pulled, Err(PullError::TooManyEntries)), "got {pulled:?}");
        Ok(())
    }

    /// A file sent twice, and a name that is a file and then a directory, are clashes, not overwrites.
    #[tokio::test]
    async fn a_repeated_file_and_a_file_directory_clash_are_refused() -> anyhow::Result<()> {
        for messages in [
            vec![chunk("a", 0, b"1"), chunk("b", 0, b"2"), chunk("a", 0, b"3"), end()],
            vec![chunk("a", 0, b"1"), chunk("a/b", 0, b"2"), end()],
        ] {
            let root = tempfile::tempdir().context("root")?;
            let (pulled, _peer) = run(&messages, false, &["a", "b"], PullLimits::default(), root.path()).await?;
            assert!(matches!(pulled, Err(PullError::Clash)), "got {pulled:?}");
        }
        Ok(())
    }

    /// An output message on the input pull is a protocol violation.
    #[tokio::test]
    async fn an_output_message_during_the_input_pull_is_refused() -> anyhow::Result<()> {
        let root = tempfile::tempdir().context("root")?;
        let output = DataLinkMessage {
            op: Some(Op::OutputChunk(OutputChunk {
                name: "x".to_owned(),
                bytes: b"x".to_vec(),
            })),
        };
        let (pulled, _peer) = run(&[output], false, &["x"], PullLimits::default(), root.path()).await?;
        assert!(matches!(pulled, Err(PullError::Unexpected)), "got {pulled:?}");
        Ok(())
    }

    /// A symlink planted in the root is never followed: a chunk below it fails and the target stays empty.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_component_is_never_followed() -> anyhow::Result<()> {
        let outer = tempfile::tempdir().context("outer")?;
        let target = outer.path().join("target");
        let root = outer.path().join("root");
        std::fs::create_dir(&target).context("target")?;
        std::fs::create_dir(&root).context("root")?;
        std::os::unix::fs::symlink(&target, root.join("src")).context("plant the symlink")?;

        let (pulled, mut peer) = run(
            &[chunk("src/x", 0, b"x"), end()],
            false,
            &["src"],
            PullLimits::default(),
            &root,
        )
        .await?;
        assert!(
            matches!(pulled, Err(PullError::Clash | PullError::Write(_))),
            "got {pulled:?}"
        );
        assert_eq!(
            std::fs::read_dir(&target).context("read target")?.count(),
            0,
            "the symlink target must stay empty"
        );
        assert!(answered(&mut peer).await?.is_some(), "the peer must be told");
        Ok(())
    }
}
