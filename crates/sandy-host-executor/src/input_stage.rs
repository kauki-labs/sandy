//! Stage a job's inputs from the data link before the run (#482 slice 5b, sandyd.md §22).
//!
//! `handle_dispatch` calls [`dial_data_link`] and [`stage_remote_inputs`] when `Dispatch.data_link_token` is not
//! empty. The pull writes the inputs under a private root and the run takes its `Input` list from there, so
//! `stage_inputs` and the backends stay as they are. The caller owns the result: dropping [`StagedInputs`] removes
//! the root, on success and on every failure path.
//!
//! What this does NOT do: send outputs back (slice 6), or decide whether a job needs a data link (the sender's
//! Submit-side rule, slice 7).

use std::{io, net::SocketAddr, os::unix::fs::PermissionsExt as _, path::Path, time::Duration};

use sandy_api::backend::{Input, RunControl};
use sandy_executor_proto::{REMOTE_LINK_TOKEN_LEN, encode_remote_link_prefix};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::input_pull::{PullError, PullLimits, pull_inputs};

/// The most time the whole input pull may take. `PullLimits::idle` bounds the gap between frames, and the job's
/// deadline can be suspended while a client is attached, so neither bounds the pull as a whole: a peer that sends a
/// frame every 29 s would otherwise hold this host's sequential dispatch loop for as long as it likes.
pub const INPUT_PULL_TOTAL_SECS: u64 = 1800;

/// How long the dial of the data link may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the pull re-checks the job's control: a cancel or a deadline has no way to wake an await.
const CONTROL_POLL: Duration = Duration::from_millis(100);

/// Why the inputs could not be staged. Every variant means the job never booted.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    /// A transferred input has an empty `Input.name`, so the sender cannot name its chunks.
    #[error("a transferred input must be named")]
    UnnamedInput,
    /// A transferred input's name is not a plain relative path the receiver would accept (too long, absolute, a `.`
    /// or `..` component, a NUL). Refused before the root exists: a name joined onto the root must never leave it
    /// (#764).
    #[error("a transferred input has a name that is not a plain relative path: {0}")]
    InvalidName(sandy_executor_proto::DataLinkViolation),
    /// The staging root could not be created.
    #[error("creating the staging root: {0}")]
    Root(#[source] io::Error),
    /// The data link could not be dialed or claimed.
    #[error("dialing the data link: {0}")]
    Dial(String),
    /// The pull failed.
    #[error("the input transfer failed: {0}")]
    Pull(#[from] PullError),
    /// The job was cancelled during the pull.
    #[error("the job was cancelled while its inputs were being pulled")]
    Cancelled,
    /// The job's deadline passed during the pull.
    #[error("the job's deadline passed while its inputs were being pulled")]
    DeadlinePassed,
    /// The pull took longer than its total time cap.
    #[error("the input transfer took longer than its total time cap")]
    TotalCapExceeded,
}

/// A data link as the host holds it after the pull: readable and writable, so the outputs can go back over it.
pub trait DataLink: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> DataLink for T {}

/// The staged inputs. Owns the root and the data link: the link stays open through the run, because a data link
/// claims once and slice 6 sends the outputs back over it.
pub struct StagedInputs {
    /// The `Input` list for the run: `host` points into the staging root; name and guest path are as declared.
    pub inputs: Vec<Input>,
    _root: tempfile::TempDir,
    /// The data link, still open: the outputs go back over it after the run (6c).
    pub link: Box<dyn DataLink>,
}

#[cfg(test)]
impl StagedInputs {
    /// Staged inputs around `link` with no inputs, for tests of what happens after the run.
    pub(crate) fn for_test(link: impl DataLink + 'static) -> io::Result<Self> {
        Ok(Self {
            inputs: Vec::new(),
            _root: tempfile::tempdir()?,
            link: Box::new(link),
        })
    }
}

/// Dial the orchestrator's mesh listener and claim the job's data link with `data_token`.
///
/// # Errors
/// [`StageError::Dial`] if the dial, the handshake or the prefix write fails or times out.
pub async fn dial_data_link(
    forward_back: SocketAddr,
    job_id: &str,
    data_token: &[u8; REMOTE_LINK_TOKEN_LEN],
    mesh_tls: &sandy_fabric_local::mesh_link::MeshTlsIdentity,
    control: &RunControl,
) -> Result<Box<dyn sandy_conn::Conn>, StageError> {
    // The prefix is the claim: the orchestrator's accept loop tells the data link from the agent link by the token.
    // Neither an error nor a log line below carries it.
    let prefix = encode_remote_link_prefix(job_id, data_token).map_err(|e| StageError::Dial(e.to_string()))?;
    let dial = tokio::time::timeout(
        DIAL_TIMEOUT,
        sandy_conn::connect_tls(
            forward_back,
            &mesh_tls.identity,
            mesh_tls.orchestrator_fingerprint,
            Some(sandy_conn::TcpKeepalive::HALF_OPEN_DETECTION),
        ),
    );
    // Control first: a job already cancelled, or past its deadline, never starts the dial, and a cancel during it
    // ends the wait at once instead of after the dial timeout.
    let mut link = tokio::select! {
        biased;
        ended = control_ended(control) => return Err(ended),
        dialed = dial => dialed
            .map_err(|_| StageError::Dial(format!("dialing {forward_back} timed out after {DIAL_TIMEOUT:?}")))?
            .map_err(|e| StageError::Dial(e.to_string()))?,
    };
    link.write_all(&prefix)
        .await
        .map_err(|e| StageError::Dial(format!("writing the link prefix: {e}")))?;
    link.flush()
        .await
        .map_err(|e| StageError::Dial(format!("writing the link prefix: {e}")))?;
    Ok(link)
}

/// Pull the declared `inputs` from `link` into a fresh private root under `parent`.
///
/// Races the pull against `control` (cancel, deadline) and `total_cap`.
///
/// # Errors
/// See [`StageError`]. The root is gone on every error.
pub async fn stage_remote_inputs<C>(
    mut link: C,
    inputs: &[sandy_executor_proto::Input],
    parent: &Path,
    control: &RunControl,
    total_cap: Duration,
    limits: PullLimits,
) -> Result<StagedInputs, StageError>
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if inputs.iter().any(|input| input.name.is_empty()) {
        return Err(StageError::UnnamedInput);
    }
    // The receiver's own name rule, run before the root exists: a name joined onto the root must never leave it.
    for input in inputs {
        sandy_executor_proto::DataLinkMessage {
            op: Some(sandy_executor_proto::data_link_message::Op::InputChunk(
                sandy_executor_proto::InputChunk {
                    name: input.name.clone(),
                    offset: 0,
                    bytes: Vec::new(),
                },
            )),
        }
        .validate()
        .map_err(StageError::InvalidName)?;
    }
    // Explicit: `tempfile` applies only the umask default (0755) unless a mode is given, and the pulled inputs are the
    // job's own files (#802).
    let root = tempfile::Builder::new()
        .prefix(&crate::staging_sweep::root_prefix("inputs"))
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .map_err(StageError::Root)?;
    let names: Vec<String> = inputs.iter().map(|input| input.name.clone()).collect();

    // A pull error drops `root`, and removes the directory, on the way out.
    let stopped = tokio::select! {
        biased;
        pulled = pull_inputs(&mut link, &names, root.path(), limits) => {
            pulled?;
            None
        }
        ended = control_ended(control) => Some(ended),
        () = tokio::time::sleep(total_cap) => Some(StageError::TotalCapExceeded),
    };
    // The pull can win the race in the same instant a cancel or the deadline lands: look once more before the run.
    if let Some(stopped) = stopped.or_else(|| control_ended_now(control)) {
        discard_root(root).await;
        return Err(stopped);
    }

    let inputs = inputs
        .iter()
        .map(|input| Input {
            host: root.path().join(&input.name),
            name: input.name.clone(),
            guest_path: input.guest_path.as_deref().map(std::path::PathBuf::from),
        })
        .collect();
    Ok(StagedInputs {
        inputs,
        _root: root,
        link: Box::new(link),
    })
}

/// Remove the staging root after a stopped pull. The pull future is dropped mid-await, but a `tokio::fs` call it
/// started keeps running on a blocking thread and can create a file after the first removal, so remove until the
/// root is gone.
async fn discard_root(root: tempfile::TempDir) {
    let path = root.path().to_owned();
    drop(root);
    for _ in 0..50 {
        if !path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        let _ = tokio::fs::remove_dir_all(&path).await;
    }
    tracing::warn!(path = %path.display(), "could not remove the input staging root after a stopped pull");
}

/// Why `control` has ended the run, if it has: cancelled, or past a live deadline. A suspended deadline never ends it.
fn control_ended_now(control: &RunControl) -> Option<StageError> {
    if control.is_cancelled() {
        Some(StageError::Cancelled)
    } else if control.timed_out() {
        Some(StageError::DeadlinePassed)
    } else {
        None
    }
}

/// Resolves once [`control_ended_now`] says so; a cancel or a deadline has no way to wake an await, so it polls.
async fn control_ended(control: &RunControl) -> StageError {
    loop {
        if let Some(ended) = control_ended_now(control) {
            return ended;
        }
        tokio::time::sleep(CONTROL_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use sandy_control_proto::write_frame;
    use sandy_executor_proto::{DataLinkMessage, InputChunk, InputEnd, TransferError, data_link_message::Op};
    use tokio::io::{AsyncReadExt, DuplexStream};

    use super::*;

    fn declared(name: &str, guest: Option<&str>) -> sandy_executor_proto::Input {
        sandy_executor_proto::Input {
            host: "/submitter/path/ignored".to_owned(),
            name: name.to_owned(),
            guest_path: guest.map(str::to_owned),
        }
    }

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

    fn entries(dir: &Path) -> anyhow::Result<usize> {
        Ok(std::fs::read_dir(dir).context("read the parent")?.count())
    }

    const CAP: Duration = Duration::from_secs(5);

    async fn stage(
        peer_messages: &[DataLinkMessage],
        inputs: &[sandy_executor_proto::Input],
        parent: &Path,
        control: &RunControl,
        total_cap: Duration,
    ) -> anyhow::Result<(Result<StagedInputs, StageError>, DuplexStream)> {
        let (mut peer, local) = tokio::io::duplex(4 * 1024 * 1024);
        for message in peer_messages {
            write_frame(&mut peer, message).await.context("peer write")?;
        }
        let limits = PullLimits {
            idle: Duration::from_secs(2),
            ..PullLimits::default()
        };
        let staged = tokio::time::timeout(
            Duration::from_secs(10),
            stage_remote_inputs(local, inputs, parent, control, total_cap, limits),
        )
        .await
        .context("staging hung")?;
        Ok((staged, peer))
    }

    fn live() -> RunControl {
        RunControl::with_timeout_secs(600)
    }

    /// The pulled inputs land under a root inside `parent`, and the run's `Input` list points at them with the
    /// declared name and guest path, never at the submitter's `host` path.
    #[tokio::test]
    async fn staged_inputs_point_into_the_private_root() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let inputs = [declared("data", Some("/work/data")), declared("src", None)];
        let messages = [chunk("data", 0, b"hello"), chunk("src/a.txt", 0, b"A"), end()];
        let (staged, _peer) = stage(&messages, &inputs, parent.path(), &live(), CAP).await?;
        let staged = staged.context("the staging")?;

        assert_eq!(staged.inputs.len(), 2);
        assert_eq!(staged.inputs[0].name, "data");
        assert_eq!(staged.inputs[0].guest_path.as_deref(), Some(Path::new("/work/data")));
        assert_eq!(staged.inputs[1].guest_path, None);
        for input in &staged.inputs {
            assert!(
                input.host.starts_with(parent.path()),
                "{:?} is outside the parent",
                input.host
            );
        }
        assert_eq!(std::fs::read(&staged.inputs[0].host).context("data")?, b"hello");
        assert_eq!(
            std::fs::read(staged.inputs[1].host.join("a.txt")).context("a.txt")?,
            b"A"
        );
        assert_eq!(entries(parent.path())?, 1, "exactly one root under the parent");
        Ok(())
    }

    /// The staging root holds a job's pulled inputs, so only its owner may enter it: mode 0700, not the umask default
    /// (0755) `tempfile` gives a directory when no mode is asked for, which lets any local user read the inputs (#802).
    #[tokio::test]
    async fn the_staging_root_is_private_to_its_owner() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().context("parent")?;
        let (staged, _peer) = stage(
            &[chunk("data", 0, b"secret"), end()],
            &[declared("data", None)],
            parent.path(),
            &live(),
            CAP,
        )
        .await?;
        let _staged = staged.context("the staging")?;

        let roots: Vec<_> = std::fs::read_dir(parent.path())
            .context("read the parent")?
            .collect::<Result<_, _>>()
            .context("list the parent")?;
        assert_eq!(roots.len(), 1, "exactly one root under the parent");
        let mode = roots[0].metadata().context("stat the root")?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "the staging root must be private to its owner, got {mode:o}"
        );
        Ok(())
    }

    /// Dropping the staged inputs removes the root, and only then does the link close: it stays open through the
    /// run so slice 6 can send the outputs back over the one claim.
    #[tokio::test]
    async fn the_root_and_the_link_live_until_the_staged_inputs_drop() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let inputs = [declared("data", None)];
        let (staged, mut peer) = stage(&[chunk("data", 0, b"x"), end()], &inputs, parent.path(), &live(), CAP).await?;
        let staged = staged.context("the staging")?;

        let mut byte = [0u8; 1];
        let open = tokio::time::timeout(Duration::from_millis(300), peer.read(&mut byte)).await;
        assert!(
            open.is_err(),
            "the link must stay open while the staged inputs live: {open:?}"
        );

        drop(staged);
        assert_eq!(entries(parent.path())?, 0, "the root must be removed on drop");
        let closed = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
            .await
            .context("the link must close after the drop")?
            .context("read")?;
        assert_eq!(closed, 0);
        Ok(())
    }

    /// A job with no declared inputs (outputs only) still reads to `InputEnd` and stages nothing.
    #[tokio::test]
    async fn zero_inputs_stage_nothing_and_succeed() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let (staged, _peer) = stage(&[end()], &[], parent.path(), &live(), CAP).await?;
        assert!(staged.context("the staging")?.inputs.is_empty());
        Ok(())
    }

    /// Every failure leaves the parent empty, and names the cause distinctly from a guest failure.
    #[tokio::test]
    async fn a_failed_pull_removes_the_root_and_names_the_cause() -> anyhow::Result<()> {
        let inputs = [declared("data", None)];
        let transfer_error = DataLinkMessage {
            op: Some(Op::TransferError(TransferError {
                reason: "disk full".to_owned(),
            })),
        };
        for (messages, check) in [
            (vec![chunk("data", 0, b"x")], "silent after a chunk"),
            (vec![transfer_error], "peer"),
            (vec![chunk("evil", 0, b"x"), end()], "undeclared"),
        ] {
            let parent = tempfile::tempdir().context("parent")?;
            let (staged, _peer) = stage(&messages, &inputs, parent.path(), &live(), CAP).await?;
            match staged {
                Err(StageError::Pull(_)) => {}
                Err(other) => anyhow::bail!("{check}: expected a Pull error, got {other}"),
                Ok(_) => anyhow::bail!("{check}: expected a failure"),
            }
            assert_eq!(entries(parent.path())?, 0, "{check}: the root must be gone");
        }
        Ok(())
    }

    /// A Cancel during the pull ends it promptly with `Cancelled`, not a transfer failure, and cleans up.
    #[tokio::test]
    async fn a_cancel_during_the_pull_is_reported_as_cancelled() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let control = live();
        let canceller = control.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            canceller.cancel();
        });
        let started = std::time::Instant::now();
        let (staged, _peer) = stage(
            &[chunk("data", 0, b"x")],
            &[declared("data", None)],
            parent.path(),
            &control,
            CAP,
        )
        .await?;
        assert!(matches!(staged, Err(StageError::Cancelled)), "got {:?}", staged.err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the cancel must end the pull promptly"
        );
        assert_eq!(entries(parent.path())?, 0);
        Ok(())
    }

    /// A deadline that has already passed ends the pull with `DeadlinePassed`.
    #[tokio::test]
    async fn a_passed_deadline_ends_the_pull() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let control = RunControl::new(std::time::Instant::now());
        let (staged, _peer) = stage(
            &[chunk("data", 0, b"x")],
            &[declared("data", None)],
            parent.path(),
            &control,
            CAP,
        )
        .await?;
        assert!(
            matches!(staged, Err(StageError::DeadlinePassed)),
            "got {:?}",
            staged.err()
        );
        assert_eq!(entries(parent.path())?, 0);
        Ok(())
    }

    /// A pull stopped by a passed deadline leaves nothing under the parent, even when a `tokio::fs` create it
    /// started is still running on a blocking thread when the future drops. One run is a race, so loop it.
    #[tokio::test]
    async fn a_stopped_pull_never_leaves_its_root() -> anyhow::Result<()> {
        for round in 0..30 {
            let parent = tempfile::tempdir().context("parent")?;
            let control = RunControl::new(std::time::Instant::now());
            let (staged, _peer) = stage(
                &[chunk("data", 0, b"x")],
                &[declared("data", None)],
                parent.path(),
                &control,
                CAP,
            )
            .await?;
            assert!(matches!(staged, Err(StageError::DeadlinePassed)), "round {round}");
            assert_eq!(entries(parent.path())?, 0, "round {round}: a root was left behind");
        }
        Ok(())
    }

    /// A peer that sends a frame inside every idle gap, forever, is stopped by the total cap.
    #[tokio::test]
    async fn a_trickle_under_the_idle_gap_hits_the_total_cap() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let (mut peer, local) = tokio::io::duplex(4 * 1024 * 1024);
        let sender = tokio::spawn(async move {
            for offset in 0..200u64 {
                if write_frame(&mut peer, &chunk("data", offset, b"x")).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            peer
        });
        let limits = PullLimits {
            idle: Duration::from_secs(2),
            ..PullLimits::default()
        };
        let staged = stage_remote_inputs(
            local,
            &[declared("data", None)],
            parent.path(),
            &live(),
            Duration::from_millis(400),
            limits,
        )
        .await;
        assert!(
            matches!(staged, Err(StageError::TotalCapExceeded)),
            "got {:?}",
            staged.err()
        );
        assert_eq!(entries(parent.path())?, 0);
        sender.abort();
        Ok(())
    }

    /// The dial is mutual TLS to the orchestrator and writes the prefix for the DATA token: `job_id`, then that token,
    /// before any other byte. A real `listen_tls` listener reads it back.
    #[tokio::test]
    async fn the_dial_claims_the_data_link_with_the_data_token() -> anyhow::Result<()> {
        use std::{collections::HashSet, sync::Arc};

        let orchestrator = sandy_conn::TlsIdentity::generate().context("orchestrator identity")?;
        let agent = sandy_conn::TlsIdentity::generate().context("agent identity")?;
        let mesh_tls = sandy_fabric_local::mesh_link::MeshTlsIdentity {
            orchestrator_fingerprint: orchestrator.fingerprint(),
            identity: Arc::new(agent),
        };
        let listener = sandy_conn::listen_tls(
            "127.0.0.1:0".parse().context("bind addr")?,
            orchestrator,
            HashSet::from([mesh_tls.identity.fingerprint()]),
            Duration::from_secs(5),
            None,
        )
        .await
        .context("listen_tls")?;
        let addr = listener.local_addr().context("local_addr")?;

        let data_token = [0x42u8; REMOTE_LINK_TOKEN_LEN];
        let expected = sandy_executor_proto::encode_remote_link_prefix("job-1", &data_token).context("encode")?;
        let accepting = tokio::spawn(async move {
            let (mut conn, _peer) = listener.accept().await.context("accept")?;
            let mut buf = vec![0u8; expected.len()];
            conn.read_exact(&mut buf).await.context("read the prefix")?;
            anyhow::Ok((buf, expected))
        });

        let _link = dial_data_link(addr, "job-1", &data_token, &mesh_tls, &live())
            .await
            .context("the dial")?;
        let (got, expected) = tokio::time::timeout(Duration::from_secs(5), accepting)
            .await
            .context("the orchestrator side hung")?
            .context("the accept task")??;
        assert_eq!(got, expected, "the prefix must carry the job id and the data token");
        Ok(())
    }

    /// A job already cancelled (or past its deadline) does not dial: a closed route would otherwise hold the
    /// sequential dispatch loop for the whole dial timeout before it reports the cancel.
    #[tokio::test]
    async fn a_cancelled_control_stops_the_dial() -> anyhow::Result<()> {
        use std::sync::Arc;

        let mesh_tls = sandy_fabric_local::mesh_link::MeshTlsIdentity {
            identity: Arc::new(sandy_conn::TlsIdentity::generate().context("identity")?),
            orchestrator_fingerprint: sandy_conn::TlsIdentity::generate().context("identity")?.fingerprint(),
        };
        // A documentation-range address nothing answers: the dial would wait, or fail, but never connect.
        let blackhole: SocketAddr = "192.0.2.1:9".parse().context("addr")?;
        let token = [1u8; REMOTE_LINK_TOKEN_LEN];

        let cancelled = live();
        cancelled.cancel();
        let started = std::time::Instant::now();
        let result = dial_data_link(blackhole, "job-1", &token, &mesh_tls, &cancelled).await;
        assert!(matches!(result, Err(StageError::Cancelled)), "got {:?}", result.err());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a cancelled job must not wait on the dial"
        );

        let late = RunControl::new(std::time::Instant::now());
        let result = dial_data_link(blackhole, "job-1", &token, &mesh_tls, &late).await;
        assert!(
            matches!(result, Err(StageError::DeadlinePassed)),
            "got {:?}",
            result.err()
        );
        Ok(())
    }

    /// A cancel that lands as the pull finishes is not lost: the pull wins the race, then the control is
    /// checked again. Zero inputs make the pull complete without a pending await, so the order is deterministic.
    #[tokio::test]
    async fn a_cancel_that_lands_as_the_pull_finishes_is_not_lost() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let control = live();
        control.cancel();
        let (staged, _peer) = stage(&[end()], &[], parent.path(), &control, CAP).await?;
        assert!(matches!(staged, Err(StageError::Cancelled)), "got {:?}", staged.err());
        assert_eq!(entries(parent.path())?, 0);
        Ok(())
    }

    /// An input with an empty name is refused before any root is made: the sender cannot name its chunks.
    #[tokio::test]
    async fn an_unnamed_input_is_refused_before_a_root_exists() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let unnamed = sandy_executor_proto::Input {
            host: "/x".to_owned(),
            name: String::new(),
            guest_path: None,
        };
        let (staged, _peer) = stage(&[end()], &[unnamed], parent.path(), &live(), CAP).await?;
        assert!(
            matches!(staged, Err(StageError::UnnamedInput)),
            "got {:?}",
            staged.err()
        );
        assert_eq!(entries(parent.path())?, 0);
        Ok(())
    }

    /// A declared name the receiver would never match is refused before any root is made, one test row per shape
    /// (#764).
    #[tokio::test]
    async fn an_input_name_that_is_not_a_plain_relative_path_is_refused_before_a_root_exists() -> anyhow::Result<()> {
        let too_long = "a".repeat(sandy_executor_proto::MAX_CHUNK_NAME_BYTES + 1);
        for name in [
            too_long.as_str(),
            "/abs",
            "../up",
            "a/../b",
            "./a",
            "a/.",
            "a//b",
            "a/",
            "a\0b",
        ] {
            let parent = tempfile::tempdir().context("parent")?;
            let bad = sandy_executor_proto::Input {
                host: "/x".to_owned(),
                name: name.to_owned(),
                guest_path: None,
            };
            let (staged, _peer) = stage(&[end()], &[bad], parent.path(), &live(), CAP).await?;
            assert!(
                matches!(staged, Err(StageError::InvalidName(_))),
                "name {name:?}: got {:?}",
                staged.err()
            );
            assert_eq!(entries(parent.path())?, 0, "name {name:?} left a root");
        }
        Ok(())
    }
}
