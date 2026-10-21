//! `sandy daemon attach`'s interactive bridge (#327): once the control
//! connection's `Attach` request succeeds, redeem its cap on `sandyd`'s
//! separate attach data-plane socket (`sandy_control_proto::attach_socket_path`,
//! `docs/decisions/sandyd.md` §1 keeps the control RPC itself pure
//! request/response — this never rides that connection) and bridge the local
//! terminal's stdin/stdout to it: raw mode while a real terminal is attached
//! (piped stdin, the ordinary case under test automation, bridges
//! unmodified), until local Ctrl-D/EOF, the connection closing, or the job
//! reaching a terminal status (polled on the now-otherwise-idle control
//! connection, which stays open for exactly this).
//!
//! Detaching never touches the job itself: it only closes this attach
//! connection. Re-attaching later is a fresh `sandy daemon attach` invocation
//! — a fresh control-RPC `Attach` call (a new CF-H-1 session) redeeming a
//! fresh cap on a fresh attach connection. #327's known limitation (see the
//! PR's design notes): only the ORIGINAL submitting connection's own session
//! gets a post-capable cap — a later invocation, even by the same operator,
//! is a different session and gets observer-only rights.

use std::io::IsTerminal as _;

use sandy_fabric_local::{
    agent::{TTY_STDERR, TTY_STDIN, TTY_STDOUT},
    link::{LinkFrame, read_frame, write_frame},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

/// The largest chunk read from local stdin per posted frame.
const STDIN_CHUNK: usize = 4096;

/// Ctrl-D's raw-mode byte (ASCII EOT, `0x04`) — the local terminal's own
/// detach gesture. Under [`RawMode`] (canonical-mode EOF handling disabled),
/// it arrives as a literal byte in the input stream, never as a 0-byte read;
/// a 0-byte read is reserved for a non-tty, piped stdin reaching real EOF.
const CTRL_D: u8 = 0x04;

/// Puts the real stdin fd into raw mode for the duration of this guard
/// (`Drop` restores the original termios) — a no-op if stdin is not a real
/// terminal (piped stdin, e.g. under test automation), since there is no
/// terminal discipline to change in the first place.
///
/// `cfmakeraw` clears `OPOST`, which would also mangle output this process
/// itself prints (not just what it relays) by turning every bare `\n` into a
/// staircase; `output_modes` is set back to `OPOST | ONLCR` right after, so
/// local output stays normal while input discipline goes raw.
struct RawMode {
    original: Option<rustix::termios::Termios>,
}

impl RawMode {
    fn enable() -> Self {
        if !std::io::stdin().is_terminal() {
            return Self { original: None };
        }
        let Ok(original) = rustix::termios::tcgetattr(std::io::stdin()) else {
            // A tty by `IsTerminal`'s own check, yet tcgetattr refused —
            // treat as "not actually controllable" rather than failing the
            // whole attach over terminal cosmetics.
            return Self { original: None };
        };
        let mut raw = original.clone();
        raw.make_raw();
        raw.output_modes = rustix::termios::OutputModes::OPOST | rustix::termios::OutputModes::ONLCR;
        if rustix::termios::tcsetattr(std::io::stdin(), rustix::termios::OptionalActions::Flush, &raw).is_err() {
            return Self { original: None };
        }
        Self {
            original: Some(original),
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = rustix::termios::tcsetattr(std::io::stdin(), rustix::termios::OptionalActions::Flush, &original);
        }
    }
}

/// Reads local stdin on its own blocking OS thread (never a tokio task):
/// `tokio::io::stdin()`'s own docs warn a blocked read on it cannot be
/// cancelled, which would otherwise hang this process's runtime shutdown
/// until the user next presses a key. A `std::thread` reading real stdin has
/// the identical "parked in the kernel read call" property, but nothing here
/// ever needs to cancel it — it's left to end on its own (process exit drops
/// it) once [`run_interactive`] itself has already returned.
fn spawn_stdin_reader() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut buf = vec![0_u8; STDIN_CHUNK];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => return, // real EOF (piped stdin, no tty)
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        return; // the receiving end dropped; nothing left to feed
                    }
                }
                Err(_) => return,
            }
        }
    });
    rx
}

/// Bridge `read_half`/`write_half` — `sandyd`'s attach data-plane connection,
/// already past its `Join`/`Joined` handshake — to the local terminal: local
/// stdin -> posted `TTY_STDIN`, delivered `TTY_STDOUT`/`TTY_STDERR` -> local
/// stdout, until local Ctrl-D/EOF, the connection closing, or
/// `status_watch` reports the job reached a terminal state.
///
/// # Errors
/// An I/O fault reading or writing the connection or the local terminal.
pub async fn run_interactive<R, W>(
    mut read_half: R,
    write_half: W,
    mut status_watch: Option<tokio::sync::oneshot::Receiver<String>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let _raw_mode = RawMode::enable();
    let write_half = std::sync::Arc::new(tokio::sync::Mutex::new(write_half));

    let mut stdin_rx = spawn_stdin_reader();
    let stdin_task = {
        let write_half = std::sync::Arc::clone(&write_half);
        tokio::spawn(async move {
            while let Some(chunk) = stdin_rx.recv().await {
                let ctrl_d_at = chunk.iter().position(|&b| b == CTRL_D);
                let (before, detach) = match ctrl_d_at {
                    Some(i) => (&chunk[..i], true),
                    None => (&chunk[..], false),
                };
                if !before.is_empty() {
                    let frame = LinkFrame::Post {
                        content_type: TTY_STDIN.to_string(),
                        payload: hex::encode(before),
                        channel: None,
                    };
                    if write_frame(&mut *write_half.lock().await, &frame).await.is_err() {
                        return;
                    }
                }
                if detach {
                    return; // Ctrl-D: stop forwarding, let the connection close
                }
            }
        })
    };

    let mut stdout = tokio::io::stdout();
    let result = loop {
        let delivered = if let Some(watch) = status_watch.as_mut() {
            tokio::select! {
                frame = read_frame(&mut read_half) => frame,
                status = watch => {
                    if let Ok(status) = status {
                        println!("sandy: job reached a terminal state ({status}); detaching");
                    }
                    break Ok(());
                }
            }
        } else {
            read_frame(&mut read_half).await
        };
        match delivered {
            Ok(Some(LinkFrame::Deliver {
                content_type, payload, ..
            })) if content_type == TTY_STDOUT || content_type == TTY_STDERR => {
                let Ok(bytes) = hex::decode(&payload) else {
                    break Err(std::io::Error::other("delivered frame payload was not valid hex"));
                };
                if let Err(e) = stdout.write_all(&bytes).await {
                    break Err(e);
                }
                if let Err(e) = stdout.flush().await {
                    break Err(e);
                }
            }
            Ok(Some(LinkFrame::Refused { reason })) => {
                eprintln!("sandy: {reason}");
            }
            Ok(Some(_other)) => {
                // Anything else on this wire would be a protocol violation
                // from `sandyd`'s side; surfaced, not silently ignored, but
                // not fatal to an otherwise-working bridge either.
                eprintln!("sandy: attach: unexpected frame from the daemon");
            }
            Ok(None) => break Ok(()), // clean close
            Err(e) => break Err(std::io::Error::other(e)),
        }
    };

    stdin_task.abort();
    result
}

/// Poll `job_id`'s status on `control_connection` (the control-RPC connection
/// `Attach` already succeeded on, left open — the data plane is a SEPARATE
/// connection, so this one is otherwise idle) every `interval`, sending its
/// name once the job reaches a terminal state (anything but
/// `Pending`/`Running`), so [`run_interactive`] can end the bridge and report
/// it. Silently stops (never sends) if the connection faults; the relay's own
/// EOF/fault handling is what ends the bridge in that case.
#[must_use]
pub fn spawn_status_watch(
    mut control_connection: tokio::net::UnixStream,
    job_id: String,
    interval: std::time::Duration,
) -> tokio::sync::oneshot::Receiver<String> {
    use sandy_control_proto::{JobStatus, StatusRequest, control_request, control_response};

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut request_id = 1_u64;
        loop {
            tokio::time::sleep(interval).await;
            request_id += 1;
            let Ok(response) = sandy_control_proto::client::call(
                &mut control_connection,
                request_id,
                control_request::Op::Status(StatusRequest { job_id: job_id.clone() }),
            )
            .await
            else {
                return;
            };
            let Some(control_response::Result::Status(status)) = response.result else {
                return;
            };
            let parsed = JobStatus::try_from(status.status).unwrap_or(JobStatus::Unspecified);
            if !matches!(parsed, JobStatus::Pending | JobStatus::Running) {
                let _ = tx.send(parsed.as_str_name().to_owned());
                return;
            }
        }
    });
    rx
}
