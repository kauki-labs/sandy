//! Wraps the dispatched job in a detached `tmux` session behind a real PTY
//! (epic #340 phase 1), replacing the old three-pipe `Stdio::piped()` spawn.
//!
//! The job is never tmux's own direct child of this process: `tmux new-session
//! -d` asks the tmux *server* (started on demand) to create the session, and
//! returns almost immediately — the pane's own PTY is allocated by tmux
//! internally. This process's only direct child is a `tmux attach` process,
//! run on a PTY slave this module allocates; its master is what gets bridged
//! over the agent-fabric channel. Detaching (ending that one `tmux attach`
//! process) never touches the session or the job inside it — only a later
//! phase adds a second concurrent `tmux attach` for genuine multi-attach;
//! today's single bridge still only ever drives one.
//!
//! The job's real exit code cannot be read from `tmux attach`'s own exit
//! status (attaching ending says nothing about whether the job inside the
//! pane has finished). Instead the pane's command is wrapped to write a
//! sentinel file once the job exits, which [`wait_for_exit`] polls for —
//! independent of whether the bridge already ended, since the whole point of
//! a persistent tmux session is that the job keeps running detached.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// `history-limit`/`pipe-pane` log bound (lines), hardcoded for phase 1 — a
/// manifest-level override is phase 6 (epic #340).
const HISTORY_LIMIT: u32 = 10_000;

/// A fixed default size for the pane and the one `tmux attach` PTY this phase
/// opens: real per-connection sizing (the `Join` frame's `cols`/`rows`) is
/// phase 2/3 — there's no client size to read yet with only one, synchronous
/// bridge.
const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 24;

/// How often [`wait_for_exit`] polls for the sentinel file.
const SENTINEL_POLL: Duration = Duration::from_millis(50);

/// A fixed `TERM` every `tmux` invocation gets explicitly: `ProcessBackend`
/// spawns `sandy-agent` itself with `.env_clear()`, passing through only
/// `PATH` (and `spec.env`, which carries no `TERM` — there is no path for
/// arbitrary job env to reach a VM-backed job today, #340 phase 6's own
/// gap) — so `tmux` would otherwise inherit NO `TERM` at all and refuse to
/// attach. Per-client terminal capability negotiation (the real client's own
/// `TERM`) is tmux's own job once a client actually attaches — this is only
/// the session's own baseline, matching what the guest closure's terminfo
/// package (added alongside `tmux` itself) covers.
const TMUX_TERM: &str = "xterm-256color";

/// `tmux -L socket` with [`TMUX_TERM`] set explicitly, never relying on
/// inherited env or the shared default socket.
fn tmux_cmd(socket: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("tmux");
    cmd.env("TERM", TMUX_TERM).args(["-L", socket]);
    cmd
}

/// A detached tmux session wrapping the job, plus where to find its result.
pub struct TmuxJob {
    /// This job's own dedicated tmux server socket name (`-L`), never the
    /// shared default: a host running more than one job's agent at once (or
    /// this crate's own concurrent tests) would otherwise all fight over one
    /// server — confirmed as a real, reproducible failure (one job's
    /// `kill-session`/server-exit racing another's `set-option`/`new-session`
    /// mid-sequence, surfacing as a bare "no server running" once
    /// `impls/local/src/process.rs`'s AgentFailed console-discard bug (#340)
    /// stopped hiding it). Each `TmuxJob` gets a server entirely its own.
    socket: String,
    session: String,
    sentinel: PathBuf,
    /// The continuous `pipe-pane` transcript of the whole session's output,
    /// started before any attach — the epic #340 archival design's source
    /// file. Delivering it back to the submitter is phase 2+ scope; this
    /// phase only guarantees the file exists and is populated.
    log: PathBuf,
}

/// `s` as one single-quoted POSIX shell word (embedded `'` escaped as
/// `'\''`). Unlike `impls/vm/src/agent.rs`'s own `sh_quote` (which quotes the
/// whole already-space-joined argv as one word, losing argument boundaries
/// for any arg containing whitespace), this one is applied per-argument,
/// which is the correct way to reconstruct a shell command line from argv.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn quote_argv(argv: &[std::ffi::OsString]) -> String {
    argv.iter()
        .map(|a| sh_quote(&a.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

impl TmuxJob {
    /// Create a detached tmux session named uniquely per agent process
    /// (one job per bootstrap, so a fixed name is safe), running `job`
    /// wrapped to report its real exit code via a sentinel file, with
    /// `history-limit` and continuous `pipe-pane` logging enabled from the
    /// moment the session exists (before any attach) — satisfying
    /// "since the start of execution" (#340).
    ///
    /// # Errors
    /// If `tmux new-session` cannot be spawned or exits non-zero.
    pub fn start(job: &[std::ffi::OsString], peer_env: Option<(&str, &Path)>) -> std::io::Result<Self> {
        // Unique per call, not just per process: several `sandy-agent`
        // processes can share one host's tmux server (a trusted-process host
        // running more than one job's agent at once), and `std::process::id`
        // alone is not enough — Rust's own test harness runs many `#[test]`s
        // concurrently as threads of the SAME process, so a PID-only name
        // collided immediately under `cargo test`.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let tmp = std::env::temp_dir();
        let socket = format!("sandy-job-{unique}");
        let session = format!("sandy-job-{unique}");
        let sentinel = tmp.join(format!("sandy-job-{unique}.exit"));
        let log = tmp.join(format!("sandy-job-{unique}.log"));
        let _ = std::fs::remove_file(&sentinel);
        let _ = std::fs::remove_file(&log);

        let script = format!(
            "{}; printf 'sandy-exit:%d\\n' \"$?\" > {}",
            quote_argv(job),
            sh_quote(&sentinel.to_string_lossy())
        );

        // `remain-on-exit` MUST take effect at the moment the server starts,
        // before the session (and its pane's command) exists at all — not
        // via a `set-option` call issued as a SEPARATE process after
        // `new-session`/`start-server` returns. Tried that first: a fast job
        // (confirmed with `tty`, finishing in well under a millisecond) can
        // exit and destroy its pane — and, since it's the session's only
        // pane, the session and the whole server with it — before a later,
        // separate OS-level process's `set-option` call ever reaches it,
        // producing "no server running" (#340, found via the agent's own
        // console output once `impls/local/src/process.rs`'s AgentFailed
        // path stopped discarding it). Also tried an explicit `start-server`
        // immediately followed by a separate `set-option -g` process: same
        // race, one layer up — `start-server` returns once the fork is
        // initiated, not once the server has actually finished binding its
        // socket and is ready for a SEPARATE client connection.
        //
        // The actual fix: a `-f <config>` file read synchronously as tmux's
        // OWN server starts, as part of the SAME `new-session` invocation
        // that starts it — not a second OS process racing the first.
        //
        // `pipe-pane` has the IDENTICAL race, confirmed live: enabling it as
        // a later, separate command missed the job's very first output
        // (`echo hello` ran and printed before that second process ever
        // reached the session, while later output the job printed after
        // blocking on `read` was captured fine — the same shape of race as
        // `remain-on-exit`, just gated on wall-clock timing rather than the
        // job's own death). Fixed the same way: a `session-created` hook
        // in this same config file fires `pipe-pane` synchronously, as part
        // of tmux's own session-creation event, before the pane's command
        // (the job) ever starts running — no second process to race at all.
        let config = tmp.join(format!("sandy-job-{unique}.tmux.conf"));
        std::fs::write(
            &config,
            format!(
                "set-option -g remain-on-exit on\nset-option -g history-limit {HISTORY_LIMIT}\nset-hook -g \
                 session-created 'pipe-pane -o \"cat >> {}\"'\n",
                log.display()
            ),
        )?;

        // From here on, this job's dedicated server may already be up —
        // any failure below must kill it before returning, or it leaks a
        // process with no `TmuxJob` value ever constructed to `Drop` it
        // (the safety net added for a failure AFTER construction does not
        // cover a failure DURING it).
        let setup = (|| -> std::io::Result<()> {
            let mut cmd = tmux_cmd(&socket);
            cmd.args(["-f", &config.to_string_lossy(), "new-session", "-d", "-s", &session]);
            cmd.args(["-x", &DEFAULT_COLS.to_string(), "-y", &DEFAULT_ROWS.to_string()]);
            if let Some((name, dir)) = peer_env {
                cmd.arg("-e").arg(format!("{name}={}", dir.display()));
            }
            cmd.args(["sh", "-c", &script]);
            run_tmux(&mut cmd)?;
            // tmux only ever reads `-f`'s config once, synchronously, at
            // server startup — which `new-session` above already waited on,
            // and which is also what registered the `session-created` hook
            // that fired `pipe-pane` for this exact session. Nothing after
            // this point needs the file.
            let _ = std::fs::remove_file(&config);
            Ok(())
        })();
        if let Err(e) = setup {
            let _ = run_tmux(tmux_cmd(&socket).arg("kill-server"));
            let _ = std::fs::remove_file(&config);
            return Err(e);
        }

        Ok(Self {
            socket,
            session,
            sentinel,
            log,
        })
    }

    /// The continuous transcript [`start`] began piping the session's output
    /// to, from before any attach.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log
    }

    /// This job's own dedicated tmux server socket name — test-only, for
    /// confirming teardown from outside this module.
    #[cfg(test)]
    #[must_use]
    pub fn socket_name(&self) -> &str {
        &self.socket
    }

    /// This job's tmux session name — test-only, for confirming it's
    /// actually gone after a drop.
    #[cfg(test)]
    #[must_use]
    pub fn session_name(&self) -> &str {
        &self.session
    }

    /// Poll for the sentinel file [`start`] wraps the job to write, parsing
    /// its real exit code. Independent of the bridge/attach lifetime: the job
    /// may still be running in the detached session after a lone attach ends.
    ///
    /// # Errors
    /// If the sentinel file exists but its contents are not the expected
    /// `sandy-exit:<code>` shape.
    pub async fn wait_for_exit(&self) -> std::io::Result<i32> {
        loop {
            // A momentarily-empty (or partial) read is a real, expected
            // state, not a failure: the wrapped script's `>` redirection
            // creates/truncates the file the instant the shell parses the
            // command line, strictly before `printf` has actually written
            // anything to it — a poll can legitimately land in that window.
            // Only treat it as ready once it parses; anything else (missing,
            // empty, partial) just means "keep polling."
            if let Ok(contents) = tokio::fs::read_to_string(&self.sentinel).await
                && let Some(code) = contents
                    .trim()
                    .strip_prefix("sandy-exit:")
                    .and_then(|n| n.parse::<i32>().ok())
            {
                return Ok(code);
            }
            tokio::time::sleep(SENTINEL_POLL).await;
        }
    }

    /// Tear the whole dedicated server down (not just the session): since
    /// this job owns its socket exclusively, leaving the server running
    /// with no sessions would leak a process per job just the same as
    /// leaving the session itself running would. Best-effort — the server
    /// may already be gone.
    pub fn kill(&self) {
        let _ = run_tmux(tmux_cmd(&self.socket).arg("kill-server"));
    }

    /// Open a fresh PTY and attach it to this job's tmux session — the one
    /// bridged stream for this phase's single-attach bridge.
    ///
    /// # Errors
    /// If the PTY cannot be allocated or `tmux attach` cannot be spawned on it.
    pub fn open_attach(
        &self,
    ) -> std::io::Result<(
        AsyncPtyReader,
        AsyncPtyWriter,
        Box<dyn portable_pty::Child + Send + Sync>,
    )> {
        let pair = portable_pty::native_pty_system()
            .openpty(portable_pty::PtySize {
                rows: DEFAULT_ROWS,
                cols: DEFAULT_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(std::io::Error::other)?;
        let mut reader = pair.master.try_clone_reader().map_err(std::io::Error::other)?;
        let writer = pair.master.take_writer().map_err(std::io::Error::other)?;

        let mut builder = portable_pty::CommandBuilder::new("tmux");
        builder.env("TERM", TMUX_TERM);
        builder.args(["-L", &self.socket, "attach", "-t", &self.session]);
        let child = pair.slave.spawn_command(builder).map_err(std::io::Error::other)?;
        drop(pair.slave);

        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        std::thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });

        let (wtx, mut wrx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut writer = writer;
            while let Some(bytes) = wrx.blocking_recv() {
                if writer.write_all(&bytes).is_err() {
                    return;
                }
            }
        });

        // Keep the master's own handle alive for the connection's lifetime —
        // dropped once both the reader thread (on EOF) and this value end,
        // matching `impls/vm/src/console/transport.rs`'s `PtyTransport`
        // precedent for the same portable-pty shape.
        let _master = pair.master;

        Ok((
            AsyncPtyReader {
                rx,
                pending: Vec::new(),
            },
            AsyncPtyWriter { tx: wtx, _master },
            child,
        ))
    }
}

impl Drop for TmuxJob {
    /// The safety net for every path out, not just the explicit `kill()`
    /// calls in `serve()`'s own normal flow: a panicking test, an early `?`
    /// return before the job even starts bridging, or any other unplanned
    /// exit must not leave a session running forever on a shared tmux
    /// server. Confirmed as a real leak in CI/test runs sharing one host
    /// before this existed (25 accumulated sessions, found during #340's
    /// phase 2 work) — `kill()` itself is already idempotent-safe against a
    /// session that's already gone, so calling it twice (once explicitly,
    /// once here) is harmless.
    fn drop(&mut self) {
        self.kill();
    }
}

fn run_tmux(cmd: &mut std::process::Command) -> std::io::Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!("tmux exited with {status}")));
    }
    Ok(())
}

/// The PTY master's read side, fed by a background thread (the master has no
/// async-native read API) — same shape as `crates/sandy-cli/src/attach.rs`'s
/// `spawn_stdin_reader`.
pub struct AsyncPtyReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
}

impl AsyncRead for AsyncPtyReader {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.pending.is_empty() {
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => self.pending = chunk,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = buf.remaining().min(self.pending.len());
        buf.put_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Poll::Ready(Ok(()))
    }
}

/// The PTY master's write side, draining to a background thread so
/// `poll_write` never blocks the async runtime on a sync `Write`.
pub struct AsyncPtyWriter {
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// Keeps the PTY master descriptor alive for this writer's lifetime.
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl AsyncWrite for AsyncPtyWriter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::other("the PTY writer thread ended"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_each_argument_separately_preserving_boundaries() {
        let argv: Vec<std::ffi::OsString> = vec!["echo".into(), "hello world".into()];
        assert_eq!(quote_argv(&argv), "'echo' 'hello world'");
    }

    #[test]
    fn escapes_embedded_single_quotes() {
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }

    /// The job runs behind a real tmux-allocated PTY, not a pipe: `tty`
    /// prints a real `/dev/pts/N`, not "not a tty" — and the continuous
    /// `pipe-pane` transcript started at session creation carries it, with
    /// no attach involved at all (epic #340's "since the start of
    /// execution").
    #[tokio::test]
    async fn the_job_runs_behind_a_real_pty_and_the_transcript_captures_it() -> std::io::Result<()> {
        let job = vec!["tty".into()];
        let tmux_job = TmuxJob::start(&job, None)?;
        let exit = tokio::time::timeout(Duration::from_secs(10), tmux_job.wait_for_exit())
            .await
            .map_err(std::io::Error::other)??;
        tmux_job.kill();
        assert_eq!(exit, 0, "`tty` must succeed under a real pty");
        let transcript = std::fs::read_to_string(tmux_job.log_path())?;
        assert!(
            transcript.contains("/dev/pts/") || transcript.contains("/dev/tty"),
            "transcript must show a real pty path, not \"not a tty\": {transcript:?}"
        );
        assert!(
            !transcript.contains("not a tty"),
            "transcript shows the job was NOT given a real tty: {transcript:?}"
        );
        Ok(())
    }

    /// The real job exit code survives the sentinel round trip, independent
    /// of `tmux attach`'s own (irrelevant) exit status.
    #[tokio::test]
    async fn the_real_exit_code_is_read_back_via_the_sentinel() -> std::io::Result<()> {
        let job = vec!["sh".into(), "-c".into(), "exit 42".into()];
        let tmux_job = TmuxJob::start(&job, None)?;
        let exit = tokio::time::timeout(Duration::from_secs(10), tmux_job.wait_for_exit())
            .await
            .map_err(std::io::Error::other)??;
        tmux_job.kill();
        assert_eq!(exit, 42);
        Ok(())
    }

    /// Regression (#340 phase 2 found this as a real leak: 25 accumulated
    /// sessions on a shared tmux server from test runs that never called
    /// `kill()` explicitly): a `TmuxJob` dropped WITHOUT an explicit `kill()`
    /// call — standing in for a panicking test or an early `?` return in
    /// `serve()` — must still tear its whole dedicated server down, not just
    /// end up with the session unreachable on the wrong socket. Checked
    /// against the job's own `-L` socket (each job owns one exclusively),
    /// via a plain `tmux` invocation, not `tmux_cmd()`, matching a real
    /// caller checking from outside this module.
    #[tokio::test]
    async fn dropping_a_tmux_job_without_an_explicit_kill_still_tears_down_its_session() -> std::io::Result<()> {
        let job = vec!["sleep".into(), "30".into()];
        let (socket, session) = {
            let tmux_job = TmuxJob::start(&job, None)?;
            let ids = (tmux_job.socket_name().to_string(), tmux_job.session_name().to_string());
            // `tmux_job` drops here, with no explicit `.kill()` call.
            ids
        };
        let has_session = std::process::Command::new("tmux")
            .args(["-L", &socket, "has-session", "-t", &session])
            .status()?;
        assert!(
            !has_session.success(),
            "the session (and its whole dedicated server) must be gone after the TmuxJob was dropped, not merely out \
             of explicit reach"
        );
        Ok(())
    }
}
