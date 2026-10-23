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
//! pane has finished). Instead the pane's command is wrapped to print a
//! sentinel line as its own last line of output once the job exits, which
//! [`wait_for_exit`] tails the `pipe-pane` transcript for — independent of
//! whether the bridge already ended, since the whole point of a persistent
//! tmux session is that the job keeps running detached. The marker rides the
//! SAME stream `log_path`'s console capture reads, rather than a separate
//! sentinel file: a separate file raced `pipe-pane`'s own, independently
//! scheduled flush under load (confirmed: concurrent runs at scale saw the
//! sentinel file's exit code land before `pipe-pane` had actually finished
//! copying the job's preceding output into the log, truncating the
//! transcript). Detecting the marker by its appearance IN the transcript
//! makes that race structurally impossible — if the marker is visible,
//! everything the job wrote before it in program order is already there too.

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

/// How often [`wait_for_exit`] polls the transcript for the exit marker.
const SENTINEL_POLL: Duration = Duration::from_millis(50);

/// The job's wrapped command prints `{EXIT_MARKER}<code>` as its own last
/// line of output; [`wait_for_exit`] tails the transcript for it.
const EXIT_MARKER: &str = "sandy-exit:";

/// The longest a real exit-code line's digits can be (`i32::MIN` is 11
/// chars, plus margin) — bounds how long [`TmuxJob::wait_for_exit`] will
/// wait on a candidate match before deciding it isn't the real marker.
const MAX_EXIT_CODE_DIGITS: usize = 16;

/// How many [`SENTINEL_POLL`] iterations between `pane_dead` checks (roughly
/// once a second) — cheap compared to an interactive job's own lifetime
/// (which can run for hours), but far too expensive to spawn `tmux
/// display-message` on every single 50ms sentinel poll.
const PANE_DEAD_CHECK_EVERY: u32 = 20;

/// How long a dead pane with no sentinel is given before
/// [`TmuxJob::wait_for_exit`] gives up and reports it as a real error,
/// rather than polling forever. Short enough that a genuinely killed job
/// resolves promptly; long enough to not race a legitimate final
/// sentinel-write still in flight.
const PANE_DEAD_GRACE: Duration = Duration::from_secs(2);

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

/// `path` as a plain UTF-8 string, rejected up front if it carries a
/// character that would break out of the TWO quoting layers it gets embedded
/// in inside the generated tmux config: tmux's own single-quoted `'...'`
/// `set-hook` argument, nested inside which is a double-quoted `"cat >>
/// ..."` shell command `pipe-pane` later spawns via `sh -c`. In ordinary use
/// this path is `std::env::temp_dir()` joined with a filename this module
/// builds itself from plain digits, so rejection is not expected — this
/// exists for whatever a host's `TMPDIR` could put there, caught before the
/// config file is ever written, not after.
fn validate_tmux_safe_path(path: &Path) -> std::io::Result<&str> {
    let s = path
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "the path is not valid UTF-8"))?;
    if s.contains(['\'', '"', '\\', '`', '$', '\n', '#']) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "the path contains a character unsafe for the tmux config's nested quoting, or tmux's own `#{{...}}` \
                 format expansion: {s:?}"
            ),
        ));
    }
    Ok(s)
}

impl TmuxJob {
    /// Create a detached tmux session named uniquely per agent process
    /// (one job per bootstrap, so a fixed name is safe), running `job`
    /// wrapped to print its real exit code as the transcript's own last line,
    /// with `history-limit` and continuous `pipe-pane` logging enabled from
    /// the moment the session exists (before any attach) — satisfying
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
        let log = tmp.join(format!("sandy-job-{unique}.log"));
        let _ = std::fs::remove_file(&log);

        // Printed to stdout, not a separate file: this marker rides the same
        // pty -> pipe-pane -> log stream `wait_for_exit` tails, so observing
        // it in the log is itself proof every byte the job wrote before it
        // is already there (see this module's own doc comment).
        let script = format!("{}; printf '{EXIT_MARKER}%d\\n' \"$?\"", quote_argv(job));

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
        let safe_log = validate_tmux_safe_path(&log)?;
        let config = tmp.join(format!("sandy-job-{unique}.tmux.conf"));
        std::fs::write(
            &config,
            format!(
                "set-option -g remain-on-exit on\nset-option -g history-limit {HISTORY_LIMIT}\nset-hook -g \
                 session-created 'pipe-pane -o \"cat >> {safe_log}\"'\n",
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
            // Each `new-session` here cold-starts a brand new tmux SERVER
            // (dedicated `-L` socket, never shared), which itself forks
            // twice (daemonize, then the pane's shell) — confirmed live: at
            // 48-way concurrency, with each job its own SEPARATE sandy-agent
            // OS process, many servers cold-starting within the same tight
            // window made tmux's OWN internal fork() intermittently fail
            // ("create window failed: fork failed"), reproducing in this
            // crate's own process tree but not in an equivalent plain shell
            // loop of the same width — something about how tightly our own
            // spawn path bunches them. Serializing just this one spawn
            // across EVERY `sandy-agent` process on the host (not the
            // session's lifetime, which still runs fully concurrently once
            // up) needs a cross-process lock, not an in-process `Mutex` —
            // each job is its own process, so a `Mutex` here would never
            // have another holder to contend with. `flock` on a fixed path
            // is released by the kernel the moment this process's fd closes
            // (including on a crash mid-spawn), so there's no stale-lock
            // cleanup to get wrong. The existing `SPAWN_LOCK` in
            // `impls/local/src/process.rs` is the same fix for the same
            // class of problem (#230/#281) one layer up, there in-process
            // because that spawn genuinely does happen inside shared
            // in-process concurrency.
            let lock_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(tmp.join("sandy-tmux-spawn.lock"))?;
            fs2::FileExt::lock_exclusive(&lock_file)?;
            let result = run_tmux(&mut cmd);
            let _ = fs2::FileExt::unlock(&lock_file);
            result?;
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

        Ok(Self { socket, session, log })
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

    /// Tail the `pipe-pane` transcript ([`start`] wraps the job to print its
    /// real exit code as the transcript's own last line) for [`EXIT_MARKER`],
    /// parsing the real exit code. Independent of the bridge/attach
    /// lifetime: the job may still be running in the detached session after
    /// a lone attach ends.
    ///
    /// Reads only newly appended bytes each poll (never the whole file), so
    /// cost stays bounded by how much the job actually writes, not by how
    /// long an interactive session has been attached.
    ///
    /// # Errors
    /// If the log file cannot be read once it exists.
    ///
    /// A pane that dies WITHOUT ever printing the marker (confirmed: a job
    /// that signals its own wrapping shell dead mid-script, before the
    /// trailing marker-print ever runs — `remain-on-exit` keeps a pane like
    /// this around, so it never shows up as a dead *session* either, just a
    /// frozen, markerless one) is treated as a real error after a grace
    /// period, not polled for forever. Without this, exactly that case
    /// leaked an orphaned dedicated tmux server indefinitely — confirmed
    /// live: several hours-old orphaned servers found from this exact
    /// scenario before this existed.
    pub async fn wait_for_exit(&self) -> std::io::Result<i32> {
        use tokio::io::AsyncReadExt;

        let mut file = loop {
            match tokio::fs::File::open(&self.log).await {
                Ok(file) => break file,
                // The `session-created` hook's `pipe-pane` spawn (a separate
                // process from `new-session` itself) can land a tick after
                // `start()` returns — not ready yet is expected, not an error.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(SENTINEL_POLL).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        // Only the as-yet-unmatched tail since the last read, as raw bytes
        // (never a `String`): a chunk boundary can land mid-codepoint in the
        // job's own (non-ASCII) output, and `String::drain`'s byte-offset
        // trimming below would panic if it didn't fall on a char boundary.
        // The marker itself and the exit code are pure ASCII, so searching
        // and parsing never needs a full UTF-8 decode of the whole tail.
        let marker = EXIT_MARKER.as_bytes();
        let mut tail: Vec<u8> = Vec::new();
        let mut dead_since: Option<std::time::Instant> = None;
        let mut iteration: u32 = 0;
        loop {
            let mut chunk = Vec::new();
            file.read_to_end(&mut chunk).await?;
            if !chunk.is_empty() {
                tail.extend_from_slice(&chunk);
                // Consume every complete candidate line starting with the
                // marker, in order: the job's own output can coincidentally
                // contain this exact text without being a real exit-code
                // line (or a line that starts with it but runs implausibly
                // long before its newline) — skip past it and keep scanning
                // rather than getting stuck on it forever. A match whose
                // line hasn't fully arrived yet is left in place for the
                // next poll.
                loop {
                    let Some(start) = tail.windows(marker.len()).position(|w| w == marker) else {
                        // No candidate at all: keep only enough of the tail
                        // to catch one split across the next read, so a
                        // long-running job's transcript never grows this
                        // buffer unbounded.
                        let keep_from = tail.len().saturating_sub(marker.len() + MAX_EXIT_CODE_DIGITS);
                        tail.drain(..keep_from);
                        break;
                    };
                    let after = start + marker.len();
                    let line_end = tail[after..].iter().position(|&b| b == b'\n');
                    match line_end {
                        Some(line_end) if line_end <= MAX_EXIT_CODE_DIGITS => {
                            let line = &tail[after..after + line_end];
                            let digits = line.strip_suffix(b"\r").unwrap_or(line);
                            if let Ok(code) = std::str::from_utf8(digits).unwrap_or("").parse::<i32>() {
                                return Ok(code);
                            }
                            // Not our marker: skip just this occurrence, not
                            // the whole line — a later, real marker can sit
                            // on the SAME line right after this decoy (no
                            // newline between them), and draining past the
                            // line's own newline would destroy it before it
                            // is ever scanned.
                            tail.drain(..start + 1);
                        }
                        // Either a complete line too long to be a real exit
                        // code, or no newline yet but already past that
                        // bound: not our marker — skip just this occurrence
                        // and keep scanning for a later, real one.
                        Some(_) => {
                            tail.drain(..start + 1);
                        }
                        None if tail.len() - after > MAX_EXIT_CODE_DIGITS => {
                            tail.drain(..start + 1);
                        }
                        // Still short enough to plausibly be ours, just not
                        // complete yet: wait for more data next poll.
                        None => {
                            tail.drain(..start);
                            break;
                        }
                    }
                }
            }
            // Throttled: a long-lived interactive job can run for hours, so
            // this must not spawn `tmux display-message` on every 50ms poll
            // — only roughly once a second, and not at all once a death is
            // already confirmed (no point re-checking after that).
            iteration += 1;
            if dead_since.is_none() && iteration.is_multiple_of(PANE_DEAD_CHECK_EVERY) && self.pane_is_dead() {
                dead_since = Some(std::time::Instant::now());
            }
            if let Some(since) = dead_since
                && since.elapsed() > PANE_DEAD_GRACE
            {
                return Err(std::io::Error::other(
                    "the pane died without ever printing its exit marker (likely killed by a signal before it could \
                     report)",
                ));
            }
            tokio::time::sleep(SENTINEL_POLL).await;
        }
    }

    /// Whether this job's pane has already died (`#{pane_dead}`), via a
    /// cheap, throttled `tmux display-message` query — best-effort: any
    /// failure (including the session already being fully gone) reads as
    /// "not dead" here, since [`wait_for_exit`]'s own sentinel read is what
    /// actually confirms completion; this only unsticks the case where the
    /// sentinel will never arrive.
    fn pane_is_dead(&self) -> bool {
        tmux_cmd(&self.socket)
            .args(["display-message", "-p", "-t", &self.session, "#{pane_dead}"])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "1")
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
    /// bridged stream for this phase's single-attach bridge. The returned
    /// [`PtyResizer`] is how a caller applies a `Join`'s initial size and any
    /// later `Resize` frame to THIS pty (epic #340 phase 2) — `open_attach`
    /// itself only ever sizes it to the fixed [`DEFAULT_COLS`]/[`DEFAULT_ROWS`].
    ///
    /// # Errors
    /// If the PTY cannot be allocated or `tmux attach` cannot be spawned on it.
    pub fn open_attach(
        &self,
    ) -> std::io::Result<(
        AsyncPtyReader,
        AsyncPtyWriter,
        PtyResizer,
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

        // Shared, not owned by one side alone: `AsyncPtyWriter` keeps it
        // alive for the connection's lifetime (matching
        // `impls/vm/src/console/transport.rs`'s `PtyTransport` precedent for
        // the same portable-pty shape), while `PtyResizer` is the only way
        // to actually call `resize` on it. A plain `Mutex`, not relying on
        // `MasterPty`'s own (unconfirmed) `Sync`-ness, since every access
        // here is a single, infrequent method call, never a hot path.
        let master = std::sync::Arc::new(std::sync::Mutex::new(pair.master));

        Ok((
            AsyncPtyReader {
                rx,
                pending: Vec::new(),
            },
            AsyncPtyWriter {
                tx: wtx,
                _master: std::sync::Arc::clone(&master),
            },
            PtyResizer(master),
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
    /// Keeps the PTY master descriptor alive for this writer's lifetime —
    /// shared with a [`PtyResizer`] for the same master, never used directly
    /// through this field (hence `_`-prefixed; `resize` is `PtyResizer`'s).
    _master: std::sync::Arc<std::sync::Mutex<Box<dyn portable_pty::MasterPty + Send>>>,
}

/// Applies a [`crate::link_source`]-independent terminal resize to the PTY
/// [`TmuxJob::open_attach`] returned alongside it (epic #340 phase 2): the
/// one way a caller can honor a `Join`'s initial size or a later `Resize`
/// frame, since neither is known yet when `open_attach` picks the fixed
/// [`DEFAULT_COLS`]/[`DEFAULT_ROWS`] default. Cheap and `Clone`: every clone
/// shares the one underlying master.
#[derive(Clone)]
pub struct PtyResizer(std::sync::Arc<std::sync::Mutex<Box<dyn portable_pty::MasterPty + Send>>>);

impl PtyResizer {
    /// # Errors
    /// If the underlying `ioctl` fails (e.g. the pty's slave side is already
    /// gone).
    pub fn resize(&self, cols: u16, rows: u16) -> std::io::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resize(portable_pty::PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(std::io::Error::other)
    }
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

    #[test]
    fn rejects_a_path_carrying_the_tmux_configs_own_quote_characters() {
        for bad in [
            "/tmp/weird\"quote",
            "/tmp/weird'quote",
            "/tmp/weird$var",
            "/tmp/weird`cmd`",
        ] {
            assert!(
                validate_tmux_safe_path(Path::new(bad)).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    /// `#{...}` is tmux's own format-expansion syntax, evaluated even inside
    /// a value already protected by ordinary shell/tmux quoting — a crafted
    /// path containing one could alter the `pipe-pane` command tmux itself
    /// builds, independent of the other rejected characters.
    #[test]
    fn rejects_a_path_carrying_a_tmux_format_expression() {
        assert!(validate_tmux_safe_path(Path::new("/tmp/#{pane_id}.log")).is_err());
    }

    #[test]
    fn accepts_an_ordinary_path() {
        assert_eq!(
            validate_tmux_safe_path(Path::new("/tmp/sandy-job-123.log")).unwrap(),
            "/tmp/sandy-job-123.log"
        );
    }

    /// Regression (CodeRabbit on #342): the job's own output can coincidentally
    /// contain the literal marker text without being the real exit-code line
    /// (here, printed before the job actually exits) — `wait_for_exit` must
    /// skip past it and keep scanning, not get stuck treating it as final.
    #[tokio::test]
    async fn a_decoy_marker_line_is_skipped_and_the_real_exit_code_still_wins() -> std::io::Result<()> {
        let job = vec![
            "sh".into(),
            "-c".into(),
            std::ffi::OsString::from(format!("echo '{EXIT_MARKER}not-a-number'; exit 9")),
        ];
        let tmux_job = TmuxJob::start(&job, None)?;
        let exit = tokio::time::timeout(Duration::from_secs(10), tmux_job.wait_for_exit())
            .await
            .map_err(std::io::Error::other)??;
        tmux_job.kill();
        assert_eq!(exit, 9, "the decoy line must not be mistaken for the real exit marker");
        Ok(())
    }

    /// Regression (CodeRabbit on #342, round 2): a decoy marker with no
    /// trailing newline before `start()`'s own real marker follows right
    /// after it, on the SAME line. Skipping the decoy must not drain past
    /// the real marker sitting right behind it on that same line.
    #[tokio::test]
    async fn a_decoy_with_no_trailing_newline_does_not_swallow_the_real_marker_right_behind_it() -> std::io::Result<()>
    {
        let job = vec![
            "sh".into(),
            "-c".into(),
            std::ffi::OsString::from(format!("printf '{EXIT_MARKER}nan'; exit 5")),
        ];
        let tmux_job = TmuxJob::start(&job, None)?;
        let exit = tokio::time::timeout(Duration::from_secs(10), tmux_job.wait_for_exit())
            .await
            .map_err(std::io::Error::other)??;
        tmux_job.kill();
        assert_eq!(
            exit, 5,
            "the real marker right behind the decoy (no newline between them) must still be found"
        );
        Ok(())
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

    /// The real job exit code survives the marker round trip through the
    /// transcript, independent of `tmux attach`'s own (irrelevant) exit
    /// status.
    #[tokio::test]
    async fn the_real_exit_code_is_read_back_from_the_transcript() -> std::io::Result<()> {
        let job = vec!["sh".into(), "-c".into(), "exit 42".into()];
        let tmux_job = TmuxJob::start(&job, None)?;
        let exit = tokio::time::timeout(Duration::from_secs(10), tmux_job.wait_for_exit())
            .await
            .map_err(std::io::Error::other)??;
        tmux_job.kill();
        assert_eq!(exit, 42);
        Ok(())
    }

    /// Regression (#340): confirmed live as the real mechanism behind a
    /// separate leak (several hours-old orphaned dedicated tmux servers
    /// found in this crate's own test runs) — a job that kills its own
    /// wrapping shell via a signal, before that shell ever reaches the
    /// trailing marker-print, must not hang `wait_for_exit` forever.
    /// `remain-on-exit` keeps a pane like this around (it's not even a dead
    /// *session*, just a frozen, markerless one), so without the
    /// `pane_is_dead` check this polled indefinitely, leaking the session.
    #[tokio::test]
    async fn a_job_that_kills_its_own_wrapping_shell_does_not_hang_forever() -> std::io::Result<()> {
        // `$PPID` from inside this nested `sh -c` is the OUTER wrapping
        // shell `TmuxJob::start` itself constructs (confirmed live:
        // completely distinct from any process outside the pane) — killing
        // it aborts that wrapper before its trailing marker-print ever
        // runs, exactly the scenario the adversarial `kill -ABRT $PPID` test
        // (`agent_process.rs`) exercises against the real spawned agent.
        let job = vec!["sh".into(), "-c".into(), "kill -ABRT $PPID; exit 0".into()];
        let tmux_job = TmuxJob::start(&job, None)?;
        let result = tokio::time::timeout(Duration::from_secs(10), tmux_job.wait_for_exit()).await;
        tmux_job.kill();
        match result {
            Ok(Err(_)) => {} // the expected, bounded "pane died, no marker" error
            Ok(Ok(code)) => panic!("expected an error, got a spurious exit code {code}"),
            Err(_) => panic!("wait_for_exit hung past its own PANE_DEAD_GRACE bound — the leak this regresses"),
        }
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
