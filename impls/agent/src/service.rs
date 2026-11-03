//! A service's readiness probe (#589).
//!
//! When the job is a declared service, the agent runs its [`HealthProbe`] inside the guest every
//! `interval_secs` until one attempt passes (`Ready`) or `max_attempts` attempts in a row fail
//! (`Failed`, with the last attempt's output). Readiness comes from this probe, never from console text.

use std::time::Duration;

use sandy_api::agent::SERVICE_ENV;
use sandy_guest_template::manifest::{HealthProbe, ProbeCheck, ServiceSpec, validate_service_spec};
use tokio::{io::AsyncReadExt, net::TcpStream, process::Command};

/// The service this agent supervises, from [`SERVICE_ENV`]. `None` for a plain job.
///
/// # Errors
/// The variable is set but is not valid UTF-8 or not a `ServiceSpec`: refused, never run as a plain job, so a
/// service whose spec was mangled in transit does not silently skip its probe.
pub fn from_env() -> Result<Option<ServiceSpec>, String> {
    match std::env::var(SERVICE_ENV) {
        Ok(json) => parse(&json).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(format!("{SERVICE_ENV}: {e}")),
    }
}

/// Parses and re-validates the spec. The executor validated it at decode, but the agent does not trust the
/// env it is given: a spec that reached it by another route (a submitter's own env entry) is checked here too.
fn parse(json: &str) -> Result<ServiceSpec, String> {
    let spec: ServiceSpec =
        serde_json::from_str(json).map_err(|e| format!("{SERVICE_ENV} is not a service spec: {e}"))?;
    validate_service_spec(&spec).map_err(|e| format!("{SERVICE_ENV} is not a runnable service spec: {e}"))?;
    Ok(spec)
}

/// The longest probe command output kept per attempt.
const ATTEMPT_OUTPUT_CAP: usize = 4096;

/// How a probe ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// One attempt passed.
    Ready,
    /// `max_attempts` attempts in a row failed; `output` is the last attempt's output.
    Failed {
        /// The last attempt's output or connect error.
        output: String,
    },
}

/// The account database the agent resolves a service's `user` against.
pub const PASSWD_PATH: &str = "/etc/passwd";

/// The uid `user` has in `passwd` (the text of `/etc/passwd`), never 0.
///
/// The manifest names an account, and another account can share uid 0 (`toor`): the name is only checked
/// for shape at decode, so the uid it resolves to is checked here, in the guest, where the account database is.
///
/// # Errors
/// `user` is absent, its entry is malformed, or it resolves to uid 0.
pub fn resolve_uid(passwd: &str, user: &str) -> Result<u32, String> {
    let entry = passwd
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .find(|line| line.split(':').next() == Some(user))
        .ok_or_else(|| format!("no such account {user:?} in {PASSWD_PATH}"))?;
    let uid = entry
        .split(':')
        .nth(2)
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| format!("the {PASSWD_PATH} entry for {user:?} has no numeric uid"))?;
    if uid == 0 {
        return Err(format!("account {user:?} has uid 0: a service must not run as root"));
    }
    Ok(uid)
}

/// `job` run as `user`: `runuser -u <user> -- <job>`. The agent stays root; only the service drops privilege.
#[must_use]
pub fn as_user(user: &str, job: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = vec!["runuser".into(), "-u".into(), user.into(), "--".into()];
    argv.extend(job);
    argv
}

/// The argv the service runs as. When the agent is root (in a guest), the account must resolve to a non-zero
/// uid and the job runs through `runuser`. When the agent is not root (the process backend on a host) there is
/// no privilege to drop, so the job runs as the agent's own user: never with more privilege than declared.
///
/// # Errors
/// The agent is root and [`resolve_uid`] refuses the account, or the account database cannot be read.
pub fn service_argv(user: &str, job: Vec<std::ffi::OsString>) -> Result<Vec<std::ffi::OsString>, String> {
    if !rustix::process::geteuid().is_root() {
        return Ok(job);
    }
    let passwd = std::fs::read_to_string(PASSWD_PATH).map_err(|e| format!("reading {PASSWD_PATH}: {e}"))?;
    resolve_uid(&passwd, user)?;
    Ok(as_user(user, job))
}

/// The running readiness probe: reports one verdict over the agent link, or is ended by [`Self::finish`].
pub struct Readiness {
    cancel: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

/// Starts `probe` in the background; its verdict goes to the host as `Ready` or `ProbeFailed`.
pub fn spawn_readiness(agent: std::sync::Arc<sandy_fabric_local::agent::LinkAgent>, probe: HealthProbe) -> Readiness {
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let verdict = tokio::select! {
            verdict = probe_until_ready(&probe) => verdict,
            _ = cancelled => return,
        };
        // Past the select, the write is never cancelled: a torn frame would corrupt the exit report after it.
        let sent = match verdict {
            ProbeVerdict::Ready => agent.report_ready().await,
            ProbeVerdict::Failed { output } => agent.report_probe_failed(&output).await,
        };
        if let Err(e) = sent {
            eprintln!("sandy-agent: reporting the service readiness: {e}");
        }
    });
    Readiness { cancel, task }
}

/// How long [`Readiness::finish`] waits for a verdict write already in progress.
const VERDICT_WRITE_BUDGET: Duration = Duration::from_secs(10);

impl Readiness {
    /// Ends the probe and waits for a verdict write already in progress. Call before the exit report.
    ///
    /// # Errors
    /// The write did not finish within [`VERDICT_WRITE_BUDGET`] (a peer that stopped reading). The link may
    /// then hold a torn frame, so the caller must not write the exit report over it: the missing `Exit` frame
    /// already means "the agent failed" (INV-11), the same rule `serve()` applies to a stuck archive send.
    pub async fn finish(self) -> Result<(), String> {
        self.finish_within(VERDICT_WRITE_BUDGET).await
    }

    async fn finish_within(self, budget: Duration) -> Result<(), String> {
        let _ = self.cancel.send(());
        match tokio::time::timeout(budget, self.task).await {
            Ok(_) => Ok(()),
            Err(_) => Err(format!(
                "writing the service readiness verdict timed out after {budget:?}; the link may be mid-frame, so the \
                 job's exit cannot be safely reported over it"
            )),
        }
    }
}

/// Runs `probe` until it passes or its attempts run out. One manifest second is one real second.
pub async fn probe_until_ready(probe: &HealthProbe) -> ProbeVerdict {
    probe_loop(probe, Duration::from_secs(1)).await
}

/// [`probe_until_ready`] with `second` as the length of one manifest second, so tests need not wait in real
/// seconds.
async fn probe_loop(probe: &HealthProbe, second: Duration) -> ProbeVerdict {
    let timeout = second * probe.timeout_secs;
    let interval = second * probe.interval_secs;
    let mut last = String::new();
    for n in 1..=probe.max_attempts {
        match attempt(&probe.check, timeout).await {
            Ok(()) => return ProbeVerdict::Ready,
            Err(output) => last = output,
        }
        // No wait after the last attempt: the verdict is final.
        if n < probe.max_attempts {
            tokio::time::sleep(interval).await;
        }
    }
    ProbeVerdict::Failed { output: last }
}

/// One attempt of `check`, bounded by `timeout`. `Err` carries the failure's output.
async fn attempt(check: &ProbeCheck, timeout: Duration) -> Result<(), String> {
    match check {
        ProbeCheck::Tcp { port } => {
            let addr = ("127.0.0.1", *port);
            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(format!("connect to 127.0.0.1:{port}: {e}")),
                Err(_) => Err(format!("connect to 127.0.0.1:{port} timed out after {timeout:?}")),
            }
        }
        ProbeCheck::Command { argv } => {
            let (program, args) = argv.split_first().ok_or("the probe command is empty")?;
            tokio::time::timeout(timeout, run_command(program, args))
                .await
                .unwrap_or_else(|_| Err(format!("{program} timed out after {timeout:?}")))
        }
    }
}

/// Kills the probe command's whole process group when dropped (a timeout drops the future), and also after a
/// normal exit so a probe leaves no background process behind. The group id is the child's pid.
struct KillGroupOnDrop(rustix::process::Pid);

impl KillGroupOnDrop {
    fn new(pid: u32) -> Option<Self> {
        i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .map(Self)
    }
}

impl Drop for KillGroupOnDrop {
    fn drop(&mut self) {
        // ESRCH (the group is already gone) is the common case and fine.
        let _ = rustix::process::kill_process_group(self.0, rustix::process::Signal::KILL);
    }
}

/// Runs `program args` with stdout and stderr merged into the failure text (capped); `Ok` only on exit 0. The
/// child dies with this future, so a timeout kills it.
async fn run_command(program: &str, args: &[String]) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Its own process group, so a timeout or cancel kills the probe's children too (`sh -c 'sleep 30'`).
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    let _group = child.id().and_then(KillGroupOnDrop::new);
    let (Some(mut out), Some(mut err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(format!("could not capture the output of {program}"));
    };
    let read_capped = async |stream: &mut (dyn tokio::io::AsyncRead + Unpin + Send)| {
        let mut kept = Vec::new();
        // Read to EOF so the child never blocks on a full pipe, but keep only the head.
        let mut chunk = [0_u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = ATTEMPT_OUTPUT_CAP.saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
        }
        kept
    };
    let (stdout, stderr) = tokio::join!(read_capped(&mut out), read_capped(&mut err));
    let status = child.wait().await.map_err(|e| format!("waiting for {program}: {e}"))?;
    if status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&stderr));
    Err(format!("{program} failed ({status}): {text}"))
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;
    use sandy_guest_template::manifest::HealthProbe;
    use tokio::net::TcpListener;

    use super::*;

    /// 100 ms per manifest second: slow enough that a spawn fits in one timeout, fast enough for a test.
    const TICK: Duration = Duration::from_millis(100);

    fn probe(check: ProbeCheck, max_attempts: u32) -> HealthProbe {
        HealthProbe {
            check,
            interval_secs: 2,
            timeout_secs: 1,
            max_attempts,
        }
    }

    fn command(argv: &[&str]) -> ProbeCheck {
        ProbeCheck::Command {
            argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
        }
    }

    /// A free local port nothing listens on.
    async fn closed_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        Ok(listener.local_addr().context("addr")?.port())
    }

    /// #589 review: a spec that skipped the executor's decode must not run a probe `validate_service` rejects.
    /// Zero interval and timeout with `u32::MAX` attempts would be a tight loop in the guest.
    #[test]
    fn a_spec_that_fails_validation_is_refused_by_the_agent() {
        for bad in [
            r#"{"user":"x","probe":{"check":{"type":"tcp","port":1},"interval_secs":0,"timeout_secs":0,"max_attempts":4294967295}}"#,
            r#"{"user":"root","probe":{"check":{"type":"tcp","port":1}}}"#,
            r#"{"user":"dev","probe":{"check":{"type":"tcp","port":0}}}"#,
        ] {
            let err = parse(bad).expect_err("must be refused");
            assert!(err.contains("not a runnable service spec"), "{bad}: {err}");
        }
    }

    /// Adversarial (#589 review): a stuck verdict write must not hold the exit report forever. The caller
    /// gets an error (and sends no `Exit`) once the budget passes.
    #[tokio::test]
    async fn a_verdict_write_that_never_finishes_is_bounded() {
        let (cancel, _cancelled) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(std::future::pending::<()>());
        let readiness = Readiness { cancel, task };
        let err = readiness
            .finish_within(Duration::from_millis(50))
            .await
            .expect_err("a write that never ends must time out");
        assert!(err.contains("timed out"), "{err}");
    }

    /// Adversarial (#589 review): killing a timed-out probe kills its children too. The probe's background
    /// child would write `late` after 0.6 s; the probe times out after 0.1 s; nothing may be written.
    #[tokio::test]
    async fn a_timed_out_probe_leaves_no_background_process() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("temp dir")?;
        let marker = dir.path().join("late");
        let script = format!("(sleep 0.6; echo late > {}) & wait", marker.display());
        let verdict = probe_loop(&probe(command(&["sh", "-c", &script]), 1), TICK).await;
        assert!(matches!(verdict, ProbeVerdict::Failed { .. }), "{verdict:?}");
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(!marker.exists(), "the probe's background child outlived the timeout");
        Ok(())
    }

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\n# a comment\ntoor:x:0:0:also \
                          root:/root:/bin/sh\ndev:x:1000:100:dev:/home/dev:/bin/sh\nbroken:x:abc:100::/:/bin/sh\\
                          nshort:x\n";

    /// A named account resolves to its uid.
    #[test]
    fn a_named_account_resolves_to_its_uid() {
        assert_eq!(resolve_uid(PASSWD, "dev"), Ok(1000));
    }

    /// Adversarial (#589): the uid, not the name, decides. `toor` shares uid 0 with root and is refused, as is
    /// root itself, an unknown account and a malformed entry. A name that is only a prefix of another is not a hit.
    #[test]
    fn an_account_that_is_root_or_unknown_or_malformed_is_refused() {
        for user in ["toor", "root", "nobody", "broken", "short", "de", ""] {
            let err = resolve_uid(PASSWD, user).expect_err(user);
            assert!(!err.is_empty(), "{user}");
        }
        assert!(resolve_uid(PASSWD, "toor").expect_err("toor").contains("uid 0"));
        assert!(resolve_uid(PASSWD, "nobody").expect_err("nobody").contains("no such"));
    }

    /// The service argv is `runuser -u <user> -- <job...>`, the job's own arguments untouched.
    #[test]
    fn the_job_is_wrapped_to_run_as_the_service_user() {
        let job = vec!["t3".into(), "serve".into(), "--port".into(), "3773".into()];
        let wrapped: Vec<String> = as_user("dev", job)
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(wrapped, ["runuser", "-u", "dev", "--", "t3", "serve", "--port", "3773"]);
    }

    #[test]
    fn a_service_spec_parses_and_a_mangled_one_is_refused() -> anyhow::Result<()> {
        let spec =
            parse(r#"{"user":"dev","probe":{"check":{"type":"tcp","port":3773}}}"#).map_err(anyhow::Error::msg)?;
        assert_eq!(spec.user, "dev");
        for bad in [
            "",
            "{",
            r#"{"user":"dev"}"#,
            r#"{"user":"dev","probe":{"check":{"type":"tcp","port":1}},"x":1}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must be refused");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_tcp_probe_passes_once_the_port_accepts() -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let port = listener.local_addr().context("addr")?.port();
        let verdict = probe_loop(&probe(ProbeCheck::Tcp { port }, 3), TICK).await;
        assert_eq!(verdict, ProbeVerdict::Ready);
        Ok(())
    }

    /// Positive (#589): the service comes up late. The probe keeps trying and passes on a later attempt.
    #[tokio::test]
    async fn a_tcp_probe_keeps_trying_until_the_service_listens() -> anyhow::Result<()> {
        let port = closed_port().await?;
        let late = tokio::spawn(async move {
            tokio::time::sleep(TICK * 3).await;
            let listener = TcpListener::bind(("127.0.0.1", port)).await?;
            tokio::time::sleep(TICK * 20).await;
            drop(listener);
            anyhow::Ok(())
        });
        let verdict = probe_loop(&probe(ProbeCheck::Tcp { port }, 10), TICK).await;
        assert_eq!(verdict, ProbeVerdict::Ready);
        late.abort();
        Ok(())
    }

    /// Adversarial (#589): a probe that never passes fails after exactly `max_attempts`, with the connect
    /// error as its output.
    #[tokio::test]
    async fn a_tcp_probe_that_never_passes_fails_with_the_connect_error() -> anyhow::Result<()> {
        let port = closed_port().await?;
        let started = tokio::time::Instant::now();
        let verdict = probe_loop(&probe(ProbeCheck::Tcp { port }, 3), TICK).await;
        let ProbeVerdict::Failed { output } = verdict else {
            anyhow::bail!("expected a failure, got {verdict:?}");
        };
        assert!(output.contains(&format!("127.0.0.1:{port}")), "{output}");
        // 3 attempts, 2 waits of 2 manifest seconds between them; none after the last.
        let took = started.elapsed();
        assert!(took >= TICK * 4, "gave up after {took:?}, before the second wait");
        assert!(took < TICK * 9, "waited after the last attempt: {took:?}");
        Ok(())
    }

    #[tokio::test]
    async fn a_command_probe_passes_on_exit_zero() {
        let verdict = probe_loop(&probe(command(&["true"]), 2), TICK).await;
        assert_eq!(verdict, ProbeVerdict::Ready);
    }

    /// Adversarial (#589): a failing command's stdout and stderr and its status reach the failure output.
    #[tokio::test]
    async fn a_failing_command_probe_reports_its_output_and_status() -> anyhow::Result<()> {
        let verdict = probe_loop(
            &probe(command(&["sh", "-c", "echo to-out; echo to-err >&2; exit 7"]), 1),
            TICK,
        )
        .await;
        let ProbeVerdict::Failed { output } = verdict else {
            anyhow::bail!("expected a failure, got {verdict:?}");
        };
        for needle in ["to-out", "to-err", "7"] {
            assert!(output.contains(needle), "{needle:?} missing from {output:?}");
        }
        Ok(())
    }

    /// Adversarial (#589): an attempt that outlives its timeout is killed and counts as failed, so a hung
    /// probe command cannot hold the environment in Starting.
    #[tokio::test]
    async fn a_hung_command_probe_is_killed_at_its_timeout() -> anyhow::Result<()> {
        let started = tokio::time::Instant::now();
        let verdict = probe_loop(&probe(command(&["sleep", "30"]), 1), TICK).await;
        let ProbeVerdict::Failed { output } = verdict else {
            anyhow::bail!("expected a failure, got {verdict:?}");
        };
        assert!(output.contains("timed out"), "{output}");
        assert!(started.elapsed() < TICK * 8, "the hung command was not cut off");
        Ok(())
    }

    /// A program that does not exist is a failed attempt with the spawn error, not a panic or a hang.
    #[tokio::test]
    async fn a_missing_probe_program_is_a_failed_attempt() -> anyhow::Result<()> {
        let verdict = probe_loop(&probe(command(&["/nonexistent/sandy-probe"]), 1), TICK).await;
        let ProbeVerdict::Failed { output } = verdict else {
            anyhow::bail!("expected a failure, got {verdict:?}");
        };
        assert!(output.contains("/nonexistent/sandy-probe"), "{output}");
        Ok(())
    }

    /// Adversarial (#589): a chatty failing command cannot grow the output past the cap.
    #[tokio::test]
    async fn a_chatty_failing_probe_has_its_output_capped() -> anyhow::Result<()> {
        let verdict = probe_loop(
            &probe(
                command(&["sh", "-c", "head -c 200000 /dev/zero | tr '\\0' x; exit 1"]),
                1,
            ),
            TICK * 5,
        )
        .await;
        let ProbeVerdict::Failed { output } = verdict else {
            anyhow::bail!("expected a failure, got {verdict:?}");
        };
        assert!(output.len() <= ATTEMPT_OUTPUT_CAP + 64, "kept {} bytes", output.len());
        Ok(())
    }
}
