//! A service's readiness probe (#589).
//!
//! When the job is a declared service, the agent runs its [`HealthProbe`] inside the guest every
//! `interval_secs` until one attempt passes (`Ready`) or `max_attempts` attempts in a row fail
//! (`Failed`, with the last attempt's output). Readiness comes from this probe, never from console text.

use std::time::Duration;

use sandy_api::agent::SERVICE_ENV;
use sandy_guest_template::manifest::{HealthProbe, ProbeCheck, RestartPolicy, ServiceSpec, validate_service_spec};
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
    if spec.restart != RestartPolicy::Never {
        return Err(format!(
            "{SERVICE_ENV}: restart policy {:?} is not implemented; refused rather than ignored",
            spec.restart
        ));
    }
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
/// The group database, read for the groups that mean root.
pub const GROUP_PATH: &str = "/etc/group";

/// Refuses an account that is root by another name: `user` must exist in `passwd` (the text of `/etc/passwd`),
/// resolve to a uid and a primary gid other than 0, and not be a member of a group with gid 0 or of `wheel`
/// (the text of `/etc/group`).
///
/// The manifest names an account and only its shape is checked at decode: another account can share uid 0
/// (`toor`), have gid 0, or sit in `wheel` (passwordless sudo on many images). The guest is where the account
/// database is, so the check is here.
///
/// # Errors
/// `user` is absent, its entry is malformed, or it is root by uid, primary gid or group membership.
pub fn check_account(passwd: &str, group: &str, user: &str) -> Result<(), String> {
    let entry = passwd
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .find(|line| line.split(':').next() == Some(user))
        .ok_or_else(|| format!("no such account {user:?} in {PASSWD_PATH}"))?;
    let id = |index: usize, what: &str| {
        entry
            .split(':')
            .nth(index)
            .and_then(|field| field.parse::<u32>().ok())
            .ok_or_else(|| format!("the {PASSWD_PATH} entry for {user:?} has no numeric {what}"))
    };
    if id(2, "uid")? == 0 {
        return Err(format!("account {user:?} has uid 0: a service must not run as root"));
    }
    if id(3, "gid")? == 0 {
        return Err(format!(
            "account {user:?} has primary gid 0: a service must not run as root"
        ));
    }
    for line in group.lines().filter(|line| !line.trim_start().starts_with('#')) {
        let mut fields = line.split(':');
        let (name, gid) = (fields.next().unwrap_or(""), fields.nth(1).unwrap_or(""));
        let members = fields.next().unwrap_or("");
        if (gid == "0" || name == "wheel" || name == "root") && members.split(',').any(|member| member == user) {
            return Err(format!(
                "account {user:?} is a member of group {name:?}: a service must not run as root"
            ));
        }
    }
    Ok(())
}

/// `job` run as `user`, with no way back up: `setpriv --no-new-privs -- runuser -u <user> -- env -u SANDY_SERVICE
/// -u TMUX <job>`. `no_new_privs` makes setuid wrappers (`sudo`) useless to the service, `runuser` drops the
/// uid and gids and sets HOME, and the two variables the agent's environment holds are removed (the probe's
/// own argv in `SANDY_SERVICE`, and the tmux socket of root's session). The agent stays root; only the
/// service drops privilege.
#[must_use]
pub fn as_user(user: &str, job: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = [
        "setpriv",
        "--no-new-privs",
        "--",
        "runuser",
        "-u",
        user,
        "--",
        "env",
        "-u",
        SERVICE_ENV,
        "-u",
        "TMUX",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    argv.extend(job);
    argv
}

/// The account a service runs as, checked: `Some(user)` when the agent is root (in a guest) and the account
/// passes [`check_account`], `None` when the agent is not root (the process backend on a host: no privilege to
/// drop, so the job runs as the agent's own user, never with more than declared).
///
/// # Errors
/// The agent is root and the account is refused, or the account databases cannot be read.
pub fn service_account(user: &str) -> Result<Option<String>, String> {
    if !rustix::process::geteuid().is_root() {
        return Ok(None);
    }
    let passwd = std::fs::read_to_string(PASSWD_PATH).map_err(|e| format!("reading {PASSWD_PATH}: {e}"))?;
    let group = std::fs::read_to_string(GROUP_PATH).map_err(|e| format!("reading {GROUP_PATH}: {e}"))?;
    check_account(&passwd, &group, user)?;
    Ok(Some(user.to_owned()))
}

/// The running readiness probe: reports one verdict over the agent link, or is ended by [`Self::finish`].
pub struct Readiness {
    cancel: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

/// Starts `probe` in the background; its verdict goes to the host as `Ready` or `ProbeFailed`.
pub fn spawn_readiness(
    agent: std::sync::Arc<sandy_fabric_local::agent::LinkAgent>,
    probe: HealthProbe,
    user: Option<String>,
) -> Readiness {
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let verdict = tokio::select! {
            verdict = probe_loop_as(&probe, Duration::from_secs(1), user.as_deref()) => verdict,
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

/// Runs `probe` until it passes or its attempts run out, with `second` as the length of one manifest second so
/// tests need not wait in real seconds. A command probe runs as `user` when one is given (the service's own
/// account), so a service that can influence the probe's program cannot make the root agent run it.
async fn probe_loop_as(probe: &HealthProbe, second: Duration, user: Option<&str>) -> ProbeVerdict {
    let timeout = second * probe.timeout_secs;
    let interval = second * probe.interval_secs;
    let mut last = String::new();
    for n in 1..=probe.max_attempts {
        let started = tokio::time::Instant::now();
        match attempt(&probe.check, timeout, user).await {
            Ok(()) => return ProbeVerdict::Ready,
            Err(output) => last = output,
        }
        // No wait after the last attempt: the verdict is final. The wait is the rest of the interval, so a
        // slow attempt does not stretch the budget past `interval_secs * max_attempts`.
        if n < probe.max_attempts {
            tokio::time::sleep(interval.saturating_sub(started.elapsed())).await;
        }
    }
    ProbeVerdict::Failed { output: last }
}

/// [`probe_loop_as`] as the agent's own user.
#[cfg(test)]
async fn probe_loop(probe: &HealthProbe, second: Duration) -> ProbeVerdict {
    probe_loop_as(probe, second, None).await
}

/// One attempt of `check`, bounded by `timeout`. `Err` carries the failure's output.
async fn attempt(check: &ProbeCheck, timeout: Duration, user: Option<&str>) -> Result<(), String> {
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
            let argv = probe_argv(user, argv);
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

/// The argv a command probe runs: as `user` through [`as_user`] when one is given.
fn probe_argv(user: Option<&str>, argv: &[String]) -> Vec<String> {
    match user {
        Some(user) => as_user(user, argv.iter().map(Into::into).collect())
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
        None => argv.to_vec(),
    }
}

/// How long the pipes get to drain after the probe command has exited and its process group was killed.
const PIPE_DRAIN: Duration = Duration::from_millis(500);

/// A command's captured output so far, shared with the task that reads it.
type SharedOutput = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

/// Reads `stream` to EOF into `kept`, keeping only the first [`ATTEMPT_OUTPUT_CAP`] bytes. It reads on past the
/// cap so the child never blocks on a full pipe.
async fn drain_capped(mut stream: impl tokio::io::AsyncRead + Unpin, kept: SharedOutput) {
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let mut kept = kept.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let room = ATTEMPT_OUTPUT_CAP.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
}

/// Runs `program args`; `Ok` only on exit 0. The attempt is decided by the exit status, never by the pipes
/// closing: a probe that exits 0 but leaves a background child holding stdout open is ready, and its process
/// group is killed so the child does not outlive the attempt. On failure the text is stderr first, then
/// stdout, so a long stdout cannot push the diagnostic out of the 4096 bytes the verdict keeps. The child dies
/// with this future, so a timeout kills it too.
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
    let group = child.id().and_then(KillGroupOnDrop::new);
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(format!("could not capture the output of {program}"));
    };
    let (stdout, stderr) = (SharedOutput::default(), SharedOutput::default());
    let mut out_task = tokio::spawn(drain_capped(out, std::sync::Arc::clone(&stdout)));
    let mut err_task = tokio::spawn(drain_capped(err, std::sync::Arc::clone(&stderr)));

    let status = child.wait().await.map_err(|e| format!("waiting for {program}: {e}"))?;
    // The command is done: end its group now so a background child cannot hold the pipes, then take what was
    // written, bounded.
    drop(group);
    let _ = tokio::time::timeout(PIPE_DRAIN, async {
        let _ = tokio::join!(&mut out_task, &mut err_task);
    })
    .await;
    out_task.abort();
    err_task.abort();
    if status.success() {
        return Ok(());
    }
    let taken = |buffer: &SharedOutput| buffer.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    let mut text = String::from_utf8_lossy(&taken(&stderr)).into_owned();
    text.push_str(&String::from_utf8_lossy(&taken(&stdout)));
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
                          root:/root:/bin/sh\ndev:x:1000:100:dev:/home/dev:/bin/sh\ngid0:x:1001:0:primary gid \
                          0:/home/gid0:/bin/sh\nadmin:x:1002:100:admin:/home/admin:/bin/sh\nrooty:x:1003:100:in the \
                          root group:/home/rooty:/bin/sh\nbroken:x:abc:100::/:/bin/sh\nnogid:x:1004::/:/bin/sh\nshort:\
                          x\n";

    const GROUP: &str = "root:x:0:rooty\nusers:x:100:dev,admin\nwheel:x:10:admin\n";

    /// A plain account passes.
    #[test]
    fn a_plain_account_is_accepted() {
        assert_eq!(check_account(PASSWD, GROUP, "dev"), Ok(()));
    }

    /// Adversarial (#589): the ids and groups decide, not the name. `toor` shares uid 0, `gid0` has primary
    /// gid 0, `admin` is in `wheel`, `rooty` is in the gid-0 group; an unknown account, a malformed entry and a
    /// name that is only a prefix of another are refused too.
    #[test]
    fn an_account_that_is_root_by_another_name_or_unknown_is_refused() {
        for (user, reason) in [
            ("toor", "uid 0"),
            ("root", "uid 0"),
            ("gid0", "primary gid 0"),
            ("admin", "wheel"),
            ("rooty", "root"),
            ("nobody", "no such"),
            ("broken", "uid"),
            ("nogid", "gid"),
            ("short", "uid"),
            ("de", "no such"),
            ("", "no such"),
        ] {
            let err = check_account(PASSWD, GROUP, user).expect_err(user);
            assert!(err.contains(reason), "{user}: {err}");
        }
    }

    /// The service argv drops privilege with no way back: no_new_privs first, then runuser, then the two
    /// variables that must not reach the service, then the job with its arguments untouched.
    #[test]
    fn the_job_runs_as_the_service_user_with_no_new_privs_and_a_clean_env() {
        let job = vec!["t3".into(), "serve".into(), "--port".into(), "3773".into()];
        let wrapped: Vec<String> = as_user("dev", job)
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            wrapped,
            [
                "setpriv",
                "--no-new-privs",
                "--",
                "runuser",
                "-u",
                "dev",
                "--",
                "env",
                "-u",
                "SANDY_SERVICE",
                "-u",
                "TMUX",
                "t3",
                "serve",
                "--port",
                "3773"
            ]
        );
    }

    /// #589 review: a command probe runs as the service user (so a service that can influence the probe's
    /// program cannot make the root agent run it); with no user it runs as given.
    #[test]
    fn a_command_probe_runs_as_the_service_user_when_there_is_one() {
        let argv = vec!["sandy-t3-ready".to_owned(), "3773".to_owned()];
        assert_eq!(probe_argv(None, &argv), argv);
        let wrapped = probe_argv(Some("t3"), &argv);
        assert_eq!(wrapped[..6], ["setpriv", "--no-new-privs", "--", "runuser", "-u", "t3"]);
        assert_eq!(wrapped[wrapped.len() - 2..], argv);
    }

    /// A restart policy is accepted by the manifest but not implemented: the agent refuses it instead of
    /// silently running a service that is never restarted.
    #[test]
    fn a_restart_policy_the_agent_cannot_honour_is_refused() {
        for policy in ["on_failure", "always"] {
            let json =
                format!(r#"{{"user":"dev","probe":{{"check":{{"type":"tcp","port":1}}}},"restart":"{policy}"}}"#);
            let err = parse(&json).expect_err(policy);
            assert!(err.contains("restart"), "{policy}: {err}");
        }
        assert!(parse(r#"{"user":"dev","probe":{"check":{"type":"tcp","port":1}},"restart":"never"}"#).is_ok());
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

    /// CodeRabbit on #632: a command probe is decided by its exit status, not by its pipes closing. A probe
    /// that exits 0 but leaves a background child holding stdout open is Ready, not a timeout, and the child
    /// does not outlive the attempt.
    #[tokio::test]
    async fn a_probe_that_exits_zero_is_ready_even_with_a_background_child_on_its_pipes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("temp dir")?;
        let marker = dir.path().join("late");
        let script = format!("(sleep 0.6; echo late > {}) & exit 0", marker.display());
        let started = tokio::time::Instant::now();
        let verdict = probe_loop(&probe(command(&["sh", "-c", &script]), 1), TICK).await;
        assert_eq!(verdict, ProbeVerdict::Ready);
        assert!(
            started.elapsed() < TICK * 8,
            "the verdict waited for the pipes: {:?}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(!marker.exists(), "the probe's background child outlived the attempt");
        Ok(())
    }

    /// CodeRabbit on #632: the wait between attempts is the rest of the interval, so a slow attempt does not
    /// stretch the budget (`interval_secs * max_attempts`) to twice its length. Three 0.3 s failures with a
    /// 0.4 s interval take about 1.1 s (not 1.7 s).
    #[tokio::test]
    async fn a_slow_attempt_shortens_the_wait_to_the_end_of_its_interval() {
        let slow = HealthProbe {
            check: command(&["sh", "-c", "sleep 0.3; exit 1"]),
            interval_secs: 2,
            timeout_secs: 2,
            max_attempts: 3,
        };
        let started = tokio::time::Instant::now();
        let verdict = probe_loop(&slow, Duration::from_millis(200)).await;
        assert!(matches!(verdict, ProbeVerdict::Failed { .. }), "{verdict:?}");
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(1_450),
            "the waits did not shrink: {took:?}"
        );
    }

    /// CodeRabbit on #632: the verdict keeps a failing probe's stderr when stdout is long, since the relay
    /// keeps only the first 4096 bytes.
    #[tokio::test]
    async fn a_failing_probe_keeps_its_stderr_ahead_of_a_long_stdout() -> anyhow::Result<()> {
        let script = "head -c 5000 /dev/zero | tr '\\0' x; echo the-diagnostic >&2; exit 1";
        let verdict = probe_loop(&probe(command(&["sh", "-c", script]), 1), TICK * 5).await;
        let ProbeVerdict::Failed { output } = verdict else {
            anyhow::bail!("expected a failure, got {verdict:?}");
        };
        let head: String = output.chars().take(4096).collect();
        assert!(
            head.contains("the-diagnostic"),
            "stderr fell off the verdict: {} bytes",
            output.len()
        );
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
