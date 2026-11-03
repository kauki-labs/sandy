//! A service's readiness probe (#589).
//!
//! When the job is a declared service, the agent runs its [`HealthProbe`] inside the guest every
//! `interval_secs` until one attempt passes (`Ready`) or `max_attempts` attempts in a row fail
//! (`Failed`, with the last attempt's output). Readiness comes from this probe, never from console text.

use std::time::Duration;

use sandy_api::agent::SERVICE_ENV;
use sandy_guest_template::manifest::{HealthProbe, ProbeCheck, ServiceSpec};
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

fn parse(json: &str) -> Result<ServiceSpec, String> {
    serde_json::from_str(json).map_err(|e| format!("{SERVICE_ENV} is not a service spec: {e}"))
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

impl Readiness {
    /// Ends the probe and waits for a verdict write already in progress. Call before the exit report.
    pub async fn finish(self) {
        let _ = self.cancel.send(());
        let _ = self.task.await;
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

/// Runs `program args` with stdout and stderr merged into the failure text (capped); `Ok` only on exit 0. The
/// child dies with this future, so a timeout kills it.
async fn run_command(program: &str, args: &[String]) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("could not run {program}: {e}"))?;
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
