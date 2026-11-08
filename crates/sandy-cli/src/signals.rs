//! Turn a termination signal into a cancel of the run (#687).
//!
//! `sandy run` owns a guest, a credential and an egress boundary. With the default action a `SIGTERM` (for example
//! `systemctl stop` on the unit that runs it) ends the process at once and leaves the job record `running` and the
//! credential unrevoked. [`cancel_on_termination`] catches `SIGTERM`, `SIGHUP` and `SIGINT` instead and cancels the
//! run's [`RunControl`]; the backend then tears the guest down and the supervisor's teardown revokes the credential
//! and writes the terminal record, the same path a timeout takes.
//!
//! On Linux a signal the process inherited as ignored (`nohup`, a backgrounded script job) stays ignored: the caller
//! chose that, and the children the run starts inherit it. macOS offers no safe way to read the mask (`ps` has no
//! such keyword and `sigaction` is `unsafe`), so there all three signals are handled.

use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

use sandy::RunControl;
use tokio::signal::unix::{Signal, SignalKind, signal};

/// Set once [`cancel_on_termination`] has installed its handlers in this process.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// What a run tells `sandy kill` in its liveness lockfile when [`cancels_on_sigterm`]: a SIGTERM makes it tear down.
pub const CANCELS_ON_SIGTERM: &str = "sigterm-cancels-the-run";

/// Whether this process turns a `SIGTERM` into a clean cancel (the handlers are installed). A run records this for
/// `sandy kill`, which signals only an owner that says so: one without the handler would die at once instead.
#[must_use]
pub fn cancels_on_sigterm() -> bool {
    INSTALLED.load(Ordering::SeqCst)
}

const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

/// Cancel `control` when the process gets `SIGTERM`, `SIGHUP` or `SIGINT`, except a signal it inherited as ignored.
/// Returns once the handlers are installed, so a signal sent after this returns is never lost to the default action.
///
/// A later signal is swallowed: the teardown in progress must finish (a second `SIGTERM` does not skip the revoke).
/// `SIGKILL` cannot be caught; the stale `running` record it leaves is the sweep's to find.
///
/// # Errors
/// The handlers or the thread that waits on them could not be set up.
pub fn cancel_on_termination(control: RunControl) -> io::Result<()> {
    let ignored = ignored_signals(std::process::id());
    let (ready, installed) = mpsc::channel();
    std::thread::Builder::new()
        .name("sandy-signals".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = ready.send(Err(e));
                    return;
                }
            };
            runtime.block_on(async move {
                let handlers = (
                    install(SIGTERM, SignalKind::terminate(), ignored),
                    install(SIGHUP, SignalKind::hangup(), ignored),
                    install(SIGINT, SignalKind::interrupt(), ignored),
                );
                let (mut term, mut hup, mut int) = match handlers {
                    (Ok(term), Ok(hup), Ok(int)) => (term, hup, int),
                    (Err(e), ..) | (_, Err(e), _) | (_, _, Err(e)) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                loop {
                    let name = tokio::select! {
                        () = next(&mut term) => "SIGTERM",
                        () = next(&mut hup) => "SIGHUP",
                        () = next(&mut int) => "SIGINT",
                    };
                    if control.is_cancelled() {
                        tracing::warn!(signal = name, "teardown is already running; signal ignored");
                    } else {
                        tracing::warn!(signal = name, "cancelling the run");
                        control.cancel();
                    }
                }
            });
        })?;
    installed
        .recv()
        .map_err(|_| io::Error::other("the signal thread ended before it installed its handlers"))??;
    INSTALLED.store(true, Ordering::SeqCst);
    Ok(())
}

/// A handler for `number`, or `None` when the process inherited it as ignored.
fn install(number: i32, kind: SignalKind, ignored: u64) -> io::Result<Option<Signal>> {
    if ignored & (1 << (number - 1)) != 0 {
        return Ok(None);
    }
    signal(kind).map(Some)
}

/// The next delivery of the signal, or never for one that is not handled.
async fn next(signal: &mut Option<Signal>) {
    match signal {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// The signals process `pid` ignores, as a mask with bit `n - 1` set for signal `n`, from `SigIgn` in
/// `/proc/<pid>/status`. Unknown (and every non-Linux host) reads as none ignored, so the run is cancelled rather
/// than left to the default action.
fn ignored_signals(pid: u32) -> u64 {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| parse_sigign(&status))
            .unwrap_or(0)
    } else {
        0
    }
}

/// The `SigIgn:` mask of a `/proc/<pid>/status` file.
fn parse_sigign(status: &str) -> Option<u64> {
    let line = status.lines().find_map(|l| l.strip_prefix("SigIgn:"))?;
    u64::from_str_radix(line.trim(), 16).ok()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use rustix::process::{Signal, getpid, kill_process};
    use sandy::RunControl;

    use super::cancel_on_termination;

    fn wait_cancelled(control: &RunControl) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if control.is_cancelled() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// Each signal runs in its own process under nextest, so a handler left installed cannot reach another test.
    fn cancels_on(signal: Signal) -> anyhow::Result<()> {
        let control = RunControl::with_timeout_secs(60);
        cancel_on_termination(control.clone())?;
        assert!(!control.is_cancelled());
        kill_process(getpid(), signal)?;
        assert!(wait_cancelled(&control), "{signal:?} must cancel the run");
        Ok(())
    }

    #[test]
    fn sigterm_cancels_the_run_and_the_process_lives() -> anyhow::Result<()> {
        cancels_on(Signal::TERM)
    }

    #[test]
    fn sighup_cancels_the_run() -> anyhow::Result<()> {
        cancels_on(Signal::HUP)
    }

    #[test]
    fn sigint_cancels_the_run() -> anyhow::Result<()> {
        cancels_on(Signal::INT)
    }

    #[test]
    fn a_status_file_names_the_ignored_signals() {
        let status = "Name:\tsandy\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000004001\nSigCgt:\t0\n";
        assert_eq!(super::parse_sigign(status), Some(0x4001));
        assert_eq!(super::parse_sigign("Name:\tx\n"), None);
    }

    /// `nohup` and a backgrounded script job start sandy with a signal ignored (#687): that choice must stay.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_signal_the_process_inherited_as_ignored_is_read_from_the_os() -> anyhow::Result<()> {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "trap '' HUP; sleep 30"])
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mask = loop {
            let mask = super::ignored_signals(child.id());
            if mask & 1 != 0 {
                break mask;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "the child never ignored SIGHUP: mask {mask:#x}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(mask & (1 << 14), 0, "SIGTERM is not ignored by that child");
        Ok(())
    }

    /// The child half of [`an_ignored_signal_stays_ignored_after_the_handlers_are_installed`]: it runs in a process
    /// that inherited SIGHUP as ignored, installs the handlers, and takes a SIGHUP.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_ignored_signal_stays_ignored_after_the_handlers_are_installed() -> anyhow::Result<()> {
        if std::env::var_os("SANDY_SIGNALS_IGNORED_CHILD").is_some() {
            let control = RunControl::with_timeout_secs(60);
            cancel_on_termination(control.clone())?;
            kill_process(getpid(), Signal::HUP)?;
            std::thread::sleep(Duration::from_millis(300));
            anyhow::ensure!(!control.is_cancelled(), "an inherited-ignored SIGHUP must stay ignored");
            return Ok(());
        }
        // `nohup` does this before it execs: SIGHUP is ignored when the program starts.
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(
                "trap '' HUP; exec \"$0\" --exact \
                 signals::tests::an_ignored_signal_stays_ignored_after_the_handlers_are_installed --nocapture",
            )
            .arg(std::env::current_exe()?)
            .env("SANDY_SIGNALS_IGNORED_CHILD", "1")
            .status()?;
        assert!(
            status.success(),
            "the child with SIGHUP ignored must not be cancelled by it: {status}"
        );
        Ok(())
    }

    #[test]
    fn a_second_signal_is_swallowed_and_the_process_lives() -> anyhow::Result<()> {
        let control = RunControl::with_timeout_secs(60);
        cancel_on_termination(control.clone())?;
        kill_process(getpid(), Signal::TERM)?;
        assert!(wait_cancelled(&control));
        // The default action would end this test process here.
        kill_process(getpid(), Signal::TERM)?;
        std::thread::sleep(Duration::from_millis(200));
        assert!(control.is_cancelled());
        Ok(())
    }
}
