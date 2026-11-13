//! An interrupt that lands before the daemon has answered `Submit` still cancels the job (#483 review of the
//! `--wait` PR). The daemon here is a fake, so the test controls when the Submit reply arrives.

use std::{
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{
    CancelResponse, ControlRequest, ControlResponse, JobStatus, StatusResponse, SubmitResponse, control_request,
    control_response, read_frame, write_frame,
};
use tokio::net::UnixListener;

const TOKEN: &[u8] = &[7, 7, 7];

type Hold = Arc<Mutex<mpsc::Receiver<()>>>;

/// Accept connections for ever, one task each: the cancel arrives on a fresh connection while the first is open.
async fn serve(
    listener: Arc<UnixListener>,
    hold: Hold,
    cancelled_with: Arc<Mutex<Option<Vec<u8>>>>,
    status: Arc<Mutex<JobStatus>>,
    got_submit: mpsc::Sender<()>,
) {
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle(
            stream,
            Arc::clone(&hold),
            Arc::clone(&cancelled_with),
            Arc::clone(&status),
            got_submit.clone(),
        ));
    }
}

/// Answer Submit after `hold` is released, Cancel by recording its token, anything else as a status.
async fn handle(
    mut stream: tokio::net::UnixStream,
    hold: Hold,
    cancelled_with: Arc<Mutex<Option<Vec<u8>>>>,
    status: Arc<Mutex<JobStatus>>,
    got_submit: mpsc::Sender<()>,
) {
    {
        while let Ok(Some(request)) = read_frame::<ControlRequest>(&mut stream).await {
            let result = match request.op {
                Some(control_request::Op::Submit(_)) => {
                    let _ = got_submit.send(());
                    let _ =
                        tokio::task::block_in_place(|| hold.lock().map(|h| h.recv_timeout(Duration::from_secs(10))));
                    control_response::Result::Submit(SubmitResponse {
                        job_id: "job-1".to_owned(),
                        attach_token: TOKEN.to_vec(),
                    })
                }
                Some(control_request::Op::Cancel(cancel)) => {
                    if let Ok(mut slot) = cancelled_with.lock() {
                        *slot = cancel.attach_token;
                    }
                    if let Ok(mut s) = status.lock() {
                        *s = JobStatus::Cancelled;
                    }
                    control_response::Result::Cancel(CancelResponse {})
                }
                _ => {
                    let state = status.lock().map(|s| *s).unwrap_or(JobStatus::Running);
                    control_response::Result::Status(StatusResponse {
                        job_id: "job-1".to_owned(),
                        status: state.into(),
                        exit_code: None,
                        console_tail: String::new(),
                        result_envelope: None,
                    })
                }
            };
            let reply = ControlResponse {
                request_id: request.request_id,
                result: Some(result),
            };
            if write_frame(&mut stream, &reply).await.is_err() {
                break;
            }
        }
    }
}

/// SIGINT sent while the Submit is still unanswered cancels the job once the reply arrives, with the token it gave.
#[test]
fn an_interrupt_before_the_submit_reply_still_cancels_the_job() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let sock = tmp.path().join("sandyd.sock");
    let manifest = tmp.path().join("manifest.bin");
    std::fs::write(&manifest, b"opaque").context("write manifest")?;
    let cancelled_with = Arc::new(Mutex::new(None));
    let (release, hold) = mpsc::channel();
    let (got_submit, submitted) = mpsc::channel();
    let server = {
        let (cancelled_with, sock) = (Arc::clone(&cancelled_with), sock.clone());
        std::thread::spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .context("runtime")?;
            rt.block_on(async {
                let listener = Arc::new(UnixListener::bind(&sock).context("bind")?);
                let status = Arc::new(Mutex::new(JobStatus::Running));
                let first = tokio::spawn(serve(
                    Arc::clone(&listener),
                    Arc::new(Mutex::new(hold)),
                    Arc::clone(&cancelled_with),
                    Arc::clone(&status),
                    got_submit,
                ));
                tokio::time::sleep(Duration::from_secs(30)).await;
                first.abort();
                Ok(())
            })
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        anyhow::ensure!(Instant::now() < deadline, "the fake daemon never bound its socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut client = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &sock)
        .env("SANDY_HOME", tmp.path())
        .args([
            "daemon",
            "submit",
            manifest.to_str().context("manifest path is utf8")?,
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "--wait",
            "--wait-timeout",
            "20",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning sandy daemon submit --wait")?;
    submitted
        .recv_timeout(Duration::from_secs(10))
        .context("the daemon never saw the Submit")?;
    // The Submit is in flight and unanswered: interrupt now, then let the reply through.
    let killed = Command::new("kill")
        .args(["-INT", &client.id().to_string()])
        .status()
        .context("kill -INT")?;
    anyhow::ensure!(killed.success(), "kill -INT failed");
    std::thread::sleep(Duration::from_millis(300));
    let _ = release.send(());
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = client.try_wait().context("polling the client")? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = client.kill();
            anyhow::bail!("the client never exited after the interrupt");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let token = cancelled_with.lock().map(|t| t.clone()).unwrap_or_default();
    drop(server);
    assert_eq!(
        token.as_deref(),
        Some(TOKEN),
        "the job was not cancelled with its token ({status:?})"
    );
    assert_eq!(status.code(), Some(1), "an interrupted wait exits 1");
    Ok(())
}
