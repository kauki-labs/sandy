//! The top-level verbs `run`, `ls`, `status`, `wait`, `kill` and `gc` are daemon-backed (#483): each makes the control
//! call its `sandy daemon` twin makes, over `$SANDY_SOCK`. The daemon here is a fake that records every request.

use std::{
    process::{Command, Output},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{
    CancelResponse, ControlRequest, ControlResponse, IsolationClass, JobStatus, JobSummary, ListResponse,
    PruneResponse, StatusResponse, SubmitResponse, control_request, control_response, read_frame, write_frame,
};
use tokio::net::UnixListener;

type Seen = Arc<Mutex<Vec<control_request::Op>>>;

fn answer(op: &control_request::Op) -> control_response::Result {
    match op {
        control_request::Op::Submit(_) => control_response::Result::Submit(SubmitResponse {
            job_id: "job-1".to_owned(),
            attach_token: vec![1, 2, 3],
        }),
        control_request::Op::Cancel(_) => control_response::Result::Cancel(CancelResponse {}),
        control_request::Op::List(_) => control_response::Result::List(ListResponse {
            jobs: vec![JobSummary {
                job_id: "job-1".to_owned(),
                status: JobStatus::Succeeded.into(),
            }],
        }),
        control_request::Op::Prune(_) => control_response::Result::Prune(PruneResponse {
            evicted: vec!["job-0".to_owned()],
            swept_staging_dirs: Vec::new(),
        }),
        _ => control_response::Result::Status(StatusResponse {
            job_id: "job-1".to_owned(),
            status: JobStatus::Succeeded.into(),
            exit_code: Some(0),
            console_tail: String::new(),
            result_envelope: None,
        }),
    }
}

/// Run `sandy ARGS` against a fake daemon; return the process output and the requests the daemon saw, in order.
fn against_fake_daemon(args: &[&str]) -> anyhow::Result<(Output, Vec<control_request::Op>)> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let sock = tmp.path().join("sandyd.sock");
    let seen: Seen = Arc::default();
    let server = {
        let (sock, seen) = (sock.clone(), Arc::clone(&seen));
        std::thread::spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .context("runtime")?;
            rt.block_on(async {
                let listener = UnixListener::bind(&sock).context("bind")?;
                let serving = async {
                    while let Ok((mut stream, _)) = listener.accept().await {
                        let seen = Arc::clone(&seen);
                        tokio::spawn(async move {
                            while let Ok(Some(request)) = read_frame::<ControlRequest>(&mut stream).await {
                                let Some(op) = request.op else { break };
                                let result = answer(&op);
                                if let Ok(mut seen) = seen.lock() {
                                    seen.push(op);
                                }
                                let reply = ControlResponse {
                                    request_id: request.request_id,
                                    result: Some(result),
                                };
                                if write_frame(&mut stream, &reply).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                };
                let _ = tokio::time::timeout(Duration::from_secs(40), serving).await;
                Ok(())
            })
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        anyhow::ensure!(Instant::now() < deadline, "the fake daemon never bound its socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &sock)
        .env("SANDY_HOME", tmp.path())
        .args(args)
        .output()
        .context("running sandy")?;
    drop(server);
    let ops = seen.lock().map(|s| s.clone()).unwrap_or_default();
    Ok((output, ops))
}

fn text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// `run TEMPLATE -- CMD` submits one untrusted VM job as a `flake/v1` manifest, waits for it, and exits by its band.
#[test]
fn run_submits_an_untrusted_job_and_waits_for_it() -> anyhow::Result<()> {
    let (out, ops) = against_fake_daemon(&["run", "topologies.x86_64-linux.qemu", "--", "echo", "hi"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let Some(control_request::Op::Submit(submit)) = ops.first() else {
        anyhow::bail!("the first request was not a Submit: {ops:?}\n{}", text(&out));
    };
    assert_eq!(
        submit.required_isolation_class,
        i32::from(IsolationClass::Untrusted),
        "a template boots a VM, so the job is untrusted"
    );
    assert_eq!(
        submit.manifest_encoding,
        sandy_guest_template::manifest::MANIFEST_ENCODING_FLAKE_V1
    );
    assert!(
        ops.iter().any(|op| matches!(op, control_request::Op::Status(_))),
        "run waits by polling Status: {ops:?}"
    );
    Ok(())
}

/// `ls` lists the daemon's jobs.
#[test]
fn ls_lists_the_daemons_jobs() -> anyhow::Result<()> {
    let (out, ops) = against_fake_daemon(&["ls"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(matches!(ops.as_slice(), [control_request::Op::List(_)]), "{ops:?}");
    assert!(text(&out).contains("job-1"), "{}", text(&out));
    Ok(())
}

/// `status ID` asks the daemon for that job.
#[test]
fn status_asks_the_daemon_for_the_job() -> anyhow::Result<()> {
    let (out, ops) = against_fake_daemon(&["status", "job-1"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(ops.as_slice(), [control_request::Op::Status(s)] if s.job_id == "job-1"),
        "{ops:?}"
    );
    Ok(())
}

/// `wait ID` polls Status until the job is terminal and exits by its band.
#[test]
fn wait_polls_status_until_the_job_ends() -> anyhow::Result<()> {
    let (out, ops) = against_fake_daemon(&["wait", "job-1"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(ops.first(), Some(control_request::Op::Status(s)) if s.job_id == "job-1"),
        "{ops:?}"
    );
    Ok(())
}

/// `kill ID` cancels the job on the daemon.
#[test]
fn kill_cancels_the_job_on_the_daemon() -> anyhow::Result<()> {
    let (out, ops) = against_fake_daemon(&["kill", "job-1"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(ops.as_slice(), [control_request::Op::Cancel(c)] if c.job_id == "job-1"),
        "{ops:?}"
    );
    Ok(())
}

/// `gc --keep-last N` prunes the daemon's store, keeping the newest N.
#[test]
fn gc_prunes_the_daemons_store() -> anyhow::Result<()> {
    let (out, ops) = against_fake_daemon(&["gc", "--keep-last", "3"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(ops.as_slice(), [control_request::Op::Prune(p)] if p.keep_last == 3),
        "{ops:?}"
    );
    Ok(())
}
