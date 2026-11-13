//! The top-level verbs `run`, `ls`, `status`, `wait`, `kill` and `gc` are daemon-backed (#483): each makes the control
//! call its `sandy daemon` twin makes, over `$SANDY_SOCK`, and exits by the same bands. The daemon here is a fake that
//! records every request and answers as scripted.

use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_control_proto::{
    CancelResponse, ControlError, ControlRequest, ControlResponse, IsolationClass, JobStatus, JobSummary, ListResponse,
    PruneResponse, StatusResponse, SubmitResponse, control_request, control_response, read_frame, write_frame,
};
use tokio::net::UnixListener;

/// How the fake daemon answers.
#[derive(Clone, Copy)]
struct Script {
    /// The state every Status reports.
    job: JobStatus,
    /// Refuse a Cancel that carries no attach token, as sandyd does (#540).
    refuse_tokenless_cancel: bool,
}

impl Script {
    const FAILING: Self = Self {
        job: JobStatus::Failed,
        refuse_tokenless_cancel: true,
    };
    const SUCCEEDING: Self = Self {
        job: JobStatus::Succeeded,
        refuse_tokenless_cancel: true,
    };
}

const TOKEN: &[u8] = &[1, 2, 3];

fn answer(script: Script, op: &control_request::Op) -> control_response::Result {
    match op {
        control_request::Op::Submit(_) => control_response::Result::Submit(SubmitResponse {
            job_id: "job-1".to_owned(),
            attach_token: TOKEN.to_vec(),
        }),
        control_request::Op::Cancel(cancel) if script.refuse_tokenless_cancel && cancel.attach_token.is_none() => {
            control_response::Result::Error(ControlError {
                message: "not authorized to cancel this job".to_owned(),
            })
        }
        control_request::Op::Cancel(_) => control_response::Result::Cancel(CancelResponse {}),
        control_request::Op::List(_) => control_response::Result::List(ListResponse {
            jobs: vec![JobSummary {
                job_id: "job-1".to_owned(),
                status: script.job.into(),
            }],
        }),
        control_request::Op::Prune(_) => control_response::Result::Prune(PruneResponse {
            evicted: vec!["job-0".to_owned()],
            swept_staging_dirs: Vec::new(),
        }),
        _ => control_response::Result::Status(StatusResponse {
            job_id: "job-1".to_owned(),
            status: script.job.into(),
            exit_code: Some(i32::from(script.job != JobStatus::Succeeded)),
            console_tail: String::new(),
            result_envelope: None,
        }),
    }
}

/// A fake sandyd on a socket in its own temp dir, which is also the `$SANDY_HOME` and `$TMPDIR` of every `sandy` run
/// against it.
struct Fake {
    dir: tempfile::TempDir,
    sock: PathBuf,
    seen: Arc<Mutex<Vec<control_request::Op>>>,
}

impl Fake {
    fn start(script: Script) -> anyhow::Result<Self> {
        let dir = tempfile::tempdir().context("temp dir")?;
        let sock = dir.path().join("sandyd.sock");
        let seen: Arc<Mutex<Vec<control_request::Op>>> = Arc::default();
        {
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
                                    let result = answer(script, &op);
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
                    // Bounded: the thread must not outlive a hung test for long.
                    let _ = tokio::time::timeout(Duration::from_secs(60), serving).await;
                    Ok(())
                })
            });
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while !sock.exists() {
            anyhow::ensure!(Instant::now() < deadline, "the fake daemon never bound its socket");
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(Self { dir, sock, seen })
    }

    /// Run `sandy ARGS` against this daemon.
    fn sandy(&self, args: &[&str]) -> anyhow::Result<Output> {
        sandy_at(self.dir.path(), &self.sock, args)
    }

    fn ops(&self) -> Vec<control_request::Op> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

fn sandy_at(home: &std::path::Path, sock: &std::path::Path, args: &[&str]) -> anyhow::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", sock)
        .env("SANDY_HOME", home)
        // The attach tokens `run` saves live under the staging base in $TMPDIR: keep them in this test's own dir.
        .env("TMPDIR", home)
        .args(args)
        .output()
        .context("running sandy")
}

/// Run `sandy ARGS` with no daemon behind `$SANDY_SOCK`.
fn sandy_without_daemon(args: &[&str]) -> anyhow::Result<(Output, PathBuf)> {
    let home = tempfile::tempdir().context("temp dir")?;
    let sock = home.path().join("no-daemon.sock");
    let output = sandy_at(home.path(), &sock, args)?;
    Ok((output, sock))
}

fn text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const RUN: &[&str] = &["run", "topologies.x86_64-linux.qemu", "--", "echo", "hi"];

/// `run TEMPLATE -- CMD` submits one untrusted VM job as a `flake/v1` manifest, waits for it, and exits by its band.
#[test]
fn run_submits_an_untrusted_job_and_waits_for_it() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let out = fake.sandy(RUN)?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let ops = fake.ops();
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

/// A job that ends failed makes `run` exit 1, the task-failure band.
#[test]
fn run_of_a_failed_job_exits_1() -> anyhow::Result<()> {
    let fake = Fake::start(Script::FAILING)?;
    let out = fake.sandy(RUN)?;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    Ok(())
}

/// With no sandyd behind the socket `run` is an infrastructure fault naming the socket.
#[test]
fn run_without_a_daemon_exits_3_naming_the_socket() -> anyhow::Result<()> {
    let (out, sock) = sandy_without_daemon(RUN)?;
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert!(
        text(&out).contains(&format!("could not connect to sandyd at {}", sock.display())),
        "{}",
        text(&out)
    );
    Ok(())
}

/// A positional that names an existing file is a forgotten manifest, not a template: `run` refuses it (exit 2) and
/// sends nothing, so a raw manifest can never ride `run`'s untrusted class.
#[test]
fn run_refuses_a_file_path_as_the_template() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let file = fake.dir.path().join("manifest.json");
    std::fs::write(&file, b"{}").context("write file")?;
    let out = fake.sandy(&["run", file.to_str().context("utf8 path")?])?;
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(fake.ops().is_empty(), "nothing is sent: {:?}", fake.ops());
    Ok(())
}

/// `ls` lists the daemon's jobs.
#[test]
fn ls_lists_the_daemons_jobs() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let out = fake.sandy(&["ls"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(fake.ops().as_slice(), [control_request::Op::List(_)]),
        "{:?}",
        fake.ops()
    );
    assert!(text(&out).contains("job-1"), "{}", text(&out));
    Ok(())
}

/// `status ID` asks the daemon for that job.
#[test]
fn status_asks_the_daemon_for_the_job() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let out = fake.sandy(&["status", "job-1"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(fake.ops().as_slice(), [control_request::Op::Status(s)] if s.job_id == "job-1"),
        "{:?}",
        fake.ops()
    );
    Ok(())
}

/// `wait ID` polls Status until the job is terminal and exits by its band.
#[test]
fn wait_polls_status_until_the_job_ends() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let out = fake.sandy(&["wait", "job-1"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(fake.ops().first(), Some(control_request::Op::Status(s)) if s.job_id == "job-1"),
        "{:?}",
        fake.ops()
    );
    Ok(())
}

/// `wait` on a job that ended failed exits 1, and on one that was cancelled too.
#[test]
fn wait_on_a_failed_or_cancelled_job_exits_1() -> anyhow::Result<()> {
    for job in [JobStatus::Failed, JobStatus::Cancelled] {
        let fake = Fake::start(Script {
            job,
            refuse_tokenless_cancel: true,
        })?;
        let out = fake.sandy(&["wait", "job-1"])?;
        assert_eq!(out.status.code(), Some(1), "{job:?}: {}", text(&out));
    }
    Ok(())
}

/// `wait`, like `run`, with no sandyd is an infrastructure fault.
#[test]
fn wait_without_a_daemon_exits_3() -> anyhow::Result<()> {
    let (out, _) = sandy_without_daemon(&["wait", "job-1"])?;
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    Ok(())
}

/// `kill ID` cancels with the attach token the submitting `run` saved.
#[test]
fn kill_cancels_with_the_token_run_saved() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    assert_eq!(fake.sandy(RUN)?.status.code(), Some(0));
    let out = fake.sandy(&["kill", "job-1"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let ops = fake.ops();
    let Some(control_request::Op::Cancel(cancel)) = ops.last() else {
        anyhow::bail!("the last request was not a Cancel: {ops:?}");
    };
    assert_eq!(cancel.job_id, "job-1");
    assert_eq!(
        cancel.attach_token.as_deref(),
        Some(TOKEN),
        "the saved token rides the Cancel"
    );
    Ok(())
}

/// With no saved token the daemon refuses the cancel; `kill` exits 2 and says why, instead of a bare refusal.
#[test]
fn kill_without_a_saved_token_is_refused_and_says_why() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let out = fake.sandy(&["kill", "job-9"])?;
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no attach token is saved on this host"), "{stderr}");
    assert!(
        !stderr.contains("job-9"),
        "the refusal must not echo the job id (#540): {stderr}"
    );
    assert!(stderr.contains("not authorized to cancel"), "{stderr}");
    Ok(())
}

/// `kill` with no sandyd is an infrastructure fault.
#[test]
fn kill_without_a_daemon_exits_3() -> anyhow::Result<()> {
    let (out, _) = sandy_without_daemon(&["kill", "job-1"])?;
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    Ok(())
}

/// `gc --keep-last N` prunes the daemon's store, keeping the newest N.
#[test]
fn gc_prunes_the_daemons_store() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let out = fake.sandy(&["gc", "--keep-last", "3"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        matches!(fake.ops().as_slice(), [control_request::Op::Prune(p)] if p.keep_last == 3),
        "{:?}",
        fake.ops()
    );
    Ok(())
}

/// `-o json` is global: it may precede the verb, and `ls` then prints the daemon's jobs as JSON.
#[test]
fn the_output_flag_may_precede_the_verb() -> anyhow::Result<()> {
    let fake = Fake::start(Script::SUCCEEDING)?;
    let out = fake.sandy(&["--output", "json", "ls"])?;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stdout = String::from_utf8(out.stdout).context("stdout utf8")?;
    serde_json::from_str::<serde_json::Value>(stdout.trim()).context("stdout must be valid JSON")?;
    Ok(())
}
