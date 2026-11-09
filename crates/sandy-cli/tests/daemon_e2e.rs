//! End-to-end: the real `sandy` binary driving the real `sandyd` binary over
//! a live Unix socket (#205, B4). No fakes on either side — this is the
//! acceptance floor for the daemon subcommands, the same bar sandy-d1's B1
//! verification held `sandyd` itself to.

use std::{
    io::{BufRead as _, Write as _},
    os::unix::fs::PermissionsExt as _,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;

/// A running `sandyd`, killed on drop so a failing assertion never leaves an
/// orphan daemon holding the test's socket/db files open.
struct Daemon {
    child: Child,
    sock: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `sandyd`'s binary path: `$SANDYD_BIN` if set, else built on demand.
///
/// `CARGO_BIN_EXE_<name>` only resolves for binaries of the package that owns
/// the integration test (`sandy-cli`, for `CARGO_BIN_EXE_sandy`) — it does not
/// reach a sibling workspace member's binary. The hermetic nix e2e check
/// (`testsDaemonE2e`, #233) builds `sandyd` as part of the whole-workspace
/// `sandy` package and points `$SANDYD_BIN` at it directly, since shelling out
/// to `cargo build` mid-test cannot complete inside that sandbox (no network,
/// no target-dir lock to share with the outer build). Outside that check
/// (the dev shell, a package-scoped `cargo nextest run -p sandy-cli`) the var
/// is unset, so `sandyd` is built explicitly here instead (a no-op if already
/// up to date) and located next to `sandy`'s own binary, in the same
/// target/profile directory `cargo` used for this test run.
fn sandyd_bin() -> anyhow::Result<std::path::PathBuf> {
    resolve_sandyd_bin(std::env::var_os("SANDYD_BIN"))
}

/// The `$SANDYD_BIN`-or-build-it-yourself logic, taking the env var's value as
/// a plain argument (rather than reading it internally) so it can be tested
/// without mutating real process environment state — `std::env::set_var` in a
/// `#[test]` would race every other test in this binary that also resolves
/// `sandyd`'s path concurrently.
fn resolve_sandyd_bin(sandyd_bin_env: Option<std::ffi::OsString>) -> anyhow::Result<std::path::PathBuf> {
    if let Some(path) = sandyd_bin_env {
        return Ok(std::path::PathBuf::from(path));
    }

    let sandy_bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sandy"));
    let target_profile_dir = sandy_bin
        .parent()
        .context("sandy's own binary path has no parent directory")?
        .to_path_buf();
    let is_release = target_profile_dir.file_name().and_then(|n| n.to_str()) == Some("release");

    let workspace_manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let mut build = Command::new(env!("CARGO"));
    build.args([
        "build",
        "--manifest-path",
        workspace_manifest,
        "-p",
        "sandyd",
        "--bin",
        "sandyd",
    ]);
    if is_release {
        build.arg("--release");
    }
    // `cargo test --target <triple>` nests the profile dir one level deeper
    // (`target/<triple>/<profile>/`, not `target/<profile>/`); without passing
    // the same `--target` here, this build lands in the untriple'd directory
    // and `target_profile_dir.join("sandyd")` below finds a stale or missing
    // binary. Detect it from the path segment right after `target/`.
    if let Some(triple) = target_triple(&target_profile_dir) {
        build.args(["--target", &triple]);
    }
    let status = build.status().context("running cargo build -p sandyd")?;
    anyhow::ensure!(status.success(), "cargo build -p sandyd --bin sandyd failed");

    Ok(target_profile_dir.join("sandyd"))
}

/// The target triple `cargo test` built under, if an explicit `--target` was
/// passed: the path segment immediately after `target/` when it isn't the
/// profile name itself (`debug`/`release`).
fn target_triple(target_profile_dir: &std::path::Path) -> Option<String> {
    let components: Vec<_> = target_profile_dir.components().collect();
    let target_pos = components.iter().position(|c| c.as_os_str() == "target")?;
    let after_target = components.get(target_pos + 1)?.as_os_str().to_str()?;
    (after_target != "debug" && after_target != "release").then(|| after_target.to_owned())
}

/// Spawn the real `sandyd` binary against a fresh temp socket/db, waiting
/// (bounded, polled) until it actually accepts a connection. A fixed sleep
/// would be either flaky under load or needlessly slow; polling for the real
/// readiness signal (the socket answering) is neither.
fn spawn_daemon(tmp: &std::path::Path) -> anyhow::Result<Daemon> {
    let sock = tmp.join("sandyd.sock");
    let db = tmp.join("sandyd.db");
    let child = Command::new(sandyd_bin()?)
        .env("SANDY_SOCK", &sock)
        .env("SANDY_DB", &db)
        .spawn()
        .context("spawning sandyd")?;
    // Construct the guard immediately: a bail! below now drops `daemon`,
    // killing and waiting on the child, instead of leaking it on a timeout.
    let daemon = Daemon { child, sock };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::os::unix::net::UnixStream::connect(&daemon.sock).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            anyhow::bail!("sandyd never accepted a connection on {}", daemon.sock.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    Ok(daemon)
}

/// Run the real `sandy` binary against `daemon`'s socket.
fn sandy(daemon: &Daemon, args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &daemon.sock)
        .args(args)
        .output()
        .context("running sandy")
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Write `contents` to `path` as a `0600` file: `sandy daemon submit
/// --cap-file` refuses a group/world-readable one (INV-1), so every cap file
/// these tests create must already be private, same as a real cap saved to
/// disk by an operator would need to be.
fn write_cap_file(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents).context("write cap file")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).context("chmod cap file")?;
    Ok(())
}

#[test]
fn submit_status_list_and_cancel_round_trip_through_a_live_sandyd() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let manifest = tmp.path().join("manifest.bin");
    std::fs::write(&manifest, b"opaque-until-b3-defines-jobmanifest").context("write manifest")?;

    let submit = sandy(
        &daemon,
        &[
            "daemon",
            "submit",
            manifest.to_str().context("manifest path is utf8")?,
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "-o",
            "json",
        ],
    )?;
    assert_eq!(submit.status.code(), Some(0), "submit stderr: {}", stderr_of(&submit));
    let submit_json: serde_json::Value = serde_json::from_slice(&submit.stdout).context("parse submit json")?;
    let job_id = submit_json["job_id"]
        .as_str()
        .context("submit json must carry a job_id")?
        .to_string();
    assert!(!job_id.is_empty());

    let status = sandy(&daemon, &["daemon", "status", &job_id, "-o", "json"])?;
    assert_eq!(status.status.code(), Some(0), "status stderr: {}", stderr_of(&status));
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).context("parse status json")?;
    assert_eq!(status_json["job_id"].as_str(), Some(job_id.as_str()));
    assert_eq!(status_json["status"].as_str(), Some("JOB_STATUS_PENDING"));

    let list = sandy(&daemon, &["daemon", "list", "-o", "json"])?;
    assert_eq!(list.status.code(), Some(0), "list stderr: {}", stderr_of(&list));
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).context("parse list json")?;
    let jobs = list_json.as_array().context("list json must be an array")?;
    assert!(
        jobs.iter().any(|j| j["job_id"].as_str() == Some(job_id.as_str())),
        "the submitted job must appear in list: {list_json}"
    );

    let cancel = sandy(&daemon, &["daemon", "cancel", &job_id])?;
    assert_eq!(cancel.status.code(), Some(0), "cancel stderr: {}", stderr_of(&cancel));
    assert!(
        String::from_utf8_lossy(&cancel.stdout).contains(&job_id),
        "cancel plain output must name the job: {}",
        String::from_utf8_lossy(&cancel.stdout)
    );

    let status_after_cancel = sandy(&daemon, &["daemon", "status", &job_id, "-o", "json"])?;
    assert_eq!(status_after_cancel.status.code(), Some(0));
    let after_json: serde_json::Value =
        serde_json::from_slice(&status_after_cancel.stdout).context("parse status json")?;
    assert_eq!(after_json["status"].as_str(), Some("JOB_STATUS_CANCELLED"));

    Ok(())
}

#[test]
fn submit_reads_the_manifest_from_stdin_when_the_path_is_a_dash() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &daemon.sock)
        .args([
            "daemon",
            "submit",
            "-",
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "-o",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning sandy daemon submit -")?;
    child
        .stdin
        .take()
        .context("child stdin")?
        .write_all(b"manifest-bytes-from-stdin")
        .context("writing manifest to stdin")?;
    let output = child.wait_with_output().context("waiting for sandy")?;

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr_of(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).context("parse submit json")?;
    assert!(json["job_id"].as_str().is_some_and(|id| !id.is_empty()));
    Ok(())
}

/// A control-plane refusal (an unknown job id) maps to the InvalidPlan band
/// (2), not a crash and not a silent success — the request itself is the
/// fault, mirroring how `run` treats an unbootable plan.
#[test]
fn status_of_an_unknown_job_is_invalid_plan_not_a_crash() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let status = sandy(&daemon, &["daemon", "status", "no-such-job"])?;
    assert_eq!(status.status.code(), Some(2), "stderr: {}", stderr_of(&status));
    assert!(
        stderr_of(&status).contains("no such job"),
        "stderr must name the real refusal: {}",
        stderr_of(&status)
    );
    Ok(())
}

/// Adversarial (#212/#205): `attach` on a job id that was never submitted
/// must surface the daemon's honest refusal rather than printing a channel
/// as if one existed.
#[test]
fn attach_surfaces_the_daemons_honest_refusal_not_a_fabricated_channel() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let attach = sandy(&daemon, &["daemon", "attach", "some-job"])?;
    assert_eq!(attach.status.code(), Some(2), "stderr: {}", stderr_of(&attach));
    assert!(
        stderr_of(&attach).contains("no such job"),
        "stderr must carry the daemon's real refusal: {}",
        stderr_of(&attach)
    );
    assert!(
        String::from_utf8_lossy(&attach.stdout).is_empty(),
        "a refusal must print nothing on stdout: {}",
        String::from_utf8_lossy(&attach.stdout)
    );
    Ok(())
}

/// #513: under `-o json` a refusal before any channel exists starts no stream: nothing on stdout (no `attached`
/// line with a fabricated cap, no `exit` line), the refusal on stderr, the same exit band as plain.
#[test]
fn attach_json_prints_no_stream_when_the_daemon_refuses() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let attach = sandy(&daemon, &["daemon", "attach", "some-job", "-o", "json"])?;
    assert_eq!(attach.status.code(), Some(2), "stderr: {}", stderr_of(&attach));
    assert!(
        stderr_of(&attach).contains("no such job"),
        "stderr must carry the daemon's real refusal: {}",
        stderr_of(&attach)
    );
    assert!(
        String::from_utf8_lossy(&attach.stdout).is_empty(),
        "no stream may start on a refusal: {}",
        String::from_utf8_lossy(&attach.stdout)
    );
    Ok(())
}

/// #540: a cancel the CLI has no attach token for (here, an id this machine never submitted) is
/// refused by the real daemon with the one refusal message, exit 2, nothing on stdout.
#[test]
fn cancel_without_a_token_is_refused_with_the_daemons_one_message() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let cancel = sandy(&daemon, &["daemon", "cancel", "never-submitted-here"])?;
    assert_eq!(cancel.status.code(), Some(2), "stderr: {}", stderr_of(&cancel));
    assert!(
        stderr_of(&cancel).contains("a valid attach token for this job is required"),
        "stderr must carry the daemon's refusal: {}",
        stderr_of(&cancel)
    );
    assert!(
        !stderr_of(&cancel).contains("never-submitted-here"),
        "the refusal must not echo the job id: {}",
        stderr_of(&cancel)
    );
    assert!(String::from_utf8_lossy(&cancel.stdout).is_empty());
    Ok(())
}

#[test]
fn connecting_to_a_dead_socket_is_an_infra_fault_not_a_hang() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", tmp.path().join("no-daemon-here.sock"))
        .args(["daemon", "list"])
        .output()
        .context("running sandy daemon list with no daemon")?;
    assert_eq!(output.status.code(), Some(3), "stderr: {}", stderr_of(&output));
    Ok(())
}

/// `$SANDYD_BIN`, when set (the hermetic nix e2e check's path, #233), is used
/// as-is — never overridden by the dev-shell build-it-yourself fallback.
#[test]
fn sandyd_bin_resolves_from_the_env_var_when_set() -> anyhow::Result<()> {
    let resolved = resolve_sandyd_bin(Some(std::ffi::OsString::from("/some/nix/store/path/bin/sandyd")))?;
    assert_eq!(resolved, std::path::PathBuf::from("/some/nix/store/path/bin/sandyd"));
    Ok(())
}

/// Adversarial (#232): a `--cap-file` whose contents aren't valid base64 is
/// refused as an invalid plan, naming the path — never silently dropped to
/// fall back to a direct-mint submit the caller didn't ask for.
#[test]
fn submit_with_malformed_cap_file_is_an_invalid_plan() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let manifest = tmp.path().join("manifest.bin");
    std::fs::write(&manifest, b"opaque").context("write manifest")?;
    let cap_file = tmp.path().join("cap.txt");
    write_cap_file(&cap_file, "not valid base64!!")?;
    let cap_file = cap_file.to_str().context("cap file path is utf8")?;

    let submit = sandy(
        &daemon,
        &[
            "daemon",
            "submit",
            manifest.to_str().context("manifest path is utf8")?,
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "--cap-file",
            cap_file,
        ],
    )?;
    assert_eq!(submit.status.code(), Some(2), "stderr: {}", stderr_of(&submit));
    assert!(
        stderr_of(&submit).contains(cap_file),
        "stderr must name the malformed file's path: {}",
        stderr_of(&submit)
    );
    Ok(())
}

/// Adversarial (CodeRabbit on this PR): a malformed `--cap-file` is refused
/// as an invalid plan even with NO `sandyd` running at all — proving the
/// read+decode happens before `dispatch_daemon_async` ever resolves the
/// socket path or attempts a connection, not merely before the request is
/// sent over an already-open one.
#[test]
fn submit_with_malformed_cap_file_is_refused_with_no_daemon_running() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let manifest = tmp.path().join("manifest.bin");
    std::fs::write(&manifest, b"opaque").context("write manifest")?;
    let cap_file = tmp.path().join("cap.txt");
    write_cap_file(&cap_file, "not valid base64!!")?;
    let cap_file = cap_file.to_str().context("cap file path is utf8")?;

    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", tmp.path().join("no-daemon-here.sock"))
        .args([
            "daemon",
            "submit",
            manifest.to_str().context("manifest path is utf8")?,
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "--cap-file",
            cap_file,
        ])
        .output()
        .context("running sandy daemon submit with no daemon")?;
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains(cap_file),
        "stderr must name the malformed file's path, not an infra-fault connection error: {}",
        stderr_of(&output)
    );
    Ok(())
}

/// Positive (#232): a `--cap-file` whose contents ARE valid base64 reaches
/// `sandyd` over the wire — proven by the daemon's own refusal, since garbage
/// bytes (valid base64, not a real encoded `Cap`) fail `decode_cap`
/// server-side rather than the CLI silently dropping the flag before it ever
/// sends anything.
#[test]
fn submit_with_a_well_formed_but_unreal_cap_file_reaches_the_daemons_own_decode() -> anyhow::Result<()> {
    use base64::Engine as _;

    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let manifest = tmp.path().join("manifest.bin");
    std::fs::write(&manifest, b"opaque").context("write manifest")?;
    let not_a_real_cap = base64::engine::general_purpose::STANDARD.encode(b"not-a-real-encoded-cap");
    let cap_file = tmp.path().join("cap.txt");
    write_cap_file(&cap_file, &not_a_real_cap)?;
    let cap_file = cap_file.to_str().context("cap file path is utf8")?;

    let submit = sandy(
        &daemon,
        &[
            "daemon",
            "submit",
            manifest.to_str().context("manifest path is utf8")?,
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "--cap-file",
            cap_file,
        ],
    )?;
    assert_eq!(submit.status.code(), Some(2), "stderr: {}", stderr_of(&submit));
    assert!(
        stderr_of(&submit).contains("could not decode a submitter capability"),
        "the daemon's own refusal must name the real cause, proving the --cap-file bytes reached it: {}",
        stderr_of(&submit)
    );
    Ok(())
}

/// Positive (CodeRabbit on this PR): the full #232 round trip with a REAL
/// cap, not just a rejection. Submit a seed job, attach to it (minting a
/// post+read cap scoped to the seed job's own channel — its job_id, CF-H-1),
/// save that cap to a file, then submit a second job whose `JobManifest`
/// requests read-only (a strict subset) on that same channel via
/// `--cap-file`. `derive_job_caps`'s subset check must grant it, proving a
/// cap minted by a real `attach` actually satisfies Submit once presented
/// back through `--cap-file` — not just that malformed or unreal bytes are
/// refused.
#[test]
fn submit_with_a_cap_file_from_a_real_attach_grants_the_requested_subset() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;

    let seed_manifest = tmp.path().join("seed.bin");
    std::fs::write(&seed_manifest, b"opaque").context("write seed manifest")?;
    let seed_submit = sandy(
        &daemon,
        &[
            "daemon",
            "submit",
            seed_manifest.to_str().context("seed manifest path is utf8")?,
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "-o",
            "json",
        ],
    )?;
    assert_eq!(
        seed_submit.status.code(),
        Some(0),
        "seed submit stderr: {}",
        stderr_of(&seed_submit)
    );
    let seed_json: serde_json::Value = serde_json::from_slice(&seed_submit.stdout).context("parse seed submit json")?;
    let seed_job_id = seed_json["job_id"]
        .as_str()
        .context("seed submit json must carry a job_id")?
        .to_owned();

    // `-o json` is an NDJSON stream (#513, owner decision on #564): the first line is `attached` and carries the
    // cap, written before the data-plane join. The seed job never ends, so read that line and stop the stream.
    let mut attach = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", &daemon.sock)
        .args(["daemon", "attach", &seed_job_id, "-o", "json"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("spawning sandy daemon attach")?;
    let mut first_line = String::new();
    let read =
        std::io::BufReader::new(attach.stdout.take().context("attach stdout is piped")?).read_line(&mut first_line);
    attach.kill().context("stopping the attach stream")?;
    attach.wait().context("reaping the attach stream")?;
    read.context("reading the first attach line")?;
    let attach_json: serde_json::Value =
        serde_json::from_str(&first_line).with_context(|| format!("first line {first_line:?}"))?;
    assert_eq!(attach_json["type"], "attached", "{first_line:?}");
    let cap_b64 = attach_json["cap"].as_str().context("attach json must carry a cap")?;
    let cap_file = tmp.path().join("cap.txt");
    write_cap_file(&cap_file, cap_b64)?;
    let cap_file = cap_file.to_str().context("cap file path is utf8")?;

    // `sandy_fabric::types::ChannelId` is a one-field newtype, so it
    // serializes transparently as the bare string, not `[seed_job_id]`.
    let manifest_json = serde_json::json!({
        "entrypoint": {"command": ["true"]},
        "requested_caps": [{
            "channel_id": seed_job_id,
            "rights": {"post": false, "read": true, "invite": false},
        }],
    });
    let manifest_path = tmp.path().join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest_json)?).context("write manifest json")?;

    let submit = sandy(
        &daemon,
        &[
            "daemon",
            "submit",
            manifest_path.to_str().context("manifest path is utf8")?,
            "--manifest-encoding",
            "sandy.orchestrator.v1.JobManifest+json",
            "--isolation-class",
            "trusted",
            "--cap-file",
            cap_file,
            "-o",
            "json",
        ],
    )?;
    assert_eq!(
        submit.status.code(),
        Some(0),
        "a read-only request strictly narrower than the attach cap's post+read must be granted: {}",
        stderr_of(&submit)
    );
    let submit_json: serde_json::Value = serde_json::from_slice(&submit.stdout).context("parse submit json")?;
    assert!(
        submit_json["job_id"].as_str().is_some_and(|id| !id.is_empty()),
        "got {submit_json:?}"
    );
    Ok(())
}

/// #481: `--credential` reaches `sandyd`. The same Submit that succeeds without
/// it is refused with it, since this daemon has no host-executor that shares the
/// submitter's filesystem to hand a minted token to; nothing is minted first.
#[test]
fn submit_with_a_credential_and_no_local_host_is_refused_by_the_daemon() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let daemon = spawn_daemon(tmp.path())?;
    let manifest = tmp.path().join("manifest.bin");
    std::fs::write(&manifest, b"opaque").context("write manifest")?;
    let manifest = manifest.to_str().context("manifest path is utf8")?;
    let base = [
        "daemon",
        "submit",
        manifest,
        "--manifest-encoding",
        "test/v1",
        "--isolation-class",
        "trusted",
    ];

    let plain = sandy(&daemon, &base)?;
    assert!(plain.status.success(), "stderr: {}", stderr_of(&plain));

    let mut with_credential = base.to_vec();
    with_credential.extend(["--credential", "gh-test", "--cred-capability", "write-code"]);
    let refused = sandy(&daemon, &with_credential)?;
    assert!(
        !refused.status.success(),
        "a credentialed Submit with no local host must be refused"
    );
    assert!(
        stderr_of(&refused).contains("no remote placement is reachable"),
        "stderr: {}",
        stderr_of(&refused)
    );
    Ok(())
}

/// An unknown `--cred-capability` value is an input error (exit 2) even with no
/// daemon to connect to, not a retryable infrastructure failure.
#[test]
fn an_unknown_cred_capability_is_refused_before_connecting() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", tmp.path().join("no-daemon-here.sock"))
        .args([
            "daemon",
            "submit",
            "manifest.bin",
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "--credential",
            "gh-test",
            "--cred-capability",
            "admin",
        ])
        .output()
        .context("running sandy daemon submit")?;
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr_of(&output));
    assert!(stderr_of(&output).contains("admin"), "stderr: {}", stderr_of(&output));
    Ok(())
}

/// `--cred-capability` without `--credential` is a usage error, never a silent no-op.
#[test]
fn a_cred_capability_without_a_credential_is_a_usage_error() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("temp dir")?;
    let output = Command::new(env!("CARGO_BIN_EXE_sandy"))
        .env("SANDY_SOCK", tmp.path().join("no-daemon-here.sock"))
        .args([
            "daemon",
            "submit",
            "manifest.bin",
            "--manifest-encoding",
            "test/v1",
            "--isolation-class",
            "trusted",
            "--cred-capability",
            "write-code",
        ])
        .output()
        .context("running sandy daemon submit")?;
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains("--credential"),
        "stderr: {}",
        stderr_of(&output)
    );
    Ok(())
}
