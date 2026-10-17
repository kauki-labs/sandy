//! The sandbox agent as a real OS process (#216), end to end through
//! `ProcessBackend::run`: the backend spawns the built `sandy-agent` binary with
//! its link on stdin, the test plays the orchestrator (the relay plus a channel
//! member), and the agent runs the job as its child.

use std::{
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use futures_util::StreamExt;
use sandy_api::backend::{BackendError, Grants, Outcome, RunSpec, VmBackend};
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapRights, CapScope},
    types::{ChannelId, PeerId},
};
use sandy_fabric_local::{
    LocalCapAuthority,
    agent::{TTY_STDIN, TTY_STDOUT},
    channel::Channel,
    inmem::InMem,
    link::{LinkError, serve_agent_link},
};
use sandy_impls_local::{AgentLaunch, AgentReport, ProcessBackend};
use sandy_proto::{MessageType, Tty};
use tokio::time::timeout;

const CHANNEL: &str = "orchestrator";
const WAIT: Duration = Duration::from_secs(10);

type TestChannel = Arc<Channel<InMem, LocalCapAuthority>>;
type RelayResult = Arc<Mutex<Option<tokio::task::JoinHandle<Result<Option<i32>, LinkError>>>>>;

fn agent_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandy-agent"))
}

fn scope(peer: &str) -> CapScope {
    CapScope {
        peer: PeerId::from(peer),
        channel: ChannelId::from(CHANNEL),
        rights: CapRights {
            post: true,
            read: true,
            invite: false,
        },
        expires_at: None,
    }
}

async fn channel_and_caps() -> anyhow::Result<(TestChannel, Cap, Cap)> {
    let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
    let agent_cap = authority.mint(scope("agent"))?;
    let orchestrator_cap = authority.mint(scope("orchestrator"))?;
    let channel = Channel::new(ChannelId::from(CHANNEL), InMem::default(), authority).await?;
    Ok((Arc::new(channel), agent_cap, orchestrator_cap))
}

/// A backend whose `on_link` runs the relay for `cap` on this test's runtime,
/// keeping the relay's handle so the test can check how it ended.
fn backend_relaying(channel: &TestChannel, cap: Cap) -> (ProcessBackend, RelayResult) {
    let relay: RelayResult = Arc::new(Mutex::new(None));
    let handle = tokio::runtime::Handle::current();
    let on_link = {
        let (channel, relay) = (Arc::clone(channel), Arc::clone(&relay));
        Arc::new(move |_box_id: &str, host_end: OwnedFd, report: AgentReport| {
            let (channel, cap) = (Arc::clone(&channel), cap.clone());
            let task = handle.spawn(async move {
                let stream = std::os::unix::net::UnixStream::from(host_end);
                stream.set_nonblocking(true)?;
                let link = tokio::net::UnixStream::from_std(stream)?;
                let relayed = serve_agent_link(channel, &cap, link).await;
                match &relayed {
                    Ok(Some(code)) => report.job_exited(*code),
                    Ok(None) => report.agent_failed("the agent ended without reporting the job's exit"),
                    Err(e) => report.agent_failed(e.to_string()),
                }
                relayed
            });
            *relay.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
        })
    };
    let backend = ProcessBackend::new().with_agent(AgentLaunch {
        program: agent_binary(),
        on_link,
    });
    (backend, relay)
}

fn grants() -> Grants {
    Grants {
        secrets: false,
        agent: false,
        shares: false,
    }
}

/// Run `command` on `backend` off the async runtime (`run` blocks).
async fn run_blocking(backend: ProcessBackend, command: Vec<String>) -> anyhow::Result<Result<Outcome, BackendError>> {
    Ok(tokio::task::spawn_blocking(move || run_on(&backend, &command)).await?)
}

fn sh(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()]
}

async fn relay_result(relay: &RelayResult) -> anyhow::Result<Result<Option<i32>, LinkError>> {
    let task = relay
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .context("on_link never ran: the backend did not hand over the link")?;
    Ok(timeout(WAIT, task).await??)
}

/// The job's output reaches the channel and channel input reaches the job,
/// across the agent's process boundary; the job's exit code and console come
/// back through `run` unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_runs_as_the_agent_child_with_tty_both_ways() -> anyhow::Result<()> {
    let (channel, agent_cap, orchestrator_cap) = channel_and_caps().await?;
    let orchestrator = channel.join(&orchestrator_cap)?;
    let mut observed = std::pin::pin!(channel.subscribe(&orchestrator)?);
    let (backend, relay) = backend_relaying(&channel, agent_cap);

    let run = tokio::spawn(run_blocking(
        backend,
        sh(r#"echo hello; read line; echo "got:$line"; exit 7"#),
    ));

    let mut stdout = Vec::new();
    while !String::from_utf8_lossy(&stdout).contains("hello") {
        let env = timeout(WAIT, observed.next()).await?.context("channel ended")??;
        if env.content_type == TTY_STDOUT {
            stdout.extend(env.payload);
        }
    }
    channel
        .post(
            &orchestrator,
            Some(MessageType::Tty(Tty {})),
            TTY_STDIN,
            b"ping\n".to_vec(),
        )
        .await?;
    while !String::from_utf8_lossy(&stdout).contains("got:ping") {
        let env = timeout(WAIT, observed.next()).await?.context("channel ended")??;
        if env.content_type == TTY_STDOUT {
            stdout.extend(env.payload);
        }
    }

    let outcome = timeout(WAIT, run).await????;
    assert_eq!(
        outcome.guest_exit,
        Some(7),
        "the job's exit code must pass through the agent"
    );
    let console = &outcome.console;
    assert!(
        console.contains("hello") && console.contains("got:ping"),
        "the console must still carry the job's output: {console}"
    );
    relay_result(&relay).await??;
    Ok(())
}

/// Adversarial (sandy-b6 on #203): the job inherits neither the agent link nor
/// the cap. Its only descriptors are fresh stdio pipes; none is the link socket.
#[tokio::test(flavor = "multi_thread")]
async fn the_job_inherits_only_fresh_stdio_and_never_the_link() -> anyhow::Result<()> {
    let (channel, agent_cap, _) = channel_and_caps().await?;
    let (backend, relay) = backend_relaying(&channel, agent_cap);

    // `ls` lists its own descriptors: 0-2 plus the one it opened to list them.
    // Anything inherited beyond stdio shows up as an extra entry.
    let script = r#"
        ls /dev/fd | sort -n | tr '\n' ' '; echo
        for fd in 0 1 2; do [ -S /dev/fd/$fd ] && echo "fd$fd-is-a-socket"; done
        exit 0
    "#;
    let outcome = timeout(WAIT, run_blocking(backend, sh(script))).await???;
    let console = &outcome.console;
    assert_eq!(outcome.guest_exit, Some(0), "console: {console}");
    assert!(
        !console.contains("is-a-socket"),
        "a job stdio fd is a socket: {console}"
    );
    let fds: Vec<&str> = console
        .lines()
        .find(|l| l.trim_start().starts_with("0 1 2"))
        .context(format!("no fd listing in the console: {console}"))?
        .split_whitespace()
        .collect();
    assert_eq!(
        fds.len(),
        4,
        "the job holds more than stdio plus ls's own handle: {fds:?}"
    );
    relay_result(&relay).await??;
    Ok(())
}

/// #230: on macOS the agent link's socket pair gets close-on-exec in a second
/// call, so a spawn on another thread could inherit a concurrent run's link.
/// Many agent-mode runs at once: every job still holds only its fresh stdio.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_runs_never_leak_one_link_into_another_job() -> anyhow::Result<()> {
    const RUNS: usize = 48;
    let script = "ls /dev/fd | sort -n | tr '\\n' ' '; echo; exit 0";
    let mut runs = Vec::new();
    for _ in 0..RUNS {
        let (channel, agent_cap, _) = channel_and_caps().await?;
        let (backend, relay) = backend_relaying(&channel, agent_cap);
        runs.push((run_blocking(backend, sh(script)), relay));
    }
    let (outcomes, relays): (Vec<_>, Vec<_>) = runs.into_iter().unzip();
    let outcomes = timeout(WAIT * 3, futures_util::future::join_all(outcomes)).await?;
    for (n, (outcome, relay)) in outcomes.into_iter().zip(&relays).enumerate() {
        let outcome = outcome??;
        let console = &outcome.console;
        let fds = console
            .lines()
            .find(|l| l.trim_start().starts_with("0 1 2"))
            .context(format!("run {n}: no fd listing in the console: {console}"))?
            .split_whitespace()
            .count();
        assert_eq!(
            fds, 4,
            "run {n}: the job holds more than stdio plus ls's own handle: {console}"
        );
        relay_result(relay).await??;
    }
    Ok(())
}

/// #281: on macOS a socket gets close-on-exec in a second call, so a socket
/// that other code in the host makes during a spawn (a relay dialing from
/// `on_link`, say) could reach the job; `SPAWN_LOCK` cannot cover code outside
/// the backend. A thread keeps making sockets while many runs spawn: every job
/// still holds only its fresh stdio.
#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sockets_made_elsewhere_during_spawns_never_reach_a_job() -> anyhow::Result<()> {
    const RUNS: usize = 32;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hammer = std::thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                // Held briefly, as a dialed connection would be.
                let pair = std::os::unix::net::UnixStream::pair();
                std::thread::yield_now();
                drop(pair);
            }
        }
    });
    let script = "ls /dev/fd | sort -n | tr '\\n' ' '; echo; exit 0";
    let mut runs = Vec::new();
    for _ in 0..RUNS {
        let (channel, agent_cap, _) = channel_and_caps().await?;
        let (backend, relay) = backend_relaying(&channel, agent_cap);
        runs.push((run_blocking(backend, sh(script)), relay));
    }
    let (outcomes, relays): (Vec<_>, Vec<_>) = runs.into_iter().unzip();
    let outcomes = timeout(WAIT * 3, futures_util::future::join_all(outcomes)).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    hammer
        .join()
        .map_err(|_| anyhow::anyhow!("the socket thread panicked"))?;
    for (n, (outcome, relay)) in outcomes?.into_iter().zip(&relays).enumerate() {
        let outcome = outcome??;
        let console = &outcome.console;
        let fds = console
            .lines()
            .find(|l| l.trim_start().starts_with("0 1 2"))
            .context(format!("run {n}: no fd listing in the console: {console}"))?
            .split_whitespace()
            .count();
        assert_eq!(
            fds, 4,
            "run {n}: the job holds more than stdio plus ls's own handle: {console}"
        );
        relay_result(relay).await??;
    }
    Ok(())
}

/// Adversarial (INV-1): the job's environment carries no trace of the link or
/// the cap — exactly what the backend passes, nothing the agent added.
#[tokio::test(flavor = "multi_thread")]
async fn the_job_environment_carries_no_link_or_cap() -> anyhow::Result<()> {
    let (channel, agent_cap, _) = channel_and_caps().await?;
    let (backend, relay) = backend_relaying(&channel, agent_cap);

    let outcome = timeout(WAIT, run_blocking(backend, vec!["env".to_string()])).await???;
    let console = &outcome.console;
    assert_eq!(outcome.guest_exit, Some(0), "console: {console}");
    for line in console.lines().filter(|l| l.contains('=')) {
        let key = line.split('=').next().unwrap_or_default();
        // A coverage build's LLVM profiling runtime sets this marker in the
        // instrumented agent's own environment before `main`; it carries no link
        // or cap, and a normal build never has it.
        let instrumentation = key == "__LLVM_PROFILE_RT_INIT_ONCE";
        assert!(
            key == "PATH" || (key.starts_with("SANDY_") && key.ends_with("_DIR")) || instrumentation,
            "the job env has an unexpected variable {key}: {console}"
        );
    }
    relay_result(&relay).await??;
    Ok(())
}

/// A forged cap is refused at the relay: the job never starts, and the run is
/// an infra fault, not a job result (INV-11).
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_cap_never_starts_the_job_and_is_an_infra_fault() -> anyhow::Result<()> {
    let (channel, ..) = channel_and_caps().await?;
    let forged = LocalCapAuthority::new(Duration::from_secs(3600))?.mint(scope("agent"))?;
    let (backend, relay) = backend_relaying(&channel, forged);
    let marker_dir = tempfile::tempdir()?;
    let marker = marker_dir.path().join("job-ran");

    let result = timeout(
        WAIT,
        run_blocking(backend, sh(&format!("touch {}", shell_quote(&marker)))),
    )
    .await??;
    assert!(
        matches!(result, Err(BackendError::Spawn(_))),
        "a refused bootstrap must be an infra fault, got {result:?}"
    );
    assert!(!marker.exists(), "the job ran although the agent was refused");
    assert!(
        matches!(relay_result(&relay).await?, Err(LinkError::Channel(_))),
        "the relay must report the refused join"
    );
    Ok(())
}

/// Adversarial (review of #216): a job that kills its own agent, after
/// printing a line that looks like an agent diagnostic, gets an infra fault
/// whose reason it did not write — never a job result it chose, and never its
/// own text as the failure reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_that_kills_its_agent_cannot_pick_the_result_or_the_reason() -> anyhow::Result<()> {
    let (channel, agent_cap, _) = channel_and_caps().await?;
    let (backend, relay) = backend_relaying(&channel, agent_cap);

    let result = timeout(
        WAIT,
        run_blocking(backend, sh(r#"echo "sandy-agent: spoofed"; kill -ABRT $PPID; exit 0"#)),
    )
    .await??;
    match result {
        Err(BackendError::Spawn(why)) => assert!(!why.contains("spoofed"), "the job wrote the reason: {why}"),
        other => panic!("a killed agent must be an infra fault, got {other:?}"),
    }
    assert!(
        matches!(relay_result(&relay).await?, Ok(None)),
        "the relay must see no exit report"
    );
    Ok(())
}

/// An agent-mode backend runs one job: a second run would re-join the same cap
/// and replay the channel's earlier stdin into the new job.
#[tokio::test(flavor = "multi_thread")]
async fn an_agent_backend_refuses_a_second_run() -> anyhow::Result<()> {
    let (channel, agent_cap, _) = channel_and_caps().await?;
    let (backend, relay) = backend_relaying(&channel, agent_cap);
    let backend = Arc::new(backend);

    let first = {
        let backend = Arc::clone(&backend);
        tokio::task::spawn_blocking(move || run_on(&backend, &sh("exit 0"))).await?
    };
    assert_eq!(first?.guest_exit, Some(0));
    relay_result(&relay).await??;

    let second = tokio::task::spawn_blocking(move || run_on(&backend, &sh("exit 0"))).await?;
    assert!(
        matches!(&second, Err(BackendError::Spawn(why)) if why.contains("one job")),
        "a second run must be refused, got {second:?}"
    );
    Ok(())
}

/// A panicking `on_link` fails the run as infra instead of unwinding through
/// `run`, which would skip the staging wipe.
#[tokio::test(flavor = "multi_thread")]
async fn a_panicking_link_handler_fails_the_run_without_unwinding() -> anyhow::Result<()> {
    let backend = ProcessBackend::new().with_agent(AgentLaunch {
        program: agent_binary(),
        on_link: Arc::new(|_: &str, _: OwnedFd, _: AgentReport| panic!("relay setup failed")),
    });
    let result = tokio::task::spawn_blocking(move || run_on(&backend, &sh("exit 0"))).await?;
    assert!(
        matches!(&result, Err(BackendError::Spawn(why)) if why.contains("on_link")),
        "got {result:?}"
    );
    Ok(())
}

fn run_on(backend: &ProcessBackend, command: &[String]) -> Result<Outcome, BackendError> {
    let grants = grants();
    backend.run(&RunSpec {
        template: "process",
        command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants: &grants,
        outcome_file: None,
        secret_dir: None,
    })
}

/// #238 slice 4b, end to end through the real agent process: the job sends on
/// its peer channel with `sandy-agent peer send`, a sibling sandbox on that
/// channel sees it and answers, and the job's `peer recv --wait` prints the
/// answer and the inbox's drop count.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_talks_to_a_sibling_over_its_peer_channel() -> anyhow::Result<()> {
    use base64::Engine;
    use sandy_fabric_local::link::{PeerGrant, serve_agent_link_with_peers};

    let (channel, agent_cap, _) = channel_and_caps().await?;
    let group_authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
    let group_scope = |peer: &str| CapScope {
        peer: PeerId::from(peer),
        channel: ChannelId::from("group-a"),
        rights: CapRights {
            post: true,
            read: true,
            invite: false,
        },
        expires_at: None,
    };
    let agent_group_cap = group_authority.mint(group_scope("agent"))?;
    let sibling_cap = group_authority.mint(group_scope("sibling"))?;
    let group = Arc::new(Channel::new(ChannelId::from("group-a"), InMem::default(), group_authority).await?);
    let sibling = group.join(&sibling_cap)?;
    let mut sibling_view = std::pin::pin!(group.subscribe(&sibling)?);

    let handle = tokio::runtime::Handle::current();
    let on_link = {
        let group = Arc::clone(&group);
        Arc::new(move |_box_id: &str, host_end: OwnedFd, report: AgentReport| {
            let (channel, cap) = (Arc::clone(&channel), agent_cap.clone());
            let grants = vec![PeerGrant {
                channel: Arc::clone(&group),
                cap: agent_group_cap.clone(),
            }];
            handle.spawn(async move {
                let stream = std::os::unix::net::UnixStream::from(host_end);
                let relayed = match stream
                    .set_nonblocking(true)
                    .and_then(|()| tokio::net::UnixStream::from_std(stream))
                {
                    Ok(link) => serve_agent_link_with_peers(channel, &cap, grants, link).await,
                    Err(e) => Err(LinkError::Io(e)),
                };
                match relayed {
                    Ok(Some(code)) => report.job_exited(code),
                    Ok(None) => report.agent_failed("no exit report"),
                    Err(e) => report.agent_failed(e.to_string()),
                }
            });
        })
    };
    let backend = ProcessBackend::new().with_agent(AgentLaunch {
        program: agent_binary(),
        on_link,
    });
    let script = format!(
        r#"[ -n "$SANDY_PEER_SOCKET" ] || exit 3
        printf from-job | {agent} peer send group-a text/plain || exit 4
        {agent} peer recv --wait"#,
        agent = shell_quote(&agent_binary())
    );
    let run = tokio::spawn(run_blocking(backend, sh(&script)));

    loop {
        let env = timeout(WAIT, sibling_view.next())
            .await?
            .context("group stream ended")??;
        if env.payload == b"from-job" {
            break;
        }
    }
    group
        .post(
            &sibling,
            Some(MessageType::PeerMsg(sandy_proto::PeerMsg {})),
            "text/plain",
            b"to-job".to_vec(),
        )
        .await?;

    let outcome = timeout(WAIT, run).await????;
    assert_eq!(outcome.guest_exit, Some(0), "console: {}", outcome.console);
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"to-job");
    assert!(
        outcome.console.contains(&encoded) && outcome.console.contains(r#"{"dropped":0,"refused":0}"#),
        "the job must print the sibling's message and the drop count: {}",
        outcome.console
    );
    Ok(())
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}
