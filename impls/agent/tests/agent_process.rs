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
use sandy_impls_local::{AgentLaunch, ProcessBackend};
use sandy_proto::{MessageType, Tty};
use tokio::time::timeout;

const CHANNEL: &str = "orchestrator";
const WAIT: Duration = Duration::from_secs(10);

type TestChannel = Arc<Channel<InMem, LocalCapAuthority>>;
type RelayResult = Arc<Mutex<Option<tokio::task::JoinHandle<Result<(), LinkError>>>>>;

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
        Arc::new(move |_box_id: &str, host_end: OwnedFd| {
            let (channel, cap) = (Arc::clone(&channel), cap.clone());
            let task = handle.spawn(async move {
                let stream = std::os::unix::net::UnixStream::from(host_end);
                stream.set_nonblocking(true)?;
                let link = tokio::net::UnixStream::from_std(stream)?;
                serve_agent_link(channel, &cap, link).await
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
    let outcome = tokio::task::spawn_blocking(move || {
        let grants = grants();
        let spec = RunSpec {
            template: "process",
            command: &command,
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
        };
        backend.run(&spec)
    })
    .await?;
    Ok(outcome)
}

fn sh(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()]
}

async fn relay_result(relay: &RelayResult) -> anyhow::Result<Result<(), LinkError>> {
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

/// Adversarial (INV-1): the job's environment carries no trace of the link or
/// the cap — exactly what the backend passes, nothing the agent added.
#[tokio::test(flavor = "multi_thread")]
async fn the_job_environment_carries_no_link_or_cap() -> anyhow::Result<()> {
    let (channel, agent_cap, _) = channel_and_caps().await?;
    let (backend, relay) = backend_relaying(&channel, agent_cap);

    let outcome = timeout(WAIT, run_blocking(backend, vec!["/usr/bin/env".to_string()])).await???;
    let console = &outcome.console;
    assert_eq!(outcome.guest_exit, Some(0), "console: {console}");
    for line in console.lines().filter(|l| l.contains('=')) {
        let key = line.split('=').next().unwrap_or_default();
        assert!(
            key == "PATH" || (key.starts_with("SANDY_") && key.ends_with("_DIR")),
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

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}
