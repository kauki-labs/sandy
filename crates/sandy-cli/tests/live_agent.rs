//! Live agent (#238): a VM job runs behind the guest's sandbox agent over vsock.
//!
//! Tier-3, behind the `live` feature like the other live suites (INV-S9). The
//! test plays the orchestrator: it holds the channel, runs the relay on the link
//! the backend's connector hands over, and posts or reads TTY traffic, while the
//! real guest agent runs the job as its child.
//!
//! Run it on the live host, e.g. on Apple silicon:
//!   nix shell nixpkgs#vfkit -c \
//!     env SANDY_LIVE=1 cargo nextest run -p sandy-cli --features live --test live_agent
#![cfg(feature = "live")]

use std::{
    os::fd::OwnedFd,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use futures_util::StreamExt;
use sandy::{BackendError, Grants, Outcome, RunSpec, VmBackend};
use sandy_api::agent::{AgentLaunch, AgentReport};
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapRights, CapScope, encode_cap},
    types::{ChannelId, PeerId},
};
use sandy_fabric_local::{
    LocalCapAuthority,
    agent::{TTY_STDIN, TTY_STDOUT},
    channel::Channel,
    inmem::InMem,
    link::{LinkError, serve_agent_link},
};
use sandy_proto::{MessageType, Tty};
use tokio::time::timeout;

mod common;
use common::{build_guest, guest_flake, require_live};

const CHANNEL: &str = "orchestrator";
/// Generous: a cold guest boot plus the job.
const WAIT: Duration = Duration::from_secs(180);

type TestChannel = Arc<Channel<InMem, LocalCapAuthority>>;
type Relay = Arc<Mutex<Option<tokio::task::JoinHandle<Result<Option<i32>, LinkError>>>>>;

#[cfg(target_os = "macos")]
fn host_backend() -> sandy_backend::VfkitBackend {
    sandy_backend::VfkitBackend::new(std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string()))
}

#[cfg(not(target_os = "macos"))]
fn host_backend() -> sandy_backend::QemuBackend {
    sandy_backend::QemuBackend::new()
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

/// An `on_link` that runs the relay for `cap` on this test's runtime and
/// resolves the run's report from it.
fn relaying(channel: &TestChannel, cap: Cap) -> (AgentLaunch, Relay) {
    let relay: Relay = Arc::new(Mutex::new(None));
    let handle = tokio::runtime::Handle::current();
    let (channel, slot) = (Arc::clone(channel), Arc::clone(&relay));
    let on_link = Arc::new(move |_box_id: &str, link: OwnedFd, report: AgentReport| {
        let (channel, cap) = (Arc::clone(&channel), cap.clone());
        let task = handle.spawn(async move {
            let stream = std::os::unix::net::UnixStream::from(link);
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
        *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    });
    (
        AgentLaunch {
            program: PathBuf::new(),
            on_link,
        },
        relay,
    )
}

/// Boot the guest and run `script` behind its agent, off the async runtime.
async fn run_in_guest(
    template: String,
    launch: AgentLaunch,
    script: &str,
) -> anyhow::Result<Result<Outcome, BackendError>> {
    let command = vec![script.to_string()];
    Ok(tokio::task::spawn_blocking(move || {
        let grants = Grants {
            secrets: false,
            agent: false,
            shares: false,
        };
        host_backend().with_agent(launch).run(&RunSpec {
            template: &template,
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &[],
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 120,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
        })
    })
    .await?)
}

fn template() -> anyhow::Result<String> {
    let target = require_live()?;
    build_guest(&target)?;
    Ok(format!("{}#{}", guest_flake().display(), target.topology_attr))
}

async fn relay_result(relay: &Relay) -> anyhow::Result<Result<Option<i32>, LinkError>> {
    let task = relay
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .context("on_link never ran: the backend never reached the guest agent")?;
    Ok(timeout(WAIT, task).await??)
}

/// The job's output reaches the channel and channel input reaches the job,
/// through the guest agent; the job's exit comes from the agent's report.
#[tokio::test(flavor = "multi_thread")]
async fn a_vm_job_runs_behind_the_guest_agent_with_tty_both_ways() -> anyhow::Result<()> {
    let template = template()?;
    let (channel, agent_cap, orchestrator_cap) = channel_and_caps().await?;
    let orchestrator = channel.join(&orchestrator_cap)?;
    let mut observed = std::pin::pin!(channel.subscribe(&orchestrator)?);
    let (launch, relay) = relaying(&channel, agent_cap);

    let run = tokio::spawn(run_in_guest(
        template,
        launch,
        r#"echo hello; read line; echo "got:$line"; exit 7"#,
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
        "the exit must come from the agent's report; console: {}",
        outcome.console
    );
    assert_eq!(relay_result(&relay).await??, Some(7));
    Ok(())
}

/// The VM job holds only fresh stdio (no vsock link socket) and its
/// environment carries no trace of the cap.
#[tokio::test(flavor = "multi_thread")]
async fn the_vm_job_holds_no_link_and_no_cap() -> anyhow::Result<()> {
    let template = template()?;
    let (channel, agent_cap, _) = channel_and_caps().await?;
    let cap_hex = hex::encode(encode_cap(&agent_cap)?);
    let (launch, relay) = relaying(&channel, agent_cap);

    let script = r#"
        echo "FDS:$(ls /proc/self/fd | sort -n | tr '\n' ' ')"
        for fd in 0 1 2; do echo "FD$fd:$(readlink /proc/self/fd/$fd)"; done
        tr '\0' '\n' < /proc/self/environ
        exit 0
    "#;
    let outcome = timeout(WAIT, run_in_guest(template, launch, script)).await???;
    let console = &outcome.console;
    assert_eq!(outcome.guest_exit, Some(0), "console: {console}");
    let fds = console
        .lines()
        .find_map(|l| after(l, "FDS:"))
        .context(format!("no fd listing: {console}"))?;
    assert_eq!(
        fds.split_whitespace().count(),
        4,
        "stdio plus ls's own handle only: {fds}"
    );
    for fd in 0..=2 {
        let line = console
            .lines()
            .find_map(|l| after(l, &format!("FD{fd}:")))
            .context(format!("no FD{fd} line: {console}"))?;
        assert!(line.starts_with("pipe:"), "fd {fd} must be a fresh pipe, got {line}");
    }
    assert!(!console.contains(&cap_hex), "the cap reached the job: {console}");
    relay_result(&relay).await??;
    Ok(())
}

/// The text after `marker` on `line`. The console's start sentinel can share the
/// line with the job's first output, so the marker need not lead it.
fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker).map(|(_, rest)| rest)
}

/// A cap the channel's authority did not mint is refused at the relay: the job
/// never starts, and the run is an infra fault.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_cap_never_starts_the_vm_job() -> anyhow::Result<()> {
    let template = template()?;
    let (channel, ..) = channel_and_caps().await?;
    let forged = LocalCapAuthority::new(Duration::from_secs(3600))?.mint(scope("agent"))?;
    let (launch, relay) = relaying(&channel, forged);

    let result = timeout(WAIT, run_in_guest(template, launch, "echo JOB-RAN; exit 0")).await??;
    assert!(
        matches!(&result, Err(BackendError::Spawn(why)) if why.contains("agent")),
        "a refused join must be an infra fault, got {result:?}"
    );
    assert!(
        matches!(relay_result(&relay).await?, Err(LinkError::Channel(_))),
        "the relay must report the refused join"
    );
    Ok(())
}
