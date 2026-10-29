//! Live agent (#238): a VM job runs behind the guest's sandbox agent over vsock.
//!
//! Tier-3, behind the `live` feature like the other live suites (INV-S9). The
//! test plays the orchestrator: it holds the channel, runs the relay on the link
//! the backend's connector hands over, and posts or reads TTY traffic, while the
//! real guest agent runs the job as its child.
//!
//! Run it on the live host (qemu on Linux needs `/dev/vhost-vsock`), e.g. on Apple silicon:
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
use sandy::{BackendError, Grants, Outcome, RunControl, RunSpec, SecretRef, SecretSource, VmBackend};
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
    link::{LinkError, PeerGrant, serve_agent_link, serve_agent_link_with_peers},
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
///
/// `RunSpec.command` is "the guest command and its arguments" (argv, exec'd
/// directly, never shell-interpreted as a whole) — so a multi-line `script`
/// must be wrapped as `["sh", "-c", script]`, not passed as a single bare
/// element (that only ever worked by accident on the pre-fix VM console path,
/// where joining a one-element command was a no-op).
async fn run_in_guest(
    template: String,
    launch: AgentLaunch,
    script: &str,
) -> anyhow::Result<Result<Outcome, BackendError>> {
    let command = vec!["sh".to_string(), "-c".to_string(), script.to_string()];
    Ok(tokio::task::spawn_blocking(move || {
        let grants = Grants {
            secrets: false,
            agent: false,
            shares: false,
        };
        let control = RunControl::with_timeout_secs(120);
        host_backend().with_agent(launch).run(&RunSpec {
            digests: false,
            egress: None,
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
            control: &control,
        })
    })
    .await?)
}

/// Like [`run_in_guest`], but with a secret staged over the secret channel —
/// needed only by the environment-contract test below, so kept separate
/// rather than growing every other caller's argument list.
async fn run_in_guest_with_secret(
    template: String,
    launch: AgentLaunch,
    script: String,
    secret_name: &str,
    secret_value: &'static [u8],
) -> anyhow::Result<Result<Outcome, BackendError>> {
    let command = vec!["sh".to_string(), "-c".to_string(), script];
    let secret_name = secret_name.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<Result<Outcome, BackendError>> {
        use std::os::unix::fs::PermissionsExt;
        let src = tempfile::TempDir::new()?;
        let secret_file = src.path().join("secret");
        std::fs::write(&secret_file, secret_value)?;
        // INV-1: the host secret source must be 0600, or staging refuses it.
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))?;
        let secrets = [SecretRef {
            name: secret_name,
            source: SecretSource::File(secret_file),
        }];
        let grants = Grants {
            secrets: true,
            agent: false,
            shares: false,
        };
        let control = RunControl::with_timeout_secs(120);
        Ok(host_backend().with_agent(launch).run(&RunSpec {
            digests: false,
            egress: None,
            template: &template,
            command: &command,
            inputs: &[],
            outputs: &[],
            secrets: &secrets,
            env: &[],
            cpu: None,
            mem: None,
            timeout_secs: 120,
            grants: &grants,
            outcome_file: None,
            secret_dir: None,
            control: &control,
        }))
    })
    .await?
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

/// The VM job holds only its tmux-allocated pty (no vsock link socket) and its
/// environment carries no trace of the cap.
///
/// Since #342 the job runs as a detached tmux session's pane, not as this
/// process's direct child over a pipe triple — so fd 0/1/2 are the pane's
/// real pty slave, all three the same device, rather than three fresh
/// `pipe:[...]` fds. This replaces that stale pipe assertion (#340 item 5).
#[tokio::test(flavor = "multi_thread")]
async fn the_vm_job_holds_no_link_and_no_cap() -> anyhow::Result<()> {
    let template = template()?;
    let (channel, agent_cap, _) = channel_and_caps().await?;
    let cap_hex = hex::encode(encode_cap(&agent_cap)?);
    let (launch, relay) = relaying(&channel, agent_cap);

    let script = r#"
        echo "FDS:$(ls /proc/self/fd | sort -n | tr '\n' ' ')"
        for fd in 0 1 2; do echo "FD$fd:$(readlink /proc/$$/fd/$fd)"; done
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
    let mut pty_devices = std::collections::HashSet::new();
    for fd in 0..=2 {
        let line = console
            .lines()
            .find_map(|l| after(l, &format!("FD{fd}:")))
            .context(format!("no FD{fd} line: {console}"))?;
        assert!(
            line.starts_with("/dev/pts/"),
            "fd {fd} must be the job's tmux-allocated pty slave, got {line}"
        );
        pty_devices.insert(line.to_string());
    }
    assert_eq!(
        pty_devices.len(),
        1,
        "stdin/stdout/stderr must all be the same pty slave, got {pty_devices:?}"
    );
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

/// #238 slice 4 on a real VM: the job inside the guest sends on its peer
/// channel with `sandy-agent peer send`, a sibling sandbox on that channel
/// receives it and answers, and the job's `peer recv --wait` prints the answer
/// and the drop count; the send happens while nothing else holds the link.
#[tokio::test(flavor = "multi_thread")]
async fn a_vm_job_talks_to_a_sibling_over_its_peer_channel() -> anyhow::Result<()> {
    use base64::Engine;

    let template = template()?;
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

    let relay: Relay = Arc::new(Mutex::new(None));
    let handle = tokio::runtime::Handle::current();
    let on_link = {
        let (group, slot) = (Arc::clone(&group), Arc::clone(&relay));
        Arc::new(move |_box_id: &str, link: OwnedFd, report: AgentReport| {
            let (channel, cap) = (Arc::clone(&channel), agent_cap.clone());
            let grants = vec![PeerGrant {
                channel: Arc::clone(&group),
                cap: agent_group_cap.clone(),
            }];
            let task = handle.spawn(async move {
                let stream = std::os::unix::net::UnixStream::from(link);
                stream.set_nonblocking(true)?;
                let link = tokio::net::UnixStream::from_std(stream)?;
                let relayed = serve_agent_link_with_peers(channel, &cap, grants, link).await;
                match &relayed {
                    Ok(Some(code)) => report.job_exited(*code),
                    Ok(None) => report.agent_failed("the agent ended without reporting the job's exit"),
                    Err(e) => report.agent_failed(e.to_string()),
                }
                relayed
            });
            *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
        })
    };
    let launch = AgentLaunch {
        program: PathBuf::new(),
        on_link,
    };
    let script = r#"[ -n "$SANDY_PEER_SOCKET" ] || exit 3
        printf from-guest | sandy-agent peer send group-a text/plain || exit 4
        sandy-agent peer recv --wait"#;
    let mut run = tokio::spawn(run_in_guest(template, launch, script));

    // Wait for the guest's message, but report the run at once if it ends first.
    timeout(WAIT, async {
        loop {
            tokio::select! {
                env = sibling_view.next() => {
                    let env = env.context("group stream ended")??;
                    if env.payload == b"from-guest" {
                        return anyhow::Ok(());
                    }
                }
                ended = &mut run => {
                    anyhow::bail!("the guest run ended before its peer message: {:?}", ended??);
                }
            }
        }
    })
    .await??;
    group
        .post(
            &sibling,
            Some(MessageType::PeerMsg(sandy_proto::PeerMsg {})),
            "text/plain",
            b"to-guest".to_vec(),
        )
        .await?;

    let outcome = timeout(WAIT, run).await????;
    assert_eq!(outcome.guest_exit, Some(0), "console: {}", outcome.console);
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"to-guest");
    assert!(
        outcome.console.contains(&encoded) && outcome.console.contains(r#"{"dropped":0,"refused":0}"#),
        "the guest job must print the sibling's message and the drop count: {}",
        outcome.console
    );
    assert_eq!(relay_result(&relay).await??, Some(0));
    Ok(())
}

/// A VM job's environment is the guest image's own login environment plus
/// exported secrets and devShell variables — not a fixed allowlist
/// (docs/decisions/agent-fabric.md §13, #509). Asserts the three parts of
/// that contract directly: a guest login-shell variable is visible, a
/// staged secret is visible as `$NAME`, and a variable set on the HOST
/// process before the run is never visible in the guest.
#[tokio::test(flavor = "multi_thread")]
async fn the_vm_job_environment_is_the_guest_login_environment() -> anyhow::Result<()> {
    let template = template()?;
    let (channel, agent_cap, orchestrator_cap) = channel_and_caps().await?;
    let orchestrator = channel.join(&orchestrator_cap)?;
    let mut observed = std::pin::pin!(channel.subscribe(&orchestrator)?);
    let (launch, relay) = relaying(&channel, agent_cap);

    // The host's own environment must never cross into the guest: a VM
    // boots from the image, never from the host process's env block, but
    // this proves it rather than assuming it. `CARGO` is set by the test
    // harness that launched this process (`cargo nextest run`), not by
    // anything guest-side — `unsafe_code = forbid` (workspace lints) rules
    // out setting a fresh host-only variable, so an already-present one
    // with a host-specific value (the path to this host's own `cargo`
    // binary) serves the same purpose.
    const HOST_MARKER_NAME: &str = "CARGO";
    let host_marker_value = std::env::var(HOST_MARKER_NAME).context("CARGO must be set by the test harness")?;

    const SECRET_NAME: &str = "SANDY_TEST_SECRET";
    const SECRET_VALUE: &[u8] = b"s3cr3t-value";

    // Echo only the three variables this test actually checks, not a full
    // `env` dump: a dump (~70 lines, some hundreds of bytes long, e.g.
    // `LS_COLORS`) reliably lost bytes somewhere in the TTY relay chain
    // (tmux PTY -> agent -> vsock -> channel) under live testing on ws01 —
    // confirmed by a run where the secret line and several neighboring
    // lines were simply missing or truncated mid-value from the collected
    // TTY_STDOUT stream, not a parsing bug. A few short, known-length lines
    // stay well under whatever buffer in that chain was overflowing.
    const LOGIN_VAR_NAME: &str = "LOGNAME";
    let script = format!(
        r#"
        echo "ENVSTART"
        echo "{LOGIN_VAR_NAME}=${LOGIN_VAR_NAME}"
        echo "{SECRET_NAME}=${{{SECRET_NAME}:-}}"
        echo "{HOST_MARKER_NAME}=${{{HOST_MARKER_NAME}:-}}"
        echo "ENVEND"
        exit 0
    "#
    );
    let run = tokio::spawn(run_in_guest_with_secret(
        template,
        launch,
        script,
        SECRET_NAME,
        SECRET_VALUE,
    ));

    // The job's output arrives over the agent-link channel as TTY_STDOUT
    // frames (not `Outcome.console`, which only ever holds the boot
    // console up to the agent handoff — the earlier version of this test
    // asserted against that field directly and failed even though the
    // guest genuinely exported the secret, since the job's own stdout was
    // never routed through it in agent mode. See the TTY round-trip test
    // above for the same pattern.)
    let mut stdout = Vec::new();
    while !String::from_utf8_lossy(&stdout).contains("ENVEND") {
        let env = timeout(WAIT, observed.next()).await?.context("channel ended")??;
        if env.content_type == TTY_STDOUT {
            stdout.extend(env.payload);
        }
    }
    let listing = String::from_utf8_lossy(&stdout).into_owned();

    let outcome = timeout(WAIT, run).await????;
    assert_eq!(outcome.guest_exit, Some(0), "console: {}", outcome.console);

    // Only the job's own printout: between its two markers, past the echoed command line.
    let listing = listing
        .rsplit_once("ENVSTART")
        .and_then(|(_, rest)| rest.split_once("ENVEND"))
        .map_or("", |(listing, _)| listing);
    let pairs: Vec<(&str, &str)> = listing.lines().filter_map(|l| l.split_once('=')).collect();

    // The guest login environment is visible: `LOGNAME` is set by the
    // guest's own login shell, never by this test or the job's command.
    assert!(
        pairs.iter().any(|(k, v)| *k == LOGIN_VAR_NAME && !v.is_empty()),
        "the job saw no value for the guest login shell's own {LOGIN_VAR_NAME}: {listing}"
    );

    // The staged secret reaches the job as a real exported variable, not
    // just a file under a secrets dir (the VM path, unlike the process
    // backend's $SANDY_SECRETS_DIR).
    assert!(
        pairs
            .iter()
            .any(|(k, v)| *k == SECRET_NAME && *v == String::from_utf8_lossy(SECRET_VALUE)),
        "the job did not see the staged secret {SECRET_NAME} exported: {listing}"
    );

    // The host's own value never crosses into the guest — the key alone
    // isn't proof (a guest image could independently define `$CARGO` for
    // its own reasons), the host's specific value is.
    assert!(
        !pairs
            .iter()
            .any(|(k, v)| *k == HOST_MARKER_NAME && *v == host_marker_value),
        "the host's own {HOST_MARKER_NAME} value leaked into the guest job: {listing}"
    );

    relay_result(&relay).await??;
    Ok(())
}
