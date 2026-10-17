//! The all-local MVP library scenario (issue #115's real acceptance, built on
//! top of increment 1/2's composition gate).
//!
//! Discover a host, open its orchestrator channel, bridge a job's TTY over it
//! via the real `SandboxAgent`, grow into a peer-group, and escalate to a
//! (fake) human backend — end to end, through real library code: `Channel`
//! (#106), `SandboxAgent` (#109), `LocalCapAuthority` (#110), placement
//! (#112), the role wrappers (#113), and the real `Executor` (#108).
//!
//! `Channel`'s membership is deliberately per-instance, not globally shared: a
//! party registers itself by calling `join` on its OWN `Channel` handle (over
//! a shared backend + authority), not by reading a global membership table.
//! So "two parties on one channel" here means two `Channel` instances wrapping
//! clones of the same `InMem` backend and the same authority (made cheaply
//! shareable via [`SharedAuthority`], since `LocalCapAuthority` itself isn't
//! `Clone` — its revocation state must stay one shared set, not forked).
//!
//! The orchestrator channel's bidirectional TTY traffic is the one place here
//! with two concurrent writers (the orchestrator posts stdin while the agent
//! posts stdout/stderr), so it uses one `Arc`-shared `Channel` instance for
//! both — `Channel::new`'s own doc is explicit that concurrent multi-instance
//! writers against one backend are unsafe (each instance's sequence counter is
//! computed once, at construction). This is a property of running the
//! orchestrator and agent in the SAME process for this scenario, not a
//! limitation of the deployed design: once #216 lands, the agent process is
//! the relay between the job and the channel, and the relay is the single
//! writer serializing both directions — the two-writer case this scenario
//! works around here doesn't arise there.
//!
//! Two things this does NOT claim, both load-bearing:
//! - **Agent process isolation.** `SandboxAgent` is a library type; no `sandy-agent` binary exists for an executor to
//!   spawn (tracked in #216). Here the agent runs in-process as an async task, driving its real `bootstrap`/`serve_tty`
//!   against a directly-spawned child process standing in for "the job" — this proves the channel/role/agent-library
//!   coordination, not OS-process isolation.
//! - **A real human-facing escalation transport.** Spec §3.4 defers which transport an escalation actually rides
//!   (mobile push, IPC, ...); this uses `sandy_fabric::contract::fakes::FakeHumanBackend` deliberately, not as a
//!   `FAKED_SEAMS` entry pending a block — there is no block for it.
//!
//! This proves all-local multi-sandbox coordination on one machine.
//! Cross-machine (sandyd + a real transport) is a separate, later epic.

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use futures_util::StreamExt as _;
use sandy_api::backend::SandboxKind;
use sandy_backend::ProcessBackend;
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights, CapScope, decode_cap, encode_cap},
    channel_backend::ChannelBackendError,
    contract::fakes::FakeHumanBackend,
    escalation::EscalationMessage,
    executor::{Arch, Capabilities, Requirements},
    placement::Lifecycle as _,
    roles::{ChannelAssignment, ChannelRole, decode_assignment},
    types::{ChannelId, HostId, PeerId},
};
use sandy_fabric_local::{
    LocalCapAuthority,
    agent::{SandboxAgent, TTY_STDOUT},
    channel::{Channel, ChannelError},
    executor::VmBackendExecutor,
    inmem::InMem,
    placement::{ExecutorCapacity, LeaseTable, StaticRegistry, place},
    roles::{EscalationRole, OrchestratorRole, PeerGroupRole},
};

/// Makes `LocalCapAuthority` cheaply shareable across the several `Channel`
/// instances one logical channel needs (one per party) without forking its
/// revocation state — `LocalCapAuthority` itself can't be `Clone` for exactly
/// that reason (the revocation set must stay one shared thing, not copies).
#[derive(Clone)]
struct SharedAuthority(Arc<LocalCapAuthority>);

impl CapAuthority for SharedAuthority {
    fn mint(&self, scope: CapScope) -> Result<Cap, CapError> {
        self.0.mint(scope)
    }

    fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
        self.0.verify(cap)
    }

    fn attenuate(&self, parent: &Cap, rights: CapRights) -> Result<Cap, CapError> {
        self.0.attenuate(parent, rights)
    }
}

type Backend = InMem;
type Authority = SharedAuthority;

fn host_arch() -> Arch {
    match std::env::consts::ARCH {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::Aarch64,
        other => panic!("unsupported host architecture for this scenario test: {other}"),
    }
}

fn full_rights() -> CapRights {
    CapRights {
        post: true,
        read: true,
        invite: true,
    }
}

fn sandbox_rights() -> CapRights {
    CapRights {
        post: true,
        read: true,
        invite: false,
    }
}

/// One sandbox's orchestrator channel. The 1:1 invariant (exactly one
/// orchestrator channel per sandbox, exactly one non-orchestrator membership
/// on it) holds by construction, not by a runtime membership count: `Channel`
/// is a generic bounded-membership primitive with no such limit (deliberate —
/// spec §3.4), so this type is the only thing that can actually guarantee it.
/// [`Self::launch`] is the only way to create one; it mints exactly one
/// bootstrap cap as part of construction and exposes no method to mint a
/// second — a caller holding a `LaunchedChannel` has no API path to invite a
/// second sandbox onto it.
struct LaunchedChannel {
    backend: Backend,
    authority: Authority,
    id: ChannelId,
    /// `Arc`-shared from construction: whoever needs to post *concurrently*
    /// with another party (the orchestrator channel's bidirectional TTY
    /// traffic is the one case in this scenario) must go through this SAME
    /// instance, via `Arc::clone` — not a second `Channel::new` over the same
    /// backend. `Channel::new`'s own doc is explicit that concurrent
    /// multi-instance writers against one backend are unsafe (sequence
    /// numbers are computed once, at construction, per instance); that's the
    /// documented single-writer-MVP limit, not something this test works
    /// around. A SEQUENTIAL second instance (constructed only after this
    /// one's writes are done, never concurrently) is fine — see
    /// [`Self::join_as_new_party`] — because its own sequence counter is
    /// computed from the backend's state at that later point.
    orchestrator: Arc<Channel<Backend, Authority>>,
    orchestrator_membership: sandy_fabric_local::channel::MembershipId,
}

impl LaunchedChannel {
    /// Mint a fresh channel, join it as the orchestrator, and mint the one
    /// cap for whoever else joins (`rights` scopes what they get).
    async fn launch(id: ChannelId, default_ttl: Duration, member_rights: CapRights) -> anyhow::Result<(Self, Vec<u8>)> {
        let authority = SharedAuthority(Arc::new(
            LocalCapAuthority::new(default_ttl).map_err(|e| anyhow::anyhow!("authority: {e}"))?,
        ));
        let backend = Backend::default();
        let orchestrator_cap = authority
            .mint(CapScope {
                peer: PeerId::from("orchestrator"),
                channel: id.clone(),
                rights: full_rights(),
                expires_at: None,
            })
            .map_err(|e| anyhow::anyhow!("mint orchestrator cap: {e}"))?;
        let orchestrator = Arc::new(
            Channel::new(id.clone(), backend.clone(), authority.clone())
                .await
                .context("Channel::new (orchestrator view)")?,
        );
        let orchestrator_membership = orchestrator
            .join(&orchestrator_cap)
            .context("orchestrator joins its own channel")?;
        let member_cap = orchestrator
            .invite(&orchestrator_membership, member_rights)
            .context("mint the one member cap")?;
        let member_cap_bytes = encode_cap(&member_cap).context("encode member cap")?;
        Ok((
            Self {
                backend,
                authority,
                id,
                orchestrator,
                orchestrator_membership,
            },
            member_cap_bytes,
        ))
    }

    /// A second party's own, exclusive view of the same channel: a fresh
    /// `Channel` instance over a clone of the same backend + shared
    /// authority. Safe only when nothing else posts on [`Self::orchestrator`]
    /// concurrently with this instance's own posts (see the field doc) —
    /// every caller here either only reads from the resulting instance, or
    /// uses it after the shared instance's writes have already finished.
    async fn join_as_new_party(&self) -> anyhow::Result<Channel<Backend, Authority>> {
        Channel::new(self.id.clone(), self.backend.clone(), self.authority.clone())
            .await
            .context("Channel::new (new party view)")
    }

    /// A fresh orchestrator-side view: a new instance (see
    /// [`Self::join_as_new_party`]'s safety note), minted and joined fresh
    /// with full rights — `members` is per-instance, so a new instance always
    /// starts with no memberships of its own regardless of what the original
    /// orchestrator instance already joined.
    async fn join_as_new_orchestrator(
        &self,
    ) -> anyhow::Result<(Channel<Backend, Authority>, sandy_fabric_local::channel::MembershipId)> {
        let channel = self.join_as_new_party().await?;
        let cap = self
            .authority
            .mint(CapScope {
                peer: PeerId::from("orchestrator"),
                channel: self.id.clone(),
                rights: full_rights(),
                expires_at: None,
            })
            .map_err(|e| anyhow::anyhow!("mint a fresh orchestrator cap: {e}"))?;
        let membership = channel.join(&cap).context("orchestrator joins its new view")?;
        Ok((channel, membership))
    }
}

/// Positive: the full scenario, all real seams/components wired together.
#[tokio::test(flavor = "multi_thread")]
async fn the_all_local_scenario_runs_end_to_end() -> anyhow::Result<()> {
    // ---- Discover a host (real Discovery + Capacity + Lifecycle + place) ----
    let caps = Capabilities {
        kind: SandboxKind::Process,
        arch: host_arch(),
        attestation: None,
    };
    let discovery = StaticRegistry::localhost(caps.kind, caps.arch);
    let host_id = HostId::from(StaticRegistry::LOCALHOST);
    let capacity = ExecutorCapacity::new().with_host(host_id.clone(), VmBackendExecutor::new(ProcessBackend::new()), 1);
    let lifecycle = LeaseTable::new(Duration::from_secs(60));
    lifecycle
        .register(host_id.clone())
        .await
        .context("register the host's lease")?;
    let req = Requirements {
        kind: SandboxKind::Process,
        arch: None,
    };
    let placed = place(&discovery, &lifecycle, &capacity, &req)
        .await
        .context("place")?
        .context("a host should have been placed")?;
    assert_eq!(placed, host_id, "the only registered host is the one placed");

    // ---- Launch the sandbox's orchestrator channel (the 1:1 invariant) ----
    let (launched, bootstrap_cap_bytes) =
        LaunchedChannel::launch(ChannelId::from("orch-1"), Duration::from_secs(300), sandbox_rights())
            .await
            .context("launch the sandbox's orchestrator channel")?;

    // ---- The agent bootstraps in-process (no sandy-agent binary exists yet
    // to spawn as its own OS process — #216), sharing the ONE orchestrator
    // Channel instance with the orchestrator's own posts below: this channel
    // is the bidirectional-TTY case, the one place in this scenario with two
    // concurrent writers, so it must stay one Arc-shared instance (see
    // LaunchedChannel's field doc) rather than a second Channel::new. ----
    let agent = SandboxAgent::bootstrap(
        Arc::clone(&launched.orchestrator),
        std::io::Cursor::new(bootstrap_cap_bytes),
    )
    .context("agent bootstrap")?;

    // ---- Dispatch a job: the agent bridges a directly-spawned child's stdio
    // over the orchestrator channel's TTY traffic (standing in for "the
    // executor hands the agent a job to supervise" — also #216's scope) ----
    let mut job = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("read line; echo \"got: $line\"")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn the stand-in job")?;
    let job_stdin = job.stdin.take().context("job stdin")?;
    let job_stdout = job.stdout.take().context("job stdout")?;
    let job_stderr = job.stderr.take().context("job stderr")?;

    let orchestrator_subscribe = launched
        .orchestrator
        .subscribe(&launched.orchestrator_membership)
        .context("orchestrator subscribes")?;
    let agent_membership = agent.membership().clone();
    let serve_tty = tokio::spawn(async move { agent.serve_tty(job_stdout, job_stderr, job_stdin).await });

    launched
        .orchestrator
        .post(
            &launched.orchestrator_membership,
            Some(sandy_proto::MessageType::Tty(sandy_proto::Tty {})),
            sandy_fabric_local::agent::TTY_STDIN,
            b"hello\n".to_vec(),
        )
        .await
        .context("orchestrator posts TTY_STDIN")?;

    let stdout_text = read_tty_stdout_until(orchestrator_subscribe, "got: hello").await?;
    assert!(
        stdout_text.contains("got: hello"),
        "the job's stdout streamed back: {stdout_text:?}"
    );

    let job_status = job.wait().await.context("job exit")?;
    assert!(job_status.success(), "the stand-in job exited cleanly");
    serve_tty.await.context("join serve_tty")??;

    // ---- A peer-group coordinates: the orchestrator assigns a peer-group
    // channel to the sandbox; the sandbox side (standing in for "the agent's
    // channel-growth logic", not yet wired into SandboxAgent itself) decodes
    // the assignment and joins ----
    let (peer_group, member_cap_bytes) = LaunchedChannel::launch(
        ChannelId::from("peer-group-1"),
        Duration::from_secs(300),
        sandbox_rights(),
    )
    .await
    .context("launch the peer-group")?;
    // `join_as_new_orchestrator`, not `join_as_new_party` +
    // `peer_group.orchestrator_membership`: a fresh instance's `members` map
    // is empty, so the original instance's membership id means nothing on it
    // — it has to join fresh, with its own cap, on its own instance.
    let (orchestrator_peer_channel, orchestrator_peer_membership) = peer_group
        .join_as_new_orchestrator()
        .await
        .context("orchestrator's peer-group view")?;
    let orchestrator_peer_role = PeerGroupRole::new(orchestrator_peer_channel, orchestrator_peer_membership);
    // A fresh instance for the orchestrator's channel, constructed only now —
    // the TTY exchange's writes are already done (serve_tty has returned, no
    // more concurrent posts), so this instance's sequence counter correctly
    // picks up after them (see LaunchedChannel's field doc on why that
    // ordering matters). Exercises the REAL OrchestratorRole API (not a
    // manual encode/decode) to post the ChannelAssignment.
    let (orchestrator_fresh_channel, orchestrator_fresh_membership) = launched
        .join_as_new_orchestrator()
        .await
        .context("orchestrator role's own view")?;
    let orchestrator_role = OrchestratorRole::new(orchestrator_fresh_channel, orchestrator_fresh_membership);
    let assignment = ChannelAssignment {
        channel_id: peer_group.id.clone(),
        cap: decode_cap(&member_cap_bytes).context("decode member cap")?,
        role: ChannelRole::PeerGroup,
    };
    orchestrator_role
        .assign_channel(&assignment)
        .await
        .context("orchestrator assigns the peer-group channel")?;

    // The sandbox side reads the assignment off its own orchestrator-channel
    // subscription and acts on it — standing in for logic SandboxAgent itself
    // doesn't yet implement (it only bootstraps + bridges TTY).
    // This subscription starts fresh at sequence 0 (cursors are per-membership
    // on this one shared instance, same as any other subscribe), so it also
    // sees the earlier TTY_STDIN/TTY_STDOUT traffic — skip to the Control one.
    let mut agent_orchestrator_subscribe = launched
        .orchestrator
        .subscribe(&agent_membership)
        .context("agent subscribes to its own orchestrator channel")?;
    let assignment_env = next_control_envelope(&mut agent_orchestrator_subscribe).await?;
    let received_assignment =
        decode_assignment(&assignment_env.payload).context("decode the received ChannelAssignment")?;
    assert_eq!(
        received_assignment.role,
        ChannelRole::PeerGroup,
        "the assignment's role round-trips"
    );

    let sandbox_peer_channel = peer_group
        .join_as_new_party()
        .await
        .context("sandbox's peer-group view")?;
    let sandbox_peer_membership = sandbox_peer_channel
        .join(&received_assignment.cap)
        .context("sandbox joins the peer-group with the assigned cap")?;
    let sandbox_peer_role = PeerGroupRole::new(sandbox_peer_channel, sandbox_peer_membership);

    let mut sandbox_peer_subscription = sandbox_peer_role
        .subscribe()
        .context("sandbox subscribes to the peer-group")?;
    orchestrator_peer_role
        .post(b"peers coordinate here".to_vec())
        .await
        .context("orchestrator-side peer posts")?;
    let peer_env = next_envelope(&mut sandbox_peer_subscription).await?;
    assert_eq!(
        peer_env.payload, b"peers coordinate here",
        "the peer-group message round-trips"
    );

    // ---- Escalation reaches a (fake) human backend ----
    let (escalation, escalation_cap_bytes) = LaunchedChannel::launch(
        ChannelId::from("escalation-1"),
        Duration::from_secs(300),
        sandbox_rights(),
    )
    .await
    .context("launch the escalation channel")?;
    let escalation_channel = escalation
        .join_as_new_party()
        .await
        .context("sandbox's escalation view")?;
    let escalation_cap = decode_cap(&escalation_cap_bytes).context("decode escalation cap")?;
    let escalation_membership = escalation_channel
        .join(&escalation_cap)
        .context("sandbox joins the escalation channel")?;
    let escalation_role = EscalationRole::new(escalation_channel, escalation_membership, FakeHumanBackend::new(true));
    escalation_role
        .escalate(&EscalationMessage {
            from: PeerId::from("sandbox-1"),
            reason: "needs a human".to_owned(),
        })
        .await
        .context("escalate")?;
    assert_eq!(
        escalation_role.sink().captured(),
        1,
        "the escalation reached the (fake) human backend"
    );

    Ok(())
}

async fn read_tty_stdout_until(
    stream: impl futures_core::Stream<Item = Result<sandy_proto::Envelope, ChannelBackendError>> + Unpin,
    marker: &str,
) -> anyhow::Result<String> {
    let mut stream = std::pin::pin!(stream);
    let mut out = String::new();
    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => anyhow::bail!("timed out waiting for {marker:?}, got {out:?}"),
            item = stream.next() => {
                let env = item.context("stream ended")?.context("stream errored")?;
                if env.content_type == TTY_STDOUT {
                    out.push_str(&String::from_utf8_lossy(&env.payload));
                    if out.contains(marker) {
                        return Ok(out);
                    }
                }
            }
        }
    }
}

/// Skip envelopes until a `Control`-typed one (e.g. a `ChannelAssignment`).
async fn next_control_envelope(
    stream: &mut (impl futures_core::Stream<Item = Result<sandy_proto::Envelope, ChannelBackendError>> + Unpin),
) -> anyhow::Result<sandy_proto::Envelope> {
    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => anyhow::bail!("timed out waiting for a Control envelope"),
            item = stream.next() => {
                let env = item.context("stream ended")?.context("stream errored")?;
                if matches!(env.message_type, Some(sandy_proto::MessageType::Control(_))) {
                    return Ok(env);
                }
            }
        }
    }
}

async fn next_envelope(
    stream: &mut (impl futures_core::Stream<Item = Result<sandy_proto::Envelope, ChannelBackendError>> + Unpin),
) -> anyhow::Result<sandy_proto::Envelope> {
    tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .context("stream did not yield before the deadline")?
        .context("stream ended")?
        .context("stream errored")
}

/// Adversarial: the 1:1 orchestrator-channel invariant. `LaunchedChannel` is
/// the only way to mint an orchestrator channel and its one bootstrap cap,
/// and it exposes no method to mint a second cap for an already-launched
/// channel — the type itself has no API path to do that (held by
/// construction, not a runtime count). What's worth testing at runtime: a cap
/// from one sandbox's launch cannot be used to join a DIFFERENT sandbox's
/// channel, so a confused or cross-wired cap can never let one sandbox
/// eavesdrop on or impersonate another.
///
/// This rejects even more strongly than a channel-scope mismatch: each
/// `launch` mints its own fresh, randomly-keyed `LocalCapAuthority` (spec
/// §3.8's per-instance key, never shared), so a cap from a different launch
/// fails cryptographic verification outright (`CapError::Forged`) before the
/// channel-id comparison is ever reached — two sandboxes' caps aren't just
/// scoped differently, they're signed under entirely different keys.
#[tokio::test(flavor = "multi_thread")]
async fn a_cap_from_one_launch_cannot_join_a_different_launch() -> anyhow::Result<()> {
    let (_launch_a, cap_a_bytes) =
        LaunchedChannel::launch(ChannelId::from("sandbox-a"), Duration::from_secs(300), sandbox_rights())
            .await
            .context("launch sandbox-a")?;
    let (launch_b, _cap_b_bytes) =
        LaunchedChannel::launch(ChannelId::from("sandbox-b"), Duration::from_secs(300), sandbox_rights())
            .await
            .context("launch sandbox-b")?;

    let cap_a = decode_cap(&cap_a_bytes).context("decode sandbox-a's cap")?;
    let b_view = launch_b
        .join_as_new_party()
        .await
        .context("a view of sandbox-b's channel")?;
    let result = b_view.join(&cap_a);
    let err = result
        .err()
        .context("a cap from a different sandbox's launch must be rejected")?;
    assert!(
        matches!(err, ChannelError::Cap(sandy_fabric::capauth::CapError::Forged)),
        "expected Cap(Forged), got {err:?}"
    );
    Ok(())
}
