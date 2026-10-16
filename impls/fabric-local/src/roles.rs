//! Channel roles (spec §3.4, #113): thin, domain-named wrappers over
//! [`Channel`]. Boundedness, capability verification and dedup/ordering all
//! live in `Channel` itself (#106); a role adds nothing to that — it just names
//! the operations a given channel is used for and, for the orchestrator and
//! escalation roles, the extra seam each one feeds.
//!
//! - [`OrchestratorRole`] — control (assigns further channels via a [`ChannelAssignment`]) plus the orchestrator
//!   channel's optional-telemetry leg: it implements [`TelemetrySink`], so `LocalFirst::new(log, orchestrator_role)`
//!   (#114) forwards every local record there.
//! - [`PeerGroupRole`] — post/subscribe plus `invite_subagent`, which is `Channel::invite` under a role-scoped name;
//!   the closed-membership boundedness it provides is entirely `Channel::join`'s existing wrong-channel rejection,
//!   nothing new here.
//! - [`EscalationRole`] — posts to its own channel AND notifies an [`EscalationSink`] independently, so one path being
//!   down does not lose the escalation; both paths failing is the only failure. The channel SHAPE (who posts, who's a
//!   member, the `Escalate` marker) is the in-fabric contract; which sink implementation reaches a human (push, IPC, …)
//!   is an operator decision deferred past step-1 (spec §9).

use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapRights},
    channel_backend::ChannelBackend,
    escalation::{EscalationMessage, EscalationSink},
    roles::{AssignmentCodecError, ChannelAssignment, encode_assignment},
    telemetry::{TelemetryError, TelemetryRecord, TelemetrySink},
};
use sandy_proto::{Control, Escalate, MessageType, PeerMsg};

use crate::channel::{Channel, ChannelError, MembershipId};

/// JSON content type for a structured payload that is not an `encode_cap`-style
/// bearer credential blob, matching [`sandy_fabric::roles`]'s own choice for
/// [`ChannelAssignment`] (the proto's per-type contracts are deferred; structured
/// content rides in the opaque payload, see envelope.proto).
const CONTENT_TYPE_JSON: &str = "application/json";

/// A role failure: either the underlying channel, or encoding the role's own
/// payload.
#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    /// The channel call failed.
    #[error(transparent)]
    Channel(#[from] ChannelError),
    /// The role's own payload (a [`ChannelAssignment`] or [`EscalationMessage`])
    /// could not be encoded.
    #[error("payload codec: {0}")]
    Codec(String),
    /// Both the escalation channel post and the sink notify failed: the only
    /// case [`EscalationRole::escalate`] reports as an outright failure.
    #[error("escalation delivered nowhere: channel: {channel}; sink: {sink}")]
    BothEscalationPathsFailed {
        /// The channel post's error.
        channel: String,
        /// The sink notify's error.
        sink: String,
    },
}

impl From<AssignmentCodecError> for RoleError {
    fn from(e: AssignmentCodecError) -> Self {
        Self::Codec(e.to_string())
    }
}

/// The orchestrator channel (spec §3.4): control (assigns channels + caps) plus
/// TTY/output recording and optional telemetry. This wrapper covers the control
/// leg and the [`TelemetrySink`] leg; TTY/output posting is the same `Channel`
/// underneath and does not need a role-specific method of its own yet.
pub struct OrchestratorRole<B, A> {
    channel: Channel<B, A>,
    membership: MembershipId,
}

impl<B: ChannelBackend, A: CapAuthority> OrchestratorRole<B, A> {
    /// Wrap `channel`, posting as `membership` (the orchestrator's own join).
    pub fn new(channel: Channel<B, A>, membership: MembershipId) -> Self {
        Self { channel, membership }
    }

    /// Grow a sandbox's membership: post `assignment` as a `Control` envelope.
    /// The agent on the other end decodes it and joins the named channel with
    /// the carried cap (#109) — this call only posts; it does not itself verify
    /// the agent received or acted on it (store-and-forward, no handshake,
    /// per the roles↔agent seam locked with #109's agent-bootstrap design).
    ///
    /// # Errors
    /// [`RoleError::Codec`] if `assignment` cannot be encoded; otherwise
    /// whatever [`Channel::post`] returns (not a member, missing `post` right,
    /// or a backend failure).
    pub async fn assign_channel(&self, assignment: &ChannelAssignment) -> Result<String, RoleError> {
        let payload = encode_assignment(assignment)?;
        Ok(self
            .channel
            .post(
                &self.membership,
                Some(MessageType::Control(Control {})),
                CONTENT_TYPE_JSON,
                payload,
            )
            .await?)
    }
}

impl<B: ChannelBackend, A: CapAuthority> TelemetrySink for OrchestratorRole<B, A> {
    /// Always available once constructed: the orchestrator channel has no
    /// separate on/off switch of its own. The actual "telemetry off by default"
    /// gate lives one layer up, in [`LocalFirst`](sandy_fabric_local::telemetry::LocalFirst)'s
    /// own `enabled()`, which never even calls this before posting.
    fn enabled(&self) -> bool {
        true
    }

    /// Forward `record` as a `Telemetry`-typed envelope. A channel failure here
    /// is a telemetry-sink error, not fatal to the caller — matches every other
    /// forwarding sink's contract (see `LocalFirst`'s own forward-failure
    /// handling, which logs and continues).
    async fn emit(&self, record: &TelemetryRecord) -> Result<(), TelemetryError> {
        let payload = serde_json::to_vec(record).map_err(|e| TelemetryError::Sink(e.to_string()))?;
        self.channel
            .post(
                &self.membership,
                Some(MessageType::Telemetry(sandy_proto::Telemetry {})),
                CONTENT_TYPE_JSON,
                payload,
            )
            .await
            .map(|_id| ())
            .map_err(|e| TelemetryError::Sink(e.to_string()))
    }
}

/// The peer-group channel (spec §3.4): a closed set of agents coordinating
/// directly. Boundedness (a member cannot reach outside the group) is entirely
/// `Channel::join`'s existing wrong-channel rejection; this wrapper adds no
/// security logic of its own.
pub struct PeerGroupRole<B, A> {
    channel: Channel<B, A>,
    membership: MembershipId,
}

impl<B: ChannelBackend, A: CapAuthority> PeerGroupRole<B, A> {
    /// Wrap `channel`, posting/inviting as `membership`.
    pub fn new(channel: Channel<B, A>, membership: MembershipId) -> Self {
        Self { channel, membership }
    }

    /// Post `payload` as a `PeerMsg`-typed envelope to the group.
    ///
    /// # Errors
    /// Whatever [`Channel::post`] returns.
    pub async fn post(&self, payload: Vec<u8>) -> Result<String, ChannelError> {
        self.channel
            .post(
                &self.membership,
                Some(MessageType::PeerMsg(PeerMsg {})),
                CONTENT_TYPE_JSON,
                payload,
            )
            .await
    }

    /// Subscribe to the group's messages.
    ///
    /// # Errors
    /// Whatever [`Channel::subscribe`] returns.
    pub fn subscribe(
        &self,
    ) -> Result<
        impl futures_core::Stream<
            Item = Result<sandy_fabric::channel_backend::Envelope, sandy_fabric::channel_backend::ChannelBackendError>,
        > + Send
        + 'static,
        ChannelError,
    > {
        self.channel.subscribe(&self.membership)
    }

    /// Request an attenuated cap for a sub-agent that will join as this
    /// membership's representative (`Channel::invite` under a role-scoped
    /// name): same principal, same channel, only narrower rights.
    ///
    /// # Errors
    /// Whatever [`Channel::invite`] returns ([`ChannelError::InsufficientRights`]
    /// if this membership lacks `invite`).
    pub fn invite_subagent(&self, rights: CapRights) -> Result<Cap, ChannelError> {
        self.channel.invite(&self.membership, rights)
    }
}

/// The escalation channel (spec §3.4): separate by design, targets a human on
/// any device, independent of where the orchestrator sits. `escalate` posts to
/// its own `Channel` (a genuinely separate backend from the orchestrator's —
/// that separation, not any logic here, is what gives "delivers when the
/// orchestrator is down") AND notifies `sink` independently; either succeeding
/// is enough.
pub struct EscalationRole<B, A, S> {
    channel: Channel<B, A>,
    membership: MembershipId,
    sink: S,
}

impl<B: ChannelBackend, A: CapAuthority, S: EscalationSink> EscalationRole<B, A, S> {
    /// Wrap `channel`, posting as `membership`, notifying `sink` on every
    /// escalation alongside the post.
    pub fn new(channel: Channel<B, A>, membership: MembershipId, sink: S) -> Self {
        Self {
            channel,
            membership,
            sink,
        }
    }

    /// The wrapped sink, for a caller (or a test) that needs to inspect it.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Escalate `message`: post it as an `Escalate`-typed envelope and notify
    /// the sink, independently. Succeeds if either delivers; a channel or sink
    /// failure alone is logged and does not fail the call — only both failing
    /// does, per [`RoleError::BothEscalationPathsFailed`].
    ///
    /// # Errors
    /// [`RoleError::Codec`] if `message` cannot be encoded;
    /// [`RoleError::BothEscalationPathsFailed`] if neither the channel post nor
    /// the sink notify succeeded.
    pub async fn escalate(&self, message: &EscalationMessage) -> Result<(), RoleError> {
        let payload = serde_json::to_vec(message).map_err(|e| RoleError::Codec(e.to_string()))?;
        let channel_result = self
            .channel
            .post(
                &self.membership,
                Some(MessageType::Escalate(Escalate {})),
                CONTENT_TYPE_JSON,
                payload,
            )
            .await;
        let sink_result = self.sink.notify(message).await;
        match (channel_result, sink_result) {
            (Ok(_), Ok(())) => Ok(()),
            (Err(c), Ok(())) => {
                tracing::warn!(error = %c, "escalation channel post failed; delivered via the sink only");
                Ok(())
            }
            (Ok(_), Err(s)) => {
                tracing::warn!(error = %s, "escalation sink notify failed; delivered via the channel only");
                Ok(())
            }
            (Err(c), Err(s)) => Err(RoleError::BothEscalationPathsFailed {
                channel: c.to_string(),
                sink: s.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Mutex, PoisonError},
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Context;
    use futures_core::Stream;
    use futures_util::StreamExt;
    use sandy_fabric::{
        capauth::{CapError, CapScope},
        channel_backend::{ChannelBackendError, Envelope},
        types::{ChannelId, PeerId},
    };

    use super::*;
    use crate::inmem::InMem;

    /// A minimal [`CapAuthority`] test double, mirroring `channel.rs`'s own
    /// (private to its test module, so this is its own small copy rather than a
    /// cross-module reuse — the established pattern here, see that module's own
    /// comment on the same tradeoff).
    #[derive(Default, Clone)]
    struct TestAuthority;

    impl TestAuthority {
        fn proof(scope: &CapScope) -> Vec<u8> {
            format!(
                "{}:{}:{:?}:{:?}",
                scope.peer.0, scope.channel.0, scope.rights, scope.expires_at
            )
            .into_bytes()
        }
    }

    impl CapAuthority for TestAuthority {
        fn mint(&self, scope: CapScope) -> Result<Cap, CapError> {
            let proof = Self::proof(&scope);
            Ok(Cap { scope, proof })
        }

        fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
            if cap.proof != Self::proof(&cap.scope) {
                return Err(CapError::Forged);
            }
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
            if cap.scope.expires_at.is_some_and(|t| t <= now) {
                return Err(CapError::Expired);
            }
            Ok(cap.scope.clone())
        }

        fn attenuate(&self, parent: &Cap, rights: CapRights) -> Result<Cap, CapError> {
            let scope = self.verify(parent)?;
            if !rights.is_subset_of(&scope.rights) {
                return Err(CapError::Widened);
            }
            self.mint(CapScope { rights, ..scope })
        }
    }

    fn full() -> CapRights {
        CapRights {
            post: true,
            read: true,
            invite: true,
        }
    }

    fn read_only() -> CapRights {
        CapRights {
            read: true,
            ..CapRights::default()
        }
    }

    fn mint(authority: &TestAuthority, peer: &str, channel: &ChannelId, rights: CapRights) -> Cap {
        authority
            .mint(CapScope {
                peer: PeerId::from(peer),
                channel: channel.clone(),
                rights,
                expires_at: None,
            })
            .expect("mint")
    }

    /// A fresh in-memory channel plus the raw backend/authority handles (both
    /// `Clone`), so a test can construct a second membership's `Channel` over
    /// the same underlying store, or inspect the backend directly.
    async fn new_channel(id: &str) -> anyhow::Result<(Channel<InMem, TestAuthority>, InMem, ChannelId, TestAuthority)> {
        let id = ChannelId::from(id);
        let backend = InMem::default();
        let authority = TestAuthority;
        let channel = Channel::new(id.clone(), backend.clone(), authority.clone())
            .await
            .context("Channel::new")?;
        Ok((channel, backend, id, authority))
    }

    async fn next(stream: &mut (impl Stream<Item = Result<Envelope, ChannelBackendError>> + Unpin)) -> Envelope {
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("stream yielded before the deadline")
            .expect("stream did not end")
            .expect("stream did not error")
    }

    // ---- OrchestratorRole ----

    #[tokio::test]
    async fn orchestrator_assigns_a_channel_and_the_payload_round_trips() -> anyhow::Result<()> {
        let (channel, backend, orch_id, authority) = new_channel("orchestrator").await?;
        let orch_cap = mint(&authority, "orchestrator", &orch_id, full());
        let membership = channel.join(&orch_cap).context("orchestrator joins its own channel")?;
        let role = OrchestratorRole::new(channel, membership);

        let peer_group_id = ChannelId::from("peer-group-1");
        let assignment = ChannelAssignment {
            channel_id: peer_group_id.clone(),
            cap: mint(&authority, "sandbox-1", &peer_group_id, full()),
            role: sandy_fabric::roles::ChannelRole::PeerGroup,
        };
        role.assign_channel(&assignment).await.context("assign_channel")?;

        let stored = backend.fetch(0).await.context("fetch")?;
        anyhow::ensure!(stored.len() == 1, "expected one stored envelope, got {}", stored.len());
        anyhow::ensure!(
            matches!(stored[0].message_type, Some(sandy_proto::MessageType::Control(_))),
            "assignment must post as a Control envelope, got {:?}",
            stored[0].message_type
        );
        let decoded = sandy_fabric::roles::decode_assignment(&stored[0].payload).context("decode_assignment")?;
        anyhow::ensure!(decoded == assignment, "the assignment changed in transit");
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_role_forwards_telemetry_as_a_telemetry_envelope() -> anyhow::Result<()> {
        use sandy_fabric::telemetry::{TelemetryRecord, TelemetrySink};

        let (channel, backend, orch_id, authority) = new_channel("orchestrator").await?;
        let cap = mint(&authority, "orchestrator", &orch_id, full());
        let membership = channel.join(&cap).context("join")?;
        let role = OrchestratorRole::new(channel, membership);

        let record = TelemetryRecord {
            kind: "job_started".to_owned(),
            fields: std::collections::BTreeMap::new(),
        };
        anyhow::ensure!(role.enabled(), "OrchestratorRole must always report enabled");
        role.emit(&record).await.context("emit")?;

        let stored = backend.fetch(0).await.context("fetch")?;
        anyhow::ensure!(
            matches!(stored[0].message_type, Some(sandy_proto::MessageType::Telemetry(_))),
            "telemetry must forward as a Telemetry envelope, got {:?}",
            stored[0].message_type
        );
        Ok(())
    }

    // ---- PeerGroupRole ----

    #[tokio::test]
    async fn peer_group_members_talk_and_a_subagent_joins_via_an_attenuated_cap() -> anyhow::Result<()> {
        // Two `Channel` instances over the same `InMem` + authority (both
        // `Clone`), one per role: `Channel` itself holds no shared-ownership
        // wrapper, so a second member needs its own instance over the same
        // underlying store, mirroring channel.rs's own multi-instance tests.
        let (parent_channel, backend, group_id, authority) = new_channel("peer-group").await?;
        let parent_cap = mint(&authority, "parent", &group_id, full());
        let parent_membership = parent_channel.join(&parent_cap).context("parent joins")?;

        // The attenuated cap travels out of band; the sub-agent's holder still
        // calls `join` itself (Channel is not a minting authority).
        let parent_role = PeerGroupRole::new(parent_channel, parent_membership);
        let sub_cap = parent_role.invite_subagent(read_only()).context("invite_subagent")?;
        anyhow::ensure!(
            !sub_cap.scope.rights.post,
            "an attenuated cap must not gain post rights"
        );

        let sub_channel = Channel::new(group_id, backend, authority)
            .await
            .context("sub Channel::new")?;
        let sub_membership = sub_channel
            .join(&sub_cap)
            .context("sub-agent joins with the attenuated cap")?;
        let sub_role = PeerGroupRole::new(sub_channel, sub_membership);

        let mut stream = std::pin::pin!(sub_role.subscribe().context("subscribe")?);
        parent_role.post(b"hello group".to_vec()).await.context("post")?;
        let received = next(&mut stream).await;
        anyhow::ensure!(
            received.payload == b"hello group",
            "the sub-agent did not see the parent's post"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_cap_scoped_to_another_channel_cannot_join_the_peer_group() -> anyhow::Result<()> {
        let (channel, _backend, _id, authority) = new_channel("peer-group").await?;
        let foreign_cap = mint(&authority, "intruder", &ChannelId::from("other-channel"), full());
        anyhow::ensure!(
            matches!(channel.join(&foreign_cap), Err(ChannelError::WrongChannel)),
            "a cap scoped to a different channel must not join this one"
        );
        Ok(())
    }

    // ---- EscalationRole ----

    /// A fake human-facing backend: records every message it's notified of.
    /// `sandy-fabric`'s own equivalent (`contract::fakes::FakeHumanBackend`) is
    /// `#[cfg(test)]`-private to that crate, so this is its own small copy.
    #[derive(Default)]
    struct FakeHumanBackend {
        received: Mutex<Vec<EscalationMessage>>,
    }

    impl FakeHumanBackend {
        fn received(&self) -> Vec<EscalationMessage> {
            self.received.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }
    }

    impl EscalationSink for FakeHumanBackend {
        fn enabled(&self) -> bool {
            true
        }

        async fn notify(
            &self,
            message: &EscalationMessage,
        ) -> Result<(), sandy_fabric::escalation::EscalationSinkError> {
            self.received
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(message.clone());
            Ok(())
        }
    }

    /// Always fails `append`: stands in for a down channel backend.
    #[derive(Default, Clone)]
    struct BrokenBackend;

    impl sandy_fabric::channel_backend::ChannelBackend for BrokenBackend {
        async fn append(&self, _env: Envelope) -> Result<(), ChannelBackendError> {
            Err(ChannelBackendError::Unavailable("backend is down".to_owned()))
        }

        async fn fetch(&self, _from_seq: u64) -> Result<Vec<Envelope>, ChannelBackendError> {
            Ok(Vec::new())
        }

        fn stream_from(
            &self,
            _from_seq: u64,
        ) -> impl Stream<Item = Result<Envelope, ChannelBackendError>> + Send + 'static {
            futures_util::stream::empty()
        }
    }

    fn message() -> EscalationMessage {
        EscalationMessage {
            from: PeerId::from("sandbox-1"),
            reason: "needs human input".to_owned(),
        }
    }

    /// Always fails `notify`: stands in for a down escalation sink.
    struct DownSink;

    impl EscalationSink for DownSink {
        fn enabled(&self) -> bool {
            true
        }

        async fn notify(
            &self,
            _message: &EscalationMessage,
        ) -> Result<(), sandy_fabric::escalation::EscalationSinkError> {
            Err(sandy_fabric::escalation::EscalationSinkError::Sink(
                "sink is down".to_owned(),
            ))
        }
    }

    #[tokio::test]
    async fn an_escalation_reaches_the_fake_human_backend() -> anyhow::Result<()> {
        let (channel, _backend, id, authority) = new_channel("escalation").await?;
        let cap = mint(&authority, "sandbox-1", &id, full());
        let membership = channel.join(&cap).context("join")?;
        let role = EscalationRole::new(channel, membership, FakeHumanBackend::default());

        role.escalate(&message()).await.context("escalate")?;
        anyhow::ensure!(
            role.sink().received() == [message()],
            "the sink did not receive the escalation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn escalation_still_delivers_when_the_channel_is_down() -> anyhow::Result<()> {
        let authority = TestAuthority;
        let id = ChannelId::from("escalation");
        let cap = mint(&authority, "sandbox-1", &id, full());
        let channel = Channel::new(id, BrokenBackend, authority)
            .await
            .context("Channel::new")?;
        let membership = channel.join(&cap).context("join")?;
        let role = EscalationRole::new(channel, membership, FakeHumanBackend::default());

        role.escalate(&message())
            .await
            .context("escalate must still succeed via the sink when the channel is down")?;
        anyhow::ensure!(
            role.sink().received() == [message()],
            "the sink must still be notified when the channel path fails"
        );
        Ok(())
    }

    #[tokio::test]
    async fn escalation_fails_only_when_both_the_channel_and_the_sink_fail() -> anyhow::Result<()> {
        let authority = TestAuthority;
        let id = ChannelId::from("escalation");
        let cap = mint(&authority, "sandbox-1", &id, full());
        let channel = Channel::new(id, BrokenBackend, authority)
            .await
            .context("Channel::new")?;
        let membership = channel.join(&cap).context("join")?;
        let role = EscalationRole::new(channel, membership, DownSink);

        let err = role
            .escalate(&message())
            .await
            .expect_err("escalate must fail when neither path delivers");
        anyhow::ensure!(
            matches!(err, RoleError::BothEscalationPathsFailed { .. }),
            "expected BothEscalationPathsFailed, got {err:?}"
        );
        Ok(())
    }
}
