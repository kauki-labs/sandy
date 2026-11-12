//! Per-job channel and capability minting (#212, B2 slice).
//!
//! Each submitted job gets its own dedicated orchestrator channel (spec
//! §3.4's one-channel-per-sandbox invariant) the moment it's submitted, not
//! when a job actually starts running: the agent needs the channel to exist
//! before it can join when dispatch wires it up, and `Attach` needs a real
//! channel + cap to hand back.
//!
//! What this does NOT do yet, honestly: run the job. There is no
//! `ProcessBackend::with_agent` (#216) and no `sandy-agent` binary for it to
//! spawn yet, so a submitted job stays `Pending` — it has a real channel and
//! real caps, but nothing ever posts to that channel because no agent ever
//! joins it. `Attach` returning the real channel/cap here is not a fake
//! success: the channel genuinely exists and the cap genuinely works, the job
//! status just honestly never advances past `Pending` until the executor
//! wiring lands and actually dispatches it.
//!
//! **Decision C-at-Submit (#226).** A job's OWN dedicated channel (this
//! module) is always minted directly by [`JobRegistry`]'s one persistent
//! [`SharedCapAuthority`] — that is infrastructure sandyd itself owns, not
//! something a submitter's held caps bound (the same way every orchestrator
//! channel in the all-local MVP is minted fresh per sandbox, a composition-
//! root responsibility, agent-fabric.md §11). What decision C bounds is a
//! manifest's ADDITIONAL `requested_caps`, onto channels the submitter
//! already participates in (its own orchestrator channel, a peer group it
//! was invited to, …) — [`crate::handler`] calls `derive_job_caps`
//! (`sandy-orchestrator`, #219) against this same shared authority for that,
//! once a manifest actually requests something. The registry's authority is
//! persistent (not fresh per job) specifically so a submitter's held caps —
//! minted under this same authority at some point before Submit — verify
//! against it.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights, CapScope},
    types::{ChannelId, PeerId},
};
use sandy_fabric_local::{
    LocalCapAuthority, SharedCapAuthority, agent::ARCHIVE_TRANSCRIPT, channel::Channel, inmem::InMem,
};
use sandy_proto::MessageType;
use uuid::Uuid;

use crate::{
    credential::{JobCredentials, Redaction},
    link_auth::{self, LinkAuthError, LinkKind, RemoteLink},
    store::JobStore,
};

/// The peer name of the broker output collector's read-only cap (#643). `Attach` mints it on
/// request for the submitter; the attach accept loop does not count a join with it.
pub const COLLECTOR_PEER: &str = sandy_control_proto::COLLECTOR_PEER;

/// A job's dedicated orchestrator channel, minted at submit time.
pub struct JobChannel {
    /// The channel itself, keyed by the job's own id (spec §3.4: dedicated,
    /// one per sandbox).
    pub channel: Arc<Channel<InMem, SharedCapAuthority>>,
    /// The bootstrap cap the agent will present to join (post + read, no
    /// invite — the agent speaks for itself, it does not grow this channel's
    /// membership). Handed to the agent over its link once dispatch wires
    /// `ProcessBackend::with_agent` up; held here in the meantime.
    pub agent_cap: Cap,
    /// The cap `Attach` hands to a client attaching from a DIFFERENT session
    /// than the one that submitted this job: read-only, no `post` — it
    /// watches the job's TTY, it does not drive its stdin through this cap.
    /// `handler::handle`'s `Attach` arm mints a separate, post-capable cap on
    /// the fly for the submitting session itself instead of handing out this
    /// one (#327) — "my own job I can log into, someone else's I can only
    /// watch".
    pub observer_cap: Cap,
    /// A read-only cap distinct from `observer_cap`, used only by
    /// `persist_archive_when_posted` (#340 item 4) — never handed to a real
    /// client. See that cap's own minting comment in `mint_job_channel` for
    /// why it must not be the same cap any attacher might hold.
    pub archiver_cap: Cap,
    /// This run's binding to a remote executor (#212 decision 6), if it has
    /// one. `None` for a job dispatched locally, which has no mesh stream to
    /// authenticate — `serve_agent_link` runs directly over a private
    /// socketpair there. Set at dispatch, never mutated after.
    pub remote_link: Option<RemoteLink>,
    /// This run's SECOND remote link, the input/output data link (#482
    /// decision 22): same executor, its own token and its own claim slot, so
    /// claiming one link never spends the other. Set beside `remote_link`,
    /// `None` exactly when that is.
    pub data_link: Option<RemoteLink>,
    /// The path inputs the data link sends to the executor (#482 slice 5c). Empty exactly when `data_link` is
    /// `None` or the job has outputs only.
    pub data_inputs: Vec<sandy_executor_proto::Input>,
    /// The path outputs the executor sends back over the data link (#482 slice 6c-2): the Submit-validated outputs,
    /// set at mint beside `data_link`. Empty exactly when `data_link` is `None` or the job has inputs only. sandyd
    /// decides from this, never from the host's `outputs_follow` flag, whether a succeeded job owes outputs.
    pub data_outputs: Vec<sandy_executor_proto::Output>,
    /// How the receive of `data_outputs` came out, for the result relay to wait on.
    pub outputs: crate::output_slot::OutputsSlot,
    /// Caps derived from the manifest's `requested_caps`, bounded by the
    /// submitter's own held caps (decision C, #226) — scoped to channels
    /// OTHER than this job's own (e.g. the submitter's orchestrator channel,
    /// a peer group). Empty for a direct-mint submission (no `submitter_caps`
    /// presented) or a manifest requesting nothing extra. Not yet consumed:
    /// there is no agent/dispatch-core wiring yet to hand these to (same
    /// honest gap as the rest of this module) — `derive_job_caps` enforcing
    /// the bound AT SUBMIT TIME (refusing an over-broad request before a job
    /// is ever created) is #226's actual deliverable; handing the granted
    /// caps to a running job is dispatch-core's job once it exists.
    pub granted_caps: Vec<Cap>,
    /// The session id (CF-H-1) of the connection that submitted this job.
    /// Defaults to [`Uuid::nil`] here — `handler::handle`'s Submit arm
    /// overwrites it with the real submitting connection's session right
    /// after minting, the same late-assignment pattern `granted_caps` above
    /// already follows. Compared, not trusted: a mismatch on a later
    /// Cancel/Attach is logged, not refused — see [`JobChannel::session_matches`].
    pub session: Uuid,
    /// The host-executor id this job was placed on (#340), `None` for a
    /// locally-run job or one never placed remotely. Set once, at the same
    /// point `remote_link` is (`handler::handle`'s Submit arm, inside the
    /// `dispatch_plan` closure), never mutated after — the attach-relay
    /// (`attach_relay.rs`) reads it to know which host to notify of an
    /// attach-membership transition via `HostRegistry::send_attach_state_changed`.
    pub host_id: Option<String>,
    /// This job's attach bookkeeping (#340): a DEDICATED count of currently
    /// connected attach clients, plus the next sequence number to assign —
    /// both updated under one lock by
    /// [`attach_relay::join_for_attach`]/[`attach_relay::leave_for_attach`].
    ///
    /// Deliberately NOT `self.channel.member_count()` (CodeRabbit finding,
    /// a real bug the first version of this feature had): the channel's
    /// own membership also includes the sandbox agent's join (a totally
    /// separate join, from a totally separate code path, that happens as
    /// part of ordinary job execution regardless of whether anyone ever
    /// attaches) — reading `member_count()` directly meant the 0→1
    /// transition this feature's whole "unlimited while attached" policy
    /// depends on could simply never fire once the agent had already
    /// joined (member_count() would already read 1 with zero real
    /// attachers). It also UNDERcounts: `MembershipId` is keyed by a
    /// digest of the cap's own proof bytes, so two distinct attach
    /// connections presenting the identical capability collapse into ONE
    /// `Channel::members` entry, not two — a dedicated counter, bumped once
    /// per real `join_for_attach`/`leave_for_attach` call regardless of
    /// what the underlying channel-level membership map does, counts
    /// actual attach connections instead.
    ///
    /// One `Mutex`, not two separate fields: the lock itself is what
    /// serializes "join/leave the channel, update the attach count, and
    /// assign the next sequence" as ONE critical section across every
    /// concurrent attach/detach on this job — two atomics would only make
    /// each NUMBER's own update atomic, not the whole transition-detection
    /// step together, which is the actual race (two concurrent joins/leaves
    /// could still interleave their `Channel::join`/count-update pair and
    /// assign sequence numbers out of true chronological order). The async
    /// send to the host-executor that follows is never ordered by this
    /// lock — only the numbers it carries are, which is what lets the
    /// host-executor resolve any out-of-order delivery by keeping the
    /// highest sequence seen.
    pub attach_tracking: std::sync::Mutex<AttachTracking>,
}

/// See [`JobChannel::attach_tracking`]'s own doc for why this exists as a
/// dedicated pair rather than reading `Channel::member_count()` directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct AttachTracking {
    /// How many attach clients are currently connected to this job.
    pub count: usize,
    /// The next sequence number to assign on this job's next attach/detach
    /// transition.
    pub next_seq: u64,
}

impl JobChannel {
    /// Whether `session` is the one that submitted this job (CF-H-1). Plain
    /// equality, not a capability or an access-control gate: a mismatch here
    /// is an audit signal for `handler` to log, never a refusal — the real
    /// connection-trust gate is the separate B6 work this pass's audit trail
    /// stands in for. Returns a flag rather than an error so the caller (and
    /// a test) can observe a mismatch directly, without scraping logs.
    #[must_use]
    pub fn session_matches(&self, session: Uuid) -> bool {
        self.session == session
    }
}

/// A dispatch failure.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// The capability authority faulted minting a cap.
    #[error("minting a job capability: {0}")]
    Cap(#[from] CapError),
    /// The channel's backend faulted creating the channel.
    #[error("creating the job channel: {0}")]
    Channel(#[from] sandy_fabric::channel_backend::ChannelBackendError),
}

/// How long a minted job cap is valid. Generous for this skeleton (no
/// long-running job outlives it); real TTL policy is a later decision once
/// jobs can actually run long enough for it to matter.
const CAP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Mint `job_id`'s dedicated channel plus its agent and observer caps, from
/// `authority` — the registry's one persistent [`SharedCapAuthority`], not a
/// fresh one per job (#226: a submitter's held caps, verified against this
/// same authority elsewhere in Submit, only mean anything if the daemon's
/// caps all come from one shared signing key). `granted_caps` is attached
/// separately by the caller once decided (empty for a direct-mint submit).
///
/// # Errors
/// [`DispatchError::Cap`] if the capability authority cannot mint;
/// [`DispatchError::Channel`] if the channel's backend cannot be constructed.
pub async fn mint_job_channel(job_id: &str, authority: &SharedCapAuthority) -> Result<JobChannel, DispatchError> {
    let channel_id = ChannelId::from(job_id);

    let agent_cap = authority.mint(CapScope {
        peer: PeerId::from("agent"),
        channel: channel_id.clone(),
        rights: CapRights {
            post: true,
            read: true,
            invite: false,
        },
        expires_at: None,
    })?;
    let observer_cap = authority.mint(CapScope {
        peer: PeerId::from("observer"),
        channel: channel_id.clone(),
        rights: CapRights {
            post: false,
            read: true,
            invite: false,
        },
        expires_at: None,
    })?;
    // A DISTINCT identity from `observer_cap` (#340 item 4), never handed out
    // to a real client: `MembershipId` is a digest of the cap's own proof
    // bytes, so `persist_archive_when_posted` joining with the SAME cap an
    // attach client holds would share that client's membership entry. A
    // later `attach_relay::leave_for_attach` for that client's detach then
    // calls `Channel::leave` on that shared id, which removes the session
    // state `CursorStream::poll_next` checks for EVERY stream still reading
    // it — ending the persister's subscription too, silently, the moment any
    // attacher using the same cap detaches (confirmed by reading
    // `Channel::leave`/`CursorStream::poll_next`: session state is keyed by
    // `MembershipId`, not per `CursorStream`). A different `peer` scope
    // mints a cap with different proof bytes and therefore a different
    // digest, regardless of how the authority handles nonces.
    let archiver_cap = authority.mint(CapScope {
        peer: PeerId::from("archiver"),
        channel: channel_id.clone(),
        rights: CapRights {
            post: false,
            read: true,
            invite: false,
        },
        expires_at: None,
    })?;

    let channel = Channel::new(channel_id, InMem::default(), authority.clone()).await?;
    Ok(JobChannel {
        channel: Arc::new(channel),
        agent_cap,
        observer_cap,
        archiver_cap,
        remote_link: None,
        data_link: None,
        data_inputs: Vec::new(),
        data_outputs: Vec::new(),
        outputs: crate::output_slot::OutputsSlot::new(),
        granted_caps: Vec::new(),
        session: Uuid::nil(),
        host_id: None,
        attach_tracking: std::sync::Mutex::new(AttachTracking::default()),
    })
}

/// How long [`persist_archive_when_posted`] waits for the agent's one-shot
/// archived-transcript post before giving up: generous enough to outlast a
/// job that runs a long time while attached (#340's "unlimited while
/// attached" timeout is enforced elsewhere; this has no view into attach
/// state at all), but bounded, so an agent that crashes, or a job that is
/// never dispatched, doesn't leave this task running for the life of the
/// daemon.
pub const ARCHIVE_WAIT_BOUND: Duration = Duration::from_secs(24 * 60 * 60);

/// Observe `channel` (read-only, via the job's own dedicated `archiver_cap`
/// — never `agent_cap`, this task never needs to write, and never
/// `observer_cap`, see that cap's own minting doc for why) for the agent's
/// one-shot `ARCHIVE_TRANSCRIPT` post (epic #340 item 4) and persist it into
/// `store`, independent of whether a `sandy daemon attach` client was ever
/// connected to see it live.
///
/// Without this, the only consumers of that post are live attach-relay
/// connections (`attach_relay.rs`'s per-connection `relay()`): a job nobody
/// ever attaches to loses the transcript for good the moment it's posted,
/// even though the agent genuinely sent it — and the registry's own doc
/// above is explicit that the in-memory `Channel` itself holds nothing
/// durable, so this (not the channel) is where a copy has to land to
/// survive a restart.
///
/// A plain, read-only `channel.join` here never touches `attach_relay.rs`'s
/// own `join_for_attach`/`AttachTracking` bookkeeping — those are explicit
/// calls that function makes, not a side effect of `Channel::join` itself —
/// so this task is invisible to attach-state accounting and the M2 timeout
/// it drives.
///
/// Best-effort and silent on every failure path (a join/subscribe refusal,
/// a channel fault, `wait_bound` elapsing with no archive ever posted, or a
/// store write error): this is a durability nicety layered onto a live
/// delivery path that already works correctly on its own. `wait_bound` is a
/// parameter (callers pass [`ARCHIVE_WAIT_BOUND`]) so tests can exercise the
/// give-up path without an actual day-long wait.
pub async fn persist_archive_when_posted(
    channel: Arc<Channel<InMem, SharedCapAuthority>>,
    archiver_cap: Cap,
    job_id: String,
    store: Arc<JobStore>,
    wait_bound: Duration,
    credentials: Option<Arc<JobCredentials>>,
) {
    let membership = match channel.join(&archiver_cap) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(job_id, error = %e, "archive persister: could not join the job channel");
            return;
        }
    };
    find_and_persist_archive(&channel, &membership, &job_id, &store, wait_bound, credentials).await;
    // Always leave once done (found it, failed, or gave up): this
    // membership belongs to this one task alone (see `archiver_cap`'s own
    // minting doc) and has no reason to linger in the channel's membership
    // table afterward.
    channel.leave(&membership);
}

/// The actual find-and-persist, split out from [`persist_archive_when_posted`]
/// purely so every early return still goes through that function's own
/// unconditional `channel.leave` at the end — a `return` in here just ends
/// this helper, not the cleanup.
async fn find_and_persist_archive(
    channel: &Channel<InMem, SharedCapAuthority>,
    membership: &sandy_fabric_local::channel::MembershipId,
    job_id: &str,
    store: &Arc<JobStore>,
    wait_bound: Duration,
    credentials: Option<Arc<JobCredentials>>,
) {
    let stream = match channel.subscribe(membership) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(job_id, error = %e, "archive persister: could not subscribe");
            return;
        }
    };
    let find_archive = async {
        let mut stream = std::pin::pin!(stream);
        while let Some(item) = stream.next().await {
            // A stream error ends this attempt rather than retrying: this
            // persister is already best-effort and silent on every failure
            // path (see this function's own doc comment above), and
            // `continue`-ing past a repeated, immediately-ready error would
            // busy-loop until `wait_bound` elapses instead of giving up
            // promptly (CodeRabbit on #378).
            let Ok(env) = item else { return None };
            if matches!(env.message_type, Some(MessageType::Output(_))) && env.content_type == ARCHIVE_TRANSCRIPT {
                return Some(env.payload);
            }
        }
        None
    };
    let Ok(Some(bytes)) = tokio::time::timeout(wait_bound, find_archive).await else {
        return;
    };
    let write_job_id = job_id.to_owned();
    let store = Arc::clone(store);
    // The agent archives the job's terminal log, which can hold the job's own
    // `GITHUB_TOKEN` (#481). For a credentialed job (`credentials` is `Some`)
    // the archive is stored only once the token is redacted: the archive can
    // arrive after the credential was released, and then it is dropped.
    match tokio::task::spawn_blocking(move || {
        let bytes = match &credentials {
            Some(credentials) => match credentials.redact_bytes(&write_job_id, bytes) {
                Redaction::Redacted(bytes) => bytes,
                Redaction::NotHeld(_) | Redaction::Unavailable => {
                    tracing::warn!(
                        job_id = write_job_id,
                        "archive persister: dropped the transcript of a credentialed job, its token could not be \
                         redacted"
                    );
                    return Ok(());
                }
            },
            None => bytes,
        };
        store.set_archive(&write_job_id, &bytes)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(job_id, error = %e, "archive persister: could not persist the transcript"),
        Err(e) => tracing::warn!(job_id, error = %e, "archive persister: the store-write task panicked"),
    }
}

/// How long a job's channel stays in the registry after it reaches a
/// terminal state, before [`JobRegistry::insert`]'s opportunistic sweep
/// reaps it (#270). `Attach` looks the channel up by id (`handler::handle`'s
/// `Attach` arm), not by a held cap — #327 mints a fresh post-capable cap
/// per Attach call rather than reusing the job's original one — so a stale
/// cap expiring doesn't gate anything here; the channel being gone from this
/// map is what actually ends Attach's window. Reuses [`CAP_TTL`] as a
/// reasonable existing duration rather than inventing a second magic number,
/// not because the two are mechanically linked.
const TERMINAL_RETENTION: Duration = CAP_TTL;

/// Every submitted job's minted channel, keyed by job id, plus the one
/// [`SharedCapAuthority`] every job's channel and every submitter-held cap
/// verified at Submit are minted/checked against (#226). Process-local and
/// ephemeral by design — channels are in-memory (the all-local MVP's step-1
/// `ChannelBackend`), so this registry holds no state that needs to survive a
/// restart; the sqlite job store is the durable record.
///
/// #270: without `mark_terminal`+the sweep in [`JobRegistry::insert`], this
/// map would retain one entry per job ever submitted for the daemon's whole
/// lifetime. A job's terminal timestamp lives in a side map, not alongside
/// the channel itself, so a non-terminal job's hot path (`get`,
/// `authenticate_remote_link`) never has to touch it.
pub struct JobRegistry {
    jobs: Mutex<HashMap<String, Arc<JobChannel>>>,
    /// When each terminal job reached that state, for the sweep in
    /// [`JobRegistry::insert`] to reap by. A job absent from this map is
    /// either still live, or was already reaped.
    terminal_at: Mutex<HashMap<String, Instant>>,
    authority: SharedCapAuthority,
    /// The grace period [`JobRegistry::insert`]'s sweep reaps by (#270).
    /// [`TERMINAL_RETENTION`] in production; overridable via
    /// [`JobRegistry::with_retention`] for tests that need to observe the
    /// sweep without waiting out the real default.
    retention: Duration,
    /// Daemon-minted job credentials (#481). `None` refuses any Submit naming a
    /// credential.
    credentials: Option<Arc<JobCredentials>>,
}

impl JobRegistry {
    /// A fresh, empty registry with a new, randomly-keyed authority.
    ///
    /// # Errors
    /// [`CapError::Authority`] if the system RNG is unavailable.
    pub fn new() -> Result<Self, CapError> {
        Ok(Self {
            jobs: Mutex::new(HashMap::new()),
            terminal_at: Mutex::new(HashMap::new()),
            authority: SharedCapAuthority::new(LocalCapAuthority::new(CAP_TTL)?),
            retention: TERMINAL_RETENTION,
            credentials: None,
        })
    }

    /// Mint, hold, and revoke job credentials through `credentials` (#481).
    #[must_use]
    pub fn with_credentials(mut self, credentials: JobCredentials) -> Self {
        self.credentials = Some(Arc::new(credentials));
        self
    }

    /// The daemon's job credentials, when configured.
    #[must_use]
    pub fn credentials(&self) -> Option<&Arc<JobCredentials>> {
        self.credentials.as_ref()
    }

    /// Revoke `job_id`'s daemon-minted credential, if it holds one (#481). Every
    /// terminal path calls this whatever its store transition was: the job is
    /// over on its host either way. Idempotent.
    pub fn release_credential(&self, job_id: &str) {
        if let Some(credentials) = &self.credentials {
            credentials.release(job_id);
        }
    }

    /// Override the terminal-retention grace period (#270). Production
    /// callers never need this — [`JobRegistry::new`] already uses
    /// [`TERMINAL_RETENTION`] — it exists so a test can pass
    /// [`Duration::ZERO`] and observe [`JobRegistry::insert`]'s sweep
    /// deterministically, instead of waiting out the real multi-hour
    /// default.
    #[must_use]
    pub fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    /// The registry's one persistent authority: every job channel is minted
    /// from it, and a submitter's `submitter_caps` are verified against it.
    #[must_use]
    pub fn authority(&self) -> &SharedCapAuthority {
        &self.authority
    }

    /// Register `job`'s channel under `job_id`, replacing any previous entry
    /// for the same id (a resubmission under a reused id would be a caller
    /// bug elsewhere; this registry just reflects the latest mint).
    ///
    /// Opportunistically sweeps every job whose [`JobRegistry::mark_terminal`]
    /// timestamp is older than [`TERMINAL_RETENTION`] (#270) — tied to Submit
    /// traffic, the same thing that grows this registry, rather than a
    /// separate background task: a daemon that stops receiving Submits also
    /// stops growing, so there's nothing that needs reaping between one
    /// Submit and the next.
    pub fn insert(&self, job_id: String, job: JobChannel) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job_id, Arc::new(job));
        self.reap_expired();
    }

    /// Record that `job_id` reached a terminal status (`Succeeded`, `Failed`,
    /// or `Cancelled`) just now, starting its [`TERMINAL_RETENTION`] clock.
    /// Call exactly once per job, from whichever call site actually applied
    /// the terminal transition in [`crate::store::JobStore`] — calling it
    /// again for an already-terminal job only pushes its reap time later,
    /// never earlier.
    pub fn mark_terminal(&self, job_id: &str) {
        self.terminal_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job_id.to_owned(), Instant::now());
    }

    /// Remove every job whose [`JobRegistry::mark_terminal`] timestamp is
    /// older than [`TERMINAL_RETENTION`] from both maps.
    fn reap_expired(&self) {
        let mut terminal_at = self.terminal_at.lock().unwrap_or_else(PoisonError::into_inner);
        let expired: Vec<String> = terminal_at
            .iter()
            .filter(|&(_, &at)| at.elapsed() >= self.retention)
            .map(|(job_id, _)| job_id.clone())
            .collect();
        if expired.is_empty() {
            return;
        }
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        for job_id in expired {
            jobs.remove(&job_id);
            terminal_at.remove(&job_id);
        }
    }

    /// `job_id`'s minted channel, if one was registered.
    #[must_use]
    pub fn get(&self, job_id: &str) -> Option<Arc<JobChannel>> {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(job_id)
            .cloned()
    }

    /// Authenticate an incoming remote agent-link stream for `job_id`
    /// against its recorded executor binding (#212 decision 6) before the
    /// caller may proceed to `serve_agent_link` at all.
    ///
    /// # Errors
    /// [`LinkAuthError::UnknownRun`] if no such job is registered;
    /// [`LinkAuthError::NotRemote`] if the job was dispatched locally and has
    /// no remote link to authenticate; otherwise see
    /// [`link_auth::authenticate`].
    pub fn authenticate_remote_link(
        &self,
        job_id: &str,
        peer_ip: std::net::IpAddr,
        presented_token: &[u8; link_auth::LINK_TOKEN_LEN],
    ) -> Result<Arc<JobChannel>, LinkAuthError> {
        let job = self.get(job_id).ok_or(LinkAuthError::UnknownRun)?;
        let link = job.remote_link.as_ref().ok_or(LinkAuthError::NotRemote)?;
        link_auth::authenticate(link, peer_ip, presented_token)?;
        Ok(job)
    }

    /// Authenticate an incoming remote stream for `job_id` against BOTH of the
    /// job's links (#482 decision 22) and say which one it claimed. The links
    /// share the executor's IP and differ in token, so the token is the
    /// namespace: a token that matches the agent link claims only the agent
    /// link, one that matches the data link claims only the data link, and
    /// neither slot is ever spent by a token for the other. `encode_remote_link_prefix`
    /// has no tag byte (an older executor would break), so the demux is here.
    ///
    /// # Errors
    /// As [`Self::authenticate_remote_link`]; a token that matches neither
    /// link is [`LinkAuthError::WrongToken`].
    pub fn authenticate_incoming_link(
        &self,
        job_id: &str,
        peer_ip: std::net::IpAddr,
        presented_token: &[u8; link_auth::LINK_TOKEN_LEN],
    ) -> Result<(Arc<JobChannel>, LinkKind), LinkAuthError> {
        let job = self.get(job_id).ok_or(LinkAuthError::UnknownRun)?;
        let agent = job.remote_link.as_ref().ok_or(LinkAuthError::NotRemote)?;
        match link_auth::authenticate(agent, peer_ip, presented_token) {
            Ok(()) => return Ok((job, LinkKind::Agent)),
            Err(LinkAuthError::WrongToken) => {}
            Err(e) => return Err(e),
        }
        let data = job.data_link.as_ref().ok_or(LinkAuthError::WrongToken)?;
        link_auth::authenticate(data, peer_ip, presented_token)?;
        Ok((job, LinkKind::Data))
    }

    /// Invalidate `job_id`'s remote links, if it has them, so a stream arriving
    /// after this point can never claim either (#269's token-lifecycle
    /// requirement: cancel, dispatch timeout, and executor teardown must each
    /// close this off). A no-op if the job has no remote link or is unknown —
    /// the caller has already decided whether the terminal transition itself
    /// (cancel, timeout, …) succeeded; this only cleans up the links that
    /// transition leaves behind.
    pub fn invalidate_remote_link(&self, job_id: &str) {
        let Some(job) = self.get(job_id) else { return };
        for link in [&job.remote_link, &job.data_link].into_iter().flatten() {
            link.invalidate();
        }
        // A receive still waiting on the data link gives up: the job it was for is over (first outcome stands).
        job.outputs
            .publish(crate::output_slot::OutputsState::Failed("the job ended".to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_authority() -> SharedCapAuthority {
        SharedCapAuthority::new(LocalCapAuthority::new(CAP_TTL).expect("getrandom for a test authority"))
    }

    #[tokio::test]
    async fn minted_caps_are_scoped_to_the_jobs_own_channel() -> anyhow::Result<()> {
        let job = mint_job_channel("job-1", &test_authority()).await?;
        job.channel.join(&job.agent_cap)?;
        job.channel.join(&job.observer_cap)?;
        Ok(())
    }

    /// Adversarial: the observer cap must not carry `post` — attaching to
    /// watch a job must never also grant the ability to inject its stdin.
    #[tokio::test]
    async fn the_observer_cap_cannot_post() -> anyhow::Result<()> {
        let job = mint_job_channel("job-1", &test_authority()).await?;
        let membership = job.channel.join(&job.observer_cap)?;
        let err = job
            .channel
            .post(&membership, None, "text/plain", b"should be refused".to_vec())
            .await
            .expect_err("the observer cap must not be able to post");
        assert!(
            matches!(
                err,
                sandy_fabric_local::channel::ChannelError::InsufficientRights("post")
            ),
            "got {err:?}"
        );
        Ok(())
    }

    /// Adversarial: a cap minted for one job's channel must be refused by a
    /// different job's channel — two jobs never share membership, even though
    /// (#226) every job's channel now mints from the SAME registry-wide
    /// authority, not a fresh one per job. That shared signing key means a
    /// cross-job cap verifies correctly (it really is validly signed) and so
    /// fails as `WrongChannel`, not `Forged` — boundedness is `Channel::join`'s
    /// own channel-id check, never the authority's identity (agent-fabric.md
    /// §11: "boundedness is entirely Channel::join's existing wrong-channel
    /// rejection").
    #[tokio::test]
    async fn a_cap_for_one_job_is_refused_by_another_jobs_channel() -> anyhow::Result<()> {
        let authority = test_authority();
        let job_a = mint_job_channel("job-a", &authority).await?;
        let job_b = mint_job_channel("job-b", &authority).await?;
        let err = job_b
            .channel
            .join(&job_a.agent_cap)
            .expect_err("a cap minted for job-a must not join job-b's channel");
        assert!(
            matches!(err, sandy_fabric_local::channel::ChannelError::WrongChannel),
            "got {err:?}"
        );
        Ok(())
    }

    /// CF-H-1: `session_matches` is a plain flag, not an error — proven
    /// directly here rather than only inferred from `handle`'s unchanged
    /// response shape on a mismatch (see `handler.rs`'s own cross-session
    /// test for that half).
    #[tokio::test]
    async fn session_matches_reports_a_mismatch_as_a_plain_flag() -> anyhow::Result<()> {
        let mut job = mint_job_channel("job-1", &test_authority()).await?;
        let submitting_session = Uuid::new_v4();
        job.session = submitting_session;

        assert!(job.session_matches(submitting_session));
        assert!(!job.session_matches(Uuid::new_v4()));
        Ok(())
    }

    #[test]
    fn the_registry_returns_none_for_an_unregistered_job() -> anyhow::Result<()> {
        let registry = JobRegistry::new()?;
        assert!(registry.get("ghost").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn the_registry_round_trips_a_registered_job() -> anyhow::Result<()> {
        let registry = JobRegistry::new()?;
        let job = mint_job_channel("job-1", registry.authority()).await?;
        let agent_cap_proof = job.agent_cap.proof().to_vec();
        registry.insert("job-1".to_owned(), job);

        let found = registry.get("job-1").expect("job-1 was registered");
        assert_eq!(found.agent_cap.proof(), agent_cap_proof.as_slice());
        assert!(registry.get("job-2").is_none());
        Ok(())
    }

    /// #270: a job marked terminal is reaped by the NEXT insert once its
    /// retention window has elapsed — `with_retention(Duration::ZERO)` makes
    /// that window elapse immediately, so a single later insert is enough to
    /// observe the sweep without a real sleep.
    #[tokio::test]
    async fn a_terminal_job_is_reaped_on_the_next_insert() -> anyhow::Result<()> {
        let registry = JobRegistry::new()?.with_retention(Duration::ZERO);
        let job = mint_job_channel("job-1", registry.authority()).await?;
        registry.insert("job-1".to_owned(), job);
        registry.mark_terminal("job-1");
        assert!(registry.get("job-1").is_some(), "not reaped before any later insert");

        let job2 = mint_job_channel("job-2", registry.authority()).await?;
        registry.insert("job-2".to_owned(), job2);

        assert!(
            registry.get("job-1").is_none(),
            "job-1 should have been reaped by job-2's insert"
        );
        assert!(
            registry.get("job-2").is_some(),
            "job-2 is not itself terminal and must survive the sweep"
        );
        Ok(())
    }

    /// #270 adversarial: a non-terminal job must never be reaped, however
    /// long it has sat in the registry — only `mark_terminal` starts the
    /// clock a later insert's sweep acts on.
    #[tokio::test]
    async fn a_non_terminal_job_is_never_reaped() -> anyhow::Result<()> {
        let registry = JobRegistry::new()?.with_retention(Duration::ZERO);
        let job = mint_job_channel("job-1", registry.authority()).await?;
        registry.insert("job-1".to_owned(), job);
        // No mark_terminal call for job-1.

        let job2 = mint_job_channel("job-2", registry.authority()).await?;
        registry.insert("job-2".to_owned(), job2);

        assert!(
            registry.get("job-1").is_some(),
            "a non-terminal job must survive every sweep"
        );
        Ok(())
    }

    /// #270: a job inside its retention window (the production default, not
    /// overridden here) stays attachable across a later insert — the sweep
    /// must not reap early.
    #[tokio::test]
    async fn a_terminal_job_inside_its_retention_window_stays_attachable() -> anyhow::Result<()> {
        let registry = JobRegistry::new()?; // default TERMINAL_RETENTION, hours away
        let job = mint_job_channel("job-1", registry.authority()).await?;
        registry.insert("job-1".to_owned(), job);
        registry.mark_terminal("job-1");

        let job2 = mint_job_channel("job-2", registry.authority()).await?;
        registry.insert("job-2".to_owned(), job2);

        assert!(
            registry.get("job-1").is_some(),
            "job-1 is well inside its retention window"
        );
        Ok(())
    }

    /// Adversarial (#212 decision 6): an unknown job id must be refused by
    /// name, not treated as having no remote link (a different refusal that
    /// would leak "this job exists but is local").
    #[test]
    fn authenticating_an_unregistered_job_is_refused_as_unknown() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let token = [0u8; link_auth::LINK_TOKEN_LEN];
        let peer: std::net::IpAddr = "127.0.0.1".parse().context("loopback literal")?;
        match registry.authenticate_remote_link("ghost", peer, &token) {
            Err(e) => assert_eq!(e, LinkAuthError::UnknownRun),
            Ok(_) => panic!("an unregistered job must be refused"),
        }
        Ok(())
    }

    /// A job dispatched locally (the only kind this slice mints) has no
    /// remote link to authenticate against — refused by name, never treated
    /// as an unknown run.
    #[tokio::test]
    async fn authenticating_a_local_jobs_link_is_refused_as_not_remote() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let job = mint_job_channel("job-1", registry.authority()).await?;
        registry.insert("job-1".to_owned(), job);

        let token = [0u8; link_auth::LINK_TOKEN_LEN];
        let peer: std::net::IpAddr = "127.0.0.1".parse().context("loopback literal")?;
        match registry.authenticate_remote_link("job-1", peer, &token) {
            Err(e) => assert_eq!(e, LinkAuthError::NotRemote),
            Ok(_) => panic!("a locally dispatched job has no remote link"),
        }
        Ok(())
    }

    /// A job bound to a remote executor authenticates against the real
    /// peer/token and refuses a second attempt, through the registry's own
    /// lookup path (not just `link_auth`'s unit tests in isolation).
    #[tokio::test]
    async fn authenticating_a_remote_jobs_link_round_trips_through_the_registry() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let mut job = mint_job_channel("job-1", registry.authority()).await?;
        let executor_ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let link = RemoteLink::new(executor_ip)?;
        let token = *link.token().as_bytes();
        job.remote_link = Some(link);
        registry.insert("job-1".to_owned(), job);

        registry.authenticate_remote_link("job-1", executor_ip, &token)?;
        match registry.authenticate_remote_link("job-1", executor_ip, &token) {
            Err(e) => assert_eq!(e, LinkAuthError::AlreadyClaimed),
            Ok(_) => panic!("a second stream for the same run must be refused"),
        }
        Ok(())
    }

    /// Regression (#269 token-lifecycle): a cancelled job's token is still
    /// cryptographically valid and still unclaimed — nothing about the token
    /// itself changes on cancel. Without `invalidate_remote_link`, a stream
    /// arriving after cancellation would present that same valid token and
    /// authenticate successfully; this test fails under that gap and passes
    /// once cancellation calls `invalidate_remote_link` before the token can
    /// be presented again.
    #[tokio::test]
    async fn a_cancelled_jobs_late_arriving_stream_gets_zero_bytes() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let mut job = mint_job_channel("job-1", registry.authority()).await?;
        let executor_ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let link = RemoteLink::new(executor_ip)?;
        let token = *link.token().as_bytes();
        job.remote_link = Some(link);
        registry.insert("job-1".to_owned(), job);

        // Simulates the Cancel control-path calling this before the job's
        // sandbox ever gets a chance to accept the real executor's stream.
        registry.invalidate_remote_link("job-1");

        match registry.authenticate_remote_link("job-1", executor_ip, &token) {
            Err(e) => assert_eq!(e, LinkAuthError::AlreadyClaimed),
            Ok(_) => panic!("a cancelled job's token must never authenticate a late-arriving stream"),
        }
        Ok(())
    }

    /// A job with both links, bound to one executor, and the two tokens.
    async fn job_with_two_links(
        registry: &JobRegistry,
        executor_ip: std::net::IpAddr,
    ) -> anyhow::Result<([u8; link_auth::LINK_TOKEN_LEN], [u8; link_auth::LINK_TOKEN_LEN])> {
        let mut job = mint_job_channel("job-1", registry.authority()).await?;
        let agent = RemoteLink::new(executor_ip)?;
        let data = RemoteLink::new(executor_ip)?;
        let tokens = (*agent.token().as_bytes(), *data.token().as_bytes());
        job.remote_link = Some(agent);
        job.data_link = Some(data);
        registry.insert("job-1".to_owned(), job);
        Ok(tokens)
    }

    /// #482: each token claims only its own link, and claiming one leaves
    /// the other claimable.
    #[tokio::test]
    async fn each_links_token_claims_only_that_link() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let (agent_token, data_token) = job_with_two_links(&registry, ip).await?;

        let (_, kind) = registry.authenticate_incoming_link("job-1", ip, &data_token)?;
        assert_eq!(kind, LinkKind::Data);
        let (_, kind) = registry.authenticate_incoming_link("job-1", ip, &agent_token)?;
        assert_eq!(
            kind,
            LinkKind::Agent,
            "claiming the data link must not spend the agent link"
        );
        Ok(())
    }

    /// #482: a link claims once; the same token again is `AlreadyClaimed`,
    /// for the data link as for the agent link.
    #[tokio::test]
    async fn the_data_link_claims_once() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let (_, data_token) = job_with_two_links(&registry, ip).await?;

        registry.authenticate_incoming_link("job-1", ip, &data_token)?;
        match registry.authenticate_incoming_link("job-1", ip, &data_token) {
            Err(e) => assert_eq!(e, LinkAuthError::AlreadyClaimed),
            Ok(_) => panic!("a second stream on the data token must be refused"),
        }
        Ok(())
    }

    /// #482: a data token is useless from any other peer, and a token that
    /// matches neither link is refused as a wrong token.
    #[tokio::test]
    async fn the_data_link_checks_peer_and_token() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let other: std::net::IpAddr = "100.64.0.9".parse().context("other ip literal")?;
        let (_, data_token) = job_with_two_links(&registry, ip).await?;

        match registry.authenticate_incoming_link("job-1", other, &data_token) {
            Err(e) => assert_eq!(e, LinkAuthError::WrongPeer),
            Ok(_) => panic!("a data token from another peer must be refused"),
        }
        match registry.authenticate_incoming_link("job-1", ip, &[0xAA; link_auth::LINK_TOKEN_LEN]) {
            Err(e) => assert_eq!(e, LinkAuthError::WrongToken),
            Ok(_) => panic!("a token for neither link must be refused"),
        }
        Ok(())
    }

    /// #482: a job with only an agent link (a Dispatch from before the data
    /// link) refuses any other token as wrong, never claims a missing link.
    #[tokio::test]
    async fn a_job_without_a_data_link_refuses_a_foreign_token() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let mut job = mint_job_channel("job-1", registry.authority()).await?;
        job.remote_link = Some(RemoteLink::new(ip)?);
        registry.insert("job-1".to_owned(), job);

        match registry.authenticate_incoming_link("job-1", ip, &[0x55; link_auth::LINK_TOKEN_LEN]) {
            Err(e) => assert_eq!(e, LinkAuthError::WrongToken),
            Ok(_) => panic!("no data link exists to claim"),
        }
        Ok(())
    }

    /// #482: cancel closes both links, not only the agent link.
    #[tokio::test]
    async fn invalidating_a_job_closes_the_data_link_too() -> anyhow::Result<()> {
        use anyhow::Context;
        let registry = JobRegistry::new()?;
        let ip: std::net::IpAddr = "100.64.0.7".parse().context("executor ip literal")?;
        let (_, data_token) = job_with_two_links(&registry, ip).await?;

        registry.invalidate_remote_link("job-1");
        match registry.authenticate_incoming_link("job-1", ip, &data_token) {
            Err(e) => assert_eq!(e, LinkAuthError::AlreadyClaimed),
            Ok(_) => panic!("a cancelled job's data token must never authenticate"),
        }
        Ok(())
    }

    /// Invalidating a job with no remote link, or an unknown job id, is a
    /// no-op — cancel's terminal-path cleanup must never fault just because
    /// the job was local or already gone.
    #[tokio::test]
    async fn invalidating_a_local_or_unknown_job_is_a_no_op() -> anyhow::Result<()> {
        let registry = JobRegistry::new()?;
        let job = mint_job_channel("job-1", registry.authority()).await?;
        registry.insert("job-1".to_owned(), job);

        registry.invalidate_remote_link("job-1");
        registry.invalidate_remote_link("ghost");
        Ok(())
    }

    /// A job's channel is minted from the registry's own authority (#226): a
    /// cap minted independently under a DIFFERENT authority — never shared
    /// with this registry — still fails as `Forged`, the genuinely untrusted
    /// case `WrongChannel` above is not.
    #[tokio::test]
    async fn a_cap_from_an_unrelated_authority_is_forged_not_merely_wrong_channel() -> anyhow::Result<()> {
        let registry = JobRegistry::new()?;
        let job = mint_job_channel("job-1", registry.authority()).await?;

        let impostor_authority = test_authority();
        let impostor_cap = impostor_authority.mint(CapScope {
            peer: PeerId::from("agent"),
            channel: ChannelId::from("job-1"),
            rights: CapRights {
                post: true,
                read: true,
                invite: false,
            },
            expires_at: None,
        })?;
        let err = job
            .channel
            .join(&impostor_cap)
            .expect_err("a cap from an unrelated authority must not join");
        assert!(
            matches!(err, sandy_fabric_local::channel::ChannelError::Cap(CapError::Forged)),
            "got {err:?}"
        );
        Ok(())
    }

    /// #340 item 4: the agent's one-shot archive post is persisted even
    /// though nothing ever joins as an attach client — the whole point of a
    /// job-level, always-on observer rather than relying on
    /// `attach_relay.rs`'s per-connection delivery.
    #[tokio::test]
    async fn an_archive_posted_by_the_agent_is_persisted_with_no_attach_client() -> anyhow::Result<()> {
        let job = mint_job_channel("job-archive", &test_authority()).await?;
        let agent = job.channel.join(&job.agent_cap)?;
        let store = Arc::new(crate::store::JobStore::open_in_memory()?);
        store.insert_pending("job-archive", b"m", "test/v1")?;

        let persisting = tokio::spawn(persist_archive_when_posted(
            Arc::clone(&job.channel),
            job.archiver_cap.clone(),
            "job-archive".to_string(),
            Arc::clone(&store),
            Duration::from_secs(5),
            None,
        ));

        job.channel
            .post(
                &agent,
                Some(MessageType::Output(sandy_proto::Output {})),
                ARCHIVE_TRANSCRIPT,
                b"the whole transcript".to_vec(),
            )
            .await?;

        tokio::time::timeout(Duration::from_secs(5), persisting).await??;

        assert_eq!(store.archive("job-archive")?, Some(b"the whole transcript".to_vec()));
        Ok(())
    }

    /// A job whose agent never posts an archive (crashed, or never ran) must
    /// not leave the persister running forever — it gives up once
    /// `wait_bound` elapses.
    #[tokio::test]
    async fn a_job_that_never_archives_leaves_no_lingering_persister() -> anyhow::Result<()> {
        use anyhow::Context;
        let job = mint_job_channel("job-no-archive", &test_authority()).await?;
        let store = Arc::new(crate::store::JobStore::open_in_memory()?);
        store.insert_pending("job-no-archive", b"m", "test/v1")?;

        let persisting = tokio::spawn(persist_archive_when_posted(
            Arc::clone(&job.channel),
            job.archiver_cap.clone(),
            "job-no-archive".to_string(),
            Arc::clone(&store),
            Duration::from_millis(50),
            None,
        ));

        tokio::time::timeout(Duration::from_secs(5), persisting)
            .await
            .context("the persister must give up once wait_bound elapses, not run forever")??;
        assert_eq!(store.archive("job-no-archive")?, None);
        Ok(())
    }

    /// A plain `channel.join` for the persister's own archiver membership
    /// must never feed `attach_relay.rs`'s `AttachTracking`/`AttachStateChanged`
    /// bookkeeping — that is driven only by `join_for_attach`'s own explicit
    /// calls, never by `Channel::join` itself. A false "attached" signal
    /// would suspend a job's M2 timeout forever.
    #[tokio::test]
    async fn the_persisters_own_join_does_not_register_as_an_attach() -> anyhow::Result<()> {
        let job = mint_job_channel("job-archive-no-attach-tracking", &test_authority()).await?;
        let store = Arc::new(crate::store::JobStore::open_in_memory()?);
        store.insert_pending("job-archive-no-attach-tracking", b"m", "test/v1")?;

        let persisting = tokio::spawn(persist_archive_when_posted(
            Arc::clone(&job.channel),
            job.archiver_cap.clone(),
            "job-archive-no-attach-tracking".to_string(),
            Arc::clone(&store),
            Duration::from_millis(50),
            None,
        ));
        tokio::time::timeout(Duration::from_secs(5), persisting).await??;

        assert_eq!(
            job.attach_tracking
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .count,
            0,
            "the persister's own read-only join must not register as an attach"
        );
        Ok(())
    }

    /// Regression: an attach client using `observer_cap` joining and then
    /// leaving must not end the persister's OWN subscription. Before the
    /// persister was given its own dedicated `archiver_cap`, both shared one
    /// `MembershipId` (a digest of the cap's proof bytes) — `Channel::leave`
    /// removes that id's whole session entry, which `CursorStream::poll_next`
    /// checks for EVERY stream still reading it, so the attacher's detach
    /// silently ended the persister's stream too, well before the agent ever
    /// posted its archive.
    #[tokio::test]
    async fn an_attach_clients_detach_does_not_end_the_archive_persisters_subscription() -> anyhow::Result<()> {
        let job = mint_job_channel("job-archive-survives-detach", &test_authority()).await?;
        let agent = job.channel.join(&job.agent_cap)?;
        let store = Arc::new(crate::store::JobStore::open_in_memory()?);
        store.insert_pending("job-archive-survives-detach", b"m", "test/v1")?;

        let persisting = tokio::spawn(persist_archive_when_posted(
            Arc::clone(&job.channel),
            job.archiver_cap.clone(),
            "job-archive-survives-detach".to_string(),
            Arc::clone(&store),
            Duration::from_secs(5),
            None,
        ));

        // `#[tokio::test]` is current-thread: the spawned persister makes no
        // progress until this task actually yields. Wait for it to have
        // joined (member count: agent + persister = 2) before the attacher's
        // own join/leave below, or the attacher could leave BEFORE the
        // persister ever subscribes — which wouldn't reproduce the bug this
        // test regresses (the persister joining fresh afterward and
        // replaying from cursor 0 would still see the later archive post,
        // masking the real race).
        let join_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while job.channel.member_count() < 2 {
            anyhow::ensure!(
                tokio::time::Instant::now() < join_deadline,
                "the persister never joined"
            );
            tokio::task::yield_now().await;
        }

        // An ordinary attach client's full lifecycle: join with the cap a
        // real attacher would hold, subscribe (as `attach_relay::relay`
        // does), then leave (as a detach does).
        let attacher = job.channel.join(&job.observer_cap)?;
        let _ = job.channel.subscribe(&attacher)?;
        job.channel.leave(&attacher);

        job.channel
            .post(
                &agent,
                Some(MessageType::Output(sandy_proto::Output {})),
                ARCHIVE_TRANSCRIPT,
                b"the whole transcript".to_vec(),
            )
            .await?;

        tokio::time::timeout(Duration::from_secs(5), persisting).await??;
        assert_eq!(
            store.archive("job-archive-survives-detach")?,
            Some(b"the whole transcript".to_vec())
        );
        Ok(())
    }
}
