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
    time::Duration,
};

use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights, CapScope},
    types::{ChannelId, PeerId},
};
use sandy_fabric_local::{LocalCapAuthority, SharedCapAuthority, channel::Channel, inmem::InMem};
use uuid::Uuid;

use crate::link_auth::{self, LinkAuthError, RemoteLink};

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
    /// The cap `Attach` hands to an observing client: read-only, no `post` —
    /// an attached client watches the job's TTY, it does not drive its stdin
    /// through this cap. A caller wanting to drive input needs a `post`-
    /// capable cap, deliberately not what `Attach` alone grants.
    pub observer_cap: Cap,
    /// This run's binding to a remote executor (#212 decision 6), if it has
    /// one. `None` for a job dispatched locally, which has no mesh stream to
    /// authenticate — `serve_agent_link` runs directly over a private
    /// socketpair there. Set at dispatch, never mutated after.
    pub remote_link: Option<RemoteLink>,
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

    let channel = Channel::new(channel_id, InMem::default(), authority.clone()).await?;
    Ok(JobChannel {
        channel: Arc::new(channel),
        agent_cap,
        observer_cap,
        remote_link: None,
        granted_caps: Vec::new(),
        session: Uuid::nil(),
    })
}

/// Every submitted job's minted channel, keyed by job id, plus the one
/// [`SharedCapAuthority`] every job's channel and every submitter-held cap
/// verified at Submit are minted/checked against (#226). Process-local and
/// ephemeral by design — channels are in-memory (the all-local MVP's step-1
/// `ChannelBackend`), so this registry holds no state that needs to survive a
/// restart; the sqlite job store is the durable record.
pub struct JobRegistry {
    jobs: Mutex<HashMap<String, Arc<JobChannel>>>,
    authority: SharedCapAuthority,
}

impl JobRegistry {
    /// A fresh, empty registry with a new, randomly-keyed authority.
    ///
    /// # Errors
    /// [`CapError::Authority`] if the system RNG is unavailable.
    pub fn new() -> Result<Self, CapError> {
        Ok(Self {
            jobs: Mutex::new(HashMap::new()),
            authority: SharedCapAuthority::new(LocalCapAuthority::new(CAP_TTL)?),
        })
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
    pub fn insert(&self, job_id: String, job: JobChannel) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job_id, Arc::new(job));
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

    /// Invalidate `job_id`'s remote link, if it has one, so a stream arriving
    /// after this point can never claim it (#269's token-lifecycle
    /// requirement: cancel, dispatch timeout, and executor teardown must each
    /// close this off). A no-op if the job has no remote link or is unknown —
    /// the caller has already decided whether the terminal transition itself
    /// (cancel, timeout, …) succeeded; this only cleans up the link that
    /// transition leaves behind.
    pub fn invalidate_remote_link(&self, job_id: &str) {
        let Some(job) = self.get(job_id) else { return };
        let Some(link) = job.remote_link.as_ref() else {
            return;
        };
        link.invalidate();
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
}
