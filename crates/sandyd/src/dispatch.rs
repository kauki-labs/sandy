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
//! **Known, tracked gap (#226): caps are minted directly, not derived from
//! the submitter.** [`mint_job_channel`] mints the agent/observer caps
//! straight from a fresh [`LocalCapAuthority`], with no reference to who
//! submitted the job or what THEY hold — decision C (a job's caps bounded by
//! the submitter's own attenuation, enforced by #219's `derive_job_caps`, not
//! called here) is not wired in. That is a deliberate, acceptable shape for a
//! single trusted local operator submitting through `sandyd`'s own control
//! RPC — there is no untrusted submitter yet, and no submitter identity/caps
//! reach this layer to derive from. It stops being safe the moment a
//! submitter is anything other than the orchestrator itself (a cross-machine
//! client, a sub-agent submitting a sub-job). #226 tracks wiring the
//! submitter's identity and held caps into Submit and calling
//! `derive_job_caps` instead of minting directly.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights, CapScope},
    types::{ChannelId, PeerId},
};
use sandy_fabric_local::{LocalCapAuthority, channel::Channel, inmem::InMem};

/// A job's dedicated orchestrator channel, minted at submit time.
pub struct JobChannel {
    /// The channel itself, keyed by the job's own id (spec §3.4: dedicated,
    /// one per sandbox).
    pub channel: Arc<Channel<InMem, LocalCapAuthority>>,
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

/// Mint `job_id`'s dedicated channel plus its agent and observer caps.
///
/// # Errors
/// [`DispatchError::Cap`] if the capability authority cannot mint (e.g. no OS
/// entropy); [`DispatchError::Channel`] if the channel's backend cannot be
/// constructed.
pub async fn mint_job_channel(job_id: &str) -> Result<JobChannel, DispatchError> {
    let authority = LocalCapAuthority::new(CAP_TTL)?;
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

    let channel = Channel::new(channel_id, InMem::default(), authority).await?;
    Ok(JobChannel {
        channel: Arc::new(channel),
        agent_cap,
        observer_cap,
    })
}

/// Every submitted job's minted channel, keyed by job id. Process-local and
/// ephemeral by design — channels are in-memory (the all-local MVP's step-1
/// `ChannelBackend`), so this registry holds no state that needs to survive a
/// restart; the sqlite job store is the durable record.
#[derive(Default)]
pub struct JobRegistry {
    jobs: Mutex<HashMap<String, Arc<JobChannel>>>,
}

impl JobRegistry {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn minted_caps_are_scoped_to_the_jobs_own_channel() -> anyhow::Result<()> {
        let job = mint_job_channel("job-1").await?;
        job.channel.join(&job.agent_cap)?;
        job.channel.join(&job.observer_cap)?;
        Ok(())
    }

    /// Adversarial: the observer cap must not carry `post` — attaching to
    /// watch a job must never also grant the ability to inject its stdin.
    #[tokio::test]
    async fn the_observer_cap_cannot_post() -> anyhow::Result<()> {
        let job = mint_job_channel("job-1").await?;
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
    /// different job's channel — two jobs never share membership. Each job
    /// mints its own [`LocalCapAuthority`] (a distinct HMAC key), so a
    /// cross-job cap fails signature verification outright (`Forged`);
    /// `WrongChannel` is for a same-authority cap scoped to a different
    /// channel, which this per-job-authority design never produces.
    #[tokio::test]
    async fn a_cap_for_one_job_is_refused_by_another_jobs_channel() -> anyhow::Result<()> {
        let job_a = mint_job_channel("job-a").await?;
        let job_b = mint_job_channel("job-b").await?;
        let err = job_b
            .channel
            .join(&job_a.agent_cap)
            .expect_err("a cap minted for job-a must not join job-b's channel");
        assert!(
            matches!(err, sandy_fabric_local::channel::ChannelError::Cap(CapError::Forged)),
            "got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn the_registry_returns_none_for_an_unregistered_job() {
        let registry = JobRegistry::default();
        assert!(registry.get("ghost").is_none());
    }

    #[tokio::test]
    async fn the_registry_round_trips_a_registered_job() -> anyhow::Result<()> {
        let registry = JobRegistry::default();
        let job = mint_job_channel("job-1").await?;
        let agent_cap_proof = job.agent_cap.proof.clone();
        registry.insert("job-1".to_owned(), job);

        let found = registry.get("job-1").expect("job-1 was registered");
        assert_eq!(found.agent_cap.proof, agent_cap_proof);
        assert!(registry.get("job-2").is_none());
        Ok(())
    }
}
