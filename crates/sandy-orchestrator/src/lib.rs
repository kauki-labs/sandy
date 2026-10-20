//! `sandy-orchestrator`: the sandyd dispatch core (epic #205, B2 skeleton + B3,
//! #218).
//!
//! This first cut holds only B3: the job manifest and the submitter-bounded
//! capability derivation (decision C) — "a job can never be granted more
//! capability than its submitter holds." The full dispatch core (wiring
//! Submit through Discovery→place, Executor→provision, Channel→wire,
//! Agent→run) is separate, larger follow-on work once those fabric seams are
//! composed end to end; this crate is where it will live, not built here.
//!
//! [`JobManifest`] is a pure in-process domain type, not (yet) tied to any
//! wire format: `sandy-control-proto`'s `SubmitRequest.manifest` carries the
//! submitted manifest as opaque bytes today (#211/#214), with the real typed
//! protobuf `JobManifest` arriving there once that crate lands. Converting
//! between the two is a small follow-up then; building the derivation logic
//! against this Rust type now is not gated on it, since the fabric seams it
//! needs (`CapAuthority`, `Cap`, `attenuate`) are already on main.
//!
//! `serde` derives (#226): `sandyd`'s Submit decodes a JSON-encoded
//! `JobManifest` from `SubmitRequest.manifest` when `manifest_encoding` names
//! it and `submitter_caps` are present, to call [`derive_job_caps`] — the
//! first real consumer of a serialized form. A submission that doesn't invoke
//! the bounded path (no `submitter_caps`) still never needs to decode this at
//! all.

use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights},
    types::ChannelId,
};
use serde::{Deserialize, Serialize};

/// What the job will run. Deliberately minimal for this first cut — the full
/// shape (working directory, environment, secrets, …) is dispatch-core work
/// (the fuller B2), not B3's concern; this just needs to exist on
/// [`JobManifest`] per the epic's "a job = entrypoint + capability manifest."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEntrypoint {
    /// The command and its arguments, `argv[0]` first.
    pub command: Vec<String>,
}

/// One capability a job asks to be granted: `rights` on `channel_id`, capped
/// at whatever the submitter already holds there (decision C).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapRequest {
    /// The channel the job wants to join.
    pub channel_id: ChannelId,
    /// The rights requested on it.
    pub rights: CapRights,
}

/// A job's manifest: what it runs, and what capabilities it asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobManifest {
    /// What the job will run.
    pub entrypoint: JobEntrypoint,
    /// The capabilities it requests; each is capped at the submitter's own
    /// held capability for that channel (decision C, enforced by
    /// [`derive_job_caps`]).
    pub requested_caps: Vec<CapRequest>,
}

/// The `manifest_encoding` tag `sandyd`'s Submit recognizes for a JSON-encoded
/// [`JobManifest`] (#226). Any other (or absent) encoding stays fully opaque
/// — Submit never guesses a shape for bytes it doesn't recognize.
pub const MANIFEST_ENCODING_JSON: &str = "sandy.orchestrator.v1.JobManifest+json";

/// A manifest could not be honoured.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The submitter holds no capability at all for a requested channel —
    /// there is nothing to attenuate from.
    #[error("no held capability for channel {0:?}")]
    NoSuchCapability(ChannelId),
    /// A requested capability exceeds (or otherwise fails) the submitter's
    /// held one: [`CapError::Widened`] for an outright escalation attempt,
    /// or any other [`CapError`] the authority raises while attenuating
    /// (e.g. a submitter cap that has expired or was revoked since it was
    /// issued).
    #[error(transparent)]
    Cap(#[from] CapError),
}

/// Derive the capabilities a job may actually be granted, by attenuating
/// `submitter_caps` against `manifest`'s requests (decision C): a job can
/// never be granted more than its submitter holds.
///
/// Each request is matched to the submitter's held capability for the same
/// channel, then narrowed via [`CapAuthority::attenuate`] — which already
/// enforces the no-escalation rule ([`CapError::Widened`] when the requested
/// rights are not a subset of the held cap's) and re-verifies the held cap
/// itself (so an expired or revoked submitter cap is caught here too, not
/// trusted blind). This function adds no authorization logic of its own; it
/// only wires the manifest through that existing, already-contract-tested
/// guard — a second, independent subset check here would risk drifting out
/// of sync with `attenuate`'s own rule rather than add real defense.
///
/// Fail-closed and atomic: if any single requested capability cannot be
/// granted, the whole manifest is rejected and **no** capabilities are
/// returned — never a partial grant. A job either gets exactly the
/// capability set it asked for, or none of it.
///
/// The same function covers an `Attach` request's cap too (`sandy-control-proto`'s
/// `AttachResponse`): call it with the job's own held caps as `submitter_caps`
/// to derive a further-narrowed cap scoped to the attach.
///
/// # Errors
///
/// [`ManifestError::NoSuchCapability`] if `submitter_caps` holds nothing for
/// a requested channel at all. [`ManifestError::Cap`] for any
/// [`CapAuthority::attenuate`] failure (a requested right the submitter's
/// cap doesn't have, or a submitter cap that no longer verifies).
pub fn derive_job_caps<A: CapAuthority>(
    authority: &A,
    submitter_caps: &[Cap],
    manifest: &JobManifest,
) -> Result<Vec<Cap>, ManifestError> {
    manifest
        .requested_caps
        .iter()
        .map(|request| {
            let held = submitter_caps
                .iter()
                .find(|cap| cap.scope().channel == request.channel_id)
                .ok_or_else(|| ManifestError::NoSuchCapability(request.channel_id.clone()))?;
            Ok(authority.attenuate(held, request.rights)?)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context;
    use sandy_fabric::capauth::CapScope;
    use sandy_fabric_local::LocalCapAuthority;

    use super::*;

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

    fn entrypoint() -> JobEntrypoint {
        JobEntrypoint {
            command: vec!["true".to_owned()],
        }
    }

    fn hold(authority: &LocalCapAuthority, peer: &str, channel: &str, rights: CapRights) -> anyhow::Result<Cap> {
        Ok(authority.mint(CapScope {
            peer: peer.into(),
            channel: ChannelId::from(channel),
            rights,
            expires_at: None,
        })?)
    }

    #[test]
    fn a_request_within_the_submitters_rights_derives_an_attenuated_cap() -> anyhow::Result<()> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let submitter = hold(&authority, "operator", "peer-group-1", full())?;
        let manifest = JobManifest {
            entrypoint: entrypoint(),
            requested_caps: vec![CapRequest {
                channel_id: ChannelId::from("peer-group-1"),
                rights: read_only(),
            }],
        };

        let granted = derive_job_caps(&authority, &[submitter], &manifest).context("derive_job_caps")?;
        anyhow::ensure!(granted.len() == 1, "expected exactly one granted cap");
        anyhow::ensure!(
            granted[0].scope().rights == read_only(),
            "the granted cap must carry exactly the requested rights, got {:?}",
            granted[0].scope().rights
        );
        // The attenuated cap must itself verify — derive_job_caps must not
        // hand back something the authority would reject downstream.
        authority.verify(&granted[0]).context("granted cap failed to verify")?;
        Ok(())
    }

    /// Decision C's core property: a request for more than the submitter holds
    /// is rejected outright, with the underlying `Widened` propagated, never
    /// silently narrowed to whatever the submitter does hold.
    #[test]
    fn a_request_exceeding_the_submitters_rights_fails_with_widened_not_swallowed() -> anyhow::Result<()> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let submitter = hold(&authority, "operator", "peer-group-1", read_only())?;
        let manifest = JobManifest {
            entrypoint: entrypoint(),
            requested_caps: vec![CapRequest {
                channel_id: ChannelId::from("peer-group-1"),
                rights: full(),
            }],
        };

        let err = derive_job_caps(&authority, &[submitter], &manifest).expect_err("escalation must be rejected");
        anyhow::ensure!(
            matches!(err, ManifestError::Cap(CapError::Widened)),
            "expected Cap(Widened), got {err:?}"
        );
        Ok(())
    }

    /// Fail-closed AND atomic: one un-grantable request among several
    /// grantable ones must fail the whole manifest, not grant the valid
    /// requests and drop the invalid one.
    #[test]
    fn one_bad_request_among_several_good_ones_zeroes_the_whole_manifest() -> anyhow::Result<()> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let submitter_a = hold(&authority, "operator", "peer-group-1", full())?;
        let submitter_b = hold(&authority, "operator", "escalation-1", read_only())?;
        let manifest = JobManifest {
            entrypoint: entrypoint(),
            requested_caps: vec![
                // Grantable: within what's held.
                CapRequest {
                    channel_id: ChannelId::from("peer-group-1"),
                    rights: read_only(),
                },
                // Not grantable: exceeds what's held for this channel.
                CapRequest {
                    channel_id: ChannelId::from("escalation-1"),
                    rights: full(),
                },
            ],
        };

        let err = derive_job_caps(&authority, &[submitter_a, submitter_b], &manifest)
            .expect_err("a manifest with any un-grantable request must fail entirely");
        anyhow::ensure!(
            matches!(err, ManifestError::Cap(CapError::Widened)),
            "expected the failing request's own error, got {err:?}"
        );
        Ok(())
    }

    /// A request for a channel the submitter holds no capability for at all
    /// is rejected by name, not silently skipped or matched to an unrelated
    /// held cap.
    #[test]
    fn a_request_for_an_unheld_channel_is_rejected_not_skipped() -> anyhow::Result<()> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let submitter = hold(&authority, "operator", "peer-group-1", full())?;
        let manifest = JobManifest {
            entrypoint: entrypoint(),
            requested_caps: vec![CapRequest {
                channel_id: ChannelId::from("escalation-1"),
                rights: read_only(),
            }],
        };

        let err = derive_job_caps(&authority, &[submitter], &manifest)
            .expect_err("a request for an unheld channel must fail");
        anyhow::ensure!(
            matches!(&err, ManifestError::NoSuchCapability(c) if *c == ChannelId::from("escalation-1")),
            "expected NoSuchCapability(escalation-1), got {err:?}"
        );
        Ok(())
    }

    /// An empty manifest (no capability requests) is trivially satisfied: not
    /// an error, and grants nothing.
    #[test]
    fn an_empty_manifest_grants_no_capabilities() -> anyhow::Result<()> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let manifest = JobManifest {
            entrypoint: entrypoint(),
            requested_caps: vec![],
        };

        let granted = derive_job_caps(&authority, &[], &manifest).context("derive_job_caps")?;
        anyhow::ensure!(granted.is_empty(), "an empty manifest must grant nothing");
        Ok(())
    }

    /// A submitter cap that no longer verifies (revoked since it was issued)
    /// is caught by `attenuate`'s own re-verify, not trusted blind because it
    /// was found in `submitter_caps`.
    #[test]
    fn a_revoked_submitter_cap_is_rejected_not_trusted_blind() -> anyhow::Result<()> {
        let authority = LocalCapAuthority::new(Duration::from_secs(3600))?;
        let submitter = hold(&authority, "operator", "peer-group-1", full())?;
        authority.revoke(&submitter);
        let manifest = JobManifest {
            entrypoint: entrypoint(),
            requested_caps: vec![CapRequest {
                channel_id: ChannelId::from("peer-group-1"),
                rights: read_only(),
            }],
        };

        let err = derive_job_caps(&authority, &[submitter], &manifest).expect_err("a revoked submitter cap must fail");
        anyhow::ensure!(
            matches!(err, ManifestError::Cap(CapError::Revoked)),
            "expected Cap(Revoked), got {err:?}"
        );
        Ok(())
    }

    /// A `JobManifest` round-trips through JSON (#226): `sandyd`'s Submit
    /// decodes exactly this shape from a `SubmitRequest.manifest` tagged
    /// [`MANIFEST_ENCODING_JSON`].
    #[test]
    fn a_job_manifest_round_trips_through_json() -> anyhow::Result<()> {
        let manifest = JobManifest {
            entrypoint: entrypoint(),
            requested_caps: vec![CapRequest {
                channel_id: ChannelId::from("peer-group-1"),
                rights: read_only(),
            }],
        };
        let json = serde_json::to_vec(&manifest).context("encode")?;
        let decoded: JobManifest = serde_json::from_slice(&json).context("decode")?;
        assert_eq!(decoded, manifest);
        Ok(())
    }
}
