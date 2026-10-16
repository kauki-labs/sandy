//! Channel-role payload types (spec §3.4, #113): the orchestrator-assignment
//! message, shared between the role wrappers that send it (an impl crate's
//! `Channel` layer) and the agent that reads it (#109), so neither side depends
//! on the other's crate for the wire shape.
//!
//! A `Control`-typed envelope's payload is deferred by the proto itself ("the
//! concrete per-type contracts are deferred... the content rides in payload"):
//! [`ChannelAssignment`] is that content for a channel-grow message, JSON-encoded
//! rather than a new nested protobuf message, matching [`crate::capauth::encode_cap`]'s
//! own encoding choice for [`Cap`] so the agent has one deserialization story for
//! a cap whether it arrives via the bootstrap fd or a later assignment.

use serde::{Deserialize, Serialize};

use crate::{capauth::Cap, types::ChannelId};

/// What a [`ChannelAssignment`] is for, so the receiving agent dispatches on an
/// explicit tag rather than inferring intent from the cap's rights or the
/// channel id — forward-compatible with a role added later (spec §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRole {
    /// The closed peer-group channel: agents coordinating directly.
    PeerGroup,
    /// The escalation channel: reaches a human, independent of the orchestrator.
    Escalation,
}

/// Grow a sandbox's channel membership after bootstrap: join `channel_id` with
/// `cap`, for `role`. Carried as the JSON payload of a `Control`-typed envelope
/// on the orchestrator channel (the bootstrap channel itself arrives over the
/// launch fd, not this message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelAssignment {
    /// The channel to join.
    pub channel_id: ChannelId,
    /// The capability to join it with — already scoped to `channel_id` by
    /// construction; the agent still verifies it, never trusts it blind.
    pub cap: Cap,
    /// What the channel is for.
    pub role: ChannelRole,
}

/// A [`ChannelAssignment`] codec failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("channel assignment codec: {0}")]
pub struct AssignmentCodecError(String);

/// Encode `assignment` for a `Control` envelope's payload.
///
/// # Errors
/// Returns [`AssignmentCodecError`] if JSON serialization fails (an invariant
/// violation of `Cap`/`ChannelId`'s own `Serialize` impls, not an expected
/// runtime condition).
pub fn encode_assignment(assignment: &ChannelAssignment) -> Result<Vec<u8>, AssignmentCodecError> {
    serde_json::to_vec(assignment).map_err(|e| AssignmentCodecError(e.to_string()))
}

/// Decode bytes written by [`encode_assignment`].
///
/// # Errors
/// Returns [`AssignmentCodecError`] if `bytes` is not a valid encoded
/// [`ChannelAssignment`] — a malformed or foreign payload, never a panic.
pub fn decode_assignment(bytes: &[u8]) -> Result<ChannelAssignment, AssignmentCodecError> {
    serde_json::from_slice(bytes).map_err(|e| AssignmentCodecError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capauth::{CapRights, CapScope};

    fn assignment() -> ChannelAssignment {
        ChannelAssignment {
            channel_id: ChannelId::from("peer-group-1"),
            cap: Cap {
                scope: CapScope {
                    peer: "agent-1".into(),
                    channel: ChannelId::from("peer-group-1"),
                    rights: CapRights {
                        post: true,
                        read: true,
                        invite: false,
                    },
                    expires_at: None,
                },
                proof: vec![1, 2, 3],
            },
            role: ChannelRole::PeerGroup,
        }
    }

    #[test]
    fn an_assignment_round_trips_through_its_encoding() -> Result<(), AssignmentCodecError> {
        let encoded = encode_assignment(&assignment())?;
        assert!(
            decode_assignment(&encoded)? == assignment(),
            "the assignment changed in the round trip"
        );
        Ok(())
    }

    #[test]
    fn a_foreign_payload_is_a_codec_error_not_a_panic() {
        assert!(decode_assignment(b"not json").is_err());
    }
}
