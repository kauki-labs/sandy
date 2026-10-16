//! Identifier newtypes shared across the fabric seams.
//!
//! Plain string newtypes: the fabric never interprets an id, it only compares and
//! routes by it, so the caller (static registry, tracker, DHT) chooses the format.

use serde::{Deserialize, Serialize};

/// A fabric participant: a sandbox agent, the orchestrator, or a human endpoint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

/// A channel: the bounded membership set messages are posted to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub String);

/// A host in the fleet that can provide sandboxes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HostId(pub String);

macro_rules! from_str_impls {
    ($($ty:ident),*) => {$(
        impl From<&str> for $ty {
            fn from(s: &str) -> Self {
                Self(s.to_owned())
            }
        }
        impl From<String> for $ty {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    )*};
}
from_str_impls!(PeerId, ChannelId, HostId);
