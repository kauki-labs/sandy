//! The transport seam (spec §3.9): moves opaque frames between peers.
//!
//! Built for the hard case: store-and-forward over a link nobody can assume is
//! live. A send to a peer that is offline, or not yet seen, is accepted and
//! delivered when that peer next polls. In-memory first, then vsock; a remote P2P
//! overlay is a deferred impl over the same contract.

use std::future::Future;

use crate::types::PeerId;

/// A frame delivered to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The sending peer.
    pub from: PeerId,
    /// The opaque frame bytes.
    pub bytes: Vec<u8>,
}

/// A transport failure. An unreachable peer is not one: the frame is queued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The transport is shut down.
    #[error("transport closed")]
    Closed,
    /// The underlying link failed.
    #[error("transport I/O: {0}")]
    Io(String),
}

/// Moves frames between peers, store-and-forward.
pub trait Transport: Send + Sync {
    /// Queue `frame` from `from` for delivery to `to`.
    fn send(&self, from: &PeerId, to: &PeerId, frame: &[u8])
    -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Drain the frames queued for `me`, in send order. A frame is delivered once.
    fn poll(&self, me: &PeerId) -> impl Future<Output = Result<Vec<Frame>, TransportError>> + Send;
}
