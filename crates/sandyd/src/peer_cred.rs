//! Peer-credential gate for sandyd's UDS listeners (#533).
//!
//! The deployment model is one sandyd per submitter user (`User=%i`), so the only peer that may
//! drive the daemon is a process with the daemon's own effective uid. The socket is mode 0600,
//! which already blocks other uids except root; this check refuses those too, and keeps holding
//! if the socket mode is ever loosened or the fd is passed to another uid.

use tokio::net::UnixStream;

/// Why a connection was refused at accept time.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerRefused {
    /// The peer's uid differs from the daemon's.
    #[error("peer uid {peer_uid} is not the daemon's uid {owner_uid}")]
    ForeignUid {
        /// The connecting process's uid.
        peer_uid: u32,
        /// The uid sandyd runs as.
        owner_uid: u32,
    },
    /// The kernel could not report the peer's credentials; refuse rather than guess.
    #[error("peer credentials unavailable: {0}")]
    Unavailable(String),
}

/// Accept `stream` only when its peer runs as this daemon's effective uid.
///
/// # Errors
/// [`PeerRefused`] when the peer uid differs or cannot be read.
pub fn require_same_user(stream: &UnixStream) -> Result<(), PeerRefused> {
    require_user(stream, rustix::process::geteuid().as_raw())
}

fn require_user(stream: &UnixStream, owner_uid: u32) -> Result<(), PeerRefused> {
    let cred = stream
        .peer_cred()
        .map_err(|err| PeerRefused::Unavailable(err.to_string()))?;
    if cred.uid() == owner_uid {
        Ok(())
    } else {
        Err(PeerRefused::ForeignUid {
            peer_uid: cred.uid(),
            owner_uid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_peer_with_the_daemons_uid_is_accepted() -> anyhow::Result<()> {
        let (a, _b) = UnixStream::pair()?;
        require_same_user(&a)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_peer_with_another_uid_is_refused() -> anyhow::Result<()> {
        let (a, _b) = UnixStream::pair()?;
        let own = rustix::process::geteuid().as_raw();
        let other = own.wrapping_add(1);

        assert_eq!(
            require_user(&a, other),
            Err(PeerRefused::ForeignUid {
                peer_uid: own,
                owner_uid: other
            })
        );
        Ok(())
    }
}
