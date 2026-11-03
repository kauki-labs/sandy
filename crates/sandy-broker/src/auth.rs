//! Bearer-token authentication against the clients file.

use sha2::{Digest, Sha256};

use crate::Client;

/// Finds the client whose token hash matches `authorization` (`Bearer <token>`).
///
/// Compares against every client without an early exit, so timing does not
/// reveal which client matched or how much of a hash agreed.
pub(crate) fn authenticate<'a>(clients: &'a [Client], authorization: Option<&str>) -> Option<&'a Client> {
    let token = authorization?.strip_prefix("Bearer ")?;
    let presented = hex::encode(Sha256::digest(token.as_bytes()));
    let mut found = None;
    for client in clients {
        if constant_time_eq(presented.as_bytes(), client.token_sha256.as_bytes()) {
            found = Some(client);
        }
    }
    found
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
