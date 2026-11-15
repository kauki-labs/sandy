//! Authentication against the clients file: a bearer token over loopback, or a pinned certificate over mutual TLS
//! (`docs/decisions/broker-api.md` decisions 2 and 10).

use std::collections::{HashMap, HashSet};

use sandy_conn::Fingerprint;
use sha2::{Digest, Sha256};

use crate::{Client, server::Peer};

/// The current time in unix seconds, or `None` when the clock cannot be read (it is before the epoch).
pub(crate) fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

#[derive(Debug, Clone, Copy)]
struct Pin {
    /// The index of the client the certificate is pinned to.
    client: usize,
    not_after: Option<u64>,
}

/// Every client's pinned certificates, by fingerprint (decision 10). A fingerprint belongs to one client.
#[derive(Debug, Default)]
pub(crate) struct Pins(HashMap<Fingerprint, Pin>);

impl Pins {
    /// Parse every pin. A fingerprint is exactly 64 ASCII hex digits and is pinned once, to one client: anything else
    /// is a message naming the client, so the broker refuses to start rather than guess.
    pub(crate) fn build(clients: &[Client]) -> Result<Self, String> {
        let mut pins = HashMap::new();
        for (index, client) in clients.iter().enumerate() {
            for cert in &client.certs {
                let fingerprint = Fingerprint::from_hex(&cert.sha256).map_err(|_| {
                    format!(
                        "client {:?}: certificate fingerprint {:?} is not exactly 64 hex digits",
                        client.id, cert.sha256
                    )
                })?;
                let pin = Pin {
                    client: index,
                    not_after: cert.not_after,
                };
                if let Some(earlier) = pins.insert(fingerprint, pin) {
                    return Err(format!(
                        "certificate fingerprint {} is pinned for more than one entry: clients {:?} and {:?}",
                        fingerprint.to_hex(),
                        clients[earlier.client].id,
                        client.id
                    ));
                }
            }
        }
        Ok(Self(pins))
    }

    /// The fingerprints whose pins are not past their `not_after` at `now`: what the handshake admits.
    ///
    /// `now` is `None` when the clock cannot be read: time-based checks cannot be trusted then, so no pin is live,
    /// whatever its `not_after` (a pin with none included).
    pub(crate) fn live(&self, now: Option<u64>) -> HashSet<Fingerprint> {
        let Some(now) = now else {
            return HashSet::new();
        };
        self.0
            .iter()
            .filter(|(_, pin)| pin.not_after.is_none_or(|deadline| now <= deadline))
            .map(|(fingerprint, _)| *fingerprint)
            .collect()
    }

    /// The client `fingerprint` is pinned to, unless its pin is past `not_after` at `now`. Checked on every request,
    /// so a connection that outlives its pin stops working at the deadline. The fingerprint is a hash of a public
    /// certificate, so nothing secret is compared and the lookup need not be constant time.
    pub(crate) fn client<'a>(
        &self,
        clients: &'a [Client],
        fingerprint: &Fingerprint,
        now: Option<u64>,
    ) -> Option<&'a Client> {
        // An unreadable clock refuses every pin, as in `live`.
        let now = now?;
        let pin = self.0.get(fingerprint)?;
        if pin.not_after.is_some_and(|deadline| now > deadline) {
            return None;
        }
        clients.get(pin.client)
    }
}

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

/// The client a request is from, by how its connection was authenticated (decision 10). Over mutual TLS the
/// `Authorization` header is not read: the certificate is the only credential, so a valid token for any client
/// neither changes who the caller is nor rescues a certificate that is not pinned or whose pin has expired.
pub(crate) fn resolve<'a>(
    clients: &'a [Client],
    pins: &Pins,
    peer: Peer,
    authorization: Option<&str>,
    now: Option<u64>,
) -> Option<&'a Client> {
    match peer {
        Peer::Bearer => authenticate(clients, authorization),
        Peer::Cert(fingerprint) => pins.client(clients, &fingerprint, now),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertPin, IsolationClass};

    fn token_hash(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    fn fingerprint(byte: u8) -> Fingerprint {
        Fingerprint::from_hex(&hex::encode([byte; 32])).expect("64 hex digits")
    }

    /// A client that holds BOTH credentials, which no valid clients file allows (startup refuses a token in mTLS
    /// mode): the point is that `resolve` does not depend on that refusal to ignore the header over mTLS.
    fn client(id: &str, token: &str, pin: u8, not_after: Option<u64>) -> Client {
        Client {
            id: id.to_owned(),
            token_sha256: token_hash(token),
            certs: vec![CertPin {
                sha256: hex::encode([pin; 32]),
                not_after,
            }],
            max_isolation_class: IsolationClass::Trusted,
            max_environments: 4,
            max_environment_records: 64,
            profiles: Vec::new(),
            roots: Vec::new(),
        }
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    /// The header is not read over mTLS: a certificate pinned to A is A whatever token is sent, a valid token of B
    /// cannot rescue a certificate that is not pinned, and one cannot rescue an expired pin either.
    #[test]
    fn a_token_never_decides_the_client_over_mtls() {
        let clients = [client("a", "ta", 1, None), client("b", "tb", 2, Some(100))];
        let pins = Pins::build(&clients).expect("distinct pins");
        let id = |peer: Peer, header: Option<&str>, now: u64| {
            resolve(&clients, &pins, peer, header, Some(now)).map(|c| c.id.as_str())
        };

        assert_eq!(
            id(Peer::Cert(fingerprint(1)), Some(&bearer("tb")), 50),
            Some("a"),
            "B's token on A's certificate"
        );
        assert_eq!(id(Peer::Cert(fingerprint(1)), None, 50), Some("a"), "no header at all");
        assert_eq!(
            id(Peer::Cert(fingerprint(9)), Some(&bearer("tb")), 50),
            None,
            "an unpinned certificate with a valid token"
        );
        assert_eq!(
            id(Peer::Cert(fingerprint(2)), Some(&bearer("tb")), 101),
            None,
            "an expired pin with its own valid token"
        );
        assert_eq!(
            id(Peer::Cert(fingerprint(2)), None, 100),
            Some("b"),
            "a pin is valid up to and including not_after"
        );
    }

    /// On a plaintext connection the token decides, and the certificates pinned in the file play no part.
    #[test]
    fn a_pin_never_decides_the_client_on_a_bearer_connection() {
        let clients = [client("a", "ta", 1, None), client("b", "tb", 2, None)];
        let pins = Pins::build(&clients).expect("distinct pins");

        assert_eq!(
            resolve(&clients, &pins, Peer::Bearer, Some(&bearer("tb")), Some(0)).map(|c| c.id.as_str()),
            Some("b")
        );
        assert!(resolve(&clients, &pins, Peer::Bearer, None, Some(0)).is_none());
    }

    /// A clock that cannot be read refuses every pin, whatever its shape: no deadline, a deadline at the largest
    /// timestamp, and an ordinary one. Time-based checks cannot be trusted on a broken clock, and the clock must never
    /// make a pin look valid. The bearer path does not use the clock, so it is unaffected.
    #[test]
    fn an_unreadable_clock_refuses_every_pin() {
        let clients = [
            client("none", "t0", 1, None),
            client("max", "t1", 2, Some(u64::MAX)),
            client("later", "t2", 3, Some(4_000_000_000)),
        ];
        let pins = Pins::build(&clients).expect("pins");

        assert_eq!(pins.live(Some(1_000)).len(), 3, "a readable clock admits all three");
        assert!(pins.live(None).is_empty(), "no pin is admitted at the handshake");
        for byte in 1..=3 {
            assert!(
                pins.client(&clients, &fingerprint(byte), None).is_none(),
                "pin {byte} is refused per request"
            );
            assert!(
                resolve(&clients, &pins, Peer::Cert(fingerprint(byte)), None, None).is_none(),
                "pin {byte} is refused by resolve"
            );
        }
        assert_eq!(
            resolve(&clients, &pins, Peer::Bearer, Some(&bearer("t0")), None).map(|c| c.id.as_str()),
            Some("none"),
            "a bearer token does not depend on the clock"
        );
    }

    fn client_pinned_to(id: &str, sha256: &str) -> Client {
        Client {
            certs: vec![CertPin {
                sha256: sha256.to_owned(),
                not_after: None,
            }],
            ..client(id, "t", 0, None)
        }
    }

    /// Only exact equality of the whole fingerprint maps to a client. Two pins share their first 8 hex digits, a
    /// fingerprint one digit off A's has that prefix too, and a prefix or a truncation is not a fingerprint at all.
    #[test]
    fn only_an_exact_fingerprint_maps_to_a_client() {
        let a_hex = hex::encode([0x11u8; 32]);
        let mut b_bytes = [0x11u8; 32];
        b_bytes[4..].fill(0x22);
        let b_hex = hex::encode(b_bytes);
        assert_eq!(a_hex[..8], b_hex[..8], "B shares A's 8-digit prefix");
        let clients = [client_pinned_to("a", &a_hex), client_pinned_to("b", &b_hex)];
        let pins = Pins::build(&clients).expect("two distinct pins");
        let id = |hex: &str| {
            Fingerprint::from_hex(hex)
                .ok()
                .and_then(|fp| pins.client(&clients, &fp, Some(0)))
                .map(|c| c.id.as_str())
        };

        assert_eq!(id(&a_hex), Some("a"));
        assert_eq!(id(&b_hex), Some("b"));
        let one_off = format!("{}0", &a_hex[..63]);
        assert_eq!(id(&one_off), None, "the last digit differs");
        let first_off = format!("0{}", &a_hex[1..]);
        assert_eq!(id(&first_off), None, "the first digit differs");
        assert_eq!(id(&a_hex[..8]), None, "an 8-digit prefix");
        assert_eq!(id(&a_hex[..63]), None, "one digit short");
        assert!(
            Pins::build(&[client_pinned_to("t", &a_hex[..8])]).is_err(),
            "a prefix is not a pin"
        );
        assert!(
            Pins::build(&[client_pinned_to("t", &a_hex[..63])]).is_err(),
            "a truncation is not a pin"
        );
        assert!(
            Pins::build(&[client_pinned_to("t", &"+0".repeat(32))]).is_err(),
            "a plus sign is not a digit"
        );
    }
}
