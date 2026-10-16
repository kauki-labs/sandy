//! Acceptance tests for [`LocalCapAuthority`] (#110). The shared `capauth_suite`
//! proves the general `CapAuthority` contract; these prove this impl's own extra
//! behaviour (cross-instance forgery, revocation) and that the suite isn't vacuous
//! for this crate's wiring.

use anyhow::Context;
use sandy_fabric::{
    capauth::{Cap, CapAuthority, CapError, CapRights, CapScope},
    contract::capauth_suite,
    types::{ChannelId, PeerId},
};
use sandy_fabric_local::LocalCapAuthority;

fn full_rights() -> CapRights {
    CapRights {
        post: true,
        read: true,
        invite: true,
    }
}

fn scope(rights: CapRights, expires_at: Option<u64>) -> CapScope {
    CapScope {
        peer: PeerId::from("agent-a"),
        channel: ChannelId::from("c1"),
        rights,
        expires_at,
    }
}

#[test]
fn passes_the_capauthority_contract() -> anyhow::Result<()> {
    capauth_suite(|| LocalCapAuthority::new().expect("getrandom for a fresh local authority")).context("capauth_suite")
}

#[test]
fn a_cap_minted_by_a_different_authority_is_forged() -> anyhow::Result<()> {
    // The sandbox never holds the authority's key (INV-1): simulate a self-minted
    // cap as one minted under a second, independently keyed authority instance.
    let authority = LocalCapAuthority::new().context("authority")?;
    let impostor = LocalCapAuthority::new().context("impostor")?;
    let cap = impostor.mint(scope(full_rights(), None)).context("impostor mint")?;
    assert!(matches!(authority.verify(&cap), Err(CapError::Forged)));
    Ok(())
}

#[test]
fn a_revoked_cap_is_refused_even_before_its_expiry() -> anyhow::Result<()> {
    let authority = LocalCapAuthority::new().context("authority")?;
    let later = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("clock")?
        .as_secs()
        + 3600;
    let cap = authority.mint(scope(full_rights(), Some(later))).context("mint")?;
    authority.verify(&cap).context("verify before revoke")?;
    authority.revoke(&cap);
    assert!(matches!(authority.verify(&cap), Err(CapError::Revoked)));
    Ok(())
}

/// Wraps a real authority but skips the proof check in `verify` — a signer that
/// accepts a forged cap. The suite must fail against it, proving it is not vacuous
/// for this crate's concrete type (mirrors #157's `NonAttenuatingAuthority`).
struct BrokenAuthority(LocalCapAuthority);

impl CapAuthority for BrokenAuthority {
    fn mint(&self, scope: CapScope) -> Result<Cap, CapError> {
        self.0.mint(scope)
    }

    fn verify(&self, cap: &Cap) -> Result<CapScope, CapError> {
        Ok(cap.scope.clone())
    }

    fn attenuate(&self, parent: &Cap, rights: CapRights) -> Result<Cap, CapError> {
        self.0.attenuate(parent, rights)
    }
}

#[test]
fn the_suite_rejects_a_signer_that_skips_verification() {
    let make = || BrokenAuthority(LocalCapAuthority::new().expect("getrandom for a fresh local authority"));
    assert!(capauth_suite(make).is_err());
}
