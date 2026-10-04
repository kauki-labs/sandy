//! Identity verification: turn an on-disk seed into a [`VerifiedSeed`] only when
//! architecture, nixpkgs revision, image format, manifest signature, and every
//! per-artifact hash match (C-REQ-2, INV-P5). Any single mismatch refuses, naming
//! the field; presence alone never qualifies.

use std::path::{Path, PathBuf};

use crate::manifest::{Requirements, SeedManifest};

/// Verifies a detached signature over a message against a trusted public key.
///
/// This is the seam that lets identity verification be unit-tested without a real
/// key: tests supply an accept/reject double, while production uses
/// [`MinisignVerifier`] over the KeePassXC-held minisign key (D12).
pub trait SignatureVerifier {
    /// Return `true` iff `signature` is a valid detached signature over `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

/// Production [`SignatureVerifier`] over a minisign public key (the KeePassXC-held key).
///
/// Real signature checking runs on the host/integration tier, not in the sandbox
/// unit suite (S9), so [`verify`](MinisignVerifier::verify) is left for the
/// implementer to wire over `minisign-verify`.
pub struct MinisignVerifier {
    public_key: String,
}

impl MinisignVerifier {
    /// Build a verifier from a minisign public key (the body of `minisign.pub`).
    pub fn new(public_key: impl Into<String>) -> Self {
        Self {
            public_key: public_key.into(),
        }
    }
}

impl SignatureVerifier for MinisignVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let _ = (&self.public_key, message, signature);
        todo!("real minisign verification against the KeePassXC public key (host/integration tier, S9)")
    }
}

/// Why a seed was refused — each variant names the field that failed identity.
///
/// A refusal is never "present → proceed": a seed that exists but does not match
/// its signed manifest is rejected, and the reason points at the exact field.
#[derive(Debug, thiserror::Error)]
pub enum SeedRefusal {
    /// The manifest signature did not verify against the trusted key.
    #[error("seed refused: manifest signature did not verify")]
    Signature,
    /// The seed's architecture is not the one required.
    #[error("seed refused: arch mismatch (required {expected}, found {found})")]
    Arch {
        /// The architecture the caller required.
        expected: String,
        /// The architecture the manifest declared.
        found: String,
    },
    /// The seed's nixpkgs revision is not the one required (stale or wrong).
    #[error("seed refused: nixpkgs rev mismatch (required {expected}, found {found})")]
    Rev {
        /// The revision the caller required.
        expected: String,
        /// The revision the manifest declared.
        found: String,
    },
    /// The seed's image format is not in [`ALLOWED_IMAGE_FORMATS`](crate::ALLOWED_IMAGE_FORMATS).
    #[error("seed refused: unsupported image format ({found})")]
    Format {
        /// The format the manifest declared.
        found: String,
    },
    /// An artifact's bytes did not hash to its manifest entry.
    #[error("seed refused: hash mismatch for artifact {artifact}")]
    Hash {
        /// The name of the artifact whose hash did not match.
        artifact: String,
    },
    /// A manifest-declared artifact file is absent from the seed root.
    #[error("seed refused: missing artifact {artifact}")]
    Missing {
        /// The name of the absent artifact.
        artifact: String,
    },
    /// The manifest could not be read from the seed root.
    #[error("seed refused: manifest I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The manifest JSON was malformed.
    #[error("seed refused: malformed manifest: {0}")]
    Parse(#[from] serde_json::Error),
}

/// A seed that passed full identity verification.
///
/// The only way to obtain one is [`acquire`], so holding a `VerifiedSeed` is proof
/// that its artifacts matched the signed manifest. It is the handle the boot path
/// consumes.
#[derive(Debug)]
pub struct VerifiedSeed {
    manifest: SeedManifest,
    root: PathBuf,
}

impl VerifiedSeed {
    /// The verified manifest (arch, rev, format, and per-artifact hashes).
    pub fn manifest(&self) -> &SeedManifest {
        &self.manifest
    }

    /// The seed root the verified artifacts live under.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Acquire a seed by identity: read and verify `manifest.json` at `seed_root`,
/// then return a [`VerifiedSeed`] only if every identity field matches.
///
/// `manifest_sig` is the detached signature over the manifest bytes; `verifier`
/// checks it against the trusted key. Presence alone never qualifies (INV-P5).
///
/// # Verification pipeline (C-REQ-2)
///
/// The implementer realizes exactly this order; the first failing check refuses:
///
/// 1. Read `seed_root/manifest.json` → [`SeedRefusal::Io`] / [`SeedRefusal::Parse`].
/// 2. Verify the manifest bytes against `manifest_sig` via `verifier` → else [`SeedRefusal::Signature`].
/// 3. `manifest.arch == required.arch` → else [`SeedRefusal::Arch`].
/// 4. `manifest.nixpkgs_rev == required.rev` → else [`SeedRefusal::Rev`] (stale/wrong).
/// 5. `manifest.image_format` in [`ALLOWED_IMAGE_FORMATS`](crate::ALLOWED_IMAGE_FORMATS) → else
///    [`SeedRefusal::Format`].
/// 6. For each artifact: the file hashes to its entry ([`sha256_hex`](crate::sha256_hex)) → else [`SeedRefusal::Hash`];
///    an absent file → [`SeedRefusal::Missing`].
pub fn acquire(
    seed_root: &Path,
    manifest_sig: &[u8],
    required: &Requirements,
    verifier: &impl SignatureVerifier,
) -> Result<VerifiedSeed, SeedRefusal> {
    let _ = (seed_root, manifest_sig, required, verifier);
    todo!("C-REQ-2: verify seed by identity (arch + rev + format + signature + per-artifact hash)")
}
