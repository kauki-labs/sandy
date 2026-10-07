//! Identity verification: turn an on-disk seed into a [`VerifiedSeed`] only when
//! architecture, nixpkgs revision, image format, manifest signature, and every
//! per-artifact hash match (C-REQ-2, INV-P5). Any single mismatch refuses, naming
//! the field; presence alone never qualifies.

use std::{
    fs,
    path::{Path, PathBuf},
};

use minisign_verify::{PublicKey, Signature};

use super::{
    hash::sha256_hex_file,
    manifest::{ALLOWED_IMAGE_FORMATS, MANIFEST_FILE, Requirements, SeedManifest},
};

/// Verifies a detached signature over a message against a trusted public key.
///
/// This is the seam that lets identity verification be unit-tested without a real
/// key: tests supply an accept/reject double, while production uses
/// [`MinisignVerifier`] over the operator-held minisign key (D12).
pub trait SignatureVerifier {
    /// Return `true` iff `signature` is a valid detached signature over `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

/// Production [`SignatureVerifier`] over a minisign public key (the operator-held key).
///
/// [`verify`](MinisignVerifier::verify) checks a detached signature with
/// `minisign-verify`. It is the live crypto path: the sandbox unit suite exercises
/// [`acquire`] through a mock verifier, while this type is driven over a real key at
/// the host/integration tier (S9).
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
        // The public key is stored as text; `.pub` carries a comment line plus the
        // base64 body, while a bare base64 string has only the body. Accept either.
        let Ok(public_key) =
            PublicKey::decode(&self.public_key).or_else(|_| PublicKey::from_base64(self.public_key.trim()))
        else {
            return false;
        };
        let Ok(signature_text) = std::str::from_utf8(signature) else {
            return false;
        };
        let Ok(signature) = Signature::decode(signature_text) else {
            return false;
        };
        public_key.verify(message, &signature, false).is_ok()
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
    // 1. Read and parse the manifest. I/O and parse failures refuse by their variant.
    let manifest_bytes = fs::read(seed_root.join(MANIFEST_FILE))?;
    let manifest: SeedManifest = serde_json::from_slice(&manifest_bytes)?;

    // 2. The manifest bytes as read are what the detached signature covers.
    if !verifier.verify(&manifest_bytes, manifest_sig) {
        return Err(SeedRefusal::Signature);
    }

    // 3. Architecture must be exactly the one required.
    if manifest.arch != required.arch {
        return Err(SeedRefusal::Arch {
            expected: required.arch.clone(),
            found: manifest.arch,
        });
    }

    // 4. nixpkgs revision must match; any other rev is stale or wrong.
    if manifest.nixpkgs_rev != required.rev {
        return Err(SeedRefusal::Rev {
            expected: required.rev.clone(),
            found: manifest.nixpkgs_rev,
        });
    }

    // 5. Image format must be one the boot path accepts.
    if !ALLOWED_IMAGE_FORMATS.contains(&manifest.image_format.as_str()) {
        return Err(SeedRefusal::Format {
            found: manifest.image_format,
        });
    }

    // 6. Every artifact must be present and hash to its pinned entry. The digest is streamed (see `sha256_hex_file`) so
    //    a multi-GB store image is not buffered.
    for entry in &manifest.artifacts {
        let path = seed_root.join(&entry.name);
        let digest = match sha256_hex_file(&path) {
            Ok(digest) => digest,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(SeedRefusal::Missing {
                    artifact: entry.name.clone(),
                });
            }
            Err(err) => return Err(SeedRefusal::Io(err)),
        };
        if !digest.eq_ignore_ascii_case(&entry.sha256) {
            return Err(SeedRefusal::Hash {
                artifact: entry.name.clone(),
            });
        }
    }

    Ok(VerifiedSeed {
        manifest,
        root: seed_root.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::{MinisignVerifier, SignatureVerifier};

    #[test]
    fn minisign_verify_refuses_malformed_inputs_without_panicking() {
        // An undecodable public key refuses (both decode paths fail) rather than panics.
        let bad_key = MinisignVerifier::new("not-a-minisign-key");
        assert!(!bad_key.verify(b"message", b"RWRunusable-signature"));

        // A non-UTF-8 signature, and well-formed-looking but undecodable signature
        // text, both refuse — the error branches return false, never unwrap.
        let verifier = MinisignVerifier::new("untrusted comment: sandy\nRWTooShortToDecode\n");
        assert!(!verifier.verify(b"message", &[0xff, 0xfe, 0xfd]));
        assert!(!verifier.verify(b"message", b"untrusted comment: x\nnope\n"));
    }
}
