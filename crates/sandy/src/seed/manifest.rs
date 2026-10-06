//! The signed seed manifest and the caller's identity requirements.

use serde::{Deserialize, Serialize};

/// File name of the manifest at a seed root.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Image formats the Nix-free-Mac boot path accepts for a seed store image.
///
/// A manifest whose `image_format` is outside this set is refused with
/// [`SeedRefusal::Format`](crate::SeedRefusal::Format). This guards the
/// manifest-declared format; the uncompressed-kernel rule (INV-P6) is a separate
/// stage-time check outside this crate.
pub const ALLOWED_IMAGE_FORMATS: &[&str] = &["erofs"];

/// One artifact in a seed, pinned by name and content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// File name of the artifact, relative to the seed root.
    pub name: String,
    /// Expected SHA-256 of the artifact bytes, lowercase hex (see [`crate::sha256_hex`]).
    pub sha256: String,
}

/// The signed description of a seed: what it is and what it contains.
///
/// Deserialized from `manifest.json` at the seed root. Its *bytes as read* are
/// what the detached signature covers, so verification signs the file contents,
/// not a re-serialization of this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedManifest {
    /// nixpkgs revision the seed was built from (identity, not freshness-by-clock).
    pub nixpkgs_rev: String,
    /// Target architecture the seed is built for, e.g. `aarch64-linux`.
    pub arch: String,
    /// Store-image format; must be one of [`ALLOWED_IMAGE_FORMATS`].
    pub image_format: String,
    /// Every artifact the seed ships, each pinned by hash.
    pub artifacts: Vec<ArtifactEntry>,
}

/// What the caller demands of a seed before it will boot from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirements {
    /// Required architecture; a seed built for another arch is refused.
    pub arch: String,
    /// Required nixpkgs revision; any other rev is refused as stale or wrong.
    pub rev: String,
}

impl Requirements {
    /// Build requirements from an architecture and a nixpkgs revision.
    pub fn new(arch: impl Into<String>, rev: impl Into<String>) -> Self {
        Self {
            arch: arch.into(),
            rev: rev.into(),
        }
    }
}
