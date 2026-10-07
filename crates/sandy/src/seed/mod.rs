//! `sandy-seed` — seed acquisition and identity verification (Phase C, C-REQ-2).
//!
//! The Nix-free-Mac path boots a builder VM from a prebuilt seed. Before any
//! boot, the seed is verified **by identity**, never by presence (INV-P5): its
//! signed manifest must match the caller's required architecture and nixpkgs
//! revision, declare an allowed image format, carry a valid signature over the
//! operator-held key, and every artifact must hash to its manifest entry. A
//! stale, wrong-arch, unsigned, or tampered seed is refused, and the refusal
//! names the field that failed.
//!
//! - [`manifest`] — the serialized [`SeedManifest`] / [`ArtifactEntry`] and the caller's [`Requirements`], plus
//!   [`ALLOWED_IMAGE_FORMATS`].
//! - [`hash`] — [`sha256_hex`], the lowercase-hex digest the manifest pins.
//! - [`verify`] — the [`SignatureVerifier`] seam, the production [`MinisignVerifier`], the [`SeedRefusal`] taxonomy,
//!   the [`VerifiedSeed`] handle, and [`acquire`], which produces one only on full identity match.
//!
//! This crate is the sandbox-provable slice (tier-1/2): verification logic over
//! fixture manifests and a mock verifier. [`MinisignVerifier`] carries the live
//! minisign check, but it is driven with a real key — and the VM boot runs — only
//! at the host/integration tier (S9).

pub mod hash;
pub mod manifest;
pub mod verify;

pub use hash::sha256_hex;
pub use manifest::{ALLOWED_IMAGE_FORMATS, ArtifactEntry, Requirements, SeedManifest};
pub use verify::{MinisignVerifier, SeedRefusal, SignatureVerifier, VerifiedSeed, acquire};
