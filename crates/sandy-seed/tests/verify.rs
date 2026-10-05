//! Tier-2 identity-verification suite for `sandy-seed` (C-REQ-2, trace INV-P5).
//!
//! Each case builds a seed in a `TempDir` (`manifest.json` + artifact files) and a
//! mock [`SignatureVerifier`], then asserts [`acquire`] accepts a matching, signed
//! seed and refuses each single-field mismatch **by name** — never "present →
//! proceed".

use std::fs;

use anyhow::Context;
use rstest::rstest;
use sandy_seed::{ArtifactEntry, Requirements, SeedManifest, SeedRefusal, SignatureVerifier, acquire, sha256_hex};
use tempfile::TempDir;

/// Accept-or-reject signature double standing in for the KeePassXC-held key.
struct MockVerifier {
    accept: bool,
}

impl SignatureVerifier for MockVerifier {
    fn verify(&self, _message: &[u8], _signature: &[u8]) -> bool {
        self.accept
    }
}

const ARCH: &str = "aarch64-linux";
const REV: &str = "nixos-24.05.abcdef0";
const FORMAT: &str = "erofs";
const SIG: &[u8] = b"detached-signature-bytes";

/// The artifacts every fixture seed ships, as `(name, bytes)`.
fn artifacts() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("store.erofs", b"erofs store image bytes".as_slice()),
        ("kernel", b"uncompressed kernel bytes".as_slice()),
    ]
}

/// A manifest whose per-artifact hashes match `arts`, for the given identity fields.
fn manifest_for(arch: &str, rev: &str, format: &str, arts: &[(&'static str, &'static [u8])]) -> SeedManifest {
    SeedManifest {
        nixpkgs_rev: rev.to_string(),
        arch: arch.to_string(),
        image_format: format.to_string(),
        artifacts: arts
            .iter()
            .map(|&(name, bytes)| ArtifactEntry {
                name: name.to_string(),
                sha256: sha256_hex(bytes),
            })
            .collect(),
    }
}

/// Write artifact files then `manifest.json` into a fresh seed root.
fn write_seed(manifest: &SeedManifest, arts: &[(&'static str, &'static [u8])]) -> anyhow::Result<TempDir> {
    let dir = TempDir::new().context("create seed tempdir")?;
    for &(name, bytes) in arts {
        fs::write(dir.path().join(name), bytes).with_context(|| format!("write artifact {name}"))?;
    }
    let json = serde_json::to_string_pretty(manifest).context("serialize manifest")?;
    fs::write(dir.path().join("manifest.json"), json).context("write manifest.json")?;
    Ok(dir)
}

fn required() -> Requirements {
    Requirements::new(ARCH, REV)
}

#[test]
fn verified_seed_accepted() -> anyhow::Result<()> {
    let arts = artifacts();
    let manifest = manifest_for(ARCH, REV, FORMAT, &arts);
    let seed = write_seed(&manifest, &arts)?;
    let verifier = MockVerifier { accept: true };

    let verified = acquire(seed.path(), SIG, &required(), &verifier).expect("a matching, signed seed is accepted");

    assert_eq!(verified.manifest().arch, ARCH);
    assert_eq!(verified.manifest().nixpkgs_rev, REV);
    assert_eq!(verified.root(), seed.path());
    Ok(())
}

/// The failing identity field a case expects the refusal to name.
#[derive(Debug)]
enum Field {
    Arch,
    Rev,
    Format,
}

#[rstest]
#[case::stale_rev(manifest_for(ARCH, "nixos-OLD.0000000", FORMAT, &artifacts()), Field::Rev)]
#[case::wrong_arch(manifest_for("x86_64-linux", REV, FORMAT, &artifacts()), Field::Arch)]
#[case::unsupported_format(manifest_for(ARCH, REV, "squashfs", &artifacts()), Field::Format)]
fn manifest_field_mismatch_refuses(#[case] manifest: SeedManifest, #[case] expected: Field) -> anyhow::Result<()> {
    let arts = artifacts();
    let seed = write_seed(&manifest, &arts)?;
    let verifier = MockVerifier { accept: true };

    let err = acquire(seed.path(), SIG, &required(), &verifier).expect_err("a single-field mismatch must refuse");

    let names_field = matches!(
        (&err, &expected),
        (SeedRefusal::Arch { .. }, Field::Arch)
            | (SeedRefusal::Rev { .. }, Field::Rev)
            | (SeedRefusal::Format { .. }, Field::Format)
    );
    assert!(names_field, "refusal must name the {expected:?} field, got {err:?}");
    Ok(())
}

#[test]
fn unsigned_or_bad_sig_refuses() -> anyhow::Result<()> {
    let arts = artifacts();
    let manifest = manifest_for(ARCH, REV, FORMAT, &arts);
    let seed = write_seed(&manifest, &arts)?;
    let verifier = MockVerifier { accept: false };

    let err =
        acquire(seed.path(), SIG, &required(), &verifier).expect_err("an unsigned or badly signed seed must refuse");
    assert!(
        matches!(err, SeedRefusal::Signature),
        "a failed signature must refuse by naming the signature, got {err:?}"
    );
    Ok(())
}

#[test]
fn tampered_artifact_refuses() -> anyhow::Result<()> {
    let arts = artifacts();
    let manifest = manifest_for(ARCH, REV, FORMAT, &arts);
    let seed = write_seed(&manifest, &arts)?;
    // Flip the bytes of one artifact after the manifest pinned its clean hash.
    let (name, _) = arts[0];
    fs::write(seed.path().join(name), b"tampered store image bytes!!").context("tamper artifact")?;
    let verifier = MockVerifier { accept: true };

    let err = acquire(seed.path(), SIG, &required(), &verifier).expect_err("a tampered artifact must refuse");
    match err {
        SeedRefusal::Hash { artifact } => assert_eq!(artifact, name),
        other => panic!("a tampered artifact must refuse by naming the hash field, got {other:?}"),
    }
    Ok(())
}
