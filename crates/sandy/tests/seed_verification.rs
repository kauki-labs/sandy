//! Seed identity verification from a consumer's view.
//!
//! Builds a real on-disk seed (a `manifest.json` plus artifact files) in a temp
//! dir and drives `sandy_seed::acquire` through a stub [`SignatureVerifier`], so
//! the manifest parse, the signature gate, the identity checks, and the streamed
//! per-artifact hashing are exercised together. The live minisign key is the
//! only part faked out.

use std::fs;

use anyhow::Context;
use rstest::rstest;
use sandy::{ArtifactEntry, Requirements, SeedManifest, SeedRefusal, SignatureVerifier, acquire, sha256_hex};
use tempfile::TempDir;

const ARCH: &str = "aarch64-linux";
const REV: &str = "nixos-24.05.abcdef0";
const FORMAT: &str = "erofs";
const SIG: &[u8] = b"detached-signature-bytes";

/// Accept-or-reject signature double standing in for the KeePassXC-held key.
struct StubVerifier {
    accept: bool,
}

impl SignatureVerifier for StubVerifier {
    fn verify(&self, _message: &[u8], _signature: &[u8]) -> bool {
        self.accept
    }
}

fn artifacts() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("store.erofs", b"erofs store image bytes".as_slice()),
        ("kernel", b"uncompressed kernel bytes".as_slice()),
    ]
}

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

/// Write the artifact files then `manifest.json` into a fresh seed root.
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

/// A seed matching arch + rev + format, correctly signed, with every artifact
/// hashing to its entry, verifies.
#[test]
fn a_matching_signed_seed_is_accepted() -> anyhow::Result<()> {
    let arts = artifacts();
    let seed = write_seed(&manifest_for(ARCH, REV, FORMAT, &arts), &arts)?;

    let verified =
        acquire(seed.path(), SIG, &required(), &StubVerifier { accept: true }).context("acquire a valid seed")?;

    assert_eq!(verified.manifest().arch, ARCH);
    assert_eq!(verified.manifest().nixpkgs_rev, REV);
    assert_eq!(verified.root(), seed.path());
    Ok(())
}

/// The identity field a case expects the refusal to name.
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
fn a_single_identity_mismatch_refuses_by_field(
    #[case] manifest: SeedManifest,
    #[case] expected: Field,
) -> anyhow::Result<()> {
    let arts = artifacts();
    let seed = write_seed(&manifest, &arts)?;

    let err = acquire(seed.path(), SIG, &required(), &StubVerifier { accept: true })
        .expect_err("a single-field mismatch must refuse");

    let names_field = matches!(
        (&err, &expected),
        (SeedRefusal::Arch { .. }, Field::Arch)
            | (SeedRefusal::Rev { .. }, Field::Rev)
            | (SeedRefusal::Format { .. }, Field::Format)
    );
    assert!(names_field, "refusal must name the {expected:?} field, got {err:?}");
    Ok(())
}

/// A failed signature refuses before any identity field is trusted.
#[test]
fn an_unsigned_or_bad_signature_refuses() -> anyhow::Result<()> {
    let arts = artifacts();
    let seed = write_seed(&manifest_for(ARCH, REV, FORMAT, &arts), &arts)?;

    let err = acquire(seed.path(), SIG, &required(), &StubVerifier { accept: false })
        .expect_err("a bad signature must refuse");
    assert!(
        matches!(err, SeedRefusal::Signature),
        "refuses naming the signature, got {err:?}"
    );
    Ok(())
}

/// Flipping an artifact's bytes after the manifest pinned its hash refuses,
/// naming the tampered artifact.
#[test]
fn a_tampered_artifact_refuses_by_hash() -> anyhow::Result<()> {
    let arts = artifacts();
    let seed = write_seed(&manifest_for(ARCH, REV, FORMAT, &arts), &arts)?;
    let (name, _) = arts[0];
    fs::write(seed.path().join(name), b"tampered store image bytes!!").context("tamper artifact")?;

    let err = acquire(seed.path(), SIG, &required(), &StubVerifier { accept: true })
        .expect_err("a tampered artifact must refuse");
    match err {
        SeedRefusal::Hash { artifact } => assert_eq!(artifact, name),
        other => panic!("a tampered artifact must refuse by hash, got {other:?}"),
    }
    Ok(())
}
