//! Deterministic SHA-256 hex digest — the primitive the manifest's per-artifact
//! hashes are expressed in (lowercase hex). It is pure and side-effect free, so
//! it is unit-tested directly rather than mocked, and may be implemented here (it
//! is not the behavior under test for C-REQ-2).

use sha2::{Digest, Sha256};

/// Return the lowercase-hex SHA-256 digest of `bytes`.
///
/// This is the exact encoding [`ArtifactEntry::sha256`](crate::ArtifactEntry::sha256)
/// stores, so a per-artifact hash check is `sha256_hex(file_bytes) == entry.sha256`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn empty_input_hashes_to_the_known_sha256_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn digest_is_sixty_four_lowercase_hex_chars() {
        let digest = sha256_hex(b"sandy");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
