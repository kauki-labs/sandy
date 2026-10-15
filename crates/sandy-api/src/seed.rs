//! The seed identity seam: detached-signature verification.

/// Verifies a detached signature over a message against a trusted public key.
///
/// This is the seam that lets identity verification be unit-tested without a real
/// key: tests supply an accept/reject double, while production uses a minisign
/// verifier over the operator-held minisign key (D12).
pub trait SignatureVerifier {
    /// Return `true` iff `signature` is a valid detached signature over `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}
