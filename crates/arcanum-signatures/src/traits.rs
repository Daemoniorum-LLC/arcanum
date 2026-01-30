//! Traits for digital signature algorithms.

#[cfg(not(feature = "std"))]
use alloc::{string::{String, ToString}, vec::Vec};

use arcanum_core::error::Result;

/// Trait for signing keys (private keys).
pub trait SigningKey: Clone + Send + Sync {
    /// The verifying key type.
    type VerifyingKey: VerifyingKey;
    /// The signature type.
    type Signature: Signature;

    /// Algorithm identifier.
    const ALGORITHM: &'static str;
    /// Key size in bytes.
    const KEY_SIZE: usize;

    /// Generate a new random signing key.
    fn generate() -> Self;

    /// Create from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Export to bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Get the corresponding verifying key.
    fn verifying_key(&self) -> Self::VerifyingKey;

    /// Sign a message.
    fn sign(&self, message: &[u8]) -> Self::Signature;

    /// Sign a pre-hashed message (for large messages).
    fn sign_prehashed(&self, hash: &[u8]) -> Result<Self::Signature>;
}

/// Trait for verifying keys (public keys).
pub trait VerifyingKey: Clone + Send + Sync + PartialEq + Eq {
    /// The signature type.
    type Signature: Signature;

    /// Algorithm identifier.
    const ALGORITHM: &'static str;
    /// Key size in bytes.
    const KEY_SIZE: usize;

    /// Create from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Export to bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Verify a signature.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<()>;

    /// Verify a pre-hashed message.
    fn verify_prehashed(&self, hash: &[u8], signature: &Self::Signature) -> Result<()>;

    /// Encode as hex string.
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from hex string.
    fn from_hex(s: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let bytes =
            hex::decode(s).map_err(|e| arcanum_core::error::Error::ParseError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Trait for signatures.
pub trait Signature: Clone + Send + Sync {
    /// Signature size in bytes.
    const SIZE: usize;

    /// Create from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Export to bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Encode as hex string.
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from hex string.
    fn from_hex(s: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let bytes =
            hex::decode(s).map_err(|e| arcanum_core::error::Error::ParseError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Trait for batch signature verification.
pub trait BatchVerifier {
    /// The verifying key type.
    type VerifyingKey: VerifyingKey;
    /// The signature type.
    type Signature: Signature;

    /// Verify multiple signatures in batch.
    ///
    /// This is more efficient than verifying each signature individually.
    fn verify_batch(items: &[(&Self::VerifyingKey, &[u8], &Self::Signature)]) -> Result<()>;
}
