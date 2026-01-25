//! Key types and utilities.
//!
//! This module provides type-safe wrappers for cryptographic keys with:
//! - Automatic zeroization on drop
//! - Compile-time size guarantees
//! - Constant-time comparison
//! - Serialization support

// Allow unsafe for ManuallyDrop operations in KeyPair to enable
// moving fields out of a type that implements Drop.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use crate::random::OsRng;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::mem::ManuallyDrop;
use subtle::{Choice, ConstantTimeEq};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

// ═══════════════════════════════════════════════════════════════════════════════
// SECRET KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// A secret key with automatic zeroization.
///
/// The key material is zeroized when dropped, preventing sensitive data
/// from lingering in memory.
///
/// # Type Parameter
///
/// * `N` - The size of the key in bytes (compile-time constant)
///
/// # Example
///
/// ```ignore
/// use arcanum_core::key::SecretKey;
///
/// // Generate a 256-bit (32 byte) key
/// let key = SecretKey::<32>::generate();
///
/// // Access the key bytes
/// let bytes: &[u8; 32] = key.as_bytes();
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretKey<N> {
    /// Create a new secret key from bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Generate a random secret key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; N];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create from a slice, returning error if length doesn't match.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidKeyLength {
                expected: N,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Access the key bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Access the key as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key length in bytes.
    pub const fn len() -> usize {
        N
    }

    /// Get the key length in bits.
    pub const fn bit_len() -> usize {
        N * 8
    }

    /// Constant-time equality comparison.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> ConstantTimeEq for SecretKey<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<const N: usize> fmt::Debug for SecretKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<{}>[REDACTED]", N)
    }
}

impl<const N: usize> AsRef<[u8]> for SecretKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// A public key (not secret, can be freely shared).
///
/// # Type Parameter
///
/// * `N` - The size of the key in bytes (compile-time constant)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> PublicKey<N> {
    /// Create a new public key from bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Create from a slice, returning error if length doesn't match.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidKeyLength {
                expected: N,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Access the key bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Access the key as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key length in bytes.
    pub const fn len() -> usize {
        N
    }

    /// Encode as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::ParseError(e.to_string()))?;
        Self::from_slice(&bytes)
    }
}

impl<const N: usize> fmt::Debug for PublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}>({})", N, self.to_hex())
    }
}

impl<const N: usize> fmt::Display for PublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<const N: usize> AsRef<[u8]> for PublicKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "serde")]
impl<const N: usize> Serialize for PublicKey<N> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.bytes)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, const N: usize> Deserialize<'de> for PublicKey<N> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            Self::from_slice(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY PAIR
// ═══════════════════════════════════════════════════════════════════════════════

/// A key pair consisting of a secret key and public key.
///
/// Note: `SecretKey` handles its own zeroization via `ZeroizeOnDrop`.
#[derive(Clone)]
pub struct KeyPair<const SK: usize, const PK: usize> {
    secret_key: ManuallyDrop<SecretKey<SK>>,
    public_key: ManuallyDrop<PublicKey<PK>>,
}

impl<const SK: usize, const PK: usize> KeyPair<SK, PK> {
    /// Create a new key pair.
    pub fn new(secret_key: SecretKey<SK>, public_key: PublicKey<PK>) -> Self {
        Self {
            secret_key: ManuallyDrop::new(secret_key),
            public_key: ManuallyDrop::new(public_key),
        }
    }

    /// Get the secret key.
    pub fn secret_key(&self) -> &SecretKey<SK> {
        &self.secret_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey<PK> {
        &self.public_key
    }

    /// Consume and return the secret key.
    pub fn into_secret_key(mut self) -> SecretKey<SK> {
        // SAFETY: We're taking ownership of the inner value and not using `self` afterward.
        // The public key in ManuallyDrop will be leaked (not dropped), which is fine.
        let secret = unsafe { ManuallyDrop::take(&mut self.secret_key) };
        std::mem::forget(self);
        secret
    }

    /// Consume and return both keys.
    pub fn into_parts(mut self) -> (SecretKey<SK>, PublicKey<PK>) {
        // SAFETY: We're taking ownership of both inner values.
        let secret = unsafe { ManuallyDrop::take(&mut self.secret_key) };
        let public = unsafe { ManuallyDrop::take(&mut self.public_key) };
        std::mem::forget(self);
        (secret, public)
    }
}

impl<const SK: usize, const PK: usize> Drop for KeyPair<SK, PK> {
    fn drop(&mut self) {
        // SAFETY: We need to manually drop the inner values since they're in ManuallyDrop.
        // The SecretKey will zeroize itself when dropped.
        unsafe {
            ManuallyDrop::drop(&mut self.secret_key);
            ManuallyDrop::drop(&mut self.public_key);
        }
    }
}

impl<const SK: usize, const PK: usize> fmt::Debug for KeyPair<SK, PK> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("secret_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY ID & METADATA
// ═══════════════════════════════════════════════════════════════════════════════

/// Unique identifier for a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(Uuid);

impl KeyId {
    /// Generate a new random key ID.
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Parse from string.
    pub fn parse(s: &str) -> Result<Self> {
        let uuid = Uuid::parse_str(s).map_err(|e| Error::ParseError(e.to_string()))?;
        Ok(Self(uuid))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key usage purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyUsage {
    /// Encryption and decryption.
    Encrypt,
    /// Digital signatures.
    Sign,
    /// Key exchange / agreement.
    KeyExchange,
    /// Key wrapping.
    WrapKey,
    /// Key derivation.
    DeriveKey,
    /// Authentication.
    Authenticate,
}

/// Key algorithm identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)] // Variants are self-documenting
pub enum KeyAlgorithm {
    // Symmetric
    Aes128,
    Aes192,
    Aes256,
    ChaCha20,
    ChaCha20Poly1305,
    XChaCha20Poly1305,

    // Asymmetric - Encryption
    Rsa2048,
    Rsa3072,
    Rsa4096,

    // Asymmetric - Signatures
    Ed25519,
    Ed448,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EcdsaSecp256k1,
    SchnorrSecp256k1,

    // Key Exchange
    X25519,
    X448,
    EcdhP256,
    EcdhP384,

    // Post-Quantum
    MlKem512,
    MlKem768,
    MlKem1024,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2_128f,
    SlhDsaSha2_128s,
    SlhDsaSha2_192f,
    SlhDsaSha2_192s,
    SlhDsaSha2_256f,
    SlhDsaSha2_256s,

    // Hybrid
    X25519MlKem768,
    Ed25519MlDsa65,

    /// Custom algorithm.
    Custom(String),
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAlgorithm::Aes128 => write!(f, "AES-128"),
            KeyAlgorithm::Aes192 => write!(f, "AES-192"),
            KeyAlgorithm::Aes256 => write!(f, "AES-256"),
            KeyAlgorithm::ChaCha20 => write!(f, "ChaCha20"),
            KeyAlgorithm::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
            KeyAlgorithm::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
            KeyAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            KeyAlgorithm::Rsa3072 => write!(f, "RSA-3072"),
            KeyAlgorithm::Rsa4096 => write!(f, "RSA-4096"),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::Ed448 => write!(f, "Ed448"),
            KeyAlgorithm::EcdsaP256 => write!(f, "ECDSA-P256"),
            KeyAlgorithm::EcdsaP384 => write!(f, "ECDSA-P384"),
            KeyAlgorithm::EcdsaP521 => write!(f, "ECDSA-P521"),
            KeyAlgorithm::EcdsaSecp256k1 => write!(f, "ECDSA-secp256k1"),
            KeyAlgorithm::SchnorrSecp256k1 => write!(f, "Schnorr-secp256k1"),
            KeyAlgorithm::X25519 => write!(f, "X25519"),
            KeyAlgorithm::X448 => write!(f, "X448"),
            KeyAlgorithm::EcdhP256 => write!(f, "ECDH-P256"),
            KeyAlgorithm::EcdhP384 => write!(f, "ECDH-P384"),
            KeyAlgorithm::MlKem512 => write!(f, "ML-KEM-512"),
            KeyAlgorithm::MlKem768 => write!(f, "ML-KEM-768"),
            KeyAlgorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
            KeyAlgorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            KeyAlgorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            KeyAlgorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            KeyAlgorithm::SlhDsaSha2_128f => write!(f, "SLH-DSA-SHA2-128f"),
            KeyAlgorithm::SlhDsaSha2_128s => write!(f, "SLH-DSA-SHA2-128s"),
            KeyAlgorithm::SlhDsaSha2_192f => write!(f, "SLH-DSA-SHA2-192f"),
            KeyAlgorithm::SlhDsaSha2_192s => write!(f, "SLH-DSA-SHA2-192s"),
            KeyAlgorithm::SlhDsaSha2_256f => write!(f, "SLH-DSA-SHA2-256f"),
            KeyAlgorithm::SlhDsaSha2_256s => write!(f, "SLH-DSA-SHA2-256s"),
            KeyAlgorithm::X25519MlKem768 => write!(f, "X25519-ML-KEM-768"),
            KeyAlgorithm::Ed25519MlDsa65 => write!(f, "Ed25519-ML-DSA-65"),
            KeyAlgorithm::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Metadata associated with a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique key identifier.
    pub id: KeyId,
    /// Algorithm used.
    pub algorithm: KeyAlgorithm,
    /// Allowed usages.
    pub usages: Vec<KeyUsage>,
    /// When the key was created.
    pub created_at: DateTime<Utc>,
    /// When the key expires (if any).
    pub expires_at: Option<DateTime<Utc>>,
    /// When the key becomes valid (if not immediate).
    pub not_before: Option<DateTime<Utc>>,
    /// Human-readable label.
    pub label: Option<String>,
    /// Whether the key can be extracted.
    pub extractable: bool,
    /// Key version (for rotation).
    pub version: u32,
    /// Custom attributes.
    pub attributes: std::collections::HashMap<String, String>,
}

impl KeyMetadata {
    /// Create new metadata with minimal fields.
    pub fn new(algorithm: KeyAlgorithm, usages: Vec<KeyUsage>) -> Self {
        Self {
            id: KeyId::generate(),
            algorithm,
            usages,
            created_at: Utc::now(),
            expires_at: None,
            not_before: None,
            label: None,
            extractable: false,
            version: 1,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// Check if the key is currently valid.
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();

        // Check not before
        if self.not_before.is_some_and(|not_before| now < not_before) {
            return false;
        }

        // Check expiration
        if self.expires_at.is_some_and(|expires_at| now > expires_at) {
            return false;
        }

        true
    }

    /// Check if the key can be used for a specific purpose.
    pub fn can_use_for(&self, usage: KeyUsage) -> bool {
        self.usages.contains(&usage) && self.is_valid()
    }

    /// Set expiration time.
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set extractable flag.
    pub fn with_extractable(mut self, extractable: bool) -> Self {
        self.extractable = extractable;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_generation() {
        let key1 = SecretKey::<32>::generate();
        let key2 = SecretKey::<32>::generate();

        // Keys should be different
        assert!(!key1.ct_eq(&key2));
    }

    #[test]
    fn test_secret_key_from_slice() {
        let bytes = [0u8; 32];
        let key = SecretKey::<32>::from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);

        // Wrong length should fail
        let short = [0u8; 16];
        assert!(SecretKey::<32>::from_slice(&short).is_err());
    }

    #[test]
    fn test_public_key_hex() {
        let bytes = [0xab; 32];
        let key = PublicKey::<32>::new(bytes);
        let hex = key.to_hex();
        let decoded = PublicKey::<32>::from_hex(&hex).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_key_metadata_validity() {
        let meta = KeyMetadata::new(KeyAlgorithm::Aes256, vec![KeyUsage::Encrypt]);
        assert!(meta.is_valid());
        assert!(meta.can_use_for(KeyUsage::Encrypt));
        assert!(!meta.can_use_for(KeyUsage::Sign));
    }

    #[test]
    fn test_key_id() {
        let id = KeyId::generate();
        let s = id.to_string();
        let parsed = KeyId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }
}
