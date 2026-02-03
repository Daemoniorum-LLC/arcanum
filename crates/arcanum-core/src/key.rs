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

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(all(not(feature = "std"), feature = "encoding"))]
use alloc::string::ToString;
#[cfg(all(not(feature = "std"), feature = "serde", feature = "encoding"))]
use alloc::vec::Vec;

use crate::error::{Error, Result};
#[cfg(feature = "std")]
use crate::random::OsRng;
#[cfg(feature = "std")]
use chrono::{DateTime, Utc};
#[cfg(feature = "std")]
use rand::RngCore;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use core::fmt;
use core::mem::ManuallyDrop;
use subtle::{Choice, ConstantTimeEq};
#[cfg(feature = "std")]
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
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        let mut bytes = [0u8; N];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create from a slice, returning error if length doesn't match.
    #[must_use = "parsing can fail; check the Result"]
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
    #[must_use = "parsing can fail; check the Result"]
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
    #[cfg(feature = "encoding")]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Decode from hex string.
    #[cfg(feature = "encoding")]
    #[must_use = "encoding can fail; check the Result"]
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::ParseError(e.to_string()))?;
        Self::from_slice(&bytes)
    }
}

#[cfg(feature = "encoding")]
impl<const N: usize> fmt::Debug for PublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}>({})", N, self.to_hex())
    }
}

#[cfg(not(feature = "encoding"))]
impl<const N: usize> fmt::Debug for PublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}>([{} bytes])", N, N)
    }
}

#[cfg(feature = "encoding")]
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

#[cfg(all(feature = "serde", feature = "encoding"))]
impl<const N: usize> Serialize for PublicKey<N> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
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

#[cfg(all(feature = "serde", feature = "encoding"))]
impl<'de, const N: usize> Deserialize<'de> for PublicKey<N> {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
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
        core::mem::forget(self);
        secret
    }

    /// Consume and return both keys.
    pub fn into_parts(mut self) -> (SecretKey<SK>, PublicKey<PK>) {
        // SAFETY: We're taking ownership of both inner values.
        let secret = unsafe { ManuallyDrop::take(&mut self.secret_key) };
        let public = unsafe { ManuallyDrop::take(&mut self.public_key) };
        core::mem::forget(self);
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
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyId(Uuid);

#[cfg(feature = "std")]
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
    #[must_use = "parsing can fail; check the Result"]
    pub fn parse(s: &str) -> Result<Self> {
        let uuid = Uuid::parse_str(s).map_err(|e| Error::ParseError(e.to_string()))?;
        Ok(Self(uuid))
    }
}

#[cfg(feature = "std")]
impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key usage purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

#[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
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

    #[cfg(feature = "encoding")]
    #[test]
    fn test_public_key_hex() {
        let bytes = [0xab; 32];
        let key = PublicKey::<32>::new(bytes);
        let hex = key.to_hex();
        let decoded = PublicKey::<32>::from_hex(&hex).unwrap();
        assert_eq!(key, decoded);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_metadata_validity() {
        let meta = KeyMetadata::new(KeyAlgorithm::Aes256, vec![KeyUsage::Encrypt]);
        assert!(meta.is_valid());
        assert!(meta.can_use_for(KeyUsage::Encrypt));
        assert!(!meta.can_use_for(KeyUsage::Sign));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_id() {
        let id = KeyId::generate();
        let s = id.to_string();
        let parsed = KeyId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    // ─── KeyPair tests ───────────────────────────────────────────────────────

    #[test]
    fn test_keypair_create_and_access() {
        let sk_bytes = [1u8; 32];
        let pk_bytes = [2u8; 32];
        let sk = SecretKey::<32>::new(sk_bytes);
        let pk = PublicKey::<32>::new(pk_bytes);

        let pair = KeyPair::new(sk, pk);

        assert_eq!(pair.secret_key().as_bytes(), &[1u8; 32]);
        assert_eq!(pair.public_key().as_bytes(), &[2u8; 32]);
    }

    #[test]
    fn test_keypair_into_secret_key() {
        let sk = SecretKey::<32>::new([0xAA; 32]);
        let pk = PublicKey::<32>::new([0xBB; 32]);
        let pair = KeyPair::new(sk, pk);

        let extracted_sk = pair.into_secret_key();
        assert_eq!(extracted_sk.as_bytes(), &[0xAA; 32]);
    }

    #[test]
    fn test_keypair_into_parts() {
        let sk = SecretKey::<32>::new([0xCC; 32]);
        let pk = PublicKey::<32>::new([0xDD; 32]);
        let pair = KeyPair::new(sk, pk);

        let (extracted_sk, extracted_pk) = pair.into_parts();
        assert_eq!(extracted_sk.as_bytes(), &[0xCC; 32]);
        assert_eq!(extracted_pk.as_bytes(), &[0xDD; 32]);
    }

    #[test]
    fn test_keypair_debug_redacts_secret() {
        let sk = SecretKey::<32>::new([0x01; 32]);
        let pk = PublicKey::<32>::new([0x02; 32]);
        let pair = KeyPair::new(sk, pk);

        let debug_output = format!("{:?}", pair);
        assert!(debug_output.contains("REDACTED"), "KeyPair Debug must redact the secret key");
        assert!(!debug_output.contains("0101"), "KeyPair Debug must not leak secret key bytes");
    }

    // ─── PublicKey tests ─────────────────────────────────────────────────────

    #[test]
    fn test_public_key_from_slice_correct_length() {
        let bytes = [0xAB; 32];
        let pk = PublicKey::<32>::from_slice(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), &[0xAB; 32]);
        assert_eq!(pk.as_slice(), &[0xAB; 32]);
    }

    #[test]
    fn test_public_key_from_slice_wrong_length() {
        let short = [0u8; 16];
        let result = PublicKey::<32>::from_slice(&short);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            Error::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            other => panic!("Expected InvalidKeyLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_public_key_len() {
        assert_eq!(PublicKey::<32>::len(), 32);
        assert_eq!(PublicKey::<64>::len(), 64);
        assert_eq!(PublicKey::<16>::len(), 16);
    }

    // ─── SecretKey tests ─────────────────────────────────────────────────────

    #[test]
    fn test_secret_key_as_slice() {
        let key = SecretKey::<16>::new([0xFF; 16]);
        let slice: &[u8] = key.as_slice();
        assert_eq!(slice.len(), 16);
        assert!(slice.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_secret_key_len_and_bit_len() {
        assert_eq!(SecretKey::<32>::len(), 32);
        assert_eq!(SecretKey::<32>::bit_len(), 256);
        assert_eq!(SecretKey::<16>::len(), 16);
        assert_eq!(SecretKey::<16>::bit_len(), 128);
    }

    #[test]
    fn test_secret_key_ct_eq_equal_keys() {
        let key1 = SecretKey::<32>::new([0x42; 32]);
        let key2 = SecretKey::<32>::new([0x42; 32]);
        assert!(key1.ct_eq(&key2));
    }

    #[test]
    fn test_secret_key_ct_eq_different_keys() {
        let key1 = SecretKey::<32>::new([0x42; 32]);
        let key2 = SecretKey::<32>::new([0x43; 32]);
        assert!(!key1.ct_eq(&key2));
    }

    #[test]
    fn test_secret_key_constant_time_eq_trait() {
        let key1 = SecretKey::<32>::new([0x10; 32]);
        let key2 = SecretKey::<32>::new([0x10; 32]);
        let key3 = SecretKey::<32>::new([0x20; 32]);

        let eq_result: bool = key1.ct_eq(&key2).into();
        assert!(eq_result);

        let neq_result: bool = key1.ct_eq(&key3).into();
        assert!(!neq_result);
    }

    #[test]
    fn test_secret_key_debug_redaction() {
        let key = SecretKey::<32>::new([0xDE; 32]);
        let debug_output = format!("{:?}", key);
        assert_eq!(debug_output, "SecretKey<32>[REDACTED]");
        assert!(!debug_output.contains("de"), "Debug output must not leak key bytes");
    }

    #[test]
    fn test_secret_key_as_ref() {
        let key = SecretKey::<16>::new([0x99; 16]);
        let as_ref: &[u8] = key.as_ref();
        assert_eq!(as_ref.len(), 16);
        assert_eq!(as_ref, &[0x99; 16]);
    }

    // ─── KeyMetadata tests ───────────────────────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn test_key_metadata_with_expiration_past_is_invalid() {
        use chrono::{Utc, Duration as ChronoDuration};
        let past = Utc::now() - ChronoDuration::hours(1);
        let meta = KeyMetadata::new(KeyAlgorithm::Aes256, vec![KeyUsage::Encrypt])
            .with_expiration(past);

        assert!(meta.expires_at.is_some());
        assert!(!meta.is_valid(), "Key with past expiration must be invalid");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_metadata_with_label() {
        let meta = KeyMetadata::new(KeyAlgorithm::Ed25519, vec![KeyUsage::Sign])
            .with_label("my-signing-key");

        assert_eq!(meta.label.as_deref(), Some("my-signing-key"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_metadata_with_extractable() {
        let meta_default = KeyMetadata::new(KeyAlgorithm::Aes256, vec![KeyUsage::Encrypt]);
        assert!(!meta_default.extractable, "Default extractable should be false");

        let meta_extractable = meta_default.with_extractable(true);
        assert!(meta_extractable.extractable);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_metadata_not_before_future_is_invalid() {
        use chrono::{Utc, Duration as ChronoDuration};
        let future = Utc::now() + ChronoDuration::hours(1);
        let mut meta = KeyMetadata::new(KeyAlgorithm::Aes256, vec![KeyUsage::Encrypt]);
        meta.not_before = Some(future);

        assert!(!meta.is_valid(), "Key with not_before in the future must be invalid");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_metadata_can_use_for_expired_key() {
        use chrono::{Utc, Duration as ChronoDuration};
        let past = Utc::now() - ChronoDuration::hours(1);
        let meta = KeyMetadata::new(KeyAlgorithm::Aes256, vec![KeyUsage::Encrypt])
            .with_expiration(past);

        assert!(!meta.can_use_for(KeyUsage::Encrypt),
            "Expired key must not be usable even for its allowed usage");
        assert!(!meta.can_use_for(KeyUsage::Sign),
            "Expired key must not be usable for any usage");
    }

    // ─── KeyAlgorithm Display tests ──────────────────────────────────────────

    #[test]
    fn test_key_algorithm_display_aes256() {
        assert_eq!(format!("{}", KeyAlgorithm::Aes256), "AES-256");
    }

    #[test]
    fn test_key_algorithm_display_ed25519() {
        assert_eq!(format!("{}", KeyAlgorithm::Ed25519), "Ed25519");
    }

    #[test]
    fn test_key_algorithm_display_ml_kem_768() {
        assert_eq!(format!("{}", KeyAlgorithm::MlKem768), "ML-KEM-768");
    }

    #[test]
    fn test_key_algorithm_display_custom() {
        let custom = KeyAlgorithm::Custom("MyCustomAlgo".into());
        assert_eq!(format!("{}", custom), "MyCustomAlgo");
    }

    // ─── KeyId tests ─────────────────────────────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn test_key_id_from_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let key_id = KeyId::from_uuid(uuid);
        assert_eq!(key_id.as_uuid(), &uuid);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_id_parse_invalid_string() {
        let result = KeyId::parse("not-a-valid-uuid");
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ParseError(msg) => {
                assert!(!msg.is_empty(), "Parse error should have a message");
            }
            other => panic!("Expected ParseError, got: {:?}", other),
        }
    }
}
