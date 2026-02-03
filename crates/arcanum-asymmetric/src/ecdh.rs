//! Elliptic Curve Diffie-Hellman (ECDH).
//!
//! ECDH key agreement using NIST curves (P-256, P-384) and secp256k1.
//!
//! ## Curve Comparison
//!
//! | Curve     | Security | Key Size | Use Case |
//! |-----------|----------|----------|----------|
//! | P-256     | 128-bit  | 32 bytes | General purpose, TLS |
//! | P-384     | 192-bit  | 48 bytes | High security |
//! | secp256k1 | 128-bit  | 32 bytes | Bitcoin, Ethereum |

use crate::traits::{DiffieHellman, EllipticCurve};
use arcanum_core::error::{Error, Result};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

// ═══════════════════════════════════════════════════════════════════════════════
// P-256 ECDH
// ═══════════════════════════════════════════════════════════════════════════════

/// P-256 secret key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct P256SecretKey {
    inner: p256::SecretKey,
}

impl P256SecretKey {
    /// Generate a new random secret key.
    pub fn generate() -> Self {
        Self {
            inner: p256::SecretKey::random(&mut OsRng),
        }
    }

    /// Create from bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p256::SecretKey::from_slice(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Derive the public key.
    pub fn public_key(&self) -> P256PublicKey {
        P256PublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Perform ECDH key agreement.
    #[must_use = "key agreement result must be checked for errors"]
    pub fn diffie_hellman(&self, peer_public: &P256PublicKey) -> Result<P256SharedSecret> {
        use p256::ecdh::diffie_hellman;
        let shared = diffie_hellman(
            self.inner.to_nonzero_scalar(),
            peer_public.inner.as_affine(),
        );
        Ok(P256SharedSecret {
            bytes: shared.raw_secret_bytes().to_vec(),
        })
    }
}

impl core::fmt::Debug for P256SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P256SecretKey([REDACTED])")
    }
}

/// P-256 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct P256PublicKey {
    inner: p256::PublicKey,
}

impl P256PublicKey {
    /// Create from SEC1-encoded bytes (compressed or uncompressed).
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export as compressed SEC1 bytes (33 bytes).
    pub fn to_sec1_bytes_compressed(&self) -> Vec<u8> {
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Export as uncompressed SEC1 bytes (65 bytes).
    pub fn to_sec1_bytes_uncompressed(&self) -> Vec<u8> {
        self.inner.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Encode as hex (compressed).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_sec1_bytes_compressed())
    }

    /// Decode from hex.
    #[must_use = "encoding can fail; check the Result"]
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|_| Error::InvalidKeyFormat)?;
        Self::from_sec1_bytes(&bytes)
    }
}

impl core::fmt::Debug for P256PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.to_sec1_bytes_compressed();
        write!(f, "P256PublicKey({}...)", &hex::encode(&bytes[..8]))
    }
}

/// P-256 shared secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct P256SharedSecret {
    bytes: Vec<u8>,
}

impl P256SharedSecret {
    /// Access the raw shared secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive a key using HKDF.
    #[must_use = "key derivation can fail; check the Result"]
    pub fn derive_key(&self, info: &[u8], output_len: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut output = vec![0u8; output_len];
        hkdf.expand(info, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(output)
    }
}

impl core::fmt::Debug for P256SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P256SharedSecret([REDACTED])")
    }
}

/// P-256 ECDH protocol.
pub struct EcdhP256;

impl EcdhP256 {
    /// Curve identifier.
    pub const CURVE: EllipticCurve = EllipticCurve::P256;
    /// Algorithm name.
    pub const ALGORITHM: &'static str = "ECDH-P256";
    /// Security level in bits.
    pub const SECURITY_BITS: usize = 128;

    /// Generate a new key pair.
    pub fn generate() -> (P256SecretKey, P256PublicKey) {
        let secret = P256SecretKey::generate();
        let public = secret.public_key();
        (secret, public)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// P-384 ECDH
// ═══════════════════════════════════════════════════════════════════════════════

/// P-384 secret key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct P384SecretKey {
    inner: p384::SecretKey,
}

impl P384SecretKey {
    /// Generate a new random secret key.
    pub fn generate() -> Self {
        Self {
            inner: p384::SecretKey::random(&mut OsRng),
        }
    }

    /// Create from bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p384::SecretKey::from_slice(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Derive the public key.
    pub fn public_key(&self) -> P384PublicKey {
        P384PublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Perform ECDH key agreement.
    #[must_use = "key agreement result must be checked for errors"]
    pub fn diffie_hellman(&self, peer_public: &P384PublicKey) -> Result<P384SharedSecret> {
        use p384::ecdh::diffie_hellman;
        let shared = diffie_hellman(
            self.inner.to_nonzero_scalar(),
            peer_public.inner.as_affine(),
        );
        Ok(P384SharedSecret {
            bytes: shared.raw_secret_bytes().to_vec(),
        })
    }
}

impl core::fmt::Debug for P384SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P384SecretKey([REDACTED])")
    }
}

/// P-384 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct P384PublicKey {
    inner: p384::PublicKey,
}

impl P384PublicKey {
    /// Create from SEC1-encoded bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p384::PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export as compressed SEC1 bytes (49 bytes).
    pub fn to_sec1_bytes_compressed(&self) -> Vec<u8> {
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Export as uncompressed SEC1 bytes (97 bytes).
    pub fn to_sec1_bytes_uncompressed(&self) -> Vec<u8> {
        self.inner.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_sec1_bytes_compressed())
    }
}

impl core::fmt::Debug for P384PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.to_sec1_bytes_compressed();
        write!(f, "P384PublicKey({}...)", &hex::encode(&bytes[..8]))
    }
}

/// P-384 shared secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct P384SharedSecret {
    bytes: Vec<u8>,
}

impl P384SharedSecret {
    /// Access the raw shared secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive a key using HKDF.
    #[must_use = "key derivation can fail; check the Result"]
    pub fn derive_key(&self, info: &[u8], output_len: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha384;

        let hkdf = Hkdf::<Sha384>::new(None, &self.bytes);
        let mut output = vec![0u8; output_len];
        hkdf.expand(info, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(output)
    }
}

impl core::fmt::Debug for P384SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P384SharedSecret([REDACTED])")
    }
}

/// P-384 ECDH protocol.
pub struct EcdhP384;

impl EcdhP384 {
    /// Curve identifier.
    pub const CURVE: EllipticCurve = EllipticCurve::P384;
    /// Algorithm name.
    pub const ALGORITHM: &'static str = "ECDH-P384";
    /// Security level in bits.
    pub const SECURITY_BITS: usize = 192;

    /// Generate a new key pair.
    pub fn generate() -> (P384SecretKey, P384PublicKey) {
        let secret = P384SecretKey::generate();
        let public = secret.public_key();
        (secret, public)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// secp256k1 ECDH
// ═══════════════════════════════════════════════════════════════════════════════

/// secp256k1 secret key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Secp256k1SecretKey {
    inner: k256::SecretKey,
}

impl Secp256k1SecretKey {
    /// Generate a new random secret key.
    pub fn generate() -> Self {
        Self {
            inner: k256::SecretKey::random(&mut OsRng),
        }
    }

    /// Create from bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = k256::SecretKey::from_slice(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Derive the public key.
    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Perform ECDH key agreement.
    #[must_use = "key agreement result must be checked for errors"]
    pub fn diffie_hellman(
        &self,
        peer_public: &Secp256k1PublicKey,
    ) -> Result<Secp256k1SharedSecret> {
        use k256::ecdh::diffie_hellman;
        let shared = diffie_hellman(
            self.inner.to_nonzero_scalar(),
            peer_public.inner.as_affine(),
        );
        Ok(Secp256k1SharedSecret {
            bytes: shared.raw_secret_bytes().to_vec(),
        })
    }
}

impl core::fmt::Debug for Secp256k1SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secp256k1SecretKey([REDACTED])")
    }
}

/// secp256k1 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct Secp256k1PublicKey {
    inner: k256::PublicKey,
}

impl Secp256k1PublicKey {
    /// Create from SEC1-encoded bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export as compressed SEC1 bytes (33 bytes).
    pub fn to_sec1_bytes_compressed(&self) -> Vec<u8> {
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Export as uncompressed SEC1 bytes (65 bytes).
    pub fn to_sec1_bytes_uncompressed(&self) -> Vec<u8> {
        self.inner.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_sec1_bytes_compressed())
    }

    /// Get Ethereum-style address (last 20 bytes of keccak256 of uncompressed pubkey).
    #[cfg(feature = "ethereum")]
    pub fn to_ethereum_address(&self) -> [u8; 20] {
        use sha3::{Digest, Keccak256};
        let uncompressed = self.to_sec1_bytes_uncompressed();
        // Skip the 0x04 prefix
        let hash = Keccak256::digest(&uncompressed[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        addr
    }
}

impl core::fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.to_sec1_bytes_compressed();
        write!(f, "Secp256k1PublicKey({}...)", &hex::encode(&bytes[..8]))
    }
}

/// secp256k1 shared secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Secp256k1SharedSecret {
    bytes: Vec<u8>,
}

impl Secp256k1SharedSecret {
    /// Access the raw shared secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive a key using HKDF.
    #[must_use = "key derivation can fail; check the Result"]
    pub fn derive_key(&self, info: &[u8], output_len: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut output = vec![0u8; output_len];
        hkdf.expand(info, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(output)
    }
}

impl core::fmt::Debug for Secp256k1SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secp256k1SharedSecret([REDACTED])")
    }
}

/// secp256k1 ECDH protocol.
pub struct EcdhSecp256k1;

impl EcdhSecp256k1 {
    /// Curve identifier.
    pub const CURVE: EllipticCurve = EllipticCurve::Secp256k1;
    /// Algorithm name.
    pub const ALGORITHM: &'static str = "ECDH-secp256k1";
    /// Security level in bits.
    pub const SECURITY_BITS: usize = 128;

    /// Generate a new key pair.
    pub fn generate() -> (Secp256k1SecretKey, Secp256k1PublicKey) {
        let secret = Secp256k1SecretKey::generate();
        let public = secret.public_key();
        (secret, public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_ecdh() {
        let (alice_sk, alice_pk) = EcdhP256::generate();
        let (bob_sk, bob_pk) = EcdhP256::generate();

        let alice_shared = alice_sk.diffie_hellman(&bob_pk).unwrap();
        let bob_shared = bob_sk.diffie_hellman(&alice_pk).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_p384_ecdh() {
        let (alice_sk, alice_pk) = EcdhP384::generate();
        let (bob_sk, bob_pk) = EcdhP384::generate();

        let alice_shared = alice_sk.diffie_hellman(&bob_pk).unwrap();
        let bob_shared = bob_sk.diffie_hellman(&alice_pk).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_secp256k1_ecdh() {
        let (alice_sk, alice_pk) = EcdhSecp256k1::generate();
        let (bob_sk, bob_pk) = EcdhSecp256k1::generate();

        let alice_shared = alice_sk.diffie_hellman(&bob_pk).unwrap();
        let bob_shared = bob_sk.diffie_hellman(&alice_pk).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_p256_key_serialization() {
        let (secret, public) = EcdhP256::generate();

        let secret_bytes = secret.to_bytes();
        let public_bytes = public.to_sec1_bytes_compressed();

        let restored_secret = P256SecretKey::from_bytes(&secret_bytes).unwrap();
        let restored_public = P256PublicKey::from_sec1_bytes(&public_bytes).unwrap();

        assert_eq!(restored_secret.public_key(), public);
        assert_eq!(restored_public, public);
    }

    #[test]
    fn test_p256_uncompressed_pubkey() {
        let (_, public) = EcdhP256::generate();
        let uncompressed = public.to_sec1_bytes_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed point prefix
    }

    #[test]
    fn test_key_derivation() {
        let (alice_sk, _) = EcdhP256::generate();
        let (_, bob_pk) = EcdhP256::generate();

        let shared = alice_sk.diffie_hellman(&bob_pk).unwrap();
        let key1 = shared.derive_key(b"encryption", 32).unwrap();
        let key2 = shared.derive_key(b"authentication", 32).unwrap();

        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_different_curves_different_key_sizes() {
        let (_, p256_pk) = EcdhP256::generate();
        let (_, p384_pk) = EcdhP384::generate();
        let (_, secp256k1_pk) = EcdhSecp256k1::generate();

        // Compressed public keys
        assert_eq!(p256_pk.to_sec1_bytes_compressed().len(), 33);
        assert_eq!(p384_pk.to_sec1_bytes_compressed().len(), 49);
        assert_eq!(secp256k1_pk.to_sec1_bytes_compressed().len(), 33);
    }
}
