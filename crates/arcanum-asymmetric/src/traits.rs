//! Traits for asymmetric cryptographic operations.

use arcanum_core::error::Result;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Trait for asymmetric encryption.
pub trait AsymmetricEncrypt {
    /// Ciphertext type.
    type Ciphertext;

    /// Encrypt a message.
    #[must_use = "encryption can fail; check the Result"]
    fn encrypt(&self, plaintext: &[u8]) -> Result<Self::Ciphertext>;
}

/// Trait for asymmetric decryption.
pub trait AsymmetricDecrypt {
    /// Ciphertext type.
    type Ciphertext;

    /// Decrypt a ciphertext.
    #[must_use = "decryption can fail; check the Result"]
    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> Result<Vec<u8>>;
}

/// Trait for Diffie-Hellman key exchange.
pub trait DiffieHellman {
    /// Public key type.
    type PublicKey;
    /// Shared secret type.
    type SharedSecret;

    /// Derive the public key from this secret key.
    fn public_key(&self) -> Self::PublicKey;

    /// Perform Diffie-Hellman key exchange.
    fn diffie_hellman(&self, peer_public: &Self::PublicKey) -> Self::SharedSecret;
}

/// Trait for key agreement protocols.
pub trait KeyAgreement {
    /// Secret key type.
    type SecretKey;
    /// Public key type.
    type PublicKey;
    /// Shared secret type.
    type SharedSecret;

    /// Generate a new key pair.
    fn generate() -> (Self::SecretKey, Self::PublicKey);

    /// Perform key agreement.
    #[must_use = "this operation can fail; check the Result"]
    fn agree(
        our_secret: &Self::SecretKey,
        their_public: &Self::PublicKey,
    ) -> Result<Self::SharedSecret>;
}

/// Trait for ECIES (Elliptic Curve Integrated Encryption Scheme).
pub trait IntegratedEncryption {
    /// Ephemeral public key type.
    type EphemeralPublic;
    /// Ciphertext type.
    type Ciphertext;

    /// Encrypt to a public key.
    #[must_use = "encryption can fail; check the Result"]
    fn encrypt(
        recipient_public: &Self::EphemeralPublic,
        plaintext: &[u8],
    ) -> Result<Self::Ciphertext>;

    /// Decrypt with a secret key.
    #[must_use = "decryption can fail; check the Result"]
    fn decrypt<S>(recipient_secret: &S, ciphertext: &Self::Ciphertext) -> Result<Vec<u8>>
    where
        S: DiffieHellman<PublicKey = Self::EphemeralPublic>;
}

/// Key sizes for RSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeySize {
    /// 2048-bit (minimum recommended)
    Bits2048 = 2048,
    /// 3072-bit (128-bit security)
    Bits3072 = 3072,
    /// 4096-bit (higher security)
    Bits4096 = 4096,
}

impl RsaKeySize {
    /// Get the key size in bits.
    pub fn bits(&self) -> usize {
        *self as usize
    }

    /// Get the key size in bytes.
    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }

    /// Get the maximum plaintext size for OAEP (with SHA-256).
    pub fn max_oaep_plaintext_size(&self) -> usize {
        // OAEP overhead with SHA-256: 2 * hash_len + 2 = 66 bytes
        self.bytes() - 66
    }
}

/// Elliptic curve types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    /// NIST P-256 (secp256r1)
    P256,
    /// NIST P-384 (secp384r1)
    P384,
    /// secp256k1 (Bitcoin curve)
    Secp256k1,
    /// Curve25519
    Curve25519,
    /// Curve448
    Curve448,
}

impl EllipticCurve {
    /// Get the security level in bits.
    pub fn security_bits(&self) -> usize {
        match self {
            EllipticCurve::P256 => 128,
            EllipticCurve::P384 => 192,
            EllipticCurve::Secp256k1 => 128,
            EllipticCurve::Curve25519 => 128,
            EllipticCurve::Curve448 => 224,
        }
    }

    /// Get the curve name.
    pub fn name(&self) -> &'static str {
        match self {
            EllipticCurve::P256 => "P-256",
            EllipticCurve::P384 => "P-384",
            EllipticCurve::Secp256k1 => "secp256k1",
            EllipticCurve::Curve25519 => "Curve25519",
            EllipticCurve::Curve448 => "Curve448",
        }
    }

    /// Get the key size in bytes.
    pub fn key_size(&self) -> usize {
        match self {
            EllipticCurve::P256 => 32,
            EllipticCurve::P384 => 48,
            EllipticCurve::Secp256k1 => 32,
            EllipticCurve::Curve25519 => 32,
            EllipticCurve::Curve448 => 56,
        }
    }
}
