//! Hybrid post-quantum key exchange schemes.
//!
//! Hybrid schemes combine classical and post-quantum algorithms for
//! defense-in-depth. The shared secret is derived from both:
//! - If the classical algorithm is broken, PQ provides security
//! - If the PQ algorithm is broken, classical provides security
//!
//! ## X25519-ML-KEM-768
//!
//! Combines X25519 (ECDH) with ML-KEM-768:
//! - Classical: X25519 (128-bit security)
//! - Post-quantum: ML-KEM-768 (192-bit security)
//! - Combined secret derived via HKDF

use crate::kem::{
    MlKem768, MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey,
    MlKem768SharedSecret,
};
use crate::traits::KeyEncapsulation;
use arcanum_core::error::{Error, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519-ML-KEM-768 hybrid decapsulation key.
#[derive(ZeroizeOnDrop)]
pub struct X25519MlKem768DecapsulationKey {
    x25519_secret: StaticSecret,
    ml_kem_dk: MlKem768DecapsulationKey,
}

impl X25519MlKem768DecapsulationKey {
    /// Get the X25519 component.
    pub fn x25519_public(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.x25519_secret).to_bytes()
    }
}

impl std::fmt::Debug for X25519MlKem768DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519MlKem768DecapsulationKey([REDACTED])")
    }
}

/// X25519-ML-KEM-768 hybrid encapsulation key.
#[derive(Clone)]
pub struct X25519MlKem768EncapsulationKey {
    x25519_public: X25519PublicKey,
    ml_kem_ek: MlKem768EncapsulationKey,
}

impl X25519MlKem768EncapsulationKey {
    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1184);
        bytes.extend_from_slice(self.x25519_public.as_bytes());
        bytes.extend_from_slice(&self.ml_kem_ek.to_bytes());
        bytes
    }

    /// Import from bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 + 1184 {
            return Err(Error::InvalidKeyLength {
                expected: 32 + 1184,
                actual: bytes.len(),
            });
        }

        let x25519_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let ml_kem_bytes = &bytes[32..];

        Ok(Self {
            x25519_public: X25519PublicKey::from(x25519_bytes),
            ml_kem_ek: MlKem768EncapsulationKey::from_bytes(ml_kem_bytes)?,
        })
    }
}

impl std::fmt::Debug for X25519MlKem768EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "X25519MlKem768EncapsulationKey({}...)",
            hex::encode(&self.x25519_public.as_bytes()[..8])
        )
    }
}

/// X25519-ML-KEM-768 hybrid ciphertext.
#[derive(Clone)]
pub struct X25519MlKem768Ciphertext {
    x25519_public: X25519PublicKey,
    ml_kem_ct: MlKem768Ciphertext,
}

impl X25519MlKem768Ciphertext {
    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1088);
        bytes.extend_from_slice(self.x25519_public.as_bytes());
        bytes.extend_from_slice(&self.ml_kem_ct.to_bytes());
        bytes
    }

    /// Import from bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 + 1088 {
            return Err(Error::InvalidCiphertext);
        }

        let x25519_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let ml_kem_bytes = &bytes[32..];

        Ok(Self {
            x25519_public: X25519PublicKey::from(x25519_bytes),
            ml_kem_ct: MlKem768Ciphertext::from_bytes(ml_kem_bytes)?,
        })
    }

    /// Get the total ciphertext size.
    pub fn size() -> usize {
        32 + 1088 // X25519 public key + ML-KEM ciphertext
    }
}

impl std::fmt::Debug for X25519MlKem768Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519MlKem768Ciphertext({} bytes)", Self::size())
    }
}

/// X25519-ML-KEM-768 hybrid shared secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct X25519MlKem768SharedSecret {
    bytes: [u8; 32],
}

impl X25519MlKem768SharedSecret {
    /// Access the shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl PartialEq for X25519MlKem768SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        let mut result = 0u8;
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Eq for X25519MlKem768SharedSecret {}

impl std::fmt::Debug for X25519MlKem768SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519MlKem768SharedSecret([REDACTED])")
    }
}

/// X25519-ML-KEM-768 hybrid key encapsulation.
///
/// Combines X25519 (classical ECDH) with ML-KEM-768 (post-quantum KEM)
/// for quantum-resistant key exchange with classical fallback.
pub struct X25519MlKem768;

impl X25519MlKem768 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "X25519-ML-KEM-768";

    /// Context string for HKDF.
    const HKDF_INFO: &'static [u8] = b"X25519-ML-KEM-768 shared secret v1";

    /// Generate a hybrid key pair.
    pub fn generate_keypair() -> (
        X25519MlKem768DecapsulationKey,
        X25519MlKem768EncapsulationKey,
    ) {
        // Generate X25519 key pair
        let x25519_secret = StaticSecret::random_from_rng(&mut OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate ML-KEM-768 key pair
        let (ml_kem_dk, ml_kem_ek) = MlKem768::generate_keypair();

        (
            X25519MlKem768DecapsulationKey {
                x25519_secret,
                ml_kem_dk,
            },
            X25519MlKem768EncapsulationKey {
                x25519_public,
                ml_kem_ek,
            },
        )
    }

    /// Encapsulate: generate a shared secret and ciphertext.
    pub fn encapsulate(
        ek: &X25519MlKem768EncapsulationKey,
    ) -> (X25519MlKem768Ciphertext, X25519MlKem768SharedSecret) {
        // X25519 key exchange
        let x25519_ephemeral = EphemeralSecret::random_from_rng(&mut OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_ephemeral);
        let x25519_shared = x25519_ephemeral.diffie_hellman(&ek.x25519_public);

        // ML-KEM encapsulation
        let (ml_kem_ct, ml_kem_ss) = MlKem768::encapsulate(&ek.ml_kem_ek);

        // Combine shared secrets using HKDF
        let combined_secret = Self::combine_secrets(x25519_shared.as_bytes(), ml_kem_ss.as_bytes());

        (
            X25519MlKem768Ciphertext {
                x25519_public,
                ml_kem_ct,
            },
            X25519MlKem768SharedSecret {
                bytes: combined_secret,
            },
        )
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    #[must_use = "decapsulation can fail; check the Result"]
    pub fn decapsulate(
        dk: &X25519MlKem768DecapsulationKey,
        ciphertext: &X25519MlKem768Ciphertext,
    ) -> Result<X25519MlKem768SharedSecret> {
        // X25519 key exchange
        let x25519_shared = dk.x25519_secret.diffie_hellman(&ciphertext.x25519_public);

        // ML-KEM decapsulation
        let ml_kem_ss = MlKem768::decapsulate(&dk.ml_kem_dk, &ciphertext.ml_kem_ct)?;

        // Combine shared secrets using HKDF
        let combined_secret = Self::combine_secrets(x25519_shared.as_bytes(), ml_kem_ss.as_bytes());

        Ok(X25519MlKem768SharedSecret {
            bytes: combined_secret,
        })
    }

    /// Combine two shared secrets using HKDF.
    fn combine_secrets(x25519_ss: &[u8], ml_kem_ss: &[u8]) -> [u8; 32] {
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(x25519_ss);
        ikm.extend_from_slice(ml_kem_ss);

        let hkdf = Hkdf::<Sha256>::new(None, &ikm);
        let mut output = [0u8; 32];
        hkdf.expand(Self::HKDF_INFO, &mut output).unwrap();

        // Zeroize intermediate key material
        ikm.zeroize();

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_roundtrip() {
        let (dk, ek) = X25519MlKem768::generate_keypair();
        let (ct, ss1) = X25519MlKem768::encapsulate(&ek);
        let ss2 = X25519MlKem768::decapsulate(&dk, &ct).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_hybrid_different_keypairs() {
        let (dk1, ek1) = X25519MlKem768::generate_keypair();
        let (dk2, _ek2) = X25519MlKem768::generate_keypair();

        let (ct, ss1) = X25519MlKem768::encapsulate(&ek1);

        // Correct key should work
        let ss_correct = X25519MlKem768::decapsulate(&dk1, &ct).unwrap();
        assert_eq!(ss1, ss_correct);

        // Wrong key should produce different result
        let ss_wrong = X25519MlKem768::decapsulate(&dk2, &ct).unwrap();
        assert_ne!(ss1, ss_wrong);
    }

    #[test]
    fn test_encapsulation_key_serialization() {
        let (_dk, ek) = X25519MlKem768::generate_keypair();

        let bytes = ek.to_bytes();
        assert_eq!(bytes.len(), 32 + 1184);

        let restored = X25519MlKem768EncapsulationKey::from_bytes(&bytes).unwrap();
        assert_eq!(ek.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let (_dk, ek) = X25519MlKem768::generate_keypair();
        let (ct, _ss) = X25519MlKem768::encapsulate(&ek);

        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), X25519MlKem768Ciphertext::size());

        let restored = X25519MlKem768Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_deterministic_combination() {
        // Same inputs should produce same combined secret
        let x25519_ss = [1u8; 32];
        let ml_kem_ss = [2u8; 32];

        let combined1 = X25519MlKem768::combine_secrets(&x25519_ss, &ml_kem_ss);
        let combined2 = X25519MlKem768::combine_secrets(&x25519_ss, &ml_kem_ss);

        assert_eq!(combined1, combined2);
    }
}
