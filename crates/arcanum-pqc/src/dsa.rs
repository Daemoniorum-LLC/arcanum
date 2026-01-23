//! ML-DSA (Module-Lattice Digital Signature Algorithm).
//!
//! Formerly known as CRYSTALS-Dilithium, ML-DSA is the NIST-standardized
//! post-quantum digital signature algorithm (FIPS 204).
//!
//! ## Security Levels
//!
//! - **ML-DSA-44**: NIST Level 2 (128-bit security)
//! - **ML-DSA-65**: NIST Level 3 (192-bit security) - **Recommended**
//! - **ML-DSA-87**: NIST Level 5 (256-bit security)

use crate::traits::PostQuantumSignature;
use arcanum_core::error::{Error, Result};
use ml_dsa::{KeyGen, signature::Signer as _, signature::Verifier as _};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

// Type aliases to distinguish from our wrapper types
type MlDsa65Inner = ml_dsa::MlDsa65;
type MlDsa44Inner = ml_dsa::MlDsa44;
type MlDsa87Inner = ml_dsa::MlDsa87;

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-65 (Recommended)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-65 signing key (private key).
#[derive(Clone, ZeroizeOnDrop)]
pub struct MlDsa65SigningKey {
    bytes: Vec<u8>,
}

impl MlDsa65SigningKey {
    /// Signing key size for ML-DSA-65.
    pub const SIZE: usize = 4032;

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn inner(&self) -> ml_dsa::SigningKey<MlDsa65Inner> {
        let arr: [u8; 4032] = self.bytes.as_slice().try_into().unwrap();
        ml_dsa::SigningKey::from_expanded(&arr.into())
    }
}

impl std::fmt::Debug for MlDsa65SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa65SigningKey([REDACTED])")
    }
}

/// ML-DSA-65 verifying key (public key).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsa65VerifyingKey {
    bytes: Vec<u8>,
}

impl MlDsa65VerifyingKey {
    /// Verifying key size for ML-DSA-65.
    pub const SIZE: usize = 1952;

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    fn inner(&self) -> ml_dsa::VerifyingKey<MlDsa65Inner> {
        let arr: [u8; 1952] = self.bytes.as_slice().try_into().unwrap();
        ml_dsa::VerifyingKey::decode(&arr.into())
    }
}

impl std::fmt::Debug for MlDsa65VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlDsa65VerifyingKey({}...)",
            &hex::encode(&self.bytes[..16])
        )
    }
}

/// ML-DSA-65 signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsa65Signature {
    bytes: Vec<u8>,
}

impl MlDsa65Signature {
    /// Signature size for ML-DSA-65.
    pub const SIZE: usize = 3309;

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSignature);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}

impl std::fmt::Debug for MlDsa65Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsa65Signature({} bytes)", self.bytes.len())
    }
}

/// ML-DSA-65: NIST Level 3 security (192-bit).
///
/// The recommended variant for most applications.
pub struct MlDsa65;

impl PostQuantumSignature for MlDsa65 {
    type SigningKey = MlDsa65SigningKey;
    type VerifyingKey = MlDsa65VerifyingKey;
    type Signature = MlDsa65Signature;

    const ALGORITHM: &'static str = "ML-DSA-65";
    const SECURITY_LEVEL: usize = 192;

    fn generate_keypair() -> (Self::SigningKey, Self::VerifyingKey) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        let kp = MlDsa65Inner::from_seed(&seed.into());
        let expanded = kp.signing_key().to_expanded();
        let sk_bytes: &[u8] = expanded.as_ref();
        (
            MlDsa65SigningKey {
                bytes: sk_bytes.to_vec(),
            },
            MlDsa65VerifyingKey {
                bytes: kp.verifying_key().encode().to_vec(),
            },
        )
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let inner_sk = sk.inner();
        let sig = inner_sk.sign(message);
        MlDsa65Signature {
            bytes: sig.encode().to_vec(),
        }
    }

    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> Result<()> {
        let inner_vk = vk.inner();
        let sig_arr: [u8; 3309] = signature
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSignature)?;
        let sig = ml_dsa::Signature::<MlDsa65Inner>::decode(&sig_arr.into())
            .ok_or(Error::InvalidSignature)?;

        inner_vk
            .verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-44 (Level 2)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-44: NIST Level 2 security (128-bit).
pub struct MlDsa44Ops;

impl MlDsa44Ops {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-DSA-44";
    /// Security level.
    pub const SECURITY_LEVEL: usize = 128;
    /// Signing key size.
    pub const SK_SIZE: usize = 2560;
    /// Verifying key size.
    pub const VK_SIZE: usize = 1312;
    /// Signature size.
    pub const SIG_SIZE: usize = 2420;

    /// Generate a key pair.
    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        let kp = MlDsa44Inner::from_seed(&seed.into());
        let expanded = kp.signing_key().to_expanded();
        let sk_bytes: &[u8] = expanded.as_ref();
        (sk_bytes.to_vec(), kp.verifying_key().encode().to_vec())
    }

    /// Sign a message.
    pub fn sign(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let arr: [u8; 2560] = sk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let sk = ml_dsa::SigningKey::<MlDsa44Inner>::from_expanded(&arr.into());

        let sig = sk.sign(message);
        Ok(sig.encode().to_vec())
    }

    /// Verify a signature.
    pub fn verify(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
        let vk_arr: [u8; 1312] = vk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let vk = ml_dsa::VerifyingKey::<MlDsa44Inner>::decode(&vk_arr.into());

        let sig_arr: [u8; 2420] = sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?;
        let sig = ml_dsa::Signature::<MlDsa44Inner>::decode(&sig_arr.into())
            .ok_or(Error::InvalidSignature)?;

        vk.verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-87 (Level 5)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-87: NIST Level 5 security (256-bit).
pub struct MlDsa87Ops;

impl MlDsa87Ops {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-DSA-87";
    /// Security level.
    pub const SECURITY_LEVEL: usize = 256;
    /// Signing key size.
    pub const SK_SIZE: usize = 4896;
    /// Verifying key size.
    pub const VK_SIZE: usize = 2592;
    /// Signature size.
    pub const SIG_SIZE: usize = 4627;

    /// Generate a key pair.
    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        let kp = MlDsa87Inner::from_seed(&seed.into());
        let expanded = kp.signing_key().to_expanded();
        let sk_bytes: &[u8] = expanded.as_ref();
        (sk_bytes.to_vec(), kp.verifying_key().encode().to_vec())
    }

    /// Sign a message.
    pub fn sign(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let arr: [u8; 4896] = sk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let sk = ml_dsa::SigningKey::<MlDsa87Inner>::from_expanded(&arr.into());

        let sig = sk.sign(message);
        Ok(sig.encode().to_vec())
    }

    /// Verify a signature.
    pub fn verify(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
        let vk_arr: [u8; 2592] = vk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let vk = ml_dsa::VerifyingKey::<MlDsa87Inner>::decode(&vk_arr.into());

        let sig_arr: [u8; 4627] = sig_bytes.try_into().map_err(|_| Error::InvalidSignature)?;
        let sig = ml_dsa::Signature::<MlDsa87Inner>::decode(&sig_arr.into())
            .ok_or(Error::InvalidSignature)?;

        vk.verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_sign_verify() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let message = b"Hello, post-quantum world!";

        let sig = MlDsa65::sign(&sk, message);
        assert!(MlDsa65::verify(&vk, message, &sig).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_wrong_message() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let message = b"Hello!";
        let wrong_message = b"Wrong!";

        let sig = MlDsa65::sign(&sk, message);
        assert!(MlDsa65::verify(&vk, wrong_message, &sig).is_err());
    }

    #[test]
    fn test_ml_dsa_65_wrong_key() {
        let (sk1, _vk1) = MlDsa65::generate_keypair();
        let (_sk2, vk2) = MlDsa65::generate_keypair();
        let message = b"Hello!";

        let sig = MlDsa65::sign(&sk1, message);
        assert!(MlDsa65::verify(&vk2, message, &sig).is_err());
    }

    #[test]
    fn test_ml_dsa_44_roundtrip() {
        let (sk, vk) = MlDsa44Ops::generate_keypair();
        let message = b"Test message";

        let sig = MlDsa44Ops::sign(&sk, message).unwrap();
        assert!(MlDsa44Ops::verify(&vk, message, &sig).is_ok());
    }

    #[test]
    fn test_ml_dsa_87_roundtrip() {
        let (sk, vk) = MlDsa87Ops::generate_keypair();
        let message = b"Test message";

        let sig = MlDsa87Ops::sign(&sk, message).unwrap();
        assert!(MlDsa87Ops::verify(&vk, message, &sig).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let (sk, vk) = MlDsa65::generate_keypair();
        assert_eq!(sk.to_bytes().len(), 4032);
        assert_eq!(vk.to_bytes().len(), 1952);

        let sig = MlDsa65::sign(&sk, b"test");
        assert_eq!(sig.to_bytes().len(), 3309);
    }
}
