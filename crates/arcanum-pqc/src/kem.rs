//! ML-KEM (Module-Lattice Key Encapsulation Mechanism).
//!
//! Formerly known as CRYSTALS-Kyber, ML-KEM is the NIST-standardized
//! post-quantum key encapsulation mechanism (FIPS 203).
//!
//! ## Security Levels
//!
//! - **ML-KEM-512**: NIST Level 1 (128-bit security)
//! - **ML-KEM-768**: NIST Level 3 (192-bit security) - **Recommended**
//! - **ML-KEM-1024**: NIST Level 5 (256-bit security)

use crate::traits::KeyEncapsulation;
use arcanum_core::error::{Error, Result};
use kem::{Decapsulate, Encapsulate};
use ml_kem::{
    EncodedSizeUser, KemCore, MlKem512Params, MlKem768Params, MlKem1024Params,
    kem::{DecapsulationKey, EncapsulationKey},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Type aliases for the actual ml-kem types
type MlKem768Inner = ml_kem::MlKem768;
type MlKem512Inner = ml_kem::MlKem512;
type MlKem1024Inner = ml_kem::MlKem1024;

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-768 (Recommended)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-768 decapsulation key (private key).
#[derive(Clone)]
pub struct MlKem768DecapsulationKey {
    bytes: Vec<u8>,
}

impl Drop for MlKem768DecapsulationKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for MlKem768DecapsulationKey {}

impl MlKem768DecapsulationKey {
    /// Decapsulation key size for ML-KEM-768.
    pub const SIZE: usize = 2400;

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

    fn inner(&self) -> DecapsulationKey<MlKem768Params> {
        let arr: [u8; 2400] = self.bytes.as_slice().try_into().unwrap();
        DecapsulationKey::from_bytes(&arr.into())
    }
}

impl std::fmt::Debug for MlKem768DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem768DecapsulationKey([REDACTED])")
    }
}

/// ML-KEM-768 encapsulation key (public key).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKem768EncapsulationKey {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)
        } else {
            <Vec<u8>>::deserialize(deserializer)
        }
    }
}

impl MlKem768EncapsulationKey {
    /// Encapsulation key size for ML-KEM-768.
    pub const SIZE: usize = 1184;

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

    /// Get inner key for operations.
    fn inner(&self) -> EncapsulationKey<MlKem768Params> {
        let arr: [u8; 1184] = self.bytes.as_slice().try_into().unwrap();
        EncapsulationKey::from_bytes(&arr.into())
    }
}

impl std::fmt::Debug for MlKem768EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MlKem768EncapsulationKey({}...)",
            &hex::encode(&self.bytes[..16])
        )
    }
}

/// ML-KEM-768 ciphertext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKem768Ciphertext {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

impl MlKem768Ciphertext {
    /// Ciphertext size for ML-KEM-768.
    pub const SIZE: usize = 1088;

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidCiphertext);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl std::fmt::Debug for MlKem768Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem768Ciphertext({} bytes)", self.bytes.len())
    }
}

/// ML-KEM-768 shared secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret {
    bytes: [u8; 32],
}

impl MlKem768SharedSecret {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKeyLength {
            expected: 32,
            actual: bytes.len(),
        })?;
        Ok(Self { bytes: arr })
    }

    /// Export to bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl PartialEq for MlKem768SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        let mut result = 0u8;
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Eq for MlKem768SharedSecret {}

impl std::fmt::Debug for MlKem768SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem768SharedSecret([REDACTED])")
    }
}

/// ML-KEM-768: NIST Level 3 security (192-bit).
///
/// The recommended variant for most applications.
pub struct MlKem768;

impl KeyEncapsulation for MlKem768 {
    type DecapsulationKey = MlKem768DecapsulationKey;
    type EncapsulationKey = MlKem768EncapsulationKey;
    type Ciphertext = MlKem768Ciphertext;
    type SharedSecret = MlKem768SharedSecret;

    const ALGORITHM: &'static str = "ML-KEM-768";
    const SECURITY_LEVEL: usize = 192;

    fn generate_keypair() -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let (dk, ek) = MlKem768Inner::generate(&mut OsRng);
        (
            MlKem768DecapsulationKey {
                bytes: dk.as_bytes().to_vec(),
            },
            MlKem768EncapsulationKey {
                bytes: ek.as_bytes().to_vec(),
            },
        )
    }

    fn encapsulate(ek: &Self::EncapsulationKey) -> (Self::Ciphertext, Self::SharedSecret) {
        let inner_ek = ek.inner();
        let (ct, ss) = inner_ek.encapsulate(&mut OsRng).unwrap();
        (
            MlKem768Ciphertext { bytes: ct.to_vec() },
            MlKem768SharedSecret {
                bytes: ss.as_slice().try_into().unwrap(),
            },
        )
    }

    fn decapsulate(
        dk: &Self::DecapsulationKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret> {
        let inner_dk = dk.inner();
        let ct_arr: [u8; 1088] = ciphertext
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidCiphertext)?;
        let ct: ml_kem::Ciphertext<MlKem768Inner> = ct_arr.into();

        let ss = inner_dk
            .decapsulate(&ct)
            .map_err(|_| Error::DecryptionFailed)?;

        Ok(MlKem768SharedSecret {
            bytes: ss.as_slice().try_into().unwrap(),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-512 (Level 1)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-512: NIST Level 1 security (128-bit).
pub struct MlKem512;

impl MlKem512 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-KEM-512";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 128;
    /// Decapsulation key size.
    pub const DK_SIZE: usize = 1632;
    /// Encapsulation key size.
    pub const EK_SIZE: usize = 800;
    /// Ciphertext size.
    pub const CT_SIZE: usize = 768;

    /// Generate a key pair.
    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let (dk, ek) = MlKem512Inner::generate(&mut OsRng);
        (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
    }

    /// Encapsulate to produce ciphertext and shared secret.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let arr: [u8; 800] = ek_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let ek = EncapsulationKey::<MlKem512Params>::from_bytes(&arr.into());

        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| Error::EncryptionFailed)?;

        Ok((ct.to_vec(), ss.as_slice().try_into().unwrap()))
    }

    /// Decapsulate to recover shared secret.
    pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32]> {
        let dk_arr: [u8; 1632] = dk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let dk = DecapsulationKey::<MlKem512Params>::from_bytes(&dk_arr.into());

        let ct_arr: [u8; 768] = ct_bytes.try_into().map_err(|_| Error::InvalidCiphertext)?;
        let ct: ml_kem::Ciphertext<MlKem512Inner> = ct_arr.into();

        let ss = dk.decapsulate(&ct).map_err(|_| Error::DecryptionFailed)?;

        Ok(ss.as_slice().try_into().unwrap())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-1024 (Level 5)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-1024: NIST Level 5 security (256-bit).
pub struct MlKem1024;

impl MlKem1024 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-KEM-1024";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 256;
    /// Decapsulation key size.
    pub const DK_SIZE: usize = 3168;
    /// Encapsulation key size.
    pub const EK_SIZE: usize = 1568;
    /// Ciphertext size.
    pub const CT_SIZE: usize = 1568;

    /// Generate a key pair.
    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let (dk, ek) = MlKem1024Inner::generate(&mut OsRng);
        (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
    }

    /// Encapsulate to produce ciphertext and shared secret.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let arr: [u8; 1568] = ek_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let ek = EncapsulationKey::<MlKem1024Params>::from_bytes(&arr.into());

        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| Error::EncryptionFailed)?;

        Ok((ct.to_vec(), ss.as_slice().try_into().unwrap()))
    }

    /// Decapsulate to recover shared secret.
    pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32]> {
        let dk_arr: [u8; 3168] = dk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?;
        let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&dk_arr.into());

        let ct_arr: [u8; 1568] = ct_bytes.try_into().map_err(|_| Error::InvalidCiphertext)?;
        let ct: ml_kem::Ciphertext<MlKem1024Inner> = ct_arr.into();

        let ss = dk.decapsulate(&ct).map_err(|_| Error::DecryptionFailed)?;

        Ok(ss.as_slice().try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let (dk, ek) = MlKem768::generate_keypair();
        let (ct, ss1) = MlKem768::encapsulate(&ek);
        let ss2 = MlKem768::decapsulate(&dk, &ct).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_768_different_keypairs() {
        let (dk1, ek1) = MlKem768::generate_keypair();
        let (dk2, _ek2) = MlKem768::generate_keypair();

        let (ct, ss1) = MlKem768::encapsulate(&ek1);

        // Correct key should work
        let ss_correct = MlKem768::decapsulate(&dk1, &ct).unwrap();
        assert_eq!(ss1, ss_correct);

        // Wrong key should produce different result (implicit reject)
        let ss_wrong = MlKem768::decapsulate(&dk2, &ct).unwrap();
        assert_ne!(ss1, ss_wrong);
    }

    #[test]
    fn test_ml_kem_512_roundtrip() {
        let (dk, ek) = MlKem512::generate_keypair();
        let (ct, ss1) = MlKem512::encapsulate(&ek).unwrap();
        let ss2 = MlKem512::decapsulate(&dk, &ct).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_1024_roundtrip() {
        let (dk, ek) = MlKem1024::generate_keypair();
        let (ct, ss1) = MlKem1024::encapsulate(&ek).unwrap();
        let ss2 = MlKem1024::decapsulate(&dk, &ct).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_key_sizes() {
        let (dk, ek) = MlKem768::generate_keypair();
        assert_eq!(dk.to_bytes().len(), 2400);
        assert_eq!(ek.to_bytes().len(), 1184);

        let (ct, _ss) = MlKem768::encapsulate(&ek);
        assert_eq!(ct.to_bytes().len(), 1088);
    }
}
