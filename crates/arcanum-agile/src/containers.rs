//! Versioned ciphertext containers for cryptographic agility.
//!
//! Self-describing containers that include algorithm metadata.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::errors::{AgileError, AgileResult};
use crate::registry::{AlgorithmId, AlgorithmRegistry};
use arcanum_symmetric::{
    Aes128Gcm, Aes256Gcm, Aes256GcmSiv, ChaCha20Poly1305Cipher, Cipher, XChaCha20Poly1305Cipher,
};
use serde::{Deserialize, Serialize};

/// Magic bytes identifying an Arcanum container.
pub const CONTAINER_MAGIC: [u8; 4] = *b"ARCN";

/// Current container format version.
pub const CONTAINER_VERSION: u8 = 1;

/// Header for a versioned container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerHeader {
    /// Magic bytes for identification
    pub magic: [u8; 4],
    /// Container format version
    pub format_version: u8,
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// Algorithm-specific version
    pub alg_version: u8,
    /// Nonce/IV length
    pub nonce_len: u8,
    /// Reserved for future use
    pub reserved: [u8; 2],
}

impl ContainerHeader {
    /// Create a new container header.
    pub fn new(algorithm: AlgorithmId) -> Self {
        Self {
            magic: CONTAINER_MAGIC,
            format_version: CONTAINER_VERSION,
            algorithm,
            alg_version: 1,
            nonce_len: 12,
            reserved: [0; 2],
        }
    }

    /// Parse a header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AgileResult<Self> {
        if bytes.len() < 10 {
            return Err(AgileError::ParseError {
                reason: "Header too short".into(),
            });
        }

        if &bytes[0..4] != &CONTAINER_MAGIC {
            return Err(AgileError::ParseError {
                reason: "Invalid magic bytes".into(),
            });
        }

        let format_version = bytes[4];
        if format_version > CONTAINER_VERSION {
            return Err(AgileError::UnsupportedVersion {
                version: format_version,
            });
        }

        // Parse algorithm ID
        let alg_id = u16::from_le_bytes([bytes[5], bytes[6]]);
        let algorithm =
            AlgorithmId::from_u16(alg_id).ok_or(AgileError::UnknownAlgorithm(alg_id))?;

        Ok(Self {
            magic: CONTAINER_MAGIC,
            format_version,
            algorithm,
            alg_version: bytes[7],
            nonce_len: bytes[8],
            reserved: [bytes[9], bytes.get(10).copied().unwrap_or(0)],
        })
    }

    /// Serialize the header to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(11);
        bytes.extend_from_slice(&self.magic);
        bytes.push(self.format_version);
        bytes.extend_from_slice(&(self.algorithm as u16).to_le_bytes());
        bytes.push(self.alg_version);
        bytes.push(self.nonce_len);
        bytes.extend_from_slice(&self.reserved);
        bytes
    }
}

/// A self-describing encrypted container.
#[derive(Debug, Clone)]
pub struct AgileCiphertext {
    /// Container header
    pub header: ContainerHeader,
    /// Nonce/IV
    pub nonce: Vec<u8>,
    /// Encrypted data (including authentication tag)
    pub ciphertext: Vec<u8>,
}

impl AgileCiphertext {
    /// Get the algorithm used.
    pub fn algorithm(&self) -> AlgorithmId {
        self.header.algorithm
    }

    /// Get the format version.
    pub fn version(&self) -> u8 {
        self.header.format_version
    }

    /// Check if this container can be decrypted with current algorithms.
    pub fn can_decrypt(&self) -> bool {
        crate::registry::AlgorithmRegistry::get(self.header.algorithm).is_some()
    }

    /// Get migration recommendation if the algorithm is deprecated.
    pub fn migration_recommendation(&self) -> Option<MigrationRecommendation> {
        let info = crate::registry::AlgorithmRegistry::get(self.header.algorithm)?;

        if info.is_deprecated() {
            Some(MigrationRecommendation {
                source: self.header.algorithm,
                target: AlgorithmId::Aes256Gcm, // Default recommendation
                reason: info
                    .deprecation_reason()
                    .unwrap_or("Algorithm deprecated")
                    .into(),
            })
        } else {
            None
        }
    }

    /// Encrypt data into a container.
    ///
    /// # Arguments
    /// * `algorithm` - The AEAD algorithm to use
    /// * `key` - Encryption key (must match algorithm's key size)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Errors
    /// Returns error if algorithm is unsupported or key size is invalid.
    pub fn encrypt(algorithm: AlgorithmId, key: &[u8], plaintext: &[u8]) -> AgileResult<Self> {
        let info = AlgorithmRegistry::get(algorithm)
            .ok_or(AgileError::UnsupportedAlgorithm { id: algorithm })?;

        // Validate key size
        if key.len() != info.key_size {
            return Err(AgileError::InvalidKeySize {
                expected: info.key_size,
                actual: key.len(),
            });
        }

        // Generate nonce and encrypt based on algorithm
        let (nonce, ciphertext) =
            match algorithm {
                AlgorithmId::Aes256Gcm => {
                    let nonce = Aes256Gcm::generate_nonce();
                    let ct = Aes256Gcm::encrypt(key, &nonce, plaintext, None).map_err(|_| {
                        AgileError::CryptoError {
                            reason: "encryption failed".into(),
                        }
                    })?;
                    (nonce, ct)
                }
                AlgorithmId::Aes128Gcm => {
                    let nonce = Aes128Gcm::generate_nonce();
                    let ct = Aes128Gcm::encrypt(key, &nonce, plaintext, None).map_err(|_| {
                        AgileError::CryptoError {
                            reason: "encryption failed".into(),
                        }
                    })?;
                    (nonce, ct)
                }
                AlgorithmId::Aes256GcmSiv => {
                    let nonce = Aes256GcmSiv::generate_nonce();
                    let ct = Aes256GcmSiv::encrypt(key, &nonce, plaintext, None).map_err(|_| {
                        AgileError::CryptoError {
                            reason: "encryption failed".into(),
                        }
                    })?;
                    (nonce, ct)
                }
                AlgorithmId::ChaCha20Poly1305 => {
                    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
                    let ct = ChaCha20Poly1305Cipher::encrypt(key, &nonce, plaintext, None)
                        .map_err(|_| AgileError::CryptoError {
                            reason: "encryption failed".into(),
                        })?;
                    (nonce, ct)
                }
                AlgorithmId::XChaCha20Poly1305 => {
                    let nonce = XChaCha20Poly1305Cipher::generate_nonce();
                    let ct = XChaCha20Poly1305Cipher::encrypt(key, &nonce, plaintext, None)
                        .map_err(|_| AgileError::CryptoError {
                            reason: "encryption failed".into(),
                        })?;
                    (nonce, ct)
                }
                _ => {
                    return Err(AgileError::UnsupportedAlgorithm { id: algorithm });
                }
            };

        let mut header = ContainerHeader::new(algorithm);
        header.nonce_len = nonce.len() as u8;

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt a container.
    ///
    /// # Arguments
    /// * `key` - Decryption key (must match algorithm's key size)
    ///
    /// # Errors
    /// Returns error if decryption fails or algorithm is unsupported.
    pub fn decrypt(&self, key: &[u8]) -> AgileResult<Vec<u8>> {
        let algorithm = self.header.algorithm;
        let info = AlgorithmRegistry::get(algorithm)
            .ok_or(AgileError::UnsupportedAlgorithm { id: algorithm })?;

        // Validate key size
        if key.len() != info.key_size {
            return Err(AgileError::InvalidKeySize {
                expected: info.key_size,
                actual: key.len(),
            });
        }

        // Decrypt based on algorithm
        match algorithm {
            AlgorithmId::Aes256Gcm => Aes256Gcm::decrypt(key, &self.nonce, &self.ciphertext, None)
                .map_err(|_| AgileError::CryptoError {
                    reason: "decryption failed".into(),
                }),
            AlgorithmId::Aes128Gcm => Aes128Gcm::decrypt(key, &self.nonce, &self.ciphertext, None)
                .map_err(|_| AgileError::CryptoError {
                    reason: "decryption failed".into(),
                }),
            AlgorithmId::Aes256GcmSiv => {
                Aes256GcmSiv::decrypt(key, &self.nonce, &self.ciphertext, None).map_err(|_| {
                    AgileError::CryptoError {
                        reason: "decryption failed".into(),
                    }
                })
            }
            AlgorithmId::ChaCha20Poly1305 => {
                ChaCha20Poly1305Cipher::decrypt(key, &self.nonce, &self.ciphertext, None).map_err(
                    |_| AgileError::CryptoError {
                        reason: "decryption failed".into(),
                    },
                )
            }
            AlgorithmId::XChaCha20Poly1305 => {
                XChaCha20Poly1305Cipher::decrypt(key, &self.nonce, &self.ciphertext, None).map_err(
                    |_| AgileError::CryptoError {
                        reason: "decryption failed".into(),
                    },
                )
            }
            _ => Err(AgileError::UnsupportedAlgorithm { id: algorithm }),
        }
    }

    /// Parse a container from bytes.
    pub fn parse(bytes: &[u8]) -> AgileResult<Self> {
        let header = ContainerHeader::from_bytes(bytes)?;
        let nonce_start = 11;
        let nonce_end = nonce_start + header.nonce_len as usize;

        if bytes.len() < nonce_end {
            return Err(AgileError::ParseError {
                reason: "Container too short for nonce".into(),
            });
        }

        Ok(Self {
            header,
            nonce: bytes[nonce_start..nonce_end].to_vec(),
            ciphertext: bytes[nonce_end..].to_vec(),
        })
    }

    /// Serialize the container to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }
}

/// Recommendation for migrating to a newer algorithm.
#[derive(Debug, Clone)]
pub struct MigrationRecommendation {
    /// Current algorithm
    pub source: AlgorithmId,
    /// Recommended target algorithm
    pub target: AlgorithmId,
    /// Reason for migration
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = ContainerHeader::new(AlgorithmId::Aes256Gcm);
        let bytes = header.to_bytes();
        let parsed = ContainerHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.algorithm, AlgorithmId::Aes256Gcm);
        assert_eq!(parsed.format_version, CONTAINER_VERSION);
    }

    #[test]
    fn test_migration_recommendation() {
        // Construct a container with a deprecated algorithm directly
        // (we don't implement TripleDES encryption, just the migration advice)
        let container = AgileCiphertext {
            header: ContainerHeader::new(AlgorithmId::TripleDes),
            nonce: vec![0u8; 8],
            ciphertext: vec![0u8; 16], // Fake ciphertext for testing
        };

        let recommendation = container.migration_recommendation();
        assert!(recommendation.is_some());
        assert_eq!(recommendation.unwrap().target, AlgorithmId::Aes256Gcm);
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = vec![0u8; 32];
        let plaintext = b"Hello, Arcanum!";

        let container = AgileCiphertext::encrypt(AlgorithmId::Aes256Gcm, &key, plaintext).unwrap();

        let decrypted = container.decrypt(&key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = vec![0u8; 32];
        let plaintext = b"Secret message";

        let container =
            AgileCiphertext::encrypt(AlgorithmId::ChaCha20Poly1305, &key, plaintext).unwrap();

        let decrypted = container.decrypt(&key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_container_serialization_roundtrip() {
        let key = vec![0u8; 32];
        let plaintext = b"Test data";

        let container = AgileCiphertext::encrypt(AlgorithmId::Aes256Gcm, &key, plaintext).unwrap();

        let bytes = container.to_bytes();
        let parsed = AgileCiphertext::parse(&bytes).unwrap();

        assert_eq!(parsed.algorithm(), AlgorithmId::Aes256Gcm);
        let decrypted = parsed.decrypt(&key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }
}
