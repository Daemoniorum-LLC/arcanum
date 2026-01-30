//! Algorithm registry for cryptographic agility.
//!
//! Central registry of all supported algorithms with metadata.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Unique identifier for a cryptographic algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum AlgorithmId {
    // Symmetric ciphers (1-15)
    /// AES-256-GCM
    Aes256Gcm = 1,
    /// AES-128-GCM
    Aes128Gcm = 2,
    /// AES-256-GCM-SIV
    Aes256GcmSiv = 3,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 4,
    /// XChaCha20-Poly1305
    XChaCha20Poly1305 = 5,

    // Hash functions (16-31)
    /// SHA-256
    Sha256 = 16,
    /// SHA-512
    Sha512 = 17,
    /// BLAKE3
    Blake3 = 18,
    /// SHA3-256
    Sha3_256 = 19,

    // Asymmetric (32-47)
    /// X25519 key exchange
    X25519 = 32,
    /// Ed25519 signatures
    Ed25519 = 33,
    /// ECDSA P-256
    EcdsaP256 = 34,
    /// ECDSA P-384
    EcdsaP384 = 35,

    // Post-quantum (64-79)
    /// ML-KEM-768
    MlKem768 = 64,
    /// ML-KEM-1024
    MlKem1024 = 65,
    /// ML-DSA-65
    MlDsa65 = 66,
    /// ML-DSA-87
    MlDsa87 = 67,

    // Hybrid (96-111)
    /// X25519 + ML-KEM-768
    HybridKem = 96,
    /// Ed25519 + ML-DSA-65
    CompositeSignature = 97,

    // Deprecated (128+)
    /// Triple DES (deprecated)
    TripleDes = 128,
    /// SHA-1 (deprecated)
    Sha1 = 129,
}

impl AlgorithmId {
    /// Try to convert from a u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Aes256Gcm),
            2 => Some(Self::Aes128Gcm),
            3 => Some(Self::Aes256GcmSiv),
            4 => Some(Self::ChaCha20Poly1305),
            5 => Some(Self::XChaCha20Poly1305),
            16 => Some(Self::Sha256),
            17 => Some(Self::Sha512),
            18 => Some(Self::Blake3),
            19 => Some(Self::Sha3_256),
            32 => Some(Self::X25519),
            33 => Some(Self::Ed25519),
            34 => Some(Self::EcdsaP256),
            35 => Some(Self::EcdsaP384),
            64 => Some(Self::MlKem768),
            65 => Some(Self::MlKem1024),
            66 => Some(Self::MlDsa65),
            67 => Some(Self::MlDsa87),
            96 => Some(Self::HybridKem),
            97 => Some(Self::CompositeSignature),
            128 => Some(Self::TripleDes),
            129 => Some(Self::Sha1),
            _ => None,
        }
    }
}

/// Security level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// ~80 bits (deprecated)
    Bits80,
    /// ~112 bits (legacy)
    Bits112,
    /// 128 bits (standard)
    Bits128,
    /// 192 bits (high security)
    Bits192,
    /// 256 bits (maximum)
    Bits256,
}

/// Metadata about an algorithm.
#[derive(Debug, Clone)]
pub struct AlgorithmInfo {
    /// Algorithm identifier
    pub id: AlgorithmId,
    /// Human-readable name
    pub name: &'static str,
    /// Security level
    pub security_level: SecurityLevel,
    /// Whether this algorithm is deprecated
    pub deprecated: bool,
    /// Reason for deprecation (if any)
    pub deprecation_reason: Option<&'static str>,
    /// Whether this is a post-quantum algorithm
    pub post_quantum: bool,
    /// Key size in bytes
    pub key_size: usize,
    /// Nonce/IV size in bytes (for symmetric ciphers)
    pub nonce_size: Option<usize>,
}

impl AlgorithmInfo {
    /// Get the algorithm name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Get the security level.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Check if the algorithm is deprecated.
    pub fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    /// Get the deprecation reason.
    pub fn deprecation_reason(&self) -> Option<&str> {
        self.deprecation_reason
    }

    /// Check if this is a post-quantum algorithm.
    pub fn is_post_quantum(&self) -> bool {
        self.post_quantum
    }

    /// Get the key size in bytes.
    pub fn key_size(&self) -> usize {
        self.key_size
    }

    /// Get the nonce size in bytes.
    pub fn nonce_size(&self) -> Option<usize> {
        self.nonce_size
    }
}

/// Central registry for algorithm information.
pub struct AlgorithmRegistry;

impl AlgorithmRegistry {
    /// Look up an algorithm by ID.
    pub fn get(id: AlgorithmId) -> Option<AlgorithmInfo> {
        Some(match id {
            AlgorithmId::Aes256Gcm => AlgorithmInfo {
                id,
                name: "AES-256-GCM",
                security_level: SecurityLevel::Bits256,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: false,
                key_size: 32,
                nonce_size: Some(12),
            },
            AlgorithmId::Aes128Gcm => AlgorithmInfo {
                id,
                name: "AES-128-GCM",
                security_level: SecurityLevel::Bits128,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: false,
                key_size: 16,
                nonce_size: Some(12),
            },
            AlgorithmId::Aes256GcmSiv => AlgorithmInfo {
                id,
                name: "AES-256-GCM-SIV",
                security_level: SecurityLevel::Bits256,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: false,
                key_size: 32,
                nonce_size: Some(12),
            },
            AlgorithmId::ChaCha20Poly1305 => AlgorithmInfo {
                id,
                name: "ChaCha20-Poly1305",
                security_level: SecurityLevel::Bits256,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: false,
                key_size: 32,
                nonce_size: Some(12),
            },
            AlgorithmId::XChaCha20Poly1305 => AlgorithmInfo {
                id,
                name: "XChaCha20-Poly1305",
                security_level: SecurityLevel::Bits256,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: false,
                key_size: 32,
                nonce_size: Some(24),
            },
            AlgorithmId::Blake3 => AlgorithmInfo {
                id,
                name: "BLAKE3",
                security_level: SecurityLevel::Bits256,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: false,
                key_size: 32,
                nonce_size: None,
            },
            AlgorithmId::MlKem768 => AlgorithmInfo {
                id,
                name: "ML-KEM-768",
                security_level: SecurityLevel::Bits192,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: true,
                key_size: 2400, // Encapsulation key size
                nonce_size: None,
            },
            AlgorithmId::TripleDes => AlgorithmInfo {
                id,
                name: "3DES",
                security_level: SecurityLevel::Bits112,
                deprecated: true,
                deprecation_reason: Some("Insufficient security margin"),
                post_quantum: false,
                key_size: 24,
                nonce_size: Some(8),
            },
            AlgorithmId::HybridKem => AlgorithmInfo {
                id,
                name: "X25519-ML-KEM-768",
                security_level: SecurityLevel::Bits192,
                deprecated: false,
                deprecation_reason: None,
                post_quantum: true, // Hybrid counts as PQ
                key_size: 32 + 2400,
                nonce_size: None,
            },
            // Add more algorithms as needed
            _ => return None,
        })
    }

    /// Get all registered algorithms.
    pub fn all() -> Vec<AlgorithmInfo> {
        use AlgorithmId::*;
        [
            Aes256Gcm,
            Aes128Gcm,
            ChaCha20Poly1305,
            Blake3,
            MlKem768,
            HybridKem,
            TripleDes,
        ]
        .iter()
        .filter_map(|&id| Self::get(id))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_lookup() {
        let aes = AlgorithmRegistry::get(AlgorithmId::Aes256Gcm).unwrap();
        assert_eq!(aes.name(), "AES-256-GCM");
        assert_eq!(aes.security_level(), SecurityLevel::Bits256);
        assert!(!aes.is_deprecated());
    }

    #[test]
    fn test_deprecated_algorithm() {
        let des = AlgorithmRegistry::get(AlgorithmId::TripleDes).unwrap();
        assert!(des.is_deprecated());
        assert!(des.deprecation_reason().is_some());
    }

    #[test]
    fn test_pqc_algorithm() {
        let mlkem = AlgorithmRegistry::get(AlgorithmId::MlKem768).unwrap();
        assert!(mlkem.is_post_quantum());
    }
}
