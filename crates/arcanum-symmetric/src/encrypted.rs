//! Encrypted data containers.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use arcanum_core::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Container for encrypted data with all necessary metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted ciphertext (includes auth tag for AEAD).
    pub ciphertext: Vec<u8>,
    /// The nonce/IV used for encryption.
    pub nonce: Vec<u8>,
    /// Algorithm identifier.
    pub algorithm: String,
    /// Optional associated data that was authenticated but not encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associated_data: Option<Vec<u8>>,
}

impl EncryptedData {
    /// Create a new encrypted data container.
    pub fn new(ciphertext: Vec<u8>, nonce: Vec<u8>, algorithm: impl Into<String>) -> Self {
        Self {
            ciphertext,
            nonce,
            algorithm: algorithm.into(),
            associated_data: None,
        }
    }

    /// Create with associated data.
    pub fn with_aad(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        algorithm: impl Into<String>,
        associated_data: Vec<u8>,
    ) -> Self {
        Self {
            ciphertext,
            nonce,
            algorithm: algorithm.into(),
            associated_data: Some(associated_data),
        }
    }

    /// Get the total size of the encrypted data.
    pub fn size(&self) -> usize {
        self.ciphertext.len()
            + self.nonce.len()
            + self.associated_data.as_ref().map_or(0, |d| d.len())
    }
}

/// Compact encrypted payload for serialization.
///
/// This format is more compact than `EncryptedData` and suitable
/// for embedding in other structures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Version byte for format compatibility.
    pub version: u8,
    /// Algorithm identifier (compact form).
    pub alg: u8,
    /// Nonce prepended to ciphertext: [nonce || ciphertext || tag].
    pub data: Vec<u8>,
}

impl EncryptedPayload {
    /// Current format version.
    pub const VERSION: u8 = 1;

    /// Algorithm identifier for AES-128-GCM.
    pub const ALG_AES_128_GCM: u8 = 1;
    /// Algorithm identifier for AES-256-GCM.
    pub const ALG_AES_256_GCM: u8 = 2;
    /// Algorithm identifier for AES-256-GCM-SIV.
    pub const ALG_AES_256_GCM_SIV: u8 = 3;
    /// Algorithm identifier for ChaCha20-Poly1305.
    pub const ALG_CHACHA20_POLY1305: u8 = 4;
    /// Algorithm identifier for XChaCha20-Poly1305.
    pub const ALG_XCHACHA20_POLY1305: u8 = 5;

    /// Create a new payload.
    pub fn new(alg: u8, nonce: &[u8], ciphertext: &[u8]) -> Self {
        let mut data = Vec::with_capacity(nonce.len() + ciphertext.len());
        data.extend_from_slice(nonce);
        data.extend_from_slice(ciphertext);

        Self {
            version: Self::VERSION,
            alg,
            data,
        }
    }

    /// Extract nonce and ciphertext based on algorithm.
    pub fn extract(&self, nonce_size: usize) -> Result<(&[u8], &[u8])> {
        if self.data.len() < nonce_size {
            return Err(Error::InvalidCiphertext);
        }

        let (nonce, ciphertext) = self.data.split_at(nonce_size);
        Ok((nonce, ciphertext))
    }

    /// Get algorithm name from identifier.
    pub fn algorithm_name(&self) -> &'static str {
        match self.alg {
            Self::ALG_AES_128_GCM => "AES-128-GCM",
            Self::ALG_AES_256_GCM => "AES-256-GCM",
            Self::ALG_AES_256_GCM_SIV => "AES-256-GCM-SIV",
            Self::ALG_CHACHA20_POLY1305 => "ChaCha20-Poly1305",
            Self::ALG_XCHACHA20_POLY1305 => "XChaCha20-Poly1305",
            _ => "Unknown",
        }
    }

    /// Encode to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.data.len());
        bytes.push(self.version);
        bytes.push(self.alg);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Decode from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(Error::InvalidCiphertext);
        }

        let version = bytes[0];
        if version != Self::VERSION {
            return Err(Error::UnsupportedFormat(format!(
                "unsupported payload version: {}",
                version
            )));
        }

        Ok(Self {
            version,
            alg: bytes[1],
            data: bytes[2..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_data() {
        let data = EncryptedData::new(vec![1, 2, 3, 4], vec![5, 6, 7], "AES-256-GCM");

        assert_eq!(data.ciphertext, vec![1, 2, 3, 4]);
        assert_eq!(data.nonce, vec![5, 6, 7]);
        assert_eq!(data.algorithm, "AES-256-GCM");
        assert!(data.associated_data.is_none());
    }

    #[test]
    fn test_encrypted_payload_roundtrip() {
        let nonce = vec![0u8; 12];
        let ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let payload = EncryptedPayload::new(EncryptedPayload::ALG_AES_256_GCM, &nonce, &ciphertext);

        let bytes = payload.to_bytes();
        let decoded = EncryptedPayload::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.version, payload.version);
        assert_eq!(decoded.alg, payload.alg);
        assert_eq!(decoded.data, payload.data);

        let (extracted_nonce, extracted_ct) = decoded.extract(12).unwrap();
        assert_eq!(extracted_nonce, &nonce[..]);
        assert_eq!(extracted_ct, &ciphertext[..]);
    }
}
