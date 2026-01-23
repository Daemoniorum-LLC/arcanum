//! Post-quantum envelope wrapping for HoloCrypt containers.
//!
//! Wraps HoloCrypt symmetric keys with ML-KEM for quantum-resistant key exchange.
//!
//! ## Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                    PQC ENVELOPE                               │
//! │                                                               │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │ ML-KEM-768 Ciphertext (encapsulated shared secret)      │ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! │                          │                                    │
//! │                          ▼                                    │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │ KDF: SHA-256(shared_secret, info="holocrypt-pqc")       │ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! │                          │                                    │
//! │                          ▼                                    │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │ Wrapped Key: ChaCha20-Poly1305(derived_key, content_key)│ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! └───────────────────────────────────────────────────────────────┘
//! ```

use crate::errors::{HoloCryptError, HoloCryptResult};
use serde::{Deserialize, Serialize};

#[cfg(feature = "pqc")]
use arcanum_pqc::{KeyEncapsulation, MlKem768};

#[cfg(all(feature = "pqc", feature = "encryption"))]
use arcanum_symmetric::{ChaCha20Poly1305Cipher, Cipher};

#[cfg(all(feature = "pqc", feature = "merkle"))]
use arcanum_hash::{Blake3, Hasher, Sha256};

// Re-export key types
#[cfg(feature = "pqc")]
pub use arcanum_pqc::kem::{
    MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey,
};

// ═══════════════════════════════════════════════════════════════════════════════
// PQC Key Pair
// ═══════════════════════════════════════════════════════════════════════════════

/// Post-quantum key pair for HoloCrypt envelope encryption.
#[cfg(feature = "pqc")]
#[derive(Clone)]
pub struct PqcKeyPair {
    /// Decapsulation key (private)
    decapsulation_key: MlKem768DecapsulationKey,
    /// Encapsulation key (public)
    encapsulation_key: MlKem768EncapsulationKey,
}

#[cfg(feature = "pqc")]
impl PqcKeyPair {
    /// Generate a new ML-KEM-768 key pair.
    pub fn generate() -> Self {
        let (dk, ek) = MlKem768::generate_keypair();
        Self {
            decapsulation_key: dk,
            encapsulation_key: ek,
        }
    }

    /// Get the public encapsulation key.
    pub fn encapsulation_key(&self) -> &MlKem768EncapsulationKey {
        &self.encapsulation_key
    }

    /// Get the private decapsulation key.
    pub fn decapsulation_key(&self) -> &MlKem768DecapsulationKey {
        &self.decapsulation_key
    }

    /// Export the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.encapsulation_key.to_bytes()
    }

    /// Export the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.decapsulation_key.to_bytes()
    }

    /// Create from existing keys.
    pub fn from_keys(
        decapsulation_key: MlKem768DecapsulationKey,
        encapsulation_key: MlKem768EncapsulationKey,
    ) -> Self {
        Self {
            decapsulation_key,
            encapsulation_key,
        }
    }
}

#[cfg(feature = "pqc")]
impl std::fmt::Debug for PqcKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqcKeyPair {{ ... }}")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQC Envelope
// ═══════════════════════════════════════════════════════════════════════════════

/// A post-quantum envelope containing a wrapped key.
#[cfg(feature = "pqc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcEnvelope {
    /// ML-KEM ciphertext (encapsulated shared secret)
    kem_ciphertext: Vec<u8>,
    /// Wrapped content key (encrypted with derived key)
    wrapped_key: Vec<u8>,
    /// Nonce used for key wrapping
    nonce: Vec<u8>,
    /// Algorithm identifier
    algorithm: String,
}

#[cfg(feature = "pqc")]
impl PqcEnvelope {
    /// Wrap a symmetric key for a recipient's public key.
    #[cfg(all(feature = "encryption", feature = "merkle"))]
    pub fn wrap(
        content_key: &[u8; 32],
        recipient_key: &MlKem768EncapsulationKey,
    ) -> HoloCryptResult<Self> {
        // Encapsulate to get shared secret
        let (ct, ss) = MlKem768::encapsulate(recipient_key);

        // Derive wrapping key using SHA-256 based KDF
        let wrapping_key = Self::derive_wrapping_key(ss.as_bytes());

        // Generate nonce for key wrapping
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();

        // Wrap the content key with ChaCha20-Poly1305
        let wrapped = ChaCha20Poly1305Cipher::encrypt(
            &wrapping_key,
            &nonce,
            content_key,
            Some(b"holocrypt-pqc-wrap"),
        )
        .map_err(|_| HoloCryptError::CryptoError {
            reason: "key wrapping failed".into(),
        })?;

        Ok(Self {
            kem_ciphertext: ct.to_bytes(),
            wrapped_key: wrapped,
            nonce,
            algorithm: "ML-KEM-768".to_string(),
        })
    }

    /// Unwrap a symmetric key using the recipient's private key.
    #[cfg(all(feature = "encryption", feature = "merkle"))]
    pub fn unwrap(&self, recipient_key: &MlKem768DecapsulationKey) -> HoloCryptResult<[u8; 32]> {
        // Reconstruct ciphertext
        let ct = MlKem768Ciphertext::from_bytes(&self.kem_ciphertext).map_err(|_| {
            HoloCryptError::CryptoError {
                reason: "invalid KEM ciphertext".into(),
            }
        })?;

        // Decapsulate to get shared secret
        let ss =
            MlKem768::decapsulate(recipient_key, &ct).map_err(|_| HoloCryptError::CryptoError {
                reason: "decapsulation failed".into(),
            })?;

        // Derive wrapping key
        let wrapping_key = Self::derive_wrapping_key(ss.as_bytes());

        // Unwrap the content key
        let content_key = ChaCha20Poly1305Cipher::decrypt(
            &wrapping_key,
            &self.nonce,
            &self.wrapped_key,
            Some(b"holocrypt-pqc-wrap"),
        )
        .map_err(|_| HoloCryptError::CryptoError {
            reason: "key unwrapping failed".into(),
        })?;

        if content_key.len() != 32 {
            return Err(HoloCryptError::CryptoError {
                reason: "invalid unwrapped key length".into(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&content_key);
        Ok(key)
    }

    /// Derive wrapping key from shared secret using SHA-256 based KDF.
    #[cfg(feature = "merkle")]
    fn derive_wrapping_key(shared_secret: &[u8; 32]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"holocrypt-pqc-kdf-v1");
        hasher.update(shared_secret);
        hasher.update(b"wrapping-key");

        let output = hasher.finalize();
        output.as_bytes()[..32].to_vec()
    }

    /// Get the algorithm identifier.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> HoloCryptResult<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            HoloCryptError::SerializationError(format!("envelope deserialization failed: {}", e))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQC Container (combines HoloCrypt with PQC envelope)
// ═══════════════════════════════════════════════════════════════════════════════

/// A HoloCrypt container with PQC-wrapped keys.
#[cfg(feature = "pqc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcContainer<T> {
    /// The sealed data (encrypted with content key)
    sealed_data: Vec<u8>,
    /// Nonce used for data encryption
    data_nonce: Vec<u8>,
    /// PQC envelope containing the wrapped content key
    envelope: PqcEnvelope,
    /// Commitment to the plaintext
    commitment: [u8; 32],
    /// Merkle root of chunks
    merkle_root: [u8; 32],
    /// Signature over the container
    signature: Vec<u8>,
    /// Verifying key bytes for verification
    #[cfg(feature = "signatures")]
    verifying_key_bytes: Vec<u8>,
    /// Phantom type for the contained data
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

#[cfg(feature = "pqc")]
impl<T: Serialize + for<'de> Deserialize<'de>> PqcContainer<T> {
    /// Seal data with PQC envelope encryption.
    #[cfg(all(feature = "encryption", feature = "merkle", feature = "signatures"))]
    pub fn seal(data: &T, recipient_key: &MlKem768EncapsulationKey) -> HoloCryptResult<Self> {
        use arcanum_signatures::{Signature, SigningKey, VerifyingKey, ed25519::Ed25519SigningKey};

        // Generate signing keypair
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        // Serialize the data
        let plaintext = serde_json::to_vec(data).map_err(|e| {
            HoloCryptError::SerializationError(format!("serialization failed: {}", e))
        })?;

        // Generate content key
        let content_key_vec = ChaCha20Poly1305Cipher::generate_key();
        let mut content_key = [0u8; 32];
        content_key.copy_from_slice(&content_key_vec);

        // Compute commitment
        let commitment = Self::compute_commitment(&plaintext);

        // Build Merkle tree for selective disclosure
        let merkle_root = Self::compute_merkle_root(&plaintext);

        // Encrypt data with content key
        let data_nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let sealed_data = ChaCha20Poly1305Cipher::encrypt(
            &content_key_vec,
            &data_nonce,
            &plaintext,
            Some(&commitment),
        )
        .map_err(|_| HoloCryptError::CryptoError {
            reason: "encryption failed".into(),
        })?;

        // Wrap content key with PQC envelope
        let envelope = PqcEnvelope::wrap(&content_key, recipient_key)?;

        // Sign the container
        let sign_data = Self::compute_sign_data(&sealed_data, &commitment, &merkle_root);
        let signature = signing_key.sign(&sign_data);

        Ok(Self {
            sealed_data,
            data_nonce,
            envelope,
            commitment,
            merkle_root,
            signature: signature.to_bytes().to_vec(),
            verifying_key_bytes: verifying_key.to_bytes().to_vec(),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Unseal data using PQC decapsulation key.
    #[cfg(all(feature = "encryption", feature = "merkle", feature = "signatures"))]
    pub fn unseal(&self, recipient_key: &MlKem768DecapsulationKey) -> HoloCryptResult<T> {
        use arcanum_signatures::{
            Signature, VerifyingKey,
            ed25519::{Ed25519Signature, Ed25519VerifyingKey},
        };

        // Verify signature
        let sign_data =
            Self::compute_sign_data(&self.sealed_data, &self.commitment, &self.merkle_root);
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&self.verifying_key_bytes).map_err(|_| {
                HoloCryptError::CryptoError {
                    reason: "invalid verifying key".into(),
                }
            })?;
        let sig = Ed25519Signature::from_bytes(&self.signature)
            .map_err(|_| HoloCryptError::SignatureInvalid)?;
        verifying_key
            .verify(&sign_data, &sig)
            .map_err(|_| HoloCryptError::SignatureInvalid)?;

        // Unwrap content key from PQC envelope
        let content_key = self.envelope.unwrap(recipient_key)?;

        // Decrypt data
        let plaintext = ChaCha20Poly1305Cipher::decrypt(
            &content_key,
            &self.data_nonce,
            &self.sealed_data,
            Some(&self.commitment),
        )
        .map_err(|_| HoloCryptError::UnsealFailed {
            reason: "decryption failed - wrong key or tampered data".into(),
        })?;

        // Verify commitment
        let computed_commitment = Self::compute_commitment(&plaintext);
        if computed_commitment != self.commitment {
            return Err(HoloCryptError::CommitmentMismatch);
        }

        // Verify Merkle root
        let computed_merkle = Self::compute_merkle_root(&plaintext);
        if computed_merkle != self.merkle_root {
            return Err(HoloCryptError::VerificationFailed {
                reason: "Merkle root mismatch".into(),
            });
        }

        // Deserialize
        serde_json::from_slice(&plaintext).map_err(|e| {
            HoloCryptError::SerializationError(format!("deserialization failed: {}", e))
        })
    }

    /// Verify container structure without decrypting.
    #[cfg(feature = "signatures")]
    #[must_use = "verification result must be checked"]
    pub fn verify_structure(&self) -> HoloCryptResult<()> {
        use arcanum_signatures::{
            Signature, VerifyingKey,
            ed25519::{Ed25519Signature, Ed25519VerifyingKey},
        };

        let sign_data =
            Self::compute_sign_data(&self.sealed_data, &self.commitment, &self.merkle_root);
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&self.verifying_key_bytes).map_err(|_| {
                HoloCryptError::CryptoError {
                    reason: "invalid verifying key".into(),
                }
            })?;
        let sig = Ed25519Signature::from_bytes(&self.signature)
            .map_err(|_| HoloCryptError::SignatureInvalid)?;
        verifying_key
            .verify(&sign_data, &sig)
            .map_err(|_| HoloCryptError::SignatureInvalid)?;

        Ok(())
    }

    /// Get the commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Get the Merkle root.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Get the PQC envelope.
    pub fn envelope(&self) -> &PqcEnvelope {
        &self.envelope
    }

    #[cfg(feature = "merkle")]
    fn compute_commitment(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"holocrypt-pqc-commitment");
        hasher.update(data);
        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    #[cfg(feature = "merkle")]
    fn compute_merkle_root(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"holocrypt-pqc-merkle");
        hasher.update(data);
        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    fn compute_sign_data(sealed: &[u8], commitment: &[u8; 32], merkle_root: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"holocrypt-pqc-sign-v1");
        data.extend_from_slice(commitment);
        data.extend_from_slice(merkle_root);
        data.extend_from_slice(&(sealed.len() as u64).to_le_bytes());
        data
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> HoloCryptResult<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            HoloCryptError::SerializationError(format!("deserialization failed: {}", e))
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wrapped Key (for use with existing HoloCrypt containers)
// ═══════════════════════════════════════════════════════════════════════════════

/// A wrapped symmetric key using PQC.
#[cfg(feature = "pqc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// The envelope containing the wrapped key
    envelope: PqcEnvelope,
}

#[cfg(feature = "pqc")]
impl WrappedKey {
    /// Wrap a key for a recipient.
    #[cfg(all(feature = "encryption", feature = "merkle"))]
    pub fn wrap(key: &[u8; 32], recipient: &MlKem768EncapsulationKey) -> HoloCryptResult<Self> {
        let envelope = PqcEnvelope::wrap(key, recipient)?;
        Ok(Self { envelope })
    }

    /// Unwrap the key using the recipient's private key.
    #[cfg(all(feature = "encryption", feature = "merkle"))]
    pub fn unwrap(&self, private_key: &MlKem768DecapsulationKey) -> HoloCryptResult<[u8; 32]> {
        self.envelope.unwrap(private_key)
    }

    /// Get the envelope.
    pub fn envelope(&self) -> &PqcEnvelope {
        &self.envelope
    }
}

#[cfg(test)]
#[cfg(all(
    feature = "pqc",
    feature = "encryption",
    feature = "merkle",
    feature = "signatures"
))]
mod tests {
    use super::*;

    #[test]
    fn pqc_keypair_generation() {
        let keypair = PqcKeyPair::generate();
        assert_eq!(keypair.public_key_bytes().len(), 1184);
        assert_eq!(keypair.private_key_bytes().len(), 2400);
    }

    #[test]
    fn pqc_envelope_wrap_unwrap() {
        let keypair = PqcKeyPair::generate();
        let content_key = [42u8; 32];

        let envelope = PqcEnvelope::wrap(&content_key, keypair.encapsulation_key()).unwrap();
        let unwrapped = envelope.unwrap(keypair.decapsulation_key()).unwrap();

        assert_eq!(content_key, unwrapped);
    }

    #[test]
    fn pqc_envelope_wrong_key_fails() {
        let keypair1 = PqcKeyPair::generate();
        let keypair2 = PqcKeyPair::generate();
        let content_key = [42u8; 32];

        let envelope = PqcEnvelope::wrap(&content_key, keypair1.encapsulation_key()).unwrap();

        // Wrong key should fail (ML-KEM implicit reject + AEAD auth failure)
        let result = envelope.unwrap(keypair2.decapsulation_key());
        assert!(result.is_err());
    }

    #[test]
    fn pqc_envelope_serialization() {
        let keypair = PqcKeyPair::generate();
        let content_key = [42u8; 32];

        let envelope = PqcEnvelope::wrap(&content_key, keypair.encapsulation_key()).unwrap();
        let bytes = envelope.to_bytes();
        let restored = PqcEnvelope::from_bytes(&bytes).unwrap();

        let unwrapped = restored.unwrap(keypair.decapsulation_key()).unwrap();
        assert_eq!(content_key, unwrapped);
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u64,
        name: String,
        values: Vec<i32>,
    }

    #[test]
    fn pqc_container_seal_unseal() {
        let pqc_keypair = PqcKeyPair::generate();

        let data = TestData {
            id: 42,
            name: "quantum-safe".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let container = PqcContainer::seal(&data, pqc_keypair.encapsulation_key()).unwrap();

        let decrypted: TestData = container.unseal(pqc_keypair.decapsulation_key()).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn pqc_container_verify_structure() {
        let pqc_keypair = PqcKeyPair::generate();

        let data = TestData {
            id: 1,
            name: "test".to_string(),
            values: vec![],
        };

        let container = PqcContainer::seal(&data, pqc_keypair.encapsulation_key()).unwrap();

        // Should verify without decryption
        assert!(container.verify_structure().is_ok());
    }

    #[test]
    fn pqc_container_wrong_pqc_key_fails() {
        let pqc_keypair1 = PqcKeyPair::generate();
        let pqc_keypair2 = PqcKeyPair::generate();

        let data = TestData {
            id: 99,
            name: "secret".to_string(),
            values: vec![1, 2, 3],
        };

        let container = PqcContainer::seal(&data, pqc_keypair1.encapsulation_key()).unwrap();

        // Wrong PQC key should fail
        let result: Result<TestData, _> = container.unseal(pqc_keypair2.decapsulation_key());
        assert!(result.is_err());
    }

    #[test]
    fn wrapped_key_roundtrip() {
        let keypair = PqcKeyPair::generate();
        let key = [0xAB; 32];

        let wrapped = WrappedKey::wrap(&key, keypair.encapsulation_key()).unwrap();
        let unwrapped = wrapped.unwrap(keypair.decapsulation_key()).unwrap();

        assert_eq!(key, unwrapped);
    }

    #[test]
    fn pqc_container_serialization() {
        let pqc_keypair = PqcKeyPair::generate();

        let data = TestData {
            id: 123,
            name: "serialized".to_string(),
            values: vec![10, 20, 30],
        };

        let container = PqcContainer::seal(&data, pqc_keypair.encapsulation_key()).unwrap();

        let bytes = container.to_bytes();
        let restored: PqcContainer<TestData> = PqcContainer::from_bytes(&bytes).unwrap();

        let decrypted: TestData = restored.unseal(pqc_keypair.decapsulation_key()).unwrap();

        assert_eq!(data, decrypted);
    }
}
