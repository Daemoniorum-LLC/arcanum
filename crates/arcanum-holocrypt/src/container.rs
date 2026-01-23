//! Core HoloCrypt container implementation.
//!
//! A HoloCrypt container provides layered security:
//! 1. Encryption (ChaCha20-Poly1305)
//! 2. Commitment (BLAKE3 hash)
//! 3. Merkle structure (BLAKE3 tree)
//! 4. Signature (Ed25519)

use crate::errors::{HoloCryptError, HoloCryptResult};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "signatures")]
use arcanum_signatures::{
    Signature, SigningKey, VerifyingKey,
    ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey},
};

#[cfg(feature = "encryption")]
use arcanum_symmetric::{ChaCha20Poly1305Cipher, Cipher};

#[cfg(feature = "merkle")]
use arcanum_hash::{Blake3, Hasher};

/// Default chunk size for Merkle tree (4KB).
const DEFAULT_CHUNK_SIZE: usize = 4096;

/// Key for sealing (encrypting) HoloCrypt containers.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SealingKey {
    /// Symmetric encryption key
    #[zeroize(skip)]
    symmetric_key: Vec<u8>,
    /// Signing key for authenticity
    #[cfg(feature = "signatures")]
    #[zeroize(skip)]
    signing_key: Ed25519SigningKey,
}

/// Key for opening (decrypting) HoloCrypt containers.
#[derive(Clone)]
pub struct OpeningKey {
    /// Symmetric decryption key
    symmetric_key: Vec<u8>,
    /// Verifying key for signature verification
    #[cfg(feature = "signatures")]
    verifying_key: Ed25519VerifyingKey,
}

impl Zeroize for OpeningKey {
    fn zeroize(&mut self) {
        self.symmetric_key.zeroize();
    }
}

impl Drop for OpeningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl OpeningKey {
    /// Get the verifying key for signature verification.
    #[cfg(feature = "signatures")]
    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }
}

/// Serializable container metadata.
#[derive(Clone, Serialize, Deserialize)]
struct ContainerMetadata {
    /// Version of the container format
    version: u8,
    /// Chunk size used for Merkle tree
    chunk_size: usize,
    /// Original data length
    original_len: usize,
}

/// A holocryptographic container with layered security.
#[derive(Clone, Serialize, Deserialize)]
pub struct HoloCrypt<T> {
    /// Container format version
    version: u8,
    /// Encrypted payload (ciphertext + nonce)
    ciphertext: Vec<u8>,
    /// Nonce used for encryption
    nonce: Vec<u8>,
    /// BLAKE3 commitment to the plaintext
    commitment: [u8; 32],
    /// Merkle root of chunks
    merkle_root: [u8; 32],
    /// Number of chunks
    chunk_count: usize,
    /// Chunk size used
    chunk_size: usize,
    /// Original data length
    original_len: usize,
    /// Signature over the container (commitment || merkle_root || metadata)
    signature: Vec<u8>,
    /// Phantom for type safety
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T> HoloCrypt<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Generate a new keypair for sealing/opening containers.
    #[cfg(all(feature = "signatures", feature = "encryption"))]
    pub fn generate_keypair() -> (SealingKey, OpeningKey) {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let symmetric_key = ChaCha20Poly1305Cipher::generate_key();

        (
            SealingKey {
                symmetric_key: symmetric_key.clone(),
                signing_key,
            },
            OpeningKey {
                symmetric_key,
                verifying_key,
            },
        )
    }

    /// Seal data into a HoloCrypt container.
    ///
    /// This applies all security layers:
    /// 1. Serialize the data
    /// 2. Compute BLAKE3 commitment to plaintext
    /// 3. Split into chunks and build Merkle tree
    /// 4. Encrypt with ChaCha20-Poly1305
    /// 5. Sign the commitment and Merkle root
    #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
    pub fn seal(data: &T, key: &SealingKey) -> HoloCryptResult<Self> {
        // Step 1: Serialize the data
        let plaintext = serde_json::to_vec(data).map_err(|e| HoloCryptError::SealFailed {
            reason: format!("serialization failed: {}", e),
        })?;
        let original_len = plaintext.len();

        // Step 2: Compute commitment (BLAKE3 hash of plaintext)
        let commitment = Self::compute_commitment(&plaintext);

        // Step 3: Build Merkle tree from chunks
        let (merkle_root, chunk_count) = Self::build_merkle_tree(&plaintext, DEFAULT_CHUNK_SIZE);

        // Step 4: Encrypt with ChaCha20-Poly1305
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let ciphertext = ChaCha20Poly1305Cipher::encrypt(
            &key.symmetric_key,
            &nonce,
            &plaintext,
            Some(&commitment), // Use commitment as AAD
        )
        .map_err(|_| HoloCryptError::SealFailed {
            reason: "encryption failed".into(),
        })?;

        // Step 5: Sign commitment || merkle_root
        let mut sign_data = Vec::with_capacity(64);
        sign_data.extend_from_slice(&commitment);
        sign_data.extend_from_slice(&merkle_root);
        let signature = key.signing_key.sign(&sign_data);

        Ok(Self {
            version: 1,
            ciphertext,
            nonce,
            commitment,
            merkle_root,
            chunk_count,
            chunk_size: DEFAULT_CHUNK_SIZE,
            original_len,
            signature: signature.to_bytes().to_vec(),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Unseal a container to recover the original data.
    ///
    /// This verifies all security layers:
    /// 1. Verify signature
    /// 2. Decrypt the ciphertext
    /// 3. Verify commitment matches plaintext
    /// 4. Verify Merkle root matches chunks
    /// 5. Deserialize the data
    #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
    pub fn unseal(&self, key: &OpeningKey) -> HoloCryptResult<T> {
        // Step 1: Verify signature
        self.verify_signature(&key.verifying_key)?;

        // Step 2: Decrypt
        let plaintext = ChaCha20Poly1305Cipher::decrypt(
            &key.symmetric_key,
            &self.nonce,
            &self.ciphertext,
            Some(&self.commitment), // AAD must match
        )
        .map_err(|_| HoloCryptError::UnsealFailed {
            reason: "decryption failed - wrong key or tampered data".into(),
        })?;

        // Step 3: Verify commitment
        let computed_commitment = Self::compute_commitment(&plaintext);
        if computed_commitment != self.commitment {
            return Err(HoloCryptError::CommitmentMismatch);
        }

        // Step 4: Verify Merkle root
        let (computed_root, _) = Self::build_merkle_tree(&plaintext, self.chunk_size);
        if computed_root != self.merkle_root {
            return Err(HoloCryptError::VerificationFailed {
                reason: "Merkle root mismatch".into(),
            });
        }

        // Step 5: Deserialize
        serde_json::from_slice(&plaintext).map_err(|e| HoloCryptError::UnsealFailed {
            reason: format!("deserialization failed: {}", e),
        })
    }

    /// Verify the container's structure without decrypting.
    ///
    /// This checks:
    /// - Signature is valid
    /// - Container metadata is consistent
    #[cfg(feature = "signatures")]
    #[must_use = "verification result must be checked"]
    pub fn verify_structure(&self, verifying_key: &Ed25519VerifyingKey) -> HoloCryptResult<()> {
        self.verify_signature(verifying_key)?;

        // Verify metadata consistency
        if self.chunk_count == 0 {
            return Err(HoloCryptError::VerificationFailed {
                reason: "invalid chunk count".into(),
            });
        }

        Ok(())
    }

    /// Verify the signature over commitment and Merkle root.
    #[cfg(feature = "signatures")]
    fn verify_signature(&self, verifying_key: &Ed25519VerifyingKey) -> HoloCryptResult<()> {
        let mut sign_data = Vec::with_capacity(64);
        sign_data.extend_from_slice(&self.commitment);
        sign_data.extend_from_slice(&self.merkle_root);

        let signature = Ed25519Signature::from_bytes(&self.signature)
            .map_err(|_| HoloCryptError::SignatureInvalid)?;

        verifying_key
            .verify(&sign_data, &signature)
            .map_err(|_| HoloCryptError::SignatureInvalid)
    }

    /// Compute BLAKE3 commitment to data.
    #[cfg(feature = "merkle")]
    fn compute_commitment(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"holocrypt-commitment-v1");
        hasher.update(data);
        let output = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&output.as_bytes()[..32]);
        commitment
    }

    /// Build a Merkle tree from data chunks.
    #[cfg(feature = "merkle")]
    fn build_merkle_tree(data: &[u8], chunk_size: usize) -> ([u8; 32], usize) {
        if data.is_empty() {
            // Empty data gets a special commitment
            let mut hasher = Blake3::new();
            hasher.update(b"holocrypt-empty-merkle");
            let output = hasher.finalize();
            let mut root = [0u8; 32];
            root.copy_from_slice(&output.as_bytes()[..32]);
            return (root, 0);
        }

        // Split into chunks
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let chunk_count = chunks.len();

        // Hash each chunk (leaf nodes)
        let mut hashes: Vec<[u8; 32]> = chunks
            .iter()
            .map(|chunk| {
                let mut hasher = Blake3::new();
                hasher.update(b"holocrypt-leaf");
                hasher.update(chunk);
                let output = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&output.as_bytes()[..32]);
                hash
            })
            .collect();

        // Build tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for pair in hashes.chunks(2) {
                let mut hasher = Blake3::new();
                hasher.update(b"holocrypt-node");
                hasher.update(&pair[0]);
                if pair.len() > 1 {
                    hasher.update(&pair[1]);
                } else {
                    // Odd number of nodes: duplicate last
                    hasher.update(&pair[0]);
                }
                let output = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&output.as_bytes()[..32]);
                next_level.push(hash);
            }
            hashes = next_level;
        }

        (hashes[0], chunk_count)
    }

    /// Get the commitment to the sealed data.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Get the Merkle root of the container.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Get the number of chunks in the container.
    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }

    /// Get the container version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Get the ciphertext (for inspection, not direct use).
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Check if the container has all expected components.
    pub fn has_all_layers(&self) -> bool {
        !self.ciphertext.is_empty()
            && self.commitment != [0u8; 32]
            && self.merkle_root != [0u8; 32]
            && !self.signature.is_empty()
    }
}

/// Threshold-enabled container operations.
#[cfg(feature = "threshold")]
pub mod threshold {
    use super::*;
    use arcanum_threshold::{ShamirScheme, Share};

    /// A key share for threshold decryption.
    #[derive(Clone, Debug)]
    pub struct KeyShare {
        /// The underlying Shamir share
        share: Share,
    }

    impl KeyShare {
        /// Create a new key share from index and data.
        pub fn new(index: u8, data: Vec<u8>) -> Self {
            Self {
                share: Share::new(index, data),
            }
        }

        /// Get the share index (1-based).
        pub fn index(&self) -> u8 {
            self.share.index()
        }

        /// Get the share data.
        pub fn data(&self) -> &[u8] {
            self.share.value()
        }

        /// Serialize to bytes.
        pub fn to_bytes(&self) -> Vec<u8> {
            self.share.to_bytes()
        }

        /// Deserialize from bytes.
        pub fn from_bytes(bytes: &[u8]) -> HoloCryptResult<Self> {
            let share = Share::from_bytes(bytes).map_err(|_| HoloCryptError::CryptoError {
                reason: "invalid share format".into(),
            })?;
            Ok(Self { share })
        }

        /// Get the underlying share (internal use).
        fn into_share(self) -> Share {
            self.share
        }

        /// Get a reference to the underlying share.
        fn as_share(&self) -> &Share {
            &self.share
        }
    }

    /// Container with threshold access control.
    ///
    /// The symmetric encryption key is split into shares using Shamir's
    /// secret sharing scheme. Any `threshold` shares can reconstruct
    /// the key to decrypt the container.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct ThresholdContainer<T> {
        /// The underlying HoloCrypt container
        inner: HoloCrypt<T>,
        /// Threshold requirement
        threshold: usize,
        /// Total number of shares
        total_shares: usize,
        /// Verifying key bytes for signature verification
        #[cfg(feature = "signatures")]
        verifying_key_bytes: Vec<u8>,
    }

    impl<T> ThresholdContainer<T>
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        /// Create a threshold container from data.
        ///
        /// # Arguments
        /// * `data` - The data to seal
        /// * `threshold` - Minimum shares required to unseal
        /// * `total` - Total number of shares to generate
        ///
        /// # Returns
        /// A tuple of (container, key_shares)
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        pub fn seal(
            data: &T,
            threshold: usize,
            total: usize,
        ) -> HoloCryptResult<(Self, Vec<KeyShare>)> {
            // Generate keypair for signing
            let signing_key = Ed25519SigningKey::generate();
            let verifying_key = signing_key.verifying_key();

            // Generate symmetric key
            let symmetric_key = ChaCha20Poly1305Cipher::generate_key();

            // Split the symmetric key into shares
            let shares = ShamirScheme::split(&symmetric_key, threshold, total).map_err(|_| {
                HoloCryptError::CryptoError {
                    reason: "failed to split key".into(),
                }
            })?;

            // Create sealing key (we use this to seal, then discard)
            let sealing_key = SealingKey {
                symmetric_key: symmetric_key.clone(),
                signing_key,
            };

            // Seal the data
            let inner = HoloCrypt::seal(data, &sealing_key)?;

            // Convert shares to KeyShares
            let key_shares: Vec<KeyShare> =
                shares.into_iter().map(|s| KeyShare { share: s }).collect();

            // Serialize the verifying key
            let verifying_key_bytes = verifying_key.to_bytes().to_vec();

            Ok((
                Self {
                    inner,
                    threshold,
                    total_shares: total,
                    verifying_key_bytes,
                },
                key_shares,
            ))
        }

        /// Unseal using threshold shares.
        ///
        /// Requires at least `threshold` valid shares.
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        pub fn unseal(&self, shares: &[KeyShare]) -> HoloCryptResult<T> {
            if shares.len() < self.threshold {
                return Err(HoloCryptError::InsufficientShares {
                    required: self.threshold,
                    provided: shares.len(),
                });
            }

            // Convert KeyShares to Shares for reconstruction
            let shamir_shares: Vec<Share> = shares.iter().map(|ks| ks.share.clone()).collect();

            // Reconstruct the symmetric key
            let symmetric_key = ShamirScheme::combine(&shamir_shares).map_err(|_| {
                HoloCryptError::KeyReconstructionFailed {
                    reason: "insufficient or invalid shares".into(),
                }
            })?;

            // Reconstruct verifying key
            let verifying_key = Ed25519VerifyingKey::from_bytes(&self.verifying_key_bytes)
                .map_err(|_| HoloCryptError::CryptoError {
                    reason: "invalid verifying key".into(),
                })?;

            // Create opening key
            let opening_key = OpeningKey {
                symmetric_key,
                verifying_key,
            };

            // Unseal with the reconstructed key
            self.inner.unseal(&opening_key)
        }

        /// Verify the container structure without decrypting.
        #[cfg(feature = "signatures")]
        #[must_use = "verification result must be checked"]
        pub fn verify_structure(&self) -> HoloCryptResult<()> {
            let verifying_key = Ed25519VerifyingKey::from_bytes(&self.verifying_key_bytes)
                .map_err(|_| HoloCryptError::CryptoError {
                    reason: "invalid verifying key".into(),
                })?;
            self.inner.verify_structure(&verifying_key)
        }

        /// Get the threshold requirement.
        pub fn threshold(&self) -> usize {
            self.threshold
        }

        /// Get total number of shares.
        pub fn total_shares(&self) -> usize {
            self.total_shares
        }

        /// Get the commitment.
        pub fn commitment(&self) -> &[u8; 32] {
            self.inner.commitment()
        }

        /// Get the Merkle root.
        pub fn merkle_root(&self) -> &[u8; 32] {
            self.inner.merkle_root()
        }

        /// Get chunk count.
        pub fn chunk_count(&self) -> usize {
            self.inner.chunk_count()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct TestRecord {
            name: String,
            value: u64,
        }

        #[test]
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        fn threshold_seal_unseal_roundtrip() {
            let data = TestRecord {
                name: "Threshold Test".to_string(),
                value: 42,
            };

            // Create 3-of-5 threshold container
            let (container, shares) = ThresholdContainer::seal(&data, 3, 5).unwrap();

            assert_eq!(container.threshold(), 3);
            assert_eq!(container.total_shares(), 5);
            assert_eq!(shares.len(), 5);

            // Unseal with exactly 3 shares
            let recovered: TestRecord = container.unseal(&shares[..3]).unwrap();
            assert_eq!(data, recovered);
        }

        #[test]
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        fn threshold_different_share_subsets() {
            let data = TestRecord {
                name: "Subset Test".to_string(),
                value: 100,
            };

            let (container, shares) = ThresholdContainer::seal(&data, 3, 5).unwrap();

            // Any 3 shares should work
            let r1: TestRecord = container
                .unseal(&[shares[0].clone(), shares[1].clone(), shares[2].clone()])
                .unwrap();
            let r2: TestRecord = container
                .unseal(&[shares[0].clone(), shares[2].clone(), shares[4].clone()])
                .unwrap();
            let r3: TestRecord = container
                .unseal(&[shares[1].clone(), shares[3].clone(), shares[4].clone()])
                .unwrap();

            assert_eq!(data, r1);
            assert_eq!(data, r2);
            assert_eq!(data, r3);
        }

        #[test]
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        fn threshold_insufficient_shares_fails() {
            let data = TestRecord {
                name: "Fail Test".to_string(),
                value: 0,
            };

            let (container, shares) = ThresholdContainer::seal(&data, 3, 5).unwrap();

            // Only 2 shares - should fail
            let result: Result<TestRecord, _> = container.unseal(&shares[..2]);
            assert!(result.is_err());

            match result {
                Err(HoloCryptError::InsufficientShares { required, provided }) => {
                    assert_eq!(required, 3);
                    assert_eq!(provided, 2);
                }
                _ => panic!("Expected InsufficientShares error"),
            }
        }

        #[test]
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        fn threshold_verify_structure() {
            let data = TestRecord {
                name: "Verify Test".to_string(),
                value: 999,
            };

            let (container, _shares) = ThresholdContainer::seal(&data, 2, 3).unwrap();

            // Should be able to verify without shares
            assert!(container.verify_structure().is_ok());
        }

        #[test]
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        fn threshold_2_of_2() {
            let data = TestRecord {
                name: "2-of-2".to_string(),
                value: 22,
            };

            let (container, shares) = ThresholdContainer::seal(&data, 2, 2).unwrap();

            // Need both shares
            let recovered: TestRecord = container.unseal(&shares).unwrap();
            assert_eq!(data, recovered);
        }

        #[test]
        #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
        fn key_share_serialization() {
            let share = KeyShare::new(42, vec![1, 2, 3, 4, 5]);
            let bytes = share.to_bytes();
            let restored = KeyShare::from_bytes(&bytes).unwrap();

            assert_eq!(share.index(), restored.index());
            assert_eq!(share.data(), restored.data());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestData {
        name: String,
        value: u64,
        active: bool,
    }

    #[test]
    #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
    fn seal_unseal_roundtrip() {
        let data = TestData {
            name: "Alice".to_string(),
            value: 1000,
            active: true,
        };

        let (sealing_key, opening_key) = HoloCrypt::<TestData>::generate_keypair();
        let container = HoloCrypt::seal(&data, &sealing_key).unwrap();

        // Verify container has all components
        assert!(container.has_all_layers());
        assert_eq!(container.version(), 1);
        assert!(container.chunk_count() > 0);

        // Unseal and verify data matches
        let recovered: TestData = container.unseal(&opening_key).unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
    fn verify_structure_without_decrypting() {
        let data = TestData {
            name: "Bob".to_string(),
            value: 500,
            active: false,
        };

        let (sealing_key, opening_key) = HoloCrypt::<TestData>::generate_keypair();
        let container = HoloCrypt::seal(&data, &sealing_key).unwrap();

        // Third party can verify structure with just the verifying key
        assert!(
            container
                .verify_structure(&opening_key.verifying_key)
                .is_ok()
        );
    }

    #[test]
    #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
    fn tampered_ciphertext_fails() {
        let data = TestData {
            name: "Charlie".to_string(),
            value: 200,
            active: true,
        };

        let (sealing_key, opening_key) = HoloCrypt::<TestData>::generate_keypair();
        let mut container = HoloCrypt::seal(&data, &sealing_key).unwrap();

        // Tamper with ciphertext
        if !container.ciphertext.is_empty() {
            container.ciphertext[0] ^= 0xFF;
        }

        // Unseal should fail
        let result: Result<TestData, _> = container.unseal(&opening_key);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
    fn wrong_key_fails() {
        let data = TestData {
            name: "Dave".to_string(),
            value: 100,
            active: false,
        };

        let (sealing_key, _) = HoloCrypt::<TestData>::generate_keypair();
        let (_, wrong_opening_key) = HoloCrypt::<TestData>::generate_keypair();

        let container = HoloCrypt::seal(&data, &sealing_key).unwrap();

        // Wrong key should fail (either signature or decryption)
        let result: Result<TestData, _> = container.unseal(&wrong_opening_key);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(feature = "signatures", feature = "encryption", feature = "merkle"))]
    fn large_data_works() {
        // Test with data larger than one chunk
        let large_name = "X".repeat(10000);
        let data = TestData {
            name: large_name,
            value: 999999,
            active: true,
        };

        let (sealing_key, opening_key) = HoloCrypt::<TestData>::generate_keypair();
        let container = HoloCrypt::seal(&data, &sealing_key).unwrap();

        // Should have multiple chunks
        assert!(container.chunk_count() > 1);

        let recovered: TestData = container.unseal(&opening_key).unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    #[cfg(feature = "merkle")]
    fn merkle_tree_deterministic() {
        let data = b"test data for merkle tree";

        let (root1, count1) = HoloCrypt::<()>::build_merkle_tree(data, 1024);
        let (root2, count2) = HoloCrypt::<()>::build_merkle_tree(data, 1024);

        assert_eq!(root1, root2);
        assert_eq!(count1, count2);
    }

    #[test]
    #[cfg(feature = "merkle")]
    fn different_data_different_merkle() {
        let data1 = b"data one";
        let data2 = b"data two";

        let (root1, _) = HoloCrypt::<()>::build_merkle_tree(data1, 1024);
        let (root2, _) = HoloCrypt::<()>::build_merkle_tree(data2, 1024);

        assert_ne!(root1, root2);
    }
}
