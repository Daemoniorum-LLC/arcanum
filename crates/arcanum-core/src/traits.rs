//! Core cryptographic traits.
//!
//! These traits define the interfaces for all cryptographic operations in Arcanum.
//! They are designed to be algorithm-agnostic, allowing code to work with any
//! implementation that satisfies the trait bounds.

#[cfg(all(not(feature = "std"), feature = "async"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use crate::error::Result;
#[cfg(feature = "async")]
use async_trait::async_trait;

// ═══════════════════════════════════════════════════════════════════════════════
// SYMMETRIC ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for symmetric encryption algorithms.
pub trait SymmetricEncrypt {
    /// The size of the key in bytes.
    const KEY_SIZE: usize;
    /// The size of the nonce/IV in bytes.
    const NONCE_SIZE: usize;
    /// The size of the authentication tag in bytes (for AEAD).
    const TAG_SIZE: usize;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Encrypt plaintext with the given key and nonce.
    ///
    /// Returns the ciphertext with authentication tag appended.
    #[must_use = "encryption can fail; check the Result"]
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with the given key and nonce.
    ///
    /// Returns the plaintext if authentication succeeds.
    #[must_use = "decryption can fail; check the Result"]
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}

/// Trait for streaming symmetric encryption.
pub trait StreamCipher {
    /// Apply keystream to data (encrypt or decrypt).
    fn apply_keystream(&mut self, data: &mut [u8]);

    /// Seek to a position in the keystream.
    fn seek(&mut self, position: u64);

    /// Get current position in the keystream.
    fn position(&self) -> u64;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ASYMMETRIC ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for asymmetric encryption algorithms.
pub trait AsymmetricEncrypt {
    /// Public key type.
    type PublicKey;
    /// Private key type.
    type PrivateKey;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Encrypt data with a public key.
    #[must_use = "encryption can fail; check the Result"]
    fn encrypt(public_key: &Self::PublicKey, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt data with a private key.
    #[must_use = "decryption can fail; check the Result"]
    fn decrypt(private_key: &Self::PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY EXCHANGE
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for key exchange algorithms.
pub trait KeyExchange {
    /// Public key type.
    type PublicKey;
    /// Private key type.
    type PrivateKey;
    /// Shared secret type.
    type SharedSecret;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Generate a new key pair.
    #[must_use = "key generation can fail; check the Result"]
    fn generate_keypair() -> Result<(Self::PrivateKey, Self::PublicKey)>;

    /// Compute shared secret from private key and peer's public key.
    #[must_use = "shared secret computation can fail; check the Result"]
    fn compute_shared_secret(
        private_key: &Self::PrivateKey,
        peer_public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret>;
}

/// Trait for key encapsulation mechanisms (KEMs).
pub trait KeyEncapsulation {
    /// Public key type.
    type PublicKey;
    /// Private key type.
    type PrivateKey;
    /// Ciphertext type (encapsulated key).
    type Ciphertext;
    /// Shared secret type.
    type SharedSecret;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Generate a new key pair.
    #[must_use = "key generation can fail; check the Result"]
    fn generate_keypair() -> Result<(Self::PrivateKey, Self::PublicKey)>;

    /// Encapsulate: generate shared secret and ciphertext.
    #[must_use = "encapsulation can fail; check the Result"]
    fn encapsulate(public_key: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret)>;

    /// Decapsulate: recover shared secret from ciphertext.
    #[must_use = "decapsulation can fail; check the Result"]
    fn decapsulate(
        private_key: &Self::PrivateKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIGITAL SIGNATURES
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for digital signature algorithms.
pub trait Signer {
    /// Public key type.
    type PublicKey;
    /// Private key type.
    type PrivateKey;
    /// Signature type.
    type Signature;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Generate a new signing key pair.
    #[must_use = "key generation can fail; check the Result"]
    fn generate_keypair() -> Result<(Self::PrivateKey, Self::PublicKey)>;

    /// Sign a message.
    #[must_use = "signing can fail; check the Result"]
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Self::Signature>;

    /// Verify a signature.
    #[must_use = "verification result must be checked"]
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool>;
}

/// Trait for batch signature verification.
pub trait BatchVerifier: Signer {
    /// Verify multiple signatures in batch (more efficient than individual verification).
    #[must_use = "verification result must be checked"]
    fn verify_batch(items: &[(&Self::PublicKey, &[u8], &Self::Signature)]) -> Result<bool>;
}

/// Trait for deterministic signatures (RFC 6979).
pub trait DeterministicSigner: Signer {
    /// Sign with deterministic nonce generation.
    #[must_use = "signing can fail; check the Result"]
    fn sign_deterministic(
        private_key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Self::Signature>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASH FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for hash functions.
pub trait Hash {
    /// The size of the hash output in bytes.
    const OUTPUT_SIZE: usize;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Compute hash of data.
    fn hash(data: &[u8]) -> Vec<u8>;

    /// Create a new hasher for incremental hashing.
    fn new() -> Self;

    /// Update hasher with data.
    fn update(&mut self, data: &[u8]);

    /// Finalize and return hash.
    fn finalize(self) -> Vec<u8>;
}

/// Trait for extendable output functions (XOFs).
pub trait ExtendableOutputFunction {
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Create a new XOF instance.
    fn new() -> Self;

    /// Update with data.
    fn update(&mut self, data: &[u8]);

    /// Read output bytes.
    fn squeeze(&mut self, output: &mut [u8]);

    /// Finalize and read all output.
    fn finalize_xof(self, output_len: usize) -> Vec<u8>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MESSAGE AUTHENTICATION CODES
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for message authentication codes (MACs).
pub trait Mac {
    /// The size of the MAC output in bytes.
    const OUTPUT_SIZE: usize;
    /// The size of the key in bytes.
    const KEY_SIZE: usize;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Compute MAC of data.
    #[must_use = "MAC computation can fail; check the Result"]
    fn compute(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    /// Verify MAC.
    #[must_use = "verification result must be checked"]
    fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY DERIVATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for key derivation functions (KDFs).
pub trait KeyDerivation {
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Derive key material from input.
    #[must_use = "key derivation can fail; check the Result"]
    fn derive(
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_length: usize,
    ) -> Result<Vec<u8>>;
}

/// Trait for password-based key derivation functions.
pub trait PasswordBasedKdf {
    /// Parameters type for this KDF.
    type Params;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Derive key from password.
    #[must_use = "key derivation can fail; check the Result"]
    fn derive(
        password: &[u8],
        salt: &[u8],
        params: &Self::Params,
        output_length: usize,
    ) -> Result<Vec<u8>>;

    /// Hash password for storage.
    #[must_use = "password hashing can fail; check the Result"]
    fn hash_password(password: &[u8], params: &Self::Params) -> Result<String>;

    /// Verify password against hash.
    #[must_use = "verification result must be checked"]
    fn verify_password(password: &[u8], hash: &str) -> Result<bool>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ZERO-KNOWLEDGE PROOFS
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for zero-knowledge proof systems.
pub trait ZkProof {
    /// Proof type.
    type Proof;
    /// Public input type.
    type PublicInput;
    /// Private witness type.
    type Witness;
    /// Verification key type.
    type VerificationKey;
    /// Proving key type.
    type ProvingKey;

    /// Generate a proof.
    #[must_use = "proof generation can fail; check the Result"]
    fn prove(
        proving_key: &Self::ProvingKey,
        public_input: &Self::PublicInput,
        witness: &Self::Witness,
    ) -> Result<Self::Proof>;

    /// Verify a proof.
    #[must_use = "verification result must be checked"]
    fn verify(
        verification_key: &Self::VerificationKey,
        public_input: &Self::PublicInput,
        proof: &Self::Proof,
    ) -> Result<bool>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECRET SHARING
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for secret sharing schemes.
pub trait SecretSharing {
    /// Share type.
    type Share;

    /// Split a secret into shares.
    #[must_use = "secret splitting can fail; check the Result"]
    fn split(secret: &[u8], threshold: usize, total_shares: usize) -> Result<Vec<Self::Share>>;

    /// Reconstruct secret from shares.
    #[must_use = "secret reconstruction can fail; check the Result"]
    fn reconstruct(shares: &[Self::Share]) -> Result<Vec<u8>>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// THRESHOLD SIGNATURES
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for threshold signature schemes.
#[cfg(feature = "async")]
#[async_trait]
pub trait ThresholdSigner {
    /// Key share type.
    type KeyShare;
    /// Signature share type.
    type SignatureShare;
    /// Combined signature type.
    type Signature;
    /// Public key type.
    type PublicKey;

    /// Generate key shares via distributed key generation.
    #[must_use = "key generation can fail; check the Result"]
    async fn distributed_keygen(
        threshold: usize,
        total_participants: usize,
    ) -> Result<Vec<Self::KeyShare>>;

    /// Generate a signature share.
    #[must_use = "signature share generation can fail; check the Result"]
    fn sign_share(key_share: &Self::KeyShare, message: &[u8]) -> Result<Self::SignatureShare>;

    /// Combine signature shares into final signature.
    #[must_use = "signature combination can fail; check the Result"]
    fn combine_signatures(
        shares: &[Self::SignatureShare],
        threshold: usize,
    ) -> Result<Self::Signature>;

    /// Verify the final signature.
    #[must_use = "verification result must be checked"]
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYSTORE
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for key storage backends.
#[cfg(feature = "async")]
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Store a key.
    #[must_use = "key store operation can fail; check the Result"]
    async fn store(&self, id: &str, key: &[u8], metadata: Option<&[u8]>) -> Result<()>;

    /// Retrieve a key.
    #[must_use = "key store operation can fail; check the Result"]
    async fn retrieve(&self, id: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a key.
    #[must_use = "key store operation can fail; check the Result"]
    async fn delete(&self, id: &str) -> Result<bool>;

    /// List all key IDs.
    #[must_use = "key store operation can fail; check the Result"]
    async fn list(&self) -> Result<Vec<String>>;

    /// Check if a key exists.
    #[must_use = "key store operation can fail; check the Result"]
    async fn exists(&self, id: &str) -> Result<bool>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RANDOM NUMBER GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for cryptographically secure random number generation.
pub trait SecureRng {
    /// Fill buffer with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);

    /// Generate random bytes.
    fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf);
        buf
    }

    /// Generate a random u64.
    fn random_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Generate a random u32.
    fn random_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HYBRID CRYPTOGRAPHY
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for hybrid encryption (combining symmetric and asymmetric).
pub trait HybridEncrypt {
    /// Public key type.
    type PublicKey;
    /// Private key type.
    type PrivateKey;

    /// Encrypt with hybrid scheme.
    #[must_use = "encryption can fail; check the Result"]
    fn encrypt(public_key: &Self::PublicKey, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt with hybrid scheme.
    #[must_use = "decryption can fail; check the Result"]
    fn decrypt(private_key: &Self::PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for post-quantum hybrid schemes (classical + PQ).
pub trait PostQuantumHybrid {
    /// Classical public key type.
    type ClassicalPublicKey;
    /// Classical private key type.
    type ClassicalPrivateKey;
    /// Post-quantum public key type.
    type PqPublicKey;
    /// Post-quantum private key type.
    type PqPrivateKey;

    /// Generate hybrid key pair.
    #[allow(clippy::type_complexity)]
    #[must_use = "key generation can fail; check the Result"]
    fn generate_keypair() -> Result<(
        (Self::ClassicalPrivateKey, Self::PqPrivateKey),
        (Self::ClassicalPublicKey, Self::PqPublicKey),
    )>;

    /// Encapsulate with hybrid KEM.
    #[must_use = "encapsulation can fail; check the Result"]
    fn encapsulate(
        classical_pk: &Self::ClassicalPublicKey,
        pq_pk: &Self::PqPublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate with hybrid KEM.
    #[must_use = "decapsulation can fail; check the Result"]
    fn decapsulate(
        classical_sk: &Self::ClassicalPrivateKey,
        pq_sk: &Self::PqPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}
