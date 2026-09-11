//! Error types for HoloCrypt operations.

#[cfg(not(feature = "std"))]
use alloc::string::String;

use thiserror::Error;

/// Errors that can occur during HoloCrypt operations.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum HoloCryptError {
    /// Sealing (encryption + commitment + signature) failed.
    #[error("Failed to seal container: {reason}")]
    SealFailed { reason: String },

    /// Unsealing (decryption + verification) failed.
    #[error("Failed to unseal container: {reason}")]
    UnsealFailed { reason: String },

    /// Container structure verification failed.
    #[error("Container structure verification failed: {reason}")]
    VerificationFailed { reason: String },

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureInvalid,

    /// Commitment verification failed.
    #[error("Commitment verification failed - data may have been tampered")]
    CommitmentMismatch,

    /// Merkle proof verification failed.
    #[error("Merkle proof verification failed for chunk {chunk_index}")]
    MerkleProofInvalid { chunk_index: usize },

    /// Zero-knowledge proof verification failed.
    #[error("Zero-knowledge proof verification failed: {reason}")]
    ZkProofInvalid { reason: String },

    /// Chunk index out of bounds.
    #[error("Chunk index {index} out of bounds (container has {total} chunks)")]
    ChunkIndexOutOfBounds { index: usize, total: usize },

    /// Property proof generation failed.
    #[error("Failed to generate property proof: {reason}")]
    PropertyProofFailed { reason: String },

    /// Property does not hold for the data.
    #[error("Property '{property}' does not hold for the sealed data")]
    PropertyNotSatisfied { property: String },

    /// Insufficient threshold shares.
    #[error("Need {required} shares to unseal, got {provided}")]
    InsufficientShares { required: usize, provided: usize },

    /// Invalid key share.
    #[error("Key share from participant {participant} is invalid")]
    InvalidKeyShare { participant: usize },

    /// Key share reconstruction failed.
    #[error("Failed to reconstruct key from shares: {reason}")]
    KeyReconstructionFailed { reason: String },

    /// PQC decapsulation failed.
    #[error("Post-quantum key decapsulation failed")]
    PqcDecapsulationFailed,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Underlying cryptographic error.
    #[error("Cryptographic error: {reason}")]
    CryptoError { reason: String },
}

/// Result type for HoloCrypt operations.
pub type HoloCryptResult<T> = Result<T, HoloCryptError>;
