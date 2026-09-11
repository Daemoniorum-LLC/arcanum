//! Error types for cryptographic agility operations.

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "registry")]
use crate::registry::AlgorithmId;
use thiserror::Error;

/// Errors that can occur during agility operations.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum AgileError {
    /// Algorithm not found in registry.
    #[error("Unknown algorithm ID: {0}")]
    UnknownAlgorithm(u16),

    /// Algorithm not supported for this operation.
    #[cfg(feature = "registry")]
    #[error("Algorithm {id:?} is not supported for this operation")]
    UnsupportedAlgorithm { id: AlgorithmId },

    /// Invalid key size for algorithm.
    #[error("Invalid key size: expected {expected} bytes, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Algorithm is deprecated and not allowed by policy.
    #[error("Algorithm {algorithm} is deprecated: {reason}")]
    DeprecatedAlgorithm { algorithm: String, reason: String },

    /// Algorithm not allowed by policy.
    #[error("Algorithm {algorithm} not allowed by policy: {reason}")]
    PolicyViolation { algorithm: String, reason: String },

    /// Container parsing failed.
    #[error("Failed to parse container: {reason}")]
    ParseError { reason: String },

    /// Unsupported container version.
    #[error("Unsupported container format version: {version}")]
    UnsupportedVersion { version: u8 },

    /// Missing required header field.
    #[error("Missing required header field: {field}")]
    MissingHeader { field: String },

    /// Migration failed.
    #[error("Migration failed: {reason}")]
    MigrationFailed { reason: String },

    /// Encryption/decryption error from underlying cipher.
    #[error("Cryptographic operation failed: {reason}")]
    CryptoError { reason: String },

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for agility operations.
pub type AgileResult<T> = Result<T, AgileError>;
