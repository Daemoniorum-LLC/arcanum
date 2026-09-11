//! Error types for cryptographic operations.
//!
//! All errors are designed to be:
//! - Non-leaking: Error messages don't reveal sensitive information
//! - Specific: Each error type has a clear meaning
//! - Recoverable: Where possible, errors indicate how to recover

#[cfg(not(feature = "std"))]
use alloc::string::String;

use thiserror::Error;

/// The primary error type for Arcanum operations.
#[derive(Debug, Error)]
pub enum Error {
    // ═══════════════════════════════════════════════════════════════════════════
    // KEY ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid key length
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Key generation failed
    #[error("key generation failed")]
    KeyGenerationFailed,

    /// Key derivation failed
    #[error("key derivation failed")]
    KeyDerivationFailed,

    /// Key not found in keystore
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Key has expired
    #[error("key expired")]
    KeyExpired,

    /// Key has been revoked
    #[error("key revoked")]
    KeyRevoked,

    /// Key is not yet valid
    #[error("key not yet valid")]
    KeyNotYetValid,

    /// Invalid key format
    #[error("invalid key format")]
    InvalidKeyFormat,

    /// Missing key (key not provided to operation)
    #[error("missing key: no key was provided")]
    MissingKey,

    /// Key import failed
    #[error("key import failed")]
    KeyImportFailed,

    /// Key export failed
    #[error("key export failed")]
    KeyExportFailed,

    // ═══════════════════════════════════════════════════════════════════════════
    // ENCRYPTION/DECRYPTION ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Encryption operation failed
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption operation failed (authentication or integrity failure)
    #[error("decryption failed")]
    DecryptionFailed,

    /// Invalid ciphertext
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// Ciphertext too short
    #[error("ciphertext too short: got {size} bytes, minimum {minimum} bytes")]
    CiphertextTooShort {
        /// Actual length received
        size: usize,
        /// Minimum expected length
        minimum: usize,
    },

    /// Plaintext too large
    #[error("plaintext too large: {size} bytes exceeds {max} byte limit")]
    PlaintextTooLarge {
        /// Actual size in bytes
        size: usize,
        /// Maximum allowed length
        max: usize,
    },

    /// Associated data (AAD) too large
    #[error("AAD too large: {size} bytes exceeds {max} byte limit")]
    AadTooLarge {
        /// Actual size in bytes
        size: usize,
        /// Maximum allowed length
        max: usize,
    },

    /// Authentication tag verification failed
    #[error("authentication failed: tag mismatch")]
    AuthenticationFailed,

    // ═══════════════════════════════════════════════════════════════════════════
    // NONCE/IV ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid nonce length
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Nonce reuse detected
    #[error("nonce reuse detected - security violation")]
    NonceReuse,

    /// Nonce exhausted (counter overflow)
    #[error("nonce exhausted - key rotation required")]
    NonceExhausted,

    /// Missing nonce (nonce not provided to operation)
    #[error("missing nonce: no nonce was provided")]
    MissingNonce,

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGNATURE ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid signature format
    #[error("invalid signature format")]
    InvalidSignature,

    /// Signing operation failed
    #[error("signing failed")]
    SigningFailed,

    // ═══════════════════════════════════════════════════════════════════════════
    // HASH ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid hash length
    #[error("invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Hash verification failed
    #[error("hash verification failed")]
    HashVerificationFailed,

    // ═══════════════════════════════════════════════════════════════════════════
    // MAC ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// MAC verification failed
    #[error("MAC verification failed")]
    MacVerificationFailed,

    /// Invalid MAC length
    #[error("invalid MAC length")]
    InvalidMacLength,

    // ═══════════════════════════════════════════════════════════════════════════
    // CERTIFICATE/FORMAT ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Certificate validation failed
    #[error("certificate validation failed: {reason}")]
    CertificateValidationFailed {
        /// Reason for failure
        reason: String,
    },

    /// Invalid certificate chain
    #[error("invalid certificate chain")]
    InvalidCertificateChain,

    /// Unsupported format
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    /// Parse error
    #[error("parse error: {0}")]
    ParseError(String),

    /// Encoding error
    #[error("encoding error: {0}")]
    EncodingError(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // ALGORITHM ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Unsupported algorithm
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Algorithm mismatch
    #[error("algorithm mismatch: expected {expected}, got {actual}")]
    AlgorithmMismatch {
        /// Expected algorithm
        expected: String,
        /// Actual algorithm
        actual: String,
    },

    /// Weak algorithm (not recommended for use)
    #[error("weak algorithm: {0}")]
    WeakAlgorithm(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // PROTOCOL ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Protocol error
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// Handshake failed
    #[error("handshake failed")]
    HandshakeFailed,

    /// Session expired
    #[error("session expired")]
    SessionExpired,

    /// Replay attack detected
    #[error("replay attack detected")]
    ReplayAttack,

    // ═══════════════════════════════════════════════════════════════════════════
    // HARDWARE/EXTERNAL ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// HSM error
    #[error("HSM error: {0}")]
    HsmError(String),

    /// TPM error
    #[error("TPM error: {0}")]
    TpmError(String),

    /// Hardware not available
    #[error("hardware not available: {0}")]
    HardwareNotAvailable(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // RANDOM NUMBER GENERATION
    // ═══════════════════════════════════════════════════════════════════════════
    /// Random number generation failed
    #[error("random number generation failed")]
    RngFailed,

    /// Insufficient entropy
    #[error("insufficient entropy")]
    InsufficientEntropy,

    // ═══════════════════════════════════════════════════════════════════════════
    // STORAGE ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Storage error
    #[error("storage error: {0}")]
    StorageError(String),

    /// Data corruption detected
    #[error("data corruption detected")]
    DataCorruption,

    // ═══════════════════════════════════════════════════════════════════════════
    // ZERO-KNOWLEDGE PROOF ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Proof generation failed
    #[error("proof generation failed")]
    ProofGenerationFailed,

    /// Proof verification failed
    #[error("proof verification failed")]
    ProofVerificationFailed,

    /// Invalid witness
    #[error("invalid witness")]
    InvalidWitness,

    // ═══════════════════════════════════════════════════════════════════════════
    // THRESHOLD/SECRET SHARING ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Insufficient shares for reconstruction
    #[error("insufficient shares: need {threshold}, got {provided}")]
    InsufficientShares {
        /// Threshold required
        threshold: usize,
        /// Number of shares provided
        provided: usize,
    },

    /// Invalid share
    #[error("invalid share")]
    InvalidShare,

    /// Duplicate share
    #[error("duplicate share")]
    DuplicateShare,

    // ═══════════════════════════════════════════════════════════════════════════
    // GENERIC ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid parameter
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// Operation not permitted
    #[error("operation not permitted")]
    NotPermitted,

    /// Internal error (should not happen)
    #[error("internal error: {0}")]
    InternalError(String),

    /// Feature not implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),
}

/// Result type alias for Arcanum operations.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl Error {
    /// Check if this error indicates authentication failure.
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            Error::DecryptionFailed
                | Error::SignatureVerificationFailed
                | Error::MacVerificationFailed
                | Error::HashVerificationFailed
        )
    }

    /// Check if this error indicates a key-related issue.
    pub fn is_key_error(&self) -> bool {
        matches!(
            self,
            Error::InvalidKeyLength { .. }
                | Error::KeyGenerationFailed
                | Error::KeyDerivationFailed
                | Error::KeyNotFound(_)
                | Error::KeyExpired
                | Error::KeyRevoked
                | Error::KeyNotYetValid
                | Error::InvalidKeyFormat
                | Error::KeyImportFailed
                | Error::KeyExportFailed
        )
    }

    /// Check if this error indicates a security violation.
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Error::NonceReuse
                | Error::ReplayAttack
                | Error::DataCorruption
                | Error::WeakAlgorithm(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString;

    #[test]
    fn test_error_categories() {
        let err = Error::DecryptionFailed;
        assert!(err.is_authentication_failure());
        assert!(!err.is_key_error());

        let err = Error::KeyExpired;
        assert!(err.is_key_error());
        assert!(!err.is_authentication_failure());

        let err = Error::NonceReuse;
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_error_display() {
        let err = Error::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(err.to_string(), "invalid key length: expected 32, got 16");
    }
}
