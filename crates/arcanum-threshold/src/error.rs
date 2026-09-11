//! Error types for threshold cryptography operations.

#[cfg(not(feature = "std"))]
use alloc::string::String;

use thiserror::Error;

/// Errors that can occur in threshold operations.
#[derive(Debug, Error)]
pub enum ThresholdError {
    /// Threshold must be at least 1.
    #[error("threshold must be at least 1, got {threshold}")]
    ThresholdTooLow {
        /// The invalid threshold value.
        threshold: usize,
    },

    /// Threshold cannot exceed total number of shares.
    #[error("threshold ({threshold}) cannot exceed total shares ({total})")]
    ThresholdExceedsTotal {
        /// The threshold value.
        threshold: usize,
        /// The total number of shares.
        total: usize,
    },

    /// Invalid threshold parameters (legacy variant).
    #[error("invalid threshold: need {threshold} of {total} shares, but {threshold} > {total}")]
    InvalidThreshold {
        /// The threshold value.
        threshold: usize,
        /// The total number of shares.
        total: usize,
    },

    /// Not enough shares for reconstruction.
    #[error("insufficient shares: need {required}, got {provided}")]
    InsufficientShares {
        /// Number of shares required.
        required: usize,
        /// Number of shares provided.
        provided: usize,
    },

    /// Share index is out of range.
    #[error("invalid share index: {index} (valid range: 1-{max})")]
    InvalidShareIndex {
        /// The invalid index.
        index: usize,
        /// Maximum valid index.
        max: usize,
    },

    /// Duplicate share indices detected.
    #[error("duplicate share index: {index}")]
    DuplicateShareIndex {
        /// The duplicated index.
        index: usize,
    },

    /// Share verification failed.
    #[error("share verification failed for participant {participant}")]
    ShareVerificationFailed {
        /// The participant whose share failed verification.
        participant: u16,
    },

    /// Invalid share format.
    #[error("invalid share format")]
    InvalidShareFormat,

    /// Invalid share data with reason.
    #[error("invalid share data: {reason}")]
    InvalidShare {
        /// The reason for invalidity.
        reason: String,
    },

    /// Invalid commitment.
    #[error("invalid commitment")]
    InvalidCommitment,

    /// DKG protocol error.
    #[error("DKG protocol error: {0}")]
    DkgError(String),

    /// Signing protocol error.
    #[error("signing protocol error: {0}")]
    SigningError(String),

    /// Invalid participant identifier.
    #[error("invalid participant identifier: {0}")]
    InvalidParticipant(u16),

    /// Missing participant in round.
    #[error("missing participant {0} in round")]
    MissingParticipant(u16),

    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Internal error.
    #[error("internal error: {0}")]
    InternalError(String),
}

/// Result type for threshold operations.
pub type Result<T> = core::result::Result<T, ThresholdError>;
