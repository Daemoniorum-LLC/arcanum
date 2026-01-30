//! Error types for verification operations.

#[cfg(not(feature = "std"))]
use alloc::string::String;

use thiserror::Error;

/// Errors that can occur during verification.
#[derive(Debug, Error)]
#[allow(missing_docs)] // Error variant fields are self-documenting
pub enum VerifyError {
    /// Timing leak detected.
    #[error("Timing leak detected: t-value {t_value:.2} exceeds threshold {threshold:.2}")]
    TimingLeakDetected { t_value: f64, threshold: f64 },

    /// Insufficient samples for statistical analysis.
    #[error("Need at least {required} samples, got {provided}")]
    InsufficientSamples { required: usize, provided: usize },

    /// Test execution failed.
    #[error("Test execution failed: {reason}")]
    ExecutionFailed { reason: String },

    /// Memory not properly zeroized.
    #[error("Memory at offset {offset} not zeroized: expected 0x00, got 0x{actual:02X}")]
    MemoryNotZeroized { offset: usize, actual: u8 },

    /// Model checking property violation.
    #[error("Property violation: {property}")]
    PropertyViolation { property: String },

    /// Report generation failed.
    #[error("Report generation failed: {reason}")]
    ReportGenerationFailed { reason: String },
}

/// Result type for verification operations.
pub type VerifyResult<T> = Result<T, VerifyError>;
