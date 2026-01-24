//! Error types for Arcanum WASM bindings.

use wasm_bindgen::prelude::*;

/// Cryptographic operation error.
///
/// All errors include a code string for programmatic handling in JavaScript.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct CryptoError {
    code: String,
    message: String,
}

#[wasm_bindgen]
impl CryptoError {
    /// Create a new CryptoError.
    #[wasm_bindgen(constructor)]
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    /// Get the error code (e.g., "INVALID_KEY", "DECRYPTION_FAILED").
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// Get the human-readable error message.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CryptoError {}

// Conversion helpers
impl CryptoError {
    pub(crate) fn invalid_key(msg: &str) -> Self {
        Self::new("INVALID_KEY", msg)
    }

    pub(crate) fn invalid_nonce(msg: &str) -> Self {
        Self::new("INVALID_NONCE", msg)
    }

    pub(crate) fn decryption_failed() -> Self {
        Self::new(
            "DECRYPTION_FAILED",
            "Authentication tag verification failed",
        )
    }

    pub(crate) fn encryption_failed(msg: &str) -> Self {
        Self::new("ENCRYPTION_FAILED", msg)
    }
}
