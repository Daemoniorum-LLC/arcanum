//! Traits for symmetric encryption algorithms.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use arcanum_core::error::{Error, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// INPUT SIZE LIMITS
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum plaintext size (64 GiB).
///
/// This limit prevents memory exhaustion and ensures compatibility with
/// AEAD algorithms that have internal limits on message sizes.
pub const MAX_PLAINTEXT_SIZE: usize = 1 << 36; // 64 GiB

/// Maximum associated data (AAD) size (16 MiB).
///
/// While most AEAD algorithms support larger AAD, this limit prevents
/// accidental misuse and ensures reasonable memory usage.
pub const MAX_AAD_SIZE: usize = 1 << 24; // 16 MiB

/// Validate plaintext size.
///
/// Returns an error if the plaintext exceeds `MAX_PLAINTEXT_SIZE`.
#[inline]
#[must_use = "validation can fail; check the Result"]
pub fn validate_plaintext_size(plaintext: &[u8]) -> Result<()> {
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(Error::PlaintextTooLarge {
            size: plaintext.len(),
            max: MAX_PLAINTEXT_SIZE,
        });
    }
    Ok(())
}

/// Validate AAD size.
///
/// Returns an error if the AAD exceeds `MAX_AAD_SIZE`.
#[inline]
#[must_use = "validation can fail; check the Result"]
pub fn validate_aad_size(aad: &[u8]) -> Result<()> {
    if aad.len() > MAX_AAD_SIZE {
        return Err(Error::AadTooLarge {
            size: aad.len(),
            max: MAX_AAD_SIZE,
        });
    }
    Ok(())
}

/// Validate both plaintext and AAD sizes.
#[inline]
#[must_use = "validation can fail; check the Result"]
pub fn validate_input_sizes(plaintext: &[u8], aad: Option<&[u8]>) -> Result<()> {
    validate_plaintext_size(plaintext)?;
    if let Some(aad) = aad {
        validate_aad_size(aad)?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// CIPHER TRAITS
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for AEAD (Authenticated Encryption with Associated Data) ciphers.
pub trait Cipher {
    /// Key size in bytes.
    const KEY_SIZE: usize;
    /// Nonce size in bytes.
    const NONCE_SIZE: usize;
    /// Authentication tag size in bytes.
    const TAG_SIZE: usize;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Generate a random key.
    fn generate_key() -> Vec<u8>;

    /// Generate a random nonce.
    fn generate_nonce() -> Vec<u8>;

    /// Encrypt plaintext with optional associated data.
    ///
    /// Returns ciphertext with authentication tag appended.
    #[must_use = "encryption can fail; check the Result"]
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with optional associated data.
    ///
    /// Returns plaintext if authentication succeeds.
    #[must_use = "decryption can fail; check the Result"]
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Encrypt in place (for zero-copy scenarios).
    #[must_use = "encryption can fail; check the Result"]
    fn encrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()>;

    /// Decrypt in place (for zero-copy scenarios).
    #[must_use = "decryption can fail; check the Result"]
    fn decrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()>;
}

/// Trait for stream ciphers.
pub trait StreamCipher {
    /// Key size in bytes.
    const KEY_SIZE: usize;
    /// Nonce size in bytes.
    const NONCE_SIZE: usize;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Create a new stream cipher instance.
    #[must_use = "construction can fail; check the Result"]
    fn new(key: &[u8], nonce: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Apply keystream to data (XOR operation).
    ///
    /// This is symmetric - the same operation encrypts and decrypts.
    fn apply_keystream(&mut self, data: &mut [u8]);

    /// Generate keystream bytes.
    fn keystream(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.apply_keystream(&mut buf);
        buf
    }

    /// Seek to a position in the keystream (if supported).
    #[must_use = "this operation can fail; check the Result"]
    fn seek(&mut self, position: u64) -> Result<()>;

    /// Get current position in the keystream.
    fn position(&self) -> u64;
}
