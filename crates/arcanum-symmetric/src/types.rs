//! Type aliases for improved API ergonomics.
//!
//! These type aliases provide more descriptive names and reduce boilerplate
//! when working with cryptographic primitives.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_symmetric::types::*;
//!
//! // Instead of raw byte arrays
//! let key: Aes256Key = Aes256Gcm::generate_key().try_into().unwrap();
//! let nonce: GcmNonce = Aes256Gcm::generate_nonce().try_into().unwrap();
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use arcanum_core::error::{Error, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// RESULT TYPE ALIAS
// ═══════════════════════════════════════════════════════════════════════════════

/// Convenient result type for cryptographic operations.
///
/// Equivalent to `Result<T, arcanum_core::error::Error>`.
pub type CryptoResult<T> = Result<T>;

// ═══════════════════════════════════════════════════════════════════════════════
// AES KEY TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// 128-bit AES key (16 bytes).
pub type Aes128Key = [u8; 16];

/// 256-bit AES key (32 bytes).
pub type Aes256Key = [u8; 32];

// ═══════════════════════════════════════════════════════════════════════════════
// CHACHA KEY TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// 256-bit ChaCha20 key (32 bytes).
pub type ChaChaKey = [u8; 32];

/// Alias for ChaCha20-Poly1305 key (same as ChaChaKey).
pub type ChaCha20Poly1305Key = ChaChaKey;

/// Alias for XChaCha20-Poly1305 key (same as ChaChaKey).
pub type XChaCha20Poly1305Key = ChaChaKey;

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// 96-bit nonce for AES-GCM (12 bytes).
///
/// This is the standard nonce size for AES-GCM as specified in NIST SP 800-38D.
pub type GcmNonce = [u8; 12];

/// Alias for AES-GCM nonce.
pub type AesGcmNonce = GcmNonce;

/// 96-bit nonce for ChaCha20-Poly1305 (12 bytes).
pub type ChaChaNonce = [u8; 12];

/// 192-bit nonce for XChaCha20-Poly1305 (24 bytes).
///
/// The extended nonce size makes random nonce generation safe
/// for up to 2^64 messages without collision risk.
pub type XChaChaNonce = [u8; 24];

/// 128-bit IV for AES-CTR (16 bytes).
pub type AesCtrIv = [u8; 16];

// ═══════════════════════════════════════════════════════════════════════════════
// TAG TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// 128-bit authentication tag (16 bytes).
///
/// Used by AES-GCM, ChaCha20-Poly1305, and other AEAD ciphers.
pub type AuthTag = [u8; 16];

/// Alias for GCM authentication tag.
pub type GcmTag = AuthTag;

/// Alias for Poly1305 authentication tag.
pub type Poly1305Tag = AuthTag;

// ═══════════════════════════════════════════════════════════════════════════════
// CONVERSION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Convert a Vec to a fixed-size array, returning an error if the length is wrong.
///
/// # Example
///
/// ```ignore
/// use arcanum_symmetric::types::{vec_to_array, Aes256Key};
///
/// let key_vec = Aes256Gcm::generate_key();
/// let key: Aes256Key = vec_to_array(key_vec)?;
/// ```
#[must_use = "this operation can fail; check the Result"]
pub fn vec_to_array<const N: usize>(vec: Vec<u8>) -> Result<[u8; N]> {
    vec.try_into()
        .map_err(|v: Vec<u8>| Error::InvalidKeyLength {
            expected: N,
            actual: v.len(),
        })
}

/// Convert a slice to a fixed-size array, returning an error if the length is wrong.
///
/// # Example
///
/// ```ignore
/// use arcanum_symmetric::types::{slice_to_array, GcmNonce};
///
/// let nonce: GcmNonce = slice_to_array(&nonce_bytes)?;
/// ```
#[must_use = "this operation can fail; check the Result"]
pub fn slice_to_array<const N: usize>(slice: &[u8]) -> Result<[u8; N]> {
    slice.try_into().map_err(|_| Error::InvalidKeyLength {
        expected: N,
        actual: slice.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_sizes() {
        assert_eq!(std::mem::size_of::<Aes128Key>(), 16);
        assert_eq!(std::mem::size_of::<Aes256Key>(), 32);
        assert_eq!(std::mem::size_of::<ChaChaKey>(), 32);
        assert_eq!(std::mem::size_of::<GcmNonce>(), 12);
        assert_eq!(std::mem::size_of::<ChaChaNonce>(), 12);
        assert_eq!(std::mem::size_of::<XChaChaNonce>(), 24);
        assert_eq!(std::mem::size_of::<AuthTag>(), 16);
    }

    #[test]
    fn test_vec_to_array() {
        let vec = vec![0u8; 32];
        let arr: Aes256Key = vec_to_array(vec).unwrap();
        assert_eq!(arr.len(), 32);
    }

    #[test]
    fn test_vec_to_array_wrong_size() {
        let vec = vec![0u8; 16];
        let result: Result<Aes256Key> = vec_to_array(vec);
        assert!(result.is_err());
    }

    #[test]
    fn test_slice_to_array() {
        let slice = [0u8; 12];
        let arr: GcmNonce = slice_to_array(&slice).unwrap();
        assert_eq!(arr.len(), 12);
    }
}
