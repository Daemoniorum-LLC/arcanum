//! Cryptographic hash functions.
//!
//! Supports SHA-256, SHA-3-256, and BLAKE3.
//! Backend selected at compile time via feature flags.

use wasm_bindgen::prelude::*;

/// Compute SHA-256 hash of input data.
///
/// # Arguments
///
/// * `data` - Input bytes to hash
///
/// # Returns
///
/// 32-byte SHA-256 digest.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).to_vec()
    }

    #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
    {
        arcanum_primitives::sha2::Sha256::hash(data).to_vec()
    }

    #[cfg(not(any(feature = "backend-rustcrypto", feature = "backend-native")))]
    {
        compile_error!("Either backend-rustcrypto or backend-native must be enabled");
    }
}

/// Compute SHA-3-256 hash of input data.
///
/// # Arguments
///
/// * `data` - Input bytes to hash
///
/// # Returns
///
/// 32-byte SHA-3-256 digest.
#[wasm_bindgen]
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(data).to_vec()
    }

    #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
    {
        // Native backend doesn't have SHA-3 - use RustCrypto sha3 crate
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(data).to_vec()
    }

    #[cfg(not(any(feature = "backend-rustcrypto", feature = "backend-native")))]
    {
        compile_error!("Either backend-rustcrypto or backend-native must be enabled");
    }
}

/// Compute BLAKE3 hash of input data.
///
/// # Arguments
///
/// * `data` - Input bytes to hash
///
/// # Returns
///
/// 32-byte BLAKE3 digest.
#[wasm_bindgen]
pub fn blake3(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        blake3::hash(data).as_bytes().to_vec()
    }

    #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
    {
        arcanum_primitives::blake3::Blake3::hash(data).to_vec()
    }

    #[cfg(not(any(feature = "backend-rustcrypto", feature = "backend-native")))]
    {
        compile_error!("Either backend-rustcrypto or backend-native must be enabled");
    }
}
