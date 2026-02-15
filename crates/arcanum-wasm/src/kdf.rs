//! Key derivation functions.
//!
//! Supports Argon2id (password hashing) and HKDF-SHA256 (key derivation).

use crate::error::CryptoError;
use wasm_bindgen::prelude::*;

/// Derive a key from a password using Argon2id.
///
/// Argon2id is the recommended algorithm for password hashing, providing
/// resistance against GPU and side-channel attacks.
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `salt` - A unique salt (should be at least 16 bytes)
/// * `config` - Optional configuration (uses secure defaults if None)
///
/// # Returns
///
/// 32-byte derived key suitable for use as an encryption key.
#[wasm_bindgen]
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    _config: Option<js_sys::Object>, // TODO: Parse config from JS object
) -> Result<Vec<u8>, CryptoError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Secure defaults for interactive use
    // Memory: 64 MiB, Iterations: 3, Parallelism: 4
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| CryptoError::new("KDF_ERROR", &format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::new("KDF_ERROR", &format!("Argon2 failed: {}", e)))?;

    Ok(output)
}

/// Derive a key using HKDF-SHA256.
///
/// HKDF is suitable for deriving keys from high-entropy input key material.
/// For password-based key derivation, use `argon2id` instead.
///
/// # Arguments
///
/// * `ikm` - Input key material (should be high-entropy)
/// * `salt` - Optional salt (can be empty, but recommended)
/// * `info` - Context/application-specific info
/// * `length` - Desired output length in bytes
///
/// # Returns
///
/// Derived key of the requested length.
#[wasm_bindgen]
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; length];

    hk.expand(info, &mut output)
        .map_err(|_| CryptoError::new("KDF_ERROR", "HKDF expand failed (output too long?)"))?;

    Ok(output)
}
