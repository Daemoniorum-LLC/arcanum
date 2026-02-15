//! Cryptographically secure random number generation.
//!
//! Uses browser's `crypto.getRandomValues()` via getrandom.

use wasm_bindgen::prelude::*;

/// Generate cryptographically secure random bytes.
///
/// Uses the browser's `crypto.getRandomValues()` API.
/// Panics if entropy source is unavailable (should never happen in modern browsers).
///
/// # Arguments
///
/// * `length` - Number of random bytes to generate
///
/// # Returns
///
/// A `Vec<u8>` containing `length` random bytes.
#[wasm_bindgen]
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    if length > 0 {
        getrandom::getrandom(&mut bytes).expect("entropy source unavailable");
    }
    bytes
}
