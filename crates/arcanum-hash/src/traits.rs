//! Traits for hash functions and key derivation.

use arcanum_core::error::Result;
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "std"))]
use alloc::{string::{String, ToString}, vec::Vec};

/// Output of a hash function.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashOutput(Vec<u8>);

impl HashOutput {
    /// Create from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create from a fixed-size array.
    pub fn from_array<const N: usize>(arr: [u8; N]) -> Self {
        Self(arr.to_vec())
    }

    /// Get the hash bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the hash length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes =
            hex::decode(s).map_err(|e| arcanum_core::error::Error::ParseError(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// Convert to fixed-size array.
    pub fn to_array<const N: usize>(&self) -> Option<[u8; N]> {
        if self.0.len() != N {
            return None;
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.0);
        Some(arr)
    }

    /// Consume and return bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for HashOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HashOutput({})", self.to_hex())
    }
}

impl core::fmt::Display for HashOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<Vec<u8>> for HashOutput {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> From<[u8; N]> for HashOutput {
    fn from(arr: [u8; N]) -> Self {
        Self(arr.to_vec())
    }
}

/// Trait for hash functions.
pub trait Hasher: Clone + Default {
    /// Output size in bytes.
    const OUTPUT_SIZE: usize;
    /// Block size in bytes.
    const BLOCK_SIZE: usize;
    /// Algorithm name.
    const ALGORITHM: &'static str;

    /// Create a new hasher.
    fn new() -> Self;

    /// Update the hasher with data.
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the hash.
    fn finalize(self) -> HashOutput;

    /// Reset the hasher to initial state.
    fn reset(&mut self);

    /// One-shot hash computation.
    fn hash(data: &[u8]) -> HashOutput {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash multiple pieces of data.
    fn hash_all(parts: &[&[u8]]) -> HashOutput {
        let mut hasher = Self::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    /// Verify a hash matches expected value.
    fn verify(data: &[u8], expected: &HashOutput) -> bool {
        let computed = Self::hash(data);
        constant_time_eq(&computed.0, &expected.0)
    }
}

/// Trait for extendable-output functions (XOFs).
pub trait ExtendableOutput: Clone {
    /// Algorithm name.
    const ALGORITHM: &'static str;

    /// Create a new XOF.
    fn new() -> Self;

    /// Update with data.
    fn update(&mut self, data: &[u8]);

    /// Read output bytes.
    fn squeeze(&mut self, output: &mut [u8]);

    /// Finalize and read specified number of bytes.
    fn finalize_xof(self, output_len: usize) -> Vec<u8>;

    /// One-shot XOF computation.
    fn hash_xof(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut xof = Self::new();
        xof.update(data);
        xof.finalize_xof(output_len)
    }
}

/// Trait for key derivation functions.
pub trait KeyDerivation {
    /// Algorithm name.
    const ALGORITHM: &'static str;

    /// Derive key material.
    ///
    /// # Arguments
    /// * `ikm` - Input key material (should be high-entropy)
    /// * `salt` - Optional salt (recommended)
    /// * `info` - Optional context/application-specific info
    /// * `output_len` - Desired output length in bytes
    fn derive(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Vec<u8>>;

    /// Derive into a fixed-size array.
    fn derive_array<const N: usize>(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<[u8; N]> {
        let derived = Self::derive(ikm, salt, info, N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(&derived);
        Ok(arr)
    }
}

/// Trait for password-based key derivation.
pub trait PasswordHash {
    /// Parameters type.
    type Params;
    /// Algorithm name.
    const ALGORITHM: &'static str;

    /// Hash a password for storage.
    ///
    /// Returns a string suitable for storage (includes salt and parameters).
    fn hash_password(password: &[u8], params: &Self::Params) -> Result<String>;

    /// Verify a password against a stored hash.
    fn verify_password(password: &[u8], hash: &str) -> Result<bool>;

    /// Derive key material from password.
    fn derive_key(
        password: &[u8],
        salt: &[u8],
        params: &Self::Params,
        output_len: usize,
    ) -> Result<Vec<u8>>;
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_output() {
        let hash = HashOutput::new(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(hash.to_hex(), "deadbeef");
        assert_eq!(hash.len(), 4);

        let restored = HashOutput::from_hex("deadbeef").unwrap();
        assert_eq!(hash, restored);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
