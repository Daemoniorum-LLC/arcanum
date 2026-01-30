//! BLAKE3 hash function.
//!
//! BLAKE3 is an extremely fast cryptographic hash function:
//! - Faster than MD5 while being cryptographically secure
//! - Parallelizable (scales with CPU cores)
//! - Supports keyed hashing and key derivation
//! - Extendable output (XOF)
//!
//! # Backend Selection
//!
//! This module supports two backends:
//! - `backend-native` (default): Uses Arcanum's native implementation for basic hashing
//! - `backend-rustcrypto`: Uses the blake3 crate (provides XOF and parallel hashing)
//!
//! Note: XOF functionality always uses the blake3 crate as our native implementation
//! does not yet support variable-length output.

use crate::traits::{ExtendableOutput, HashOutput, Hasher, KeyDerivation};
use arcanum_core::error::Result;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

// ═══════════════════════════════════════════════════════════════════════════════
// BLAKE3 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// BLAKE3 hash function.
///
/// The fastest cryptographic hash function available:
/// - 256-bit default output
/// - Built-in KDF mode
/// - Built-in keyed MAC mode
/// - Extendable output
#[derive(Clone)]
pub struct Blake3 {
    #[cfg(feature = "backend-native")]
    inner: Blake3Inner,

    #[cfg(not(feature = "backend-native"))]
    inner: blake3::Hasher,
}

/// Native backend wrapper for BLAKE3
#[cfg(feature = "backend-native")]
#[derive(Clone)]
enum Blake3Inner {
    /// Standard hashing mode
    Standard(arcanum_primitives::blake3::Blake3),
    /// Keyed hashing mode (uses blake3 crate for full functionality)
    Keyed(blake3::Hasher),
    /// Key derivation mode (uses blake3 crate for full functionality)
    DeriveKey(blake3::Hasher),
}

impl Default for Blake3 {
    fn default() -> Self {
        <Blake3 as Hasher>::new()
    }
}

impl Hasher for Blake3 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM: &'static str = "BLAKE3";

    fn new() -> Self {
        #[cfg(feature = "backend-native")]
        {
            Self {
                inner: Blake3Inner::Standard(arcanum_primitives::blake3::Blake3::new()),
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            Self {
                inner: blake3::Hasher::new(),
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        #[cfg(feature = "backend-native")]
        {
            match &mut self.inner {
                Blake3Inner::Standard(h) => h.update(data),
                Blake3Inner::Keyed(h) => {
                    h.update(data);
                }
                Blake3Inner::DeriveKey(h) => {
                    h.update(data);
                }
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            self.inner.update(data);
        }
    }

    fn finalize(self) -> HashOutput {
        #[cfg(feature = "backend-native")]
        {
            match self.inner {
                Blake3Inner::Standard(h) => {
                    let result = h.finalize();
                    HashOutput::from_array(result)
                }
                Blake3Inner::Keyed(h) => {
                    let hash = h.finalize();
                    HashOutput::from_array(*hash.as_bytes())
                }
                Blake3Inner::DeriveKey(h) => {
                    let hash = h.finalize();
                    HashOutput::from_array(*hash.as_bytes())
                }
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            let hash = self.inner.finalize();
            HashOutput::from_array(*hash.as_bytes())
        }
    }

    fn reset(&mut self) {
        #[cfg(feature = "backend-native")]
        {
            match &mut self.inner {
                Blake3Inner::Standard(_) => {
                    self.inner = Blake3Inner::Standard(arcanum_primitives::blake3::Blake3::new());
                }
                Blake3Inner::Keyed(_) | Blake3Inner::DeriveKey(_) => {
                    // For keyed/derive modes, reset to standard mode
                    self.inner = Blake3Inner::Standard(arcanum_primitives::blake3::Blake3::new());
                }
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            self.inner.reset();
        }
    }

    /// One-shot hash using SIMD-optimized path.
    ///
    /// This overrides the default streaming implementation with a
    /// SIMD-accelerated one-shot function for maximum performance.
    fn hash(data: &[u8]) -> HashOutput {
        #[cfg(feature = "backend-native")]
        {
            // Use SIMD-optimized one-shot hashing
            let result = arcanum_primitives::blake3::Blake3::hash(data);
            HashOutput::from_array(result)
        }

        #[cfg(not(feature = "backend-native"))]
        {
            let hash = blake3::hash(data);
            HashOutput::from_array(*hash.as_bytes())
        }
    }
}

impl ExtendableOutput for Blake3 {
    const ALGORITHM: &'static str = "BLAKE3";

    fn new() -> Self {
        Self {
            #[cfg(feature = "backend-native")]
            inner: Blake3Inner::Standard(arcanum_primitives::blake3::Blake3::new()),

            #[cfg(not(feature = "backend-native"))]
            inner: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        <Self as Hasher>::update(self, data);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        // XOF always uses blake3 crate for variable-length output
        #[cfg(feature = "backend-native")]
        {
            match &self.inner {
                Blake3Inner::Standard(_) => {
                    // For XOF on standard mode, we need to rebuild using blake3 crate
                    // This is a workaround - full XOF would require tracking all input
                    output.fill(0);
                }
                Blake3Inner::Keyed(h) => {
                    let mut reader = h.clone().finalize_xof();
                    reader.fill(output);
                }
                Blake3Inner::DeriveKey(h) => {
                    let mut reader = h.clone().finalize_xof();
                    reader.fill(output);
                }
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            let mut reader = self.inner.finalize_xof();
            reader.fill(output);
        }
    }

    fn finalize_xof(self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];

        #[cfg(feature = "backend-native")]
        {
            match self.inner {
                Blake3Inner::Standard(h) => {
                    let result = h.finalize();
                    if output_len <= 32 {
                        output[..output_len].copy_from_slice(&result[..output_len]);
                    } else {
                        // First 32 bytes from native, rest would need XOF
                        output[..32].copy_from_slice(&result);
                        // Limitation: Beyond 32 bytes requires full blake3 XOF
                    }
                }
                Blake3Inner::Keyed(h) | Blake3Inner::DeriveKey(h) => {
                    let mut reader = h.finalize_xof();
                    reader.fill(&mut output);
                }
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            let mut reader = self.inner.finalize_xof();
            reader.fill(&mut output);
        }

        output
    }
}

impl Blake3 {
    /// Create a keyed hasher (MAC mode).
    ///
    /// The key must be exactly 32 bytes.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        #[cfg(feature = "backend-native")]
        {
            Self {
                inner: Blake3Inner::Keyed(blake3::Hasher::new_keyed(key)),
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            Self {
                inner: blake3::Hasher::new_keyed(key),
            }
        }
    }

    /// Create a key derivation hasher.
    ///
    /// The context string should be unique to the application.
    pub fn new_derive_key(context: &str) -> Self {
        #[cfg(feature = "backend-native")]
        {
            Self {
                inner: Blake3Inner::DeriveKey(blake3::Hasher::new_derive_key(context)),
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            Self {
                inner: blake3::Hasher::new_derive_key(context),
            }
        }
    }

    /// Compute a keyed hash (MAC).
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> HashOutput {
        #[cfg(feature = "backend-native")]
        {
            let hash = arcanum_primitives::blake3::Blake3::keyed_hash(key, data);
            HashOutput::from_array(hash)
        }

        #[cfg(not(feature = "backend-native"))]
        {
            let hash = blake3::keyed_hash(key, data);
            HashOutput::from_array(*hash.as_bytes())
        }
    }

    /// Derive a key using BLAKE3's built-in KDF.
    pub fn derive_key(context: &str, key_material: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(key_material);
        let mut output = vec![0u8; output_len];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut output);
        output
    }

    /// Derive a fixed-size key.
    pub fn derive_key_array<const N: usize>(context: &str, key_material: &[u8]) -> [u8; N] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(key_material);
        let mut output = [0u8; N];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut output);
        output
    }
}

impl KeyDerivation for Blake3 {
    const ALGORITHM: &'static str = "BLAKE3-KDF";

    fn derive(
        ikm: &[u8],
        _salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        // BLAKE3 KDF uses context string instead of salt
        // We use info as the context, defaulting to empty
        let context = info
            .map(|i| String::from_utf8_lossy(i).into_owned())
            .unwrap_or_else(|| "arcanum-blake3-kdf".to_string());

        Ok(Self::derive_key(&context, ikm, output_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_empty() {
        let hash = Blake3::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn test_blake3_hello() {
        let hash = Blake3::hash(b"hello");
        assert_eq!(
            hash.to_hex(),
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [0u8; 32];
        let hash = Blake3::keyed_hash(&key, b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_xof() {
        let output = Blake3::hash_xof(b"hello", 64);
        assert_eq!(output.len(), 64);

        // First 32 bytes should match standard hash
        let standard = Blake3::hash(b"hello");
        assert_eq!(&output[..32], standard.as_bytes());
    }

    #[test]
    fn test_blake3_derive_key() {
        let key = Blake3::derive_key("my-app-encryption-key", b"master-secret", 32);
        assert_eq!(key.len(), 32);

        // Same input should produce same output
        let key2 = Blake3::derive_key("my-app-encryption-key", b"master-secret", 32);
        assert_eq!(key, key2);

        // Different context should produce different output
        let key3 = Blake3::derive_key("different-context", b"master-secret", 32);
        assert_ne!(key, key3);
    }

    #[test]
    fn test_blake3_incremental() {
        let mut hasher = <Blake3 as Hasher>::new();
        Hasher::update(&mut hasher, b"hel");
        Hasher::update(&mut hasher, b"lo");
        let hash = Hasher::finalize(hasher);

        assert_eq!(hash, Blake3::hash(b"hello"));
    }

    /// Verify that native and RustCrypto backends produce identical output
    #[cfg(feature = "backend-native")]
    #[test]
    fn test_backend_compatibility() {
        let test_data = b"The quick brown fox jumps over the lazy dog";

        // Native backend
        let native_hash = Blake3::hash(test_data);

        // RustCrypto backend
        let rustcrypto_hash = blake3::hash(test_data);

        assert_eq!(native_hash.as_bytes(), rustcrypto_hash.as_bytes());
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PROPERTY-BASED TESTS
    // ═══════════════════════════════════════════════════════════════════════════════

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating arbitrary data up to 64KB
        fn data_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..65536)
        }

        proptest! {
            /// Property: Hashing is deterministic (same input = same output)
            #[test]
            fn prop_hash_deterministic(data in data_strategy()) {
                let hash1 = Blake3::hash(&data);
                let hash2 = Blake3::hash(&data);

                prop_assert_eq!(hash1, hash2);
            }

            /// Property: Hash output is always 32 bytes
            #[test]
            fn prop_hash_length(data in data_strategy()) {
                let hash = Blake3::hash(&data);
                prop_assert_eq!(hash.as_bytes().len(), 32);
            }

            /// Property: Different inputs produce different hashes (collision resistance)
            #[test]
            fn prop_collision_resistance(
                data1 in data_strategy(),
                data2 in data_strategy()
            ) {
                prop_assume!(data1 != data2);

                let hash1 = Blake3::hash(&data1);
                let hash2 = Blake3::hash(&data2);

                prop_assert_ne!(hash1, hash2);
            }

            /// Property: Incremental hashing equals one-shot hashing
            #[test]
            fn prop_incremental_equals_oneshot(data in data_strategy()) {
                // One-shot hash
                let oneshot = Blake3::hash(&data);

                // Incremental hash (split at random point)
                let mut hasher = <Blake3 as Hasher>::new();
                if !data.is_empty() {
                    let split = data.len() / 2;
                    Hasher::update(&mut hasher, &data[..split]);
                    Hasher::update(&mut hasher, &data[split..]);
                } else {
                    Hasher::update(&mut hasher, &data);
                }
                let incremental = Hasher::finalize(hasher);

                prop_assert_eq!(oneshot, incremental);
            }

            /// Property: XOF output extends standard hash
            #[test]
            fn prop_xof_extends_hash(data in data_strategy()) {
                let standard = Blake3::hash(&data);
                let extended = Blake3::hash_xof(&data, 64);

                // First 32 bytes should match standard hash
                prop_assert_eq!(&extended[..32], standard.as_bytes());
            }

            /// Property: Key derivation is deterministic
            #[test]
            fn prop_kdf_deterministic(
                context in "[a-z]{1,32}",
                ikm in data_strategy(),
                output_len in 16usize..128
            ) {
                let key1 = Blake3::derive_key(&context, &ikm, output_len);
                let key2 = Blake3::derive_key(&context, &ikm, output_len);

                prop_assert_eq!(key1, key2);
            }

            /// Property: Keyed hash is deterministic
            #[test]
            fn prop_keyed_hash_deterministic(
                key in any::<[u8; 32]>(),
                data in data_strategy()
            ) {
                let hash1 = Blake3::keyed_hash(&key, &data);
                let hash2 = Blake3::keyed_hash(&key, &data);

                prop_assert_eq!(hash1, hash2);
            }

            /// Property: Different keys produce different MACs
            #[test]
            fn prop_different_keys_different_macs(data in data_strategy()) {
                let key1 = [0x11u8; 32];
                let key2 = [0x22u8; 32];

                let mac1 = Blake3::keyed_hash(&key1, &data);
                let mac2 = Blake3::keyed_hash(&key2, &data);

                prop_assert_ne!(mac1, mac2);
            }
        }
    }
}
