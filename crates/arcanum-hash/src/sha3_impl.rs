//! SHA-3 (Keccak) hash functions.
//!
//! SHA-3 is based on the Keccak sponge construction and provides:
//! - **SHA3-256**: 256-bit output
//! - **SHA3-512**: 512-bit output
//! - **SHAKE128**: Extendable-output function (XOF)
//! - **SHAKE256**: Extendable-output function (XOF)

use crate::traits::{ExtendableOutput, HashOutput, Hasher};
use digest::{Digest, ExtendableOutput as DigestXof, Update, XofReader};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

// ═══════════════════════════════════════════════════════════════════════════════
// SHA3-256
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA3-256 hash function.
#[derive(Clone)]
pub struct Sha3_256 {
    inner: sha3::Sha3_256,
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha3_256 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 136; // 1088 bits
    const ALGORITHM: &'static str = "SHA3-256";

    fn new() -> Self {
        Self {
            inner: sha3::Sha3_256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self) -> HashOutput {
        let result = self.inner.finalize();
        HashOutput::from_array(result.into())
    }

    fn reset(&mut self) {
        self.inner = sha3::Sha3_256::new();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA3-512
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA3-512 hash function.
#[derive(Clone)]
pub struct Sha3_512 {
    inner: sha3::Sha3_512,
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha3_512 {
    const OUTPUT_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 72; // 576 bits
    const ALGORITHM: &'static str = "SHA3-512";

    fn new() -> Self {
        Self {
            inner: sha3::Sha3_512::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self) -> HashOutput {
        let result = self.inner.finalize();
        HashOutput::from_array(result.into())
    }

    fn reset(&mut self) {
        self.inner = sha3::Sha3_512::new();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHAKE128 (XOF)
// ═══════════════════════════════════════════════════════════════════════════════

/// SHAKE128 extendable-output function.
///
/// Can produce arbitrary-length output. Security level: 128 bits.
#[derive(Clone)]
pub struct Shake128 {
    inner: sha3::Shake128,
}

impl ExtendableOutput for Shake128 {
    const ALGORITHM: &'static str = "SHAKE128";

    fn new() -> Self {
        Self {
            inner: sha3::Shake128::default(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.inner, data);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        // Note: This consumes self in the underlying impl, so we clone
        let reader = self.inner.clone().finalize_xof();
        let mut reader = reader;
        reader.read(output);
    }

    fn finalize_xof(self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        let mut reader = self.inner.finalize_xof();
        reader.read(&mut output);
        output
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHAKE256 (XOF)
// ═══════════════════════════════════════════════════════════════════════════════

/// SHAKE256 extendable-output function.
///
/// Can produce arbitrary-length output. Security level: 256 bits.
#[derive(Clone)]
pub struct Shake256 {
    inner: sha3::Shake256,
}

impl ExtendableOutput for Shake256 {
    const ALGORITHM: &'static str = "SHAKE256";

    fn new() -> Self {
        Self {
            inner: sha3::Shake256::default(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.inner, data);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        let reader = self.inner.clone().finalize_xof();
        let mut reader = reader;
        reader.read(output);
    }

    fn finalize_xof(self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        let mut reader = self.inner.finalize_xof();
        reader.read(&mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = Sha3_256::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_512_empty() {
        let hash = Sha3_512::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn test_shake128() {
        let output = Shake128::hash_xof(b"hello", 32);
        assert_eq!(output.len(), 32);

        // Longer output
        let output_long = Shake128::hash_xof(b"hello", 64);
        assert_eq!(output_long.len(), 64);

        // First 32 bytes should match
        assert_eq!(&output_long[..32], &output[..]);
    }

    #[test]
    fn test_shake256() {
        let output = Shake256::hash_xof(b"hello", 64);
        assert_eq!(output.len(), 64);
    }
}
