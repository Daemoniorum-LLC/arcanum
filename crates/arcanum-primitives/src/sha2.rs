//! SHA-2 hash function family (SHA-256, SHA-384, SHA-512).
//!
//! Native implementation following FIPS 180-4.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_primitives::sha2::{Sha256, Sha384, Sha512};
//!
//! let hash256 = Sha256::hash(b"hello world");
//! assert_eq!(hash256.len(), 32);
//!
//! let hash384 = Sha384::hash(b"hello world");
//! assert_eq!(hash384.len(), 48);
//!
//! let hash512 = Sha512::hash(b"hello world");
//! assert_eq!(hash512.len(), 64);
//! ```

use crate::ct::ct_zeroize;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-256 CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const H256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-256 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-256 hash function.
///
/// Produces a 256-bit (32 byte) hash value.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha256 {
    /// Current hash state
    state: [u32; 8],
    /// Unprocessed data buffer
    buffer: [u8; 64],
    /// Number of bytes in buffer
    buffer_len: usize,
    /// Total bytes processed
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Block size in bytes (512 bits)
    pub const BLOCK_SIZE: usize = 64;
    /// Output size in bytes (256 bits)
    pub const OUTPUT_SIZE: usize = 32;
    /// Algorithm name
    pub const ALGORITHM: &'static str = "SHA-256";

    /// Create a new SHA-256 hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            state: H256_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update the hasher with data.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // If we have buffered data, try to fill the buffer
        if self.buffer_len > 0 {
            let space = Self::BLOCK_SIZE - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            // If buffer is full, process it
            if self.buffer_len == Self::BLOCK_SIZE {
                let block = self.buffer;
                self.compress_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process full blocks directly from input
        while offset + Self::BLOCK_SIZE <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.compress_block(&block);
            offset += Self::BLOCK_SIZE;
        }

        // Buffer any remaining data
        if offset < data.len() {
            let remainder = data.len() - offset;
            self.buffer[..remainder].copy_from_slice(&data[offset..]);
            self.buffer_len = remainder;
        }
    }

    /// Finalize the hash and return the digest.
    pub fn finalize(mut self) -> [u8; 32] {
        // Padding
        let bit_len = self.total_len.wrapping_mul(8);

        // Append 0x80
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for length, pad and compress
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..64].fill(0);
            let block = self.buffer;
            self.compress_block(&block);
            self.buffer.fill(0);
            self.buffer_len = 0;
        } else {
            self.buffer[self.buffer_len..56].fill(0);
        }

        // Append length in bits (big-endian)
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress_block(&block);

        // Produce output
        let mut output = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        output
    }

    /// Hash data in one shot.
    #[inline]
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Reset the hasher to initial state.
    pub fn reset(&mut self) {
        self.state = H256_INIT;
        ct_zeroize(&mut self.buffer);
        self.buffer_len = 0;
        self.total_len = 0;
    }

    /// Compress a single 64-byte block.
    #[inline(always)]
    fn compress_block(&mut self, block: &[u8; 64]) {
        // Use x86_64 SIMD when available
        #[cfg(all(feature = "simd", feature = "std", not(target_arch = "wasm32")))]
        {
            crate::sha2_simd::compress_block_auto(&mut self.state, block);
            return;
        }

        // Use WASM SIMD when targeting wasm32 with wasm-simd feature
        // NOTE: target_feature cfg removed - it's always set via .cargo/config.toml
        #[cfg(all(feature = "wasm-simd", target_arch = "wasm32",))]
        {
            crate::sha256_wasm_simd::compress_block(&mut self.state, block);
            return;
        }

        #[cfg(not(any(
            all(feature = "simd", feature = "std", not(target_arch = "wasm32")),
            all(feature = "wasm-simd", target_arch = "wasm32")
        )))]
        self.compress_block_portable(block);
    }

    /// Portable SHA-256 compression function.
    fn compress_block_portable(&mut self, block: &[u8; 64]) {
        // Parse block into message schedule
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        // Extend message schedule
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // 64 rounds
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);

            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to current hash value
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-512 CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-512 round constants
const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 initial hash values
const H512_INIT: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-512 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-512 hash function.
///
/// Produces a 512-bit (64 byte) hash value.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha512 {
    /// Current hash state
    state: [u64; 8],
    /// Unprocessed data buffer
    buffer: [u8; 128],
    /// Number of bytes in buffer
    buffer_len: usize,
    /// Total bytes processed (low 64 bits)
    total_len_lo: u64,
    /// Total bytes processed (high 64 bits)
    total_len_hi: u64,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Block size in bytes (1024 bits)
    pub const BLOCK_SIZE: usize = 128;
    /// Output size in bytes (512 bits)
    pub const OUTPUT_SIZE: usize = 64;
    /// Algorithm name
    pub const ALGORITHM: &'static str = "SHA-512";

    /// Create a new SHA-512 hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            state: H512_INIT,
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len_lo: 0,
            total_len_hi: 0,
        }
    }

    /// Update the hasher with data.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Update total length (128-bit counter)
        let (new_lo, overflow) = self.total_len_lo.overflowing_add(data.len() as u64);
        self.total_len_lo = new_lo;
        if overflow {
            self.total_len_hi = self.total_len_hi.wrapping_add(1);
        }

        // If we have buffered data, try to fill the buffer
        if self.buffer_len > 0 {
            let space = Self::BLOCK_SIZE - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == Self::BLOCK_SIZE {
                let block = self.buffer;
                self.compress_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + Self::BLOCK_SIZE <= data.len() {
            let block: [u8; 128] = data[offset..offset + 128].try_into().unwrap();
            self.compress_block(&block);
            offset += Self::BLOCK_SIZE;
        }

        // Buffer remainder
        if offset < data.len() {
            let remainder = data.len() - offset;
            self.buffer[..remainder].copy_from_slice(&data[offset..]);
            self.buffer_len = remainder;
        }
    }

    /// Finalize the hash and return the digest.
    pub fn finalize(mut self) -> [u8; 64] {
        // Calculate bit length (128-bit)
        let bit_len_lo = self.total_len_lo.wrapping_mul(8);
        let bit_len_hi = self
            .total_len_hi
            .wrapping_mul(8)
            .wrapping_add(self.total_len_lo >> 61);

        // Append 0x80
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Pad and compress if needed
        if self.buffer_len > 112 {
            self.buffer[self.buffer_len..128].fill(0);
            let block = self.buffer;
            self.compress_block(&block);
            self.buffer.fill(0);
            self.buffer_len = 0;
        } else {
            self.buffer[self.buffer_len..112].fill(0);
        }

        // Append length (128-bit big-endian)
        self.buffer[112..120].copy_from_slice(&bit_len_hi.to_be_bytes());
        self.buffer[120..128].copy_from_slice(&bit_len_lo.to_be_bytes());
        let block = self.buffer;
        self.compress_block(&block);

        // Produce output
        let mut output = [0u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            output[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }

        output
    }

    /// Hash data in one shot.
    #[inline]
    pub fn hash(data: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Compress a single 128-byte block.
    #[inline(always)]
    fn compress_block(&mut self, block: &[u8; 128]) {
        #[cfg(all(feature = "simd", feature = "std"))]
        {
            crate::sha2_simd::compress_block_512_auto(&mut self.state, block);
            return;
        }

        #[cfg(not(all(feature = "simd", feature = "std")))]
        self.compress_block_portable(block);
    }

    /// Portable SHA-512 compression function.
    #[cfg(not(all(feature = "simd", feature = "std")))]
    fn compress_block_portable(&mut self, block: &[u8; 128]) {
        // Parse block into message schedule
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        // Extend message schedule
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // 80 rounds
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);

            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add to state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-384 CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-384 initial hash values (first 64 bits of fractional parts of square roots of 9th-16th primes)
const H384_INIT: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-384 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-384 hash function.
///
/// Produces a 384-bit (48 byte) hash value.
/// Uses the same algorithm as SHA-512 but with different initial values
/// and a truncated output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha384 {
    /// Current hash state
    state: [u64; 8],
    /// Unprocessed data buffer
    buffer: [u8; 128],
    /// Number of bytes in buffer
    buffer_len: usize,
    /// Total bytes processed (low 64 bits)
    total_len_lo: u64,
    /// Total bytes processed (high 64 bits)
    total_len_hi: u64,
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
    /// Block size in bytes (1024 bits)
    pub const BLOCK_SIZE: usize = 128;
    /// Output size in bytes (384 bits)
    pub const OUTPUT_SIZE: usize = 48;
    /// Algorithm name
    pub const ALGORITHM: &'static str = "SHA-384";

    /// Create a new SHA-384 hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            state: H384_INIT,
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len_lo: 0,
            total_len_hi: 0,
        }
    }

    /// Update the hasher with data.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Update total length (128-bit counter)
        let (new_lo, overflow) = self.total_len_lo.overflowing_add(data.len() as u64);
        self.total_len_lo = new_lo;
        if overflow {
            self.total_len_hi = self.total_len_hi.wrapping_add(1);
        }

        // If we have buffered data, try to fill the buffer
        if self.buffer_len > 0 {
            let space = Self::BLOCK_SIZE - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == Self::BLOCK_SIZE {
                let block = self.buffer;
                self.compress_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + Self::BLOCK_SIZE <= data.len() {
            let block: [u8; 128] = data[offset..offset + 128].try_into().unwrap();
            self.compress_block(&block);
            offset += Self::BLOCK_SIZE;
        }

        // Buffer remainder
        if offset < data.len() {
            let remainder = data.len() - offset;
            self.buffer[..remainder].copy_from_slice(&data[offset..]);
            self.buffer_len = remainder;
        }
    }

    /// Finalize the hash and return the digest.
    pub fn finalize(mut self) -> [u8; 48] {
        // Calculate bit length (128-bit)
        let bit_len_lo = self.total_len_lo.wrapping_mul(8);
        let bit_len_hi = self
            .total_len_hi
            .wrapping_mul(8)
            .wrapping_add(self.total_len_lo >> 61);

        // Append 0x80
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Pad and compress if needed
        if self.buffer_len > 112 {
            self.buffer[self.buffer_len..128].fill(0);
            let block = self.buffer;
            self.compress_block(&block);
            self.buffer.fill(0);
            self.buffer_len = 0;
        } else {
            self.buffer[self.buffer_len..112].fill(0);
        }

        // Append length (128-bit big-endian)
        self.buffer[112..120].copy_from_slice(&bit_len_hi.to_be_bytes());
        self.buffer[120..128].copy_from_slice(&bit_len_lo.to_be_bytes());
        let block = self.buffer;
        self.compress_block(&block);

        // Produce output - only first 48 bytes (6 words)
        let mut output = [0u8; 48];
        for i in 0..6 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        output
    }

    /// Hash data in one shot.
    #[inline]
    pub fn hash(data: &[u8]) -> [u8; 48] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Compress a single 128-byte block.
    /// Uses the same compression function as SHA-512 (with SIMD when available).
    #[inline(always)]
    fn compress_block(&mut self, block: &[u8; 128]) {
        #[cfg(all(feature = "simd", feature = "std"))]
        {
            crate::sha2_simd::compress_block_512_auto(&mut self.state, block);
            return;
        }

        #[cfg(not(all(feature = "simd", feature = "std")))]
        self.compress_block_portable(block);
    }

    /// Portable SHA-384 compression function (identical to SHA-512).
    #[cfg(not(all(feature = "simd", feature = "std")))]
    fn compress_block_portable(&mut self, block: &[u8; 128]) {
        // Parse block into message schedule
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        // Extend message schedule
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // 80 rounds
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);

            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add to state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS - TDD: Known Answer Tests from NIST
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SHA-256 Known Answer Tests (NIST FIPS 180-4)
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_empty() {
        let hash = Sha256::hash(b"");
        let expected =
            hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_abc() {
        let hash = Sha256::hash(b"abc");
        let expected =
            hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_448_bits() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha256::hash(msg);
        let expected =
            hex_to_bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_896_bits() {
        // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha256::hash(msg);
        let expected =
            hex_to_bytes("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_one_million_a() {
        // One million 'a' characters
        let msg = vec![b'a'; 1_000_000];
        let hash = Sha256::hash(&msg);
        let expected =
            hex_to_bytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_incremental() {
        // Test incremental hashing matches one-shot
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        hasher.update(b"def");
        let incremental = hasher.finalize();

        let oneshot = Sha256::hash(b"abcdef");
        assert_eq!(incremental, oneshot);
    }

    #[test]
    fn test_sha256_incremental_byte_by_byte() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mut hasher = Sha256::new();
        for byte in msg {
            hasher.update(&[*byte]);
        }
        let incremental = hasher.finalize();

        let oneshot = Sha256::hash(msg);
        assert_eq!(incremental, oneshot);
    }

    #[test]
    fn test_sha256_vs_reference() {
        // Compare against sha2 crate
        use sha2::{Digest, Sha256 as RefSha256};

        let test_cases = [
            b"".as_slice(),
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        ];

        for msg in test_cases {
            let our_hash = Sha256::hash(msg);
            let ref_hash = RefSha256::digest(msg);
            assert_eq!(
                our_hash.as_slice(),
                ref_hash.as_slice(),
                "Mismatch for: {:?}",
                msg
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SHA-512 Known Answer Tests (NIST FIPS 180-4)
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sha512_empty() {
        let hash = Sha512::hash(b"");
        let expected = hex_to_bytes(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_abc() {
        let hash = Sha512::hash(b"abc");
        let expected = hex_to_bytes(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_448_bits() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha512::hash(msg);
        let expected = hex_to_bytes(
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_896_bits() {
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha512::hash(msg);
        let expected = hex_to_bytes(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_vs_reference() {
        use sha2::{Digest, Sha512 as RefSha512};

        let test_cases = [b"".as_slice(), b"a", b"abc", b"message digest"];

        for msg in test_cases {
            let our_hash = Sha512::hash(msg);
            let ref_hash = RefSha512::digest(msg);
            assert_eq!(
                our_hash.as_slice(),
                ref_hash.as_slice(),
                "SHA-512 mismatch for: {:?}",
                msg
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SHA-384 Known Answer Tests (NIST FIPS 180-4)
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sha384_empty() {
        let hash = Sha384::hash(b"");
        let expected = hex_to_bytes(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_abc() {
        let hash = Sha384::hash(b"abc");
        let expected = hex_to_bytes(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_448_bits() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha384::hash(msg);
        let expected = hex_to_bytes(
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_896_bits() {
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha384::hash(msg);
        let expected = hex_to_bytes(
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        );
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_incremental() {
        let mut hasher = Sha384::new();
        hasher.update(b"abc");
        hasher.update(b"def");
        let incremental = hasher.finalize();

        let oneshot = Sha384::hash(b"abcdef");
        assert_eq!(incremental, oneshot);
    }

    #[test]
    fn test_sha384_vs_reference() {
        use sha2::{Digest, Sha384 as RefSha384};

        let test_cases = [
            b"".as_slice(),
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
        ];

        for msg in test_cases {
            let our_hash = Sha384::hash(msg);
            let ref_hash = RefSha384::digest(msg);
            assert_eq!(
                our_hash.as_slice(),
                ref_hash.as_slice(),
                "SHA-384 mismatch for: {:?}",
                msg
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Property tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_deterministic() {
        let msg = b"deterministic test";
        let hash1 = Sha256::hash(msg);
        let hash2 = Sha256::hash(msg);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_different_inputs() {
        let hash1 = Sha256::hash(b"hello");
        let hash2 = Sha256::hash(b"Hello");
        assert_ne!(hash1, hash2);
    }
}
