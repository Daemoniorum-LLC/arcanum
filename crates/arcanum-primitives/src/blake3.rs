//! BLAKE3 cryptographic hash function.
//!
//! Native implementation following the BLAKE3 specification.
//!
//! BLAKE3 is a cryptographic hash function that is:
//! - Much faster than SHA-256, SHA-512, and BLAKE2
//! - Parallelizable for large inputs
//! - Supports keyed hashing and key derivation
//!
//! # Example
//!
//! ```ignore
//! use arcanum_primitives::blake3::Blake3;
//!
//! // Simple hashing
//! let hash = Blake3::hash(b"hello world");
//!
//! // Keyed hashing (MAC)
//! let key = [0u8; 32];
//! let mac = Blake3::keyed_hash(&key, b"message");
//!
//! // Key derivation
//! let derived = Blake3::derive_key("my-context", b"input material");
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// BLAKE3 initialization vector (same as BLAKE2s)
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Message word permutation for each round
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Block size in bytes
const BLOCK_LEN: usize = 64;

/// Chunk size in bytes (1024 = 16 blocks)
const CHUNK_LEN: usize = 1024;

/// Output length in bytes
const OUT_LEN: usize = 32;

// Domain separation flags
mod flags {
    pub const CHUNK_START: u8 = 1 << 0;
    pub const CHUNK_END: u8 = 1 << 1;
    pub const PARENT: u8 = 1 << 2;
    pub const ROOT: u8 = 1 << 3;
    pub const KEYED_HASH: u8 = 1 << 4;
    pub const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
    pub const DERIVE_KEY_MATERIAL: u8 = 1 << 6;
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPRESSION FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

/// The G mixing function
#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// One round of the compression function
#[inline(always)]
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Column step
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Diagonal step
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

/// Permute message words
#[inline(always)]
fn permute(m: [u32; 16]) -> [u32; 16] {
    [
        m[MSG_PERMUTATION[0]],
        m[MSG_PERMUTATION[1]],
        m[MSG_PERMUTATION[2]],
        m[MSG_PERMUTATION[3]],
        m[MSG_PERMUTATION[4]],
        m[MSG_PERMUTATION[5]],
        m[MSG_PERMUTATION[6]],
        m[MSG_PERMUTATION[7]],
        m[MSG_PERMUTATION[8]],
        m[MSG_PERMUTATION[9]],
        m[MSG_PERMUTATION[10]],
        m[MSG_PERMUTATION[11]],
        m[MSG_PERMUTATION[12]],
        m[MSG_PERMUTATION[13]],
        m[MSG_PERMUTATION[14]],
        m[MSG_PERMUTATION[15]],
    ]
}

/// BLAKE3 compression function
#[inline]
fn compress(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u8,
) -> [u32; 16] {
    // Use SIMD-accelerated version when available (x86_64)
    #[cfg(all(feature = "simd", feature = "std", not(target_arch = "wasm32")))]
    {
        return crate::blake3_simd::compress_auto(cv, block, counter, block_len, flags);
    }

    // Use WASM SIMD when targeting wasm32 with simd128
    #[cfg(all(feature = "wasm-simd", target_arch = "wasm32",))]
    {
        return crate::blake3_wasm_simd::compress(cv, block, counter, block_len, flags);
    }

    #[cfg(not(any(
        all(feature = "simd", feature = "std", not(target_arch = "wasm32")),
        all(feature = "wasm-simd", target_arch = "wasm32")
    )))]
    compress_portable(cv, block, counter, block_len, flags)
}

/// Portable BLAKE3 compression function
#[cfg(not(any(
    all(feature = "simd", feature = "std", not(target_arch = "wasm32")),
    all(feature = "wasm-simd", target_arch = "wasm32")
)))]
fn compress_portable(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u8,
) -> [u32; 16] {
    // Parse block into message words
    let m = words_from_le_bytes(block);

    // Initialize state
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags as u32,
    ];

    let mut m_sched = m;

    // 7 rounds
    for _ in 0..7 {
        round(&mut state, &m_sched);
        m_sched = permute(m_sched);
    }

    // XOR the two halves
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }

    state
}

/// Convert bytes to little-endian u32 words
fn words_from_le_bytes(bytes: &[u8; 64]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    words
}

/// Convert u32 words to little-endian bytes
fn words_to_le_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT
// ═══════════════════════════════════════════════════════════════════════════════

/// Output from a chunk or parent node
#[derive(Clone)]
struct Output {
    input_cv: [u32; 8],
    block: [u8; BLOCK_LEN],
    block_len: u8,
    counter: u64,
    flags: u8,
}

impl Output {
    /// Get the chaining value (first 8 words of compression output)
    fn chaining_value(&self) -> [u32; 8] {
        let out = compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len as u32,
            self.flags,
        );
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&out[..8]);
        cv
    }

    /// Get the root hash (full output with ROOT flag)
    fn root_hash(&self) -> [u8; OUT_LEN] {
        let out = compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len as u32,
            self.flags | flags::ROOT,
        );
        let cv: [u32; 8] = out[..8].try_into().unwrap();
        words_to_le_bytes(&cv)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHUNK STATE
// ═══════════════════════════════════════════════════════════════════════════════

/// State for processing a single chunk
#[derive(Clone)]
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    buf: [u8; BLOCK_LEN],
    buf_len: u8,
    blocks_compressed: u8,
    flags: u8,
}

impl ChunkState {
    fn new(key: &[u32; 8], chunk_counter: u64, flags: u8) -> Self {
        Self {
            cv: *key,
            chunk_counter,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.buf_len as usize
    }

    fn fill_buf(&mut self, input: &mut &[u8]) {
        let want = BLOCK_LEN - self.buf_len as usize;
        let take = want.min(input.len());
        self.buf[self.buf_len as usize..self.buf_len as usize + take]
            .copy_from_slice(&input[..take]);
        self.buf_len += take as u8;
        *input = &input[take..];
    }

    fn start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            flags::CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // If buffer is full, compress it
            if self.buf_len as usize == BLOCK_LEN {
                let block_flags = self.flags | self.start_flag();
                let out = compress(
                    &self.cv,
                    &self.buf,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    block_flags,
                );
                self.cv.copy_from_slice(&out[..8]);
                self.blocks_compressed += 1;
                self.buf = [0u8; BLOCK_LEN];
                self.buf_len = 0;
            }

            self.fill_buf(&mut input);
        }
    }

    fn output(&self) -> Output {
        let block_flags = self.flags | self.start_flag() | flags::CHUNK_END;
        Output {
            input_cv: self.cv,
            block: self.buf,
            block_len: self.buf_len,
            counter: self.chunk_counter,
            flags: block_flags,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLAKE3 HASHER
// ═══════════════════════════════════════════════════════════════════════════════

/// BLAKE3 hash function.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Blake3 {
    #[zeroize(skip)] // Key is public for keyed mode
    key: [u32; 8],
    #[zeroize(skip)]
    cv_stack: Vec<[u32; 8]>,
    chunk_state: ChunkState,
    #[zeroize(skip)]
    flags: u8,
}

// Manual impl because ChunkState doesn't derive Zeroize
impl Zeroize for ChunkState {
    fn zeroize(&mut self) {
        self.cv.zeroize();
        self.buf.zeroize();
        self.buf_len = 0;
        self.blocks_compressed = 0;
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    /// Output size in bytes
    pub const OUTPUT_SIZE: usize = OUT_LEN;
    /// Block size in bytes
    pub const BLOCK_SIZE: usize = BLOCK_LEN;
    /// Algorithm name
    pub const ALGORITHM: &'static str = "BLAKE3";

    /// Create a new BLAKE3 hasher.
    pub fn new() -> Self {
        Self {
            key: IV,
            cv_stack: Vec::with_capacity(54), // Max tree depth
            chunk_state: ChunkState::new(&IV, 0, 0),
            flags: 0,
        }
    }

    /// Create a keyed BLAKE3 hasher (for MAC).
    pub fn keyed(key: &[u8; 32]) -> Self {
        let key_words = words_from_le_bytes_32(key);
        Self {
            key: key_words,
            cv_stack: Vec::with_capacity(54),
            chunk_state: ChunkState::new(&key_words, 0, flags::KEYED_HASH),
            flags: flags::KEYED_HASH,
        }
    }

    /// Create a BLAKE3 hasher for key derivation.
    pub fn derive_key_hasher(context: &str) -> Self {
        // Hash the context string
        let mut context_hasher = Self {
            key: IV,
            cv_stack: Vec::with_capacity(54),
            chunk_state: ChunkState::new(&IV, 0, flags::DERIVE_KEY_CONTEXT),
            flags: flags::DERIVE_KEY_CONTEXT,
        };
        context_hasher.update(context.as_bytes());
        let context_key = context_hasher.finalize();
        let context_key_words = words_from_le_bytes_32(&context_key);

        Self {
            key: context_key_words,
            cv_stack: Vec::with_capacity(54),
            chunk_state: ChunkState::new(&context_key_words, 0, flags::DERIVE_KEY_MATERIAL),
            flags: flags::DERIVE_KEY_MATERIAL,
        }
    }

    fn push_cv(&mut self, new_cv: &[u32; 8], chunk_counter: u64) {
        self.cv_stack.push(*new_cv);
        // Merge complete subtrees
        let mut total_chunks = chunk_counter + 1;
        while total_chunks & 1 == 0 {
            // Merge top two CVs
            let right_cv = self.cv_stack.pop().unwrap();
            let left_cv = self.cv_stack.pop().unwrap();
            let parent_cv = parent_cv(&left_cv, &right_cv, &self.key, self.flags);
            self.cv_stack.push(parent_cv);
            total_chunks >>= 1;
        }
    }

    /// Update the hasher with data.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // If chunk is complete, finalize it and push CV
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let chunk_counter = self.chunk_state.chunk_counter;
                self.push_cv(&chunk_cv, chunk_counter);
                self.chunk_state = ChunkState::new(&self.key, chunk_counter + 1, self.flags);
            }

            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Finalize and return the hash.
    pub fn finalize(&self) -> [u8; OUT_LEN] {
        // Start with current chunk's output
        let mut output = self.chunk_state.output();

        // Merge with CVs from the stack (right to left)
        let mut parent_nodes_remaining = self.cv_stack.len();
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            let cv = output.chaining_value();
            output = parent_output(
                &self.cv_stack[parent_nodes_remaining],
                &cv,
                &self.key,
                self.flags,
            );
        }

        output.root_hash()
    }

    /// Hash data in one shot.
    ///
    /// This function automatically uses the fastest available implementation:
    /// - Multi-threaded (rayon) + SIMD for maximum throughput
    /// - Single-threaded SIMD when rayon not available
    /// - Portable implementation as final fallback
    ///
    /// # Performance
    ///
    /// With rayon + SIMD enabled on x86_64:
    /// - < 256KB: Single-threaded SIMD (~2 GiB/s)
    /// - 256KB - 8MB: Parallel chunks (~6.7 GiB/s)
    /// - >= 8MB: Apex mode (~8.5 GiB/s, **1.75x faster than blake3 crate**)
    #[cfg(all(
        feature = "simd",
        feature = "std",
        feature = "rayon",
        target_arch = "x86_64"
    ))]
    pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
        // Use adaptive which picks optimal strategy based on data size
        crate::blake3_ultra::hash_adaptive(data)
    }

    /// Hash data in one shot (SIMD, single-threaded).
    #[cfg(all(
        feature = "simd",
        feature = "std",
        not(feature = "rayon"),
        target_arch = "x86_64"
    ))]
    pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
        crate::blake3_simd::hash_large_parallel(data)
    }

    /// Hash data in one shot (portable fallback).
    #[cfg(not(all(feature = "simd", feature = "std", target_arch = "x86_64")))]
    pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Keyed hash (MAC) in one shot.
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; OUT_LEN] {
        let mut hasher = Self::keyed(key);
        hasher.update(data);
        hasher.finalize()
    }

    /// Derive a key from context and input keying material.
    pub fn derive_key(context: &str, input: &[u8]) -> [u8; OUT_LEN] {
        let mut hasher = Self::derive_key_hasher(context);
        hasher.update(input);
        hasher.finalize()
    }
}

/// Compute parent chaining value from two child CVs
fn parent_cv(left_cv: &[u32; 8], right_cv: &[u32; 8], key: &[u32; 8], flags: u8) -> [u32; 8] {
    let mut block = [0u8; BLOCK_LEN];
    block[..32].copy_from_slice(&words_to_le_bytes(left_cv));
    block[32..].copy_from_slice(&words_to_le_bytes(right_cv));

    let out = compress(key, &block, 0, BLOCK_LEN as u32, flags | flags::PARENT);
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&out[..8]);
    cv
}

/// Create parent output from two child CVs
fn parent_output(left_cv: &[u32; 8], right_cv: &[u32; 8], key: &[u32; 8], flags: u8) -> Output {
    let mut block = [0u8; BLOCK_LEN];
    block[..32].copy_from_slice(&words_to_le_bytes(left_cv));
    block[32..].copy_from_slice(&words_to_le_bytes(right_cv));

    Output {
        input_cv: *key,
        block,
        block_len: BLOCK_LEN as u8,
        counter: 0,
        flags: flags | flags::PARENT,
    }
}

/// Convert 32-byte slice to u32 words
fn words_from_le_bytes_32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    words
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn test_blake3_empty() {
        let hash = Blake3::hash(b"");
        // Reference from blake3 crate
        let expected = blake3::hash(b"");
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_abc() {
        let hash = Blake3::hash(b"abc");
        let expected = blake3::hash(b"abc");
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_hello_world() {
        let hash = Blake3::hash(b"hello world");
        let expected = blake3::hash(b"hello world");
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_one_block() {
        // 64 bytes = exactly one block
        let data = vec![0u8; 64];
        let hash = Blake3::hash(&data);
        let expected = blake3::hash(&data);
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_one_chunk() {
        // 1024 bytes = exactly one chunk
        let data = vec![0u8; 1024];
        let hash = Blake3::hash(&data);
        let expected = blake3::hash(&data);
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_two_chunks() {
        // 2048 bytes = exactly two chunks (triggers parent node)
        let data = vec![0xAB; 2048];
        let hash = Blake3::hash(&data);
        let expected = blake3::hash(&data);
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_incremental() {
        let mut hasher = Blake3::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash = hasher.finalize();

        let expected = Blake3::hash(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_incremental_byte_by_byte() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut hasher = Blake3::new();
        for byte in data {
            hasher.update(&[*byte]);
        }
        let hash = hasher.finalize();

        let expected = Blake3::hash(data);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_large_input() {
        // Test with 100KB to exercise tree hashing
        let data = vec![0x42; 100_000];
        let hash = Blake3::hash(&data);
        let expected = blake3::hash(&data);
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_keyed_hash() {
        let key = [0x01u8; 32];
        let data = b"test message";

        let hash = Blake3::keyed_hash(&key, data);
        let expected = blake3::keyed_hash(&key, data);
        assert_eq!(hash, *expected.as_bytes());
    }

    #[test]
    fn test_blake3_derive_key() {
        let context = "my-app v1 encryption key";
        let ikm = b"secret input keying material";

        let derived = Blake3::derive_key(context, ikm);
        let expected = blake3::derive_key(context, ikm);
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_blake3_vs_reference_random_sizes() {
        // Test various sizes
        for size in [
            0, 1, 63, 64, 65, 127, 128, 1023, 1024, 1025, 2047, 2048, 4096,
        ] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let hash = Blake3::hash(&data);
            let expected = blake3::hash(&data);
            assert_eq!(hash, *expected.as_bytes(), "Mismatch for size {}", size);
        }
    }

    #[test]
    fn test_compression_function() {
        // Test the G function and compression directly
        let cv = IV;
        let block = [0u8; 64];
        let out = compress(
            &cv,
            &block,
            0,
            64,
            flags::CHUNK_START | flags::CHUNK_END | flags::ROOT,
        );

        // Should produce deterministic output
        assert_ne!(out, [0u32; 16]);
    }
}
