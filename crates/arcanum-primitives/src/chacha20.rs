//! ChaCha20 stream cipher.
//!
//! Native implementation following RFC 8439.
//!
//! ChaCha20 is a high-speed stream cipher designed by Daniel J. Bernstein.
//! It is widely used in TLS 1.3 and other protocols as part of ChaCha20-Poly1305.
//!
//! # SIMD Optimization
//!
//! On x86_64 platforms, this implementation uses SSE2 to process 4 blocks in parallel
//! when available. Runtime detection ensures the optimal path is selected automatically.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_primitives::chacha20::ChaCha20;
//!
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//!
//! let mut cipher = ChaCha20::new(&key, &nonce);
//! let mut data = b"hello world".to_vec();
//! cipher.apply_keystream(&mut data);
//! // data is now encrypted
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "simd")]
use crate::chacha20_simd;

#[cfg(all(feature = "wasm-simd", target_arch = "wasm32",))]
use crate::chacha20_wasm_simd;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// ChaCha20 block size in bytes
pub const BLOCK_SIZE: usize = 64;

/// ChaCha20 key size in bytes
pub const KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (RFC 8439 uses 12-byte nonce)
pub const NONCE_SIZE: usize = 12;

/// "expand 32-byte k" in little-endian u32s
const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

// ═══════════════════════════════════════════════════════════════════════════════
// QUARTER ROUND
// ═══════════════════════════════════════════════════════════════════════════════

/// The ChaCha20 quarter round operation.
///
/// This is the core building block of the cipher.
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Perform the inner block function (20 rounds).
#[inline(always)]
fn inner_block(state: &mut [u32; 16]) {
    // 10 double-rounds (20 rounds total)
    for _ in 0..10 {
        // Column rounds
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLOCK FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a single 64-byte keystream block.
///
/// This is the ChaCha20 block function as specified in RFC 8439.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // Initialize state
    let mut state = [0u32; 16];

    // Constants
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Counter (1 word)
    state[12] = counter;

    // Nonce (3 words)
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Save initial state
    let initial_state = state;

    // Apply 20 rounds
    inner_block(&mut state);

    // Add initial state (feedforward)
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }

    // Serialize output
    let mut output = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    output
}

// ═══════════════════════════════════════════════════════════════════════════════
// HCHACHA20 (for XChaCha20)
// ═══════════════════════════════════════════════════════════════════════════════

/// HChaCha20 - the core PRF used to derive subkeys for XChaCha20.
///
/// Takes a 256-bit key and 128-bit nonce, outputs a 256-bit subkey.
/// This is the ChaCha core function without the final addition,
/// outputting only words 0-3 and 12-15.
///
/// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha>
pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    // Initialize state (same as ChaCha20 but with 16-byte nonce in place of counter+nonce)
    let mut state = [0u32; 16];

    // Constants
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Nonce (4 words) - note: full 16 bytes, not counter + 12-byte nonce
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes(nonce[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Apply 20 rounds (NO feedforward for HChaCha20)
    inner_block(&mut state);

    // Output words 0-3 and 12-15 (256 bits total)
    let mut output = [0u8; 32];
    for i in 0..4 {
        output[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    for i in 0..4 {
        output[16 + i * 4..16 + (i + 1) * 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }

    output
}

// ═══════════════════════════════════════════════════════════════════════════════
// STREAM CIPHER
// ═══════════════════════════════════════════════════════════════════════════════

/// ChaCha20 stream cipher.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20 {
    /// 256-bit key
    key: [u8; KEY_SIZE],
    /// 96-bit nonce
    nonce: [u8; NONCE_SIZE],
    /// Block counter
    counter: u32,
    /// Buffered keystream block
    buffer: [u8; BLOCK_SIZE],
    /// Position in buffer
    buffer_pos: usize,
}

impl ChaCha20 {
    /// Create a new ChaCha20 cipher with the given key and nonce.
    ///
    /// Counter starts at 0.
    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
            counter: 0,
            buffer: [0u8; BLOCK_SIZE],
            buffer_pos: BLOCK_SIZE, // Empty buffer
        }
    }

    /// Create a new ChaCha20 cipher with the given key, nonce, and initial counter.
    pub fn new_with_counter(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], counter: u32) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
            counter,
            buffer: [0u8; BLOCK_SIZE],
            buffer_pos: BLOCK_SIZE,
        }
    }

    /// Apply keystream to data (XOR in place).
    ///
    /// This encrypts plaintext or decrypts ciphertext (same operation).
    ///
    /// On x86_64 with SSE2, uses SIMD to process 4 blocks in parallel for
    /// improved performance on large data.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        // If we have buffered data, process it first
        if self.buffer_pos < BLOCK_SIZE && !data.is_empty() {
            let buffered = BLOCK_SIZE - self.buffer_pos;
            let to_process = data.len().min(buffered);
            for i in 0..to_process {
                data[i] ^= self.buffer[self.buffer_pos + i];
            }
            self.buffer_pos += to_process;

            if to_process == data.len() {
                return;
            }

            // Process remaining data
            return self.apply_keystream(&mut data[to_process..]);
        }

        // Use SIMD path for large aligned chunks
        #[cfg(feature = "simd")]
        {
            if data.len() >= 256 {
                self.counter =
                    chacha20_simd::apply_keystream_auto(&self.key, &self.nonce, self.counter, data);
                self.buffer_pos = BLOCK_SIZE; // Invalidate buffer
                return;
            }
        }

        // Use WASM SIMD path when available (compile-time feature)
        #[cfg(all(feature = "wasm-simd", target_arch = "wasm32",))]
        {
            if data.len() >= 256 {
                self.counter = chacha20_wasm_simd::apply_keystream_auto(
                    &self.key,
                    &self.nonce,
                    self.counter,
                    data,
                );
                self.buffer_pos = BLOCK_SIZE; // Invalidate buffer
                return;
            }
        }

        // Scalar path for small data or when SIMD is not available
        for byte in data.iter_mut() {
            if self.buffer_pos >= BLOCK_SIZE {
                self.buffer = chacha20_block(&self.key, self.counter, &self.nonce);
                self.counter = self.counter.wrapping_add(1);
                self.buffer_pos = 0;
            }
            *byte ^= self.buffer[self.buffer_pos];
            self.buffer_pos += 1;
        }
    }

    /// Generate keystream bytes without XORing.
    pub fn keystream(&mut self, output: &mut [u8]) {
        output.fill(0);
        self.apply_keystream(output);
    }

    /// Seek to a specific block position.
    pub fn seek(&mut self, block_counter: u32) {
        self.counter = block_counter;
        self.buffer_pos = BLOCK_SIZE; // Invalidate buffer
    }

    /// Get the current block counter.
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

/// Encrypt/decrypt data with ChaCha20 (one-shot).
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut cipher = ChaCha20::new_with_counter(key, nonce, counter);
    cipher.apply_keystream(data);
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

    // RFC 8439 test vector for the quarter round
    #[test]
    fn test_quarter_round() {
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;

        // Test with indices 0, 1, 2, 3 (not the actual ChaCha indices, just a test)
        quarter_round(&mut state, 0, 1, 2, 3);

        // Expected results from RFC 8439 section 2.1
        assert_eq!(state[0], 0xea2a92f4);
        assert_eq!(state[1], 0xcb1cf8ce);
        assert_eq!(state[2], 0x4581472e);
        assert_eq!(state[3], 0x5881c4bb);
    }

    // RFC 8439 test vector for the block function
    #[test]
    fn test_chacha20_block_rfc8439() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex_to_bytes("000000090000004a00000000");
        let counter = 1u32;

        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let output = chacha20_block(&key, counter, &nonce);

        let expected = hex_to_bytes(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );

        assert_eq!(output.as_slice(), expected.as_slice());
    }

    // Test encryption/decryption round-trip
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"Hello, ChaCha20!";

        let mut ciphertext = plaintext.to_vec();
        chacha20_encrypt(&key, &nonce, 0, &mut ciphertext);

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        // Decrypt
        chacha20_encrypt(&key, &nonce, 0, &mut ciphertext);

        // Should recover plaintext
        assert_eq!(ciphertext.as_slice(), plaintext.as_slice());
    }

    // Test incremental encryption matches one-shot
    #[test]
    fn test_incremental_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // One-shot encryption
        let mut data1 = vec![0xAB; 200];
        chacha20_encrypt(&key, &nonce, 0, &mut data1);

        // Incremental encryption
        let mut data2 = vec![0xAB; 200];
        let mut cipher = ChaCha20::new(&key, &nonce);
        cipher.apply_keystream(&mut data2[..50]);
        cipher.apply_keystream(&mut data2[50..100]);
        cipher.apply_keystream(&mut data2[100..]);

        assert_eq!(data1, data2);
    }

    // Test byte-by-byte encryption
    #[test]
    fn test_byte_by_byte() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // One-shot
        let mut data1 = vec![0xAB; 100];
        chacha20_encrypt(&key, &nonce, 0, &mut data1);

        // Byte-by-byte
        let mut data2 = vec![0xAB; 100];
        let mut cipher = ChaCha20::new(&key, &nonce);
        for byte in data2.iter_mut() {
            cipher.apply_keystream(core::slice::from_mut(byte));
        }

        assert_eq!(data1, data2);
    }

    // Test seeking
    #[test]
    fn test_seek() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Encrypt blocks 0 and 1
        let mut block0 = [0u8; 64];
        let mut block1 = [0u8; 64];

        let mut cipher = ChaCha20::new(&key, &nonce);
        cipher.keystream(&mut block0);
        cipher.keystream(&mut block1);

        // Seek back to block 0 and verify
        cipher.seek(0);
        let mut block0_again = [0u8; 64];
        cipher.keystream(&mut block0_again);

        assert_eq!(block0, block0_again);
    }

    // Test against reference implementation via RFC vector
    #[test]
    fn test_vs_reference() {
        // RFC 8439 Section 2.4.2 test vector
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex_to_bytes("000000000000004a00000000");
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let plaintext = hex_to_bytes(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373\
             206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c\
             79206f6e652074697020666f7220746865206675747572652c2073756e73637265\
             656e20776f756c642062652069742e",
        );

        let expected_ciphertext = hex_to_bytes(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );

        let mut ciphertext = plaintext.clone();
        chacha20_encrypt(&key, &nonce, 1, &mut ciphertext);

        assert_eq!(ciphertext, expected_ciphertext);
    }

    // Test large data
    #[test]
    fn test_large_data() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // 100KB of data
        let mut data = vec![0xAB; 100_000];
        let original = data.clone();

        chacha20_encrypt(&key, &nonce, 0, &mut data);
        assert_ne!(data, original);

        chacha20_encrypt(&key, &nonce, 0, &mut data);
        assert_eq!(data, original);
    }

    // Test counter overflow behavior (should wrap)
    #[test]
    fn test_counter_wrap() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        let mut cipher = ChaCha20::new_with_counter(&key, &nonce, u32::MAX);
        let mut data = [0u8; 128]; // Two blocks
        cipher.apply_keystream(&mut data);

        // Counter should wrap to 0 after u32::MAX
        assert_eq!(cipher.counter(), 1);
    }
}
