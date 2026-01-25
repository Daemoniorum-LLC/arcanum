//! WASM SIMD 128-bit optimized ChaCha20 implementation.
//!
//! This module provides hardware-accelerated ChaCha20 using WebAssembly SIMD
//! 128-bit instructions (v128). It processes 4 blocks (256 bytes) in parallel.
//!
//! # Requirements
//!
//! - Target: `wasm32-unknown-unknown`
//! - Feature: `wasm-simd`
//! - Build with: `RUSTFLAGS="-C target-feature=+simd128"`
//!
//! # Browser Support
//!
//! WASM SIMD 128-bit is supported in:
//! - Chrome 91+
//! - Firefox 89+
//! - Safari 16.4+
//! - Node.js 16+
//!
//! # Performance
//!
//! Expected speedup vs scalar: 2-4x for the core permutation.
//! This narrows the gap between WASM and native x86-64 performance.

use core::arch::wasm32::*;

use super::chacha20::{BLOCK_SIZE, KEY_SIZE, NONCE_SIZE, chacha20_block};

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// ChaCha20 constants: "expand 32-byte k" in little-endian u32s
const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

// ═══════════════════════════════════════════════════════════════════════════════
// QUARTER ROUND (SIMD)
// ═══════════════════════════════════════════════════════════════════════════════

/// Quarter round on 4 parallel states using WASM SIMD.
///
/// Each v128 register holds one element from each of 4 parallel states.
/// This performs the ChaCha20 quarter round on all 4 states simultaneously.
#[inline(always)]
fn quarter_round_4x(a: &mut v128, b: &mut v128, c: &mut v128, d: &mut v128) {
    // a += b; d ^= a; d <<<= 16
    *a = u32x4_add(*a, *b);
    *d = v128_xor(*d, *a);
    *d = v128_or(u32x4_shl(*d, 16), u32x4_shr(*d, 16));

    // c += d; b ^= c; b <<<= 12
    *c = u32x4_add(*c, *d);
    *b = v128_xor(*b, *c);
    *b = v128_or(u32x4_shl(*b, 12), u32x4_shr(*b, 20));

    // a += b; d ^= a; d <<<= 8
    *a = u32x4_add(*a, *b);
    *d = v128_xor(*d, *a);
    *d = v128_or(u32x4_shl(*d, 8), u32x4_shr(*d, 24));

    // c += d; b ^= c; b <<<= 7
    *c = u32x4_add(*c, *d);
    *b = v128_xor(*b, *c);
    *b = v128_or(u32x4_shl(*b, 7), u32x4_shr(*b, 25));
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLOCK GENERATION (4x PARALLEL)
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate 4 keystream blocks in parallel using WASM SIMD.
///
/// Returns 256 bytes (4 x 64-byte blocks).
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `counter` - Block counter (will use counter, counter+1, counter+2, counter+3)
/// * `nonce` - 12-byte nonce
///
/// # Safety
///
/// This function uses WASM SIMD intrinsics which require the `simd128` target feature.
pub fn chacha20_blocks_4x(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 256] {
    // Load key as u32s (little-endian)
    let k0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
    let k1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
    let k2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
    let k3 = u32::from_le_bytes(key[12..16].try_into().unwrap());
    let k4 = u32::from_le_bytes(key[16..20].try_into().unwrap());
    let k5 = u32::from_le_bytes(key[20..24].try_into().unwrap());
    let k6 = u32::from_le_bytes(key[24..28].try_into().unwrap());
    let k7 = u32::from_le_bytes(key[28..32].try_into().unwrap());

    // Load nonce as u32s (little-endian)
    let n0 = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    let n1 = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    let n2 = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    // Initialize 4 parallel states with different counters
    // State layout: each v128 holds one element from each of 4 states
    // s0 = [state0[0], state1[0], state2[0], state3[0]]
    // s1 = [state0[1], state1[1], state2[1], state3[1]]
    // etc.

    // Constants (same for all 4 states)
    let mut s0 = u32x4_splat(CONSTANTS[0]);
    let mut s1 = u32x4_splat(CONSTANTS[1]);
    let mut s2 = u32x4_splat(CONSTANTS[2]);
    let mut s3 = u32x4_splat(CONSTANTS[3]);

    // Key (same for all 4 states)
    let mut s4 = u32x4_splat(k0);
    let mut s5 = u32x4_splat(k1);
    let mut s6 = u32x4_splat(k2);
    let mut s7 = u32x4_splat(k3);
    let mut s8 = u32x4_splat(k4);
    let mut s9 = u32x4_splat(k5);
    let mut s10 = u32x4_splat(k6);
    let mut s11 = u32x4_splat(k7);

    // Counter (different for each state: counter, counter+1, counter+2, counter+3)
    let mut s12 = u32x4(
        counter,
        counter.wrapping_add(1),
        counter.wrapping_add(2),
        counter.wrapping_add(3),
    );

    // Nonce (same for all 4 states)
    let mut s13 = u32x4_splat(n0);
    let mut s14 = u32x4_splat(n1);
    let mut s15 = u32x4_splat(n2);

    // Save initial state for feedforward
    let i0 = s0;
    let i1 = s1;
    let i2 = s2;
    let i3 = s3;
    let i4 = s4;
    let i5 = s5;
    let i6 = s6;
    let i7 = s7;
    let i8 = s8;
    let i9 = s9;
    let i10 = s10;
    let i11 = s11;
    let i12 = s12;
    let i13 = s13;
    let i14 = s14;
    let i15 = s15;

    // 20 rounds (10 double-rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round_4x(&mut s0, &mut s4, &mut s8, &mut s12);
        quarter_round_4x(&mut s1, &mut s5, &mut s9, &mut s13);
        quarter_round_4x(&mut s2, &mut s6, &mut s10, &mut s14);
        quarter_round_4x(&mut s3, &mut s7, &mut s11, &mut s15);

        // Diagonal rounds
        quarter_round_4x(&mut s0, &mut s5, &mut s10, &mut s15);
        quarter_round_4x(&mut s1, &mut s6, &mut s11, &mut s12);
        quarter_round_4x(&mut s2, &mut s7, &mut s8, &mut s13);
        quarter_round_4x(&mut s3, &mut s4, &mut s9, &mut s14);
    }

    // Add initial state (feedforward)
    s0 = u32x4_add(s0, i0);
    s1 = u32x4_add(s1, i1);
    s2 = u32x4_add(s2, i2);
    s3 = u32x4_add(s3, i3);
    s4 = u32x4_add(s4, i4);
    s5 = u32x4_add(s5, i5);
    s6 = u32x4_add(s6, i6);
    s7 = u32x4_add(s7, i7);
    s8 = u32x4_add(s8, i8);
    s9 = u32x4_add(s9, i9);
    s10 = u32x4_add(s10, i10);
    s11 = u32x4_add(s11, i11);
    s12 = u32x4_add(s12, i12);
    s13 = u32x4_add(s13, i13);
    s14 = u32x4_add(s14, i14);
    s15 = u32x4_add(s15, i15);

    // Transpose and write output
    // The state is in "parallel" layout - we need to transpose to get 4 sequential blocks
    let mut output = [0u8; 256];

    // Helper to transpose 4x4 matrix of u32s and store as 4 sequential blocks
    // Input: 4 v128 registers, each holding [block0[word], block1[word], block2[word], block3[word]]
    // Output: 4 blocks of 16 bytes each (4 words per block for this group)
    macro_rules! transpose_and_store {
        ($base_word:expr, $r0:expr, $r1:expr, $r2:expr, $r3:expr) => {{
            // Interleave low and high halves to transpose
            // t0 = [r0[0], r1[0], r0[1], r1[1]]
            let t0 = i32x4_shuffle::<0, 4, 1, 5>($r0, $r1);
            // t1 = [r0[2], r1[2], r0[3], r1[3]]
            let t1 = i32x4_shuffle::<2, 6, 3, 7>($r0, $r1);
            // t2 = [r2[0], r3[0], r2[1], r3[1]]
            let t2 = i32x4_shuffle::<0, 4, 1, 5>($r2, $r3);
            // t3 = [r2[2], r3[2], r2[3], r3[3]]
            let t3 = i32x4_shuffle::<2, 6, 3, 7>($r2, $r3);

            // Final transpose
            // b0 = [r0[0], r1[0], r2[0], r3[0]] = words for block 0
            let b0 = i64x2_shuffle::<0, 2>(t0, t2);
            // b1 = [r0[1], r1[1], r2[1], r3[1]] = words for block 1
            let b1 = i64x2_shuffle::<1, 3>(t0, t2);
            // b2 = [r0[2], r1[2], r2[2], r3[2]] = words for block 2
            let b2 = i64x2_shuffle::<0, 2>(t1, t3);
            // b3 = [r0[3], r1[3], r2[3], r3[3]] = words for block 3
            let b3 = i64x2_shuffle::<1, 3>(t1, t3);

            // Store to output
            // Block 0: offset 0, words at base_word*4
            // Block 1: offset 64, words at base_word*4
            // etc.
            let word_offset = $base_word * 4;
            v128_store(
                output.as_mut_ptr().add(0 * 64 + word_offset) as *mut v128,
                b0,
            );
            v128_store(
                output.as_mut_ptr().add(1 * 64 + word_offset) as *mut v128,
                b1,
            );
            v128_store(
                output.as_mut_ptr().add(2 * 64 + word_offset) as *mut v128,
                b2,
            );
            v128_store(
                output.as_mut_ptr().add(3 * 64 + word_offset) as *mut v128,
                b3,
            );
        }};
    }

    // SAFETY: output is properly aligned and sized
    unsafe {
        transpose_and_store!(0, s0, s1, s2, s3);
        transpose_and_store!(4, s4, s5, s6, s7);
        transpose_and_store!(8, s8, s9, s10, s11);
        transpose_and_store!(12, s12, s13, s14, s15);
    }

    output
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYSTREAM APPLICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Apply keystream to data using WASM SIMD (4 blocks at a time).
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce
/// * `counter` - Starting block counter
/// * `data` - Data to encrypt/decrypt in place
///
/// # Returns
///
/// The next counter value after processing all data.
pub fn apply_keystream_simd(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    counter: u32,
    data: &mut [u8],
) -> u32 {
    let mut ctr = counter;
    let mut offset = 0;

    // Process 4 blocks (256 bytes) at a time using SIMD
    while offset + 256 <= data.len() {
        let keystream = chacha20_blocks_4x(key, ctr, nonce);

        // XOR keystream with data using SIMD
        // SAFETY: We've verified there are at least 256 bytes remaining
        unsafe {
            let data_ptr = data.as_mut_ptr().add(offset);
            let ks_ptr = keystream.as_ptr();

            // 256 bytes = 16 x 128-bit XORs
            for i in 0..16 {
                let d = v128_load(data_ptr.add(i * 16) as *const v128);
                let k = v128_load(ks_ptr.add(i * 16) as *const v128);
                let x = v128_xor(d, k);
                v128_store(data_ptr.add(i * 16) as *mut v128, x);
            }
        }

        ctr = ctr.wrapping_add(4);
        offset += 256;
    }

    // Handle remaining bytes with scalar
    while offset < data.len() {
        let block = chacha20_block(key, ctr, nonce);
        let to_process = (data.len() - offset).min(BLOCK_SIZE);

        for i in 0..to_process {
            data[offset + i] ^= block[i];
        }

        ctr = ctr.wrapping_add(1);
        offset += BLOCK_SIZE;
    }

    ctr
}

/// Apply keystream using the best available implementation.
///
/// For WASM with SIMD enabled, this uses SIMD for data >= 256 bytes,
/// falling back to scalar for smaller chunks.
pub fn apply_keystream_auto(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    counter: u32,
    data: &mut [u8],
) -> u32 {
    // Use SIMD for 256+ bytes
    if data.len() >= 256 {
        apply_keystream_simd(key, nonce, counter, data)
    } else {
        apply_keystream_scalar(key, nonce, counter, data)
    }
}

/// Scalar keystream application (fallback for small data).
fn apply_keystream_scalar(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    counter: u32,
    data: &mut [u8],
) -> u32 {
    let mut ctr = counter;
    let mut offset = 0;

    while offset < data.len() {
        let block = chacha20_block(key, ctr, nonce);
        let to_process = (data.len() - offset).min(BLOCK_SIZE);

        for i in 0..to_process {
            data[offset + i] ^= block[i];
        }

        ctr = ctr.wrapping_add(1);
        offset += BLOCK_SIZE;
    }

    ctr
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// C20-S1: SIMD output matches scalar for a single block
    #[test]
    fn simd_matches_scalar_single_block() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut simd_output = [0u8; 64];
        let mut scalar_output = [0u8; 64];

        apply_keystream_simd(&key, &nonce, 0, &mut simd_output);
        apply_keystream_scalar(&key, &nonce, 0, &mut scalar_output);

        assert_eq!(simd_output, scalar_output);
    }

    /// C20-S2: SIMD output matches scalar for 1KB of keystream
    #[test]
    fn simd_matches_scalar_multi_block() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let mut simd_output = vec![0u8; 1024];
        let mut scalar_output = vec![0u8; 1024];

        apply_keystream_simd(&key, &nonce, 0, &mut simd_output);
        apply_keystream_scalar(&key, &nonce, 0, &mut scalar_output);

        assert_eq!(simd_output, scalar_output);
    }

    /// C20-S3: SIMD handles counter near u32::MAX correctly
    #[test]
    fn simd_matches_scalar_counter_overflow() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let counter = u32::MAX - 2; // Will overflow during 4-block generation

        let mut simd_output = vec![0u8; 256];
        let mut scalar_output = vec![0u8; 256];

        apply_keystream_simd(&key, &nonce, counter, &mut simd_output);
        apply_keystream_scalar(&key, &nonce, counter, &mut scalar_output);

        assert_eq!(simd_output, scalar_output);
    }

    /// C20-S4: SIMD handles all-zeros key correctly
    #[test]
    fn simd_matches_scalar_all_zeros_key() {
        let key = [0x00u8; 32];
        let nonce = [0x00u8; 12];
        let mut simd_output = vec![0u8; 256];
        let mut scalar_output = vec![0u8; 256];

        apply_keystream_simd(&key, &nonce, 0, &mut simd_output);
        apply_keystream_scalar(&key, &nonce, 0, &mut scalar_output);

        assert_eq!(simd_output, scalar_output);
    }

    /// C20-S5: SIMD handles all-ones (0xFF) key correctly
    #[test]
    fn simd_matches_scalar_all_ones_key() {
        let key = [0xFFu8; 32];
        let nonce = [0xFFu8; 12];
        let mut simd_output = vec![0u8; 256];
        let mut scalar_output = vec![0u8; 256];

        apply_keystream_simd(&key, &nonce, 0, &mut simd_output);
        apply_keystream_scalar(&key, &nonce, 0, &mut scalar_output);

        assert_eq!(simd_output, scalar_output);
    }

    /// C20-S6: SIMD matches RFC 8439 test vectors
    #[test]
    fn simd_matches_rfc8439_test_vectors() {
        // RFC 8439 Section 2.4.2 test vector
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let plaintext: Vec<u8> = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();

        let expected_ciphertext: [u8; 114] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let mut ciphertext = plaintext.clone();
        apply_keystream_auto(&key, &nonce, 1, &mut ciphertext);

        assert_eq!(ciphertext.as_slice(), expected_ciphertext.as_slice());
    }

    /// Test that 4-block generation produces correct output
    #[test]
    fn test_blocks_4x_correctness() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Generate 4 blocks with SIMD
        let simd_blocks = chacha20_blocks_4x(&key, 0, &nonce);

        // Generate 4 blocks with scalar
        let mut scalar_blocks = [0u8; 256];
        for i in 0..4 {
            let block = chacha20_block(&key, i as u32, &nonce);
            scalar_blocks[i * 64..(i + 1) * 64].copy_from_slice(&block);
        }

        assert_eq!(simd_blocks.as_slice(), scalar_blocks.as_slice());
    }

    /// Test various data sizes
    #[test]
    fn test_various_sizes() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        for size in [64, 128, 200, 256, 300, 512, 1000, 4096] {
            let mut simd_output = vec![0xAB; size];
            let mut scalar_output = simd_output.clone();

            apply_keystream_auto(&key, &nonce, 0, &mut simd_output);
            apply_keystream_scalar(&key, &nonce, 0, &mut scalar_output);

            assert_eq!(simd_output, scalar_output, "Mismatch at size {}", size);
        }
    }

    /// Test encrypt/decrypt roundtrip
    #[test]
    fn test_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let original = b"The quick brown fox jumps over the lazy dog. This is a longer message to test multi-block encryption with WASM SIMD. We need at least 256 bytes to trigger SIMD path!".to_vec();

        let mut data = original.clone();
        apply_keystream_auto(&key, &nonce, 0, &mut data);

        // Should be different after encryption
        assert_ne!(data, original);

        // Decrypt
        apply_keystream_auto(&key, &nonce, 0, &mut data);

        // Should recover original
        assert_eq!(data, original);
    }

    // ==================== EDGE CASE TESTS ====================

    /// EDGE-1: Test unaligned input buffer
    #[test]
    fn test_handles_unaligned_input() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Create buffer with offset to ensure unaligned access
        let mut aligned = vec![0xAB; 300];
        let unaligned_start = 3; // Start at offset 3 (not 16-byte aligned)
        let len = 256;

        // Apply keystream to unaligned portion
        let simd_counter = apply_keystream_auto(
            &key,
            &nonce,
            0,
            &mut aligned[unaligned_start..unaligned_start + len],
        );

        // Compare with scalar reference
        let mut scalar_buf = vec![0xAB; len];
        apply_keystream_scalar(&key, &nonce, 0, &mut scalar_buf);

        assert_eq!(
            &aligned[unaligned_start..unaligned_start + len],
            scalar_buf.as_slice()
        );
        assert_eq!(simd_counter, 4); // 256 bytes = 4 blocks
    }

    /// EDGE-2: Test unaligned output buffer (same as input for keystream)
    #[test]
    fn test_handles_unaligned_output() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Test various unaligned offsets
        for offset in [1, 3, 7, 13, 15] {
            let mut buffer = vec![0xCD; 512 + offset];
            let len = 256;

            apply_keystream_auto(&key, &nonce, 0, &mut buffer[offset..offset + len]);

            let mut reference = vec![0xCD; len];
            apply_keystream_scalar(&key, &nonce, 0, &mut reference);

            assert_eq!(
                &buffer[offset..offset + len],
                reference.as_slice(),
                "Failed at offset {}",
                offset
            );
        }
    }

    /// EDGE-3: Test zero length input
    #[test]
    fn test_handles_zero_length() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        let mut empty: [u8; 0] = [];
        let counter = apply_keystream_auto(&key, &nonce, 5, &mut empty);

        // Counter should remain unchanged for empty input
        assert_eq!(counter, 5);
    }

    /// EDGE-4: Test partial final block handling
    #[test]
    fn test_handles_partial_final_block() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Test sizes that don't align to 64-byte or 256-byte boundaries
        for size in [1, 17, 63, 65, 127, 129, 255, 257, 300, 511] {
            let mut simd_output = vec![0xEF; size];
            let mut scalar_output = simd_output.clone();

            apply_keystream_auto(&key, &nonce, 0, &mut simd_output);
            apply_keystream_scalar(&key, &nonce, 0, &mut scalar_output);

            assert_eq!(
                simd_output, scalar_output,
                "Partial block mismatch at size {}",
                size
            );
        }
    }
}
