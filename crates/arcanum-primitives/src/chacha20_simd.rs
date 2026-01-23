//! SIMD-optimized ChaCha20 implementations.
//!
//! This module provides hardware-accelerated ChaCha20 using:
//! - **AVX2**: 8 blocks (512 bytes) in parallel using 256-bit registers
//! - **SSE2**: 4 blocks (256 bytes) in parallel using 128-bit registers
//!
//! The appropriate implementation is selected at runtime based on CPU features.
//! This enables the same binary to run optimally on different hardware.
//!
//! # Performance
//!
//! | Implementation | Blocks | Throughput |
//! |----------------|--------|------------|
//! | Scalar         | 1      | ~350 MiB/s |
//! | SSE2           | 4      | ~960 MiB/s |
//! | AVX2           | 8      | ~1.2 GiB/s |
//!
//! Note: Actual throughput varies by CPU model and workload.

use super::chacha20::{chacha20_block, BLOCK_SIZE, KEY_SIZE, NONCE_SIZE};

// ═══════════════════════════════════════════════════════════════════════════════
// SSE2 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Process 4 blocks in parallel using SSE2.
///
/// SSE2 provides 128-bit registers that can hold 4 x 32-bit values.
/// We process 4 ChaCha20 blocks simultaneously.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
pub mod sse2 {
    use core::arch::x86_64::*;

    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// Quarter round on 4 parallel states using SSE2.
    #[inline(always)]
    unsafe fn quarter_round_4x(a: &mut __m128i, b: &mut __m128i, c: &mut __m128i, d: &mut __m128i) {
        // a += b; d ^= a; d <<<= 16
        *a = _mm_add_epi32(*a, *b);
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_or_si128(_mm_slli_epi32(*d, 16), _mm_srli_epi32(*d, 16));

        // c += d; b ^= c; b <<<= 12
        *c = _mm_add_epi32(*c, *d);
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_or_si128(_mm_slli_epi32(*b, 12), _mm_srli_epi32(*b, 20));

        // a += b; d ^= a; d <<<= 8
        *a = _mm_add_epi32(*a, *b);
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_or_si128(_mm_slli_epi32(*d, 8), _mm_srli_epi32(*d, 24));

        // c += d; b ^= c; b <<<= 7
        *c = _mm_add_epi32(*c, *d);
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_or_si128(_mm_slli_epi32(*b, 7), _mm_srli_epi32(*b, 25));
    }

    /// Generate 4 keystream blocks in parallel.
    ///
    /// Returns 256 bytes (4 x 64-byte blocks).
    #[target_feature(enable = "sse2")]
    pub unsafe fn chacha20_blocks_4x(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 256] {
        // Load key as u32s
        let key_ptr = key.as_ptr() as *const u32;
        let k0 = *key_ptr.add(0);
        let k1 = *key_ptr.add(1);
        let k2 = *key_ptr.add(2);
        let k3 = *key_ptr.add(3);
        let k4 = *key_ptr.add(4);
        let k5 = *key_ptr.add(5);
        let k6 = *key_ptr.add(6);
        let k7 = *key_ptr.add(7);

        // Load nonce as u32s
        let nonce_ptr = nonce.as_ptr() as *const u32;
        let n0 = *nonce_ptr.add(0);
        let n1 = *nonce_ptr.add(1);
        let n2 = *nonce_ptr.add(2);

        // Initialize 4 parallel states with different counters
        // State layout: [c0, c1, c2, c3] for constants, [k0..k7] for key, etc.
        // For parallel: each SSE register holds one element from each of 4 states

        // Constants (same for all 4 states)
        let mut s0 = _mm_set1_epi32(CONSTANTS[0] as i32);
        let mut s1 = _mm_set1_epi32(CONSTANTS[1] as i32);
        let mut s2 = _mm_set1_epi32(CONSTANTS[2] as i32);
        let mut s3 = _mm_set1_epi32(CONSTANTS[3] as i32);

        // Key (same for all 4 states)
        let mut s4 = _mm_set1_epi32(k0 as i32);
        let mut s5 = _mm_set1_epi32(k1 as i32);
        let mut s6 = _mm_set1_epi32(k2 as i32);
        let mut s7 = _mm_set1_epi32(k3 as i32);
        let mut s8 = _mm_set1_epi32(k4 as i32);
        let mut s9 = _mm_set1_epi32(k5 as i32);
        let mut s10 = _mm_set1_epi32(k6 as i32);
        let mut s11 = _mm_set1_epi32(k7 as i32);

        // Counter (different for each state: counter, counter+1, counter+2, counter+3)
        let mut s12 = _mm_set_epi32(
            (counter.wrapping_add(3)) as i32,
            (counter.wrapping_add(2)) as i32,
            (counter.wrapping_add(1)) as i32,
            counter as i32,
        );

        // Nonce (same for all 4 states)
        let mut s13 = _mm_set1_epi32(n0 as i32);
        let mut s14 = _mm_set1_epi32(n1 as i32);
        let mut s15 = _mm_set1_epi32(n2 as i32);

        // Save initial state
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
        s0 = _mm_add_epi32(s0, i0);
        s1 = _mm_add_epi32(s1, i1);
        s2 = _mm_add_epi32(s2, i2);
        s3 = _mm_add_epi32(s3, i3);
        s4 = _mm_add_epi32(s4, i4);
        s5 = _mm_add_epi32(s5, i5);
        s6 = _mm_add_epi32(s6, i6);
        s7 = _mm_add_epi32(s7, i7);
        s8 = _mm_add_epi32(s8, i8);
        s9 = _mm_add_epi32(s9, i9);
        s10 = _mm_add_epi32(s10, i10);
        s11 = _mm_add_epi32(s11, i11);
        s12 = _mm_add_epi32(s12, i12);
        s13 = _mm_add_epi32(s13, i13);
        s14 = _mm_add_epi32(s14, i14);
        s15 = _mm_add_epi32(s15, i15);

        // Transpose and write output
        // The state is in "parallel" layout - we need to transpose to get 4 sequential blocks
        let mut output = [0u8; 256];
        let out_ptr = output.as_mut_ptr() as *mut __m128i;

        // Helper to transpose 4x4 matrix of u32s
        macro_rules! transpose_and_store {
            ($base:expr, $r0:expr, $r1:expr, $r2:expr, $r3:expr) => {
                // Interleave low/high halves to transpose
                let t0 = _mm_unpacklo_epi32($r0, $r1);
                let t1 = _mm_unpackhi_epi32($r0, $r1);
                let t2 = _mm_unpacklo_epi32($r2, $r3);
                let t3 = _mm_unpackhi_epi32($r2, $r3);

                let b0 = _mm_unpacklo_epi64(t0, t2);
                let b1 = _mm_unpackhi_epi64(t0, t2);
                let b2 = _mm_unpacklo_epi64(t1, t3);
                let b3 = _mm_unpackhi_epi64(t1, t3);

                // Store: block 0 gets element 0 from each register, etc.
                _mm_storeu_si128(out_ptr.add($base), b0);
                _mm_storeu_si128(out_ptr.add($base + 4), b1);
                _mm_storeu_si128(out_ptr.add($base + 8), b2);
                _mm_storeu_si128(out_ptr.add($base + 12), b3);
            };
        }

        transpose_and_store!(0, s0, s1, s2, s3);
        transpose_and_store!(1, s4, s5, s6, s7);
        transpose_and_store!(2, s8, s9, s10, s11);
        transpose_and_store!(3, s12, s13, s14, s15);

        output
    }

    /// Apply keystream to data using SSE2 (4 blocks at a time).
    #[target_feature(enable = "sse2")]
    pub unsafe fn apply_keystream_sse2(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> u32 {
        let mut ctr = counter;
        let mut offset = 0;

        // Process 4 blocks (256 bytes) at a time
        while offset + 256 <= data.len() {
            let keystream = chacha20_blocks_4x(key, ctr, nonce);

            // XOR keystream with data
            for i in 0..256 {
                data[offset + i] ^= keystream[i];
            }

            ctr = ctr.wrapping_add(4);
            offset += 256;
        }

        // Handle remaining bytes with scalar
        if offset < data.len() {
            let mut remaining = &mut data[offset..];
            while !remaining.is_empty() {
                let block = super::chacha20_block(key, ctr, nonce);
                let to_process = remaining.len().min(64);
                for i in 0..to_process {
                    remaining[i] ^= block[i];
                }
                remaining = &mut remaining[to_process..];
                ctr = ctr.wrapping_add(1);
            }
        }

        ctr
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AVX2 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Process 8 blocks in parallel using AVX2.
///
/// AVX2 provides 256-bit registers that can hold 8 x 32-bit values.
/// We process 8 ChaCha20 blocks simultaneously for maximum throughput.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
pub mod avx2 {
    use core::arch::x86_64::*;

    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// Quarter round on 8 parallel states using AVX2.
    #[inline(always)]
    unsafe fn quarter_round_8x(a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
        // a += b; d ^= a; d <<<= 16
        *a = _mm256_add_epi32(*a, *b);
        *d = _mm256_xor_si256(*d, *a);
        *d = _mm256_or_si256(_mm256_slli_epi32(*d, 16), _mm256_srli_epi32(*d, 16));

        // c += d; b ^= c; b <<<= 12
        *c = _mm256_add_epi32(*c, *d);
        *b = _mm256_xor_si256(*b, *c);
        *b = _mm256_or_si256(_mm256_slli_epi32(*b, 12), _mm256_srli_epi32(*b, 20));

        // a += b; d ^= a; d <<<= 8
        *a = _mm256_add_epi32(*a, *b);
        *d = _mm256_xor_si256(*d, *a);
        *d = _mm256_or_si256(_mm256_slli_epi32(*d, 8), _mm256_srli_epi32(*d, 24));

        // c += d; b ^= c; b <<<= 7
        *c = _mm256_add_epi32(*c, *d);
        *b = _mm256_xor_si256(*b, *c);
        *b = _mm256_or_si256(_mm256_slli_epi32(*b, 7), _mm256_srli_epi32(*b, 25));
    }

    /// Generate 8 keystream blocks in parallel.
    ///
    /// Returns 512 bytes (8 x 64-byte blocks).
    #[target_feature(enable = "avx2")]
    pub unsafe fn chacha20_blocks_8x(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 512] {
        // Load key as u32s
        let key_ptr = key.as_ptr() as *const u32;
        let k0 = *key_ptr.add(0);
        let k1 = *key_ptr.add(1);
        let k2 = *key_ptr.add(2);
        let k3 = *key_ptr.add(3);
        let k4 = *key_ptr.add(4);
        let k5 = *key_ptr.add(5);
        let k6 = *key_ptr.add(6);
        let k7 = *key_ptr.add(7);

        // Load nonce as u32s
        let nonce_ptr = nonce.as_ptr() as *const u32;
        let n0 = *nonce_ptr.add(0);
        let n1 = *nonce_ptr.add(1);
        let n2 = *nonce_ptr.add(2);

        // Initialize 8 parallel states with different counters
        // Constants (same for all 8 states)
        let mut s0 = _mm256_set1_epi32(CONSTANTS[0] as i32);
        let mut s1 = _mm256_set1_epi32(CONSTANTS[1] as i32);
        let mut s2 = _mm256_set1_epi32(CONSTANTS[2] as i32);
        let mut s3 = _mm256_set1_epi32(CONSTANTS[3] as i32);

        // Key (same for all 8 states)
        let mut s4 = _mm256_set1_epi32(k0 as i32);
        let mut s5 = _mm256_set1_epi32(k1 as i32);
        let mut s6 = _mm256_set1_epi32(k2 as i32);
        let mut s7 = _mm256_set1_epi32(k3 as i32);
        let mut s8 = _mm256_set1_epi32(k4 as i32);
        let mut s9 = _mm256_set1_epi32(k5 as i32);
        let mut s10 = _mm256_set1_epi32(k6 as i32);
        let mut s11 = _mm256_set1_epi32(k7 as i32);

        // Counter (different for each state: counter+0 through counter+7)
        let mut s12 = _mm256_set_epi32(
            (counter.wrapping_add(7)) as i32,
            (counter.wrapping_add(6)) as i32,
            (counter.wrapping_add(5)) as i32,
            (counter.wrapping_add(4)) as i32,
            (counter.wrapping_add(3)) as i32,
            (counter.wrapping_add(2)) as i32,
            (counter.wrapping_add(1)) as i32,
            counter as i32,
        );

        // Nonce (same for all 8 states)
        let mut s13 = _mm256_set1_epi32(n0 as i32);
        let mut s14 = _mm256_set1_epi32(n1 as i32);
        let mut s15 = _mm256_set1_epi32(n2 as i32);

        // Save initial state
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
            quarter_round_8x(&mut s0, &mut s4, &mut s8, &mut s12);
            quarter_round_8x(&mut s1, &mut s5, &mut s9, &mut s13);
            quarter_round_8x(&mut s2, &mut s6, &mut s10, &mut s14);
            quarter_round_8x(&mut s3, &mut s7, &mut s11, &mut s15);

            // Diagonal rounds
            quarter_round_8x(&mut s0, &mut s5, &mut s10, &mut s15);
            quarter_round_8x(&mut s1, &mut s6, &mut s11, &mut s12);
            quarter_round_8x(&mut s2, &mut s7, &mut s8, &mut s13);
            quarter_round_8x(&mut s3, &mut s4, &mut s9, &mut s14);
        }

        // Add initial state (feedforward)
        s0 = _mm256_add_epi32(s0, i0);
        s1 = _mm256_add_epi32(s1, i1);
        s2 = _mm256_add_epi32(s2, i2);
        s3 = _mm256_add_epi32(s3, i3);
        s4 = _mm256_add_epi32(s4, i4);
        s5 = _mm256_add_epi32(s5, i5);
        s6 = _mm256_add_epi32(s6, i6);
        s7 = _mm256_add_epi32(s7, i7);
        s8 = _mm256_add_epi32(s8, i8);
        s9 = _mm256_add_epi32(s9, i9);
        s10 = _mm256_add_epi32(s10, i10);
        s11 = _mm256_add_epi32(s11, i11);
        s12 = _mm256_add_epi32(s12, i12);
        s13 = _mm256_add_epi32(s13, i13);
        s14 = _mm256_add_epi32(s14, i14);
        s15 = _mm256_add_epi32(s15, i15);

        // Transpose and write output
        // We need to extract 8 sequential 64-byte blocks from the parallel state
        let mut output = [0u8; 512];

        // Extract each block by gathering the appropriate elements
        // For block i, we need element i from each state register
        for block in 0..8 {
            let block_offset = block * 64;

            // Extract the 32-bit element at position `block` from each state register
            // and write as the block's state words
            macro_rules! extract_and_store {
                ($reg:expr, $word:expr) => {
                    let val = match block {
                        0 => _mm256_extract_epi32($reg, 0) as u32,
                        1 => _mm256_extract_epi32($reg, 1) as u32,
                        2 => _mm256_extract_epi32($reg, 2) as u32,
                        3 => _mm256_extract_epi32($reg, 3) as u32,
                        4 => _mm256_extract_epi32($reg, 4) as u32,
                        5 => _mm256_extract_epi32($reg, 5) as u32,
                        6 => _mm256_extract_epi32($reg, 6) as u32,
                        7 => _mm256_extract_epi32($reg, 7) as u32,
                        _ => unreachable!(),
                    };
                    output[block_offset + $word * 4..block_offset + $word * 4 + 4]
                        .copy_from_slice(&val.to_le_bytes());
                };
            }

            extract_and_store!(s0, 0);
            extract_and_store!(s1, 1);
            extract_and_store!(s2, 2);
            extract_and_store!(s3, 3);
            extract_and_store!(s4, 4);
            extract_and_store!(s5, 5);
            extract_and_store!(s6, 6);
            extract_and_store!(s7, 7);
            extract_and_store!(s8, 8);
            extract_and_store!(s9, 9);
            extract_and_store!(s10, 10);
            extract_and_store!(s11, 11);
            extract_and_store!(s12, 12);
            extract_and_store!(s13, 13);
            extract_and_store!(s14, 14);
            extract_and_store!(s15, 15);
        }

        output
    }

    /// Apply keystream to data using AVX2 (8 blocks at a time).
    #[target_feature(enable = "avx2")]
    pub unsafe fn apply_keystream_avx2(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> u32 {
        let mut ctr = counter;
        let mut offset = 0;

        // Process 8 blocks (512 bytes) at a time
        while offset + 512 <= data.len() {
            let keystream = chacha20_blocks_8x(key, ctr, nonce);

            // XOR keystream with data using AVX2 for the XOR too
            let data_ptr = data.as_mut_ptr().add(offset);
            let ks_ptr = keystream.as_ptr();

            for i in 0..16 {
                let d = _mm256_loadu_si256((data_ptr as *const __m256i).add(i));
                let k = _mm256_loadu_si256((ks_ptr as *const __m256i).add(i));
                let x = _mm256_xor_si256(d, k);
                _mm256_storeu_si256((data_ptr as *mut __m256i).add(i), x);
            }

            ctr = ctr.wrapping_add(8);
            offset += 512;
        }

        // Handle remaining bytes with SSE2 or scalar
        if offset + 256 <= data.len() {
            // Use SSE2 for 4-block chunks
            let keystream = super::sse2::chacha20_blocks_4x(key, ctr, nonce);
            for i in 0..256 {
                data[offset + i] ^= keystream[i];
            }
            ctr = ctr.wrapping_add(4);
            offset += 256;
        }

        // Remaining bytes with scalar
        while offset < data.len() {
            let block = super::chacha20_block(key, ctr, nonce);
            let to_process = (data.len() - offset).min(64);
            for i in 0..to_process {
                data[offset + i] ^= block[i];
            }
            ctr = ctr.wrapping_add(1);
            offset += 64;
        }

        ctr
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AVX-512 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Process 16 blocks in parallel using AVX-512.
///
/// AVX-512 provides 512-bit registers that can hold 16 x 32-bit values.
/// We process 16 ChaCha20 blocks simultaneously for maximum throughput.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
pub mod avx512 {
    use core::arch::x86_64::*;

    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// Quarter round on 16 parallel states using AVX-512.
    #[inline(always)]
    unsafe fn quarter_round_16x(
        a: &mut __m512i,
        b: &mut __m512i,
        c: &mut __m512i,
        d: &mut __m512i,
    ) {
        // a += b; d ^= a; d <<<= 16
        *a = _mm512_add_epi32(*a, *b);
        *d = _mm512_xor_si512(*d, *a);
        *d = _mm512_rol_epi32(*d, 16);

        // c += d; b ^= c; b <<<= 12
        *c = _mm512_add_epi32(*c, *d);
        *b = _mm512_xor_si512(*b, *c);
        *b = _mm512_rol_epi32(*b, 12);

        // a += b; d ^= a; d <<<= 8
        *a = _mm512_add_epi32(*a, *b);
        *d = _mm512_xor_si512(*d, *a);
        *d = _mm512_rol_epi32(*d, 8);

        // c += d; b ^= c; b <<<= 7
        *c = _mm512_add_epi32(*c, *d);
        *b = _mm512_xor_si512(*b, *c);
        *b = _mm512_rol_epi32(*b, 7);
    }

    /// Generate 16 keystream blocks in parallel.
    ///
    /// Returns 1024 bytes (16 x 64-byte blocks).
    #[target_feature(enable = "avx512f")]
    pub unsafe fn chacha20_blocks_16x(
        key: &[u8; 32],
        counter: u32,
        nonce: &[u8; 12],
    ) -> [u8; 1024] {
        // Load key as u32s
        let key_ptr = key.as_ptr() as *const u32;
        let k0 = *key_ptr.add(0);
        let k1 = *key_ptr.add(1);
        let k2 = *key_ptr.add(2);
        let k3 = *key_ptr.add(3);
        let k4 = *key_ptr.add(4);
        let k5 = *key_ptr.add(5);
        let k6 = *key_ptr.add(6);
        let k7 = *key_ptr.add(7);

        // Load nonce as u32s
        let nonce_ptr = nonce.as_ptr() as *const u32;
        let n0 = *nonce_ptr.add(0);
        let n1 = *nonce_ptr.add(1);
        let n2 = *nonce_ptr.add(2);

        // Initialize 16 parallel states with different counters
        // Constants (same for all 16 states)
        let mut s0 = _mm512_set1_epi32(CONSTANTS[0] as i32);
        let mut s1 = _mm512_set1_epi32(CONSTANTS[1] as i32);
        let mut s2 = _mm512_set1_epi32(CONSTANTS[2] as i32);
        let mut s3 = _mm512_set1_epi32(CONSTANTS[3] as i32);

        // Key (same for all 16 states)
        let mut s4 = _mm512_set1_epi32(k0 as i32);
        let mut s5 = _mm512_set1_epi32(k1 as i32);
        let mut s6 = _mm512_set1_epi32(k2 as i32);
        let mut s7 = _mm512_set1_epi32(k3 as i32);
        let mut s8 = _mm512_set1_epi32(k4 as i32);
        let mut s9 = _mm512_set1_epi32(k5 as i32);
        let mut s10 = _mm512_set1_epi32(k6 as i32);
        let mut s11 = _mm512_set1_epi32(k7 as i32);

        // Counter (different for each state: counter+0 through counter+15)
        let mut s12 = _mm512_set_epi32(
            (counter.wrapping_add(15)) as i32,
            (counter.wrapping_add(14)) as i32,
            (counter.wrapping_add(13)) as i32,
            (counter.wrapping_add(12)) as i32,
            (counter.wrapping_add(11)) as i32,
            (counter.wrapping_add(10)) as i32,
            (counter.wrapping_add(9)) as i32,
            (counter.wrapping_add(8)) as i32,
            (counter.wrapping_add(7)) as i32,
            (counter.wrapping_add(6)) as i32,
            (counter.wrapping_add(5)) as i32,
            (counter.wrapping_add(4)) as i32,
            (counter.wrapping_add(3)) as i32,
            (counter.wrapping_add(2)) as i32,
            (counter.wrapping_add(1)) as i32,
            counter as i32,
        );

        // Nonce (same for all 16 states)
        let mut s13 = _mm512_set1_epi32(n0 as i32);
        let mut s14 = _mm512_set1_epi32(n1 as i32);
        let mut s15 = _mm512_set1_epi32(n2 as i32);

        // Save initial state
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
            quarter_round_16x(&mut s0, &mut s4, &mut s8, &mut s12);
            quarter_round_16x(&mut s1, &mut s5, &mut s9, &mut s13);
            quarter_round_16x(&mut s2, &mut s6, &mut s10, &mut s14);
            quarter_round_16x(&mut s3, &mut s7, &mut s11, &mut s15);

            // Diagonal rounds
            quarter_round_16x(&mut s0, &mut s5, &mut s10, &mut s15);
            quarter_round_16x(&mut s1, &mut s6, &mut s11, &mut s12);
            quarter_round_16x(&mut s2, &mut s7, &mut s8, &mut s13);
            quarter_round_16x(&mut s3, &mut s4, &mut s9, &mut s14);
        }

        // Add initial state (feedforward)
        s0 = _mm512_add_epi32(s0, i0);
        s1 = _mm512_add_epi32(s1, i1);
        s2 = _mm512_add_epi32(s2, i2);
        s3 = _mm512_add_epi32(s3, i3);
        s4 = _mm512_add_epi32(s4, i4);
        s5 = _mm512_add_epi32(s5, i5);
        s6 = _mm512_add_epi32(s6, i6);
        s7 = _mm512_add_epi32(s7, i7);
        s8 = _mm512_add_epi32(s8, i8);
        s9 = _mm512_add_epi32(s9, i9);
        s10 = _mm512_add_epi32(s10, i10);
        s11 = _mm512_add_epi32(s11, i11);
        s12 = _mm512_add_epi32(s12, i12);
        s13 = _mm512_add_epi32(s13, i13);
        s14 = _mm512_add_epi32(s14, i14);
        s15 = _mm512_add_epi32(s15, i15);

        // Transpose and write output
        // We need to extract 16 sequential 64-byte blocks from the parallel state
        let mut output = [0u8; 1024];

        // Use gather/scatter for efficient extraction
        // For each block, extract element i from each state register
        for block in 0..16 {
            let block_offset = block * 64;

            // Create index for extraction (just the block index)
            let idx = _mm512_set1_epi32(block as i32);

            // Extract each state word using permutexvar
            macro_rules! extract_and_store {
                ($reg:expr, $word:expr) => {
                    // Use permutexvar to broadcast the element at index 'block' to all lanes
                    let extracted = _mm512_permutexvar_epi32(idx, $reg);
                    // Get the first element (they're all the same now)
                    let val = _mm512_cvtsi512_si32(extracted) as u32;
                    output[block_offset + $word * 4..block_offset + $word * 4 + 4]
                        .copy_from_slice(&val.to_le_bytes());
                };
            }

            extract_and_store!(s0, 0);
            extract_and_store!(s1, 1);
            extract_and_store!(s2, 2);
            extract_and_store!(s3, 3);
            extract_and_store!(s4, 4);
            extract_and_store!(s5, 5);
            extract_and_store!(s6, 6);
            extract_and_store!(s7, 7);
            extract_and_store!(s8, 8);
            extract_and_store!(s9, 9);
            extract_and_store!(s10, 10);
            extract_and_store!(s11, 11);
            extract_and_store!(s12, 12);
            extract_and_store!(s13, 13);
            extract_and_store!(s14, 14);
            extract_and_store!(s15, 15);
        }

        output
    }

    /// Apply keystream to data using AVX-512 (16 blocks at a time).
    #[target_feature(enable = "avx512f")]
    pub unsafe fn apply_keystream_avx512(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> u32 {
        let mut ctr = counter;
        let mut offset = 0;

        // Process 16 blocks (1024 bytes) at a time
        while offset + 1024 <= data.len() {
            let keystream = chacha20_blocks_16x(key, ctr, nonce);

            // XOR keystream with data using AVX-512
            let data_ptr = data.as_mut_ptr().add(offset);
            let ks_ptr = keystream.as_ptr();

            // 16 x 64 bytes = 1024 bytes = 16 x 512-bit XORs
            for i in 0..16 {
                let d = _mm512_loadu_si512((data_ptr as *const __m512i).add(i));
                let k = _mm512_loadu_si512((ks_ptr as *const __m512i).add(i));
                let x = _mm512_xor_si512(d, k);
                _mm512_storeu_si512((data_ptr as *mut __m512i).add(i), x);
            }

            ctr = ctr.wrapping_add(16);
            offset += 1024;
        }

        // Handle remaining bytes with AVX2
        if offset + 512 <= data.len() {
            let keystream = super::avx2::chacha20_blocks_8x(key, ctr, nonce);
            let data_ptr = data.as_mut_ptr().add(offset);
            let ks_ptr = keystream.as_ptr();

            for i in 0..8 {
                let d = _mm512_loadu_si512((data_ptr as *const __m512i).add(i));
                let k = _mm512_loadu_si512((ks_ptr as *const __m512i).add(i));
                let x = _mm512_xor_si512(d, k);
                _mm512_storeu_si512((data_ptr as *mut __m512i).add(i), x);
            }

            ctr = ctr.wrapping_add(8);
            offset += 512;
        }

        // Handle remaining bytes with SSE2 or scalar
        if offset + 256 <= data.len() {
            let keystream = super::sse2::chacha20_blocks_4x(key, ctr, nonce);
            for i in 0..256 {
                data[offset + i] ^= keystream[i];
            }
            ctr = ctr.wrapping_add(4);
            offset += 256;
        }

        // Remaining bytes with scalar
        while offset < data.len() {
            let block = super::chacha20_block(key, ctr, nonce);
            let to_process = (data.len() - offset).min(64);
            for i in 0..to_process {
                data[offset + i] ^= block[i];
            }
            ctr = ctr.wrapping_add(1);
            offset += 64;
        }

        ctr
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUNTIME DISPATCH
// ═══════════════════════════════════════════════════════════════════════════════

/// Check if SSE2 is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn has_sse2() -> bool {
    std::is_x86_feature_detected!("sse2")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
pub fn has_sse2() -> bool {
    false
}

/// Check if AVX2 is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn has_avx2() -> bool {
    std::is_x86_feature_detected!("avx2")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
pub fn has_avx2() -> bool {
    false
}

/// Check if AVX-512F is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn has_avx512f() -> bool {
    std::is_x86_feature_detected!("avx512f")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
pub fn has_avx512f() -> bool {
    false
}

/// Apply keystream using the best available implementation.
///
/// Automatically selects SIMD or scalar based on CPU features:
/// - AVX-512: 16 blocks (1024 bytes) in parallel
/// - AVX2: 8 blocks (512 bytes) in parallel
/// - SSE2: 4 blocks (256 bytes) in parallel
/// - Scalar: 1 block (64 bytes) at a time
pub fn apply_keystream_auto(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    counter: u32,
    data: &mut [u8],
) -> u32 {
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        // Prefer AVX-512 for very large data (16 blocks at a time)
        if has_avx512f() && data.len() >= 1024 {
            // SAFETY: We've verified AVX-512F is available at runtime
            return unsafe { avx512::apply_keystream_avx512(key, nonce, counter, data) };
        }

        // Prefer AVX2 for large data (8 blocks at a time)
        if has_avx2() && data.len() >= 512 {
            // SAFETY: We've verified AVX2 is available at runtime
            return unsafe { avx2::apply_keystream_avx2(key, nonce, counter, data) };
        }

        // Fall back to SSE2 for medium data (4 blocks at a time)
        if has_sse2() && data.len() >= 256 {
            // SAFETY: We've verified SSE2 is available at runtime
            return unsafe { sse2::apply_keystream_sse2(key, nonce, counter, data) };
        }
    }

    // Fallback to scalar for non-x86_64 or small data
    apply_keystream_scalar(key, nonce, counter, data)
}

/// Scalar keystream application (fallback).
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

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn test_simd_matches_scalar() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Test various data sizes
        for size in [64, 128, 256, 512, 1000, 4096] {
            let mut data_scalar = vec![0xAB; size];
            let mut data_auto = data_scalar.clone();

            // Scalar
            apply_keystream_scalar(&key, &nonce, 0, &mut data_scalar);

            // Auto (may use SIMD)
            apply_keystream_auto(&key, &nonce, 0, &mut data_auto);

            assert_eq!(data_scalar, data_auto, "Mismatch at size {}", size);
        }
    }

    #[test]
    fn test_rfc8439_vector_with_simd() {
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

        let expected = hex_to_bytes(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );

        let mut ciphertext = plaintext.clone();
        apply_keystream_auto(&key, &nonce, 1, &mut ciphertext);

        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_roundtrip_large() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // 10KB test
        let original = vec![0xAB; 10_000];
        let mut data = original.clone();

        apply_keystream_auto(&key, &nonce, 0, &mut data);
        assert_ne!(data, original);

        apply_keystream_auto(&key, &nonce, 0, &mut data);
        assert_eq!(data, original);
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_sse2_blocks_4x() {
        if !has_sse2() {
            return;
        }

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Generate 4 blocks with SSE2
        let simd_blocks = unsafe { sse2::chacha20_blocks_4x(&key, 0, &nonce) };

        // Generate 4 blocks with scalar
        let mut scalar_blocks = [0u8; 256];
        for i in 0..4 {
            let block = chacha20_block(&key, i as u32, &nonce);
            scalar_blocks[i * 64..(i + 1) * 64].copy_from_slice(&block);
        }

        assert_eq!(simd_blocks.as_slice(), scalar_blocks.as_slice());
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_avx2_blocks_8x() {
        if !has_avx2() {
            println!("AVX2 not available, skipping test");
            return;
        }

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Generate 8 blocks with AVX2
        let simd_blocks = unsafe { avx2::chacha20_blocks_8x(&key, 0, &nonce) };

        // Generate 8 blocks with scalar
        let mut scalar_blocks = [0u8; 512];
        for i in 0..8 {
            let block = chacha20_block(&key, i as u32, &nonce);
            scalar_blocks[i * 64..(i + 1) * 64].copy_from_slice(&block);
        }

        assert_eq!(simd_blocks.as_slice(), scalar_blocks.as_slice());
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_avx2_apply_keystream() {
        if !has_avx2() {
            println!("AVX2 not available, skipping test");
            return;
        }

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Test various sizes including AVX2 threshold boundaries
        for size in [512, 600, 1024, 2048, 4096, 10000] {
            let mut data_scalar = vec![0xAB; size];
            let mut data_avx2 = data_scalar.clone();

            // Scalar
            apply_keystream_scalar(&key, &nonce, 0, &mut data_scalar);

            // AVX2
            unsafe { avx2::apply_keystream_avx2(&key, &nonce, 0, &mut data_avx2) };

            assert_eq!(data_scalar, data_avx2, "AVX2 mismatch at size {}", size);
        }
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_avx512_blocks_16x() {
        if !has_avx512f() {
            println!("AVX-512F not available, skipping test");
            return;
        }

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Generate 16 blocks with AVX-512
        let simd_blocks = unsafe { avx512::chacha20_blocks_16x(&key, 0, &nonce) };

        // Generate 16 blocks with scalar
        let mut scalar_blocks = [0u8; 1024];
        for i in 0..16 {
            let block = chacha20_block(&key, i as u32, &nonce);
            scalar_blocks[i * 64..(i + 1) * 64].copy_from_slice(&block);
        }

        assert_eq!(simd_blocks.as_slice(), scalar_blocks.as_slice());
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_avx512_apply_keystream() {
        if !has_avx512f() {
            println!("AVX-512F not available, skipping test");
            return;
        }

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        // Test various sizes including AVX-512 threshold boundaries
        for size in [1024, 1500, 2048, 4096, 10000, 65536] {
            let mut data_scalar = vec![0xAB; size];
            let mut data_avx512 = data_scalar.clone();

            // Scalar
            apply_keystream_scalar(&key, &nonce, 0, &mut data_scalar);

            // AVX-512
            unsafe { avx512::apply_keystream_avx512(&key, &nonce, 0, &mut data_avx512) };

            assert_eq!(
                data_scalar, data_avx512,
                "AVX-512 mismatch at size {}",
                size
            );
        }
    }

    #[test]
    fn test_simd_feature_detection() {
        // Just verify feature detection doesn't crash
        println!("SSE2 available: {}", has_sse2());
        println!("AVX2 available: {}", has_avx2());
        println!("AVX-512F available: {}", has_avx512f());
    }
}
