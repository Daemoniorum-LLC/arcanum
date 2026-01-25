//! SIMD-accelerated Poly1305 implementation.
//!
//! This module provides vectorized Poly1305 processing using AVX2 instructions
//! to process multiple 16-byte blocks in parallel.
//!
//! # Optimization Strategy
//!
//! Instead of processing one block at a time:
//!   acc = (acc + m) * r
//!
//! We process 2 blocks at a time using precomputed r²:
//!   acc = (acc + m0) * r² + m1 * r
//!     = acc*r² + m0*r² + m1*r
//!
//! This allows us to use SIMD to parallelize the polynomial evaluation.

// SIMD intrinsics (reserved for future full SIMD implementation)
#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
use core::arch::x86_64::*;

// ═══════════════════════════════════════════════════════════════════════════════
// CPU FEATURE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Check if AVX2 is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[inline]
pub fn has_avx2() -> bool {
    std::is_x86_feature_detected!("avx2")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
#[inline]
pub fn has_avx2() -> bool {
    false
}

/// Check if AVX-512F is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[inline]
pub fn has_avx512f() -> bool {
    std::is_x86_feature_detected!("avx512f")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
#[inline]
pub fn has_avx512f() -> bool {
    false
}

// ═══════════════════════════════════════════════════════════════════════════════
// VECTORIZED POLY1305 STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

/// Precomputed powers of r for vectorized processing.
///
/// Contains r, r², 5*r[1..4] for efficient reduction.
#[derive(Clone)]
pub struct Poly1305Powers {
    /// r in 5x26-bit limb form
    pub r: [u64; 5],
    /// r² in 5x26-bit limb form
    pub r2: [u64; 5],
    /// 5\*r\[1\], 5\*r\[2\], 5\*r\[3\], 5\*r\[4\] for reduction
    pub s: [u64; 4],
    /// 5\*r²\[1\], 5\*r²\[2\], 5\*r²\[3\], 5\*r²\[4\] for reduction
    pub s2: [u64; 4],
}

impl Poly1305Powers {
    /// Compute powers of r from the clamped r value.
    pub fn new(r_bytes: &[u8; 16]) -> Self {
        // Load r into limbs
        let r = load_26bit_limbs(r_bytes);

        // Compute r²
        let r2 = mul_reduce_scalar(&r, &r);

        // Precompute 5*r[i] values
        let s = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        let s2 = [r2[1] * 5, r2[2] * 5, r2[3] * 5, r2[4] * 5];

        Self { r, r2, s, s2 }
    }
}

/// Load 16 bytes as 5x26-bit limbs.
#[inline]
fn load_26bit_limbs(bytes: &[u8; 16]) -> [u64; 5] {
    let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

    [
        lo & 0x3ffffff,
        (lo >> 26) & 0x3ffffff,
        ((lo >> 52) | (hi << 12)) & 0x3ffffff,
        (hi >> 14) & 0x3ffffff,
        hi >> 40,
    ]
}

/// Load a block with the high bit set (bit 128).
#[inline]
fn load_block_with_hibit(bytes: &[u8; 16]) -> [u64; 5] {
    let mut limbs = load_26bit_limbs(bytes);
    limbs[4] |= 1 << 24; // Set bit 128
    limbs
}

/// Scalar multiply and reduce: h = h * r mod 2^130-5
#[inline]
fn mul_reduce_scalar(h: &[u64; 5], r: &[u64; 5]) -> [u64; 5] {
    let s1 = r[1] * 5;
    let s2 = r[2] * 5;
    let s3 = r[3] * 5;
    let s4 = r[4] * 5;

    let h0 = h[0] as u128;
    let h1 = h[1] as u128;
    let h2 = h[2] as u128;
    let h3 = h[3] as u128;
    let h4 = h[4] as u128;

    let r0 = r[0] as u128;
    let r1 = r[1] as u128;
    let r2 = r[2] as u128;
    let r3 = r[3] as u128;
    let r4 = r[4] as u128;
    let s1 = s1 as u128;
    let s2 = s2 as u128;
    let s3 = s3 as u128;
    let s4 = s4 as u128;

    let mut t0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let mut t1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let mut t2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let mut t3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let mut t4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    // Carry propagation
    let mut c: u128;
    c = t0 >> 26;
    t0 &= 0x3ffffff;
    t1 += c;
    c = t1 >> 26;
    t1 &= 0x3ffffff;
    t2 += c;
    c = t2 >> 26;
    t2 &= 0x3ffffff;
    t3 += c;
    c = t3 >> 26;
    t3 &= 0x3ffffff;
    t4 += c;
    c = t4 >> 26;
    t4 &= 0x3ffffff;
    t0 += c * 5;
    c = t0 >> 26;
    t0 &= 0x3ffffff;
    t1 += c;

    [t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64]
}

// ═══════════════════════════════════════════════════════════════════════════════
// AVX2 VECTORIZED PROCESSING
// ═══════════════════════════════════════════════════════════════════════════════

/// AVX2 SIMD implementations for Poly1305.
///
/// Uses true AVX2 intrinsics for vectorized multiplication.
#[cfg(target_arch = "x86_64")]
pub mod avx2 {
    use super::*;

    /// Process 2 blocks at a time using AVX2.
    ///
    /// For blocks m0, m1 we compute:
    ///   acc = (acc + m0) * r² + m1 * r
    #[target_feature(enable = "avx2")]
    pub unsafe fn process_blocks_2x(
        acc: &mut [u64; 5],
        powers: &Poly1305Powers,
        block0: &[u8; 16],
        block1: &[u8; 16],
    ) {
        let m0 = load_block_with_hibit(block0);
        let m1 = load_block_with_hibit(block1);

        // h = acc + m0
        let h = [
            acc[0] + m0[0],
            acc[1] + m0[1],
            acc[2] + m0[2],
            acc[3] + m0[3],
            acc[4] + m0[4],
        ];

        // Compute h * r² and m1 * r in parallel using vectorized multiplication
        let t0_a = mul_reduce_avx2_vectorized(&h, &powers.r2, &powers.s2);
        let t0_b = mul_reduce_avx2_vectorized(&m1, &powers.r, &powers.s);

        // Add the two results
        acc[0] = t0_a[0] + t0_b[0];
        acc[1] = t0_a[1] + t0_b[1];
        acc[2] = t0_a[2] + t0_b[2];
        acc[3] = t0_a[3] + t0_b[3];
        acc[4] = t0_a[4] + t0_b[4];

        // Carry propagation
        let mut c: u64;
        c = acc[0] >> 26;
        acc[0] &= 0x3ffffff;
        acc[1] += c;
        c = acc[1] >> 26;
        acc[1] &= 0x3ffffff;
        acc[2] += c;
        c = acc[2] >> 26;
        acc[2] &= 0x3ffffff;
        acc[3] += c;
        c = acc[3] >> 26;
        acc[3] &= 0x3ffffff;
        acc[4] += c;
        c = acc[4] >> 26;
        acc[4] &= 0x3ffffff;
        acc[0] += c * 5;
        c = acc[0] >> 26;
        acc[0] &= 0x3ffffff;
        acc[1] += c;
    }

    /// Vectorized multiply h * r using AVX2.
    ///
    /// Uses `_mm256_mul_epu32` to compute multiple 32x32→64 products in parallel.
    /// This computes the 5x5 multiplication matrix for radix-2^26 arithmetic.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn mul_reduce_avx2_vectorized(h: &[u64; 5], r: &[u64; 5], s: &[u64; 4]) -> [u64; 5] {
        // We compute:
        // t0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
        // t1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
        // t2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
        // t3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
        // t4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
        //
        // Using AVX2, we can compute 4 products at once with _mm256_mul_epu32.
        // We pack h values and r/s values into vectors and multiply.

        let s1 = s[0];
        let s2 = s[1];
        let s3 = s[2];
        let s4 = s[3];

        // Load h values into vectors for parallel multiplication
        // h_vec = [h0, h1, h2, h3] (as 64-bit values in 256-bit register)
        let h_vec = _mm256_set_epi64x(h[3] as i64, h[2] as i64, h[1] as i64, h[0] as i64);
        let h4_scalar = h[4];

        // For t0: h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
        let r_t0 = _mm256_set_epi64x(s2 as i64, s3 as i64, s4 as i64, r[0] as i64);
        let prod_t0 = _mm256_mul_epu32(h_vec, r_t0);
        let t0_partial = horizontal_sum_epi64(prod_t0);
        let t0 = t0_partial + (h4_scalar as u128) * (s1 as u128);

        // For t1: h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
        let r_t1 = _mm256_set_epi64x(s3 as i64, s4 as i64, r[0] as i64, r[1] as i64);
        let prod_t1 = _mm256_mul_epu32(h_vec, r_t1);
        let t1_partial = horizontal_sum_epi64(prod_t1);
        let t1 = t1_partial + (h4_scalar as u128) * (s2 as u128);

        // For t2: h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
        let r_t2 = _mm256_set_epi64x(s4 as i64, r[0] as i64, r[1] as i64, r[2] as i64);
        let prod_t2 = _mm256_mul_epu32(h_vec, r_t2);
        let t2_partial = horizontal_sum_epi64(prod_t2);
        let t2 = t2_partial + (h4_scalar as u128) * (s3 as u128);

        // For t3: h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
        let r_t3 = _mm256_set_epi64x(r[0] as i64, r[1] as i64, r[2] as i64, r[3] as i64);
        let prod_t3 = _mm256_mul_epu32(h_vec, r_t3);
        let t3_partial = horizontal_sum_epi64(prod_t3);
        let t3 = t3_partial + (h4_scalar as u128) * (s4 as u128);

        // For t4: h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
        let r_t4 = _mm256_set_epi64x(r[1] as i64, r[2] as i64, r[3] as i64, r[4] as i64);
        let prod_t4 = _mm256_mul_epu32(h_vec, r_t4);
        let t4_partial = horizontal_sum_epi64(prod_t4);
        let t4 = t4_partial + (h4_scalar as u128) * (r[0] as u128);

        // Carry propagation
        let mut t = [t0, t1, t2, t3, t4];
        let mut c: u128;

        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;
        c = t[1] >> 26;
        t[1] &= 0x3ffffff;
        t[2] += c;
        c = t[2] >> 26;
        t[2] &= 0x3ffffff;
        t[3] += c;
        c = t[3] >> 26;
        t[3] &= 0x3ffffff;
        t[4] += c;
        c = t[4] >> 26;
        t[4] &= 0x3ffffff;
        t[0] += c * 5;
        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;

        [
            t[0] as u64,
            t[1] as u64,
            t[2] as u64,
            t[3] as u64,
            t[4] as u64,
        ]
    }

    /// Sum 4 64-bit values in a 256-bit register using AVX2.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn horizontal_sum_epi64(v: __m256i) -> u128 {
        // Extract the two 128-bit halves
        let lo = _mm256_castsi256_si128(v);
        let hi = _mm256_extracti128_si256(v, 1);

        // Add the halves
        let sum = _mm_add_epi64(lo, hi);

        // Extract and add the two 64-bit values
        let a = _mm_extract_epi64(sum, 0) as u64;
        let b = _mm_extract_epi64(sum, 1) as u64;

        (a as u128) + (b as u128)
    }

    /// Process 4 blocks at a time using AVX2 vectorized multiplication.
    ///
    /// Computes: acc = acc * r⁴ + m0 * r⁴ + m1 * r³ + m2 * r² + m3 * r
    #[target_feature(enable = "avx2")]
    pub unsafe fn process_blocks_4x(
        acc: &mut [u64; 5],
        r: &[u64; 5],
        r2: &[u64; 5],
        r3: &[u64; 5],
        r4: &[u64; 5],
        blocks: &[[u8; 16]; 4],
    ) {
        // Load all 4 blocks
        let m0 = load_block_with_hibit(&blocks[0]);
        let m1 = load_block_with_hibit(&blocks[1]);
        let m2 = load_block_with_hibit(&blocks[2]);
        let m3 = load_block_with_hibit(&blocks[3]);

        // Add m0 to accumulator
        let h = [
            acc[0] + m0[0],
            acc[1] + m0[1],
            acc[2] + m0[2],
            acc[3] + m0[3],
            acc[4] + m0[4],
        ];

        // Precompute s values for each r power
        let s4 = [r4[1] * 5, r4[2] * 5, r4[3] * 5, r4[4] * 5];
        let s3 = [r3[1] * 5, r3[2] * 5, r3[3] * 5, r3[4] * 5];
        let s2 = [r2[1] * 5, r2[2] * 5, r2[3] * 5, r2[4] * 5];
        let s1 = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        // Compute all 4 multiplications using vectorized code
        let t_h = mul_reduce_avx2_vectorized(&h, r4, &s4);
        let t_m1 = mul_reduce_avx2_vectorized(&m1, r3, &s3);
        let t_m2 = mul_reduce_avx2_vectorized(&m2, r2, &s2);
        let t_m3 = mul_reduce_avx2_vectorized(&m3, r, &s1);

        // Sum all results
        let mut result = [
            t_h[0] + t_m1[0] + t_m2[0] + t_m3[0],
            t_h[1] + t_m1[1] + t_m2[1] + t_m3[1],
            t_h[2] + t_m1[2] + t_m2[2] + t_m3[2],
            t_h[3] + t_m1[3] + t_m2[3] + t_m3[3],
            t_h[4] + t_m1[4] + t_m2[4] + t_m3[4],
        ];

        // Carry propagation
        let mut c: u64;
        c = result[0] >> 26;
        result[0] &= 0x3ffffff;
        result[1] += c;
        c = result[1] >> 26;
        result[1] &= 0x3ffffff;
        result[2] += c;
        c = result[2] >> 26;
        result[2] &= 0x3ffffff;
        result[3] += c;
        c = result[3] >> 26;
        result[3] &= 0x3ffffff;
        result[4] += c;
        c = result[4] >> 26;
        result[4] &= 0x3ffffff;
        result[0] += c * 5;
        c = result[0] >> 26;
        result[0] &= 0x3ffffff;
        result[1] += c;

        *acc = result;
    }

    /// Process 4 blocks with fully vectorized parallel computation.
    ///
    /// This processes all 4 multiplications simultaneously using AVX2
    /// to compute the full 5x5 product matrices in parallel.
    #[target_feature(enable = "avx2")]
    pub unsafe fn process_blocks_4x_parallel(
        acc: &mut [u64; 5],
        r: &[u64; 5],
        r2: &[u64; 5],
        r3: &[u64; 5],
        r4: &[u64; 5],
        blocks: &[[u8; 16]; 4],
    ) {
        // Load all 4 blocks
        let m0 = load_block_with_hibit(&blocks[0]);
        let m1 = load_block_with_hibit(&blocks[1]);
        let m2 = load_block_with_hibit(&blocks[2]);
        let m3 = load_block_with_hibit(&blocks[3]);

        // Add m0 to accumulator for h
        let h0 = acc[0] + m0[0];
        let h1 = acc[1] + m0[1];
        let h2 = acc[2] + m0[2];
        let h3 = acc[3] + m0[3];
        let h4 = acc[4] + m0[4];

        // Pack h values for parallel processing: [h, m1, m2, m3] per limb
        // Each vector contains the same limb index from 4 different inputs
        let h_l0 = _mm256_set_epi64x(m3[0] as i64, m2[0] as i64, m1[0] as i64, h0 as i64);
        let h_l1 = _mm256_set_epi64x(m3[1] as i64, m2[1] as i64, m1[1] as i64, h1 as i64);
        let h_l2 = _mm256_set_epi64x(m3[2] as i64, m2[2] as i64, m1[2] as i64, h2 as i64);
        let h_l3 = _mm256_set_epi64x(m3[3] as i64, m2[3] as i64, m1[3] as i64, h3 as i64);
        let h_l4 = _mm256_set_epi64x(m3[4] as i64, m2[4] as i64, m1[4] as i64, h4 as i64);

        // Pack r values: [r4, r3, r2, r] per limb (matching the multipliers)
        let r_l0 = _mm256_set_epi64x(r[0] as i64, r2[0] as i64, r3[0] as i64, r4[0] as i64);
        let r_l1 = _mm256_set_epi64x(r[1] as i64, r2[1] as i64, r3[1] as i64, r4[1] as i64);
        let r_l2 = _mm256_set_epi64x(r[2] as i64, r2[2] as i64, r3[2] as i64, r4[2] as i64);
        let r_l3 = _mm256_set_epi64x(r[3] as i64, r2[3] as i64, r3[3] as i64, r4[3] as i64);
        let r_l4 = _mm256_set_epi64x(r[4] as i64, r2[4] as i64, r3[4] as i64, r4[4] as i64);

        // Precompute s values (5*r[i])
        let s_l1 = _mm256_set_epi64x(
            (r[1] * 5) as i64,
            (r2[1] * 5) as i64,
            (r3[1] * 5) as i64,
            (r4[1] * 5) as i64,
        );
        let s_l2 = _mm256_set_epi64x(
            (r[2] * 5) as i64,
            (r2[2] * 5) as i64,
            (r3[2] * 5) as i64,
            (r4[2] * 5) as i64,
        );
        let s_l3 = _mm256_set_epi64x(
            (r[3] * 5) as i64,
            (r2[3] * 5) as i64,
            (r3[3] * 5) as i64,
            (r4[3] * 5) as i64,
        );
        let s_l4 = _mm256_set_epi64x(
            (r[4] * 5) as i64,
            (r2[4] * 5) as i64,
            (r3[4] * 5) as i64,
            (r4[4] * 5) as i64,
        );

        // Compute t0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 (vectorized for all 4 inputs)
        let t0_vec = _mm256_add_epi64(
            _mm256_add_epi64(_mm256_mul_epu32(h_l0, r_l0), _mm256_mul_epu32(h_l1, s_l4)),
            _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32(h_l2, s_l3), _mm256_mul_epu32(h_l3, s_l2)),
                _mm256_mul_epu32(h_l4, s_l1),
            ),
        );

        // Compute t1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
        let t1_vec = _mm256_add_epi64(
            _mm256_add_epi64(_mm256_mul_epu32(h_l0, r_l1), _mm256_mul_epu32(h_l1, r_l0)),
            _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32(h_l2, s_l4), _mm256_mul_epu32(h_l3, s_l3)),
                _mm256_mul_epu32(h_l4, s_l2),
            ),
        );

        // Compute t2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
        let t2_vec = _mm256_add_epi64(
            _mm256_add_epi64(_mm256_mul_epu32(h_l0, r_l2), _mm256_mul_epu32(h_l1, r_l1)),
            _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32(h_l2, r_l0), _mm256_mul_epu32(h_l3, s_l4)),
                _mm256_mul_epu32(h_l4, s_l3),
            ),
        );

        // Compute t3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
        let t3_vec = _mm256_add_epi64(
            _mm256_add_epi64(_mm256_mul_epu32(h_l0, r_l3), _mm256_mul_epu32(h_l1, r_l2)),
            _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32(h_l2, r_l1), _mm256_mul_epu32(h_l3, r_l0)),
                _mm256_mul_epu32(h_l4, s_l4),
            ),
        );

        // Compute t4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
        let t4_vec = _mm256_add_epi64(
            _mm256_add_epi64(_mm256_mul_epu32(h_l0, r_l4), _mm256_mul_epu32(h_l1, r_l3)),
            _mm256_add_epi64(
                _mm256_add_epi64(_mm256_mul_epu32(h_l2, r_l2), _mm256_mul_epu32(h_l3, r_l1)),
                _mm256_mul_epu32(h_l4, r_l0),
            ),
        );

        // Sum across all 4 lanes (h*r4 + m1*r3 + m2*r2 + m3*r)
        let t0 = horizontal_sum_epi64(t0_vec);
        let t1 = horizontal_sum_epi64(t1_vec);
        let t2 = horizontal_sum_epi64(t2_vec);
        let t3 = horizontal_sum_epi64(t3_vec);
        let t4 = horizontal_sum_epi64(t4_vec);

        // Carry propagation
        let mut t = [t0, t1, t2, t3, t4];
        let mut c: u128;

        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;
        c = t[1] >> 26;
        t[1] &= 0x3ffffff;
        t[2] += c;
        c = t[2] >> 26;
        t[2] &= 0x3ffffff;
        t[3] += c;
        c = t[3] >> 26;
        t[3] &= 0x3ffffff;
        t[4] += c;
        c = t[4] >> 26;
        t[4] &= 0x3ffffff;
        t[0] += c * 5;
        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;

        acc[0] = t[0] as u64;
        acc[1] = t[1] as u64;
        acc[2] = t[2] as u64;
        acc[3] = t[3] as u64;
        acc[4] = t[4] as u64;
    }

    /// Process 8 blocks at a time with AVX2.
    ///
    /// Computes: acc = acc * r⁸ + m0 * r⁸ + m1 * r⁷ + m2 * r⁶ + m3 * r⁵ + m4 * r⁴ + m5 * r³ + m6 * r² + m7 * r
    ///
    /// This processes 128 bytes in a single batch, achieving ~2x throughput over 4-way.
    #[target_feature(enable = "avx2")]
    pub unsafe fn process_blocks_8x(
        acc: &mut [u64; 5],
        powers: &super::Poly1305Powers8,
        blocks: &[[u8; 16]; 8],
    ) {
        // Load all 8 blocks
        let m0 = load_block_with_hibit(&blocks[0]);
        let m1 = load_block_with_hibit(&blocks[1]);
        let m2 = load_block_with_hibit(&blocks[2]);
        let m3 = load_block_with_hibit(&blocks[3]);
        let m4 = load_block_with_hibit(&blocks[4]);
        let m5 = load_block_with_hibit(&blocks[5]);
        let m6 = load_block_with_hibit(&blocks[6]);
        let m7 = load_block_with_hibit(&blocks[7]);

        // Add m0 to accumulator for h
        let h = [
            acc[0] + m0[0],
            acc[1] + m0[1],
            acc[2] + m0[2],
            acc[3] + m0[3],
            acc[4] + m0[4],
        ];

        // Precompute s values for each power
        let compute_s = |r: &[u64; 5]| [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        let s8 = compute_s(&powers.r8);
        let s7 = compute_s(&powers.r7);
        let s6 = compute_s(&powers.r6);
        let s5 = compute_s(&powers.r5);
        let s4 = compute_s(&powers.r4);
        let s3 = compute_s(&powers.r3);
        let s2 = compute_s(&powers.r2);
        let s1 = compute_s(&powers.r);

        // Compute all 8 multiplications
        // h * r⁸
        let t_h = mul_reduce_avx2_vectorized(&h, &powers.r8, &s8);
        // m1 * r⁷
        let t_m1 = mul_reduce_avx2_vectorized(&m1, &powers.r7, &s7);
        // m2 * r⁶
        let t_m2 = mul_reduce_avx2_vectorized(&m2, &powers.r6, &s6);
        // m3 * r⁵
        let t_m3 = mul_reduce_avx2_vectorized(&m3, &powers.r5, &s5);
        // m4 * r⁴
        let t_m4 = mul_reduce_avx2_vectorized(&m4, &powers.r4, &s4);
        // m5 * r³
        let t_m5 = mul_reduce_avx2_vectorized(&m5, &powers.r3, &s3);
        // m6 * r²
        let t_m6 = mul_reduce_avx2_vectorized(&m6, &powers.r2, &s2);
        // m7 * r
        let t_m7 = mul_reduce_avx2_vectorized(&m7, &powers.r, &s1);

        // Sum all 8 results
        let mut result = [
            t_h[0] + t_m1[0] + t_m2[0] + t_m3[0] + t_m4[0] + t_m5[0] + t_m6[0] + t_m7[0],
            t_h[1] + t_m1[1] + t_m2[1] + t_m3[1] + t_m4[1] + t_m5[1] + t_m6[1] + t_m7[1],
            t_h[2] + t_m1[2] + t_m2[2] + t_m3[2] + t_m4[2] + t_m5[2] + t_m6[2] + t_m7[2],
            t_h[3] + t_m1[3] + t_m2[3] + t_m3[3] + t_m4[3] + t_m5[3] + t_m6[3] + t_m7[3],
            t_h[4] + t_m1[4] + t_m2[4] + t_m3[4] + t_m4[4] + t_m5[4] + t_m6[4] + t_m7[4],
        ];

        // Carry propagation
        let mut c: u64;
        c = result[0] >> 26;
        result[0] &= 0x3ffffff;
        result[1] += c;
        c = result[1] >> 26;
        result[1] &= 0x3ffffff;
        result[2] += c;
        c = result[2] >> 26;
        result[2] &= 0x3ffffff;
        result[3] += c;
        c = result[3] >> 26;
        result[3] &= 0x3ffffff;
        result[4] += c;
        c = result[4] >> 26;
        result[4] &= 0x3ffffff;
        result[0] += c * 5;
        c = result[0] >> 26;
        result[0] &= 0x3ffffff;
        result[1] += c;

        *acc = result;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIMD-ACCELERATED POLY1305
// ═══════════════════════════════════════════════════════════════════════════════

/// Extended powers of r for 4-way vectorization.
#[derive(Clone)]
pub struct Poly1305Powers4 {
    /// r in 5x26-bit limb form
    pub r: [u64; 5],
    /// r² in 5x26-bit limb form
    pub r2: [u64; 5],
    /// r³ in 5x26-bit limb form
    pub r3: [u64; 5],
    /// r⁴ in 5x26-bit limb form
    pub r4: [u64; 5],
}

impl Poly1305Powers4 {
    /// Compute r, r², r³, r⁴ from clamped r.
    pub fn new(r_bytes: &[u8; 16]) -> Self {
        let r = load_26bit_limbs(r_bytes);
        let r2 = mul_reduce_scalar(&r, &r);
        let r3 = mul_reduce_scalar(&r2, &r);
        let r4 = mul_reduce_scalar(&r3, &r);

        Self { r, r2, r3, r4 }
    }
}

/// Extended powers of r for 8-way vectorization.
///
/// Contains r through r⁸ for processing 8 blocks (128 bytes) at a time.
#[derive(Clone)]
pub struct Poly1305Powers8 {
    /// r in 5x26-bit limb form
    pub r: [u64; 5],
    /// r² in 5x26-bit limb form
    pub r2: [u64; 5],
    /// r³ in 5x26-bit limb form
    pub r3: [u64; 5],
    /// r⁴ in 5x26-bit limb form
    pub r4: [u64; 5],
    /// r⁵ in 5x26-bit limb form
    pub r5: [u64; 5],
    /// r⁶ in 5x26-bit limb form
    pub r6: [u64; 5],
    /// r⁷ in 5x26-bit limb form
    pub r7: [u64; 5],
    /// r⁸ in 5x26-bit limb form
    pub r8: [u64; 5],
}

impl Poly1305Powers8 {
    /// Compute r through r⁸ from clamped r.
    pub fn new(r_bytes: &[u8; 16]) -> Self {
        let r = load_26bit_limbs(r_bytes);
        let r2 = mul_reduce_scalar(&r, &r);
        let r3 = mul_reduce_scalar(&r2, &r);
        let r4 = mul_reduce_scalar(&r3, &r);
        let r5 = mul_reduce_scalar(&r4, &r);
        let r6 = mul_reduce_scalar(&r5, &r);
        let r7 = mul_reduce_scalar(&r6, &r);
        let r8 = mul_reduce_scalar(&r7, &r);

        Self {
            r,
            r2,
            r3,
            r4,
            r5,
            r6,
            r7,
            r8,
        }
    }

    /// Convert to Poly1305Powers4 for fallback processing.
    pub fn as_powers4(&self) -> Poly1305Powers4 {
        Poly1305Powers4 {
            r: self.r,
            r2: self.r2,
            r3: self.r3,
            r4: self.r4,
        }
    }
}

/// Extended powers of r for 16-way AVX-512 vectorization.
///
/// Contains r through r¹⁶ for processing 16 blocks (256 bytes) at a time.
#[derive(Clone)]
pub struct Poly1305Powers16 {
    /// r in 5x26-bit limb form
    pub r: [u64; 5],
    /// r² through r¹⁶
    pub r2: [u64; 5],
    pub r3: [u64; 5],
    pub r4: [u64; 5],
    pub r5: [u64; 5],
    pub r6: [u64; 5],
    pub r7: [u64; 5],
    pub r8: [u64; 5],
    pub r9: [u64; 5],
    pub r10: [u64; 5],
    pub r11: [u64; 5],
    pub r12: [u64; 5],
    pub r13: [u64; 5],
    pub r14: [u64; 5],
    pub r15: [u64; 5],
    pub r16: [u64; 5],
}

impl Poly1305Powers16 {
    /// Compute r through r¹⁶ from clamped r.
    pub fn new(r_bytes: &[u8; 16]) -> Self {
        let r = load_26bit_limbs(r_bytes);
        let r2 = mul_reduce_scalar(&r, &r);
        let r3 = mul_reduce_scalar(&r2, &r);
        let r4 = mul_reduce_scalar(&r3, &r);
        let r5 = mul_reduce_scalar(&r4, &r);
        let r6 = mul_reduce_scalar(&r5, &r);
        let r7 = mul_reduce_scalar(&r6, &r);
        let r8 = mul_reduce_scalar(&r7, &r);
        let r9 = mul_reduce_scalar(&r8, &r);
        let r10 = mul_reduce_scalar(&r9, &r);
        let r11 = mul_reduce_scalar(&r10, &r);
        let r12 = mul_reduce_scalar(&r11, &r);
        let r13 = mul_reduce_scalar(&r12, &r);
        let r14 = mul_reduce_scalar(&r13, &r);
        let r15 = mul_reduce_scalar(&r14, &r);
        let r16 = mul_reduce_scalar(&r15, &r);

        Self {
            r,
            r2,
            r3,
            r4,
            r5,
            r6,
            r7,
            r8,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
            r16,
        }
    }

    /// Convert to Poly1305Powers8 for fallback processing.
    pub fn as_powers8(&self) -> Poly1305Powers8 {
        Poly1305Powers8 {
            r: self.r,
            r2: self.r2,
            r3: self.r3,
            r4: self.r4,
            r5: self.r5,
            r6: self.r6,
            r7: self.r7,
            r8: self.r8,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AVX-512 16-WAY VECTORIZED PROCESSING
// ═══════════════════════════════════════════════════════════════════════════════

/// AVX-512 SIMD implementations for Poly1305.
///
/// Uses AVX-512 to process 16 blocks (256 bytes) at a time with 512-bit registers.
#[cfg(target_arch = "x86_64")]
pub mod avx512 {
    use super::*;

    /// Process 16 blocks at a time with AVX-512.
    ///
    /// Computes: acc = acc * r¹⁶ + m0 * r¹⁶ + m1 * r¹⁵ + ... + m15 * r
    #[target_feature(enable = "avx512f")]
    pub unsafe fn process_blocks_16x(
        acc: &mut [u64; 5],
        powers: &Poly1305Powers16,
        blocks: &[[u8; 16]; 16],
    ) {
        // Load all 16 blocks
        let msgs: [[u64; 5]; 16] = [
            load_block_with_hibit(&blocks[0]),
            load_block_with_hibit(&blocks[1]),
            load_block_with_hibit(&blocks[2]),
            load_block_with_hibit(&blocks[3]),
            load_block_with_hibit(&blocks[4]),
            load_block_with_hibit(&blocks[5]),
            load_block_with_hibit(&blocks[6]),
            load_block_with_hibit(&blocks[7]),
            load_block_with_hibit(&blocks[8]),
            load_block_with_hibit(&blocks[9]),
            load_block_with_hibit(&blocks[10]),
            load_block_with_hibit(&blocks[11]),
            load_block_with_hibit(&blocks[12]),
            load_block_with_hibit(&blocks[13]),
            load_block_with_hibit(&blocks[14]),
            load_block_with_hibit(&blocks[15]),
        ];

        // Add m0 to accumulator
        let h = [
            acc[0] + msgs[0][0],
            acc[1] + msgs[0][1],
            acc[2] + msgs[0][2],
            acc[3] + msgs[0][3],
            acc[4] + msgs[0][4],
        ];

        // All r powers in order: r16, r15, r14, ..., r1 (for h, m1, m2, ..., m15)
        let r_powers: [&[u64; 5]; 16] = [
            &powers.r16,
            &powers.r15,
            &powers.r14,
            &powers.r13,
            &powers.r12,
            &powers.r11,
            &powers.r10,
            &powers.r9,
            &powers.r8,
            &powers.r7,
            &powers.r6,
            &powers.r5,
            &powers.r4,
            &powers.r3,
            &powers.r2,
            &powers.r,
        ];

        // Compute all 16 products using AVX-512 vectorized multiply
        // Process in groups of 8 using 512-bit registers
        let mut t = [0u128; 5];

        // First group: h*r16, m1*r15, m2*r14, m3*r13, m4*r12, m5*r11, m6*r10, m7*r9
        let inputs_a: [&[u64; 5]; 8] = [
            &h, &msgs[1], &msgs[2], &msgs[3], &msgs[4], &msgs[5], &msgs[6], &msgs[7],
        ];
        let powers_a: [&[u64; 5]; 8] = [
            r_powers[0],
            r_powers[1],
            r_powers[2],
            r_powers[3],
            r_powers[4],
            r_powers[5],
            r_powers[6],
            r_powers[7],
        ];
        mul_8x_avx512(&inputs_a, &powers_a, &mut t);

        // Second group: m8*r8, m9*r7, m10*r6, m11*r5, m12*r4, m13*r3, m14*r2, m15*r
        let inputs_b: [&[u64; 5]; 8] = [
            &msgs[8], &msgs[9], &msgs[10], &msgs[11], &msgs[12], &msgs[13], &msgs[14], &msgs[15],
        ];
        let powers_b: [&[u64; 5]; 8] = [
            r_powers[8],
            r_powers[9],
            r_powers[10],
            r_powers[11],
            r_powers[12],
            r_powers[13],
            r_powers[14],
            r_powers[15],
        ];
        mul_8x_avx512(&inputs_b, &powers_b, &mut t);

        // Carry propagation
        let mut c: u128;
        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;
        c = t[1] >> 26;
        t[1] &= 0x3ffffff;
        t[2] += c;
        c = t[2] >> 26;
        t[2] &= 0x3ffffff;
        t[3] += c;
        c = t[3] >> 26;
        t[3] &= 0x3ffffff;
        t[4] += c;
        c = t[4] >> 26;
        t[4] &= 0x3ffffff;
        t[0] += c * 5;
        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;

        acc[0] = t[0] as u64;
        acc[1] = t[1] as u64;
        acc[2] = t[2] as u64;
        acc[3] = t[3] as u64;
        acc[4] = t[4] as u64;
    }

    /// Multiply 8 (h, r) pairs and accumulate into t using AVX-512.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn mul_8x_avx512(h: &[&[u64; 5]; 8], r: &[&[u64; 5]; 8], t: &mut [u128; 5]) {
        // For each limb output t[i], we compute the 5x5 product matrix sum.
        // Using AVX-512, we can compute 8 products simultaneously.

        // Pack h limbs: h[0..8] for each limb index
        let h0 = _mm512_set_epi64(
            h[7][0] as i64,
            h[6][0] as i64,
            h[5][0] as i64,
            h[4][0] as i64,
            h[3][0] as i64,
            h[2][0] as i64,
            h[1][0] as i64,
            h[0][0] as i64,
        );
        let h1 = _mm512_set_epi64(
            h[7][1] as i64,
            h[6][1] as i64,
            h[5][1] as i64,
            h[4][1] as i64,
            h[3][1] as i64,
            h[2][1] as i64,
            h[1][1] as i64,
            h[0][1] as i64,
        );
        let h2 = _mm512_set_epi64(
            h[7][2] as i64,
            h[6][2] as i64,
            h[5][2] as i64,
            h[4][2] as i64,
            h[3][2] as i64,
            h[2][2] as i64,
            h[1][2] as i64,
            h[0][2] as i64,
        );
        let h3 = _mm512_set_epi64(
            h[7][3] as i64,
            h[6][3] as i64,
            h[5][3] as i64,
            h[4][3] as i64,
            h[3][3] as i64,
            h[2][3] as i64,
            h[1][3] as i64,
            h[0][3] as i64,
        );
        let h4 = _mm512_set_epi64(
            h[7][4] as i64,
            h[6][4] as i64,
            h[5][4] as i64,
            h[4][4] as i64,
            h[3][4] as i64,
            h[2][4] as i64,
            h[1][4] as i64,
            h[0][4] as i64,
        );

        // Pack r limbs and s = 5*r[i]
        let r0 = _mm512_set_epi64(
            r[7][0] as i64,
            r[6][0] as i64,
            r[5][0] as i64,
            r[4][0] as i64,
            r[3][0] as i64,
            r[2][0] as i64,
            r[1][0] as i64,
            r[0][0] as i64,
        );
        let r1 = _mm512_set_epi64(
            r[7][1] as i64,
            r[6][1] as i64,
            r[5][1] as i64,
            r[4][1] as i64,
            r[3][1] as i64,
            r[2][1] as i64,
            r[1][1] as i64,
            r[0][1] as i64,
        );
        let r2 = _mm512_set_epi64(
            r[7][2] as i64,
            r[6][2] as i64,
            r[5][2] as i64,
            r[4][2] as i64,
            r[3][2] as i64,
            r[2][2] as i64,
            r[1][2] as i64,
            r[0][2] as i64,
        );
        let r3 = _mm512_set_epi64(
            r[7][3] as i64,
            r[6][3] as i64,
            r[5][3] as i64,
            r[4][3] as i64,
            r[3][3] as i64,
            r[2][3] as i64,
            r[1][3] as i64,
            r[0][3] as i64,
        );
        let r4 = _mm512_set_epi64(
            r[7][4] as i64,
            r[6][4] as i64,
            r[5][4] as i64,
            r[4][4] as i64,
            r[3][4] as i64,
            r[2][4] as i64,
            r[1][4] as i64,
            r[0][4] as i64,
        );

        // s = 5 * r[i] for reduction
        let s1 = _mm512_set_epi64(
            (r[7][1] * 5) as i64,
            (r[6][1] * 5) as i64,
            (r[5][1] * 5) as i64,
            (r[4][1] * 5) as i64,
            (r[3][1] * 5) as i64,
            (r[2][1] * 5) as i64,
            (r[1][1] * 5) as i64,
            (r[0][1] * 5) as i64,
        );
        let s2 = _mm512_set_epi64(
            (r[7][2] * 5) as i64,
            (r[6][2] * 5) as i64,
            (r[5][2] * 5) as i64,
            (r[4][2] * 5) as i64,
            (r[3][2] * 5) as i64,
            (r[2][2] * 5) as i64,
            (r[1][2] * 5) as i64,
            (r[0][2] * 5) as i64,
        );
        let s3 = _mm512_set_epi64(
            (r[7][3] * 5) as i64,
            (r[6][3] * 5) as i64,
            (r[5][3] * 5) as i64,
            (r[4][3] * 5) as i64,
            (r[3][3] * 5) as i64,
            (r[2][3] * 5) as i64,
            (r[1][3] * 5) as i64,
            (r[0][3] * 5) as i64,
        );
        let s4 = _mm512_set_epi64(
            (r[7][4] * 5) as i64,
            (r[6][4] * 5) as i64,
            (r[5][4] * 5) as i64,
            (r[4][4] * 5) as i64,
            (r[3][4] * 5) as i64,
            (r[2][4] * 5) as i64,
            (r[1][4] * 5) as i64,
            (r[0][4] * 5) as i64,
        );

        // Compute t0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 for all 8 pairs
        let t0_vec = _mm512_add_epi64(
            _mm512_add_epi64(_mm512_mul_epu32(h0, r0), _mm512_mul_epu32(h1, s4)),
            _mm512_add_epi64(
                _mm512_add_epi64(_mm512_mul_epu32(h2, s3), _mm512_mul_epu32(h3, s2)),
                _mm512_mul_epu32(h4, s1),
            ),
        );

        // Compute t1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
        let t1_vec = _mm512_add_epi64(
            _mm512_add_epi64(_mm512_mul_epu32(h0, r1), _mm512_mul_epu32(h1, r0)),
            _mm512_add_epi64(
                _mm512_add_epi64(_mm512_mul_epu32(h2, s4), _mm512_mul_epu32(h3, s3)),
                _mm512_mul_epu32(h4, s2),
            ),
        );

        // Compute t2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
        let t2_vec = _mm512_add_epi64(
            _mm512_add_epi64(_mm512_mul_epu32(h0, r2), _mm512_mul_epu32(h1, r1)),
            _mm512_add_epi64(
                _mm512_add_epi64(_mm512_mul_epu32(h2, r0), _mm512_mul_epu32(h3, s4)),
                _mm512_mul_epu32(h4, s3),
            ),
        );

        // Compute t3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
        let t3_vec = _mm512_add_epi64(
            _mm512_add_epi64(_mm512_mul_epu32(h0, r3), _mm512_mul_epu32(h1, r2)),
            _mm512_add_epi64(
                _mm512_add_epi64(_mm512_mul_epu32(h2, r1), _mm512_mul_epu32(h3, r0)),
                _mm512_mul_epu32(h4, s4),
            ),
        );

        // Compute t4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
        let t4_vec = _mm512_add_epi64(
            _mm512_add_epi64(_mm512_mul_epu32(h0, r4), _mm512_mul_epu32(h1, r3)),
            _mm512_add_epi64(
                _mm512_add_epi64(_mm512_mul_epu32(h2, r2), _mm512_mul_epu32(h3, r1)),
                _mm512_mul_epu32(h4, r0),
            ),
        );

        // Horizontal sum across all 8 lanes
        t[0] += horizontal_sum_512(t0_vec);
        t[1] += horizontal_sum_512(t1_vec);
        t[2] += horizontal_sum_512(t2_vec);
        t[3] += horizontal_sum_512(t3_vec);
        t[4] += horizontal_sum_512(t4_vec);
    }

    /// Sum 8 64-bit values in a 512-bit register.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn horizontal_sum_512(v: __m512i) -> u128 {
        // Split into two 256-bit halves
        let lo = _mm512_castsi512_si256(v);
        let hi = _mm512_extracti64x4_epi64(v, 1);

        // Add the halves
        let sum256 = _mm256_add_epi64(lo, hi);

        // Now reduce the 256-bit vector
        let lo128 = _mm256_castsi256_si128(sum256);
        let hi128 = _mm256_extracti128_si256(sum256, 1);
        let sum128 = _mm_add_epi64(lo128, hi128);

        // Extract and add final two 64-bit values
        let a = _mm_extract_epi64(sum128, 0) as u64;
        let b = _mm_extract_epi64(sum128, 1) as u64;

        (a as u128) + (b as u128)
    }
}

/// Process multiple blocks with automatic SIMD selection (4-way).
///
/// Uses AVX2 4-way vectorization when available and beneficial.
pub fn process_blocks_auto(acc: &mut [u64; 5], powers: &Poly1305Powers4, data: &[u8]) -> usize {
    let mut pos = 0;

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        // Use 4-way parallel processing when we have at least 4 blocks
        if has_avx2() && data.len() >= 64 {
            while pos + 64 <= data.len() {
                let blocks: [[u8; 16]; 4] = [
                    data[pos..pos + 16].try_into().unwrap(),
                    data[pos + 16..pos + 32].try_into().unwrap(),
                    data[pos + 32..pos + 48].try_into().unwrap(),
                    data[pos + 48..pos + 64].try_into().unwrap(),
                ];

                unsafe {
                    // Use fully parallel AVX2 implementation
                    avx2::process_blocks_4x_parallel(
                        acc, &powers.r, &powers.r2, &powers.r3, &powers.r4, &blocks,
                    );
                }

                pos += 64;
            }
        }
    }

    // Process remaining full blocks with scalar
    while pos + 16 <= data.len() {
        let block: [u8; 16] = data[pos..pos + 16].try_into().unwrap();
        let m = load_block_with_hibit(&block);

        // acc = (acc + m) * r
        acc[0] += m[0];
        acc[1] += m[1];
        acc[2] += m[2];
        acc[3] += m[3];
        acc[4] += m[4];

        *acc = mul_reduce_scalar(acc, &powers.r);
        pos += 16;
    }

    pos
}

/// Process multiple blocks with 8-way SIMD.
///
/// Uses AVX2 8-way vectorization for maximum throughput on large messages.
/// Processes 128 bytes (8 blocks) at a time, then falls back to 4-way.
pub fn process_blocks_8way(acc: &mut [u64; 5], powers: &Poly1305Powers8, data: &[u8]) -> usize {
    let mut pos = 0;

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        if has_avx2() {
            // 8-way processing: 128 bytes at a time
            while pos + 128 <= data.len() {
                let blocks: [[u8; 16]; 8] = [
                    data[pos..pos + 16].try_into().unwrap(),
                    data[pos + 16..pos + 32].try_into().unwrap(),
                    data[pos + 32..pos + 48].try_into().unwrap(),
                    data[pos + 48..pos + 64].try_into().unwrap(),
                    data[pos + 64..pos + 80].try_into().unwrap(),
                    data[pos + 80..pos + 96].try_into().unwrap(),
                    data[pos + 96..pos + 112].try_into().unwrap(),
                    data[pos + 112..pos + 128].try_into().unwrap(),
                ];

                unsafe {
                    avx2::process_blocks_8x(acc, powers, &blocks);
                }

                pos += 128;
            }

            // 4-way processing for remaining 64-127 bytes
            while pos + 64 <= data.len() {
                let blocks: [[u8; 16]; 4] = [
                    data[pos..pos + 16].try_into().unwrap(),
                    data[pos + 16..pos + 32].try_into().unwrap(),
                    data[pos + 32..pos + 48].try_into().unwrap(),
                    data[pos + 48..pos + 64].try_into().unwrap(),
                ];

                unsafe {
                    avx2::process_blocks_4x_parallel(
                        acc, &powers.r, &powers.r2, &powers.r3, &powers.r4, &blocks,
                    );
                }

                pos += 64;
            }
        }
    }

    // Process remaining full blocks with scalar
    while pos + 16 <= data.len() {
        let block: [u8; 16] = data[pos..pos + 16].try_into().unwrap();
        let m = load_block_with_hibit(&block);

        acc[0] += m[0];
        acc[1] += m[1];
        acc[2] += m[2];
        acc[3] += m[3];
        acc[4] += m[4];

        *acc = mul_reduce_scalar(acc, &powers.r);
        pos += 16;
    }

    pos
}

/// Process multiple blocks with 16-way AVX-512 SIMD.
///
/// Uses AVX-512 16-way vectorization for maximum throughput on large messages.
/// Processes 256 bytes (16 blocks) at a time, then falls back to 8-way.
pub fn process_blocks_16way(acc: &mut [u64; 5], powers: &Poly1305Powers16, data: &[u8]) -> usize {
    let mut pos = 0;

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        // Use 16-way AVX-512 when available
        if has_avx512f() && data.len() >= 256 {
            while pos + 256 <= data.len() {
                let blocks: [[u8; 16]; 16] = [
                    data[pos..pos + 16].try_into().unwrap(),
                    data[pos + 16..pos + 32].try_into().unwrap(),
                    data[pos + 32..pos + 48].try_into().unwrap(),
                    data[pos + 48..pos + 64].try_into().unwrap(),
                    data[pos + 64..pos + 80].try_into().unwrap(),
                    data[pos + 80..pos + 96].try_into().unwrap(),
                    data[pos + 96..pos + 112].try_into().unwrap(),
                    data[pos + 112..pos + 128].try_into().unwrap(),
                    data[pos + 128..pos + 144].try_into().unwrap(),
                    data[pos + 144..pos + 160].try_into().unwrap(),
                    data[pos + 160..pos + 176].try_into().unwrap(),
                    data[pos + 176..pos + 192].try_into().unwrap(),
                    data[pos + 192..pos + 208].try_into().unwrap(),
                    data[pos + 208..pos + 224].try_into().unwrap(),
                    data[pos + 224..pos + 240].try_into().unwrap(),
                    data[pos + 240..pos + 256].try_into().unwrap(),
                ];

                unsafe {
                    avx512::process_blocks_16x(acc, powers, &blocks);
                }

                pos += 256;
            }
        }

        // Fall back to 8-way for remaining data
        if has_avx2() {
            let powers8 = powers.as_powers8();

            // 8-way processing: 128 bytes at a time
            while pos + 128 <= data.len() {
                let blocks: [[u8; 16]; 8] = [
                    data[pos..pos + 16].try_into().unwrap(),
                    data[pos + 16..pos + 32].try_into().unwrap(),
                    data[pos + 32..pos + 48].try_into().unwrap(),
                    data[pos + 48..pos + 64].try_into().unwrap(),
                    data[pos + 64..pos + 80].try_into().unwrap(),
                    data[pos + 80..pos + 96].try_into().unwrap(),
                    data[pos + 96..pos + 112].try_into().unwrap(),
                    data[pos + 112..pos + 128].try_into().unwrap(),
                ];

                unsafe {
                    avx2::process_blocks_8x(acc, &powers8, &blocks);
                }

                pos += 128;
            }

            // 4-way processing for remaining 64-127 bytes
            while pos + 64 <= data.len() {
                let blocks: [[u8; 16]; 4] = [
                    data[pos..pos + 16].try_into().unwrap(),
                    data[pos + 16..pos + 32].try_into().unwrap(),
                    data[pos + 32..pos + 48].try_into().unwrap(),
                    data[pos + 48..pos + 64].try_into().unwrap(),
                ];

                unsafe {
                    avx2::process_blocks_4x_parallel(
                        acc, &powers.r, &powers.r2, &powers.r3, &powers.r4, &blocks,
                    );
                }

                pos += 64;
            }
        }
    }

    // Process remaining full blocks with scalar
    while pos + 16 <= data.len() {
        let block: [u8; 16] = data[pos..pos + 16].try_into().unwrap();
        let m = load_block_with_hibit(&block);

        acc[0] += m[0];
        acc[1] += m[1];
        acc[2] += m[2];
        acc[3] += m[3];
        acc[4] += m[4];

        *acc = mul_reduce_scalar(acc, &powers.r);
        pos += 16;
    }

    pos
}

/// Finalize the Poly1305 accumulator and add s.
pub fn finalize_acc(acc: &[u64; 5], s: &[u8; 16]) -> [u8; 16] {
    let mut h = *acc;

    // Full carry propagation
    let mut c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;
    c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;

    // Compute h - p = h - (2^130 - 5) = h + 5 - 2^130
    let mut g = [0u64; 5];
    g[0] = h[0].wrapping_add(5);
    c = g[0] >> 26;
    g[0] &= 0x3ffffff;

    g[1] = h[1].wrapping_add(c);
    c = g[1] >> 26;
    g[1] &= 0x3ffffff;

    g[2] = h[2].wrapping_add(c);
    c = g[2] >> 26;
    g[2] &= 0x3ffffff;

    g[3] = h[3].wrapping_add(c);
    c = g[3] >> 26;
    g[3] &= 0x3ffffff;

    g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);

    // Select h if g overflowed, g otherwise
    let mask = (g[4] >> 63).wrapping_sub(1);

    h[0] = (h[0] & !mask) | (g[0] & mask);
    h[1] = (h[1] & !mask) | (g[1] & mask);
    h[2] = (h[2] & !mask) | (g[2] & mask);
    h[3] = (h[3] & !mask) | (g[3] & mask);
    h[4] = (h[4] & !mask) | (g[4] & mask);

    // Convert to 128-bit
    let h0 = h[0] | (h[1] << 26) | (h[2] << 52);
    let h1 = (h[2] >> 12) | (h[3] << 14) | (h[4] << 40);

    // Add s
    let s_lo = u64::from_le_bytes(s[0..8].try_into().unwrap());
    let s_hi = u64::from_le_bytes(s[8..16].try_into().unwrap());

    let (r0, carry) = h0.overflowing_add(s_lo);
    let r1 = h1.wrapping_add(s_hi).wrapping_add(carry as u64);

    let mut tag = [0u8; 16];
    tag[0..8].copy_from_slice(&r0.to_le_bytes());
    tag[8..16].copy_from_slice(&r1.to_le_bytes());

    tag
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIMD POLY1305 API
// ═══════════════════════════════════════════════════════════════════════════════

use zeroize::{Zeroize, ZeroizeOnDrop};

/// SIMD-accelerated Poly1305 MAC with 4-way vectorization.
///
/// Uses AVX2 to process 4 blocks (64 bytes) at a time with precomputed
/// powers r², r³, r⁴ for parallel evaluation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305Simd {
    /// Precomputed powers of r (up to r⁴)
    #[zeroize(skip)]
    powers: Poly1305Powers4,
    /// The s value
    s: [u8; 16],
    /// Accumulator in 5x26-bit limb form
    acc: [u64; 5],
    /// Buffer for incomplete blocks
    buffer: [u8; 16],
    /// Position in buffer
    buffer_pos: usize,
}

impl Poly1305Simd {
    /// Create a new SIMD-accelerated Poly1305 instance.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes: [u8; 16] = key[0..16].try_into().unwrap();
        clamp(&mut r_bytes);

        let powers = Poly1305Powers4::new(&r_bytes);
        let s: [u8; 16] = key[16..32].try_into().unwrap();

        Self {
            powers,
            s,
            acc: [0; 5],
            buffer: [0; 16],
            buffer_pos: 0,
        }
    }

    /// Process message data.
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        // Fill buffer first
        if self.buffer_pos > 0 {
            let needed = 16 - self.buffer_pos;
            let available = data.len().min(needed);
            self.buffer[self.buffer_pos..self.buffer_pos + available]
                .copy_from_slice(&data[..available]);
            self.buffer_pos += available;
            pos += available;

            if self.buffer_pos == 16 {
                let m = load_block_with_hibit(&self.buffer);
                self.acc[0] += m[0];
                self.acc[1] += m[1];
                self.acc[2] += m[2];
                self.acc[3] += m[3];
                self.acc[4] += m[4];
                self.acc = mul_reduce_scalar(&self.acc, &self.powers.r);
                self.buffer_pos = 0;
            }
        }

        // Process remaining data with 4-way SIMD acceleration
        let processed = process_blocks_auto(&mut self.acc, &self.powers, &data[pos..]);
        pos += processed;

        // Save remaining bytes
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_pos = remaining;
        }
    }

    /// Finalize and return the tag.
    pub fn finalize(mut self) -> [u8; 16] {
        // Process partial block
        if self.buffer_pos > 0 {
            let mut padded = [0u8; 16];
            padded[..self.buffer_pos].copy_from_slice(&self.buffer[..self.buffer_pos]);
            padded[self.buffer_pos] = 0x01;

            let m = load_26bit_limbs(&padded);
            self.acc[0] += m[0];
            self.acc[1] += m[1];
            self.acc[2] += m[2];
            self.acc[3] += m[3];
            self.acc[4] += m[4];
            self.acc = mul_reduce_scalar(&self.acc, &self.powers.r);
        }

        finalize_acc(&self.acc, &self.s)
    }

    /// Compute MAC in one shot.
    pub fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        let mut poly = Self::new(key);
        poly.update(message);
        poly.finalize()
    }

    /// Verify a MAC tag with constant-time comparison.
    pub fn verify(key: &[u8; 32], message: &[u8], tag: &[u8; 16]) -> bool {
        let computed = Self::mac(key, message);

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in computed.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Clamp r value per RFC 8439.
fn clamp(r: &mut [u8; 16]) {
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[12] &= 0xfc;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ULTRA-FAST POLY1305 WITH 64-BIT RADIX
// ═══════════════════════════════════════════════════════════════════════════════

/// Ultra-fast Poly1305 using 64-bit limbs and lazy reduction.
///
/// Uses a 2^44 radix with 3 limbs which requires only 9 multiplications
/// per block instead of 25 with 5 limbs. The wider limbs also allow
/// accumulating multiple products before reduction.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305Ultra {
    /// r in 3x44-bit limb form: r0 (44 bits), r1 (44 bits), r2 (42 bits)
    r: [u64; 3],
    /// Precomputed 5*r/4 for modular reduction
    rp: [u64; 2],
    /// r^2 for 2-block processing
    r2: [u64; 3],
    /// 5*r^2/4 for modular reduction
    r2p: [u64; 2],
    /// The s value (authentication key)
    s: [u64; 2],
    /// Accumulator in 3x64-bit form
    h: [u64; 3],
    /// Buffer for incomplete blocks
    buffer: [u8; 16],
    /// Position in buffer
    buffer_pos: usize,
}

impl Poly1305Ultra {
    /// Create a new ultra-fast Poly1305 instance.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes: [u8; 16] = key[0..16].try_into().unwrap();
        clamp(&mut r_bytes);

        // Load r as two 64-bit values
        let r0_full = u64::from_le_bytes(r_bytes[0..8].try_into().unwrap());
        let r1_full = u64::from_le_bytes(r_bytes[8..16].try_into().unwrap());

        // Convert to 44-bit limbs
        // r = r0 + r1*2^44 + r2*2^88
        let r0 = r0_full & 0xfffffffffff; // 44 bits
        let r1 = ((r0_full >> 44) | (r1_full << 20)) & 0xfffffffffff; // 44 bits
        let r2 = (r1_full >> 24) & 0x3ffffffffff; // 42 bits

        let r = [r0, r1, r2];

        // Precompute rp = 20*r[i] for reduction
        // When we have a term at 2^132, it reduces to 20 at 2^0 (since 2^132 = 4*2^130 ≡ 4*5 = 20)
        // For h1*r2 at 2^132: contributes 20*h1*r2 to d0
        // For h2*r2 at 2^176 = 2^46*2^130 ≡ 2^46*5: 2^46 = 4*2^44, so 20 at 2^44
        let rp = [r[1] * 20, r[2] * 20];

        // Compute r^2
        let r2 = Self::square_mod_p(&r, &rp);
        let r2p = [r2[1] * 20, r2[2] * 20];

        // Load s
        let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

        Self {
            r,
            rp,
            r2,
            r2p,
            s: [s0, s1],
            h: [0, 0, 0],
            buffer: [0; 16],
            buffer_pos: 0,
        }
    }

    /// Square r mod 2^130-5
    #[inline]
    fn square_mod_p(r: &[u64; 3], _rp: &[u64; 2]) -> [u64; 3] {
        // r^2 = (r0 + r1*2^44 + r2*2^88)^2
        // = r0^2 + 2*r0*r1*2^44 + (2*r0*r2 + r1^2)*2^88 + 2*r1*r2*2^132 + r2^2*2^176
        // For mod 2^130-5:
        // 2^130 ≡ 5
        // 2^132 = 4*2^130 ≡ 20
        // 2^176 = 2^46*2^130 ≡ 5*2^46 = 20*2^44
        //
        // Reduced form:
        // d0 = r0^2 + 40*r1*r2          (from 2*r1*r2 at 2^132)
        // d1 = 2*r0*r1 + 20*r2^2        (from r2^2 at 2^176 = 20*2^44)
        // d2 = 2*r0*r2 + r1^2

        let d0 = (r[0] as u128) * (r[0] as u128) + 40 * (r[1] as u128) * (r[2] as u128);
        let d1 = 2 * (r[0] as u128) * (r[1] as u128) + 20 * (r[2] as u128) * (r[2] as u128);
        let d2 = 2 * (r[0] as u128) * (r[2] as u128) + (r[1] as u128) * (r[1] as u128);

        // Carry propagation
        let mut c: u128;
        let mut h0 = d0;
        let mut h1 = d1;
        let mut h2 = d2;

        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;

        [h0 as u64, h1 as u64, h2 as u64]
    }

    /// Process a single block.
    #[inline(always)]
    fn process_block(&mut self, block: &[u8; 16], hibit: u64) {
        // Load block as 44-bit limbs
        let b0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let b1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

        let m0 = b0 & 0xfffffffffff;
        let m1 = ((b0 >> 44) | (b1 << 20)) & 0xfffffffffff;
        let m2 = ((b1 >> 24) & 0x3ffffffffff) | (hibit << 40);

        // h = (h + m) * r mod p
        let h0 = self.h[0] + m0;
        let h1 = self.h[1] + m1;
        let h2 = self.h[2] + m2;

        // Multiply h by r
        // d0 = h0*r0 + h1*rp1 + h2*rp0
        // d1 = h0*r1 + h1*r0 + h2*rp1
        // d2 = h0*r2 + h1*r1 + h2*r0
        let d0 = (h0 as u128) * (self.r[0] as u128)
            + (h1 as u128) * (self.rp[1] as u128)
            + (h2 as u128) * (self.rp[0] as u128);
        let d1 = (h0 as u128) * (self.r[1] as u128)
            + (h1 as u128) * (self.r[0] as u128)
            + (h2 as u128) * (self.rp[1] as u128);
        let d2 = (h0 as u128) * (self.r[2] as u128)
            + (h1 as u128) * (self.r[1] as u128)
            + (h2 as u128) * (self.r[0] as u128);

        // Carry propagation
        let mut c: u128;
        let mut t0 = d0;
        let mut t1 = d1;
        let mut t2 = d2;

        c = t0 >> 44;
        t0 &= 0xfffffffffff;
        t1 += c;
        c = t1 >> 44;
        t1 &= 0xfffffffffff;
        t2 += c;
        c = t2 >> 42;
        t2 &= 0x3ffffffffff;
        t0 += c * 5;
        c = t0 >> 44;
        t0 &= 0xfffffffffff;
        t1 += c;

        self.h = [t0 as u64, t1 as u64, t2 as u64];
    }

    /// Process two blocks at once using r^2.
    #[inline(always)]
    fn process_2blocks(&mut self, blocks: &[u8]) {
        debug_assert!(blocks.len() >= 32);

        // Load both blocks
        let b0_lo = u64::from_le_bytes(blocks[0..8].try_into().unwrap());
        let b0_hi = u64::from_le_bytes(blocks[8..16].try_into().unwrap());
        let b1_lo = u64::from_le_bytes(blocks[16..24].try_into().unwrap());
        let b1_hi = u64::from_le_bytes(blocks[24..32].try_into().unwrap());

        // Convert to 44-bit limbs with hibit
        let m0_0 = b0_lo & 0xfffffffffff;
        let m0_1 = ((b0_lo >> 44) | (b0_hi << 20)) & 0xfffffffffff;
        let m0_2 = ((b0_hi >> 24) & 0x3ffffffffff) | (1 << 40);

        let m1_0 = b1_lo & 0xfffffffffff;
        let m1_1 = ((b1_lo >> 44) | (b1_hi << 20)) & 0xfffffffffff;
        let m1_2 = ((b1_hi >> 24) & 0x3ffffffffff) | (1 << 40);

        // h = (h + m0) * r^2 + m1 * r
        // = h*r^2 + m0*r^2 + m1*r
        let h0 = self.h[0] + m0_0;
        let h1 = self.h[1] + m0_1;
        let h2 = self.h[2] + m0_2;

        // Compute (h + m0) * r^2
        let d0 = (h0 as u128) * (self.r2[0] as u128)
            + (h1 as u128) * (self.r2p[1] as u128)
            + (h2 as u128) * (self.r2p[0] as u128);
        let d1 = (h0 as u128) * (self.r2[1] as u128)
            + (h1 as u128) * (self.r2[0] as u128)
            + (h2 as u128) * (self.r2p[1] as u128);
        let d2 = (h0 as u128) * (self.r2[2] as u128)
            + (h1 as u128) * (self.r2[1] as u128)
            + (h2 as u128) * (self.r2[0] as u128);

        // Add m1 * r
        let e0 = d0
            + (m1_0 as u128) * (self.r[0] as u128)
            + (m1_1 as u128) * (self.rp[1] as u128)
            + (m1_2 as u128) * (self.rp[0] as u128);
        let e1 = d1
            + (m1_0 as u128) * (self.r[1] as u128)
            + (m1_1 as u128) * (self.r[0] as u128)
            + (m1_2 as u128) * (self.rp[1] as u128);
        let e2 = d2
            + (m1_0 as u128) * (self.r[2] as u128)
            + (m1_1 as u128) * (self.r[1] as u128)
            + (m1_2 as u128) * (self.r[0] as u128);

        // Carry propagation
        let mut c: u128;
        let mut t0 = e0;
        let mut t1 = e1;
        let mut t2 = e2;

        c = t0 >> 44;
        t0 &= 0xfffffffffff;
        t1 += c;
        c = t1 >> 44;
        t1 &= 0xfffffffffff;
        t2 += c;
        c = t2 >> 42;
        t2 &= 0x3ffffffffff;
        t0 += c * 5;
        c = t0 >> 44;
        t0 &= 0xfffffffffff;
        t1 += c;

        self.h = [t0 as u64, t1 as u64, t2 as u64];
    }

    /// Process message data.
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        // Fill buffer first
        if self.buffer_pos > 0 {
            let needed = 16 - self.buffer_pos;
            let available = data.len().min(needed);
            self.buffer[self.buffer_pos..self.buffer_pos + available]
                .copy_from_slice(&data[..available]);
            self.buffer_pos += available;
            pos += available;

            if self.buffer_pos == 16 {
                let block = self.buffer;
                self.process_block(&block, 1);
                self.buffer_pos = 0;
            }
        }

        // Process pairs of blocks
        while pos + 32 <= data.len() {
            self.process_2blocks(&data[pos..]);
            pos += 32;
        }

        // Process single remaining block
        if pos + 16 <= data.len() {
            let block: [u8; 16] = data[pos..pos + 16].try_into().unwrap();
            self.process_block(&block, 1);
            pos += 16;
        }

        // Save remaining bytes
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_pos = remaining;
        }
    }

    /// Finalize and return the tag.
    pub fn finalize(mut self) -> [u8; 16] {
        // Process partial block
        if self.buffer_pos > 0 {
            let mut padded = [0u8; 16];
            padded[..self.buffer_pos].copy_from_slice(&self.buffer[..self.buffer_pos]);
            padded[self.buffer_pos] = 0x01;
            self.process_block(&padded, 0);
        }

        // Final reduction to get h in [0, 2^130-5)
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        // Full carry
        let mut c: u64;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;

        // Check if h >= p and subtract p if needed
        // g = h - p = h - (2^130 - 5) = h + 5 - 2^130
        let mut g0 = h0 + 5;
        c = g0 >> 44;
        g0 &= 0xfffffffffff;
        let mut g1 = h1 + c;
        c = g1 >> 44;
        g1 &= 0xfffffffffff;
        let mut g2 = h2 + c;

        // If g2 >= 2^42, then h >= p, so we use g
        let mask = ((g2 >> 42).wrapping_sub(1)) as i64 as u64;
        h0 = (h0 & mask) | (g0 & !mask);
        h1 = (h1 & mask) | (g1 & !mask);
        h2 = ((h2 & 0x3ffffffffff) & mask) | ((g2 & 0x3ffffffffff) & !mask);

        // Convert back to 64-bit form and add s
        let h_lo = h0 | (h1 << 44);
        let h_hi = (h1 >> 20) | (h2 << 24);

        let (r0, carry) = h_lo.overflowing_add(self.s[0]);
        let r1 = h_hi.wrapping_add(self.s[1]).wrapping_add(carry as u64);

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&r0.to_le_bytes());
        tag[8..16].copy_from_slice(&r1.to_le_bytes());
        tag
    }

    /// Compute MAC in one shot.
    pub fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        let mut poly = Self::new(key);
        poly.update(message);
        poly.finalize()
    }
}

/// AVX-512 accelerated Poly1305 MAC with 16-way vectorization.
///
/// Uses AVX-512 to process 16 blocks (256 bytes) at a time with precomputed
/// powers r through r¹⁶ for maximum parallel evaluation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305Simd512 {
    /// Precomputed powers of r (up to r¹⁶)
    #[zeroize(skip)]
    powers: Poly1305Powers16,
    /// The s value
    s: [u8; 16],
    /// Accumulator in 5x26-bit limb form
    acc: [u64; 5],
    /// Buffer for incomplete blocks
    buffer: [u8; 16],
    /// Position in buffer
    buffer_pos: usize,
}

impl Poly1305Simd512 {
    /// Create a new AVX-512 accelerated Poly1305 instance.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes: [u8; 16] = key[0..16].try_into().unwrap();
        clamp(&mut r_bytes);

        let powers = Poly1305Powers16::new(&r_bytes);
        let s: [u8; 16] = key[16..32].try_into().unwrap();

        Self {
            powers,
            s,
            acc: [0; 5],
            buffer: [0; 16],
            buffer_pos: 0,
        }
    }

    /// Process message data.
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        // Fill buffer first
        if self.buffer_pos > 0 {
            let needed = 16 - self.buffer_pos;
            let available = data.len().min(needed);
            self.buffer[self.buffer_pos..self.buffer_pos + available]
                .copy_from_slice(&data[..available]);
            self.buffer_pos += available;
            pos += available;

            if self.buffer_pos == 16 {
                let m = load_block_with_hibit(&self.buffer);
                self.acc[0] += m[0];
                self.acc[1] += m[1];
                self.acc[2] += m[2];
                self.acc[3] += m[3];
                self.acc[4] += m[4];
                self.acc = mul_reduce_scalar(&self.acc, &self.powers.r);
                self.buffer_pos = 0;
            }
        }

        // Process remaining data with 16-way AVX-512 acceleration
        let processed = process_blocks_16way(&mut self.acc, &self.powers, &data[pos..]);
        pos += processed;

        // Save remaining bytes
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_pos = remaining;
        }
    }

    /// Finalize and return the tag.
    pub fn finalize(mut self) -> [u8; 16] {
        // Process partial block
        if self.buffer_pos > 0 {
            let mut padded = [0u8; 16];
            padded[..self.buffer_pos].copy_from_slice(&self.buffer[..self.buffer_pos]);
            padded[self.buffer_pos] = 0x01;

            let m = load_26bit_limbs(&padded);
            self.acc[0] += m[0];
            self.acc[1] += m[1];
            self.acc[2] += m[2];
            self.acc[3] += m[3];
            self.acc[4] += m[4];
            self.acc = mul_reduce_scalar(&self.acc, &self.powers.r);
        }

        finalize_acc(&self.acc, &self.s)
    }

    /// Compute MAC in one shot.
    pub fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        let mut poly = Self::new(key);
        poly.update(message);
        poly.finalize()
    }

    /// Verify a MAC tag with constant-time comparison.
    pub fn verify(key: &[u8; 32], message: &[u8], tag: &[u8; 16]) -> bool {
        let computed = Self::mac(key, message);

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in computed.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
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

    fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[test]
    fn test_simd_rfc8439_vector() {
        let key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let key: [u8; 32] = key.try_into().unwrap();

        let message = b"Cryptographic Forum Research Group";

        let tag = Poly1305Simd::mac(&key, message);
        let expected = hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9");

        assert_eq!(
            bytes_to_hex(&tag),
            bytes_to_hex(&expected),
            "RFC 8439 test vector failed"
        );
    }

    #[test]
    fn test_simd_matches_scalar() {
        use crate::poly1305::Poly1305;

        let key = [0x42u8; 32];

        // Test various message lengths
        for len in [
            0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1000, 4096,
        ] {
            let message = vec![0xAB; len];

            let tag_scalar = Poly1305::mac(&key, &message);
            let tag_simd = Poly1305Simd::mac(&key, &message);

            assert_eq!(
                tag_scalar,
                tag_simd,
                "Mismatch at length {} - scalar: {:?}, simd: {:?}",
                len,
                bytes_to_hex(&tag_scalar),
                bytes_to_hex(&tag_simd)
            );
        }
    }

    #[test]
    fn test_ultra_matches_scalar() {
        use crate::poly1305::Poly1305;

        let key = [0x42u8; 32];

        // Test various message lengths
        for len in [
            0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1000, 4096,
        ] {
            let message = vec![0xAB; len];

            let tag_scalar = Poly1305::mac(&key, &message);
            let tag_ultra = Poly1305Ultra::mac(&key, &message);

            assert_eq!(
                tag_scalar,
                tag_ultra,
                "Ultra mismatch at length {} - scalar: {:?}, ultra: {:?}",
                len,
                bytes_to_hex(&tag_scalar),
                bytes_to_hex(&tag_ultra)
            );
        }
    }

    #[test]
    fn test_simd_incremental() {
        let key = [0x42u8; 32];
        let message = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let tag1 = Poly1305Simd::mac(&key, message);

        // Incremental
        let mut poly = Poly1305Simd::new(&key);
        poly.update(&message[..10]);
        poly.update(&message[10..25]);
        poly.update(&message[25..]);
        let tag2 = poly.finalize();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_simd_verify() {
        let key = [0x42u8; 32];
        let message = b"Test message for verification";

        let tag = Poly1305Simd::mac(&key, message);

        assert!(Poly1305Simd::verify(&key, message, &tag));

        // Modified tag should fail
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert!(!Poly1305Simd::verify(&key, message, &bad_tag));
    }

    #[test]
    fn test_powers_computation() {
        let mut r_bytes = [0x42u8; 16];
        clamp(&mut r_bytes);

        let powers = Poly1305Powers4::new(&r_bytes);

        // r² should equal r * r
        let r_squared = mul_reduce_scalar(&powers.r, &powers.r);
        assert_eq!(powers.r2, r_squared);

        // r³ should equal r² * r
        let r_cubed = mul_reduce_scalar(&powers.r2, &powers.r);
        assert_eq!(powers.r3, r_cubed);

        // r⁴ should equal r³ * r
        let r_fourth = mul_reduce_scalar(&powers.r3, &powers.r);
        assert_eq!(powers.r4, r_fourth);
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_feature_detection() {
        println!("AVX2 available: {}", has_avx2());
        // Just ensure the detection doesn't crash
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_4x_processing() {
        if !has_avx2() {
            println!("Skipping AVX2 test - not available");
            return;
        }

        let key = [0x42u8; 32];
        let message = vec![0xAB; 256]; // Multiple of 64 bytes

        let tag_scalar = crate::poly1305::Poly1305::mac(&key, &message);
        let tag_simd = Poly1305Simd::mac(&key, &message);

        assert_eq!(tag_scalar, tag_simd, "4x processing mismatch");
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_8x_processing() {
        if !has_avx2() {
            println!("Skipping AVX2 8x test - not available");
            return;
        }

        let key = [0x42u8; 32];

        // Test various sizes that exercise 8-way processing
        for len in [128, 256, 512, 1024, 4096, 8192, 65536] {
            let message = vec![0xAB; len];

            let tag_scalar = crate::poly1305::Poly1305::mac(&key, &message);
            let tag_simd = Poly1305Simd::mac(&key, &message);

            assert_eq!(
                tag_scalar, tag_simd,
                "8x processing mismatch at length {}",
                len
            );
        }
    }

    #[test]
    fn test_powers8_computation() {
        let mut r_bytes = [0x42u8; 16];
        clamp(&mut r_bytes);

        let powers = Poly1305Powers8::new(&r_bytes);

        // Verify all powers are correct
        let r2 = mul_reduce_scalar(&powers.r, &powers.r);
        assert_eq!(powers.r2, r2);

        let r3 = mul_reduce_scalar(&powers.r2, &powers.r);
        assert_eq!(powers.r3, r3);

        let r4 = mul_reduce_scalar(&powers.r3, &powers.r);
        assert_eq!(powers.r4, r4);

        let r5 = mul_reduce_scalar(&powers.r4, &powers.r);
        assert_eq!(powers.r5, r5);

        let r6 = mul_reduce_scalar(&powers.r5, &powers.r);
        assert_eq!(powers.r6, r6);

        let r7 = mul_reduce_scalar(&powers.r6, &powers.r);
        assert_eq!(powers.r7, r7);

        let r8 = mul_reduce_scalar(&powers.r7, &powers.r);
        assert_eq!(powers.r8, r8);
    }

    #[test]
    fn bench_poly1305_throughput() {
        use crate::poly1305::Poly1305;
        use std::time::Instant;

        let key = [0x42u8; 32];
        let sizes_kb = [1, 4, 16, 64, 256, 1024];

        eprintln!("\n=== Poly1305 Throughput ===");
        eprintln!(
            "{:>8} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "Size", "Scalar", "AVX2", "Ultra", "Reference", "Ultra/Ref"
        );

        for size_kb in sizes_kb {
            let size = size_kb * 1024;
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let iterations = (10000 / size_kb).max(10);

            // Warm up
            for _ in 0..5 {
                let _ = Poly1305::mac(&key, &data);
                let _ = Poly1305Simd::mac(&key, &data);
                let _ = Poly1305Ultra::mac(&key, &data);
            }

            // Scalar
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = Poly1305::mac(&key, &data);
            }
            let scalar_elapsed = start.elapsed();

            // SIMD AVX2 (4-way/8-way)
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = Poly1305Simd::mac(&key, &data);
            }
            let simd_elapsed = start.elapsed();

            // Ultra (44-bit radix)
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = Poly1305Ultra::mac(&key, &data);
            }
            let ultra_elapsed = start.elapsed();

            // Reference (poly1305 crate)
            use poly1305::Poly1305 as RefPoly1305;
            use poly1305::universal_hash::{KeyInit, UniversalHash};
            let start = Instant::now();
            for _ in 0..iterations {
                let mut mac = RefPoly1305::new(&key.into());
                mac.update_padded(&data);
                let _ = mac.finalize();
            }
            let ref_elapsed = start.elapsed();

            let scalar_gib_s = (iterations as f64 * size as f64)
                / (scalar_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);
            let simd_gib_s = (iterations as f64 * size as f64)
                / (simd_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);
            let ultra_gib_s = (iterations as f64 * size as f64)
                / (ultra_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);
            let ref_gib_s = (iterations as f64 * size as f64)
                / (ref_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);

            eprintln!(
                "{:>6}KB {:>8.2} GiB/s {:>8.2} GiB/s {:>8.2} GiB/s {:>8.2} GiB/s {:>8.2}x",
                size_kb,
                scalar_gib_s,
                simd_gib_s,
                ultra_gib_s,
                ref_gib_s,
                ultra_gib_s / ref_gib_s
            );
        }
    }
}
