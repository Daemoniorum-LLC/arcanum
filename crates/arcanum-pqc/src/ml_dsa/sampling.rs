//! Sampling functions for ML-DSA (FIPS 204)
//!
//! This module implements the various sampling algorithms required by ML-DSA:
//! - Uniform polynomial sampling (for matrix A)
//! - Small coefficient sampling (for secrets s₁, s₂)
//! - Gamma1 range sampling (for masking polynomial y)
//! - Challenge polynomial sampling (for c)
//!
//! All functions use SHAKE (from arcanum-primitives) as the underlying XOF.

#![allow(dead_code)]
// Allow unsafe code when SIMD is enabled for 4-way Keccak optimization
#![cfg_attr(all(feature = "simd", target_arch = "x86_64"), allow(unsafe_code))]

use super::params::{MlDsaParams, N, Params44, Params65, Params87, Q};
use super::poly::Poly;
use arcanum_primitives::shake::{Shake128, Shake256};

/// Rejection bound for uniform sampling
/// We reject samples >= Q to maintain uniform distribution
const REJECTION_BOUND: i32 = Q;

// ═══════════════════════════════════════════════════════════════════════════════
// Uniform Sampling (for matrix A)
// ═══════════════════════════════════════════════════════════════════════════════

/// Sample a polynomial with uniformly random coefficients in [0, q)
///
/// Uses rejection sampling from SHAKE128 output.
/// This is Algorithm 6 (RejNTTPoly) from FIPS 204.
///
/// # Arguments
///
/// * `rho` - 32-byte seed
/// * `i` - Row index (0-based)
/// * `j` - Column index (0-based)
pub fn sample_poly_uniform(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut poly = Poly::zero();

    // Initialize SHAKE128 with rho || i || j
    let mut shake = Shake128::new();
    shake.update(rho);
    shake.update(&[j, i]); // Note: FIPS 204 uses j || i order
    let mut reader = shake.finalize_xof();

    // Sample coefficients using rejection sampling
    // Squeeze larger blocks to reduce function call overhead and Keccak permutations
    // SHAKE128 rate is 168 bytes; we use 504 bytes (3 blocks) for efficiency
    let mut idx = 0;
    let mut buf = [0u8; 504]; // 504 = 168 * 3, divisible by 3
    let mut buf_pos = 504; // Start exhausted to trigger initial fill

    while idx < N {
        // Refill buffer when exhausted
        if buf_pos >= 504 {
            reader.squeeze(&mut buf);
            buf_pos = 0;
        }

        // Extract 24 bits and interpret as two 12-bit samples
        // Following FIPS 204 Algorithm 6
        let d1 = (buf[buf_pos] as i32) | ((buf[buf_pos + 1] as i32 & 0x0F) << 8);
        let d2 = ((buf[buf_pos + 1] as i32) >> 4) | ((buf[buf_pos + 2] as i32) << 4);
        buf_pos += 3;

        // Reject samples >= q
        if d1 < REJECTION_BOUND {
            poly.coeffs[idx] = d1;
            idx += 1;
        }
        if idx < N && d2 < REJECTION_BOUND {
            poly.coeffs[idx] = d2;
            idx += 1;
        }
    }

    poly
}

/// Expand seed ρ to matrix A ∈ R_q^(k×l)
///
/// Each entry A[i][j] is sampled using sample_poly_uniform with indices (i, j).
/// This is Algorithm 27 (ExpandA) from FIPS 204.
///
/// # Arguments
///
/// * `rho` - 32-byte seed
///
/// # Returns
///
/// Matrix A in NTT domain
pub fn expand_a<P: MlDsaParams>(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    // Use 4-way SIMD version when available (fastest)
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { expand_a_x4::<P>(rho) };
        }
    }

    // Fall back to sequential
    expand_a_sequential::<P>(rho)
}

/// Sequential ExpandA implementation (baseline)
pub fn expand_a_sequential<P: MlDsaParams>(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    let mut a = Vec::with_capacity(P::K);

    for i in 0..P::K {
        let mut row = Vec::with_capacity(P::L);
        for j in 0..P::L {
            let mut poly = sample_poly_uniform(rho, i as u8, j as u8);
            poly.ntt(); // A is stored in NTT domain
            row.push(poly);
        }
        a.push(row);
    }

    a
}

/// 4-way SIMD ExpandA using batched Keccak
///
/// Processes 4 matrix entries at a time using AVX2 parallel Keccak.
/// Pre-squeezes data from all 4 states together to maximize parallelism.
///
/// # Safety
///
/// Requires AVX2 support. Caller must verify `is_x86_feature_detected!("avx2")`.
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn expand_a_x4<P: MlDsaParams>(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    use arcanum_primitives::keccak_x4::Shake128X4;

    // Initialize matrix
    let mut a: Vec<Vec<Poly>> = (0..P::K)
        .map(|_| (0..P::L).map(|_| Poly::zero()).collect())
        .collect();

    // Flatten indices
    let indices: Vec<(usize, usize)> = (0..P::K)
        .flat_map(|i| (0..P::L).map(move |j| (i, j)))
        .collect();

    // Process 4 entries at a time
    let mut idx = 0;
    while idx < indices.len() {
        let batch_size = (indices.len() - idx).min(4);

        // SAFETY: All Shake128X4 operations require AVX2, which is guaranteed by
        // the caller checking is_x86_feature_detected!("avx2") before calling.
        unsafe {
            // Create 4-way SHAKE128
            let mut shake_x4 = Shake128X4::new();

            // Absorb into each state
            for b in 0..batch_size {
                let (i, j) = indices[idx + b];
                let mut seed = [0u8; 34];
                seed[..32].copy_from_slice(rho);
                seed[32] = j as u8;
                seed[33] = i as u8;
                shake_x4.absorb(b, &seed);
            }

            // Finalize all states
            shake_x4.finalize();

            // Pre-squeeze 840 bytes from each state (5 * 168 = 840 bytes = 5 SHAKE128 blocks)
            // This gives ~560 candidate coefficients, enough for 256 with ~55% rejection margin
            let mut bufs = [[0u8; 840]; 4];
            let mut buf_pos = [0usize; 4];
            let mut poly_idx = [0usize; 4];
            let mut polys = [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()];

            // Squeeze all 4 states together in parallel
            shake_x4.squeeze_blocks_x4(&mut bufs, 5, batch_size);

            // Sample from pre-squeezed buffers
            for b in 0..batch_size {
                while poly_idx[b] < N && buf_pos[b] + 2 < 840 {
                    let d1 = (bufs[b][buf_pos[b]] as i32)
                        | ((bufs[b][buf_pos[b] + 1] as i32 & 0x0F) << 8);
                    let d2 = ((bufs[b][buf_pos[b] + 1] as i32) >> 4)
                        | ((bufs[b][buf_pos[b] + 2] as i32) << 4);
                    buf_pos[b] += 3;

                    if d1 < REJECTION_BOUND && poly_idx[b] < N {
                        polys[b].coeffs[poly_idx[b]] = d1;
                        poly_idx[b] += 1;
                    }
                    if d2 < REJECTION_BOUND && poly_idx[b] < N {
                        polys[b].coeffs[poly_idx[b]] = d2;
                        poly_idx[b] += 1;
                    }
                }

                // Rare case: need more data (very unlikely with 840 bytes)
                while poly_idx[b] < N {
                    let mut extra = [0u8; 168];
                    shake_x4.squeeze_one_block(b, &mut extra);

                    let mut pos = 0;
                    while poly_idx[b] < N && pos + 2 < 168 {
                        let d1 = (extra[pos] as i32) | ((extra[pos + 1] as i32 & 0x0F) << 8);
                        let d2 = ((extra[pos + 1] as i32) >> 4) | ((extra[pos + 2] as i32) << 4);
                        pos += 3;

                        if d1 < REJECTION_BOUND && poly_idx[b] < N {
                            polys[b].coeffs[poly_idx[b]] = d1;
                            poly_idx[b] += 1;
                        }
                        if d2 < REJECTION_BOUND && poly_idx[b] < N {
                            polys[b].coeffs[poly_idx[b]] = d2;
                            poly_idx[b] += 1;
                        }
                    }
                }
            }

            // Store results and apply NTT
            for b in 0..batch_size {
                let (i, j) = indices[idx + b];
                a[i][j] = polys[b].clone();
                a[i][j].ntt();
            }
        }

        idx += 4;
    }

    a
}

/// Parallel ExpandA using Rayon
///
/// Each matrix entry A[i][j] is sampled independently, making this
/// embarrassingly parallel. Uses Rayon's parallel iterator.
///
/// Performance: ~3x speedup on 4+ core systems for ML-DSA-65 (K=6, L=5 = 30 entries)
#[cfg(feature = "parallel")]
pub fn expand_a_parallel<P: MlDsaParams>(rho: &[u8; 32]) -> Vec<Vec<Poly>> {
    use rayon::prelude::*;

    // Flatten to (i, j) pairs for parallel processing
    let indices: Vec<(usize, usize)> = (0..P::K)
        .flat_map(|i| (0..P::L).map(move |j| (i, j)))
        .collect();

    // Process all K*L entries in parallel
    let flat_polys: Vec<(usize, usize, Poly)> = indices
        .into_par_iter()
        .map(|(i, j)| {
            let mut poly = sample_poly_uniform(rho, i as u8, j as u8);
            poly.ntt();
            (i, j, poly)
        })
        .collect();

    // Reconstruct matrix structure
    let mut a: Vec<Vec<Poly>> = (0..P::K).map(|_| Vec::with_capacity(P::L)).collect();

    // Initialize with zero polys
    for row in &mut a {
        for _ in 0..P::L {
            row.push(Poly::zero());
        }
    }

    // Place computed polynomials
    for (i, j, poly) in flat_polys {
        a[i][j] = poly;
    }

    a
}

// ═══════════════════════════════════════════════════════════════════════════════
// Small Coefficient Sampling (for secrets s₁, s₂)
// ═══════════════════════════════════════════════════════════════════════════════

/// Sample a polynomial with coefficients in [-η, η]
///
/// Uses rejection sampling from SHAKE256 output.
/// This is Algorithm 7 (RejBoundedPoly) from FIPS 204.
///
/// # Arguments
///
/// * `seed` - 64-byte seed (typically K || rho' from key generation)
/// * `nonce` - 16-bit counter for domain separation
/// * `eta` - Bound for coefficients (2 or 4)
pub fn sample_poly_eta(seed: &[u8; 64], nonce: u16, eta: usize) -> Poly {
    let mut poly = Poly::zero();

    // Initialize SHAKE256 with seed || nonce
    let mut shake = Shake256::new();
    shake.update(seed);
    shake.update(&nonce.to_le_bytes());
    let mut reader = shake.finalize_xof();

    // Sample coefficients using rejection sampling
    // Squeeze larger blocks to reduce function call overhead and Keccak permutations
    // SHAKE256 rate is 136 bytes; we use 272 bytes (2 blocks) for efficiency
    let mut idx = 0;
    let mut buf = [0u8; 272];
    let mut buf_pos = 272; // Start exhausted to trigger initial fill

    while idx < N {
        // Refill buffer when exhausted
        if buf_pos >= 272 {
            reader.squeeze(&mut buf);
            buf_pos = 0;
        }

        let b = buf[buf_pos];
        buf_pos += 1;

        if eta == 2 {
            // η = 2: extract two 4-bit samples, reject > 4
            let t0 = b & 0x0F;
            let t1 = b >> 4;

            if t0 < 15 {
                let coeff = sample_eta2(t0);
                poly.coeffs[idx] = coeff;
                idx += 1;
            }
            if idx < N && t1 < 15 {
                let coeff = sample_eta2(t1);
                poly.coeffs[idx] = coeff;
                idx += 1;
            }
        } else if eta == 4 {
            // η = 4: each 4-bit sample in [0, 8] gives coefficient in [-4, 4]
            let t0 = b & 0x0F;
            let t1 = b >> 4;

            if t0 < 9 {
                poly.coeffs[idx] = 4 - t0 as i32;
                idx += 1;
            }
            if idx < N && t1 < 9 {
                poly.coeffs[idx] = 4 - t1 as i32;
                idx += 1;
            }
        }
    }

    poly
}

/// Convert 4-bit value to coefficient in [-2, 2] for η=2
/// Follows FIPS 204 Algorithm 7
#[inline]
fn sample_eta2(t: u8) -> i32 {
    // t in [0, 14], map to coefficient in [-2, 2]
    // Formula: coeff = 2 - (t mod 5)
    // This gives: 0->2, 1->1, 2->0, 3->-1, 4->-2, 5->2, 6->1, 7->0, 8->-1, 9->-2, 10->2, 11->1, 12->0, 13->-1, 14->-2
    let t_mod_5 = (t % 5) as i32;
    2 - t_mod_5
}

// ═══════════════════════════════════════════════════════════════════════════════
// Gamma1 Sampling (for masking polynomial y)
// ═══════════════════════════════════════════════════════════════════════════════

/// Sample a polynomial with coefficients in (-γ₁, γ₁]
///
/// Uses SHAKE256 to generate uniform bytes and maps to the range.
/// This is Algorithm 8 (ExpandMask) from FIPS 204.
///
/// # Arguments
///
/// * `seed` - Seed for SHAKE256
/// * `nonce` - 16-bit counter for domain separation
/// * `gamma1` - The γ₁ parameter (2^17 or 2^19)
pub fn sample_poly_gamma1(seed: &[u8], nonce: u16, gamma1: u32) -> Poly {
    let mut poly = Poly::zero();

    // Initialize SHAKE256 with seed || nonce
    let mut shake = Shake256::new();
    shake.update(seed);
    shake.update(&nonce.to_le_bytes());
    let mut reader = shake.finalize_xof();

    if gamma1 == (1 << 17) {
        // γ₁ = 2^17: use 18 bits per coefficient
        sample_gamma1_17(&mut reader, &mut poly);
    } else if gamma1 == (1 << 19) {
        // γ₁ = 2^19: use 20 bits per coefficient
        sample_gamma1_19(&mut reader, &mut poly);
    }

    poly
}

/// Sample coefficients for γ₁ = 2^17 (18 bits per coefficient)
fn sample_gamma1_17(reader: &mut arcanum_primitives::shake::Shake256Reader, poly: &mut Poly) {
    const GAMMA1: i32 = 1 << 17;
    // Squeeze all needed bytes at once: 256 coeffs * 18 bits / 8 = 576 bytes
    // Round up to rate boundary for efficiency
    let mut buf = [0u8; 576];
    reader.squeeze(&mut buf);

    for chunk in 0..(N / 4) {
        let b = &buf[9 * chunk..9 * chunk + 9];

        // Extract four 18-bit values
        let r0 = (b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x03) << 16);
        let r1 = ((b[2] as i32) >> 2) | ((b[3] as i32) << 6) | (((b[4] as i32) & 0x0F) << 14);
        let r2 = ((b[4] as i32) >> 4) | ((b[5] as i32) << 4) | (((b[6] as i32) & 0x3F) << 12);
        let r3 = ((b[6] as i32) >> 6) | ((b[7] as i32) << 2) | ((b[8] as i32) << 10);

        // Map [0, 2*gamma1) to (-gamma1, gamma1]
        // coefficient = gamma1 - r
        poly.coeffs[4 * chunk] = GAMMA1 - r0;
        poly.coeffs[4 * chunk + 1] = GAMMA1 - r1;
        poly.coeffs[4 * chunk + 2] = GAMMA1 - r2;
        poly.coeffs[4 * chunk + 3] = GAMMA1 - r3;
    }
}

/// Sample coefficients for γ₁ = 2^19 (20 bits per coefficient)
fn sample_gamma1_19(reader: &mut arcanum_primitives::shake::Shake256Reader, poly: &mut Poly) {
    const GAMMA1: i32 = 1 << 19;
    // Squeeze all needed bytes at once: 256 coeffs * 20 bits / 8 = 640 bytes
    let mut buf = [0u8; 640];
    reader.squeeze(&mut buf);

    for chunk in 0..(N / 2) {
        let b = &buf[5 * chunk..5 * chunk + 5];

        // Extract two 20-bit values
        let r0 = (b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x0F) << 16);
        let r1 = ((b[2] as i32) >> 4) | ((b[3] as i32) << 4) | ((b[4] as i32) << 12);

        // Map [0, 2*gamma1) to (-gamma1, gamma1]
        poly.coeffs[2 * chunk] = GAMMA1 - r0;
        poly.coeffs[2 * chunk + 1] = GAMMA1 - r1;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Challenge Polynomial Sampling
// ═══════════════════════════════════════════════════════════════════════════════

/// Sample challenge polynomial c with exactly τ coefficients in {-1, 1}
///
/// Uses SHAKE256 output to determine positions and signs.
/// This is Algorithm 9 (SampleInBall) from FIPS 204.
///
/// # Arguments
///
/// * `seed` - Seed for SHAKE256 (typically c̃ = H(μ || w₁))
/// * `tau` - Number of non-zero coefficients
pub fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
    let mut poly = Poly::zero();

    // Initialize SHAKE256 with seed
    let mut shake = Shake256::new();
    shake.update(seed);
    let mut reader = shake.finalize_xof();

    // Get sign bits (first 8 bytes = 64 bits for signs)
    let mut sign_bytes = [0u8; 8];
    reader.squeeze(&mut sign_bytes);
    let signs = u64::from_le_bytes(sign_bytes);

    // Sample positions using Fisher-Yates-like sampling
    // c_i ∈ {-1, 1} for τ random positions
    let mut buf = [0u8; 1];

    for i in (N - tau)..N {
        // Sample j ∈ [0, i]
        loop {
            reader.squeeze(&mut buf);
            let j = buf[0] as usize;
            if j <= i {
                // Swap position i with position j
                poly.coeffs[i] = poly.coeffs[j];

                // Set new value at position j based on sign bit
                let sign_bit = (signs >> (i - (N - tau))) & 1;
                poly.coeffs[j] = 1 - 2 * (sign_bit as i32); // 1 if sign_bit=0, -1 if sign_bit=1
                break;
            }
        }
    }

    poly
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Expand secret seed to secret vectors s₁ and s₂
///
/// # Arguments
///
/// * `seed` - 64-byte seed (rho' from key generation)
/// * `eta` - Bound for coefficients
///
/// # Returns
///
/// (s₁, s₂) where s₁ has L polynomials and s₂ has K polynomials
pub fn expand_s<P: MlDsaParams>(seed: &[u8; 64]) -> (Vec<Poly>, Vec<Poly>) {
    let mut s1 = Vec::with_capacity(P::L);
    let mut s2 = Vec::with_capacity(P::K);

    // Sample s₁ with nonces 0..L
    for i in 0..P::L {
        s1.push(sample_poly_eta(seed, i as u16, P::ETA));
    }

    // Sample s₂ with nonces L..L+K
    for i in 0..P::K {
        s2.push(sample_poly_eta(seed, (P::L + i) as u16, P::ETA));
    }

    (s1, s2)
}

/// Expand mask seed to masking vector y
///
/// # Arguments
///
/// * `seed` - Seed for SHAKE256
/// * `nonce` - Base nonce value
/// * `gamma1` - The γ₁ parameter
///
/// # Returns
///
/// Vector y with L polynomials
pub fn expand_mask<P: MlDsaParams>(seed: &[u8], nonce: u16, gamma1: u32) -> Vec<Poly> {
    // Use 4-way SIMD optimization when L is a multiple of 4 and SIMD is available
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    if P::L % 4 == 0 && is_x86_feature_detected!("avx2") {
        return unsafe { expand_mask_x4::<P>(seed, nonce, gamma1) };
    }

    // Fallback: sequential sampling
    let mut y = Vec::with_capacity(P::L);
    for i in 0..P::L {
        y.push(sample_poly_gamma1(seed, nonce + i as u16, gamma1));
    }
    y
}

/// 4-way parallel expand_mask using AVX2 SIMD
///
/// Processes 4 polynomials in parallel using 4-way Keccak.
/// Only used when L is a multiple of 4 (Arcanum-DSA parameters).
///
/// # Safety
///
/// Requires AVX2 support. Caller must verify `is_x86_feature_detected!("avx2")`.
///
/// # Security Notes
///
/// - Buffer sizing: 680 bytes (5 × 136) is sufficient for both gamma1 values:
///   - gamma1 = 2^17: needs 576 bytes (256 × 18 bits / 8)
///   - gamma1 = 2^19: needs 640 bytes (256 × 20 bits / 8)
/// - No rejection sampling: data extraction is deterministic and constant-time
/// - The nonce addition is checked for overflow (debug builds)
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn expand_mask_x4<P: MlDsaParams>(seed: &[u8], nonce: u16, gamma1: u32) -> Vec<Poly> {
    use arcanum_primitives::keccak_x4::Shake256X4;

    // Validate gamma1 is a supported value
    debug_assert!(
        gamma1 == (1 << 17) || gamma1 == (1 << 19),
        "expand_mask_x4: unsupported gamma1 value {}",
        gamma1
    );

    let mut y = Vec::with_capacity(P::L);

    // Process in batches of 4
    let num_batches = P::L / 4;

    for batch in 0..num_batches {
        // Check for nonce overflow (important for correctness)
        let base_nonce = nonce
            .checked_add((batch * 4) as u16)
            .expect("expand_mask_x4: nonce overflow");

        // SAFETY: All operations below require AVX2, which is guaranteed by
        // the caller checking is_x86_feature_detected!("avx2") before calling.
        // The Shake256X4 methods are unsafe due to SIMD requirements.
        unsafe {
            // Initialize 4-way SHAKE256
            let mut shake_x4 = Shake256X4::new();

            // Absorb seed || nonce for each of the 4 states
            for i in 0..4 {
                let n = base_nonce + i as u16;
                shake_x4.absorb(i, seed);
                shake_x4.absorb(i, &n.to_le_bytes());
            }

            // Finalize all states
            shake_x4.finalize();

            // Squeeze and sample based on gamma1
            if gamma1 == (1 << 17) {
                // γ₁ = 2^17: need 576 bytes per polynomial (4.2 blocks of 136)
                // Using 680 bytes (5 blocks) provides sufficient margin
                let mut bufs = [[0u8; 680]; 4];
                shake_x4.squeeze_blocks_x4(&mut bufs, 5, 4);

                for i in 0..4 {
                    y.push(decode_gamma1_17(&bufs[i]));
                }
            } else if gamma1 == (1 << 19) {
                // γ₁ = 2^19: need 640 bytes per polynomial (4.7 blocks of 136)
                // Using 680 bytes (5 blocks) provides sufficient margin
                let mut bufs = [[0u8; 680]; 4];
                shake_x4.squeeze_blocks_x4(&mut bufs, 5, 4);

                for i in 0..4 {
                    y.push(decode_gamma1_19(&bufs[i]));
                }
            } else {
                // Unsupported gamma1 value - fall back to sequential
                // This path should never be reached with valid parameters
                for i in 0..4 {
                    let n = base_nonce + i as u16;
                    y.push(sample_poly_gamma1(seed, n, gamma1));
                }
            }
        }
    }

    y
}

/// Decode polynomial coefficients from bytes for γ₁ = 2^17 (18 bits per coefficient)
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn decode_gamma1_17(buf: &[u8]) -> Poly {
    const GAMMA1: i32 = 1 << 17;
    let mut poly = Poly::zero();

    for chunk in 0..(N / 4) {
        let b = &buf[9 * chunk..9 * chunk + 9];

        // Extract four 18-bit values
        let r0 = (b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x03) << 16);
        let r1 = ((b[2] as i32) >> 2) | ((b[3] as i32) << 6) | (((b[4] as i32) & 0x0F) << 14);
        let r2 = ((b[4] as i32) >> 4) | ((b[5] as i32) << 4) | (((b[6] as i32) & 0x3F) << 12);
        let r3 = ((b[6] as i32) >> 6) | ((b[7] as i32) << 2) | ((b[8] as i32) << 10);

        // Map [0, 2*gamma1) to (-gamma1, gamma1]
        poly.coeffs[4 * chunk] = GAMMA1 - r0;
        poly.coeffs[4 * chunk + 1] = GAMMA1 - r1;
        poly.coeffs[4 * chunk + 2] = GAMMA1 - r2;
        poly.coeffs[4 * chunk + 3] = GAMMA1 - r3;
    }

    poly
}

/// Decode polynomial coefficients from bytes for γ₁ = 2^19 (20 bits per coefficient)
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn decode_gamma1_19(buf: &[u8]) -> Poly {
    const GAMMA1: i32 = 1 << 19;
    let mut poly = Poly::zero();

    for chunk in 0..(N / 2) {
        let b = &buf[5 * chunk..5 * chunk + 5];

        // Extract two 20-bit values
        let r0 = (b[0] as i32) | ((b[1] as i32) << 8) | (((b[2] as i32) & 0x0F) << 16);
        let r1 = ((b[2] as i32) >> 4) | ((b[3] as i32) << 4) | ((b[4] as i32) << 12);

        // Map [0, 2*gamma1) to (-gamma1, gamma1]
        poly.coeffs[2 * chunk] = GAMMA1 - r0;
        poly.coeffs[2 * chunk + 1] = GAMMA1 - r1;
    }

    poly
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_poly_uniform_deterministic() {
        // Same seed and indices should produce same polynomial
        let rho = [0u8; 32];
        let p1 = sample_poly_uniform(&rho, 0, 0);
        let p2 = sample_poly_uniform(&rho, 0, 0);

        for i in 0..N {
            assert_eq!(p1.coeffs[i], p2.coeffs[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_sample_poly_uniform_in_range() {
        // All coefficients should be in [0, q)
        let rho = [0x42u8; 32];
        let poly = sample_poly_uniform(&rho, 1, 2);

        for i in 0..N {
            assert!(
                poly.coeffs[i] >= 0,
                "Coefficient {} is negative: {}",
                i,
                poly.coeffs[i]
            );
            assert!(
                poly.coeffs[i] < Q,
                "Coefficient {} >= q: {}",
                i,
                poly.coeffs[i]
            );
        }
    }

    #[test]
    fn test_sample_poly_uniform_different_indices() {
        // Different indices should produce different polynomials
        let rho = [0u8; 32];
        let p1 = sample_poly_uniform(&rho, 0, 0);
        let p2 = sample_poly_uniform(&rho, 0, 1);
        let p3 = sample_poly_uniform(&rho, 1, 0);

        // Very unlikely to be equal
        let mut same_01 = true;
        let mut same_02 = true;
        for i in 0..N {
            if p1.coeffs[i] != p2.coeffs[i] {
                same_01 = false;
            }
            if p1.coeffs[i] != p3.coeffs[i] {
                same_02 = false;
            }
        }
        assert!(!same_01, "p(0,0) should differ from p(0,1)");
        assert!(!same_02, "p(0,0) should differ from p(1,0)");
    }

    #[test]
    fn test_sample_eta2() {
        // Test the η=2 mapping function: coeff = 2 - (t mod 5)
        // t in [0,14] maps to [-2, 2]
        assert_eq!(sample_eta2(0), 2); // 2 - 0 = 2
        assert_eq!(sample_eta2(1), 1); // 2 - 1 = 1
        assert_eq!(sample_eta2(2), 0); // 2 - 2 = 0
        assert_eq!(sample_eta2(3), -1); // 2 - 3 = -1
        assert_eq!(sample_eta2(4), -2); // 2 - 4 = -2
        assert_eq!(sample_eta2(5), 2); // 2 - 0 = 2
        assert_eq!(sample_eta2(6), 1); // 2 - 1 = 1
        assert_eq!(sample_eta2(7), 0); // 2 - 2 = 0
        assert_eq!(sample_eta2(8), -1); // 2 - 3 = -1
        assert_eq!(sample_eta2(9), -2); // 2 - 4 = -2
        assert_eq!(sample_eta2(10), 2); // 2 - 0 = 2
        assert_eq!(sample_eta2(11), 1); // 2 - 1 = 1
        assert_eq!(sample_eta2(12), 0); // 2 - 2 = 0
        assert_eq!(sample_eta2(13), -1); // 2 - 3 = -1
        assert_eq!(sample_eta2(14), -2); // 2 - 4 = -2
    }

    #[test]
    fn test_sample_poly_eta2_in_range() {
        // All coefficients should be in [-2, 2]
        let seed = [0x42u8; 64];
        let poly = sample_poly_eta(&seed, 0, 2);

        for i in 0..N {
            assert!(
                poly.coeffs[i] >= -2,
                "Coefficient {} < -2: {}",
                i,
                poly.coeffs[i]
            );
            assert!(
                poly.coeffs[i] <= 2,
                "Coefficient {} > 2: {}",
                i,
                poly.coeffs[i]
            );
        }
    }

    #[test]
    fn test_sample_poly_eta4_in_range() {
        // All coefficients should be in [-4, 4]
        let seed = [0x42u8; 64];
        let poly = sample_poly_eta(&seed, 0, 4);

        for i in 0..N {
            assert!(
                poly.coeffs[i] >= -4,
                "Coefficient {} < -4: {}",
                i,
                poly.coeffs[i]
            );
            assert!(
                poly.coeffs[i] <= 4,
                "Coefficient {} > 4: {}",
                i,
                poly.coeffs[i]
            );
        }
    }

    #[test]
    fn test_sample_poly_gamma1_17_in_range() {
        // All coefficients should be in (-2^17, 2^17]
        let seed = [0x42u8; 64];
        let gamma1 = 1u32 << 17;
        let poly = sample_poly_gamma1(&seed, 0, gamma1);

        for i in 0..N {
            let c = poly.coeffs[i];
            assert!(c > -(gamma1 as i32), "Coefficient {} <= -gamma1: {}", i, c);
            assert!(c <= gamma1 as i32, "Coefficient {} > gamma1: {}", i, c);
        }
    }

    #[test]
    fn test_sample_poly_gamma1_19_in_range() {
        // All coefficients should be in (-2^19, 2^19]
        let seed = [0x42u8; 64];
        let gamma1 = 1u32 << 19;
        let poly = sample_poly_gamma1(&seed, 0, gamma1);

        for i in 0..N {
            let c = poly.coeffs[i];
            assert!(c > -(gamma1 as i32), "Coefficient {} <= -gamma1: {}", i, c);
            assert!(c <= gamma1 as i32, "Coefficient {} > gamma1: {}", i, c);
        }
    }

    #[test]
    fn test_sample_in_ball_tau_nonzero() {
        // Challenge polynomial should have exactly τ non-zero coefficients
        let seed = [0x42u8; 32];
        let tau = 39; // ML-DSA-44
        let poly = sample_in_ball(&seed, tau);

        let mut count = 0;
        for i in 0..N {
            if poly.coeffs[i] != 0 {
                count += 1;
                // Each non-zero coefficient should be +1 or -1
                assert!(
                    poly.coeffs[i] == 1 || poly.coeffs[i] == -1,
                    "Non-zero coefficient {} is not +/-1: {}",
                    i,
                    poly.coeffs[i]
                );
            }
        }
        assert_eq!(
            count, tau,
            "Expected {} non-zero coefficients, got {}",
            tau, count
        );
    }

    #[test]
    fn test_sample_in_ball_different_taus() {
        // Test different τ values for different security levels
        let seed = [0x42u8; 32];

        for tau in [39usize, 49, 60] {
            let poly = sample_in_ball(&seed, tau);
            let count: usize = poly.coeffs.iter().filter(|&&c| c != 0).count();
            assert_eq!(
                count, tau,
                "τ={}: expected {} non-zero, got {}",
                tau, tau, count
            );
        }
    }

    #[test]
    fn test_expand_a_dimensions() {
        // ExpandA should produce k×l matrix
        let rho = [0u8; 32];

        let a44: Vec<Vec<Poly>> = expand_a::<Params44>(&rho);
        assert_eq!(a44.len(), 4, "ML-DSA-44: k should be 4");
        assert_eq!(a44[0].len(), 4, "ML-DSA-44: l should be 4");

        let a65: Vec<Vec<Poly>> = expand_a::<Params65>(&rho);
        assert_eq!(a65.len(), 6, "ML-DSA-65: k should be 6");
        assert_eq!(a65[0].len(), 5, "ML-DSA-65: l should be 5");

        let a87: Vec<Vec<Poly>> = expand_a::<Params87>(&rho);
        assert_eq!(a87.len(), 8, "ML-DSA-87: k should be 8");
        assert_eq!(a87[0].len(), 7, "ML-DSA-87: l should be 7");
    }

    #[test]
    fn test_expand_s_dimensions() {
        // ExpandS should produce (l, k) vectors
        let seed = [0u8; 64];

        let (s1_44, s2_44) = expand_s::<Params44>(&seed);
        assert_eq!(s1_44.len(), 4, "ML-DSA-44: s1 should have l=4 polynomials");
        assert_eq!(s2_44.len(), 4, "ML-DSA-44: s2 should have k=4 polynomials");

        let (s1_65, s2_65) = expand_s::<Params65>(&seed);
        assert_eq!(s1_65.len(), 5, "ML-DSA-65: s1 should have l=5 polynomials");
        assert_eq!(s2_65.len(), 6, "ML-DSA-65: s2 should have k=6 polynomials");

        let (s1_87, s2_87) = expand_s::<Params87>(&seed);
        assert_eq!(s1_87.len(), 7, "ML-DSA-87: s1 should have l=7 polynomials");
        assert_eq!(s2_87.len(), 8, "ML-DSA-87: s2 should have k=8 polynomials");
    }
}
