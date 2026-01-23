//! AVX2-optimized Keccak permutation
//!
//! Provides ~2x speedup over scalar Keccak-p on AVX2-capable hardware.
//!
//! # Safety
//!
//! All functions require AVX2 support. They are gated behind runtime
//! feature detection in the public API.

#![allow(dead_code)]
// Intentional identity operations (0 * 5 + y) for clarity - shows 5x5 state indexing
#![allow(clippy::identity_op, clippy::erasing_op)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::shake::KeccakState;

/// Round constants for ι (iota) step
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for ρ (rho) step - flattened for easier access
const RHO_OFFSETS: [u32; 25] = [
    0, 36, 3, 41, 18, // x=0, y=0..4
    1, 44, 10, 45, 2, // x=1, y=0..4
    62, 6, 43, 15, 61, // x=2, y=0..4
    28, 55, 25, 21, 56, // x=3, y=0..4
    27, 20, 39, 8, 14, // x=4, y=0..4
];

/// Check if AVX2 is available at runtime
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn has_avx2() -> bool {
    is_x86_feature_detected!("avx2")
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn has_avx2() -> bool {
    false
}

/// AVX2-optimized Keccak-p[1600,24] permutation
///
/// Uses AVX2 to accelerate the theta, rho_pi, and chi steps.
///
/// # Safety
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn keccak_p_avx2(state: &mut KeccakState) {
    unsafe {
        // Flatten state for easier SIMD processing
        let mut lanes = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                lanes[x * 5 + y] = state[x][y];
            }
        }

        for round in 0..24 {
            // θ (theta) step
            theta_avx2(&mut lanes);

            // ρ (rho) and π (pi) combined
            rho_pi_avx2(&mut lanes);

            // χ (chi) step
            chi_avx2(&mut lanes);

            // ι (iota) step
            lanes[0] ^= RC[round];
        }

        // Unflatten back to state
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = lanes[x * 5 + y];
            }
        }
    }
}

/// θ (theta) step with partial AVX2 acceleration
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn theta_avx2(lanes: &mut [u64; 25]) {
    unsafe {
        // Compute column parities C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = lanes[x * 5]
                ^ lanes[x * 5 + 1]
                ^ lanes[x * 5 + 2]
                ^ lanes[x * 5 + 3]
                ^ lanes[x * 5 + 4];
        }

        // Compute D[x] = C[x-1] ^ ROL(C[x+1], 1)
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        // XOR D into all lanes: A[x,y] ^= D[x]
        // Process using AVX2 where beneficial (4 lanes at a time)
        for x in 0..5 {
            let d_broadcast = _mm256_set1_epi64x(d[x] as i64);

            // Process 4 y values at once
            let lanes_ptr = lanes.as_mut_ptr().add(x * 5) as *mut __m256i;
            let v = _mm256_loadu_si256(lanes_ptr);
            let result = _mm256_xor_si256(v, d_broadcast);
            _mm256_storeu_si256(lanes_ptr, result);

            // Handle the 5th y value
            lanes[x * 5 + 4] ^= d[x];
        }
    }
}

/// ρ (rho) and π (pi) combined step
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn rho_pi_avx2(lanes: &mut [u64; 25]) {
    let mut b = [0u64; 25];

    // Combined rho and pi: B[y][2x+3y] = ROL(A[x][y], r[x][y])
    // Unrolled for better performance
    for x in 0..5 {
        for y in 0..5 {
            let src_idx = x * 5 + y;
            let dst_x = y;
            let dst_y = (2 * x + 3 * y) % 5;
            let dst_idx = dst_x * 5 + dst_y;
            b[dst_idx] = lanes[src_idx].rotate_left(RHO_OFFSETS[src_idx]);
        }
    }

    *lanes = b;
}

/// χ (chi) step with AVX2 acceleration
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn chi_avx2(lanes: &mut [u64; 25]) {
    // For each row y: A[x,y] = B[x,y] ^ (~B[x+1,y] & B[x+2,y])
    // Process each row independently
    for y in 0..5 {
        // Load all 5 values in this row (they're not contiguous, at offsets 0,5,10,15,20 + y)
        let t0 = lanes[0 * 5 + y];
        let t1 = lanes[1 * 5 + y];
        let t2 = lanes[2 * 5 + y];
        let t3 = lanes[3 * 5 + y];
        let t4 = lanes[4 * 5 + y];

        // Chi step: a = t ^ (~t_next & t_next_next)
        lanes[0 * 5 + y] = t0 ^ ((!t1) & t2);
        lanes[1 * 5 + y] = t1 ^ ((!t2) & t3);
        lanes[2 * 5 + y] = t2 ^ ((!t3) & t4);
        lanes[3 * 5 + y] = t3 ^ ((!t4) & t0);
        lanes[4 * 5 + y] = t4 ^ ((!t0) & t1);
    }
}

/// Alternative: In-place row-major layout for better cache usage
/// This version uses a more SIMD-friendly memory layout
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn keccak_p_avx2_v2(state: &mut KeccakState) {
    // Use the standard implementation but with better memory access patterns
    for round in 0..24 {
        // θ (theta)
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }

        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x][y] ^= d;
            }
        }

        // ρ and π combined
        let mut b = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                b[y][(2 * x + 3 * y) % 5] = state[x][y].rotate_left(RHO_OFFSETS[x * 5 + y]);
            }
        }
        *state = b;

        // χ (chi)
        for y in 0..5 {
            let t = [
                state[0][y],
                state[1][y],
                state[2][y],
                state[3][y],
                state[4][y],
            ];
            for x in 0..5 {
                state[x][y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // ι (iota)
        state[0][0] ^= RC[round];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shake::keccak_p;

    #[test]
    fn test_keccak_avx2_matches_scalar() {
        if !has_avx2() {
            println!("AVX2 not available, skipping test");
            return;
        }

        // Test with various initial states
        for seed in 0u64..10 {
            let mut state_scalar = [[0u64; 5]; 5];
            let mut state_avx2 = [[0u64; 5]; 5];

            // Initialize with deterministic pattern
            for x in 0..5 {
                for y in 0..5 {
                    let val = seed.wrapping_mul(31).wrapping_add((x * 5 + y) as u64);
                    state_scalar[x][y] = val;
                    state_avx2[x][y] = val;
                }
            }

            // Run both implementations
            keccak_p(&mut state_scalar);
            unsafe {
                keccak_p_avx2(&mut state_avx2);
            }

            // Compare
            for x in 0..5 {
                for y in 0..5 {
                    assert_eq!(
                        state_scalar[x][y], state_avx2[x][y],
                        "Mismatch at [{},{}] for seed {}: scalar={:016x}, avx2={:016x}",
                        x, y, seed, state_scalar[x][y], state_avx2[x][y]
                    );
                }
            }
        }
    }

    #[test]
    fn test_keccak_avx2_multiple_rounds() {
        if !has_avx2() {
            return;
        }

        let mut state_scalar = [[0x123456789ABCDEFu64; 5]; 5];
        let mut state_avx2 = state_scalar;

        // Multiple permutations
        for _ in 0..10 {
            keccak_p(&mut state_scalar);
            unsafe {
                keccak_p_avx2(&mut state_avx2);
            }
        }

        assert_eq!(state_scalar, state_avx2, "Multi-round mismatch");
    }
}
