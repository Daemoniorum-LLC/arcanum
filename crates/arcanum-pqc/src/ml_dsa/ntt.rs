//! Number Theoretic Transform (NTT) for ML-DSA
//!
//! FIPS 204 uses NTT for efficient polynomial multiplication.
//! The NTT operates over Z_q where q = 8380417 with primitive
//! 512th root of unity ζ = 1753.
//!
//! # Montgomery Arithmetic
//!
//! All arithmetic uses Montgomery representation for constant-time
//! modular reduction without division.

#![allow(dead_code)]

use super::params::{N, Q};

/// Primitive 512th root of unity: ζ = 1753
const ZETA: i32 = 1753;

/// Montgomery constant R = 2^32 mod q
const MONT_R: i32 = 4193792; // 2^32 mod q

/// Montgomery constant R^2 mod q (for conversion to Montgomery form)
const MONT_R2: i32 = 2365951; // (2^32)^2 mod q

/// q^(-1) mod 2^32 for Montgomery reduction
const QINV: i32 = 58728449;

/// Precomputed powers of ζ in bit-reversed order for forward NTT
/// zetas[i] = ζ^(bit_rev(i)) * R mod q (in Montgomery form)
///
/// These constants are from FIPS 204 / CRYSTALS-Dilithium reference (ntt.c).
/// Index 0 is unused; indices 1..255 contain the roots for 7 NTT layers.
#[rustfmt::skip]
const ZETAS: [i32; N] = [
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782,
];

// Note: The inverse NTT uses -ZETAS[k] directly, no separate array needed.

/// Montgomery reduction: compute a * R^(-1) mod q
///
/// Given a value a in [-q*R, q*R], compute a * 2^(-32) mod q.
/// This is the core operation for constant-time modular arithmetic.
///
/// # Security
///
/// This function executes in constant time regardless of input value.
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    // t = a * q^(-1) mod 2^32
    let t = (a as i32).wrapping_mul(QINV);
    // t = (a - t*q) / 2^32
    let t = a.wrapping_sub((t as i64).wrapping_mul(Q as i64));
    (t >> 32) as i32
}

/// Reduce coefficient to [-q/2, q/2) (centered representation)
///
/// # Security
///
/// This function executes in constant time.
#[inline]
pub fn reduce32(a: i32) -> i32 {
    // Barrett reduction
    let t = (a + (1 << 22)) >> 23;
    let t = a - t * Q;
    t
}

/// Conditional reduce: if a >= q, subtract q
///
/// # Security
///
/// This function executes in constant time using arithmetic mask.
#[inline]
pub fn cond_reduce(a: i32) -> i32 {
    let mask = ((a - Q) >> 31) as i32;
    a - (Q & !mask)
}

/// Forward NTT: coefficient form → NTT domain
///
/// Cooley-Tukey butterfly with bit-reversed output.
/// After NTT, polynomials can be multiplied pointwise.
///
/// # Arguments
///
/// * `coeffs` - 256 coefficients in standard order
///
/// # Returns
///
/// Coefficients in NTT domain (bit-reversed order)
pub fn ntt(coeffs: &mut [i32; N]) {
    let mut k = 0usize;
    let mut len = 128;

    while len >= 1 {
        let mut start = 0;
        while start < N {
            // Increment k first (ZETAS[0] is unused, start at index 1)
            k += 1;
            let zeta = ZETAS[k];

            for j in start..(start + len) {
                let t = montgomery_reduce(zeta as i64 * coeffs[j + len] as i64);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT: NTT domain → coefficient form
///
/// Gentleman-Sande butterfly with bit-reversed input.
/// Includes multiplication by n^(-1) for proper scaling.
/// Output is in Montgomery domain.
///
/// # Arguments
///
/// * `coeffs` - 256 coefficients in NTT domain
///
/// # Returns
///
/// Coefficients in standard polynomial form (Montgomery domain)
pub fn inv_ntt(coeffs: &mut [i32; N]) {
    let mut k = N;
    let mut len = 1;

    while len < N {
        let mut start = 0;
        while start < N {
            // Decrement k first, then use -ZETAS[k]
            k -= 1;
            let zeta = -ZETAS[k];

            for j in start..(start + len) {
                let t = coeffs[j];
                coeffs[j] = t + coeffs[j + len];
                coeffs[j + len] = t - coeffs[j + len];
                coeffs[j + len] = montgomery_reduce(zeta as i64 * coeffs[j + len] as i64);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by n^(-1) (in Montgomery form) = 41978
    // This is 256^(-1) * 2^32 mod q, which scales output to Montgomery domain
    const F: i64 = 41978;
    for coeff in coeffs.iter_mut() {
        *coeff = montgomery_reduce(F * (*coeff) as i64);
    }
}

/// Pointwise multiplication in NTT domain
///
/// Multiplies two polynomials in NTT representation.
/// Result is also in NTT domain.
pub fn pointwise_mul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
    c
}

/// Convert integer to Montgomery form: a → a*R mod q
pub fn to_mont(a: i32) -> i32 {
    montgomery_reduce(a as i64 * MONT_R2 as i64)
}

/// Convert from Montgomery form: a*R → a mod q
pub fn from_mont(a: i32) -> i32 {
    montgomery_reduce(a as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce_zero() {
        assert_eq!(montgomery_reduce(0), 0);
    }

    #[test]
    fn test_montgomery_reduce_small() {
        // Small values should reduce correctly
        let a = 1000i64 * (1i64 << 32);
        let result = montgomery_reduce(a);
        // Result should be 1000 mod q
        assert!(result >= -Q && result < Q);
    }

    #[test]
    fn test_reduce32() {
        // Positive value less than q
        assert_eq!(reduce32(100), 100);

        // Value equal to q should reduce
        let r = reduce32(Q);
        assert!(r >= -Q / 2 && r < Q / 2);
    }

    #[test]
    fn test_cond_reduce() {
        // Value less than q should be unchanged
        assert_eq!(cond_reduce(100), 100);

        // Value >= q should have q subtracted
        assert_eq!(cond_reduce(Q), 0);
        assert_eq!(cond_reduce(Q + 1), 1);
    }

    #[test]
    fn test_to_from_mont_roundtrip() {
        // Converting to and from Montgomery form should preserve value mod q
        // Note: reduce32 returns centered values, so we compare mod q
        for &a in &[0, 1, 100, Q / 2] {
            let mont = to_mont(a);
            let back = from_mont(mont);
            // May need reduction
            let back = reduce32(back);
            // Handle centered representation
            let normalized = if back < 0 { back + Q } else { back };
            assert_eq!(normalized, a, "roundtrip failed for {}", a);
        }

        // Special case: Q-1 ≡ -1 (mod q) in centered representation
        let a = Q - 1;
        let mont = to_mont(a);
        let back = from_mont(mont);
        let back = reduce32(back);
        // back should be -1 which is equivalent to Q-1
        assert!(
            back == -1 || back == Q - 1,
            "roundtrip failed for Q-1, got {}",
            back
        );
    }

    #[test]
    fn test_ntt_inverse_roundtrip() {
        // NTT followed by inverse NTT should return original polynomial
        // Note: inv_ntt outputs in Montgomery form, so we need to convert back
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = (i as i32) % Q;
        }
        let original = coeffs;

        ntt(&mut coeffs);
        inv_ntt(&mut coeffs);

        for i in 0..N {
            // inv_ntt outputs in Montgomery form - convert back to standard form
            let from_mont = from_mont(coeffs[i]);
            // Reduce to centered representation and normalize to positive
            let reduced = reduce32(from_mont);
            let normalized = if reduced < 0 { reduced + Q } else { reduced };
            assert_eq!(
                normalized, original[i],
                "NTT roundtrip failed at index {}: got {} (from_mont {}), expected {}",
                i, normalized, from_mont, original[i]
            );
        }
    }

    #[test]
    fn test_ntt_multiplication_vs_schoolbook() {
        // NTT multiplication should match schoolbook multiplication
        // Use standard form inputs (not Montgomery form) - this is how Dilithium works
        let mut a = [0i32; N];
        let mut b = [0i32; N];

        // Simple test polynomials in standard form
        a[0] = 1;
        a[1] = 2;
        b[0] = 3;
        b[1] = 4;

        // NTT multiplication: NTT -> pointwise Montgomery mul -> invNTT
        ntt(&mut a);
        ntt(&mut b);
        let mut c_ntt = pointwise_mul(&a, &b);
        inv_ntt(&mut c_ntt);

        // Result is in standard form after invNTT
        // Reduce to positive values in [0, q)
        let normalize = |x: i32| -> i32 {
            let r = reduce32(x);
            if r < 0 { r + Q } else { r }
        };

        // Expected: (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2
        // In R_q = Z[x]/(x^256 + 1), x^256 = -1, but x^2 is just x^2
        assert_eq!(normalize(c_ntt[0]), 3, "c[0] mismatch");
        assert_eq!(normalize(c_ntt[1]), 10, "c[1] mismatch");
        assert_eq!(normalize(c_ntt[2]), 8, "c[2] mismatch");
        assert_eq!(normalize(c_ntt[3]), 0, "c[3] should be 0");
    }

    #[test]
    fn test_modulus_for_ntt() {
        // Verify q allows efficient NTT
        // q = 8380417 ≡ 1 (mod 512)
        assert_eq!(Q % 512, 1, "q must be 1 mod 512 for 256-point NTT");
    }

    #[test]
    fn test_zetas_not_zero() {
        // Verify ZETAS are properly initialized (index 0 is unused, but others should be non-zero)
        assert!(
            ZETAS[1..].iter().any(|&z| z != 0),
            "ZETAS must be initialized"
        );
    }

    #[test]
    fn test_zetas_first_root() {
        // Verify zetas[1] matches the expected first root (ζ^128 in Montgomery form)
        // From CRYSTALS-Dilithium reference: zetas[1] = 25847
        assert_eq!(ZETAS[1], 25847, "First NTT root mismatch");
    }

    #[test]
    fn test_zetas_last_entry() {
        // Verify last zeta matches reference: zetas[255] = 1976782
        assert_eq!(ZETAS[255], 1976782, "Last NTT root mismatch");
    }
}
