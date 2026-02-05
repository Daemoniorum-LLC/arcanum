//! Shamir secret sharing implementation.
//!
//! Provides (t, n) threshold secret sharing where any t shares
//! can reconstruct the secret, but t-1 shares reveal nothing.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::error::{Result, ThresholdError};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single share of a secret.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Share {
    /// The x-coordinate (share index, 1-based).
    index: u8,
    /// The y-coordinate (share value).
    value: Vec<u8>,
}

impl Share {
    /// Create a new share.
    pub fn new(index: u8, value: Vec<u8>) -> Self {
        Self { index, value }
    }

    /// Get the share index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Get the share value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Get mutable access to the share value.
    pub fn value_mut(&mut self) -> &mut [u8] {
        &mut self.value
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.value.len());
        bytes.push(self.index);
        bytes.extend_from_slice(&self.value);
        bytes
    }

    /// Deserialize from bytes.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(ThresholdError::InvalidShareFormat);
        }
        Ok(Self {
            index: bytes[0],
            value: bytes[1..].to_vec(),
        })
    }
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Share(index={}, {} bytes)", self.index, self.value.len())
    }
}

/// Shamir secret sharing scheme over GF(256).
pub struct ShamirScheme;

impl ShamirScheme {
    /// Split a secret into n shares with threshold t.
    ///
    /// Any t shares can reconstruct the secret, but t-1 shares
    /// reveal no information about the secret.
    #[must_use = "secret sharing result must be checked for errors"]
    pub fn split(secret: &[u8], threshold: usize, total: usize) -> Result<Vec<Share>> {
        if threshold == 0 || threshold > total {
            return Err(ThresholdError::InvalidThreshold { threshold, total });
        }
        if total > 255 {
            return Err(ThresholdError::InvalidThreshold { threshold, total });
        }
        if secret.is_empty() {
            return Err(ThresholdError::InvalidShareFormat);
        }

        let mut shares: Vec<Share> = (1..=total as u8)
            .map(|i| Share::new(i, vec![0u8; secret.len()]))
            .collect();

        // For each byte of the secret, create a random polynomial
        // and evaluate at each share index
        let mut rng = rand::rngs::OsRng;
        let mut coeffs = vec![0u8; threshold];

        for (byte_idx, &secret_byte) in secret.iter().enumerate() {
            // Coefficient 0 is the secret byte
            coeffs[0] = secret_byte;

            // Random coefficients for degree 1 to threshold-1
            rng.fill_bytes(&mut coeffs[1..]);

            // Evaluate polynomial at each x value (1 to n)
            for share in &mut shares {
                let x = share.index;
                let y = evaluate_polynomial(&coeffs, x);
                share.value[byte_idx] = y;
            }
        }

        coeffs.zeroize();
        Ok(shares)
    }

    /// Combine shares to reconstruct the secret.
    ///
    /// Requires at least threshold shares.
    #[must_use = "secret reconstruction result must be checked for errors"]
    pub fn combine(shares: &[Share]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(ThresholdError::InsufficientShares {
                required: 1,
                provided: 0,
            });
        }

        // Check for duplicate indices
        let mut seen = [false; 256];
        for share in shares {
            if seen[share.index as usize] {
                return Err(ThresholdError::DuplicateShareIndex {
                    index: share.index as usize,
                });
            }
            seen[share.index as usize] = true;
        }

        // All shares must have the same length
        let len = shares[0].value.len();
        if !shares.iter().all(|s| s.value.len() == len) {
            return Err(ThresholdError::InvalidShareFormat);
        }

        let mut secret = vec![0u8; len];

        // Reconstruct each byte using Lagrange interpolation
        for byte_idx in 0..len {
            let points: Vec<(u8, u8)> = shares
                .iter()
                .map(|s| (s.index, s.value[byte_idx]))
                .collect();
            secret[byte_idx] = lagrange_interpolate(&points, 0);
        }

        Ok(secret)
    }

    /// Verify that shares are consistent (for debugging).
    pub fn verify_shares(shares: &[Share], threshold: usize) -> bool {
        if shares.len() < threshold {
            return false;
        }

        // Try reconstruction with different subsets
        if let Ok(secret1) = Self::combine(&shares[..threshold]) {
            if shares.len() > threshold
                && let Ok(secret2) = Self::combine(&shares[1..=threshold])
            {
                return secret1 == secret2;
            }
            return true;
        }
        false
    }
}

/// Evaluate a polynomial over GF(256) at point x.
fn evaluate_polynomial(coeffs: &[u8], x: u8) -> u8 {
    if x == 0 {
        return coeffs[0];
    }

    let mut result = 0u8;
    let mut x_power = 1u8;

    for &coeff in coeffs {
        result = gf256_add(result, gf256_mul(coeff, x_power));
        x_power = gf256_mul(x_power, x);
    }

    result
}

/// Lagrange interpolation over GF(256) to find f(0).
fn lagrange_interpolate(points: &[(u8, u8)], x: u8) -> u8 {
    let mut result = 0u8;

    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;

        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                numerator = gf256_mul(numerator, gf256_sub(x, xj));
                denominator = gf256_mul(denominator, gf256_sub(xi, xj));
            }
        }

        let term = gf256_mul(yi, gf256_mul(numerator, gf256_inv(denominator)));
        result = gf256_add(result, term);
    }

    result
}

// GF(256) operations using the AES polynomial x^8 + x^4 + x^3 + x + 1

/// GF(256) addition (XOR).
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) subtraction (same as addition in GF(2^n)).
#[inline]
fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) multiplication.
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;

    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b; // AES polynomial reduction
        }
        b >>= 1;
    }

    result
}

/// GF(256) multiplicative inverse using extended Euclidean algorithm.
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // 0 has no inverse, return 0 as convention
    }

    // Use Fermat's little theorem: a^(-1) = a^(254) in GF(256)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine() {
        let secret = b"Hello, Shamir!";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Combine with exactly threshold shares
        let recovered = ShamirScheme::combine(&shares[..3]).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());

        // Combine with more than threshold
        let recovered = ShamirScheme::combine(&shares).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_different_share_subsets() {
        let secret = b"test secret";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();

        // Any 3 shares should work
        let r1 = ShamirScheme::combine(&[shares[0].clone(), shares[1].clone(), shares[2].clone()])
            .unwrap();
        let r2 = ShamirScheme::combine(&[shares[0].clone(), shares[2].clone(), shares[4].clone()])
            .unwrap();
        let r3 = ShamirScheme::combine(&[shares[1].clone(), shares[3].clone(), shares[4].clone()])
            .unwrap();

        assert_eq!(secret.as_slice(), r1.as_slice());
        assert_eq!(secret.as_slice(), r2.as_slice());
        assert_eq!(secret.as_slice(), r3.as_slice());
    }

    #[test]
    fn test_threshold_2_of_3() {
        let secret = b"2-of-3";
        let shares = ShamirScheme::split(secret, 2, 3).unwrap();

        let recovered = ShamirScheme::combine(&shares[..2]).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_threshold_1_of_n() {
        let secret = b"no security";
        let shares = ShamirScheme::split(secret, 1, 5).unwrap();

        // Single share is enough
        let recovered = ShamirScheme::combine(&shares[..1]).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_invalid_threshold() {
        let secret = b"test";

        assert!(ShamirScheme::split(secret, 0, 5).is_err());
        assert!(ShamirScheme::split(secret, 6, 5).is_err());
    }

    #[test]
    fn test_duplicate_indices() {
        let share1 = Share::new(1, vec![1, 2, 3]);
        let share2 = Share::new(1, vec![4, 5, 6]); // Duplicate index

        assert!(ShamirScheme::combine(&[share1, share2]).is_err());
    }

    #[test]
    fn test_share_serialization() {
        let share = Share::new(42, vec![1, 2, 3, 4, 5]);
        let bytes = share.to_bytes();
        let restored = Share::from_bytes(&bytes).unwrap();

        assert_eq!(share.index, restored.index);
        assert_eq!(share.value, restored.value);
    }

    #[test]
    fn test_gf256_operations() {
        // Test identity
        assert_eq!(gf256_mul(1, 42), 42);
        assert_eq!(gf256_mul(42, 1), 42);

        // Test inverse
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "Failed for a={}", a);
        }
    }

    #[test]
    fn test_large_secret() {
        let secret: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        let shares = ShamirScheme::split(&secret, 5, 10).unwrap();
        let recovered = ShamirScheme::combine(&shares[..5]).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_verify_shares() {
        let secret = b"verify me";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();
        assert!(ShamirScheme::verify_shares(&shares, 3));
    }

    #[test]
    fn test_split_empty_secret() {
        let result = ShamirScheme::split(b"", 2, 3);
        assert!(matches!(result, Err(ThresholdError::InvalidShareFormat)));
    }

    #[test]
    fn test_split_threshold_zero() {
        let result = ShamirScheme::split(b"test", 0, 5);
        assert!(matches!(
            result,
            Err(ThresholdError::InvalidThreshold {
                threshold: 0,
                total: 5
            })
        ));
    }

    #[test]
    fn test_split_threshold_exceeds_total() {
        let result = ShamirScheme::split(b"test", 6, 5);
        assert!(matches!(
            result,
            Err(ThresholdError::InvalidThreshold {
                threshold: 6,
                total: 5
            })
        ));
    }

    #[test]
    fn test_split_total_exceeds_255() {
        let result = ShamirScheme::split(b"test", 2, 256);
        assert!(matches!(
            result,
            Err(ThresholdError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn test_combine_empty_shares() {
        let result = ShamirScheme::combine(&[]);
        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientShares {
                required: 1,
                provided: 0
            })
        ));
    }

    #[test]
    fn test_combine_mismatched_share_lengths() {
        let share1 = Share::new(1, vec![1, 2, 3]);
        let share2 = Share::new(2, vec![4, 5]);
        let result = ShamirScheme::combine(&[share1, share2]);
        assert!(matches!(result, Err(ThresholdError::InvalidShareFormat)));
    }

    #[test]
    fn test_share_from_empty_bytes() {
        let result = Share::from_bytes(&[]);
        assert!(matches!(result, Err(ThresholdError::InvalidShareFormat)));
    }

    #[test]
    fn test_share_from_single_byte() {
        let share = Share::from_bytes(&[42]).unwrap();
        assert_eq!(share.index(), 42);
        assert!(share.value().is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PROPERTY-BASED TESTS
    // ═══════════════════════════════════════════════════════════════════════════════

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: split then combine recovers the original secret
            #[test]
            fn prop_split_combine_roundtrip(
                secret in proptest::collection::vec(any::<u8>(), 1..128),
                threshold in 1usize..10,
            ) {
                let total = threshold + (threshold / 2).max(1); // total > threshold
                let total = total.min(255);
                prop_assume!(threshold <= total);

                let shares = ShamirScheme::split(&secret, threshold, total).unwrap();
                prop_assert_eq!(shares.len(), total);

                // Combine with exactly threshold shares
                let recovered = ShamirScheme::combine(&shares[..threshold]).unwrap();
                prop_assert_eq!(recovered, secret);
            }

            /// Property: all subsets of threshold shares recover the same secret
            #[test]
            fn prop_any_threshold_subset_works(
                secret in proptest::collection::vec(any::<u8>(), 1..64),
            ) {
                let threshold = 3;
                let total = 5;
                let shares = ShamirScheme::split(&secret, threshold, total).unwrap();

                // Try first and last subset of threshold shares
                let r1 = ShamirScheme::combine(&shares[..threshold]).unwrap();
                let r2 = ShamirScheme::combine(&shares[total - threshold..]).unwrap();
                prop_assert_eq!(&r1, &secret);
                prop_assert_eq!(&r2, &secret);
            }

            /// Property: share serialization roundtrip preserves data
            #[test]
            fn prop_share_serialization_roundtrip(
                index in 0u8..=255,
                value in proptest::collection::vec(any::<u8>(), 0..128),
            ) {
                let share = Share::new(index, value.clone());
                let bytes = share.to_bytes();
                let restored = Share::from_bytes(&bytes).unwrap();
                prop_assert_eq!(restored.index(), index);
                prop_assert_eq!(restored.value(), value.as_slice());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PHASE 5.1: THRESHOLD SECURITY VERIFICATION
    // These tests verify the fundamental security property of Shamir's scheme:
    // t-1 shares reveal NOTHING about the secret (information-theoretic security).
    // ═══════════════════════════════════════════════════════════════════════════════

    mod threshold_security {
        use super::*;
        use itertools::Itertools;

        /// Verify that t-1 shares produce incorrect reconstruction.
        /// This is the FUNDAMENTAL security property of Shamir's scheme.
        #[test]
        fn test_combine_with_insufficient_shares_produces_wrong_secret() {
            let secret = b"top secret data that must stay hidden";
            let threshold = 3;
            let total = 5;

            let shares = ShamirScheme::split(secret, threshold, total).unwrap();

            // Try every possible subset of t-1 shares
            for subset in shares.iter().cloned().combinations(threshold - 1) {
                let result = ShamirScheme::combine(&subset).unwrap(); // Returns Ok, but wrong data
                assert_ne!(
                    result.as_slice(),
                    secret.as_slice(),
                    "t-1 shares MUST NOT reconstruct the original secret"
                );
            }
        }

        /// Verify the boundary: exactly t shares always succeeds.
        #[test]
        fn test_combine_with_exactly_threshold_shares_succeeds() {
            let secret = b"threshold boundary test";
            let threshold = 3;
            let total = 5;

            let shares = ShamirScheme::split(secret, threshold, total).unwrap();

            // Every t-sized subset must reconstruct correctly
            for subset in shares.iter().cloned().combinations(threshold) {
                let result = ShamirScheme::combine(&subset).unwrap();
                assert_eq!(
                    result.as_slice(),
                    secret.as_slice(),
                    "Exactly t shares must reconstruct the secret"
                );
            }
        }

        /// Statistical test: t-1 share reconstructions should appear random.
        /// With t-1 shares, the result should be uniformly random in GF(256)^n,
        /// independent of the actual secret.
        #[test]
        fn test_insufficient_shares_produce_random_looking_output() {
            let secret = vec![0xAA; 32]; // Known pattern
            let threshold = 3;
            let total = 5;

            let shares = ShamirScheme::split(&secret, threshold, total).unwrap();
            let partial: Vec<_> = shares[..threshold - 1].to_vec();
            let wrong_result = ShamirScheme::combine(&partial).unwrap();

            // Check byte distribution isn't suspiciously close to the secret
            let matching_bytes = wrong_result
                .iter()
                .zip(secret.iter())
                .filter(|(a, b)| a == b)
                .count();

            // With 32 random bytes, expected matching ≈ 32/256 ≈ 0.125
            // Allow generous margin but catch if all/most bytes match
            assert!(
                matching_bytes < secret.len() / 2,
                "t-1 reconstruction matched {}/{} bytes — suspiciously close to secret",
                matching_bytes,
                secret.len()
            );
        }

        /// Boundary test across multiple threshold/total configurations.
        /// Verifies the exact boundary between t-1 (reveals nothing) and t (reveals all).
        #[test]
        fn test_threshold_boundary_multiple_configurations() {
            for (threshold, total) in [(2, 3), (2, 5), (3, 5), (5, 10), (10, 20)] {
                let secret = b"boundary test secret";
                let shares = ShamirScheme::split(secret, threshold, total).unwrap();

                // t shares: must succeed
                let result = ShamirScheme::combine(&shares[..threshold]).unwrap();
                assert_eq!(
                    result.as_slice(),
                    secret.as_slice(),
                    "t={},n={}: t shares failed",
                    threshold,
                    total
                );

                // t-1 shares: must produce wrong result
                let wrong = ShamirScheme::combine(&shares[..threshold - 1]).unwrap();
                assert_ne!(
                    wrong.as_slice(),
                    secret.as_slice(),
                    "t={},n={}: t-1 shares matched (SECURITY VIOLATION)",
                    threshold,
                    total
                );
            }
        }

        /// Verify that t-1 results are different for different secrets with same shares indices.
        /// This ensures the wrong reconstruction isn't leaking a fixed pattern.
        #[test]
        fn test_insufficient_shares_vary_with_secret() {
            let threshold = 3;
            let total = 5;

            let secret_a = vec![0x00; 16];
            let secret_b = vec![0xFF; 16];

            let shares_a = ShamirScheme::split(&secret_a, threshold, total).unwrap();
            let shares_b = ShamirScheme::split(&secret_b, threshold, total).unwrap();

            let partial_a: Vec<_> = shares_a[..threshold - 1].to_vec();
            let partial_b: Vec<_> = shares_b[..threshold - 1].to_vec();

            let wrong_a = ShamirScheme::combine(&partial_a).unwrap();
            let wrong_b = ShamirScheme::combine(&partial_b).unwrap();

            // Different secrets should produce different wrong results
            // (with overwhelming probability)
            assert_ne!(
                wrong_a, wrong_b,
                "Different secrets produced identical t-1 reconstructions"
            );
        }

        /// Edge case: verify 2-of-n threshold security.
        /// With 1 share, reconstruction should be completely determined by that share alone,
        /// not revealing the secret.
        #[test]
        fn test_single_share_reveals_nothing_in_2_of_n() {
            let secret = b"2-of-n security test";
            let threshold = 2;
            let total = 5;

            let shares = ShamirScheme::split(secret, threshold, total).unwrap();

            // Each single share should produce a different wrong result
            let results: Vec<Vec<u8>> = shares
                .iter()
                .map(|s| ShamirScheme::combine(&[s.clone()]).unwrap())
                .collect();

            for result in &results {
                assert_ne!(
                    result.as_slice(),
                    secret.as_slice(),
                    "Single share must not reveal secret in 2-of-n"
                );
            }

            // All single-share results should be different from each other
            // (each share produces a unique wrong reconstruction)
            for i in 0..results.len() {
                for j in (i + 1)..results.len() {
                    assert_ne!(
                        results[i], results[j],
                        "Shares {} and {} produced identical single-share reconstructions",
                        i + 1,
                        j + 1
                    );
                }
            }
        }

        /// Verify that the t-1 security property holds for large secrets.
        #[test]
        fn test_threshold_security_large_secret() {
            let secret: Vec<u8> = (0..256).map(|i| i as u8).collect(); // 256 byte secret
            let threshold = 5;
            let total = 10;

            let shares = ShamirScheme::split(&secret, threshold, total).unwrap();

            // t-1 shares must not recover the secret
            let partial: Vec<_> = shares[..threshold - 1].to_vec();
            let wrong = ShamirScheme::combine(&partial).unwrap();

            assert_ne!(
                wrong.as_slice(),
                secret.as_slice(),
                "t-1 shares reconstructed large secret (SECURITY VIOLATION)"
            );

            // Check that at least half the bytes differ
            let matching = wrong
                .iter()
                .zip(secret.iter())
                .filter(|(a, b)| a == b)
                .count();
            assert!(
                matching < secret.len() / 2,
                "t-1 reconstruction suspiciously similar to secret: {} of {} bytes match",
                matching,
                secret.len()
            );
        }
    }
}
