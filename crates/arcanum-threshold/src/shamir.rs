//! Shamir secret sharing implementation.
//!
//! Provides (t, n) threshold secret sharing where any t shares
//! can reconstruct the secret, but t-1 shares reveal nothing.

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

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
}
