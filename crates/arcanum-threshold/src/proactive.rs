//! Proactive secret sharing - refresh shares without changing the secret.
//!
//! Proactive secret sharing allows periodic refresh of shares to limit the
//! window of compromise. Even if an attacker collects shares over time,
//! refreshed shares are incompatible with old shares.
//!
//! ## Algorithm
//!
//! The refresh protocol works by adding shares of a zero-secret polynomial:
//!
//! 1. Generate a random polynomial q(x) of degree (threshold - 1) with q(0) = 0
//! 2. Evaluate q(x) at each share index to get "refresh deltas"
//! 3. Add each delta to its corresponding share value (in GF(256))
//!
//! Since q(0) = 0, the reconstructed secret remains unchanged:
//! - new_share[i] = old_share[i] + q(i)
//! - secret = Σ(lagrange_i * new_share[i]) = Σ(lagrange_i * old_share[i]) + Σ(lagrange_i * q(i))
//!   = old_secret + q(0) = old_secret + 0 = old_secret
//!
//! ## Distributed Refresh
//!
//! For distributed refresh without a trusted dealer:
//!
//! 1. Each participant generates their own zero-polynomial and distributes shares
//! 2. Each participant adds all received contributions to their existing share
//! 3. The combined effect is equivalent to adding shares of a single zero-polynomial

use crate::error::{Result, ThresholdError};
use crate::shamir::Share;
use rand::RngCore;

/// Refresh shares generated from a zero-constant polynomial.
///
/// These can be added to existing shares to refresh them without
/// changing the underlying secret.
#[derive(Debug, Clone)]
pub struct RefreshShares {
    /// The refresh contributions for each participant.
    pub contributions: Vec<Share>,
}

impl RefreshShares {
    /// Get the contribution for a specific participant index.
    pub fn for_participant(&self, index: u8) -> Option<&Share> {
        self.contributions.iter().find(|s| s.index() == index)
    }
}

/// Proactive share refresh protocol.
pub struct ProactiveRefresh;

impl ProactiveRefresh {
    /// Refresh all shares without changing the underlying secret.
    ///
    /// After refresh:
    /// - New shares have different values than old shares
    /// - New shares reconstruct to the same secret
    /// - Old shares are incompatible with new shares for reconstruction
    ///
    /// # Arguments
    /// * `shares` - Current shares to refresh
    /// * `threshold` - The threshold (t) for reconstruction
    ///
    /// # Returns
    /// New shares that reconstruct to the same secret
    ///
    /// # Errors
    /// Returns error if parameters are invalid
    pub fn refresh(shares: &[Share], threshold: usize) -> Result<Vec<Share>> {
        if shares.is_empty() {
            return Err(ThresholdError::InsufficientShares {
                required: 1,
                provided: 0,
            });
        }

        if threshold == 0 {
            return Err(ThresholdError::InvalidThreshold {
                threshold,
                total: shares.len(),
            });
        }

        // Get the share value length from the first share
        let value_len = shares[0].value().len();
        if value_len == 0 {
            return Err(ThresholdError::InvalidShareFormat);
        }

        // Generate refresh shares for each byte position
        let mut refreshed: Vec<Share> = shares
            .iter()
            .map(|s| Share::new(s.index(), s.value().to_vec()))
            .collect();

        // Generate a zero-polynomial and add its evaluations to each share
        let mut rng = rand::rngs::OsRng;

        // For each byte position, generate a random polynomial with zero constant term
        // and add its evaluations to the corresponding share bytes
        for byte_idx in 0..value_len {
            // Generate random coefficients for degree 1 to threshold-1
            // (coefficient 0 is always 0 for a zero-polynomial)
            let mut coeffs = vec![0u8; threshold];
            // coeffs[0] = 0 (zero constant term - this is what preserves the secret)
            if threshold > 1 {
                rng.fill_bytes(&mut coeffs[1..]);
            }

            // Add polynomial evaluation to each share
            for share in &mut refreshed {
                let delta = evaluate_polynomial_gf256(&coeffs, share.index());
                let current = share.value()[byte_idx];
                let new_value = gf256_add(current, delta);
                share.value_mut()[byte_idx] = new_value;
            }
        }

        Ok(refreshed)
    }

    /// Generate refresh contributions for distributed refresh.
    ///
    /// In a distributed setting, each participant generates their own
    /// zero-polynomial and distributes shares to all participants.
    ///
    /// # Arguments
    /// * `threshold` - The threshold (t) for reconstruction
    /// * `participant_indices` - The indices of all participants
    /// * `value_len` - Length of the secret in bytes
    ///
    /// # Returns
    /// Refresh shares to distribute to each participant
    pub fn generate_refresh_shares(
        threshold: usize,
        participant_indices: &[u8],
        value_len: usize,
    ) -> Result<RefreshShares> {
        if threshold == 0 || participant_indices.is_empty() {
            return Err(ThresholdError::InvalidThreshold {
                threshold,
                total: participant_indices.len(),
            });
        }

        if value_len == 0 {
            return Err(ThresholdError::InvalidShareFormat);
        }

        let mut contributions: Vec<Share> = participant_indices
            .iter()
            .map(|&idx| Share::new(idx, vec![0u8; value_len]))
            .collect();

        let mut rng = rand::rngs::OsRng;

        // For each byte position, generate a zero-polynomial
        for byte_idx in 0..value_len {
            let mut coeffs = vec![0u8; threshold];
            // coeffs[0] = 0 (zero constant term)
            if threshold > 1 {
                rng.fill_bytes(&mut coeffs[1..]);
            }

            // Evaluate at each participant index
            for share in &mut contributions {
                let value = evaluate_polynomial_gf256(&coeffs, share.index());
                share.value_mut()[byte_idx] = value;
            }
        }

        Ok(RefreshShares { contributions })
    }

    /// Apply refresh contributions to update a participant's share.
    ///
    /// Each participant adds all received contributions to their existing share.
    ///
    /// # Arguments
    /// * `current_share` - The participant's current share
    /// * `contributions` - Refresh contributions from all participants (including self)
    ///
    /// # Returns
    /// Updated share with all contributions applied
    pub fn apply_refresh(current_share: &Share, contributions: &[&Share]) -> Result<Share> {
        // All contributions must be for the same index as current_share
        for contrib in contributions {
            if contrib.index() != current_share.index() {
                return Err(ThresholdError::InvalidShareIndex {
                    index: contrib.index() as usize,
                    max: current_share.index() as usize,
                });
            }
            if contrib.value().len() != current_share.value().len() {
                return Err(ThresholdError::InvalidShareFormat);
            }
        }

        let mut new_value = current_share.value().to_vec();

        // Add all contributions (GF(256) addition = XOR)
        for contrib in contributions {
            for (i, &byte) in contrib.value().iter().enumerate() {
                new_value[i] = gf256_add(new_value[i], byte);
            }
        }

        Ok(Share::new(current_share.index(), new_value))
    }

    /// Verify that refreshed shares still reconstruct to the same secret.
    ///
    /// This is primarily for testing/debugging purposes.
    #[cfg(test)]
    pub fn verify_refresh(
        original_shares: &[Share],
        refreshed_shares: &[Share],
        threshold: usize,
    ) -> bool {
        use crate::shamir::ShamirScheme;

        if original_shares.len() < threshold || refreshed_shares.len() < threshold {
            return false;
        }

        let original_secret = match ShamirScheme::combine(&original_shares[..threshold]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let refreshed_secret = match ShamirScheme::combine(&refreshed_shares[..threshold]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        original_secret == refreshed_secret
    }
}

/// Evaluate a polynomial over GF(256) at point x.
fn evaluate_polynomial_gf256(coeffs: &[u8], x: u8) -> u8 {
    if x == 0 {
        return coeffs.first().copied().unwrap_or(0);
    }

    let mut result = 0u8;
    let mut x_power = 1u8;

    for &coeff in coeffs {
        result = gf256_add(result, gf256_mul(coeff, x_power));
        x_power = gf256_mul(x_power, x);
    }

    result
}

/// GF(256) addition (XOR).
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) multiplication using AES polynomial (x^8 + x^4 + x^3 + x + 1).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::ShamirScheme;

    #[test]
    fn test_refresh_preserves_secret() {
        let secret = b"test secret for proactive refresh";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();

        let refreshed = ProactiveRefresh::refresh(&shares, 3).unwrap();

        // Shares should be different
        assert_ne!(shares[0].value(), refreshed[0].value());
        assert_ne!(shares[1].value(), refreshed[1].value());

        // Both should reconstruct to the same secret
        let original_secret = ShamirScheme::combine(&shares[0..3]).unwrap();
        let refreshed_secret = ShamirScheme::combine(&refreshed[0..3]).unwrap();
        assert_eq!(original_secret, refreshed_secret);
        assert_eq!(secret.as_slice(), refreshed_secret.as_slice());
    }

    #[test]
    fn test_refresh_different_subsets() {
        let secret = b"any subset should work";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();
        let refreshed = ProactiveRefresh::refresh(&shares, 3).unwrap();

        // Try different subsets of refreshed shares
        let r1 = ShamirScheme::combine(&[
            refreshed[0].clone(),
            refreshed[1].clone(),
            refreshed[2].clone(),
        ])
        .unwrap();
        let r2 = ShamirScheme::combine(&[
            refreshed[0].clone(),
            refreshed[2].clone(),
            refreshed[4].clone(),
        ])
        .unwrap();
        let r3 = ShamirScheme::combine(&[
            refreshed[1].clone(),
            refreshed[3].clone(),
            refreshed[4].clone(),
        ])
        .unwrap();

        assert_eq!(secret.as_slice(), r1.as_slice());
        assert_eq!(secret.as_slice(), r2.as_slice());
        assert_eq!(secret.as_slice(), r3.as_slice());
    }

    #[test]
    fn test_old_and_new_shares_incompatible() {
        let secret = b"incompatibility test";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();
        let refreshed = ProactiveRefresh::refresh(&shares, 3).unwrap();

        // Mixing old and new shares should NOT reconstruct correctly
        // (unless by coincidence - very unlikely)
        let mixed = ShamirScheme::combine(&[
            shares[0].clone(),    // old
            refreshed[1].clone(), // new
            refreshed[2].clone(), // new
        ])
        .unwrap();

        // This should be different from the original secret
        assert_ne!(secret.as_slice(), mixed.as_slice());
    }

    #[test]
    fn test_multiple_refreshes() {
        let secret = b"refresh multiple times";
        let shares = ShamirScheme::split(secret, 2, 4).unwrap();

        // Refresh multiple times
        let r1 = ProactiveRefresh::refresh(&shares, 2).unwrap();
        let r2 = ProactiveRefresh::refresh(&r1, 2).unwrap();
        let r3 = ProactiveRefresh::refresh(&r2, 2).unwrap();

        // Each refresh should produce different shares
        assert_ne!(shares[0].value(), r1[0].value());
        assert_ne!(r1[0].value(), r2[0].value());
        assert_ne!(r2[0].value(), r3[0].value());

        // But all should reconstruct to the same secret
        assert_eq!(
            secret.as_slice(),
            ShamirScheme::combine(&r3[..2]).unwrap().as_slice()
        );
    }

    #[test]
    fn test_distributed_refresh() {
        let secret = b"distributed refresh protocol";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();

        let indices: Vec<u8> = shares.iter().map(|s| s.index()).collect();
        let value_len = shares[0].value().len();

        // Each participant generates refresh shares
        let refresh1 = ProactiveRefresh::generate_refresh_shares(3, &indices, value_len).unwrap();
        let refresh2 = ProactiveRefresh::generate_refresh_shares(3, &indices, value_len).unwrap();
        let refresh3 = ProactiveRefresh::generate_refresh_shares(3, &indices, value_len).unwrap();

        // Each participant applies contributions from all participants
        let mut refreshed = Vec::new();
        for share in &shares {
            let idx = share.index();
            let c1 = refresh1.for_participant(idx).unwrap();
            let c2 = refresh2.for_participant(idx).unwrap();
            let c3 = refresh3.for_participant(idx).unwrap();

            let new_share = ProactiveRefresh::apply_refresh(share, &[c1, c2, c3]).unwrap();
            refreshed.push(new_share);
        }

        // Refreshed shares should reconstruct to the same secret
        let reconstructed = ShamirScheme::combine(&refreshed[..3]).unwrap();
        assert_eq!(secret.as_slice(), reconstructed.as_slice());
    }

    #[test]
    fn test_threshold_2_of_3_refresh() {
        let secret = b"2-of-3 secret";
        let shares = ShamirScheme::split(secret, 2, 3).unwrap();
        let refreshed = ProactiveRefresh::refresh(&shares, 2).unwrap();

        let reconstructed = ShamirScheme::combine(&refreshed[..2]).unwrap();
        assert_eq!(secret.as_slice(), reconstructed.as_slice());
    }

    #[test]
    fn test_gf256_polynomial_zero_constant() {
        // A polynomial with zero constant term should evaluate to 0 at x=0
        let coeffs = vec![0u8, 0x42, 0x13, 0x37]; // q(x) = 0 + 0x42*x + 0x13*x^2 + 0x37*x^3
        assert_eq!(evaluate_polynomial_gf256(&coeffs, 0), 0);

        // But non-zero at other points
        assert_ne!(evaluate_polynomial_gf256(&coeffs, 1), 0);
        assert_ne!(evaluate_polynomial_gf256(&coeffs, 2), 0);
    }

    #[test]
    fn test_verify_refresh() {
        let secret = b"verify test";
        let shares = ShamirScheme::split(secret, 3, 5).unwrap();
        let refreshed = ProactiveRefresh::refresh(&shares, 3).unwrap();

        assert!(ProactiveRefresh::verify_refresh(&shares, &refreshed, 3));
    }
}
