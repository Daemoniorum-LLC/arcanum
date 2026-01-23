//! Verification for ML-DSA (FIPS 204)
//!
//! Implements Algorithm 3 (ML-DSA.Verify) from FIPS 204.
//!
//! # Algorithm Overview
//!
//! 1. (c̃, z, h) ← σ
//! 2. A ← ExpandA(ρ)
//! 3. μ ← H(H(pk) || M)
//! 4. c ← SampleInBall(c̃)
//! 5. w' ← Az - ct₁ · 2^d
//! 6. w'₁ ← UseHint(h, w')
//! 7. c̃' ← H(μ || w'₁)
//! 8. return ||z||∞ < γ₁ - β and c̃ = c̃' and #ones(h) ≤ ω

#![allow(dead_code)]

use super::keygen::unpack_pk;
use super::params::{D, MlDsaParams, N, Q};
use super::poly::Poly;
use super::rounding::use_hint;
use super::sampling::{expand_a, sample_in_ball};
use super::sign::unpack_signature;
use arcanum_primitives::shake::Shake256;

/// Verify an ML-DSA signature
///
/// # Arguments
///
/// * `pk_bytes` - Packed public key
/// * `message` - Message that was signed
/// * `sig_bytes` - Packed signature
///
/// # Returns
///
/// `true` if signature is valid, `false` otherwise
pub fn verify_internal<P: MlDsaParams>(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> bool {
    // Unpack public key (mutable for in-place NTT)
    let (rho, mut t1) = match unpack_pk::<P>(pk_bytes) {
        Some(pk) => pk,
        None => return false,
    };

    // Step 1: Unpack signature (c̃, z, h) - z is mutable for in-place NTT
    let (c_tilde, mut z, h) = match unpack_signature::<P>(sig_bytes) {
        Some(sig) => sig,
        None => return false,
    };

    // Check hint weight ≤ ω
    let hint_count: usize = h
        .iter()
        .map(|poly| poly.coeffs.iter().filter(|&&c| c != 0).count())
        .sum();

    if hint_count > P::OMEGA {
        return false;
    }

    // Check ||z||∞ < γ₁ - β (before NTT conversion)
    let gamma1_minus_beta = P::GAMMA1 - P::BETA;
    for poly in &z {
        let norm = poly.infinity_norm();
        if norm >= gamma1_minus_beta {
            return false;
        }
    }

    // Step 2: A ← ExpandA(ρ)
    let a = expand_a::<P>(&rho);

    // Step 3: μ ← H(tr || M) where tr = H(pk)
    // First compute tr = H(pk)
    let mut shake = Shake256::new();
    shake.update(pk_bytes);
    let mut reader = shake.finalize_xof();
    let mut tr = [0u8; 64];
    reader.squeeze(&mut tr);

    // Then compute μ = H(tr || M)
    let mut shake = Shake256::new();
    shake.update(&tr);
    shake.update(message);
    let mut reader = shake.finalize_xof();
    let mut mu = [0u8; 64];
    reader.squeeze(&mut mu);

    // Step 4: c ← SampleInBall(c̃)
    let mut c = sample_in_ball(&c_tilde, P::TAU);
    c.ntt();

    // Convert z to NTT domain (in-place, no clone needed)
    for poly in &mut z {
        poly.ntt();
    }

    // Convert t₁ to NTT domain (in-place, no clone needed)
    for poly in &mut t1 {
        poly.ntt();
    }

    // Step 5: w' ← Az - ct₁ · 2^d
    // First compute Az (in NTT domain)
    let mut az_ntt = vec![Poly::zero(); P::K];
    for i in 0..P::K {
        for j in 0..P::L {
            let product = a[i][j].pointwise_mul(&z[j]);
            az_ntt[i] = az_ntt[i].add(&product);
        }
    }

    // Compute ct₁ (in NTT domain)
    let mut ct1_ntt = vec![Poly::zero(); P::K];
    for i in 0..P::K {
        ct1_ntt[i] = c.pointwise_mul(&t1[i]);
    }

    // Convert Az and ct1 to coefficient domain
    let mut w_prime = vec![Poly::zero(); P::K];
    for i in 0..P::K {
        // Convert Az from NTT
        let mut az_i = az_ntt[i];
        az_i.inv_ntt();
        az_i.reduce();

        // Convert ct1 from NTT
        let mut ct1_i = ct1_ntt[i];
        ct1_i.inv_ntt();
        ct1_i.reduce_centered();

        // w' = Az - ct₁ · 2^d
        // Use i64 to avoid overflow since ct1 * 2^D can exceed i32 range
        for j in 0..N {
            let az_val = az_i.coeffs[j] as i64;
            let ct1_scaled = (ct1_i.coeffs[j] as i64) * (1i64 << D);
            let mut val = az_val - ct1_scaled;

            // Reduce to [0, q)
            val = ((val % (Q as i64)) + (Q as i64)) % (Q as i64);
            w_prime[i].coeffs[j] = val as i32;
        }
    }

    // Step 6: w'₁ ← UseHint(h, w')
    let mut w_prime_1 = vec![Poly::zero(); P::K];
    for i in 0..P::K {
        for j in 0..N {
            let hint_bit = h[i].coeffs[j] != 0;
            w_prime_1[i].coeffs[j] = use_hint(hint_bit, w_prime[i].coeffs[j], P::GAMMA2 as i32);
        }
    }

    // Step 7: c̃' ← H(μ || w'₁)
    let c_tilde_prime = compute_challenge_hash::<P>(&mu, &w_prime_1);

    // Step 8: Check c̃ = c̃'
    c_tilde == c_tilde_prime
}

/// Compute the challenge hash c̃ = H(μ || w₁)
fn compute_challenge_hash<P: MlDsaParams>(mu: &[u8; 64], w1: &[Poly]) -> Vec<u8> {
    let c_tilde_len = P::LAMBDA / 4;

    let mut shake = Shake256::new();
    shake.update(mu);

    // Pack w₁ for hashing
    for poly in w1.iter().take(P::K) {
        let packed = pack_w1_poly::<P>(poly);
        shake.update(&packed);
    }

    let mut reader = shake.finalize_xof();
    let mut c_tilde = vec![0u8; c_tilde_len];
    reader.squeeze(&mut c_tilde);
    c_tilde
}

/// Pack a w₁ polynomial for hashing
fn pack_w1_poly<P: MlDsaParams>(poly: &Poly) -> Vec<u8> {
    if P::GAMMA2 == (Q as u32 - 1) / 88 {
        // ML-DSA-44: 6 bits per coefficient
        pack_w1_6bits(poly)
    } else {
        // ML-DSA-65/87: 4 bits per coefficient
        pack_w1_4bits(poly)
    }
}

/// Pack w₁ with 6 bits per coefficient
fn pack_w1_6bits(poly: &Poly) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(192);

    for chunk in 0..(N / 4) {
        let c0 = poly.coeffs[4 * chunk] as u32;
        let c1 = poly.coeffs[4 * chunk + 1] as u32;
        let c2 = poly.coeffs[4 * chunk + 2] as u32;
        let c3 = poly.coeffs[4 * chunk + 3] as u32;

        bytes.push((c0 | (c1 << 6)) as u8);
        bytes.push(((c1 >> 2) | (c2 << 4)) as u8);
        bytes.push(((c2 >> 4) | (c3 << 2)) as u8);
    }

    bytes
}

/// Pack w₁ with 4 bits per coefficient
fn pack_w1_4bits(poly: &Poly) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);

    for chunk in 0..(N / 2) {
        let c0 = poly.coeffs[2 * chunk] as u8;
        let c1 = poly.coeffs[2 * chunk + 1] as u8;
        bytes.push(c0 | (c1 << 4));
    }

    bytes
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::super::keygen::{generate_keypair_internal, pack_pk, pack_sk};
    use super::super::params::{Params44, Params65, Params87};
    use super::super::sign::sign_internal;
    use super::*;

    fn get_test_keypair<P: MlDsaParams>() -> (Vec<u8>, Vec<u8>) {
        let seed = [0x42u8; 32];
        let kp = generate_keypair_internal::<P>(&seed);
        let pk = pack_pk::<P>(&kp.rho, &kp.t1);
        let sk = pack_sk::<P>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);
        (pk, sk)
    }

    #[test]
    fn test_verify_44_valid_signature() {
        let (pk, sk) = get_test_keypair::<Params44>();
        let message = b"Test message for ML-DSA-44";

        let sig = sign_internal::<Params44>(&sk, message).expect("Signing should succeed");
        assert!(
            verify_internal::<Params44>(&pk, message, &sig),
            "Verification should succeed"
        );
    }

    #[test]
    fn test_verify_65_valid_signature() {
        let (pk, sk) = get_test_keypair::<Params65>();
        let message = b"Test message for ML-DSA-65";

        let sig = sign_internal::<Params65>(&sk, message).expect("Signing should succeed");
        assert!(
            verify_internal::<Params65>(&pk, message, &sig),
            "Verification should succeed"
        );
    }

    #[test]
    fn test_verify_87_valid_signature() {
        let (pk, sk) = get_test_keypair::<Params87>();
        let message = b"Test message for ML-DSA-87";

        let sig = sign_internal::<Params87>(&sk, message).expect("Signing should succeed");
        assert!(
            verify_internal::<Params87>(&pk, message, &sig),
            "Verification should succeed"
        );
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let (pk, sk) = get_test_keypair::<Params44>();
        let message1 = b"Original message";
        let message2 = b"Different message";

        let sig = sign_internal::<Params44>(&sk, message1).expect("Signing should succeed");
        assert!(
            !verify_internal::<Params44>(&pk, message2, &sig),
            "Verification should fail for wrong message"
        );
    }

    #[test]
    fn test_verify_various_messages() {
        // Test various message lengths to ensure verification works across different cases
        let (pk, sk) = get_test_keypair::<Params44>();

        let messages: &[&[u8]] = &[
            b"",                                                        // Empty message
            b"A",                                                       // Single byte
            b"Test message",                                            // Short message
            b"Test message for ML-DSA-44",                              // Medium message
            b"The quick brown fox jumps over the lazy dog. 0123456789", // Longer message
        ];

        for (idx, message) in messages.iter().enumerate() {
            let sig = sign_internal::<Params44>(&sk, message)
                .expect(&format!("Signing message {} should succeed", idx));
            assert!(
                verify_internal::<Params44>(&pk, message, &sig),
                "Verification should succeed for message {} ({} bytes)",
                idx,
                message.len()
            );
        }
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (pk1, sk1) = get_test_keypair::<Params44>();
        let seed2 = [0x43u8; 32];
        let kp2 = generate_keypair_internal::<Params44>(&seed2);
        let pk2 = pack_pk::<Params44>(&kp2.rho, &kp2.t1);

        let message = b"Test message";
        let sig = sign_internal::<Params44>(&sk1, message).expect("Signing should succeed");

        // Verify with wrong key should fail
        assert!(
            !verify_internal::<Params44>(&pk2, message, &sig),
            "Verification should fail with wrong key"
        );
        // But correct key should work
        assert!(
            verify_internal::<Params44>(&pk1, message, &sig),
            "Verification should succeed with correct key"
        );
    }

    #[test]
    fn test_verify_corrupted_signature_fails() {
        let (pk, sk) = get_test_keypair::<Params44>();
        let message = b"Test message";

        let mut sig = sign_internal::<Params44>(&sk, message).expect("Signing should succeed");

        // Corrupt the signature
        sig[50] ^= 0xFF;

        assert!(
            !verify_internal::<Params44>(&pk, message, &sig),
            "Verification should fail for corrupted signature"
        );
    }

    #[test]
    fn test_verify_invalid_pk_size() {
        let message = b"Test";
        let sig = vec![0u8; Params44::SIG_SIZE];
        let pk = vec![0u8; 100]; // Wrong size

        assert!(!verify_internal::<Params44>(&pk, message, &sig));
    }

    #[test]
    fn test_verify_invalid_sig_size() {
        let (pk, _sk) = get_test_keypair::<Params44>();
        let message = b"Test";
        let sig = vec![0u8; 100]; // Wrong size

        assert!(!verify_internal::<Params44>(&pk, message, &sig));
    }

    #[test]
    fn test_sign_verify_empty_message() {
        let (pk, sk) = get_test_keypair::<Params65>();
        let message = b"";

        let sig = sign_internal::<Params65>(&sk, message).expect("Signing should succeed");
        assert!(
            verify_internal::<Params65>(&pk, message, &sig),
            "Verification should succeed for empty message"
        );
    }

    #[test]
    fn test_sign_verify_long_message() {
        let (pk, sk) = get_test_keypair::<Params65>();
        let message = vec![0xABu8; 10000]; // 10KB message

        let sig = sign_internal::<Params65>(&sk, &message).expect("Signing should succeed");
        assert!(
            verify_internal::<Params65>(&pk, &message, &sig),
            "Verification should succeed for long message"
        );
    }
}
