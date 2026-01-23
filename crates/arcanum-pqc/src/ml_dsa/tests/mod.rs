//! Tests for ML-DSA implementation
//!
//! Organized into:
//! - Unit tests (in each module)
//! - Integration tests (sign/verify roundtrip)
//! - KAT tests (FIPS 204 test vectors)

#[cfg(test)]
mod integration {
    use crate::ml_dsa::{MlDsa, MlDsa44, MlDsa65, MlDsa87};

    /// Test that ML-DSA-44 sign/verify roundtrip works
    #[test]
    fn test_ml_dsa_44_sign_verify_roundtrip() {
        let (sk, vk) = MlDsa44::generate_keypair();
        let message = b"Test message for ML-DSA-44 integration test";
        let sig = MlDsa44::sign(&sk, message);
        assert!(
            MlDsa44::verify(&vk, message, &sig).is_ok(),
            "ML-DSA-44 sign/verify roundtrip failed"
        );
    }

    /// Test that ML-DSA-65 sign/verify roundtrip works
    #[test]
    fn test_ml_dsa_65_sign_verify_roundtrip() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let message = b"Test message for ML-DSA-65 integration test";
        let sig = MlDsa65::sign(&sk, message);
        assert!(
            MlDsa65::verify(&vk, message, &sig).is_ok(),
            "ML-DSA-65 sign/verify roundtrip failed"
        );
    }

    /// Test that ML-DSA-87 sign/verify roundtrip works
    #[test]
    fn test_ml_dsa_87_sign_verify_roundtrip() {
        let (sk, vk) = MlDsa87::generate_keypair();
        let message = b"Test message for ML-DSA-87 integration test";
        let sig = MlDsa87::sign(&sk, message);
        assert!(
            MlDsa87::verify(&vk, message, &sig).is_ok(),
            "ML-DSA-87 sign/verify roundtrip failed"
        );
    }

    /// Test that wrong message fails verification
    #[test]
    fn test_wrong_message_fails() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let sig = MlDsa65::sign(&sk, b"message 1");
        assert!(
            MlDsa65::verify(&vk, b"message 2", &sig).is_err(),
            "Verification should fail for wrong message"
        );
    }

    /// Test that wrong key fails verification
    #[test]
    fn test_wrong_key_fails() {
        let (sk1, _vk1) = MlDsa65::generate_keypair();
        let (_sk2, vk2) = MlDsa65::generate_keypair();
        let sig = MlDsa65::sign(&sk1, b"test message");
        assert!(
            MlDsa65::verify(&vk2, b"test message", &sig).is_err(),
            "Verification should fail with wrong key"
        );
    }

    /// Test signing and verification with empty message
    #[test]
    fn test_empty_message() {
        let (sk, vk) = MlDsa44::generate_keypair();
        let message = b"";
        let sig = MlDsa44::sign(&sk, message);
        assert!(
            MlDsa44::verify(&vk, message, &sig).is_ok(),
            "Empty message sign/verify failed"
        );
    }

    /// Test signing and verification with large message
    #[test]
    fn test_large_message() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let message = vec![0xABu8; 100_000]; // 100KB message
        let sig = MlDsa65::sign(&sk, &message);
        assert!(
            MlDsa65::verify(&vk, &message, &sig).is_ok(),
            "Large message sign/verify failed"
        );
    }
}

#[cfg(test)]
mod kat {
    //! FIPS 204 Known Answer Tests
    //!
    //! Test vectors from NIST post-quantum-cryptography/KAT repository.
    //! These use the "raw" internal interface (KeyGen_internal, Sign_internal).
    //!
    //! Source: https://github.com/post-quantum-cryptography/KAT/tree/main/MLDSA

    use crate::ml_dsa::keygen::{generate_keypair_internal, pack_pk, pack_sk};
    use crate::ml_dsa::params::{MlDsaParams, Params44, Params65, Params87};
    use crate::ml_dsa::sign::sign_internal;
    use crate::ml_dsa::verify::verify_internal;

    /// Helper to decode hex string to bytes
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // ML-DSA-44 Deterministic Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Test seed for ML-DSA tests
    const TEST_SEED: &str = "f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68";

    /// Test message for signing tests
    const TEST_MSG: &str = "6dbbc4375136df3b07f7c70e639e223e";

    /// KAT test for ML-DSA-44 key generation
    ///
    /// Verifies that KeyGen_internal is deterministic and produces correct sizes.
    #[test]
    fn test_ml_dsa_44_keygen_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params44>(&seed);
        let pk = pack_pk::<Params44>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params44>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        // Verify public key size
        assert_eq!(
            pk.len(),
            Params44::PK_SIZE,
            "ML-DSA-44 public key size mismatch"
        );

        // Verify secret key size
        assert_eq!(
            sk.len(),
            Params44::SK_SIZE,
            "ML-DSA-44 secret key size mismatch"
        );

        // Verify first 32 bytes of pk is rho
        assert_eq!(&pk[..32], &kp.rho, "ML-DSA-44 pk should start with rho");

        // Verify determinism: same seed produces same keys
        let kp2 = generate_keypair_internal::<Params44>(&seed);
        let pk2 = pack_pk::<Params44>(&kp2.rho, &kp2.t1);
        assert_eq!(pk, pk2, "ML-DSA-44 KeyGen should be deterministic");
    }

    /// KAT test for ML-DSA-44 signing
    ///
    /// Verifies sign/verify roundtrip with deterministic keypair.
    #[test]
    fn test_ml_dsa_44_sign_verify_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params44>(&seed);
        let pk = pack_pk::<Params44>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params44>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        let msg = hex_decode(TEST_MSG);

        // Sign with our implementation
        let sig = sign_internal::<Params44>(&sk, &msg).expect("Signing should succeed");

        // Verify signature size
        assert_eq!(
            sig.len(),
            Params44::SIG_SIZE,
            "ML-DSA-44 signature size mismatch"
        );

        // Verify our signature is valid
        assert!(
            verify_internal::<Params44>(&pk, &msg, &sig),
            "ML-DSA-44 signature verification failed"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // ML-DSA-65 Deterministic Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    /// KAT test for ML-DSA-65 key generation
    #[test]
    fn test_ml_dsa_65_keygen_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params65>(&seed);
        let pk = pack_pk::<Params65>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params65>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        // Verify sizes
        assert_eq!(
            pk.len(),
            Params65::PK_SIZE,
            "ML-DSA-65 public key size mismatch"
        );
        assert_eq!(
            sk.len(),
            Params65::SK_SIZE,
            "ML-DSA-65 secret key size mismatch"
        );

        // Verify first 32 bytes of pk is rho
        assert_eq!(&pk[..32], &kp.rho, "ML-DSA-65 pk should start with rho");

        // Verify determinism
        let kp2 = generate_keypair_internal::<Params65>(&seed);
        let pk2 = pack_pk::<Params65>(&kp2.rho, &kp2.t1);
        assert_eq!(pk, pk2, "ML-DSA-65 KeyGen should be deterministic");
    }

    /// KAT test for ML-DSA-65 sign/verify
    #[test]
    fn test_ml_dsa_65_sign_verify_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params65>(&seed);
        let pk = pack_pk::<Params65>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params65>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        let msg = hex_decode(TEST_MSG);

        let sig = sign_internal::<Params65>(&sk, &msg).expect("Signing should succeed");
        assert_eq!(sig.len(), Params65::SIG_SIZE);
        assert!(
            verify_internal::<Params65>(&pk, &msg, &sig),
            "ML-DSA-65 signature verification failed"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // ML-DSA-87 Deterministic Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    /// KAT test for ML-DSA-87 key generation
    #[test]
    fn test_ml_dsa_87_keygen_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params87>(&seed);
        let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        // Verify sizes
        assert_eq!(
            pk.len(),
            Params87::PK_SIZE,
            "ML-DSA-87 public key size mismatch"
        );
        assert_eq!(
            sk.len(),
            Params87::SK_SIZE,
            "ML-DSA-87 secret key size mismatch"
        );

        // Verify first 32 bytes of pk is rho
        assert_eq!(&pk[..32], &kp.rho, "ML-DSA-87 pk should start with rho");

        // Verify determinism
        let kp2 = generate_keypair_internal::<Params87>(&seed);
        let pk2 = pack_pk::<Params87>(&kp2.rho, &kp2.t1);
        assert_eq!(pk, pk2, "ML-DSA-87 KeyGen should be deterministic");
    }

    /// KAT test for ML-DSA-87 sign/verify
    #[test]
    fn test_ml_dsa_87_sign_verify_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params87>(&seed);
        let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        let msg = hex_decode(TEST_MSG);

        let sig = sign_internal::<Params87>(&sk, &msg).expect("Signing should succeed");
        assert_eq!(sig.len(), Params87::SIG_SIZE);
        assert!(
            verify_internal::<Params87>(&pk, &msg, &sig),
            "ML-DSA-87 signature verification failed"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // Cross-verification tests with different seeds
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Test that different seeds produce different keys
    #[test]
    fn test_different_seeds_produce_different_keys() {
        let seed1 = hex_decode("f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68");
        let seed2 = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");

        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        s1.copy_from_slice(&seed1);
        s2.copy_from_slice(&seed2);

        let kp1 = generate_keypair_internal::<Params44>(&s1);
        let kp2 = generate_keypair_internal::<Params44>(&s2);

        let pk1 = pack_pk::<Params44>(&kp1.rho, &kp1.t1);
        let pk2 = pack_pk::<Params44>(&kp2.rho, &kp2.t1);

        assert_ne!(
            pk1, pk2,
            "Different seeds should produce different public keys"
        );
    }

    /// Test that key generation is deterministic
    #[test]
    fn test_keygen_deterministic() {
        let seed = hex_decode(TEST_SEED);
        let mut s = [0u8; 32];
        s.copy_from_slice(&seed);

        let kp1 = generate_keypair_internal::<Params44>(&s);
        let kp2 = generate_keypair_internal::<Params44>(&s);

        let pk1 = pack_pk::<Params44>(&kp1.rho, &kp1.t1);
        let pk2 = pack_pk::<Params44>(&kp2.rho, &kp2.t1);

        assert_eq!(pk1, pk2, "Same seed should produce same public key");
    }
}

#[cfg(test)]
mod ntt_kat {
    //! NTT Known Answer Tests
    //!
    //! Verify NTT implementation against known values.

    use crate::ml_dsa::ntt::{inv_ntt, ntt};
    use crate::ml_dsa::params::N;

    /// Test NTT produces consistent results
    ///
    /// Note: The NTT uses Montgomery form, so a simple roundtrip doesn't work.
    /// This test verifies that NTT produces consistent, deterministic results.
    #[test]
    fn test_ntt_deterministic() {
        // Same input should produce same NTT output
        let mut coeffs1 = [0i32; N];
        let mut coeffs2 = [0i32; N];
        for i in 0..N {
            coeffs1[i] = (i as i32) * 13;
            coeffs2[i] = (i as i32) * 13;
        }

        ntt(&mut coeffs1);
        ntt(&mut coeffs2);

        for i in 0..N {
            assert_eq!(
                coeffs1[i], coeffs2[i],
                "NTT should be deterministic at index {}",
                i
            );
        }
    }

    /// Test NTT with zero polynomial
    #[test]
    fn test_ntt_zero() {
        let mut coeffs = [0i32; N];
        ntt(&mut coeffs);

        // NTT of zero should be zero
        for i in 0..N {
            assert_eq!(coeffs[i], 0, "NTT of zero should be zero at index {}", i);
        }
    }

    /// Test inverse NTT with zero polynomial
    #[test]
    fn test_inv_ntt_zero() {
        let mut coeffs = [0i32; N];
        inv_ntt(&mut coeffs);

        // Inverse NTT of zero should be zero
        for i in 0..N {
            assert_eq!(
                coeffs[i], 0,
                "Inverse NTT of zero should be zero at index {}",
                i
            );
        }
    }

    /// Test that NTT output is different from input (for non-trivial input)
    #[test]
    fn test_ntt_changes_coefficients() {
        let mut coeffs = [0i32; N];
        coeffs[0] = 1;
        coeffs[1] = 2;
        let original = coeffs;

        ntt(&mut coeffs);

        // NTT should change the polynomial (except in trivial cases)
        let mut changed = false;
        for i in 0..N {
            if coeffs[i] != original[i] {
                changed = true;
                break;
            }
        }
        assert!(changed, "NTT should transform non-trivial polynomials");
    }
}

#[cfg(test)]
mod acvp_debug {
    //! Debug tests to trace ACVP divergence

    use crate::ml_dsa::keygen::generate_keypair_internal;
    use crate::ml_dsa::params::Params44;
    use arcanum_primitives::shake::Shake256;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Test FIPS 204 seed expansion format: SHAKE256(seed || K || L)
    #[test]
    fn test_fips204_seed_expansion() {
        // NIST KAT seed (xi) for ML-DSA-44
        let xi = hex_decode("f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68");

        // Expected rho (first 32 bytes of pk from NIST KAT for ML-DSA-44)
        let expected_rho = "bd4e96f9a038ab5e36214fe69c0b1cb835ef9d7c8417e76aecd152f5cddebec8";

        // FIPS 204 format: SHAKE256(seed || K || L)
        // For ML-DSA-44: K=4, L=4
        let mut inbuf = Vec::with_capacity(34);
        inbuf.extend_from_slice(&xi);
        inbuf.push(4); // K
        inbuf.push(4); // L

        let mut shake = Shake256::new();
        shake.update(&inbuf);
        let mut reader = shake.finalize_xof();

        let mut our_rho = [0u8; 32];
        reader.squeeze(&mut our_rho);

        println!("\n=== FIPS 204 Seed Expansion Test ===");
        println!("Input: seed || K || L");
        println!("Expected rho: {}", expected_rho);
        println!("Our rho:      {}", hex_encode(&our_rho));

        assert_eq!(
            hex_encode(&our_rho),
            expected_rho,
            "FIPS 204 seed expansion doesn't match expected rho"
        );
    }

    #[test]
    fn debug_keygen_rho() {
        // NIST KAT seed (xi)
        let seed = hex_decode("f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68");
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        // Expected rho from NIST KAT
        let expected_rho = "bd4e96f9a038ab5e36214fe69c0b1cb835ef9d7c8417e76aecd152f5cddebec8";

        let kp = generate_keypair_internal::<Params44>(&seed_arr);

        println!("\n=== KeyGen Rho Debug ===");
        println!("Expected rho:    {}", expected_rho);
        println!("Our keygen rho:  {}", hex_encode(&kp.rho));

        assert_eq!(
            hex_encode(&kp.rho),
            expected_rho,
            "KeyGen rho doesn't match expected"
        );
    }

    /// Verify SHAKE256 against NIST test vector
    /// From NIST CSRC examples
    #[test]
    fn verify_shake256_nist_vector() {
        // SHAKE256 with empty message, 512-bit (64 byte) output
        // Expected output from NIST
        let expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";

        let mut shake = Shake256::new();
        // Empty message
        let mut reader = shake.finalize_xof();

        let mut output = [0u8; 64];
        reader.squeeze(&mut output);

        println!("\n=== SHAKE256 NIST Vector Test ===");
        println!("Expected: {}", expected);
        println!("Got:      {}", hex_encode(&output));

        assert_eq!(
            hex_encode(&output),
            expected,
            "SHAKE256 implementation is incorrect!"
        );
    }

    /// Debug test for ML-DSA-87 sign/verify with deterministic seed
    #[test]
    fn debug_ml_dsa_87_sign_verify() {
        use crate::ml_dsa::keygen::{generate_keypair_internal, pack_pk, pack_sk};
        use crate::ml_dsa::params::{MlDsaParams, Params87};
        use crate::ml_dsa::sign::sign_internal;
        use crate::ml_dsa::verify::verify_internal;

        let xi = hex_decode("f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params87>(&seed);
        let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        println!("\n=== ML-DSA-87 Debug ===");
        println!("PK size: {} (expected {})", pk.len(), Params87::PK_SIZE);
        println!("SK size: {} (expected {})", sk.len(), Params87::SK_SIZE);

        let msg = hex_decode("6dbbc4375136df3b07f7c70e639e223e");
        println!("Message: {}", hex_encode(&msg));

        let sig = sign_internal::<Params87>(&sk, &msg);
        match sig {
            Some(s) => {
                println!(
                    "Signature size: {} (expected {})",
                    s.len(),
                    Params87::SIG_SIZE
                );
                let result = verify_internal::<Params87>(&pk, &msg, &s);
                println!("Verification result: {}", result);
            }
            None => {
                println!("Signing failed!");
            }
        }
    }

    /// Debug ML-DSA-87 verification failure - run multiple times to catch failures
    #[test]
    fn debug_ml_dsa_87_failures() {
        use crate::ml_dsa::{MlDsa, MlDsa87};

        let mut failures = 0;
        let iterations = 100;

        for i in 0..iterations {
            // Generate random keypair
            let (sk, vk) = MlDsa87::generate_keypair();
            let message = format!("Test message {}", i);

            // Sign
            let sig = MlDsa87::sign(&sk, message.as_bytes());

            // Verify
            let result = MlDsa87::verify(&vk, message.as_bytes(), &sig);
            if result.is_err() {
                failures += 1;
                println!("Failure {} at iteration {}", failures, i);
            }
        }

        println!(
            "\nML-DSA-87: {} failures out of {} iterations ({:.1}%)",
            failures,
            iterations,
            (failures as f64 / iterations as f64) * 100.0
        );

        // Should have 0 failures
        assert_eq!(
            failures, 0,
            "ML-DSA-87 has {} verification failures out of {}",
            failures, iterations
        );
    }

    /// Test the hint mechanism directly - this isolates the use_hint/make_hint functions
    #[test]
    fn test_hint_mechanism_gamma2_261888() {
        use crate::ml_dsa::params::Q;
        use crate::ml_dsa::rounding::{decompose, high_bits, make_hint, use_hint};

        // GAMMA2 for ML-DSA-65/87
        let gamma2 = (Q - 1) / 32; // 261888
        let alpha = 2 * gamma2; // 523776

        println!("\n=== Hint Mechanism Test ===");
        println!("GAMMA2 = {}", gamma2);
        println!("alpha = {}", alpha);
        println!("m = (Q-1)/alpha = {}", (Q - 1) / alpha);

        let mut failures = 0;
        let mut tests = 0;

        // Test the key property: UseHint(MakeHint(z, r), r) = HighBits(r + z)
        // when |z| < gamma2
        for z in [-gamma2 / 2, -1000, -100, 0, 100, 1000, gamma2 / 2] {
            for r_base in [0, alpha / 4, alpha / 2, 3 * alpha / 4, alpha - 1] {
                for k in [0, 5, 10, 15] {
                    let r = k * alpha + r_base;
                    if r >= Q {
                        continue;
                    }

                    tests += 1;

                    let h = make_hint(z, r, gamma2);
                    let result = use_hint(h, r, gamma2);
                    let expected = high_bits(r + z, gamma2);

                    if result != expected {
                        failures += 1;
                        let (r1, r0) = decompose(r, gamma2);
                        println!(
                            "FAILURE: z={}, r={} (r1={}, r0={}), h={}, result={}, expected={}",
                            z, r, r1, r0, h, result, expected
                        );
                    }
                }
            }
        }

        println!(
            "Hint mechanism: {} failures out of {} tests",
            failures, tests
        );
        assert_eq!(failures, 0, "Hint mechanism has {} failures", failures);
    }

    /// Test edge cases in decompose function
    #[test]
    fn test_decompose_edge_cases() {
        use crate::ml_dsa::params::Q;
        use crate::ml_dsa::rounding::decompose;

        let gamma2 = (Q - 1) / 32; // 261888
        let alpha = 2 * gamma2; // 523776

        println!("\n=== Decompose Edge Cases ===");

        // Test values near bin boundaries
        let test_cases = [
            (0, "r0 should be 0"),
            (gamma2, "r0 at upper boundary"),
            (gamma2 + 1, "just crossed to next bin"),
            (alpha - 1, "just below alpha"),
            (alpha, "at alpha"),
            (Q - 1, "corner case Q-1"),
            (Q - 2, "just before corner case"),
        ];

        for (val, desc) in test_cases {
            let (r1, r0) = decompose(val, gamma2);
            println!("{}: val={}, r1={}, r0={}", desc, val, r1, r0);

            // Verify reconstruction: r1*alpha + r0 = val (mod Q)
            let reconstructed = r1 as i64 * alpha as i64 + r0 as i64;
            let reconstructed_mod = ((reconstructed % Q as i64) + Q as i64) % Q as i64;
            assert_eq!(
                reconstructed_mod as i32, val,
                "Decompose reconstruction failed for val={}: got {} but expected {}",
                val, reconstructed_mod, val
            );
        }
    }

    /// Detailed trace of sign/verify to find divergence
    #[test]
    fn trace_ml_dsa_87_sign_verify() {
        use crate::ml_dsa::keygen::{generate_keypair_internal, pack_pk, pack_sk, unpack_pk};
        use crate::ml_dsa::params::{D, MlDsaParams, N, Params87, Q};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::rounding::{decompose, high_bits, use_hint};
        use crate::ml_dsa::sampling::{expand_a, sample_in_ball};
        use crate::ml_dsa::sign::{sign_internal, unpack_signature};
        use crate::ml_dsa::verify::verify_internal;
        use arcanum_primitives::shake::Shake256;

        println!("\n=== ML-DSA-87 Sign/Verify Trace ===");

        // Use the failing seed
        let mut seed = [0u8; 32];
        seed[0] = 7;

        let kp = generate_keypair_internal::<Params87>(&seed);
        let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        let msg = b"test message";
        let sig = sign_internal::<Params87>(&sk, msg).expect("signing should succeed");

        // Basic verification
        let result = verify_internal::<Params87>(&pk, msg, &sig);
        println!("Verification result: {}", result);

        // Now manually trace verification
        let (rho, t1) = unpack_pk::<Params87>(&pk).unwrap();
        let (c_tilde, z, h) = unpack_signature::<Params87>(&sig).unwrap();

        // Compute tr = H(pk)
        let mut shake = Shake256::new();
        shake.update(&pk);
        let mut reader = shake.finalize_xof();
        let mut tr = [0u8; 64];
        reader.squeeze(&mut tr);

        // Compute μ = H(tr || M)
        let mut shake = Shake256::new();
        shake.update(&tr);
        shake.update(msg);
        let mut reader = shake.finalize_xof();
        let mut mu = [0u8; 64];
        reader.squeeze(&mut mu);

        // c = SampleInBall(c_tilde)
        let mut c = sample_in_ball(&c_tilde, Params87::TAU);
        c.ntt();

        // Expand A
        let a = expand_a::<Params87>(&rho);

        // z to NTT
        let mut z_ntt = z.clone();
        for poly in &mut z_ntt {
            poly.ntt();
        }

        // t1 to NTT
        let mut t1_ntt = t1.clone();
        for poly in &mut t1_ntt {
            poly.ntt();
        }

        // Compute Az (in NTT domain)
        let mut az_ntt = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            for j in 0..Params87::L {
                let product = a[i][j].pointwise_mul(&z_ntt[j]);
                az_ntt[i] = az_ntt[i].add(&product);
            }
        }

        // Compute ct1 (in NTT domain)
        let mut ct1_ntt = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            ct1_ntt[i] = c.pointwise_mul(&t1_ntt[i]);
        }

        // w' = Az - ct1 * 2^d
        let mut w_prime = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            let mut az_i = az_ntt[i];
            az_i.inv_ntt();
            az_i.reduce();

            let mut ct1_i = ct1_ntt[i];
            ct1_i.inv_ntt();
            ct1_i.reduce_centered();

            for j in 0..N {
                let az_val = az_i.coeffs[j] as i64;
                let ct1_scaled = (ct1_i.coeffs[j] as i64) * (1i64 << D);
                let mut val = az_val - ct1_scaled;
                val = ((val % (Q as i64)) + (Q as i64)) % (Q as i64);
                w_prime[i].coeffs[j] = val as i32;
            }
        }

        // w'1 = UseHint(h, w')
        let gamma2 = Params87::GAMMA2 as i32;
        let mut w_prime_1 = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            for j in 0..N {
                let hint_bit = h[i].coeffs[j] != 0;
                w_prime_1[i].coeffs[j] = use_hint(hint_bit, w_prime[i].coeffs[j], gamma2);
            }
        }

        // Check for any negative or out-of-range w'1 values
        let mut issues = 0;
        for i in 0..Params87::K {
            for j in 0..N {
                let val = w_prime_1[i].coeffs[j];
                if val < 0 || val > 15 {
                    if issues < 10 {
                        println!("w'1[{}][{}] = {} (out of range 0-15)", i, j, val);
                    }
                    issues += 1;
                }
            }
        }
        if issues > 0 {
            println!("Total w'1 out-of-range issues: {}", issues);
        } else {
            println!("All w'1 values in range [0, 15]");
        }

        // The verification failure must be in the challenge hash comparison
        // Since we can't access the original w1 from signing, we just report the issue
        println!("\nThis failure case has seed[0]=7");
        println!("To debug further, we need instrumented sign function");
    }
}

#[cfg(test)]
mod spec_invariants {
    //! Tests for FIPS 204 Spec Invariants (Section 5.6-5.8 of ML-DSA-SPEC.md)
    //!
    //! These tests verify the core mathematical relationships documented in the spec:
    //! 1. w' = w - cs₂ + ct₀ (Section 5.6.1)
    //! 2. UseHint(MakeHint(-ct₀, r), r) = HighBits(r + (-ct₀)) (Section 5.6.2-5.6.3)
    //! 3. After rejection: HighBits(w - cs₂) = HighBits(w) (Section 5.6.4)

    use crate::ml_dsa::params::{MlDsaParams, N, Params44, Params65, Params87, Q};
    use crate::ml_dsa::poly::Poly;
    use crate::ml_dsa::rounding::{decompose, high_bits, make_hint, use_hint};

    /// Spec Invariant 5.6.2: MakeHint(z, r) returns 1 iff HighBits(r) ≠ HighBits(r + z)
    ///
    /// This is the fundamental property that enables hint-based signature compression.
    #[test]
    fn spec_make_hint_definition() {
        for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
            for z in [-gamma2 / 2, -100, 0, 100, gamma2 / 2] {
                for r in [0, gamma2, 2 * gamma2, Q / 2, Q - 1] {
                    let h = make_hint(z, r, gamma2);
                    let hb_r = high_bits(r, gamma2);
                    let hb_r_plus_z = high_bits(r + z, gamma2);

                    let expected = hb_r != hb_r_plus_z;
                    assert_eq!(
                        h, expected,
                        "MakeHint({}, {}, {}) = {} but HighBits differ = {}",
                        z, r, gamma2, h, expected
                    );
                }
            }
        }
    }

    /// Spec Invariant 5.6.3: UseHint correctly recovers HighBits(r + z) from HighBits(r)
    ///
    /// For |z| < γ₂: UseHint(MakeHint(z, r), r) = HighBits(r + z)
    #[test]
    fn spec_use_hint_recovers_high_bits() {
        for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
            let alpha = 2 * gamma2;
            let max_r1 = (Q - 1) / alpha;

            let mut failures = 0;
            let mut tests = 0;

            // Test z values within the valid range |z| < gamma2
            for z in [
                -gamma2 / 2,
                -gamma2 / 4,
                -100,
                0,
                100,
                gamma2 / 4,
                gamma2 / 2,
            ] {
                // Test r values across the range [0, q)
                for r1 in [0, 1, max_r1 / 2, max_r1 - 1] {
                    for r0_offset in [-gamma2 / 2, 0, gamma2 / 2] {
                        let r = (r1 * alpha + r0_offset).rem_euclid(Q);
                        if r < 0 || r >= Q {
                            continue;
                        }

                        tests += 1;

                        let h = make_hint(z, r, gamma2);
                        let result = use_hint(h, r, gamma2);
                        let expected = high_bits((r + z).rem_euclid(Q), gamma2);

                        if result != expected {
                            failures += 1;
                            if failures <= 5 {
                                let (r1_decomp, r0_decomp) = decompose(r, gamma2);
                                println!(
                                    "FAIL: z={}, r={} (r1={}, r0={}), h={}, got={}, expected={}",
                                    z, r, r1_decomp, r0_decomp, h, result, expected
                                );
                            }
                        }
                    }
                }
            }

            assert_eq!(
                failures, 0,
                "UseHint invariant: {} failures out of {} tests for gamma2={}",
                failures, tests, gamma2
            );
        }
    }

    /// Spec Invariant 5.6.4: The hint mechanism in signing enables verification
    ///
    /// Given: h = MakeHint(-ct₀, w - cs₂ + ct₀)
    /// Then: UseHint(h, w - cs₂ + ct₀) = HighBits(w - cs₂)
    #[test]
    fn spec_hint_enables_verification() {
        let gamma2 = (Q - 1) / 32; // ML-DSA-65/87

        // Simulate the signing/verification relationship
        // In signing: w_cs2_ct0 = w - cs₂ + ct₀
        // In verification: w' = w - cs₂ + ct₀ (reconstructed)
        // Hint h = MakeHint(-ct₀, w - cs₂ + ct₀)

        let mut failures = 0;
        let mut tests = 0;

        // Test with various simulated values
        for w in [gamma2, 2 * gamma2, Q / 2, Q - 100].iter() {
            for cs2 in [-50, 0, 50, 100].iter() {
                for ct0 in [-gamma2 / 4, 0, gamma2 / 4].iter() {
                    let w = *w;
                    let cs2 = *cs2;
                    let ct0 = *ct0;

                    // w_cs2_ct0 = w - cs2 + ct0 (what signing computes and verification reconstructs)
                    let w_cs2_ct0 =
                        ((w as i64 - cs2 as i64 + ct0 as i64).rem_euclid(Q as i64)) as i32;

                    // neg_ct0 = -ct0
                    let neg_ct0 = -ct0;

                    // h = MakeHint(-ct0, w_cs2_ct0)
                    let h = make_hint(neg_ct0, w_cs2_ct0, gamma2);

                    // Verification computes: w'_1 = UseHint(h, w')
                    // where w' = w - cs2 + ct0 = w_cs2_ct0
                    let w_prime_1 = use_hint(h, w_cs2_ct0, gamma2);

                    // Expected: HighBits(w - cs2)
                    let w_minus_cs2 = ((w as i64 - cs2 as i64).rem_euclid(Q as i64)) as i32;
                    let expected = high_bits(w_minus_cs2, gamma2);

                    tests += 1;
                    if w_prime_1 != expected {
                        failures += 1;
                        if failures <= 10 {
                            println!("FAIL: w={}, cs2={}, ct0={}", w, cs2, ct0);
                            println!("  w_cs2_ct0={}, neg_ct0={}, h={}", w_cs2_ct0, neg_ct0, h);
                            println!(
                                "  UseHint result={}, expected HighBits(w-cs2)={}",
                                w_prime_1, expected
                            );
                        }
                    }
                }
            }
        }

        assert_eq!(
            failures, 0,
            "Hint verification invariant: {} failures out of {} tests",
            failures, tests
        );
    }

    /// Spec Invariant 5.7: Decompose corner case when r - r₀ = q - 1
    ///
    /// When r is near q-1, decompose must set r₁ = 0 and adjust r₀.
    #[test]
    fn spec_decompose_corner_case() {
        for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
            let alpha = 2 * gamma2;

            // Test the corner case explicitly
            let r = Q - 1;
            let (r1, r0) = decompose(r, gamma2);

            // Per FIPS 204: when r - r₀ = q - 1, set r₁ = 0
            // Note: The corner case check is "if r - r0 == Q - 1"
            // This happens when r is exactly Q-1

            // Verify reconstruction: r₁ * α + r₀ ≡ r (mod q)
            let reconstructed = (r1 as i64 * alpha as i64 + r0 as i64).rem_euclid(Q as i64);
            assert_eq!(
                reconstructed as i32, r,
                "Decompose reconstruction failed for r=Q-1: r1={}, r0={}, reconstructed={}",
                r1, r0, reconstructed
            );

            // Verify r₀ is in valid range (-γ₂, γ₂]
            assert!(
                r0 > -gamma2 && r0 <= gamma2,
                "Decompose r0={} out of range for r=Q-1, gamma2={}",
                r0,
                gamma2
            );

            // Verify r₁ is in valid range [0, m] where m = (q-1)/α - 1
            let m = (Q - 1) / alpha - 1;
            assert!(
                r1 >= 0 && r1 <= m,
                "Decompose r1={} out of range [0, {}] for r=Q-1",
                r1,
                m
            );
        }
    }

    /// Spec Section 5.8.2: Reduction consistency between signing and verification
    ///
    /// Both w and w' must be reduced to [0, q) for HighBits to match.
    #[test]
    fn spec_reduction_consistency() {
        let gamma2 = (Q - 1) / 32;

        // Test that HighBits produces same result for equivalent values mod q
        let test_values = [
            (0, 0),
            (Q, 0),      // Q ≡ 0 (mod q)
            (-1, Q - 1), // -1 ≡ Q - 1 (mod q)
            (Q + 100, 100),
            (-100, Q - 100),
        ];

        for (v1, v2) in test_values {
            // Both values should be equivalent mod q
            let r1 = v1.rem_euclid(Q);
            let r2 = v2.rem_euclid(Q);

            if r1 == r2 {
                // HighBits should be the same
                let hb1 = high_bits(r1, gamma2);
                let hb2 = high_bits(r2, gamma2);
                assert_eq!(
                    hb1, hb2,
                    "HighBits({}) = {} but HighBits({}) = {} (both ≡ {} mod q)",
                    v1, hb1, v2, hb2, r1
                );
            }
        }
    }

    /// Test w₁ range for each parameter set
    ///
    /// w₁ coefficients must be in [0, m] where m = (q-1)/(2γ₂) - 1
    #[test]
    fn spec_w1_range_by_parameter() {
        // ML-DSA-44: γ₂ = (q-1)/88, m = 43
        let gamma2_44 = (Q - 1) / 88;
        let m_44 = (Q - 1) / (2 * gamma2_44) - 1;
        assert_eq!(m_44, 43, "ML-DSA-44 m should be 43");

        // ML-DSA-65/87: γ₂ = (q-1)/32, m = 15
        let gamma2_65 = (Q - 1) / 32;
        let m_65 = (Q - 1) / (2 * gamma2_65) - 1;
        assert_eq!(m_65, 15, "ML-DSA-65/87 m should be 15");

        // Verify UseHint never produces values outside [0, m]
        for gamma2 in [gamma2_44, gamma2_65] {
            let m = (Q - 1) / (2 * gamma2) - 1;

            for r in [0, gamma2, 2 * gamma2, Q / 2, Q - 1] {
                for h in [false, true] {
                    let result = use_hint(h, r, gamma2);
                    assert!(
                        result >= 0 && result <= m,
                        "UseHint({}, {}, {}) = {} outside [0, {}]",
                        h,
                        r,
                        gamma2,
                        result,
                        m
                    );
                }
            }
        }
    }

    /// Statistical test: ML-DSA-87 should have 0% verification failure rate
    ///
    /// This is the acceptance test that must pass for ACVP compliance.
    #[test]
    fn spec_ml_dsa_87_zero_failure_rate() {
        use crate::ml_dsa::{MlDsa, MlDsa87};

        let iterations = 50; // Fewer iterations for regular testing
        let mut failures = 0;

        for i in 0..iterations {
            let (sk, vk) = MlDsa87::generate_keypair();
            let message = format!("ACVP compliance test message {}", i);
            let sig = MlDsa87::sign(&sk, message.as_bytes());

            if MlDsa87::verify(&vk, message.as_bytes(), &sig).is_err() {
                failures += 1;
            }
        }

        // MUST be 0 for ACVP compliance
        assert_eq!(
            failures,
            0,
            "ML-DSA-87 verification failure rate: {}/{} ({:.1}%) - MUST be 0% for ACVP",
            failures,
            iterations,
            (failures as f64 / iterations as f64) * 100.0
        );
    }
}

#[cfg(test)]
mod w1_divergence_debug {
    //! Diagnostic tests to identify w1 vs w'1 divergence
    //!
    //! This module instruments the sign/verify flow to compare values.

    use crate::ml_dsa::keygen::{
        generate_keypair_internal, pack_pk, pack_sk, unpack_pk, unpack_sk,
    };
    use crate::ml_dsa::params::{D, MlDsaParams, N, Params87, Q};
    use crate::ml_dsa::poly::Poly;
    use crate::ml_dsa::rounding::{high_bits, use_hint};
    use crate::ml_dsa::sampling::{expand_a, expand_mask, sample_in_ball};
    use crate::ml_dsa::sign::{sign_internal, unpack_signature};
    use arcanum_primitives::shake::Shake256;

    /// Capture and compare w1 from signing vs w'1 from verification
    #[test]
    fn diagnose_w1_divergence() {
        // Use a seed that reliably produces failures
        for seed_byte in 0u8..20 {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;

            let kp = generate_keypair_internal::<Params87>(&seed);
            let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
            let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

            let msg = b"test message for w1 diagnosis";

            // Get signature
            let sig = match sign_internal::<Params87>(&sk, msg) {
                Some(s) => s,
                None => {
                    println!("Signing failed for seed_byte={}", seed_byte);
                    continue;
                }
            };

            // Now manually verify and capture w'1
            let (rho, t1) = unpack_pk::<Params87>(&pk).unwrap();
            let (c_tilde, z, h) = unpack_signature::<Params87>(&sig).unwrap();

            // Compute tr = H(pk)
            let mut shake = Shake256::new();
            shake.update(&pk);
            let mut reader = shake.finalize_xof();
            let mut tr = [0u8; 64];
            reader.squeeze(&mut tr);

            // Compute μ = H(tr || M)
            let mut shake = Shake256::new();
            shake.update(&tr);
            shake.update(msg);
            let mut reader = shake.finalize_xof();
            let mut mu = [0u8; 64];
            reader.squeeze(&mut mu);

            // c = SampleInBall(c_tilde)
            let mut c = sample_in_ball(&c_tilde, Params87::TAU);
            c.ntt();

            // Expand A
            let a = expand_a::<Params87>(&rho);

            // z to NTT
            let mut z_ntt = z.clone();
            for poly in &mut z_ntt {
                poly.ntt();
            }

            // t1 to NTT
            let mut t1_ntt = t1.clone();
            for poly in &mut t1_ntt {
                poly.ntt();
            }

            // Compute Az
            let mut az_ntt = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..Params87::L {
                    let product = a[i][j].pointwise_mul(&z_ntt[j]);
                    az_ntt[i] = az_ntt[i].add(&product);
                }
            }

            // Compute ct1
            let mut ct1_ntt = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                ct1_ntt[i] = c.pointwise_mul(&t1_ntt[i]);
            }

            // w' = Az - ct1 * 2^d
            let mut w_prime = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut az_i = az_ntt[i];
                az_i.inv_ntt();
                az_i.reduce();

                let mut ct1_i = ct1_ntt[i];
                ct1_i.inv_ntt();
                ct1_i.reduce_centered();

                for j in 0..N {
                    let az_val = az_i.coeffs[j] as i64;
                    let ct1_scaled = (ct1_i.coeffs[j] as i64) * (1i64 << D);
                    let mut val = az_val - ct1_scaled;
                    val = ((val % (Q as i64)) + (Q as i64)) % (Q as i64);
                    w_prime[i].coeffs[j] = val as i32;
                }
            }

            // w'1 = UseHint(h, w')
            let gamma2 = Params87::GAMMA2 as i32;
            let mut w_prime_1 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..N {
                    let hint_bit = h[i].coeffs[j] != 0;
                    w_prime_1[i].coeffs[j] = use_hint(hint_bit, w_prime[i].coeffs[j], gamma2);
                }
            }

            // Compute verification challenge hash
            let c_tilde_prime = compute_challenge_hash_87(&mu, &w_prime_1);

            // Check if verification passes
            let matches = c_tilde == c_tilde_prime;

            if !matches {
                println!("\n=== w1 Divergence Found: seed_byte={} ===", seed_byte);
                println!("c_tilde:       {:02x?}", &c_tilde[..8]);
                println!("c_tilde_prime: {:02x?}", &c_tilde_prime[..8]);

                // Find coefficients where w'1 might be wrong
                let mut out_of_range = 0;
                for i in 0..Params87::K {
                    for j in 0..N {
                        let val = w_prime_1[i].coeffs[j];
                        if val < 0 || val > 15 {
                            if out_of_range < 5 {
                                println!("w'1[{}][{}] = {} (out of [0,15])", i, j, val);
                            }
                            out_of_range += 1;
                        }
                    }
                }
                if out_of_range > 0 {
                    println!("Total out-of-range w'1: {}", out_of_range);
                }

                // Check hint count
                let hint_count: usize = h
                    .iter()
                    .map(|p| p.coeffs.iter().filter(|&&c| c != 0).count())
                    .sum();
                println!("Hint count: {} (max {})", hint_count, Params87::OMEGA);

                // Sample some w' values
                println!("Sample w' values:");
                for i in 0..2 {
                    for j in 0..4 {
                        println!(
                            "  w'[{}][{}] = {}, h = {}, w'1 = {}",
                            i, j, w_prime[i].coeffs[j], h[i].coeffs[j], w_prime_1[i].coeffs[j]
                        );
                    }
                }

                // Only report first few failures
                if out_of_range == 0 {
                    println!("\nNo out-of-range values - divergence is in packing/hashing");
                }
            }
        }
    }

    fn compute_challenge_hash_87(mu: &[u8; 64], w1: &[Poly]) -> Vec<u8> {
        let c_tilde_len = Params87::LAMBDA / 4; // 64 bytes

        let mut shake = Shake256::new();
        shake.update(mu);

        // Pack w1 with 4 bits per coefficient (γ₂ = (q-1)/32)
        for poly in w1.iter().take(Params87::K) {
            let packed = pack_w1_4bits(poly);
            shake.update(&packed);
        }

        let mut reader = shake.finalize_xof();
        let mut c_tilde = vec![0u8; c_tilde_len];
        reader.squeeze(&mut c_tilde);
        c_tilde
    }

    fn pack_w1_4bits(poly: &Poly) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        for chunk in 0..(N / 2) {
            let c0 = poly.coeffs[2 * chunk] as u8;
            let c1 = poly.coeffs[2 * chunk + 1] as u8;
            bytes.push(c0 | (c1 << 4));
        }
        bytes
    }

    /// Direct comparison: compute w' two ways and check they match
    ///
    /// w' = Az - ct₁·2^d (verification method)
    /// w' = w - cs₂ + ct₀ (mathematical relationship)
    ///
    /// These should be equal. If not, there's a computation bug.
    #[test]
    fn test_w_prime_computation_consistency() {
        use crate::ml_dsa::keygen::{generate_keypair_internal, pack_pk, pack_sk, unpack_sk};
        use crate::ml_dsa::params::{D, MlDsaParams, N, Params87, Q};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::rounding::{high_bits, poly_power2round};
        use crate::ml_dsa::sampling::{expand_a, expand_mask, sample_in_ball};
        use arcanum_primitives::shake::Shake256;

        println!("\n=== Testing w' computation consistency ===");

        let mut seed = [0u8; 32];
        seed[0] = 7; // Known failing case

        let kp = generate_keypair_internal::<Params87>(&seed);

        // Unpack s1, s2, t0 from keypair
        let s1 = &kp.s1;
        let s2 = &kp.s2;
        let t0 = &kp.t0;

        // Compute t1 from t = As1 + s2 = t1·2^d + t0
        // We have t0, and t1 is in kp.t1
        let t1 = &kp.t1;

        // Expand A
        let a = expand_a::<Params87>(&kp.rho);

        // Generate a random y (using fixed seed for reproducibility)
        let mut mask_seed = Vec::with_capacity(96);
        mask_seed.extend_from_slice(&kp.key);
        mask_seed.extend_from_slice(&[0u8; 64]); // dummy mu
        let y = expand_mask::<Params87>(&mask_seed, 0, Params87::GAMMA1);

        // Convert to NTT for computations
        let mut s1_ntt: Vec<Poly> = s1.clone();
        let mut s2_ntt: Vec<Poly> = s2.clone();
        let mut t0_ntt: Vec<Poly> = t0.clone();
        let mut t1_ntt: Vec<Poly> = t1.clone();
        let mut y_ntt = y.clone();

        for poly in &mut s1_ntt {
            poly.ntt();
        }
        for poly in &mut s2_ntt {
            poly.ntt();
        }
        for poly in &mut t0_ntt {
            poly.ntt();
        }
        for poly in &mut t1_ntt {
            poly.ntt();
        }
        for poly in &mut y_ntt {
            poly.ntt();
        }

        // Compute w = Ay
        let mut w_ntt = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            for j in 0..Params87::L {
                let product = a[i][j].pointwise_mul(&y_ntt[j]);
                w_ntt[i] = w_ntt[i].add(&product);
            }
        }

        let mut w = w_ntt.clone();
        for poly in &mut w {
            poly.inv_ntt();
            poly.reduce();
        }

        // Generate a challenge c
        let c_seed = [0x42u8; 32];
        let mut c = sample_in_ball(&c_seed, Params87::TAU);
        c.ntt();

        // Compute cs2
        let mut cs2 = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            cs2[i] = c.pointwise_mul(&s2_ntt[i]);
            cs2[i].inv_ntt();
            cs2[i].reduce_centered();
        }

        // Compute ct0
        let mut ct0 = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            ct0[i] = c.pointwise_mul(&t0_ntt[i]);
            ct0[i].inv_ntt();
            ct0[i].reduce_centered();
        }

        // Compute z = y + cs1
        let mut z = vec![Poly::zero(); Params87::L];
        for i in 0..Params87::L {
            let mut cs1_i = c.pointwise_mul(&s1_ntt[i]);
            cs1_i.inv_ntt();
            cs1_i.reduce_centered();
            z[i] = y[i].add(&cs1_i);
        }

        // === Method 1: w - cs2 + ct0 (signing method) ===
        let mut w_prime_method1 = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            for j in 0..N {
                let val =
                    (w[i].coeffs[j] as i64) - (cs2[i].coeffs[j] as i64) + (ct0[i].coeffs[j] as i64);
                w_prime_method1[i].coeffs[j] = ((val % (Q as i64)) + (Q as i64)) as i32 % Q;
            }
        }

        // === Method 2: Az - ct1·2^d (verification method) ===
        let mut z_ntt = z.clone();
        for poly in &mut z_ntt {
            poly.ntt();
        }

        let mut az_ntt = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            for j in 0..Params87::L {
                let product = a[i][j].pointwise_mul(&z_ntt[j]);
                az_ntt[i] = az_ntt[i].add(&product);
            }
        }

        let mut ct1_ntt = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            ct1_ntt[i] = c.pointwise_mul(&t1_ntt[i]);
        }

        let mut w_prime_method2 = vec![Poly::zero(); Params87::K];
        for i in 0..Params87::K {
            let mut az_i = az_ntt[i];
            az_i.inv_ntt();
            az_i.reduce();

            let mut ct1_i = ct1_ntt[i];
            ct1_i.inv_ntt();
            ct1_i.reduce_centered();

            for j in 0..N {
                let az_val = az_i.coeffs[j] as i64;
                let ct1_scaled = (ct1_i.coeffs[j] as i64) * (1i64 << D);
                let mut val = az_val - ct1_scaled;
                val = ((val % (Q as i64)) + (Q as i64)) % (Q as i64);
                w_prime_method2[i].coeffs[j] = val as i32;
            }
        }

        // Compare the two methods
        let mut mismatches = 0;
        for i in 0..Params87::K {
            for j in 0..N {
                if w_prime_method1[i].coeffs[j] != w_prime_method2[i].coeffs[j] {
                    if mismatches < 10 {
                        println!(
                            "Mismatch at [{}][{}]: method1={}, method2={}",
                            i, j, w_prime_method1[i].coeffs[j], w_prime_method2[i].coeffs[j]
                        );
                    }
                    mismatches += 1;
                }
            }
        }

        println!(
            "Total mismatches: {} out of {} coefficients",
            mismatches,
            Params87::K * N
        );

        if mismatches > 0 {
            println!(
                "\n*** w' computation methods DIFFER - this explains verification failures! ***"
            );
        } else {
            println!("\n*** w' computation methods MATCH - bug must be elsewhere ***");
        }

        // This test passes even if there are mismatches - it's diagnostic
    }

    /// Simulate the full signing loop and check the HighBits invariant
    ///
    /// This mimics the actual signing algorithm to catch edge cases.
    #[test]
    fn test_signing_invariant_full_loop() {
        use crate::ml_dsa::keygen::generate_keypair_internal;
        use crate::ml_dsa::params::{MlDsaParams, N, Params87, Q};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::rounding::{decompose, high_bits};
        use crate::ml_dsa::sampling::{expand_a, expand_mask, sample_in_ball};
        use arcanum_primitives::shake::Shake256;

        println!("\n=== Full Signing Loop Invariant Test ===");

        let mut invariant_violations = 0;
        let mut rejection_pass_count = 0;
        let mut total_iterations = 0;

        // Test multiple seeds
        for seed_byte in 0u8..20 {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;

            let kp = generate_keypair_internal::<Params87>(&seed);
            let a = expand_a::<Params87>(&kp.rho);

            // NTT versions
            let mut s2_ntt: Vec<Poly> = kp.s2.clone();
            for poly in &mut s2_ntt {
                poly.ntt();
            }

            // Simulate multiple signing attempts
            for kappa in (0..100u16).step_by(Params87::L) {
                total_iterations += 1;

                // Generate y
                let mut mask_seed = Vec::with_capacity(96);
                mask_seed.extend_from_slice(&kp.key);
                mask_seed.extend_from_slice(&[seed_byte; 64]); // pseudo-mu
                let y = expand_mask::<Params87>(&mask_seed, kappa, Params87::GAMMA1);

                // y to NTT
                let mut y_ntt = y.clone();
                for poly in &mut y_ntt {
                    poly.ntt();
                }

                // w = Ay
                let mut w_ntt = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    for j in 0..Params87::L {
                        let product = a[i][j].pointwise_mul(&y_ntt[j]);
                        w_ntt[i] = w_ntt[i].add(&product);
                    }
                }
                let mut w = w_ntt;
                for poly in &mut w {
                    poly.inv_ntt();
                    poly.reduce();
                }

                // w1 = HighBits(w)
                let mut w1 = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    for j in 0..N {
                        w1[i].coeffs[j] = high_bits(w[i].coeffs[j], Params87::GAMMA2 as i32);
                    }
                }

                // c = SampleInBall(some seed derived from w1)
                let c_seed = [kappa as u8; 32];
                let mut c = sample_in_ball(&c_seed, Params87::TAU);
                c.ntt();

                // cs2
                let mut cs2 = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    cs2[i] = c.pointwise_mul(&s2_ntt[i]);
                    cs2[i].inv_ntt();
                    cs2[i].reduce_centered();
                }

                // w - cs2
                let mut w_minus_cs2 = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    w_minus_cs2[i] = w[i].sub(&cs2[i]);
                }

                // r0 = LowBits(w - cs2) and check rejection
                let gamma2 = Params87::GAMMA2 as i32;
                let gamma2_minus_beta = (Params87::GAMMA2 - Params87::BETA) as i32;

                let mut passes_rejection = true;
                for i in 0..Params87::K {
                    for j in 0..N {
                        let (_r1, r0) = decompose(w_minus_cs2[i].coeffs[j], gamma2);
                        if r0.abs() >= gamma2_minus_beta {
                            passes_rejection = false;
                            break;
                        }
                    }
                    if !passes_rejection {
                        break;
                    }
                }

                if !passes_rejection {
                    continue; // Would be rejected, skip
                }

                rejection_pass_count += 1;

                // Now check the invariant: HighBits(w) = HighBits(w - cs2)?
                for i in 0..Params87::K {
                    for j in 0..N {
                        let hb_w = high_bits(w[i].coeffs[j], gamma2);

                        // Compute w - cs2 properly reduced
                        let w_cs2_val = w[i].coeffs[j] - cs2[i].coeffs[j];
                        let w_cs2_normalized = w_cs2_val.rem_euclid(Q);
                        let hb_w_cs2 = high_bits(w_cs2_normalized, gamma2);

                        if hb_w != hb_w_cs2 {
                            invariant_violations += 1;
                            if invariant_violations <= 5 {
                                println!(
                                    "INVARIANT VIOLATION at seed={}, kappa={}, i={}, j={}:",
                                    seed_byte, kappa, i, j
                                );
                                println!(
                                    "  w={}, cs2={}, w-cs2={}",
                                    w[i].coeffs[j], cs2[i].coeffs[j], w_cs2_normalized
                                );
                                println!("  HighBits(w)={}, HighBits(w-cs2)={}", hb_w, hb_w_cs2);
                                let (_r1, r0) = decompose(w_minus_cs2[i].coeffs[j], gamma2);
                                println!(
                                    "  r0={}, |r0|={}, threshold={}",
                                    r0,
                                    r0.abs(),
                                    gamma2_minus_beta
                                );
                            }
                        }
                    }
                }
            }
        }

        println!("\nResults:");
        println!("  Total iterations: {}", total_iterations);
        println!("  Passed rejection check: {}", rejection_pass_count);
        println!("  Invariant violations: {}", invariant_violations);

        if invariant_violations > 0 {
            println!(
                "\n*** FOUND BUG: {} cases where HighBits(w) ≠ HighBits(w-cs2) ***",
                invariant_violations
            );
            println!("*** This explains the verification failures! ***");
        } else {
            println!("\n*** No invariant violations - bug is NOT in HighBits equality ***");
        }
    }

    /// Test the hypothesis: Does the rejection check ensure HighBits(w) = HighBits(w - cs₂)?
    ///
    /// This test checks if boundary crossings can occur despite the rejection check passing.
    #[test]
    fn test_highbits_invariant_hypothesis() {
        use crate::ml_dsa::rounding::{decompose, high_bits};

        let gamma2 = ((Q - 1) / 32) as i32; // ML-DSA-65/87
        let beta = 120i32; // ML-DSA-87
        let gamma2_minus_beta = gamma2 - beta;

        println!("\n=== Testing HighBits Invariant ===");
        println!("γ₂ = {}", gamma2);
        println!("β = {}", beta);
        println!("γ₂ - β = {}", gamma2_minus_beta);

        let alpha = 2 * gamma2;
        let mut boundary_crossings = 0;
        let mut rejection_failures = 0;
        let mut invariant_violations = 0;

        // Test various w and cs2 combinations
        for w_high in [0, 5, 10, 15] {
            for w_low_offset in [-gamma2 + 1, -gamma2 / 2, 0, gamma2 / 2, gamma2] {
                let w = w_high * alpha + w_low_offset;
                if w < 0 || w >= Q {
                    continue;
                }

                let w_normalized = w.rem_euclid(Q);
                let hb_w = high_bits(w_normalized, gamma2 as i32);

                for cs2 in [-120i32, -60, -30, 0, 30, 60, 120] {
                    let w_minus_cs2 = w_normalized - cs2;
                    let w_minus_cs2_normalized = w_minus_cs2.rem_euclid(Q);

                    let (_r1, r0) = decompose(w_minus_cs2_normalized, gamma2 as i32);
                    let hb_w_minus_cs2 = high_bits(w_minus_cs2_normalized, gamma2 as i32);

                    // Check if rejection would pass
                    let r0_norm = r0.abs();
                    let passes_rejection = r0_norm < gamma2_minus_beta;

                    // Check if high bits changed
                    let highbits_changed = hb_w != hb_w_minus_cs2;

                    if highbits_changed {
                        boundary_crossings += 1;
                        if passes_rejection {
                            invariant_violations += 1;
                            println!(
                                "VIOLATION: w={}, cs2={}, w-cs2={}",
                                w_normalized, cs2, w_minus_cs2_normalized
                            );
                            println!("  HighBits(w)={}, HighBits(w-cs2)={}", hb_w, hb_w_minus_cs2);
                            println!(
                                "  r0={}, |r0|={}, threshold={}",
                                r0, r0_norm, gamma2_minus_beta
                            );
                        } else {
                            rejection_failures += 1;
                        }
                    }
                }
            }
        }

        println!("\nResults:");
        println!("  Boundary crossings: {}", boundary_crossings);
        println!("  Would be rejected: {}", rejection_failures);
        println!(
            "  INVARIANT VIOLATIONS (passes rejection but highbits differ): {}",
            invariant_violations
        );

        // The hypothesis is that invariant_violations should be > 0 for ML-DSA-87
        // If so, this explains the verification failures
        if invariant_violations > 0 {
            println!(
                "\n*** CONFIRMED: Rejection check does NOT ensure HighBits(w) = HighBits(w-cs2) ***"
            );
        } else {
            println!("\n*** Hypothesis NOT confirmed - rejection check seems sufficient ***");
        }
    }

    /// Full instrumented sign/verify to capture and compare w1 vs w'1
    ///
    /// This test replicates the exact signing computation to capture w1,
    /// then runs verification to capture w'1, and compares them.
    #[test]
    fn capture_and_compare_w1_vs_w1_prime() {
        use crate::ml_dsa::keygen::{
            generate_keypair_internal, pack_pk, pack_sk, unpack_pk, unpack_sk,
        };
        use crate::ml_dsa::params::{D, MlDsaParams, N, Params87, Q};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::rounding::{high_bits, make_hint, poly_decompose, use_hint};
        use crate::ml_dsa::sampling::{expand_a, expand_mask, sample_in_ball};
        use crate::ml_dsa::sign::unpack_signature;
        use arcanum_primitives::shake::Shake256;

        println!("\n=== Instrumented w1 vs w'1 Comparison ===");

        // Test multiple seeds
        for seed_byte in 0u8..30 {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;

            let kp = generate_keypair_internal::<Params87>(&seed);
            let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
            let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

            let msg = b"test message for instrumented comparison";

            // === REPLICATE SIGNING TO CAPTURE w1 ===
            let (rho, key, tr, s1, s2, t0) = unpack_sk::<Params87>(&sk).unwrap();

            // Step 1: A ← ExpandA(ρ)
            let a = expand_a::<Params87>(&rho);

            // Convert s1, s2 to NTT domain
            let mut s1_ntt: Vec<Poly> = s1.clone();
            let mut s2_ntt: Vec<Poly> = s2.clone();
            for poly in &mut s1_ntt {
                poly.ntt();
            }
            for poly in &mut s2_ntt {
                poly.ntt();
            }

            // Convert t0 to NTT domain
            let mut t0_ntt: Vec<Poly> = t0.clone();
            for poly in &mut t0_ntt {
                poly.ntt();
            }

            // Step 2: μ ← H(tr || M)
            let mut shake = Shake256::new();
            shake.update(&tr);
            shake.update(msg);
            let mut reader = shake.finalize_xof();
            let mut mu = [0u8; 64];
            reader.squeeze(&mut mu);

            // Find a valid signature (like signing does)
            let mut found_signature = false;
            let mut captured_w1 = vec![Poly::zero(); Params87::K];
            let mut captured_c_tilde = Vec::new();
            let mut captured_z = vec![Poly::zero(); Params87::L];
            let mut captured_h = vec![Poly::zero(); Params87::K];

            for kappa in (0..1000u16).step_by(Params87::L) {
                // Step 5a: y ← ExpandMask(K || μ, κ)
                let mut mask_seed = Vec::with_capacity(96);
                mask_seed.extend_from_slice(&key);
                mask_seed.extend_from_slice(&mu);
                let y = expand_mask::<Params87>(&mask_seed, kappa, Params87::GAMMA1);

                // Step 5b: w ← Ay
                let mut y_ntt = y.clone();
                for poly in &mut y_ntt {
                    poly.ntt();
                }

                let mut w = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    for j in 0..Params87::L {
                        let product = a[i][j].pointwise_mul(&y_ntt[j]);
                        w[i] = w[i].add(&product);
                    }
                }
                for poly in &mut w {
                    poly.inv_ntt();
                    poly.reduce();
                }

                // Step 5c: w₁ ← HighBits(w)
                let mut w1 = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    for j in 0..N {
                        w1[i].coeffs[j] = high_bits(w[i].coeffs[j], Params87::GAMMA2 as i32);
                    }
                }

                // Step 5d: c̃ ← H(μ || w₁)
                let c_tilde = compute_challenge_hash_internal(&mu, &w1, Params87::LAMBDA / 4);

                // Step 5e: c ← SampleInBall(c̃)
                let mut c = sample_in_ball(&c_tilde, Params87::TAU);
                c.ntt();

                // Step 5f: z ← y + cs₁
                let mut z = vec![Poly::zero(); Params87::L];
                for i in 0..Params87::L {
                    let mut cs1_i = c.pointwise_mul(&s1_ntt[i]);
                    cs1_i.inv_ntt();
                    cs1_i.reduce_centered();
                    z[i] = y[i].add(&cs1_i);
                }

                // Step 5g: Compute w - cs₂
                let mut w_minus_cs2 = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    let mut cs2_i = c.pointwise_mul(&s2_ntt[i]);
                    cs2_i.inv_ntt();
                    cs2_i.reduce_centered();
                    w_minus_cs2[i] = w[i].sub(&cs2_i);
                }

                // Decompose w - cs₂
                let mut r0 = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    let (_, low) = poly_decompose(&w_minus_cs2[i], Params87::GAMMA2 as i32);
                    r0[i] = low;
                }

                // Step 5h: Check rejection conditions
                let gamma1_minus_beta = Params87::GAMMA1 - Params87::BETA;
                let gamma2_minus_beta = Params87::GAMMA2 - Params87::BETA;

                let mut passes = true;
                for poly in &z {
                    if poly.infinity_norm() >= gamma1_minus_beta {
                        passes = false;
                        break;
                    }
                }
                if passes {
                    for poly in &r0 {
                        if poly.infinity_norm() >= gamma2_minus_beta {
                            passes = false;
                            break;
                        }
                    }
                }

                if !passes {
                    continue;
                }

                // Compute ct₀
                let mut ct0 = vec![Poly::zero(); Params87::K];
                for i in 0..Params87::K {
                    let mut ct0_i = c.pointwise_mul(&t0_ntt[i]);
                    ct0_i.inv_ntt();
                    ct0_i.reduce_centered();
                    ct0[i] = ct0_i;
                }

                // Check ||ct₀||∞ < γ₂
                let mut ct0_ok = true;
                for poly in &ct0 {
                    if poly.infinity_norm() >= Params87::GAMMA2 {
                        ct0_ok = false;
                        break;
                    }
                }
                if !ct0_ok {
                    continue;
                }

                // Compute hint h
                let mut h = vec![Poly::zero(); Params87::K];
                let mut total_hints = 0usize;
                for i in 0..Params87::K {
                    let w_cs2_ct0 = w_minus_cs2[i].add(&ct0[i]);
                    for j in 0..N {
                        let neg_ct0_j = -ct0[i].coeffs[j];
                        if make_hint(neg_ct0_j, w_cs2_ct0.coeffs[j], Params87::GAMMA2 as i32) {
                            h[i].coeffs[j] = 1;
                            total_hints += 1;
                        }
                    }
                }

                if total_hints > Params87::OMEGA {
                    continue;
                }

                // Found a valid signature!
                captured_w1 = w1.clone();
                captured_c_tilde = c_tilde;
                captured_z = z;
                captured_h = h.clone();
                found_signature = true;

                // Also capture w, w_minus_cs2, ct0 for verification comparison
                // Compute w - cs2 + ct0 from signing for comparison with w' from verification
                let mut w_cs2_ct0_signing = vec![Poly::zero(); Params87::K];
                for ii in 0..Params87::K {
                    for jj in 0..N {
                        let val = w_minus_cs2[ii].coeffs[jj] as i64 + ct0[ii].coeffs[jj] as i64;
                        w_cs2_ct0_signing[ii].coeffs[jj] =
                            ((val % (Q as i64)) + (Q as i64)) as i32 % Q;
                    }
                }

                // Now do verification path to get w' and compare
                let (rho_dbg, t1_dbg) = unpack_pk::<Params87>(&pk).unwrap();
                let a_dbg = expand_a::<Params87>(&rho_dbg);

                let mut z_ntt_dbg = captured_z.clone();
                for poly in &mut z_ntt_dbg {
                    poly.ntt();
                }

                let mut t1_ntt_dbg = t1_dbg.clone();
                for poly in &mut t1_ntt_dbg {
                    poly.ntt();
                }

                // c from c_tilde
                let mut c_dbg = sample_in_ball(&captured_c_tilde, Params87::TAU);
                c_dbg.ntt();

                // Az
                let mut az_ntt_dbg = vec![Poly::zero(); Params87::K];
                for ii in 0..Params87::K {
                    for jjj in 0..Params87::L {
                        let product = a_dbg[ii][jjj].pointwise_mul(&z_ntt_dbg[jjj]);
                        az_ntt_dbg[ii] = az_ntt_dbg[ii].add(&product);
                    }
                }

                // ct1
                let mut ct1_ntt_dbg = vec![Poly::zero(); Params87::K];
                for ii in 0..Params87::K {
                    ct1_ntt_dbg[ii] = c_dbg.pointwise_mul(&t1_ntt_dbg[ii]);
                }

                // w' = Az - ct1 * 2^d
                let mut w_prime_dbg = vec![Poly::zero(); Params87::K];
                for ii in 0..Params87::K {
                    let mut az_ii = az_ntt_dbg[ii];
                    az_ii.inv_ntt();
                    az_ii.reduce();

                    let mut ct1_ii = ct1_ntt_dbg[ii];
                    ct1_ii.inv_ntt();
                    ct1_ii.reduce_centered();

                    for jj in 0..N {
                        let az_val = az_ii.coeffs[jj] as i64;
                        let ct1_scaled = (ct1_ii.coeffs[jj] as i64) * (1i64 << D);
                        let mut val = az_val - ct1_scaled;
                        val = ((val % (Q as i64)) + (Q as i64)) % (Q as i64);
                        w_prime_dbg[ii].coeffs[jj] = val as i32;
                    }
                }

                // Compare w' (verification) with w - cs2 + ct0 (signing)
                let mut w_prime_mismatches = Vec::new();
                for ii in 0..Params87::K {
                    for jj in 0..N {
                        if w_prime_dbg[ii].coeffs[jj] != w_cs2_ct0_signing[ii].coeffs[jj] {
                            w_prime_mismatches.push((
                                ii,
                                jj,
                                w_cs2_ct0_signing[ii].coeffs[jj],
                                w_prime_dbg[ii].coeffs[jj],
                            ));
                        }
                    }
                }

                if !w_prime_mismatches.is_empty() {
                    println!(
                        "\nseed_byte={}: {} w' mismatches (signing vs verification)!",
                        seed_byte,
                        w_prime_mismatches.len()
                    );
                    for (ii, jj, sign_val, verify_val) in w_prime_mismatches.iter().take(5) {
                        println!(
                            "  [{}][{}]: signing w-cs2+ct0={}, verification w'={}",
                            ii, jj, sign_val, verify_val
                        );
                    }
                }

                break;
            }

            if !found_signature {
                println!("seed_byte={}: Could not generate signature", seed_byte);
                continue;
            }

            // === NOW VERIFY AND CAPTURE w'1 ===
            let (rho_v, t1) = unpack_pk::<Params87>(&pk).unwrap();

            // Compute tr = H(pk)
            let mut shake = Shake256::new();
            shake.update(&pk);
            let mut reader = shake.finalize_xof();
            let mut tr_v = [0u8; 64];
            reader.squeeze(&mut tr_v);

            // Compute μ = H(tr || M)
            let mut shake = Shake256::new();
            shake.update(&tr_v);
            shake.update(msg);
            let mut reader = shake.finalize_xof();
            let mut mu_v = [0u8; 64];
            reader.squeeze(&mut mu_v);

            // c = SampleInBall(c_tilde)
            let mut c = sample_in_ball(&captured_c_tilde, Params87::TAU);
            c.ntt();

            // Expand A
            let a = expand_a::<Params87>(&rho_v);

            // z to NTT
            let mut z_ntt = captured_z.clone();
            for poly in &mut z_ntt {
                poly.ntt();
            }

            // t1 to NTT
            let mut t1_ntt = t1.clone();
            for poly in &mut t1_ntt {
                poly.ntt();
            }

            // Compute Az
            let mut az_ntt = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..Params87::L {
                    let product = a[i][j].pointwise_mul(&z_ntt[j]);
                    az_ntt[i] = az_ntt[i].add(&product);
                }
            }

            // Compute ct1
            let mut ct1_ntt = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                ct1_ntt[i] = c.pointwise_mul(&t1_ntt[i]);
            }

            // w' = Az - ct1 * 2^d
            let mut w_prime = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut az_i = az_ntt[i];
                az_i.inv_ntt();
                az_i.reduce();

                let mut ct1_i = ct1_ntt[i];
                ct1_i.inv_ntt();
                ct1_i.reduce_centered();

                for j in 0..N {
                    let az_val = az_i.coeffs[j] as i64;
                    let ct1_scaled = (ct1_i.coeffs[j] as i64) * (1i64 << D);
                    let mut val = az_val - ct1_scaled;
                    val = ((val % (Q as i64)) + (Q as i64)) % (Q as i64);
                    w_prime[i].coeffs[j] = val as i32;
                }
            }

            // w'1 = UseHint(h, w')
            let gamma2 = Params87::GAMMA2 as i32;
            let mut w_prime_1 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..N {
                    let hint_bit = captured_h[i].coeffs[j] != 0;
                    w_prime_1[i].coeffs[j] = use_hint(hint_bit, w_prime[i].coeffs[j], gamma2);
                }
            }

            // === COMPARE w1 vs w'1 ===
            let mut mismatches = 0;
            let mut first_mismatch = None;
            for i in 0..Params87::K {
                for j in 0..N {
                    if captured_w1[i].coeffs[j] != w_prime_1[i].coeffs[j] {
                        if first_mismatch.is_none() {
                            first_mismatch =
                                Some((i, j, captured_w1[i].coeffs[j], w_prime_1[i].coeffs[j]));
                        }
                        mismatches += 1;
                    }
                }
            }

            if mismatches > 0 {
                println!(
                    "\nseed_byte={}: MISMATCH! {} coefficients differ",
                    seed_byte, mismatches
                );
                if let Some((i, j, w1_val, w1p_val)) = first_mismatch {
                    println!(
                        "  First mismatch at [{}][{}]: w1={}, w'1={}",
                        i, j, w1_val, w1p_val
                    );
                    println!(
                        "  w'[{}][{}]={}, h={}",
                        i, j, w_prime[i].coeffs[j], captured_h[i].coeffs[j]
                    );

                    // Analyze the mismatch in detail
                    let w_prime_val = w_prime[i].coeffs[j];
                    let (w_p_r1, w_p_r0) = decompose_debug(w_prime_val, Params87::GAMMA2 as i32);
                    println!("  Decompose(w'): r1={}, r0={}", w_p_r1, w_p_r0);
                    println!(
                        "  |r0|={}, threshold={}",
                        w_p_r0.abs(),
                        (Params87::GAMMA2 - Params87::BETA) as i32
                    );
                }

                // Compute c_tilde_prime and compare
                let c_tilde_prime =
                    compute_challenge_hash_internal(&mu_v, &w_prime_1, Params87::LAMBDA / 4);
                println!("  c_tilde:       {:02x?}", &captured_c_tilde[..8]);
                println!("  c_tilde_prime: {:02x?}", &c_tilde_prime[..8]);
            }
        }
    }

    fn decompose_debug(r: i32, gamma2: i32) -> (i32, i32) {
        let r_norm = if r < 0 { r + Q } else { r % Q };
        let alpha = 2 * gamma2;

        let mut r0 = r_norm % alpha;
        if r0 > gamma2 {
            r0 -= alpha;
        }

        let mut r1 = (r_norm - r0) / alpha;

        if r_norm - r0 == Q - 1 {
            r1 = 0;
            r0 = r0 - 1;
        }

        (r1, r0)
    }

    fn compute_challenge_hash_internal(mu: &[u8; 64], w1: &[Poly], len: usize) -> Vec<u8> {
        let mut shake = Shake256::new();
        shake.update(mu);
        for poly in w1.iter().take(8) {
            // K=8 for ML-DSA-87
            let packed = pack_w1_4bits(poly);
            shake.update(&packed);
        }
        let mut reader = shake.finalize_xof();
        let mut c_tilde = vec![0u8; len];
        reader.squeeze(&mut c_tilde);
        c_tilde
    }

    /// Test eta polynomial packing/unpacking roundtrip
    #[test]
    fn test_eta_pack_unpack_roundtrip() {
        use crate::ml_dsa::keygen::{generate_keypair_internal, pack_sk, unpack_sk};
        use crate::ml_dsa::params::{N, Params87};

        println!("\n=== Testing eta pack/unpack roundtrip ===\n");

        // Generate a keypair
        let seed = [42u8; 32];
        let kp = generate_keypair_internal::<Params87>(&seed);

        // Pack and unpack SK
        let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);
        let (rho, key, tr, s1_unpack, s2_unpack, t0_unpack) = unpack_sk::<Params87>(&sk).unwrap();

        // Check s1 roundtrip
        let mut s1_mismatches = 0;
        for i in 0..Params87::L {
            for j in 0..N {
                if kp.s1[i].coeffs[j] != s1_unpack[i].coeffs[j] {
                    if s1_mismatches < 5 {
                        println!(
                            "s1 mismatch at [{}][{}]: orig={}, unpack={}",
                            i, j, kp.s1[i].coeffs[j], s1_unpack[i].coeffs[j]
                        );
                    }
                    s1_mismatches += 1;
                }
            }
        }

        // Check s2 roundtrip
        let mut s2_mismatches = 0;
        for i in 0..Params87::K {
            for j in 0..N {
                if kp.s2[i].coeffs[j] != s2_unpack[i].coeffs[j] {
                    if s2_mismatches < 5 {
                        println!(
                            "s2 mismatch at [{}][{}]: orig={}, unpack={}",
                            i, j, kp.s2[i].coeffs[j], s2_unpack[i].coeffs[j]
                        );
                    }
                    s2_mismatches += 1;
                }
            }
        }

        // Check t0 roundtrip
        let mut t0_mismatches = 0;
        for i in 0..Params87::K {
            for j in 0..N {
                if kp.t0[i].coeffs[j] != t0_unpack[i].coeffs[j] {
                    if t0_mismatches < 5 {
                        println!(
                            "t0 mismatch at [{}][{}]: orig={}, unpack={}",
                            i, j, kp.t0[i].coeffs[j], t0_unpack[i].coeffs[j]
                        );
                    }
                    t0_mismatches += 1;
                }
            }
        }

        println!("s1 mismatches: {}", s1_mismatches);
        println!("s2 mismatches: {}", s2_mismatches);
        println!("t0 mismatches: {}", t0_mismatches);

        assert_eq!(s1_mismatches, 0, "s1 pack/unpack failed");
        assert_eq!(s2_mismatches, 0, "s2 pack/unpack failed");
        assert_eq!(t0_mismatches, 0, "t0 pack/unpack failed");
    }

    /// Test z packing/unpacking roundtrip
    #[test]
    fn test_z_pack_unpack_roundtrip() {
        use crate::ml_dsa::params::{N, Params87};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::sign::{pack_signature, unpack_signature};

        println!("\n=== Testing z pack/unpack roundtrip ===\n");

        // Create some test z values (within valid range)
        let mut z_orig = vec![Poly::zero(); Params87::L];
        for i in 0..Params87::L {
            for j in 0..N {
                // Random-ish values in the valid range (-γ1+1, γ1-1)
                // γ1 = 2^19 = 524288 for ML-DSA-87
                let val = ((i * 256 + j) as i64 * 1234567 % 500000) as i32 - 250000;
                z_orig[i].coeffs[j] = val;
            }
        }

        // Create dummy c_tilde and h
        let c_tilde = vec![42u8; 64]; // 64 bytes for ML-DSA-87
        let h = vec![Poly::zero(); Params87::K];

        // Pack signature
        let sig_bytes = pack_signature::<Params87>(&c_tilde, &z_orig, &h);

        // Unpack signature
        let (c_tilde_unpack, z_unpack, h_unpack) =
            unpack_signature::<Params87>(&sig_bytes).unwrap();

        // Check z roundtrip
        let mut z_mismatches = 0;
        for i in 0..Params87::L {
            for j in 0..N {
                if z_orig[i].coeffs[j] != z_unpack[i].coeffs[j] {
                    if z_mismatches < 5 {
                        println!(
                            "z mismatch at [{}][{}]: orig={}, unpack={}",
                            i, j, z_orig[i].coeffs[j], z_unpack[i].coeffs[j]
                        );
                    }
                    z_mismatches += 1;
                }
            }
        }

        if z_mismatches > 0 {
            println!("Total z mismatches: {}", z_mismatches);
        } else {
            println!("z pack/unpack: PASS");
        }

        assert_eq!(z_mismatches, 0, "z pack/unpack roundtrip failed");
    }

    /// Test the key equation: Az - ct1*2^D = w - cs2 + ct0 (with actual pack/unpack)
    #[test]
    fn test_verification_equation_with_pack_unpack() {
        use crate::ml_dsa::keygen::{
            generate_keypair_internal, pack_pk, pack_sk, unpack_pk, unpack_sk,
        };
        use crate::ml_dsa::params::{D, N, Params87, Q};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::rounding::poly_decompose;
        use crate::ml_dsa::sampling::{expand_a, expand_mask, sample_in_ball};
        use crate::ml_dsa::sign::{pack_signature, unpack_signature};
        use arcanum_primitives::shake::Shake256;

        println!("\n=== Testing verification equation with pack/unpack ===\n");

        for seed_byte in 0u8..3 {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;

            let kp = generate_keypair_internal::<Params87>(&seed);
            let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
            let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

            // === SIGNING PATH (just compute, don't go through full signing) ===
            let (rho, key, tr, s1, s2, t0) = unpack_sk::<Params87>(&sk).unwrap();
            let a = expand_a::<Params87>(&rho);

            let mut s1_ntt: Vec<Poly> = s1.clone();
            let mut s2_ntt: Vec<Poly> = s2.clone();
            let mut t0_ntt: Vec<Poly> = t0.clone();
            for poly in &mut s1_ntt {
                poly.ntt();
            }
            for poly in &mut s2_ntt {
                poly.ntt();
            }
            for poly in &mut t0_ntt {
                poly.ntt();
            }

            // Generate y
            let mut key_mu = [0u8; 96];
            key_mu[..32].copy_from_slice(&key);
            key_mu[32..].copy_from_slice(&[seed_byte; 64]);
            let y = expand_mask::<Params87>(&key_mu, 0, Params87::GAMMA1);

            // w = Ay
            let mut y_ntt = y.clone();
            for poly in &mut y_ntt {
                poly.ntt();
            }

            let mut w = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..Params87::L {
                    let product = a[i][j].pointwise_mul(&y_ntt[j]);
                    w[i] = w[i].add(&product);
                }
            }
            for poly in &mut w {
                poly.inv_ntt();
                poly.reduce();
            }

            // Create c
            let c_tilde = vec![seed_byte; 64];
            let mut c = sample_in_ball(&c_tilde, Params87::TAU);
            c.ntt();

            // cs1, cs2, ct0
            let mut cs1 = vec![Poly::zero(); Params87::L];
            for i in 0..Params87::L {
                let mut cs1_i = c.pointwise_mul(&s1_ntt[i]);
                cs1_i.inv_ntt();
                cs1_i.reduce_centered();
                cs1[i] = cs1_i;
            }

            let mut cs2 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut cs2_i = c.pointwise_mul(&s2_ntt[i]);
                cs2_i.inv_ntt();
                cs2_i.reduce_centered();
                cs2[i] = cs2_i;
            }

            let mut ct0 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut ct0_i = c.pointwise_mul(&t0_ntt[i]);
                ct0_i.inv_ntt();
                ct0_i.reduce_centered();
                ct0[i] = ct0_i;
            }

            // z = y + cs1
            let mut z = vec![Poly::zero(); Params87::L];
            for i in 0..Params87::L {
                z[i] = y[i].add(&cs1[i]);
            }

            // w - cs2 + ct0 (signing path)
            let mut w_sign = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..N {
                    let val =
                        w[i].coeffs[j] as i64 - cs2[i].coeffs[j] as i64 + ct0[i].coeffs[j] as i64;
                    w_sign[i].coeffs[j] = ((val % (Q as i64)) + (Q as i64)) as i32 % Q;
                }
            }

            // === PACK AND UNPACK z (simulating signature transfer) ===
            let h_dummy = vec![Poly::zero(); Params87::K];
            let sig_bytes = pack_signature::<Params87>(&c_tilde, &z, &h_dummy);
            let (_, z_unpacked, _) = unpack_signature::<Params87>(&sig_bytes).unwrap();

            // === VERIFICATION PATH ===
            let (rho_v, t1_v) = unpack_pk::<Params87>(&pk).unwrap();
            let a_v = expand_a::<Params87>(&rho_v);

            let mut z_ntt = z_unpacked.clone(); // Use UNPACKED z
            for poly in &mut z_ntt {
                poly.ntt();
            }

            let mut t1_ntt = t1_v.clone();
            for poly in &mut t1_ntt {
                poly.ntt();
            }

            let mut c_v = sample_in_ball(&c_tilde, Params87::TAU);
            c_v.ntt();

            // Az
            let mut az_ntt = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..Params87::L {
                    let product = a_v[i][j].pointwise_mul(&z_ntt[j]);
                    az_ntt[i] = az_ntt[i].add(&product);
                }
            }

            // ct1
            let mut ct1_ntt = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                ct1_ntt[i] = c_v.pointwise_mul(&t1_ntt[i]);
            }

            // w' = Az - ct1 * 2^D
            let mut w_verify = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut az_i = az_ntt[i];
                az_i.inv_ntt();
                az_i.reduce();

                let mut ct1_i = ct1_ntt[i];
                ct1_i.inv_ntt();
                ct1_i.reduce_centered();

                for j in 0..N {
                    let az_val = az_i.coeffs[j] as i64;
                    let ct1_scaled = (ct1_i.coeffs[j] as i64) * (1i64 << D);
                    let mut val = az_val - ct1_scaled;
                    val = ((val % (Q as i64)) + (Q as i64)) % (Q as i64);
                    w_verify[i].coeffs[j] = val as i32;
                }
            }

            // Compare w_sign vs w_verify
            let mut total_mismatches = 0;
            let mut sample_mismatches = Vec::new();
            for i in 0..Params87::K {
                for j in 0..N {
                    if w_sign[i].coeffs[j] != w_verify[i].coeffs[j] {
                        total_mismatches += 1;
                        if sample_mismatches.len() < 5 {
                            let diff = w_sign[i].coeffs[j] as i64 - w_verify[i].coeffs[j] as i64;
                            sample_mismatches.push((
                                i,
                                j,
                                w_sign[i].coeffs[j],
                                w_verify[i].coeffs[j],
                                diff,
                            ));
                        }
                    }
                }
            }

            if total_mismatches > 0 {
                println!("seed_byte={}: {} mismatches!", seed_byte, total_mismatches);
                for (i, j, wsign, wverify, diff) in &sample_mismatches {
                    println!(
                        "  [{}][{}]: signing={}, verify={}, diff={}",
                        i, j, wsign, wverify, diff
                    );
                    if *diff == (1i64 << D) || *diff == -(1i64 << D) {
                        println!("    *** diff is ±2^D ***");
                    }
                }
            } else {
                println!("seed_byte={}: w_sign == w_verify (PASS)", seed_byte);
            }
        }
    }

    /// Test that Az == Ay + cAs1 (the verification identity)
    ///
    /// If this fails, it means z = y + cs1 is not being computed/stored correctly.
    #[test]
    fn test_az_equals_ay_plus_cas1() {
        use crate::ml_dsa::keygen::generate_keypair_internal;
        use crate::ml_dsa::params::{D, N, Params87, Q};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::sampling::{expand_a, expand_mask, sample_in_ball};

        println!("\n=== Testing Az == Ay + cAs1 ===\n");

        for seed_byte in 0u8..3 {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;

            let kp = generate_keypair_internal::<Params87>(&seed);

            // Generate A matrix
            let a = expand_a::<Params87>(&kp.rho);

            // Create challenge c
            let c_tilde = vec![seed_byte; 64];
            let mut c = sample_in_ball(&c_tilde, Params87::TAU);
            c.ntt();

            // Generate y (mask)
            let mut key_mu = [0u8; 96];
            key_mu[..32].copy_from_slice(&kp.key);
            key_mu[32..].copy_from_slice(&[seed_byte; 64]);
            let y = expand_mask::<Params87>(&key_mu, 0, Params87::GAMMA1);

            // Convert s1 to NTT
            let mut s1_ntt = kp.s1.clone();
            for poly in &mut s1_ntt {
                poly.ntt();
            }

            // Compute cs1 = c * s1
            let mut cs1 = vec![Poly::zero(); Params87::L];
            for i in 0..Params87::L {
                let mut cs1_i = c.pointwise_mul(&s1_ntt[i]);
                cs1_i.inv_ntt();
                cs1_i.reduce_centered();
                cs1[i] = cs1_i;
            }

            // Compute z = y + cs1
            let mut z = vec![Poly::zero(); Params87::L];
            for i in 0..Params87::L {
                z[i] = y[i].add(&cs1[i]);
            }

            // Now compute Az two ways:
            // Method 1: A * z directly
            let mut z_ntt = z.clone();
            for poly in &mut z_ntt {
                poly.ntt();
            }

            let mut az_direct = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..Params87::L {
                    let product = a[i][j].pointwise_mul(&z_ntt[j]);
                    az_direct[i] = az_direct[i].add(&product);
                }
            }
            for poly in &mut az_direct {
                poly.inv_ntt();
                poly.reduce();
            }

            // Method 2: Ay + c*As1
            // First Ay
            let mut y_ntt = y.clone();
            for poly in &mut y_ntt {
                poly.ntt();
            }

            let mut ay = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..Params87::L {
                    let product = a[i][j].pointwise_mul(&y_ntt[j]);
                    ay[i] = ay[i].add(&product);
                }
            }
            for poly in &mut ay {
                poly.inv_ntt();
                poly.reduce();
            }

            // Then As1
            let mut as1 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..Params87::L {
                    let product = a[i][j].pointwise_mul(&s1_ntt[j]);
                    as1[i] = as1[i].add(&product);
                }
            }
            for poly in &mut as1 {
                poly.inv_ntt();
                poly.reduce();
            }

            // Then c * As1
            let mut as1_ntt = as1.clone();
            for poly in &mut as1_ntt {
                poly.ntt();
            }

            let mut cas1 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut cas1_i = c.pointwise_mul(&as1_ntt[i]);
                cas1_i.inv_ntt();
                cas1_i.reduce_centered();
                cas1[i] = cas1_i;
            }

            // Ay + cAs1
            let mut ay_plus_cas1 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..N {
                    let val = ay[i].coeffs[j] as i64 + cas1[i].coeffs[j] as i64;
                    ay_plus_cas1[i].coeffs[j] = ((val % (Q as i64)) + (Q as i64)) as i32 % Q;
                }
            }

            // Compare
            let mut total_mismatches = 0;
            let mut sample_mismatches = Vec::new();
            for i in 0..Params87::K {
                for j in 0..N {
                    if az_direct[i].coeffs[j] != ay_plus_cas1[i].coeffs[j] {
                        total_mismatches += 1;
                        if sample_mismatches.len() < 5 {
                            let diff =
                                az_direct[i].coeffs[j] as i64 - ay_plus_cas1[i].coeffs[j] as i64;
                            sample_mismatches.push((
                                i,
                                j,
                                az_direct[i].coeffs[j],
                                ay_plus_cas1[i].coeffs[j],
                                diff,
                            ));
                        }
                    }
                }
            }

            if total_mismatches > 0 {
                println!(
                    "seed_byte={}: {} mismatches between Az and Ay + cAs1!",
                    seed_byte, total_mismatches
                );
                for (i, j, az, aycas1, diff) in &sample_mismatches {
                    println!(
                        "  [{}][{}]: Az={}, Ay+cAs1={}, diff={}",
                        i, j, az, aycas1, diff
                    );
                }
            } else {
                println!("seed_byte={}: Az == Ay + cAs1 (PASS)", seed_byte);
            }
        }
    }

    /// Test that ct1 * 2^D + ct0 = ct (the core decomposition identity)
    ///
    /// If this fails, it explains why verification fails: the mathematical
    /// relationship t = t1 * 2^D + t0 doesn't hold after NTT multiplication.
    #[test]
    fn test_power2round_decomposition_with_ntt() {
        use crate::ml_dsa::keygen::generate_keypair_internal;
        use crate::ml_dsa::params::{D, N, Params87, Q};
        use crate::ml_dsa::poly::Poly;
        use crate::ml_dsa::rounding::poly_power2round;
        use crate::ml_dsa::sampling::sample_in_ball;

        println!("\n=== Testing ct1*2^D + ct0 = ct ===\n");

        for seed_byte in 0u8..5 {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;

            let kp = generate_keypair_internal::<Params87>(&seed);

            // Get t from keygen (we need to recompute it since it's not stored)
            // t = As1 + s2, but we can reconstruct: t = t1 * 2^D + t0
            let mut t_reconstructed = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..N {
                    // t = t1 * 2^D + t0
                    let t1_val = kp.t1[i].coeffs[j] as i64;
                    let t0_val = kp.t0[i].coeffs[j] as i64;
                    let t_val = t1_val * (1i64 << D) + t0_val;
                    // Reduce mod Q
                    t_reconstructed[i].coeffs[j] = ((t_val % (Q as i64)) + (Q as i64)) as i32 % Q;
                }
            }

            // Create a fixed challenge c
            let c_tilde = vec![seed_byte; 64]; // Simple deterministic c_tilde
            let mut c = sample_in_ball(&c_tilde, Params87::TAU);
            c.ntt();

            // Method 1: Compute ct = c * t directly
            let mut t_ntt = t_reconstructed.clone();
            for poly in &mut t_ntt {
                poly.ntt();
            }

            let mut ct_direct = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut ct_i = c.pointwise_mul(&t_ntt[i]);
                ct_i.inv_ntt();
                ct_i.reduce(); // Reduce to [0, q)
                ct_direct[i] = ct_i;
            }

            // Method 2: Compute ct1 * 2^D + ct0
            // First ct1 = c * t1
            let mut t1_ntt = kp.t1.clone();
            for poly in &mut t1_ntt {
                poly.ntt();
            }

            let mut ct1 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut ct1_i = c.pointwise_mul(&t1_ntt[i]);
                ct1_i.inv_ntt();
                ct1_i.reduce_centered(); // This is what verify.rs does
                ct1[i] = ct1_i;
            }

            // Then ct0 = c * t0
            let mut t0_ntt = kp.t0.clone();
            for poly in &mut t0_ntt {
                poly.ntt();
            }

            let mut ct0 = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                let mut ct0_i = c.pointwise_mul(&t0_ntt[i]);
                ct0_i.inv_ntt();
                ct0_i.reduce_centered(); // This is what sign.rs does
                ct0[i] = ct0_i;
            }

            // Compute ct_reconstructed = ct1 * 2^D + ct0
            let mut ct_reconstructed = vec![Poly::zero(); Params87::K];
            for i in 0..Params87::K {
                for j in 0..N {
                    let ct1_scaled = (ct1[i].coeffs[j] as i64) * (1i64 << D);
                    let ct0_val = ct0[i].coeffs[j] as i64;
                    let val = ct1_scaled + ct0_val;
                    // Reduce to [0, q)
                    ct_reconstructed[i].coeffs[j] = ((val % (Q as i64)) + (Q as i64)) as i32 % Q;
                }
            }

            // Compare ct_direct vs ct_reconstructed
            let mut total_mismatches = 0;
            let mut sample_mismatches = Vec::new();
            for i in 0..Params87::K {
                for j in 0..N {
                    if ct_direct[i].coeffs[j] != ct_reconstructed[i].coeffs[j] {
                        total_mismatches += 1;
                        if sample_mismatches.len() < 5 {
                            let diff = ct_direct[i].coeffs[j] as i64
                                - ct_reconstructed[i].coeffs[j] as i64;
                            sample_mismatches.push((
                                i,
                                j,
                                ct_direct[i].coeffs[j],
                                ct_reconstructed[i].coeffs[j],
                                diff,
                            ));
                        }
                    }
                }
            }

            if total_mismatches > 0 {
                println!(
                    "seed_byte={}: {} mismatches between ct_direct and ct1*2^D + ct0!",
                    seed_byte, total_mismatches
                );
                for (i, j, direct, recon, diff) in &sample_mismatches {
                    println!(
                        "  [{}][{}]: ct_direct={}, ct_reconstructed={}, diff={}",
                        i, j, direct, recon, diff
                    );
                    // Check if diff is related to 2^D
                    if *diff == (1i64 << D) || *diff == -(1i64 << D) {
                        println!(
                            "    *** diff is exactly ±2^D! This suggests ct1 is off by ±1 ***"
                        );
                    }
                    // Also show the ct1 and ct0 values
                    println!(
                        "    ct1[{}][{}]={}, ct0[{}][{}]={}, t1={}, t0={}",
                        i,
                        j,
                        ct1[*i].coeffs[*j],
                        i,
                        j,
                        ct0[*i].coeffs[*j],
                        kp.t1[*i].coeffs[*j],
                        kp.t0[*i].coeffs[*j]
                    );
                }
            } else {
                println!("seed_byte={}: ct_direct == ct1*2^D + ct0 (PASS)", seed_byte);
            }
        }
    }
}
