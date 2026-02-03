//! SLH-DSA Test Suite
//!
//! Comprehensive tests following TDD methodology.
//! These tests define the expected behavior and will fail until implementation is complete.

use super::*;

// ============================================================================
// Level 1: Unit Tests (per module) - see individual module test sections
// ============================================================================

// ============================================================================
// Level 2: Integration Tests
// ============================================================================

mod integration {
    use super::*;

    /// Test basic sign/verify roundtrip for SHA2-128f
    #[test]
    fn test_sha2_128f_sign_verify_roundtrip() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message = b"Test message for SLH-DSA";

        let signature = SlhDsaSha2_128f::sign(&sk, message);

        // Signature should have correct size
        assert_eq!(signature.len(), Sha2_128f::SIG_SIZE);

        // Verification should succeed
        let result = SlhDsaSha2_128f::verify(&vk, message, &signature);
        assert!(
            result.is_ok(),
            "Signature verification failed: {:?}",
            result
        );
    }

    /// Test basic sign/verify roundtrip for SHA2-128s
    #[test]
    fn test_sha2_128s_sign_verify_roundtrip() {
        let (sk, vk) = SlhDsaSha2_128s::generate_keypair();
        let message = b"Test message for SLH-DSA small variant";

        let signature = SlhDsaSha2_128s::sign(&sk, message);

        assert_eq!(signature.len(), Sha2_128s::SIG_SIZE);
        assert!(SlhDsaSha2_128s::verify(&vk, message, &signature).is_ok());
    }

    /// Test that wrong message fails verification
    #[test]
    fn test_wrong_message_fails_verification() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message1 = b"Original message";
        let message2 = b"Different message";

        let signature = SlhDsaSha2_128f::sign(&sk, message1);

        // Verification with wrong message should fail
        let result = SlhDsaSha2_128f::verify(&vk, message2, &signature);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SignatureError::InvalidSignature);
    }

    /// Test that wrong key fails verification
    #[test]
    fn test_wrong_key_fails_verification() {
        let (sk1, _vk1) = SlhDsaSha2_128f::generate_keypair();
        let (_sk2, vk2) = SlhDsaSha2_128f::generate_keypair();
        let message = b"Test message";

        let signature = SlhDsaSha2_128f::sign(&sk1, message);

        // Verification with wrong key should fail
        let result = SlhDsaSha2_128f::verify(&vk2, message, &signature);
        assert!(result.is_err());
    }

    /// Test that modified signature fails verification
    #[test]
    fn test_modified_signature_fails_verification() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message = b"Test message";

        let signature = SlhDsaSha2_128f::sign(&sk, message);
        let mut sig_bytes = signature.to_bytes();

        // Flip a bit in the signature
        sig_bytes[100] ^= 0x01;
        let modified_sig = SlhDsaSignature::<Sha2_128f>::from_bytes(&sig_bytes).unwrap();

        // Verification should fail
        let result = SlhDsaSha2_128f::verify(&vk, message, &modified_sig);
        assert!(result.is_err());
    }

    /// Test empty message handling
    #[test]
    fn test_empty_message() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message = b"";

        let signature = SlhDsaSha2_128f::sign(&sk, message);
        assert!(SlhDsaSha2_128f::verify(&vk, message, &signature).is_ok());
    }

    /// Test large message handling
    #[test]
    fn test_large_message() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message = vec![0x42u8; 1_000_000]; // 1 MB message

        let signature = SlhDsaSha2_128f::sign(&sk, &message);
        assert!(SlhDsaSha2_128f::verify(&vk, &message, &signature).is_ok());
    }

    /// Test deterministic signing produces same signature
    #[test]
    fn test_deterministic_signing() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message = b"Deterministic test";

        let sig1 = SlhDsaSha2_128f::sign_deterministic(&sk, message);
        let sig2 = SlhDsaSha2_128f::sign_deterministic(&sk, message);

        // Deterministic signatures should be identical
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());

        // Both should verify
        assert!(SlhDsaSha2_128f::verify(&vk, message, &sig1).is_ok());
        assert!(SlhDsaSha2_128f::verify(&vk, message, &sig2).is_ok());
    }

    /// Test randomized signing produces different signatures
    #[test]
    fn test_randomized_signing() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message = b"Randomized test";

        let sig1 = SlhDsaSha2_128f::sign(&sk, message);
        let sig2 = SlhDsaSha2_128f::sign(&sk, message);

        // Randomized signatures should be different
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());

        // Both should still verify
        assert!(SlhDsaSha2_128f::verify(&vk, message, &sig1).is_ok());
        assert!(SlhDsaSha2_128f::verify(&vk, message, &sig2).is_ok());
    }
}

// ============================================================================
// Level 3: Key Serialization Tests
// ============================================================================

mod serialization {
    use super::*;

    #[test]
    fn test_signing_key_serialization_roundtrip() {
        let (sk, _vk) = SlhDsaSha2_128f::generate_keypair();

        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), Sha2_128f::SK_SIZE);

        let restored = SlhDsaSigningKey::<Sha2_128f>::from_bytes(&bytes).unwrap();

        // Verify the restored key produces valid signatures
        let message = b"Serialization test";
        let sig = SlhDsaSha2_128f::sign(&restored, message);
        assert!(SlhDsaSha2_128f::verify(&sk.verifying_key(), message, &sig).is_ok());
    }

    #[test]
    fn test_verifying_key_serialization_roundtrip() {
        let (_sk, vk) = SlhDsaSha2_128f::generate_keypair();

        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), Sha2_128f::PK_SIZE);

        let restored = SlhDsaVerifyingKey::<Sha2_128f>::from_bytes(&bytes).unwrap();
        assert_eq!(vk, restored);
    }

    #[test]
    fn test_signature_serialization_roundtrip() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
        let message = b"Signature serialization test";

        let sig = SlhDsaSha2_128f::sign(&sk, message);
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), Sha2_128f::SIG_SIZE);

        let restored = SlhDsaSignature::<Sha2_128f>::from_bytes(&bytes).unwrap();
        assert!(SlhDsaSha2_128f::verify(&vk, message, &restored).is_ok());
    }

    #[test]
    fn test_invalid_key_length_rejected() {
        let short_bytes = vec![0u8; Sha2_128f::SK_SIZE - 1];
        assert!(SlhDsaSigningKey::<Sha2_128f>::from_bytes(&short_bytes).is_none());

        let long_bytes = vec![0u8; Sha2_128f::SK_SIZE + 1];
        assert!(SlhDsaSigningKey::<Sha2_128f>::from_bytes(&long_bytes).is_none());
    }

    #[test]
    fn test_invalid_signature_length_rejected() {
        let short_bytes = vec![0u8; Sha2_128f::SIG_SIZE - 1];
        assert!(SlhDsaSignature::<Sha2_128f>::from_bytes(&short_bytes).is_none());
    }
}

// ============================================================================
// Level 4: Property-Based Tests (using proptest when available)
// ============================================================================

mod properties {
    use super::*;

    /// Property: Any message signed with a key can be verified with the corresponding public key
    #[test]
    fn property_sign_verify_any_message() {
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair();

        // Test various message patterns
        let range_msg: Vec<u8> = (0..=255).collect();
        let test_messages: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"Hello, World!",
            &[0u8; 100],
            &[0xFFu8; 100],
            &range_msg,
        ];

        for message in test_messages {
            let sig = SlhDsaSha2_128f::sign(&sk, message);
            assert!(
                SlhDsaSha2_128f::verify(&vk, message, &sig).is_ok(),
                "Failed for message of length {}",
                message.len()
            );
        }
    }

    /// Property: Different keypairs produce independent signatures
    #[test]
    fn property_keypair_independence() {
        let (sk1, vk1) = SlhDsaSha2_128f::generate_keypair();
        let (sk2, vk2) = SlhDsaSha2_128f::generate_keypair();
        let message = b"Independence test";

        // Sign with both keys
        let sig1 = SlhDsaSha2_128f::sign_deterministic(&sk1, message);
        let sig2 = SlhDsaSha2_128f::sign_deterministic(&sk2, message);

        // Signatures should be different
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());

        // Cross-verification should fail
        assert!(SlhDsaSha2_128f::verify(&vk2, message, &sig1).is_err());
        assert!(SlhDsaSha2_128f::verify(&vk1, message, &sig2).is_err());

        // Self-verification should succeed
        assert!(SlhDsaSha2_128f::verify(&vk1, message, &sig1).is_ok());
        assert!(SlhDsaSha2_128f::verify(&vk2, message, &sig2).is_ok());
    }

    /// Property: Verifying key derivation is deterministic
    #[test]
    fn property_verifying_key_derivation() {
        let (sk, _) = SlhDsaSha2_128f::generate_keypair();

        let vk1 = sk.verifying_key();
        let vk2 = sk.verifying_key();

        assert_eq!(vk1, vk2);
    }
}

// ============================================================================
// Level 5: All Parameter Set Tests
// ============================================================================

mod all_variants {
    use super::*;

    macro_rules! test_variant {
        ($name:ident, $type:ty, $params:ty) => {
            mod $name {
                use super::*;

                #[test]
                fn test_keygen() {
                    let (sk, vk) = <$type>::generate_keypair();
                    assert_eq!(sk.to_bytes().len(), <$params>::SK_SIZE);
                    assert_eq!(vk.to_bytes().len(), <$params>::PK_SIZE);
                }

                #[test]
                fn test_sign_verify() {
                    let (sk, vk) = <$type>::generate_keypair();
                    let message = b"Test for variant";

                    let sig = <$type>::sign(&sk, message);
                    assert_eq!(sig.len(), <$params>::SIG_SIZE);
                    assert!(<$type>::verify(&vk, message, &sig).is_ok());
                }

                #[test]
                fn test_algorithm_name() {
                    assert!(<$params>::ALGORITHM.starts_with("SLH-DSA"));
                }
            }
        };
    }

    test_variant!(sha2_128s, SlhDsaSha2_128s, Sha2_128s);
    test_variant!(sha2_128f, SlhDsaSha2_128f, Sha2_128f);
    test_variant!(sha2_192s, SlhDsaSha2_192s, Sha2_192s);
    test_variant!(sha2_192f, SlhDsaSha2_192f, Sha2_192f);
    test_variant!(sha2_256s, SlhDsaSha2_256s, Sha2_256s);
    test_variant!(sha2_256f, SlhDsaSha2_256f, Sha2_256f);
}

// ============================================================================
// KAT Vector Tests (placeholder - will be populated with NIST vectors)
// ============================================================================

mod kat_vectors {
    use super::*;

    /// Helper: generate KAT data from seeds and print for recording.
    /// Run with `cargo test -p arcanum-pqc --features slh-dsa -- kat_vectors::print_kat --nocapture --ignored`
    #[test]
    #[ignore]
    fn print_kat_vectors_for_recording() {
        use sha2::{Sha256, Digest};

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }

        // SHA2-128f
        let sk_seed: Vec<u8> = (0u8..16).collect();
        let sk_prf: Vec<u8> = (16u8..32).collect();
        let pk_seed: Vec<u8> = (32u8..48).collect();
        let message = b"SLH-DSA FIPS 205 KAT test vector";

        let (sk, vk) = SlhDsaSha2_128f::generate_keypair_from_seed(&sk_seed, &sk_prf, &pk_seed);
        let sig = SlhDsaSha2_128f::sign_deterministic(&sk, message);
        let sig_bytes = sig.to_bytes();
        let sig_hash = Sha256::digest(&sig_bytes);
        eprintln!("=== SHA2-128f ===");
        eprintln!("pk:         {}", hex(&vk.to_bytes()));
        eprintln!("sig_sha256: {}", hex(&sig_hash));
        eprintln!("sig_prefix: {}", hex(&sig_bytes[..32]));
        eprintln!("sig_len:    {}", sig_bytes.len());

        // SHA2-128s
        let (sk_s, vk_s) = SlhDsaSha2_128s::generate_keypair_from_seed(&sk_seed, &sk_prf, &pk_seed);
        let sig_s = SlhDsaSha2_128s::sign_deterministic(&sk_s, message);
        let sig_s_bytes = sig_s.to_bytes();
        let sig_s_hash = Sha256::digest(&sig_s_bytes);
        eprintln!("=== SHA2-128s ===");
        eprintln!("pk:         {}", hex(&vk_s.to_bytes()));
        eprintln!("sig_sha256: {}", hex(&sig_s_hash));
        eprintln!("sig_prefix: {}", hex(&sig_s_bytes[..32]));
        eprintln!("sig_len:    {}", sig_s_bytes.len());
    }

    /// Self-consistency KAT test for SLH-DSA-SHA2-128f.
    ///
    /// Verifies that deterministic key generation and signing produce
    /// stable outputs. Seeds are sequential bytes; expected values were
    /// recorded from a verified run.
    #[test]
    fn test_sha2_128f_self_consistency_kat() {
        use sha2::{Sha256, Digest};

        let sk_seed: Vec<u8> = (0u8..16).collect();
        let sk_prf: Vec<u8> = (16u8..32).collect();
        let pk_seed: Vec<u8> = (32u8..48).collect();
        let message = b"SLH-DSA FIPS 205 KAT test vector";

        // Generate keypair from known seeds
        let (sk, vk) = SlhDsaSha2_128f::generate_keypair_from_seed(&sk_seed, &sk_prf, &pk_seed);

        // Verify public key matches expected value
        let pk_hex = vk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(pk_hex, EXPECTED_SHA2_128F_PK, "SHA2-128f public key mismatch — implementation changed");

        // Sign deterministically and verify signature hash
        let sig = SlhDsaSha2_128f::sign_deterministic(&sk, message);
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), Sha2_128f::SIG_SIZE);

        let sig_hash = Sha256::digest(&sig_bytes);
        let sig_hash_hex = sig_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(sig_hash_hex, EXPECTED_SHA2_128F_SIG_SHA256, "SHA2-128f signature hash mismatch — implementation changed");

        // Verify signature is valid
        assert!(SlhDsaSha2_128f::verify(&vk, message, &sig).is_ok());

        // Verify determinism: second sign must produce identical signature
        let sig2 = SlhDsaSha2_128f::sign_deterministic(&sk, message);
        assert_eq!(sig.to_bytes(), sig2.to_bytes(), "Deterministic signing not stable");
    }

    /// Self-consistency KAT test for SLH-DSA-SHA2-128s.
    #[test]
    fn test_sha2_128s_self_consistency_kat() {
        use sha2::{Sha256, Digest};

        let sk_seed: Vec<u8> = (0u8..16).collect();
        let sk_prf: Vec<u8> = (16u8..32).collect();
        let pk_seed: Vec<u8> = (32u8..48).collect();
        let message = b"SLH-DSA FIPS 205 KAT test vector";

        let (sk, vk) = SlhDsaSha2_128s::generate_keypair_from_seed(&sk_seed, &sk_prf, &pk_seed);

        let pk_hex = vk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(pk_hex, EXPECTED_SHA2_128S_PK, "SHA2-128s public key mismatch — implementation changed");

        let sig = SlhDsaSha2_128s::sign_deterministic(&sk, message);
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), Sha2_128s::SIG_SIZE);

        let sig_hash = Sha256::digest(&sig_bytes);
        let sig_hash_hex = sig_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(sig_hash_hex, EXPECTED_SHA2_128S_SIG_SHA256, "SHA2-128s signature hash mismatch — implementation changed");

        assert!(SlhDsaSha2_128s::verify(&vk, message, &sig).is_ok());

        let sig2 = SlhDsaSha2_128s::sign_deterministic(&sk, message);
        assert_eq!(sig.to_bytes(), sig2.to_bytes(), "Deterministic signing not stable");
    }

    // Expected values recorded from verified run (sequential seeds 0x00..0x2f)
    const EXPECTED_SHA2_128F_PK: &str = "202122232425262728292a2b2c2d2e2f902f02ebec7996b03694f8744a0a25f8";
    const EXPECTED_SHA2_128F_SIG_SHA256: &str = "2f93b3a280801b1339d9bded2fdc4b1cefe5ff3cc71b03118ca08b05b0bb3b52";
    const EXPECTED_SHA2_128S_PK: &str = "202122232425262728292a2b2c2d2e2fff924831e188087f18a24674badb611c";
    const EXPECTED_SHA2_128S_SIG_SHA256: &str = "36a0bd02aa35bc5528c1fc558f6690c908d684e22942e1b8bc19d25681cd95cf";
}
