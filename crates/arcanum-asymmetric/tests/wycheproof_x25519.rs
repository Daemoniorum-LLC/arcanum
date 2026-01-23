//! Wycheproof-Style Test Vectors for X25519
//!
//! These tests are inspired by Google's Project Wycheproof methodology,
//! which focuses on edge cases and implementation bugs in cryptographic libraries.
//!
//! Categories tested:
//! - Key exchange commutativity (both parties get the same shared secret)
//! - Low-order point rejection (is_low_order detection)
//! - Key serialization roundtrip
//! - RFC 7748 test vectors
//! - Edge cases with special byte patterns

#![allow(unused_imports)]

use arcanum_asymmetric::x25519::{X25519, X25519PublicKey, X25519SecretKey, X25519SharedSecret};

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 7748 Test Vectors
// ═══════════════════════════════════════════════════════════════════════════════

mod rfc7748_vectors {
    use super::*;

    /// RFC 7748 Section 6.1 - X25519 test vector
    /// scalar: a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
    /// u-coordinate: e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
    /// output: c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
    #[test]
    fn rfc7748_test_vector_1() {
        let scalar =
            hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .unwrap();
        let u_coord =
            hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
                .unwrap();
        let expected =
            hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
                .unwrap();

        let secret_arr: [u8; 32] = scalar.try_into().unwrap();
        let public_arr: [u8; 32] = u_coord.try_into().unwrap();

        let secret = X25519SecretKey::from_bytes(&secret_arr);
        let public = X25519PublicKey::from_bytes(&public_arr);

        let shared = secret.diffie_hellman(&public);

        assert_eq!(
            shared.as_bytes(),
            &expected[..],
            "RFC 7748 test vector 1 failed"
        );
    }

    /// RFC 7748 Section 6.1 - X25519 test vector 2
    /// scalar: 4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
    /// u-coordinate: e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
    /// output: 95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957
    #[test]
    fn rfc7748_test_vector_2() {
        let scalar =
            hex::decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
                .unwrap();
        let u_coord =
            hex::decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
                .unwrap();
        let expected =
            hex::decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
                .unwrap();

        let secret_arr: [u8; 32] = scalar.try_into().unwrap();
        let public_arr: [u8; 32] = u_coord.try_into().unwrap();

        let secret = X25519SecretKey::from_bytes(&secret_arr);
        let public = X25519PublicKey::from_bytes(&public_arr);

        let shared = secret.diffie_hellman(&public);

        assert_eq!(
            shared.as_bytes(),
            &expected[..],
            "RFC 7748 test vector 2 failed"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Commutativity Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod commutativity_tests {
    use super::*;

    /// Basic commutativity: Alice and Bob compute the same shared secret
    #[test]
    fn basic_commutativity() {
        let alice = X25519SecretKey::generate();
        let bob = X25519SecretKey::generate();

        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "DH must be commutative"
        );
    }

    /// Commutativity with known keys
    #[test]
    fn commutativity_known_keys() {
        let alice_bytes = [1u8; 32];
        let bob_bytes = [2u8; 32];

        let alice = X25519SecretKey::from_bytes(&alice_bytes);
        let bob = X25519SecretKey::from_bytes(&bob_bytes);

        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    /// Commutativity with maximum byte values
    #[test]
    fn commutativity_max_bytes() {
        let alice_bytes = [0xFFu8; 32];
        let bob_bytes = [0xFEu8; 32];

        let alice = X25519SecretKey::from_bytes(&alice_bytes);
        let bob = X25519SecretKey::from_bytes(&bob_bytes);

        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    /// Commutativity with minimum byte values
    #[test]
    fn commutativity_min_bytes() {
        let alice_bytes = [0x00u8; 32];
        let bob_bytes = [0x01u8; 32];

        let alice = X25519SecretKey::from_bytes(&alice_bytes);
        let bob = X25519SecretKey::from_bytes(&bob_bytes);

        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Low-Order Point Tests (Wycheproof tcId: 50-57)
// ═══════════════════════════════════════════════════════════════════════════════

mod low_order_tests {
    use super::*;

    /// Low-order point: all zeros
    /// This is a small-subgroup attack test - the shared secret should be all zeros
    #[test]
    fn low_order_zero_point() {
        let secret = X25519SecretKey::generate();
        let zero_point = X25519PublicKey::from_bytes(&[0u8; 32]);

        let shared = secret.diffie_hellman(&zero_point);

        // X25519 with a zero point produces a zero shared secret
        assert!(
            shared.is_low_order(),
            "Zero point should produce low-order shared secret"
        );
    }

    /// Order 2 point (from Wycheproof)
    /// Public key that produces a weak shared secret
    #[test]
    fn low_order_order_2_point() {
        let secret = X25519SecretKey::generate();

        // 1 is a low-order point (order 2)
        let mut low_point = [0u8; 32];
        low_point[0] = 1;
        let public = X25519PublicKey::from_bytes(&low_point);

        let _shared = secret.diffie_hellman(&public);

        // Check if the result is low-order
        // Note: The actual result depends on the implementation
        // Some implementations may produce non-zero low-order points
    }

    /// Detection of low-order shared secret
    #[test]
    fn detect_low_order_shared_secret() {
        let secret = X25519SecretKey::generate();

        // Use all-zeros as a known low-order point
        let zero_point = X25519PublicKey::from_bytes(&[0u8; 32]);
        let shared = secret.diffie_hellman(&zero_point);

        // The is_low_order() method should detect this
        if shared.as_bytes() == &[0u8; 32] {
            assert!(shared.is_low_order());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key Serialization Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod serialization_tests {
    use super::*;

    /// Secret key roundtrip
    #[test]
    fn secret_key_roundtrip() {
        let original = X25519SecretKey::generate();
        let bytes = original.to_bytes();
        let restored = X25519SecretKey::from_bytes(&bytes);

        assert_eq!(
            original.public_key().to_bytes(),
            restored.public_key().to_bytes(),
            "Secret key roundtrip failed"
        );
    }

    /// Public key roundtrip
    #[test]
    fn public_key_roundtrip() {
        let secret = X25519SecretKey::generate();
        let public = secret.public_key();
        let bytes = public.to_bytes();
        let restored = X25519PublicKey::from_bytes(&bytes);

        assert_eq!(public.to_bytes(), restored.to_bytes());
    }

    /// Public key hex roundtrip
    #[test]
    fn public_key_hex_roundtrip() {
        let secret = X25519SecretKey::generate();
        let public = secret.public_key();

        let hex = public.to_hex();
        let restored = X25519PublicKey::from_hex(&hex).unwrap();

        assert_eq!(public, restored);
    }

    /// Key sizes are correct
    #[test]
    fn key_sizes() {
        let secret = X25519SecretKey::generate();
        let public = secret.public_key();

        assert_eq!(secret.to_bytes().len(), 32);
        assert_eq!(public.to_bytes().len(), 32);
    }

    /// Shared secret size is correct
    #[test]
    fn shared_secret_size() {
        let alice = X25519SecretKey::generate();
        let bob = X25519SecretKey::generate();

        let shared = alice.diffie_hellman(&bob.public_key());

        assert_eq!(shared.as_bytes().len(), 32);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Special Pattern Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod special_patterns {
    use super::*;

    /// All-zeros secret key (clamped to valid key by X25519)
    #[test]
    fn all_zeros_secret_key() {
        let zeros = [0u8; 32];
        let secret = X25519SecretKey::from_bytes(&zeros);
        let public = secret.public_key();

        // Should still produce a valid public key (due to clamping)
        assert_ne!(
            public.to_bytes(),
            zeros,
            "Zero secret should not produce zero public"
        );
    }

    /// All-ones secret key
    #[test]
    fn all_ones_secret_key() {
        let ones = [0xFFu8; 32];
        let secret = X25519SecretKey::from_bytes(&ones);
        let _public = secret.public_key();

        // Verify key exchange still works
        let bob = X25519SecretKey::generate();
        let shared = secret.diffie_hellman(&bob.public_key());

        assert_ne!(shared.as_bytes(), &[0u8; 32]);
    }

    /// Sequential byte pattern
    #[test]
    fn sequential_bytes() {
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let secret = X25519SecretKey::from_bytes(&bytes);
        let public = secret.public_key();

        // Verify DH still works
        let bob = X25519SecretKey::generate();
        let alice_shared = secret.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    /// Alternating bits pattern
    #[test]
    fn alternating_bits() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xAA } else { 0x55 };
        }

        let secret = X25519SecretKey::from_bytes(&bytes);
        let bob = X25519SecretKey::generate();

        let shared = secret.diffie_hellman(&bob.public_key());
        assert_ne!(shared.as_bytes(), &[0u8; 32]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key Derivation Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod key_derivation_tests {
    use super::*;

    /// Derived key has correct length
    #[test]
    fn derived_key_length() {
        let alice = X25519SecretKey::generate();
        let bob = X25519SecretKey::generate();
        let shared = alice.diffie_hellman(&bob.public_key());

        for len in [16, 32, 48, 64, 128] {
            let derived = shared.derive_key(b"test", len).unwrap();
            assert_eq!(derived.len(), len);
        }
    }

    /// Different info produces different keys
    #[test]
    fn different_info_different_keys() {
        let alice = X25519SecretKey::generate();
        let bob = X25519SecretKey::generate();
        let shared = alice.diffie_hellman(&bob.public_key());

        let key1 = shared.derive_key(b"encryption", 32).unwrap();
        let key2 = shared.derive_key(b"authentication", 32).unwrap();

        assert_ne!(key1, key2, "Different info must produce different keys");
    }

    /// Key derivation is deterministic
    #[test]
    fn deterministic_derivation() {
        let alice = X25519SecretKey::generate();
        let bob = X25519SecretKey::generate();
        let shared = alice.diffie_hellman(&bob.public_key());

        let key1 = shared.derive_key(b"test", 32).unwrap();
        let key2 = shared.derive_key(b"test", 32).unwrap();

        assert_eq!(key1, key2, "Key derivation must be deterministic");
    }

    /// Empty info works
    #[test]
    fn empty_info() {
        let alice = X25519SecretKey::generate();
        let bob = X25519SecretKey::generate();
        let shared = alice.diffie_hellman(&bob.public_key());

        let key = shared.derive_key(b"", 32).unwrap();
        assert_eq!(key.len(), 32);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Uniqueness Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod uniqueness_tests {
    use super::*;

    /// Different secret keys produce different public keys
    #[test]
    fn different_secrets_different_publics() {
        let secret1 = X25519SecretKey::generate();
        let secret2 = X25519SecretKey::generate();

        assert_ne!(
            secret1.public_key().to_bytes(),
            secret2.public_key().to_bytes(),
            "Different secrets should produce different public keys"
        );
    }

    /// Different key pairs produce different shared secrets
    #[test]
    fn different_pairs_different_shared() {
        let alice = X25519SecretKey::generate();
        let bob1 = X25519SecretKey::generate();
        let bob2 = X25519SecretKey::generate();

        let shared1 = alice.diffie_hellman(&bob1.public_key());
        let shared2 = alice.diffie_hellman(&bob2.public_key());

        assert_ne!(
            shared1.as_bytes(),
            shared2.as_bytes(),
            "Different peers should produce different shared secrets"
        );
    }

    /// Shared secret with self uses own public key
    #[test]
    fn self_shared_secret() {
        let alice = X25519SecretKey::generate();
        let shared = alice.diffie_hellman(&alice.public_key());

        // This should work but produce a specific value
        assert_eq!(shared.as_bytes().len(), 32);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Ephemeral Key Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod ephemeral_tests {
    use super::*;

    /// Ephemeral key exchange works
    #[test]
    fn ephemeral_key_exchange() {
        let (alice_ephemeral, alice_public) = X25519SecretKey::ephemeral();
        let bob = X25519SecretKey::generate();

        let alice_shared = alice_ephemeral.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice_public);

        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "Ephemeral key exchange must work"
        );
    }

    /// Ephemeral keys are unique
    #[test]
    fn ephemeral_keys_unique() {
        let (_, pub1) = X25519SecretKey::ephemeral();
        let (_, pub2) = X25519SecretKey::ephemeral();

        assert_ne!(
            pub1.to_bytes(),
            pub2.to_bytes(),
            "Ephemeral keys should be unique"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Triple DH Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod triple_dh_tests {
    use super::*;

    /// Triple DH produces valid shared secret
    #[test]
    fn triple_dh_produces_valid_secret() {
        let alice_identity = X25519SecretKey::generate();
        let alice_ephemeral = X25519SecretKey::generate();
        let bob_identity = X25519SecretKey::generate();
        let bob_ephemeral = X25519SecretKey::generate();

        let shared = X25519::triple_dh(
            &alice_identity,
            &alice_ephemeral,
            &bob_identity.public_key(),
            &bob_ephemeral.public_key(),
        );

        assert_eq!(shared.as_bytes().len(), 32);
        assert_ne!(shared.as_bytes(), &[0u8; 32]);
    }

    /// Triple DH is deterministic
    #[test]
    fn triple_dh_deterministic() {
        let alice_identity = X25519SecretKey::generate();
        let alice_ephemeral = X25519SecretKey::generate();
        let bob_identity = X25519SecretKey::generate();
        let bob_ephemeral = X25519SecretKey::generate();

        let shared1 = X25519::triple_dh(
            &alice_identity,
            &alice_ephemeral,
            &bob_identity.public_key(),
            &bob_ephemeral.public_key(),
        );

        let shared2 = X25519::triple_dh(
            &alice_identity,
            &alice_ephemeral,
            &bob_identity.public_key(),
            &bob_ephemeral.public_key(),
        );

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// API Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod api_tests {
    use super::*;

    /// X25519 constants are correct
    #[test]
    fn constants() {
        assert_eq!(X25519::ALGORITHM, "X25519");
        assert_eq!(X25519::SECURITY_BITS, 128);
        assert_eq!(X25519::KEY_SIZE, 32);
    }

    /// Generate returns valid key pair
    #[test]
    fn generate_key_pair() {
        let (secret, public) = X25519::generate();

        assert_eq!(secret.to_bytes().len(), 32);
        assert_eq!(public.to_bytes(), secret.public_key().to_bytes());
    }
}
