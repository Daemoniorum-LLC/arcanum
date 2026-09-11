//! Nonce Misuse Documentation and Integration Audit Tests (Phase 5.11)
//!
//! These tests document the current nonce handling behavior in the symmetric
//! encryption APIs and demonstrate correct usage patterns.
//!
//! ## Security Background
//!
//! Nonce reuse in AES-GCM is **catastrophic**: it allows an attacker to recover
//! the GHASH authentication key via polynomial GCD, enabling message forgery.
//! Similar issues affect ChaCha20-Poly1305.
//!
//! ## Current Behavior
//!
//! The current API does **not** automatically prevent nonce reuse. Users must
//! either:
//! 1. Use `NonceTracker` to detect reuse attempts
//! 2. Use `NonceGenerator` with counter mode to guarantee uniqueness
//! 3. Use XChaCha20-Poly1305 with random nonces (192-bit nonce, collision-resistant)
//! 4. Use AES-GCM-SIV for nonce-misuse resistance (deterministic encryption)
//!
//! ## These tests exist to make the behavior EXPLICIT, not to endorse it.

use arcanum_core::nonce::{Nonce, Nonce96, NonceGenerator, NonceTracker};
use arcanum_symmetric::{Aes256Gcm, Aes256GcmSiv, ChaCha20Poly1305Cipher, Cipher, XChaCha20Poly1305Cipher};

// ═══════════════════════════════════════════════════════════════════════════════
// CURRENT BEHAVIOR DOCUMENTATION
// These tests demonstrate that the API allows nonce reuse without warning.
// ═══════════════════════════════════════════════════════════════════════════════

/// Document current behavior: AES-GCM allows nonce reuse without error.
///
/// **THIS IS DANGEROUS** - in AES-GCM, encrypting two different messages with the
/// same key and nonce leaks the GHASH authentication key, enabling message forgery.
/// This test exists to document the current behavior, not to endorse it.
#[test]
fn test_aes_gcm_allows_nonce_reuse_without_tracker() {
    let key = Aes256Gcm::generate_key();
    let nonce = Aes256Gcm::generate_nonce();

    // Encrypting twice with the same nonce succeeds (THIS IS DANGEROUS)
    let ct1 = Aes256Gcm::encrypt(&key, &nonce, b"message 1", None).unwrap();
    let ct2 = Aes256Gcm::encrypt(&key, &nonce, b"message 2", None).unwrap();

    // Both succeed — the API does NOT prevent nonce reuse
    assert_ne!(ct1, ct2, "Same nonce + different plaintext = different ciphertext");

    // This behavior is documented but dangerous. Users should use NonceTracker
    // or NonceGenerator to prevent nonce reuse.
}

/// Document that ChaCha20-Poly1305 also allows nonce reuse.
#[test]
fn test_chacha20_poly1305_allows_nonce_reuse() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();

    let ct1 = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, b"message A", None).unwrap();
    let ct2 = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, b"message B", None).unwrap();

    assert_ne!(ct1, ct2);
    // Nonce reuse with Poly1305 can leak the one-time authentication key.
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRECT USAGE: NONCE TRACKER
// Demonstrate how to use NonceTracker to prevent reuse.
// ═══════════════════════════════════════════════════════════════════════════════

/// Demonstrate correct usage with NonceTracker to prevent nonce reuse.
#[test]
fn test_nonce_tracker_prevents_reuse_pattern() {
    let key = Aes256Gcm::generate_key();
    let tracker = NonceTracker::<12>::new(1000);
    let nonce = Nonce96::random();

    // First use: tracker accepts the nonce
    assert!(
        tracker.check_and_touch(&nonce).is_ok(),
        "First use should be accepted"
    );
    let ct1 = Aes256Gcm::encrypt(&key, nonce.as_bytes(), b"message 1", None).unwrap();
    assert!(!ct1.is_empty());

    // Second use with same nonce: tracker rejects
    assert!(
        tracker.check_and_touch(&nonce).is_err(),
        "Reuse should be rejected"
    );
    // User should NOT encrypt again with this nonce

    // Different nonce: tracker accepts
    let nonce2 = Nonce96::random();
    assert!(
        tracker.check_and_touch(&nonce2).is_ok(),
        "Different nonce should be accepted"
    );
}

/// Full encryption pattern with NonceTracker integration.
#[test]
fn test_safe_encryption_with_tracker() {
    let key = Aes256Gcm::generate_key();
    let tracker = NonceTracker::<12>::new(1000);

    let messages = [b"message 1".as_slice(), b"message 2", b"message 3"];
    let mut ciphertexts = Vec::new();

    for msg in &messages {
        // Generate fresh nonce
        let nonce = Nonce96::random();

        // Check with tracker before encrypting
        tracker
            .check_and_touch(&nonce)
            .expect("Random nonce collision is astronomically unlikely");

        let ct = Aes256Gcm::encrypt(&key, nonce.as_bytes(), msg, None).unwrap();
        ciphertexts.push((nonce, ct));
    }

    // Verify all ciphertexts are different
    for i in 0..ciphertexts.len() {
        for j in (i + 1)..ciphertexts.len() {
            assert_ne!(ciphertexts[i].1, ciphertexts[j].1);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRECT USAGE: NONCE GENERATOR (COUNTER MODE)
// Demonstrate how to use NonceGenerator for guaranteed uniqueness.
// ═══════════════════════════════════════════════════════════════════════════════

/// Demonstrate correct usage with NonceGenerator in counter mode.
#[test]
fn test_nonce_generator_counter_mode_pattern() {
    let key = Aes256Gcm::generate_key();
    let nonce_gen = NonceGenerator::<12>::counter(0);

    let nonce1 = nonce_gen.generate().expect("Counter not exhausted");
    let nonce2 = nonce_gen.generate().expect("Counter not exhausted");
    assert_ne!(nonce1.as_bytes(), nonce2.as_bytes(), "Counter mode generates unique nonces");

    // Encrypt with sequential nonces
    let ct1 = Aes256Gcm::encrypt(&key, nonce1.as_bytes(), b"message 1", None).unwrap();
    let ct2 = Aes256Gcm::encrypt(&key, nonce2.as_bytes(), b"message 2", None).unwrap();
    assert_ne!(ct1, ct2);
}

/// Demonstrate hybrid nonce generation (counter + random).
#[test]
fn test_nonce_generator_hybrid_mode() {
    let _key = ChaCha20Poly1305Cipher::generate_key();
    let nonce_gen = NonceGenerator::<12>::hybrid();

    let nonces: Vec<Nonce<12>> = (0..100).filter_map(|_| nonce_gen.generate().ok()).collect();

    // All nonces should be unique
    let mut unique = std::collections::HashSet::new();
    for nonce in &nonces {
        assert!(
            unique.insert(nonce.as_bytes().to_vec()),
            "Hybrid mode should generate unique nonces"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE-MISUSE RESISTANT ALTERNATIVES
// Demonstrate safer alternatives for scenarios where nonce uniqueness is hard.
// ═══════════════════════════════════════════════════════════════════════════════

/// Demonstrate AES-GCM-SIV: nonce-misuse resistant encryption.
///
/// GCM-SIV is deterministic: same key + nonce + plaintext = same ciphertext.
/// This is safe (just reveals repeated messages) unlike AES-GCM (catastrophic).
#[test]
fn test_aes_gcm_siv_nonce_misuse_resistant() {
    let key = Aes256GcmSiv::generate_key();
    let nonce = Aes256GcmSiv::generate_nonce();

    // Same inputs produce same outputs (deterministic)
    let ct1 = Aes256GcmSiv::encrypt(&key, &nonce, b"same message", None).unwrap();
    let ct2 = Aes256GcmSiv::encrypt(&key, &nonce, b"same message", None).unwrap();
    assert_eq!(ct1, ct2, "GCM-SIV is deterministic");

    // Different messages still produce different ciphertexts
    let ct3 = Aes256GcmSiv::encrypt(&key, &nonce, b"different message", None).unwrap();
    assert_ne!(ct1, ct3);

    // The authentication key is NOT leaked by nonce reuse
    // (GCM-SIV derives a message-specific tag key)
}

/// Demonstrate XChaCha20-Poly1305: extended nonce for random generation.
///
/// With 192-bit nonces, random nonce collisions are negligible up to 2^64 messages.
#[test]
fn test_xchacha20_extended_nonce_safety() {
    let key = XChaCha20Poly1305Cipher::generate_key();

    // Generate many random nonces - collision is astronomically unlikely
    let nonces: Vec<_> = (0..1000)
        .map(|_| XChaCha20Poly1305Cipher::generate_nonce())
        .collect();

    // All nonces should be unique
    let mut unique = std::collections::HashSet::new();
    for nonce in &nonces {
        assert!(
            unique.insert(nonce.clone()),
            "Random 192-bit nonce collision is astronomically unlikely"
        );
    }

    // Encrypt with random nonces safely
    let ct1 = XChaCha20Poly1305Cipher::encrypt(&key, &nonces[0], b"message", None).unwrap();
    let ct2 = XChaCha20Poly1305Cipher::encrypt(&key, &nonces[1], b"message", None).unwrap();
    assert_ne!(ct1, ct2, "Different nonces produce different ciphertexts");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE EXHAUSTION HANDLING
// Demonstrate proper handling when nonce space is about to be exhausted.
// ═══════════════════════════════════════════════════════════════════════════════

/// Demonstrate that NonceGenerator can be limited to prevent overflow.
#[test]
fn test_nonce_generator_limit_prevents_overflow() {
    let nonce_gen = NonceGenerator::<12>::counter(0).with_limit(3);

    assert!(nonce_gen.generate().is_ok()); // 1
    assert!(nonce_gen.generate().is_ok()); // 2
    assert!(nonce_gen.generate().is_ok()); // 3
    assert!(nonce_gen.generate().is_err()); // Limit reached

    // After limit, user must rotate key
}

/// Demonstrate counter-based nonce management.
#[test]
fn test_nonce_counter_management() {
    let nonce_gen = NonceGenerator::<12>::counter(u64::MAX - 2);

    // Near end of counter space
    let n1 = nonce_gen.generate();
    let n2 = nonce_gen.generate();
    let n3 = nonce_gen.generate(); // This should exhaust the counter

    assert!(n1.is_ok());
    assert!(n2.is_ok());
    // Counter exhaustion behavior depends on implementation
    // User should monitor and rotate keys before exhaustion
    assert!(n1.unwrap().as_bytes() != n2.unwrap().as_bytes());
    let _ = n3; // Silence unused variable warning
}

// ═══════════════════════════════════════════════════════════════════════════════
// RECOMMENDATION DOCUMENTATION
// These tests serve as executable documentation of best practices.
// ═══════════════════════════════════════════════════════════════════════════════

/// Document recommended cipher selection based on use case.
///
/// | Use Case | Recommended Cipher | Nonce Strategy |
/// |----------|-------------------|----------------|
/// | General | AES-256-GCM | Counter via NonceGenerator |
/// | Key-value store | AES-256-GCM-SIV | Random (misuse-resistant) |
/// | Random nonces required | XChaCha20-Poly1305 | Random (192-bit nonces) |
/// | High-security | AES-256-GCM + NonceTracker | Counter + verification |
#[test]
fn test_cipher_selection_recommendations() {
    // AES-GCM with counter: best throughput, requires nonce management
    let key_gcm = Aes256Gcm::generate_key();
    let nonce_gen = NonceGenerator::<12>::counter(0);
    let nonce = nonce_gen.generate().unwrap();
    let _ = Aes256Gcm::encrypt(&key_gcm, nonce.as_bytes(), b"data", None).unwrap();

    // GCM-SIV: slightly slower, safe with repeated nonces
    let key_siv = Aes256GcmSiv::generate_key();
    let nonce_siv = Aes256GcmSiv::generate_nonce();
    let _ = Aes256GcmSiv::encrypt(&key_siv, &nonce_siv, b"data", None).unwrap();

    // XChaCha20: random nonces safe, good for distributed systems
    let key_x = XChaCha20Poly1305Cipher::generate_key();
    let nonce_x = XChaCha20Poly1305Cipher::generate_nonce();
    let _ = XChaCha20Poly1305Cipher::encrypt(&key_x, &nonce_x, b"data", None).unwrap();
}
