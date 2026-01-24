# WASM Support TDD Roadmap

**Document ID:** TDD-WASM-001
**Version:** 0.1.0
**Date:** 2026-01-24
**Governing Spec:** [WASM-SUPPORT.md](./WASM-SUPPORT.md)
**Status:** RED Phase

---

## Overview

This roadmap defines the test-driven implementation path for Arcanum WASM support, following Agent-TDD methodology. Tests are organized by priority (P0-P2) and phase alignment with the governing spec.

**Methodology:**
- Tests are crystallized understanding, not coverage theater
- Each test specifies behavior, not implementation
- Property tests preferred over example tests where feasible
- Spec gaps discovered during testing trigger SDD UPDATE cycle

---

## Test Priority Levels

| Priority | Description | Gate |
|----------|-------------|------|
| **P0** | Core functionality - must pass for any release | Blocks merge |
| **P1** | Expected behavior - should pass for stable release | Blocks stable tag |
| **P2** | Edge cases & hardening - nice to have | Advisory |

---

## Phase 1: Foundation (MVP)

### 1.1 Random Number Generation (P0)

**Spec Requirement:** Browser entropy via `crypto.getRandomValues()`, panic if unavailable.

```rust
// Specification tests - these define the contract

#[wasm_bindgen_test]
fn spec_random_bytes_returns_requested_length() {
    let bytes = random_bytes(32);
    assert_eq!(bytes.len(), 32);
}

#[wasm_bindgen_test]
fn spec_random_bytes_unique_per_call() {
    let a = random_bytes(32);
    let b = random_bytes(32);
    assert_ne!(a, b);  // Probabilistically guaranteed (2^-256 collision)
}

#[wasm_bindgen_test]
fn spec_random_bytes_zero_length_returns_empty() {
    let bytes = random_bytes(0);
    assert_eq!(bytes.len(), 0);
}

#[wasm_bindgen_test]
fn spec_random_bytes_large_request() {
    let bytes = random_bytes(1024 * 1024);  // 1MB
    assert_eq!(bytes.len(), 1024 * 1024);
}
```

**Property Tests:**
```rust
#[wasm_bindgen_test]
fn property_random_bytes_length_matches_request() {
    for len in [0, 1, 16, 32, 64, 128, 256, 1024] {
        assert_eq!(random_bytes(len).len(), len);
    }
}
```

### 1.2 Hash Functions (P0)

**Spec Requirement:** SHA-256, SHA-3-256, BLAKE3 with correct output.

```rust
// Known Answer Tests (KAT) - NIST/reference vectors

#[wasm_bindgen_test]
fn spec_sha256_empty_input() {
    let hash = sha256(&[]);
    assert_eq!(
        hex::encode(&hash),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[wasm_bindgen_test]
fn spec_sha256_hello() {
    let hash = sha256(b"hello");
    assert_eq!(
        hex::encode(&hash),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[wasm_bindgen_test]
fn spec_sha3_256_empty_input() {
    let hash = sha3_256(&[]);
    assert_eq!(
        hex::encode(&hash),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[wasm_bindgen_test]
fn spec_sha3_256_hello() {
    let hash = sha3_256(b"hello");
    assert_eq!(
        hex::encode(&hash),
        "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
    );
}

#[wasm_bindgen_test]
fn spec_blake3_empty_input() {
    let hash = blake3(&[]);
    assert_eq!(
        hex::encode(&hash),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

#[wasm_bindgen_test]
fn spec_blake3_hello() {
    let hash = blake3(b"hello");
    assert_eq!(
        hex::encode(&hash),
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
    );
}
```

**Property Tests:**
```rust
#[wasm_bindgen_test]
fn property_sha256_output_length() {
    for input in [&[][..], b"a", b"hello", &[0u8; 1000]] {
        assert_eq!(sha256(input).len(), 32);
    }
}

#[wasm_bindgen_test]
fn property_sha256_deterministic() {
    let input = b"determinism test";
    assert_eq!(sha256(input), sha256(input));
}

#[wasm_bindgen_test]
fn property_blake3_output_length() {
    for input in [&[][..], b"a", b"hello", &[0u8; 1000]] {
        assert_eq!(blake3(input).len(), 32);
    }
}
```

### 1.3 Symmetric Encryption - AES-GCM (P0)

**Spec Requirement:** AES-256-GCM encrypt/decrypt with authentication.

```rust
#[wasm_bindgen_test]
fn spec_aes_gcm_roundtrip() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"secret message";

    let cipher = AesGcm::new(&key).unwrap();
    let ciphertext = cipher.encrypt(plaintext, &nonce, None).unwrap();
    let decrypted = cipher.decrypt(&ciphertext, &nonce, None).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn spec_aes_gcm_with_aad() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"secret message";
    let aad = b"additional authenticated data";

    let cipher = AesGcm::new(&key).unwrap();
    let ciphertext = cipher.encrypt(plaintext, &nonce, Some(aad)).unwrap();
    let decrypted = cipher.decrypt(&ciphertext, &nonce, Some(aad)).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn spec_aes_gcm_authentication_failure_on_tamper() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"secret message";

    let cipher = AesGcm::new(&key).unwrap();
    let mut ciphertext = cipher.encrypt(plaintext, &nonce, None).unwrap();

    // Tamper with ciphertext
    ciphertext[0] ^= 0xff;

    // Should fail authentication
    let result = cipher.decrypt(&ciphertext, &nonce, None);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn spec_aes_gcm_wrong_aad_fails() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"secret message";
    let aad = b"correct aad";
    let wrong_aad = b"wrong aad";

    let cipher = AesGcm::new(&key).unwrap();
    let ciphertext = cipher.encrypt(plaintext, &nonce, Some(aad)).unwrap();

    let result = cipher.decrypt(&ciphertext, &nonce, Some(wrong_aad));
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn spec_aes_gcm_invalid_key_length() {
    let short_key = random_bytes(16);  // AES-128, but we require AES-256
    let result = AesGcm::new(&short_key);
    // Behavior TBD: error or accept AES-128?
}

#[wasm_bindgen_test]
fn spec_aes_gcm_invalid_nonce_length() {
    let key = random_bytes(32);
    let short_nonce = random_bytes(8);  // Should be 12 bytes

    let cipher = AesGcm::new(&key).unwrap();
    let result = cipher.encrypt(b"test", &short_nonce, None);
    assert!(result.is_err());
}
```

### 1.4 Symmetric Encryption - ChaCha20-Poly1305 (P0)

**Spec Requirement:** ChaCha20-Poly1305 encrypt/decrypt with authentication.

```rust
#[wasm_bindgen_test]
fn spec_chacha20poly1305_roundtrip() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"secret message";

    let cipher = ChaCha20Poly1305::new(&key).unwrap();
    let ciphertext = cipher.encrypt(plaintext, &nonce, None).unwrap();
    let decrypted = cipher.decrypt(&ciphertext, &nonce, None).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn spec_chacha20poly1305_with_aad() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"secret message";
    let aad = b"additional authenticated data";

    let cipher = ChaCha20Poly1305::new(&key).unwrap();
    let ciphertext = cipher.encrypt(plaintext, &nonce, Some(aad)).unwrap();
    let decrypted = cipher.decrypt(&ciphertext, &nonce, Some(aad)).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn spec_chacha20poly1305_authentication_failure_on_tamper() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"secret message";

    let cipher = ChaCha20Poly1305::new(&key).unwrap();
    let mut ciphertext = cipher.encrypt(plaintext, &nonce, None).unwrap();

    ciphertext[0] ^= 0xff;

    let result = cipher.decrypt(&ciphertext, &nonce, None);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn spec_chacha20poly1305_empty_plaintext() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);
    let plaintext = b"";

    let cipher = ChaCha20Poly1305::new(&key).unwrap();
    let ciphertext = cipher.encrypt(plaintext, &nonce, None).unwrap();

    // Ciphertext should be 16 bytes (Poly1305 tag only)
    assert_eq!(ciphertext.len(), 16);

    let decrypted = cipher.decrypt(&ciphertext, &nonce, None).unwrap();
    assert_eq!(decrypted, plaintext);
}
```

### 1.5 Key Derivation (P1)

**Spec Requirement:** Argon2id for password hashing, HKDF-SHA256 for key derivation.

```rust
#[wasm_bindgen_test]
fn spec_argon2id_produces_key() {
    let password = b"correct horse battery staple";
    let salt = random_bytes(16);

    let key = argon2id(password, &salt, None).unwrap();
    assert_eq!(key.len(), 32);  // Default output length
}

#[wasm_bindgen_test]
fn spec_argon2id_deterministic_with_same_salt() {
    let password = b"password";
    let salt = b"fixed_salt_1234!";  // 16 bytes

    let key1 = argon2id(password, salt, None).unwrap();
    let key2 = argon2id(password, salt, None).unwrap();

    assert_eq!(key1, key2);
}

#[wasm_bindgen_test]
fn spec_argon2id_different_with_different_salt() {
    let password = b"password";
    let salt1 = random_bytes(16);
    let salt2 = random_bytes(16);

    let key1 = argon2id(password, &salt1, None).unwrap();
    let key2 = argon2id(password, &salt2, None).unwrap();

    assert_ne!(key1, key2);
}

#[wasm_bindgen_test]
fn spec_hkdf_sha256_produces_key() {
    let ikm = random_bytes(32);
    let salt = random_bytes(32);
    let info = b"application context";

    let key = hkdf_sha256(&ikm, &salt, info, 32).unwrap();
    assert_eq!(key.len(), 32);
}

#[wasm_bindgen_test]
fn spec_hkdf_sha256_deterministic() {
    let ikm = b"input key material";
    let salt = b"salt value here!";  // 16 bytes
    let info = b"context";

    let key1 = hkdf_sha256(ikm, salt, info, 32).unwrap();
    let key2 = hkdf_sha256(ikm, salt, info, 32).unwrap();

    assert_eq!(key1, key2);
}

#[wasm_bindgen_test]
fn spec_hkdf_sha256_variable_length() {
    let ikm = random_bytes(32);
    let salt = random_bytes(32);
    let info = b"test";

    for len in [16, 32, 64, 128] {
        let key = hkdf_sha256(&ikm, &salt, info, len).unwrap();
        assert_eq!(key.len(), len);
    }
}
```

### 1.6 Memory Safety (P1)

**Spec Requirement:** Secrets zeroized on drop.

```rust
// Note: These tests verify API contracts. Actual zeroization
// is difficult to test in WASM due to memory model constraints.

#[wasm_bindgen_test]
fn spec_cipher_can_be_dropped() {
    let key = random_bytes(32);
    {
        let cipher = AesGcm::new(&key).unwrap();
        let _ = cipher.encrypt(b"test", &random_bytes(12), None);
        // cipher dropped here
    }
    // No panic, no leak
}

#[wasm_bindgen_test]
fn spec_explicit_free_available() {
    let key = random_bytes(32);
    let cipher = AesGcm::new(&key).unwrap();
    cipher.free();  // Explicit cleanup for JS interop
    // Using cipher after free should... (TBD: panic or no-op?)
}
```

### 1.7 Error Handling (P1)

**Spec Requirement:** Errors surface as CryptoError with code.

```rust
#[wasm_bindgen_test]
fn spec_error_has_code() {
    let key = random_bytes(32);
    let nonce = random_bytes(12);

    let cipher = AesGcm::new(&key).unwrap();
    let ciphertext = cipher.encrypt(b"test", &nonce, None).unwrap();

    // Tamper
    let mut bad = ciphertext.clone();
    bad[0] ^= 0xff;

    match cipher.decrypt(&bad, &nonce, None) {
        Err(e) => {
            assert_eq!(e.code(), "DECRYPTION_FAILED");
        }
        Ok(_) => panic!("Expected error"),
    }
}

#[wasm_bindgen_test]
fn spec_invalid_key_error() {
    let bad_key = random_bytes(15);  // Wrong length
    match AesGcm::new(&bad_key) {
        Err(e) => {
            assert_eq!(e.code(), "INVALID_KEY");
        }
        Ok(_) => panic!("Expected error"),
    }
}
```

---

## Phase 2: Asymmetric Cryptography

### 2.1 X25519 Key Exchange (P0)

```rust
#[wasm_bindgen_test]
fn spec_x25519_generate_keypair() {
    let keypair = X25519KeyPair::generate();
    assert_eq!(keypair.public_key().len(), 32);
}

#[wasm_bindgen_test]
fn spec_x25519_diffie_hellman() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    let shared_alice = alice.diffie_hellman(&bob.public_key());
    let shared_bob = bob.diffie_hellman(&alice.public_key());

    assert_eq!(shared_alice, shared_bob);
}

#[wasm_bindgen_test]
fn spec_x25519_shared_secret_length() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    let shared = alice.diffie_hellman(&bob.public_key());
    assert_eq!(shared.len(), 32);
}
```

### 2.2 Ed25519 Signatures (P0)

```rust
#[wasm_bindgen_test]
fn spec_ed25519_sign_verify() {
    let keypair = Ed25519KeyPair::generate();
    let message = b"test message";

    let signature = keypair.sign(message);
    assert!(Ed25519KeyPair::verify(&keypair.public_key(), message, &signature));
}

#[wasm_bindgen_test]
fn spec_ed25519_signature_length() {
    let keypair = Ed25519KeyPair::generate();
    let signature = keypair.sign(b"test");
    assert_eq!(signature.len(), 64);
}

#[wasm_bindgen_test]
fn spec_ed25519_public_key_length() {
    let keypair = Ed25519KeyPair::generate();
    assert_eq!(keypair.public_key().len(), 32);
}

#[wasm_bindgen_test]
fn spec_ed25519_wrong_message_fails() {
    let keypair = Ed25519KeyPair::generate();
    let signature = keypair.sign(b"original message");

    assert!(!Ed25519KeyPair::verify(
        &keypair.public_key(),
        b"different message",
        &signature
    ));
}

#[wasm_bindgen_test]
fn spec_ed25519_from_seed_deterministic() {
    let seed = random_bytes(32);

    let keypair1 = Ed25519KeyPair::from_seed(&seed);
    let keypair2 = Ed25519KeyPair::from_seed(&seed);

    assert_eq!(keypair1.public_key(), keypair2.public_key());
}
```

---

## Backend Parity Tests (P0)

These tests ensure both backends produce identical results:

```rust
#[cfg(all(feature = "backend-native", feature = "backend-rustcrypto"))]
mod parity_tests {
    // These run with both backends to verify identical behavior

    #[wasm_bindgen_test]
    fn parity_sha256() {
        let input = b"test vector for parity";
        let native = native_sha256(input);
        let rustcrypto = rustcrypto_sha256(input);
        assert_eq!(native, rustcrypto);
    }

    #[wasm_bindgen_test]
    fn parity_blake3() {
        let input = b"test vector for parity";
        let native = native_blake3(input);
        let rustcrypto = rustcrypto_blake3(input);
        assert_eq!(native, rustcrypto);
    }

    // ... etc for all algorithms
}
```

---

## Gap Tracking

| Gap ID | Discovery | Spec Impact | Resolution |
|--------|-----------|-------------|------------|
| *None yet* | | | |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-01-24 | Initial RED phase - spec tests defined |
