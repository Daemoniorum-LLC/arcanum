//! Fuzz target for XChaCha20-Poly1305
//! Tests the extended nonce variant with HChaCha20 subkey derivation

#![no_main]

use arcanum_symmetric::{Cipher, XChaCha20Poly1305Cipher};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // XChaCha20 uses 24-byte nonces
    if data.len() < 32 + 24 + 1 {
        return;
    }

    // Split input into key, nonce, and plaintext
    let key = &data[..32];
    let nonce = &data[32..56];
    let plaintext = &data[56..];

    // Test encrypt/decrypt roundtrip
    if let Ok(ciphertext) = XChaCha20Poly1305Cipher::encrypt(key, nonce, plaintext, None) {
        let decrypted = XChaCha20Poly1305Cipher::decrypt(key, nonce, &ciphertext, None);
        assert!(decrypted.is_ok(), "Decryption of valid ciphertext should succeed");
        assert_eq!(decrypted.unwrap(), plaintext, "Decrypted data should match plaintext");
    }

    // Test decryption of arbitrary ciphertext (should fail gracefully)
    if plaintext.len() >= 16 {
        let _ = XChaCha20Poly1305Cipher::decrypt(key, nonce, plaintext, None);
    }

    // Test with associated data
    if data.len() >= 32 + 24 + 16 + 1 {
        let aad = &data[56..72];
        let plaintext = &data[72..];
        if let Ok(ciphertext) = XChaCha20Poly1305Cipher::encrypt(key, nonce, plaintext, Some(aad)) {
            let decrypted = XChaCha20Poly1305Cipher::decrypt(key, nonce, &ciphertext, Some(aad));
            assert!(decrypted.is_ok());

            // Wrong AAD should fail
            let mut wrong_aad = [0u8; 16];
            for (i, &b) in aad.iter().enumerate() {
                wrong_aad[i] = b ^ 0xFF;
            }
            let result = XChaCha20Poly1305Cipher::decrypt(key, nonce, &ciphertext, Some(&wrong_aad));
            assert!(result.is_err(), "Decryption with wrong AAD should fail");
        }
    }

    // Test that different nonces produce different ciphertexts (HChaCha20 derivation)
    if data.len() >= 32 + 24 + 24 + 1 {
        let nonce2 = &data[56..80];
        let plaintext = &data[80..];
        if !plaintext.is_empty() && nonce != nonce2 {
            let ct1 = XChaCha20Poly1305Cipher::encrypt(key, nonce, plaintext, None);
            let ct2 = XChaCha20Poly1305Cipher::encrypt(key, nonce2, plaintext, None);
            if let (Ok(c1), Ok(c2)) = (ct1, ct2) {
                // Different nonces should produce different ciphertexts
                assert_ne!(c1, c2, "Different nonces must produce different ciphertexts");
            }
        }
    }
});
