//! Fuzz target for AES-256-GCM-SIV
//! Tests the nonce-misuse resistant AEAD variant

#![no_main]

use arcanum_symmetric::{Aes256GcmSiv, Cipher};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // GCM-SIV uses 12-byte nonces
    if data.len() < 32 + 12 + 1 {
        return;
    }

    // Split input into key, nonce, and plaintext
    let key = &data[..32];
    let nonce = &data[32..44];
    let plaintext = &data[44..];

    // Test encrypt/decrypt roundtrip
    if let Ok(ciphertext) = Aes256GcmSiv::encrypt(key, nonce, plaintext, None) {
        let decrypted = Aes256GcmSiv::decrypt(key, nonce, &ciphertext, None);
        assert!(decrypted.is_ok(), "Decryption of valid ciphertext should succeed");
        assert_eq!(decrypted.unwrap(), plaintext, "Decrypted data should match plaintext");
    }

    // Test decryption of arbitrary ciphertext (should fail gracefully)
    if plaintext.len() >= 16 {
        let _ = Aes256GcmSiv::decrypt(key, nonce, plaintext, None);
    }

    // Test nonce-misuse resistance property: same key+nonce+plaintext = same ciphertext
    // (GCM-SIV is deterministic)
    if let (Ok(ct1), Ok(ct2)) = (
        Aes256GcmSiv::encrypt(key, nonce, plaintext, None),
        Aes256GcmSiv::encrypt(key, nonce, plaintext, None),
    ) {
        assert_eq!(ct1, ct2, "GCM-SIV must be deterministic (nonce-misuse resistance)");
    }

    // Test with associated data
    if data.len() >= 32 + 12 + 16 + 1 {
        let aad = &data[44..60];
        let plaintext = &data[60..];
        if let Ok(ciphertext) = Aes256GcmSiv::encrypt(key, nonce, plaintext, Some(aad)) {
            let decrypted = Aes256GcmSiv::decrypt(key, nonce, &ciphertext, Some(aad));
            assert!(decrypted.is_ok());

            // Wrong AAD should fail
            let mut wrong_aad = [0u8; 16];
            for (i, &b) in aad.iter().enumerate() {
                wrong_aad[i] = b ^ 0xFF;
            }
            let result = Aes256GcmSiv::decrypt(key, nonce, &ciphertext, Some(&wrong_aad));
            assert!(result.is_err(), "Decryption with wrong AAD should fail");
        }
    }

    // Test that same key+nonce with different plaintext produces different ciphertexts
    if data.len() >= 32 + 12 + 2 {
        let pt1 = &data[44..45];
        let pt2 = &data[45..46];
        if pt1 != pt2 {
            let ct1 = Aes256GcmSiv::encrypt(key, nonce, pt1, None);
            let ct2 = Aes256GcmSiv::encrypt(key, nonce, pt2, None);
            if let (Ok(c1), Ok(c2)) = (ct1, ct2) {
                assert_ne!(c1, c2, "Different plaintexts must produce different ciphertexts");
            }
        }
    }
});
