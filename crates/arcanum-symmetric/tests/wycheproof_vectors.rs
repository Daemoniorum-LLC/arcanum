//! Wycheproof-Style Test Vectors for Symmetric Ciphers
//!
//! These tests are inspired by Google's Project Wycheproof methodology,
//! which focuses on edge cases and implementation bugs in cryptographic libraries.
//!
//! Categories tested:
//! - Edge cases at block boundaries (0, 1, 15, 16, 17, 31, 32, 63, 64, 65 bytes)
//! - Invalid tag handling (must reject modified tags)
//! - Empty message/AAD handling
//! - Authentication failure detection
//! - Large message handling

#![allow(clippy::needless_range_loop)]

use arcanum_symmetric::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Cipher, Cipher};

// ═══════════════════════════════════════════════════════════════════════════════
// AES-GCM Block Boundary Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod aes_gcm_boundaries {
    use super::*;

    fn test_key() -> Vec<u8> {
        hex::decode(
            "feffe9928665731c6d6a8f9467308308\
             feffe9928665731c6d6a8f9467308308",
        )
        .unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        hex::decode("cafebabefacedbaddecaf888").unwrap()
    }

    /// 0-byte message (empty)
    #[test]
    fn aes256_gcm_0_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();
        assert_eq!(ct.len(), 16, "Empty message should produce tag only");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "Empty message roundtrip failed");
    }

    /// 1-byte message
    #[test]
    fn aes256_gcm_1_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 1];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 1 + 16, "1-byte message wrong output length");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "1-byte message roundtrip failed");
    }

    /// 15-byte message (one byte under block boundary)
    #[test]
    fn aes256_gcm_15_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 15];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 15 + 16, "15-byte message wrong output length");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "15-byte message roundtrip failed");
    }

    /// 16-byte message (exactly one AES block)
    #[test]
    fn aes256_gcm_16_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 16];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 16 + 16, "16-byte message wrong output length");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "16-byte message roundtrip failed");
    }

    /// 17-byte message (one byte over block boundary)
    #[test]
    fn aes256_gcm_17_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 17];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 17 + 16, "17-byte message wrong output length");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "17-byte message roundtrip failed");
    }

    /// 31-byte message (one byte under two blocks)
    #[test]
    fn aes256_gcm_31_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 31];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 31 + 16, "31-byte message wrong output length");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "31-byte message roundtrip failed");
    }

    /// 32-byte message (exactly two AES blocks)
    #[test]
    fn aes256_gcm_32_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 32];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 32 + 16, "32-byte message wrong output length");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "32-byte message roundtrip failed");
    }

    /// 33-byte message (one byte over two blocks)
    #[test]
    fn aes256_gcm_33_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 33];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 33 + 16, "33-byte message wrong output length");

        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "33-byte message roundtrip failed");
    }

    /// 255-byte message
    #[test]
    fn aes256_gcm_255_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 255];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "255-byte message roundtrip failed");
    }

    /// 256-byte message (power of 2)
    #[test]
    fn aes256_gcm_256_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 256];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "256-byte message roundtrip failed");
    }

    /// 4096-byte message (4KB)
    #[test]
    fn aes256_gcm_4kb_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 4096];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "4KB message roundtrip failed");
    }

    /// 65536-byte message (64KB)
    #[test]
    fn aes256_gcm_64kb_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 65536];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg, "64KB message roundtrip failed");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AES-GCM AAD Boundary Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod aes_gcm_aad_boundaries {
    use super::*;

    fn test_key() -> Vec<u8> {
        hex::decode(
            "feffe9928665731c6d6a8f9467308308\
             feffe9928665731c6d6a8f9467308308",
        )
        .unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        hex::decode("cafebabefacedbaddecaf888").unwrap()
    }

    /// Empty message with 1-byte AAD
    #[test]
    fn aes256_gcm_empty_msg_1_byte_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];
        let aad = vec![0x42u8; 1];

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty message with 16-byte AAD (one block)
    #[test]
    fn aes256_gcm_empty_msg_16_byte_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];
        let aad = vec![0x42u8; 16];

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty message with 255-byte AAD
    #[test]
    fn aes256_gcm_empty_msg_255_byte_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];
        let aad = vec![0x42u8; 255];

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty message with 256-byte AAD
    #[test]
    fn aes256_gcm_empty_msg_256_byte_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];
        let aad = vec![0x42u8; 256];

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// 32-byte message with 32-byte AAD
    #[test]
    fn aes256_gcm_32_msg_32_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x55u8; 32];
        let aad = vec![0xAAu8; 32];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Large message with large AAD
    #[test]
    fn aes256_gcm_4kb_msg_4kb_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x55u8; 4096];
        let aad = vec![0xAAu8; 4096];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AES-GCM Authentication Failure Tests (MUST reject)
// ═══════════════════════════════════════════════════════════════════════════════

mod aes_gcm_auth_failures {
    use super::*;

    fn test_key() -> Vec<u8> {
        hex::decode(
            "feffe9928665731c6d6a8f9467308308\
             feffe9928665731c6d6a8f9467308308",
        )
        .unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        hex::decode("cafebabefacedbaddecaf888").unwrap()
    }

    /// Modified tag (last byte flipped) - MUST fail
    #[test]
    fn aes256_gcm_modified_tag_last_byte() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for authentication";

        let mut ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip last byte of tag
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified tag (last byte) must fail");
    }

    /// Modified tag (first byte flipped) - MUST fail
    #[test]
    fn aes256_gcm_modified_tag_first_byte() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for authentication";

        let mut ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip first byte of tag (byte after ciphertext)
        let tag_start = ct.len() - 16;
        ct[tag_start] ^= 0xFF;

        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified tag (first byte) must fail");
    }

    /// All-zero tag - MUST fail
    #[test]
    fn aes256_gcm_zero_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let mut ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Zero out the tag
        let tag_start = ct.len() - 16;
        for i in tag_start..ct.len() {
            ct[i] = 0;
        }

        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Zero tag must fail");
    }

    /// All-ones tag - MUST fail
    #[test]
    fn aes256_gcm_ones_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let mut ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Set tag to all 0xFF
        let tag_start = ct.len() - 16;
        for i in tag_start..ct.len() {
            ct[i] = 0xFF;
        }

        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "All-ones tag must fail");
    }

    /// Modified ciphertext (first byte) - MUST fail
    #[test]
    fn aes256_gcm_modified_ciphertext_first() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for ciphertext modification";

        let mut ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip first byte of ciphertext
        ct[0] ^= 0xFF;

        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, None);
        assert!(
            result.is_err(),
            "Modified ciphertext (first byte) must fail"
        );
    }

    /// Modified ciphertext (middle byte) - MUST fail
    #[test]
    fn aes256_gcm_modified_ciphertext_middle() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for ciphertext modification testing";

        let mut ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip a middle byte (in ciphertext, not tag)
        let mid = (ct.len() - 16) / 2;
        ct[mid] ^= 0xFF;

        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified ciphertext (middle) must fail");
    }

    /// Modified AAD - MUST fail
    #[test]
    fn aes256_gcm_modified_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";
        let aad = b"Authenticated data";
        let wrong_aad = b"Authenticated dota"; // 'a' -> 'o'

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, Some(aad)).unwrap();

        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(wrong_aad));
        assert!(result.is_err(), "Modified AAD must fail");
    }

    /// Missing AAD when expected - MUST fail
    #[test]
    fn aes256_gcm_missing_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";
        let aad = b"Required authenticated data";

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, Some(aad)).unwrap();

        // Decrypt with no AAD
        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Missing required AAD must fail");
    }

    /// Extra AAD when none expected - MUST fail
    #[test]
    fn aes256_gcm_extra_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";
        let extra_aad = b"Unexpected authenticated data";

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Decrypt with unexpected AAD
        let result = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(extra_aad));
        assert!(result.is_err(), "Extra unexpected AAD must fail");
    }

    /// Wrong key - MUST fail
    #[test]
    fn aes256_gcm_wrong_key() {
        let key = test_key();
        let wrong_key = vec![0u8; 32];
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        let result = Aes256Gcm::decrypt(&wrong_key, &nonce, &ct, None);
        assert!(result.is_err(), "Wrong key must fail");
    }

    /// Wrong nonce - MUST fail
    #[test]
    fn aes256_gcm_wrong_nonce() {
        let key = test_key();
        let nonce = test_nonce();
        let wrong_nonce = vec![0u8; 12];
        let msg = b"Test message";

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        let result = Aes256Gcm::decrypt(&key, &wrong_nonce, &ct, None);
        assert!(result.is_err(), "Wrong nonce must fail");
    }

    /// Empty ciphertext (no tag) - MUST fail
    #[test]
    fn aes256_gcm_empty_ciphertext() {
        let key = test_key();
        let nonce = test_nonce();
        let empty: &[u8] = &[];

        let result = Aes256Gcm::decrypt(&key, &nonce, empty, None);
        assert!(result.is_err(), "Empty ciphertext (no tag) must fail");
    }

    /// Truncated tag - MUST fail
    #[test]
    fn aes256_gcm_truncated_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = Aes256Gcm::encrypt(&key, &nonce, msg, None).unwrap();

        // Truncate the tag by 1 byte
        let truncated = &ct[..ct.len() - 1];

        let result = Aes256Gcm::decrypt(&key, &nonce, truncated, None);
        assert!(result.is_err(), "Truncated tag must fail");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ChaCha20-Poly1305 Block Boundary Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod chacha20_poly1305_boundaries {
    use super::*;

    fn test_key() -> Vec<u8> {
        hex::decode(
            "808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        hex::decode("070000004041424344454647").unwrap()
    }

    /// 0-byte message (empty)
    #[test]
    fn chacha20_poly1305_0_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();
        assert_eq!(ct.len(), 16, "Empty message should produce tag only");

        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 1-byte message
    #[test]
    fn chacha20_poly1305_1_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 1];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 1 + 16);

        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 63-byte message (one under ChaCha block)
    #[test]
    fn chacha20_poly1305_63_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 63];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 63 + 16);

        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 64-byte message (exactly one ChaCha block)
    #[test]
    fn chacha20_poly1305_64_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 64];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 64 + 16);

        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 65-byte message (one over ChaCha block)
    #[test]
    fn chacha20_poly1305_65_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 65];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        assert_eq!(ct.len(), 65 + 16);

        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 127-byte message
    #[test]
    fn chacha20_poly1305_127_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 127];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 128-byte message (two ChaCha blocks)
    #[test]
    fn chacha20_poly1305_128_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 128];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 256-byte message (four ChaCha blocks)
    #[test]
    fn chacha20_poly1305_256_byte_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 256];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 4096-byte message (64 ChaCha blocks)
    #[test]
    fn chacha20_poly1305_4kb_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 4096];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// 65536-byte message (64KB)
    #[test]
    fn chacha20_poly1305_64kb_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 65536];

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ChaCha20-Poly1305 Authentication Failure Tests (MUST reject)
// ═══════════════════════════════════════════════════════════════════════════════

mod chacha20_poly1305_auth_failures {
    use super::*;

    fn test_key() -> Vec<u8> {
        hex::decode(
            "808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        hex::decode("070000004041424344454647").unwrap()
    }

    /// Modified tag - MUST fail
    #[test]
    fn chacha20_poly1305_modified_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for ChaCha20-Poly1305";

        let mut ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip last byte of tag
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified tag must fail");
    }

    /// Zero tag - MUST fail
    #[test]
    fn chacha20_poly1305_zero_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let mut ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        // Zero out the tag
        let tag_start = ct.len() - 16;
        for i in tag_start..ct.len() {
            ct[i] = 0;
        }

        let result = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Zero tag must fail");
    }

    /// Modified ciphertext - MUST fail
    #[test]
    fn chacha20_poly1305_modified_ciphertext() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for ciphertext modification";

        let mut ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip first byte of ciphertext
        ct[0] ^= 0xFF;

        let result = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified ciphertext must fail");
    }

    /// Modified AAD - MUST fail
    #[test]
    fn chacha20_poly1305_modified_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";
        let aad = b"Authenticated data";
        let wrong_aad = b"Xuthenticated data";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, Some(aad)).unwrap();

        let result = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, Some(wrong_aad));
        assert!(result.is_err(), "Modified AAD must fail");
    }

    /// Wrong key - MUST fail
    #[test]
    fn chacha20_poly1305_wrong_key() {
        let key = test_key();
        let wrong_key = vec![0u8; 32];
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        let result = ChaCha20Poly1305Cipher::decrypt(&wrong_key, &nonce, &ct, None);
        assert!(result.is_err(), "Wrong key must fail");
    }

    /// Wrong nonce - MUST fail
    #[test]
    fn chacha20_poly1305_wrong_nonce() {
        let key = test_key();
        let nonce = test_nonce();
        let wrong_nonce = vec![0u8; 12];
        let msg = b"Test message";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        let result = ChaCha20Poly1305Cipher::decrypt(&key, &wrong_nonce, &ct, None);
        assert!(result.is_err(), "Wrong nonce must fail");
    }

    /// Truncated ciphertext - MUST fail
    #[test]
    fn chacha20_poly1305_truncated() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        // Truncate by 1 byte
        let truncated = &ct[..ct.len() - 1];

        let result = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, truncated, None);
        assert!(result.is_err(), "Truncated ciphertext must fail");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Special Pattern Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod special_patterns {
    use super::*;

    /// All-zeros pattern
    #[test]
    fn all_zeros_aes256_gcm() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let msg = [0u8; 64];
        let aad = [0u8; 16];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// All-ones pattern
    #[test]
    fn all_ones_aes256_gcm() {
        let key = [0xFFu8; 32];
        let nonce = [0xFFu8; 12];
        let msg = [0xFFu8; 64];
        let aad = [0xFFu8; 16];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Alternating bits (0xAA/0x55)
    #[test]
    fn alternating_bits_aes256_gcm() {
        let key = [0xAAu8; 32];
        let nonce = [0x55u8; 12];
        let msg = vec![0xAAu8; 64];
        let aad = vec![0x55u8; 16];

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Sequential bytes (0x00, 0x01, 0x02, ...)
    #[test]
    fn sequential_bytes_aes256_gcm() {
        let key: Vec<u8> = (0..32).collect();
        let nonce: Vec<u8> = (0..12).collect();
        let msg: Vec<u8> = (0..=255).collect();
        let aad: Vec<u8> = (0..16).collect();

        let ct = Aes256Gcm::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = Aes256Gcm::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Same message, different nonces produce different output
    #[test]
    fn different_nonces_different_output() {
        let key = [0x42u8; 32];
        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];
        let msg = b"Same message for both";

        let ct1 = Aes256Gcm::encrypt(&key, &nonce1, msg, None).unwrap();
        let ct2 = Aes256Gcm::encrypt(&key, &nonce2, msg, None).unwrap();

        assert_ne!(
            ct1, ct2,
            "Different nonces must produce different ciphertexts"
        );
    }

    /// Same nonce, different messages produce different output
    #[test]
    fn different_messages_different_output() {
        let key = [0x42u8; 32];
        let nonce = [0x42u8; 12];
        let msg1 = b"First message";
        let msg2 = b"Second message";

        let ct1 = Aes256Gcm::encrypt(&key, &nonce, msg1, None).unwrap();
        let ct2 = Aes256Gcm::encrypt(&key, &nonce, msg2, None).unwrap();

        assert_ne!(
            ct1, ct2,
            "Different messages must produce different ciphertexts"
        );
    }

    /// Deterministic encryption (same inputs = same output)
    #[test]
    fn deterministic_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0x42u8; 12];
        let msg = b"Same message";
        let aad = b"Same AAD";

        let ct1 = Aes256Gcm::encrypt(&key, &nonce, msg, Some(aad)).unwrap();
        let ct2 = Aes256Gcm::encrypt(&key, &nonce, msg, Some(aad)).unwrap();

        assert_eq!(ct1, ct2, "Same inputs must produce same ciphertext");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AES-128-GCM Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod aes128_gcm_tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        hex::decode("feffe9928665731c6d6a8f9467308308").unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        hex::decode("cafebabefacedbaddecaf888").unwrap()
    }

    /// Basic roundtrip
    #[test]
    fn aes128_gcm_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for AES-128-GCM";

        let ct = Aes128Gcm::encrypt(&key, &nonce, msg, None).unwrap();
        let pt = Aes128Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty message
    #[test]
    fn aes128_gcm_empty() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];

        let ct = Aes128Gcm::encrypt(&key, &nonce, msg, None).unwrap();
        assert_eq!(ct.len(), 16);

        let pt = Aes128Gcm::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// With AAD
    #[test]
    fn aes128_gcm_with_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Message";
        let aad = b"Additional data";

        let ct = Aes128Gcm::encrypt(&key, &nonce, msg, Some(aad)).unwrap();
        let pt = Aes128Gcm::decrypt(&key, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Invalid key length rejected
    #[test]
    fn aes128_gcm_invalid_key_length() {
        let short_key = vec![0u8; 8]; // Too short
        let nonce = test_nonce();

        let result = Aes128Gcm::encrypt(&short_key, &nonce, b"test", None);
        assert!(result.is_err(), "Invalid key length must be rejected");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 5.3: AES-256-GCM-SIV Tests
// GCM-SIV provides nonce-misuse resistance: same nonce + same message = same ciphertext
// (deterministic encryption), but different messages with same nonce remain secure.
// ═══════════════════════════════════════════════════════════════════════════════

mod aes256_gcm_siv_tests {
    use arcanum_symmetric::{Aes256GcmSiv, Cipher};

    fn test_key() -> Vec<u8> {
        hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        hex::decode("030000000000000000000000").unwrap()
    }

    /// Basic roundtrip
    #[test]
    fn aes256_gcm_siv_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for AES-256-GCM-SIV";

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();
        let pt = Aes256GcmSiv::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty message
    #[test]
    fn aes256_gcm_siv_empty_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();
        assert_eq!(ct.len(), 16, "Empty message should produce 16-byte tag");

        let pt = Aes256GcmSiv::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// NONCE-MISUSE RESISTANCE: Same nonce + same message = same ciphertext (deterministic)
    /// This is the key property of GCM-SIV that distinguishes it from regular GCM.
    #[test]
    fn aes256_gcm_siv_deterministic_encryption() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Same message encrypted twice";

        let ct1 = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();
        let ct2 = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();

        // GCM-SIV is deterministic: same inputs produce same output
        assert_eq!(
            ct1, ct2,
            "GCM-SIV must be deterministic (nonce-misuse resistance)"
        );
    }

    /// NONCE-MISUSE RESISTANCE: Same nonce + different message = different ciphertext
    /// Unlike regular GCM, this remains secure (doesn't leak the poly key).
    #[test]
    fn aes256_gcm_siv_different_messages_same_nonce() {
        let key = test_key();
        let nonce = test_nonce();
        let msg1 = b"First message";
        let msg2 = b"Second message";

        let ct1 = Aes256GcmSiv::encrypt(&key, &nonce, msg1, None).unwrap();
        let ct2 = Aes256GcmSiv::encrypt(&key, &nonce, msg2, None).unwrap();

        // Different messages produce different ciphertexts
        assert_ne!(ct1, ct2, "Different messages must produce different ciphertexts");
    }

    /// With AAD
    #[test]
    fn aes256_gcm_siv_with_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Message with AAD";
        let aad = b"Additional authenticated data";

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, Some(aad)).unwrap();
        let pt = Aes256GcmSiv::decrypt(&key, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Modified tag - MUST fail
    #[test]
    fn aes256_gcm_siv_modified_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let mut ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip last byte of tag
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = Aes256GcmSiv::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified tag must fail");
    }

    /// Modified ciphertext - MUST fail
    #[test]
    fn aes256_gcm_siv_modified_ciphertext() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for modification";

        let mut ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();

        // Flip first byte of ciphertext
        ct[0] ^= 0xFF;

        let result = Aes256GcmSiv::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified ciphertext must fail");
    }

    /// Modified AAD - MUST fail
    #[test]
    fn aes256_gcm_siv_modified_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";
        let aad = b"Original AAD";
        let wrong_aad = b"Modified AAD";

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, Some(aad)).unwrap();

        let result = Aes256GcmSiv::decrypt(&key, &nonce, &ct, Some(wrong_aad));
        assert!(result.is_err(), "Modified AAD must fail");
    }

    /// Wrong key - MUST fail
    #[test]
    fn aes256_gcm_siv_wrong_key() {
        let key = test_key();
        let wrong_key = vec![0u8; 32];
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();

        let result = Aes256GcmSiv::decrypt(&wrong_key, &nonce, &ct, None);
        assert!(result.is_err(), "Wrong key must fail");
    }

    /// Wrong nonce - MUST fail
    #[test]
    fn aes256_gcm_siv_wrong_nonce() {
        let key = test_key();
        let nonce = test_nonce();
        let wrong_nonce = vec![0u8; 12];
        let msg = b"Test message";

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();

        let result = Aes256GcmSiv::decrypt(&key, &wrong_nonce, &ct, None);
        assert!(result.is_err(), "Wrong nonce must fail");
    }

    /// Block boundary tests (GCM-SIV uses AES blocks)
    #[test]
    fn aes256_gcm_siv_block_boundaries() {
        let key = test_key();
        let nonce = test_nonce();

        for size in [1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256] {
            let msg = vec![0x42u8; size];
            let ct = Aes256GcmSiv::encrypt(&key, &nonce, &msg, None).unwrap();
            let pt = Aes256GcmSiv::decrypt(&key, &nonce, &ct, None).unwrap();
            assert_eq!(pt, msg, "Roundtrip failed for size={}", size);
        }
    }

    /// Large message
    #[test]
    fn aes256_gcm_siv_large_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 65536]; // 64KB

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = Aes256GcmSiv::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty ciphertext (no tag) - MUST fail
    #[test]
    fn aes256_gcm_siv_empty_ciphertext() {
        let key = test_key();
        let nonce = test_nonce();
        let empty: &[u8] = &[];

        let result = Aes256GcmSiv::decrypt(&key, &nonce, empty, None);
        assert!(result.is_err(), "Empty ciphertext must fail");
    }

    /// Truncated tag - MUST fail
    #[test]
    fn aes256_gcm_siv_truncated() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = Aes256GcmSiv::encrypt(&key, &nonce, msg, None).unwrap();
        let truncated = &ct[..ct.len() - 1];

        let result = Aes256GcmSiv::decrypt(&key, &nonce, truncated, None);
        assert!(result.is_err(), "Truncated ciphertext must fail");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 5.3: XChaCha20-Poly1305 Tests
// Extended nonce variant with 192-bit (24-byte) nonces via HChaCha20 subkey derivation.
// ═══════════════════════════════════════════════════════════════════════════════

mod xchacha20_poly1305_tests {
    use arcanum_symmetric::{Cipher, XChaCha20Poly1305Cipher};

    fn test_key() -> Vec<u8> {
        hex::decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()
    }

    fn test_nonce() -> Vec<u8> {
        // 24-byte (192-bit) nonce for XChaCha20
        hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap()
    }

    /// Basic roundtrip
    #[test]
    fn xchacha20_poly1305_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for XChaCha20-Poly1305";

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();
        let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty message
    #[test]
    fn xchacha20_poly1305_empty_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg: &[u8] = &[];

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();
        assert_eq!(ct.len(), 16, "Empty message should produce 16-byte tag");

        let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// NONCE DOMAIN SEPARATION: Different 24-byte nonces must produce different ciphertexts
    /// This verifies the HChaCha20 subkey derivation is working correctly.
    #[test]
    fn xchacha20_poly1305_nonce_domain_separation() {
        let key = test_key();
        let nonce_a = vec![0x01u8; 24];
        let nonce_b = vec![0x02u8; 24];
        let msg = b"Same message for both nonces";

        let ct_a = XChaCha20Poly1305Cipher::encrypt(&key, &nonce_a, msg, None).unwrap();
        let ct_b = XChaCha20Poly1305Cipher::encrypt(&key, &nonce_b, msg, None).unwrap();

        assert_ne!(
            ct_a, ct_b,
            "Different nonces must produce different ciphertexts (HChaCha20 derivation)"
        );
    }

    /// Verify 24-byte nonce is required
    #[test]
    fn xchacha20_poly1305_requires_24_byte_nonce() {
        let key = test_key();
        let short_nonce = vec![0u8; 12]; // 12-byte nonce is wrong for XChaCha20
        let msg = b"Test";

        let result = XChaCha20Poly1305Cipher::encrypt(&key, &short_nonce, msg, None);
        assert!(result.is_err(), "XChaCha20 must reject 12-byte nonce");
    }

    /// With AAD
    #[test]
    fn xchacha20_poly1305_with_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Message with additional data";
        let aad = b"Additional authenticated data";

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, Some(aad)).unwrap();
        let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty AAD
    #[test]
    fn xchacha20_poly1305_empty_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Message with empty AAD";
        let empty_aad: &[u8] = &[];

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, Some(empty_aad)).unwrap();
        let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, Some(empty_aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// Modified tag - MUST fail
    #[test]
    fn xchacha20_poly1305_modified_tag() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let mut ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        let last = ct.len() - 1;
        ct[last] ^= 0xFF;

        let result = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified tag must fail");
    }

    /// Modified ciphertext - MUST fail
    #[test]
    fn xchacha20_poly1305_modified_ciphertext() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message for modification";

        let mut ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        ct[0] ^= 0xFF;

        let result = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err(), "Modified ciphertext must fail");
    }

    /// Modified AAD - MUST fail
    #[test]
    fn xchacha20_poly1305_modified_aad() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";
        let aad = b"Original AAD";
        let wrong_aad = b"Modified AAD";

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, Some(aad)).unwrap();

        let result = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, Some(wrong_aad));
        assert!(result.is_err(), "Modified AAD must fail");
    }

    /// Wrong key - MUST fail
    #[test]
    fn xchacha20_poly1305_wrong_key() {
        let key = test_key();
        let wrong_key = vec![0u8; 32];
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        let result = XChaCha20Poly1305Cipher::decrypt(&wrong_key, &nonce, &ct, None);
        assert!(result.is_err(), "Wrong key must fail");
    }

    /// Wrong nonce - MUST fail
    #[test]
    fn xchacha20_poly1305_wrong_nonce() {
        let key = test_key();
        let nonce = test_nonce();
        let wrong_nonce = vec![0u8; 24];
        let msg = b"Test message";

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        let result = XChaCha20Poly1305Cipher::decrypt(&key, &wrong_nonce, &ct, None);
        assert!(result.is_err(), "Wrong nonce must fail");
    }

    /// Block boundary tests (ChaCha uses 64-byte blocks)
    #[test]
    fn xchacha20_poly1305_block_boundaries() {
        let key = test_key();
        let nonce = test_nonce();

        for size in [1, 63, 64, 65, 127, 128, 129, 255, 256, 512, 1024] {
            let msg = vec![0x42u8; size];
            let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
            let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
            assert_eq!(pt, msg, "Roundtrip failed for size={}", size);
        }
    }

    /// Large message
    #[test]
    fn xchacha20_poly1305_large_message() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = vec![0x42u8; 65536]; // 64KB

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, None).unwrap();
        let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, msg);
    }

    /// Empty ciphertext - MUST fail
    #[test]
    fn xchacha20_poly1305_empty_ciphertext() {
        let key = test_key();
        let nonce = test_nonce();
        let empty: &[u8] = &[];

        let result = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, empty, None);
        assert!(result.is_err(), "Empty ciphertext must fail");
    }

    /// Truncated tag - MUST fail
    #[test]
    fn xchacha20_poly1305_truncated() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Test message";

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();
        let truncated = &ct[..ct.len() - 1];

        let result = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, truncated, None);
        assert!(result.is_err(), "Truncated ciphertext must fail");
    }

    /// Deterministic encryption: same inputs = same output
    #[test]
    fn xchacha20_poly1305_deterministic() {
        let key = test_key();
        let nonce = test_nonce();
        let msg = b"Deterministic test message";

        let ct1 = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();
        let ct2 = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, msg, None).unwrap();

        assert_eq!(ct1, ct2, "Same inputs must produce same ciphertext");
    }

    /// All-zeros inputs
    #[test]
    fn xchacha20_poly1305_all_zeros() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 24];
        let msg = vec![0u8; 64];
        let aad = vec![0u8; 16];

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }

    /// All-ones inputs
    #[test]
    fn xchacha20_poly1305_all_ones() {
        let key = vec![0xFFu8; 32];
        let nonce = vec![0xFFu8; 24];
        let msg = vec![0xFFu8; 64];
        let aad = vec![0xFFu8; 16];

        let ct = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, &msg, Some(&aad)).unwrap();
        let pt = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ct, Some(&aad)).unwrap();
        assert_eq!(pt, msg);
    }
}
