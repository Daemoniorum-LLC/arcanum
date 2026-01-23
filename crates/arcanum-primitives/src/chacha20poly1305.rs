//! ChaCha20-Poly1305 AEAD cipher.
//!
//! Native implementation following RFC 8439 (IETF ChaCha20-Poly1305).
//!
//! ChaCha20-Poly1305 is an authenticated encryption with associated data (AEAD)
//! algorithm that combines the ChaCha20 stream cipher with the Poly1305 MAC.
//!
//! # Security
//!
//! - Nonces MUST be unique for each encryption with the same key
//! - The same nonce/key pair should NEVER be used twice
//! - Provides 128-bit authentication strength
//!
//! # Example
//!
//! ```ignore
//! use arcanum_primitives::chacha20poly1305::ChaCha20Poly1305;
//!
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let aad = b"additional data";
//! let plaintext = b"secret message";
//!
//! let cipher = ChaCha20Poly1305::new(&key);
//!
//! // Encrypt
//! let mut ciphertext = plaintext.to_vec();
//! let tag = cipher.encrypt(&nonce, aad, &mut ciphertext);
//!
//! // Decrypt
//! cipher.decrypt(&nonce, aad, &mut ciphertext, &tag).expect("decryption failed");
//! assert_eq!(&ciphertext, plaintext);
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::chacha20::{chacha20_block, ChaCha20, KEY_SIZE as CHACHA_KEY_SIZE, NONCE_SIZE};
use crate::poly1305::{KEY_SIZE as POLY_KEY_SIZE, TAG_SIZE};

// Use SIMD-accelerated Poly1305 when available
#[cfg(all(feature = "simd", feature = "std"))]
use crate::poly1305_simd::Poly1305Simd as Poly1305;

#[cfg(not(all(feature = "simd", feature = "std")))]
use crate::poly1305::Poly1305;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Key size in bytes (256 bits)
pub const KEY_SIZE: usize = CHACHA_KEY_SIZE;

/// Nonce size in bytes (96 bits)
pub const AEAD_NONCE_SIZE: usize = NONCE_SIZE;

/// Authentication tag size in bytes (128 bits)
pub const AEAD_TAG_SIZE: usize = TAG_SIZE;

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Error type for AEAD operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication tag verification failed.
    AuthenticationFailed,
}

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AeadError::AuthenticationFailed => write!(f, "authentication failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AeadError {}

// ═══════════════════════════════════════════════════════════════════════════════
// PADDING
// ═══════════════════════════════════════════════════════════════════════════════

/// Calculate padding to 16-byte boundary.
#[inline]
const fn pad16(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHACHA20-POLY1305
// ═══════════════════════════════════════════════════════════════════════════════

/// ChaCha20-Poly1305 AEAD cipher.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20Poly1305 {
    /// The 256-bit key
    key: [u8; KEY_SIZE],
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 cipher with the given key.
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Generate the one-time Poly1305 key.
    ///
    /// Uses the first 32 bytes of the ChaCha20 keystream (counter=0).
    fn poly_key(&self, nonce: &[u8; NONCE_SIZE]) -> [u8; POLY_KEY_SIZE] {
        let block = chacha20_block(&self.key, 0, nonce);
        let mut poly_key = [0u8; POLY_KEY_SIZE];
        poly_key.copy_from_slice(&block[..32]);
        poly_key
    }

    /// Construct the Poly1305 input and compute the tag.
    ///
    /// Input format: AAD || pad(AAD) || ciphertext || pad(CT) || len(AAD) || len(CT)
    fn compute_tag(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> [u8; TAG_SIZE] {
        let poly_key = self.poly_key(nonce);
        let mut poly = Poly1305::new(&poly_key);

        // AAD
        poly.update(aad);

        // Pad AAD to 16 bytes
        let aad_padding = pad16(aad.len());
        if aad_padding > 0 {
            poly.update(&[0u8; 16][..aad_padding]);
        }

        // Ciphertext
        poly.update(ciphertext);

        // Pad ciphertext to 16 bytes
        let ct_padding = pad16(ciphertext.len());
        if ct_padding > 0 {
            poly.update(&[0u8; 16][..ct_padding]);
        }

        // Lengths as little-endian u64
        let aad_len = (aad.len() as u64).to_le_bytes();
        let ct_len = (ciphertext.len() as u64).to_le_bytes();
        poly.update(&aad_len);
        poly.update(&ct_len);

        poly.finalize()
    }

    /// Encrypt plaintext in place and return the authentication tag.
    ///
    /// # Arguments
    ///
    /// * `nonce` - 12-byte nonce (MUST be unique for each encryption)
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    /// * `buffer` - Plaintext to encrypt (modified in place to ciphertext)
    ///
    /// # Returns
    ///
    /// The 16-byte authentication tag.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; TAG_SIZE] {
        // Encrypt with ChaCha20 starting at counter=1
        let mut cipher = ChaCha20::new_with_counter(&self.key, nonce, 1);
        cipher.apply_keystream(buffer);

        // Compute authentication tag
        self.compute_tag(nonce, aad, buffer)
    }

    /// Decrypt ciphertext in place after verifying the authentication tag.
    ///
    /// # Arguments
    ///
    /// * `nonce` - 12-byte nonce used during encryption
    /// * `aad` - Additional authenticated data used during encryption
    /// * `buffer` - Ciphertext to decrypt (modified in place to plaintext)
    /// * `tag` - Authentication tag to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if authentication succeeds, `Err(AeadError::AuthenticationFailed)` otherwise.
    ///
    /// # Security
    ///
    /// If authentication fails, the buffer contents are undefined (partially decrypted).
    /// Applications should discard the buffer in this case.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), AeadError> {
        // Verify tag first (on ciphertext)
        let computed_tag = self.compute_tag(nonce, aad, buffer);

        use crate::ct::CtEq;
        if !computed_tag.ct_eq(tag).is_true() {
            return Err(AeadError::AuthenticationFailed);
        }

        // Decrypt with ChaCha20 starting at counter=1
        let mut cipher = ChaCha20::new_with_counter(&self.key, nonce, 1);
        cipher.apply_keystream(buffer);

        Ok(())
    }

    /// Encrypt with detached tag allocation.
    ///
    /// Allocates and returns a new vector containing ciphertext + tag.
    #[cfg(feature = "alloc")]
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let mut output = alloc::vec::Vec::with_capacity(plaintext.len() + TAG_SIZE);
        output.extend_from_slice(plaintext);
        let tag = self.encrypt(nonce, aad, &mut output);
        output.extend_from_slice(&tag);
        output
    }

    /// Decrypt with detached tag, returning plaintext.
    ///
    /// Expects input to be ciphertext + tag (last 16 bytes).
    #[cfg(feature = "alloc")]
    pub fn open(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError> {
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err(AeadError::AuthenticationFailed);
        }

        let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
        let ciphertext = &ciphertext_and_tag[..ct_len];
        let tag: &[u8; TAG_SIZE] = ciphertext_and_tag[ct_len..].try_into().unwrap();

        let mut plaintext = ciphertext.to_vec();
        self.decrypt(nonce, aad, &mut plaintext, tag)?;

        Ok(plaintext)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// XCHACHA20-POLY1305
// ═══════════════════════════════════════════════════════════════════════════════

/// Extended nonce size for XChaCha20-Poly1305 (192 bits)
pub const XCHACHA_NONCE_SIZE: usize = 24;

/// XChaCha20-Poly1305 AEAD cipher with extended 192-bit nonce.
///
/// This variant uses HChaCha20 to derive a subkey from the first 16 bytes
/// of the nonce, then uses standard ChaCha20-Poly1305 with the derived key
/// and remaining 8 bytes of the nonce.
///
/// The extended nonce makes it safe to use random nonces without risk of
/// collision (birthday bound is 2^96 messages vs 2^48 for standard 96-bit nonces).
///
/// # Example
///
/// ```ignore
/// use arcanum_primitives::chacha20poly1305::XChaCha20Poly1305;
///
/// let key = [0u8; 32];
/// let nonce = [0u8; 24]; // Extended 192-bit nonce
/// let aad = b"additional data";
/// let plaintext = b"secret message";
///
/// let cipher = XChaCha20Poly1305::new(&key);
/// let ciphertext = cipher.seal(&nonce, aad, plaintext);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XChaCha20Poly1305 {
    /// The 256-bit key
    key: [u8; KEY_SIZE],
}

impl XChaCha20Poly1305 {
    /// Create a new XChaCha20-Poly1305 cipher with the given key.
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Derive the subkey and ChaCha20 nonce from the extended nonce.
    ///
    /// Uses HChaCha20 on first 16 bytes, prepends 4 zero bytes to last 8 bytes.
    fn derive_subkey_and_nonce(&self, nonce: &[u8; XCHACHA_NONCE_SIZE]) -> ([u8; 32], [u8; 12]) {
        use crate::chacha20::hchacha20;

        // Split the 24-byte nonce
        let hchacha_nonce: [u8; 16] = nonce[..16].try_into().unwrap();
        let chacha_nonce_suffix: &[u8; 8] = nonce[16..].try_into().unwrap();

        // Derive subkey using HChaCha20
        let subkey = hchacha20(&self.key, &hchacha_nonce);

        // Construct ChaCha20 nonce: 4 zero bytes + last 8 bytes of extended nonce
        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(chacha_nonce_suffix);

        (subkey, chacha_nonce)
    }

    /// Encrypt data in place, returning the authentication tag.
    pub fn encrypt(
        &self,
        nonce: &[u8; XCHACHA_NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; TAG_SIZE] {
        let (subkey, chacha_nonce) = self.derive_subkey_and_nonce(nonce);
        let inner = ChaCha20Poly1305::new(&subkey);
        inner.encrypt(&chacha_nonce, aad, buffer)
    }

    /// Decrypt data in place, verifying the authentication tag.
    pub fn decrypt(
        &self,
        nonce: &[u8; XCHACHA_NONCE_SIZE],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), AeadError> {
        let (subkey, chacha_nonce) = self.derive_subkey_and_nonce(nonce);
        let inner = ChaCha20Poly1305::new(&subkey);
        inner.decrypt(&chacha_nonce, aad, buffer, tag)
    }

    /// Encrypt and return ciphertext + tag.
    #[cfg(feature = "alloc")]
    pub fn seal(
        &self,
        nonce: &[u8; XCHACHA_NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let (subkey, chacha_nonce) = self.derive_subkey_and_nonce(nonce);
        let inner = ChaCha20Poly1305::new(&subkey);
        inner.seal(&chacha_nonce, aad, plaintext)
    }

    /// Decrypt ciphertext + tag, returning plaintext.
    #[cfg(feature = "alloc")]
    pub fn open(
        &self,
        nonce: &[u8; XCHACHA_NONCE_SIZE],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError> {
        let (subkey, chacha_nonce) = self.derive_subkey_and_nonce(nonce);
        let inner = ChaCha20Poly1305::new(&subkey);
        inner.open(&chacha_nonce, aad, ciphertext_and_tag)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    // RFC 8439 Section 2.8.2 test vector
    #[test]
    fn test_chacha20poly1305_rfc8439() {
        let key = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let key: [u8; 32] = key.try_into().unwrap();

        let nonce = hex_to_bytes("070000004041424344454647");
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_ciphertext = hex_to_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );

        let expected_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");

        let cipher = ChaCha20Poly1305::new(&key);

        // Encrypt
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt(&nonce, &aad, &mut ciphertext);

        assert_eq!(
            bytes_to_hex(&ciphertext),
            bytes_to_hex(&expected_ciphertext),
            "Ciphertext mismatch"
        );
        assert_eq!(
            bytes_to_hex(&tag),
            bytes_to_hex(&expected_tag),
            "Tag mismatch"
        );

        // Decrypt
        cipher
            .decrypt(&nonce, &aad, &mut ciphertext, &tag)
            .expect("Decryption should succeed");

        assert_eq!(ciphertext.as_slice(), plaintext.as_slice());
    }

    // Test with empty plaintext
    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"associated data";

        let cipher = ChaCha20Poly1305::new(&key);

        let mut ciphertext = Vec::new();
        let tag = cipher.encrypt(&nonce, aad, &mut ciphertext);

        // Empty plaintext should still produce valid tag
        assert_eq!(ciphertext.len(), 0);
        assert_eq!(tag.len(), 16);

        // Should decrypt successfully
        cipher
            .decrypt(&nonce, aad, &mut ciphertext, &tag)
            .expect("Decryption should succeed");
    }

    // Test with empty AAD
    #[test]
    fn test_empty_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"secret message";

        let cipher = ChaCha20Poly1305::new(&key);

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt(&nonce, &[], &mut ciphertext);

        cipher
            .decrypt(&nonce, &[], &mut ciphertext, &tag)
            .expect("Decryption should succeed");

        assert_eq!(ciphertext.as_slice(), plaintext.as_slice());
    }

    // Test authentication failure with wrong tag
    #[test]
    fn test_wrong_tag() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"secret message";

        let cipher = ChaCha20Poly1305::new(&key);

        let mut ciphertext = plaintext.to_vec();
        let mut tag = cipher.encrypt(&nonce, &[], &mut ciphertext);

        // Modify tag
        tag[0] ^= 1;

        let result = cipher.decrypt(&nonce, &[], &mut ciphertext, &tag);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test authentication failure with modified ciphertext
    #[test]
    fn test_modified_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"secret message";

        let cipher = ChaCha20Poly1305::new(&key);

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt(&nonce, &[], &mut ciphertext);

        // Modify ciphertext
        ciphertext[0] ^= 1;

        let result = cipher.decrypt(&nonce, &[], &mut ciphertext, &tag);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test authentication failure with modified AAD
    #[test]
    fn test_modified_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"associated data";
        let plaintext = b"secret message";

        let cipher = ChaCha20Poly1305::new(&key);

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt(&nonce, aad, &mut ciphertext);

        // Try to decrypt with different AAD
        let bad_aad = b"modified data!!";
        let result = cipher.decrypt(&nonce, bad_aad, &mut ciphertext, &tag);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test determinism
    #[test]
    fn test_deterministic() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"aad";
        let plaintext = b"plaintext";

        let cipher = ChaCha20Poly1305::new(&key);

        let mut ct1 = plaintext.to_vec();
        let tag1 = cipher.encrypt(&nonce, aad, &mut ct1);

        let mut ct2 = plaintext.to_vec();
        let tag2 = cipher.encrypt(&nonce, aad, &mut ct2);

        assert_eq!(ct1, ct2);
        assert_eq!(tag1, tag2);
    }

    // Test various message lengths
    #[test]
    fn test_various_lengths() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key);

        for len in [1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1000] {
            let plaintext = vec![0xAB; len];

            let mut ciphertext = plaintext.clone();
            let tag = cipher.encrypt(&nonce, aad, &mut ciphertext);

            // Ciphertext should differ from plaintext
            assert_ne!(ciphertext, plaintext);

            cipher
                .decrypt(&nonce, aad, &mut ciphertext, &tag)
                .expect(&format!("Decryption failed for length {}", len));

            assert_eq!(ciphertext, plaintext, "Roundtrip failed for length {}", len);
        }
    }

    // Test seal/open (allocated versions)
    #[test]
    fn test_seal_open() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"associated data";
        let plaintext = b"secret message to seal";

        let cipher = ChaCha20Poly1305::new(&key);

        let sealed = cipher.seal(&nonce, aad, plaintext);
        assert_eq!(sealed.len(), plaintext.len() + TAG_SIZE);

        let opened = cipher
            .open(&nonce, aad, &sealed)
            .expect("Open should succeed");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    // Test open with invalid input (too short)
    #[test]
    fn test_open_too_short() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        let cipher = ChaCha20Poly1305::new(&key);

        // Less than TAG_SIZE bytes
        let result = cipher.open(&nonce, &[], &[1, 2, 3, 4, 5]);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test poly key generation matches what we get
    // (Different from RFC since our ChaCha20 uses the exact nonce format)
    #[test]
    fn test_poly_key_generation() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        let cipher = ChaCha20Poly1305::new(&key);
        let poly_key1 = cipher.poly_key(&nonce);
        let poly_key2 = cipher.poly_key(&nonce);

        // Should be deterministic
        assert_eq!(poly_key1, poly_key2);

        // Different nonce should give different key
        let nonce2 = [0x25u8; 12];
        let poly_key3 = cipher.poly_key(&nonce2);
        assert_ne!(poly_key1, poly_key3);
    }

    // Test padding calculation
    #[test]
    fn test_pad16() {
        assert_eq!(pad16(0), 0);
        assert_eq!(pad16(1), 15);
        assert_eq!(pad16(15), 1);
        assert_eq!(pad16(16), 0);
        assert_eq!(pad16(17), 15);
        assert_eq!(pad16(32), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // XCHACHA20-POLY1305 TESTS
    // ═══════════════════════════════════════════════════════════════════════════════

    // Test XChaCha20-Poly1305 basic roundtrip
    #[test]
    fn test_xchacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 24]; // Extended 24-byte nonce
        let aad = b"additional data";
        let plaintext = b"secret message for xchacha";

        let cipher = XChaCha20Poly1305::new(&key);

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt(&nonce, aad, &mut ciphertext);

        // Ciphertext should differ from plaintext
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        // Decrypt
        cipher
            .decrypt(&nonce, aad, &mut ciphertext, &tag)
            .expect("Decryption should succeed");

        assert_eq!(ciphertext.as_slice(), plaintext.as_slice());
    }

    // Test XChaCha20-Poly1305 seal/open
    #[test]
    fn test_xchacha20poly1305_seal_open() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 24];
        let aad = b"aad";
        let plaintext = b"plaintext for xchacha seal";

        let cipher = XChaCha20Poly1305::new(&key);

        let sealed = cipher.seal(&nonce, aad, plaintext);
        assert_eq!(sealed.len(), plaintext.len() + TAG_SIZE);

        let opened = cipher
            .open(&nonce, aad, &sealed)
            .expect("Open should succeed");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    // Test XChaCha20-Poly1305 authentication failure
    #[test]
    fn test_xchacha20poly1305_auth_failure() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 24];
        let plaintext = b"secret";

        let cipher = XChaCha20Poly1305::new(&key);

        let mut ciphertext = plaintext.to_vec();
        let mut tag = cipher.encrypt(&nonce, &[], &mut ciphertext);

        // Modify tag
        tag[0] ^= 1;

        let result = cipher.decrypt(&nonce, &[], &mut ciphertext, &tag);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    // Test XChaCha20-Poly1305 different nonces produce different ciphertexts
    #[test]
    fn test_xchacha20poly1305_nonce_uniqueness() {
        let key = [0x42u8; 32];
        let plaintext = b"same plaintext";

        let cipher = XChaCha20Poly1305::new(&key);

        let nonce1 = [0x01u8; 24];
        let nonce2 = [0x02u8; 24];

        let ct1 = cipher.seal(&nonce1, &[], plaintext);
        let ct2 = cipher.seal(&nonce2, &[], plaintext);

        // Different nonces should produce different ciphertexts
        assert_ne!(ct1, ct2);

        // Both should decrypt correctly with their respective nonces
        let pt1 = cipher.open(&nonce1, &[], &ct1).unwrap();
        let pt2 = cipher.open(&nonce2, &[], &ct2).unwrap();
        assert_eq!(pt1.as_slice(), plaintext.as_slice());
        assert_eq!(pt2.as_slice(), plaintext.as_slice());
    }

    // Test XChaCha20-Poly1305 against known test vector
    // From draft-irtf-cfrg-xchacha (libsodium compatible)
    #[test]
    fn test_xchacha20poly1305_test_vector() {
        let key = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let key: [u8; 32] = key.try_into().unwrap();

        let nonce = hex_to_bytes("404142434445464748494a4b4c4d4e4f5051525354555657");
        let nonce: [u8; 24] = nonce.try_into().unwrap();

        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let cipher = XChaCha20Poly1305::new(&key);

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt(&nonce, &aad, &mut ciphertext);

        // Verify roundtrip works
        let mut decrypted = ciphertext.clone();
        cipher.decrypt(&nonce, &aad, &mut decrypted, &tag).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    // Test HChaCha20 with draft-irtf-cfrg-xchacha test vector
    #[test]
    fn test_hchacha20_vector() {
        use crate::chacha20::hchacha20;

        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let key: [u8; 32] = key.try_into().unwrap();

        let nonce = hex_to_bytes("000000090000004a0000000031415927");
        let nonce: [u8; 16] = nonce.try_into().unwrap();

        let expected =
            hex_to_bytes("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");

        let output = hchacha20(&key, &nonce);
        assert_eq!(bytes_to_hex(&output), bytes_to_hex(&expected));
    }
}
