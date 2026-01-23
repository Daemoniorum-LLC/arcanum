//! AES-based encryption algorithms.

use crate::traits::{Cipher, StreamCipher, validate_input_sizes};
use aead::generic_array::GenericArray;
use aead::{Aead, AeadInPlace, KeyInit, Payload, consts::U12};
use arcanum_core::error::{Error, Result};
use rand_core::{OsRng, RngCore};

/// Type alias for 12-byte nonces used by AES-GCM ciphers.
type AeadNonce = GenericArray<u8, U12>;

// ═══════════════════════════════════════════════════════════════════════════════
// AEAD CIPHER MACRO
// ═══════════════════════════════════════════════════════════════════════════════

/// Macro to implement AEAD cipher trait with minimal boilerplate.
///
/// This macro generates the full `Cipher` trait implementation for AEAD ciphers
/// that follow the standard encrypt/decrypt pattern with optional AAD.
///
/// # Parameters
/// - `$struct_name`: The name of the cipher struct
/// - `$inner_cipher`: The underlying AEAD cipher type (e.g., aes_gcm::Aes256Gcm)
/// - `$nonce_type`: The nonce type for the cipher
/// - `$key_size`: Key size in bytes
/// - `$nonce_size`: Nonce size in bytes
/// - `$tag_size`: Authentication tag size in bytes
/// - `$algorithm`: Algorithm name string
macro_rules! impl_aead_cipher {
    (
        $struct_name:ident,
        $inner_cipher:ty,
        $nonce_type:ty,
        $key_size:expr,
        $nonce_size:expr,
        $tag_size:expr,
        $algorithm:expr
    ) => {
        impl Cipher for $struct_name {
            const KEY_SIZE: usize = $key_size;
            const NONCE_SIZE: usize = $nonce_size;
            const TAG_SIZE: usize = $tag_size;
            const ALGORITHM: &'static str = $algorithm;

            fn generate_key() -> Vec<u8> {
                let mut key = vec![0u8; Self::KEY_SIZE];
                OsRng.fill_bytes(&mut key);
                key
            }

            fn generate_nonce() -> Vec<u8> {
                let mut nonce = vec![0u8; Self::NONCE_SIZE];
                OsRng.fill_bytes(&mut nonce);
                nonce
            }

            fn encrypt(
                key: &[u8],
                nonce: &[u8],
                plaintext: &[u8],
                associated_data: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                validate_key_nonce::<Self>(key, nonce)?;
                validate_input_sizes(plaintext, associated_data)?;

                let cipher =
                    <$inner_cipher>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength {
                        expected: Self::KEY_SIZE,
                        actual: key.len(),
                    })?;

                let nonce = <$nonce_type>::from_slice(nonce);

                let ciphertext = match associated_data {
                    Some(aad) => cipher
                        .encrypt(
                            nonce,
                            Payload {
                                msg: plaintext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::EncryptionFailed)?,
                    None => cipher
                        .encrypt(nonce, plaintext)
                        .map_err(|_| Error::EncryptionFailed)?,
                };

                Ok(ciphertext)
            }

            fn decrypt(
                key: &[u8],
                nonce: &[u8],
                ciphertext: &[u8],
                associated_data: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                validate_key_nonce::<Self>(key, nonce)?;

                if ciphertext.len() < Self::TAG_SIZE {
                    return Err(Error::CiphertextTooShort {
                        size: ciphertext.len(),
                        minimum: Self::TAG_SIZE,
                    });
                }

                let cipher =
                    <$inner_cipher>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength {
                        expected: Self::KEY_SIZE,
                        actual: key.len(),
                    })?;

                let nonce = <$nonce_type>::from_slice(nonce);

                let plaintext = match associated_data {
                    Some(aad) => cipher
                        .decrypt(
                            nonce,
                            Payload {
                                msg: ciphertext,
                                aad,
                            },
                        )
                        .map_err(|_| Error::DecryptionFailed)?,
                    None => cipher
                        .decrypt(nonce, ciphertext)
                        .map_err(|_| Error::DecryptionFailed)?,
                };

                Ok(plaintext)
            }

            fn encrypt_in_place(
                key: &[u8],
                nonce: &[u8],
                associated_data: &[u8],
                buffer: &mut Vec<u8>,
            ) -> Result<()> {
                validate_key_nonce::<Self>(key, nonce)?;
                validate_input_sizes(buffer, Some(associated_data))?;

                let cipher =
                    <$inner_cipher>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength {
                        expected: Self::KEY_SIZE,
                        actual: key.len(),
                    })?;

                let nonce = <$nonce_type>::from_slice(nonce);

                cipher
                    .encrypt_in_place(nonce, associated_data, buffer)
                    .map_err(|_| Error::EncryptionFailed)
            }

            fn decrypt_in_place(
                key: &[u8],
                nonce: &[u8],
                associated_data: &[u8],
                buffer: &mut Vec<u8>,
            ) -> Result<()> {
                validate_key_nonce::<Self>(key, nonce)?;

                let cipher =
                    <$inner_cipher>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength {
                        expected: Self::KEY_SIZE,
                        actual: key.len(),
                    })?;

                let nonce = <$nonce_type>::from_slice(nonce);

                cipher
                    .decrypt_in_place(nonce, associated_data, buffer)
                    .map_err(|_| Error::DecryptionFailed)
            }
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// AES-256-GCM
// ═══════════════════════════════════════════════════════════════════════════════

/// AES-256-GCM authenticated encryption.
///
/// This is the recommended default for most applications:
/// - 256-bit key security
/// - Hardware acceleration on modern CPUs (AES-NI)
/// - Fast and widely supported
///
/// **Warning**: Nonce reuse is catastrophic. Never use the same nonce twice
/// with the same key.
pub struct Aes256Gcm;

impl_aead_cipher!(
    Aes256Gcm,
    aes_gcm::Aes256Gcm,
    AeadNonce,
    32,
    12,
    16,
    "AES-256-GCM"
);

// ═══════════════════════════════════════════════════════════════════════════════
// AES-128-GCM
// ═══════════════════════════════════════════════════════════════════════════════

/// AES-128-GCM authenticated encryption.
///
/// Faster than AES-256-GCM but with 128-bit key security.
/// Still considered secure for most applications.
pub struct Aes128Gcm;

impl_aead_cipher!(
    Aes128Gcm,
    aes_gcm::Aes128Gcm,
    AeadNonce,
    16,
    12,
    16,
    "AES-128-GCM"
);

// ═══════════════════════════════════════════════════════════════════════════════
// AES-256-GCM-SIV
// ═══════════════════════════════════════════════════════════════════════════════

/// AES-256-GCM-SIV nonce-misuse resistant authenticated encryption.
///
/// This variant provides security even if nonces are accidentally reused:
/// - Reusing a nonce only reveals if two messages are identical
/// - Does NOT leak key material or enable forgeries
///
/// Slightly slower than standard GCM but much safer for applications
/// where nonce uniqueness is hard to guarantee.
pub struct Aes256GcmSiv;

impl_aead_cipher!(
    Aes256GcmSiv,
    aes_gcm_siv::Aes256GcmSiv,
    AeadNonce,
    32,
    12,
    16,
    "AES-256-GCM-SIV"
);

// ═══════════════════════════════════════════════════════════════════════════════
// AES-256-CTR (Stream Cipher)
// ═══════════════════════════════════════════════════════════════════════════════

/// AES-256 in CTR (Counter) mode.
///
/// This is a stream cipher - it does NOT provide authentication.
/// Use this only when you need streaming encryption or have external
/// authentication (e.g., in a larger protocol).
///
/// For most applications, use AES-256-GCM instead.
pub struct Aes256Ctr {
    cipher: ctr::Ctr64BE<aes::Aes256>,
    position: u64,
}

impl StreamCipher for Aes256Ctr {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 16; // Full block size for CTR
    const ALGORITHM: &'static str = "AES-256-CTR";

    fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            });
        }

        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceLength {
                expected: Self::NONCE_SIZE,
                actual: nonce.len(),
            });
        }

        use cipher::KeyIvInit;
        let cipher = ctr::Ctr64BE::<aes::Aes256>::new_from_slices(key, nonce).map_err(|_| {
            Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            }
        })?;

        Ok(Self {
            cipher,
            position: 0,
        })
    }

    fn apply_keystream(&mut self, data: &mut [u8]) {
        use cipher::StreamCipher;
        self.cipher.apply_keystream(data);
        self.position += data.len() as u64;
    }

    fn seek(&mut self, position: u64) -> Result<()> {
        use cipher::StreamCipherSeek;
        self.cipher.seek(position);
        self.position = position;
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

fn validate_key_nonce<C: Cipher>(key: &[u8], nonce: &[u8]) -> Result<()> {
    if key.len() != C::KEY_SIZE {
        return Err(Error::InvalidKeyLength {
            expected: C::KEY_SIZE,
            actual: key.len(),
        });
    }

    if nonce.len() != C::NONCE_SIZE {
        return Err(Error::InvalidNonceLength {
            expected: C::NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher_roundtrip<C: Cipher>() {
        let key = C::generate_key();
        let nonce = C::generate_nonce();
        let plaintext = b"Hello, Arcanum! This is a test message.";

        let ciphertext = C::encrypt(&key, &nonce, plaintext, None).unwrap();
        let decrypted = C::decrypt(&key, &nonce, &ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    fn test_cipher_with_aad<C: Cipher>() {
        let key = C::generate_key();
        let nonce = C::generate_nonce();
        let plaintext = b"Secret data";
        let aad = b"Additional authenticated data";

        let ciphertext = C::encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let decrypted = C::decrypt(&key, &nonce, &ciphertext, Some(aad)).unwrap();

        assert_eq!(decrypted, plaintext);

        // Wrong AAD should fail
        let wrong_aad = b"Wrong AAD";
        assert!(C::decrypt(&key, &nonce, &ciphertext, Some(wrong_aad)).is_err());
    }

    #[test]
    fn test_aes_256_gcm() {
        test_cipher_roundtrip::<Aes256Gcm>();
        test_cipher_with_aad::<Aes256Gcm>();
    }

    #[test]
    fn test_aes_128_gcm() {
        test_cipher_roundtrip::<Aes128Gcm>();
        test_cipher_with_aad::<Aes128Gcm>();
    }

    #[test]
    fn test_aes_256_gcm_siv() {
        test_cipher_roundtrip::<Aes256GcmSiv>();
        test_cipher_with_aad::<Aes256GcmSiv>();
    }

    #[test]
    fn test_aes_256_ctr() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 16];

        let mut cipher = Aes256Ctr::new(&key, &nonce).unwrap();
        let mut data = b"Hello, World!".to_vec();
        let original = data.clone();

        cipher.apply_keystream(&mut data);
        assert_ne!(data, original);

        // Decrypt by re-applying keystream
        let mut cipher = Aes256Ctr::new(&key, &nonce).unwrap();
        cipher.apply_keystream(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = Aes256Gcm::generate_key();
        let wrong_key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = b"Secret";

        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None).unwrap();
        assert!(Aes256Gcm::decrypt(&wrong_key, &nonce, &ciphertext, None).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Too short for AES-256
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = b"Test";

        let result = Aes256Gcm::encrypt(&short_key, &nonce, plaintext, None);
        assert!(matches!(result, Err(Error::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = Aes256Gcm::generate_key();
        let short_nonce = vec![0u8; 8]; // Too short
        let plaintext = b"Test";

        let result = Aes256Gcm::encrypt(&key, &short_nonce, plaintext, None);
        assert!(matches!(result, Err(Error::InvalidNonceLength { .. })));
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PROPERTY-BASED TESTS
    // ═══════════════════════════════════════════════════════════════════════════════

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating arbitrary plaintext up to 64KB
        fn plaintext_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..65536)
        }

        /// Strategy for generating arbitrary AAD up to 1KB
        fn aad_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..1024)
        }

        proptest! {
            /// Property: Encrypt then decrypt returns original plaintext
            #[test]
            fn prop_aes256gcm_roundtrip(plaintext in plaintext_strategy()) {
                let key = Aes256Gcm::generate_key();
                let nonce = Aes256Gcm::generate_nonce();

                let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None).unwrap();
                let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None).unwrap();

                prop_assert_eq!(decrypted, plaintext);
            }

            /// Property: Encrypt then decrypt with AAD returns original plaintext
            #[test]
            fn prop_aes256gcm_roundtrip_with_aad(
                plaintext in plaintext_strategy(),
                aad in aad_strategy()
            ) {
                let key = Aes256Gcm::generate_key();
                let nonce = Aes256Gcm::generate_nonce();

                let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, Some(&aad)).unwrap();
                let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, Some(&aad)).unwrap();

                prop_assert_eq!(decrypted, plaintext);
            }

            /// Property: Ciphertext length = plaintext length + tag size
            #[test]
            fn prop_aes256gcm_ciphertext_length(plaintext in plaintext_strategy()) {
                let key = Aes256Gcm::generate_key();
                let nonce = Aes256Gcm::generate_nonce();

                let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None).unwrap();
                prop_assert_eq!(ciphertext.len(), plaintext.len() + Aes256Gcm::TAG_SIZE);
            }

            /// Property: Same plaintext with different keys produces different ciphertexts
            #[test]
            fn prop_aes256gcm_different_keys(plaintext in plaintext_strategy()) {
                prop_assume!(!plaintext.is_empty());

                let key1 = Aes256Gcm::generate_key();
                let key2 = Aes256Gcm::generate_key();
                let nonce = Aes256Gcm::generate_nonce();

                let ct1 = Aes256Gcm::encrypt(&key1, &nonce, &plaintext, None).unwrap();
                let ct2 = Aes256Gcm::encrypt(&key2, &nonce, &plaintext, None).unwrap();

                // Keys are random, so ciphertexts should differ
                prop_assert_ne!(ct1, ct2);
            }

            /// Property: AES-128-GCM roundtrip
            #[test]
            fn prop_aes128gcm_roundtrip(plaintext in plaintext_strategy()) {
                let key = Aes128Gcm::generate_key();
                let nonce = Aes128Gcm::generate_nonce();

                let ciphertext = Aes128Gcm::encrypt(&key, &nonce, &plaintext, None).unwrap();
                let decrypted = Aes128Gcm::decrypt(&key, &nonce, &ciphertext, None).unwrap();

                prop_assert_eq!(decrypted, plaintext);
            }

            /// Property: AES-256-GCM-SIV roundtrip
            #[test]
            fn prop_aes256gcmsiv_roundtrip(plaintext in plaintext_strategy()) {
                let key = Aes256GcmSiv::generate_key();
                let nonce = Aes256GcmSiv::generate_nonce();

                let ciphertext = Aes256GcmSiv::encrypt(&key, &nonce, &plaintext, None).unwrap();
                let decrypted = Aes256GcmSiv::decrypt(&key, &nonce, &ciphertext, None).unwrap();

                prop_assert_eq!(decrypted, plaintext);
            }

            /// Property: AES-CTR stream cipher is its own inverse
            #[test]
            fn prop_aes256ctr_involution(data in plaintext_strategy()) {
                let key = vec![0x42u8; 32];
                let nonce = vec![0u8; 16];

                let mut encrypted = data.clone();
                let mut cipher = Aes256Ctr::new(&key, &nonce).unwrap();
                cipher.apply_keystream(&mut encrypted);

                let mut decrypted = encrypted.clone();
                let mut cipher = Aes256Ctr::new(&key, &nonce).unwrap();
                cipher.apply_keystream(&mut decrypted);

                prop_assert_eq!(decrypted, data);
            }
        }
    }
}
