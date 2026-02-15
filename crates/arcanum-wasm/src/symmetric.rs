//! Symmetric encryption (AEAD).
//!
//! Supports AES-256-GCM and ChaCha20-Poly1305.

use crate::error::CryptoError;
use wasm_bindgen::prelude::*;

/// AES-256-GCM authenticated encryption.
///
/// Provides confidentiality and authenticity for messages up to 64GB.
/// Nonce must be 12 bytes and unique per message with the same key.
///
/// Note: Always uses RustCrypto aes-gcm (native primitives doesn't have AES).
#[wasm_bindgen]
pub struct AesGcm {
    cipher: aes_gcm::Aes256Gcm,
}

#[wasm_bindgen]
impl AesGcm {
    /// Create a new AES-256-GCM cipher with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte (256-bit) encryption key
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` with code "INVALID_KEY" if key length is not 32 bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Result<AesGcm, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::invalid_key(&format!(
                "AES-256 requires 32-byte key, got {} bytes",
                key.len()
            )));
        }

        use aes_gcm::{Aes256Gcm, KeyInit};
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::invalid_key("Failed to initialize AES-GCM"))?;
        Ok(AesGcm { cipher })
    }

    /// Encrypt plaintext with optional additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 12-byte unique nonce (MUST be unique per message)
    /// * `aad` - Optional additional data to authenticate but not encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext with 16-byte authentication tag appended.
    #[wasm_bindgen]
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_nonce(&format!(
                "AES-GCM requires 12-byte nonce, got {} bytes",
                nonce.len()
            )));
        }

        use aes_gcm::{Nonce, aead::Aead, aead::Payload};

        let nonce = Nonce::from_slice(nonce);
        let payload = match &aad {
            Some(aad_data) => Payload {
                msg: plaintext,
                aad: aad_data,
            },
            None => Payload {
                msg: plaintext,
                aad: &[],
            },
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::encryption_failed("AES-GCM encryption failed"))
    }

    /// Decrypt ciphertext with optional additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Data to decrypt (includes 16-byte auth tag)
    /// * `nonce` - 12-byte nonce used during encryption
    /// * `aad` - Optional additional data that was authenticated during encryption
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` with code "DECRYPTION_FAILED" if authentication fails.
    #[wasm_bindgen]
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_nonce(&format!(
                "AES-GCM requires 12-byte nonce, got {} bytes",
                nonce.len()
            )));
        }

        use aes_gcm::{Nonce, aead::Aead, aead::Payload};

        let nonce = Nonce::from_slice(nonce);
        let payload = match &aad {
            Some(aad_data) => Payload {
                msg: ciphertext,
                aad: aad_data,
            },
            None => Payload {
                msg: ciphertext,
                aad: &[],
            },
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::decryption_failed())
    }

    /// Explicitly free the cipher and zeroize the key material.
    ///
    /// Called automatically on drop, but available for explicit cleanup in JS.
    #[wasm_bindgen]
    pub fn free(self) {
        drop(self);
    }
}

/// ChaCha20-Poly1305 authenticated encryption.
///
/// Provides confidentiality and authenticity. Preferred over AES-GCM when
/// hardware AES acceleration is unavailable (like in WASM).
#[wasm_bindgen]
pub struct ChaCha20Poly1305 {
    #[cfg(feature = "backend-rustcrypto")]
    cipher: chacha20poly1305::ChaCha20Poly1305,
    #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
    cipher: arcanum_primitives::chacha20poly1305::ChaCha20Poly1305,
}

#[wasm_bindgen]
impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 cipher with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte (256-bit) encryption key
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` with code "INVALID_KEY" if key length is not 32 bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Result<ChaCha20Poly1305, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::invalid_key(&format!(
                "ChaCha20-Poly1305 requires 32-byte key, got {} bytes",
                key.len()
            )));
        }

        #[cfg(feature = "backend-rustcrypto")]
        {
            use chacha20poly1305::KeyInit;
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| CryptoError::invalid_key("Failed to initialize ChaCha20-Poly1305"))?;
            Ok(ChaCha20Poly1305 { cipher })
        }

        #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
        {
            let key_arr: [u8; 32] = key.try_into().unwrap();
            let cipher = arcanum_primitives::chacha20poly1305::ChaCha20Poly1305::new(&key_arr);
            Ok(ChaCha20Poly1305 { cipher })
        }
    }

    /// Encrypt plaintext with optional additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 12-byte unique nonce (MUST be unique per message)
    /// * `aad` - Optional additional data to authenticate but not encrypt
    ///
    /// # Returns
    ///
    /// Ciphertext with 16-byte Poly1305 authentication tag appended.
    #[wasm_bindgen]
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_nonce(&format!(
                "ChaCha20-Poly1305 requires 12-byte nonce, got {} bytes",
                nonce.len()
            )));
        }

        #[cfg(feature = "backend-rustcrypto")]
        {
            use chacha20poly1305::{Nonce, aead::Aead, aead::Payload};

            let nonce = Nonce::from_slice(nonce);
            let payload = match &aad {
                Some(aad_data) => Payload {
                    msg: plaintext,
                    aad: aad_data,
                },
                None => Payload {
                    msg: plaintext,
                    aad: &[],
                },
            };

            self.cipher
                .encrypt(nonce, payload)
                .map_err(|_| CryptoError::encryption_failed("ChaCha20-Poly1305 encryption failed"))
        }

        #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
        {
            let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
            let aad_slice = aad.as_deref().unwrap_or(&[]);

            // Copy plaintext to buffer for in-place encryption
            let mut buffer = plaintext.to_vec();
            let tag = self.cipher.encrypt(&nonce_arr, aad_slice, &mut buffer);

            // Append tag to ciphertext
            buffer.extend_from_slice(&tag);
            Ok(buffer)
        }
    }

    /// Decrypt ciphertext with optional additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Data to decrypt (includes 16-byte auth tag)
    /// * `nonce` - 12-byte nonce used during encryption
    /// * `aad` - Optional additional data that was authenticated during encryption
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` with code "DECRYPTION_FAILED" if authentication fails.
    #[wasm_bindgen]
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_nonce(&format!(
                "ChaCha20-Poly1305 requires 12-byte nonce, got {} bytes",
                nonce.len()
            )));
        }

        #[cfg(feature = "backend-rustcrypto")]
        {
            use chacha20poly1305::{Nonce, aead::Aead, aead::Payload};

            let nonce = Nonce::from_slice(nonce);
            let payload = match &aad {
                Some(aad_data) => Payload {
                    msg: ciphertext,
                    aad: aad_data,
                },
                None => Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            };

            self.cipher
                .decrypt(nonce, payload)
                .map_err(|_| CryptoError::decryption_failed())
        }

        #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
        {
            if ciphertext.len() < 16 {
                return Err(CryptoError::decryption_failed());
            }

            let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
            let aad_slice = aad.as_deref().unwrap_or(&[]);

            // Split ciphertext and tag
            let (ct, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
            let tag: [u8; 16] = tag_slice.try_into().unwrap();

            // Copy ciphertext to buffer for in-place decryption
            let mut buffer = ct.to_vec();
            self.cipher
                .decrypt(&nonce_arr, aad_slice, &mut buffer, &tag)
                .map_err(|_| CryptoError::decryption_failed())?;

            Ok(buffer)
        }
    }

    /// Explicitly free the cipher and zeroize the key material.
    #[wasm_bindgen]
    pub fn free(self) {
        drop(self);
    }
}
