//! Symmetric encryption (AEAD).
//!
//! Supports AES-256-GCM and ChaCha20-Poly1305.

use crate::error::CryptoError;
use wasm_bindgen::prelude::*;
#[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
use zeroize::Zeroize;

/// AES-256-GCM authenticated encryption.
///
/// Provides confidentiality and authenticity for messages up to 64GB.
/// Nonce must be 12 bytes and unique per message with the same key.
#[wasm_bindgen]
pub struct AesGcm {
    #[cfg(feature = "backend-rustcrypto")]
    cipher: aes_gcm::Aes256Gcm,
    // Native backend would store key here
    #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
    key: [u8; 32],
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

        #[cfg(feature = "backend-rustcrypto")]
        {
            use aes_gcm::{Aes256Gcm, KeyInit};
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| CryptoError::invalid_key("Failed to initialize AES-GCM"))?;
            Ok(AesGcm { cipher })
        }

        #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
        {
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(key);
            Ok(AesGcm { key: key_arr })
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

        #[cfg(feature = "backend-rustcrypto")]
        {
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

        #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
        {
            // Native implementation placeholder
            Err(CryptoError::encryption_failed(
                "Native backend not yet implemented",
            ))
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
                "AES-GCM requires 12-byte nonce, got {} bytes",
                nonce.len()
            )));
        }

        #[cfg(feature = "backend-rustcrypto")]
        {
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

        #[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
        {
            Err(CryptoError::decryption_failed())
        }
    }

    /// Explicitly free the cipher and zeroize the key material.
    ///
    /// Called automatically on drop, but available for explicit cleanup in JS.
    #[wasm_bindgen]
    pub fn free(self) {
        // Dropping self will trigger zeroization
        drop(self);
    }
}

#[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
impl Drop for AesGcm {
    fn drop(&mut self) {
        self.key.zeroize();
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
    key: [u8; 32],
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
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(key);
            Ok(ChaCha20Poly1305 { key: key_arr })
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
            Err(CryptoError::encryption_failed(
                "Native backend not yet implemented",
            ))
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
            Err(CryptoError::decryption_failed())
        }
    }

    /// Explicitly free the cipher and zeroize the key material.
    #[wasm_bindgen]
    pub fn free(self) {
        drop(self);
    }
}

#[cfg(all(feature = "backend-native", not(feature = "backend-rustcrypto")))]
impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
