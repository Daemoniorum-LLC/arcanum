//! Builder pattern for ergonomic encryption/decryption operations.
//!
//! This module provides a fluent builder API for encryption operations,
//! offering a more readable alternative to the static method calls.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_symmetric::builder::EncryptionBuilder;
//!
//! // Using the builder pattern
//! let ciphertext = EncryptionBuilder::<Aes256Gcm>::new()
//!     .key(&key)
//!     .nonce(&nonce)
//!     .aad(b"metadata")
//!     .encrypt(b"secret message")?;
//!
//! // Decryption
//! let plaintext = EncryptionBuilder::<Aes256Gcm>::new()
//!     .key(&key)
//!     .nonce(&nonce)
//!     .aad(b"metadata")
//!     .decrypt(&ciphertext)?;
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::traits::Cipher;
use arcanum_core::error::{Error, Result};
use core::marker::PhantomData;

/// Builder for encryption and decryption operations.
///
/// This provides a fluent API for configuring and executing
/// symmetric encryption operations.
///
/// # Type Parameters
///
/// * `C` - The cipher type implementing the `Cipher` trait
///
/// # Example
///
/// ```ignore
/// use arcanum_symmetric::{Aes256Gcm, Cipher};
/// use arcanum_symmetric::builder::EncryptionBuilder;
///
/// let key = Aes256Gcm::generate_key();
/// let nonce = Aes256Gcm::generate_nonce();
///
/// let ciphertext = EncryptionBuilder::<Aes256Gcm>::new()
///     .key(&key)
///     .nonce(&nonce)
///     .encrypt(b"Hello, World!")?;
/// ```
#[derive(Clone)]
pub struct EncryptionBuilder<'a, C: Cipher> {
    key: Option<&'a [u8]>,
    nonce: Option<&'a [u8]>,
    aad: Option<&'a [u8]>,
    _cipher: PhantomData<C>,
}

impl<'a, C: Cipher> Default for EncryptionBuilder<'a, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, C: Cipher> EncryptionBuilder<'a, C> {
    /// Create a new encryption builder.
    #[inline]
    pub fn new() -> Self {
        Self {
            key: None,
            nonce: None,
            aad: None,
            _cipher: PhantomData,
        }
    }

    /// Set the encryption key.
    ///
    /// # Panics
    ///
    /// This method does not panic, but encryption will fail if the key
    /// has an incorrect length.
    #[inline]
    pub fn key(mut self, key: &'a [u8]) -> Self {
        self.key = Some(key);
        self
    }

    /// Set the nonce (initialization vector).
    ///
    /// # Security
    ///
    /// **Never reuse a nonce with the same key.** This is catastrophic
    /// for GCM and Poly1305-based ciphers.
    #[inline]
    pub fn nonce(mut self, nonce: &'a [u8]) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set additional authenticated data (AAD).
    ///
    /// AAD is authenticated but not encrypted. It binds the ciphertext
    /// to additional context (e.g., user ID, timestamp).
    #[inline]
    pub fn aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }

    /// Encrypt the plaintext.
    ///
    /// Returns the ciphertext with the authentication tag appended.
    ///
    /// # Errors
    ///
    /// - `MissingKey` if no key was provided
    /// - `MissingNonce` if no nonce was provided
    /// - `InvalidKeyLength` if the key has wrong length
    /// - `InvalidNonceLength` if the nonce has wrong length
    /// - `EncryptionFailed` if encryption fails
    #[must_use = "encryption result must be checked for errors"]
    pub fn encrypt(self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.ok_or(Error::MissingKey)?;
        let nonce = self.nonce.ok_or(Error::MissingNonce)?;

        C::encrypt(key, nonce, plaintext, self.aad)
    }

    /// Decrypt the ciphertext.
    ///
    /// Returns the plaintext if decryption and authentication succeed.
    ///
    /// # Errors
    ///
    /// - `MissingKey` if no key was provided
    /// - `MissingNonce` if no nonce was provided
    /// - `InvalidKeyLength` if the key has wrong length
    /// - `InvalidNonceLength` if the nonce has wrong length
    /// - `DecryptionFailed` if decryption or authentication fails
    #[must_use = "decryption result must be checked - failure indicates tampering"]
    pub fn decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = self.key.ok_or(Error::MissingKey)?;
        let nonce = self.nonce.ok_or(Error::MissingNonce)?;

        C::decrypt(key, nonce, ciphertext, self.aad)
    }
}

/// Extension trait for ciphers to enable builder pattern.
pub trait CipherExt: Cipher {
    /// Create a new encryption builder for this cipher.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use arcanum_symmetric::{Aes256Gcm, CipherExt};
    ///
    /// let ciphertext = Aes256Gcm::builder()
    ///     .key(&key)
    ///     .nonce(&nonce)
    ///     .encrypt(b"secret")?;
    /// ```
    fn builder<'a>() -> EncryptionBuilder<'a, Self>
    where
        Self: Sized,
    {
        EncryptionBuilder::new()
    }
}

// Implement CipherExt for all Cipher types
impl<T: Cipher> CipherExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Aes256Gcm;

    #[test]
    fn test_builder_encrypt_decrypt() {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = b"Hello, builder pattern!";

        let ciphertext = EncryptionBuilder::<Aes256Gcm>::new()
            .key(&key)
            .nonce(&nonce)
            .encrypt(plaintext)
            .unwrap();

        let decrypted = EncryptionBuilder::<Aes256Gcm>::new()
            .key(&key)
            .nonce(&nonce)
            .decrypt(&ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_builder_with_aad() {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = b"Secret data";
        let aad = b"user_id=12345";

        let ciphertext = EncryptionBuilder::<Aes256Gcm>::new()
            .key(&key)
            .nonce(&nonce)
            .aad(aad)
            .encrypt(plaintext)
            .unwrap();

        let decrypted = EncryptionBuilder::<Aes256Gcm>::new()
            .key(&key)
            .nonce(&nonce)
            .aad(aad)
            .decrypt(&ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_builder_wrong_aad_fails() {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = b"Secret";

        let ciphertext = EncryptionBuilder::<Aes256Gcm>::new()
            .key(&key)
            .nonce(&nonce)
            .aad(b"correct_aad")
            .encrypt(plaintext)
            .unwrap();

        let result = EncryptionBuilder::<Aes256Gcm>::new()
            .key(&key)
            .nonce(&nonce)
            .aad(b"wrong_aad")
            .decrypt(&ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_ext_trait() {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = b"Using CipherExt trait";

        let ciphertext = Aes256Gcm::builder()
            .key(&key)
            .nonce(&nonce)
            .encrypt(plaintext)
            .unwrap();

        let decrypted = Aes256Gcm::builder()
            .key(&key)
            .nonce(&nonce)
            .decrypt(&ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_missing_key_error() {
        let nonce = Aes256Gcm::generate_nonce();

        let result = EncryptionBuilder::<Aes256Gcm>::new()
            .nonce(&nonce)
            .encrypt(b"test");

        assert!(matches!(result, Err(Error::MissingKey)));
    }

    #[test]
    fn test_missing_nonce_error() {
        let key = Aes256Gcm::generate_key();

        let result = EncryptionBuilder::<Aes256Gcm>::new()
            .key(&key)
            .encrypt(b"test");

        assert!(matches!(result, Err(Error::MissingNonce)));
    }
}
