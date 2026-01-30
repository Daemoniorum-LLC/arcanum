//! ECIES (Elliptic Curve Integrated Encryption Scheme).
//!
//! ECIES combines ECDH key agreement with symmetric encryption to provide
//! public-key encryption using elliptic curves.
//!
//! ## How ECIES Works
//!
//! 1. Generate ephemeral EC key pair
//! 2. Perform ECDH with recipient's public key
//! 3. Derive symmetric key from shared secret using KDF
//! 4. Encrypt message with symmetric cipher (e.g., AES-GCM)
//! 5. Output: ephemeral public key + ciphertext + auth tag
//!
//! ## Variants
//!
//! - **ECIES-P256**: NIST P-256 curve
//! - **ECIES-P384**: NIST P-384 curve
//! - **ECIES-secp256k1**: Bitcoin curve (compatible with Ethereum)

use crate::ecdh::{
    P256PublicKey, P256SecretKey, P384PublicKey, P384SecretKey, Secp256k1PublicKey,
    Secp256k1SecretKey,
};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use arcanum_core::error::{Error, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// ECIES ciphertext containing ephemeral public key and encrypted data.
#[derive(Clone)]
pub struct EciesCiphertext {
    /// Ephemeral public key (SEC1 compressed format).
    pub ephemeral_public: Vec<u8>,
    /// Nonce for the symmetric cipher.
    pub nonce: [u8; 12],
    /// Encrypted data with authentication tag.
    pub ciphertext: Vec<u8>,
}

impl EciesCiphertext {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Length-prefixed ephemeral public key
        bytes.push(self.ephemeral_public.len() as u8);
        bytes.extend_from_slice(&self.ephemeral_public);
        // Nonce
        bytes.extend_from_slice(&self.nonce);
        // Ciphertext
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::InvalidCiphertext);
        }

        let pk_len = bytes[0] as usize;
        if bytes.len() < 1 + pk_len + 12 {
            return Err(Error::InvalidCiphertext);
        }

        let ephemeral_public = bytes[1..1 + pk_len].to_vec();
        let nonce: [u8; 12] = bytes[1 + pk_len..1 + pk_len + 12]
            .try_into()
            .map_err(|_| Error::InvalidCiphertext)?;
        let ciphertext = bytes[1 + pk_len + 12..].to_vec();

        Ok(Self {
            ephemeral_public,
            nonce,
            ciphertext,
        })
    }

    /// Get the total size in bytes.
    pub fn size(&self) -> usize {
        1 + self.ephemeral_public.len() + 12 + self.ciphertext.len()
    }
}

impl core::fmt::Debug for EciesCiphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EciesCiphertext({} bytes)", self.size())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECIES-P256
// ═══════════════════════════════════════════════════════════════════════════════

/// ECIES with P-256 curve.
pub struct EciesP256;

impl EciesP256 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ECIES-P256-AES256-GCM";

    /// HKDF info string.
    const HKDF_INFO: &'static [u8] = b"ECIES-P256-AES256-GCM";

    /// Encrypt a message to a recipient's public key.
    pub fn encrypt(recipient_public: &P256PublicKey, plaintext: &[u8]) -> Result<EciesCiphertext> {
        // Generate ephemeral key pair
        let ephemeral_secret = P256SecretKey::generate();
        let ephemeral_public = ephemeral_secret.public_key();

        // ECDH to derive shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(recipient_public)?;

        // Derive symmetric key using HKDF
        let mut symmetric_key = Self::derive_key(shared_secret.as_bytes())?;

        // Generate random nonce
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        // Encrypt with AES-256-GCM
        let cipher =
            Aes256Gcm::new_from_slice(&symmetric_key).map_err(|_| Error::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::EncryptionFailed)?;

        // Zeroize key material
        symmetric_key.zeroize();

        Ok(EciesCiphertext {
            ephemeral_public: ephemeral_public.to_sec1_bytes_compressed(),
            nonce,
            ciphertext,
        })
    }

    /// Decrypt a message using the recipient's secret key.
    #[must_use = "decryption result must be checked - failure indicates tampering"]
    pub fn decrypt(
        recipient_secret: &P256SecretKey,
        ciphertext: &EciesCiphertext,
    ) -> Result<Vec<u8>> {
        // Parse ephemeral public key
        let ephemeral_public = P256PublicKey::from_sec1_bytes(&ciphertext.ephemeral_public)?;

        // ECDH to derive shared secret
        let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public)?;

        // Derive symmetric key using HKDF
        let mut symmetric_key = Self::derive_key(shared_secret.as_bytes())?;

        // Decrypt with AES-256-GCM
        let cipher =
            Aes256Gcm::new_from_slice(&symmetric_key).map_err(|_| Error::DecryptionFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&ciphertext.nonce),
                ciphertext.ciphertext.as_slice(),
            )
            .map_err(|_| Error::DecryptionFailed)?;

        // Zeroize key material
        symmetric_key.zeroize();

        Ok(plaintext)
    }

    fn derive_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(Self::HKDF_INFO, &mut key)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(key)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECIES-P384
// ═══════════════════════════════════════════════════════════════════════════════

/// ECIES with P-384 curve.
pub struct EciesP384;

impl EciesP384 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ECIES-P384-AES256-GCM";

    /// HKDF info string.
    const HKDF_INFO: &'static [u8] = b"ECIES-P384-AES256-GCM";

    /// Encrypt a message to a recipient's public key.
    pub fn encrypt(recipient_public: &P384PublicKey, plaintext: &[u8]) -> Result<EciesCiphertext> {
        // Generate ephemeral key pair
        let ephemeral_secret = P384SecretKey::generate();
        let ephemeral_public = ephemeral_secret.public_key();

        // ECDH to derive shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(recipient_public)?;

        // Derive symmetric key using HKDF
        let mut symmetric_key = Self::derive_key(shared_secret.as_bytes())?;

        // Generate random nonce
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        // Encrypt with AES-256-GCM
        let cipher =
            Aes256Gcm::new_from_slice(&symmetric_key).map_err(|_| Error::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::EncryptionFailed)?;

        // Zeroize key material
        symmetric_key.zeroize();

        Ok(EciesCiphertext {
            ephemeral_public: ephemeral_public.to_sec1_bytes_compressed(),
            nonce,
            ciphertext,
        })
    }

    /// Decrypt a message using the recipient's secret key.
    #[must_use = "decryption result must be checked - failure indicates tampering"]
    pub fn decrypt(
        recipient_secret: &P384SecretKey,
        ciphertext: &EciesCiphertext,
    ) -> Result<Vec<u8>> {
        // Parse ephemeral public key
        let ephemeral_public = P384PublicKey::from_sec1_bytes(&ciphertext.ephemeral_public)?;

        // ECDH to derive shared secret
        let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public)?;

        // Derive symmetric key using HKDF
        let mut symmetric_key = Self::derive_key(shared_secret.as_bytes())?;

        // Decrypt with AES-256-GCM
        let cipher =
            Aes256Gcm::new_from_slice(&symmetric_key).map_err(|_| Error::DecryptionFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&ciphertext.nonce),
                ciphertext.ciphertext.as_slice(),
            )
            .map_err(|_| Error::DecryptionFailed)?;

        // Zeroize key material
        symmetric_key.zeroize();

        Ok(plaintext)
    }

    fn derive_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(Self::HKDF_INFO, &mut key)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(key)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECIES-secp256k1
// ═══════════════════════════════════════════════════════════════════════════════

/// ECIES with secp256k1 curve (Ethereum-compatible).
pub struct EciesSecp256k1;

impl EciesSecp256k1 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ECIES-secp256k1-AES256-GCM";

    /// HKDF info string.
    const HKDF_INFO: &'static [u8] = b"ECIES-secp256k1-AES256-GCM";

    /// Encrypt a message to a recipient's public key.
    pub fn encrypt(
        recipient_public: &Secp256k1PublicKey,
        plaintext: &[u8],
    ) -> Result<EciesCiphertext> {
        // Generate ephemeral key pair
        let ephemeral_secret = Secp256k1SecretKey::generate();
        let ephemeral_public = ephemeral_secret.public_key();

        // ECDH to derive shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(recipient_public)?;

        // Derive symmetric key using HKDF
        let mut symmetric_key = Self::derive_key(shared_secret.as_bytes())?;

        // Generate random nonce
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        // Encrypt with AES-256-GCM
        let cipher =
            Aes256Gcm::new_from_slice(&symmetric_key).map_err(|_| Error::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::EncryptionFailed)?;

        // Zeroize key material
        symmetric_key.zeroize();

        Ok(EciesCiphertext {
            ephemeral_public: ephemeral_public.to_sec1_bytes_compressed(),
            nonce,
            ciphertext,
        })
    }

    /// Decrypt a message using the recipient's secret key.
    #[must_use = "decryption result must be checked - failure indicates tampering"]
    pub fn decrypt(
        recipient_secret: &Secp256k1SecretKey,
        ciphertext: &EciesCiphertext,
    ) -> Result<Vec<u8>> {
        // Parse ephemeral public key
        let ephemeral_public = Secp256k1PublicKey::from_sec1_bytes(&ciphertext.ephemeral_public)?;

        // ECDH to derive shared secret
        let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public)?;

        // Derive symmetric key using HKDF
        let mut symmetric_key = Self::derive_key(shared_secret.as_bytes())?;

        // Decrypt with AES-256-GCM
        let cipher =
            Aes256Gcm::new_from_slice(&symmetric_key).map_err(|_| Error::DecryptionFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&ciphertext.nonce),
                ciphertext.ciphertext.as_slice(),
            )
            .map_err(|_| Error::DecryptionFailed)?;

        // Zeroize key material
        symmetric_key.zeroize();

        Ok(plaintext)
    }

    fn derive_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(Self::HKDF_INFO, &mut key)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdh::{EcdhP256, EcdhP384, EcdhSecp256k1};

    #[test]
    fn test_ecies_p256_roundtrip() {
        let (secret, public) = EcdhP256::generate();
        let message = b"Hello, ECIES!";

        let ciphertext = EciesP256::encrypt(&public, message).unwrap();
        let decrypted = EciesP256::decrypt(&secret, &ciphertext).unwrap();

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_p384_roundtrip() {
        let (secret, public) = EcdhP384::generate();
        let message = b"Hello, ECIES with P-384!";

        let ciphertext = EciesP384::encrypt(&public, message).unwrap();
        let decrypted = EciesP384::decrypt(&secret, &ciphertext).unwrap();

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_secp256k1_roundtrip() {
        let (secret, public) = EcdhSecp256k1::generate();
        let message = b"Hello, Ethereum!";

        let ciphertext = EciesSecp256k1::encrypt(&public, message).unwrap();
        let decrypted = EciesSecp256k1::decrypt(&secret, &ciphertext).unwrap();

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_wrong_key_fails() {
        let (_, public1) = EcdhP256::generate();
        let (secret2, _) = EcdhP256::generate();
        let message = b"Secret message";

        let ciphertext = EciesP256::encrypt(&public1, message).unwrap();
        let result = EciesP256::decrypt(&secret2, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_ciphertext_serialization() {
        let (secret, public) = EcdhP256::generate();
        let message = b"Test serialization";

        let ciphertext = EciesP256::encrypt(&public, message).unwrap();
        let bytes = ciphertext.to_bytes();
        let restored = EciesCiphertext::from_bytes(&bytes).unwrap();

        let decrypted = EciesP256::decrypt(&secret, &restored).unwrap();
        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_different_messages_different_ciphertexts() {
        let (_, public) = EcdhP256::generate();

        let ct1 = EciesP256::encrypt(&public, b"message1").unwrap();
        let ct2 = EciesP256::encrypt(&public, b"message1").unwrap();

        // Different ephemeral keys mean different ciphertexts
        assert_ne!(ct1.ephemeral_public, ct2.ephemeral_public);
    }

    #[test]
    fn test_ecies_empty_message() {
        let (secret, public) = EcdhP256::generate();

        let ciphertext = EciesP256::encrypt(&public, b"").unwrap();
        let decrypted = EciesP256::decrypt(&secret, &ciphertext).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_ecies_large_message() {
        let (secret, public) = EcdhP256::generate();
        let message = vec![0xABu8; 1024 * 1024]; // 1 MB

        let ciphertext = EciesP256::encrypt(&public, &message).unwrap();
        let decrypted = EciesP256::decrypt(&secret, &ciphertext).unwrap();

        assert_eq!(message, decrypted);
    }
}
