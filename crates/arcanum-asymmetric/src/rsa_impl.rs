//! RSA encryption and signatures.
//!
//! RSA with modern padding schemes for encryption and signatures.
//!
//! ## Padding Schemes
//!
//! ### Encryption
//! - **OAEP** (Optimal Asymmetric Encryption Padding): Recommended
//! - **PKCS#1 v1.5**: Legacy, avoid for new applications
//!
//! ### Signatures
//! - **PSS** (Probabilistic Signature Scheme): Recommended
//! - **PKCS#1 v1.5**: Legacy, still widely used
//!
//! ## Key Sizes
//!
//! - 2048 bits: Minimum recommended (128-bit security until ~2030)
//! - 3072 bits: 128-bit security beyond 2030
//! - 4096 bits: Higher security margin
//!
//! ## Warning
//!
//! RSA is significantly slower than ECC. Prefer ECIES or X25519 for
//! new applications unless RSA is specifically required.

use crate::traits::{AsymmetricDecrypt, AsymmetricEncrypt, RsaKeySize};
use arcanum_core::error::{Error, Result};
use rand::rngs::OsRng;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{
    Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey as InnerPrivateKey,
    RsaPublicKey as InnerPublicKey, traits::PublicKeyParts,
};
use sha2::{Sha256, Sha384, Sha512};
use zeroize::ZeroizeOnDrop;

/// RSA private key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RsaPrivateKey {
    #[zeroize(skip)]
    inner: InnerPrivateKey,
}

impl RsaPrivateKey {
    /// Generate a new RSA private key.
    #[must_use = "key generation result must be checked for errors"]
    pub fn generate(bits: usize) -> Result<Self> {
        let inner =
            InnerPrivateKey::new(&mut OsRng, bits).map_err(|_| Error::KeyGenerationFailed)?;
        Ok(Self { inner })
    }

    /// Get the key size in bits.
    pub fn bits(&self) -> usize {
        self.inner.size() * 8
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            inner: self.inner.to_public_key(),
        }
    }

    /// Decrypt using OAEP padding (recommended).
    #[must_use = "decryption result must be checked - failure indicates tampering"]
    pub fn decrypt_oaep(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        self.inner
            .decrypt(padding, ciphertext)
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Decrypt using OAEP with SHA-384.
    #[must_use = "decryption result must be checked - failure indicates tampering"]
    pub fn decrypt_oaep_sha384(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha384>();
        self.inner
            .decrypt(padding, ciphertext)
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Decrypt using OAEP with SHA-512.
    #[must_use = "decryption result must be checked - failure indicates tampering"]
    pub fn decrypt_oaep_sha512(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha512>();
        self.inner
            .decrypt(padding, ciphertext)
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Decrypt using PKCS#1 v1.5 padding (legacy).
    #[deprecated(note = "Use OAEP instead for new applications")]
    pub fn decrypt_pkcs1(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Sign a message using PSS padding (recommended).
    pub fn sign_pss(&self, message: &[u8]) -> RsaPssSignature {
        use rsa::pss::BlindedSigningKey;
        use sha2::Sha256;

        let signing_key = BlindedSigningKey::<Sha256>::new(self.inner.clone());
        let signature = signing_key.sign_with_rng(&mut OsRng, message);
        RsaPssSignature {
            bytes: signature.to_bytes().into_vec(),
        }
    }

    /// Sign a message using PKCS#1 v1.5 padding.
    pub fn sign_pkcs1(&self, message: &[u8]) -> RsaPkcs1Signature {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Signer;

        let signing_key = SigningKey::<Sha256>::new(self.inner.clone());
        let signature = signing_key.sign(message);
        RsaPkcs1Signature {
            bytes: signature.to_bytes().into_vec(),
        }
    }

    /// Export to PKCS#8 DER format.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        use pkcs8::EncodePrivateKey;
        let der = self
            .inner
            .to_pkcs8_der()
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(der.as_bytes().to_vec())
    }

    /// Import from PKCS#8 DER format.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        let inner = InnerPrivateKey::from_pkcs8_der(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export to PKCS#8 PEM format.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        use pkcs8::EncodePrivateKey;
        use pkcs8::LineEnding;
        let pem = self
            .inner
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(pem.to_string())
    }

    /// Import from PKCS#8 PEM format.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        let inner = InnerPrivateKey::from_pkcs8_pem(pem).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPrivateKey({}-bit, [REDACTED])", self.bits())
    }
}

/// RSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    inner: InnerPublicKey,
}

impl RsaPublicKey {
    /// Get the key size in bits.
    pub fn bits(&self) -> usize {
        self.inner.size() * 8
    }

    /// Encrypt using OAEP padding (recommended).
    pub fn encrypt_oaep(&self, plaintext: &[u8]) -> Result<RsaOaepCiphertext> {
        let padding = Oaep::new::<Sha256>();
        let ciphertext = self
            .inner
            .encrypt(&mut OsRng, padding, plaintext)
            .map_err(|_| Error::EncryptionFailed)?;
        Ok(RsaOaepCiphertext { bytes: ciphertext })
    }

    /// Encrypt using OAEP with SHA-384.
    pub fn encrypt_oaep_sha384(&self, plaintext: &[u8]) -> Result<RsaOaepCiphertext> {
        let padding = Oaep::new::<Sha384>();
        let ciphertext = self
            .inner
            .encrypt(&mut OsRng, padding, plaintext)
            .map_err(|_| Error::EncryptionFailed)?;
        Ok(RsaOaepCiphertext { bytes: ciphertext })
    }

    /// Encrypt using OAEP with SHA-512.
    pub fn encrypt_oaep_sha512(&self, plaintext: &[u8]) -> Result<RsaOaepCiphertext> {
        let padding = Oaep::new::<Sha512>();
        let ciphertext = self
            .inner
            .encrypt(&mut OsRng, padding, plaintext)
            .map_err(|_| Error::EncryptionFailed)?;
        Ok(RsaOaepCiphertext { bytes: ciphertext })
    }

    /// Encrypt using PKCS#1 v1.5 padding (legacy).
    #[deprecated(note = "Use OAEP instead for new applications")]
    pub fn encrypt_pkcs1(&self, plaintext: &[u8]) -> Result<RsaPkcs1Ciphertext> {
        let ciphertext = self
            .inner
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext)
            .map_err(|_| Error::EncryptionFailed)?;
        Ok(RsaPkcs1Ciphertext { bytes: ciphertext })
    }

    /// Verify a PSS signature.
    #[must_use = "signature verification must be checked - ignoring bypasses authentication"]
    pub fn verify_pss(&self, message: &[u8], signature: &RsaPssSignature) -> Result<()> {
        use rsa::pss::VerifyingKey;

        let verifying_key = VerifyingKey::<Sha256>::new(self.inner.clone());
        let sig = rsa::pss::Signature::try_from(signature.bytes.as_slice())
            .map_err(|_| Error::InvalidSignature)?;
        verifying_key
            .verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    /// Verify a PKCS#1 v1.5 signature.
    #[must_use = "signature verification must be checked - ignoring bypasses authentication"]
    pub fn verify_pkcs1(&self, message: &[u8], signature: &RsaPkcs1Signature) -> Result<()> {
        use rsa::pkcs1v15::VerifyingKey;

        let verifying_key = VerifyingKey::<Sha256>::new(self.inner.clone());
        let sig = rsa::pkcs1v15::Signature::try_from(signature.bytes.as_slice())
            .map_err(|_| Error::InvalidSignature)?;
        verifying_key
            .verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    /// Export to SPKI DER format.
    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        use spki::EncodePublicKey;
        let der = self
            .inner
            .to_public_key_der()
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(der.as_bytes().to_vec())
    }

    /// Import from SPKI DER format.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self> {
        use spki::DecodePublicKey;
        let inner =
            InnerPublicKey::from_public_key_der(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Export to SPKI PEM format.
    pub fn to_spki_pem(&self) -> Result<String> {
        use pkcs8::LineEnding;
        use spki::EncodePublicKey;
        let pem = self
            .inner
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(pem)
    }

    /// Import from SPKI PEM format.
    pub fn from_spki_pem(pem: &str) -> Result<Self> {
        use spki::DecodePublicKey;
        let inner =
            InnerPublicKey::from_public_key_pem(pem).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    /// Get the maximum plaintext size for OAEP with SHA-256.
    pub fn max_oaep_plaintext_size(&self) -> usize {
        // OAEP overhead: 2 * hash_len + 2 = 2 * 32 + 2 = 66 bytes for SHA-256
        self.inner.size() - 66
    }
}

impl std::fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPublicKey({}-bit)", self.bits())
    }
}

/// RSA key pair (private + public).
pub struct RsaKeyPair {
    /// Private key.
    pub private: RsaPrivateKey,
    /// Public key.
    pub public: RsaPublicKey,
}

impl RsaKeyPair {
    /// Generate a new RSA key pair.
    pub fn generate(bits: usize) -> Result<Self> {
        let private = RsaPrivateKey::generate(bits)?;
        let public = private.public_key();
        Ok(Self { private, public })
    }

    /// Generate with a predefined key size.
    pub fn generate_with_size(size: RsaKeySize) -> Result<Self> {
        Self::generate(size.bits())
    }
}

impl std::fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaKeyPair({}-bit)", self.public.bits())
    }
}

/// RSA-OAEP ciphertext.
#[derive(Clone)]
pub struct RsaOaepCiphertext {
    bytes: Vec<u8>,
}

impl RsaOaepCiphertext {
    /// Get the raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl std::fmt::Debug for RsaOaepCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaOaepCiphertext({} bytes)", self.bytes.len())
    }
}

/// RSA-PKCS#1 v1.5 ciphertext (legacy).
#[derive(Clone)]
pub struct RsaPkcs1Ciphertext {
    bytes: Vec<u8>,
}

impl RsaPkcs1Ciphertext {
    /// Get the raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl std::fmt::Debug for RsaPkcs1Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPkcs1Ciphertext({} bytes)", self.bytes.len())
    }
}

/// RSA-PSS signature.
#[derive(Clone)]
pub struct RsaPssSignature {
    bytes: Vec<u8>,
}

impl RsaPssSignature {
    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}

impl std::fmt::Debug for RsaPssSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPssSignature({} bytes)", self.bytes.len())
    }
}

/// RSA-PKCS#1 v1.5 signature.
#[derive(Clone)]
pub struct RsaPkcs1Signature {
    bytes: Vec<u8>,
}

impl RsaPkcs1Signature {
    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}

impl std::fmt::Debug for RsaPkcs1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPkcs1Signature({} bytes)", self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_oaep_roundtrip() {
        let keypair = RsaKeyPair::generate(2048).unwrap();
        let message = b"Hello, RSA-OAEP!";

        let ciphertext = keypair.public.encrypt_oaep(message).unwrap();
        let decrypted = keypair.private.decrypt_oaep(ciphertext.as_bytes()).unwrap();

        assert_eq!(message.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_rsa_pss_signature() {
        let keypair = RsaKeyPair::generate(2048).unwrap();
        let message = b"Sign this message";

        let signature = keypair.private.sign_pss(message);
        let result = keypair.public.verify_pss(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_rsa_pss_wrong_message_fails() {
        let keypair = RsaKeyPair::generate(2048).unwrap();
        let message = b"Sign this message";
        let wrong_message = b"Wrong message";

        let signature = keypair.private.sign_pss(message);
        let result = keypair.public.verify_pss(wrong_message, &signature);

        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_pkcs1_signature() {
        let keypair = RsaKeyPair::generate(2048).unwrap();
        let message = b"Sign this message";

        let signature = keypair.private.sign_pkcs1(message);
        let result = keypair.public.verify_pkcs1(message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_rsa_key_sizes() {
        let keypair_2048 = RsaKeyPair::generate(2048).unwrap();
        assert_eq!(keypair_2048.public.bits(), 2048);

        // Note: 3072+ bit key generation is slow in tests
    }

    #[test]
    fn test_rsa_key_serialization() {
        let keypair = RsaKeyPair::generate(2048).unwrap();

        // Private key PKCS#8
        let private_der = keypair.private.to_pkcs8_der().unwrap();
        let restored_private = RsaPrivateKey::from_pkcs8_der(&private_der).unwrap();
        assert_eq!(keypair.private.bits(), restored_private.bits());

        // Public key SPKI
        let public_der = keypair.public.to_spki_der().unwrap();
        let restored_public = RsaPublicKey::from_spki_der(&public_der).unwrap();
        assert_eq!(keypair.public, restored_public);
    }

    #[test]
    fn test_rsa_pem_serialization() {
        let keypair = RsaKeyPair::generate(2048).unwrap();

        // Private key PEM
        let private_pem = keypair.private.to_pkcs8_pem().unwrap();
        assert!(private_pem.contains("BEGIN PRIVATE KEY"));
        let restored_private = RsaPrivateKey::from_pkcs8_pem(&private_pem).unwrap();
        assert_eq!(keypair.private.bits(), restored_private.bits());

        // Public key PEM
        let public_pem = keypair.public.to_spki_pem().unwrap();
        assert!(public_pem.contains("BEGIN PUBLIC KEY"));
        let restored_public = RsaPublicKey::from_spki_pem(&public_pem).unwrap();
        assert_eq!(keypair.public, restored_public);
    }

    #[test]
    fn test_rsa_max_plaintext_size() {
        let keypair = RsaKeyPair::generate(2048).unwrap();
        let max_size = keypair.public.max_oaep_plaintext_size();

        // 2048 bits = 256 bytes, minus 66 bytes OAEP overhead = 190 bytes
        assert_eq!(max_size, 190);

        // Should be able to encrypt max_size bytes
        let message = vec![0xABu8; max_size];
        let ciphertext = keypair.public.encrypt_oaep(&message).unwrap();
        let decrypted = keypair.private.decrypt_oaep(ciphertext.as_bytes()).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_rsa_wrong_key_decryption_fails() {
        let keypair1 = RsaKeyPair::generate(2048).unwrap();
        let keypair2 = RsaKeyPair::generate(2048).unwrap();

        let message = b"Secret message";
        let ciphertext = keypair1.public.encrypt_oaep(message).unwrap();

        // Decryption with wrong key should fail
        let result = keypair2.private.decrypt_oaep(ciphertext.as_bytes());
        assert!(result.is_err());
    }
}
