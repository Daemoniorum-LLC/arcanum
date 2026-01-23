//! Schnorr digital signatures.
//!
//! Schnorr signatures over secp256k1, compatible with BIP-340 (Bitcoin Taproot).
//!
//! Advantages over ECDSA:
//! - Provable security under standard assumptions
//! - Linear (enables signature aggregation)
//! - Simpler, more efficient

use crate::traits;
use arcanum_core::error::{Error, Result};
use k256::schnorr::{
    Signature as SchnorrSignatureInner, SigningKey as SchnorrSigningKeyInner,
    VerifyingKey as SchnorrVerifyingKeyInner,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

// ═══════════════════════════════════════════════════════════════════════════════
// SCHNORR SIGNING KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// Schnorr signing key (secp256k1, BIP-340 compatible).
#[derive(Clone, ZeroizeOnDrop)]
pub struct SchnorrSigningKey {
    inner: SchnorrSigningKeyInner,
}

impl traits::SigningKey for SchnorrSigningKey {
    type VerifyingKey = SchnorrVerifyingKey;
    type Signature = SchnorrSignature;

    const ALGORITHM: &'static str = "Schnorr-secp256k1";
    const KEY_SIZE: usize = 32;

    fn generate() -> Self {
        let inner = SchnorrSigningKeyInner::random(&mut OsRng);
        Self { inner }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner =
            SchnorrSigningKeyInner::from_bytes(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        SchnorrVerifyingKey {
            inner: *self.inner.verifying_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        use signature::Signer;
        let sig = self.inner.sign(message);
        SchnorrSignature { inner: sig }
    }

    fn sign_prehashed(&self, hash: &[u8]) -> Result<Self::Signature> {
        // BIP-340 signs the message directly (it's already tagged-hashed internally)
        Ok(self.sign(hash))
    }
}

impl std::fmt::Debug for SchnorrSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SchnorrSigningKey([REDACTED])")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCHNORR VERIFYING KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// Schnorr verifying key (x-only public key per BIP-340).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrVerifyingKey {
    #[serde(with = "schnorr_verifying_key_serde")]
    inner: SchnorrVerifyingKeyInner,
}

mod schnorr_verifying_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        key: &SchnorrVerifyingKeyInner,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<SchnorrVerifyingKeyInner, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };

        SchnorrVerifyingKeyInner::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl traits::VerifyingKey for SchnorrVerifyingKey {
    type Signature = SchnorrSignature;

    const ALGORITHM: &'static str = "Schnorr-secp256k1";
    const KEY_SIZE: usize = 32; // X-only (no sign byte)

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner =
            SchnorrVerifyingKeyInner::from_bytes(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<()> {
        use signature::Verifier;
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    fn verify_prehashed(&self, hash: &[u8], signature: &Self::Signature) -> Result<()> {
        self.verify(hash, signature)
    }
}

impl std::fmt::Debug for SchnorrVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SchnorrVerifyingKey({})",
            hex::encode(self.inner.to_bytes())
        )
    }
}

impl std::fmt::Display for SchnorrVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.inner.to_bytes()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCHNORR SIGNATURE
// ═══════════════════════════════════════════════════════════════════════════════

/// Schnorr signature (64 bytes per BIP-340).
#[derive(Clone, Serialize, Deserialize)]
pub struct SchnorrSignature {
    #[serde(with = "schnorr_signature_serde")]
    inner: SchnorrSignatureInner,
}

mod schnorr_signature_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        sig: &SchnorrSignatureInner,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = sig.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<SchnorrSignatureInner, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };

        SchnorrSignatureInner::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

impl traits::Signature for SchnorrSignature {
    const SIZE: usize = 64;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = SchnorrSignatureInner::try_from(bytes).map_err(|_| Error::InvalidSignature)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl std::fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SchnorrSignature({})",
            hex::encode(self.inner.to_bytes())
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a new Schnorr key pair.
pub fn generate_keypair() -> (SchnorrSigningKey, SchnorrVerifyingKey) {
    use crate::traits::SigningKey;
    let signing_key = SchnorrSigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Signature, SigningKey, VerifyingKey};

    #[test]
    fn test_sign_verify() {
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, Schnorr!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello!";
        let wrong_message = b"Wrong!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_key_roundtrip() {
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let bytes = verifying_key.to_bytes();
        let restored = SchnorrVerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, restored);
    }

    #[test]
    fn test_signature_roundtrip() {
        let signing_key = SchnorrSigningKey::generate();
        let message = b"Test";
        let signature = signing_key.sign(message);

        let bytes = signature.to_bytes();
        let restored = SchnorrSignature::from_bytes(&bytes).unwrap();

        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &restored).is_ok());
    }

    #[test]
    fn test_x_only_public_key() {
        // Schnorr uses 32-byte x-only public keys
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        assert_eq!(verifying_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_serde_json() {
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let json = serde_json::to_string(&verifying_key).unwrap();
        let restored: SchnorrVerifyingKey = serde_json::from_str(&json).unwrap();

        assert_eq!(verifying_key, restored);
    }
}
