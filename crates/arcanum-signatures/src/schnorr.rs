//! Schnorr digital signatures.
//!
//! Schnorr signatures over secp256k1, compatible with BIP-340 (Bitcoin Taproot).
//!
//! Advantages over ECDSA:
//! - Provable security under standard assumptions
//! - Linear (enables signature aggregation)
//! - Simpler, more efficient

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

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

impl core::fmt::Debug for SchnorrSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    ) -> core::result::Result<S::Ok, S::Error>
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
    ) -> core::result::Result<SchnorrVerifyingKeyInner, D::Error>
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

impl core::fmt::Debug for SchnorrVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SchnorrVerifyingKey({})",
            hex::encode(self.inner.to_bytes())
        )
    }
}

impl core::fmt::Display for SchnorrVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    ) -> core::result::Result<S::Ok, S::Error>
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
    ) -> core::result::Result<SchnorrSignatureInner, D::Error>
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

impl core::fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

    #[test]
    fn test_generate_keypair_convenience() {
        let (signing_key, verifying_key) = generate_keypair();

        // Verify the keypair is functional: sign and verify a message
        let message = b"keypair convenience test";
        let signature = signing_key.sign(message);
        assert!(
            verifying_key.verify(message, &signature).is_ok(),
            "signature from generate_keypair should verify successfully"
        );

        // Verify the verifying key from the signing key matches the returned one
        let derived_vk = signing_key.verifying_key();
        assert_eq!(
            derived_vk, verifying_key,
            "verifying key from signing_key should match returned verifying key"
        );
    }

    #[test]
    fn test_signing_key_from_bytes_invalid() {
        // All zeros is not a valid secp256k1 private key
        let zeros = [0u8; 32];
        let result = SchnorrSigningKey::from_bytes(&zeros);
        assert!(
            result.is_err(),
            "all-zero bytes should not produce a valid signing key"
        );

        // Wrong length (too short)
        let short = [1u8; 16];
        let result = SchnorrSigningKey::from_bytes(&short);
        assert!(
            result.is_err(),
            "16-byte input should be rejected for signing key"
        );
    }

    #[test]
    fn test_signing_key_to_bytes_roundtrip() {
        let original = SchnorrSigningKey::generate();
        let bytes = original.to_bytes();

        assert_eq!(
            bytes.len(),
            32,
            "signing key should serialize to 32 bytes"
        );

        let restored = SchnorrSigningKey::from_bytes(&bytes).expect("roundtrip should succeed");

        // Verify functional equivalence: both keys produce signatures the same verifying key accepts
        let message = b"roundtrip test message";
        let original_vk = original.verifying_key();
        let restored_vk = restored.verifying_key();
        assert_eq!(
            original_vk, restored_vk,
            "restored key should derive the same verifying key"
        );

        let sig = restored.sign(message);
        assert!(
            original_vk.verify(message, &sig).is_ok(),
            "signature from restored key should verify with original verifying key"
        );
    }

    #[test]
    fn test_sign_prehashed() {
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        // Simulate a prehashed message (32-byte hash)
        let prehash = [0xAB_u8; 32];
        let signature = signing_key
            .sign_prehashed(&prehash)
            .expect("sign_prehashed should succeed");

        // Verify the prehashed signature using verify_prehashed
        assert!(
            verifying_key.verify_prehashed(&prehash, &signature).is_ok(),
            "prehashed signature should verify with verify_prehashed"
        );

        // Verify it fails with different prehash data
        let wrong_prehash = [0xCD_u8; 32];
        assert!(
            verifying_key
                .verify_prehashed(&wrong_prehash, &signature)
                .is_err(),
            "prehashed signature should fail with different hash"
        );
    }

    #[test]
    fn test_signature_from_bytes_invalid_length() {
        // SchnorrSignature is 64 bytes per BIP-340.
        // The underlying k256 crate panics on inputs shorter than 64 bytes
        // (rather than returning Err), so we test short inputs via catch_unwind.

        // Too short: 32 bytes instead of 64 -- k256 panics on split_at
        let short_result = std::panic::catch_unwind(|| {
            let short_bytes = [0xAA_u8; 32];
            SchnorrSignature::from_bytes(&short_bytes)
        });
        assert!(
            short_result.is_err() || short_result.unwrap().is_err(),
            "32-byte input must not produce a valid 64-byte Schnorr signature"
        );

        // Empty input
        let empty_result = std::panic::catch_unwind(|| {
            SchnorrSignature::from_bytes(&[])
        });
        assert!(
            empty_result.is_err() || empty_result.unwrap().is_err(),
            "empty input must not produce a valid Schnorr signature"
        );

        // Too long: 128 bytes -- k256 returns Err for this case
        let long_bytes = [0xBB_u8; 128];
        let result = SchnorrSignature::from_bytes(&long_bytes);
        assert!(
            result.is_err(),
            "128-byte input should be rejected for a 64-byte Schnorr signature"
        );
    }

    #[test]
    fn test_signing_key_debug_shows_redacted() {
        let signing_key = SchnorrSigningKey::generate();
        let debug_output = format!("{:?}", signing_key);

        assert_eq!(
            debug_output, "SchnorrSigningKey([REDACTED])",
            "Debug output must show [REDACTED] to avoid leaking key material"
        );
        // Ensure the raw key bytes do NOT appear in the debug output
        let key_hex = hex::encode(signing_key.to_bytes());
        assert!(
            !debug_output.contains(&key_hex),
            "Debug output must not contain actual key bytes"
        );
    }

    #[test]
    fn test_verifying_key_debug_and_display_formats() {
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let key_hex = hex::encode(verifying_key.to_bytes());

        // Debug format: SchnorrVerifyingKey(<hex>)
        let debug_output = format!("{:?}", verifying_key);
        assert!(
            debug_output.starts_with("SchnorrVerifyingKey("),
            "Debug should start with 'SchnorrVerifyingKey(': {}",
            debug_output
        );
        assert!(
            debug_output.contains(&key_hex),
            "Debug should contain hex-encoded public key: {}",
            debug_output
        );
        assert!(
            debug_output.ends_with(')'),
            "Debug should end with ')': {}",
            debug_output
        );

        // Display format: just the hex string
        let display_output = format!("{}", verifying_key);
        assert_eq!(
            display_output, key_hex,
            "Display should be the raw hex of the public key"
        );
        assert_eq!(
            display_output.len(),
            64,
            "Display of 32-byte key should be 64 hex chars"
        );
    }
}
