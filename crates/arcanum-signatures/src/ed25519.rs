//! Ed25519 digital signatures.
//!
//! Ed25519 is the recommended default signature algorithm:
//! - Fast signing and verification
//! - Small signatures (64 bytes) and keys (32 bytes)
//! - Deterministic: same message always produces same signature
//! - Resistant to side-channel attacks
//! - Widely deployed (SSH, TLS, Signal, etc.)

use crate::traits::{self, BatchVerifier, VerifyingKey};
use arcanum_core::error::{Error, Result};
use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey as DalekSigningKey, Verifier,
    VerifyingKey as DalekVerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNING KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// Ed25519 signing key (private key).
#[derive(Clone, ZeroizeOnDrop)]
pub struct Ed25519SigningKey {
    inner: DalekSigningKey,
}

impl traits::SigningKey for Ed25519SigningKey {
    type VerifyingKey = Ed25519VerifyingKey;
    type Signature = Ed25519Signature;

    const ALGORITHM: &'static str = "Ed25519";
    const KEY_SIZE: usize = 32;

    fn generate() -> Self {
        let inner = DalekSigningKey::generate(&mut OsRng);
        Self { inner }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let inner = DalekSigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();

        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        Ed25519VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let sig = self.inner.sign(message);
        Ed25519Signature { inner: sig }
    }

    fn sign_prehashed(&self, hash: &[u8]) -> Result<Self::Signature> {
        // Ed25519 doesn't directly support prehashed signing in the standard variant
        // For prehashed, use Ed25519ph (not implemented here for simplicity)
        // We'll sign the hash as if it were a message
        Ok(self.sign(hash))
    }
}

impl std::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519SigningKey([REDACTED])")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERIFYING KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// Ed25519 verifying key (public key).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519VerifyingKey {
    #[serde(with = "verifying_key_serde")]
    inner: DalekVerifyingKey,
}

mod verifying_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        key: &DalekVerifyingKey,
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

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<DalekVerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid key length"))?;
            DalekVerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid key length"))?;
            DalekVerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

impl traits::VerifyingKey for Ed25519VerifyingKey {
    type Signature = Ed25519Signature;

    const ALGORITHM: &'static str = "Ed25519";
    const KEY_SIZE: usize = 32;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let inner =
            DalekVerifyingKey::from_bytes(&key_bytes).map_err(|_| Error::InvalidKeyFormat)?;

        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<()> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    fn verify_prehashed(&self, hash: &[u8], signature: &Self::Signature) -> Result<()> {
        // Same as sign_prehashed - treat hash as message
        self.verify(hash, signature)
    }
}

impl std::fmt::Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ed25519VerifyingKey({})",
            hex::encode(self.inner.to_bytes())
        )
    }
}

impl std::fmt::Display for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.inner.to_bytes()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNATURE
// ═══════════════════════════════════════════════════════════════════════════════

/// Ed25519 signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519Signature {
    #[serde(with = "signature_serde")]
    inner: DalekSignature,
}

mod signature_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(sig: &DalekSignature, serializer: S) -> std::result::Result<S::Ok, S::Error>
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

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<DalekSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            let arr: [u8; 64] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid signature length"))?;
            Ok(DalekSignature::from_bytes(&arr))
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            let arr: [u8; 64] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid signature length"))?;
            Ok(DalekSignature::from_bytes(&arr))
        }
    }
}

impl traits::Signature for Ed25519Signature {
    const SIZE: usize = 64;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidSignature);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);

        let inner = DalekSignature::from_bytes(&sig_bytes);
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ed25519Signature({})",
            hex::encode(self.inner.to_bytes())
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Ed25519 batch verifier.
pub struct Ed25519BatchVerifier;

impl BatchVerifier for Ed25519BatchVerifier {
    type VerifyingKey = Ed25519VerifyingKey;
    type Signature = Ed25519Signature;

    fn verify_batch(items: &[(&Self::VerifyingKey, &[u8], &Self::Signature)]) -> Result<()> {
        #[cfg(feature = "batch")]
        {
            let messages: Vec<&[u8]> = items.iter().map(|(_, m, _)| *m).collect();
            let signatures: Vec<DalekSignature> = items.iter().map(|(_, _, s)| s.inner).collect();
            let verifying_keys: Vec<DalekVerifyingKey> =
                items.iter().map(|(k, _, _)| k.inner).collect();

            ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys)
                .map_err(|_| Error::SignatureVerificationFailed)
        }

        #[cfg(not(feature = "batch"))]
        {
            // Fall back to individual verification
            for (key, message, signature) in items {
                key.verify(message, signature)?;
            }
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a new Ed25519 key pair.
pub fn generate_keypair() -> (Ed25519SigningKey, Ed25519VerifyingKey) {
    use crate::traits::SigningKey;
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with Ed25519.
pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8]) -> Ed25519Signature {
    use crate::traits::SigningKey;
    signing_key.sign(message)
}

/// Verify an Ed25519 signature.
pub fn verify(
    verifying_key: &Ed25519VerifyingKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<()> {
    use crate::traits::VerifyingKey;
    verifying_key.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Signature, SigningKey, VerifyingKey};

    #[test]
    fn test_sign_verify() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, Arcanum!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello, Arcanum!";
        let wrong_message = b"Wrong message";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();

        let message = b"Hello, Arcanum!";
        let signature = signing_key.sign(message);

        assert!(
            wrong_key
                .verifying_key()
                .verify(message, &signature)
                .is_err()
        );
    }

    #[test]
    fn test_key_serialization() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        // Serialize and deserialize
        let bytes = verifying_key.to_bytes();
        let restored = Ed25519VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, restored);
    }

    #[test]
    fn test_signature_serialization() {
        let signing_key = Ed25519SigningKey::generate();
        let message = b"Test message";
        let signature = signing_key.sign(message);

        // Serialize and deserialize
        let bytes = signature.to_bytes();
        let restored = Ed25519Signature::from_bytes(&bytes).unwrap();

        // Verify with restored signature
        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &restored).is_ok());
    }

    #[test]
    fn test_deterministic_signatures() {
        let signing_key = Ed25519SigningKey::generate();
        let message = b"Test message";

        let sig1 = signing_key.sign(message);
        let sig2 = signing_key.sign(message);

        // Ed25519 is deterministic
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_hex_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let hex = verifying_key.to_hex();
        let restored = Ed25519VerifyingKey::from_hex(&hex).unwrap();

        assert_eq!(verifying_key, restored);
    }

    #[test]
    fn test_serde_json() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let json = serde_json::to_string(&verifying_key).unwrap();
        let restored: Ed25519VerifyingKey = serde_json::from_str(&json).unwrap();

        assert_eq!(verifying_key, restored);
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PROPERTY-BASED TESTS
    // ═══════════════════════════════════════════════════════════════════════════════

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating arbitrary messages up to 64KB
        fn message_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..65536)
        }

        proptest! {
            /// Property: Sign then verify succeeds for any message
            #[test]
            fn prop_sign_verify_roundtrip(message in message_strategy()) {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let signature = signing_key.sign(&message);
                prop_assert!(verifying_key.verify(&message, &signature).is_ok());
            }

            /// Property: Ed25519 signatures are deterministic
            #[test]
            fn prop_deterministic_signatures(message in message_strategy()) {
                let signing_key = Ed25519SigningKey::generate();

                let sig1 = signing_key.sign(&message);
                let sig2 = signing_key.sign(&message);

                prop_assert_eq!(sig1.to_bytes(), sig2.to_bytes());
            }

            /// Property: Ed25519 signatures are always 64 bytes
            #[test]
            fn prop_signature_size(message in message_strategy()) {
                let signing_key = Ed25519SigningKey::generate();
                let signature = signing_key.sign(&message);

                prop_assert_eq!(signature.to_bytes().len(), 64);
            }

            /// Property: Different keys produce different signatures
            #[test]
            fn prop_different_keys_different_signatures(message in message_strategy()) {
                prop_assume!(!message.is_empty());

                let key1 = Ed25519SigningKey::generate();
                let key2 = Ed25519SigningKey::generate();

                let sig1 = key1.sign(&message);
                let sig2 = key2.sign(&message);

                // Different keys should produce different signatures
                prop_assert_ne!(sig1.to_bytes(), sig2.to_bytes());
            }

            /// Property: Signature fails with wrong key
            #[test]
            fn prop_wrong_key_fails(message in message_strategy()) {
                let signing_key = Ed25519SigningKey::generate();
                let wrong_key = Ed25519SigningKey::generate();

                let signature = signing_key.sign(&message);
                let wrong_verifying_key = wrong_key.verifying_key();

                prop_assert!(wrong_verifying_key.verify(&message, &signature).is_err());
            }

            /// Property: Key serialization roundtrip
            #[test]
            fn prop_key_serialization_roundtrip(seed in any::<[u8; 32]>()) {
                let signing_key = Ed25519SigningKey::from_bytes(&seed).unwrap();
                let verifying_key = signing_key.verifying_key();

                // Test verifying key roundtrip
                let bytes = verifying_key.to_bytes();
                let restored = Ed25519VerifyingKey::from_bytes(&bytes).unwrap();
                prop_assert_eq!(verifying_key.to_bytes(), restored.to_bytes());

                // Test signing key roundtrip
                let key_bytes = signing_key.to_bytes();
                let restored_signing = Ed25519SigningKey::from_bytes(&key_bytes).unwrap();
                prop_assert_eq!(restored_signing.verifying_key().to_bytes(), verifying_key.to_bytes());
            }
        }
    }
}
