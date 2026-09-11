//! ECDSA digital signatures.
//!
//! ECDSA (Elliptic Curve Digital Signature Algorithm) provides signatures
//! using various elliptic curves:
//!
//! - **P-256 (secp256r1)**: NIST standard, widely supported
//! - **P-384 (secp384r1)**: Higher security level
//! - **secp256k1**: Bitcoin/Ethereum curve

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::traits;
use arcanum_core::error::{Error, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

// ═══════════════════════════════════════════════════════════════════════════════
// P-256 (NIST)
// ═══════════════════════════════════════════════════════════════════════════════

/// P-256 ECDSA signing key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct P256SigningKey {
    inner: p256::ecdsa::SigningKey,
}

impl traits::SigningKey for P256SigningKey {
    type VerifyingKey = P256VerifyingKey;
    type Signature = P256Signature;

    const ALGORITHM: &'static str = "ECDSA-P256";
    const KEY_SIZE: usize = 32;

    fn generate() -> Self {
        let inner = p256::ecdsa::SigningKey::random(&mut OsRng);
        Self { inner }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p256::ecdsa::SigningKey::from_bytes(bytes.into())
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        P256VerifyingKey {
            inner: *self.inner.verifying_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        use ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = self.inner.sign(message);
        P256Signature { inner: sig }
    }

    fn sign_prehashed(&self, hash: &[u8]) -> Result<Self::Signature> {
        use ecdsa::signature::hazmat::PrehashSigner;
        let sig = self
            .inner
            .sign_prehash(hash)
            .map_err(|_| Error::SigningFailed)?;
        Ok(P256Signature { inner: sig })
    }
}

impl core::fmt::Debug for P256SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P256SigningKey([REDACTED])")
    }
}

/// P-256 ECDSA verifying key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P256VerifyingKey {
    #[serde(with = "p256_verifying_key_serde")]
    inner: p256::ecdsa::VerifyingKey,
}

mod p256_verifying_key_serde {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        key: &p256::ecdsa::VerifyingKey,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_encoded_point(true);
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes.as_bytes()))
        } else {
            serializer.serialize_bytes(bytes.as_bytes())
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> core::result::Result<p256::ecdsa::VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };

        p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl traits::VerifyingKey for P256VerifyingKey {
    type Signature = P256Signature;

    const ALGORITHM: &'static str = "ECDSA-P256";
    const KEY_SIZE: usize = 33; // Compressed point

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<()> {
        use ecdsa::signature::Verifier;
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    fn verify_prehashed(&self, hash: &[u8], signature: &Self::Signature) -> Result<()> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        self.inner
            .verify_prehash(hash, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

impl core::fmt::Debug for P256VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use traits::VerifyingKey;
        write!(f, "P256VerifyingKey({})", self.to_hex())
    }
}

/// P-256 ECDSA signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct P256Signature {
    #[serde(with = "p256_signature_serde")]
    inner: p256::ecdsa::Signature,
}

mod p256_signature_serde {
    use super::*;
    use ecdsa::signature::SignatureEncoding;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        sig: &p256::ecdsa::Signature,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = sig.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> core::result::Result<p256::ecdsa::Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };

        p256::ecdsa::Signature::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

impl traits::Signature for P256Signature {
    const SIZE: usize = 64;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner =
            p256::ecdsa::Signature::from_slice(bytes).map_err(|_| Error::InvalidSignature)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        use ecdsa::signature::SignatureEncoding;
        self.inner.to_bytes().to_vec()
    }
}

impl core::fmt::Debug for P256Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use traits::Signature;
        write!(f, "P256Signature({})", self.to_hex())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// P-384 (NIST)
// ═══════════════════════════════════════════════════════════════════════════════

/// P-384 ECDSA signing key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct P384SigningKey {
    inner: p384::ecdsa::SigningKey,
}

impl traits::SigningKey for P384SigningKey {
    type VerifyingKey = P384VerifyingKey;
    type Signature = P384Signature;

    const ALGORITHM: &'static str = "ECDSA-P384";
    const KEY_SIZE: usize = 48;

    fn generate() -> Self {
        let inner = p384::ecdsa::SigningKey::random(&mut OsRng);
        Self { inner }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p384::ecdsa::SigningKey::from_bytes(bytes.into())
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        P384VerifyingKey {
            inner: *self.inner.verifying_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        use ecdsa::signature::Signer;
        let sig: p384::ecdsa::Signature = self.inner.sign(message);
        P384Signature { inner: sig }
    }

    fn sign_prehashed(&self, hash: &[u8]) -> Result<Self::Signature> {
        use ecdsa::signature::hazmat::PrehashSigner;
        let sig = self
            .inner
            .sign_prehash(hash)
            .map_err(|_| Error::SigningFailed)?;
        Ok(P384Signature { inner: sig })
    }
}

impl core::fmt::Debug for P384SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P384SigningKey([REDACTED])")
    }
}

/// P-384 ECDSA verifying key.
#[derive(Clone, PartialEq, Eq)]
pub struct P384VerifyingKey {
    inner: p384::ecdsa::VerifyingKey,
}

impl traits::VerifyingKey for P384VerifyingKey {
    type Signature = P384Signature;

    const ALGORITHM: &'static str = "ECDSA-P384";
    const KEY_SIZE: usize = 49; // Compressed point

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<()> {
        use ecdsa::signature::Verifier;
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    fn verify_prehashed(&self, hash: &[u8], signature: &Self::Signature) -> Result<()> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        self.inner
            .verify_prehash(hash, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

impl core::fmt::Debug for P384VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use traits::VerifyingKey;
        write!(f, "P384VerifyingKey({})", self.to_hex())
    }
}

/// P-384 ECDSA signature.
#[derive(Clone)]
pub struct P384Signature {
    inner: p384::ecdsa::Signature,
}

impl traits::Signature for P384Signature {
    const SIZE: usize = 96;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner =
            p384::ecdsa::Signature::from_slice(bytes).map_err(|_| Error::InvalidSignature)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        use ecdsa::signature::SignatureEncoding;
        self.inner.to_bytes().to_vec()
    }
}

impl core::fmt::Debug for P384Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use traits::Signature;
        write!(f, "P384Signature({})", self.to_hex())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// secp256k1 (Bitcoin/Ethereum)
// ═══════════════════════════════════════════════════════════════════════════════

/// secp256k1 ECDSA signing key (Bitcoin/Ethereum compatible).
#[derive(Clone, ZeroizeOnDrop)]
pub struct Secp256k1SigningKey {
    inner: k256::ecdsa::SigningKey,
}

impl traits::SigningKey for Secp256k1SigningKey {
    type VerifyingKey = Secp256k1VerifyingKey;
    type Signature = Secp256k1Signature;

    const ALGORITHM: &'static str = "ECDSA-secp256k1";
    const KEY_SIZE: usize = 32;

    fn generate() -> Self {
        let inner = k256::ecdsa::SigningKey::random(&mut OsRng);
        Self { inner }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = k256::ecdsa::SigningKey::from_bytes(bytes.into())
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        Secp256k1VerifyingKey {
            inner: *self.inner.verifying_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        use ecdsa::signature::Signer;
        let sig: k256::ecdsa::Signature = self.inner.sign(message);
        Secp256k1Signature { inner: sig }
    }

    fn sign_prehashed(&self, hash: &[u8]) -> Result<Self::Signature> {
        use ecdsa::signature::hazmat::PrehashSigner;
        let sig = self
            .inner
            .sign_prehash(hash)
            .map_err(|_| Error::SigningFailed)?;
        Ok(Secp256k1Signature { inner: sig })
    }
}

impl core::fmt::Debug for Secp256k1SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secp256k1SigningKey([REDACTED])")
    }
}

/// secp256k1 ECDSA verifying key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1VerifyingKey {
    #[serde(with = "secp256k1_verifying_key_serde")]
    inner: k256::ecdsa::VerifyingKey,
}

mod secp256k1_verifying_key_serde {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        key: &k256::ecdsa::VerifyingKey,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_encoded_point(true);
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes.as_bytes()))
        } else {
            serializer.serialize_bytes(bytes.as_bytes())
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> core::result::Result<k256::ecdsa::VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };

        k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl traits::VerifyingKey for Secp256k1VerifyingKey {
    type Signature = Secp256k1Signature;

    const ALGORITHM: &'static str = "ECDSA-secp256k1";
    const KEY_SIZE: usize = 33; // Compressed point

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| Error::InvalidKeyFormat)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        self.inner.to_encoded_point(true).as_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<()> {
        use ecdsa::signature::Verifier;
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    fn verify_prehashed(&self, hash: &[u8], signature: &Self::Signature) -> Result<()> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        self.inner
            .verify_prehash(hash, &signature.inner)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

impl core::fmt::Debug for Secp256k1VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use traits::VerifyingKey;
        write!(f, "Secp256k1VerifyingKey({})", self.to_hex())
    }
}

/// secp256k1 ECDSA signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Secp256k1Signature {
    #[serde(with = "secp256k1_signature_serde")]
    inner: k256::ecdsa::Signature,
}

mod secp256k1_signature_serde {
    use super::*;
    use ecdsa::signature::SignatureEncoding;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        sig: &k256::ecdsa::Signature,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = sig.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> core::result::Result<k256::ecdsa::Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)?
        } else {
            <Vec<u8>>::deserialize(deserializer)?
        };

        k256::ecdsa::Signature::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

impl traits::Signature for Secp256k1Signature {
    const SIZE: usize = 64;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner =
            k256::ecdsa::Signature::from_slice(bytes).map_err(|_| Error::InvalidSignature)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> Vec<u8> {
        use ecdsa::signature::SignatureEncoding;
        self.inner.to_bytes().to_vec()
    }
}

impl core::fmt::Debug for Secp256k1Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use traits::Signature;
        write!(f, "Secp256k1Signature({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Signature, SigningKey, VerifyingKey};

    macro_rules! test_ecdsa_curve {
        ($signing_key:ty, $name:ident) => {
            mod $name {
                use super::*;

                #[test]
                fn test_sign_verify() {
                    let signing_key = <$signing_key>::generate();
                    let verifying_key = signing_key.verifying_key();

                    let message = b"Hello, ECDSA!";
                    let signature = signing_key.sign(message);

                    assert!(verifying_key.verify(message, &signature).is_ok());
                }

                #[test]
                fn test_wrong_message_fails() {
                    let signing_key = <$signing_key>::generate();
                    let verifying_key = signing_key.verifying_key();

                    let message = b"Hello!";
                    let wrong_message = b"Wrong!";
                    let signature = signing_key.sign(message);

                    assert!(verifying_key.verify(wrong_message, &signature).is_err());
                }

                #[test]
                fn test_key_roundtrip() {
                    let signing_key = <$signing_key>::generate();
                    let verifying_key = signing_key.verifying_key();

                    let bytes = verifying_key.to_bytes();
                    let restored =
                        <<$signing_key as SigningKey>::VerifyingKey>::from_bytes(&bytes).unwrap();

                    assert_eq!(verifying_key, restored);
                }

                #[test]
                fn test_signature_roundtrip() {
                    let signing_key = <$signing_key>::generate();
                    let message = b"Test";
                    let signature = signing_key.sign(message);

                    let bytes = signature.to_bytes();
                    let restored =
                        <<$signing_key as SigningKey>::Signature>::from_bytes(&bytes).unwrap();

                    let verifying_key = signing_key.verifying_key();
                    assert!(verifying_key.verify(message, &restored).is_ok());
                }
            }
        };
    }

    test_ecdsa_curve!(P256SigningKey, p256_tests);
    test_ecdsa_curve!(P384SigningKey, p384_tests);
    test_ecdsa_curve!(Secp256k1SigningKey, secp256k1_tests);
}
