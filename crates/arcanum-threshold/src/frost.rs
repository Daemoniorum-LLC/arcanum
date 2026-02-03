//! FROST (Flexible Round-Optimized Schnorr Threshold) signatures.
//!
//! FROST provides threshold Schnorr signatures with the following properties:
//! - t-of-n threshold: any t participants can create a valid signature
//! - Two-round signing: optimized for efficiency
//! - Robust against malicious participants
//!
//! ## Curve Support
//!
//! - **Ed25519**: For EdDSA-compatible signatures
//! - **secp256k1**: For Bitcoin/Ethereum compatibility

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::{Result, ThresholdError};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

#[cfg(feature = "frost-ed25519")]
use frost_ed25519 as frost;

#[cfg(all(feature = "frost-secp256k1", not(feature = "frost-ed25519")))]
use frost_secp256k1 as frost;

/// A participant's signing share (private key share).
#[derive(Clone)]
pub struct SigningShare {
    /// The participant's identifier.
    identifier: frost::Identifier,
    /// The secret signing share.
    share: frost::keys::SigningShare,
}

impl SigningShare {
    /// Create from FROST signing share.
    pub fn from_frost(id: frost::Identifier, share: frost::keys::SigningShare) -> Self {
        Self {
            identifier: id,
            share,
        }
    }

    /// Get the participant identifier.
    pub fn identifier(&self) -> frost::Identifier {
        self.identifier
    }

    /// Get the underlying FROST signing share.
    pub fn inner(&self) -> &frost::keys::SigningShare {
        &self.share
    }
}

impl core::fmt::Debug for SigningShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningShare(id={:?})", self.identifier)
    }
}

/// A participant's verifying share (public key share).
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingShare {
    /// The participant's identifier (serialized).
    identifier_bytes: Vec<u8>,
    /// Serialized verifying share.
    bytes: Vec<u8>,
}

impl VerifyingShare {
    /// Create from FROST verifying share.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_frost(id: frost::Identifier, share: &frost::keys::VerifyingShare) -> Result<Self> {
        Ok(Self {
            identifier_bytes: id.serialize(),
            bytes: share
                .serialize()
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
        })
    }

    /// Get the serialized bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for VerifyingShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VerifyingShare({} bytes)", self.identifier_bytes.len())
    }
}

/// Group verifying key (public key for the threshold group).
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupVerifyingKey {
    bytes: Vec<u8>,
}

impl GroupVerifyingKey {
    /// Create from FROST verifying key.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_frost(key: &frost::VerifyingKey) -> Result<Self> {
        Ok(Self {
            bytes: key
                .serialize()
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
        })
    }

    /// Get the serialized bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to FROST verifying key.
    #[must_use = "this operation can fail; check the Result"]
    pub fn to_frost(&self) -> Result<frost::VerifyingKey> {
        frost::VerifyingKey::deserialize(&self.bytes)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))
    }
}

impl core::fmt::Debug for GroupVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GroupVerifyingKey({} bytes)", self.bytes.len())
    }
}

/// FROST signer for creating threshold signatures.
pub struct FrostSigner {
    /// Key package containing signing share and group info.
    key_package: frost::keys::KeyPackage,
}

impl FrostSigner {
    /// Create a signer from a key package.
    pub fn new(key_package: frost::keys::KeyPackage) -> Self {
        Self { key_package }
    }

    /// Get the participant's identifier.
    pub fn identifier(&self) -> frost::Identifier {
        *self.key_package.identifier()
    }

    /// Get the group verifying key.
    #[must_use = "this operation can fail; check the Result"]
    pub fn group_verifying_key(&self) -> Result<GroupVerifyingKey> {
        GroupVerifyingKey::from_frost(self.key_package.verifying_key())
    }

    /// Generate round 1 commitment for signing.
    #[must_use = "signing can fail; check the Result"]
    pub fn round1(&self) -> Result<(SigningNonces, SigningCommitments)> {
        let mut rng = rand::rngs::OsRng;
        let (nonces, commitments) =
            frost::round1::commit(self.key_package.signing_share(), &mut rng);

        Ok((
            SigningNonces { inner: nonces },
            SigningCommitments::from_frost(self.identifier(), &commitments)?,
        ))
    }

    /// Generate signature share in round 2.
    #[must_use = "signing can fail; check the Result"]
    pub fn round2(
        &self,
        _message: &[u8],
        nonces: &SigningNonces,
        signing_package: &SigningPackage,
    ) -> Result<SignatureShare> {
        let sig_share =
            frost::round2::sign(&signing_package.inner, &nonces.inner, &self.key_package)
                .map_err(|e| ThresholdError::SigningError(e.to_string()))?;

        Ok(SignatureShare::from_frost(self.identifier(), &sig_share))
    }
}

/// Signing nonces (kept secret by each participant).
pub struct SigningNonces {
    inner: frost::round1::SigningNonces,
}

/// Signing commitments (shared with coordinator).
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningCommitments {
    identifier_bytes: Vec<u8>,
    bytes: Vec<u8>,
}

impl SigningCommitments {
    fn from_frost(id: frost::Identifier, c: &frost::round1::SigningCommitments) -> Result<Self> {
        Ok(Self {
            identifier_bytes: id.serialize(),
            bytes: c
                .serialize()
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
        })
    }

    fn to_frost(&self) -> Result<(frost::Identifier, frost::round1::SigningCommitments)> {
        let id = frost::Identifier::deserialize(&self.identifier_bytes)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

        let commitments = frost::round1::SigningCommitments::deserialize(&self.bytes)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

        Ok((id, commitments))
    }
}

/// Signing package containing all commitments.
pub struct SigningPackage {
    inner: frost::SigningPackage,
}

impl SigningPackage {
    /// Create a signing package from commitments.
    #[must_use = "construction can fail; check the Result"]
    pub fn new(commitments: &[SigningCommitments], message: &[u8]) -> Result<Self> {
        let mut commitment_map = BTreeMap::new();

        for c in commitments {
            let (id, frost_c) = c.to_frost()?;
            commitment_map.insert(id, frost_c);
        }

        let inner = frost::SigningPackage::new(commitment_map, message);
        Ok(Self { inner })
    }
}

/// A participant's signature share.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignatureShare {
    identifier_bytes: Vec<u8>,
    bytes: Vec<u8>,
}

impl SignatureShare {
    fn from_frost(id: frost::Identifier, share: &frost::round2::SignatureShare) -> Self {
        Self {
            identifier_bytes: id.serialize(),
            bytes: share.serialize(),
        }
    }

    fn to_frost(&self) -> Result<(frost::Identifier, frost::round2::SignatureShare)> {
        let id = frost::Identifier::deserialize(&self.identifier_bytes)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

        let share = frost::round2::SignatureShare::deserialize(&self.bytes)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

        Ok((id, share))
    }
}

/// FROST verifier and signature aggregator.
pub struct FrostVerifier {
    /// Group verifying key.
    verifying_key: frost::VerifyingKey,
}

impl FrostVerifier {
    /// Create a verifier from the group verifying key.
    #[must_use = "construction can fail; check the Result"]
    pub fn new(key: &GroupVerifyingKey) -> Result<Self> {
        Ok(Self {
            verifying_key: key.to_frost()?,
        })
    }

    /// Aggregate signature shares into a complete signature.
    #[must_use = "signing can fail; check the Result"]
    pub fn aggregate(
        &self,
        signing_package: &SigningPackage,
        signature_shares: &[SignatureShare],
        pubkey_package: &PublicKeyPackage,
    ) -> Result<Signature> {
        let mut share_map = BTreeMap::new();

        for share in signature_shares {
            let (id, frost_share) = share.to_frost()?;
            share_map.insert(id, frost_share);
        }

        let signature = frost::aggregate(&signing_package.inner, &share_map, &pubkey_package.inner)
            .map_err(|e| ThresholdError::SigningError(e.to_string()))?;

        Ok(Signature {
            bytes: signature
                .serialize()
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
        })
    }

    /// Verify a threshold signature.
    #[must_use = "signature verification must be checked - ignoring bypasses authentication"]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        let sig = frost::Signature::deserialize(&signature.bytes)
            .map_err(|_| ThresholdError::InvalidSignature)?;

        self.verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(|_| ThresholdError::InvalidSignature)
    }
}

/// Public key package for signature verification.
#[derive(Clone)]
pub struct PublicKeyPackage {
    inner: frost::keys::PublicKeyPackage,
}

impl PublicKeyPackage {
    /// Create from FROST public key package.
    pub fn from_frost(pkg: frost::keys::PublicKeyPackage) -> Self {
        Self { inner: pkg }
    }

    /// Get the group verifying key.
    #[must_use = "this operation can fail; check the Result"]
    pub fn group_verifying_key(&self) -> Result<GroupVerifyingKey> {
        GroupVerifyingKey::from_frost(self.inner.verifying_key())
    }
}

/// A complete threshold signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl Signature {
    /// Get signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Signature length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({} bytes)", self.bytes.len())
    }
}

/// Generate key shares using a trusted dealer.
///
/// For production, use DKG instead of trusted dealer.
#[must_use = "key generation can fail; check the Result"]
pub fn trusted_dealer_keygen(
    threshold: u16,
    total: u16,
) -> Result<(Vec<frost::keys::SecretShare>, frost::keys::PublicKeyPackage)> {
    let mut rng = rand::rngs::OsRng;

    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

    Ok((shares.into_values().collect(), pubkeys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frost_trusted_dealer() {
        let threshold = 2u16;
        let total = 3u16;

        // Generate keys with trusted dealer
        let (shares, _pubkey_package) = trusted_dealer_keygen(threshold, total).unwrap();
        assert_eq!(shares.len(), total as usize);

        // Verify we can create key packages
        for share in &shares {
            let key_package = frost::keys::KeyPackage::try_from(share.clone()).unwrap();
            let _ = FrostSigner::new(key_package);
        }
    }

    #[test]
    fn test_frost_signing_flow() {
        let threshold = 2u16;
        let total = 3u16;
        let message = b"Test message for FROST signing";

        // Generate keys
        let (shares, pubkey_package) = trusted_dealer_keygen(threshold, total).unwrap();

        // Create signers from first 2 participants
        let key_packages: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|s| frost::keys::KeyPackage::try_from(s.clone()).unwrap())
            .collect();

        let signers: Vec<_> = key_packages
            .iter()
            .map(|kp| FrostSigner::new(kp.clone()))
            .collect();

        // Round 1: Generate commitments
        let mut all_nonces = Vec::new();
        let mut all_commitments = Vec::new();

        for signer in &signers {
            let (nonces, commitments) = signer.round1().unwrap();
            all_nonces.push(nonces);
            all_commitments.push(commitments);
        }

        // Create signing package
        let signing_package = SigningPackage::new(&all_commitments, message).unwrap();

        // Round 2: Generate signature shares
        let mut signature_shares = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = signer
                .round2(message, &all_nonces[i], &signing_package)
                .unwrap();
            signature_shares.push(share);
        }

        // Aggregate and verify
        let group_key = GroupVerifyingKey::from_frost(pubkey_package.verifying_key()).unwrap();
        let verifier = FrostVerifier::new(&group_key).unwrap();
        let pkg = PublicKeyPackage::from_frost(pubkey_package);

        let signature = verifier
            .aggregate(&signing_package, &signature_shares, &pkg)
            .unwrap();
        assert!(verifier.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_frost_wrong_message_fails() {
        let threshold = 2u16;
        let total = 3u16;
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        // Generate keys
        let (shares, pubkey_package) = trusted_dealer_keygen(threshold, total).unwrap();

        let key_packages: Vec<_> = shares
            .iter()
            .take(threshold as usize)
            .map(|s| frost::keys::KeyPackage::try_from(s.clone()).unwrap())
            .collect();

        let signers: Vec<_> = key_packages
            .iter()
            .map(|kp| FrostSigner::new(kp.clone()))
            .collect();

        // Sign the original message
        let mut all_nonces = Vec::new();
        let mut all_commitments = Vec::new();

        for signer in &signers {
            let (nonces, commitments) = signer.round1().unwrap();
            all_nonces.push(nonces);
            all_commitments.push(commitments);
        }

        let signing_package = SigningPackage::new(&all_commitments, message).unwrap();

        let mut signature_shares = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = signer
                .round2(message, &all_nonces[i], &signing_package)
                .unwrap();
            signature_shares.push(share);
        }

        let group_key = GroupVerifyingKey::from_frost(pubkey_package.verifying_key()).unwrap();
        let verifier = FrostVerifier::new(&group_key).unwrap();
        let pkg = PublicKeyPackage::from_frost(pubkey_package);

        let signature = verifier
            .aggregate(&signing_package, &signature_shares, &pkg)
            .unwrap();

        // Verify with wrong message should fail
        assert!(verifier.verify(wrong_message, &signature).is_err());
    }
}
