//! Distributed Key Generation (DKG) for FROST.
//!
//! DKG allows a group of participants to collaboratively generate
//! a shared group key without any trusted dealer knowing the complete
//! secret key.
//!
//! ## Protocol Overview
//!
//! 1. **Round 1**: Each participant generates a secret polynomial and
//!    broadcasts commitments to the polynomial coefficients.
//!
//! 2. **Round 2**: Each participant computes and sends encrypted shares
//!    to all other participants.
//!
//! 3. **Verification**: Each participant verifies received shares against
//!    the commitments and computes their final signing share.

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, format};

use crate::error::{Result, ThresholdError};
use crate::frost::PublicKeyPackage;
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

#[cfg(feature = "frost-ed25519")]
use frost_ed25519 as frost;

#[cfg(all(feature = "frost-secp256k1", not(feature = "frost-ed25519")))]
use frost_secp256k1 as frost;

/// A participant in the DKG protocol.
pub struct DkgParticipant {
    /// Participant identifier as u16 (1-based).
    id: u16,
    /// Participant identifier for FROST.
    identifier: frost::Identifier,
    /// Threshold for the scheme.
    threshold: u16,
    /// Total number of participants.
    total: u16,
    /// Round 1 secret package (kept private).
    round1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    /// Round 2 secret package (kept private).
    round2_secret: Option<frost::keys::dkg::round2::SecretPackage>,
}

impl DkgParticipant {
    /// Create a new DKG participant.
    ///
    /// # Arguments
    /// * `id` - Participant identifier (1-based, must be <= total)
    /// * `threshold` - Minimum number of participants needed to sign
    /// * `total` - Total number of participants
    #[must_use = "construction can fail; check the Result"]
    pub fn new(id: u16, threshold: u16, total: u16) -> Result<Self> {
        if id == 0 || id > total {
            return Err(ThresholdError::InvalidParticipant(id));
        }
        if threshold == 0 || threshold > total {
            return Err(ThresholdError::InvalidThreshold {
                threshold: threshold as usize,
                total: total as usize,
            });
        }

        let identifier = frost::Identifier::try_from(id)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

        Ok(Self {
            id,
            identifier,
            threshold,
            total,
            round1_secret: None,
            round2_secret: None,
        })
    }

    /// Get participant identifier as u16.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Execute Round 1 of DKG.
    ///
    /// Generates a secret polynomial and returns the public package
    /// to broadcast to all participants.
    #[must_use = "this operation can fail; check the Result"]
    pub fn round1(&mut self) -> Result<DkgRound1> {
        let mut rng = rand::rngs::OsRng;

        let (secret_package, public_package) =
            frost::keys::dkg::part1(self.identifier, self.total, self.threshold, &mut rng)
                .map_err(|e| ThresholdError::DkgError(e.to_string()))?;

        self.round1_secret = Some(secret_package);

        DkgRound1::from_frost(self.identifier, &public_package)
    }

    /// Execute Round 2 of DKG.
    ///
    /// Receives Round 1 packages from all participants and generates
    /// encrypted shares for each participant.
    ///
    /// # Arguments
    /// * `round1_packages` - Round 1 packages from all participants (including self)
    #[must_use = "this operation can fail; check the Result"]
    pub fn round2(&mut self, round1_packages: &[DkgRound1]) -> Result<Vec<DkgRound2>> {
        let secret_package = self
            .round1_secret
            .take()
            .ok_or_else(|| ThresholdError::DkgError("Round 1 not executed".to_string()))?;

        // Convert to FROST format, excluding self's package
        let mut frost_packages = BTreeMap::new();
        for pkg in round1_packages {
            let (id, frost_pkg) = pkg.to_frost()?;
            // FROST expects packages from OTHER participants only
            if id != self.identifier {
                frost_packages.insert(id, frost_pkg);
            }
        }

        let (secret_package, round2_packages) =
            frost::keys::dkg::part2(secret_package, &frost_packages)
                .map_err(|e| ThresholdError::DkgError(e.to_string()))?;

        self.round2_secret = Some(secret_package);

        // Convert output packages
        round2_packages
            .into_iter()
            .map(|(recipient, pkg)| DkgRound2::from_frost(self.identifier, recipient, &pkg))
            .collect()
    }

    /// Finalize DKG and compute the signing share.
    ///
    /// # Arguments
    /// * `round1_packages` - Round 1 packages from all participants
    /// * `round2_packages` - Round 2 packages addressed to this participant
    #[must_use = "this operation can fail; check the Result"]
    pub fn finalize(
        &mut self,
        round1_packages: &[DkgRound1],
        round2_packages: &[DkgRound2],
    ) -> Result<(frost::keys::KeyPackage, PublicKeyPackage)> {
        let secret_package = self
            .round2_secret
            .take()
            .ok_or_else(|| ThresholdError::DkgError("Round 2 not executed".to_string()))?;

        // Convert round 1 packages, excluding self's package
        let mut frost_round1 = BTreeMap::new();
        for pkg in round1_packages {
            let (id, frost_pkg) = pkg.to_frost()?;
            // FROST expects packages from OTHER participants only
            if id != self.identifier {
                frost_round1.insert(id, frost_pkg);
            }
        }

        // Convert round 2 packages (only those for this participant)
        let mut frost_round2 = BTreeMap::new();
        for pkg in round2_packages {
            if pkg.recipient_id == self.identifier {
                let (sender, frost_pkg) = pkg.to_frost()?;
                frost_round2.insert(sender, frost_pkg);
            }
        }

        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(&secret_package, &frost_round1, &frost_round2)
                .map_err(|e| ThresholdError::DkgError(e.to_string()))?;

        Ok((key_package, PublicKeyPackage::from_frost(pubkey_package)))
    }
}

impl core::fmt::Debug for DkgParticipant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DkgParticipant(id={}, threshold={}, total={})",
            self.id(),
            self.threshold,
            self.total
        )
    }
}

/// Round 1 DKG package (broadcast to all participants).
#[derive(Clone, Serialize, Deserialize)]
pub struct DkgRound1 {
    /// Sender identifier (serialized).
    sender_bytes: Vec<u8>,
    /// Serialized package.
    bytes: Vec<u8>,
}

impl DkgRound1 {
    fn from_frost(id: frost::Identifier, pkg: &frost::keys::dkg::round1::Package) -> Result<Self> {
        Ok(Self {
            sender_bytes: id.serialize(),
            bytes: pkg
                .serialize()
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
        })
    }

    fn to_frost(&self) -> Result<(frost::Identifier, frost::keys::dkg::round1::Package)> {
        let id = frost::Identifier::deserialize(&self.sender_bytes)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

        let pkg = frost::keys::dkg::round1::Package::deserialize(&self.bytes)
            .map_err(|e| ThresholdError::DkgError(format!("invalid round1 package: {}", e)))?;

        Ok((id, pkg))
    }
}

impl core::fmt::Debug for DkgRound1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DkgRound1({} bytes)", self.bytes.len())
    }
}

/// Round 2 DKG package (sent to specific recipient).
#[derive(Clone)]
pub struct DkgRound2 {
    /// Sender identifier.
    sender_bytes: Vec<u8>,
    /// Recipient identifier.
    recipient_id: frost::Identifier,
    /// Serialized package (encrypted for recipient).
    bytes: Vec<u8>,
}

impl DkgRound2 {
    fn from_frost(
        sender: frost::Identifier,
        recipient: frost::Identifier,
        pkg: &frost::keys::dkg::round2::Package,
    ) -> Result<Self> {
        Ok(Self {
            sender_bytes: sender.serialize(),
            recipient_id: recipient,
            bytes: pkg
                .serialize()
                .map_err(|e| ThresholdError::SerializationError(e.to_string()))?,
        })
    }

    fn to_frost(&self) -> Result<(frost::Identifier, frost::keys::dkg::round2::Package)> {
        let sender = frost::Identifier::deserialize(&self.sender_bytes)
            .map_err(|e| ThresholdError::InternalError(e.to_string()))?;

        let pkg = frost::keys::dkg::round2::Package::deserialize(&self.bytes)
            .map_err(|e| ThresholdError::DkgError(format!("invalid round2 package: {}", e)))?;

        Ok((sender, pkg))
    }
}

impl core::fmt::Debug for DkgRound2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DkgRound2({} bytes)", self.bytes.len())
    }
}

/// Run a complete DKG ceremony for all participants.
///
/// This is a helper for testing that simulates the full DKG protocol.
/// In production, participants would communicate over a network.
#[must_use = "this operation can fail; check the Result"]
pub fn run_dkg(
    threshold: u16,
    total: u16,
) -> Result<Vec<(frost::keys::KeyPackage, PublicKeyPackage)>> {
    // Create participants
    let mut participants: Vec<DkgParticipant> = (1..=total)
        .map(|id| DkgParticipant::new(id, threshold, total))
        .collect::<Result<Vec<_>>>()?;

    // Round 1: Generate and collect all round1 packages
    let round1_packages: Vec<DkgRound1> = participants
        .iter_mut()
        .map(|p| p.round1())
        .collect::<Result<Vec<_>>>()?;

    // Round 2: Generate all round2 packages
    let mut all_round2_packages: Vec<DkgRound2> = Vec::new();
    for participant in &mut participants {
        let packages = participant.round2(&round1_packages)?;
        all_round2_packages.extend(packages);
    }

    // Finalize: Each participant computes their key package
    participants
        .iter_mut()
        .map(|p| p.finalize(&round1_packages, &all_round2_packages))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{FrostSigner, FrostVerifier, SigningPackage};

    #[test]
    fn test_dkg_basic() {
        let threshold = 2u16;
        let total = 3u16;

        let results = run_dkg(threshold, total).unwrap();
        assert_eq!(results.len(), total as usize);

        // All participants should have the same group verifying key
        let group_key = results[0].1.group_verifying_key().unwrap();
        for (_, pubkey_pkg) in &results[1..] {
            assert_eq!(
                group_key.as_bytes(),
                pubkey_pkg.group_verifying_key().unwrap().as_bytes()
            );
        }
    }

    #[test]
    fn test_dkg_then_sign() {
        let threshold = 2u16;
        let total = 3u16;
        let message = b"DKG test message";

        // Run DKG
        let results = run_dkg(threshold, total).unwrap();

        // Create signers from first `threshold` participants
        let signers: Vec<FrostSigner> = results
            .iter()
            .take(threshold as usize)
            .map(|(kp, _)| FrostSigner::new(kp.clone()))
            .collect();

        // Round 1: Collect commitments
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
        let signature_shares: Vec<_> = signers
            .iter()
            .enumerate()
            .map(|(i, signer)| {
                signer
                    .round2(message, &all_nonces[i], &signing_package)
                    .unwrap()
            })
            .collect();

        // Aggregate and verify
        let (_, pubkey_package) = &results[0];
        let group_key = pubkey_package.group_verifying_key().unwrap();
        let verifier = FrostVerifier::new(&group_key).unwrap();

        let signature = verifier
            .aggregate(&signing_package, &signature_shares, pubkey_package)
            .unwrap();

        assert!(verifier.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_dkg_3_of_5() {
        let threshold = 3u16;
        let total = 5u16;

        let results = run_dkg(threshold, total).unwrap();
        assert_eq!(results.len(), 5);

        // Verify group key consistency
        let group_key = results[0].1.group_verifying_key().unwrap();
        for (_, pkg) in &results {
            assert_eq!(
                group_key.as_bytes(),
                pkg.group_verifying_key().unwrap().as_bytes()
            );
        }
    }

    #[test]
    fn test_dkg_invalid_params() {
        // Threshold > total
        assert!(run_dkg(5, 3).is_err());

        // Zero threshold
        assert!(run_dkg(0, 3).is_err());

        // Invalid participant ID
        assert!(DkgParticipant::new(0, 2, 3).is_err());
        assert!(DkgParticipant::new(4, 2, 3).is_err());
    }
}
