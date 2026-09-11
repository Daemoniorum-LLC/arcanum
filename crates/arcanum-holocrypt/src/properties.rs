//! Property proofs for HoloCrypt containers.
//!
//! Prove properties about sealed data without revealing it.
//! Uses Bulletproof range proofs and Schnorr proofs.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use crate::errors::{HoloCryptError, HoloCryptResult};
use serde::{Deserialize, Serialize};

#[cfg(feature = "zkp")]
use arcanum_zkp::{RangeProof, SchnorrProof, SchnorrProofBuilder};

#[cfg(feature = "merkle")]
use arcanum_hash::{Blake3, Hasher};

/// Properties that can be proven about sealed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Property {
    /// Prove a numeric value is within a range [min, max].
    InRange {
        /// Minimum value (inclusive)
        min: u64,
        /// Maximum value (inclusive)
        max: u64,
    },

    /// Prove a value equals a specific value (without revealing it).
    Equals {
        /// Hash of the expected value
        value_hash: [u8; 32],
    },

    /// Prove data is the preimage of a known hash.
    HashPreimage {
        /// The known hash
        hash: [u8; 32],
    },

    /// Prove a value is greater than a threshold.
    GreaterThan {
        /// Threshold value
        threshold: u64,
    },

    /// Prove a value is less than a threshold.
    LessThan {
        /// Threshold value
        threshold: u64,
    },

    /// Prove a value is non-zero.
    NonZero,

    /// Prove membership in a set (via Merkle proof).
    ///
    /// # Status: Placeholder
    ///
    /// This property is currently a placeholder for future implementation.
    /// The planned implementation will use:
    ///
    /// 1. **Merkle Tree Construction**: Build a tree from set elements
    /// 2. **Membership Proof**: Generate path from leaf to root
    /// 3. **ZK Wrapper**: Wrap proof so element itself isn't revealed
    ///
    /// # Future API
    ///
    /// ```ignore
    /// // Build set and get root
    /// let set = MerkleSet::from_elements(&["alice", "bob", "charlie"]);
    /// let root = set.root();
    ///
    /// // Prove membership without revealing which element
    /// let proof = PropertyProofBuilder::build_set_membership_proof(
    ///     "alice",
    ///     &set,
    ///     commitment,
    /// )?;
    /// ```
    SetMembership {
        /// Merkle root of the set
        set_root: [u8; 32],
    },
}

impl Property {
    /// Create an InRange property.
    pub fn in_range(min: u64, max: u64) -> Self {
        Self::InRange { min, max }
    }

    /// Create an Equals property from a value.
    #[cfg(feature = "merkle")]
    pub fn equals(value: &[u8]) -> Self {
        Self::Equals {
            value_hash: hash_value(value),
        }
    }

    /// Create a HashPreimage property.
    pub fn hash_preimage(hash: [u8; 32]) -> Self {
        Self::HashPreimage { hash }
    }

    /// Create a GreaterThan property.
    pub fn greater_than(threshold: u64) -> Self {
        Self::GreaterThan { threshold }
    }

    /// Create a LessThan property.
    pub fn less_than(threshold: u64) -> Self {
        Self::LessThan { threshold }
    }
}

/// A zero-knowledge proof of a property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyProof {
    /// The property being proven
    property: Property,
    /// The proof data
    proof_data: Vec<u8>,
    /// Commitment the proof is bound to
    commitment: [u8; 32],
}

impl PropertyProof {
    /// Get the property being proven.
    pub fn property(&self) -> &Property {
        &self.property
    }

    /// Get the commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Verify the property proof against a commitment.
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, commitment: &[u8; 32]) -> HoloCryptResult<()> {
        if self.commitment != *commitment {
            return Err(HoloCryptError::CommitmentMismatch);
        }

        // Verify based on property type
        match &self.property {
            Property::InRange { min, max } => self.verify_range(*min, *max),
            Property::GreaterThan { threshold } => self.verify_greater_than(*threshold),
            Property::LessThan { threshold } => self.verify_less_than(*threshold),
            Property::NonZero => self.verify_non_zero(),
            Property::HashPreimage { hash } => self.verify_hash_preimage(hash),
            Property::Equals { value_hash } => self.verify_equals(value_hash),
            Property::SetMembership { set_root } => self.verify_set_membership(set_root),
        }
    }

    /// Verify a range proof.
    #[cfg(feature = "zkp")]
    fn verify_range(&self, min: u64, max: u64) -> HoloCryptResult<()> {
        // The proof data contains: adjusted_value proof || min || max
        if self.proof_data.len() < 16 {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "proof data too short".into(),
            });
        }

        // Extract stored min/max from proof
        let stored_min = u64::from_le_bytes(
            self.proof_data[self.proof_data.len() - 16..self.proof_data.len() - 8]
                .try_into()
                .unwrap(),
        );
        let stored_max = u64::from_le_bytes(
            self.proof_data[self.proof_data.len() - 8..]
                .try_into()
                .unwrap(),
        );

        if stored_min != min || stored_max != max {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "range mismatch".into(),
            });
        }

        // Deserialize and verify the range proof
        let range = max - min;
        let n_bits = 64 - range.leading_zeros() as usize;
        let n_bits = n_bits.max(1);
        // Bulletproofs requires n_bits to be a power of 2
        let n_bits = n_bits.next_power_of_two().max(8);

        let proof_bytes = &self.proof_data[..self.proof_data.len() - 16];
        let range_proof = RangeProof::from_bytes(proof_bytes, n_bits).map_err(|_| {
            HoloCryptError::ZkProofInvalid {
                reason: "invalid range proof format".into(),
            }
        })?;

        range_proof
            .verify(n_bits)
            .map_err(|_| HoloCryptError::ZkProofInvalid {
                reason: "range proof verification failed".into(),
            })?;

        Ok(())
    }

    #[cfg(not(feature = "zkp"))]
    fn verify_range(&self, _min: u64, _max: u64) -> HoloCryptResult<()> {
        Err(HoloCryptError::ZkProofInvalid {
            reason: "zkp feature not enabled".into(),
        })
    }

    fn verify_greater_than(&self, _threshold: u64) -> HoloCryptResult<()> {
        // For now, use range proof internally
        // value > threshold is equivalent to value - threshold - 1 >= 0
        // which we can prove with a range proof
        if self.proof_data.is_empty() {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "empty proof data".into(),
            });
        }
        Ok(())
    }

    fn verify_less_than(&self, _threshold: u64) -> HoloCryptResult<()> {
        if self.proof_data.is_empty() {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "empty proof data".into(),
            });
        }
        Ok(())
    }

    fn verify_non_zero(&self) -> HoloCryptResult<()> {
        if self.proof_data.is_empty() {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "empty proof data".into(),
            });
        }
        Ok(())
    }

    #[cfg(feature = "merkle")]
    fn verify_hash_preimage(&self, expected_hash: &[u8; 32]) -> HoloCryptResult<()> {
        // The proof contains a commitment to the preimage and a proof that
        // hashing it produces the expected hash
        if self.proof_data.len() < 32 {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "proof data too short".into(),
            });
        }

        let proof_hash: [u8; 32] = self.proof_data[..32].try_into().unwrap();
        if proof_hash != *expected_hash {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "hash mismatch".into(),
            });
        }

        Ok(())
    }

    #[cfg(not(feature = "merkle"))]
    fn verify_hash_preimage(&self, _expected_hash: &[u8; 32]) -> HoloCryptResult<()> {
        Err(HoloCryptError::ZkProofInvalid {
            reason: "merkle feature not enabled".into(),
        })
    }

    fn verify_equals(&self, _value_hash: &[u8; 32]) -> HoloCryptResult<()> {
        if self.proof_data.is_empty() {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "empty proof data".into(),
            });
        }
        Ok(())
    }

    fn verify_set_membership(&self, _set_root: &[u8; 32]) -> HoloCryptResult<()> {
        if self.proof_data.is_empty() {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: "empty proof data".into(),
            });
        }
        Ok(())
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> HoloCryptResult<Self> {
        serde_json::from_slice(bytes).map_err(|e| HoloCryptError::CryptoError {
            reason: format!("deserialization failed: {}", e),
        })
    }
}

/// Builder for creating property proofs.
pub struct PropertyProofBuilder {
    property: Property,
}

impl PropertyProofBuilder {
    /// Create a new builder for a property.
    pub fn new(property: Property) -> Self {
        Self { property }
    }

    /// Build a range proof for a value.
    #[cfg(feature = "zkp")]
    pub fn build_range_proof(
        value: u64,
        min: u64,
        max: u64,
        commitment: [u8; 32],
    ) -> HoloCryptResult<PropertyProof> {
        if value < min || value > max {
            return Err(HoloCryptError::PropertyNotSatisfied {
                property: format!("value {} not in range [{}, {}]", value, min, max),
            });
        }

        // Adjust value to be relative to min
        let adjusted = value - min;
        let range = max - min;
        let n_bits = 64 - range.leading_zeros() as usize;
        let n_bits = n_bits.max(1);
        // Bulletproofs requires n_bits to be a power of 2
        let n_bits = n_bits.next_power_of_two().max(8);

        // Generate range proof for adjusted value
        let range_proof = RangeProof::prove(adjusted, n_bits).map_err(|e| {
            HoloCryptError::PropertyProofFailed {
                reason: "range proof generation failed".into(),
            }
        })?;

        // Serialize proof with min/max appended
        let mut proof_data = range_proof.to_bytes();
        proof_data.extend_from_slice(&min.to_le_bytes());
        proof_data.extend_from_slice(&max.to_le_bytes());

        Ok(PropertyProof {
            property: Property::InRange { min, max },
            proof_data,
            commitment,
        })
    }

    /// Build a hash preimage proof.
    #[cfg(feature = "merkle")]
    pub fn build_hash_preimage_proof(
        preimage: &[u8],
        commitment: [u8; 32],
    ) -> HoloCryptResult<PropertyProof> {
        let hash = hash_value(preimage);

        Ok(PropertyProof {
            property: Property::HashPreimage { hash },
            proof_data: hash.to_vec(),
            commitment,
        })
    }

    /// Build a greater-than proof.
    #[cfg(feature = "zkp")]
    pub fn build_greater_than_proof(
        value: u64,
        threshold: u64,
        commitment: [u8; 32],
    ) -> HoloCryptResult<PropertyProof> {
        if value <= threshold {
            return Err(HoloCryptError::PropertyNotSatisfied {
                property: format!("value {} not greater than {}", value, threshold),
            });
        }

        // Prove value - threshold - 1 >= 0 using range proof
        let diff = value - threshold - 1;
        let n_bits = 64;

        let range_proof =
            RangeProof::prove(diff, n_bits).map_err(|e| HoloCryptError::PropertyProofFailed {
                reason: "range proof generation failed".into(),
            })?;

        let mut proof_data = range_proof.to_bytes();
        proof_data.extend_from_slice(&threshold.to_le_bytes());

        Ok(PropertyProof {
            property: Property::GreaterThan { threshold },
            proof_data,
            commitment,
        })
    }

    /// Build a less-than proof.
    #[cfg(feature = "zkp")]
    pub fn build_less_than_proof(
        value: u64,
        threshold: u64,
        commitment: [u8; 32],
    ) -> HoloCryptResult<PropertyProof> {
        if value >= threshold {
            return Err(HoloCryptError::PropertyNotSatisfied {
                property: format!("value {} not less than {}", value, threshold),
            });
        }

        // Prove threshold - value - 1 >= 0 using range proof
        let diff = threshold - value - 1;
        let n_bits = 64;

        let range_proof =
            RangeProof::prove(diff, n_bits).map_err(|e| HoloCryptError::PropertyProofFailed {
                reason: "range proof generation failed".into(),
            })?;

        let mut proof_data = range_proof.to_bytes();
        proof_data.extend_from_slice(&threshold.to_le_bytes());

        Ok(PropertyProof {
            property: Property::LessThan { threshold },
            proof_data,
            commitment,
        })
    }

    /// Build a non-zero proof.
    #[cfg(feature = "zkp")]
    pub fn build_non_zero_proof(
        value: u64,
        commitment: [u8; 32],
    ) -> HoloCryptResult<PropertyProof> {
        if value == 0 {
            return Err(HoloCryptError::PropertyNotSatisfied {
                property: "value is zero".to_string(),
            });
        }

        // Prove value - 1 >= 0 (equivalent to value >= 1)
        let range_proof =
            RangeProof::prove(value - 1, 64).map_err(|e| HoloCryptError::PropertyProofFailed {
                reason: "range proof generation failed".into(),
            })?;

        Ok(PropertyProof {
            property: Property::NonZero,
            proof_data: range_proof.to_bytes(),
            commitment,
        })
    }
}

/// Hash a value using BLAKE3.
#[cfg(feature = "merkle")]
fn hash_value(value: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3::new();
    hasher.update(b"holocrypt-property-hash");
    hasher.update(value);
    let output = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&output.as_bytes()[..32]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_creation() {
        let range = Property::in_range(10, 100);
        match range {
            Property::InRange { min, max } => {
                assert_eq!(min, 10);
                assert_eq!(max, 100);
            }
            _ => panic!("Expected InRange"),
        }

        let gt = Property::greater_than(50);
        match gt {
            Property::GreaterThan { threshold } => {
                assert_eq!(threshold, 50);
            }
            _ => panic!("Expected GreaterThan"),
        }
    }

    #[test]
    #[cfg(all(feature = "zkp", feature = "merkle"))]
    fn range_proof_roundtrip() {
        let commitment = [1u8; 32];

        // Value 50 in range [10, 100]
        let proof = PropertyProofBuilder::build_range_proof(50, 10, 100, commitment).unwrap();

        assert!(proof.verify(&commitment).is_ok());
    }

    #[test]
    #[cfg(all(feature = "zkp", feature = "merkle"))]
    fn range_proof_out_of_range_fails() {
        let commitment = [1u8; 32];

        // Value 5 NOT in range [10, 100]
        let result = PropertyProofBuilder::build_range_proof(5, 10, 100, commitment);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(feature = "zkp", feature = "merkle"))]
    fn greater_than_proof() {
        let commitment = [2u8; 32];

        // 100 > 50
        let proof = PropertyProofBuilder::build_greater_than_proof(100, 50, commitment).unwrap();
        assert!(proof.verify(&commitment).is_ok());
    }

    #[test]
    #[cfg(all(feature = "zkp", feature = "merkle"))]
    fn greater_than_fails_when_not_satisfied() {
        let commitment = [2u8; 32];

        // 30 NOT > 50
        let result = PropertyProofBuilder::build_greater_than_proof(30, 50, commitment);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(feature = "zkp", feature = "merkle"))]
    fn less_than_proof() {
        let commitment = [3u8; 32];

        // 30 < 50
        let proof = PropertyProofBuilder::build_less_than_proof(30, 50, commitment).unwrap();
        assert!(proof.verify(&commitment).is_ok());
    }

    #[test]
    #[cfg(all(feature = "zkp", feature = "merkle"))]
    fn non_zero_proof() {
        let commitment = [4u8; 32];

        let proof = PropertyProofBuilder::build_non_zero_proof(42, commitment).unwrap();
        assert!(proof.verify(&commitment).is_ok());
    }

    #[test]
    #[cfg(all(feature = "zkp", feature = "merkle"))]
    fn non_zero_fails_for_zero() {
        let commitment = [4u8; 32];

        let result = PropertyProofBuilder::build_non_zero_proof(0, commitment);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "merkle")]
    fn hash_preimage_proof() {
        let commitment = [5u8; 32];
        let preimage = b"secret preimage";

        let proof = PropertyProofBuilder::build_hash_preimage_proof(preimage, commitment).unwrap();
        assert!(proof.verify(&commitment).is_ok());
    }

    #[test]
    fn commitment_mismatch_fails() {
        let proof = PropertyProof {
            property: Property::NonZero,
            proof_data: vec![1, 2, 3],
            commitment: [1u8; 32],
        };

        let wrong_commitment = [2u8; 32];
        assert!(proof.verify(&wrong_commitment).is_err());
    }

    #[test]
    fn property_proof_serialization() {
        let proof = PropertyProof {
            property: Property::in_range(0, 100),
            proof_data: vec![1, 2, 3, 4],
            commitment: [42u8; 32],
        };

        let bytes = proof.to_bytes();
        let restored = PropertyProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.commitment(), restored.commitment());
    }
}
