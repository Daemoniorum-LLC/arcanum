//! Bulletproofs range proofs.
//!
//! Range proofs prove that a committed value lies within a range
//! without revealing the value itself.
//!
//! ## Properties
//!
//! - No trusted setup required
//! - Logarithmic proof size O(log n)
//! - Aggregatable: multiple proofs can be batched

#[cfg(not(feature = "std"))]
use alloc::{format, string::{String, ToString}, vec::Vec};

use arcanum_core::error::{Error, Result};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof as BpRangeProof};
use merlin::Transcript;
use rand::RngCore;

// Use curve25519-dalek-ng types for bulletproofs compatibility
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;

/// Range proof proving a value is in [0, 2^n).
#[derive(Clone)]
pub struct RangeProof {
    proof: BpRangeProof,
    commitment: CompressedRistretto,
}

impl RangeProof {
    /// Maximum supported bit range.
    pub const MAX_BITS: usize = 64;

    /// Prove that a value is in the range [0, 2^n_bits).
    ///
    /// Returns the commitment and the proof.
    pub fn prove(value: u64, n_bits: usize) -> Result<Self> {
        if n_bits > Self::MAX_BITS {
            return Err(Error::InvalidParameter(format!(
                "n_bits must be <= {}",
                Self::MAX_BITS
            )));
        }

        // Check value is in range
        if n_bits < 64 && value >= (1u64 << n_bits) {
            return Err(Error::InvalidParameter("value out of range".to_string()));
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n_bits, 1);

        let mut blinding_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut blinding_bytes);
        let blinding = Scalar::from_bytes_mod_order(blinding_bytes);

        let mut transcript = Transcript::new(b"arcanum-range-proof");

        let (proof, commitment) = BpRangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            value,
            &blinding,
            n_bits,
        )
        .map_err(|_| Error::ProofGenerationFailed)?;

        Ok(Self { proof, commitment })
    }

    /// Prove with a specific blinding factor (as raw bytes).
    pub fn prove_with_blinding(
        value: u64,
        blinding_bytes: &[u8; 32],
        n_bits: usize,
    ) -> Result<Self> {
        if n_bits > Self::MAX_BITS {
            return Err(Error::InvalidParameter(format!(
                "n_bits must be <= {}",
                Self::MAX_BITS
            )));
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n_bits, 1);

        let blinding = Scalar::from_bytes_mod_order(*blinding_bytes);
        let mut transcript = Transcript::new(b"arcanum-range-proof");

        let (proof, commitment) = BpRangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            value,
            &blinding,
            n_bits,
        )
        .map_err(|_| Error::ProofGenerationFailed)?;

        Ok(Self { proof, commitment })
    }

    /// Verify the range proof.
    pub fn verify(&self, n_bits: usize) -> Result<bool> {
        if n_bits > Self::MAX_BITS {
            return Err(Error::InvalidParameter(format!(
                "n_bits must be <= {}",
                Self::MAX_BITS
            )));
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n_bits, 1);

        let mut transcript = Transcript::new(b"arcanum-range-proof");

        self.proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &self.commitment,
                n_bits,
            )
            .map(|_| true)
            .map_err(|_| Error::ProofVerificationFailed)
    }

    /// Get the commitment as bytes.
    pub fn commitment_bytes(&self) -> [u8; 32] {
        self.commitment.to_bytes()
    }

    /// Serialize the proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.commitment.to_bytes());
        bytes.extend_from_slice(&self.proof.to_bytes());
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8], n_bits: usize) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(Error::InvalidParameter("proof bytes too short".to_string()));
        }

        let commitment_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let commitment = CompressedRistretto::from_slice(&commitment_bytes);

        let proof = BpRangeProof::from_bytes(&bytes[32..])
            .map_err(|_| Error::InvalidParameter("invalid proof bytes".to_string()))?;

        // Verify the proof is valid before returning
        let result = Self { proof, commitment };
        result.verify(n_bits)?;

        Ok(result)
    }
}

impl core::fmt::Debug for RangeProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RangeProof({} bytes)", self.to_bytes().len())
    }
}

/// Batch range proof for proving multiple values.
pub struct RangeProofBatch {
    proof: BpRangeProof,
    commitments: Vec<CompressedRistretto>,
}

impl RangeProofBatch {
    /// Prove multiple values are in range [0, 2^n_bits).
    ///
    /// The number of values must be a power of 2.
    pub fn prove(values: &[u64], n_bits: usize) -> Result<Self> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(Error::InvalidParameter(
                "number of values must be a power of 2".to_string(),
            ));
        }

        if n_bits > RangeProof::MAX_BITS {
            return Err(Error::InvalidParameter(format!(
                "n_bits must be <= {}",
                RangeProof::MAX_BITS
            )));
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n_bits, values.len());

        // Generate random blindings
        let blindings: Vec<Scalar> = (0..values.len())
            .map(|_| {
                let mut bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                Scalar::from_bytes_mod_order(bytes)
            })
            .collect();

        let mut transcript = Transcript::new(b"arcanum-batch-range-proof");

        let (proof, commitments) = BpRangeProof::prove_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            values,
            &blindings,
            n_bits,
        )
        .map_err(|_| Error::ProofGenerationFailed)?;

        Ok(Self { proof, commitments })
    }

    /// Verify the batch range proof.
    pub fn verify(&self, n_bits: usize) -> Result<bool> {
        if n_bits > RangeProof::MAX_BITS {
            return Err(Error::InvalidParameter(format!(
                "n_bits must be <= {}",
                RangeProof::MAX_BITS
            )));
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n_bits, self.commitments.len());

        let mut transcript = Transcript::new(b"arcanum-batch-range-proof");

        self.proof
            .verify_multiple(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &self.commitments,
                n_bits,
            )
            .map(|_| true)
            .map_err(|_| Error::ProofVerificationFailed)
    }

    /// Get the commitments as bytes.
    pub fn commitment_bytes(&self) -> Vec<[u8; 32]> {
        self.commitments.iter().map(|c| c.to_bytes()).collect()
    }

    /// Number of values in this batch.
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }
}

impl core::fmt::Debug for RangeProofBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RangeProofBatch({} values)", self.commitments.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof_32_bits() {
        let value = 1000u64;
        let proof = RangeProof::prove(value, 32).unwrap();
        assert!(proof.verify(32).unwrap());
    }

    #[test]
    fn test_range_proof_64_bits() {
        let value = u64::MAX / 2;
        let proof = RangeProof::prove(value, 64).unwrap();
        assert!(proof.verify(64).unwrap());
    }

    #[test]
    fn test_range_proof_out_of_range() {
        let value = 256u64; // > 2^8
        let result = RangeProof::prove(value, 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_range_proof_serialization() {
        let value = 42u64;
        let proof = RangeProof::prove(value, 32).unwrap();

        let bytes = proof.to_bytes();
        let restored = RangeProof::from_bytes(&bytes, 32).unwrap();

        assert!(restored.verify(32).unwrap());
    }

    #[test]
    fn test_batch_range_proof() {
        let values = vec![10u64, 20, 30, 40];
        let proof = RangeProofBatch::prove(&values, 32).unwrap();
        assert!(proof.verify(32).unwrap());
        assert_eq!(proof.len(), 4);
    }

    #[test]
    fn test_range_proof_with_blinding() {
        let value = 100u64;
        let mut blinding = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut blinding);

        let proof = RangeProof::prove_with_blinding(value, &blinding, 32).unwrap();
        assert!(proof.verify(32).unwrap());
    }
}
