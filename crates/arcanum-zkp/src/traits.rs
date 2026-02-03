//! Traits for zero-knowledge proofs.

use arcanum_core::error::Result;

/// Trait for zero-knowledge proofs.
pub trait ZeroKnowledgeProof: Sized {
    /// The statement being proven.
    type Statement;
    /// The witness (secret) used to create the proof.
    type Witness;

    /// Create a proof.
    #[must_use = "proof generation can fail; check the Result"]
    fn prove(statement: &Self::Statement, witness: &Self::Witness) -> Result<Self>;

    /// Verify a proof.
    #[must_use = "verification result must be checked"]
    fn verify(&self, statement: &Self::Statement) -> Result<bool>;
}

/// Trait for cryptographic commitments.
pub trait Commitment: Sized {
    /// The value being committed to.
    type Value;
    /// The opening (randomness) used.
    type Opening;

    /// Create a commitment.
    fn commit(value: &Self::Value, opening: &Self::Opening) -> Self;

    /// Verify that an opening is valid.
    fn verify(&self, value: &Self::Value, opening: &Self::Opening) -> bool;
}

/// Trait for homomorphic commitments.
pub trait HomomorphicCommitment: Commitment {
    /// Add two commitments.
    fn add(&self, other: &Self) -> Self;

    /// Subtract two commitments.
    fn sub(&self, other: &Self) -> Self;

    /// Multiply by a scalar.
    fn mul_scalar(&self, scalar: &Self::Value) -> Self;
}

/// Trait for range proofs.
pub trait RangeProofTrait: Sized {
    /// The commitment type.
    type Commitment;

    /// Prove that a committed value is in range [0, 2^n).
    #[must_use = "proof generation can fail; check the Result"]
    fn prove(value: u64, blinding: &[u8], n_bits: usize) -> Result<(Self::Commitment, Self)>;

    /// Verify a range proof.
    #[must_use = "verification result must be checked"]
    fn verify(&self, commitment: &Self::Commitment, n_bits: usize) -> Result<bool>;
}

/// Proof status after verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStatus {
    /// Proof is valid.
    Valid,
    /// Proof is invalid.
    Invalid,
    /// Verification error occurred.
    Error,
}

impl ProofStatus {
    /// Check if the proof is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, ProofStatus::Valid)
    }
}
