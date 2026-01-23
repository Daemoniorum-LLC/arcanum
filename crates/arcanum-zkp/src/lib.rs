//! # Arcanum Zero-Knowledge Proofs
//!
//! Zero-knowledge proof systems for proving statements without revealing secrets.
//!
//! ## Bulletproofs
//!
//! Efficient range proofs without trusted setup:
//! - Prove a committed value is within a range [0, 2^n)
//! - Logarithmic proof size
//! - Aggregatable for multiple proofs
//!
//! ## Schnorr Proofs
//!
//! Interactive proofs of knowledge:
//! - Proof of discrete log knowledge
//! - Proof of equality of discrete logs
//! - Made non-interactive via Fiat-Shamir
//!
//! ## Pedersen Commitments
//!
//! Information-theoretically hiding commitments:
//! - Perfectly hiding: reveals nothing about the value
//! - Computationally binding: cannot open to different value
//! - Homomorphic: C(a) + C(b) = C(a + b)
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_zkp::prelude::*;
//!
//! // Range proof: prove value is in [0, 2^32)
//! let value = 42u64;
//! let blinding = Scalar::random(&mut OsRng);
//! let (commitment, proof) = RangeProof::prove(value, blinding, 32)?;
//!
//! // Verify the proof
//! assert!(proof.verify(&commitment, 32)?);
//! ```

#![deny(unsafe_code)]
#![allow(clippy::needless_return)]
#![allow(clippy::needless_borrow, clippy::needless_borrows_for_generic_args)]
#![allow(unused_imports, unused_mut, dead_code, clippy::needless_range_loop)]
#![warn(missing_docs, rust_2018_idioms)]

mod commitment;
mod traits;

#[cfg(feature = "bulletproofs")]
pub mod range_proof;

#[cfg(feature = "schnorr-proofs")]
pub mod schnorr_proof;

pub use commitment::{PedersenCommitment, PedersenOpening};
pub use traits::*;

#[cfg(feature = "bulletproofs")]
pub use range_proof::{RangeProof, RangeProofBatch};

#[cfg(feature = "schnorr-proofs")]
pub use schnorr_proof::{DiscreteLogProof, EqualityProof, SchnorrProof, SchnorrProofBuilder};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::commitment::{PedersenCommitment, PedersenOpening};
    pub use crate::traits::*;

    #[cfg(feature = "bulletproofs")]
    pub use crate::range_proof::{RangeProof, RangeProofBatch};

    #[cfg(feature = "schnorr-proofs")]
    pub use crate::schnorr_proof::{DiscreteLogProof, EqualityProof, SchnorrProof};
}

/// Re-export curve25519-dalek types for convenience.
pub mod curve {
    pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    pub use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    pub use curve25519_dalek::scalar::Scalar;
}
