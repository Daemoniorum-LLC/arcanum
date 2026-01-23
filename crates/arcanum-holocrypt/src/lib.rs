//! # Arcanum HoloCrypt
//!
//! Holocryptographic framework for composable cryptographic data structures.
//!
//! A HoloCrypt container simultaneously provides multiple security properties
//! that reinforce each other:
//!
//! ## Layered Security Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    HOLOCRYPT CONTAINER                               │
//! │                                                                      │
//! │  Layer 1: ENCRYPTION (confidentiality)                              │
//! │  ├── AEAD encryption (AES-GCM / ChaCha20-Poly1305)                 │
//! │  └── Post-quantum envelope (ML-KEM hybrid)                          │
//! │                                                                      │
//! │  Layer 2: COMMITMENT (binding)                                      │
//! │  └── Pedersen commitment to plaintext                               │
//! │                                                                      │
//! │  Layer 3: MERKLE STRUCTURE (verifiability)                          │
//! │  ├── BLAKE3 Merkle tree of chunks                                   │
//! │  └── Efficient selective disclosure proofs                          │
//! │                                                                      │
//! │  Layer 4: ZERO-KNOWLEDGE (privacy)                                  │
//! │  ├── Bulletproof validity proofs                                    │
//! │  └── Property proofs without revealing data                         │
//! │                                                                      │
//! │  Layer 5: THRESHOLD ACCESS (distributed trust)                      │
//! │  ├── FROST key shares for decryption                                │
//! │  └── k-of-n access control                                          │
//! │                                                                      │
//! │  Layer 6: SIGNATURE (authenticity)                                  │
//! │  └── Composite signature (Ed25519 + ML-DSA)                         │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Key Operations
//!
//! - **Seal**: Create a container with all cryptographic layers
//! - **Unseal**: Decrypt and verify a container
//! - **Verify**: Check structure without decrypting (ZK)
//! - **Reveal**: Selective disclosure of specific chunks
//! - **Prove**: Generate ZK proofs of properties
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_holocrypt::prelude::*;
//!
//! // Seal data with all protections
//! let data = SensitiveRecord { /* ... */ };
//! let (sealing_key, opening_key) = HoloCrypt::generate_keypair();
//! let container = HoloCrypt::seal(&data, &sealing_key)?;
//!
//! // Third party can verify without decrypting
//! container.verify_structure()?;
//!
//! // Selective disclosure - reveal only one chunk
//! let (chunk, proof) = container.reveal_chunk(2, &opening_key)?;
//! HoloCrypt::verify_chunk(&chunk, &proof, container.merkle_root())?;
//!
//! // Prove properties without revealing data
//! let proof = container.prove_property(
//!     Property::InRange { field: "age", min: 18, max: 65 },
//!     &opening_key,
//! )?;
//! proof.verify(container.commitment())?;
//!
//! // Threshold access - any 3 of 5 can decrypt
//! let container = HoloCrypt::seal_threshold(&data, &recipients, 3)?;
//! let shares = collect_shares_from_3_recipients();
//! let decrypted = container.unseal_threshold(&shares)?;
//! ```
//!
//! ## Security Properties
//!
//! | Property | Guarantee | Mechanism |
//! |----------|-----------|-----------|
//! | Confidentiality | Data hidden | AEAD + PQC envelope |
//! | Integrity | Tampering detected | Poly1305/GHASH + signature |
//! | Binding | Cannot change committed value | Pedersen commitment |
//! | Verifiability | Structure checkable | Merkle proofs + ZK |
//! | Privacy | Prove without revealing | Bulletproofs |
//! | Distributed trust | No single point of failure | FROST threshold |
//! | Quantum resistance | Future-proof | ML-KEM/ML-DSA hybrid |
//!
//! ## Research Background
//!
//! HoloCrypt combines established cryptographic primitives in a novel
//! composition that provides stronger guarantees than any single primitive.
//! The security relies on standard assumptions:
//!
//! - Discrete log hardness (Pedersen, Schnorr)
//! - AES/ChaCha security (AEAD)
//! - Module-LWE hardness (ML-KEM, ML-DSA)
//! - Random oracle model (Fiat-Shamir)

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_imports, unused_variables, dead_code, clippy::manual_div_ceil)]

pub mod container;
pub mod errors;
pub mod properties;
pub mod selective;

#[cfg(feature = "pqc")]
pub mod pqc;

pub use container::{HoloCrypt, OpeningKey, SealingKey};
pub use errors::HoloCryptError;

#[cfg(feature = "threshold")]
pub use container::threshold::{KeyShare, ThresholdContainer};

#[cfg(feature = "selective-disclosure")]
pub use selective::{ChunkProof, MerkleTreeBuilder, SelectiveDisclosure, verify_chunk};

#[cfg(feature = "property-proofs")]
pub use properties::{Property, PropertyProof};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::container::{HoloCrypt, OpeningKey, SealingKey};
    pub use crate::errors::HoloCryptError;

    #[cfg(feature = "threshold")]
    pub use crate::container::threshold::{KeyShare, ThresholdContainer};

    #[cfg(feature = "selective-disclosure")]
    pub use crate::selective::{ChunkProof, SelectiveDisclosure};

    #[cfg(feature = "property-proofs")]
    pub use crate::properties::{Property, PropertyProof};

    #[cfg(feature = "pqc")]
    pub use crate::pqc::{PqcContainer, PqcEnvelope, PqcKeyPair, WrappedKey};
}
