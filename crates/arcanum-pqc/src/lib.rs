//! # Arcanum Post-Quantum Cryptography
//!
//! Post-quantum cryptographic algorithms resistant to attacks by quantum computers.
//!
//! ## NIST Standards
//!
//! These algorithms are standardized by NIST for post-quantum cryptography:
//!
//! ### Key Encapsulation Mechanisms (KEMs)
//!
//! - **ML-KEM** (Module-Lattice KEM, formerly CRYSTALS-Kyber): FIPS 203
//!   - ML-KEM-512: 128-bit security
//!   - ML-KEM-768: 192-bit security (recommended)
//!   - ML-KEM-1024: 256-bit security
//!
//! ### Digital Signatures
//!
//! - **ML-DSA** (Module-Lattice Digital Signature, formerly CRYSTALS-Dilithium): FIPS 204
//!   - ML-DSA-44: 128-bit security
//!   - ML-DSA-65: 192-bit security (recommended)
//!   - ML-DSA-87: 256-bit security
//!
//! - **SLH-DSA** (Stateless Hash-based Digital Signature, formerly SPHINCS+): FIPS 205
//!   - Hash-based, very conservative security assumptions
//!
//! ## Hybrid Schemes
//!
//! Hybrid schemes combine classical and post-quantum algorithms for defense-in-depth:
//!
//! - **X25519-ML-KEM-768**: Classical ECDH + ML-KEM
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_pqc::prelude::*;
//!
//! // ML-KEM key encapsulation
//! let (dk, ek) = MlKem768::generate_keypair();
//! let (ciphertext, shared_secret) = MlKem768::encapsulate(&ek);
//! let decapsulated = MlKem768::decapsulate(&dk, &ciphertext)?;
//! assert_eq!(shared_secret, decapsulated);
//!
//! // ML-DSA signatures
//! let (sk, vk) = MlDsa65::generate_keypair();
//! let signature = MlDsa65::sign(&sk, b"message");
//! assert!(MlDsa65::verify(&vk, b"message", &signature).is_ok());
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::too_many_arguments, dead_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "ml-kem")]
pub mod kem;

#[cfg(feature = "ml-dsa")]
pub mod dsa;

#[cfg(feature = "ml-dsa-native")]
pub mod ml_dsa;

/// Arcanum-DSA: SIMD-optimized digital signatures (experimental)
///
/// Variant of ML-DSA with parameters optimized for modern SIMD architectures.
/// Maintains equivalent or stronger security while enabling efficient batching.
#[cfg(feature = "ml-dsa-native")]
pub mod arcanum_dsa;

#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

#[cfg(feature = "hybrid")]
pub mod hybrid;

mod traits;

pub use traits::{KeyEncapsulation, PostQuantumSignature};

#[cfg(feature = "ml-kem")]
pub use kem::{MlKem1024, MlKem512, MlKem768};

#[cfg(feature = "ml-dsa")]
pub use dsa::{MlDsa44Ops, MlDsa65, MlDsa87Ops};

#[cfg(feature = "hybrid")]
pub use hybrid::X25519MlKem768;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::{KeyEncapsulation, PostQuantumSignature};

    #[cfg(feature = "ml-kem")]
    pub use crate::kem::{MlKem1024, MlKem512, MlKem768};

    #[cfg(feature = "ml-dsa")]
    pub use crate::dsa::{MlDsa44Ops, MlDsa65, MlDsa87Ops};

    #[cfg(feature = "hybrid")]
    pub use crate::hybrid::X25519MlKem768;
}
