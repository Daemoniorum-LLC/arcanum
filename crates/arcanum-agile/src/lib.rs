//! # Arcanum Cryptographic Agility
//!
//! Framework for managing algorithm selection, versioning, and migration.
//!
//! ## Algorithm Registry
//!
//! Central registry of all supported algorithms with metadata:
//!
//! - Security level classification
//! - Deprecation status and timeline
//! - Performance characteristics
//! - Compliance mappings (FIPS, SOC2, etc.)
//!
//! ## Versioned Containers
//!
//! Self-describing encrypted containers:
//!
//! - Algorithm identification in header
//! - Forward-compatible parsing
//! - Automatic migration recommendations
//!
//! ## Policy Engine
//!
//! Declarative algorithm restrictions:
//!
//! - Minimum security levels
//! - Required post-quantum support
//! - Compliance profiles (FIPS 140-3, etc.)
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_agile::prelude::*;
//!
//! // Look up algorithm metadata
//! let algo = AlgorithmRegistry::get(AlgorithmId::Aes256Gcm)?;
//! assert_eq!(algo.security_level(), SecurityLevel::Bits256);
//! assert!(!algo.is_deprecated());
//!
//! // Create versioned container
//! let container = AgileCiphertext::encrypt(
//!     AlgorithmId::Aes256Gcm,
//!     &key,
//!     &plaintext,
//! )?;
//!
//! // Check migration status
//! if let Some(recommendation) = container.migration_recommendation() {
//!     println!("Recommend migrating to {:?}", recommendation.target);
//! }
//!
//! // Enforce policy
//! let policy = Policy::fips_140_3();
//! assert!(policy.allows(AlgorithmId::Aes256Gcm));
//! assert!(!policy.allows(AlgorithmId::ChaCha20Poly1305)); // Not FIPS
//! ```
//!
//! ## Migration Support
//!
//! - Automatic re-encryption with newer algorithms
//! - Batch migration pipelines
//! - Progress tracking and rollback

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::op_ref)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "registry")]
pub mod registry;

#[cfg(feature = "containers")]
pub mod containers;

#[cfg(feature = "policy")]
pub mod policy;

#[cfg(feature = "migration")]
pub mod migration;

mod errors;

pub use errors::AgileError;

#[cfg(feature = "registry")]
pub use registry::{AlgorithmId, AlgorithmInfo, AlgorithmRegistry, SecurityLevel};

#[cfg(feature = "containers")]
pub use containers::{AgileCiphertext, ContainerHeader};

#[cfg(feature = "policy")]
pub use policy::{ComplianceProfile, Policy, PolicyBuilder};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::errors::AgileError;

    #[cfg(feature = "registry")]
    pub use crate::registry::{AlgorithmId, AlgorithmInfo, AlgorithmRegistry, SecurityLevel};

    #[cfg(feature = "containers")]
    pub use crate::containers::{AgileCiphertext, ContainerHeader};

    #[cfg(feature = "policy")]
    pub use crate::policy::{ComplianceProfile, Policy};
}
