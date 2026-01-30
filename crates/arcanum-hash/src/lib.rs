//! # Arcanum Hash
//!
//! Cryptographic hash functions and key derivation for the Arcanum engine.
//!
//! ## Hash Function Selection
//!
//! ### Performance Comparison (4KB message, typical desktop CPU)
//!
//! | Algorithm | Throughput | Security | Use Case |
//! |-----------|------------|----------|----------|
//! | **BLAKE3** | **5.2 GiB/s** | 256-bit | **Recommended default** |
//! | SHA-256 | 1.7 GiB/s | 256-bit | TLS, Bitcoin, compatibility |
//! | SHA-512 | 1.9 GiB/s | 512-bit | Ed25519, larger output |
//! | SHA-3-256 | 0.8 GiB/s | 256-bit | NIST compliance |
//! | BLAKE2b | 1.2 GiB/s | 512-bit | Legacy BLAKE support |
//!
//! ### Recommendations
//!
//! **Use BLAKE3 ([`Blake3`]) for:**
//! - Content addressing / deduplication (file systems, object stores)
//! - File integrity checking (checksums, manifests)
//! - Key derivation with [`Blake3::derive_key`]
//! - Keyed hashing / MAC with [`Blake3::keyed_hash`]
//! - Any new application without legacy compatibility requirements
//! - Streaming large files (BLAKE3 is parallelizable)
//!
//! **Use SHA-256 ([`Sha256`]) for:**
//! - TLS / X.509 certificates
//! - Bitcoin / cryptocurrency protocols
//! - Compatibility with existing systems (HMAC, JWT, etc.)
//! - NIST-approved algorithm requirements
//!
//! **Use SHA-3 ([`Sha3_256`]) for:**
//! - Government/compliance requiring NIST SP 800-185
//! - Defense-in-depth (different construction than SHA-2)
//!
//! ### Type Alias
//!
//! For convenience, [`PreferredHasher`] is an alias for [`Blake3`]:
//!
//! ```ignore
//! use arcanum_hash::PreferredHasher;
//!
//! let hash = PreferredHasher::hash(b"data");
//! ```
//!
//! ## Hash Functions
//!
//! - **BLAKE3**: Ultra-fast, parallelizable, recommended default
//! - **SHA-2**: SHA-256, SHA-384, SHA-512 (NIST standard)
//! - **SHA-3**: SHA3-256, SHA3-512, SHAKE128, SHAKE256 (Keccak)
//! - **Blake2**: Blake2b, Blake2s (fast, secure, legacy)
//!
//! ## Key Derivation Functions
//!
//! - **Argon2id**: Password hashing (PHC winner, recommended)
//! - **BLAKE3 KDF**: Fast key derivation from high-entropy input
//! - **HKDF**: Key derivation from high-entropy input (RFC 5869)
//! - **scrypt**: Memory-hard password hashing
//! - **PBKDF2**: Legacy password hashing
//!
//! ## Message Authentication Codes
//!
//! - **BLAKE3 keyed**: Fast keyed hashing built into BLAKE3
//! - **HMAC**: Hash-based MAC (with any hash function)
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_hash::prelude::*;
//!
//! // Recommended: Use BLAKE3 for new applications
//! let hash = Blake3::hash(b"hello world");
//!
//! // BLAKE3 keyed hash (MAC)
//! let key = [0u8; 32];
//! let mac = Blake3::keyed_hash(&key, b"message");
//!
//! // BLAKE3 key derivation
//! let derived = Blake3::derive_key("my-app v1 encryption key", b"context data");
//!
//! // Incremental hashing for large data
//! let mut hasher = Blake3::new();
//! hasher.update(b"hello ");
//! hasher.update(b"world");
//! let hash = hasher.finalize();
//!
//! // SHA-256 for compatibility
//! let sha_hash = Sha256::hash(b"hello world");
//!
//! // Password hashing (always use Argon2id)
//! let hash = Argon2::hash_password(b"password", &Argon2Params::default())?;
//! assert!(Argon2::verify_password(b"password", &hash)?);
//!
//! // HKDF for protocol key derivation
//! let key = Hkdf::<Sha256>::derive(ikm, salt, info, 32)?;
//! ```
//!
//! ## Security Notes
//!
//! - **BLAKE3** is cryptographically secure with 256-bit security level
//! - All hash functions in this crate are collision-resistant and pre-image resistant
//! - For password hashing, **always** use Argon2id, never raw hash functions
//! - BLAKE3 keyed hashing is a proper MAC construction, not just `H(key || message)`

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_variables, dead_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "sha2")]
pub mod sha2_impl;

#[cfg(feature = "sha3")]
pub mod sha3_impl;

#[cfg(feature = "blake2")]
pub mod blake2_impl;

#[cfg(feature = "blake3")]
pub mod blake3_impl;

#[cfg(feature = "argon2")]
pub mod argon2_impl;

#[cfg(feature = "hkdf")]
pub mod hkdf_impl;

#[cfg(feature = "scrypt")]
pub mod scrypt_impl;

#[cfg(feature = "mac")]
pub mod hmac_impl;

mod traits;

pub use traits::{HashOutput, Hasher, KeyDerivation, PasswordHash};

#[cfg(feature = "sha2")]
pub use sha2_impl::{Sha256, Sha384, Sha512};

#[cfg(feature = "sha3")]
pub use sha3_impl::{Sha3_256, Sha3_512, Shake128, Shake256};

#[cfg(feature = "blake2")]
pub use blake2_impl::{Blake2b, Blake2s};

#[cfg(feature = "blake3")]
pub use blake3_impl::Blake3;

/// Preferred hash function for new applications.
///
/// This is an alias for [`Blake3`], which provides:
/// - 4-5x faster hashing than SHA-256
/// - Built-in keyed hashing (MAC)
/// - Built-in key derivation function
/// - Parallelizable for large inputs
/// - 256-bit security level
///
/// Use SHA-256 instead only when compatibility with existing systems is required.
#[cfg(feature = "blake3")]
pub type PreferredHasher = Blake3;

#[cfg(feature = "argon2")]
pub use argon2_impl::{Argon2, Argon2Params};

#[cfg(feature = "hkdf")]
pub use hkdf_impl::Hkdf;

#[cfg(feature = "scrypt")]
pub use scrypt_impl::{Scrypt, ScryptParams};

#[cfg(feature = "mac")]
pub use hmac_impl::Hmac;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::{HashOutput, Hasher, KeyDerivation, PasswordHash};

    #[cfg(feature = "sha2")]
    pub use crate::sha2_impl::{Sha256, Sha384, Sha512};

    #[cfg(feature = "sha3")]
    pub use crate::sha3_impl::{Sha3_256, Sha3_512};

    #[cfg(feature = "blake3")]
    pub use crate::blake3_impl::Blake3;

    #[cfg(feature = "blake3")]
    pub use crate::PreferredHasher;

    #[cfg(feature = "argon2")]
    pub use crate::argon2_impl::{Argon2, Argon2Params};

    #[cfg(feature = "hkdf")]
    pub use crate::hkdf_impl::Hkdf;
}
