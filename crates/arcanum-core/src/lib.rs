//! # Arcanum Core
//!
//! The foundational crate for the Arcanum cryptographic engine.
//!
//! This crate provides:
//! - Core traits for cryptographic operations
//! - Error types and result handling
//! - Secure memory types with automatic zeroization
//! - Cryptographically secure random number generation
//! - Key representations and type-safe wrappers
//! - Constant-time comparison utilities
//!
//! ## Design Principles
//!
//! 1. **Memory Safety**: All sensitive data is zeroized on drop
//! 2. **Type Safety**: Distinct types prevent mixing incompatible keys
//! 3. **Constant Time**: Side-channel resistant operations by default
//! 4. **Fail Secure**: Errors don't leak sensitive information
//! 5. **Composability**: Traits enable algorithm-agnostic code
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_core::prelude::*;
//!
//! // Generate a secure random key
//! let key = SecretKey::<32>::generate();
//!
//! // Constant-time comparison
//! assert!(key.ct_eq(&key));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod buffer;
#[cfg(feature = "encoding")]
pub mod encoding;
pub mod error;
pub mod key;
pub mod nonce;
pub mod random;
#[cfg(feature = "std")]
pub mod time;
pub mod traits;
pub mod version;

/// Re-exports of commonly used types
pub mod prelude {
    pub use crate::buffer::{SecretBuffer, SecretBytes, SecureVec};
    #[cfg(feature = "encoding")]
    pub use crate::encoding::{Base64, Hex};
    pub use crate::error::{Error, Result};
    #[cfg(feature = "std")]
    pub use crate::key::{KeyId, KeyMetadata};
    pub use crate::key::{PublicKey, SecretKey};
    pub use crate::nonce::Nonce;
    #[cfg(feature = "std")]
    pub use crate::random::{CryptoRng, OsRng};
    pub use crate::traits::*;
    pub use crate::version::Version;
}

// Re-export for convenience
pub use secrecy::{ExposeSecret, SecretBox, SecretString};
pub use zeroize::{Zeroize, ZeroizeOnDrop};
/// Type alias for backward compatibility with older secrecy API
pub type Secret<T> = SecretBox<T>;
pub use subtle::{Choice, ConstantTimeEq, CtOption};
