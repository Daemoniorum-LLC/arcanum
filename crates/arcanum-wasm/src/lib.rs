//! # Arcanum WASM
//!
//! WebAssembly bindings for the Arcanum cryptographic library.
//!
//! ## Backend Selection
//!
//! This crate supports two backends:
//!
//! - `backend-rustcrypto` (default): Wrappers around audited RustCrypto libraries.
//!   Recommended for production systems where security audit status matters.
//!
//! - `backend-native`: Arcanum's native primitives, optimized for tensor decompression
//!   and batch operations. **Not audited.** Smaller bundles. Your risk, your choice.
//!
//! ## Usage
//!
//! ```bash
//! # Build with audited RustCrypto (recommended)
//! wasm-pack build --features backend-rustcrypto
//!
//! # Build with native primitives (not audited)
//! wasm-pack build --features backend-native
//! ```

#![deny(missing_docs)]

mod error;
mod hash;
mod kdf;
mod random;
mod symmetric;

// Phase 2 (stubs for now)
mod asymmetric;

// Re-exports
pub use error::CryptoError;
pub use hash::{blake3, sha3_256, sha256};
pub use kdf::{argon2id, hkdf_sha256};
pub use random::random_bytes;
pub use symmetric::{AesGcm, ChaCha20Poly1305};

// Phase 2
pub use asymmetric::{Ed25519KeyPair, X25519KeyPair};
