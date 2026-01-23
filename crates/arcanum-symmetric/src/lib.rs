//! # Arcanum Symmetric Encryption
//!
//! High-performance symmetric encryption algorithms with a unified interface.
//!
//! ## Security Guarantees
//!
//! All cipher implementations in this crate provide:
//!
//! - **Constant-time operations**: Key comparison, authentication tag verification,
//!   and decryption are implemented in constant time to prevent timing attacks.
//!
//! - **Memory zeroization**: All secret key material is automatically zeroized
//!   when dropped using the `zeroize` crate via `SecretBytes`.
//!
//! - **Authenticated encryption**: All AEAD ciphers provide both confidentiality
//!   and integrity. Any tampering with ciphertext or AAD is detected on decryption.
//!
//! - **Cryptographically secure RNG**: All key and nonce generation uses `OsRng`
//!   from the operating system, never `thread_rng()` or other non-cryptographic sources.
//!
//! - **Input validation**: Plaintext and AAD sizes are validated against safe limits
//!   to prevent integer overflow attacks.
//!
//! ## Nonce Requirements
//!
//! **CRITICAL**: Nonce reuse with the same key is catastrophic for most AEAD ciphers:
//!
//! | Cipher | Nonce Size | Nonce Reuse Impact |
//! |--------|------------|-------------------|
//! | AES-256-GCM | 96-bit | **Complete key compromise** - attacker can forge messages and recover plaintext |
//! | AES-128-GCM | 96-bit | **Complete key compromise** - same as above |
//! | AES-256-GCM-SIV | 96-bit | Reveals if same message encrypted twice (deterministic) |
//! | ChaCha20-Poly1305 | 96-bit | **Complete key compromise** - poly1305 key revealed |
//! | XChaCha20-Poly1305 | 192-bit | **Complete key compromise** - but collision probability negligible |
//!
//! ### Nonce Selection Recommendations
//!
//! - **Counter-based nonces**: For high-volume encryption, use a monotonic counter.
//!   Never resets, never reuses. Best for databases, file encryption, network protocols.
//!
//! - **Random nonces with XChaCha20**: If you must use random nonces, use XChaCha20-Poly1305.
//!   With 192-bit nonces, collision probability is negligible even after 2^64 messages.
//!
//! - **Nonce-misuse resistance**: Use AES-256-GCM-SIV when accidental nonce reuse is possible
//!   (at ~15% performance cost). This is the safest choice for key-value stores.
//!
//! ## Algorithm Selection Guide
//!
//! | Use Case | Recommended Cipher | Reason |
//! |----------|-------------------|--------|
//! | General purpose | AES-256-GCM | Hardware-accelerated (AES-NI), widely supported, fast |
//! | Random nonces required | XChaCha20-Poly1305 | 192-bit nonce prevents collisions up to 2^64 messages |
//! | Nonce-misuse tolerance | AES-256-GCM-SIV | Deterministic encryption safe for repeated messages |
//! | No hardware AES | ChaCha20-Poly1305 | Fast constant-time software implementation |
//! | High-security 128-bit | AES-128-GCM | Slightly faster, 128-bit security sufficient for most uses |
//! | Streaming encryption | AES-256-CTR or ChaCha20Stream | For encrypting large files in chunks |
//!
//! ### Performance Characteristics (Typical Desktop CPU)
//!
//! | Cipher | Throughput (with HW) | Throughput (software) |
//! |--------|---------------------|----------------------|
//! | AES-256-GCM | ~4 GiB/s | ~200 MiB/s |
//! | AES-128-GCM | ~5 GiB/s | ~250 MiB/s |
//! | ChaCha20-Poly1305 | ~1.5 GiB/s | ~1.5 GiB/s |
//! | XChaCha20-Poly1305 | ~1.5 GiB/s | ~1.5 GiB/s |
//!
//! ## Supported Algorithms
//!
//! ### AEAD (Authenticated Encryption with Associated Data)
//!
//! - **AES-256-GCM**: Industry standard, hardware-accelerated on modern CPUs
//! - **AES-128-GCM**: Faster variant with 128-bit keys
//! - **AES-256-GCM-SIV**: Nonce-misuse resistant variant (RFC 8452)
//! - **ChaCha20-Poly1305**: Fast software implementation, constant-time (RFC 8439)
//! - **XChaCha20-Poly1305**: Extended nonce variant (192-bit nonces)
//!
//! ### Stream Ciphers
//!
//! - **AES-CTR**: Counter mode for streaming encryption
//! - **ChaCha20**: Standalone stream cipher
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_symmetric::{Aes256Gcm, Cipher};
//!
//! // Generate a random key and nonce
//! let key = Aes256Gcm::generate_key();
//! let nonce = Aes256Gcm::generate_nonce();
//!
//! // Encrypt with optional associated data (AAD)
//! let plaintext = b"secret message";
//! let aad = b"additional authenticated data";
//! let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, Some(aad))?;
//!
//! // Decrypt (must provide same AAD)
//! let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, Some(aad))?;
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! ## Security Best Practices
//!
//! 1. **Never reuse nonces** with the same key - this is catastrophic for GCM/Poly1305
//! 2. **Use XChaCha20-Poly1305** if random nonces are required (192-bit nonce space)
//! 3. **Use AES-256-GCM-SIV** for nonce-misuse resistance when safety is paramount
//! 4. **Rotate keys periodically** - after 2^32 messages for GCM, 2^64 for XChaCha20
//! 5. **Validate decryption errors** - authentication failures indicate tampering
//! 6. **Use AAD appropriately** - bind ciphertext to context (user ID, timestamp, etc.)

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(unused_imports)]

#[cfg(feature = "aes")]
pub mod aes_ciphers;

#[cfg(feature = "chacha20")]
pub mod chacha_ciphers;

pub mod builder;
mod encrypted;
mod traits;
pub mod types;

pub use encrypted::{EncryptedData, EncryptedPayload};
pub use traits::{
    Cipher, MAX_AAD_SIZE, MAX_PLAINTEXT_SIZE, StreamCipher, validate_aad_size,
    validate_input_sizes, validate_plaintext_size,
};

#[cfg(feature = "aes")]
pub use aes_ciphers::{Aes128Gcm, Aes256Ctr, Aes256Gcm, Aes256GcmSiv};

#[cfg(feature = "chacha20")]
pub use chacha_ciphers::{ChaCha20Poly1305Cipher, ChaCha20Stream, XChaCha20Poly1305Cipher};

// Re-export builder traits
pub use builder::{CipherExt, EncryptionBuilder};

// Re-export type aliases
pub use types::{
    Aes128Key, Aes256Key, AesCtrIv, AesGcmNonce, AuthTag, ChaChaKey, ChaChaNonce, CryptoResult,
    GcmNonce, GcmTag, Poly1305Tag, XChaChaNonce,
};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::builder::{CipherExt, EncryptionBuilder};
    pub use crate::encrypted::{EncryptedData, EncryptedPayload};
    pub use crate::traits::{Cipher, StreamCipher};
    pub use crate::types::*;

    #[cfg(feature = "aes")]
    pub use crate::aes_ciphers::{Aes128Gcm, Aes256Gcm, Aes256GcmSiv};

    #[cfg(feature = "chacha20")]
    pub use crate::chacha_ciphers::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};
}
