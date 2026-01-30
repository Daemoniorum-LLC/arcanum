//! # Arcanum Asymmetric Cryptography
//!
//! Asymmetric (public-key) cryptography algorithms for encryption,
//! key exchange, and key agreement.
//!
//! ## RSA
//!
//! RSA encryption and signatures with modern padding schemes:
//! - **RSA-OAEP**: Optimal Asymmetric Encryption Padding
//! - **RSA-PSS**: Probabilistic Signature Scheme
//! - **RSA-PKCS#1**: Legacy padding (use OAEP/PSS for new applications)
//!
//! ## ECIES
//!
//! Elliptic Curve Integrated Encryption Scheme:
//! - ECIES-P256: Using NIST P-256 curve
//! - ECIES-P384: Using NIST P-384 curve
//! - ECIES-secp256k1: Using Bitcoin's curve
//!
//! ## Key Exchange
//!
//! - **X25519**: Curve25519 Diffie-Hellman (recommended)
//! - **X448**: Curve448 Diffie-Hellman (higher security)
//! - **ECDH**: Elliptic Curve Diffie-Hellman (P-256, P-384, secp256k1)
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_asymmetric::prelude::*;
//!
//! // X25519 key exchange
//! let alice_secret = X25519SecretKey::generate();
//! let alice_public = alice_secret.public_key();
//!
//! let bob_secret = X25519SecretKey::generate();
//! let bob_public = bob_secret.public_key();
//!
//! let alice_shared = alice_secret.diffie_hellman(&bob_public);
//! let bob_shared = bob_secret.diffie_hellman(&alice_public);
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//!
//! // RSA encryption
//! let (private_key, public_key) = RsaKeyPair::generate(2048)?;
//! let ciphertext = public_key.encrypt_oaep(b"secret message")?;
//! let plaintext = private_key.decrypt_oaep(&ciphertext)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(
    unused_imports,
    unused_variables,
    clippy::needless_borrows_for_generic_args
)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

mod traits;

#[cfg(feature = "rsa")]
pub mod rsa_impl;

#[cfg(feature = "ecies")]
pub mod ecies;

#[cfg(feature = "x25519")]
pub mod x25519;

#[cfg(feature = "x448")]
pub mod x448_impl;

pub mod ecdh;

pub use traits::*;

#[cfg(feature = "rsa")]
pub use rsa_impl::{
    RsaKeyPair, RsaOaepCiphertext, RsaPkcs1Ciphertext, RsaPkcs1Signature, RsaPrivateKey,
    RsaPssSignature, RsaPublicKey,
};

#[cfg(feature = "ecies")]
pub use ecies::{EciesCiphertext, EciesP256, EciesP384, EciesSecp256k1};

#[cfg(feature = "x25519")]
pub use x25519::{X25519PublicKey, X25519SecretKey, X25519SharedSecret};

#[cfg(feature = "x448")]
pub use x448_impl::{X448PublicKey, X448SecretKey, X448SharedSecret};

pub use ecdh::{
    EcdhP256, EcdhP384, EcdhSecp256k1, P256PublicKey, P256SecretKey, P384PublicKey, P384SecretKey,
    Secp256k1PublicKey, Secp256k1SecretKey,
};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::*;

    #[cfg(feature = "rsa")]
    pub use crate::rsa_impl::{RsaKeyPair, RsaPrivateKey, RsaPublicKey};

    #[cfg(feature = "ecies")]
    pub use crate::ecies::{EciesCiphertext, EciesP256, EciesP384, EciesSecp256k1};

    #[cfg(feature = "x25519")]
    pub use crate::x25519::{X25519PublicKey, X25519SecretKey, X25519SharedSecret};

    #[cfg(feature = "x448")]
    pub use crate::x448_impl::{X448PublicKey, X448SecretKey, X448SharedSecret};

    pub use crate::ecdh::{EcdhP256, EcdhP384, EcdhSecp256k1};
}
