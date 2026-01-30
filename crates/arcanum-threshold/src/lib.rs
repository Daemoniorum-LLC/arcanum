//! # Arcanum Threshold Cryptography
//!
//! Threshold cryptographic schemes for distributed key management and signing.
//!
//! ## Secret Sharing
//!
//! - **Shamir**: Basic (t, n) secret sharing
//! - **Feldman**: Verifiable secret sharing with public commitments
//! - **Pedersen**: Information-theoretically hiding verifiable secret sharing
//!
//! ## Threshold Signatures (FROST)
//!
//! FROST (Flexible Round-Optimized Schnorr Threshold) signatures:
//!
//! - **FROST-Ed25519**: Ed25519-compatible threshold signatures
//! - **FROST-secp256k1**: Bitcoin/Ethereum compatible signatures
//!
//! ## Distributed Key Generation (DKG)
//!
//! Generate group keys without trusted dealer:
//!
//! - **Pedersen DKG**: Two-round DKG with information-theoretic security
//! - **FROST DKG**: Integrated key generation for FROST signing
//!
//! ## Proactive Refresh
//!
//! Limit the window of compromise with periodic share refresh:
//!
//! - **Centralized refresh**: Dealer refreshes all shares at once
//! - **Distributed refresh**: Participants cooperatively refresh without dealer
//!
//! After refresh, old shares are incompatible with new shares, preventing
//! attackers from combining shares collected over different time periods.
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_threshold::prelude::*;
//!
//! // Create 3-of-5 Shamir sharing
//! let secret = b"my secret key";
//! let shares = ShamirScheme::split(secret, 3, 5)?;
//!
//! // Reconstruct from any 3 shares
//! let recovered = ShamirScheme::combine(&shares[..3])?;
//! assert_eq!(secret.as_slice(), recovered.as_slice());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(
    clippy::needless_range_loop,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args
)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod error;

#[cfg(feature = "shamir")]
pub mod shamir;

#[cfg(feature = "frost")]
pub mod frost;

#[cfg(feature = "dkg")]
pub mod dkg;

#[cfg(feature = "proactive")]
pub mod proactive;

pub use error::{Result, ThresholdError};

#[cfg(feature = "shamir")]
pub use shamir::{ShamirScheme, Share};

#[cfg(feature = "frost")]
pub use frost::{FrostSigner, FrostVerifier, SigningShare, VerifyingShare};

#[cfg(feature = "dkg")]
pub use dkg::{DkgParticipant, DkgRound1, DkgRound2};

#[cfg(feature = "proactive")]
pub use proactive::{ProactiveRefresh, RefreshShares};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::error::{Result, ThresholdError};

    #[cfg(feature = "shamir")]
    pub use crate::shamir::{ShamirScheme, Share};

    #[cfg(feature = "frost")]
    pub use crate::frost::{FrostSigner, FrostVerifier};

    #[cfg(feature = "dkg")]
    pub use crate::dkg::{DkgParticipant, DkgRound1, DkgRound2};

    #[cfg(feature = "proactive")]
    pub use crate::proactive::{ProactiveRefresh, RefreshShares};
}

/// Re-export identifier type for participants.
pub type Identifier = u16;
