//! HKDF (HMAC-based Key Derivation Function).
//!
//! HKDF (RFC 5869) is used for deriving cryptographic keys from
//! high-entropy input key material. It is NOT suitable for passwords.
//!
//! Use cases:
//! - Deriving multiple keys from a shared secret
//! - Deriving keys from DH/ECDH outputs
//! - Key expansion

use crate::traits::KeyDerivation;
use arcanum_core::error::{Error, Result};
use hkdf::Hkdf as HkdfInner;
use sha2::{Sha256, Sha384, Sha512};
use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// HKDF key derivation function.
///
/// Generic over the underlying hash function.
pub struct Hkdf<H> {
    _marker: PhantomData<H>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// HKDF-SHA256
// ═══════════════════════════════════════════════════════════════════════════════

impl KeyDerivation for Hkdf<Sha256> {
    const ALGORITHM: &'static str = "HKDF-SHA256";

    fn derive(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let hkdf = HkdfInner::<Sha256>::new(salt, ikm);
        let mut output = vec![0u8; output_len];

        hkdf.expand(info.unwrap_or(&[]), &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(output)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HKDF-SHA384
// ═══════════════════════════════════════════════════════════════════════════════

impl KeyDerivation for Hkdf<Sha384> {
    const ALGORITHM: &'static str = "HKDF-SHA384";

    fn derive(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let hkdf = HkdfInner::<Sha384>::new(salt, ikm);
        let mut output = vec![0u8; output_len];

        hkdf.expand(info.unwrap_or(&[]), &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(output)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HKDF-SHA512
// ═══════════════════════════════════════════════════════════════════════════════

impl KeyDerivation for Hkdf<Sha512> {
    const ALGORITHM: &'static str = "HKDF-SHA512";

    fn derive(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let hkdf = HkdfInner::<Sha512>::new(salt, ikm);
        let mut output = vec![0u8; output_len];

        hkdf.expand(info.unwrap_or(&[]), &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(output)
    }
}

/// Type alias for HKDF with SHA-256.
pub type HkdfSha256 = Hkdf<Sha256>;
/// Type alias for HKDF with SHA-384.
pub type HkdfSha384 = Hkdf<Sha384>;
/// Type alias for HKDF with SHA-512.
pub type HkdfSha512 = Hkdf<Sha512>;

/// Convenience functions for HKDF-SHA256.
impl Hkdf<Sha256> {
    /// Derive a 256-bit key.
    #[must_use = "key derivation can fail; check the Result"]
    pub fn derive_256(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>) -> Result<[u8; 32]> {
        Self::derive_array(ikm, salt, info)
    }

    /// Derive multiple keys from the same IKM.
    ///
    /// Each key is derived with a different info string.
    #[must_use = "key derivation can fail; check the Result"]
    pub fn derive_multiple<const N: usize>(
        ikm: &[u8],
        salt: Option<&[u8]>,
        infos: &[&[u8]],
        key_len: usize,
    ) -> Result<Vec<Vec<u8>>> {
        infos
            .iter()
            .map(|info| Self::derive(ikm, salt, Some(info), key_len))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_rfc5869_test1() {
        // RFC 5869 Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let okm = Hkdf::<Sha256>::derive(&ikm, Some(&salt), Some(&info), 42).unwrap();

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        assert_eq!(okm, expected);
    }

    #[test]
    fn test_hkdf_sha256_no_salt() {
        let ikm = b"input key material";
        let info = b"context info";

        let key = Hkdf::<Sha256>::derive(ikm, None, Some(info), 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_sha256_no_info() {
        let ikm = b"input key material";
        let salt = b"salt value";

        let key = Hkdf::<Sha256>::derive(ikm, Some(salt), None, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_derive_256() {
        let ikm = b"shared secret";
        let key: [u8; 32] = Hkdf::<Sha256>::derive_256(ikm, None, Some(b"encryption")).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_different_info() {
        let ikm = b"shared secret";
        let salt = Some(b"salt".as_slice());

        let key1 = Hkdf::<Sha256>::derive(ikm, salt, Some(b"purpose1"), 32).unwrap();
        let key2 = Hkdf::<Sha256>::derive(ikm, salt, Some(b"purpose2"), 32).unwrap();

        // Different info should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_sha512() {
        let ikm = b"input key material";
        let key = Hkdf::<Sha512>::derive(ikm, None, None, 64).unwrap();
        assert_eq!(key.len(), 64);
    }
}
