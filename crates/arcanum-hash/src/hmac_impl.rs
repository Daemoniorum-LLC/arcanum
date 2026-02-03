//! HMAC (Hash-based Message Authentication Code).
//!
//! HMAC provides message authentication using a secret key and hash function.

use arcanum_core::error::{Error, Result};
use hmac::{Hmac as HmacInner, Mac};
use sha2::{Sha256, Sha384, Sha512};
use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// HMAC message authentication code.
pub struct Hmac<H> {
    _marker: PhantomData<H>,
}

/// HMAC-SHA256.
pub type HmacSha256 = Hmac<Sha256>;
/// HMAC-SHA384.
pub type HmacSha384 = Hmac<Sha384>;
/// HMAC-SHA512.
pub type HmacSha512 = Hmac<Sha512>;

impl Hmac<Sha256> {
    /// MAC output size in bytes.
    pub const OUTPUT_SIZE: usize = 32;
    /// Algorithm name.
    pub const ALGORITHM: &'static str = "HMAC-SHA256";

    /// Compute HMAC.
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacInner::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify HMAC.
    #[must_use = "verification result must be checked"]
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
        let mut mac =
            HmacInner::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.verify_slice(tag)
            .map_err(|_| Error::MacVerificationFailed)
    }

    /// Compute and return as fixed-size array.
    pub fn compute_array(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac =
            HmacInner::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

impl Hmac<Sha384> {
    /// MAC output size in bytes.
    pub const OUTPUT_SIZE: usize = 48;
    /// Algorithm name.
    pub const ALGORITHM: &'static str = "HMAC-SHA384";

    /// Compute HMAC.
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacInner::<Sha384>::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify HMAC.
    #[must_use = "verification result must be checked"]
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
        let mut mac =
            HmacInner::<Sha384>::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.verify_slice(tag)
            .map_err(|_| Error::MacVerificationFailed)
    }
}

impl Hmac<Sha512> {
    /// MAC output size in bytes.
    pub const OUTPUT_SIZE: usize = 64;
    /// Algorithm name.
    pub const ALGORITHM: &'static str = "HMAC-SHA512";

    /// Compute HMAC.
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacInner::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify HMAC.
    #[must_use = "verification result must be checked"]
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
        let mut mac =
            HmacInner::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.verify_slice(tag)
            .map_err(|_| Error::MacVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let tag = Hmac::<Sha256>::compute(key, data);
        assert_eq!(tag.len(), 32);

        // Verification should succeed
        assert!(Hmac::<Sha256>::verify(key, data, &tag).is_ok());

        // Wrong data should fail
        assert!(Hmac::<Sha256>::verify(key, b"wrong data", &tag).is_err());

        // Wrong key should fail
        assert!(Hmac::<Sha256>::verify(b"wrong key", data, &tag).is_err());
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test1() {
        // RFC 4231 Test Case 1
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";

        let tag = Hmac::<Sha256>::compute(&key, data);

        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_hmac_sha512() {
        let key = b"secret key";
        let data = b"message";

        let tag = Hmac::<Sha512>::compute(key, data);
        assert_eq!(tag.len(), 64);

        assert!(Hmac::<Sha512>::verify(key, data, &tag).is_ok());
    }
}
