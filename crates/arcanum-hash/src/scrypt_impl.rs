//! scrypt password hashing.
//!
//! scrypt is a memory-hard password hashing function designed to be
//! expensive to attack with custom hardware.

use crate::traits::PasswordHash;
use arcanum_core::error::{Error, Result};
use rand::rngs::OsRng;
use scrypt::{
    Params, Scrypt as ScryptInner,
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
};
use serde::{Deserialize, Serialize};

/// scrypt parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptParams {
    /// Log2 of the CPU/memory cost parameter (default: 15, meaning 2^15)
    pub log_n: u8,
    /// Block size parameter (default: 8)
    pub r: u32,
    /// Parallelization parameter (default: 1)
    pub p: u32,
    /// Output length in bytes (default: 32)
    pub output_len: usize,
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self::moderate()
    }
}

impl ScryptParams {
    /// Create custom parameters.
    pub fn new(log_n: u8, r: u32, p: u32) -> Self {
        Self {
            log_n,
            r,
            p,
            output_len: 32,
        }
    }

    /// Low security parameters (for testing).
    ///
    /// log_n: 12, r: 8, p: 1 (~4 MiB memory)
    pub fn low() -> Self {
        Self {
            log_n: 12,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// Moderate security parameters.
    ///
    /// log_n: 15, r: 8, p: 1 (~32 MiB memory)
    pub fn moderate() -> Self {
        Self {
            log_n: 15,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// High security parameters.
    ///
    /// log_n: 17, r: 8, p: 1 (~128 MiB memory)
    pub fn high() -> Self {
        Self {
            log_n: 17,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// Interactive parameters (fast response time).
    ///
    /// log_n: 14, r: 8, p: 1 (~16 MiB memory)
    pub fn interactive() -> Self {
        Self {
            log_n: 14,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// Sensitive parameters (for highly sensitive data).
    ///
    /// log_n: 20, r: 8, p: 1 (~1 GiB memory)
    pub fn sensitive() -> Self {
        Self {
            log_n: 20,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }
}

/// scrypt password hashing.
pub struct Scrypt;

impl PasswordHash for Scrypt {
    type Params = ScryptParams;
    const ALGORITHM: &'static str = "scrypt";

    fn hash_password(password: &[u8], params: &Self::Params) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);

        let scrypt_params = Params::new(params.log_n, params.r, params.p, params.output_len)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        let hash = ScryptInner
            .hash_password_customized(password, None, None, scrypt_params, &salt)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        Ok(hash.to_string())
    }

    fn verify_password(password: &[u8], hash: &str) -> Result<bool> {
        let parsed_hash = scrypt::password_hash::PasswordHash::new(hash)
            .map_err(|e| Error::ParseError(e.to_string()))?;

        Ok(ScryptInner.verify_password(password, &parsed_hash).is_ok())
    }

    fn derive_key(
        password: &[u8],
        salt: &[u8],
        params: &Self::Params,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let scrypt_params = Params::new(params.log_n, params.r, params.p, output_len)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        let mut output = vec![0u8; output_len];
        scrypt::scrypt(password, salt, &scrypt_params, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(output)
    }
}

impl Scrypt {
    /// Hash a password with default (moderate) parameters.
    pub fn hash(password: &[u8]) -> Result<String> {
        Self::hash_password(password, &ScryptParams::default())
    }

    /// Verify a password against a hash.
    pub fn verify(password: &[u8], hash: &str) -> Result<bool> {
        Self::verify_password(password, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify() {
        let password = b"correct horse battery staple";
        let hash = Scrypt::hash_password(password, &ScryptParams::low()).unwrap();

        assert!(Scrypt::verify_password(password, &hash).unwrap());
        assert!(!Scrypt::verify_password(b"wrong password", &hash).unwrap());
    }

    #[test]
    fn test_derive_key() {
        let password = b"password";
        let salt = b"somesalt12345678";

        let key1 = Scrypt::derive_key(password, salt, &ScryptParams::low(), 32).unwrap();
        let key2 = Scrypt::derive_key(password, salt, &ScryptParams::low(), 32).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_hash_format() {
        let password = b"test";
        let hash = Scrypt::hash_password(password, &ScryptParams::low()).unwrap();

        assert!(hash.starts_with("$scrypt$"));
    }
}
