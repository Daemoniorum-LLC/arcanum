//! Argon2 password hashing.
//!
//! Argon2 is the winner of the Password Hashing Competition (PHC) and the
//! recommended algorithm for password hashing. It provides:
//!
//! - **Memory-hardness**: Resistant to GPU/ASIC attacks
//! - **Time-hardness**: Configurable computation time
//! - **Parallelism**: Can utilize multiple cores
//!
//! We use **Argon2id** which combines Argon2i and Argon2d for best security.

use crate::traits::PasswordHash;
use arcanum_core::error::{Error, Result};
use argon2::{
    Algorithm, Argon2 as Argon2Inner, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Argon2id parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 64 MiB)
    pub memory_cost: u32,
    /// Time cost (iterations) (default: 3)
    pub time_cost: u32,
    /// Parallelism (lanes) (default: 4)
    pub parallelism: u32,
    /// Output length in bytes (default: 32)
    pub output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::moderate()
    }
}

impl Argon2Params {
    /// Create custom parameters.
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
            output_len: 32,
        }
    }

    /// Low security parameters (for testing or low-security contexts).
    ///
    /// Memory: 16 MiB, Time: 2, Parallelism: 1
    pub fn low() -> Self {
        Self {
            memory_cost: 16 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
        }
    }

    /// Moderate security parameters (good balance).
    ///
    /// Memory: 64 MiB, Time: 3, Parallelism: 4
    pub fn moderate() -> Self {
        Self {
            memory_cost: 64 * 1024,
            time_cost: 3,
            parallelism: 4,
            output_len: 32,
        }
    }

    /// High security parameters (for sensitive data).
    ///
    /// Memory: 256 MiB, Time: 4, Parallelism: 4
    pub fn high() -> Self {
        Self {
            memory_cost: 256 * 1024,
            time_cost: 4,
            parallelism: 4,
            output_len: 32,
        }
    }

    /// Maximum security parameters (for extremely sensitive data).
    ///
    /// Memory: 1 GiB, Time: 6, Parallelism: 4
    pub fn maximum() -> Self {
        Self {
            memory_cost: 1024 * 1024,
            time_cost: 6,
            parallelism: 4,
            output_len: 32,
        }
    }

    /// OWASP recommended parameters (2024).
    ///
    /// Memory: 19 MiB, Time: 2, Parallelism: 1
    pub fn owasp() -> Self {
        Self {
            memory_cost: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
        }
    }
}

/// Argon2id password hashing.
pub struct Argon2;

impl PasswordHash for Argon2 {
    type Params = Argon2Params;
    const ALGORITHM: &'static str = "Argon2id";

    fn hash_password(password: &[u8], params: &Self::Params) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);

        let argon2_params = Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(params.output_len),
        )
        .map_err(|e| Error::InternalError(e.to_string()))?;

        let argon2 = Argon2Inner::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        let hash = argon2
            .hash_password(password, &salt)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        Ok(hash.to_string())
    }

    fn verify_password(password: &[u8], hash: &str) -> Result<bool> {
        let parsed_hash =
            argon2::PasswordHash::new(hash).map_err(|e| Error::ParseError(e.to_string()))?;

        let argon2 = Argon2Inner::default();

        Ok(argon2.verify_password(password, &parsed_hash).is_ok())
    }

    fn derive_key(
        password: &[u8],
        salt: &[u8],
        params: &Self::Params,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let argon2_params = Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(output_len),
        )
        .map_err(|e| Error::InternalError(e.to_string()))?;

        let argon2 = Argon2Inner::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| Error::KeyDerivationFailed)?;

        Ok(output)
    }
}

impl Argon2 {
    /// Hash a password with default (moderate) parameters.
    pub fn hash(password: &[u8]) -> Result<String> {
        Self::hash_password(password, &Argon2Params::default())
    }

    /// Verify a password against a hash.
    pub fn verify(password: &[u8], hash: &str) -> Result<bool> {
        Self::verify_password(password, hash)
    }

    /// Derive a 256-bit key from a password.
    pub fn derive_key_256(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
        let key = Self::derive_key(password, salt, &Argon2Params::default(), 32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify() {
        let password = b"correct horse battery staple";
        let hash = Argon2::hash_password(password, &Argon2Params::low()).unwrap();

        // Correct password should verify
        assert!(Argon2::verify_password(password, &hash).unwrap());

        // Wrong password should fail
        assert!(!Argon2::verify_password(b"wrong password", &hash).unwrap());
    }

    #[test]
    fn test_hash_format() {
        let password = b"test";
        let hash = Argon2::hash_password(password, &Argon2Params::low()).unwrap();

        // Should be in PHC string format
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_derive_key() {
        let password = b"password";
        let salt = b"somesalt12345678"; // 16 bytes minimum

        let key1 = Argon2::derive_key(password, salt, &Argon2Params::low(), 32).unwrap();
        let key2 = Argon2::derive_key(password, salt, &Argon2Params::low(), 32).unwrap();

        // Same inputs should produce same output
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        // Different password should produce different key
        let key3 = Argon2::derive_key(b"different", salt, &Argon2Params::low(), 32).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_different_salts() {
        let password = b"password";
        let hash1 = Argon2::hash_password(password, &Argon2Params::low()).unwrap();
        let hash2 = Argon2::hash_password(password, &Argon2Params::low()).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // Both should still verify
        assert!(Argon2::verify_password(password, &hash1).unwrap());
        assert!(Argon2::verify_password(password, &hash2).unwrap());
    }
}
