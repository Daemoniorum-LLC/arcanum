//! Cryptographically secure random number generation.
//!
//! This module provides wrappers around the operating system's CSPRNG
//! and additional utilities for generating random cryptographic values.

#[cfg(feature = "std")]
use crate::error::{Error, Result};
use rand::{CryptoRng as RandCryptoRng, RngCore};
#[cfg(feature = "std")]
use rand::SeedableRng;
#[cfg(feature = "std")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "std")]
use std::sync::Mutex;

// Re-export for convenience
#[cfg(feature = "std")]
pub use rand::rngs::OsRng;

// ═══════════════════════════════════════════════════════════════════════════════
// CRYPTO RNG TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Marker trait for cryptographically secure RNGs.
///
/// This is a re-export of `rand::CryptoRng` for convenience.
pub trait CryptoRng: RandCryptoRng + RngCore {}
impl<T: RandCryptoRng + RngCore> CryptoRng for T {}

// ═══════════════════════════════════════════════════════════════════════════════
// RANDOM GENERATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate random bytes using the OS CSPRNG.
#[cfg(feature = "std")]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate a random array of fixed size.
#[cfg(feature = "std")]
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate a random u64.
#[cfg(feature = "std")]
pub fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

/// Generate a random u32.
#[cfg(feature = "std")]
pub fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    OsRng.fill_bytes(&mut buf);
    u32::from_le_bytes(buf)
}

/// Generate a random u128.
#[cfg(feature = "std")]
pub fn random_u128() -> u128 {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    u128::from_le_bytes(buf)
}

/// Generate a random value in range [0, max).
#[cfg(feature = "std")]
pub fn random_range(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }

    // Rejection sampling for uniform distribution
    let threshold = u64::MAX - (u64::MAX % max);
    loop {
        let value = random_u64();
        if value < threshold {
            return value % max;
        }
    }
}

/// Fill a buffer with random bytes, returning an error on failure.
#[cfg(feature = "std")]
pub fn try_fill_bytes(dest: &mut [u8]) -> Result<()> {
    getrandom::getrandom(dest).map_err(|_| Error::RngFailed)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC RNG (for testing)
// ═══════════════════════════════════════════════════════════════════════════════

/// A deterministic RNG for testing purposes.
///
/// **WARNING**: This is NOT cryptographically secure for production use.
/// Only use this for testing where reproducibility is needed.
#[cfg(feature = "std")]
pub struct DeterministicRng {
    inner: ChaCha20Rng,
}

#[cfg(feature = "std")]
impl DeterministicRng {
    /// Create a new deterministic RNG from a seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Create from a u64 seed (extended to 32 bytes).
    pub fn from_u64(seed: u64) -> Self {
        let mut full_seed = [0u8; 32];
        full_seed[..8].copy_from_slice(&seed.to_le_bytes());
        Self::from_seed(full_seed)
    }
}

#[cfg(feature = "std")]
impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand::Error> {
        self.inner.try_fill_bytes(dest)
    }
}

// Note: DeterministicRng does NOT implement CryptoRng intentionally

// ═══════════════════════════════════════════════════════════════════════════════
// THREAD-LOCAL RNG
// ═══════════════════════════════════════════════════════════════════════════════

/// Thread-local cryptographic RNG for high-performance scenarios.
///
/// This uses ChaCha20 seeded from OsRng, providing fast random generation
/// while maintaining cryptographic security.
#[cfg(feature = "std")]
pub struct ThreadLocalRng {
    rng: Mutex<ChaCha20Rng>,
}

#[cfg(feature = "std")]
impl ThreadLocalRng {
    /// Create a new thread-local RNG.
    pub fn new() -> Self {
        Self {
            rng: Mutex::new(ChaCha20Rng::from_entropy()),
        }
    }

    /// Generate random bytes.
    ///
    /// # Thread Safety
    ///
    /// This function will not panic even if the mutex was poisoned by a panic
    /// in another thread - it recovers the inner RNG state.
    pub fn fill_bytes(&self, dest: &mut [u8]) {
        self.rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fill_bytes(dest);
    }

    /// Generate a random array.
    pub fn random_array<const N: usize>(&self) -> [u8; N] {
        let mut buf = [0u8; N];
        self.fill_bytes(&mut buf);
        buf
    }

    /// Reseed from the OS RNG.
    ///
    /// # Thread Safety
    ///
    /// This function will not panic even if the mutex was poisoned by a panic
    /// in another thread - it recovers and reseeds the RNG.
    pub fn reseed(&self) {
        *self
            .rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = ChaCha20Rng::from_entropy();
    }
}

#[cfg(feature = "std")]
impl Default for ThreadLocalRng {
    fn default() -> Self {
        Self::new()
    }
}

// Thread-local instance
#[cfg(feature = "std")]
thread_local! {
    static THREAD_RNG: ThreadLocalRng = ThreadLocalRng::new();
}

/// Get random bytes using the thread-local RNG.
#[cfg(feature = "std")]
pub fn thread_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    THREAD_RNG.with(|rng| rng.fill_bytes(&mut buf));
    buf
}

/// Get a random array using the thread-local RNG.
#[cfg(feature = "std")]
pub fn thread_random_array<const N: usize>() -> [u8; N] {
    THREAD_RNG.with(|rng| rng.random_array())
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY MIXING
// ═══════════════════════════════════════════════════════════════════════════════

/// Mix additional entropy into a seed.
///
/// Uses HKDF-like construction to mix multiple entropy sources.
#[cfg(feature = "std")]
pub fn mix_entropy(sources: &[&[u8]]) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();

    // Add OS entropy
    let mut os_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut os_entropy);
    hasher.update(&os_entropy);

    // Add provided sources
    for source in sources {
        hasher.update(&(source.len() as u64).to_le_bytes());
        hasher.update(source);
    }

    // Add timestamp for additional uniqueness
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    hasher.update(&timestamp.to_le_bytes());

    *hasher.finalize().as_bytes()
}

// ═══════════════════════════════════════════════════════════════════════════════
// RANDOM ID GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a random identifier as a hex string.
#[cfg(all(feature = "std", feature = "encoding"))]
pub fn random_id(bytes: usize) -> String {
    hex::encode(random_bytes(bytes))
}

/// Generate a random alphanumeric string.
#[cfg(feature = "std")]
pub fn random_alphanumeric(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    (0..len)
        .map(|_| {
            let idx = random_range(CHARSET.len() as u64) as usize;
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a random base64url-safe string (suitable for tokens).
#[cfg(all(feature = "std", feature = "encoding"))]
pub fn random_token(bytes: usize) -> String {
    <base64ct::Base64UrlUnpadded as base64ct::Encoding>::encode_string(&random_bytes(bytes))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let b1 = random_bytes(32);
        let b2 = random_bytes(32);
        assert_ne!(b1, b2);
        assert_eq!(b1.len(), 32);
    }

    #[test]
    fn test_random_array() {
        let arr: [u8; 16] = random_array();
        assert_eq!(arr.len(), 16);
    }

    #[test]
    fn test_random_range() {
        for _ in 0..1000 {
            let value = random_range(100);
            assert!(value < 100);
        }
    }

    #[test]
    fn test_deterministic_rng() {
        let mut rng1 = DeterministicRng::from_u64(42);
        let mut rng2 = DeterministicRng::from_u64(42);

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_thread_local_rng() {
        let b1 = thread_random_bytes(32);
        let b2 = thread_random_bytes(32);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_mix_entropy() {
        let mixed1 = mix_entropy(&[b"source1", b"source2"]);
        let mixed2 = mix_entropy(&[b"source1", b"source2"]);
        // Should be different due to timestamp and OS entropy
        assert_ne!(mixed1, mixed2);
    }

    #[cfg(feature = "encoding")]
    #[test]
    fn test_random_id() {
        let id = random_id(16);
        assert_eq!(id.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_random_alphanumeric() {
        let s = random_alphanumeric(20);
        assert_eq!(s.len(), 20);
        assert!(s.chars().all(|c| c.is_alphanumeric()));
    }
}
