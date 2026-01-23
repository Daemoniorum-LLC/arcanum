//! Nonce generation and management.
//!
//! Proper nonce handling is critical for cryptographic security.
//! This module provides utilities for generating and tracking nonces
//! to prevent catastrophic nonce reuse.

use crate::error::{Error, Result};
use crate::random::OsRng;
use lru::LruCache;
use parking_lot::Mutex;
use rand::RngCore;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE TYPE
// ═══════════════════════════════════════════════════════════════════════════════

/// A cryptographic nonce (number used once).
///
/// This type ensures compile-time sizing and provides various
/// generation strategies.
#[derive(Clone, Zeroize)]
pub struct Nonce<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Nonce<N> {
    /// Create a nonce from bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Create from a slice, returning error if length doesn't match.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidNonceLength {
                expected: N,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Generate a random nonce.
    pub fn random() -> Self {
        let mut bytes = [0u8; N];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create a zero nonce (use with counter-based schemes).
    pub fn zero() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Access the nonce bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Access as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the nonce size in bytes.
    pub const fn len() -> usize {
        N
    }

    /// Increment the nonce (for counter-based nonces).
    ///
    /// Returns `Err` if overflow would occur.
    pub fn increment(&mut self) -> Result<()> {
        for byte in self.bytes.iter_mut().rev() {
            if *byte == 255 {
                *byte = 0;
            } else {
                *byte += 1;
                return Ok(());
            }
        }
        Err(Error::NonceExhausted)
    }

    /// Create from a u64 counter (for 12-byte nonces).
    ///
    /// The counter is placed in the last 8 bytes.
    ///
    /// # Panics
    /// Panics if N < 8 (nonce must be at least 8 bytes to hold a u64 counter).
    pub fn from_counter(counter: u64) -> Self {
        assert!(N >= 8, "Nonce must be at least 8 bytes to use from_counter");
        let mut bytes = [0u8; N];
        bytes[N - 8..].copy_from_slice(&counter.to_be_bytes());
        Self { bytes }
    }
}

impl<const N: usize> AsRef<[u8]> for Nonce<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> std::fmt::Debug for Nonce<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce<{}>({})", N, hex::encode(self.bytes))
    }
}

impl<const N: usize> std::fmt::Display for Nonce<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════

/// Strategy for generating nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceStrategy {
    /// Purely random nonces (recommended for most use cases).
    Random,
    /// Counter-based nonces (for high-volume encryption).
    Counter,
    /// Hybrid: random prefix + counter suffix.
    Hybrid,
}

/// Thread-safe nonce generator.
///
/// Tracks nonce generation to help prevent reuse.
pub struct NonceGenerator<const N: usize> {
    strategy: NonceStrategy,
    counter: AtomicU64,
    random_prefix: [u8; 4],
    generated_count: AtomicU64,
    max_nonces: Option<u64>,
}

impl<const N: usize> NonceGenerator<N> {
    /// Create a new random nonce generator.
    pub fn random() -> Self {
        Self {
            strategy: NonceStrategy::Random,
            counter: AtomicU64::new(0),
            random_prefix: [0; 4],
            generated_count: AtomicU64::new(0),
            max_nonces: None,
        }
    }

    /// Create a counter-based nonce generator.
    ///
    /// Useful when you need deterministic nonces or very high throughput.
    pub fn counter(start: u64) -> Self {
        Self {
            strategy: NonceStrategy::Counter,
            counter: AtomicU64::new(start),
            random_prefix: [0; 4],
            generated_count: AtomicU64::new(0),
            max_nonces: None,
        }
    }

    /// Create a hybrid nonce generator.
    ///
    /// Combines a random prefix with a counter for the best of both worlds.
    pub fn hybrid() -> Self {
        let mut prefix = [0u8; 4];
        OsRng.fill_bytes(&mut prefix);

        Self {
            strategy: NonceStrategy::Hybrid,
            counter: AtomicU64::new(0),
            random_prefix: prefix,
            generated_count: AtomicU64::new(0),
            max_nonces: None,
        }
    }

    /// Set a maximum number of nonces that can be generated.
    ///
    /// After this limit, `generate` will return an error.
    pub fn with_limit(mut self, max: u64) -> Self {
        self.max_nonces = Some(max);
        self
    }

    /// Generate the next nonce.
    pub fn generate(&self) -> Result<Nonce<N>> {
        // Check limit and always increment count
        let count = self.generated_count.fetch_add(1, Ordering::SeqCst);
        if let Some(max) = self.max_nonces {
            if count >= max {
                // Revert the increment since we're not generating
                self.generated_count.fetch_sub(1, Ordering::SeqCst);
                return Err(Error::NonceExhausted);
            }
        }

        match self.strategy {
            NonceStrategy::Random => Ok(Nonce::random()),

            NonceStrategy::Counter => {
                let counter = self.counter.fetch_add(1, Ordering::SeqCst);
                if counter == u64::MAX {
                    return Err(Error::NonceExhausted);
                }

                let mut bytes = [0u8; N];
                let counter_bytes = counter.to_be_bytes();
                let start = N.saturating_sub(8);
                bytes[start..].copy_from_slice(&counter_bytes[8 - (N - start)..]);
                Ok(Nonce::new(bytes))
            }

            NonceStrategy::Hybrid => {
                let counter = self.counter.fetch_add(1, Ordering::SeqCst);
                if counter == u64::MAX {
                    return Err(Error::NonceExhausted);
                }

                let mut bytes = [0u8; N];
                // First 4 bytes: random prefix
                let prefix_len = 4.min(N);
                bytes[..prefix_len].copy_from_slice(&self.random_prefix[..prefix_len]);

                // Remaining bytes: counter
                if N > 4 {
                    let counter_bytes = counter.to_be_bytes();
                    let counter_space = N - 4;
                    let counter_start = 8usize.saturating_sub(counter_space);
                    bytes[4..].copy_from_slice(&counter_bytes[counter_start..]);
                }

                Ok(Nonce::new(bytes))
            }
        }
    }

    /// Get the number of nonces generated.
    pub fn count(&self) -> u64 {
        self.generated_count.load(Ordering::SeqCst)
    }

    /// Get the current counter value.
    pub fn current_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Reset the generator (use with extreme caution).
    ///
    /// # Security Warning
    ///
    /// **DANGER**: Resetting a nonce generator can lead to catastrophic nonce reuse
    /// if the same encryption key is still in use. Only call this when you are
    /// absolutely certain a new key will be used.
    ///
    /// This method is intentionally verbose to prevent accidental misuse.
    pub fn reset_dangerous_nonce_reuse_possible(&self) {
        self.counter.store(0, Ordering::SeqCst);
        self.generated_count.store(0, Ordering::SeqCst);
    }
}

impl<const N: usize> Default for NonceGenerator<N> {
    fn default() -> Self {
        Self::random()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE TRACKER
// ═══════════════════════════════════════════════════════════════════════════════

/// Tracks used nonces to detect reuse using LRU eviction.
///
/// Useful for receiving encrypted messages where you need to
/// ensure an attacker isn't replaying old messages.
///
/// When the tracker reaches capacity, the least recently used entries
/// are automatically evicted to make room for new entries. This is more
/// secure than random eviction as it maintains protection for actively
/// used communication channels.
///
/// # Security Considerations
///
/// - The tracker protects against replay attacks within its capacity
/// - Evicted nonces can be replayed if reused by an attacker
/// - Size the capacity appropriately for your security requirements
/// - Consider using with sliding time windows for long-running systems
pub struct NonceTracker<const N: usize> {
    cache: Mutex<LruCache<[u8; N], ()>>,
    max_entries: NonZeroUsize,
    eviction_count: AtomicU64,
}

impl<const N: usize> NonceTracker<N> {
    /// Create a new nonce tracker with the specified capacity.
    ///
    /// # Panics
    ///
    /// Panics if `max_entries` is 0.
    pub fn new(max_entries: usize) -> Self {
        let max_entries =
            NonZeroUsize::new(max_entries).expect("NonceTracker capacity must be greater than 0");
        Self {
            cache: Mutex::new(LruCache::new(max_entries)),
            max_entries,
            eviction_count: AtomicU64::new(0),
        }
    }

    /// Check and record a nonce.
    ///
    /// Returns `Ok(())` if this is a new nonce, `Err(NonceReuse)` if seen before.
    ///
    /// When at capacity, the least recently checked nonce is automatically
    /// evicted to make room.
    #[must_use = "nonce reuse check must be verified - reuse is catastrophic"]
    pub fn check(&self, nonce: &Nonce<N>) -> Result<()> {
        let mut cache = self.cache.lock();

        // Check for reuse - peek doesn't update LRU order
        if cache.peek(nonce.as_bytes()).is_some() {
            return Err(Error::NonceReuse);
        }

        // Track evictions when at capacity
        if cache.len() >= self.max_entries.get() {
            self.eviction_count.fetch_add(1, Ordering::Relaxed);
        }

        // Insert the nonce - LruCache automatically evicts oldest if at capacity
        cache.put(*nonce.as_bytes(), ());
        Ok(())
    }

    /// Check and record a nonce, updating its LRU position.
    ///
    /// Use this variant when you want successful checks to refresh
    /// the nonce's position in the LRU cache (preventing eviction
    /// of frequently-used channels).
    #[must_use = "nonce reuse check must be verified - reuse is catastrophic"]
    pub fn check_and_touch(&self, nonce: &Nonce<N>) -> Result<()> {
        let mut cache = self.cache.lock();

        // Check for reuse - get updates LRU order
        if cache.get(nonce.as_bytes()).is_some() {
            return Err(Error::NonceReuse);
        }

        // Track evictions when at capacity
        if cache.len() >= self.max_entries.get() {
            self.eviction_count.fetch_add(1, Ordering::Relaxed);
        }

        cache.put(*nonce.as_bytes(), ());
        Ok(())
    }

    /// Clear all tracked nonces.
    pub fn clear(&self) {
        self.cache.lock().clear();
    }

    /// Get the number of tracked nonces.
    pub fn len(&self) -> usize {
        self.cache.lock().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.cache.lock().is_empty()
    }

    /// Get the tracker's capacity.
    pub fn capacity(&self) -> usize {
        self.max_entries.get()
    }

    /// Get the total number of evictions that have occurred.
    ///
    /// This is useful for monitoring and alerting - a high eviction
    /// rate may indicate the tracker is undersized for the workload.
    pub fn eviction_count(&self) -> u64 {
        self.eviction_count.load(Ordering::Relaxed)
    }

    /// Reset the eviction counter.
    pub fn reset_eviction_count(&self) {
        self.eviction_count.store(0, Ordering::Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMMON NONCE SIZES
// ═══════════════════════════════════════════════════════════════════════════════

/// 96-bit nonce (12 bytes) - used by AES-GCM, ChaCha20-Poly1305
pub type Nonce96 = Nonce<12>;

/// 192-bit nonce (24 bytes) - used by XChaCha20-Poly1305, XSalsa20
pub type Nonce192 = Nonce<24>;

/// 128-bit nonce (16 bytes) - used by AES-SIV
pub type Nonce128 = Nonce<16>;

/// 64-bit nonce (8 bytes) - used by Salsa20, ChaCha20 (original)
pub type Nonce64 = Nonce<8>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_random() {
        let n1 = Nonce96::random();
        let n2 = Nonce96::random();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = Nonce96::zero();
        for i in 1..=256 {
            nonce.increment().unwrap();
            assert_eq!(nonce.as_bytes()[11], (i & 0xFF) as u8);
        }
    }

    #[test]
    fn test_nonce_generator_counter() {
        let generator = NonceGenerator::<12>::counter(0);
        let n1 = generator.generate().unwrap();
        let n2 = generator.generate().unwrap();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
        assert_eq!(generator.count(), 2);
    }

    #[test]
    fn test_nonce_generator_limit() {
        let generator = NonceGenerator::<12>::counter(0).with_limit(2);
        assert!(generator.generate().is_ok());
        assert!(generator.generate().is_ok());
        assert!(generator.generate().is_err()); // Should fail
    }

    #[test]
    fn test_nonce_tracker() {
        let tracker = NonceTracker::<12>::new(100);
        let nonce = Nonce96::random();

        // First use should succeed
        assert!(tracker.check(&nonce).is_ok());

        // Second use should fail (replay)
        assert!(tracker.check(&nonce).is_err());

        // Different nonce should succeed
        let nonce2 = Nonce96::random();
        assert!(tracker.check(&nonce2).is_ok());
    }

    #[test]
    fn test_nonce_tracker_lru_eviction() {
        // Create a tracker with capacity of 3
        let tracker = NonceTracker::<12>::new(3);

        let n1 = Nonce96::random();
        let n2 = Nonce96::random();
        let n3 = Nonce96::random();
        let n4 = Nonce96::random();

        // Insert 3 nonces
        assert!(tracker.check(&n1).is_ok());
        assert!(tracker.check(&n2).is_ok());
        assert!(tracker.check(&n3).is_ok());

        // All should be tracked
        assert_eq!(tracker.len(), 3);
        assert_eq!(tracker.eviction_count(), 0);

        // Insert 4th nonce - should evict n1 (oldest)
        assert!(tracker.check(&n4).is_ok());
        assert_eq!(tracker.len(), 3);
        assert_eq!(tracker.eviction_count(), 1);

        // n1 should now be accepted (was evicted)
        assert!(tracker.check(&n1).is_ok());
        assert_eq!(tracker.eviction_count(), 2);

        // n2, n3 should still be rejected (still in cache)
        assert!(tracker.check(&n3).is_err());
        assert!(tracker.check(&n4).is_err());
    }

    #[test]
    fn test_nonce_tracker_capacity() {
        let tracker = NonceTracker::<12>::new(50);
        assert_eq!(tracker.capacity(), 50);
        assert!(tracker.is_empty());
    }
}
