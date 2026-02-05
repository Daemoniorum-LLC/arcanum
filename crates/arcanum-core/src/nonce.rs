//! Nonce generation and management.
//!
//! Proper nonce handling is critical for cryptographic security.
//! This module provides utilities for generating and tracking nonces
//! to prevent catastrophic nonce reuse.

use crate::error::{Error, Result};
#[cfg(feature = "std")]
use crate::random::OsRng;
#[cfg(feature = "std")]
use lru::LruCache;
#[cfg(feature = "std")]
use parking_lot::Mutex;
#[cfg(feature = "std")]
use rand::RngCore;
#[cfg(feature = "std")]
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicU64, Ordering};
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
    #[must_use = "parsing can fail; check the Result"]
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
    #[cfg(feature = "std")]
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
    #[must_use = "this operation can fail; check the Result"]
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

#[cfg(feature = "encoding")]
impl<const N: usize> core::fmt::Debug for Nonce<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Nonce<{}>({})", N, hex::encode(self.bytes))
    }
}

#[cfg(not(feature = "encoding"))]
impl<const N: usize> core::fmt::Debug for Nonce<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Nonce<{}>([{} bytes])", N, N)
    }
}

#[cfg(feature = "encoding")]
impl<const N: usize> core::fmt::Display for Nonce<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    random_prefix: [u8; 4],
    generated_count: AtomicU64,
    max_nonces: Option<u64>,
}

impl<const N: usize> NonceGenerator<N> {
    /// Create a new random nonce generator.
    #[cfg(feature = "std")]
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
    #[cfg(feature = "std")]
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
    #[must_use = "key generation can fail; check the Result"]
    pub fn generate(&self) -> Result<Nonce<N>> {
        // Check limit and always increment count
        let count = self.generated_count.fetch_add(1, Ordering::SeqCst);
        if let Some(max) = self.max_nonces
            && count >= max
        {
            // Revert the increment since we're not generating
            self.generated_count.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::NonceExhausted);
        }

        match self.strategy {
            #[cfg(feature = "std")]
            NonceStrategy::Random => Ok(Nonce::random()),

            #[cfg(not(feature = "std"))]
            NonceStrategy::Random => Err(Error::NotImplemented(
                "random nonces require std feature".into(),
            )),

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

            #[cfg(feature = "std")]
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

            #[cfg(not(feature = "std"))]
            NonceStrategy::Hybrid => Err(Error::NotImplemented(
                "hybrid nonces require std feature".into(),
            )),
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

#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
pub struct NonceTracker<const N: usize> {
    cache: Mutex<LruCache<[u8; N], ()>>,
    max_entries: NonZeroUsize,
    eviction_count: AtomicU64,
}

#[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
    #[test]
    fn test_nonce_tracker_capacity() {
        let tracker = NonceTracker::<12>::new(50);
        assert_eq!(tracker.capacity(), 50);
        assert!(tracker.is_empty());
    }

    // ─── NonceTracker: check_and_touch, clear, reset_eviction_count ──────────

    #[cfg(feature = "std")]
    #[test]
    fn test_nonce_tracker_check_and_touch_detects_reuse() {
        let tracker = NonceTracker::<12>::new(100);
        let nonce = Nonce96::random();

        // First use via check_and_touch should succeed
        assert!(tracker.check_and_touch(&nonce).is_ok());
        assert_eq!(tracker.len(), 1);

        // Second use of same nonce should fail (reuse detected)
        let result = tracker.check_and_touch(&nonce);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::NonceReuse => {} // expected
            other => panic!("Expected NonceReuse, got: {:?}", other),
        }

        // A different nonce should still succeed
        let nonce2 = Nonce96::random();
        assert!(tracker.check_and_touch(&nonce2).is_ok());
        assert_eq!(tracker.len(), 2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_nonce_tracker_clear() {
        let tracker = NonceTracker::<12>::new(100);
        let n1 = Nonce96::random();
        let n2 = Nonce96::random();

        tracker.check(&n1).unwrap();
        tracker.check(&n2).unwrap();
        assert_eq!(tracker.len(), 2);

        tracker.clear();
        assert_eq!(tracker.len(), 0);
        assert!(tracker.is_empty());

        // After clear, previously tracked nonces should be accepted again
        assert!(tracker.check(&n1).is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_nonce_tracker_reset_eviction_count() {
        let tracker = NonceTracker::<12>::new(2);

        let n1 = Nonce96::random();
        let n2 = Nonce96::random();
        let n3 = Nonce96::random();

        tracker.check(&n1).unwrap();
        tracker.check(&n2).unwrap();
        assert_eq!(tracker.eviction_count(), 0);

        // This triggers an eviction
        tracker.check(&n3).unwrap();
        assert_eq!(tracker.eviction_count(), 1);

        tracker.reset_eviction_count();
        assert_eq!(tracker.eviction_count(), 0);
    }

    // ─── NonceGenerator: hybrid, current_counter, reset ──────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn test_nonce_generator_hybrid() {
        let nonce_gen = NonceGenerator::<12>::hybrid();

        let n1 = nonce_gen.generate().unwrap();
        let n2 = nonce_gen.generate().unwrap();

        // Hybrid nonces should differ (different counter values)
        assert_ne!(n1.as_bytes(), n2.as_bytes());
        assert_eq!(nonce_gen.count(), 2);

        // The first 4 bytes (random prefix) should be the same for both
        assert_eq!(&n1.as_bytes()[..4], &n2.as_bytes()[..4],
            "Hybrid nonces from the same generator should share the random prefix");
    }

    #[test]
    fn test_nonce_generator_current_counter() {
        let nonce_gen = NonceGenerator::<12>::counter(100);
        assert_eq!(nonce_gen.current_counter(), 100);

        nonce_gen.generate().unwrap();
        assert_eq!(nonce_gen.current_counter(), 101);

        nonce_gen.generate().unwrap();
        assert_eq!(nonce_gen.current_counter(), 102);
    }

    #[test]
    fn test_nonce_generator_reset_dangerous() {
        let nonce_gen = NonceGenerator::<12>::counter(0);

        nonce_gen.generate().unwrap();
        nonce_gen.generate().unwrap();
        assert_eq!(nonce_gen.count(), 2);
        assert_eq!(nonce_gen.current_counter(), 2);

        nonce_gen.reset_dangerous_nonce_reuse_possible();
        assert_eq!(nonce_gen.count(), 0);
        assert_eq!(nonce_gen.current_counter(), 0);
    }

    // ─── Nonce: from_counter, from_slice error, increment overflow ───────────

    #[test]
    fn test_nonce_from_counter_bytes_at_end() {
        let nonce = Nonce::<12>::from_counter(1);
        let bytes = nonce.as_bytes();

        // First 4 bytes should be zero (padding)
        assert_eq!(&bytes[..4], &[0, 0, 0, 0]);
        // Last 8 bytes should contain the counter in big-endian
        assert_eq!(&bytes[4..], &1u64.to_be_bytes());

        // Verify a larger counter value
        let nonce2 = Nonce::<12>::from_counter(0x0102030405060708);
        let bytes2 = nonce2.as_bytes();
        assert_eq!(&bytes2[..4], &[0, 0, 0, 0]);
        assert_eq!(&bytes2[4..], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_nonce_from_slice_wrong_length() {
        let short = [0u8; 8];
        let result = Nonce::<12>::from_slice(&short);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidNonceLength { expected, actual } => {
                assert_eq!(expected, 12);
                assert_eq!(actual, 8);
            }
            other => panic!("Expected InvalidNonceLength, got: {:?}", other),
        }

        let long = [0u8; 16];
        let result2 = Nonce::<12>::from_slice(&long);
        assert!(result2.is_err());
    }

    #[test]
    fn test_nonce_increment_overflow() {
        let mut nonce = Nonce::<12>::new([0xFF; 12]);
        let result = nonce.increment();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::NonceExhausted => {} // expected
            other => panic!("Expected NonceExhausted, got: {:?}", other),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // NONCETRACKER CONCURRENT ACCESS TESTS (Phase 5.6)
    // ═══════════════════════════════════════════════════════════════════════════════

    #[cfg(feature = "std")]
    mod concurrent_nonce_tracker {
        use super::*;
        use std::sync::{Arc, Barrier};
        use std::thread;

        /// Test that concurrent check_and_touch on the SAME nonce results in exactly 1 success.
        /// This verifies the mutex properly serializes access and detects races.
        #[test]
        fn test_concurrent_same_nonce_exactly_one_success() {
            const NUM_THREADS: usize = 10;

            let tracker = Arc::new(NonceTracker::<12>::new(1000));
            let barrier = Arc::new(Barrier::new(NUM_THREADS));
            let nonce = Nonce96::random();

            let handles: Vec<_> = (0..NUM_THREADS)
                .map(|_| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);
                    let nonce_clone = Nonce::new(*nonce.as_bytes());

                    thread::spawn(move || {
                        // Wait for all threads to be ready
                        barrier.wait();
                        // Race to touch the nonce
                        tracker.check_and_touch(&nonce_clone)
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            let successes = results.iter().filter(|r| r.is_ok()).count();
            let failures = results.iter().filter(|r| r.is_err()).count();

            assert_eq!(successes, 1, "Exactly one thread should succeed in touching the nonce");
            assert_eq!(failures, NUM_THREADS - 1, "All other threads should detect reuse");
        }

        /// Test that concurrent check_and_touch on DISTINCT nonces all succeed.
        /// This verifies the tracker doesn't have false positives under contention.
        #[test]
        fn test_concurrent_distinct_nonces_all_succeed() {
            const NUM_THREADS: usize = 50;

            let tracker = Arc::new(NonceTracker::<12>::new(1000));
            let barrier = Arc::new(Barrier::new(NUM_THREADS));

            // Pre-generate distinct nonces for each thread
            let nonces: Vec<Nonce96> = (0..NUM_THREADS)
                .map(|_| Nonce96::random())
                .collect();

            let handles: Vec<_> = nonces
                .into_iter()
                .map(|nonce| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);

                    thread::spawn(move || {
                        barrier.wait();
                        tracker.check_and_touch(&nonce)
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            let successes = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(successes, NUM_THREADS, "All threads with distinct nonces should succeed");
            assert_eq!(tracker.len(), NUM_THREADS, "Tracker should contain all nonces");
        }

        /// Test that concurrent check (not touch) on the SAME nonce also results in exactly 1 success.
        #[test]
        fn test_concurrent_check_same_nonce_exactly_one_success() {
            const NUM_THREADS: usize = 10;

            let tracker = Arc::new(NonceTracker::<12>::new(1000));
            let barrier = Arc::new(Barrier::new(NUM_THREADS));
            let nonce = Nonce96::random();

            let handles: Vec<_> = (0..NUM_THREADS)
                .map(|_| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);
                    let nonce_clone = Nonce::new(*nonce.as_bytes());

                    thread::spawn(move || {
                        barrier.wait();
                        tracker.check(&nonce_clone)
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            let successes = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(successes, 1, "Exactly one thread should succeed");
        }

        /// Stress test: high contention with mixed same/different nonces.
        /// Verifies no panics, deadlocks, or data corruption.
        #[test]
        fn test_concurrent_stress_no_panics_or_deadlocks() {
            const NUM_THREADS: usize = 20;
            const OPS_PER_THREAD: usize = 100;

            let tracker = Arc::new(NonceTracker::<12>::new(500));
            let barrier = Arc::new(Barrier::new(NUM_THREADS));

            // Create a shared pool of nonces that threads will contend over
            let shared_nonces: Arc<Vec<Nonce96>> = Arc::new(
                (0..10).map(|_| Nonce96::random()).collect()
            );

            let handles: Vec<_> = (0..NUM_THREADS)
                .map(|thread_id| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);
                    let nonces = Arc::clone(&shared_nonces);

                    thread::spawn(move || {
                        barrier.wait();

                        let mut successes = 0usize;
                        let mut failures = 0usize;

                        for i in 0..OPS_PER_THREAD {
                            // Mix between shared nonces (contention) and unique nonces
                            let result = if i % 3 == 0 {
                                // Use a shared nonce (high contention)
                                let idx = (thread_id + i) % nonces.len();
                                let nonce = Nonce::new(*nonces[idx].as_bytes());
                                tracker.check_and_touch(&nonce)
                            } else {
                                // Use a unique nonce (no contention)
                                let unique_nonce = Nonce96::random();
                                tracker.check_and_touch(&unique_nonce)
                            };

                            match result {
                                Ok(()) => successes += 1,
                                Err(Error::NonceReuse) => failures += 1,
                                Err(e) => panic!("Unexpected error: {:?}", e),
                            }
                        }

                        (successes, failures)
                    })
                })
                .collect();

            // All threads should complete without panic or deadlock
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            let total_successes: usize = results.iter().map(|(s, _)| s).sum();
            let total_failures: usize = results.iter().map(|(_, f)| f).sum();
            let total_ops = NUM_THREADS * OPS_PER_THREAD;

            assert_eq!(total_successes + total_failures, total_ops,
                "All operations should have a definitive result");
            assert!(total_successes > 0, "Some operations should succeed");

            // The tracker should be in a consistent state
            assert!(tracker.len() <= tracker.capacity(),
                "Tracker should not exceed capacity");
        }

        /// Test concurrent operations with LRU eviction occurring.
        /// Verifies eviction counter is properly maintained under concurrent access.
        #[test]
        fn test_concurrent_with_eviction() {
            const NUM_THREADS: usize = 10;
            const NONCES_PER_THREAD: usize = 20;
            const CAPACITY: usize = 50;

            let tracker = Arc::new(NonceTracker::<12>::new(CAPACITY));
            let barrier = Arc::new(Barrier::new(NUM_THREADS));

            let handles: Vec<_> = (0..NUM_THREADS)
                .map(|_| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);

                    thread::spawn(move || {
                        barrier.wait();

                        // Each thread inserts unique nonces
                        for _ in 0..NONCES_PER_THREAD {
                            let nonce = Nonce96::random();
                            let _ = tracker.check_and_touch(&nonce);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }

            // Total nonces inserted: NUM_THREADS * NONCES_PER_THREAD = 200
            // Capacity is 50, so we should have evicted 150
            let total_inserted = NUM_THREADS * NONCES_PER_THREAD;
            let expected_evictions = total_inserted.saturating_sub(CAPACITY);

            assert_eq!(tracker.len(), CAPACITY, "Tracker should be at capacity");
            assert_eq!(tracker.eviction_count() as usize, expected_evictions,
                "Eviction count should match expected evictions");
        }

        /// Test mixed check and check_and_touch operations concurrently.
        #[test]
        fn test_concurrent_mixed_check_operations() {
            const NUM_THREADS: usize = 10;

            let tracker = Arc::new(NonceTracker::<12>::new(1000));
            let barrier = Arc::new(Barrier::new(NUM_THREADS));
            let nonce = Nonce96::random();

            let handles: Vec<_> = (0..NUM_THREADS)
                .map(|i| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);
                    let nonce_clone = Nonce::new(*nonce.as_bytes());

                    thread::spawn(move || {
                        barrier.wait();
                        // Alternate between check and check_and_touch
                        if i % 2 == 0 {
                            tracker.check(&nonce_clone)
                        } else {
                            tracker.check_and_touch(&nonce_clone)
                        }
                    })
                })
                .collect();

            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            let successes = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(successes, 1, "Exactly one operation should succeed regardless of type");
        }

        /// Test that clear operation doesn't cause issues with concurrent access.
        #[test]
        fn test_concurrent_clear_safety() {
            const NUM_THREADS: usize = 5;
            const OPS_PER_THREAD: usize = 50;

            let tracker = Arc::new(NonceTracker::<12>::new(100));
            let barrier = Arc::new(Barrier::new(NUM_THREADS + 1));

            // Spawn threads that continuously add nonces
            let handles: Vec<_> = (0..NUM_THREADS)
                .map(|_| {
                    let tracker = Arc::clone(&tracker);
                    let barrier = Arc::clone(&barrier);

                    thread::spawn(move || {
                        barrier.wait();

                        for _ in 0..OPS_PER_THREAD {
                            let nonce = Nonce96::random();
                            let _ = tracker.check_and_touch(&nonce);
                        }
                    })
                })
                .collect();

            // Clear thread - periodically clears the tracker
            let tracker_clear = Arc::clone(&tracker);
            let barrier_clear = Arc::clone(&barrier);
            let clear_handle = thread::spawn(move || {
                barrier_clear.wait();

                for _ in 0..5 {
                    thread::yield_now(); // Let other threads do some work
                    tracker_clear.clear();
                }
            });

            // All threads should complete without panic
            for h in handles {
                h.join().expect("Worker thread should not panic");
            }
            clear_handle.join().expect("Clear thread should not panic");

            // Tracker should be in a valid state
            assert!(tracker.len() <= tracker.capacity());
        }
    }
}
