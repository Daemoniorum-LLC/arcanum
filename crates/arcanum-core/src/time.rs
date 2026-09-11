//! Time-related utilities for cryptographic operations.
//!
//! Provides monotonic timestamps and timing attack resistance.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════════════════════════════════════
// TIMESTAMPS
// ═══════════════════════════════════════════════════════════════════════════════

/// Get current Unix timestamp in seconds.
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Get current Unix timestamp in milliseconds.
pub fn unix_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Get current Unix timestamp in nanoseconds.
pub fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Perform an operation with constant-time duration.
///
/// This helps prevent timing attacks by ensuring operations take
/// a consistent amount of time regardless of the input.
///
/// # Arguments
///
/// * `min_duration` - Minimum duration the operation should take
/// * `operation` - The operation to perform
///
/// # Returns
///
/// The result of the operation
pub fn constant_time<T, F: FnOnce() -> T>(min_duration: Duration, operation: F) -> T {
    let start = Instant::now();
    let result = operation();
    let elapsed = start.elapsed();

    if elapsed < min_duration {
        std::thread::sleep(min_duration - elapsed);
    }

    result
}

/// Perform a comparison with minimum time guarantee.
///
/// Useful for password verification where you want to prevent
/// timing attacks even when using constant-time comparison internally.
pub fn timed_compare<F: FnOnce() -> bool>(min_duration: Duration, compare: F) -> bool {
    constant_time(min_duration, compare)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIMESTAMP VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Check if a timestamp is within acceptable bounds.
///
/// Useful for preventing replay attacks with timestamped messages.
///
/// # Arguments
///
/// * `timestamp` - Unix timestamp to check (seconds)
/// * `max_drift` - Maximum allowed drift from current time
pub fn is_timestamp_valid(timestamp: u64, max_drift: Duration) -> bool {
    let now = unix_timestamp();
    let drift_secs = max_drift.as_secs();

    // Check if timestamp is in the future (with drift allowance)
    if timestamp > now + drift_secs {
        return false;
    }

    // Check if timestamp is too old
    if timestamp + drift_secs < now {
        return false;
    }

    true
}

/// Timestamp range for validity checking.
#[derive(Debug, Clone, Copy)]
pub struct TimestampRange {
    /// Earliest valid timestamp (Unix seconds)
    pub not_before: u64,
    /// Latest valid timestamp (Unix seconds)
    pub not_after: u64,
}

impl TimestampRange {
    /// Create a new timestamp range.
    pub fn new(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Create a range starting now and lasting for the given duration.
    pub fn from_now(duration: Duration) -> Self {
        let now = unix_timestamp();
        Self {
            not_before: now,
            not_after: now + duration.as_secs(),
        }
    }

    /// Create a range centered around now with the given tolerance.
    pub fn centered_on_now(tolerance: Duration) -> Self {
        let now = unix_timestamp();
        let tolerance_secs = tolerance.as_secs();
        Self {
            not_before: now.saturating_sub(tolerance_secs),
            not_after: now + tolerance_secs,
        }
    }

    /// Check if a timestamp is within this range.
    pub fn contains(&self, timestamp: u64) -> bool {
        timestamp >= self.not_before && timestamp <= self.not_after
    }

    /// Check if the range has expired.
    pub fn is_expired(&self) -> bool {
        unix_timestamp() > self.not_after
    }

    /// Check if the range is not yet valid.
    pub fn is_not_yet_valid(&self) -> bool {
        unix_timestamp() < self.not_before
    }

    /// Get remaining validity duration.
    pub fn remaining(&self) -> Option<Duration> {
        let now = unix_timestamp();
        if now > self.not_after {
            None
        } else {
            Some(Duration::from_secs(self.not_after - now))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MONOTONIC COUNTER
// ═══════════════════════════════════════════════════════════════════════════════

use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonically increasing counter based on time.
///
/// Useful for generating unique, ordered identifiers that incorporate
/// the current timestamp.
pub struct MonotonicClock {
    last_value: AtomicU64,
}

impl MonotonicClock {
    /// Create a new monotonic clock.
    pub const fn new() -> Self {
        Self {
            last_value: AtomicU64::new(0),
        }
    }

    /// Get the next monotonic value.
    ///
    /// Returns a value that is guaranteed to be greater than any
    /// previously returned value.
    pub fn next(&self) -> u64 {
        loop {
            let current = unix_timestamp_millis();
            let last = self.last_value.load(Ordering::SeqCst);

            // Ensure monotonicity
            let next = if current > last { current } else { last + 1 };

            if self
                .last_value
                .compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return next;
            }
        }
    }

    /// Get the last value without advancing.
    pub fn last(&self) -> u64 {
        self.last_value.load(Ordering::SeqCst)
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

// Global monotonic clock
static GLOBAL_CLOCK: MonotonicClock = MonotonicClock::new();

/// Get the next global monotonic value.
pub fn monotonic_next() -> u64 {
    GLOBAL_CLOCK.next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_timestamp() {
        let ts = unix_timestamp();
        assert!(ts > 1700000000); // After 2023
    }

    #[test]
    fn test_constant_time() {
        let min_duration = Duration::from_millis(50);
        let start = Instant::now();

        constant_time(min_duration, || {
            // Quick operation
            let _ = 1 + 1;
        });

        let elapsed = start.elapsed();
        assert!(elapsed >= min_duration);
    }

    #[test]
    fn test_timestamp_validity() {
        let now = unix_timestamp();
        let drift = Duration::from_secs(60);

        // Current time should be valid
        assert!(is_timestamp_valid(now, drift));

        // Time in the past (within drift) should be valid
        assert!(is_timestamp_valid(now - 30, drift));

        // Time in the future (within drift) should be valid
        assert!(is_timestamp_valid(now + 30, drift));

        // Time too far in the past should be invalid
        assert!(!is_timestamp_valid(now - 120, drift));

        // Time too far in the future should be invalid
        assert!(!is_timestamp_valid(now + 120, drift));
    }

    #[test]
    fn test_timestamp_range() {
        let range = TimestampRange::centered_on_now(Duration::from_secs(60));
        let now = unix_timestamp();

        assert!(range.contains(now));
        assert!(range.contains(now + 30));
        assert!(range.contains(now - 30));
        assert!(!range.contains(now + 120));
    }

    #[test]
    fn test_monotonic_clock() {
        let clock = MonotonicClock::new();

        let v1 = clock.next();
        let v2 = clock.next();
        let v3 = clock.next();

        assert!(v2 > v1);
        assert!(v3 > v2);
    }

    #[test]
    fn test_global_monotonic() {
        let v1 = monotonic_next();
        let v2 = monotonic_next();
        assert!(v2 > v1);
    }

    // ─── Timestamp precision tests ───────────────────────────────────────────

    #[test]
    fn test_unix_timestamp_millis_positive_and_greater_than_seconds() {
        let secs = unix_timestamp();
        let millis = unix_timestamp_millis();

        assert!(millis > 0, "Millis timestamp must be positive");
        assert!(millis >= secs * 1000,
            "Millis ({}) must be >= seconds * 1000 ({})", millis, secs * 1000);
    }

    #[test]
    fn test_unix_timestamp_nanos_positive_and_greater_than_millis() {
        let millis = unix_timestamp_millis();
        let nanos = unix_timestamp_nanos();

        assert!(nanos > 0, "Nanos timestamp must be positive");
        assert!(nanos >= (millis as u128) * 1_000_000,
            "Nanos ({}) must be >= millis * 1_000_000 ({})", nanos, (millis as u128) * 1_000_000);
    }

    // ─── timed_compare tests ─────────────────────────────────────────────────

    #[test]
    fn test_timed_compare_returns_true_result() {
        let min_dur = Duration::from_millis(50);
        let start = Instant::now();
        let result = timed_compare(min_dur, || true);
        let elapsed = start.elapsed();

        assert!(result, "timed_compare must return the inner comparison result (true)");
        assert!(elapsed >= min_dur, "timed_compare must take at least min_duration");
    }

    #[test]
    fn test_timed_compare_returns_false_result() {
        let min_dur = Duration::from_millis(50);
        let start = Instant::now();
        let result = timed_compare(min_dur, || false);
        let elapsed = start.elapsed();

        assert!(!result, "timed_compare must return the inner comparison result (false)");
        assert!(elapsed >= min_dur, "timed_compare must take at least min_duration");
    }

    // ─── TimestampRange tests ────────────────────────────────────────────────

    #[test]
    fn test_timestamp_range_new_and_contains() {
        let range = TimestampRange::new(100, 200);
        assert_eq!(range.not_before, 100);
        assert_eq!(range.not_after, 200);

        assert!(range.contains(100), "Range must contain not_before boundary");
        assert!(range.contains(150), "Range must contain middle value");
        assert!(range.contains(200), "Range must contain not_after boundary");
        assert!(!range.contains(99), "Range must not contain value before not_before");
        assert!(!range.contains(201), "Range must not contain value after not_after");
    }

    #[test]
    fn test_timestamp_range_from_now_contains_current_time() {
        let range = TimestampRange::from_now(Duration::from_secs(3600));
        let now = unix_timestamp();

        assert!(range.contains(now), "from_now range must contain current time");
        assert!(range.contains(now + 1800), "from_now range must contain time within duration");
        assert!(!range.contains(now + 7200), "from_now range must not contain time past duration");
    }

    #[test]
    fn test_timestamp_range_is_expired() {
        // A range entirely in the past
        let range = TimestampRange::new(1000, 2000);
        assert!(range.is_expired(), "Range with not_after=2000 must be expired");
    }

    #[test]
    fn test_timestamp_range_is_not_yet_valid() {
        // A range entirely in the future
        let far_future = unix_timestamp() + 100_000;
        let range = TimestampRange::new(far_future, far_future + 3600);
        assert!(range.is_not_yet_valid(), "Range with not_before in the far future must not yet be valid");
        assert!(!range.is_expired(), "Future range must not be expired");
    }

    #[test]
    fn test_timestamp_range_remaining_valid() {
        let range = TimestampRange::from_now(Duration::from_secs(3600));
        let remaining = range.remaining();
        assert!(remaining.is_some(), "Active range must have remaining time");
        let dur = remaining.unwrap();
        // Remaining should be close to 3600 seconds (allow some slack for test execution)
        assert!(dur.as_secs() <= 3600, "Remaining must not exceed the original duration");
        assert!(dur.as_secs() >= 3598, "Remaining must be close to the original duration");
    }

    #[test]
    fn test_timestamp_range_remaining_expired() {
        let range = TimestampRange::new(1000, 2000);
        assert!(range.remaining().is_none(), "Expired range must return None for remaining");
    }

    // ─── MonotonicClock: Default, last() ─────────────────────────────────────

    #[test]
    fn test_monotonic_clock_default_trait() {
        let clock = MonotonicClock::default();
        // A freshly created clock should have last_value of 0
        assert_eq!(clock.last(), 0, "Default MonotonicClock must start at 0");
    }

    #[test]
    fn test_monotonic_clock_last_returns_previous_value() {
        let clock = MonotonicClock::new();
        assert_eq!(clock.last(), 0, "New clock must start with last() == 0");

        let v1 = clock.next();
        assert_eq!(clock.last(), v1, "last() must return the value from the most recent next() call");

        let v2 = clock.next();
        assert_eq!(clock.last(), v2, "last() must update after each next() call");
        assert!(v2 > v1, "Monotonic clock values must strictly increase");
    }
}
