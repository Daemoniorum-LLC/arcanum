//! Timing analysis tools for detecting side-channel leaks.
//!
//! Uses statistical methods (inspired by dudect) to detect timing
//! variations that could leak secret information.
//!
//! ## Methodology
//!
//! The timing test works by:
//! 1. Running the same operation on two input classes (e.g., all-zero vs random)
//! 2. Collecting timing measurements for each class
//! 3. Using Welch's t-test to detect statistically significant differences
//!
//! A large |t-value| indicates the operation takes different time for
//! different inputs, which could leak secret information.
//!
//! ## Usage
//!
//! ```ignore
//! use arcanum_verify::prelude::*;
//!
//! let result = TimingTest::new("my_crypto_operation")
//!     .iterations(100_000)
//!     .with_percentile_cropping(5.0) // Remove top/bottom 5%
//!     .run(|class| {
//!         let input = match class {
//!             Class::Left => [0u8; 32],
//!             Class::Right => random_bytes(),
//!         };
//!         crypto_operation(&input)
//!     });
//!
//! assert!(result.is_constant_time());
//! ```

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use core::cmp::Ordering;

use crate::errors::{VerifyError, VerifyResult};
use crate::stats;

/// Classification for timing test inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// First class of inputs (e.g., all-zero keys)
    Left,
    /// Second class of inputs (e.g., all-one keys)
    Right,
}

/// Configuration for percentile-based outlier removal.
#[derive(Debug, Clone, Copy)]
pub struct PercentileCrop {
    /// Percentage to remove from the low end (0-50)
    pub low: f64,
    /// Percentage to remove from the high end (0-50)
    pub high: f64,
}

impl Default for PercentileCrop {
    fn default() -> Self {
        Self {
            low: 0.0,
            high: 0.0,
        }
    }
}

impl PercentileCrop {
    /// Create symmetric cropping (same percentage from both ends).
    pub fn symmetric(percent: f64) -> Self {
        Self {
            low: percent,
            high: percent,
        }
    }

    /// Create asymmetric cropping.
    pub fn asymmetric(low: f64, high: f64) -> Self {
        Self { low, high }
    }
}

/// Result of a timing analysis test.
#[derive(Debug, Clone)]
pub struct TimingResult {
    /// Name of the test
    pub name: String,
    /// Number of raw samples collected
    pub samples: usize,
    /// Number of samples after cropping
    pub samples_after_crop: usize,
    /// Welch's t-statistic
    pub t_value: f64,
    /// Whether the test passed (no leak detected)
    pub passed: bool,
    /// Threshold used for detection
    pub threshold: f64,
    /// Mean timing for left class (nanoseconds)
    pub mean_left: f64,
    /// Mean timing for right class (nanoseconds)
    pub mean_right: f64,
    /// Standard deviation for left class
    pub std_left: f64,
    /// Standard deviation for right class
    pub std_right: f64,
}

impl TimingResult {
    /// Check if the operation is constant-time.
    pub fn is_constant_time(&self) -> bool {
        self.passed
    }

    /// Get the absolute t-value.
    pub fn abs_t_value(&self) -> f64 {
        self.t_value.abs()
    }

    /// Get timing difference as percentage of mean.
    pub fn timing_difference_percent(&self) -> f64 {
        let mean = (self.mean_left + self.mean_right) / 2.0;
        if mean == 0.0 {
            0.0
        } else {
            ((self.mean_left - self.mean_right).abs() / mean) * 100.0
        }
    }

    /// Get a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "{}: t={:.2} (threshold={:.1}) - {}",
            self.name,
            self.t_value,
            self.threshold,
            if self.passed {
                "PASS"
            } else {
                "FAIL - TIMING LEAK DETECTED"
            }
        )
    }

    /// Get detailed report.
    pub fn detailed_report(&self) -> String {
        format!(
            "{}\n\
             Samples: {} (after crop: {})\n\
             Left class:  mean={:.2}ns, std={:.2}ns\n\
             Right class: mean={:.2}ns, std={:.2}ns\n\
             Difference: {:.4}%\n\
             t-statistic: {:.4} (threshold: ±{:.1})\n\
             Result: {}",
            self.name,
            self.samples,
            self.samples_after_crop,
            self.mean_left,
            self.std_left,
            self.mean_right,
            self.std_right,
            self.timing_difference_percent(),
            self.t_value,
            self.threshold,
            if self.passed {
                "PASS (constant-time)"
            } else {
                "FAIL (timing leak detected)"
            }
        )
    }
}

impl core::fmt::Display for TimingResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Online statistics accumulator using Welford's algorithm.
///
/// Computes mean and variance in a single pass with numerical stability.
#[derive(Debug, Clone, Default)]
pub struct OnlineStats {
    count: usize,
    mean: f64,
    m2: f64, // Sum of squares of differences from mean
}

impl OnlineStats {
    /// Create a new accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new sample.
    pub fn update(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    /// Get the number of samples.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get the mean.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Get the sample variance.
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    /// Get the standard deviation.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}

/// Builder for timing tests.
pub struct TimingTest {
    name: String,
    iterations: usize,
    warmup: usize,
    threshold: f64,
    percentile_crop: PercentileCrop,
}

impl TimingTest {
    /// Create a new timing test.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            iterations: 10_000,
            warmup: 100,
            threshold: stats::TIMING_LEAK_THRESHOLD,
            percentile_crop: PercentileCrop::default(),
        }
    }

    /// Set the number of iterations.
    pub fn iterations(mut self, n: usize) -> Self {
        self.iterations = n;
        self
    }

    /// Set the number of warmup iterations.
    pub fn warmup(mut self, n: usize) -> Self {
        self.warmup = n;
        self
    }

    /// Set the t-value threshold.
    pub fn threshold(mut self, t: f64) -> Self {
        self.threshold = t;
        self
    }

    /// Enable symmetric percentile cropping.
    ///
    /// Removes the specified percentage of samples from both ends
    /// of the timing distribution to reduce noise from outliers.
    pub fn with_percentile_cropping(mut self, percent: f64) -> Self {
        self.percentile_crop = PercentileCrop::symmetric(percent);
        self
    }

    /// Enable asymmetric percentile cropping.
    pub fn with_asymmetric_cropping(mut self, low: f64, high: f64) -> Self {
        self.percentile_crop = PercentileCrop::asymmetric(low, high);
        self
    }

    /// Crop timing samples based on percentiles.
    fn crop_samples(&self, samples: &mut Vec<f64>) {
        if self.percentile_crop.low == 0.0 && self.percentile_crop.high == 0.0 {
            return;
        }

        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

        let n = samples.len();
        let low_idx = ((n as f64 * self.percentile_crop.low / 100.0) as usize).min(n / 2);
        let high_idx = n - ((n as f64 * self.percentile_crop.high / 100.0) as usize).min(n / 2);

        *samples = samples[low_idx..high_idx].to_vec();
    }

    /// Run the timing test.
    ///
    /// The function `f` should take a `Class` and return some result.
    /// Timing measurements are taken for both classes and compared.
    #[cfg(feature = "std")]
    pub fn run<F, R>(self, mut f: F) -> TimingResult
    where
        F: FnMut(Class) -> R,
    {
        use std::time::Instant;

        // Warmup phase
        for _ in 0..self.warmup {
            let _ = f(Class::Left);
            let _ = f(Class::Right);
        }

        let mut left_times = Vec::with_capacity(self.iterations);
        let mut right_times = Vec::with_capacity(self.iterations);

        // Interleave measurements to reduce systematic bias
        for _ in 0..self.iterations {
            // Measure left class
            let start = Instant::now();
            let _result = core::hint::black_box(f(Class::Left));
            let elapsed = start.elapsed().as_nanos() as f64;
            left_times.push(elapsed);

            // Measure right class
            let start = Instant::now();
            let _result = core::hint::black_box(f(Class::Right));
            let elapsed = start.elapsed().as_nanos() as f64;
            right_times.push(elapsed);
        }

        let raw_samples = self.iterations * 2;

        // Apply percentile cropping
        self.crop_samples(&mut left_times);
        self.crop_samples(&mut right_times);

        let samples_after_crop = left_times.len() + right_times.len();

        // Compute statistics
        let mut left_stats = OnlineStats::new();
        for &t in &left_times {
            left_stats.update(t);
        }

        let mut right_stats = OnlineStats::new();
        for &t in &right_times {
            right_stats.update(t);
        }

        // Compute t-statistic
        let t_value = stats::welch_t_test(&left_times, &right_times);
        let passed = t_value.abs() < self.threshold;

        TimingResult {
            name: self.name,
            samples: raw_samples,
            samples_after_crop,
            t_value,
            passed,
            threshold: self.threshold,
            mean_left: left_stats.mean(),
            mean_right: right_stats.mean(),
            std_left: left_stats.std_dev(),
            std_right: right_stats.std_dev(),
        }
    }

    /// Run with online statistics (memory-efficient for large iterations).
    #[cfg(feature = "std")]
    pub fn run_online<F, R>(self, mut f: F) -> TimingResult
    where
        F: FnMut(Class) -> R,
    {
        use std::time::Instant;

        // Warmup
        for _ in 0..self.warmup {
            let _ = f(Class::Left);
            let _ = f(Class::Right);
        }

        let mut left_stats = OnlineStats::new();
        let mut right_stats = OnlineStats::new();

        // Collect measurements with online statistics
        for _ in 0..self.iterations {
            // Measure left class
            let start = Instant::now();
            let _result = core::hint::black_box(f(Class::Left));
            let elapsed = start.elapsed().as_nanos() as f64;
            left_stats.update(elapsed);

            // Measure right class
            let start = Instant::now();
            let _result = core::hint::black_box(f(Class::Right));
            let elapsed = start.elapsed().as_nanos() as f64;
            right_stats.update(elapsed);
        }

        // Compute t-statistic using online stats
        let t_value = stats::welch_t_online(&left_stats, &right_stats);
        let passed = t_value.abs() < self.threshold;

        TimingResult {
            name: self.name,
            samples: self.iterations * 2,
            samples_after_crop: self.iterations * 2, // No cropping in online mode
            t_value,
            passed,
            threshold: self.threshold,
            mean_left: left_stats.mean(),
            mean_right: right_stats.mean(),
            std_left: left_stats.std_dev(),
            std_right: right_stats.std_dev(),
        }
    }
}

/// Run a timing test and return an error if a leak is detected.
#[cfg(feature = "std")]
pub fn assert_constant_time<F, R>(name: &str, iterations: usize, f: F) -> VerifyResult<()>
where
    F: FnMut(Class) -> R,
{
    let result = TimingTest::new(name).iterations(iterations).run(f);

    if result.passed {
        Ok(())
    } else {
        Err(VerifyError::TimingLeakDetected {
            t_value: result.t_value,
            threshold: result.threshold,
        })
    }
}

/// Common test patterns for cryptographic operations.
#[cfg(feature = "std")]
pub mod patterns {
    use super::*;

    /// Test key comparison for constant-time behavior.
    ///
    /// Compares timing of operations on all-zero vs all-one keys.
    pub fn test_key_comparison<F, R>(name: &str, iterations: usize, mut op: F) -> TimingResult
    where
        F: FnMut(&[u8; 32]) -> R,
    {
        let zero_key = [0u8; 32];
        let one_key = [0xFFu8; 32];

        TimingTest::new(name)
            .iterations(iterations)
            .run(move |class| {
                let key = match class {
                    Class::Left => &zero_key,
                    Class::Right => &one_key,
                };
                op(key)
            })
    }

    /// Test early exit behavior (e.g., MAC verification).
    ///
    /// Compares timing when the first byte differs vs last byte differs.
    pub fn test_early_exit<F>(name: &str, iterations: usize, mut compare: F) -> TimingResult
    where
        F: FnMut(&[u8; 32], &[u8; 32]) -> bool,
    {
        let correct = [0u8; 32];
        let mut wrong_first = [0u8; 32];
        wrong_first[0] = 0xFF;
        let mut wrong_last = [0u8; 32];
        wrong_last[31] = 0xFF;

        TimingTest::new(name)
            .iterations(iterations)
            .run(move |class| {
                let wrong = match class {
                    Class::Left => &wrong_first,
                    Class::Right => &wrong_last,
                };
                compare(&correct, wrong)
            })
    }

    /// Test padding oracle behavior.
    ///
    /// Compares timing for valid vs invalid padding.
    pub fn test_padding_oracle<F, R, E>(
        name: &str,
        iterations: usize,
        mut decrypt: F,
    ) -> TimingResult
    where
        F: FnMut(&[u8]) -> Result<R, E>,
    {
        // Valid PKCS#7 padding (last byte = 1)
        let mut valid_padding = vec![0u8; 48];
        valid_padding[47] = 0x01;

        // Invalid padding (last byte = 17, impossible)
        let mut invalid_padding = vec![0u8; 48];
        invalid_padding[47] = 0x11;

        TimingTest::new(name)
            .iterations(iterations)
            .run(move |class| {
                let data = match class {
                    Class::Left => &valid_padding,
                    Class::Right => &invalid_padding,
                };
                let _ = decrypt(data);
            })
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_operation() {
        // A truly constant-time operation should pass
        let result = TimingTest::new("constant_add")
            .iterations(1000)
            .run(|class| {
                let a = match class {
                    Class::Left => 0u64,
                    Class::Right => u64::MAX,
                };
                // Simple addition is constant-time
                core::hint::black_box(a.wrapping_add(42))
            });

        // Should pass (t-value close to 0)
        assert!(
            result.t_value.abs() < 10.0,
            "t-value too high: {}",
            result.t_value
        );
    }

    #[test]
    fn test_timing_result_display() {
        let result = TimingResult {
            name: "test".into(),
            samples: 1000,
            samples_after_crop: 900,
            t_value: 1.5,
            passed: true,
            threshold: 4.5,
            mean_left: 100.0,
            mean_right: 100.5,
            std_left: 10.0,
            std_right: 10.0,
        };

        assert!(result.to_string().contains("PASS"));
        assert!(result.detailed_report().contains("100.00ns"));
    }

    #[test]
    fn test_online_stats() {
        let mut stats = OnlineStats::new();
        stats.update(1.0);
        stats.update(2.0);
        stats.update(3.0);

        assert_eq!(stats.count(), 3);
        assert!((stats.mean() - 2.0).abs() < 0.001);
        assert!((stats.variance() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_percentile_cropping() {
        let test = TimingTest::new("test")
            .iterations(100)
            .with_percentile_cropping(10.0);

        let result = test.run(|_| 42);
        // 10% from each end = 20% removed
        assert!(result.samples_after_crop < result.samples);
    }

    #[test]
    fn test_online_mode() {
        let result =
            TimingTest::new("online_test")
                .iterations(1000)
                .run_online(|class| match class {
                    Class::Left => 1u64,
                    Class::Right => 2u64,
                });

        assert!(result.samples_after_crop == result.samples);
    }

    #[test]
    fn test_key_comparison_pattern() {
        let result = patterns::test_key_comparison("test_key", 500, |key| {
            // Simple sum - should be constant time
            key.iter().fold(0u64, |acc, &b| acc.wrapping_add(b as u64))
        });

        // Key sum is constant-time
        assert!(
            result.t_value.abs() < 20.0,
            "Unexpected timing variation: {}",
            result.t_value
        );
    }
}
