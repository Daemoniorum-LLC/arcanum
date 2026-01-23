//! # Arcanum Verification Tools
//!
//! Tools for verifying security properties of cryptographic implementations.
//!
//! ## Timing Analysis
//!
//! Detect timing side-channels using statistical methods:
//!
//! - **dudect**: Statistical timing leak detection
//! - **CI integration**: Automated timing regression tests
//! - **Reports**: Human-readable timing analysis reports
//!
//! ## Model Checking
//!
//! Formal verification of memory safety and correctness:
//!
//! - **Kani**: Bounded model checking for Rust
//! - **Memory safety**: Prove absence of buffer overflows
//! - **Functional correctness**: Verify invariants
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_verify::prelude::*;
//!
//! // Test AES-GCM for timing leaks
//! let result = TimingTest::new("aes_gcm_encrypt")
//!     .iterations(100_000)
//!     .run(|class| {
//!         let key = match class {
//!             Class::Left => [0x00u8; 32],
//!             Class::Right => [0xFFu8; 32],
//!         };
//!         Aes256Gcm::encrypt(&key, &nonce, &plaintext, None)
//!     });
//!
//! assert!(result.is_constant_time(), "Timing leak detected: {}", result);
//! ```
//!
//! ## Security Properties Verified
//!
//! - **Constant-time execution**: No timing side-channels
//! - **Memory zeroization**: Secrets cleared on drop
//! - **No buffer overflows**: Bounds checking verified
//! - **No use-after-free**: Memory safety guaranteed

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "timing")]
pub mod timing;

pub mod reports;

mod errors;

pub use errors::VerifyError;

#[cfg(feature = "timing")]
pub use timing::{Class, TimingResult, TimingTest};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::errors::VerifyError;

    #[cfg(feature = "timing")]
    pub use crate::timing::{Class, TimingResult, TimingTest};
}

/// Statistical utilities for timing analysis.
pub mod stats {
    #[cfg(feature = "timing")]
    use crate::timing::OnlineStats;

    /// Compute Welch's t-statistic for two samples.
    ///
    /// Used to determine if two timing distributions differ significantly.
    /// A |t| > 4.5 indicates a probable timing leak.
    pub fn welch_t_test(sample1: &[f64], sample2: &[f64]) -> f64 {
        let n1 = sample1.len() as f64;
        let n2 = sample2.len() as f64;

        if n1 < 2.0 || n2 < 2.0 {
            return 0.0;
        }

        let mean1: f64 = sample1.iter().sum::<f64>() / n1;
        let mean2: f64 = sample2.iter().sum::<f64>() / n2;

        let var1: f64 = sample1.iter().map(|x| (x - mean1).powi(2)).sum::<f64>() / (n1 - 1.0);
        let var2: f64 = sample2.iter().map(|x| (x - mean2).powi(2)).sum::<f64>() / (n2 - 1.0);

        let se = (var1 / n1 + var2 / n2).sqrt();

        if se == 0.0 {
            0.0 // Identical distributions
        } else {
            (mean1 - mean2) / se
        }
    }

    /// Compute Welch's t-statistic from online statistics.
    ///
    /// Memory-efficient version that uses pre-computed statistics.
    #[cfg(feature = "timing")]
    pub fn welch_t_online(stats1: &OnlineStats, stats2: &OnlineStats) -> f64 {
        let n1 = stats1.count() as f64;
        let n2 = stats2.count() as f64;

        if n1 < 2.0 || n2 < 2.0 {
            return 0.0;
        }

        let mean1 = stats1.mean();
        let mean2 = stats2.mean();
        let var1 = stats1.variance();
        let var2 = stats2.variance();

        let se = (var1 / n1 + var2 / n2).sqrt();

        if se == 0.0 { 0.0 } else { (mean1 - mean2) / se }
    }

    /// Threshold for timing leak detection.
    ///
    /// A t-value above this threshold indicates a probable timing leak.
    /// 4.5 corresponds to roughly 3 in 100,000 false positive rate.
    pub const TIMING_LEAK_THRESHOLD: f64 = 4.5;

    /// More stringent threshold for high-security applications.
    pub const TIMING_LEAK_THRESHOLD_STRICT: f64 = 3.0;
}
