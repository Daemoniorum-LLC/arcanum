//! Phase 3 — P1: Random module degraded API (TDD-CORE-NOSTD-001 §3.3)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_random_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    // Under no_std, the random module should still be importable
    // but OsRng and ThreadLocalRng should not be available.

    #[test]
    fn spec_random_module_exists() {
        // The module itself should be visible even under no_std,
        // with CryptoRng trait available.
        use arcanum_core::random::CryptoRng;
        // CryptoRng is a trait - verify it's importable
        fn _assert_crypto_rng<T: CryptoRng>() {}
    }

    #[cfg(feature = "std")]
    #[test]
    fn spec_os_rng_available_with_std() {
        use arcanum_core::random::OsRng;
        use rand::RngCore;
        let mut rng = OsRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        // At least one byte should be non-zero (probabilistic)
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[cfg(feature = "std")]
    #[test]
    fn spec_random_bytes_with_std() {
        use arcanum_core::random::random_bytes;
        let b1 = random_bytes(32);
        let b2 = random_bytes(32);
        assert_ne!(b1, b2);
        assert_eq!(b1.len(), 32);
    }
}
