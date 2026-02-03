//! Phase 3 — P2: Async traits isolation (TDD-CORE-NOSTD-001 §3.4)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_traits_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    // Sync traits should be available under no_std + alloc
    use arcanum_core::traits::{
        Hash, KeyDerivation, KeyEncapsulation, KeyExchange, Mac, SecureRng, Signer,
        SymmetricEncrypt,
    };

    #[test]
    fn spec_sync_traits_available() {
        // Compile-time check: these traits exist under no_std
        fn _assert_symmetric_encrypt<T: SymmetricEncrypt>() {}
        fn _assert_hash<T: Hash>() {}
        fn _assert_signer<T: Signer>() {}
        fn _assert_mac<T: Mac>() {}
        fn _assert_kdf<T: KeyDerivation>() {}
        fn _assert_kem<T: KeyEncapsulation>() {}
        fn _assert_kex<T: KeyExchange>() {}
        fn _assert_rng<T: SecureRng>() {}
    }

    #[test]
    fn spec_secret_sharing_trait_available() {
        use arcanum_core::traits::SecretSharing;
        fn _assert_ss<T: SecretSharing>() {}
    }

    #[test]
    fn spec_hybrid_traits_available() {
        use arcanum_core::traits::{HybridEncrypt, PostQuantumHybrid};
        fn _assert_hybrid<T: HybridEncrypt>() {}
        fn _assert_pqhybrid<T: PostQuantumHybrid>() {}
    }
}
