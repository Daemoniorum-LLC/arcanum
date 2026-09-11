//! Phase 2 — P1: SecretKey and PublicKey under alloc (TDD-CORE-NOSTD-001 §2.3)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_key_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::key::{PublicKey, SecretKey};

    #[test]
    fn spec_secret_key_new() {
        let key = SecretKey::<32>::new([0u8; 32]);
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn spec_public_key_from_bytes() {
        let bytes = [0xABu8; 32];
        let pk = PublicKey::<32>::new(bytes);
        assert_eq!(pk.as_ref(), &bytes);
    }

    #[test]
    fn spec_secret_key_constant_time_eq() {
        let key1 = SecretKey::<32>::new([0u8; 32]);
        let key2 = SecretKey::<32>::new([0u8; 32]);
        // Both are zeroed, so they should be equal
        // Uses the inherent ct_eq method which returns bool
        assert!(key1.ct_eq(&key2));
    }

    #[test]
    fn spec_secret_key_from_slice() {
        let bytes = [0xFFu8; 32];
        let key = SecretKey::<32>::from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);

        // Wrong length should fail
        let short = [0u8; 16];
        assert!(SecretKey::<32>::from_slice(&short).is_err());
    }

    #[test]
    fn spec_public_key_from_slice() {
        let bytes = [0xCDu8; 32];
        let pk = PublicKey::<32>::from_slice(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    fn spec_key_algorithm_display() {
        use arcanum_core::key::KeyAlgorithm;
        use alloc::string::ToString;
        let alg = KeyAlgorithm::Aes256;
        assert_eq!(alg.to_string(), "AES-256");

        let custom = KeyAlgorithm::Custom("MyAlgo".into());
        assert_eq!(custom.to_string(), "MyAlgo");
    }

    #[test]
    fn spec_key_usage_no_std() {
        use arcanum_core::key::KeyUsage;
        // KeyUsage should be available under no_std
        let usage = KeyUsage::Encrypt;
        assert_eq!(usage, KeyUsage::Encrypt);
    }
}
