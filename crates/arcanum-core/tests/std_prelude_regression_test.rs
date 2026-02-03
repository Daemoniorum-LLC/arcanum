//! Phase 4 — P3: Prelude under full std, regression (TDD-CORE-NOSTD-001 §4.2)
//!
//! Run: cargo test -p arcanum-core --test std_prelude_regression_test

#[cfg(test)]
mod tests {
    use arcanum_core::prelude::*;

    #[test]
    fn spec_prelude_std_extras_available() {
        // These should be in the prelude when std is enabled
        #[cfg(feature = "std")]
        {
            let _rng = OsRng;
            let _id = KeyId::generate();
            let _meta = KeyMetadata::new(
                arcanum_core::key::KeyAlgorithm::Aes256,
                vec![arcanum_core::key::KeyUsage::Encrypt],
            );
            assert!(_meta.is_valid());
        }

        #[cfg(feature = "encoding")]
        {
            let encoded = Hex::encode(&[0xFF]);
            assert_eq!(encoded, "ff");
        }
    }

    #[test]
    fn spec_prelude_all_core_types() {
        // All core types should still be available under std
        let _key = SecretKey::<32>::new([0u8; 32]);
        let _buf = SecretBuffer::<16>::new();
        let _v = Version::new(0, 1, 0);
        let _nonce = Nonce::<12>::zero();
        let _vec = SecureVec::zeroed(8);
        let _e: Error = Error::KeyGenerationFailed;
        let _r: Result<()> = Ok(());
    }
}
