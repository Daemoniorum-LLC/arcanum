//! Phase 4 — P1: Prelude under no_std + alloc (TDD-CORE-NOSTD-001 §4.1)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_prelude_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::prelude::*;

    #[test]
    fn spec_prelude_core_types_available() {
        // These must always be in the prelude under alloc
        let _key = SecretKey::<32>::new([0u8; 32]);
        let _buf = SecretBuffer::<16>::new();
        let _v = Version::new(0, 1, 0);
        let _nonce = Nonce::<12>::zero();
    }

    #[test]
    fn spec_prelude_error_types_available() {
        let _e: Error = Error::KeyGenerationFailed;
        let _r: Result<()> = Ok(());
    }

    #[test]
    fn spec_prelude_reexports_available() {
        // zeroize, subtle, secrecy re-exports at crate root
        use arcanum_core::{ConstantTimeEq, Zeroize, ZeroizeOnDrop};
        fn _assert_zeroize<T: Zeroize>() {}
        fn _assert_ct_eq<T: ConstantTimeEq>() {}
        fn _assert_zod<T: ZeroizeOnDrop>() {}
    }

    #[test]
    fn spec_prelude_secure_vec() {
        let v = SecureVec::zeroed(16);
        assert_eq!(v.len(), 16);

        let sb = SecretBytes::from_slice(&[1, 2, 3]);
        assert_eq!(sb.len(), 3);
    }
}
