//! Phase 2 — P1: Nonce under no_std (TDD-CORE-NOSTD-001 §2.4)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_nonce_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::nonce::Nonce;

    #[test]
    fn spec_nonce_from_bytes() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce = Nonce::<12>::new(bytes);
        assert_eq!(nonce.as_ref(), &bytes);
    }

    #[test]
    fn spec_nonce_zeroed() {
        let nonce = Nonce::<12>::zero();
        assert!(nonce.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn spec_nonce_increment() {
        let mut nonce = Nonce::<12>::zero();
        nonce.increment().unwrap();
        // Last byte should be 1
        assert_eq!(nonce.as_bytes()[11], 1);
    }

    #[test]
    fn spec_nonce_from_counter() {
        let nonce = Nonce::<12>::from_counter(42);
        let bytes = nonce.as_bytes();
        // Counter placed in last 8 bytes
        assert_eq!(&bytes[4..], &42u64.to_be_bytes());
    }

    #[test]
    fn spec_nonce_from_slice() {
        let bytes = [0xABu8; 12];
        let nonce = Nonce::<12>::from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);

        // Wrong length should fail
        let short = [0u8; 8];
        assert!(Nonce::<12>::from_slice(&short).is_err());
    }

    #[test]
    fn spec_nonce_generator_counter_no_std() {
        use arcanum_core::nonce::NonceGenerator;
        let nonce_gen = NonceGenerator::<12>::counter(0);
        let n1 = nonce_gen.generate().unwrap();
        let n2 = nonce_gen.generate().unwrap();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
        assert_eq!(nonce_gen.count(), 2);
    }

    #[test]
    fn spec_nonce_type_aliases() {
        use arcanum_core::nonce::{Nonce128, Nonce192, Nonce64, Nonce96};
        // Type aliases should compile
        let _n96 = Nonce96::zero();
        let _n192 = Nonce192::zero();
        let _n128 = Nonce128::zero();
        let _n64 = Nonce64::zero();
    }
}
