//! Phase 2 — P1: SecretBuffer and SecureVec under alloc (TDD-CORE-NOSTD-001 §2.1)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_buffer_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::buffer::{SecretBuffer, SecureVec};

    #[test]
    fn spec_secret_buffer_create_and_access() {
        // SecretBuffer should be constructible from a fixed-size array
        let buf = SecretBuffer::<32>::from_array([0x42u8; 32]);
        assert_eq!(buf.as_ref().len(), 32);
        assert_eq!(buf.as_ref()[0], 0x42);
    }

    #[test]
    fn spec_secret_buffer_zeroed_default() {
        // Default SecretBuffer is zeroed
        let buf = SecretBuffer::<32>::new();
        assert!(buf.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn spec_secure_vec_create_zeroed() {
        // SecureVec requires alloc but not std
        let v = SecureVec::zeroed(64);
        assert_eq!(v.len(), 64);
        // Initialized to zero
        assert!(v.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn spec_secure_vec_from_slice() {
        let data = [1u8, 2, 3, 4, 5];
        let v = SecureVec::from(&data[..]);
        assert_eq!(v.as_ref(), &data);
    }

    #[test]
    fn spec_secret_buffer_from_slice_validates_length() {
        let data = [1u8; 16];
        let buf = SecretBuffer::<16>::from_slice(&data);
        assert!(buf.is_ok());

        // Wrong length should fail
        let bad = SecretBuffer::<32>::from_slice(&data);
        assert!(bad.is_err());
    }
}
