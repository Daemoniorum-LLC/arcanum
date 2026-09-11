//! Phase 2 — P1: Error types under alloc (TDD-CORE-NOSTD-001 §2.2)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_error_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use arcanum_core::error::Error;

    #[test]
    fn spec_error_invalid_key_length_no_alloc_needed() {
        // Variants with only primitive fields work without alloc
        let e = Error::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        match e {
            Error::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn spec_error_string_variants_with_alloc() {
        // String-carrying variants require alloc
        let e = Error::KeyNotFound("test-key-id".to_string());
        match e {
            Error::KeyNotFound(id) => assert_eq!(id, "test-key-id"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn spec_error_io_conversion_absent_without_std() {
        // std::io::Error conversion should not be available without std.
        // If this file compiles under no_std + alloc, the From<std::io::Error>
        // impl is correctly gated. This is a compile-time contract.
    }

    #[test]
    fn spec_error_category_checks() {
        let e = Error::DecryptionFailed;
        assert!(e.is_authentication_failure());
        assert!(!e.is_key_error());

        let e = Error::KeyExpired;
        assert!(e.is_key_error());

        let e = Error::NonceReuse;
        assert!(e.is_security_violation());
    }
}
