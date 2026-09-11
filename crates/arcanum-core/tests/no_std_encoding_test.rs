//! Phase 3 — P2: Encoding module isolation (TDD-CORE-NOSTD-001 §3.1)
//!
//! Run with encoding: cargo test -p arcanum-core --no-default-features --features "alloc,encoding" --test no_std_encoding_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn spec_encoding_available_with_feature() {
        // This test file is compiled with --features "alloc,encoding"
        // If encoding module is correctly gated, this import works
        #[cfg(feature = "encoding")]
        {
            use alloc::vec;
            use arcanum_core::encoding::Hex;
            let encoded = Hex::encode(&[0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(encoded, "deadbeef");

            let decoded = Hex::decode("deadbeef").unwrap();
            assert_eq!(decoded, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
    }

    #[cfg(feature = "encoding")]
    #[test]
    fn spec_base64_encoding_no_std() {
        use arcanum_core::encoding::Base64;
        let data = b"hello world";
        let encoded = Base64::encode(data);
        let decoded = Base64::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[cfg(feature = "encoding")]
    #[test]
    fn spec_hex_validation() {
        use arcanum_core::encoding::Hex;
        assert!(Hex::is_valid("deadbeef"));
        assert!(!Hex::is_valid("xyz"));
    }
}
