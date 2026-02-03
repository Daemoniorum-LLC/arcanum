//! Phase 2 — P1: Version types under no_std (TDD-CORE-NOSTD-001 §2.5)
//!
//! Run: cargo test -p arcanum-core --no-default-features --features alloc --test no_std_version_test

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::version::Version;

    #[test]
    fn spec_version_create_and_compare() {
        let v1 = Version::new(0, 1, 0);
        let v2 = Version::new(0, 2, 0);

        assert_eq!(v1.major, 0);
        assert_eq!(v1.minor, 1);
        assert_eq!(v1.patch, 0);

        // v2 > v1
        assert!(v2 > v1);
    }

    #[test]
    fn spec_version_equality() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 0);
        assert_eq!(v1, v2);
    }

    #[test]
    fn spec_version_compatibility() {
        let v1 = Version::new(1, 2, 0);
        let v2 = Version::new(1, 1, 0);
        let v3 = Version::new(2, 0, 0);

        assert!(v1.is_compatible_with(&v2));
        assert!(!v2.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn spec_version_u64_encoding() {
        let v = Version::new(1, 2, 3);
        let encoded = v.to_u64();
        let decoded = Version::from_u64(encoded);
        assert_eq!(v, decoded);
    }

    #[test]
    fn spec_version_display() {
        use alloc::string::ToString;
        let v = Version::new(0, 1, 2);
        assert_eq!(v.to_string(), "0.1.2");
    }

    #[test]
    fn spec_protocol_id_no_std() {
        use arcanum_core::version::ProtocolId;
        let p = ProtocolId::new("arcanum-vault", Version::new(1, 0, 0));
        assert_eq!(p.name, "arcanum-vault");
        assert_eq!(p.version, Version::new(1, 0, 0));
    }

    #[test]
    fn spec_algorithm_id_no_std() {
        use arcanum_core::version::AlgorithmId;
        let alg = AlgorithmId::new("AES-256-GCM");
        assert_eq!(alg.name, "AES-256-GCM");
    }
}
