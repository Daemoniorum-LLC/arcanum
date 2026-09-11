//! Version information and compatibility checking.

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use core::fmt;

/// Arcanum library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version information for cryptographic data.
///
/// Used to ensure forward/backward compatibility when deserializing
/// encrypted data or cryptographic structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version {
    /// Major version (breaking changes)
    pub major: u16,
    /// Minor version (new features, backward compatible)
    pub minor: u16,
    /// Patch version (bug fixes)
    pub patch: u16,
}

impl Version {
    /// Create a new version.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Current library version.
    pub fn current() -> Self {
        Self {
            major: 0,
            minor: 1,
            patch: 0,
        }
    }

    /// Check if this version is compatible with another.
    ///
    /// Compatible means the major version matches and our version
    /// is >= the other version.
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        if self.major != other.major {
            return false;
        }

        if self.minor < other.minor {
            return false;
        }

        if self.minor == other.minor && self.patch < other.patch {
            return false;
        }

        true
    }

    /// Encode as a u64 for compact storage.
    pub fn to_u64(&self) -> u64 {
        ((self.major as u64) << 32) | ((self.minor as u64) << 16) | (self.patch as u64)
    }

    /// Decode from a u64.
    pub fn from_u64(value: u64) -> Self {
        Self {
            major: ((value >> 32) & 0xFFFF) as u16,
            minor: ((value >> 16) & 0xFFFF) as u16,
            patch: (value & 0xFFFF) as u16,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::current()
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match self.major.cmp(&other.major) {
            core::cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
                core::cmp::Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

/// Protocol/format identifier with version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProtocolId {
    /// Protocol name.
    pub name: String,
    /// Protocol version.
    pub version: Version,
}

impl ProtocolId {
    /// Create a new protocol identifier.
    pub fn new(name: impl Into<String>, version: Version) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }

    /// Check compatibility with another protocol.
    pub fn is_compatible_with(&self, other: &ProtocolId) -> bool {
        self.name == other.name && self.version.is_compatible_with(&other.version)
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.version)
    }
}

/// Algorithm identifier with version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AlgorithmId {
    /// Algorithm name (e.g., "AES-256-GCM", "Ed25519")
    pub name: String,
    /// Algorithm variant or parameter set (optional)
    pub variant: Option<String>,
}

#[allow(missing_docs)] // Algorithm identifier constants are self-documenting
impl AlgorithmId {
    /// Create a new algorithm identifier.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            variant: None,
        }
    }

    /// Create with a variant.
    pub fn with_variant(name: impl Into<String>, variant: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            variant: Some(variant.into()),
        }
    }

    // Common algorithm identifiers
    pub const AES_128_GCM: &'static str = "AES-128-GCM";
    pub const AES_256_GCM: &'static str = "AES-256-GCM";
    pub const CHACHA20_POLY1305: &'static str = "ChaCha20-Poly1305";
    pub const XCHACHA20_POLY1305: &'static str = "XChaCha20-Poly1305";
    pub const ED25519: &'static str = "Ed25519";
    pub const X25519: &'static str = "X25519";
    pub const ECDSA_P256: &'static str = "ECDSA-P256";
    pub const ECDSA_P384: &'static str = "ECDSA-P384";
    pub const RSA_OAEP: &'static str = "RSA-OAEP";
    pub const RSA_PSS: &'static str = "RSA-PSS";
    pub const ML_KEM_768: &'static str = "ML-KEM-768";
    pub const ML_DSA_65: &'static str = "ML-DSA-65";
    pub const ARGON2ID: &'static str = "Argon2id";
    pub const HKDF_SHA256: &'static str = "HKDF-SHA256";
    pub const BLAKE3: &'static str = "BLAKE3";
    pub const SHA256: &'static str = "SHA-256";
    pub const SHA384: &'static str = "SHA-384";
    pub const SHA512: &'static str = "SHA-512";
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.variant {
            Some(variant) => write!(f, "{}/{}", self.name, variant),
            None => write!(f, "{}", self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString;

    #[test]
    fn test_version_comparison() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 1, 0);
        let v3 = Version::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = Version::new(1, 2, 0);
        let v2 = Version::new(1, 1, 0);
        let v3 = Version::new(2, 0, 0);

        // v1 is compatible with v2 (same major, higher minor)
        assert!(v1.is_compatible_with(&v2));

        // v2 is not compatible with v1 (lower minor)
        assert!(!v2.is_compatible_with(&v1));

        // Different major versions are not compatible
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_version_encoding() {
        let v = Version::new(1, 2, 3);
        let encoded = v.to_u64();
        let decoded = Version::from_u64(encoded);
        assert_eq!(v, decoded);
    }

    #[test]
    fn test_protocol_id() {
        let p1 = ProtocolId::new("arcanum-vault", Version::new(1, 0, 0));
        let p2 = ProtocolId::new("arcanum-vault", Version::new(1, 1, 0));
        let p3 = ProtocolId::new("other-protocol", Version::new(1, 0, 0));

        // Same protocol, compatible versions
        assert!(p2.is_compatible_with(&p1));

        // Different protocols
        assert!(!p1.is_compatible_with(&p3));
    }

    #[test]
    fn test_algorithm_id() {
        let alg = AlgorithmId::with_variant("AES-GCM", "256");
        assert_eq!(alg.to_string(), "AES-GCM/256");

        let alg2 = AlgorithmId::new("Ed25519");
        assert_eq!(alg2.to_string(), "Ed25519");
    }
}
