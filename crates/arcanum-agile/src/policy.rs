//! Cryptographic policy engine.
//!
//! Declarative restrictions on algorithm usage.

#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};

use crate::registry::{AlgorithmId, AlgorithmRegistry, SecurityLevel};
use serde::{Deserialize, Serialize};

/// Compliance profile for algorithm restrictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceProfile {
    /// No restrictions
    None,
    /// FIPS 140-3 approved algorithms only
    Fips140_3,
    /// SOC 2 compliance
    Soc2,
    /// HIPAA requirements
    Hipaa,
    /// PCI-DSS requirements
    PciDss,
    /// Custom profile
    Custom,
}

/// Cryptographic usage policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Minimum security level
    min_security_level: SecurityLevel,
    /// Require post-quantum algorithms
    require_post_quantum: bool,
    /// Allow deprecated algorithms
    allow_deprecated: bool,
    /// Compliance profile
    compliance_profile: ComplianceProfile,
    /// Explicitly allowed algorithms
    allowlist: Vec<AlgorithmId>,
    /// Explicitly blocked algorithms
    blocklist: Vec<AlgorithmId>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_security_level: SecurityLevel::Bits128,
            require_post_quantum: false,
            allow_deprecated: false,
            compliance_profile: ComplianceProfile::None,
            allowlist: Vec::new(),
            blocklist: Vec::new(),
        }
    }
}

impl Policy {
    /// Create a new policy builder.
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::new()
    }

    /// Create a FIPS 140-3 compliant policy.
    pub fn fips_140_3() -> Self {
        Self {
            min_security_level: SecurityLevel::Bits128,
            require_post_quantum: false,
            allow_deprecated: false,
            compliance_profile: ComplianceProfile::Fips140_3,
            allowlist: vec![
                AlgorithmId::Aes256Gcm,
                AlgorithmId::Aes128Gcm,
                AlgorithmId::Sha256,
                AlgorithmId::Sha512,
                AlgorithmId::EcdsaP256,
                AlgorithmId::EcdsaP384,
            ],
            blocklist: vec![
                AlgorithmId::ChaCha20Poly1305, // Not FIPS approved
                AlgorithmId::Blake3,           // Not FIPS approved
            ],
        }
    }

    /// Check if an algorithm is allowed by this policy.
    pub fn allows(&self, algorithm: AlgorithmId) -> bool {
        // Check blocklist first
        if self.blocklist.contains(&algorithm) {
            return false;
        }

        // If allowlist is non-empty, algorithm must be in it
        if !self.allowlist.is_empty() && !self.allowlist.contains(&algorithm) {
            return false;
        }

        // Get algorithm info
        let Some(info) = AlgorithmRegistry::get(algorithm) else {
            return false;
        };

        // Check deprecation
        if info.is_deprecated() && !self.allow_deprecated {
            return false;
        }

        // Check security level
        if info.security_level() < self.min_security_level {
            return false;
        }

        // Check post-quantum requirement
        if self.require_post_quantum && !info.is_post_quantum() {
            return false;
        }

        true
    }

    /// Get the reason an algorithm is not allowed.
    pub fn denial_reason(&self, algorithm: AlgorithmId) -> Option<String> {
        if self.blocklist.contains(&algorithm) {
            return Some("Algorithm is explicitly blocked".into());
        }

        if !self.allowlist.is_empty() && !self.allowlist.contains(&algorithm) {
            return Some("Algorithm is not in allowlist".into());
        }

        let Some(info) = AlgorithmRegistry::get(algorithm) else {
            return Some("Unknown algorithm".into());
        };

        if info.is_deprecated() && !self.allow_deprecated {
            return Some(format!(
                "Algorithm is deprecated: {}",
                info.deprecation_reason().unwrap_or("unknown reason")
            ));
        }

        if info.security_level() < self.min_security_level {
            return Some(format!(
                "Security level {:?} below minimum {:?}",
                info.security_level(),
                self.min_security_level
            ));
        }

        if self.require_post_quantum && !info.is_post_quantum() {
            return Some("Post-quantum algorithm required".into());
        }

        None
    }
}

/// Builder for constructing policies.
#[derive(Default)]
pub struct PolicyBuilder {
    policy: Policy,
}

impl PolicyBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum security level.
    pub fn min_security_level(mut self, level: SecurityLevel) -> Self {
        self.policy.min_security_level = level;
        self
    }

    /// Require post-quantum algorithms.
    pub fn require_post_quantum(mut self, require: bool) -> Self {
        self.policy.require_post_quantum = require;
        self
    }

    /// Allow deprecated algorithms.
    pub fn allow_deprecated(mut self, allow: bool) -> Self {
        self.policy.allow_deprecated = allow;
        self
    }

    /// Add an algorithm to the allowlist.
    pub fn allow(mut self, algorithm: AlgorithmId) -> Self {
        self.policy.allowlist.push(algorithm);
        self
    }

    /// Add an algorithm to the blocklist.
    pub fn block(mut self, algorithm: AlgorithmId) -> Self {
        self.policy.blocklist.push(algorithm);
        self
    }

    /// Build the policy.
    pub fn build(self) -> Policy {
        self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = Policy::default();
        assert!(policy.allows(AlgorithmId::Aes256Gcm));
        assert!(!policy.allows(AlgorithmId::TripleDes)); // Deprecated
    }

    #[test]
    fn test_fips_policy() {
        let policy = Policy::fips_140_3();
        assert!(policy.allows(AlgorithmId::Aes256Gcm));
        assert!(!policy.allows(AlgorithmId::ChaCha20Poly1305)); // Not FIPS
        assert!(!policy.allows(AlgorithmId::Blake3)); // Not FIPS
    }

    #[test]
    fn test_post_quantum_requirement() {
        let policy = Policy::builder().require_post_quantum(true).build();

        assert!(!policy.allows(AlgorithmId::Aes256Gcm)); // Classical
        assert!(policy.allows(AlgorithmId::MlKem768)); // PQC
        assert!(policy.allows(AlgorithmId::HybridKem)); // Hybrid counts
    }
}
