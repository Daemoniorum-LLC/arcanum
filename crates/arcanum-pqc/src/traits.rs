//! Traits for post-quantum cryptographic algorithms.

use arcanum_core::error::Result;

/// Trait for Key Encapsulation Mechanisms (KEMs).
///
/// KEMs are the post-quantum replacement for key exchange (DH/ECDH).
pub trait KeyEncapsulation {
    /// Decapsulation (private) key type.
    type DecapsulationKey;
    /// Encapsulation (public) key type.
    type EncapsulationKey;
    /// Ciphertext type.
    type Ciphertext;
    /// Shared secret type.
    type SharedSecret;

    /// Algorithm identifier.
    const ALGORITHM: &'static str;
    /// Security level in bits.
    const SECURITY_LEVEL: usize;

    /// Generate a new key pair.
    fn generate_keypair() -> (Self::DecapsulationKey, Self::EncapsulationKey);

    /// Encapsulate: generate a shared secret and ciphertext.
    ///
    /// The ciphertext can only be decapsulated by the holder of the
    /// corresponding decapsulation key.
    fn encapsulate(ek: &Self::EncapsulationKey) -> (Self::Ciphertext, Self::SharedSecret);

    /// Decapsulate: recover the shared secret from a ciphertext.
    #[must_use = "decapsulation can fail; check the Result"]
    fn decapsulate(
        dk: &Self::DecapsulationKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret>;
}

/// Trait for post-quantum digital signatures.
pub trait PostQuantumSignature {
    /// Signing (private) key type.
    type SigningKey;
    /// Verifying (public) key type.
    type VerifyingKey;
    /// Signature type.
    type Signature;

    /// Algorithm identifier.
    const ALGORITHM: &'static str;
    /// Security level in bits.
    const SECURITY_LEVEL: usize;

    /// Generate a new key pair.
    fn generate_keypair() -> (Self::SigningKey, Self::VerifyingKey);

    /// Sign a message.
    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Self::Signature;

    /// Verify a signature.
    #[must_use = "verification result must be checked"]
    fn verify(vk: &Self::VerifyingKey, message: &[u8], signature: &Self::Signature) -> Result<()>;
}

/// Security levels for post-quantum algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    /// NIST Level 1: Equivalent to AES-128
    Level1 = 128,
    /// NIST Level 3: Equivalent to AES-192
    Level3 = 192,
    /// NIST Level 5: Equivalent to AES-256
    Level5 = 256,
}

impl SecurityLevel {
    /// Get the bit strength.
    pub fn bits(&self) -> usize {
        *self as usize
    }

    /// Get recommended ML-KEM variant for this security level.
    pub fn ml_kem_variant(&self) -> &'static str {
        match self {
            SecurityLevel::Level1 => "ML-KEM-512",
            SecurityLevel::Level3 => "ML-KEM-768",
            SecurityLevel::Level5 => "ML-KEM-1024",
        }
    }

    /// Get recommended ML-DSA variant for this security level.
    pub fn ml_dsa_variant(&self) -> &'static str {
        match self {
            SecurityLevel::Level1 => "ML-DSA-44",
            SecurityLevel::Level3 => "ML-DSA-65",
            SecurityLevel::Level5 => "ML-DSA-87",
        }
    }
}
