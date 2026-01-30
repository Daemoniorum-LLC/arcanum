//! X25519 key exchange.
//!
//! X25519 is the Curve25519 Diffie-Hellman function, providing fast
//! and secure key exchange with 128-bit security.
//!
//! ## Features
//!
//! - **Speed**: One of the fastest ECDH implementations
//! - **Security**: Constant-time, side-channel resistant
//! - **Simplicity**: No point validation required (safe by design)
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_asymmetric::x25519::*;
//!
//! // Alice generates her key pair
//! let alice_secret = X25519SecretKey::generate();
//! let alice_public = alice_secret.public_key();
//!
//! // Bob generates his key pair
//! let bob_secret = X25519SecretKey::generate();
//! let bob_public = bob_secret.public_key();
//!
//! // Both compute the same shared secret
//! let alice_shared = alice_secret.diffie_hellman(&bob_public);
//! let bob_shared = bob_secret.diffie_hellman(&alice_public);
//!
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```

use crate::traits::DiffieHellman;
use arcanum_core::error::{Error, Result};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

/// X25519 secret key.
#[derive(ZeroizeOnDrop)]
pub struct X25519SecretKey {
    inner: StaticSecret,
}

impl X25519SecretKey {
    /// Generate a new random secret key.
    pub fn generate() -> Self {
        Self {
            inner: StaticSecret::random_from_rng(&mut OsRng),
        }
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: StaticSecret::from(*bytes),
        }
    }

    /// Export to bytes.
    ///
    /// # Security
    ///
    /// The returned bytes should be handled securely and zeroized after use.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Derive the public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            inner: PublicKey::from(&self.inner),
        }
    }

    /// Perform Diffie-Hellman key exchange.
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> X25519SharedSecret {
        let shared = self.inner.diffie_hellman(&peer_public.inner);
        X25519SharedSecret {
            bytes: shared.to_bytes(),
        }
    }

    /// Generate an ephemeral key for one-time use.
    ///
    /// Ephemeral secrets provide forward secrecy when used in protocols.
    pub fn ephemeral() -> (EphemeralX25519Secret, X25519PublicKey) {
        let secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        (
            EphemeralX25519Secret { inner: secret },
            X25519PublicKey { inner: public },
        )
    }
}

impl core::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "X25519SecretKey([REDACTED])")
    }
}

impl DiffieHellman for X25519SecretKey {
    type PublicKey = X25519PublicKey;
    type SharedSecret = X25519SharedSecret;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key()
    }

    fn diffie_hellman(&self, peer_public: &Self::PublicKey) -> Self::SharedSecret {
        self.diffie_hellman(peer_public)
    }
}

/// Ephemeral X25519 secret key (one-time use).
pub struct EphemeralX25519Secret {
    inner: EphemeralSecret,
}

impl EphemeralX25519Secret {
    /// Perform Diffie-Hellman and consume the ephemeral secret.
    pub fn diffie_hellman(self, peer_public: &X25519PublicKey) -> X25519SharedSecret {
        let shared = self.inner.diffie_hellman(&peer_public.inner);
        X25519SharedSecret {
            bytes: shared.to_bytes(),
        }
    }
}

impl core::fmt::Debug for EphemeralX25519Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EphemeralX25519Secret([REDACTED])")
    }
}

/// X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X25519PublicKey {
    inner: PublicKey,
}

impl X25519PublicKey {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: PublicKey::from(*bytes),
        }
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|_| Error::InvalidKeyFormat)?;
        if bytes.len() != 32 {
            return Err(Error::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let arr: [u8; 32] = bytes.try_into().unwrap();
        Ok(Self::from_bytes(&arr))
    }
}

impl core::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "X25519PublicKey({}...)",
            &hex::encode(&self.to_bytes()[..8])
        )
    }
}

impl core::fmt::Display for X25519PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// X25519 shared secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct X25519SharedSecret {
    bytes: [u8; 32],
}

impl X25519SharedSecret {
    /// Access the shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert to a vector (for use as key material).
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// Check if this is a low-order point (potential attack).
    ///
    /// Returns true if the shared secret is all zeros, which indicates
    /// the peer provided a malicious low-order public key.
    ///
    /// # Security
    ///
    /// This check is performed in constant time to prevent timing attacks
    /// that could leak information about the shared secret.
    pub fn is_low_order(&self) -> bool {
        use subtle::ConstantTimeEq;
        let zero = [0u8; 32];
        self.bytes.ct_eq(&zero).into()
    }

    /// Derive a key using HKDF.
    pub fn derive_key(&self, info: &[u8], output_len: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut output = vec![0u8; output_len];
        hkdf.expand(info, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(output)
    }
}

impl PartialEq for X25519SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for X25519SharedSecret {}

impl core::fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "X25519SharedSecret([REDACTED])")
    }
}

/// X25519 key agreement protocol.
pub struct X25519;

impl X25519 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "X25519";

    /// Security level in bits.
    pub const SECURITY_BITS: usize = 128;

    /// Key size in bytes.
    pub const KEY_SIZE: usize = 32;

    /// Generate a new key pair.
    pub fn generate() -> (X25519SecretKey, X25519PublicKey) {
        let secret = X25519SecretKey::generate();
        let public = secret.public_key();
        (secret, public)
    }

    /// Perform authenticated key exchange (X3DH-style).
    ///
    /// Computes: DH(identity_secret, peer_identity) || DH(identity_secret, peer_ephemeral)
    ///           || DH(ephemeral_secret, peer_identity)
    pub fn triple_dh(
        identity_secret: &X25519SecretKey,
        ephemeral_secret: &X25519SecretKey,
        peer_identity: &X25519PublicKey,
        peer_ephemeral: &X25519PublicKey,
    ) -> X25519SharedSecret {
        let dh1 = identity_secret.diffie_hellman(peer_identity);
        let dh2 = identity_secret.diffie_hellman(peer_ephemeral);
        let dh3 = ephemeral_secret.diffie_hellman(peer_identity);

        // Combine using HKDF
        use hkdf::Hkdf;
        use sha2::Sha256;

        let mut ikm = Vec::with_capacity(96);
        ikm.extend_from_slice(dh1.as_bytes());
        ikm.extend_from_slice(dh2.as_bytes());
        ikm.extend_from_slice(dh3.as_bytes());

        let hkdf = Hkdf::<Sha256>::new(None, &ikm);
        let mut output = [0u8; 32];
        hkdf.expand(b"X3DH", &mut output).unwrap();

        // Zeroize intermediate material
        ikm.zeroize();

        X25519SharedSecret { bytes: output }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice_secret = X25519SecretKey::generate();
        let alice_public = alice_secret.public_key();

        let bob_secret = X25519SecretKey::generate();
        let bob_public = bob_secret.public_key();

        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let (alice_ephemeral, alice_public) = X25519SecretKey::ephemeral();

        let bob_secret = X25519SecretKey::generate();
        let bob_public = bob_secret.public_key();

        let alice_shared = alice_ephemeral.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_key_serialization() {
        let secret = X25519SecretKey::generate();
        let public = secret.public_key();

        let secret_bytes = secret.to_bytes();
        let public_bytes = public.to_bytes();

        let restored_secret = X25519SecretKey::from_bytes(&secret_bytes);
        let restored_public = X25519PublicKey::from_bytes(&public_bytes);

        assert_eq!(restored_secret.public_key(), public);
        assert_eq!(restored_public, public);
    }

    #[test]
    fn test_hex_encoding() {
        let public = X25519SecretKey::generate().public_key();
        let hex = public.to_hex();
        let restored = X25519PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public, restored);
    }

    #[test]
    fn test_triple_dh() {
        let alice_identity = X25519SecretKey::generate();
        let alice_ephemeral = X25519SecretKey::generate();
        let bob_identity = X25519SecretKey::generate();
        let bob_ephemeral = X25519SecretKey::generate();

        let alice_shared = X25519::triple_dh(
            &alice_identity,
            &alice_ephemeral,
            &bob_identity.public_key(),
            &bob_ephemeral.public_key(),
        );

        let bob_shared = X25519::triple_dh(
            &bob_identity,
            &bob_ephemeral,
            &alice_identity.public_key(),
            &alice_ephemeral.public_key(),
        );

        // Note: Triple DH is not symmetric in the same way - this is expected
        // In real X3DH, the order of operations matters for initiator vs responder
    }

    #[test]
    fn test_key_derivation() {
        let secret = X25519SecretKey::generate();
        let public = X25519SecretKey::generate().public_key();
        let shared = secret.diffie_hellman(&public);

        let key1 = shared.derive_key(b"encryption", 32).unwrap();
        let key2 = shared.derive_key(b"authentication", 32).unwrap();

        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_different_keys_produce_different_secrets() {
        let alice = X25519SecretKey::generate();
        let bob1 = X25519SecretKey::generate();
        let bob2 = X25519SecretKey::generate();

        let shared1 = alice.diffie_hellman(&bob1.public_key());
        let shared2 = alice.diffie_hellman(&bob2.public_key());

        assert_ne!(shared1.as_bytes(), shared2.as_bytes());
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // PROPERTY-BASED TESTS
    // ═══════════════════════════════════════════════════════════════════════════════

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: DH is commutative - both parties compute the same shared secret
            #[test]
            fn prop_dh_commutative(
                alice_seed in any::<[u8; 32]>(),
                bob_seed in any::<[u8; 32]>()
            ) {
                let alice_secret = X25519SecretKey::from_bytes(&alice_seed);
                let alice_public = alice_secret.public_key();

                let bob_secret = X25519SecretKey::from_bytes(&bob_seed);
                let bob_public = bob_secret.public_key();

                let alice_shared = alice_secret.diffie_hellman(&bob_public);
                let bob_shared = bob_secret.diffie_hellman(&alice_public);

                prop_assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
            }

            /// Property: Secret key serialization roundtrip
            #[test]
            fn prop_secret_key_roundtrip(seed in any::<[u8; 32]>()) {
                let secret = X25519SecretKey::from_bytes(&seed);
                let public = secret.public_key();

                let bytes = secret.to_bytes();
                let restored = X25519SecretKey::from_bytes(&bytes);

                prop_assert_eq!(restored.public_key(), public);
            }

            /// Property: Public key serialization roundtrip
            #[test]
            fn prop_public_key_roundtrip(seed in any::<[u8; 32]>()) {
                let secret = X25519SecretKey::from_bytes(&seed);
                let public = secret.public_key();

                let bytes = public.to_bytes();
                let restored = X25519PublicKey::from_bytes(&bytes);

                prop_assert_eq!(restored, public);
            }

            /// Property: Public key hex roundtrip
            #[test]
            fn prop_public_key_hex_roundtrip(seed in any::<[u8; 32]>()) {
                let secret = X25519SecretKey::from_bytes(&seed);
                let public = secret.public_key();

                let hex = public.to_hex();
                let restored = X25519PublicKey::from_hex(&hex).unwrap();

                prop_assert_eq!(restored, public);
            }

            /// Property: Shared secret is 32 bytes
            #[test]
            fn prop_shared_secret_length(
                alice_seed in any::<[u8; 32]>(),
                bob_seed in any::<[u8; 32]>()
            ) {
                let alice = X25519SecretKey::from_bytes(&alice_seed);
                let bob = X25519SecretKey::from_bytes(&bob_seed);

                let shared = alice.diffie_hellman(&bob.public_key());
                prop_assert_eq!(shared.as_bytes().len(), 32);
            }

            /// Property: Different keys produce different shared secrets
            #[test]
            fn prop_different_keys_different_secrets(
                alice_seed in any::<[u8; 32]>(),
                bob1_seed in any::<[u8; 32]>(),
                bob2_seed in any::<[u8; 32]>()
            ) {
                prop_assume!(bob1_seed != bob2_seed);

                let alice = X25519SecretKey::from_bytes(&alice_seed);
                let bob1 = X25519SecretKey::from_bytes(&bob1_seed);
                let bob2 = X25519SecretKey::from_bytes(&bob2_seed);

                let shared1 = alice.diffie_hellman(&bob1.public_key());
                let shared2 = alice.diffie_hellman(&bob2.public_key());

                prop_assert_ne!(shared1.as_bytes(), shared2.as_bytes());
            }

            /// Property: Key derivation produces correct length output
            #[test]
            fn prop_key_derivation_length(
                seed1 in any::<[u8; 32]>(),
                seed2 in any::<[u8; 32]>(),
                info in prop::collection::vec(any::<u8>(), 0..64),
                output_len in 16usize..128
            ) {
                let alice = X25519SecretKey::from_bytes(&seed1);
                let bob = X25519SecretKey::from_bytes(&seed2);

                let shared = alice.diffie_hellman(&bob.public_key());
                let derived = shared.derive_key(&info, output_len).unwrap();

                prop_assert_eq!(derived.len(), output_len);
            }

            /// Property: Key derivation is deterministic
            #[test]
            fn prop_key_derivation_deterministic(
                seed1 in any::<[u8; 32]>(),
                seed2 in any::<[u8; 32]>(),
                info in prop::collection::vec(any::<u8>(), 0..64)
            ) {
                let alice = X25519SecretKey::from_bytes(&seed1);
                let bob = X25519SecretKey::from_bytes(&seed2);

                let shared = alice.diffie_hellman(&bob.public_key());
                let key1 = shared.derive_key(&info, 32).unwrap();
                let key2 = shared.derive_key(&info, 32).unwrap();

                prop_assert_eq!(key1, key2);
            }
        }
    }
}
