//! Asymmetric cryptography.
//!
//! Supports X25519 key exchange and Ed25519 signatures.

use wasm_bindgen::prelude::*;

/// X25519 key pair for Diffie-Hellman key exchange.
#[wasm_bindgen]
pub struct X25519KeyPair {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

#[wasm_bindgen]
impl X25519KeyPair {
    /// Generate a new random X25519 key pair.
    #[wasm_bindgen]
    pub fn generate() -> X25519KeyPair {
        use rand_core::OsRng;
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        X25519KeyPair { secret, public }
    }

    /// Get the public key bytes (32 bytes).
    #[wasm_bindgen]
    pub fn public_key(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - The peer's 32-byte public key
    ///
    /// # Returns
    ///
    /// 32-byte shared secret. Both parties derive the same secret.
    #[wasm_bindgen]
    pub fn diffie_hellman(&self, peer_public: &[u8]) -> Vec<u8> {
        let peer_public: [u8; 32] = peer_public
            .try_into()
            .expect("peer public key must be 32 bytes");
        let peer = x25519_dalek::PublicKey::from(peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        shared.as_bytes().to_vec()
    }
}

/// Ed25519 key pair for digital signatures.
#[wasm_bindgen]
pub struct Ed25519KeyPair {
    signing_key: ed25519_dalek::SigningKey,
}

#[wasm_bindgen]
impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    #[wasm_bindgen]
    pub fn generate() -> Ed25519KeyPair {
        use rand_core::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Ed25519KeyPair { signing_key }
    }

    /// Create an Ed25519 key pair from a 32-byte seed.
    ///
    /// Deterministic: the same seed always produces the same key pair.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed value
    #[wasm_bindgen]
    pub fn from_seed(seed: &[u8]) -> Ed25519KeyPair {
        let seed: [u8; 32] = seed.try_into().expect("seed must be 32 bytes");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ed25519KeyPair { signing_key }
    }

    /// Get the public key bytes (32 bytes).
    #[wasm_bindgen]
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// 64-byte Ed25519 signature.
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's 32-byte public key
    /// * `message` - The message that was signed
    /// * `signature` - The 64-byte signature
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise.
    #[wasm_bindgen]
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        use ed25519_dalek::Verifier;

        let public_key: [u8; 32] = match public_key.try_into() {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let signature: [u8; 64] = match signature.try_into() {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&public_key) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        let signature = ed25519_dalek::Signature::from_bytes(&signature);

        verifying_key.verify(message, &signature).is_ok()
    }
}
