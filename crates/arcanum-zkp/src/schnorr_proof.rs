//! Schnorr proofs of knowledge.
//!
//! Schnorr proofs allow proving knowledge of discrete logarithms
//! and their relationships without revealing the secrets.
//!
//! ## Proof Types
//!
//! - **Discrete Log Proof**: Prove knowledge of x such that Y = x*G
//! - **Equality Proof**: Prove two commitments hide the same value
//! - **Representation Proof**: Prove knowledge of representation

use crate::curve::{CompressedRistretto, RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use arcanum_core::error::{Error, Result};
use rand::RngCore;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Schnorr proof of discrete log knowledge.
///
/// Proves knowledge of x such that Y = x*G without revealing x.
#[derive(Clone)]
pub struct DiscreteLogProof {
    /// Commitment R = k*G
    commitment: CompressedRistretto,
    /// Response s = k + c*x
    response: Scalar,
}

impl DiscreteLogProof {
    /// Create a proof of knowledge of discrete log.
    ///
    /// Proves: "I know x such that public_key = x * G"
    pub fn prove(secret: &Scalar, public_key: &RistrettoPoint) -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;

        // Generate random k
        let mut k_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        // R = k * G
        let r = k * g;
        let commitment = r.compress();

        // Challenge c = H(G, Y, R)
        let c = Self::challenge(&g, public_key, &r);

        // Response s = k + c * x
        let response = k + c * secret;

        // Zeroize sensitive data
        k_bytes.zeroize();

        Self {
            commitment,
            response,
        }
    }

    /// Verify the proof.
    pub fn verify(&self, public_key: &RistrettoPoint) -> Result<bool> {
        let g = RISTRETTO_BASEPOINT_POINT;

        // Decompress commitment
        let r = self
            .commitment
            .decompress()
            .ok_or(Error::InvalidParameter("invalid commitment".to_string()))?;

        // Recompute challenge
        let c = Self::challenge(&g, public_key, &r);

        // Verify: s * G = R + c * Y
        let lhs = self.response * g;
        let rhs = r + c * public_key;

        Ok(lhs == rhs)
    }

    fn challenge(g: &RistrettoPoint, y: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"arcanum-dlog-proof");
        hasher.update(g.compress().as_bytes());
        hasher.update(y.compress().as_bytes());
        hasher.update(r.compress().as_bytes());
        Scalar::from_hash(hasher)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.commitment.as_bytes());
        bytes.extend_from_slice(self.response.as_bytes());
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::InvalidParameter(
                "proof must be 64 bytes".to_string(),
            ));
        }

        let commitment_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let response_bytes: [u8; 32] = bytes[32..].try_into().unwrap();

        let commitment = CompressedRistretto::from_slice(&commitment_bytes)
            .map_err(|_| Error::InvalidParameter("invalid commitment bytes".to_string()))?;
        let response = Scalar::from_canonical_bytes(response_bytes)
            .into_option()
            .ok_or(Error::InvalidParameter(
                "invalid response scalar".to_string(),
            ))?;

        Ok(Self {
            commitment,
            response,
        })
    }
}

impl std::fmt::Debug for DiscreteLogProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DiscreteLogProof(64 bytes)")
    }
}

/// Proof of equality of discrete logs.
///
/// Proves that two public keys share the same discrete log:
/// Y1 = x * G1 and Y2 = x * G2 for the same x.
#[derive(Clone)]
pub struct EqualityProof {
    /// Commitment R1 = k * G1
    commitment1: CompressedRistretto,
    /// Commitment R2 = k * G2
    commitment2: CompressedRistretto,
    /// Response s = k + c * x
    response: Scalar,
}

impl EqualityProof {
    /// Prove equality of discrete logs.
    ///
    /// Proves: "I know x such that Y1 = x * G1 AND Y2 = x * G2"
    pub fn prove(
        secret: &Scalar,
        generator1: &RistrettoPoint,
        generator2: &RistrettoPoint,
        public1: &RistrettoPoint,
        public2: &RistrettoPoint,
    ) -> Self {
        // Generate random k
        let mut k_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        // R1 = k * G1, R2 = k * G2
        let r1 = k * generator1;
        let r2 = k * generator2;

        // Challenge
        let c = Self::challenge(generator1, generator2, public1, public2, &r1, &r2);

        // Response s = k + c * x
        let response = k + c * secret;

        k_bytes.zeroize();

        Self {
            commitment1: r1.compress(),
            commitment2: r2.compress(),
            response,
        }
    }

    /// Verify the equality proof.
    pub fn verify(
        &self,
        generator1: &RistrettoPoint,
        generator2: &RistrettoPoint,
        public1: &RistrettoPoint,
        public2: &RistrettoPoint,
    ) -> Result<bool> {
        let r1 = self
            .commitment1
            .decompress()
            .ok_or(Error::InvalidParameter("invalid commitment1".to_string()))?;
        let r2 = self
            .commitment2
            .decompress()
            .ok_or(Error::InvalidParameter("invalid commitment2".to_string()))?;

        let c = Self::challenge(generator1, generator2, public1, public2, &r1, &r2);

        // Verify: s * G1 = R1 + c * Y1
        let lhs1 = self.response * generator1;
        let rhs1 = r1 + c * public1;

        // Verify: s * G2 = R2 + c * Y2
        let lhs2 = self.response * generator2;
        let rhs2 = r2 + c * public2;

        Ok(lhs1 == rhs1 && lhs2 == rhs2)
    }

    fn challenge(
        g1: &RistrettoPoint,
        g2: &RistrettoPoint,
        y1: &RistrettoPoint,
        y2: &RistrettoPoint,
        r1: &RistrettoPoint,
        r2: &RistrettoPoint,
    ) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"arcanum-equality-proof");
        hasher.update(g1.compress().as_bytes());
        hasher.update(g2.compress().as_bytes());
        hasher.update(y1.compress().as_bytes());
        hasher.update(y2.compress().as_bytes());
        hasher.update(r1.compress().as_bytes());
        hasher.update(r2.compress().as_bytes());
        Scalar::from_hash(hasher)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96);
        bytes.extend_from_slice(self.commitment1.as_bytes());
        bytes.extend_from_slice(self.commitment2.as_bytes());
        bytes.extend_from_slice(self.response.as_bytes());
        bytes
    }
}

impl std::fmt::Debug for EqualityProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EqualityProof(96 bytes)")
    }
}

/// Generic Schnorr proof (Sigma protocol).
#[derive(Clone)]
pub struct SchnorrProof {
    commitments: Vec<CompressedRistretto>,
    response: Scalar,
}

impl SchnorrProof {
    /// Get the response scalar.
    pub fn response(&self) -> &Scalar {
        &self.response
    }

    /// Get the commitments.
    pub fn commitments(&self) -> &[CompressedRistretto] {
        &self.commitments
    }
}

impl std::fmt::Debug for SchnorrProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SchnorrProof({} commitments)", self.commitments.len())
    }
}

/// Builder for constructing Schnorr proofs.
pub struct SchnorrProofBuilder {
    generators: Vec<RistrettoPoint>,
    public_keys: Vec<RistrettoPoint>,
    label: Vec<u8>,
}

impl SchnorrProofBuilder {
    /// Create a new builder.
    pub fn new(label: &[u8]) -> Self {
        Self {
            generators: Vec::new(),
            public_keys: Vec::new(),
            label: label.to_vec(),
        }
    }

    /// Add a generator-public key pair.
    pub fn add_statement(mut self, generator: RistrettoPoint, public_key: RistrettoPoint) -> Self {
        self.generators.push(generator);
        self.public_keys.push(public_key);
        self
    }

    /// Build the proof.
    pub fn prove(self, secret: &Scalar) -> SchnorrProof {
        // Generate random k
        let mut k_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

        // Compute commitments R_i = k * G_i
        let rs: Vec<RistrettoPoint> = self.generators.iter().map(|g| k * g).collect();

        // Compute challenge
        let c = self.challenge(&rs);

        // Compute response s = k + c * x
        let response = k + c * secret;

        k_bytes.zeroize();

        SchnorrProof {
            commitments: rs.iter().map(|r| r.compress()).collect(),
            response,
        }
    }

    /// Verify a proof.
    pub fn verify(&self, proof: &SchnorrProof) -> Result<bool> {
        if proof.commitments.len() != self.generators.len() {
            return Err(Error::InvalidParameter(
                "commitment count mismatch".to_string(),
            ));
        }

        let rs: Vec<RistrettoPoint> = proof
            .commitments
            .iter()
            .map(|c| {
                c.decompress()
                    .ok_or(Error::InvalidParameter("invalid commitment".to_string()))
            })
            .collect::<Result<Vec<_>>>()?;

        let c = self.challenge(&rs);

        // Verify each statement: s * G_i = R_i + c * Y_i
        for (i, (g, y)) in self
            .generators
            .iter()
            .zip(self.public_keys.iter())
            .enumerate()
        {
            let lhs = proof.response * g;
            let rhs = rs[i] + c * y;
            if lhs != rhs {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn challenge(&self, rs: &[RistrettoPoint]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(&self.label);

        for g in &self.generators {
            hasher.update(g.compress().as_bytes());
        }
        for y in &self.public_keys {
            hasher.update(y.compress().as_bytes());
        }
        for r in rs {
            hasher.update(r.compress().as_bytes());
        }

        Scalar::from_hash(hasher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discrete_log_proof() {
        let g = RISTRETTO_BASEPOINT_POINT;

        // Secret and public key
        let mut secret_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);
        let public = secret * g;

        // Create and verify proof
        let proof = DiscreteLogProof::prove(&secret, &public);
        assert!(proof.verify(&public).unwrap());
    }

    #[test]
    fn test_discrete_log_proof_wrong_key() {
        let g = RISTRETTO_BASEPOINT_POINT;

        let mut secret_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);
        let public = secret * g;

        // Wrong public key
        let wrong_public = Scalar::from(42u64) * g;

        let proof = DiscreteLogProof::prove(&secret, &public);
        assert!(!proof.verify(&wrong_public).unwrap());
    }

    #[test]
    fn test_discrete_log_proof_serialization() {
        let g = RISTRETTO_BASEPOINT_POINT;

        let mut secret_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);
        let public = secret * g;

        let proof = DiscreteLogProof::prove(&secret, &public);
        let bytes = proof.to_bytes();
        let restored = DiscreteLogProof::from_bytes(&bytes).unwrap();

        assert!(restored.verify(&public).unwrap());
    }

    #[test]
    fn test_equality_proof() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        // Generate g2 deterministically by scalar multiplication
        let g2 = Scalar::from(42u64) * g1;

        let mut secret_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);

        let y1 = secret * g1;
        let y2 = secret * g2;

        let proof = EqualityProof::prove(&secret, &g1, &g2, &y1, &y2);
        assert!(proof.verify(&g1, &g2, &y1, &y2).unwrap());
    }

    #[test]
    fn test_equality_proof_different_secrets_fails() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        // Generate g2 deterministically by scalar multiplication
        let g2 = Scalar::from(42u64) * g1;

        let secret1 = Scalar::from(42u64);
        let secret2 = Scalar::from(43u64);

        let y1 = secret1 * g1;
        let y2 = secret2 * g2;

        // Try to prove with secret1, but y2 uses secret2
        let proof = EqualityProof::prove(&secret1, &g1, &g2, &y1, &y2);
        assert!(!proof.verify(&g1, &g2, &y1, &y2).unwrap());
    }

    #[test]
    fn test_schnorr_proof_builder() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        // Generate g2 deterministically by scalar multiplication
        let g2 = Scalar::from(123u64) * g1;

        let mut secret_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);

        let y1 = secret * g1;
        let y2 = secret * g2;

        let builder = SchnorrProofBuilder::new(b"test-proof")
            .add_statement(g1, y1)
            .add_statement(g2, y2);

        let proof = builder.prove(&secret);

        let verifier = SchnorrProofBuilder::new(b"test-proof")
            .add_statement(g1, y1)
            .add_statement(g2, y2);

        assert!(verifier.verify(&proof).unwrap());
    }
}
