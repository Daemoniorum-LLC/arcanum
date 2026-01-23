//! Pedersen commitments.
//!
//! Pedersen commitments are information-theoretically hiding and
//! computationally binding commitments with homomorphic properties.
//!
//! ## Properties
//!
//! - **Hiding**: The commitment reveals nothing about the value
//! - **Binding**: Cannot open commitment to different value (assuming DL is hard)
//! - **Homomorphic**: C(a) + C(b) = C(a + b)
//!
//! ## Construction
//!
//! C = v*G + r*H
//!
//! Where:
//! - v is the value
//! - r is the blinding factor (randomness)
//! - G, H are generator points (H is chosen via hash-to-curve)

use crate::curve::{CompressedRistretto, RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use arcanum_core::error::{Error, Result};
use rand::RngCore;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The second generator point H, derived from hashing G.
fn generator_h() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"arcanum-pedersen-generator-H");
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    RistrettoPoint::from_hash(hasher)
}

/// Pedersen commitment opening (the blinding factor).
#[derive(Clone, ZeroizeOnDrop)]
pub struct PedersenOpening {
    blinding: Scalar,
}

impl PedersenOpening {
    /// Generate a random opening.
    pub fn random() -> Self {
        let mut bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self {
            blinding: Scalar::from_bytes_mod_order_wide(&bytes),
        }
    }

    /// Create from a scalar.
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { blinding: scalar }
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let scalar = Scalar::from_canonical_bytes(*bytes);
        if scalar.is_none().into() {
            return Err(Error::InvalidKeyFormat);
        }
        Ok(Self {
            blinding: scalar.unwrap(),
        })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.blinding.to_bytes()
    }

    /// Get the blinding factor.
    pub fn blinding(&self) -> &Scalar {
        &self.blinding
    }

    /// Add two openings (for homomorphic operations).
    pub fn add(&self, other: &Self) -> Self {
        Self {
            blinding: self.blinding + other.blinding,
        }
    }

    /// Subtract two openings.
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            blinding: self.blinding - other.blinding,
        }
    }
}

impl std::fmt::Debug for PedersenOpening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PedersenOpening([REDACTED])")
    }
}

/// Pedersen commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct PedersenCommitment {
    point: RistrettoPoint,
}

impl PedersenCommitment {
    /// Create a commitment to a value.
    pub fn commit(value: u64, opening: &PedersenOpening) -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let v = Scalar::from(value);
        let point = v * g + opening.blinding * h;
        Self { point }
    }

    /// Create a commitment to a scalar value.
    pub fn commit_scalar(value: &Scalar, opening: &PedersenOpening) -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let point = value * g + opening.blinding * h;
        Self { point }
    }

    /// Verify that an opening is valid for a given value.
    pub fn verify(&self, value: u64, opening: &PedersenOpening) -> bool {
        let expected = Self::commit(value, opening);
        self.point == expected.point
    }

    /// Verify with a scalar value.
    pub fn verify_scalar(&self, value: &Scalar, opening: &PedersenOpening) -> bool {
        let expected = Self::commit_scalar(value, opening);
        self.point == expected.point
    }

    /// Get the commitment point.
    pub fn point(&self) -> &RistrettoPoint {
        &self.point
    }

    /// Compress to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Decompress from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let compressed =
            CompressedRistretto::from_slice(bytes).map_err(|_| Error::InvalidKeyFormat)?;
        let point = compressed.decompress().ok_or(Error::InvalidKeyFormat)?;
        Ok(Self { point })
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
        Self::from_bytes(&arr)
    }

    /// Add two commitments (homomorphic addition).
    ///
    /// C(a) + C(b) = C(a + b) when using the sum of openings.
    pub fn add(&self, other: &Self) -> Self {
        Self {
            point: self.point + other.point,
        }
    }

    /// Subtract two commitments.
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            point: self.point - other.point,
        }
    }

    /// Multiply by a scalar.
    pub fn mul_scalar(&self, scalar: &Scalar) -> Self {
        Self {
            point: scalar * self.point,
        }
    }

    /// Create a zero commitment (identity element).
    pub fn zero() -> Self {
        use curve25519_dalek::traits::Identity;
        Self {
            point: RistrettoPoint::identity(),
        }
    }
}

impl std::fmt::Debug for PedersenCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PedersenCommitment({}...)", &self.to_hex()[..16])
    }
}

impl std::ops::Add for PedersenCommitment {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            point: self.point + other.point,
        }
    }
}

impl std::ops::Add for &PedersenCommitment {
    type Output = PedersenCommitment;

    fn add(self, other: Self) -> PedersenCommitment {
        PedersenCommitment {
            point: self.point + other.point,
        }
    }
}

impl std::ops::Sub for PedersenCommitment {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self {
            point: self.point - other.point,
        }
    }
}

/// Vector Pedersen commitment for committing to multiple values.
pub struct VectorCommitment {
    point: RistrettoPoint,
}

impl VectorCommitment {
    /// Create a commitment to a vector of values.
    ///
    /// Uses independent generators G_1, G_2, ..., G_n, H.
    pub fn commit(values: &[u64], blinding: &Scalar) -> Self {
        let h = generator_h();
        let mut point = blinding * h;

        for (i, value) in values.iter().enumerate() {
            let g_i = Self::generator(i);
            let v = Scalar::from(*value);
            point += v * g_i;
        }

        Self { point }
    }

    /// Generate the i-th generator point.
    fn generator(index: usize) -> RistrettoPoint {
        let mut hasher = Sha512::new();
        hasher.update(b"arcanum-vector-generator");
        hasher.update(&(index as u64).to_le_bytes());
        RistrettoPoint::from_hash(hasher)
    }

    /// Get the commitment point.
    pub fn point(&self) -> &RistrettoPoint {
        &self.point
    }

    /// Compress to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
}

impl std::fmt::Debug for VectorCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VectorCommitment({} bytes)", 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_open() {
        let value = 42u64;
        let opening = PedersenOpening::random();
        let commitment = PedersenCommitment::commit(value, &opening);

        assert!(commitment.verify(value, &opening));
        assert!(!commitment.verify(43, &opening));
    }

    #[test]
    fn test_commitment_homomorphic() {
        let value1 = 10u64;
        let value2 = 20u64;
        let opening1 = PedersenOpening::random();
        let opening2 = PedersenOpening::random();

        let c1 = PedersenCommitment::commit(value1, &opening1);
        let c2 = PedersenCommitment::commit(value2, &opening2);
        let c_sum = c1.add(&c2);

        let opening_sum = opening1.add(&opening2);
        assert!(c_sum.verify(value1 + value2, &opening_sum));
    }

    #[test]
    fn test_commitment_serialization() {
        let value = 100u64;
        let opening = PedersenOpening::random();
        let commitment = PedersenCommitment::commit(value, &opening);

        let bytes = commitment.to_bytes();
        let restored = PedersenCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(commitment, restored);
    }

    #[test]
    fn test_commitment_hex() {
        let value = 100u64;
        let opening = PedersenOpening::random();
        let commitment = PedersenCommitment::commit(value, &opening);

        let hex = commitment.to_hex();
        let restored = PedersenCommitment::from_hex(&hex).unwrap();
        assert_eq!(commitment, restored);
    }

    #[test]
    fn test_opening_serialization() {
        let opening = PedersenOpening::random();
        let bytes = opening.to_bytes();
        let restored = PedersenOpening::from_bytes(&bytes).unwrap();
        assert_eq!(opening.blinding, restored.blinding);
    }

    #[test]
    fn test_commitment_subtraction() {
        let value1 = 50u64;
        let value2 = 20u64;
        let opening1 = PedersenOpening::random();
        let opening2 = PedersenOpening::random();

        let c1 = PedersenCommitment::commit(value1, &opening1);
        let c2 = PedersenCommitment::commit(value2, &opening2);
        let c_diff = c1.sub(&c2);

        let opening_diff = opening1.sub(&opening2);
        assert!(c_diff.verify(value1 - value2, &opening_diff));
    }

    #[test]
    fn test_commitment_zero() {
        let zero = PedersenCommitment::zero();
        let opening = PedersenOpening::from_scalar(Scalar::ZERO);
        assert!(zero.verify(0, &opening));
    }

    #[test]
    fn test_vector_commitment() {
        let values = vec![1u64, 2, 3, 4, 5];
        let mut blinding_bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut blinding_bytes);
        let blinding = Scalar::from_bytes_mod_order_wide(&blinding_bytes);

        let commitment = VectorCommitment::commit(&values, &blinding);
        let bytes = commitment.to_bytes();
        assert_eq!(bytes.len(), 32);
    }
}
