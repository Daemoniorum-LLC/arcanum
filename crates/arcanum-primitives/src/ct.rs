//! Constant-time operations for cryptographic code.
//!
//! These utilities ensure that operations on secret data do not leak
//! information through timing side-channels.
//!
//! # Security Model
//!
//! All operations in this module are designed to execute in constant time
//! regardless of the input values. This prevents timing attacks where an
//! adversary measures execution time to learn about secret data.
//!
//! # Example
//!
//! ```
//! use arcanum_primitives::ct::{CtBool, CtEq};
//!
//! let secret_a = [1u8, 2, 3, 4];
//! let secret_b = [1u8, 2, 3, 4];
//! let secret_c = [1u8, 2, 3, 5];
//!
//! // Constant-time comparison
//! assert!(secret_a.ct_eq(&secret_b).is_true());
//! assert!(!secret_c.ct_eq(&secret_a).is_true());
//! ```

use core::ops::{BitAnd, BitOr, BitXor, Not};
use zeroize::Zeroize;

/// A constant-time boolean value.
///
/// Internally represented as `0x00` (false) or `0xff` (true) to enable
/// constant-time selection operations.
#[derive(Clone, Copy, Debug, Zeroize)]
#[repr(transparent)]
pub struct CtBool(u8);

impl CtBool {
    /// Constant-time true value (0xff).
    pub const TRUE: Self = Self(0xff);

    /// Constant-time false value (0x00).
    pub const FALSE: Self = Self(0x00);

    /// Create a `CtBool` from a regular boolean.
    ///
    /// This operation is constant-time.
    #[inline]
    pub const fn from_bool(b: bool) -> Self {
        // Convert bool to 0 or 1, then negate to get 0x00 or 0xff
        Self((-(b as i8)) as u8)
    }

    /// Create a `CtBool` from a u8 where 0 means false, non-zero means true.
    ///
    /// This operation is constant-time.
    #[inline]
    pub const fn from_u8_nonzero(value: u8) -> Self {
        // Collapse non-zero values to 1, then convert to 0xff
        let nonzero = ((value as u16 | (value as u16).wrapping_neg()) >> 8) as u8;
        Self((-(nonzero as i8)) as u8)
    }

    /// Returns true if this represents a true value.
    ///
    /// **Warning**: This leaks timing information. Only use at the end of
    /// a computation when the result is no longer secret.
    #[inline]
    pub const fn is_true(self) -> bool {
        self.0 != 0
    }

    /// Constant-time conditional select.
    ///
    /// Returns `a` if self is true, `b` otherwise.
    #[inline]
    pub fn select<T: CtSelect>(self, a: T, b: T) -> T {
        T::ct_select(self, a, b)
    }

    /// Constant-time conditional swap.
    ///
    /// Swaps `a` and `b` if self is true.
    #[inline]
    pub fn swap<T: CtSelect + Copy>(self, a: &mut T, b: &mut T) {
        let old_a = *a;
        let old_b = *b;
        *a = self.select(old_b, old_a);
        *b = self.select(old_a, old_b);
    }
}

impl Default for CtBool {
    fn default() -> Self {
        Self::FALSE
    }
}

impl From<bool> for CtBool {
    #[inline]
    fn from(b: bool) -> Self {
        Self::from_bool(b)
    }
}

impl From<CtBool> for bool {
    #[inline]
    fn from(ct: CtBool) -> bool {
        ct.is_true()
    }
}

impl Not for CtBool {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(self.0 ^ 0xff)
    }
}

impl BitAnd for CtBool {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for CtBool {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitXor for CtBool {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

/// Trait for constant-time equality comparison.
pub trait CtEq {
    /// Compare two values in constant time.
    ///
    /// Returns `CtBool::TRUE` if equal, `CtBool::FALSE` otherwise.
    fn ct_eq(&self, other: &Self) -> CtBool;

    /// Compare two values for inequality in constant time.
    #[inline]
    fn ct_ne(&self, other: &Self) -> CtBool {
        !self.ct_eq(other)
    }
}

/// Trait for constant-time conditional selection.
pub trait CtSelect: Sized {
    /// Select between two values based on a condition.
    ///
    /// Returns `a` if `condition` is true, `b` otherwise.
    /// This operation is constant-time.
    fn ct_select(condition: CtBool, a: Self, b: Self) -> Self;
}

// ═══════════════════════════════════════════════════════════════════════════════
// IMPLEMENTATIONS FOR PRIMITIVE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

impl CtEq for u8 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        // XOR gives 0 if equal, non-zero otherwise
        // Then convert 0 to true, non-zero to false
        let diff = self ^ other;
        // If diff is 0, we want true (0xff)
        // If diff is non-zero, we want false (0x00)
        let is_zero = (((diff as u16).wrapping_sub(1)) >> 8) as u8;
        CtBool(is_zero)
    }
}

impl CtSelect for u8 {
    #[inline]
    fn ct_select(condition: CtBool, a: Self, b: Self) -> Self {
        // condition.0 is 0xff if true, 0x00 if false
        // (a & mask) | (b & !mask)
        (a & condition.0) | (b & !condition.0)
    }
}

impl CtEq for u32 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        let diff = self ^ other;
        // Collapse to single bit: if any bit is set, result is non-zero
        // Use wrapping_neg to get the high bit set if diff != 0
        let is_nonzero = ((diff | diff.wrapping_neg()) >> 31) as u8;
        // is_nonzero is 1 if diff != 0, 0 if diff == 0
        // We want to return true (0xff) if equal, false (0x00) if not
        let is_zero = (is_nonzero ^ 1) & 1;
        CtBool((-(is_zero as i8)) as u8)
    }
}

impl CtSelect for u32 {
    #[inline]
    fn ct_select(condition: CtBool, a: Self, b: Self) -> Self {
        let mask = (condition.0 as u32) * 0x01010101; // Broadcast to all bytes
        (a & mask) | (b & !mask)
    }
}

impl CtEq for u64 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        let diff = self ^ other;
        let is_nonzero = ((diff | diff.wrapping_neg()) >> 63) as u8;
        let is_zero = is_nonzero ^ 1;
        CtBool::from_bool(is_zero != 0)
    }
}

impl CtSelect for u64 {
    #[inline]
    fn ct_select(condition: CtBool, a: Self, b: Self) -> Self {
        let mask = (condition.0 as u64) * 0x0101010101010101;
        (a & mask) | (b & !mask)
    }
}

impl<const N: usize> CtEq for [u8; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        let mut diff = 0u8;
        for i in 0..N {
            diff |= self[i] ^ other[i];
        }
        // diff is 0 iff all bytes equal
        let is_zero = (((diff as u16).wrapping_sub(1)) >> 8) as u8;
        CtBool(is_zero)
    }
}

impl CtEq for [u8] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        // First check lengths match (this leaks length info, which is typically public)
        if self.len() != other.len() {
            return CtBool::FALSE;
        }

        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        let is_zero = (((diff as u16).wrapping_sub(1)) >> 8) as u8;
        CtBool(is_zero)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Constant-time comparison of two byte slices.
///
/// Returns true if the slices are equal, false otherwise.
/// If the slices have different lengths, returns false (length is not secret).
#[inline]
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> CtBool {
    a.ct_eq(b)
}

/// Zeroize a byte slice in a way that won't be optimized away.
#[inline]
pub fn ct_zeroize(data: &mut [u8]) {
    data.zeroize();
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // CtBool tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ct_bool_constants() {
        assert!(CtBool::TRUE.is_true());
        assert!(!CtBool::FALSE.is_true());
        assert_eq!(CtBool::TRUE.0, 0xff);
        assert_eq!(CtBool::FALSE.0, 0x00);
    }

    #[test]
    fn test_ct_bool_from_bool() {
        assert!(CtBool::from_bool(true).is_true());
        assert!(!CtBool::from_bool(false).is_true());
    }

    #[test]
    fn test_ct_bool_from_u8_nonzero() {
        assert!(!CtBool::from_u8_nonzero(0).is_true());
        assert!(CtBool::from_u8_nonzero(1).is_true());
        assert!(CtBool::from_u8_nonzero(42).is_true());
        assert!(CtBool::from_u8_nonzero(255).is_true());
    }

    #[test]
    fn test_ct_bool_not() {
        assert!(!(!CtBool::TRUE).is_true());
        assert!((!CtBool::FALSE).is_true());
    }

    #[test]
    fn test_ct_bool_and() {
        assert!((CtBool::TRUE & CtBool::TRUE).is_true());
        assert!(!(CtBool::TRUE & CtBool::FALSE).is_true());
        assert!(!(CtBool::FALSE & CtBool::TRUE).is_true());
        assert!(!(CtBool::FALSE & CtBool::FALSE).is_true());
    }

    #[test]
    fn test_ct_bool_or() {
        assert!((CtBool::TRUE | CtBool::TRUE).is_true());
        assert!((CtBool::TRUE | CtBool::FALSE).is_true());
        assert!((CtBool::FALSE | CtBool::TRUE).is_true());
        assert!(!(CtBool::FALSE | CtBool::FALSE).is_true());
    }

    #[test]
    fn test_ct_bool_xor() {
        assert!(!(CtBool::TRUE ^ CtBool::TRUE).is_true());
        assert!((CtBool::TRUE ^ CtBool::FALSE).is_true());
        assert!((CtBool::FALSE ^ CtBool::TRUE).is_true());
        assert!(!(CtBool::FALSE ^ CtBool::FALSE).is_true());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CtEq tests for u8
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_u8_ct_eq() {
        assert!(0u8.ct_eq(&0u8).is_true());
        assert!(255u8.ct_eq(&255u8).is_true());
        assert!(42u8.ct_eq(&42u8).is_true());
        assert!(!0u8.ct_eq(&1u8).is_true());
        assert!(!255u8.ct_eq(&254u8).is_true());
    }

    #[test]
    fn test_u8_ct_ne() {
        assert!(!0u8.ct_ne(&0u8).is_true());
        assert!(0u8.ct_ne(&1u8).is_true());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CtSelect tests for u8
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_u8_ct_select() {
        assert_eq!(u8::ct_select(CtBool::TRUE, 10, 20), 10);
        assert_eq!(u8::ct_select(CtBool::FALSE, 10, 20), 20);
        assert_eq!(u8::ct_select(CtBool::TRUE, 0, 255), 0);
        assert_eq!(u8::ct_select(CtBool::FALSE, 0, 255), 255);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CtEq tests for u32
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_u32_ct_eq() {
        assert!(0u32.ct_eq(&0u32).is_true());
        assert!(0xFFFFFFFFu32.ct_eq(&0xFFFFFFFFu32).is_true());
        assert!(12345678u32.ct_eq(&12345678u32).is_true());
        assert!(!0u32.ct_eq(&1u32).is_true());
        assert!(!0x80000000u32.ct_eq(&0x80000001u32).is_true());
    }

    #[test]
    fn test_u32_ct_select() {
        assert_eq!(u32::ct_select(CtBool::TRUE, 100, 200), 100);
        assert_eq!(u32::ct_select(CtBool::FALSE, 100, 200), 200);
        assert_eq!(
            u32::ct_select(CtBool::TRUE, 0xDEADBEEF, 0xCAFEBABE),
            0xDEADBEEF
        );
        assert_eq!(
            u32::ct_select(CtBool::FALSE, 0xDEADBEEF, 0xCAFEBABE),
            0xCAFEBABE
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CtEq tests for u64
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_u64_ct_eq() {
        assert!(0u64.ct_eq(&0u64).is_true());
        assert!(0xFFFFFFFFFFFFFFFFu64
            .ct_eq(&0xFFFFFFFFFFFFFFFFu64)
            .is_true());
        assert!(!0u64.ct_eq(&1u64).is_true());
        assert!(!0x8000000000000000u64
            .ct_eq(&0x8000000000000001u64)
            .is_true());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CtEq tests for byte arrays
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_byte_array_ct_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        let d = [0u8, 0, 0, 0];

        assert!(a.ct_eq(&b).is_true());
        assert!(!a.ct_eq(&c).is_true());
        assert!(!a.ct_eq(&d).is_true());
    }

    #[test]
    fn test_byte_array_ct_eq_empty() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        assert!(a.ct_eq(&b).is_true());
    }

    #[test]
    fn test_byte_array_ct_eq_32() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        assert!(a.ct_eq(&b).is_true());

        b[31] = 1;
        assert!(!a.ct_eq(&b).is_true());

        b[31] = 0;
        b[0] = 1;
        assert!(!a.ct_eq(&b).is_true());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CtEq tests for byte slices
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_byte_slice_ct_eq() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![1u8, 2, 3, 4];
        let c = vec![1u8, 2, 3, 5];

        assert!(a.as_slice().ct_eq(b.as_slice()).is_true());
        assert!(!a.as_slice().ct_eq(c.as_slice()).is_true());
    }

    #[test]
    fn test_byte_slice_ct_eq_different_lengths() {
        let a = vec![1u8, 2, 3];
        let b = vec![1u8, 2, 3, 4];

        assert!(!a.as_slice().ct_eq(b.as_slice()).is_true());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Swap tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ct_swap() {
        let mut a = 10u8;
        let mut b = 20u8;

        CtBool::TRUE.swap(&mut a, &mut b);
        assert_eq!(a, 20);
        assert_eq!(b, 10);

        CtBool::FALSE.swap(&mut a, &mut b);
        assert_eq!(a, 20); // No swap
        assert_eq!(b, 10);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helper function tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ct_eq_slice() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(ct_eq_slice(&a, &b).is_true());
        assert!(!ct_eq_slice(&a, &c).is_true());
    }
}
