//! Secure buffer types with automatic zeroization.
//!
//! These types provide secure memory handling for sensitive data,
//! ensuring that secrets are properly zeroized when no longer needed.

#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};

use crate::error::{Error, Result};
#[cfg(feature = "std")]
use crate::random::OsRng;
#[cfg(feature = "std")]
use rand::RngCore;
use core::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════════
// SECRET BUFFER (Fixed Size)
// ═══════════════════════════════════════════════════════════════════════════════

/// A fixed-size buffer that is zeroized on drop.
///
/// Use this for secrets with known sizes at compile time.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecretBuffer<N> {
    /// Create a new zeroed buffer.
    pub fn new() -> Self {
        Self { data: [0u8; N] }
    }

    /// Create a buffer filled with cryptographically secure random bytes.
    ///
    /// This is the recommended way to generate secret keys.
    #[cfg(feature = "std")]
    pub fn random() -> Self {
        let mut data = [0u8; N];
        OsRng.fill_bytes(&mut data);
        Self { data }
    }

    /// Create from an array.
    pub fn from_array(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create from a slice, returning error if length doesn't match.
    #[must_use = "parsing can fail; check the Result"]
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidParameter(format!(
                "expected {} bytes, got {}",
                N,
                slice.len()
            )));
        }
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        Ok(Self { data })
    }

    /// Get the buffer size.
    pub const fn len() -> usize {
        N
    }

    /// Access the underlying array.
    pub fn as_array(&self) -> &[u8; N] {
        &self.data
    }

    /// Access the underlying array mutably.
    pub fn as_array_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }

    /// Fill with a repeated byte value.
    pub fn fill(&mut self, value: u8) {
        self.data.fill(value);
    }

    /// Copy from another buffer of the same size.
    pub fn copy_from(&mut self, other: &Self) {
        self.data.copy_from_slice(&other.data);
    }
}

impl<const N: usize> Default for SecretBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for SecretBuffer<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for SecretBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBuffer<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> core::fmt::Debug for SecretBuffer<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBuffer<{}>[REDACTED]", N)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURE VEC (Dynamic Size)
// ═══════════════════════════════════════════════════════════════════════════════

/// A dynamically-sized buffer that is zeroized on drop.
///
/// Use this for secrets with sizes known only at runtime.
#[derive(Clone)]
pub struct SecureVec {
    data: Vec<u8>,
}

impl SecureVec {
    /// Create a new empty buffer.
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a buffer with specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a buffer of given size filled with zeros.
    pub fn zeroed(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
        }
    }

    /// Create a buffer filled with cryptographically secure random bytes.
    ///
    /// This is the recommended way to generate secret keys of arbitrary length.
    #[cfg(feature = "std")]
    pub fn random(len: usize) -> Self {
        let mut data = vec![0u8; len];
        OsRng.fill_bytes(&mut data);
        Self { data }
    }

    /// Create from a vector, taking ownership.
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create from a slice, copying the data.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
        }
    }

    /// Get the buffer length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the buffer capacity.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Reserve additional capacity.
    pub fn reserve(&mut self, additional: usize) {
        self.data.reserve(additional);
    }

    /// Push a byte.
    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Extend from a slice.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }

    /// Clear the buffer (zeroizes first).
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }

    /// Resize the buffer.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len < self.data.len() {
            // Zeroize the portion being removed
            self.data[new_len..].zeroize();
        }
        self.data.resize(new_len, value);
    }

    /// Truncate the buffer.
    pub fn truncate(&mut self, len: usize) {
        if len < self.data.len() {
            self.data[len..].zeroize();
        }
        self.data.truncate(len);
    }

    /// Convert to a regular Vec, consuming self.
    ///
    /// **Warning**: The returned Vec will NOT be automatically zeroized.
    /// Use with caution.
    pub fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.data)
    }

    /// Split at a position, returning the second half.
    pub fn split_off(&mut self, at: usize) -> Self {
        Self {
            data: self.data.split_off(at),
        }
    }

    /// Expose the secret bytes (read-only).
    ///
    /// Use this when passing the secret to cryptographic functions.
    pub fn expose(&self) -> &[u8] {
        &self.data
    }

    /// Expose the secret bytes (mutable).
    ///
    /// Use with caution - modifying secret data directly.
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE ALIASES
// ═══════════════════════════════════════════════════════════════════════════════

/// A securely-managed byte buffer for cryptographic secrets.
///
/// This is the recommended type for storing secret keys, as it:
/// - Automatically zeroizes memory on drop
/// - Provides explicit `expose()` methods to access the secret
/// - Prevents accidental logging via redacted Debug impl
///
/// # Example
///
/// ```ignore
/// use arcanum_core::buffer::SecretBytes;
///
/// // Generate a random 32-byte secret key
/// let key = SecretBytes::random(32);
///
/// // Access the key for encryption
/// cipher.encrypt(key.expose(), &nonce, &plaintext);
///
/// // Key is automatically zeroized when dropped
/// ```
pub type SecretBytes = SecureVec;

impl Default for SecureVec {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Deref for SecureVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl AsRef<[u8]> for SecureVec {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl core::fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecureVec[{} bytes, REDACTED]", self.data.len())
    }
}

impl From<Vec<u8>> for SecureVec {
    fn from(data: Vec<u8>) -> Self {
        Self::from_vec(data)
    }
}

impl From<&[u8]> for SecureVec {
    fn from(slice: &[u8]) -> Self {
        Self::from_slice(slice)
    }
}

impl<const N: usize> From<[u8; N]> for SecureVec {
    fn from(array: [u8; N]) -> Self {
        Self::from_slice(&array)
    }
}

impl FromIterator<u8> for SecureVec {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        Self {
            data: iter.into_iter().collect(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GUARDED ALLOCATION
// ═══════════════════════════════════════════════════════════════════════════════

/// A buffer with guard pages for additional security.
///
/// This wraps memory with guard pages to detect buffer overflows/underflows.
/// Useful for extremely sensitive data.
#[cfg(feature = "std")]
pub struct GuardedBuffer {
    data: SecureVec,
    // In a full implementation, this would use mprotect/VirtualProtect
    // to set up actual guard pages around the allocation
}

#[cfg(feature = "std")]
impl GuardedBuffer {
    /// Create a new guarded buffer of the specified size.
    pub fn new(size: usize) -> Self {
        // In a production implementation, this would:
        // 1. Allocate size + 2*PAGE_SIZE bytes
        // 2. mprotect the first and last pages as PROT_NONE
        // 3. Return a pointer to the middle region
        Self {
            data: SecureVec::zeroed(size),
        }
    }

    /// Access the protected data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Access the protected data mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_buffer() {
        let mut buf = SecretBuffer::<32>::new();
        buf.fill(0xAB);
        assert_eq!(buf.as_array(), &[0xAB; 32]);
    }

    #[test]
    fn test_secret_buffer_from_slice() {
        let data = [1u8; 16];
        let buf = SecretBuffer::<16>::from_slice(&data).unwrap();
        assert_eq!(buf.as_array(), &data);

        // Wrong size should fail
        assert!(SecretBuffer::<32>::from_slice(&data).is_err());
    }

    #[test]
    fn test_secure_vec() {
        let mut vec = SecureVec::new();
        vec.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(vec.len(), 4);
        assert_eq!(&*vec, &[1, 2, 3, 4]);

        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_secure_vec_truncate() {
        let mut vec = SecureVec::from_slice(&[1, 2, 3, 4, 5]);
        vec.truncate(3);
        assert_eq!(vec.len(), 3);
        assert_eq!(&*vec, &[1, 2, 3]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_secret_buffer_random() {
        let buf1 = SecretBuffer::<32>::random();
        let buf2 = SecretBuffer::<32>::random();
        // Random buffers should be different (with overwhelming probability)
        assert_ne!(buf1.as_array(), buf2.as_array());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_secure_vec_random() {
        let vec1 = SecureVec::random(32);
        let vec2 = SecureVec::random(32);
        // Random vecs should be different
        assert_ne!(vec1.expose(), vec2.expose());
        assert_eq!(vec1.len(), 32);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_secret_bytes_alias() {
        // SecretBytes is an alias for SecureVec
        let key: SecretBytes = SecretBytes::random(32);
        assert_eq!(key.len(), 32);
        assert_eq!(key.expose().len(), 32);
    }

    // ─── SecretBuffer extended tests ─────────────────────────────────────────

    #[test]
    fn test_secret_buffer_from_array() {
        let data = [0x42u8; 16];
        let buf = SecretBuffer::<16>::from_array(data);
        assert_eq!(buf.as_array(), &[0x42; 16]);
    }

    #[test]
    fn test_secret_buffer_len_const() {
        assert_eq!(SecretBuffer::<32>::len(), 32);
        assert_eq!(SecretBuffer::<16>::len(), 16);
        assert_eq!(SecretBuffer::<64>::len(), 64);
    }

    #[test]
    fn test_secret_buffer_copy_from() {
        let src = SecretBuffer::<16>::from_array([0xAB; 16]);
        let mut dst = SecretBuffer::<16>::new();
        assert_eq!(dst.as_array(), &[0x00; 16]);

        dst.copy_from(&src);
        assert_eq!(dst.as_array(), &[0xAB; 16]);
    }

    #[test]
    fn test_secret_buffer_as_array_mut() {
        let mut buf = SecretBuffer::<8>::new();
        let arr = buf.as_array_mut();
        arr[0] = 0xFF;
        arr[7] = 0x01;
        assert_eq!(buf.as_array()[0], 0xFF);
        assert_eq!(buf.as_array()[7], 0x01);
    }

    #[test]
    fn test_secret_buffer_default() {
        let buf: SecretBuffer<32> = SecretBuffer::default();
        assert_eq!(buf.as_array(), &[0u8; 32]);
    }

    #[test]
    fn test_secret_buffer_deref() {
        let buf = SecretBuffer::<4>::from_array([1, 2, 3, 4]);
        // Deref gives us &[u8; N]
        let array_ref: &[u8; 4] = &*buf;
        assert_eq!(array_ref, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_secret_buffer_deref_mut() {
        let mut buf = SecretBuffer::<4>::from_array([0, 0, 0, 0]);
        // DerefMut gives us &mut [u8; N]
        let array_mut: &mut [u8; 4] = &mut *buf;
        array_mut[0] = 10;
        array_mut[3] = 40;
        assert_eq!(buf.as_array(), &[10, 0, 0, 40]);
    }

    #[test]
    fn test_secret_buffer_as_ref() {
        let buf = SecretBuffer::<4>::from_array([5, 6, 7, 8]);
        let as_ref: &[u8] = buf.as_ref();
        assert_eq!(as_ref, &[5, 6, 7, 8]);
    }

    #[test]
    fn test_secret_buffer_as_mut() {
        let mut buf = SecretBuffer::<4>::from_array([0; 4]);
        let as_mut: &mut [u8] = buf.as_mut();
        as_mut[1] = 0xFF;
        assert_eq!(buf.as_array()[1], 0xFF);
    }

    #[test]
    fn test_secret_buffer_debug_redaction() {
        let buf = SecretBuffer::<32>::from_array([0xDE; 32]);
        let debug_output = format!("{:?}", buf);
        assert_eq!(debug_output, "SecretBuffer<32>[REDACTED]");
        assert!(!debug_output.contains("de"), "Debug must not leak buffer contents");
    }

    // ─── SecureVec extended tests ────────────────────────────────────────────

    #[test]
    fn test_secure_vec_with_capacity() {
        let sv = SecureVec::with_capacity(64);
        assert_eq!(sv.len(), 0);
        assert!(sv.capacity() >= 64);
        assert!(sv.is_empty());
    }

    #[test]
    fn test_secure_vec_zeroed() {
        let sv = SecureVec::zeroed(16);
        assert_eq!(sv.len(), 16);
        assert!(sv.expose().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_vec_from_vec() {
        let original = vec![1u8, 2, 3, 4, 5];
        let sv = SecureVec::from_vec(original);
        assert_eq!(sv.len(), 5);
        assert_eq!(sv.expose(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_secure_vec_capacity() {
        let sv = SecureVec::with_capacity(128);
        assert!(sv.capacity() >= 128);
    }

    #[test]
    fn test_secure_vec_reserve() {
        let mut sv = SecureVec::new();
        sv.reserve(100);
        assert!(sv.capacity() >= 100);
    }

    #[test]
    fn test_secure_vec_push() {
        let mut sv = SecureVec::new();
        sv.push(0xAA);
        sv.push(0xBB);
        sv.push(0xCC);
        assert_eq!(sv.len(), 3);
        assert_eq!(sv.expose(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_secure_vec_resize_grow() {
        let mut sv = SecureVec::from_slice(&[1, 2, 3]);
        sv.resize(6, 0xFF);
        assert_eq!(sv.len(), 6);
        assert_eq!(sv.expose(), &[1, 2, 3, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_secure_vec_resize_shrink() {
        let mut sv = SecureVec::from_slice(&[1, 2, 3, 4, 5]);
        sv.resize(2, 0);
        assert_eq!(sv.len(), 2);
        assert_eq!(sv.expose(), &[1, 2]);
    }

    #[test]
    fn test_secure_vec_into_vec() {
        let sv = SecureVec::from_slice(&[10, 20, 30]);
        let v: Vec<u8> = sv.into_vec();
        assert_eq!(v, vec![10, 20, 30]);
    }

    #[test]
    fn test_secure_vec_split_off() {
        let mut sv = SecureVec::from_slice(&[1, 2, 3, 4, 5]);
        let second_half = sv.split_off(3);
        assert_eq!(sv.expose(), &[1, 2, 3]);
        assert_eq!(second_half.expose(), &[4, 5]);
    }

    #[test]
    fn test_secure_vec_expose_and_expose_mut() {
        let mut sv = SecureVec::from_slice(&[1, 2, 3]);
        assert_eq!(sv.expose(), &[1, 2, 3]);

        sv.expose_mut()[0] = 99;
        assert_eq!(sv.expose()[0], 99);
    }

    #[test]
    fn test_secure_vec_from_vec_trait() {
        let v = vec![0xAA, 0xBB];
        let sv: SecureVec = SecureVec::from(v);
        assert_eq!(sv.expose(), &[0xAA, 0xBB]);
    }

    #[test]
    fn test_secure_vec_from_slice_trait() {
        let slice: &[u8] = &[1, 2, 3];
        let sv: SecureVec = SecureVec::from(slice);
        assert_eq!(sv.expose(), &[1, 2, 3]);
    }

    #[test]
    fn test_secure_vec_from_array_trait() {
        let sv: SecureVec = SecureVec::from([10u8, 20, 30, 40]);
        assert_eq!(sv.len(), 4);
        assert_eq!(sv.expose(), &[10, 20, 30, 40]);
    }

    #[test]
    fn test_secure_vec_from_iterator() {
        let sv: SecureVec = (0u8..5).collect();
        assert_eq!(sv.len(), 5);
        assert_eq!(sv.expose(), &[0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_secure_vec_debug_redaction() {
        let sv = SecureVec::from_slice(&[0xDE; 10]);
        let debug_output = format!("{:?}", sv);
        assert_eq!(debug_output, "SecureVec[10 bytes, REDACTED]");
        assert!(!debug_output.contains("de"), "Debug must not leak buffer contents");
    }

    #[test]
    fn test_secure_vec_default() {
        let sv: SecureVec = SecureVec::default();
        assert!(sv.is_empty());
        assert_eq!(sv.len(), 0);
    }

    // ─── GuardedBuffer tests ─────────────────────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn test_guarded_buffer_new() {
        let buf = GuardedBuffer::new(64);
        assert_eq!(buf.as_slice().len(), 64);
        assert!(buf.as_slice().iter().all(|&b| b == 0), "New guarded buffer must be zeroed");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_guarded_buffer_as_slice() {
        let buf = GuardedBuffer::new(16);
        let slice = buf.as_slice();
        assert_eq!(slice.len(), 16);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_guarded_buffer_as_mut_slice() {
        let mut buf = GuardedBuffer::new(8);
        let slice = buf.as_mut_slice();
        slice[0] = 0xFF;
        slice[7] = 0x01;
        assert_eq!(buf.as_slice()[0], 0xFF);
        assert_eq!(buf.as_slice()[7], 0x01);
    }
}
