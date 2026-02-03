//! Poly1305 message authentication code.
//!
//! Native implementation following RFC 8439.
//!
//! Poly1305 is a one-time authenticator designed by Daniel J. Bernstein.
//! It takes a 32-byte one-time key and a message and produces a 16-byte tag.
//!
//! # Security
//!
//! The key MUST be unique for each message. Reusing a key is catastrophic.
//! In ChaCha20-Poly1305, the Poly1305 key is derived from the ChaCha20 keystream.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_primitives::poly1305::Poly1305;
//!
//! let key = [0u8; 32]; // In practice, use ChaCha20 to derive this
//! let message = b"Cryptographic Forum Research Group";
//!
//! let tag = Poly1305::mac(&key, message);
//! assert!(Poly1305::verify(&key, message, &tag));
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Poly1305 key size in bytes
pub const KEY_SIZE: usize = 32;

/// Poly1305 tag size in bytes
pub const TAG_SIZE: usize = 16;

/// Poly1305 block size in bytes
pub const BLOCK_SIZE: usize = 16;

// ═══════════════════════════════════════════════════════════════════════════════
// CLAMPING
// ═══════════════════════════════════════════════════════════════════════════════

/// Clamp the r value according to RFC 8439.
///
/// Certain bits of r are required to be 0:
/// - Top 4 bits of bytes 3, 7, 11, 15 are cleared
/// - Bottom 2 bits of bytes 4, 8, 12 are cleared
#[inline]
fn clamp(r: &mut [u8; 16]) {
    r[3] &= 0x0f;
    r[7] &= 0x0f;
    r[11] &= 0x0f;
    r[15] &= 0x0f;
    r[4] &= 0xfc;
    r[8] &= 0xfc;
    r[12] &= 0xfc;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 130-BIT ARITHMETIC
// ═══════════════════════════════════════════════════════════════════════════════

/// 130-bit number represented as 5 x 26-bit limbs.
///
/// This representation allows efficient multiplication without overflow
/// when using 64-bit arithmetic.
#[derive(Clone, Copy, Zeroize)]
struct U130 {
    limbs: [u64; 5],
}

impl U130 {
    /// Create a zero value.
    #[inline]
    const fn zero() -> Self {
        Self { limbs: [0; 5] }
    }

    /// Load a 128-bit value from little-endian bytes.
    #[inline]
    fn from_le_bytes_128(bytes: &[u8; 16]) -> Self {
        // Split into 26-bit limbs
        let mut limbs = [0u64; 5];

        // Read as little-endian u64s
        // Safety: split_at(8) on a 16-byte array yields two 8-byte slices
        let (lo_half, hi_half) = bytes.split_at(8);
        let lo = u64::from_le_bytes([
            lo_half[0], lo_half[1], lo_half[2], lo_half[3],
            lo_half[4], lo_half[5], lo_half[6], lo_half[7],
        ]);
        let hi = u64::from_le_bytes([
            hi_half[0], hi_half[1], hi_half[2], hi_half[3],
            hi_half[4], hi_half[5], hi_half[6], hi_half[7],
        ]);

        limbs[0] = lo & 0x3ffffff;
        limbs[1] = (lo >> 26) & 0x3ffffff;
        limbs[2] = ((lo >> 52) | (hi << 12)) & 0x3ffffff;
        limbs[3] = (hi >> 14) & 0x3ffffff;
        limbs[4] = hi >> 40;

        Self { limbs }
    }

    /// Load a 16-byte block with the high bit set (for Poly1305 padding).
    #[inline]
    fn from_block(block: &[u8; 16]) -> Self {
        let mut result = Self::from_le_bytes_128(block);
        // Set bit 128 (hibit)
        result.limbs[4] |= 1 << 24;
        result
    }

    /// Load a partial block (< 16 bytes) with high bit.
    #[inline]
    fn from_partial_block(block: &[u8]) -> Self {
        debug_assert!(block.len() < 16);
        let mut padded = [0u8; 16];
        padded[..block.len()].copy_from_slice(block);
        padded[block.len()] = 0x01; // Pad with 0x01

        Self::from_le_bytes_128(&padded)
    }

    /// Add two 130-bit numbers.
    #[inline]
    fn add(&self, other: &Self) -> Self {
        let mut limbs = [0u64; 5];
        for i in 0..5 {
            limbs[i] = self.limbs[i] + other.limbs[i];
        }
        Self { limbs }
    }

    /// Multiply by r and reduce modulo 2^130 - 5.
    ///
    /// This uses the fact that 2^130 ≡ 5 (mod 2^130 - 5).
    #[inline]
    fn mul_reduce(&self, r: &Self) -> Self {
        // Full multiplication producing 260-bit result
        let mut t = [0u128; 5];

        // Precompute 5*r for reduction
        let r0 = r.limbs[0] as u128;
        let r1 = r.limbs[1] as u128;
        let r2 = r.limbs[2] as u128;
        let r3 = r.limbs[3] as u128;
        let r4 = r.limbs[4] as u128;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let h0 = self.limbs[0] as u128;
        let h1 = self.limbs[1] as u128;
        let h2 = self.limbs[2] as u128;
        let h3 = self.limbs[3] as u128;
        let h4 = self.limbs[4] as u128;

        // Schoolbook multiplication with reduction
        t[0] = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        t[1] = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        t[2] = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        t[3] = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        t[4] = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Carry propagation (partial)
        let mut c: u128;
        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;

        c = t[1] >> 26;
        t[1] &= 0x3ffffff;
        t[2] += c;

        c = t[2] >> 26;
        t[2] &= 0x3ffffff;
        t[3] += c;

        c = t[3] >> 26;
        t[3] &= 0x3ffffff;
        t[4] += c;

        c = t[4] >> 26;
        t[4] &= 0x3ffffff;
        t[0] += c * 5; // Reduce: 2^130 ≡ 5

        c = t[0] >> 26;
        t[0] &= 0x3ffffff;
        t[1] += c;

        Self {
            limbs: [
                t[0] as u64,
                t[1] as u64,
                t[2] as u64,
                t[3] as u64,
                t[4] as u64,
            ],
        }
    }

    /// Finalize: fully reduce and add s to get the 128-bit tag.
    #[inline]
    fn finalize(&self, s: &[u8; 16]) -> [u8; 16] {
        let mut h = *self;

        // Full carry propagation
        let mut c = h.limbs[0] >> 26;
        h.limbs[0] &= 0x3ffffff;
        h.limbs[1] += c;

        c = h.limbs[1] >> 26;
        h.limbs[1] &= 0x3ffffff;
        h.limbs[2] += c;

        c = h.limbs[2] >> 26;
        h.limbs[2] &= 0x3ffffff;
        h.limbs[3] += c;

        c = h.limbs[3] >> 26;
        h.limbs[3] &= 0x3ffffff;
        h.limbs[4] += c;

        c = h.limbs[4] >> 26;
        h.limbs[4] &= 0x3ffffff;
        h.limbs[0] += c * 5;

        c = h.limbs[0] >> 26;
        h.limbs[0] &= 0x3ffffff;
        h.limbs[1] += c;

        // Compute h - p = h - (2^130 - 5) = h + 5 - 2^130
        // If h >= p, we need to reduce
        let mut g = [0u64; 5];
        g[0] = h.limbs[0].wrapping_add(5);
        c = g[0] >> 26;
        g[0] &= 0x3ffffff;

        g[1] = h.limbs[1].wrapping_add(c);
        c = g[1] >> 26;
        g[1] &= 0x3ffffff;

        g[2] = h.limbs[2].wrapping_add(c);
        c = g[2] >> 26;
        g[2] &= 0x3ffffff;

        g[3] = h.limbs[3].wrapping_add(c);
        c = g[3] >> 26;
        g[3] &= 0x3ffffff;

        g[4] = h.limbs[4].wrapping_add(c).wrapping_sub(1 << 26);

        // Select h if g >= 2^130, else select g
        // mask is all 1s if g[4] >= 2^26 (i.e., g overflowed), 0 otherwise
        let mask = (g[4] >> 63).wrapping_sub(1); // 0 if overflow, all 1s otherwise

        h.limbs[0] = (h.limbs[0] & !mask) | (g[0] & mask);
        h.limbs[1] = (h.limbs[1] & !mask) | (g[1] & mask);
        h.limbs[2] = (h.limbs[2] & !mask) | (g[2] & mask);
        h.limbs[3] = (h.limbs[3] & !mask) | (g[3] & mask);
        h.limbs[4] = (h.limbs[4] & !mask) | (g[4] & mask);

        // Convert to 128-bit little-endian
        let h0 = h.limbs[0] | (h.limbs[1] << 26) | (h.limbs[2] << 52);
        let h1 = (h.limbs[2] >> 12) | (h.limbs[3] << 14) | (h.limbs[4] << 40);

        // Add s
        // Safety: split_at(8) on a 16-byte array yields two 8-byte slices
        let (s_lo_half, s_hi_half) = s.split_at(8);
        let s_lo = u64::from_le_bytes([
            s_lo_half[0], s_lo_half[1], s_lo_half[2], s_lo_half[3],
            s_lo_half[4], s_lo_half[5], s_lo_half[6], s_lo_half[7],
        ]);
        let s_hi = u64::from_le_bytes([
            s_hi_half[0], s_hi_half[1], s_hi_half[2], s_hi_half[3],
            s_hi_half[4], s_hi_half[5], s_hi_half[6], s_hi_half[7],
        ]);

        let (r0, carry) = h0.overflowing_add(s_lo);
        let r1 = h1.wrapping_add(s_hi).wrapping_add(carry as u64);

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&r0.to_le_bytes());
        tag[8..16].copy_from_slice(&r1.to_le_bytes());

        tag
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// POLY1305 MAC
// ═══════════════════════════════════════════════════════════════════════════════

/// Poly1305 message authentication code.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305 {
    /// The r value (clamped)
    r: U130,
    /// The s value (second half of key)
    s: [u8; 16],
    /// The accumulator
    acc: U130,
    /// Buffer for incomplete blocks
    buffer: [u8; 16],
    /// Position in buffer
    buffer_pos: usize,
}

impl Poly1305 {
    /// Create a new Poly1305 instance with the given key.
    ///
    /// The key is split into r (clamped) and s.
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        // Split key into r (first 16 bytes) and s (last 16 bytes)
        let (r_half, s_half) = key.split_at(16);
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(r_half);
        clamp(&mut r_bytes);
        let r = U130::from_le_bytes_128(&r_bytes);

        let mut s = [0u8; 16];
        s.copy_from_slice(s_half);

        Self {
            r,
            s,
            acc: U130::zero(),
            buffer: [0u8; 16],
            buffer_pos: 0,
        }
    }

    /// Process more message data.
    pub fn update(&mut self, data: &[u8]) {
        let mut remaining = data;

        // Fill buffer if we have leftover data
        if self.buffer_pos > 0 {
            let needed = BLOCK_SIZE - self.buffer_pos;
            let available = remaining.len().min(needed);
            self.buffer[self.buffer_pos..self.buffer_pos + available]
                .copy_from_slice(&remaining[..available]);
            self.buffer_pos += available;
            remaining = &remaining[available..];

            if self.buffer_pos == BLOCK_SIZE {
                let block = U130::from_block(&self.buffer);
                self.acc = self.acc.add(&block).mul_reduce(&self.r);
                self.buffer_pos = 0;
            }
        }

        // Process full blocks using chunks_exact (guaranteed 16-byte slices)
        let chunks = remaining.chunks_exact(BLOCK_SIZE);
        let tail = chunks.remainder();

        for chunk in chunks {
            // chunks_exact guarantees each chunk is exactly BLOCK_SIZE bytes
            let block_bytes: &[u8; 16] = chunk.try_into().expect(
                "chunks_exact(16) yields 16-byte slices"
            );
            let block = U130::from_block(block_bytes);
            self.acc = self.acc.add(&block).mul_reduce(&self.r);
        }

        // Save remaining bytes (guaranteed < BLOCK_SIZE by chunks_exact)
        if !tail.is_empty() {
            self.buffer[..tail.len()].copy_from_slice(tail);
            self.buffer_pos = tail.len();
        }
    }

    /// Finalize and return the 16-byte tag.
    pub fn finalize(mut self) -> [u8; TAG_SIZE] {
        // Process any remaining partial block
        if self.buffer_pos > 0 {
            let block = U130::from_partial_block(&self.buffer[..self.buffer_pos]);
            self.acc = self.acc.add(&block).mul_reduce(&self.r);
        }

        self.acc.finalize(&self.s)
    }

    /// Compute the MAC in one shot.
    pub fn mac(key: &[u8; KEY_SIZE], message: &[u8]) -> [u8; TAG_SIZE] {
        let mut poly = Self::new(key);
        poly.update(message);
        poly.finalize()
    }

    /// Verify a MAC tag.
    ///
    /// Returns true if the tag matches, false otherwise.
    /// Uses constant-time comparison.
    pub fn verify(key: &[u8; KEY_SIZE], message: &[u8], tag: &[u8; TAG_SIZE]) -> bool {
        use crate::ct::CtEq;
        let computed = Self::mac(key, message);
        computed.ct_eq(tag).is_true()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    // RFC 8439 Section 2.5.2 test vector
    #[test]
    fn test_poly1305_rfc8439() {
        let key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let key: [u8; 32] = key.try_into().unwrap();

        let message = b"Cryptographic Forum Research Group";

        let tag = Poly1305::mac(&key, message);

        let expected = hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9");

        assert_eq!(
            bytes_to_hex(&tag),
            bytes_to_hex(&expected),
            "RFC 8439 test vector failed"
        );
    }

    // Test with empty message
    #[test]
    fn test_poly1305_empty() {
        let key = [0x42u8; 32];
        let tag = Poly1305::mac(&key, b"");

        // Empty message should produce a valid tag (just s)
        assert_eq!(tag.len(), 16);
    }

    // Test key clamping
    #[test]
    fn test_clamp() {
        let mut r = [0xffu8; 16];
        clamp(&mut r);

        // Check clamped bits
        assert_eq!(r[3] & 0xf0, 0);
        assert_eq!(r[7] & 0xf0, 0);
        assert_eq!(r[11] & 0xf0, 0);
        assert_eq!(r[15] & 0xf0, 0);
        assert_eq!(r[4] & 0x03, 0);
        assert_eq!(r[8] & 0x03, 0);
        assert_eq!(r[12] & 0x03, 0);
    }

    // Test incremental vs one-shot
    #[test]
    fn test_poly1305_incremental() {
        let key = [0x42u8; 32];
        let message = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let tag1 = Poly1305::mac(&key, message);

        // Incremental (various chunk sizes)
        let mut poly = Poly1305::new(&key);
        poly.update(&message[..10]);
        poly.update(&message[10..25]);
        poly.update(&message[25..]);
        let tag2 = poly.finalize();

        assert_eq!(tag1, tag2);
    }

    // Test byte-by-byte
    #[test]
    fn test_poly1305_byte_by_byte() {
        let key = [0x42u8; 32];
        let message = b"Hello, Poly1305!";

        // One-shot
        let tag1 = Poly1305::mac(&key, message);

        // Byte-by-byte
        let mut poly = Poly1305::new(&key);
        for byte in message {
            poly.update(&[*byte]);
        }
        let tag2 = poly.finalize();

        assert_eq!(tag1, tag2);
    }

    // Test verification
    #[test]
    fn test_poly1305_verify() {
        let key = [0x42u8; 32];
        let message = b"Test message";

        let tag = Poly1305::mac(&key, message);

        // Valid tag should verify
        assert!(Poly1305::verify(&key, message, &tag));

        // Modified tag should fail
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert!(!Poly1305::verify(&key, message, &bad_tag));

        // Modified message should fail
        let bad_message = b"Test messag!";
        assert!(!Poly1305::verify(&key, bad_message, &tag));
    }

    // Test with messages of various lengths
    #[test]
    fn test_poly1305_various_lengths() {
        let key = [0x42u8; 32];

        for len in [1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 256, 1000] {
            let message = vec![0xAB; len];
            let tag1 = Poly1305::mac(&key, &message);

            // Verify the tag
            assert!(Poly1305::verify(&key, &message, &tag1));

            // Also test incremental with 7-byte chunks
            let mut poly = Poly1305::new(&key);
            for chunk in message.chunks(7) {
                poly.update(chunk);
            }
            let tag2 = poly.finalize();

            assert_eq!(tag1, tag2, "Mismatch for length {}", len);
        }
    }

    // Test deterministic output
    #[test]
    fn test_poly1305_deterministic() {
        let key = [0x42u8; 32];
        let message = b"Deterministic test";

        let tag1 = Poly1305::mac(&key, message);
        let tag2 = Poly1305::mac(&key, message);

        assert_eq!(tag1, tag2);
    }

    // Test different keys produce different tags
    #[test]
    fn test_poly1305_different_keys() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let message = b"Same message";

        let tag1 = Poly1305::mac(&key1, message);
        let tag2 = Poly1305::mac(&key2, message);

        assert_ne!(tag1, tag2);
    }

    // Additional RFC 8439 test: Section 2.5.2 example breakdown
    #[test]
    fn test_poly1305_rfc_key_clamping() {
        // Test that r is properly clamped
        let key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");

        // First 16 bytes (r) before clamping: 85d6be7857556d337f4452fe42d506a8
        // After clamping certain bits should be 0

        let mut r = [0u8; 16];
        r.copy_from_slice(&key[0..16]);
        let original_r = r;
        clamp(&mut r);

        // r should be modified
        assert_ne!(r, original_r);

        // Verify specific clamped values
        // r[3] &= 0x0f means top 4 bits of byte 3 are 0
        assert_eq!(r[3] & 0xf0, 0);
    }

    // Test U130 arithmetic
    #[test]
    fn test_u130_from_bytes() {
        // Test loading all zeros
        let zeros = [0u8; 16];
        let u = U130::from_le_bytes_128(&zeros);
        assert_eq!(u.limbs, [0, 0, 0, 0, 0]);

        // Test loading all 0xff
        let ones = [0xffu8; 16];
        let u = U130::from_le_bytes_128(&ones);
        // Should have non-zero limbs
        assert!(u.limbs.iter().any(|&x| x != 0));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ROBUSTNESS TESTS (Release Roadmap §1.2)
    // ═══════════════════════════════════════════════════════════════════════════

    // Test all input sizes from 0 to 100 — no panics for any size
    #[test]
    fn test_poly1305_all_sizes_0_to_100() {
        let key = [0x42u8; 32];

        for size in 0..=100 {
            let input = vec![0xAB; size];
            let mut poly = Poly1305::new(&key);
            poly.update(&input);
            let tag = poly.finalize();
            assert_eq!(tag.len(), 16, "Tag length wrong at input size {}", size);
        }
    }

    // Test multiple unaligned updates that don't sum to block boundaries
    #[test]
    fn test_poly1305_multiple_unaligned_updates() {
        let key = [0x42u8; 32];

        // One-shot reference
        let full_msg: Vec<u8> = (0..=20).collect();
        let tag_ref = Poly1305::mac(&key, &full_msg);

        // Split into odd-sized updates: 3 + 5 + 1 + 11 + 1 = 21 bytes
        let mut poly = Poly1305::new(&key);
        poly.update(&full_msg[0..3]);
        poly.update(&full_msg[3..8]);
        poly.update(&full_msg[8..9]);
        poly.update(&full_msg[9..20]);
        poly.update(&full_msg[20..21]);
        let tag = poly.finalize();

        assert_eq!(tag, tag_ref);
    }

    // Test large input (1MB) — ensures no overflow or panic
    #[test]
    fn test_poly1305_large_input() {
        let key = [0x42u8; 32];
        let input = vec![0xCD; 1_000_000];

        let mut poly = Poly1305::new(&key);
        poly.update(&input);
        let tag = poly.finalize();
        assert_eq!(tag.len(), 16);

        // Verify against one-shot
        let tag_ref = Poly1305::mac(&key, &input);
        assert_eq!(tag, tag_ref);
    }

    // Test single-byte updates for sizes crossing block boundaries
    #[test]
    fn test_poly1305_single_byte_boundary_cross() {
        let key = [0x42u8; 32];

        // Build a message that's exactly 2.5 blocks (40 bytes)
        let message: Vec<u8> = (0..40).collect();
        let tag_ref = Poly1305::mac(&key, &message);

        // Feed one byte at a time
        let mut poly = Poly1305::new(&key);
        for &byte in &message {
            poly.update(&[byte]);
        }
        let tag = poly.finalize();

        assert_eq!(tag, tag_ref);
    }
}
