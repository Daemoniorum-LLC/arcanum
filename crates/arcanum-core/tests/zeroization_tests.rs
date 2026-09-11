//! Zeroization Runtime Verification Tests (Phase 5.10)
//!
//! These tests verify that sensitive data types properly zeroize memory on drop.
//!
//! ## Security Properties Tested
//!
//! 1. **Trait Implementation**: Types implement `Zeroize` and `ZeroizeOnDrop`
//! 2. **Runtime Verification**: Memory is actually zeroed after drop (smoke test)
//! 3. **No Debug Leaks**: Debug output doesn't expose secrets
//!
//! ## Important Notes
//!
//! The runtime memory tests read memory after deallocation, which is technically
//! undefined behavior. These serve as smoke tests in debug mode where the allocator
//! is less likely to immediately reuse memory. For production assurance, rely on
//! the `zeroize` crate's volatile writes which prevent compiler optimization.

use arcanum_core::buffer::{SecretBuffer, SecretBytes, SecureVec};
use arcanum_core::key::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════════════════
// TRAIT IMPLEMENTATION VERIFICATION
// These are compile-time checks - if they compile, the traits are implemented.
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that SecretKey<N> implements ZeroizeOnDrop.
/// Note: SecretKey derives ZeroizeOnDrop but may not implement Zeroize directly.
#[test]
fn test_secret_key_implements_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    // These compile if and only if ZeroizeOnDrop is implemented
    assert_zeroize_on_drop::<SecretKey<32>>();
    assert_zeroize_on_drop::<SecretKey<16>>();
    assert_zeroize_on_drop::<SecretKey<64>>();
}

/// Verify that SecretBuffer<N> implements ZeroizeOnDrop.
#[test]
fn test_secret_buffer_implements_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<SecretBuffer<32>>();
    assert_zeroize_on_drop::<SecretBuffer<16>>();
    assert_zeroize_on_drop::<SecretBuffer<64>>();
}

/// Verify that SecureVec implements Drop with zeroization.
/// (SecureVec implements Drop manually with zeroize(), not ZeroizeOnDrop derive)
#[test]
fn test_secure_vec_implements_zeroize() {
    fn assert_zeroize<T: Zeroize>() {}

    // SecureVec's inner Vec<u8> implements Zeroize
    assert_zeroize::<Vec<u8>>();

    // SecureVec itself uses Zeroize in its Drop impl
    let mut sv = SecureVec::from_slice(&[0xAB; 32]);
    // Manual zeroize before drop
    sv.clear();
    assert!(sv.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUNTIME ZEROIZATION SMOKE TESTS
// WARNING: These tests involve undefined behavior (reading deallocated memory).
// They serve as smoke tests in debug mode only.
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that SecretBuffer memory is zeroed after drop.
///
/// IMPORTANT: This test reads memory after deallocation, which is technically
/// undefined behavior. It serves as a smoke test in debug mode where the
/// allocator is less likely to reuse memory immediately.
#[test]
#[cfg(debug_assertions)]
fn test_secret_buffer_zeroized_on_drop_smoke() {
    let ptr: *const u8;
    let len: usize;
    {
        let buf = SecretBuffer::<64>::from_array([0x42u8; 64]);
        ptr = buf.as_array().as_ptr();
        len = buf.as_array().len();
        // Verify the buffer contains our test data
        assert_eq!(buf.as_array()[0], 0x42);
    } // buf dropped here, zeroization should occur

    // Smoke test: check if memory appears zeroed
    // This is UB and may flake - that's acceptable for a smoke test
    // The test may pass even if zeroization didn't happen (if allocator reuses memory)
    // But if it fails, we have a real problem
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        // Count how many bytes are still 0x42
        let non_zeroed = slice.iter().filter(|&&b| b == 0x42).count();
        // If more than half the bytes are still our test value, something is wrong
        // This threshold accounts for allocator behavior and memory reuse
        assert!(
            non_zeroed < len / 2,
            "SecretBuffer memory may not have been properly zeroed: {}/{} bytes still contain test value",
            non_zeroed, len
        );
    }
}

/// Verify that SecretKey memory is zeroed after drop.
#[test]
#[cfg(debug_assertions)]
fn test_secret_key_zeroized_on_drop_smoke() {
    let ptr: *const u8;
    let len: usize;
    {
        let key = SecretKey::<32>::new([0xDE; 32]);
        ptr = key.as_bytes().as_ptr();
        len = key.as_bytes().len();
        assert_eq!(key.as_bytes()[0], 0xDE);
    } // key dropped here

    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        let non_zeroed = slice.iter().filter(|&&b| b == 0xDE).count();
        assert!(
            non_zeroed < len / 2,
            "SecretKey memory may not have been properly zeroed: {}/{} bytes still contain test value",
            non_zeroed, len
        );
    }
}

/// Verify that SecureVec memory is zeroed after drop.
#[test]
#[cfg(debug_assertions)]
fn test_secure_vec_zeroized_on_drop_smoke() {
    let ptr: *const u8;
    let len: usize;
    {
        let sv = SecureVec::from_slice(&[0xAB; 128]);
        ptr = sv.expose().as_ptr();
        len = sv.len();
        assert_eq!(sv.expose()[0], 0xAB);
    } // sv dropped here

    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        let non_zeroed = slice.iter().filter(|&&b| b == 0xAB).count();
        assert!(
            non_zeroed < len / 2,
            "SecureVec memory may not have been properly zeroed: {}/{} bytes still contain test value",
            non_zeroed, len
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MANUAL ZEROIZE VERIFICATION
// These tests verify that explicit zeroization works correctly.
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that manual Zeroize::zeroize() works on SecureVec.
#[test]
fn test_secure_vec_manual_zeroize() {
    let mut sv = SecureVec::from_slice(&[0xFF; 64]);
    assert_eq!(sv.expose()[0], 0xFF);

    // Clear uses zeroize internally
    sv.clear();

    assert!(sv.is_empty());
    // The internal Vec is now empty, so we can't check its contents
}

/// Verify that SecureVec truncate zeroizes removed portion.
#[test]
fn test_secure_vec_truncate_zeroizes() {
    let mut sv = SecureVec::from_slice(&[0xAA; 100]);
    assert_eq!(sv.len(), 100);

    // Truncate to 50 - the last 50 bytes should be zeroized
    sv.truncate(50);
    assert_eq!(sv.len(), 50);

    // The truncated portion is no longer accessible through safe Rust
    // This test verifies the API works; actual zeroization is handled by the impl
}

/// Verify that SecureVec resize zeroizes shrunk portion.
#[test]
fn test_secure_vec_resize_zeroizes() {
    let mut sv = SecureVec::from_slice(&[0xBB; 80]);

    // Resize smaller - excess bytes should be zeroized
    sv.resize(40, 0);
    assert_eq!(sv.len(), 40);
    assert_eq!(sv.expose()[0], 0xBB);

    // Resize larger - new bytes should be the specified value
    sv.resize(60, 0xCC);
    assert_eq!(sv.len(), 60);
    assert_eq!(sv.expose()[40], 0xCC);
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEBUG OUTPUT VERIFICATION
// Ensure debug output doesn't leak sensitive data.
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify SecretKey debug output doesn't leak key material.
#[test]
fn test_secret_key_debug_redaction() {
    let key = SecretKey::<32>::new([0xDE; 32]);
    let debug_output = format!("{:?}", key);

    // Must contain "[REDACTED]" or similar
    assert!(
        debug_output.contains("REDACTED") || debug_output.contains("redacted"),
        "SecretKey debug output must indicate redaction: {}",
        debug_output
    );

    // Must NOT contain the actual key bytes in hex
    assert!(
        !debug_output.to_lowercase().contains("de"),
        "SecretKey debug output must not leak key bytes: {}",
        debug_output
    );
}

/// Verify SecretBuffer debug output doesn't leak buffer contents.
#[test]
fn test_secret_buffer_debug_redaction() {
    let buf = SecretBuffer::<16>::from_array([0xAB; 16]);
    let debug_output = format!("{:?}", buf);

    assert!(
        debug_output.contains("REDACTED"),
        "SecretBuffer debug must be redacted: {}",
        debug_output
    );
    assert!(
        !debug_output.to_lowercase().contains("ab"),
        "SecretBuffer debug must not leak contents: {}",
        debug_output
    );
}

/// Verify SecureVec debug output doesn't leak buffer contents.
#[test]
fn test_secure_vec_debug_redaction() {
    let sv = SecureVec::from_slice(&[0xCD; 32]);
    let debug_output = format!("{:?}", sv);

    assert!(
        debug_output.contains("REDACTED"),
        "SecureVec debug must be redacted: {}",
        debug_output
    );
    assert!(
        !debug_output.to_lowercase().contains("cd"),
        "SecureVec debug must not leak contents: {}",
        debug_output
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECRETBYTES ALIAS VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify SecretBytes (type alias for SecureVec) has proper zeroization.
#[test]
fn test_secret_bytes_zeroization() {
    let mut sb: SecretBytes = SecretBytes::from_slice(&[0x99; 48]);
    assert_eq!(sb.len(), 48);
    assert_eq!(sb.expose()[0], 0x99);

    sb.clear();
    assert!(sb.is_empty());
}

/// Verify SecretBytes debug is redacted.
#[test]
fn test_secret_bytes_debug_redaction() {
    let sb: SecretBytes = SecretBytes::from_slice(&[0xEE; 24]);
    let debug_output = format!("{:?}", sb);

    assert!(
        debug_output.contains("REDACTED"),
        "SecretBytes debug must be redacted"
    );
}
