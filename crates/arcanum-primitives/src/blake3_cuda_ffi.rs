//! Rust FFI bindings for CUDA BLAKE3 implementation
//!
//! This module provides safe Rust wrappers around the CUDA BLAKE3 kernels.
//! Requires linking with the compiled CUDA library (blake3_cuda.so).
//!
//! # Building the CUDA library
//!
//! ```bash
//! nvcc -O3 -arch=sm_89 -shared -fPIC blake3_cuda.cu -o libblake3_cuda.so
//! ```
//!
//! For RTX 4500 (Ada Lovelace), use `-arch=sm_89`.
//! For RTX 3000 series (Ampere), use `-arch=sm_86`.
//! For RTX 2000 series (Turing), use `-arch=sm_75`.

#![allow(unused)]

use std::ffi::c_void;
use std::ptr;

/// Opaque CUDA context structure
#[repr(C)]
pub struct Blake3CudaContext {
    d_messages: *mut u8,
    d_lengths: *mut u32,
    d_offsets: *mut u64,
    d_hashes: *mut u8,
    buffer_size: usize,
}

impl Default for Blake3CudaContext {
    fn default() -> Self {
        Self {
            d_messages: ptr::null_mut(),
            d_lengths: ptr::null_mut(),
            d_offsets: ptr::null_mut(),
            d_hashes: ptr::null_mut(),
            buffer_size: 0,
        }
    }
}

// FFI declarations
#[cfg(feature = "cuda")]
unsafe extern "C" {
    fn blake3_cuda_init(
        ctx: *mut Blake3CudaContext,
        max_buffer_size: usize,
        max_messages: u32,
    ) -> i32;

    fn blake3_cuda_hash_batch(
        ctx: *mut Blake3CudaContext,
        messages: *const u8,
        lengths: *const u32,
        offsets: *const u64,
        num_messages: u32,
        total_size: usize,
        hashes_out: *mut u8,
    ) -> i32;

    fn blake3_cuda_hash_small_batch(
        ctx: *mut Blake3CudaContext,
        messages: *const u8,
        message_size: u32,
        num_messages: u32,
        hashes_out: *mut u8,
    ) -> i32;

    fn blake3_cuda_cleanup(ctx: *mut Blake3CudaContext);

    fn blake3_cuda_device_info();
}

/// Error type for CUDA operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CudaError {
    InitFailed(i32),
    HashFailed(i32),
    MessageTooLarge,
    NoCudaSupport,
}

impl std::fmt::Display for CudaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CudaError::InitFailed(code) => write!(f, "CUDA init failed with code {}", code),
            CudaError::HashFailed(code) => write!(f, "CUDA hash failed with code {}", code),
            CudaError::MessageTooLarge => write!(f, "Message too large for GPU hashing"),
            CudaError::NoCudaSupport => write!(f, "CUDA support not compiled in"),
        }
    }
}

impl std::error::Error for CudaError {}

/// Safe wrapper around CUDA BLAKE3 context
#[cfg(feature = "cuda")]
pub struct CudaHasher {
    ctx: Blake3CudaContext,
    max_messages: u32,
}

#[cfg(feature = "cuda")]
impl CudaHasher {
    /// Create a new CUDA hasher with the specified capacity
    ///
    /// # Arguments
    /// * `max_buffer_size` - Maximum total size of all messages in bytes
    /// * `max_messages` - Maximum number of messages in a batch
    pub fn new(max_buffer_size: usize, max_messages: u32) -> Result<Self, CudaError> {
        let mut ctx = Blake3CudaContext::default();
        let result = unsafe { blake3_cuda_init(&mut ctx, max_buffer_size, max_messages) };

        if result != 0 {
            return Err(CudaError::InitFailed(result));
        }

        Ok(Self { ctx, max_messages })
    }

    /// Hash a batch of variable-length messages
    ///
    /// # Arguments
    /// * `messages` - Slice of message slices to hash
    ///
    /// # Returns
    /// Vector of 32-byte hashes, one per message
    pub fn hash_batch(&mut self, messages: &[&[u8]]) -> Result<Vec<[u8; 32]>, CudaError> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }

        // Calculate total size and offsets
        let mut total_size = 0usize;
        let mut lengths = Vec::with_capacity(messages.len());
        let mut offsets = Vec::with_capacity(messages.len());

        for msg in messages {
            offsets.push(total_size as u64);
            lengths.push(msg.len() as u32);
            total_size += msg.len();
        }

        // Concatenate all messages
        let mut buffer = Vec::with_capacity(total_size);
        for msg in messages {
            buffer.extend_from_slice(msg);
        }

        // Allocate output
        let mut hashes = vec![0u8; messages.len() * 32];

        let result = unsafe {
            blake3_cuda_hash_batch(
                &mut self.ctx,
                buffer.as_ptr(),
                lengths.as_ptr(),
                offsets.as_ptr(),
                messages.len() as u32,
                total_size,
                hashes.as_mut_ptr(),
            )
        };

        if result != 0 {
            return Err(CudaError::HashFailed(result));
        }

        // Convert to array format
        let mut result_hashes = Vec::with_capacity(messages.len());
        for i in 0..messages.len() {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hashes[i * 32..(i + 1) * 32]);
            result_hashes.push(hash);
        }

        Ok(result_hashes)
    }

    /// Hash a batch of fixed-size messages (optimized path)
    ///
    /// # Arguments
    /// * `messages` - Concatenated buffer of fixed-size messages
    /// * `message_size` - Size of each message (must be ≤ 1024)
    /// * `num_messages` - Number of messages in the buffer
    ///
    /// # Returns
    /// Vector of 32-byte hashes
    pub fn hash_small_batch(
        &mut self,
        messages: &[u8],
        message_size: u32,
        num_messages: u32,
    ) -> Result<Vec<[u8; 32]>, CudaError> {
        if message_size > 1024 {
            return Err(CudaError::MessageTooLarge);
        }

        if num_messages == 0 {
            return Ok(Vec::new());
        }

        let mut hashes = vec![0u8; num_messages as usize * 32];

        let result = unsafe {
            blake3_cuda_hash_small_batch(
                &mut self.ctx,
                messages.as_ptr(),
                message_size,
                num_messages,
                hashes.as_mut_ptr(),
            )
        };

        if result != 0 {
            return Err(CudaError::HashFailed(result));
        }

        // Convert to array format
        let mut result_hashes = Vec::with_capacity(num_messages as usize);
        for i in 0..num_messages as usize {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hashes[i * 32..(i + 1) * 32]);
            result_hashes.push(hash);
        }

        Ok(result_hashes)
    }

    /// Print CUDA device information
    pub fn print_device_info() {
        unsafe { blake3_cuda_device_info() };
    }
}

#[cfg(feature = "cuda")]
impl Drop for CudaHasher {
    fn drop(&mut self) {
        unsafe { blake3_cuda_cleanup(&mut self.ctx) };
    }
}

// Non-CUDA fallback
#[cfg(not(feature = "cuda"))]
pub struct CudaHasher;

#[cfg(not(feature = "cuda"))]
impl CudaHasher {
    pub fn new(_max_buffer_size: usize, _max_messages: u32) -> Result<Self, CudaError> {
        Err(CudaError::NoCudaSupport)
    }

    pub fn hash_batch(&mut self, _messages: &[&[u8]]) -> Result<Vec<[u8; 32]>, CudaError> {
        Err(CudaError::NoCudaSupport)
    }

    pub fn hash_small_batch(
        &mut self,
        _messages: &[u8],
        _message_size: u32,
        _num_messages: u32,
    ) -> Result<Vec<[u8; 32]>, CudaError> {
        Err(CudaError::NoCudaSupport)
    }

    pub fn print_device_info() {
        eprintln!("CUDA support not compiled in");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "cuda")]
    fn test_cuda_batch_hash() {
        let mut hasher = match CudaHasher::new(1024 * 1024, 1000) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping CUDA test: {}", e);
                return;
            }
        };

        let messages: Vec<&[u8]> = vec![b"hello world", b"foo bar baz", b"test message 123"];

        let hashes = hasher.hash_batch(&messages).expect("hash failed");
        assert_eq!(hashes.len(), 3);

        // Each hash should be 32 bytes
        for hash in &hashes {
            assert_eq!(hash.len(), 32);
        }
    }
}
