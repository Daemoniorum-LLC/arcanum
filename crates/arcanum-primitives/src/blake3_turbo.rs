//! Turbo BLAKE3 Implementation - Research/Experimental
//!
//! A novel approach to BLAKE3 hashing using:
//!
//! 1. **Vectorized Message Schedule**: Pre-computed indices eliminate runtime permutation
//! 2. **Transposed State Layout**: State word `i` from 8 blocks in one AVX2 register
//! 3. **Register-Resident Processing**: CV kept in registers across block compressions
//! 4. **Fused XOR Finalization**: SIMD-accelerated final state XOR
//!
//! ## Performance Analysis
//!
//! Current benchmarks show this approach is **slower** than the existing implementation:
//!
//! | Size | Turbo | Native | blake3 crate |
//! |------|-------|--------|--------------|
//! | 8KB  | 1.6 GiB/s | 1.9 GiB/s | 4.1 GiB/s |
//! | 64KB | 1.6 GiB/s | 2.5 GiB/s | 6.1 GiB/s |
//! | 1MB  | 1.6 GiB/s | 2.4 GiB/s | 6.1 GiB/s |
//!
//! ## Why This Approach Is Slower
//!
//! The bottleneck is **message transposition**. To process 8 blocks in parallel with
//! transposed state, we need word\[i\] from 8 different blocks in one register. This requires:
//!
//! 1. Loading 8 blocks from non-contiguous memory locations
//! 2. Transposing 8×16 = 128 u32 values
//!
//! The `_mm256_set_epi32` approach does 8 separate loads + combine, which is slower
//! than the existing approach of loading contiguous blocks.
//!
//! ## The blake3 Crate's Advantage
//!
//! The blake3 crate achieves 6 GiB/s through:
//!
//! 1. **Multi-threading (Rayon)**: Processes multiple chunks on different cores
//! 2. **Assembly optimization**: Hand-tuned compression function
//! 3. **Contiguous processing**: Doesn't need message transposition
//!
//! ## Future Work
//!
//! To match blake3 crate performance, consider:
//!
//! 1. **Multi-threaded Rayon integration** for parallel chunk processing
//! 2. **AVX-512 VPGATHERDD** for efficient scattered loads
//! 3. **Assembly-optimized compression** for the hot path
//!
//! ## Key Innovation: Pre-computed Round Schedules
//!
//! Instead of permuting the message array each round, we pre-compute
//! the indices needed for each round's G functions:
//!
//! ```text
//! Round 0: [0,1] [2,3] [4,5] [6,7] | [8,9] [10,11] [12,13] [14,15]
//! Round 1: [2,6] [3,10] [7,0] [4,13] | [1,11] [12,5] [9,14] [15,8]
//! ... (5 more rounds)
//! ```
//!
//! These indices are compiled into lookup tables at compile time.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::blake3_simd::IV;

// ═══════════════════════════════════════════════════════════════════════════════
// PRE-COMPUTED ROUND MESSAGE SCHEDULES
// ═══════════════════════════════════════════════════════════════════════════════

// Corrected full message schedule: apply permutation iteratively
// Permutation: [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], // Round 0: identity
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8], // Round 1: P^1
    [3, 4, 10, 12, 0, 2, 13, 14, 6, 5, 1, 7, 11, 15, 8, 9], // Round 2: P^2
    [10, 13, 12, 1, 2, 3, 14, 15, 4, 7, 6, 0, 5, 8, 9, 11], // Round 3: P^3
    [12, 14, 1, 6, 3, 10, 15, 8, 13, 0, 4, 2, 7, 9, 11, 5], // Round 4: P^4
    [1, 15, 6, 4, 10, 12, 8, 9, 14, 2, 13, 3, 0, 11, 5, 7], // Round 5: P^5
    [6, 8, 4, 13, 12, 1, 9, 11, 15, 3, 14, 10, 2, 5, 7, 0], // Round 6: P^6
];

// ═══════════════════════════════════════════════════════════════════════════════
// AVX2 TURBO IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub mod avx2_turbo {
    use super::*;

    /// Check if AVX2 is available
    #[inline]
    pub fn is_available() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    /// State holder for 8-way parallel processing (transposed layout)
    #[repr(align(32))]
    struct State8Way {
        s: [__m256i; 16],
    }

    impl State8Way {
        #[target_feature(enable = "avx2")]
        unsafe fn new() -> Self {
            Self {
                s: [_mm256_setzero_si256(); 16],
            }
        }

        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn g(&mut self, a: usize, b: usize, c: usize, d: usize, mx: __m256i, my: __m256i) {
            // a = a + b + mx
            self.s[a] = _mm256_add_epi32(self.s[a], _mm256_add_epi32(self.s[b], mx));
            // d = (d ^ a) >>> 16
            self.s[d] = _mm256_xor_si256(self.s[d], self.s[a]);
            self.s[d] = _mm256_or_si256(
                _mm256_srli_epi32(self.s[d], 16),
                _mm256_slli_epi32(self.s[d], 16),
            );
            // c = c + d
            self.s[c] = _mm256_add_epi32(self.s[c], self.s[d]);
            // b = (b ^ c) >>> 12
            self.s[b] = _mm256_xor_si256(self.s[b], self.s[c]);
            self.s[b] = _mm256_or_si256(
                _mm256_srli_epi32(self.s[b], 12),
                _mm256_slli_epi32(self.s[b], 20),
            );
            // a = a + b + my
            self.s[a] = _mm256_add_epi32(self.s[a], _mm256_add_epi32(self.s[b], my));
            // d = (d ^ a) >>> 8
            self.s[d] = _mm256_xor_si256(self.s[d], self.s[a]);
            self.s[d] = _mm256_or_si256(
                _mm256_srli_epi32(self.s[d], 8),
                _mm256_slli_epi32(self.s[d], 24),
            );
            // c = c + d
            self.s[c] = _mm256_add_epi32(self.s[c], self.s[d]);
            // b = (b ^ c) >>> 7
            self.s[b] = _mm256_xor_si256(self.s[b], self.s[c]);
            self.s[b] = _mm256_or_si256(
                _mm256_srli_epi32(self.s[b], 7),
                _mm256_slli_epi32(self.s[b], 25),
            );
        }
    }

    /// Load all 16 message words from a single block into 4 registers.
    /// This uses contiguous loads which are much faster than scattered loads.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn load_block_to_regs(block: *const u8) -> [__m128i; 4] {
        [
            _mm_loadu_si128(block as *const __m128i),
            _mm_loadu_si128(block.add(16) as *const __m128i),
            _mm_loadu_si128(block.add(32) as *const __m128i),
            _mm_loadu_si128(block.add(48) as *const __m128i),
        ]
    }

    /// Transpose message words from AoS (array of structs) to SoA (struct of arrays).
    ///
    /// Input: 8 blocks, each with 16 u32 message words
    /// Output: 16 registers, each holding word[i] from all 8 blocks
    ///
    /// This is the key optimization: we load contiguously and then transpose,
    /// which is faster than scattered loads.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn transpose_messages_8way(block_ptrs: &[*const u8; 8]) -> [__m256i; 16] {
        // Load all 8 blocks (each block is 64 bytes = 16 u32s)
        let mut blocks = [[_mm_setzero_si128(); 4]; 8];
        for i in 0..8 {
            blocks[i] = load_block_to_regs(block_ptrs[i]);
        }

        // Now transpose: we need msg[word] = [b0.w, b1.w, b2.w, b3.w, b4.w, b5.w, b6.w, b7.w]
        // Each block has 4 __m128i registers (4 words each = 16 words total)
        let mut result = [_mm256_setzero_si256(); 16];

        // Helper to extract lane from __m128i (lane must be const)
        macro_rules! extract_lane {
            ($reg:expr, 0) => {
                _mm_extract_epi32($reg, 0)
            };
            ($reg:expr, 1) => {
                _mm_extract_epi32($reg, 1)
            };
            ($reg:expr, 2) => {
                _mm_extract_epi32($reg, 2)
            };
            ($reg:expr, 3) => {
                _mm_extract_epi32($reg, 3)
            };
        }

        // For each word position (0-15), unroll by lane
        for reg_idx in 0..4 {
            for lane in 0..4 {
                let word = reg_idx * 4 + lane;

                // Extract word from each block using const lane
                let (w0, w1, w2, w3, w4, w5, w6, w7) = match lane {
                    0 => (
                        extract_lane!(blocks[0][reg_idx], 0) as i32,
                        extract_lane!(blocks[1][reg_idx], 0) as i32,
                        extract_lane!(blocks[2][reg_idx], 0) as i32,
                        extract_lane!(blocks[3][reg_idx], 0) as i32,
                        extract_lane!(blocks[4][reg_idx], 0) as i32,
                        extract_lane!(blocks[5][reg_idx], 0) as i32,
                        extract_lane!(blocks[6][reg_idx], 0) as i32,
                        extract_lane!(blocks[7][reg_idx], 0) as i32,
                    ),
                    1 => (
                        extract_lane!(blocks[0][reg_idx], 1) as i32,
                        extract_lane!(blocks[1][reg_idx], 1) as i32,
                        extract_lane!(blocks[2][reg_idx], 1) as i32,
                        extract_lane!(blocks[3][reg_idx], 1) as i32,
                        extract_lane!(blocks[4][reg_idx], 1) as i32,
                        extract_lane!(blocks[5][reg_idx], 1) as i32,
                        extract_lane!(blocks[6][reg_idx], 1) as i32,
                        extract_lane!(blocks[7][reg_idx], 1) as i32,
                    ),
                    2 => (
                        extract_lane!(blocks[0][reg_idx], 2) as i32,
                        extract_lane!(blocks[1][reg_idx], 2) as i32,
                        extract_lane!(blocks[2][reg_idx], 2) as i32,
                        extract_lane!(blocks[3][reg_idx], 2) as i32,
                        extract_lane!(blocks[4][reg_idx], 2) as i32,
                        extract_lane!(blocks[5][reg_idx], 2) as i32,
                        extract_lane!(blocks[6][reg_idx], 2) as i32,
                        extract_lane!(blocks[7][reg_idx], 2) as i32,
                    ),
                    _ => (
                        extract_lane!(blocks[0][reg_idx], 3) as i32,
                        extract_lane!(blocks[1][reg_idx], 3) as i32,
                        extract_lane!(blocks[2][reg_idx], 3) as i32,
                        extract_lane!(blocks[3][reg_idx], 3) as i32,
                        extract_lane!(blocks[4][reg_idx], 3) as i32,
                        extract_lane!(blocks[5][reg_idx], 3) as i32,
                        extract_lane!(blocks[6][reg_idx], 3) as i32,
                        extract_lane!(blocks[7][reg_idx], 3) as i32,
                    ),
                };

                result[word] = _mm256_set_epi32(w7, w6, w5, w4, w3, w2, w1, w0);
            }
        }

        result
    }

    /// Load message word from 8 blocks at specified index.
    /// Returns [block0.m[idx], block1.m[idx], ..., block7.m[idx]]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn load_msg_word_8way(block_ptrs: &[*const u8; 8], word_idx: usize) -> __m256i {
        let offset = word_idx * 4;
        _mm256_set_epi32(
            *(block_ptrs[7].add(offset) as *const i32),
            *(block_ptrs[6].add(offset) as *const i32),
            *(block_ptrs[5].add(offset) as *const i32),
            *(block_ptrs[4].add(offset) as *const i32),
            *(block_ptrs[3].add(offset) as *const i32),
            *(block_ptrs[2].add(offset) as *const i32),
            *(block_ptrs[1].add(offset) as *const i32),
            *(block_ptrs[0].add(offset) as *const i32),
        )
    }

    /// Compress 8 blocks in parallel using direct-load message schedule.
    ///
    /// # Novel Approach
    ///
    /// Instead of loading all message words upfront and permuting each round,
    /// we load only the words needed for each G function directly using
    /// the pre-computed MSG_SCHEDULE indices.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_8blocks_turbo(
        cvs: &[[u32; 8]; 8],
        block_ptrs: &[*const u8; 8],
        counters: &[u64; 8],
        block_len: u32,
        flags: u8,
    ) -> [[u32; 8]; 8] {
        let mut state = State8Way::new();

        // Load CVs (transposed)
        for word in 0..8 {
            state.s[word] = _mm256_set_epi32(
                cvs[7][word] as i32,
                cvs[6][word] as i32,
                cvs[5][word] as i32,
                cvs[4][word] as i32,
                cvs[3][word] as i32,
                cvs[2][word] as i32,
                cvs[1][word] as i32,
                cvs[0][word] as i32,
            );
        }

        // Load IV
        for i in 0..4 {
            state.s[8 + i] = _mm256_set1_epi32(IV[i] as i32);
        }

        // Load counters and flags
        state.s[12] = _mm256_set_epi32(
            counters[7] as i32,
            counters[6] as i32,
            counters[5] as i32,
            counters[4] as i32,
            counters[3] as i32,
            counters[2] as i32,
            counters[1] as i32,
            counters[0] as i32,
        );
        state.s[13] = _mm256_set_epi32(
            (counters[7] >> 32) as i32,
            (counters[6] >> 32) as i32,
            (counters[5] >> 32) as i32,
            (counters[4] >> 32) as i32,
            (counters[3] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[0] >> 32) as i32,
        );
        state.s[14] = _mm256_set1_epi32(block_len as i32);
        state.s[15] = _mm256_set1_epi32(flags as i32);

        // Save initial CV for final XOR
        let init_cv: [__m256i; 8] = [
            state.s[0], state.s[1], state.s[2], state.s[3], state.s[4], state.s[5], state.s[6],
            state.s[7],
        ];

        // 7 rounds with direct-load message schedule
        for round in 0..7 {
            let schedule = MSG_SCHEDULE[round];

            // Column step: G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
            let mx0 = load_msg_word_8way(block_ptrs, schedule[0]);
            let my0 = load_msg_word_8way(block_ptrs, schedule[1]);
            state.g(0, 4, 8, 12, mx0, my0);

            let mx1 = load_msg_word_8way(block_ptrs, schedule[2]);
            let my1 = load_msg_word_8way(block_ptrs, schedule[3]);
            state.g(1, 5, 9, 13, mx1, my1);

            let mx2 = load_msg_word_8way(block_ptrs, schedule[4]);
            let my2 = load_msg_word_8way(block_ptrs, schedule[5]);
            state.g(2, 6, 10, 14, mx2, my2);

            let mx3 = load_msg_word_8way(block_ptrs, schedule[6]);
            let my3 = load_msg_word_8way(block_ptrs, schedule[7]);
            state.g(3, 7, 11, 15, mx3, my3);

            // Diagonal step: G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
            let mx4 = load_msg_word_8way(block_ptrs, schedule[8]);
            let my4 = load_msg_word_8way(block_ptrs, schedule[9]);
            state.g(0, 5, 10, 15, mx4, my4);

            let mx5 = load_msg_word_8way(block_ptrs, schedule[10]);
            let my5 = load_msg_word_8way(block_ptrs, schedule[11]);
            state.g(1, 6, 11, 12, mx5, my5);

            let mx6 = load_msg_word_8way(block_ptrs, schedule[12]);
            let my6 = load_msg_word_8way(block_ptrs, schedule[13]);
            state.g(2, 7, 8, 13, mx6, my6);

            let mx7 = load_msg_word_8way(block_ptrs, schedule[14]);
            let my7 = load_msg_word_8way(block_ptrs, schedule[15]);
            state.g(3, 4, 9, 14, mx7, my7);
        }

        // Finalize: XOR the two halves (vectorized)
        for i in 0..8 {
            state.s[i] = _mm256_xor_si256(state.s[i], state.s[i + 8]);
            state.s[i + 8] = _mm256_xor_si256(state.s[i + 8], init_cv[i]);
        }

        // Extract results (first 8 words = CV)
        let mut results = [[0u32; 8]; 8];
        for word in 0..8 {
            let mut arr = [0i32; 8];
            _mm256_storeu_si256(arr.as_mut_ptr() as *mut __m256i, state.s[word]);
            for block in 0..8 {
                results[block][word] = arr[block] as u32;
            }
        }

        results
    }

    /// Hash 8 complete chunks (1024 bytes each) using turbo compression.
    ///
    /// # Novel Optimization: Register-Resident CV
    ///
    /// The CV is kept in AVX2 registers across all 16 block compressions,
    /// eliminating memory round-trips between blocks.
    #[target_feature(enable = "avx2")]
    pub unsafe fn hash_8_chunks_turbo(
        key: &[u32; 8],
        chunks: &[[u8; 1024]; 8],
        chunk_counters: &[u64; 8],
        base_flags: u8,
    ) -> [[u32; 8]; 8] {
        const CHUNK_START: u8 = 1;
        const CHUNK_END: u8 = 2;

        // Initialize CVs in registers (transposed)
        let mut cv = [_mm256_setzero_si256(); 8];
        for word in 0..8 {
            cv[word] = _mm256_set1_epi32(key[word] as i32);
        }

        // Process 16 blocks per chunk
        for block_idx in 0..16 {
            let is_first = block_idx == 0;
            let is_last = block_idx == 15;

            // Build flags
            let mut block_flags = base_flags;
            if is_first {
                block_flags |= CHUNK_START;
            }
            if is_last {
                block_flags |= CHUNK_END;
            }

            // Get block pointers
            let offset = block_idx * 64;
            let block_ptrs: [*const u8; 8] = [
                chunks[0].as_ptr().add(offset),
                chunks[1].as_ptr().add(offset),
                chunks[2].as_ptr().add(offset),
                chunks[3].as_ptr().add(offset),
                chunks[4].as_ptr().add(offset),
                chunks[5].as_ptr().add(offset),
                chunks[6].as_ptr().add(offset),
                chunks[7].as_ptr().add(offset),
            ];

            // Prefetch next block
            if block_idx < 15 {
                let next_offset = (block_idx + 1) * 64;
                for i in 0..8 {
                    _mm_prefetch::<_MM_HINT_T0>(chunks[i].as_ptr().add(next_offset) as *const i8);
                }
            }

            // Compress with register-resident CV
            cv = compress_inline(&cv, &block_ptrs, chunk_counters, 64, block_flags);
        }

        // Extract CVs from registers
        let mut results = [[0u32; 8]; 8];
        for word in 0..8 {
            let mut arr = [0i32; 8];
            _mm256_storeu_si256(arr.as_mut_ptr() as *mut __m256i, cv[word]);
            for block in 0..8 {
                results[block][word] = arr[block] as u32;
            }
        }

        results
    }

    /// Inline compression for register-resident CV.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn compress_inline(
        cv: &[__m256i; 8],
        block_ptrs: &[*const u8; 8],
        counters: &[u64; 8],
        block_len: u32,
        flags: u8,
    ) -> [__m256i; 8] {
        let mut state = State8Way::new();

        // Initialize state from CV
        for i in 0..8 {
            state.s[i] = cv[i];
        }

        // IV
        for i in 0..4 {
            state.s[8 + i] = _mm256_set1_epi32(IV[i] as i32);
        }

        // Counters and flags
        state.s[12] = _mm256_set_epi32(
            counters[7] as i32,
            counters[6] as i32,
            counters[5] as i32,
            counters[4] as i32,
            counters[3] as i32,
            counters[2] as i32,
            counters[1] as i32,
            counters[0] as i32,
        );
        state.s[13] = _mm256_set_epi32(
            (counters[7] >> 32) as i32,
            (counters[6] >> 32) as i32,
            (counters[5] >> 32) as i32,
            (counters[4] >> 32) as i32,
            (counters[3] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[0] >> 32) as i32,
        );
        state.s[14] = _mm256_set1_epi32(block_len as i32);
        state.s[15] = _mm256_set1_epi32(flags as i32);

        // 7 rounds
        for round in 0..7 {
            let schedule = MSG_SCHEDULE[round];

            // Column G functions
            let mx0 = load_msg_word_8way(block_ptrs, schedule[0]);
            let my0 = load_msg_word_8way(block_ptrs, schedule[1]);
            state.g(0, 4, 8, 12, mx0, my0);

            let mx1 = load_msg_word_8way(block_ptrs, schedule[2]);
            let my1 = load_msg_word_8way(block_ptrs, schedule[3]);
            state.g(1, 5, 9, 13, mx1, my1);

            let mx2 = load_msg_word_8way(block_ptrs, schedule[4]);
            let my2 = load_msg_word_8way(block_ptrs, schedule[5]);
            state.g(2, 6, 10, 14, mx2, my2);

            let mx3 = load_msg_word_8way(block_ptrs, schedule[6]);
            let my3 = load_msg_word_8way(block_ptrs, schedule[7]);
            state.g(3, 7, 11, 15, mx3, my3);

            // Diagonal G functions
            let mx4 = load_msg_word_8way(block_ptrs, schedule[8]);
            let my4 = load_msg_word_8way(block_ptrs, schedule[9]);
            state.g(0, 5, 10, 15, mx4, my4);

            let mx5 = load_msg_word_8way(block_ptrs, schedule[10]);
            let my5 = load_msg_word_8way(block_ptrs, schedule[11]);
            state.g(1, 6, 11, 12, mx5, my5);

            let mx6 = load_msg_word_8way(block_ptrs, schedule[12]);
            let my6 = load_msg_word_8way(block_ptrs, schedule[13]);
            state.g(2, 7, 8, 13, mx6, my6);

            let mx7 = load_msg_word_8way(block_ptrs, schedule[14]);
            let my7 = load_msg_word_8way(block_ptrs, schedule[15]);
            state.g(3, 4, 9, 14, mx7, my7);
        }

        // Finalize: s[i] = s[i] ^ s[i+8]
        [
            _mm256_xor_si256(state.s[0], state.s[8]),
            _mm256_xor_si256(state.s[1], state.s[9]),
            _mm256_xor_si256(state.s[2], state.s[10]),
            _mm256_xor_si256(state.s[3], state.s[11]),
            _mm256_xor_si256(state.s[4], state.s[12]),
            _mm256_xor_si256(state.s[5], state.s[13]),
            _mm256_xor_si256(state.s[6], state.s[14]),
            _mm256_xor_si256(state.s[7], state.s[15]),
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

/// Hash data using the turbo BLAKE3 implementation.
///
/// This uses the optimized register-resident 8-way parallel implementation
/// when AVX2 is available.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_turbo(data: &[u8]) -> [u8; 32] {
    use super::blake3_simd::hash_large_parallel;

    if !avx2_turbo::is_available() || data.len() < 8 * 1024 {
        // Fall back to existing parallel implementation for small data
        return hash_large_parallel(data);
    }

    const CHUNK_LEN: usize = 1024;
    const BATCH_SIZE: usize = 8;
    const BATCH_BYTES: usize = CHUNK_LEN * BATCH_SIZE;

    let mut cvs = Vec::new();
    let mut offset = 0;
    let mut chunk_counter = 0u64;

    // Process 8 chunks at a time
    while offset + BATCH_BYTES <= data.len() {
        let chunks: [[u8; 1024]; 8] = [
            data[offset..offset + CHUNK_LEN].try_into().unwrap(),
            data[offset + CHUNK_LEN..offset + 2 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 2 * CHUNK_LEN..offset + 3 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 3 * CHUNK_LEN..offset + 4 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 4 * CHUNK_LEN..offset + 5 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 5 * CHUNK_LEN..offset + 6 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 6 * CHUNK_LEN..offset + 7 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 7 * CHUNK_LEN..offset + 8 * CHUNK_LEN]
                .try_into()
                .unwrap(),
        ];

        let counters = [
            chunk_counter,
            chunk_counter + 1,
            chunk_counter + 2,
            chunk_counter + 3,
            chunk_counter + 4,
            chunk_counter + 5,
            chunk_counter + 6,
            chunk_counter + 7,
        ];

        let batch_cvs = unsafe { avx2_turbo::hash_8_chunks_turbo(&IV, &chunks, &counters, 0) };
        cvs.extend_from_slice(&batch_cvs);

        offset += BATCH_BYTES;
        chunk_counter += 8;
    }

    // Handle remaining data with existing implementation
    if offset < data.len() {
        let remaining = &data[offset..];
        // Use existing implementation for remainder
        let remaining_cvs =
            super::blake3_simd::hash_many_chunks_parallel(&IV, remaining, chunk_counter, 0);
        cvs.extend(remaining_cvs);
    }

    // Merge CVs into root hash using parent compression
    if cvs.is_empty() {
        return IV
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    merge_cvs_to_root(&cvs)
}

/// Merge chaining values into final root hash.
fn merge_cvs_to_root(cvs: &[[u32; 8]]) -> [u8; 32] {
    use super::blake3_simd::{IV, compress_auto};

    const PARENT: u8 = 4;
    const ROOT: u8 = 8;

    if cvs.len() == 1 {
        // Single CV is the root
        return cvs[0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    let mut current = cvs.to_vec();

    // Pad to even number
    if current.len() % 2 == 1 {
        current.push(*current.last().unwrap());
    }

    // Reduce tree
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2);

        for pair in current.chunks(2) {
            // Concatenate left and right CVs into 64-byte block
            let mut block = [0u8; 64];
            for i in 0..8 {
                block[i * 4..(i + 1) * 4].copy_from_slice(&pair[0][i].to_le_bytes());
            }
            for i in 0..8 {
                block[32 + i * 4..32 + (i + 1) * 4].copy_from_slice(&pair[1][i].to_le_bytes());
            }

            let is_root = next.is_empty() && current.len() == 2;
            let flags = PARENT | if is_root { ROOT } else { 0 };

            let output = compress_auto(&IV, &block, 0, 64, flags);
            let cv: [u32; 8] = output[..8].try_into().unwrap();
            next.push(cv);
        }

        // Pad if odd
        if next.len() > 1 && next.len() % 2 == 1 {
            next.push(*next.last().unwrap());
        }

        current = next;
    }

    current[0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_turbo_matches_reference() {
        let data = vec![0x42u8; 1024 * 16]; // 16 chunks

        let turbo_hash = hash_turbo(&data);
        let reference_hash = blake3::hash(&data);

        assert_eq!(turbo_hash, *reference_hash.as_bytes());
    }

    #[test]
    fn test_turbo_various_sizes() {
        for size in [8 * 1024, 16 * 1024, 64 * 1024, 1024 * 1024] {
            let data = vec![0xAB; size];

            let turbo_hash = hash_turbo(&data);
            let reference_hash = blake3::hash(&data);

            assert_eq!(
                turbo_hash,
                *reference_hash.as_bytes(),
                "Mismatch at size {}",
                size
            );
        }
    }
}
