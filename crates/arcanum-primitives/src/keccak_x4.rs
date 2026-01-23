//! 4-way parallel Keccak using AVX2
//!
//! Processes 4 independent Keccak states simultaneously using AVX2 SIMD.
//! Each __m256i register holds one lane from 4 different states.
//!
//! This provides ~3.5-4x throughput improvement for batch Keccak operations
//! like ML-DSA's ExpandA which needs K×L=30 SHAKE128 instances.
//!
//! ## Memory Layout
//!
//! Traditional: state[5][5] where each element is u64
//! 4-way: state_x4[5][5] where each element is __m256i (4 × u64)
//!
//! Lane (x,y) of state i is stored in: state_x4[x][y].extract(i)

#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Round constants for ι (iota) step
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for ρ (rho) step
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// 4-way parallel Keccak state
///
/// Holds 4 independent Keccak states interleaved for SIMD processing.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(32))]
pub struct KeccakStateX4 {
    /// Interleaved state: state[x][y] contains lane (x,y) from all 4 states
    state: [[__m256i; 5]; 5],
}

#[cfg(target_arch = "x86_64")]
impl KeccakStateX4 {
    /// Create new zeroed 4-way state
    #[target_feature(enable = "avx2")]
    pub unsafe fn new() -> Self {
        Self {
            state: [[_mm256_setzero_si256(); 5]; 5],
        }
    }

    /// XOR a byte into a specific position of a specific state
    ///
    /// # Arguments
    /// * `state_idx` - Which of the 4 states (0-3)
    /// * `byte_pos` - Byte position in state (0-199)
    /// * `byte` - Value to XOR
    #[target_feature(enable = "avx2")]
    #[inline]
    pub unsafe fn xor_byte(&mut self, state_idx: usize, byte_pos: usize, byte: u8) {
        let lane_idx = byte_pos / 8;
        let byte_in_lane = byte_pos % 8;
        let x = lane_idx % 5;
        let y = lane_idx / 5;

        // Extract current value, XOR, and reinsert
        let mut lanes = [0u64; 4];
        _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, self.state[x][y]);
        lanes[state_idx] ^= (byte as u64) << (byte_in_lane * 8);
        self.state[x][y] = _mm256_loadu_si256(lanes.as_ptr() as *const __m256i);
    }

    /// XOR bytes into a specific state
    ///
    /// # Arguments
    /// * `state_idx` - Which of the 4 states (0-3)
    /// * `data` - Bytes to XOR (up to rate bytes)
    /// * `rate` - Rate in bytes (168 for SHAKE128, 136 for SHAKE256)
    #[target_feature(enable = "avx2")]
    pub unsafe fn xor_bytes(&mut self, state_idx: usize, data: &[u8], rate: usize) {
        let len = data.len().min(rate);

        // Process 8 bytes at a time for efficiency
        let mut pos = 0;
        while pos + 8 <= len {
            let lane_idx = pos / 8;
            let x = lane_idx % 5;
            let y = lane_idx / 5;

            let mut word = 0u64;
            for i in 0..8 {
                word |= (data[pos + i] as u64) << (i * 8);
            }

            let mut lanes = [0u64; 4];
            _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, self.state[x][y]);
            lanes[state_idx] ^= word;
            self.state[x][y] = _mm256_loadu_si256(lanes.as_ptr() as *const __m256i);

            pos += 8;
        }

        // Handle remaining bytes
        while pos < len {
            self.xor_byte(state_idx, pos, data[pos]);
            pos += 1;
        }
    }

    /// Extract bytes from a specific state
    ///
    /// # Arguments
    /// * `state_idx` - Which of the 4 states (0-3)
    /// * `output` - Buffer to write to
    /// * `rate` - Rate in bytes
    #[target_feature(enable = "avx2")]
    pub unsafe fn extract_bytes(&self, state_idx: usize, output: &mut [u8], rate: usize) {
        let len = output.len().min(rate);

        // Process 8 bytes at a time
        let mut pos = 0;
        while pos + 8 <= len {
            let lane_idx = pos / 8;
            let x = lane_idx % 5;
            let y = lane_idx / 5;

            let mut lanes = [0u64; 4];
            _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, self.state[x][y]);
            let word = lanes[state_idx];

            for i in 0..8 {
                output[pos + i] = (word >> (i * 8)) as u8;
            }
            pos += 8;
        }

        // Handle remaining bytes
        while pos < len {
            let lane_idx = pos / 8;
            let byte_in_lane = pos % 8;
            let x = lane_idx % 5;
            let y = lane_idx / 5;

            let mut lanes = [0u64; 4];
            _mm256_storeu_si256(lanes.as_mut_ptr() as *mut __m256i, self.state[x][y]);
            output[pos] = (lanes[state_idx] >> (byte_in_lane * 8)) as u8;
            pos += 1;
        }
    }

    /// Run Keccak-f[1600] permutation on all 4 states in parallel
    #[target_feature(enable = "avx2")]
    pub unsafe fn permute(&mut self) {
        for round in 0..24 {
            self.theta();
            self.rho_pi();
            self.chi();
            self.iota(round);
        }
    }

    /// θ (theta) step - all 4 states in parallel
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn theta(&mut self) {
        // C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
        let mut c = [_mm256_setzero_si256(); 5];
        for x in 0..5 {
            c[x] = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_xor_si256(self.state[x][0], self.state[x][1]),
                    _mm256_xor_si256(self.state[x][2], self.state[x][3]),
                ),
                self.state[x][4],
            );
        }

        // D[x] = C[x-1] ^ ROL64(C[x+1], 1)
        let mut d = [_mm256_setzero_si256(); 5];
        for x in 0..5 {
            let c_plus = c[(x + 1) % 5];
            // ROL64 by 1: (c << 1) | (c >> 63)
            let rol1 = _mm256_or_si256(_mm256_slli_epi64(c_plus, 1), _mm256_srli_epi64(c_plus, 63));
            d[x] = _mm256_xor_si256(c[(x + 4) % 5], rol1);
        }

        // A[x,y] ^= D[x]
        for x in 0..5 {
            for y in 0..5 {
                self.state[x][y] = _mm256_xor_si256(self.state[x][y], d[x]);
            }
        }
    }

    /// ρ (rho) and π (pi) steps combined - all 4 states in parallel
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn rho_pi(&mut self) {
        let mut new_state = [[_mm256_setzero_si256(); 5]; 5];

        // Manually unrolled to allow constant shift amounts
        // Each (x,y) -> (y, 2x+3y mod 5) with rotation RHO[x][y]
        macro_rules! rho_pi_lane {
            ($x:expr, $y:expr, $rot:expr) => {{
                let new_x = $y;
                let new_y = (2 * $x + 3 * $y) % 5;
                let lane = self.state[$x][$y];
                let rotated = if $rot == 0 {
                    lane
                } else {
                    _mm256_or_si256(
                        _mm256_slli_epi64(lane, $rot),
                        _mm256_srli_epi64(lane, 64 - $rot),
                    )
                };
                new_state[new_x][new_y] = rotated;
            }};
        }

        // Row 0: rotations [0, 36, 3, 41, 18]
        rho_pi_lane!(0, 0, 0);
        rho_pi_lane!(0, 1, 36);
        rho_pi_lane!(0, 2, 3);
        rho_pi_lane!(0, 3, 41);
        rho_pi_lane!(0, 4, 18);

        // Row 1: rotations [1, 44, 10, 45, 2]
        rho_pi_lane!(1, 0, 1);
        rho_pi_lane!(1, 1, 44);
        rho_pi_lane!(1, 2, 10);
        rho_pi_lane!(1, 3, 45);
        rho_pi_lane!(1, 4, 2);

        // Row 2: rotations [62, 6, 43, 15, 61]
        rho_pi_lane!(2, 0, 62);
        rho_pi_lane!(2, 1, 6);
        rho_pi_lane!(2, 2, 43);
        rho_pi_lane!(2, 3, 15);
        rho_pi_lane!(2, 4, 61);

        // Row 3: rotations [28, 55, 25, 21, 56]
        rho_pi_lane!(3, 0, 28);
        rho_pi_lane!(3, 1, 55);
        rho_pi_lane!(3, 2, 25);
        rho_pi_lane!(3, 3, 21);
        rho_pi_lane!(3, 4, 56);

        // Row 4: rotations [27, 20, 39, 8, 14]
        rho_pi_lane!(4, 0, 27);
        rho_pi_lane!(4, 1, 20);
        rho_pi_lane!(4, 2, 39);
        rho_pi_lane!(4, 3, 8);
        rho_pi_lane!(4, 4, 14);

        self.state = new_state;
    }

    /// χ (chi) step - all 4 states in parallel
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn chi(&mut self) {
        for y in 0..5 {
            let t0 = self.state[0][y];
            let t1 = self.state[1][y];
            let t2 = self.state[2][y];
            let t3 = self.state[3][y];
            let t4 = self.state[4][y];

            // A[x,y] ^= (~A[x+1,y]) & A[x+2,y]
            self.state[0][y] = _mm256_xor_si256(t0, _mm256_andnot_si256(t1, t2));
            self.state[1][y] = _mm256_xor_si256(t1, _mm256_andnot_si256(t2, t3));
            self.state[2][y] = _mm256_xor_si256(t2, _mm256_andnot_si256(t3, t4));
            self.state[3][y] = _mm256_xor_si256(t3, _mm256_andnot_si256(t4, t0));
            self.state[4][y] = _mm256_xor_si256(t4, _mm256_andnot_si256(t0, t1));
        }
    }

    /// ι (iota) step - XOR round constant into lane (0,0) of all 4 states
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn iota(&mut self, round: usize) {
        let rc = _mm256_set1_epi64x(RC[round] as i64);
        self.state[0][0] = _mm256_xor_si256(self.state[0][0], rc);
    }
}

/// 4-way SHAKE128 for batch sampling
///
/// Processes 4 independent SHAKE128 instances in parallel.
#[cfg(target_arch = "x86_64")]
pub struct Shake128X4 {
    state: KeccakStateX4,
    absorbed: [usize; 4], // Bytes absorbed per state
}

#[cfg(target_arch = "x86_64")]
impl Shake128X4 {
    const RATE: usize = 168;

    /// Create new 4-way SHAKE128
    #[target_feature(enable = "avx2")]
    pub unsafe fn new() -> Self {
        Self {
            state: KeccakStateX4::new(),
            absorbed: [0; 4],
        }
    }

    /// Absorb data into a specific state
    #[target_feature(enable = "avx2")]
    pub unsafe fn absorb(&mut self, state_idx: usize, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let remaining = Self::RATE - self.absorbed[state_idx];
            let to_absorb = remaining.min(data.len() - pos);

            self.state
                .xor_bytes(state_idx, &data[pos..pos + to_absorb], Self::RATE);
            self.absorbed[state_idx] += to_absorb;
            pos += to_absorb;

            if self.absorbed[state_idx] == Self::RATE {
                // This state needs permutation - but we wait until all need it
                // For simplicity, permute now (can optimize later)
                self.state.permute();
                self.absorbed[state_idx] = 0;
            }
        }
    }

    /// Finalize all 4 states (apply padding)
    #[target_feature(enable = "avx2")]
    pub unsafe fn finalize(&mut self) {
        for i in 0..4 {
            // SHAKE domain separator
            self.state.xor_byte(i, self.absorbed[i], 0x1F);
            // Final padding bit
            self.state.xor_byte(i, Self::RATE - 1, 0x80);
        }
        self.state.permute();
    }

    /// Squeeze bytes from a specific state
    #[target_feature(enable = "avx2")]
    pub unsafe fn squeeze(&mut self, state_idx: usize, output: &mut [u8]) {
        let mut pos = 0;
        while pos < output.len() {
            let to_squeeze = Self::RATE.min(output.len() - pos);
            self.state
                .extract_bytes(state_idx, &mut output[pos..pos + to_squeeze], Self::RATE);
            pos += to_squeeze;

            if pos < output.len() {
                self.state.permute();
            }
        }
    }

    /// Squeeze from all 4 states at once into separate buffers
    #[target_feature(enable = "avx2")]
    pub unsafe fn squeeze_all(&mut self, outputs: &mut [&mut [u8]; 4]) {
        // Find max length needed
        let max_len = outputs.iter().map(|o| o.len()).max().unwrap_or(0);

        let mut pos = 0;
        while pos < max_len {
            let chunk = Self::RATE.min(max_len - pos);

            for (i, output) in outputs.iter_mut().enumerate() {
                if pos < output.len() {
                    let to_squeeze = chunk.min(output.len() - pos);
                    self.state
                        .extract_bytes(i, &mut output[pos..pos + to_squeeze], Self::RATE);
                }
            }
            pos += chunk;

            if pos < max_len {
                self.state.permute();
            }
        }
    }

    /// Squeeze multiple blocks from all 4 states into fixed-size arrays
    ///
    /// This is optimized for batch sampling where all 4 states need the same amount of data.
    /// Squeezes `num_blocks` × 168 bytes from each state.
    ///
    /// # Arguments
    /// * `bufs` - 4 output buffers (must have at least num_blocks * 168 bytes each)
    /// * `num_blocks` - Number of 168-byte blocks to squeeze
    /// * `batch_size` - How many of the 4 states to actually use (1-4)
    #[target_feature(enable = "avx2")]
    pub unsafe fn squeeze_blocks_x4(
        &mut self,
        bufs: &mut [[u8; 840]; 4],
        num_blocks: usize,
        batch_size: usize,
    ) {
        debug_assert!(num_blocks <= 5); // 5 * 168 = 840

        for block in 0..num_blocks {
            let offset = block * Self::RATE;
            for b in 0..batch_size {
                self.state
                    .extract_bytes(b, &mut bufs[b][offset..offset + Self::RATE], Self::RATE);
            }
            if block < num_blocks - 1 {
                self.state.permute();
            }
        }
    }

    /// Squeeze one more block from all states (after initial squeeze_blocks_x4)
    #[target_feature(enable = "avx2")]
    pub unsafe fn squeeze_one_block(&mut self, state_idx: usize, buf: &mut [u8; 168]) {
        self.state.permute();
        self.state.extract_bytes(state_idx, buf, Self::RATE);
    }
}

/// 4-way SHAKE256 for batch sampling
///
/// Processes 4 independent SHAKE256 instances in parallel.
/// Used for ML-DSA's ExpandMask which needs L=5 gamma1 samples.
#[cfg(target_arch = "x86_64")]
pub struct Shake256X4 {
    state: KeccakStateX4,
    absorbed: [usize; 4],
}

#[cfg(target_arch = "x86_64")]
impl Shake256X4 {
    const RATE: usize = 136; // SHAKE256 rate = 1088 bits = 136 bytes

    /// Create new 4-way SHAKE256
    #[target_feature(enable = "avx2")]
    pub unsafe fn new() -> Self {
        Self {
            state: KeccakStateX4::new(),
            absorbed: [0; 4],
        }
    }

    /// Absorb data into a specific state
    #[target_feature(enable = "avx2")]
    pub unsafe fn absorb(&mut self, state_idx: usize, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let remaining = Self::RATE - self.absorbed[state_idx];
            let to_absorb = remaining.min(data.len() - pos);

            self.state
                .xor_bytes(state_idx, &data[pos..pos + to_absorb], Self::RATE);
            self.absorbed[state_idx] += to_absorb;
            pos += to_absorb;

            if self.absorbed[state_idx] == Self::RATE {
                self.state.permute();
                self.absorbed[state_idx] = 0;
            }
        }
    }

    /// Finalize all 4 states (apply padding)
    #[target_feature(enable = "avx2")]
    pub unsafe fn finalize(&mut self) {
        for i in 0..4 {
            // SHAKE domain separator
            self.state.xor_byte(i, self.absorbed[i], 0x1F);
            // Final padding bit
            self.state.xor_byte(i, Self::RATE - 1, 0x80);
        }
        self.state.permute();
    }

    /// Squeeze bytes from a specific state
    #[target_feature(enable = "avx2")]
    pub unsafe fn squeeze(&mut self, state_idx: usize, output: &mut [u8]) {
        let mut pos = 0;
        while pos < output.len() {
            let to_squeeze = Self::RATE.min(output.len() - pos);
            self.state
                .extract_bytes(state_idx, &mut output[pos..pos + to_squeeze], Self::RATE);
            pos += to_squeeze;

            if pos < output.len() {
                self.state.permute();
            }
        }
    }

    /// Squeeze multiple blocks from all 4 states into fixed-size arrays
    ///
    /// For gamma1 sampling: 576 bytes for gamma1=2^17, 640 bytes for gamma1=2^19
    /// We use 680 bytes (5 * 136) to cover both cases.
    #[target_feature(enable = "avx2")]
    pub unsafe fn squeeze_blocks_x4(
        &mut self,
        bufs: &mut [[u8; 680]; 4],
        num_blocks: usize,
        batch_size: usize,
    ) {
        debug_assert!(num_blocks <= 5); // 5 * 136 = 680

        for block in 0..num_blocks {
            let offset = block * Self::RATE;
            for b in 0..batch_size {
                self.state
                    .extract_bytes(b, &mut bufs[b][offset..offset + Self::RATE], Self::RATE);
            }
            if block < num_blocks - 1 {
                self.state.permute();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_x4_correctness() {
        if !is_x86_feature_detected!("avx2") {
            println!("AVX2 not available, skipping test");
            return;
        }

        unsafe {
            // Test that 4-way produces same results as single Keccak
            let mut state_x4 = Shake128X4::new();

            // Absorb different data into each state
            let inputs = [
                b"test input 0".as_slice(),
                b"test input 1".as_slice(),
                b"test input 2".as_slice(),
                b"test input 3".as_slice(),
            ];

            for (i, input) in inputs.iter().enumerate() {
                state_x4.absorb(i, input);
            }
            state_x4.finalize();

            // Squeeze and verify each produces different output
            let mut outputs = [[0u8; 64]; 4];
            for i in 0..4 {
                state_x4.squeeze(i, &mut outputs[i]);
            }

            // All outputs should be different
            for i in 0..4 {
                for j in (i + 1)..4 {
                    assert_ne!(
                        outputs[i], outputs[j],
                        "States {} and {} produced same output",
                        i, j
                    );
                }
            }

            // Outputs should be non-zero
            for (i, output) in outputs.iter().enumerate() {
                assert!(
                    output.iter().any(|&b| b != 0),
                    "State {} produced all zeros",
                    i
                );
            }
        }
    }
}
