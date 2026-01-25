# WASM SIMD TDD Roadmap

**Spec:** [WASM-SIMD.md](./WASM-SIMD.md)
**Methodology:** Agent-TDD (Tests as Crystallized Understanding)

## Philosophy

Tests for SIMD are not about coverage metrics. They crystallize our understanding of:
1. **Correctness**: SIMD output must be bit-identical to scalar
2. **Performance**: SIMD must provide measurable speedup
3. **Boundaries**: Edge cases where SIMD behavior differs from scalar

## Test Categories

### P0: Correctness (Must Pass Before Any Code Ships)

These tests verify SIMD implementations produce identical output to scalar.

#### ChaCha20 SIMD Correctness

| ID | Test | Purpose |
|----|------|---------|
| C20-S1 | `simd_matches_scalar_single_block` | One 64-byte block |
| C20-S2 | `simd_matches_scalar_multi_block` | 1KB of keystream |
| C20-S3 | `simd_matches_scalar_counter_overflow` | Counter near u32::MAX |
| C20-S4 | `simd_matches_scalar_all_zeros_key` | Zero key edge case |
| C20-S5 | `simd_matches_scalar_all_ones_key` | 0xFF key edge case |
| C20-S6 | `simd_matches_rfc8439_test_vectors` | RFC 8439 KAT |

```rust
#[test]
fn simd_matches_scalar_single_block() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let mut scalar_output = [0u8; 64];
    let mut simd_output = [0u8; 64];

    chacha20_scalar(&key, &nonce, 0, &mut scalar_output);
    chacha20_simd(&key, &nonce, 0, &mut simd_output);

    assert_eq!(scalar_output, simd_output);
}
```

#### Poly1305 SIMD Correctness

| ID | Test | Purpose |
|----|------|---------|
| P13-S1 | `simd_matches_scalar_short_message` | < 16 bytes |
| P13-S2 | `simd_matches_scalar_block_aligned` | Exact 16-byte multiple |
| P13-S3 | `simd_matches_scalar_unaligned` | Non-multiple lengths |
| P13-S4 | `simd_matches_rfc8439_test_vectors` | RFC 8439 Poly1305 KAT |

#### BLAKE3 SIMD Correctness

| ID | Test | Purpose |
|----|------|---------|
| B3-S1 | `simd_matches_scalar_empty` | Empty input |
| B3-S2 | `simd_matches_scalar_single_chunk` | < 1024 bytes |
| B3-S3 | `simd_matches_scalar_multi_chunk` | > 1024 bytes |
| B3-S4 | `simd_matches_scalar_keyed` | Keyed hash mode |
| B3-S5 | `simd_matches_official_test_vectors` | BLAKE3 reference vectors |

#### SHA-256 SIMD Correctness

| ID | Test | Purpose |
|----|------|---------|
| SHA-S1 | `simd_matches_scalar_empty` | Empty input |
| SHA-S2 | `simd_matches_scalar_short` | < 64 bytes |
| SHA-S3 | `simd_matches_scalar_multi_block` | > 64 bytes |
| SHA-S4 | `simd_matches_nist_test_vectors` | NIST CAVP vectors |

### P0: Cross-Platform Consistency

| ID | Test | Purpose |
|----|------|---------|
| XP-1 | `wasm_simd_matches_native_simd` | Same output as x86 AVX2 |
| XP-2 | `wasm_simd_matches_scalar_all_platforms` | Bit-identical everywhere |

### P1: Performance Regression

These tests ensure SIMD actually improves performance.

| ID | Test | Threshold |
|----|------|-----------|
| PERF-C20-1 | `chacha20_simd_faster_than_scalar` | > 1.5x at 1KB |
| PERF-C20-2 | `chacha20_simd_faster_than_rustcrypto` | > 1.0x at 1KB |
| PERF-B3-1 | `blake3_simd_faster_than_scalar` | > 1.3x at 16KB |
| PERF-SHA-1 | `sha256_simd_faster_than_scalar` | > 1.2x at 16KB |

```rust
#[test]
fn chacha20_simd_faster_than_scalar() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut buf = vec![0u8; 1024];

    let scalar_start = Instant::now();
    for _ in 0..10000 {
        chacha20_scalar(&key, &nonce, 0, &mut buf);
    }
    let scalar_time = scalar_start.elapsed();

    let simd_start = Instant::now();
    for _ in 0..10000 {
        chacha20_simd(&key, &nonce, 0, &mut buf);
    }
    let simd_time = simd_start.elapsed();

    let speedup = scalar_time.as_nanos() as f64 / simd_time.as_nanos() as f64;
    assert!(speedup > 1.5, "SIMD should be >1.5x faster, got {}x", speedup);
}
```

### P1: Edge Cases

| ID | Test | Purpose |
|----|------|---------|
| EDGE-1 | `handles_unaligned_input` | Input not 16-byte aligned |
| EDGE-2 | `handles_unaligned_output` | Output buffer not aligned |
| EDGE-3 | `handles_zero_length` | Empty input/output |
| EDGE-4 | `handles_partial_final_block` | Input not block-aligned |

### P2: Build Verification

| ID | Test | Purpose |
|----|------|---------|
| BUILD-1 | `simd_instructions_present` | Check wasm contains v128 ops |
| BUILD-2 | `fallback_works_without_simd` | Scalar path still works |
| BUILD-3 | `feature_flag_controls_simd` | wasm-simd feature toggles impl |

```rust
#[test]
fn simd_instructions_present() {
    // This test runs at build time via wasm2wat
    // wasm2wat pkg/arcanum_wasm_bg.wasm | grep -c "v128" > 0
    // Automated in CI
}
```

### P2: Integration Tests (JS Side)

| ID | Test | Purpose |
|----|------|---------|
| JS-SIMD-1 | `simd_build_loads_in_browser` | SIMD bundle works |
| JS-SIMD-2 | `simd_matches_scalar_from_js` | JS can verify output |
| JS-SIMD-3 | `feature_detection_works` | JS can detect SIMD support |

```javascript
test("simd_build_loads_in_browser", async () => {
    const simdWasm = await loadWasm("arcanum_wasm_simd.wasm");
    const scalarWasm = await loadWasm("arcanum_wasm.wasm");

    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const data = randomBytes(1024);

    const simdResult = simdWasm.chacha20_encrypt(key, nonce, data);
    const scalarResult = scalarWasm.chacha20_encrypt(key, nonce, data);

    expect(simdResult).toEqual(scalarResult);
});
```

## Test Implementation Order

### Phase 1: ChaCha20 SIMD (Week 1)

1. [x] Create `chacha20_wasm_simd.rs` skeleton
2. [x] Write C20-S6 (RFC KAT) - this drives implementation
3. [x] Implement quarter round SIMD
4. [x] Write C20-S1 through C20-S5
5. [x] Write PERF-C20-1 and PERF-C20-2
6. [x] Verify performance targets met

### Phase 2: BLAKE3 SIMD (Week 2)

1. [x] Create `blake3_wasm_simd.rs` skeleton
2. [x] Write B3-S5 (reference vectors)
3. [x] Implement compression SIMD
4. [x] Write B3-S1 through B3-S4
5. [x] Write PERF-B3-1
6. [x] Verify performance targets met

### Phase 3: SHA-256 SIMD (Week 3)

1. [x] Create `sha256_wasm_simd.rs` skeleton
2. [x] Write SHA-S4 (NIST vectors)
3. [x] Implement message schedule SIMD
4. [x] Write SHA-S1 through SHA-S3
5. [x] Write PERF-SHA-1
6. [x] Verify performance targets met

### Phase 4: Integration & Polish (Week 4)

1. [x] Write XP-1 and XP-2 (cross-platform) - xp_test_vectors.rs + test-simd.mjs
2. [x] Write EDGE-1 through EDGE-4
3. [x] Write BUILD-1 through BUILD-3 (CI wasm.yml)
4. [x] Write JS-SIMD-1 through JS-SIMD-3 (test-simd.mjs)
5. [x] Update CI to build both SIMD and scalar
6. [x] Document feature detection for consumers

## Test File Structure

```
crates/arcanum-primitives/
├── src/
│   ├── chacha20.rs           # Scalar impl
│   ├── chacha20_wasm_simd.rs # WASM SIMD impl (new)
│   ├── blake3.rs             # Scalar impl
│   ├── blake3_wasm_simd.rs   # WASM SIMD impl (new)
│   └── ...
└── tests/
    ├── chacha20_simd_tests.rs
    ├── blake3_simd_tests.rs
    └── sha256_simd_tests.rs

crates/arcanum-wasm/
└── tests/
    └── js/
        ├── test-simd.mjs      # SIMD-specific JS tests
        └── bench-simd.mjs     # SIMD benchmarks
```

## CI Configuration

```yaml
# .github/workflows/wasm.yml additions

  build-simd:
    name: Build WASM (SIMD)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - name: Build SIMD bundle
        run: |
          RUSTFLAGS="-C target-feature=+simd128" \
          wasm-pack build crates/arcanum-wasm \
            --target web \
            --features backend-native-simd
      - name: Verify SIMD instructions present
        run: |
          wasm2wat crates/arcanum-wasm/pkg/arcanum_wasm_bg.wasm \
            | grep -c "v128" | xargs test 0 -lt

  test-simd-correctness:
    name: SIMD Correctness Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SIMD vs Scalar tests
        run: |
          RUSTFLAGS="-C target-feature=+simd128" \
          cargo test --features wasm-simd simd_matches
```

## Definition of Done

A SIMD implementation is complete when:

1. **All P0 tests pass** - Correctness is non-negotiable
2. **Performance targets met** - Must be faster than scalar
3. **No regressions** - Existing tests still pass
4. **CI green** - Both SIMD and scalar builds succeed
5. **Documentation updated** - README reflects SIMD support

---

## Appendix: Test Vector Sources

- **ChaCha20**: [RFC 8439 Section 2.4.2](https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2)
- **Poly1305**: [RFC 8439 Section 2.5.2](https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.2)
- **BLAKE3**: [BLAKE3 Test Vectors](https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json)
- **SHA-256**: [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
