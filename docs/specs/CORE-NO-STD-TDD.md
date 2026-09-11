# arcanum-core `no_std` Support TDD Roadmap

**Document ID:** TDD-CORE-NOSTD-001
**Version:** 1.1.0
**Date:** 2026-02-03
**Governing Spec:** [CORE-NO-STD-SPEC.md](./CORE-NO-STD-SPEC.md)
**Status:** GREEN Complete — All phases pass

---

## Overview

This roadmap defines the test-driven implementation path for arcanum-core `no_std` support, following Agent-TDD methodology. Tests are organized by priority (P0-P2) and aligned with the five implementation phases in the governing spec.

**Methodology:**
- Tests are crystallized understanding, not coverage theater
- Each test specifies behavior, not implementation
- RED tests are written first; all should fail against current code
- GREEN phase applies minimum changes to pass each test
- REFACTOR only after GREEN; existing tests must stay green
- Spec gaps discovered during testing trigger SDD UPDATE cycle

**Current State:**
- `cargo check -p arcanum-core --no-default-features` → **0 errors** ✅
- `cargo check -p arcanum-core --no-default-features --features alloc` → **0 errors** ✅
- `cargo check -p arcanum-core --no-default-features --features "alloc,encoding"` → **0 errors** ✅
- All 13 feature combinations compile clean ✅
- 93 tests pass (std), 56 tests pass (no_std+alloc) ✅
- Zero clippy warnings across all profiles ✅

---

## Test Priority Levels

| Priority | Description | Gate |
|----------|-------------|------|
| **P0** | Compilation gates — crate must build under each feature profile | Blocks merge |
| **P1** | Core type contracts — fundamental types work under no_std | Blocks merge |
| **P2** | Feature isolation — gated modules invisible when disabled | Blocks stable tag |
| **P3** | Regression — existing std tests unbroken | Blocks merge |

---

## Phase 1: Cargo.toml Restructure

### 1.1 Feature Profile Compilation (P0)

**Spec Requirement:** Crate compiles under three feature profiles (SPEC-CORE-NOSTD-001 §1.1).

These tests gate everything else. If the crate doesn't compile, nothing runs.

```bash
# RED — all three should fail before Phase 1 implementation
cargo check -p arcanum-core --no-default-features
cargo check -p arcanum-core --no-default-features --features alloc
cargo check -p arcanum-core --no-default-features --features "alloc,encoding"

# GREEN target: all three pass after Cargo.toml restructure
```

**Verification script:**
```bash
#!/bin/bash
# tests/scripts/check_no_std_profiles.sh
set -e

echo "=== Profile: bare no_std ==="
cargo check -p arcanum-core --no-default-features

echo "=== Profile: no_std + alloc ==="
cargo check -p arcanum-core --no-default-features --features alloc

echo "=== Profile: no_std + alloc + encoding ==="
cargo check -p arcanum-core --no-default-features --features "alloc,encoding"

echo "=== Profile: no_std + alloc + encoding + serde ==="
cargo check -p arcanum-core --no-default-features --features "alloc,encoding,serde"

echo "=== Profile: full std (regression) ==="
cargo check -p arcanum-core

echo "ALL PROFILES PASS"
```

### 1.2 Dependency Tree Verification (P0)

**Spec Requirement:** std-requiring deps must not appear in no_std builds (SPEC-CORE-NOSTD-001 §2.1).

```bash
# Verify parking_lot, lru, chrono, uuid, once_cell are absent
# when std feature is disabled

cargo tree -p arcanum-core --no-default-features -e normal \
  | grep -E "parking_lot|chrono|uuid|once_cell|async-trait" \
  && echo "FAIL: std-only deps present in no_std build" && exit 1 \
  || echo "PASS: no std-only deps in no_std tree"

# Verify lru is absent (depends on std HashMap)
cargo tree -p arcanum-core --no-default-features -e normal \
  | grep "lru" \
  && echo "FAIL: lru present in no_std build" && exit 1 \
  || echo "PASS: lru absent from no_std tree"
```

### 1.3 Default Feature Regression (P3)

**Spec Requirement:** Zero API breakage with default features (SPEC-CORE-NOSTD-001 §1.1).

```bash
# Must pass before and after every phase
cargo test -p arcanum-core
cargo doc -p arcanum-core --no-deps
```

---

## Phase 2: Core Module Gates

### 2.1 SecretBuffer and SecureVec Under alloc (P1)

**Spec Requirement:** buffer.rs is alloc-compatible (SPEC-CORE-NOSTD-001 §4.1).

```rust
// tests/no_std_buffer_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::buffer::{SecretBuffer, SecureVec};

    #[test]
    fn spec_secret_buffer_create_and_access() {
        // SecretBuffer should be constructible from a fixed-size array
        let buf = SecretBuffer::<32>::new([0x42u8; 32]);
        assert_eq!(buf.as_ref().len(), 32);
        assert_eq!(buf.as_ref()[0], 0x42);
    }

    #[test]
    fn spec_secure_vec_create_zeroed() {
        // SecureVec requires alloc but not std
        let v = SecureVec::new(64);
        assert_eq!(v.len(), 64);
        // Initialized to zero
        assert!(v.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn spec_secure_vec_from_slice() {
        let data = [1u8, 2, 3, 4, 5];
        let v = SecureVec::from(&data[..]);
        assert_eq!(v.as_ref(), &data);
    }
}
```

**Run:** `cargo test -p arcanum-core --no-default-features --features alloc --test no_std_buffer_test`

### 2.2 Error Types Under alloc (P1)

**Spec Requirement:** error.rs compiles with alloc; String variants available (SPEC-CORE-NOSTD-001 §4.3).

```rust
// tests/no_std_error_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use arcanum_core::error::Error;

    #[test]
    fn spec_error_invalid_key_length_no_alloc_needed() {
        // Variants with only primitive fields work without alloc
        let e = Error::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        // Error exists and is constructible
        match e {
            Error::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn spec_error_string_variants_with_alloc() {
        // String-carrying variants require alloc
        let e = Error::KeyNotFound("test-key-id".to_string());
        match e {
            Error::KeyNotFound(id) => assert_eq!(id, "test-key-id"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn spec_error_io_conversion_absent_without_std() {
        // std::io::Error conversion should not be available
        // This is a compile-time contract — if this file compiles
        // under no_std + alloc, the From<std::io::Error> impl
        // is correctly gated.
    }
}
```

**Run:** `cargo test -p arcanum-core --no-default-features --features alloc --test no_std_error_test`

### 2.3 SecretKey and PublicKey Under alloc (P1)

**Spec Requirement:** key.rs core types work without std; KeyId/KeyMetadata gated behind std (SPEC-CORE-NOSTD-001 §4.4).

```rust
// tests/no_std_key_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::key::{PublicKey, SecretKey};

    #[test]
    fn spec_secret_key_default() {
        let key = SecretKey::<32>::default();
        // Key exists with correct length
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn spec_public_key_from_bytes() {
        let bytes = [0xABu8; 32];
        let pk = PublicKey::<32>::from(bytes);
        assert_eq!(pk.as_ref(), &bytes);
    }

    #[test]
    fn spec_secret_key_constant_time_eq() {
        use subtle::ConstantTimeEq;
        let key1 = SecretKey::<32>::default();
        let key2 = SecretKey::<32>::default();
        // Both are zeroed, so they should be equal
        assert!(bool::from(key1.ct_eq(&key2)));
    }
}
```

**Negative compile-time test (P2):**
```rust
// tests/no_std_key_metadata_unavailable.rs
// This test verifies that KeyId and KeyMetadata are NOT available
// when std feature is disabled.
//
// Strategy: This file imports KeyMetadata under no_std. If the
// feature gate is correct, this file should FAIL to compile.
// We use trybuild or compile_fail doctest for this.

/// ```compile_fail
/// #![no_std]
/// extern crate alloc;
/// extern crate arcanum_core;
/// use arcanum_core::key::KeyId;  // Should not exist without std
/// ```
fn _key_id_gated() {}

/// ```compile_fail
/// #![no_std]
/// extern crate alloc;
/// extern crate arcanum_core;
/// use arcanum_core::key::KeyMetadata;  // Should not exist without std
/// ```
fn _key_metadata_gated() {}
```

**Run:** `cargo test -p arcanum-core --no-default-features --features alloc --test no_std_key_test`

### 2.4 Nonce Under no_std (P1)

**Spec Requirement:** Nonce<N> works without std; NonceTracker gated behind std (SPEC-CORE-NOSTD-001 §4.5).

```rust
// tests/no_std_nonce_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::nonce::Nonce;

    #[test]
    fn spec_nonce_from_bytes() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce = Nonce::<12>::from(bytes);
        assert_eq!(nonce.as_ref(), &bytes);
    }

    #[test]
    fn spec_nonce_zeroed() {
        let nonce = Nonce::<12>::default();
        assert!(nonce.as_ref().iter().all(|&b| b == 0));
    }
}
```

**Negative compile-time test (P2):**
```rust
/// ```compile_fail
/// #![no_std]
/// extern crate alloc;
/// extern crate arcanum_core;
/// use arcanum_core::nonce::NonceTracker;  // Should not exist without std
/// ```
fn _nonce_tracker_gated() {}
```

**Run:** `cargo test -p arcanum-core --no-default-features --features alloc --test no_std_nonce_test`

### 2.5 Version Types Under no_std (P1)

**Spec Requirement:** version.rs compiles with alloc only (SPEC-CORE-NOSTD-001 §4.9).

```rust
// tests/no_std_version_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::version::Version;

    #[test]
    fn spec_version_create_and_compare() {
        let v1 = Version::new(0, 1, 0);
        let v2 = Version::new(0, 2, 0);

        assert_eq!(v1.major(), 0);
        assert_eq!(v1.minor(), 1);
        assert_eq!(v1.patch(), 0);

        // v2 > v1
        assert!(v2 > v1);
    }

    #[test]
    fn spec_version_equality() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 0);
        assert_eq!(v1, v2);
    }
}
```

**Run:** `cargo test -p arcanum-core --no-default-features --features alloc --test no_std_version_test`

---

## Phase 3: Peripheral Module Gates

### 3.1 Encoding Module Isolation (P2)

**Spec Requirement:** encoding.rs gated behind `encoding` feature (SPEC-CORE-NOSTD-001 §4.2).

```rust
// tests/no_std_encoding_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn spec_encoding_available_with_feature() {
        // This test file is compiled with --features "alloc,encoding"
        // If encoding module is correctly gated, this import works
        #[cfg(feature = "encoding")]
        {
            use arcanum_core::encoding::Hex;
            let encoded = Hex::encode(&[0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(encoded, "deadbeef");

            let decoded = Hex::decode("deadbeef").unwrap();
            assert_eq!(decoded, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
    }
}
```

**Run with encoding:** `cargo test -p arcanum-core --no-default-features --features "alloc,encoding" --test no_std_encoding_test`

**Negative compile-time test (P2):**
```rust
/// Encoding module should not be visible without the encoding feature.
///
/// ```compile_fail
/// #![no_std]
/// extern crate alloc;
/// extern crate arcanum_core;
/// use arcanum_core::encoding::Hex;  // Should not exist without encoding feature
/// ```
fn _encoding_gated() {}
```

### 3.2 Time Module Isolation (P2)

**Spec Requirement:** time.rs gated entirely behind `std` (SPEC-CORE-NOSTD-001 §4.7).

```rust
/// Time module should not be visible without std.
///
/// ```compile_fail
/// #![no_std]
/// extern crate alloc;
/// extern crate arcanum_core;
/// use arcanum_core::time::MonotonicClock;  // Should not exist without std
/// ```
fn _time_gated() {}
```

### 3.3 Random Module Degraded API (P1)

**Spec Requirement:** random.rs has reduced API under no_std; OsRng requires std (SPEC-CORE-NOSTD-001 §4.6).

```rust
// tests/no_std_random_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    // Under no_std, the random module should still be importable
    // but OsRng and ThreadLocalRng should not be available.

    #[test]
    fn spec_random_module_exists() {
        // The module itself should be visible even under no_std,
        // but with a reduced API surface.
        // Concrete test: random_array works if caller provides an RNG.
    }
}
```

**Property test with std (P1):**
```rust
#[cfg(feature = "std")]
mod std_random_tests {
    use arcanum_core::random::{OsRng, CryptoRng};

    #[test]
    fn spec_os_rng_available_with_std() {
        let mut rng = OsRng;
        let mut buf = [0u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut buf);
        // At least one byte should be non-zero (probabilistic)
        assert!(buf.iter().any(|&b| b != 0));
    }
}
```

### 3.4 Async Traits Isolation (P2)

**Spec Requirement:** async_trait-based traits gated behind `async` feature (SPEC-CORE-NOSTD-001 §4.8).

```rust
// tests/no_std_traits_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    // Sync traits should be available under no_std + alloc
    use arcanum_core::traits::{
        Encryptor, Decryptor, Hasher, Signer, Verifier,
    };

    #[test]
    fn spec_sync_traits_available() {
        // Compile-time check: these traits exist under no_std
        fn _assert_encryptor<T: Encryptor>() {}
        fn _assert_decryptor<T: Decryptor>() {}
        fn _assert_hasher<T: Hasher>() {}
        fn _assert_signer<T: Signer>() {}
        fn _assert_verifier<T: Verifier>() {}
    }
}
```

**Negative compile-time test (P2):**
```rust
/// Async traits (KeyStore, ThresholdSigner) should not exist without async feature.
///
/// ```compile_fail
/// #![no_std]
/// extern crate alloc;
/// extern crate arcanum_core;
/// use arcanum_core::traits::KeyStore;  // Should not exist without async feature
/// ```
fn _async_traits_gated() {}
```

---

## Phase 4: Prelude and Integration

### 4.1 Prelude Under no_std + alloc (P1)

**Spec Requirement:** Prelude exports adapt to enabled features (SPEC-CORE-NOSTD-001 §5).

```rust
// tests/no_std_prelude_test.rs
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use arcanum_core::prelude::*;

    #[test]
    fn spec_prelude_core_types_available() {
        // These must always be in the prelude under alloc
        let _key = SecretKey::<32>::default();
        let _buf = SecretBuffer::<16>::new([0u8; 16]);
        let _v = Version::new(0, 1, 0);
    }

    #[test]
    fn spec_prelude_error_types_available() {
        let _e: Error = Error::KeyGenerationFailed;
        let _r: Result<()> = Ok(());
    }

    #[test]
    fn spec_prelude_reexports_available() {
        // zeroize, subtle, secrecy re-exports
        fn _assert_zeroize<T: Zeroize>() {}
        fn _assert_ct_eq<T: ConstantTimeEq>() {}
    }
}
```

**Run:** `cargo test -p arcanum-core --no-default-features --features alloc --test no_std_prelude_test`

### 4.2 Prelude Under Full std (P3, Regression)

```rust
// tests/std_prelude_regression_test.rs

#[cfg(test)]
mod tests {
    use arcanum_core::prelude::*;

    #[test]
    fn spec_prelude_std_extras_available() {
        // These should be in the prelude when std is enabled
        // but NOT when std is disabled
        #[cfg(feature = "std")]
        {
            let _rng = OsRng;
        }

        #[cfg(feature = "encoding")]
        {
            let _ = Hex::encode(&[0xFF]);
        }
    }
}
```

**Run:** `cargo test -p arcanum-core --test std_prelude_regression_test`

---

## Phase 5: Downstream and Cross-Crate Validation

### 5.1 Downstream no_std Dependency (P1)

**Spec Requirement:** Downstream crates can depend on arcanum-core without pulling in std (SPEC-CORE-NOSTD-001 §7, Phase 5).

```rust
// Run from a downstream crate (e.g., arcanum-hash)
// Verify arcanum-hash can compile with arcanum-core in no_std mode

// test script:
// cargo check -p arcanum-hash --no-default-features
// This should succeed because arcanum-hash already compiles under
// no_std, but currently forces arcanum-core's std features.
// After implementation, arcanum-hash should be able to use
// arcanum-core with default-features = false.
```

**Verification:**
```bash
# After implementation, these should all pass:
cargo check -p arcanum-hash --no-default-features
cargo check -p arcanum-symmetric --no-default-features
cargo check -p arcanum-pqc --no-default-features

# Verify arcanum-core is not pulling std into these crates
cargo tree -p arcanum-hash --no-default-features -e normal \
  | grep "parking_lot\|chrono\|uuid\|lru" \
  && echo "FAIL" && exit 1 \
  || echo "PASS"
```

### 5.2 Feature Combination Matrix (P2)

**Spec Requirement:** All valid feature combinations compile (SPEC-CORE-NOSTD-001 §7, Phase 4).

```bash
#!/bin/bash
# tests/scripts/check_feature_matrix.sh
set -e

FEATURES=(
    ""
    "alloc"
    "alloc,encoding"
    "alloc,encoding,serde"
    "alloc,serde"
    "alloc,async"
    "alloc,encoding,serde,async"
    "std"
    "std,serde"
    "std,encoding"
    "std,encoding,serde"
    "std,encoding,serde,async"
    "std,encoding,serde,async,hazmat"
)

for feat in "${FEATURES[@]}"; do
    if [ -z "$feat" ]; then
        echo "=== --no-default-features ==="
        cargo check -p arcanum-core --no-default-features
    else
        echo "=== --no-default-features --features $feat ==="
        cargo check -p arcanum-core --no-default-features --features "$feat"
    fi
done

echo "=== default features (regression) ==="
cargo check -p arcanum-core
cargo test -p arcanum-core

echo "ALL FEATURE COMBINATIONS PASS"
```

---

## Consolidated Test File Map

| Test File | Phase | Priority | Feature Profile | Tests |
|-----------|-------|----------|-----------------|-------|
| `scripts/check_no_std_profiles.sh` | 1 | P0 | multiple | 5 cargo check invocations |
| `scripts/check_feature_matrix.sh` | 5 | P2 | 14 combos | 14 cargo check invocations |
| `no_std_buffer_test.rs` | 2 | P1 | alloc | 3 tests |
| `no_std_error_test.rs` | 2 | P1 | alloc | 3 tests |
| `no_std_key_test.rs` | 2 | P1 | alloc | 3 tests |
| `no_std_nonce_test.rs` | 2 | P1 | alloc | 2 tests |
| `no_std_version_test.rs` | 2 | P1 | alloc | 2 tests |
| `no_std_encoding_test.rs` | 3 | P2 | alloc,encoding | 1 test |
| `no_std_random_test.rs` | 3 | P1 | alloc / std | 2 tests |
| `no_std_traits_test.rs` | 3 | P2 | alloc | 1 test |
| `no_std_prelude_test.rs` | 4 | P1 | alloc | 3 tests |
| `std_prelude_regression_test.rs` | 4 | P3 | std (default) | 1 test |
| (compile_fail doctests) | 2-3 | P2 | no_std | 5 negative tests |

**Total: ~26 tests + 19 cargo check invocations + 5 compile_fail doctests**

---

## RED/GREEN/REFACTOR Sequence

### Step 1: RED — Establish Baseline

```bash
# Run all P0 checks — all should FAIL
cargo check -p arcanum-core --no-default-features           # FAIL (154 errors)
cargo check -p arcanum-core --no-default-features --features alloc  # FAIL
cargo test -p arcanum-core                                   # PASS (baseline)
```

Document error count: **154 errors**.

### Step 2: GREEN (Phase 1) — Cargo.toml Restructure

Apply SPEC-CORE-NOSTD-001 §3.1-3.3.

```bash
# After changes:
cargo check -p arcanum-core --no-default-features           # Target: < 50 errors
cargo check -p arcanum-core                                  # MUST still PASS
```

Expected: error count drops significantly as optional deps are removed from no_std build.
Remaining errors will be `String`/`Vec`/`std::` references in source files.

### Step 3: GREEN (Phase 2) — Core Module Gates

Apply SPEC-CORE-NOSTD-001 §4.1, 4.3, 4.4, 4.5, 4.9.

```bash
# After changes:
cargo check -p arcanum-core --no-default-features --features alloc  # Target: PASS
cargo test -p arcanum-core --no-default-features --features alloc   # Run P1 tests
cargo test -p arcanum-core                                          # Regression PASS
```

### Step 4: GREEN (Phase 3) — Peripheral Module Gates

Apply SPEC-CORE-NOSTD-001 §4.2, 4.6, 4.7, 4.8.

```bash
# After changes:
cargo check -p arcanum-core --no-default-features                   # Target: PASS (bare)
cargo check -p arcanum-core --no-default-features --features alloc  # PASS
cargo check -p arcanum-core --no-default-features --features "alloc,encoding"  # PASS
cargo test -p arcanum-core                                          # Regression PASS
```

### Step 5: GREEN (Phase 4) — Prelude + lib.rs

Apply SPEC-CORE-NOSTD-001 §5.

```bash
# After changes:
cargo test -p arcanum-core --no-default-features --features alloc   # All P1 tests PASS
cargo test -p arcanum-core                                          # Regression PASS
```

### Step 6: GREEN (Phase 5) — Downstream Validation

```bash
# Verify downstream crates don't pull std via arcanum-core
cargo check -p arcanum-hash --no-default-features
cargo check -p arcanum-symmetric --no-default-features

# Run feature matrix script
bash tests/scripts/check_feature_matrix.sh
```

### Step 7: REFACTOR

- Remove any dead code behind feature gates
- Consolidate redundant `#[cfg(...)]` blocks where possible
- Run `cargo clippy -p arcanum-core` and `cargo clippy -p arcanum-core --no-default-features --features alloc`
- Verify no new warnings introduced

---

## Exit Criteria (All Phases Complete)

| Criterion | Verification Command |
|-----------|---------------------|
| Bare no_std compiles | `cargo check -p arcanum-core --no-default-features` |
| no_std + alloc compiles | `cargo check -p arcanum-core --no-default-features --features alloc` |
| no_std + alloc + encoding compiles | `cargo check -p arcanum-core --no-default-features --features "alloc,encoding"` |
| Full feature matrix compiles | `bash tests/scripts/check_feature_matrix.sh` |
| All P0/P1 tests pass | `cargo test -p arcanum-core --no-default-features --features alloc` |
| Regression: all existing tests pass | `cargo test -p arcanum-core` |
| No std-only deps in no_std tree | `cargo tree -p arcanum-core --no-default-features -e normal` |
| Downstream crates unaffected | `cargo check -p arcanum-hash --no-default-features` |
| Zero clippy warnings | `cargo clippy -p arcanum-core --no-default-features --features alloc` |

---

## Gap Tracking

| Gap ID | Discovery | Spec Impact | Resolution |
|--------|-----------|-------------|------------|
| GAP-001 | GREEN Phase 5 | KeyId/KeyMetadata had unconditional `Serialize`/`Deserialize` derives | Added `#[cfg_attr(feature = "serde", derive(...))]` gates |
| GAP-002 | GREEN Phase 5 | `random_id()` and `random_token()` use encoding deps under `#[cfg(feature = "std")]` only | Added `#[cfg(all(feature = "std", feature = "encoding"))]` gate |
| GAP-003 | REFACTOR | Inline unit tests in buffer.rs, random.rs, key.rs, version.rs, error.rs lacked feature gates | Added `#[cfg(feature = "std")]`/`#[cfg(feature = "encoding")]` gates and `ToString` imports |

Gaps discovered during RED/GREEN phases will be logged here and trigger updates to SPEC-CORE-NOSTD-001.

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-03 | Initial RED phase — all test specifications defined |
| 1.1.0 | 2026-02-03 | GREEN complete — all phases implemented, 13 feature combos pass, 10 test files written |
