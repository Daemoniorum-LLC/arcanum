# arcanum-core `no_std` Support Specification

**Document ID:** SPEC-CORE-NOSTD-001
**Version:** 1.0.0
**Date:** 2026-02-03
**Author:** Arcanum Development Team
**Status:** Draft

**Related Specs:**
- [WASM-SUPPORT.md](./WASM-SUPPORT.md) — Identifies arcanum-core blockers (Sections 2.1, 2.2)
- [WASM-TDD-ROADMAP.md](./WASM-TDD-ROADMAP.md) — Test requirements for no_std compliance
- [RELEASE-ROADMAP.md](../RELEASE-ROADMAP.md) — Phase 3.3: Add no_std Gates

---

## 1. Executive Summary

arcanum-core declares `#![cfg_attr(not(feature = "std"), no_std)]` in its `lib.rs` and
lists `"no-std"` in its crate categories, but compilation with `--no-default-features`
fails with **154 errors** across all 9 source modules. The root cause is unconditional
dependencies on std-requiring crates (`parking_lot`, `chrono`, `uuid`, `lru`, `once_cell`,
`async-trait`) and missing conditional `alloc` imports throughout the source.

This specification defines the feature-gating strategy, module-level changes, and TDD
plan to make arcanum-core compile under `no_std` while preserving full functionality
when the `std` feature is enabled.

### 1.1 Goals

- arcanum-core compiles with `--no-default-features` (no_std + no alloc)
- arcanum-core compiles with `--no-default-features --features alloc` (no_std + alloc)
- All existing tests pass with default features (`std`)
- Zero API breakage for downstream crates using default features
- Downstream crates can depend on arcanum-core without pulling in std

### 1.2 Non-Goals

- Making all dependency crates themselves no_std-compatible (out of scope)
- Removing any existing functionality under the `std` feature
- Rewriting modules; changes should be additive (feature gates + conditional imports)

### 1.3 Current Error Distribution

| Source File | Errors | Primary Causes |
|-------------|--------|----------------|
| encoding.rs | 30 | String, Vec, format!, encoding crate deps |
| traits.rs | 26 | Vec, Box, async_trait, String |
| error.rs | 21 | String (in error variants), std::io::Error |
| buffer.rs | 20 | Vec, std::ops, std::fmt, std::mem |
| key.rs | 16 | String, Vec, chrono, uuid, HashMap |
| version.rs | 15 | String, std::fmt, std::cmp, serde |
| random.rs | 14 | Vec, String, std::sync, std::time, thread_local |
| nonce.rs | 8 | format!, parking_lot, lru, std::sync::atomic |
| time.rs | 3 | std::time, std::thread, std::sync::atomic |

---

## 2. Dependency Audit

### 2.1 Dependency Classification

Every dependency in arcanum-core's `Cargo.toml` falls into one of three categories:

**Category A — Core (always required, no_std compatible):**

| Dependency | no_std Support | Notes |
|------------|:-:|-------|
| `zeroize` | Yes | Already feature-propagated via `std = ["zeroize/std"]` |
| `subtle` | Yes | Pure no_std crate |
| `constant_time_eq` | Yes | Pure no_std crate |
| `thiserror` | Yes (v2.0) | Workspace uses 2.0 which supports no_std |
| `secrecy` | Yes | Core re-export, no_std compatible |
| `typenum` | Yes | Compile-time integers, no_std |
| `generic-array` | Yes | no_std compatible |
| `arrayvec` | Yes | Stack-allocated, no_std by default |

**Category B — Conditionally required (feature-gate behind `std` or dedicated feature):**

| Dependency | Gate Feature | Used In | Rationale |
|------------|-------------|---------|-----------|
| `parking_lot` | `std` | nonce.rs (NonceTracker) | OS sync primitives, no no_std equivalent |
| `lru` | `std` | nonce.rs (NonceTracker) | Requires std::collections::HashMap internally |
| `once_cell` | `std` | (transitive) | std::sync-based; `core` has `LazyCell` since 1.80 |
| `chrono` | `std` | key.rs (KeyMetadata) | System time, timezone; no embedded equivalent |
| `uuid` | `std` | key.rs (KeyId) | Requires OS entropy via getrandom for v4 |
| `async-trait` | `async` | traits.rs | Requires alloc + proc-macro; irrelevant in embedded |
| `blake3` | `alloc` | encoding.rs, random.rs | Hashing is no_std but streaming needs alloc |
| `rand` | `std` | buffer.rs, key.rs, random.rs | Already propagated; OsRng requires std |
| `rand_core` | `std` | random.rs | Already propagated via features |
| `rand_chacha` | `std` | random.rs (DeterministicRng) | Seedable RNG, could work with alloc |
| `getrandom` | `std` | random.rs | OS entropy source; unavailable in bare no_std |

**Category C — Encoding (feature-gate behind dedicated `encoding` feature):**

| Dependency | Gate Feature | Used In |
|------------|-------------|---------|
| `hex` | `encoding` | encoding.rs, key.rs, nonce.rs, random.rs |
| `base64ct` | `encoding` | encoding.rs, random.rs |
| `base32ct` | `encoding` | encoding.rs |
| `bs58` | `encoding` | encoding.rs |
| `bech32` | `encoding` | encoding.rs |
| `multibase` | `encoding` | encoding.rs |

**Category D — Collection types (no_std compatible, keep unconditional):**

| Dependency | no_std Support | Notes |
|------------|:-:|-------|
| `bytes` | Yes | no_std compatible with alloc feature |
| `smallvec` | Yes | no_std compatible |
| `bitvec` | Yes | no_std compatible with alloc |

### 2.2 Module → Dependency Matrix

```
                parking  once           rand   async
Module     lru  _lot    _cell  chrono  uuid  _chacha  _trait  encoding_crates
─────────  ───  ──────  ─────  ──────  ────  ───────  ──────  ───────────────
buffer.rs                                                      hex (debug)
encoding.rs                                                    ALL
error.rs
key.rs                          ✓       ✓                      hex
nonce.rs   ✓    ✓
random.rs                                     ✓                hex, base64ct
time.rs
traits.rs                                              ✓
version.rs
```

---

## 3. Feature Flag Design

### 3.1 Proposed Cargo.toml Features

```toml
[features]
default = ["std", "serde", "encoding"]

# Standard library support - enables all std-dependent functionality
std = [
    "alloc",
    "zeroize/std",
    "rand/std",
    "rand_core/std",
    "getrandom/std",
    "bytes/std",
    "dep:parking_lot",
    "dep:lru",
    "dep:once_cell",
    "dep:chrono",
    "dep:uuid",
    "dep:rand_chacha",
]

# Alloc support without full std (Vec, String, Box)
alloc = [
    "zeroize/alloc",
    "dep:blake3",
]

# Encoding formats (requires alloc for String returns)
encoding = [
    "alloc",
    "dep:hex",
    "dep:base64ct",
    "dep:base32ct",
    "dep:bs58",
    "dep:bech32",
    "dep:multibase",
]

# Async trait support
async = ["dep:async-trait"]

# Serialization
serde = ["dep:serde", "secrecy/serde"]

# Hazardous materials
hazmat = []
```

### 3.2 Feature Dependency Graph

```
default
├── std
│   ├── alloc
│   │   ├── zeroize/alloc
│   │   └── dep:blake3
│   ├── zeroize/std, rand/std, rand_core/std, getrandom/std, bytes/std
│   ├── dep:parking_lot
│   ├── dep:lru
│   ├── dep:once_cell
│   ├── dep:chrono
│   ├── dep:uuid
│   └── dep:rand_chacha
├── serde
│   ├── dep:serde
│   └── secrecy/serde
└── encoding
    ├── alloc
    ├── dep:hex, dep:base64ct, dep:base32ct
    ├── dep:bs58, dep:bech32, dep:multibase
    └── (encoding functions return String → requires alloc)
```

### 3.3 Dependency Section Changes

All currently unconditional std-requiring dependencies become optional:

```toml
[dependencies]
# Category A: Always required (no_std compatible)
zeroize = { workspace = true }
secrecy = { workspace = true }
subtle = { workspace = true }
constant_time_eq = { workspace = true }
thiserror = { workspace = true }
generic-array = { workspace = true }
typenum = { workspace = true }
arrayvec = { workspace = true }
rand = { workspace = true }
rand_core = { workspace = true }

# Category D: Collection types (no_std compatible)
bytes = { workspace = true }
smallvec = { workspace = true }
bitvec = { workspace = true }

# Category B: std-gated (optional)
parking_lot = { workspace = true, optional = true }
lru = { workspace = true, optional = true }
once_cell = { workspace = true, optional = true }
chrono = { workspace = true, optional = true }
uuid = { workspace = true, optional = true }
rand_chacha = { workspace = true, optional = true }
getrandom = { workspace = true, optional = true }

# Category C: Encoding (optional)
hex = { workspace = true, optional = true }
base64ct = { workspace = true, optional = true }
base32ct = { workspace = true, optional = true }
bs58 = { workspace = true, optional = true }
bech32 = { workspace = true, optional = true }
multibase = { workspace = true, optional = true }

# Alloc-gated
blake3 = { workspace = true, optional = true }

# Async (optional)
async-trait = { workspace = true, optional = true }

# Serialization (already optional)
serde = { workspace = true, optional = true }
```

---

## 4. Module-Level Implementation Plan

Each module requires specific changes. The pattern is consistent:

1. Add conditional `alloc` imports for `Vec`, `String`, `format!`, `vec!`, `Box`
2. Replace `use std::` with `use core::` where equivalent exists
3. Gate std-only code behind `#[cfg(feature = "std")]`
4. Gate dependency-specific code behind the relevant feature

### 4.1 buffer.rs (20 errors)

**Changes:**
- Add `#[cfg(not(feature = "std"))] use alloc::{vec, vec::Vec, string::String};`
- Replace `use std::ops::{Deref, DerefMut}` → `use core::ops::{Deref, DerefMut}`
- Replace `use std::fmt` → `use core::fmt`
- Replace `use std::mem::take` → `use core::mem::take`

**Feature gates:** None needed. All functionality is alloc-compatible.

### 4.2 encoding.rs (30 errors)

**Changes:**
- Add conditional alloc imports for `String`, `Vec`, `format!`
- Replace `use std::str::from_utf8` → `use core::str::from_utf8`
- Gate entire module behind `#[cfg(feature = "encoding")]`:

```rust
#[cfg(feature = "encoding")]
pub mod encoding;
```

**Feature gates:**
- `#[cfg(feature = "encoding")]` on the module declaration in lib.rs
- Individual encoding structs gated behind their respective deps

### 4.3 error.rs (21 errors)

**Changes:**
- Add `#[cfg(not(feature = "std"))] use alloc::string::String;`
- Gate `std::io::Error` conversion behind `#[cfg(feature = "std")]`:

```rust
#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self { ... }
}
```

- Gate `std::result::Result` type alias: use `core::result::Result` instead

**Feature gates:** Minimal. Error types are core infrastructure.

### 4.4 key.rs (16 errors)

**Changes:**
- Add conditional alloc imports for `String`, `Vec`, `format!`
- Replace `use std::fmt` → `use core::fmt`
- Replace `use std::mem::ManuallyDrop` → `use core::mem::ManuallyDrop`
- Gate `KeyMetadata` timestamp fields behind `#[cfg(feature = "std")]`:

```rust
pub struct KeyMetadata {
    // Always available
    pub algorithm: String,
    pub key_size: usize,
    pub usages: Vec<KeyUsage>,
    pub label: Option<String>,

    // std-only (requires chrono + uuid)
    #[cfg(feature = "std")]
    pub created: DateTime<Utc>,
    #[cfg(feature = "std")]
    pub expires: Option<DateTime<Utc>>,
    #[cfg(feature = "std")]
    pub id: KeyId,
}
```

- Gate `KeyId` (uuid-based) behind `#[cfg(feature = "std")]`
- Replace `use std::collections::HashMap` → conditional:

```rust
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
```

**Feature gates:** `chrono`, `uuid` gated behind `std`.

### 4.5 nonce.rs (8 errors)

**Changes:**
- Add conditional alloc imports for `format!`
- Gate `NonceTracker` entirely behind `#[cfg(feature = "std")]`:

```rust
#[cfg(feature = "std")]
pub struct NonceTracker { ... }
```

- Replace `use std::sync::atomic` → `use core::sync::atomic`
- Replace `use std::num::NonZeroUsize` → `use core::num::NonZeroUsize`

**Feature gates:** `parking_lot` + `lru` gated behind `std` (NonceTracker only).

### 4.6 random.rs (14 errors)

**Changes:**
- Add conditional alloc imports for `Vec`, `String`, `vec!`, `format!`
- Gate `ThreadLocalRng` behind `#[cfg(feature = "std")]` (uses `thread_local!`, `std::sync::Mutex`)
- Gate `DeterministicRng` behind `#[cfg(feature = "std")]` (uses `rand_chacha`)
- Gate `mix_entropy()` behind `#[cfg(feature = "std")]` (uses `std::time`, `blake3`)
- Gate `random_token()` behind `#[cfg(feature = "std")]` (uses `base64ct`)
- Gate `random_id()` and `random_alphanumeric()` behind `#[cfg(feature = "std")]`
- Core functions `random_bytes()`, `random_array()`, `OsRng` remain (need `rand_core`)

**Feature gates:** Heavy. Most of random.rs is std-only. Core random generation
  depends on `rand`/`rand_core` which need at minimum the `getrandom` backend.

**no_std random strategy:** Under pure no_std, expose only `random_array()` using
  a user-provided RNG, not OsRng. Document this limitation.

### 4.7 time.rs (3 errors)

**Changes:**
- Gate entire module behind `#[cfg(feature = "std")]`:

```rust
#[cfg(feature = "std")]
pub mod time;
```

**Rationale:** All functionality uses `std::time::{Duration, Instant, SystemTime}` and
`std::thread::sleep`. No meaningful no_std equivalent exists.

### 4.8 traits.rs (26 errors)

**Changes:**
- Add conditional alloc imports for `Vec`, `Box`, `String`
- Gate async traits behind `#[cfg(feature = "async")]`:

```rust
#[cfg(feature = "async")]
use async_trait::async_trait;

#[cfg(feature = "async")]
#[async_trait]
pub trait KeyStore { ... }

#[cfg(feature = "async")]
#[async_trait]
pub trait ThresholdSigner { ... }
```

**Feature gates:** `async-trait` gated behind `async` feature.

### 4.9 version.rs (15 errors)

**Changes:**
- Add conditional alloc imports for `String`
- Replace `use std::fmt` → `use core::fmt`
- Replace `use std::cmp::Ordering` → `use core::cmp::Ordering`
- `serde` derives already gated behind `#[cfg(feature = "serde")]`

**Feature gates:** None beyond existing serde gate.

---

## 5. Prelude and Re-export Changes

The prelude in `lib.rs` must adapt to available features:

```rust
pub mod prelude {
    pub use crate::buffer::{SecretBuffer, SecretBytes, SecureVec};
    pub use crate::error::{Error, Result};
    pub use crate::key::{PublicKey, SecretKey};
    pub use crate::nonce::Nonce;
    pub use crate::traits::*;
    pub use crate::version::Version;

    #[cfg(feature = "encoding")]
    pub use crate::encoding::{Base64, Hex};

    #[cfg(feature = "std")]
    pub use crate::key::{KeyId, KeyMetadata};

    #[cfg(feature = "std")]
    pub use crate::random::{CryptoRng, OsRng};
}
```

Module declarations in `lib.rs`:

```rust
pub mod buffer;
pub mod error;
pub mod key;
pub mod nonce;
pub mod traits;
pub mod version;

#[cfg(feature = "encoding")]
pub mod encoding;

#[cfg(feature = "std")]
pub mod time;

pub mod random;  // Available but reduced API under no_std
```

---

## 6. Test Strategy (TDD)

### 6.1 Test Hierarchy

```
Level 0: Compilation Tests (P0)
├── no_std_bare_compile       — compiles with no features
├── no_std_alloc_compile      — compiles with alloc only
├── no_std_encoding_compile   — compiles with alloc + encoding
└── std_full_compile          — compiles with all features (regression)

Level 1: Unit Tests — no_std Core (P0)
├── buffer_tests              — SecretBuffer, SecureVec under alloc
├── error_tests               — Error construction without std::io
├── key_tests                 — SecretKey, PublicKey (no KeyId/KeyMetadata)
├── nonce_tests               — Nonce generation (no NonceTracker)
├── traits_tests              — Sync trait definitions compile
└── version_tests             — Version, AlgorithmId

Level 2: Unit Tests — std Features (P1)
├── time_tests                — MonotonicClock, ConstantTime
├── encoding_tests            — All encoding formats
├── random_full_tests         — OsRng, DeterministicRng, mix_entropy
├── nonce_tracker_tests       — NonceTracker with LRU
└── key_metadata_tests        — KeyMetadata with chrono, uuid

Level 3: Integration Tests (P1)
├── downstream_no_std_test    — Verify arcanum-hash/symmetric/etc can
│                               depend on arcanum-core without std
└── feature_combination_test  — All valid feature combos compile
```

### 6.2 TDD Implementation Cycles

#### Cycle 1: Compilation Gate (RED → GREEN)

**RED — Write failing no_std compilation test:**

```rust
// tests/no_std_compile_test.rs
#![no_std]

extern crate alloc;
extern crate arcanum_core;

use arcanum_core::error::Error;
use arcanum_core::key::SecretKey;
use arcanum_core::buffer::SecureVec;

#[test]
fn no_std_types_exist() {
    // Verify core types are accessible without std
    let _key = SecretKey::<32>::default();
}
```

Run: `cargo test -p arcanum-core --no-default-features --features alloc --test no_std_compile_test`

Expected: **FAILS** (154 compilation errors)

**GREEN — Apply Cargo.toml feature gates + conditional imports:**

1. Restructure `[features]` per Section 3.1
2. Make std-requiring deps optional per Section 3.3
3. Add conditional alloc imports per Section 4
4. Gate modules per Section 5

Run same test command. Expected: **PASSES**

#### Cycle 2: Bare no_std (RED → GREEN)

**RED — Write bare no_std test (no alloc):**

```rust
// tests/no_std_bare_test.rs
#![no_std]

extern crate arcanum_core;

use arcanum_core::error::Error;
use arcanum_core::version::Version;

// Verify types that don't require allocation exist
fn _version_check() {
    let v = Version::new(0, 1, 2);
    let _ = v.major();
}
```

Run: `cargo test -p arcanum-core --no-default-features --test no_std_bare_test`

Expected: **FAILS** — modules using Vec/String fail without alloc

**GREEN — Gate alloc-requiring types:**

- Gate `SecureVec`, `SecretBuffer` behind `#[cfg(feature = "alloc")]`
- Gate String-containing error variants behind `#[cfg(feature = "alloc")]`
- Provide static-string alternatives for no-alloc error variants

Run same test. Expected: **PASSES**

#### Cycle 3: Feature Isolation (RED → GREEN)

**RED — Verify encoding is properly gated:**

```rust
// tests/no_encoding_test.rs
#![no_std]

extern crate alloc;
extern crate arcanum_core;

// This should compile — encoding module should not be visible
fn _check() {
    // Verify encoding is not available without the feature
    // (compile_fail test or negative assertion)
}
```

**GREEN — Ensure `#[cfg(feature = "encoding")]` on encoding module.**

#### Cycle 4: Regression (GREEN stays GREEN)

**Run full test suite with default features:**

```bash
cargo test -p arcanum-core
```

Expected: **All existing tests still pass.** Zero regressions.

---

## 7. Implementation Phases

### Phase 1: Cargo.toml Restructure

**Deliverables:**
- [ ] Restructure `[features]` section per Section 3.1
- [ ] Make std-requiring deps optional per Section 3.3
- [ ] Verify `cargo check -p arcanum-core` still passes (default features)

**Exit Criteria:**
- Default feature compilation passes with zero warnings
- `cargo check -p arcanum-core --no-default-features` error count decreases

---

### Phase 2: Core Module Gates (buffer, error, key, nonce, version)

**Deliverables:**
- [ ] buffer.rs — alloc imports + core:: replacements
- [ ] error.rs — alloc imports + gate std::io::Error conversion
- [ ] key.rs — alloc imports + gate KeyMetadata timestamps, KeyId
- [ ] nonce.rs — alloc imports + gate NonceTracker behind std
- [ ] version.rs — alloc imports + core:: replacements

**Exit Criteria:**
- `cargo check -p arcanum-core --no-default-features --features alloc` passes
- All existing unit tests pass with default features

---

### Phase 3: Peripheral Module Gates (encoding, random, time, traits)

**Deliverables:**
- [ ] encoding.rs — gate entire module behind `encoding` feature
- [ ] random.rs — gate std-only functions, preserve core random_array
- [ ] time.rs — gate entire module behind `std`
- [ ] traits.rs — alloc imports + gate async traits behind `async` feature

**Exit Criteria:**
- `cargo check -p arcanum-core --no-default-features` passes (bare no_std)
- `cargo check -p arcanum-core --no-default-features --features alloc` passes
- All existing unit tests pass with default features

---

### Phase 4: Prelude and lib.rs Cleanup

**Deliverables:**
- [ ] Update prelude with conditional re-exports per Section 5
- [ ] Update module declarations with feature gates
- [ ] Update crate-level documentation to document feature flags

**Exit Criteria:**
- Full compilation under all feature combinations:
  - `--no-default-features` (bare no_std)
  - `--no-default-features --features alloc`
  - `--no-default-features --features "alloc,encoding"`
  - `--no-default-features --features "alloc,encoding,serde"`
  - `--features std` (default, regression)

---

### Phase 5: Tests and Validation

**Deliverables:**
- [ ] Write `tests/no_std_compile_test.rs`
- [ ] Write `tests/no_std_bare_test.rs`
- [ ] Verify downstream crate compilation without std
- [ ] Run full test suite with default features (regression)

**Exit Criteria:**
- All TDD cycle tests pass (Section 6.2)
- `cargo test -p arcanum-core` passes (full regression)
- At least one downstream crate (arcanum-hash or arcanum-symmetric) can depend on
  arcanum-core with `default-features = false`

---

## 8. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking downstream API | Medium | High | Phase 4 regression tests; default features preserve all existing behavior |
| `rand`/`getrandom` not working without std | High | Medium | Document that OsRng requires std; provide trait-based RNG injection for no_std |
| `bitvec`/`bytes` pulling std transitively | Low | Medium | Verify with `cargo tree --no-default-features`; add `default-features = false` if needed |
| Feature combination explosion | Medium | Low | Test the 5 key combinations listed in Phase 4 exit criteria |
| `serde` derive incompatibility under no_std | Low | Low | serde 1.x supports no_std with `default-features = false` |
| `KeyMetadata` API divergence (std vs no_std) | Medium | Medium | Provide a no_std `KeyMetadataBasic` or builder pattern that works in both modes |

---

## 9. API Surface Under Each Feature Combination

### 9.1 `--no-default-features` (bare no_std, no alloc)

Available:
- `Version`, version comparison
- `Error` (with static string variants only)
- `Nonce<N>` (stack-allocated)
- Core traits (sync only)
- `ConstantTimeEq`, `Zeroize`, `ZeroizeOnDrop` re-exports
- `SecretKey<N>`, `PublicKey<N>` (fixed-size only)

Unavailable:
- All Vec/String-returning APIs
- `SecureVec`, `SecretBuffer`
- `KeyId`, `KeyMetadata`
- `encoding` module
- `time` module
- `NonceTracker`
- `random` module (no entropy source)
- Async traits

### 9.2 `--no-default-features --features alloc`

Additional:
- `SecureVec`, `SecretBuffer`
- `Error` with full String variants
- `PublicKey`/`SecretKey` with Vec-returning methods
- Core traits with Vec parameters

### 9.3 `--no-default-features --features "alloc,encoding"`

Additional:
- Full `encoding` module (Hex, Base64, Base32, Base58, Bech32, Multibase)

### 9.4 Default (`std,serde,encoding`)

Full API — all modules, all types, all functionality. Zero changes from current behavior.

---

## 10. References

1. Rust Reference: Conditional Compilation
   https://doc.rust-lang.org/reference/conditional-compilation.html

2. Rust Embedded Working Group: no_std Guide
   https://docs.rust-embedded.org/book/intro/no-std.html

3. WASM Support Specification (arcanum-core blockers)
   `docs/specs/WASM-SUPPORT.md`

4. Release Roadmap Phase 3.3: no_std Gates
   `docs/RELEASE-ROADMAP.md`

5. WASM TDD Roadmap (test requirements)
   `docs/specs/WASM-TDD-ROADMAP.md`

---

## Appendix A: Full Error Catalog (154 Errors by Category)

| Error Type | Count | Fix Category |
|------------|-------|-------------|
| `cannot find type String` | 55 | Conditional alloc import |
| `cannot find type Vec` | 42 | Conditional alloc import |
| `unresolved module std` | 36 | Replace with core:: or feature-gate |
| `cannot find macro vec` | 5 | Conditional alloc import |
| `cannot find macro format` | 3 | Conditional alloc import |
| `cannot find type Box` | 2 | Conditional alloc import |
| `unresolved import serde` | 2 | Already feature-gated (activate with serde feature) |
| `cannot find value THREAD_RNG` | 2 | Gate behind std |
| `ambiguous associated type` | 2 | Resolve with explicit type annotation |
| `cannot find macro thread_local` | 1 | Gate behind std |
| Other | 4 | Case-by-case |

## Appendix B: Estimated Lines of Change

| Phase | Files Modified | Lines Added | Lines Removed | Net |
|-------|---------------|-------------|---------------|-----|
| Phase 1 (Cargo.toml) | 1 | ~30 | ~15 | +15 |
| Phase 2 (Core modules) | 5 | ~60 | ~15 | +45 |
| Phase 3 (Peripheral modules) | 4 | ~45 | ~10 | +35 |
| Phase 4 (Prelude/lib.rs) | 1 | ~15 | ~5 | +10 |
| Phase 5 (Tests) | 2-3 | ~50 | 0 | +50 |
| **Total** | **~14** | **~200** | **~45** | **+155** |
