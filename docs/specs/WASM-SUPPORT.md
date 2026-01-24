# WebAssembly Support Specification

**Document ID:** SPEC-WASM-001
**Version:** 0.1.0
**Date:** 2026-01-24
**Author:** Arcanum Development Team
**Status:** Draft

---

## 1. Executive Summary

This specification defines WebAssembly (WASM) support for the Arcanum cryptographic library. The goal is to enable browser-based and edge runtime cryptography while maintaining security guarantees and performance within the constraints of the WASM execution environment.

### Objectives

1. **Minimal Viable Surface**: Enable core cryptographic operations in WASM
2. **Feature Parity**: Match native API where WASM constraints allow
3. **Security**: No degradation of cryptographic security properties
4. **Ergonomics**: Provide wasm-bindgen bindings for JavaScript interop

### Non-Goals

- Hardware acceleration (AES-NI, AVX2, etc.) - not available in WASM
- Parallel processing (rayon) - limited WASM thread support
- Hardware security modules (TPM, YubiKey) - no browser API

### Positioning

Arcanum WASM exposes **two backend options**:

1. **`backend-rustcrypto`** - Wrappers around audited RustCrypto libraries. Recommended for production systems where security audit status matters.

2. **`backend-native`** - Arcanum's native primitives, optimized for inference workloads. **Not audited.** Smaller bundles, batch-optimized. Your risk, your choice.

Arcanum does not compete with RustCrypto. Our native primitives serve specific optimization goals (tensor decompression, batch hashing for large binary artifacts). The dual-backend approach lets users make informed decisions about their risk tolerance.

---

## 2. Compatibility Assessment

### 2.1 Crate-by-Crate Analysis

| Crate | WASM Compatible | Blockers | Notes |
|-------|-----------------|----------|-------|
| `arcanum-primitives` | **YES** | None | Pure Rust, no_std ready |
| `arcanum-core` | **PARTIAL** | tokio, parking_lot, getrandom | Needs feature gates |
| `arcanum-hash` | **YES** | None | RustCrypto deps are WASM-ready |
| `arcanum-symmetric` | **YES** | hardware-accel | Disable HW features |
| `arcanum-asymmetric` | **YES** | None | RustCrypto elliptic curves work |
| `arcanum-signatures` | **YES** | None | Ed25519, ECDSA pure Rust |
| `arcanum-pqc` | **PARTIAL** | rayon, SIMD | Needs feature gates |
| `arcanum-zkp` | **UNCLEAR** | arkworks deps | Needs investigation |
| `arcanum-threshold` | **PARTIAL** | rayon | Needs feature gates |
| `arcanum-verify` | **YES** | None | Pure verification logic |
| `arcanum-agile` | **PARTIAL** | Depends on constituent crates | |
| `arcanum-holocrypt` | **PARTIAL** | Complex dependencies | Phase 2 |

### 2.2 Dependency Blockers

#### Critical: `getrandom`

**Problem:** Default getrandom uses OS entropy sources unavailable in WASM.

**Solution:** Enable `js` feature for browser WASM:
```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

#### Critical: `tokio`

**Problem:** Tokio requires OS threads and I/O, unavailable in WASM.

**Solution:** Make tokio optional, exclude from WASM builds:
```toml
[features]
wasm = []  # Excludes tokio and other incompatible deps
```

#### Medium: `parking_lot`

**Problem:** Uses OS-specific synchronization primitives.

**Solution:** Use `std::sync` alternatives or feature-gate.

#### Medium: `rayon`

**Problem:** Thread-based parallelism not supported in most WASM runtimes.

**Solution:** Exclude via feature flag:
```toml
[features]
parallel = ["dep:rayon"]  # Excluded from wasm feature
```

---

## 3. Architecture

### 3.1 Dual-Backend Architecture

Arcanum provides two implementation channels, matching the native library pattern:

| Backend | Description | Use Case |
|---------|-------------|----------|
| `backend-native` | Arcanum's native primitives | Optimized for specific workloads, smaller bundles |
| `backend-rustcrypto` | Wrappers around audited RustCrypto | Production systems requiring audited implementations |

**Positioning:**

1. **Not Audited**: Arcanum's native primitives have not undergone formal security audit. Users choosing `backend-native` accept this risk. We provide extensive test coverage, fuzzing, and Known Answer Tests - but that is not a substitute for professional audit.

2. **Not Competing**: Arcanum does not seek to replace or compete with established libraries like RustCrypto. Our native primitives exist for specific optimization goals (tensor decompression, batch operations, streaming workloads). The RustCrypto backend exists precisely because those libraries are battle-tested.

3. **Informed Choice**: By exposing both backends, users can make their own risk/performance tradeoffs. Security-critical applications should use `backend-rustcrypto`. Performance-critical pipelines may choose `backend-native`.

### 3.2 Feature Flag Design

```toml
[features]
default = ["std"]
std = []
alloc = []

# WASM target - excludes incompatible dependencies
wasm = ["alloc", "getrandom/js"]

# Backend selection - choose implementation strategy
backend-native = ["arcanum-primitives/wasm"]      # Native primitives (not audited)
backend-rustcrypto = []                            # RustCrypto wrappers (audited)

# Explicit exclusions for clarity
wasm-bindgen = ["wasm", "dep:wasm-bindgen"]
```

### 3.3 Conditional Compilation

```rust
// In lib.rs
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// WASM-specific entropy source
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
use getrandom::getrandom;

// Native-only features
#[cfg(not(target_arch = "wasm32"))]
mod hardware_accel;

#[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
mod parallel;
```

### 3.4 WASM Bindings Structure

```
crates/
├── arcanum-wasm/           # New crate: WASM bindings
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs          # wasm-bindgen exports, backend dispatch
│   │   ├── hash.rs         # Hash function bindings
│   │   ├── symmetric.rs    # Symmetric crypto bindings
│   │   ├── asymmetric.rs   # Key exchange, ECIES bindings
│   │   ├── signatures.rs   # Signing/verification bindings
│   │   └── random.rs       # CSPRNG bindings
│   └── tests/
│       └── web.rs          # wasm-pack test
```

### 3.5 Backend Dispatch

The WASM bindings abstract over the backend choice at compile time:

```rust
// src/hash.rs
#[cfg(feature = "backend-native")]
use arcanum_primitives::sha2::Sha256;

#[cfg(feature = "backend-rustcrypto")]
use sha2::Sha256;

#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    // Same API, different implementation
    Sha256::digest(data).to_vec()
}
```

Users build with their chosen backend:

```bash
# For audited RustCrypto implementations
wasm-pack build --features backend-rustcrypto

# For native Arcanum primitives (not audited)
wasm-pack build --features backend-native
```

The resulting npm package is identical in API - only the underlying implementation differs.

---

## 4. Implementation Phases

### Phase 1: Foundation (MVP)

**Goal:** Basic hashing, symmetric encryption, and random number generation.

**Scope:**
- [ ] Add `wasm` feature to `arcanum-primitives`
- [ ] Add `wasm` feature to `arcanum-core` (exclude tokio, parking_lot)
- [ ] Add `wasm` feature to `arcanum-hash`
- [ ] Add `wasm` feature to `arcanum-symmetric`
- [ ] Create `arcanum-wasm` crate with wasm-bindgen
- [ ] Implement hash bindings (SHA-256, SHA-3, BLAKE3)
- [ ] Implement symmetric bindings (AES-GCM, ChaCha20-Poly1305)
- [ ] Implement CSPRNG bindings
- [ ] Add `wasm32-unknown-unknown` to CI

**Deliverables:**
- `npm` package: `@arcanum/crypto` (or similar)
- JS API for hashing and encryption

### Phase 2: Asymmetric Cryptography

**Goal:** Key exchange, ECIES, digital signatures.

**Scope:**
- [ ] Add `wasm` feature to `arcanum-asymmetric`
- [ ] Add `wasm` feature to `arcanum-signatures`
- [ ] Implement X25519 key exchange bindings
- [ ] Implement ECIES encryption bindings
- [ ] Implement Ed25519 signature bindings
- [ ] Implement ECDSA (P-256, secp256k1) bindings

**Deliverables:**
- Key generation in browser
- Sign/verify operations
- Encrypted communication setup

### Phase 3: Post-Quantum

**Goal:** Future-proof cryptography for web applications.

**Scope:**
- [ ] Add `wasm` feature to `arcanum-pqc` (exclude rayon)
- [ ] Implement ML-KEM (Kyber) bindings
- [ ] Implement ML-DSA (Dilithium) bindings (if performance acceptable)
- [ ] Implement hybrid key exchange (X25519 + ML-KEM)

**Deliverables:**
- Post-quantum key encapsulation in browser
- Hybrid encryption for transitional security

### Phase 4: Advanced Features

**Goal:** Zero-knowledge proofs, threshold cryptography (where feasible).

**Scope:**
- [ ] Evaluate arkworks WASM compatibility
- [ ] Implement selective ZKP bindings if feasible
- [ ] Evaluate FROST threshold signatures in WASM

**Status:** Exploratory - depends on Phase 1-3 learnings

---

## 5. API Design

### 5.1 JavaScript API (wasm-bindgen)

```typescript
// Hash functions
function sha256(data: Uint8Array): Uint8Array;
function sha3_256(data: Uint8Array): Uint8Array;
function blake3(data: Uint8Array): Uint8Array;

// Symmetric encryption
class AesGcm {
  constructor(key: Uint8Array);
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;
}

class ChaCha20Poly1305 {
  constructor(key: Uint8Array);
  encrypt(plaintext: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;
}

// Key derivation
function argon2id(password: Uint8Array, salt: Uint8Array, config?: Argon2Config): Uint8Array;
function hkdf_sha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;

// Random
function random_bytes(length: number): Uint8Array;

// Asymmetric (Phase 2)
class X25519KeyPair {
  static generate(): X25519KeyPair;
  publicKey(): Uint8Array;
  diffieHellman(peerPublic: Uint8Array): Uint8Array;
}

class Ed25519KeyPair {
  static generate(): Ed25519KeyPair;
  static fromSeed(seed: Uint8Array): Ed25519KeyPair;
  publicKey(): Uint8Array;
  sign(message: Uint8Array): Uint8Array;
  static verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}
```

### 5.2 Error Handling

```typescript
// All crypto operations return Result<T, CryptoError>
// wasm-bindgen converts to exceptions

class CryptoError extends Error {
  code: string;  // "INVALID_KEY", "DECRYPTION_FAILED", etc.
}
```

### 5.3 Memory Safety

- All sensitive data (keys, plaintexts) zeroized on drop
- No direct memory access from JS (use typed arrays)
- Explicit `free()` methods for long-lived objects

---

## 6. Testing Strategy

### 6.1 Spec Tests (Agent-TDD RED Phase)

```rust
// tests/wasm_spec.rs - These should fail until implementation complete

#[cfg(target_arch = "wasm32")]
mod wasm_spec_tests {
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn spec_sha256_produces_correct_hash() {
        let hash = arcanum_wasm::sha256(b"hello");
        assert_eq!(
            hex::encode(&hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[wasm_bindgen_test]
    fn spec_aes_gcm_roundtrip() {
        let key = arcanum_wasm::random_bytes(32);
        let nonce = arcanum_wasm::random_bytes(12);
        let plaintext = b"secret message";

        let cipher = arcanum_wasm::AesGcm::new(&key);
        let ciphertext = cipher.encrypt(plaintext, &nonce, None);
        let decrypted = cipher.decrypt(&ciphertext, &nonce, None);

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn spec_chacha20poly1305_authenticated() {
        let key = arcanum_wasm::random_bytes(32);
        let nonce = arcanum_wasm::random_bytes(12);
        let plaintext = b"authenticated data";
        let aad = b"additional data";

        let cipher = arcanum_wasm::ChaCha20Poly1305::new(&key);
        let ciphertext = cipher.encrypt(plaintext, &nonce, Some(aad));

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xff;

        // Should fail authentication
        assert!(cipher.decrypt(&tampered, &nonce, Some(aad)).is_err());
    }

    #[wasm_bindgen_test]
    fn spec_random_bytes_unique() {
        let a = arcanum_wasm::random_bytes(32);
        let b = arcanum_wasm::random_bytes(32);
        assert_ne!(a, b);  // Probabilistically guaranteed
    }
}
```

### 6.2 Known Answer Tests (KAT)

Use NIST test vectors and Wycheproof for all algorithms.

### 6.3 CI Integration

```yaml
# .github/workflows/wasm.yml
name: WASM Build

on: [push, pull_request]

jobs:
  wasm-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - uses: taiki-e/install-action@wasm-pack

      - name: Build WASM
        run: wasm-pack build crates/arcanum-wasm --target web

      - name: Test WASM (Node)
        run: wasm-pack test --node crates/arcanum-wasm

      - name: Test WASM (Chrome)
        run: wasm-pack test --headless --chrome crates/arcanum-wasm
```

---

## 7. Performance Considerations

### 7.1 Expected Performance Degradation

| Operation | Native | WASM (estimated) | Degradation |
|-----------|--------|------------------|-------------|
| SHA-256 (1KB) | ~2 µs | ~10 µs | 5x |
| AES-GCM (1KB) | ~0.5 µs | ~5 µs | 10x (no AES-NI) |
| ChaCha20 (1KB) | ~0.3 µs | ~2 µs | 6x |
| X25519 | ~50 µs | ~200 µs | 4x |
| Ed25519 sign | ~25 µs | ~100 µs | 4x |

*Estimates based on typical WASM overhead. Actual performance depends on browser/runtime.*

### 7.2 Optimization Opportunities

1. **SIMD.js** - WASM SIMD proposal (widely supported)
2. **Streaming APIs** - Avoid large memory copies
3. **Web Crypto fallback** - Use native Web Crypto when available (AES-GCM, SHA-256)

---

## 8. Security Considerations

### 8.1 Side-Channel Resistance

- All operations must remain constant-time in WASM
- Verify timing properties with dudect in WASM environment
- No secret-dependent branches or memory access patterns

### 8.2 Entropy Quality

- Browser entropy via `crypto.getRandomValues()` (getrandom `js` feature)
- No fallback to weak entropy sources
- Panic if entropy unavailable

### 8.3 Memory Handling

- Zeroize all secrets before deallocation
- Avoid copying secrets to JS heap where possible
- Document memory model limitations

---

## 9. Gaps Discovered (SDD)

*This section will be updated as implementation proceeds.*

| Gap ID | Description | Impact | Resolution |
|--------|-------------|--------|------------|
| GAP-001 | *None yet* | - | - |

---

## 10. Revision History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-01-24 | Initial draft. Compatibility assessment complete. |

---

## Appendix A: Full Dependency Audit

### arcanum-core Dependencies

| Dependency | WASM Compatible | Notes |
|------------|-----------------|-------|
| zeroize | YES | Pure Rust |
| secrecy | YES | Pure Rust |
| subtle | YES | Pure Rust, constant-time |
| rand | YES (with js) | Needs getrandom/js |
| rand_core | YES | |
| rand_chacha | YES | Pure Rust ChaCha20 |
| getrandom | YES (with js) | **Requires `js` feature** |
| generic-array | YES | |
| typenum | YES | |
| bytes | YES | |
| blake3 | YES | Pure Rust available |
| thiserror | YES | |
| async-trait | PARTIAL | No async runtime in WASM |
| chrono | YES | |
| uuid | YES | |
| parking_lot | **NO** | Use std::sync |
| once_cell | YES | std feature |
| lru | YES | |

### arcanum-pqc Dependencies

| Dependency | WASM Compatible | Notes |
|------------|-----------------|-------|
| ml-kem | YES | Pure Rust |
| ml-dsa | YES | Pure Rust |
| x25519-dalek | YES | Pure Rust |
| sha2 | YES | |
| hkdf | YES | |
| rayon | **NO** | Feature-gate |
