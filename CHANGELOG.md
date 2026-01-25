# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **WebAssembly support:** New `arcanum-wasm` crate with wasm-bindgen bindings
  - Hashing: SHA-256, SHA-3-256, BLAKE3
  - Symmetric encryption: AES-256-GCM, ChaCha20-Poly1305
  - Key derivation: Argon2id, HKDF-SHA256
  - Asymmetric: X25519 key exchange, Ed25519 signatures
  - CSPRNG: Browser-safe random number generation
- **WASM SIMD acceleration:** 128-bit SIMD for ChaCha20 (1.30x), BLAKE3 (1.23x)
- **Dual backend architecture:** Choose between `backend-rustcrypto` (audited) or `backend-native` (optimized)

### Security

- ⚠️ **WASM code paths have not been fuzzed.** While cryptographic correctness is validated via Known Answer Tests and cross-platform verification, users requiring high-assurance deployments should use `backend-rustcrypto` or conduct independent security review.

## [0.1.1] - 2026-01-22

### Security

- **RSA now optional:** Removed RSA from default features due to RUSTSEC-2023-0071 (Marvin Attack timing vulnerability in the `rsa` crate). Users who don't need RSA are no longer affected by this upstream vulnerability.

### Changed

- `arcanum-asymmetric`: RSA feature is now opt-in (`features = ["rsa"]`)
- Default features for `arcanum-asymmetric` are now: `ecies`, `x25519`, `x448`

## [0.1.0] - 2025-01-19

### Added

- Initial open source release
- Symmetric encryption: AES-256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305
- Asymmetric encryption: X25519, ECDH (P-256, P-384, secp256k1), RSA-OAEP, ECIES
- Digital signatures: Ed25519, ECDSA, RSA-PSS with batch verification
- Hashing: SHA-2, SHA-3, BLAKE3 with SIMD acceleration
- Key derivation: Argon2id, HKDF, PBKDF2
- Post-quantum: ML-KEM-768, ML-DSA-65/87 (NIST FIPS 203/204)
- Zero-knowledge proofs: Schnorr proofs, Bulletproofs range proofs, Pedersen commitments
- Threshold cryptography: FROST signatures, Shamir secret sharing, DKG
