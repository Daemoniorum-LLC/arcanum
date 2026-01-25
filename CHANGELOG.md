# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
