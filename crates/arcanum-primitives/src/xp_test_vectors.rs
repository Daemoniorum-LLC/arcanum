//! Cross-Platform Test Vectors (XP-1/XP-2)
//!
//! These canonical test vectors are generated from the native x86-64 implementation.
//! Both WASM SIMD and native SIMD implementations must produce identical outputs.
//!
//! Test IDs:
//! - XP-1: WASM SIMD matches native x86 AVX2
//! - XP-2: WASM SIMD matches scalar on all platforms

/// SHA-256 canonical test vectors
/// Format: (name, input_description, expected_hash_hex)
pub const SHA256_VECTORS: &[(&str, &str, &str)] = &[
    (
        "empty",
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "hello",
        "hello",
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    ),
    (
        "64_sequential",
        "0..64",
        "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
    ),
    (
        "256_pattern",
        "(i*0x42+0x24)&0xff for i in 0..256",
        "ffd75fd96f97049ac629708ffced682458d168ec089dd7dc6fcf768ebaed3cae",
    ),
    (
        "1024_pattern",
        "(i*0x17+0x31)&0xff for i in 0..1024",
        "1177442d23333da6a3ec810c68ba8b6d8fbdc8244ba7a672598a86271e3771a0",
    ),
];

/// BLAKE3 canonical test vectors
pub const BLAKE3_VECTORS: &[(&str, &str, &str)] = &[
    (
        "empty",
        "",
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    ),
    (
        "hello",
        "hello",
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f",
    ),
    (
        "64_sequential",
        "0..64",
        "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    ),
    (
        "256_pattern",
        "(i*0x42+0x24)&0xff for i in 0..256",
        "4143d1e27a6c35fac48f4d32ab64b7e3ee02f3ead0f904a6b684d216530bd9d9",
    ),
    (
        "1024_pattern",
        "(i*0x17+0x31)&0xff for i in 0..1024",
        "f92654c4e459e9bc0bd22b96403d9014e373739636a36107e68b6e4f68f00aa0",
    ),
];

/// ChaCha20 canonical test vectors
/// Key: [0x42; 32], Nonce: [0x24; 12], Counter: 0
/// Format: (size, first_32_bytes_hex, last_32_bytes_hex)
pub const CHACHA20_VECTORS: &[(usize, &str, &str)] = &[
    (
        64,
        "e405626e4f1236b3670ee428332ea20e325a20ad55a1b53de7d5cf673d5694c2",
        "84d2afe53b26ffb2b0b3d872309d007d4493c6be5f949f4aed10217177536196",
    ),
    (
        256,
        "e405626e4f1236b3670ee428332ea20e325a20ad55a1b53de7d5cf673d5694c2",
        "7b4bf3c7de7a252a8777d4371a9bb13706de492aa6cc000fe1161e9038493629",
    ),
    (
        512,
        "e405626e4f1236b3670ee428332ea20e325a20ad55a1b53de7d5cf673d5694c2",
        "5f6835fdd81331fa556a20147d81d00ee9f4fb89c205ff9a12a51c6890086e1b",
    ),
    (
        1024,
        "e405626e4f1236b3670ee428332ea20e325a20ad55a1b53de7d5cf673d5694c2",
        "b0496cb2fbab504d30741db42d84024becf35ef3e60127f9dc0d4aef4b8609f5",
    ),
];

/// Generate test input based on pattern name
pub fn generate_input(name: &str) -> Vec<u8> {
    match name {
        "empty" => vec![],
        "hello" => b"hello".to_vec(),
        "64_sequential" => (0..64).collect(),
        "256_pattern" => (0..256).map(|i| ((i * 0x42 + 0x24) & 0xff) as u8).collect(),
        "1024_pattern" => (0..1024)
            .map(|i| ((i * 0x17 + 0x31) & 0xff) as u8)
            .collect(),
        _ => panic!("Unknown pattern: {}", name),
    }
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XP-1/XP-2: Verify SHA-256 produces canonical outputs
    #[test]
    #[cfg(feature = "sha2")]
    fn xp_sha256_matches_canonical() {
        use crate::sha2::Sha256;

        for (name, _, expected_hex) in SHA256_VECTORS {
            let input = generate_input(name);
            let expected = hex_to_bytes(expected_hex);

            let mut hasher = Sha256::new();
            hasher.update(&input);
            let actual = hasher.finalize();

            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "SHA-256 XP mismatch for '{}': expected {}, got {}",
                name,
                expected_hex,
                bytes_to_hex(&actual)
            );
        }
    }

    /// XP-1/XP-2: Verify BLAKE3 produces canonical outputs
    #[test]
    #[cfg(feature = "blake3")]
    fn xp_blake3_matches_canonical() {
        use crate::blake3::Blake3;

        for (name, _, expected_hex) in BLAKE3_VECTORS {
            let input = generate_input(name);
            let expected = hex_to_bytes(expected_hex);

            let mut hasher = Blake3::new();
            hasher.update(&input);
            let actual = hasher.finalize();

            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "BLAKE3 XP mismatch for '{}': expected {}, got {}",
                name,
                expected_hex,
                bytes_to_hex(&actual)
            );
        }
    }

    /// XP-1/XP-2: Verify ChaCha20 produces canonical outputs
    #[test]
    #[cfg(feature = "chacha20")]
    fn xp_chacha20_matches_canonical() {
        use crate::chacha20::ChaCha20;

        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];

        for (size, first32_hex, last32_hex) in CHACHA20_VECTORS {
            let mut data: Vec<u8> = (0..*size).map(|i| (i & 0xff) as u8).collect();
            let expected_first = hex_to_bytes(first32_hex);
            let expected_last = hex_to_bytes(last32_hex);

            let mut cipher = ChaCha20::new(&key, &nonce);
            cipher.apply_keystream(&mut data);

            assert_eq!(
                &data[..32],
                expected_first.as_slice(),
                "ChaCha20 XP mismatch for size {} first 32: expected {}, got {}",
                size,
                first32_hex,
                bytes_to_hex(&data[..32])
            );

            assert_eq!(
                &data[data.len() - 32..],
                expected_last.as_slice(),
                "ChaCha20 XP mismatch for size {} last 32: expected {}, got {}",
                size,
                last32_hex,
                bytes_to_hex(&data[data.len() - 32..])
            );
        }
    }

    /// Verify test vector consistency (self-test)
    #[test]
    fn xp_vectors_are_valid() {
        // Verify all hex strings are valid
        for (name, _, hex) in SHA256_VECTORS {
            assert_eq!(
                hex.len(),
                64,
                "SHA-256 vector '{}' should be 64 hex chars",
                name
            );
            let bytes = hex_to_bytes(hex);
            assert_eq!(
                bytes.len(),
                32,
                "SHA-256 vector '{}' should be 32 bytes",
                name
            );
        }

        for (name, _, hex) in BLAKE3_VECTORS {
            assert_eq!(
                hex.len(),
                64,
                "BLAKE3 vector '{}' should be 64 hex chars",
                name
            );
            let bytes = hex_to_bytes(hex);
            assert_eq!(
                bytes.len(),
                32,
                "BLAKE3 vector '{}' should be 32 bytes",
                name
            );
        }

        for (size, first, last) in CHACHA20_VECTORS {
            assert_eq!(
                first.len(),
                64,
                "ChaCha20 {} first should be 64 hex chars",
                size
            );
            assert_eq!(
                last.len(),
                64,
                "ChaCha20 {} last should be 64 hex chars",
                size
            );
        }
    }
}
