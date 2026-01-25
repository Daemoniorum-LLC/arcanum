//! Generate cross-platform test vectors for XP-1/XP-2 validation
//!
//! Run with: cargo run --example gen_xp_vectors --features "sha2,blake3,chacha20"

use arcanum_primitives::blake3::Blake3;
use arcanum_primitives::chacha20::ChaCha20;
use arcanum_primitives::sha2::Sha256;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    println!("// Cross-Platform Test Vectors (XP-1/XP-2)");
    println!("// Generated from native x86-64 implementation");
    println!("// Both WASM SIMD and native SIMD must produce these exact outputs\n");

    // Test patterns
    let patterns: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("hello", b"hello".to_vec()),
        ("64_sequential", (0..64).collect()),
        (
            "256_pattern",
            (0..256).map(|i| ((i * 0x42 + 0x24) & 0xff) as u8).collect(),
        ),
        (
            "1024_pattern",
            (0..1024)
                .map(|i| ((i * 0x17 + 0x31) & 0xff) as u8)
                .collect(),
        ),
    ];

    // SHA-256 vectors
    println!("=== SHA-256 Test Vectors ===");
    for (name, data) in &patterns {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        println!("(\"{}\", \"{}\"),", name, to_hex(&hash));
    }

    println!("\n=== BLAKE3 Test Vectors ===");
    for (name, data) in &patterns {
        let mut hasher = Blake3::new();
        hasher.update(data);
        let hash = hasher.finalize();
        println!("(\"{}\", \"{}\"),", name, to_hex(&hash));
    }

    println!("\n=== ChaCha20 Test Vectors ===");
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];

    for size in [64, 256, 512, 1024] {
        let mut data: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
        let mut cipher = ChaCha20::new(&key, &nonce);
        cipher.apply_keystream(&mut data);

        // Print first and last 32 bytes for verification
        println!("// ChaCha20 {} bytes - first 32:", size);
        println!("\"{}\"", to_hex(&data[..32]));
        println!("// last 32:");
        println!("\"{}\"", to_hex(&data[data.len() - 32..]));
        println!();
    }
}
