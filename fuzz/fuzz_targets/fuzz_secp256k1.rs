//! Fuzz target for secp256k1 ECDH
//! Tests key exchange with the Bitcoin/Ethereum curve

#![no_main]

use arcanum_asymmetric::ecdh::{EcdhSecp256k1, Secp256k1PublicKey, Secp256k1SecretKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test key generation and DH
    let (alice_sk, alice_pk) = EcdhSecp256k1::generate();
    let (bob_sk, bob_pk) = EcdhSecp256k1::generate();

    // DH should be commutative
    let shared1 = alice_sk.diffie_hellman(&bob_pk);
    let shared2 = bob_sk.diffie_hellman(&alice_pk);

    if let (Ok(s1), Ok(s2)) = (shared1, shared2) {
        assert_eq!(s1.as_bytes(), s2.as_bytes(), "ECDH must be commutative");
    }

    // Test secret key generation
    let sk = Secp256k1SecretKey::generate();
    let pk = sk.public_key();

    // Public key derivation should be deterministic
    let pk2 = sk.public_key();
    assert_eq!(
        pk.to_sec1_bytes_compressed(),
        pk2.to_sec1_bytes_compressed(),
        "Public key derivation must be deterministic"
    );

    // Test DH with generated key against itself (degenerate case, shouldn't panic)
    let _ = sk.diffie_hellman(&pk);

    // Test public key parsing from fuzzed data
    // secp256k1 compressed public key is 33 bytes, uncompressed is 65 bytes
    if data.len() >= 33 {
        let _ = Secp256k1PublicKey::from_sec1_bytes(&data[..33]);
    }
    if data.len() >= 65 {
        let _ = Secp256k1PublicKey::from_sec1_bytes(&data[..65]);
    }

    // Test serialization roundtrip
    let pk_bytes = pk.to_sec1_bytes_compressed();
    let pk_restored = Secp256k1PublicKey::from_sec1_bytes(&pk_bytes);
    assert!(pk_restored.is_ok(), "Valid public key should deserialize");

    // Test uncompressed serialization roundtrip
    let pk_uncompressed = pk.to_sec1_bytes_uncompressed();
    let pk_restored_uncompressed = Secp256k1PublicKey::from_sec1_bytes(&pk_uncompressed);
    assert!(
        pk_restored_uncompressed.is_ok(),
        "Valid uncompressed public key should deserialize"
    );

    // Test DH with fuzzed peer public key (should fail gracefully for invalid keys)
    if data.len() >= 33 {
        if let Ok(peer_pk) = Secp256k1PublicKey::from_sec1_bytes(&data[..33]) {
            let _ = sk.diffie_hellman(&peer_pk);
        }
    }

    // Test shared secret key derivation
    if let Ok(shared) = alice_sk.diffie_hellman(&bob_pk) {
        // Key derivation should succeed
        let derived = shared.derive_key(b"secp256k1 test", 32);
        assert!(derived.is_ok(), "Key derivation from shared secret should succeed");
        if let Ok(key) = derived {
            assert_eq!(key.len(), 32, "Derived key should be requested length");
        }
    }
});
