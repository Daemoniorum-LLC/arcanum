#![no_main]

use arcanum_asymmetric::ecdh::{P256SecretKey, P256PublicKey, EcdhP256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test key generation and DH
    let (alice_sk, alice_pk) = EcdhP256::generate();
    let (bob_sk, bob_pk) = EcdhP256::generate();

    // DH should be commutative
    let shared1 = alice_sk.diffie_hellman(&bob_pk);
    let shared2 = bob_sk.diffie_hellman(&alice_pk);

    if let (Ok(s1), Ok(s2)) = (shared1, shared2) {
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    // Test secret key generation from random bytes
    let sk = P256SecretKey::generate();
    let pk = sk.public_key();

    // Public key derivation should be deterministic
    let pk2 = sk.public_key();
    assert_eq!(pk.to_sec1_bytes_compressed(), pk2.to_sec1_bytes_compressed());

    // Test DH with generated key against itself (degenerate case, but shouldn't panic)
    let _ = sk.diffie_hellman(&pk);

    // Test public key parsing from fuzzed data
    // P256 compressed public key is 33 bytes, uncompressed is 65 bytes
    if data.len() >= 33 {
        let _ = P256PublicKey::from_sec1_bytes(&data[..33]);
    }
    if data.len() >= 65 {
        let _ = P256PublicKey::from_sec1_bytes(&data[..65]);
    }

    // Test serialization roundtrip
    let pk_bytes = pk.to_sec1_bytes_compressed();
    let pk_restored = P256PublicKey::from_sec1_bytes(&pk_bytes);
    assert!(pk_restored.is_ok());

    // Test DH with fuzzed peer public key (should fail gracefully for invalid keys)
    if data.len() >= 33 {
        if let Ok(peer_pk) = P256PublicKey::from_sec1_bytes(&data[..33]) {
            let _ = sk.diffie_hellman(&peer_pk);
        }
    }
});
