#![no_main]

use arcanum_pqc::PostQuantumSignature;
use arcanum_pqc::dsa::{MlDsa65, MlDsa65SigningKey, MlDsa65VerifyingKey, MlDsa65Signature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test sign/verify roundtrip with generated keypair
    let (sk, vk): (MlDsa65SigningKey, MlDsa65VerifyingKey) = MlDsa65::generate_keypair();

    // Sign the fuzzed data
    let signature: MlDsa65Signature = MlDsa65::sign(&sk, data);

    // Verify should succeed
    assert!(MlDsa65::verify(&vk, data, &signature).is_ok());

    // Verify with wrong message should fail
    if !data.is_empty() {
        let mut wrong_message = data.to_vec();
        wrong_message[0] ^= 0xff;
        assert!(MlDsa65::verify(&vk, &wrong_message, &signature).is_err());
    }

    // Test key parsing with fuzzed data (should handle gracefully)
    if data.len() >= MlDsa65SigningKey::SIZE {
        let _ = MlDsa65SigningKey::from_bytes(&data[..MlDsa65SigningKey::SIZE]);
    }

    if data.len() >= MlDsa65VerifyingKey::SIZE {
        let _ = MlDsa65VerifyingKey::from_bytes(&data[..MlDsa65VerifyingKey::SIZE]);
    }

    // Test signature parsing with fuzzed data
    if data.len() >= MlDsa65Signature::SIZE {
        if let Ok(fuzzed_sig) = MlDsa65Signature::from_bytes(&data[..MlDsa65Signature::SIZE]) {
            // Verification with fuzzed signature should fail (or rarely succeed if we hit valid sig)
            let _ = MlDsa65::verify(&vk, b"test", &fuzzed_sig);
        }
    }

    // Test serialization roundtrip
    let sk_bytes: Vec<u8> = sk.to_bytes();
    let vk_bytes: Vec<u8> = vk.to_bytes();
    let sig_bytes: Vec<u8> = signature.to_bytes();

    let sk_restored = MlDsa65SigningKey::from_bytes(&sk_bytes);
    let vk_restored = MlDsa65VerifyingKey::from_bytes(&vk_bytes);
    let sig_restored = MlDsa65Signature::from_bytes(&sig_bytes);

    assert!(sk_restored.is_ok());
    assert!(vk_restored.is_ok());
    assert!(sig_restored.is_ok());
});
