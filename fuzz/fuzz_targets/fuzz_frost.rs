//! Fuzz target for FROST threshold signatures
//! Tests the multi-party signing protocol with structured inputs

#![no_main]

use arcanum_threshold::frost::{
    trusted_dealer_keygen, FrostSigner, FrostVerifier, SigningPackage,
    GroupVerifyingKey, PublicKeyPackage,
};
use libfuzzer_sys::fuzz_target;

// Re-export frost types needed for KeyPackage conversion
extern crate frost_ed25519 as frost;

fuzz_target!(|data: &[u8]| {
    // Need at least 2 bytes for threshold and total, plus message
    if data.len() < 3 {
        return;
    }

    // Extract threshold and total from fuzz input
    // Constrain to valid ranges: 2 <= threshold <= total <= 10
    let threshold = ((data[0] % 9) + 2) as u16; // 2-10
    let remaining = (11 - threshold) as u8;
    let total = threshold + (data[1] % remaining.max(1)) as u16; // threshold to 10
    let message = &data[2..];

    // Skip if constraints aren't met
    if threshold < 2 || total < threshold || total > 10 {
        return;
    }

    // Generate keys using trusted dealer
    let keygen_result = trusted_dealer_keygen(threshold, total);
    if keygen_result.is_err() {
        return;
    }
    let (shares, pubkey_package) = keygen_result.unwrap();

    // Convert shares to key packages and create signers
    let key_packages: Vec<_> = shares
        .iter()
        .take(threshold as usize)
        .filter_map(|s| frost::keys::KeyPackage::try_from(s.clone()).ok())
        .collect();

    if key_packages.len() < threshold as usize {
        return;
    }

    let signers: Vec<_> = key_packages
        .iter()
        .map(|kp| FrostSigner::new(kp.clone()))
        .collect();

    // Round 1: Generate nonces and commitments
    let mut all_nonces = Vec::new();
    let mut all_commitments = Vec::new();

    for signer in &signers {
        match signer.round1() {
            Ok((nonces, commitments)) => {
                all_nonces.push(nonces);
                all_commitments.push(commitments);
            }
            Err(_) => return, // Round 1 failed, exit gracefully
        }
    }

    // Create signing package
    let signing_package = match SigningPackage::new(&all_commitments, message) {
        Ok(pkg) => pkg,
        Err(_) => return,
    };

    // Round 2: Generate signature shares
    let mut signature_shares = Vec::new();
    for (i, signer) in signers.iter().enumerate() {
        match signer.round2(message, &all_nonces[i], &signing_package) {
            Ok(share) => signature_shares.push(share),
            Err(_) => return, // Round 2 failed, exit gracefully
        }
    }

    // Create verifier from the group key
    let group_key = match GroupVerifyingKey::from_frost(pubkey_package.verifying_key()) {
        Ok(k) => k,
        Err(_) => return,
    };
    let verifier = match FrostVerifier::new(&group_key) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Wrap the public key package
    let pkg = PublicKeyPackage::from_frost(pubkey_package);

    // Aggregate signature
    let aggregate_result = verifier.aggregate(&signing_package, &signature_shares, &pkg);
    if aggregate_result.is_err() {
        return;
    }
    let signature = aggregate_result.unwrap();

    // Verify the signature
    let verify_result = verifier.verify(message, &signature);
    assert!(verify_result.is_ok(), "Valid FROST signature should verify");
    if let Ok(valid) = verify_result {
        assert!(valid, "Signature verification should return true");
    }

    // Test that wrong message fails verification
    if !message.is_empty() {
        let mut wrong_message = message.to_vec();
        wrong_message[0] ^= 0xFF;
        let wrong_result = verifier.verify(&wrong_message, &signature);
        if let Ok(valid) = wrong_result {
            assert!(!valid, "Wrong message should not verify");
        }
    }

    // Signature bytes should exist and be non-empty
    let sig_bytes = signature.as_bytes();
    assert!(!sig_bytes.is_empty(), "Signature should have non-empty bytes");
});
