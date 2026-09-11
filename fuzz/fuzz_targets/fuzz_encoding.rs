#![no_main]

use arcanum_core::encoding::{Base58, Base64, Bech32, Hex, Multibase, Pem};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test all decoders with arbitrary bytes — should never panic
    if let Ok(s) = core::str::from_utf8(data) {
        // Hex decode
        let _ = Hex::decode(s);
        let _ = Hex::decode_array::<32>(s);
        let _ = Hex::is_valid(s);

        // Base64 decode
        let _ = Base64::decode(s);
        let _ = Base64::decode_url(s);

        // Base58 decode
        let _ = Base58::decode(s);
        let _ = Base58::decode_check(s);

        // Bech32 decode
        let _ = Bech32::decode(s);

        // PEM decode
        let _ = Pem::decode(s);

        // Multibase decode
        let _ = Multibase::decode(s);
    }

    // Test encode/decode roundtrips — encoded then decoded should match
    let hex_encoded = Hex::encode(data);
    assert_eq!(Hex::decode(&hex_encoded).unwrap(), data);

    let b64_encoded = Base64::encode(data);
    assert_eq!(Base64::decode(&b64_encoded).unwrap(), data);

    let b58_encoded = Base58::encode(data);
    assert_eq!(Base58::decode(&b58_encoded).unwrap(), data);

    let b58check_encoded = Base58::encode_check(data);
    assert_eq!(Base58::decode_check(&b58check_encoded).unwrap(), data);
});
