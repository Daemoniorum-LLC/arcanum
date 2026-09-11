#![no_main]

use arcanum_threshold::shamir::{ShamirScheme, Share};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let threshold = data[0] as usize;
    let total = data[1] as usize;
    let secret = &data[2..];

    // Test split with arbitrary parameters — should never panic
    match ShamirScheme::split(secret, threshold, total) {
        Ok(shares) => {
            // Verify roundtrip: combine all shares should recover secret
            if let Ok(recovered) = ShamirScheme::combine(&shares) {
                assert_eq!(recovered, secret);
            }

            // Combine with threshold shares (if we have enough)
            if shares.len() >= threshold && threshold > 0 {
                if let Ok(recovered) = ShamirScheme::combine(&shares[..threshold]) {
                    assert_eq!(recovered, secret);
                }
            }
        }
        Err(_) => {
            // Errors are fine — we're fuzzing invalid inputs
        }
    }

    // Test Share::from_bytes with arbitrary data — should never panic
    let _ = Share::from_bytes(data);

    // Test combine with crafted shares — should never panic
    if data.len() >= 6 {
        let share1 = Share::new(data[0], data[2..].to_vec());
        let share2 = Share::new(data[1], data[2..].to_vec());
        let _ = ShamirScheme::combine(&[share1, share2]);
    }
});
