use arcanum_symmetric::{ChaCha20Poly1305Cipher, Cipher};

fn main() {
    let data: [u8; 61] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00,
        0x00, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x27, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a
    ];
    
    let key = &data[..32];
    let nonce = &data[32..44];
    let plaintext = &data[44..];
    
    println!("Testing encrypt...");
    match ChaCha20Poly1305Cipher::encrypt(key, nonce, plaintext, None) {
        Ok(ciphertext) => {
            println!("Encrypt succeeded, ciphertext len: {}", ciphertext.len());
            println!("Testing decrypt roundtrip...");
            let decrypted = ChaCha20Poly1305Cipher::decrypt(key, nonce, &ciphertext, None);
            println!("Decrypt result: {:?}", decrypted.map(|d| d.len()));
            assert!(decrypted.is_ok());
            assert_eq!(decrypted.unwrap(), plaintext);
            println!("Roundtrip OK!");
        }
        Err(e) => println!("Encrypt failed: {:?}", e),
    }
    
    println!("\nTesting arbitrary decrypt (should fail gracefully)...");
    if plaintext.len() >= 16 {
        let result = ChaCha20Poly1305Cipher::decrypt(key, nonce, plaintext, None);
        println!("Arbitrary decrypt result: {:?}", result);
    }
    
    println!("\nTesting with AAD...");
    if data.len() >= 32 + 12 + 16 + 1 {
        let aad = &data[44..60];
        let pt = &data[60..];
        println!("AAD len: {}, plaintext len: {}", aad.len(), pt.len());
        match ChaCha20Poly1305Cipher::encrypt(key, nonce, pt, Some(aad)) {
            Ok(ct) => {
                println!("Encrypt with AAD succeeded");
                let dec = ChaCha20Poly1305Cipher::decrypt(key, nonce, &ct, Some(aad));
                println!("Decrypt with AAD: {:?}", dec.map(|d| d.len()));
                
                // Wrong AAD test
                let wrong_aad = [0u8; 16];
                let wrong_result = ChaCha20Poly1305Cipher::decrypt(key, nonce, &ct, Some(&wrong_aad));
                println!("Wrong AAD result (should fail): {:?}", wrong_result);
            }
            Err(e) => println!("Encrypt with AAD failed: {:?}", e),
        }
    }
    
    println!("\nAll tests passed without crash!");
}
