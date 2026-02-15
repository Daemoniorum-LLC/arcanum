/**
 * Arcanum WASM Integration Tests
 *
 * These tests exercise the actual JavaScript bindings, not just Rust-in-WASM.
 * They verify that the published API works correctly from real JavaScript.
 *
 * Run with: node --test test.mjs
 * Requires: wasm-pack build --target nodejs to have run first (../pkg must exist)
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Node.js target auto-initializes the WASM module on require
const pkgPath = join(__dirname, "..", "..", "pkg", "arcanum_wasm.js");

let wasm;

async function loadWasm() {
  if (wasm) return wasm;
  // Node.js target synchronously loads WASM on require
  wasm = require(pkgPath);
  return wasm;
}

// ============================================================================
// Module Loading & Export Verification
// ============================================================================

describe("Module Loading", () => {
  test("WASM module loads successfully", async () => {
    const m = await loadWasm();
    assert.ok(m, "Module should load");
  });

  test("all expected exports exist", async () => {
    const m = await loadWasm();

    // Hash functions
    assert.equal(typeof m.sha256, "function", "sha256 should be exported");
    assert.equal(typeof m.sha3_256, "function", "sha3_256 should be exported");
    assert.equal(typeof m.blake3, "function", "blake3 should be exported");

    // Random
    assert.equal(
      typeof m.random_bytes,
      "function",
      "random_bytes should be exported"
    );

    // KDF
    assert.equal(typeof m.argon2id, "function", "argon2id should be exported");
    assert.equal(
      typeof m.hkdf_sha256,
      "function",
      "hkdf_sha256 should be exported"
    );

    // Symmetric ciphers (classes)
    assert.equal(typeof m.AesGcm, "function", "AesGcm should be exported");
    assert.equal(
      typeof m.ChaCha20Poly1305,
      "function",
      "ChaCha20Poly1305 should be exported"
    );

    // Asymmetric (classes)
    assert.equal(
      typeof m.X25519KeyPair,
      "function",
      "X25519KeyPair should be exported"
    );
    assert.equal(
      typeof m.Ed25519KeyPair,
      "function",
      "Ed25519KeyPair should be exported"
    );

    // Error type
    assert.equal(
      typeof m.CryptoError,
      "function",
      "CryptoError should be exported"
    );
  });
});

// ============================================================================
// TypedArray Input Handling
// ============================================================================

describe("TypedArray Inputs", () => {
  test("sha256 accepts Uint8Array", async () => {
    const m = await loadWasm();
    const input = new Uint8Array([104, 101, 108, 108, 111]); // "hello"
    const hash = m.sha256(input);

    assert.ok(hash instanceof Uint8Array, "Output should be Uint8Array");
    assert.equal(hash.length, 32, "SHA-256 output should be 32 bytes");
  });

  test("sha256 accepts regular Array (converted)", async () => {
    const m = await loadWasm();
    // wasm-bindgen should handle Array -> Uint8Array conversion
    const input = [104, 101, 108, 108, 111];
    const hash = m.sha256(input);

    assert.equal(hash.length, 32);
  });

  test("random_bytes returns Uint8Array", async () => {
    const m = await loadWasm();
    const bytes = m.random_bytes(32);

    assert.ok(bytes instanceof Uint8Array, "Should return Uint8Array");
    assert.equal(bytes.length, 32);
  });

  test("AesGcm accepts Uint8Array for all parameters", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
    const aad = new Uint8Array([10, 20, 30]);

    const cipher = new m.AesGcm(key);
    const ciphertext = cipher.encrypt(plaintext, nonce, aad);

    assert.ok(ciphertext instanceof Uint8Array);
    assert.ok(ciphertext.length > plaintext.length); // Includes auth tag

    const decrypted = cipher.decrypt(ciphertext, nonce, aad);
    assert.deepEqual(decrypted, plaintext);

    cipher.free();
  });
});

// ============================================================================
// Hash Function KAT (Known Answer Tests)
// ============================================================================

describe("Hash Functions - KAT", () => {
  test("sha256 empty input matches NIST", async () => {
    const m = await loadWasm();
    const hash = m.sha256(new Uint8Array(0));
    const hex = Buffer.from(hash).toString("hex");

    assert.equal(
      hex,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  test("sha256 'hello' matches known value", async () => {
    const m = await loadWasm();
    const hash = m.sha256(new TextEncoder().encode("hello"));
    const hex = Buffer.from(hash).toString("hex");

    assert.equal(
      hex,
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });

  test("sha3_256 empty input matches NIST", async () => {
    const m = await loadWasm();
    const hash = m.sha3_256(new Uint8Array(0));
    const hex = Buffer.from(hash).toString("hex");

    assert.equal(
      hex,
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
  });

  test("blake3 empty input matches reference", async () => {
    const m = await loadWasm();
    const hash = m.blake3(new Uint8Array(0));
    const hex = Buffer.from(hash).toString("hex");

    assert.equal(
      hex,
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
  });
});

// ============================================================================
// Symmetric Encryption
// ============================================================================

describe("AES-GCM", () => {
  test("roundtrip encryption/decryption", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const plaintext = new TextEncoder().encode("secret message");

    const cipher = new m.AesGcm(key);
    const ciphertext = cipher.encrypt(plaintext, nonce, null);
    const decrypted = cipher.decrypt(ciphertext, nonce, null);

    assert.deepEqual(decrypted, plaintext);
    cipher.free();
  });

  test("ciphertext includes 16-byte auth tag", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const plaintext = new Uint8Array(100);

    const cipher = new m.AesGcm(key);
    const ciphertext = cipher.encrypt(plaintext, nonce, null);

    // Ciphertext = plaintext length + 16 byte tag
    assert.equal(ciphertext.length, 100 + 16);
    cipher.free();
  });

  test("tampered ciphertext throws CryptoError", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const plaintext = new TextEncoder().encode("secret");

    const cipher = new m.AesGcm(key);
    const ciphertext = cipher.encrypt(plaintext, nonce, null);

    // Tamper
    ciphertext[0] ^= 0xff;

    try {
      cipher.decrypt(ciphertext, nonce, null);
      assert.fail("Should have thrown");
    } catch (e) {
      // CryptoError objects have code and message getters
      assert.equal(e.code, "DECRYPTION_FAILED");
    }
    cipher.free();
  });

  test("wrong AAD throws CryptoError", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const plaintext = new TextEncoder().encode("secret");
    const aad = new TextEncoder().encode("correct");
    const wrongAad = new TextEncoder().encode("wrong");

    const cipher = new m.AesGcm(key);
    const ciphertext = cipher.encrypt(plaintext, nonce, aad);

    try {
      cipher.decrypt(ciphertext, nonce, wrongAad);
      assert.fail("Should have thrown");
    } catch (e) {
      assert.equal(e.code, "DECRYPTION_FAILED");
    }
    cipher.free();
  });

  test("invalid key length throws INVALID_KEY", async () => {
    const m = await loadWasm();
    const badKey = m.random_bytes(16); // Should be 32

    try {
      new m.AesGcm(badKey);
      assert.fail("Should have thrown");
    } catch (e) {
      assert.equal(e.code, "INVALID_KEY");
    }
  });

  test("invalid nonce length throws INVALID_NONCE", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const badNonce = m.random_bytes(8); // Should be 12

    const cipher = new m.AesGcm(key);
    try {
      cipher.encrypt(new Uint8Array(10), badNonce, null);
      assert.fail("Should have thrown");
    } catch (e) {
      assert.equal(e.code, "INVALID_NONCE");
    }
    cipher.free();
  });
});

describe("ChaCha20-Poly1305", () => {
  test("roundtrip encryption/decryption", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const plaintext = new TextEncoder().encode("secret message");

    const cipher = new m.ChaCha20Poly1305(key);
    const ciphertext = cipher.encrypt(plaintext, nonce, null);
    const decrypted = cipher.decrypt(ciphertext, nonce, null);

    assert.deepEqual(decrypted, plaintext);
    cipher.free();
  });

  test("empty plaintext produces 16-byte tag only", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);

    const cipher = new m.ChaCha20Poly1305(key);
    const ciphertext = cipher.encrypt(new Uint8Array(0), nonce, null);

    assert.equal(ciphertext.length, 16); // Just the Poly1305 tag
    cipher.free();
  });
});

// ============================================================================
// Key Derivation
// ============================================================================

describe("Key Derivation", () => {
  test("argon2id produces 32-byte key by default", async () => {
    const m = await loadWasm();
    const password = new TextEncoder().encode("password");
    const salt = m.random_bytes(16);

    const key = m.argon2id(password, salt, null);

    assert.equal(key.length, 32);
  });

  test("argon2id is deterministic with same inputs", async () => {
    const m = await loadWasm();
    const password = new TextEncoder().encode("password");
    const salt = new TextEncoder().encode("fixed_salt_1234!");

    const key1 = m.argon2id(password, salt, null);
    const key2 = m.argon2id(password, salt, null);

    assert.deepEqual(key1, key2);
  });

  test("hkdf_sha256 produces requested length", async () => {
    const m = await loadWasm();
    const ikm = m.random_bytes(32);
    const salt = m.random_bytes(32);
    const info = new TextEncoder().encode("context");

    for (const len of [16, 32, 64, 128]) {
      const key = m.hkdf_sha256(ikm, salt, info, len);
      assert.equal(key.length, len);
    }
  });

  test("hkdf_sha256 is deterministic", async () => {
    const m = await loadWasm();
    const ikm = new TextEncoder().encode("input key material");
    const salt = new TextEncoder().encode("salt");
    const info = new TextEncoder().encode("info");

    const key1 = m.hkdf_sha256(ikm, salt, info, 32);
    const key2 = m.hkdf_sha256(ikm, salt, info, 32);

    assert.deepEqual(key1, key2);
  });
});

// ============================================================================
// Asymmetric Cryptography
// ============================================================================

describe("X25519 Key Exchange", () => {
  test("generate produces 32-byte public key", async () => {
    const m = await loadWasm();
    const keypair = m.X25519KeyPair.generate();

    assert.equal(keypair.public_key().length, 32);
    keypair.free();
  });

  test("diffie_hellman produces same shared secret", async () => {
    const m = await loadWasm();
    const alice = m.X25519KeyPair.generate();
    const bob = m.X25519KeyPair.generate();

    const sharedAlice = alice.diffie_hellman(bob.public_key());
    const sharedBob = bob.diffie_hellman(alice.public_key());

    assert.deepEqual(sharedAlice, sharedBob);
    assert.equal(sharedAlice.length, 32);

    alice.free();
    bob.free();
  });

  test("different keypairs produce different public keys", async () => {
    const m = await loadWasm();
    const kp1 = m.X25519KeyPair.generate();
    const kp2 = m.X25519KeyPair.generate();

    const pk1 = Buffer.from(kp1.public_key()).toString("hex");
    const pk2 = Buffer.from(kp2.public_key()).toString("hex");

    assert.notEqual(pk1, pk2);

    kp1.free();
    kp2.free();
  });
});

describe("Ed25519 Signatures", () => {
  test("generate produces 32-byte public key", async () => {
    const m = await loadWasm();
    const keypair = m.Ed25519KeyPair.generate();

    assert.equal(keypair.public_key().length, 32);
    keypair.free();
  });

  test("sign produces 64-byte signature", async () => {
    const m = await loadWasm();
    const keypair = m.Ed25519KeyPair.generate();
    const message = new TextEncoder().encode("test message");

    const signature = keypair.sign(message);

    assert.equal(signature.length, 64);
    keypair.free();
  });

  test("verify accepts valid signature", async () => {
    const m = await loadWasm();
    const keypair = m.Ed25519KeyPair.generate();
    const message = new TextEncoder().encode("test message");

    const signature = keypair.sign(message);
    const valid = m.Ed25519KeyPair.verify(
      keypair.public_key(),
      message,
      signature
    );

    assert.equal(valid, true);
    keypair.free();
  });

  test("verify rejects wrong message", async () => {
    const m = await loadWasm();
    const keypair = m.Ed25519KeyPair.generate();
    const message = new TextEncoder().encode("original");
    const wrongMessage = new TextEncoder().encode("different");

    const signature = keypair.sign(message);
    const valid = m.Ed25519KeyPair.verify(
      keypair.public_key(),
      wrongMessage,
      signature
    );

    assert.equal(valid, false);
    keypair.free();
  });

  test("verify rejects tampered signature", async () => {
    const m = await loadWasm();
    const keypair = m.Ed25519KeyPair.generate();
    const message = new TextEncoder().encode("test");

    const signature = keypair.sign(message);
    signature[0] ^= 0xff; // Tamper

    const valid = m.Ed25519KeyPair.verify(
      keypair.public_key(),
      message,
      signature
    );

    assert.equal(valid, false);
    keypair.free();
  });

  test("from_seed is deterministic", async () => {
    const m = await loadWasm();
    const seed = m.random_bytes(32);

    const kp1 = m.Ed25519KeyPair.from_seed(seed);
    const kp2 = m.Ed25519KeyPair.from_seed(seed);

    assert.deepEqual(kp1.public_key(), kp2.public_key());

    kp1.free();
    kp2.free();
  });
});

// ============================================================================
// Error Handling from JS
// ============================================================================

describe("Error Handling", () => {
  test("CryptoError has code getter", async () => {
    const m = await loadWasm();
    const badKey = m.random_bytes(16);

    try {
      new m.AesGcm(badKey);
      assert.fail("Should have thrown");
    } catch (e) {
      // CryptoError has code and message getters
      assert.equal(e.code, "INVALID_KEY");
      assert.ok(e.message.includes("32-byte key"));
    }
  });

  test("CryptoError has message getter", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const cipher = new m.AesGcm(key);

    const ciphertext = cipher.encrypt(new Uint8Array([1, 2, 3]), nonce, null);
    ciphertext[0] ^= 0xff;

    try {
      cipher.decrypt(ciphertext, nonce, null);
      assert.fail("Should have thrown");
    } catch (e) {
      assert.equal(e.code, "DECRYPTION_FAILED");
      assert.equal(e.message, "Authentication tag verification failed");
    }
    cipher.free();
  });

  test("errors are catchable in try/catch", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);
    const nonce = m.random_bytes(12);
    const cipher = new m.AesGcm(key);

    const ciphertext = cipher.encrypt(new Uint8Array([1, 2, 3]), nonce, null);
    ciphertext[0] ^= 0xff;

    let caught = false;
    try {
      cipher.decrypt(ciphertext, nonce, null);
    } catch (e) {
      caught = true;
      assert.equal(e.code, "DECRYPTION_FAILED");
    }

    assert.ok(caught, "Error should have been caught");
    cipher.free();
  });
});

// ============================================================================
// Memory Management
// ============================================================================

describe("Memory Management", () => {
  test("cipher.free() does not throw", async () => {
    const m = await loadWasm();
    const key = m.random_bytes(32);

    const aes = new m.AesGcm(key);
    const chacha = new m.ChaCha20Poly1305(key);

    // Should not throw
    aes.free();
    chacha.free();
  });

  test("keypair.free() does not throw", async () => {
    const m = await loadWasm();

    const x25519 = m.X25519KeyPair.generate();
    const ed25519 = m.Ed25519KeyPair.generate();

    // Should not throw
    x25519.free();
    ed25519.free();
  });
});
