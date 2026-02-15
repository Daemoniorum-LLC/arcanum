/**
 * Arcanum WASM Cross-Validation Tests
 *
 * These tests validate that arcanum-wasm produces output compatible with
 * Node.js crypto module and other reference implementations.
 *
 * This catches subtle issues like endianness, padding, or algorithm parameter
 * mismatches that unit tests might miss.
 *
 * Run with: node --test test-crypto-interop.mjs
 * Requires: wasm-pack build --target nodejs to have run first
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const pkgPath = join(__dirname, "..", "..", "pkg", "arcanum_wasm.js");

let wasm;

async function loadWasm() {
  if (wasm) return wasm;
  wasm = require(pkgPath);
  return wasm;
}

// ============================================================================
// SHA-256 Cross-Validation with Node.js crypto
// ============================================================================

describe("SHA-256 vs Node.js crypto", () => {
  test("empty input matches", async () => {
    const m = await loadWasm();

    const arcanumHash = m.sha256(new Uint8Array(0));
    const nodeHash = crypto.createHash("sha256").update("").digest();

    assert.deepEqual(Buffer.from(arcanumHash), nodeHash);
  });

  test("'hello world' matches", async () => {
    const m = await loadWasm();
    const input = "hello world";

    const arcanumHash = m.sha256(new TextEncoder().encode(input));
    const nodeHash = crypto.createHash("sha256").update(input).digest();

    assert.deepEqual(Buffer.from(arcanumHash), nodeHash);
  });

  test("binary data matches", async () => {
    const m = await loadWasm();
    const input = crypto.randomBytes(1000);

    const arcanumHash = m.sha256(input);
    const nodeHash = crypto.createHash("sha256").update(input).digest();

    assert.deepEqual(Buffer.from(arcanumHash), nodeHash);
  });

  test("large input (1MB) matches", async () => {
    const m = await loadWasm();
    const input = crypto.randomBytes(1024 * 1024);

    const arcanumHash = m.sha256(input);
    const nodeHash = crypto.createHash("sha256").update(input).digest();

    assert.deepEqual(Buffer.from(arcanumHash), nodeHash);
  });
});

// ============================================================================
// SHA3-256 Cross-Validation
// ============================================================================

describe("SHA3-256 vs Node.js crypto", () => {
  test("empty input matches", async () => {
    const m = await loadWasm();

    const arcanumHash = m.sha3_256(new Uint8Array(0));
    const nodeHash = crypto.createHash("sha3-256").update("").digest();

    assert.deepEqual(Buffer.from(arcanumHash), nodeHash);
  });

  test("'hello world' matches", async () => {
    const m = await loadWasm();
    const input = "hello world";

    const arcanumHash = m.sha3_256(new TextEncoder().encode(input));
    const nodeHash = crypto.createHash("sha3-256").update(input).digest();

    assert.deepEqual(Buffer.from(arcanumHash), nodeHash);
  });

  test("binary data matches", async () => {
    const m = await loadWasm();
    const input = crypto.randomBytes(1000);

    const arcanumHash = m.sha3_256(input);
    const nodeHash = crypto.createHash("sha3-256").update(input).digest();

    assert.deepEqual(Buffer.from(arcanumHash), nodeHash);
  });
});

// ============================================================================
// AES-256-GCM Cross-Validation
// ============================================================================

describe("AES-256-GCM vs Node.js crypto", () => {
  test("arcanum can decrypt Node.js ciphertext", async () => {
    const m = await loadWasm();

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const plaintext = "Hello from Node.js!";

    // Encrypt with Node.js
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    const nodeCiphertext = Buffer.concat([encrypted, tag]);

    // Decrypt with Arcanum
    const arcanumCipher = new m.AesGcm(key);
    const decrypted = arcanumCipher.decrypt(nodeCiphertext, nonce, null);

    assert.equal(new TextDecoder().decode(decrypted), plaintext);
    arcanumCipher.free();
  });

  test("Node.js can decrypt arcanum ciphertext", async () => {
    const m = await loadWasm();

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const plaintext = "Hello from Arcanum!";

    // Encrypt with Arcanum
    const arcanumCipher = new m.AesGcm(key);
    const ciphertext = arcanumCipher.encrypt(
      new TextEncoder().encode(plaintext),
      nonce,
      null
    );
    arcanumCipher.free();

    // Split ciphertext and tag (last 16 bytes)
    const encrypted = ciphertext.slice(0, -16);
    const tag = ciphertext.slice(-16);

    // Decrypt with Node.js
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    assert.equal(decrypted.toString("utf8"), plaintext);
  });

  test("cross-validation with AAD", async () => {
    const m = await loadWasm();

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const plaintext = "Secret data";
    const aad = Buffer.from("additional authenticated data");

    // Encrypt with Node.js
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    const nodeCiphertext = Buffer.concat([encrypted, tag]);

    // Decrypt with Arcanum
    const arcanumCipher = new m.AesGcm(key);
    const decrypted = arcanumCipher.decrypt(nodeCiphertext, nonce, aad);

    assert.equal(new TextDecoder().decode(decrypted), plaintext);
    arcanumCipher.free();
  });

  test("AAD mismatch detected by both", async () => {
    const m = await loadWasm();

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const plaintext = "Secret";
    const aad = Buffer.from("correct aad");
    const wrongAad = Buffer.from("wrong aad");

    // Encrypt with Arcanum using correct AAD
    const arcanumCipher = new m.AesGcm(key);
    const ciphertext = arcanumCipher.encrypt(
      new TextEncoder().encode(plaintext),
      nonce,
      aad
    );

    // Try to decrypt with wrong AAD
    assert.throws(() => arcanumCipher.decrypt(ciphertext, nonce, wrongAad));

    // Same with Node.js
    const encrypted = ciphertext.slice(0, -16);
    const tag = ciphertext.slice(-16);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    decipher.setAAD(wrongAad);

    assert.throws(() => {
      decipher.update(encrypted);
      decipher.final();
    });

    arcanumCipher.free();
  });
});

// ============================================================================
// ChaCha20-Poly1305 Cross-Validation
// ============================================================================

describe("ChaCha20-Poly1305 vs Node.js crypto", () => {
  test("arcanum can decrypt Node.js ciphertext", async () => {
    const m = await loadWasm();

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const plaintext = "Hello from Node.js ChaCha!";

    // Encrypt with Node.js
    const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, {
      authTagLength: 16,
    });
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    const nodeCiphertext = Buffer.concat([encrypted, tag]);

    // Decrypt with Arcanum
    const arcanumCipher = new m.ChaCha20Poly1305(key);
    const decrypted = arcanumCipher.decrypt(nodeCiphertext, nonce, null);

    assert.equal(new TextDecoder().decode(decrypted), plaintext);
    arcanumCipher.free();
  });

  test("Node.js can decrypt arcanum ciphertext", async () => {
    const m = await loadWasm();

    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const plaintext = "Hello from Arcanum ChaCha!";

    // Encrypt with Arcanum
    const arcanumCipher = new m.ChaCha20Poly1305(key);
    const ciphertext = arcanumCipher.encrypt(
      new TextEncoder().encode(plaintext),
      nonce,
      null
    );
    arcanumCipher.free();

    // Split ciphertext and tag
    const encrypted = ciphertext.slice(0, -16);
    const tag = ciphertext.slice(-16);

    // Decrypt with Node.js
    const decipher = crypto.createDecipheriv("chacha20-poly1305", key, nonce, {
      authTagLength: 16,
    });
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    assert.equal(decrypted.toString("utf8"), plaintext);
  });
});

// ============================================================================
// HKDF Cross-Validation
// ============================================================================

describe("HKDF-SHA256 vs Node.js crypto", () => {
  test("output matches Node.js hkdf", async () => {
    const m = await loadWasm();

    const ikm = crypto.randomBytes(32);
    const salt = crypto.randomBytes(32);
    const info = Buffer.from("application context");
    const length = 64;

    // Derive with Arcanum
    const arcanumKey = m.hkdf_sha256(ikm, salt, info, length);

    // Derive with Node.js
    const nodeKey = await new Promise((resolve, reject) => {
      crypto.hkdf("sha256", ikm, salt, info, length, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(Buffer.from(derivedKey));
      });
    });

    assert.deepEqual(Buffer.from(arcanumKey), nodeKey);
  });

  test("matches with empty salt", async () => {
    const m = await loadWasm();

    const ikm = crypto.randomBytes(32);
    const salt = new Uint8Array(0);
    const info = Buffer.from("info");
    const length = 32;

    const arcanumKey = m.hkdf_sha256(ikm, salt, info, length);

    const nodeKey = await new Promise((resolve, reject) => {
      crypto.hkdf("sha256", ikm, salt, info, length, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(Buffer.from(derivedKey));
      });
    });

    assert.deepEqual(Buffer.from(arcanumKey), nodeKey);
  });

  test("matches with empty info", async () => {
    const m = await loadWasm();

    const ikm = crypto.randomBytes(32);
    const salt = crypto.randomBytes(16);
    const info = new Uint8Array(0);
    const length = 32;

    const arcanumKey = m.hkdf_sha256(ikm, salt, info, length);

    const nodeKey = await new Promise((resolve, reject) => {
      crypto.hkdf("sha256", ikm, salt, info, length, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(Buffer.from(derivedKey));
      });
    });

    assert.deepEqual(Buffer.from(arcanumKey), nodeKey);
  });
});

// ============================================================================
// Ed25519 Cross-Validation
// ============================================================================

describe("Ed25519 vs Node.js crypto", () => {
  test("arcanum signature verifies with Node.js", async () => {
    const m = await loadWasm();

    // Generate with Arcanum
    const keypair = m.Ed25519KeyPair.generate();
    const publicKey = keypair.public_key();
    const message = Buffer.from("test message for signing");
    const signature = keypair.sign(message);
    keypair.free();

    // Verify with Node.js
    const nodePublicKey = crypto.createPublicKey({
      key: Buffer.concat([
        // Ed25519 public key DER prefix
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(publicKey),
      ]),
      format: "der",
      type: "spki",
    });

    const valid = crypto.verify(null, message, nodePublicKey, signature);
    assert.equal(valid, true);
  });

  test("Node.js signature verifies with arcanum", async () => {
    const m = await loadWasm();

    // Generate with Node.js
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const message = Buffer.from("test message for signing");
    const signature = crypto.sign(null, message, privateKey);

    // Extract raw public key bytes
    const rawPublicKey = publicKey.export({ format: "der", type: "spki" });
    // Skip the 12-byte DER prefix to get raw 32-byte key
    const publicKeyBytes = rawPublicKey.slice(12);

    // Verify with Arcanum
    const valid = m.Ed25519KeyPair.verify(publicKeyBytes, message, signature);
    assert.equal(valid, true);
  });

  test("from_seed produces same key as Node.js", async () => {
    const m = await loadWasm();

    const seed = crypto.randomBytes(32);

    // Generate with Arcanum
    const arcanumKeypair = m.Ed25519KeyPair.from_seed(seed);
    const arcanumPubKey = arcanumKeypair.public_key();
    arcanumKeypair.free();

    // Generate with Node.js
    const nodeKeypair = crypto.createPrivateKey({
      key: Buffer.concat([
        // Ed25519 private key seed DER prefix
        Buffer.from("302e020100300506032b657004220420", "hex"),
        seed,
      ]),
      format: "der",
      type: "pkcs8",
    });
    const nodePublicKey = crypto
      .createPublicKey(nodeKeypair)
      .export({ format: "der", type: "spki" });
    const nodePubKeyBytes = nodePublicKey.slice(12);

    assert.deepEqual(Buffer.from(arcanumPubKey), nodePubKeyBytes);
  });
});

// ============================================================================
// X25519 Cross-Validation
// ============================================================================

describe("X25519 vs Node.js crypto", () => {
  test("shared secret matches with Node.js peer", async () => {
    const m = await loadWasm();

    // Generate Arcanum keypair
    const arcanumKp = m.X25519KeyPair.generate();
    const arcanumPubKey = arcanumKp.public_key();

    // Generate Node.js keypair
    const nodeKp = crypto.generateKeyPairSync("x25519");
    const nodePubKeyRaw = nodeKp.publicKey
      .export({ format: "der", type: "spki" })
      .slice(12);

    // Arcanum computes shared secret with Node's public key
    const arcanumShared = arcanumKp.diffie_hellman(nodePubKeyRaw);

    // Node computes shared secret with Arcanum's public key
    const arcanumPubKeyObj = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b656e032100", "hex"),
        Buffer.from(arcanumPubKey),
      ]),
      format: "der",
      type: "spki",
    });
    const nodeShared = crypto.diffieHellman({
      privateKey: nodeKp.privateKey,
      publicKey: arcanumPubKeyObj,
    });

    assert.deepEqual(Buffer.from(arcanumShared), nodeShared);

    arcanumKp.free();
  });
});

// ============================================================================
// Random Number Generation Sanity
// ============================================================================

describe("Random Generation Sanity", () => {
  test("random_bytes has reasonable entropy", async () => {
    const m = await loadWasm();

    // Generate many random bytes and check they're not all zeros or repeating
    const samples = [];
    for (let i = 0; i < 100; i++) {
      samples.push(Buffer.from(m.random_bytes(32)).toString("hex"));
    }

    // All samples should be unique
    const unique = new Set(samples);
    assert.equal(unique.size, 100, "All random samples should be unique");
  });

  test("random_bytes distribution sanity check", async () => {
    const m = await loadWasm();

    // Generate a lot of random bytes
    const bytes = m.random_bytes(10000);

    // Count byte value frequencies
    const counts = new Array(256).fill(0);
    for (const b of bytes) {
      counts[b]++;
    }

    // Expected count per byte value: 10000/256 ≈ 39
    // Check that no value is extremely over or under-represented
    // Using 75% tolerance to avoid flaky failures from normal statistical variation
    const expected = 10000 / 256;
    const tolerance = expected * 0.75; // 75% tolerance

    for (let i = 0; i < 256; i++) {
      assert.ok(
        counts[i] > expected - tolerance && counts[i] < expected + tolerance,
        `Byte ${i} appears ${counts[i]} times (expected ~${expected.toFixed(0)})`
      );
    }
  });
});
