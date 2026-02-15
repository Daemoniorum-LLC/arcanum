/**
 * Arcanum WASM Benchmarks
 *
 * Measures performance of cryptographic operations and compares against
 * Node.js crypto module (native OpenSSL/BoringSSL).
 *
 * Run with: node bench.mjs
 * Requires: wasm-pack build --target nodejs
 */

import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const wasm = require(join(__dirname, "..", "..", "pkg", "arcanum_wasm.js"));

// ============================================================================
// Benchmark Infrastructure
// ============================================================================

const WARMUP_ITERATIONS = 100;
const MIN_DURATION_MS = 1000; // Run each benchmark for at least 1 second

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatRate(bytesPerSec) {
  if (bytesPerSec >= 1024 * 1024 * 1024)
    return `${(bytesPerSec / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
  if (bytesPerSec >= 1024 * 1024)
    return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
  if (bytesPerSec >= 1024)
    return `${(bytesPerSec / 1024).toFixed(2)} KB/s`;
  return `${bytesPerSec.toFixed(2)} B/s`;
}

function formatOps(opsPerSec) {
  if (opsPerSec >= 1000000) return `${(opsPerSec / 1000000).toFixed(2)}M ops/s`;
  if (opsPerSec >= 1000) return `${(opsPerSec / 1000).toFixed(2)}K ops/s`;
  return `${opsPerSec.toFixed(2)} ops/s`;
}

async function benchmark(name, fn, { bytes = 0, warmup = WARMUP_ITERATIONS } = {}) {
  // Warmup
  for (let i = 0; i < warmup; i++) {
    await fn();
  }

  // Timed run
  let iterations = 0;
  const start = performance.now();
  let elapsed = 0;

  while (elapsed < MIN_DURATION_MS) {
    await fn();
    iterations++;
    elapsed = performance.now() - start;
  }

  const opsPerSec = (iterations / elapsed) * 1000;
  const result = {
    name,
    iterations,
    totalMs: elapsed,
    opsPerSec,
    avgMs: elapsed / iterations,
  };

  if (bytes > 0) {
    result.bytesPerSec = (bytes * iterations / elapsed) * 1000;
    result.throughput = formatRate(result.bytesPerSec);
  }

  return result;
}

function printResult(result, baseline = null) {
  let line = `  ${result.name.padEnd(35)} ${formatOps(result.opsPerSec).padStart(14)}`;

  if (result.throughput) {
    line += `  ${result.throughput.padStart(12)}`;
  }

  if (baseline) {
    const ratio = result.opsPerSec / baseline.opsPerSec;
    const pct = ((ratio - 1) * 100).toFixed(1);
    const indicator = ratio >= 1 ? "✓" : "✗";
    line += `  ${indicator} ${ratio.toFixed(2)}x (${pct > 0 ? "+" : ""}${pct}%)`;
  }

  console.log(line);
}

function printHeader(title) {
  console.log(`\n${"═".repeat(80)}`);
  console.log(`  ${title}`);
  console.log(`${"═".repeat(80)}`);
}

function printSubheader(title) {
  console.log(`\n  ${title}`);
  console.log(`  ${"-".repeat(title.length)}`);
}

// ============================================================================
// Hash Benchmarks
// ============================================================================

async function benchmarkHashes() {
  printHeader("HASH FUNCTIONS");

  const sizes = [64, 1024, 16 * 1024, 1024 * 1024];

  for (const size of sizes) {
    const data = crypto.randomBytes(size);
    printSubheader(`Input size: ${formatBytes(size)}`);

    // SHA-256
    const sha256Node = await benchmark(
      "SHA-256 (Node.js crypto)",
      () => crypto.createHash("sha256").update(data).digest(),
      { bytes: size }
    );
    printResult(sha256Node);

    const sha256Wasm = await benchmark(
      "SHA-256 (Arcanum WASM)",
      () => wasm.sha256(data),
      { bytes: size }
    );
    printResult(sha256Wasm, sha256Node);

    // SHA3-256
    const sha3Node = await benchmark(
      "SHA3-256 (Node.js crypto)",
      () => crypto.createHash("sha3-256").update(data).digest(),
      { bytes: size }
    );
    printResult(sha3Node);

    const sha3Wasm = await benchmark(
      "SHA3-256 (Arcanum WASM)",
      () => wasm.sha3_256(data),
      { bytes: size }
    );
    printResult(sha3Wasm, sha3Node);

    // BLAKE3
    const blake3Wasm = await benchmark(
      "BLAKE3 (Arcanum WASM)",
      () => wasm.blake3(data),
      { bytes: size }
    );
    printResult(blake3Wasm);
  }
}

// ============================================================================
// AEAD Benchmarks
// ============================================================================

async function benchmarkAead() {
  printHeader("AUTHENTICATED ENCRYPTION (AEAD)");

  const sizes = [64, 1024, 16 * 1024, 64 * 1024];

  for (const size of sizes) {
    const plaintext = crypto.randomBytes(size);
    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);

    printSubheader(`Payload size: ${formatBytes(size)}`);

    // AES-256-GCM Encryption
    const aesEncNode = await benchmark(
      "AES-256-GCM encrypt (Node.js)",
      () => {
        const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
        const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        cipher.getAuthTag();
        return encrypted;
      },
      { bytes: size }
    );
    printResult(aesEncNode);

    const aesCipher = new wasm.AesGcm(key);
    const aesEncWasm = await benchmark(
      "AES-256-GCM encrypt (Arcanum WASM)",
      () => aesCipher.encrypt(plaintext, nonce, null),
      { bytes: size }
    );
    printResult(aesEncWasm, aesEncNode);

    // AES-256-GCM Decryption
    const ciphertext = aesCipher.encrypt(plaintext, nonce, null);

    const aesDecNode = await benchmark(
      "AES-256-GCM decrypt (Node.js)",
      () => {
        const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
        decipher.setAuthTag(ciphertext.slice(-16));
        return Buffer.concat([decipher.update(ciphertext.slice(0, -16)), decipher.final()]);
      },
      { bytes: size }
    );
    printResult(aesDecNode);

    const aesDecWasm = await benchmark(
      "AES-256-GCM decrypt (Arcanum WASM)",
      () => aesCipher.decrypt(ciphertext, nonce, null),
      { bytes: size }
    );
    printResult(aesDecWasm, aesDecNode);
    aesCipher.free();

    // ChaCha20-Poly1305 Encryption
    const chachaEncNode = await benchmark(
      "ChaCha20-Poly1305 encrypt (Node.js)",
      () => {
        const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
        const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        cipher.getAuthTag();
        return encrypted;
      },
      { bytes: size }
    );
    printResult(chachaEncNode);

    const chachaCipher = new wasm.ChaCha20Poly1305(key);
    const chachaEncWasm = await benchmark(
      "ChaCha20-Poly1305 encrypt (Arcanum WASM)",
      () => chachaCipher.encrypt(plaintext, nonce, null),
      { bytes: size }
    );
    printResult(chachaEncWasm, chachaEncNode);

    // ChaCha20-Poly1305 Decryption
    const chachaCiphertext = chachaCipher.encrypt(plaintext, nonce, null);

    const chachaDecNode = await benchmark(
      "ChaCha20-Poly1305 decrypt (Node.js)",
      () => {
        const decipher = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
        decipher.setAuthTag(chachaCiphertext.slice(-16));
        return Buffer.concat([decipher.update(chachaCiphertext.slice(0, -16)), decipher.final()]);
      },
      { bytes: size }
    );
    printResult(chachaDecNode);

    const chachaDecWasm = await benchmark(
      "ChaCha20-Poly1305 decrypt (Arcanum WASM)",
      () => chachaCipher.decrypt(chachaCiphertext, nonce, null),
      { bytes: size }
    );
    printResult(chachaDecWasm, chachaDecNode);
    chachaCipher.free();
  }
}

// ============================================================================
// Key Derivation Benchmarks
// ============================================================================

async function benchmarkKdf() {
  printHeader("KEY DERIVATION");

  const password = Buffer.from("correct horse battery staple");
  const salt = crypto.randomBytes(16);
  const ikm = crypto.randomBytes(32);
  const info = Buffer.from("application context");

  printSubheader("HKDF-SHA256 (32-byte output)");

  const hkdfNode = await benchmark(
    "HKDF-SHA256 (Node.js crypto)",
    () => new Promise((resolve, reject) => {
      crypto.hkdf("sha256", ikm, salt, info, 32, (err, key) => {
        if (err) reject(err);
        else resolve(key);
      });
    })
  );
  printResult(hkdfNode);

  const hkdfWasm = await benchmark(
    "HKDF-SHA256 (Arcanum WASM)",
    () => wasm.hkdf_sha256(ikm, salt, info, 32)
  );
  printResult(hkdfWasm, hkdfNode);

  printSubheader("Argon2id (default params, 32-byte output)");
  console.log("  Note: Argon2id is intentionally slow (password hashing)\n");

  const argon2Wasm = await benchmark(
    "Argon2id (Arcanum WASM)",
    () => wasm.argon2id(password, salt, null),
    { warmup: 5 }
  );
  printResult(argon2Wasm);
}

// ============================================================================
// Asymmetric Benchmarks
// ============================================================================

async function benchmarkAsymmetric() {
  printHeader("ASYMMETRIC CRYPTOGRAPHY");

  printSubheader("X25519 Key Exchange");

  // X25519 key generation
  const x25519GenNode = await benchmark(
    "X25519 keygen (Node.js crypto)",
    () => crypto.generateKeyPairSync("x25519")
  );
  printResult(x25519GenNode);

  const x25519GenWasm = await benchmark(
    "X25519 keygen (Arcanum WASM)",
    () => {
      const kp = wasm.X25519KeyPair.generate();
      kp.free();
    }
  );
  printResult(x25519GenWasm, x25519GenNode);

  // X25519 DH
  const nodeKp = crypto.generateKeyPairSync("x25519");
  const nodePubRaw = nodeKp.publicKey.export({ format: "der", type: "spki" }).slice(12);
  const wasmKp = wasm.X25519KeyPair.generate();
  const wasmPub = wasmKp.public_key();
  const wasmPubObj = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(wasmPub)]),
    format: "der",
    type: "spki",
  });

  const x25519DhNode = await benchmark(
    "X25519 DH (Node.js crypto)",
    () => crypto.diffieHellman({ privateKey: nodeKp.privateKey, publicKey: wasmPubObj })
  );
  printResult(x25519DhNode);

  const x25519DhWasm = await benchmark(
    "X25519 DH (Arcanum WASM)",
    () => wasmKp.diffie_hellman(nodePubRaw)
  );
  printResult(x25519DhWasm, x25519DhNode);
  wasmKp.free();

  printSubheader("Ed25519 Signatures");

  // Ed25519 key generation
  const ed25519GenNode = await benchmark(
    "Ed25519 keygen (Node.js crypto)",
    () => crypto.generateKeyPairSync("ed25519")
  );
  printResult(ed25519GenNode);

  const ed25519GenWasm = await benchmark(
    "Ed25519 keygen (Arcanum WASM)",
    () => {
      const kp = wasm.Ed25519KeyPair.generate();
      kp.free();
    }
  );
  printResult(ed25519GenWasm, ed25519GenNode);

  // Ed25519 signing
  const message = Buffer.from("test message for signing benchmarks");
  const nodeEdKp = crypto.generateKeyPairSync("ed25519");
  const wasmEdKp = wasm.Ed25519KeyPair.generate();

  const ed25519SignNode = await benchmark(
    "Ed25519 sign (Node.js crypto)",
    () => crypto.sign(null, message, nodeEdKp.privateKey)
  );
  printResult(ed25519SignNode);

  const ed25519SignWasm = await benchmark(
    "Ed25519 sign (Arcanum WASM)",
    () => wasmEdKp.sign(message)
  );
  printResult(ed25519SignWasm, ed25519SignNode);

  // Ed25519 verification
  const nodeEdSig = crypto.sign(null, message, nodeEdKp.privateKey);
  const wasmEdSig = wasmEdKp.sign(message);
  const wasmEdPub = wasmEdKp.public_key();

  const ed25519VerifyNode = await benchmark(
    "Ed25519 verify (Node.js crypto)",
    () => crypto.verify(null, message, nodeEdKp.publicKey, nodeEdSig)
  );
  printResult(ed25519VerifyNode);

  const ed25519VerifyWasm = await benchmark(
    "Ed25519 verify (Arcanum WASM)",
    () => wasm.Ed25519KeyPair.verify(wasmEdPub, message, wasmEdSig)
  );
  printResult(ed25519VerifyWasm, ed25519VerifyNode);
  wasmEdKp.free();
}

// ============================================================================
// Random Generation Benchmarks
// ============================================================================

async function benchmarkRandom() {
  printHeader("RANDOM NUMBER GENERATION");

  const sizes = [32, 256, 1024, 16 * 1024];

  for (const size of sizes) {
    printSubheader(`Size: ${formatBytes(size)}`);

    const randNode = await benchmark(
      "randomBytes (Node.js crypto)",
      () => crypto.randomBytes(size),
      { bytes: size }
    );
    printResult(randNode);

    const randWasm = await benchmark(
      "random_bytes (Arcanum WASM)",
      () => wasm.random_bytes(size),
      { bytes: size }
    );
    printResult(randWasm, randNode);
  }
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  console.log("\n" + "█".repeat(80));
  console.log("  ARCANUM WASM BENCHMARKS");
  console.log("  " + "-".repeat(76));
  console.log("  Comparing Arcanum WASM vs Node.js crypto (native OpenSSL/BoringSSL)");
  console.log("  Each benchmark runs for at least 1 second after warmup");
  console.log("█".repeat(80));

  await benchmarkHashes();
  await benchmarkAead();
  await benchmarkKdf();
  await benchmarkAsymmetric();
  await benchmarkRandom();

  console.log("\n" + "═".repeat(80));
  console.log("  BENCHMARK COMPLETE");
  console.log("═".repeat(80));
  console.log("\n  Legend:");
  console.log("  ✓ Faster or equal to native");
  console.log("  ✗ Slower than native (expected for WASM vs native code)");
  console.log("");
}

main().catch(console.error);
