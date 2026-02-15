/**
 * Arcanum WASM Backend Comparison Benchmark
 *
 * Compares performance between backend-rustcrypto and backend-native.
 * Run this after building each backend separately.
 *
 * Usage:
 *   # Build and benchmark rustcrypto backend
 *   wasm-pack build ../.. --target nodejs --features backend-rustcrypto --no-default-features
 *   node bench-compare.mjs rustcrypto
 *
 *   # Build and benchmark native backend
 *   wasm-pack build ../.. --target nodejs --features backend-native --no-default-features
 *   node bench-compare.mjs native
 */

import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const wasm = require(join(__dirname, "..", "..", "pkg", "arcanum_wasm.js"));

const RESULTS_FILE = join(__dirname, "bench-results.json");
const MIN_DURATION_MS = 500;

const backendName = process.argv[2] || "unknown";

async function benchmark(name, fn, { bytes = 0, warmup = 50 } = {}) {
  for (let i = 0; i < warmup; i++) await fn();

  let iterations = 0;
  const start = performance.now();
  let elapsed = 0;

  while (elapsed < MIN_DURATION_MS) {
    await fn();
    iterations++;
    elapsed = performance.now() - start;
  }

  const opsPerSec = (iterations / elapsed) * 1000;
  return {
    name,
    opsPerSec,
    ...(bytes > 0 && { bytesPerSec: (bytes * iterations / elapsed) * 1000 }),
  };
}

async function runBenchmarks() {
  const results = {};

  // SHA-256 (various sizes)
  for (const size of [64, 1024, 16384]) {
    const data = crypto.randomBytes(size);
    results[`sha256_${size}B`] = await benchmark(
      `SHA-256 ${size}B`,
      () => wasm.sha256(data),
      { bytes: size }
    );
  }

  // BLAKE3 (various sizes)
  for (const size of [64, 1024, 16384]) {
    const data = crypto.randomBytes(size);
    results[`blake3_${size}B`] = await benchmark(
      `BLAKE3 ${size}B`,
      () => wasm.blake3(data),
      { bytes: size }
    );
  }

  // ChaCha20-Poly1305 (this is where native backend differs)
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  for (const size of [64, 1024, 16384]) {
    const plaintext = crypto.randomBytes(size);
    const cipher = new wasm.ChaCha20Poly1305(key);

    results[`chacha20_encrypt_${size}B`] = await benchmark(
      `ChaCha20 encrypt ${size}B`,
      () => cipher.encrypt(plaintext, nonce, null),
      { bytes: size }
    );

    const ciphertext = cipher.encrypt(plaintext, nonce, null);
    results[`chacha20_decrypt_${size}B`] = await benchmark(
      `ChaCha20 decrypt ${size}B`,
      () => cipher.decrypt(ciphertext, nonce, null),
      { bytes: size }
    );
    cipher.free();
  }

  return results;
}

async function main() {
  console.log(`\nRunning benchmarks for backend: ${backendName}\n`);

  const results = await runBenchmarks();

  // Load existing results if any
  let allResults = {};
  if (existsSync(RESULTS_FILE)) {
    allResults = JSON.parse(readFileSync(RESULTS_FILE, "utf8"));
  }

  // Save results for this backend
  allResults[backendName] = results;
  writeFileSync(RESULTS_FILE, JSON.stringify(allResults, null, 2));

  console.log(`Results saved to ${RESULTS_FILE}`);

  // If we have both backends, show comparison
  if (allResults.rustcrypto && allResults.native) {
    console.log("\n" + "=".repeat(80));
    console.log("  BACKEND COMPARISON: rustcrypto vs native");
    console.log("=".repeat(80));
    console.log("\n  Benchmark".padEnd(35) + "RustCrypto".padStart(15) + "Native".padStart(15) + "Ratio".padStart(12));
    console.log("  " + "-".repeat(75));

    for (const key of Object.keys(allResults.rustcrypto)) {
      const rc = allResults.rustcrypto[key];
      const nat = allResults.native[key];
      if (rc && nat) {
        const ratio = nat.opsPerSec / rc.opsPerSec;
        const ratioStr = ratio >= 1
          ? `✓ ${ratio.toFixed(2)}x`
          : `✗ ${ratio.toFixed(2)}x`;
        console.log(
          `  ${rc.name.padEnd(33)}` +
          `${(rc.opsPerSec / 1000).toFixed(1)}K`.padStart(15) +
          `${(nat.opsPerSec / 1000).toFixed(1)}K`.padStart(15) +
          ratioStr.padStart(12)
        );
      }
    }
    console.log("");
  }
}

main().catch(console.error);
