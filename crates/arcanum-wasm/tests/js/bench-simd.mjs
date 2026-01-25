/**
 * Arcanum WASM SIMD Benchmark
 *
 * Compares performance between scalar and SIMD WASM builds.
 *
 * Usage:
 *   # Build scalar WASM
 *   wasm-pack build ../.. --target nodejs --features backend-native --no-default-features
 *   cp ../../pkg ../../pkg-scalar -r
 *
 *   # Build SIMD WASM
 *   RUSTFLAGS="-C target-feature=+simd128" wasm-pack build ../.. --target nodejs --features backend-native-simd --no-default-features
 *   cp ../../pkg ../../pkg-simd -r
 *
 *   # Run benchmark
 *   node bench-simd.mjs
 */

import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const MIN_DURATION_MS = 500;

// Try to load both builds
let scalarWasm = null;
let simdWasm = null;

const scalarPath = join(__dirname, "..", "..", "pkg-scalar", "arcanum_wasm.js");
const simdPath = join(__dirname, "..", "..", "pkg-simd", "arcanum_wasm.js");
const defaultPath = join(__dirname, "..", "..", "pkg", "arcanum_wasm.js");

if (existsSync(scalarPath)) {
  scalarWasm = require(scalarPath);
  console.log("Loaded scalar WASM from pkg-scalar/");
} else if (existsSync(defaultPath)) {
  scalarWasm = require(defaultPath);
  console.log("Loaded scalar WASM from pkg/ (assuming scalar build)");
}

if (existsSync(simdPath)) {
  simdWasm = require(simdPath);
  console.log("Loaded SIMD WASM from pkg-simd/");
}

async function benchmark(name, fn, { bytes = 0, warmup = 50 } = {}) {
  // Warmup
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
  const throughput = bytes > 0 ? (bytes * iterations / elapsed) * 1000 : null;

  return {
    name,
    opsPerSec,
    throughput,
    iterations,
    elapsedMs: elapsed,
  };
}

async function runChaCha20Benchmarks(wasm, label) {
  const results = {};
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);

  // Test various sizes - SIMD kicks in at 256+ bytes
  for (const size of [64, 256, 1024, 4096, 16384]) {
    const plaintext = crypto.randomBytes(size);
    const cipher = new wasm.ChaCha20Poly1305(key);

    const result = await benchmark(
      `ChaCha20 encrypt ${size}B`,
      () => cipher.encrypt(plaintext, nonce, null),
      { bytes: size }
    );

    results[`encrypt_${size}B`] = result;
    cipher.free();
  }

  return results;
}

async function runHashBenchmarks(wasm, label) {
  const results = {};

  // Test various sizes
  for (const size of [64, 256, 1024, 4096, 16384]) {
    const data = crypto.randomBytes(size);

    // SHA-256
    const sha256Result = await benchmark(
      `SHA-256 ${size}B`,
      () => wasm.sha256(data),
      { bytes: size }
    );
    results[`sha256_${size}B`] = sha256Result;

    // BLAKE3
    const blake3Result = await benchmark(
      `BLAKE3 ${size}B`,
      () => wasm.blake3(data),
      { bytes: size }
    );
    results[`blake3_${size}B`] = blake3Result;
  }

  return results;
}

async function main() {
  console.log("\n" + "=".repeat(80));
  console.log("  WASM SIMD BENCHMARK: Scalar vs SIMD");
  console.log("=".repeat(80) + "\n");

  if (!scalarWasm && !simdWasm) {
    console.error("No WASM builds found. Please build with:");
    console.error("  # Scalar build:");
    console.error("  wasm-pack build ../.. --target nodejs --features backend-native --no-default-features");
    console.error("  cp ../../pkg ../../pkg-scalar -r");
    console.error("");
    console.error("  # SIMD build:");
    console.error('  RUSTFLAGS="-C target-feature=+simd128" wasm-pack build ../.. --target nodejs --features backend-native-simd --no-default-features');
    console.error("  cp ../../pkg ../../pkg-simd -r");
    process.exit(1);
  }

  let scalarResults = null;
  let simdResults = null;
  let scalarHashResults = null;
  let simdHashResults = null;

  if (scalarWasm) {
    console.log("Running scalar benchmarks...");
    scalarResults = await runChaCha20Benchmarks(scalarWasm, "scalar");
    scalarHashResults = await runHashBenchmarks(scalarWasm, "scalar");
  }

  if (simdWasm) {
    console.log("Running SIMD benchmarks...");
    simdResults = await runChaCha20Benchmarks(simdWasm, "simd");
    simdHashResults = await runHashBenchmarks(simdWasm, "simd");
  }

  // Print results
  console.log("\n" + "=".repeat(80));
  console.log("  RESULTS");
  console.log("=".repeat(80) + "\n");

  const header = "  Test".padEnd(30) +
    (scalarResults ? "Scalar".padStart(15) : "") +
    (simdResults ? "SIMD".padStart(15) : "") +
    (scalarResults && simdResults ? "Speedup".padStart(12) : "");

  console.log(header);
  console.log("  " + "-".repeat(header.length - 2));

  const sizes = [64, 256, 1024, 4096, 16384];
  for (const size of sizes) {
    const key = `encrypt_${size}B`;
    const scalar = scalarResults?.[key];
    const simd = simdResults?.[key];

    let line = `  ChaCha20 encrypt ${size}B`.padEnd(30);

    if (scalar) {
      line += `${(scalar.opsPerSec / 1000).toFixed(1)}K`.padStart(15);
    }
    if (simd) {
      line += `${(simd.opsPerSec / 1000).toFixed(1)}K`.padStart(15);
    }
    if (scalar && simd) {
      const speedup = simd.opsPerSec / scalar.opsPerSec;
      const indicator = speedup >= 1.0 ? "✓" : "✗";
      line += `${indicator} ${speedup.toFixed(2)}x`.padStart(12);
    }

    console.log(line);
  }

  console.log("");

  // Print throughput for larger sizes
  if (scalarResults || simdResults) {
    console.log("  Throughput (MB/s):");
    console.log("  " + "-".repeat(50));

    for (const size of [1024, 4096, 16384]) {
      const key = `encrypt_${size}B`;
      const scalar = scalarResults?.[key];
      const simd = simdResults?.[key];

      let line = `  ${size} bytes:`.padEnd(20);

      if (scalar && scalar.throughput) {
        const mbps = scalar.throughput / (1024 * 1024);
        line += `Scalar: ${mbps.toFixed(1)} MB/s`.padEnd(25);
      }
      if (simd && simd.throughput) {
        const mbps = simd.throughput / (1024 * 1024);
        line += `SIMD: ${mbps.toFixed(1)} MB/s`;
      }

      console.log(line);
    }
    console.log("");
  }

  // Hash benchmarks
  if (scalarHashResults || simdHashResults) {
    console.log("\n" + "=".repeat(80));
    console.log("  HASH BENCHMARKS");
    console.log("=".repeat(80) + "\n");

    const hashHeader = "  Test".padEnd(30) +
      (scalarHashResults ? "Scalar".padStart(15) : "") +
      (simdHashResults ? "SIMD".padStart(15) : "") +
      (scalarHashResults && simdHashResults ? "Speedup".padStart(12) : "");

    console.log(hashHeader);
    console.log("  " + "-".repeat(hashHeader.length - 2));

    for (const algo of ["sha256", "blake3"]) {
      for (const size of [64, 256, 1024, 4096, 16384]) {
        const key = `${algo}_${size}B`;
        const scalar = scalarHashResults?.[key];
        const simd = simdHashResults?.[key];

        let line = `  ${algo.toUpperCase()} ${size}B`.padEnd(30);

        if (scalar) {
          line += `${(scalar.opsPerSec / 1000).toFixed(1)}K`.padStart(15);
        }
        if (simd) {
          line += `${(simd.opsPerSec / 1000).toFixed(1)}K`.padStart(15);
        }
        if (scalar && simd) {
          const speedup = simd.opsPerSec / scalar.opsPerSec;
          const indicator = speedup >= 1.0 ? "✓" : "✗";
          line += `${indicator} ${speedup.toFixed(2)}x`.padStart(12);
        }

        console.log(line);
      }
      console.log("");
    }
  }

  // Summary
  if (scalarResults && simdResults) {
    console.log("  Summary:");
    console.log("  " + "-".repeat(50));

    // Calculate average speedup for SIMD-eligible sizes (256+)
    let totalSpeedup = 0;
    let count = 0;
    for (const size of [256, 1024, 4096, 16384]) {
      const key = `encrypt_${size}B`;
      const scalar = scalarResults[key];
      const simd = simdResults[key];
      if (scalar && simd) {
        totalSpeedup += simd.opsPerSec / scalar.opsPerSec;
        count++;
      }
    }

    if (count > 0) {
      const avgSpeedup = totalSpeedup / count;
      console.log(`  Average speedup (256B+): ${avgSpeedup.toFixed(2)}x`);

      if (avgSpeedup >= 1.5) {
        console.log("  ✓ SIMD target met (>1.5x speedup for SIMD-eligible sizes)");
      } else {
        console.log("  ✗ SIMD target not met (expected >1.5x speedup)");
      }
    }

    // Check 64B (should be similar or scalar slightly faster)
    const scalar64 = scalarResults["encrypt_64B"];
    const simd64 = simdResults["encrypt_64B"];
    if (scalar64 && simd64) {
      const speedup64 = simd64.opsPerSec / scalar64.opsPerSec;
      if (speedup64 >= 0.9) {
        console.log(`  ✓ Small message performance acceptable (64B: ${speedup64.toFixed(2)}x)`);
      } else {
        console.log(`  ⚠ Small message regression (64B: ${speedup64.toFixed(2)}x)`);
      }
    }
  }

  console.log("");
}

main().catch(console.error);
