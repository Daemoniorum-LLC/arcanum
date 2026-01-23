//! Comprehensive benchmarks for hash functions.
//!
//! Compares Arcanum implementations against peer libraries:
//! - RustCrypto (direct backend)
//! - ring (BoringSSL wrapper)
//! - blake3 crate (reference implementation)

#![allow(dead_code)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

// Data sizes for benchmarking (covering various use cases)
const SIZES: &[usize] = &[64, 256, 1024, 4096, 16384, 65536, 1048576];

// ═══════════════════════════════════════════════════════════════════════════════
// ARCANUM SHA-256 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod arcanum_sha256 {
    use arcanum_hash::{Hasher, Sha256};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn hash_oneshot(data: &[u8]) -> Vec<u8> {
        Sha256::hash(data).as_bytes().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARCANUM SHA-512 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod arcanum_sha512 {
    use arcanum_hash::{Hasher, Sha512};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().as_bytes().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARCANUM BLAKE3 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod arcanum_blake3 {
    use arcanum_hash::{Blake3, Hasher};

    /// Uses SIMD-optimized one-shot hashing for maximum performance
    pub fn hash(data: &[u8]) -> Vec<u8> {
        Blake3::hash(data).as_bytes().to_vec()
    }

    /// Streaming API for incremental hashing
    pub fn hash_streaming(data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake3::new();
        hasher.update(data);
        hasher.finalize().as_bytes().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECT RUSTCRYPTO SHA-256 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod rustcrypto_sha256 {
    use sha2::{Digest, Sha256};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

mod rustcrypto_sha512 {
    use sha2::{Digest, Sha512};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECT BLAKE3 CRATE BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod blake3_direct {
    pub fn hash(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    pub fn hash_incremental(data: &[u8]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        hasher.finalize().as_bytes().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RING SHA-256 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "bench-ring")]
mod ring_sha256 {
    use ring::digest::{SHA256, digest};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        digest(&SHA256, data).as_ref().to_vec()
    }
}

#[cfg(feature = "bench-ring")]
mod ring_sha512 {
    use ring::digest::{SHA512, digest};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        digest(&SHA512, data).as_ref().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK GROUPS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-256");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        group.bench_with_input(BenchmarkId::new("Arcanum", size), size, |b, _| {
            b.iter(|| arcanum_sha256::hash(black_box(&data)))
        });

        // RustCrypto (direct)
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, _| {
            b.iter(|| rustcrypto_sha256::hash(black_box(&data)))
        });

        // ring
        #[cfg(feature = "bench-ring")]
        group.bench_with_input(BenchmarkId::new("ring", size), size, |b, _| {
            b.iter(|| ring_sha256::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-512");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        group.bench_with_input(BenchmarkId::new("Arcanum", size), size, |b, _| {
            b.iter(|| arcanum_sha512::hash(black_box(&data)))
        });

        // RustCrypto (direct)
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, _| {
            b.iter(|| rustcrypto_sha512::hash(black_box(&data)))
        });

        // ring
        #[cfg(feature = "bench-ring")]
        group.bench_with_input(BenchmarkId::new("ring", size), size, |b, _| {
            b.iter(|| ring_sha512::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLAKE3");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        group.bench_with_input(BenchmarkId::new("Arcanum", size), size, |b, _| {
            b.iter(|| arcanum_blake3::hash(black_box(&data)))
        });

        // blake3 crate (direct)
        group.bench_with_input(BenchmarkId::new("blake3-crate", size), size, |b, _| {
            b.iter(|| blake3_direct::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_algorithm_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("HashComparison/4KB");

    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    // SHA-256
    group.bench_function("Arcanum/SHA-256", |b| {
        b.iter(|| arcanum_sha256::hash(black_box(&data)))
    });

    group.bench_function("RustCrypto/SHA-256", |b| {
        b.iter(|| rustcrypto_sha256::hash(black_box(&data)))
    });

    #[cfg(feature = "bench-ring")]
    group.bench_function("ring/SHA-256", |b| {
        b.iter(|| ring_sha256::hash(black_box(&data)))
    });

    // SHA-512
    group.bench_function("Arcanum/SHA-512", |b| {
        b.iter(|| arcanum_sha512::hash(black_box(&data)))
    });

    group.bench_function("RustCrypto/SHA-512", |b| {
        b.iter(|| rustcrypto_sha512::hash(black_box(&data)))
    });

    #[cfg(feature = "bench-ring")]
    group.bench_function("ring/SHA-512", |b| {
        b.iter(|| ring_sha512::hash(black_box(&data)))
    });

    // BLAKE3
    group.bench_function("Arcanum/BLAKE3", |b| {
        b.iter(|| arcanum_blake3::hash(black_box(&data)))
    });

    group.bench_function("blake3-crate/BLAKE3", |b| {
        b.iter(|| blake3_direct::hash(black_box(&data)))
    });

    group.finish();
}

fn bench_large_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("LargeData/1MB");

    let data = vec![0u8; 1048576]; // 1MB
    group.throughput(Throughput::Bytes(1048576));

    // SHA-256
    group.bench_function("Arcanum/SHA-256", |b| {
        b.iter(|| arcanum_sha256::hash(black_box(&data)))
    });

    group.bench_function("RustCrypto/SHA-256", |b| {
        b.iter(|| rustcrypto_sha256::hash(black_box(&data)))
    });

    // SHA-512 (often faster on 64-bit for large data)
    group.bench_function("Arcanum/SHA-512", |b| {
        b.iter(|| arcanum_sha512::hash(black_box(&data)))
    });

    group.bench_function("RustCrypto/SHA-512", |b| {
        b.iter(|| rustcrypto_sha512::hash(black_box(&data)))
    });

    // BLAKE3 (optimized for large data, uses SIMD)
    group.bench_function("Arcanum/BLAKE3", |b| {
        b.iter(|| arcanum_blake3::hash(black_box(&data)))
    });

    group.bench_function("blake3-crate/BLAKE3", |b| {
        b.iter(|| blake3_direct::hash(black_box(&data)))
    });

    #[cfg(feature = "bench-ring")]
    {
        group.bench_function("ring/SHA-256", |b| {
            b.iter(|| ring_sha256::hash(black_box(&data)))
        });

        group.bench_function("ring/SHA-512", |b| {
            b.iter(|| ring_sha512::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_small_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("SmallData/64B");

    let data = vec![0u8; 64];
    group.throughput(Throughput::Bytes(64));

    // SHA-256
    group.bench_function("Arcanum/SHA-256", |b| {
        b.iter(|| arcanum_sha256::hash(black_box(&data)))
    });

    group.bench_function("RustCrypto/SHA-256", |b| {
        b.iter(|| rustcrypto_sha256::hash(black_box(&data)))
    });

    // BLAKE3
    group.bench_function("Arcanum/BLAKE3", |b| {
        b.iter(|| arcanum_blake3::hash(black_box(&data)))
    });

    group.bench_function("blake3-crate/BLAKE3", |b| {
        b.iter(|| blake3_direct::hash(black_box(&data)))
    });

    #[cfg(feature = "bench-ring")]
    group.bench_function("ring/SHA-256", |b| {
        b.iter(|| ring_sha256::hash(black_box(&data)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_sha512,
    bench_blake3,
    bench_algorithm_comparison,
    bench_large_data,
    bench_small_data,
);
criterion_main!(benches);
