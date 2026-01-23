//! Benchmarks for arcanum-primitives
//!
//! Run with: cargo bench -p arcanum-primitives --features "std,alloc,sha2,blake3,chacha20poly1305"
//!
//! These benchmarks compare native Arcanum implementations against RustCrypto equivalents.

#![allow(
    unused_imports,
    clippy::needless_range_loop,
    clippy::manual_memcpy,
    clippy::get_first
)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use arcanum_primitives::blake3::Blake3;
use arcanum_primitives::chacha20::ChaCha20;
use arcanum_primitives::chacha20poly1305::ChaCha20Poly1305;
use arcanum_primitives::sha2::{Sha256, Sha512};

const SIZES: &[usize] = &[64, 256, 1024, 4096, 16384];

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-256 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-256/Native");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| Sha256::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_sha256_vs_rustcrypto(c: &mut Criterion) {
    use sha2::{Digest, Sha256 as RefSha256};

    let mut group = c.benchmark_group("SHA-256/Comparison");
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native", |b| b.iter(|| Sha256::hash(black_box(&data))));

    group.bench_function("RustCrypto", |b| {
        b.iter(|| RefSha256::digest(black_box(&data)))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-512 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-512/Native");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| Sha512::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_sha512_vs_rustcrypto(c: &mut Criterion) {
    use sha2::{Digest, Sha512 as RefSha512};

    let mut group = c.benchmark_group("SHA-512/Comparison");
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native", |b| b.iter(|| Sha512::hash(black_box(&data))));

    group.bench_function("RustCrypto", |b| {
        b.iter(|| RefSha512::digest(black_box(&data)))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLAKE3 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLAKE3/Native");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| Blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_blake3_vs_rustcrypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLAKE3/Comparison");
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native", |b| b.iter(|| Blake3::hash(black_box(&data))));

    group.bench_function("RustCrypto", |b| b.iter(|| blake3::hash(black_box(&data))));

    group.finish();
}

fn bench_blake3_keyed(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLAKE3-Keyed/Comparison");
    let key = [0x42u8; 32];
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native", |b| {
        b.iter(|| Blake3::keyed_hash(black_box(&key), black_box(&data)))
    });

    group.bench_function("RustCrypto", |b| {
        b.iter(|| blake3::keyed_hash(black_box(&key), black_box(&data)))
    });

    group.finish();
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_parallel(c: &mut Criterion) {
    use arcanum_primitives::blake3_simd::hash_large_parallel;

    // Large sizes where parallel processing provides benefit
    const LARGE_SIZES: &[usize] = &[4096, 16384, 65536, 262144, 1048576];

    let mut group = c.benchmark_group("BLAKE3-Parallel/Native");

    for size in LARGE_SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| hash_large_parallel(black_box(&data)))
        });
    }

    group.finish();
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_parallel_vs_rustcrypto(c: &mut Criterion) {
    use arcanum_primitives::blake3_simd::hash_large_parallel;
    #[cfg(feature = "rayon")]
    use arcanum_primitives::blake3_simd::hash_large_parallel_mt;

    let mut group = c.benchmark_group("BLAKE3-Parallel/Comparison");

    // Test at 1MB where parallel processing should shine
    let size = 1048576;
    let data = vec![0u8; size];
    group.throughput(Throughput::Bytes(size as u64));

    group.bench_function("Native (parallel)", |b| {
        b.iter(|| hash_large_parallel(black_box(&data)))
    });

    #[cfg(feature = "rayon")]
    group.bench_function("Native (multi-threaded)", |b| {
        b.iter(|| hash_large_parallel_mt(black_box(&data)))
    });

    group.bench_function("Native (sequential)", |b| {
        b.iter(|| Blake3::hash(black_box(&data)))
    });

    group.bench_function("RustCrypto", |b| b.iter(|| blake3::hash(black_box(&data))));

    group.finish();
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_turbo(c: &mut Criterion) {
    use arcanum_primitives::blake3_simd::hash_large_parallel;
    use arcanum_primitives::blake3_turbo::hash_turbo;

    let mut group = c.benchmark_group("BLAKE3-Turbo/Comparison");

    // Test at various sizes
    for size in [8 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024] {
        let data = vec![0u8; size];
        let size_label = if size >= 1024 * 1024 {
            format!("{}MB", size / (1024 * 1024))
        } else {
            format!("{}KB", size / 1024)
        };

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("Turbo ({})", size_label), |b| {
            b.iter(|| hash_turbo(black_box(&data)))
        });

        group.bench_function(format!("Native ({})", size_label), |b| {
            b.iter(|| hash_large_parallel(black_box(&data)))
        });

        group.bench_function(format!("RustCrypto ({})", size_label), |b| {
            b.iter(|| blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

#[cfg(all(feature = "simd", feature = "rayon", target_arch = "x86_64"))]
fn bench_blake3_hyper(c: &mut Criterion) {
    use arcanum_primitives::blake3_hyper::hash_hyper;

    let mut group = c.benchmark_group("BLAKE3-Hyper/Comparison");

    // Test at large sizes where multi-threading shines
    for size in [256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let data = vec![0u8; size];
        let size_label = if size >= 1024 * 1024 {
            format!("{}MB", size / (1024 * 1024))
        } else {
            format!("{}KB", size / 1024)
        };

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("Hyper ({})", size_label), |b| {
            b.iter(|| hash_hyper(black_box(&data)))
        });

        group.bench_function(format!("blake3 crate ({})", size_label), |b| {
            b.iter(|| blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_asm(c: &mut Criterion) {
    use arcanum_primitives::blake3_asm::hash_asm;
    use arcanum_primitives::blake3_hyper::hash_hyper;

    let mut group = c.benchmark_group("BLAKE3-ASM/Comparison");

    // Test at large sizes where assembly should show benefit
    for size in [256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let data = vec![0u8; size];
        let size_label = if size >= 1024 * 1024 {
            format!("{}MB", size / (1024 * 1024))
        } else {
            format!("{}KB", size / 1024)
        };

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("ASM ({})", size_label), |b| {
            b.iter(|| hash_asm(black_box(&data)))
        });

        group.bench_function(format!("Hyper ({})", size_label), |b| {
            b.iter(|| hash_hyper(black_box(&data)))
        });

        group.bench_function(format!("blake3 crate ({})", size_label), |b| {
            b.iter(|| blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

#[cfg(all(feature = "simd", feature = "rayon", target_arch = "x86_64"))]
fn bench_blake3_ultra(c: &mut Criterion) {
    use arcanum_primitives::blake3_hyper::hash_hyper;
    use arcanum_primitives::blake3_ultra::{hash_ultra, hash_ultra_streaming};

    let mut group = c.benchmark_group("BLAKE3-Ultra/Comparison");

    // Test at large sizes where novel optimizations should shine
    for size in [256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let data = vec![0u8; size];
        let size_label = if size >= 1024 * 1024 {
            format!("{}MB", size / (1024 * 1024))
        } else {
            format!("{}KB", size / 1024)
        };

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("Ultra ({})", size_label), |b| {
            b.iter(|| hash_ultra(black_box(&data)))
        });

        group.bench_function(format!("Ultra-Streaming ({})", size_label), |b| {
            b.iter(|| hash_ultra_streaming(black_box(&data)))
        });

        group.bench_function(format!("Hyper ({})", size_label), |b| {
            b.iter(|| hash_hyper(black_box(&data)))
        });

        group.bench_function(format!("blake3 crate ({})", size_label), |b| {
            b.iter(|| blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

#[cfg(all(feature = "simd", feature = "rayon", target_arch = "x86_64"))]
fn bench_blake3_adaptive(c: &mut Criterion) {
    use arcanum_primitives::blake3_hyper::hash_hyper;
    use arcanum_primitives::blake3_ultra::{hash_adaptive, hash_minimal_alloc};

    let mut group = c.benchmark_group("BLAKE3-Adaptive/Comparison");

    // Test across all size ranges to verify adaptive picks correctly
    for size in [
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
        16 * 1024 * 1024,
    ] {
        let data = vec![0u8; size];
        let size_label = if size >= 1024 * 1024 {
            format!("{}MB", size / (1024 * 1024))
        } else {
            format!("{}KB", size / 1024)
        };

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("Adaptive ({})", size_label), |b| {
            b.iter(|| hash_adaptive(black_box(&data)))
        });

        group.bench_function(format!("MinimalAlloc ({})", size_label), |b| {
            b.iter(|| hash_minimal_alloc(black_box(&data)))
        });

        group.bench_function(format!("Hyper ({})", size_label), |b| {
            b.iter(|| hash_hyper(black_box(&data)))
        });

        group.bench_function(format!("blake3 crate ({})", size_label), |b| {
            b.iter(|| blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

#[cfg(all(feature = "simd", feature = "rayon", target_arch = "x86_64"))]
fn bench_blake3_apex(c: &mut Criterion) {
    use arcanum_primitives::blake3_ultra::{hash_apex, hash_minimal_alloc};

    let mut group = c.benchmark_group("BLAKE3-Apex/Comparison");

    // Focus on large sizes where apex optimizations should shine
    for size in [4 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024] {
        let data = vec![0u8; size];
        let size_label = format!("{}MB", size / (1024 * 1024));

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("Apex ({})", size_label), |b| {
            b.iter(|| hash_apex(black_box(&data)))
        });

        group.bench_function(format!("MinimalAlloc ({})", size_label), |b| {
            b.iter(|| hash_minimal_alloc(black_box(&data)))
        });

        group.bench_function(format!("blake3 crate ({})", size_label), |b| {
            b.iter(|| blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

/// Benchmark hyper-parallel for small data (Threadripper optimization)
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_hyper_parallel(c: &mut Criterion) {
    use arcanum_primitives::blake3_simd::{hash_hyper_parallel, hash_large_parallel};

    let mut group = c.benchmark_group("BLAKE3-HyperParallel/SmallData");

    // Focus on "small" data where reference crate uses single-thread
    // but Threadripper can still parallelize
    for size in [32 * 1024, 64 * 1024, 128 * 1024, 256 * 1024] {
        let data = vec![0u8; size];
        let size_label = format!("{}KB", size / 1024);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("HyperParallel ({})", size_label), |b| {
            b.iter(|| hash_hyper_parallel(black_box(&data)))
        });

        group.bench_function(format!("Native ({})", size_label), |b| {
            b.iter(|| hash_large_parallel(black_box(&data)))
        });

        group.bench_function(format!("blake3 crate ({})", size_label), |b| {
            b.iter(|| blake3::hash(black_box(&data)))
        });
    }

    group.finish();
}

/// Micro-benchmark: Assembly vs Intrinsics compression function
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_compress_asm_vs_intrinsics(c: &mut Criterion) {
    use arcanum_primitives::blake3_asm::compress_16blocks_asm;
    use arcanum_primitives::blake3_simd::parallel16::compress_16blocks;

    if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512bw") {
        return;
    }

    let mut group = c.benchmark_group("BLAKE3-Compress/ASM-vs-Intrinsics");

    // Create test data
    let cvs: [[u32; 8]; 16] = core::array::from_fn(|i| {
        core::array::from_fn(|j| ((i * 8 + j) as u32).wrapping_mul(0x01010101))
    });
    let blocks: [[u8; 64]; 16] =
        core::array::from_fn(|i| core::array::from_fn(|j| ((i * 64 + j) % 256) as u8));
    let counters: [u64; 16] = core::array::from_fn(|i| i as u64);
    let block_lens = [64u32; 16];
    let flags: [u8; 16] = [0; 16];

    // 16 blocks x 64 bytes = 1024 bytes per call
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("ASM (16 blocks)", |b| {
        b.iter(|| unsafe {
            compress_16blocks_asm(
                black_box(&cvs),
                black_box(&blocks),
                black_box(&counters),
                black_box(&block_lens),
                black_box(&flags),
            )
        })
    });

    group.bench_function("Intrinsics (16 blocks)", |b| {
        b.iter(|| unsafe {
            compress_16blocks(
                black_box(&cvs),
                black_box(&blocks),
                black_box(&counters),
                black_box(&block_lens),
                black_box(&flags),
            )
        })
    });

    group.finish();
}

/// Micro-benchmark: Monolithic vs Per-Round ASM vs Intrinsics
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_monolithic(c: &mut Criterion) {
    use arcanum_primitives::blake3_monolithic::hash_16_chunks_monolithic;
    use arcanum_primitives::blake3_simd::parallel16::hash_16_chunks_asm;

    if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512bw") {
        return;
    }

    let mut group = c.benchmark_group("BLAKE3-Monolithic");

    // Create test data: 16 chunks of 1024 bytes each (16KB total)
    let data: Vec<u8> = (0..16 * 1024).map(|i| (i % 256) as u8).collect();
    let key: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    let counters: [u64; 16] = core::array::from_fn(|i| i as u64);

    // 16 chunks x 1024 bytes = 16KB per call
    group.throughput(Throughput::Bytes(16 * 1024));

    group.bench_function("Monolithic (16 chunks)", |b| {
        b.iter(|| unsafe {
            hash_16_chunks_monolithic(
                black_box(&key),
                black_box(data.as_ptr()),
                black_box(&counters),
                black_box(0),
            )
        })
    });

    group.bench_function("Per-Round ASM (16 chunks)", |b| {
        b.iter(|| unsafe {
            hash_16_chunks_asm(
                black_box(&key),
                black_box(data.as_ptr()),
                black_box(&counters),
                black_box(0),
            )
        })
    });

    group.finish();
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_batch(c: &mut Criterion) {
    use arcanum_primitives::blake3_simd::{hash_batch, hash_batch_8};

    let mut group = c.benchmark_group("BLAKE3-Batch");

    // Test with 256-byte messages (typical small file/block size)
    let msg_size = 256;
    let messages: Vec<Vec<u8>> = (0..8)
        .map(|i| vec![(i as u8).wrapping_mul(0x42); msg_size])
        .collect();
    let msg_refs: [&[u8]; 8] = [
        &messages[0],
        &messages[1],
        &messages[2],
        &messages[3],
        &messages[4],
        &messages[5],
        &messages[6],
        &messages[7],
    ];

    // Total bytes: 8 * 256 = 2048
    group.throughput(Throughput::Bytes((8 * msg_size) as u64));

    group.bench_function("Batch (8x256B)", |b| {
        b.iter(|| hash_batch_8(black_box(&msg_refs)))
    });

    group.bench_function("Sequential (8x256B)", |b| {
        b.iter(|| {
            let mut results = [[0u8; 32]; 8];
            for (i, msg) in msg_refs.iter().enumerate() {
                results[i] = *blake3::hash(black_box(msg)).as_bytes();
            }
            results
        })
    });

    // Test with 64-byte messages (single block, best case for batch)
    let small_msgs: Vec<Vec<u8>> = (0..8)
        .map(|i| vec![(i as u8).wrapping_mul(0x17); 64])
        .collect();
    let small_refs: [&[u8]; 8] = [
        &small_msgs[0],
        &small_msgs[1],
        &small_msgs[2],
        &small_msgs[3],
        &small_msgs[4],
        &small_msgs[5],
        &small_msgs[6],
        &small_msgs[7],
    ];

    group.throughput(Throughput::Bytes((8 * 64) as u64));

    group.bench_function("Batch (8x64B)", |b| {
        b.iter(|| hash_batch_8(black_box(&small_refs)))
    });

    group.bench_function("Sequential (8x64B)", |b| {
        b.iter(|| {
            let mut results = [[0u8; 32]; 8];
            for (i, msg) in small_refs.iter().enumerate() {
                results[i] = *blake3::hash(black_box(msg)).as_bytes();
            }
            results
        })
    });

    group.finish();
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
fn bench_blake3_avx512(c: &mut Criterion) {
    use arcanum_primitives::blake3_simd::{
        has_avx512f, hash_16_chunks_parallel, hash_8_chunks_parallel, IV,
    };

    let mut group = c.benchmark_group("BLAKE3-AVX512");

    // Create 16 unique 1024-byte chunks
    let mut chunks16 = [[0u8; 1024]; 16];
    for i in 0..16 {
        for j in 0..1024 {
            chunks16[i][j] = ((i * 1024 + j) % 256) as u8;
        }
    }
    let counters16: [u64; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    // Create 8-chunk version for comparison
    let mut chunks8 = [[0u8; 1024]; 8];
    for i in 0..8 {
        chunks8[i] = chunks16[i];
    }
    let counters8: [u64; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    // 16KB for 16 chunks
    group.throughput(Throughput::Bytes((16 * 1024) as u64));

    // Print AVX-512 detection
    if has_avx512f() {
        println!("AVX-512 detected - using native 16-way path");
    } else {
        println!("AVX-512 not detected - using 2x 8-way fallback");
    }

    group.bench_function("16-way parallel (16KB)", |b| {
        b.iter(|| {
            hash_16_chunks_parallel(
                black_box(&IV),
                black_box(&chunks16),
                black_box(&counters16),
                0,
            )
        })
    });

    // 8KB for 8 chunks
    group.throughput(Throughput::Bytes((8 * 1024) as u64));

    group.bench_function("8-way parallel (8KB)", |b| {
        b.iter(|| {
            hash_8_chunks_parallel(
                black_box(&IV),
                black_box(&chunks8),
                black_box(&counters8),
                0,
            )
        })
    });

    // Compare 2x 8-way vs 1x 16-way (both processing 16 chunks)
    group.throughput(Throughput::Bytes((16 * 1024) as u64));

    group.bench_function("2x 8-way parallel (16KB)", |b| {
        b.iter(|| {
            let cv1 = hash_8_chunks_parallel(
                black_box(&IV),
                black_box(&chunks8),
                black_box(&counters8),
                0,
            );
            let mut chunks8_2 = [[0u8; 1024]; 8];
            for i in 0..8 {
                chunks8_2[i] = chunks16[i + 8];
            }
            let counters8_2: [u64; 8] = [8, 9, 10, 11, 12, 13, 14, 15];
            let cv2 = hash_8_chunks_parallel(
                black_box(&IV),
                black_box(&chunks8_2),
                black_box(&counters8_2),
                0,
            );
            (cv1, cv2)
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHACHA20 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_chacha20(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20/Native");
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];

    for size in SIZES {
        let mut data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let mut cipher = ChaCha20::new(&key, &nonce);
                cipher.apply_keystream(black_box(&mut data));
            })
        });
    }

    group.finish();
}

fn bench_chacha20_vs_rustcrypto(c: &mut Criterion) {
    use chacha20::ChaCha20 as RefChaCha20;
    use cipher::{KeyIvInit, StreamCipher};

    let mut group = c.benchmark_group("ChaCha20/Comparison");
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];
    let mut data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native", |b| {
        b.iter(|| {
            let mut cipher = ChaCha20::new(&key, &nonce);
            cipher.apply_keystream(black_box(&mut data));
        })
    });

    group.bench_function("RustCrypto", |b| {
        b.iter(|| {
            let mut cipher = RefChaCha20::new(&key.into(), &nonce.into());
            cipher.apply_keystream(black_box(&mut data));
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHACHA20-POLY1305 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_chacha20poly1305_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20-Poly1305-Seal/Native");
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];
    let aad = b"associated data";

    for size in SIZES {
        let plaintext = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let cipher = ChaCha20Poly1305::new(&key);
            b.iter(|| cipher.seal(black_box(&nonce), black_box(aad), black_box(&plaintext)))
        });
    }

    group.finish();
}

fn bench_chacha20poly1305_vs_rustcrypto(c: &mut Criterion) {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305 as RefChaCha20Poly1305, KeyInit, Nonce};

    let mut group = c.benchmark_group("ChaCha20-Poly1305/Comparison");
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];
    let aad = b"associated data";
    let plaintext = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native (encrypt)", |b| {
        let cipher = ChaCha20Poly1305::new(&key);
        b.iter(|| cipher.seal(black_box(&nonce), black_box(aad), black_box(&plaintext)))
    });

    group.bench_function("RustCrypto (encrypt)", |b| {
        let cipher = RefChaCha20Poly1305::new(&key.into());
        let nonce_ref = Nonce::from_slice(&nonce);
        b.iter(|| {
            cipher.encrypt(
                black_box(nonce_ref),
                chacha20poly1305::aead::Payload {
                    msg: black_box(&plaintext),
                    aad: black_box(aad),
                },
            )
        })
    });

    // Also benchmark decryption
    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher.seal(&nonce, aad, &plaintext);

    group.bench_function("Native (decrypt)", |b| {
        let cipher = ChaCha20Poly1305::new(&key);
        b.iter(|| cipher.open(black_box(&nonce), black_box(aad), black_box(&ciphertext)))
    });

    group.bench_function("RustCrypto (decrypt)", |b| {
        let cipher = RefChaCha20Poly1305::new(&key.into());
        let nonce_ref = Nonce::from_slice(&nonce);
        b.iter(|| {
            cipher.decrypt(
                black_box(nonce_ref),
                chacha20poly1305::aead::Payload {
                    msg: black_box(&ciphertext),
                    aad: black_box(aad),
                },
            )
        })
    });

    group.finish();
}

fn bench_chacha20poly1305_in_place(c: &mut Criterion) {
    use chacha20poly1305::{
        aead::AeadInPlace, ChaCha20Poly1305 as RefChaCha20Poly1305, KeyInit, Nonce,
    };

    let mut group = c.benchmark_group("ChaCha20-Poly1305-InPlace/Comparison");
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];
    let aad = b"associated data";
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native", |b| {
        let cipher = ChaCha20Poly1305::new(&key);
        b.iter(|| {
            let mut buffer = vec![0u8; 4096];
            let _tag = cipher.encrypt(black_box(&nonce), black_box(aad), black_box(&mut buffer));
        })
    });

    group.bench_function("RustCrypto", |b| {
        let cipher = RefChaCha20Poly1305::new(&key.into());
        let nonce_ref = Nonce::from_slice(&nonce);
        b.iter(|| {
            let mut buffer = vec![0u8; 4096];
            let _ = cipher.encrypt_in_place(
                black_box(nonce_ref),
                black_box(aad),
                black_box(&mut buffer),
            );
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// POLY1305 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_poly1305(c: &mut Criterion) {
    use arcanum_primitives::poly1305::Poly1305;
    use poly1305::universal_hash::{KeyInit, UniversalHash};
    use poly1305::Poly1305 as RefPoly1305;

    let mut group = c.benchmark_group("Poly1305/Comparison");
    let key = [0x42u8; 32];
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native", |b| {
        b.iter(|| Poly1305::mac(black_box(&key), black_box(&data)))
    });

    group.bench_function("RustCrypto", |b| {
        b.iter(|| {
            let mut mac = RefPoly1305::new(&key.into());
            mac.update_padded(black_box(&data));
            mac.finalize()
        })
    });

    group.finish();
}

#[cfg(feature = "simd")]
fn bench_poly1305_simd(c: &mut Criterion) {
    use arcanum_primitives::poly1305::Poly1305;
    use arcanum_primitives::poly1305_simd::Poly1305Simd;
    use poly1305::universal_hash::{KeyInit, UniversalHash};
    use poly1305::Poly1305 as RefPoly1305;

    let mut group = c.benchmark_group("Poly1305-SIMD/Comparison");
    let key = [0x42u8; 32];
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("Native (scalar)", |b| {
        b.iter(|| Poly1305::mac(black_box(&key), black_box(&data)))
    });

    group.bench_function("Native (SIMD)", |b| {
        b.iter(|| Poly1305Simd::mac(black_box(&key), black_box(&data)))
    });

    group.bench_function("RustCrypto", |b| {
        b.iter(|| {
            let mut mac = RefPoly1305::new(&key.into());
            mac.update_padded(black_box(&data));
            mac.finalize()
        })
    });

    group.finish();
}

#[cfg(feature = "simd")]
fn bench_poly1305_simd_various_sizes(c: &mut Criterion) {
    use arcanum_primitives::poly1305_simd::Poly1305Simd;

    let mut group = c.benchmark_group("Poly1305-SIMD/Native");
    let key = [0x42u8; 32];

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| Poly1305Simd::mac(black_box(&key), black_box(&data)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// LARGE-SCALE CHACHA20-POLY1305 BENCHMARKS (Scaling Analysis)
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_chacha20poly1305_large_scale(c: &mut Criterion) {
    use arcanum_primitives::fused::FusedChaCha20Poly1305;

    let mut group = c.benchmark_group("ChaCha20-Poly1305-LargeScale");
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];
    let aad = b"associated data";

    // Test at large sizes: 256KB, 1MB, 4MB
    for size in [262144, 1048576, 4194304] {
        let plaintext = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        let size_label = match size {
            262144 => "256KB",
            1048576 => "1MB",
            4194304 => "4MB",
            _ => "unknown",
        };

        // Native Standard implementation
        group.bench_function(format!("Native ({})", size_label), |b| {
            let cipher = ChaCha20Poly1305::new(&key);
            b.iter(|| {
                let mut buffer = plaintext.clone();
                cipher.encrypt(black_box(&nonce), black_box(aad), black_box(&mut buffer))
            })
        });

        // Fused implementation
        group.bench_function(format!("Fused ({})", size_label), |b| {
            let cipher = FusedChaCha20Poly1305::new(&key);
            b.iter(|| {
                let mut buffer = plaintext.clone();
                cipher.encrypt(black_box(&nonce), black_box(aad), black_box(&mut buffer))
            })
        });

        // RustCrypto for reference
        group.bench_function(format!("RustCrypto ({})", size_label), |b| {
            use chacha20poly1305::{
                aead::AeadInPlace, ChaCha20Poly1305 as RefChaCha20Poly1305, KeyInit, Nonce,
            };
            let cipher = RefChaCha20Poly1305::new(&key.into());
            let nonce_ref = Nonce::from_slice(&nonce);
            b.iter(|| {
                let mut buffer = plaintext.clone();
                cipher.encrypt_in_place(
                    black_box(nonce_ref),
                    black_box(aad),
                    black_box(&mut buffer),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    // SHA-256
    bench_sha256,
    bench_sha256_vs_rustcrypto,
    // SHA-512
    bench_sha512,
    bench_sha512_vs_rustcrypto,
    // BLAKE3
    bench_blake3,
    bench_blake3_vs_rustcrypto,
    bench_blake3_keyed,
    bench_blake3_turbo,
    bench_blake3_hyper,
    // ChaCha20
    bench_chacha20,
    bench_chacha20_vs_rustcrypto,
    // ChaCha20-Poly1305
    bench_chacha20poly1305_seal,
    bench_chacha20poly1305_vs_rustcrypto,
    bench_chacha20poly1305_in_place,
    // Poly1305
    bench_poly1305,
    // Novel operations
    bench_batch_sha256,
    bench_fused_chacha20poly1305,
    bench_merkle_tree,
    // Large-scale scaling analysis
    bench_chacha20poly1305_large_scale,
);

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH SHA-256 BENCHMARKS (Novel Arcanum API)
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_batch_sha256(c: &mut Criterion) {
    use arcanum_primitives::batch::BatchSha256x4;

    let mut group = c.benchmark_group("SHA-256-Batch/Novel");

    // Test with various message sizes
    for msg_size in [64, 256, 1024, 4096] {
        let messages: Vec<Vec<u8>> = (0..4)
            .map(|i| vec![(i as u8).wrapping_mul(0x42); msg_size])
            .collect();
        let msg_refs: [&[u8]; 4] = [&messages[0], &messages[1], &messages[2], &messages[3]];

        // Total bytes: 4 * msg_size
        let total_bytes = 4 * msg_size;
        group.throughput(Throughput::Bytes(total_bytes as u64));

        // Batch (4x parallel)
        group.bench_function(format!("Batch-4x ({}B)", msg_size), |b| {
            b.iter(|| BatchSha256x4::hash_parallel(black_box(msg_refs)))
        });

        // Sequential for comparison
        group.bench_function(format!("Sequential-4x ({}B)", msg_size), |b| {
            b.iter(|| {
                let mut results = [[0u8; 32]; 4];
                for (i, msg) in msg_refs.iter().enumerate() {
                    results[i] = Sha256::hash(black_box(msg));
                }
                results
            })
        });

        // RustCrypto sequential
        group.bench_function(format!("RustCrypto-4x ({}B)", msg_size), |b| {
            use sha2::{Digest, Sha256 as RefSha256};
            b.iter(|| {
                let mut results = [[0u8; 32]; 4];
                for (i, msg) in msg_refs.iter().enumerate() {
                    results[i] = RefSha256::digest(black_box(msg)).into();
                }
                results
            })
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// FUSED CHACHA20-POLY1305 BENCHMARKS (Novel Arcanum API)
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_fused_chacha20poly1305(c: &mut Criterion) {
    use arcanum_primitives::fused::FusedChaCha20Poly1305;

    let mut group = c.benchmark_group("ChaCha20-Poly1305-Fused/Novel");
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 12];
    let aad = b"associated data";

    // Test at various sizes where fused should show benefit
    for size in [1024, 4096, 16384, 65536] {
        let plaintext = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Fused implementation
        group.bench_function(format!("Fused ({}B)", size), |b| {
            let cipher = FusedChaCha20Poly1305::new(&key);
            b.iter(|| {
                let mut buffer = plaintext.clone();
                cipher.encrypt(black_box(&nonce), black_box(aad), black_box(&mut buffer))
            })
        });

        // Standard implementation
        group.bench_function(format!("Standard ({}B)", size), |b| {
            let cipher = ChaCha20Poly1305::new(&key);
            b.iter(|| {
                let mut buffer = plaintext.clone();
                cipher.encrypt(black_box(&nonce), black_box(aad), black_box(&mut buffer))
            })
        });

        // RustCrypto for reference
        group.bench_function(format!("RustCrypto ({}B)", size), |b| {
            use chacha20poly1305::{
                aead::AeadInPlace, ChaCha20Poly1305 as RefChaCha20Poly1305, KeyInit, Nonce,
            };
            let cipher = RefChaCha20Poly1305::new(&key.into());
            let nonce_ref = Nonce::from_slice(&nonce);
            b.iter(|| {
                let mut buffer = plaintext.clone();
                cipher.encrypt_in_place(
                    black_box(nonce_ref),
                    black_box(aad),
                    black_box(&mut buffer),
                )
            })
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// MERKLE TREE BENCHMARKS (Novel Arcanum API)
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_merkle_tree(c: &mut Criterion) {
    use arcanum_primitives::batch::merkle_root_sha256;

    let mut group = c.benchmark_group("Merkle-Tree/Novel");

    // Test with various tree sizes
    for leaf_count in [4, 16, 64, 256, 1024] {
        // Pre-compute leaves (simulating a file chunked into 32-byte hashes)
        let leaves: Vec<[u8; 32]> = (0..leaf_count)
            .map(|i| Sha256::hash(&(i as u32).to_le_bytes()))
            .collect();

        // Total hashes to compute (rough estimate)
        let hash_ops = leaf_count; // Approximately n-1 internal nodes for n leaves
        group.throughput(Throughput::Elements(hash_ops as u64));

        // Batch Merkle root (uses 4-way parallel hashing internally)
        group.bench_function(format!("Batch ({} leaves)", leaf_count), |b| {
            b.iter(|| merkle_root_sha256(black_box(&leaves)))
        });

        // Sequential Merkle root for comparison
        group.bench_function(format!("Sequential ({} leaves)", leaf_count), |b| {
            b.iter(|| {
                let mut current = leaves.clone();
                if current.len() % 2 == 1 {
                    current.push(*current.last().unwrap());
                }
                while current.len() > 1 {
                    let mut next = Vec::with_capacity(current.len() / 2);
                    for pair in current.chunks(2) {
                        let mut concat = [0u8; 64];
                        concat[..32].copy_from_slice(&pair[0]);
                        concat[32..].copy_from_slice(&pair[1]);
                        next.push(Sha256::hash(&concat));
                    }
                    if next.len() > 1 && next.len() % 2 == 1 {
                        next.push(*next.last().unwrap());
                    }
                    current = next;
                }
                current.get(0).copied().unwrap_or([0u8; 32])
            })
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUDA BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "cuda")]
fn bench_cuda_blake3_batch(c: &mut Criterion) {
    use arcanum_primitives::blake3_cuda_ffi::CudaHasher;

    // Try to initialize CUDA hasher
    let mut hasher = match CudaHasher::new(64 * 1024 * 1024, 100_000) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("CUDA benchmark skipped: {}", e);
            return;
        }
    };

    let mut group = c.benchmark_group("BLAKE3-CUDA");

    // Test with various batch sizes
    for (num_messages, msg_size) in [(1000, 256), (1000, 1024), (10000, 256), (10000, 1024)] {
        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|i| vec![(i % 256) as u8; msg_size])
            .collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        let total_bytes = num_messages * msg_size;
        group.throughput(Throughput::Bytes(total_bytes as u64));

        let label = format!("{}x{}B", num_messages, msg_size);

        group.bench_function(format!("CUDA ({})", label), |b| {
            b.iter(|| hasher.hash_batch(black_box(&msg_refs)))
        });

        // Compare with sequential CPU
        group.bench_function(format!("CPU-Sequential ({})", label), |b| {
            b.iter(|| {
                let mut results = Vec::with_capacity(num_messages);
                for msg in &msg_refs {
                    results.push(*blake3::hash(black_box(msg)).as_bytes());
                }
                results
            })
        });
    }

    group.finish();
}

#[cfg(feature = "cuda")]
fn bench_cuda_blake3_small_batch(c: &mut Criterion) {
    use arcanum_primitives::blake3_cuda_ffi::CudaHasher;

    let mut hasher = match CudaHasher::new(64 * 1024 * 1024, 100_000) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("CUDA small batch benchmark skipped: {}", e);
            return;
        }
    };

    let mut group = c.benchmark_group("BLAKE3-CUDA-SmallBatch");

    // Fixed-size small message batches (optimized CUDA path)
    for (num_messages, msg_size) in [(10000, 64), (10000, 256), (10000, 512), (10000, 1024)] {
        let messages: Vec<u8> = (0..num_messages * msg_size)
            .map(|i| (i % 256) as u8)
            .collect();

        let total_bytes = num_messages * msg_size;
        group.throughput(Throughput::Bytes(total_bytes as u64));

        let label = format!("{}x{}B", num_messages, msg_size);

        group.bench_function(format!("CUDA-Optimized ({})", label), |b| {
            b.iter(|| {
                hasher.hash_small_batch(black_box(&messages), msg_size as u32, num_messages as u32)
            })
        });
    }

    group.finish();
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
criterion_group!(
    benches_simd,
    bench_poly1305_simd,
    bench_poly1305_simd_various_sizes,
    bench_blake3_parallel,
    bench_blake3_parallel_vs_rustcrypto,
    bench_blake3_batch,
    bench_blake3_avx512,
    bench_blake3_asm,
    bench_blake3_ultra,
    bench_blake3_adaptive,
    bench_blake3_apex,
    bench_blake3_hyper_parallel,
    bench_blake3_compress_asm_vs_intrinsics,
    bench_blake3_monolithic,
);

#[cfg(all(feature = "simd", not(target_arch = "x86_64")))]
criterion_group!(
    benches_simd,
    bench_poly1305_simd,
    bench_poly1305_simd_various_sizes,
);

#[cfg(feature = "cuda")]
criterion_group!(
    benches_cuda,
    bench_cuda_blake3_batch,
    bench_cuda_blake3_small_batch,
);

// Main entry points based on feature combinations
#[cfg(all(feature = "simd", feature = "cuda"))]
criterion_main!(benches, benches_simd, benches_cuda);

#[cfg(all(feature = "simd", not(feature = "cuda")))]
criterion_main!(benches, benches_simd);

#[cfg(all(not(feature = "simd"), feature = "cuda"))]
criterion_main!(benches, benches_cuda);

#[cfg(all(not(feature = "simd"), not(feature = "cuda")))]
criterion_main!(benches);
