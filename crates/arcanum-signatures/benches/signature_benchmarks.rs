//! Comprehensive benchmarks for digital signature algorithms.
//!
//! Compares Arcanum implementations against peer libraries:
//! - RustCrypto (direct backend via ed25519-dalek)
//! - ring (BoringSSL wrapper)

#![allow(clippy::redundant_closure)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

// Message sizes for benchmarking
const SIZES: &[usize] = &[32, 256, 1024, 4096, 16384];

// Batch sizes for batch verification benchmarks
const BATCH_SIZES: &[usize] = &[2, 4, 8, 16, 32, 64, 128];

// ═══════════════════════════════════════════════════════════════════════════════
// ARCANUM ED25519 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod arcanum_ed25519 {
    use arcanum_signatures::ed25519::Ed25519BatchVerifier;
    use arcanum_signatures::{BatchVerifier, SigningKey, VerifyingKey};
    use arcanum_signatures::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};

    pub fn keygen() -> (Ed25519SigningKey, Ed25519VerifyingKey) {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8]) -> Ed25519Signature {
        signing_key.sign(message)
    }

    pub fn verify(
        verifying_key: &Ed25519VerifyingKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> bool {
        verifying_key.verify(message, signature).is_ok()
    }

    /// Batch verification using ed25519-dalek's optimized batch verify.
    pub fn verify_batch(items: &[(&Ed25519VerifyingKey, &[u8], &Ed25519Signature)]) -> bool {
        Ed25519BatchVerifier::verify_batch(items).is_ok()
    }

    /// Sequential verification (baseline for comparison).
    pub fn verify_sequential(items: &[(&Ed25519VerifyingKey, &[u8], &Ed25519Signature)]) -> bool {
        for (key, message, signature) in items {
            if key.verify(message, signature).is_err() {
                return false;
            }
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARCANUM ECDSA-P256 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod arcanum_p256 {
    use arcanum_signatures::{P256Signature, P256SigningKey, P256VerifyingKey};
    use arcanum_signatures::{SigningKey, VerifyingKey};

    pub fn keygen() -> (P256SigningKey, P256VerifyingKey) {
        let signing_key = P256SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    pub fn sign(signing_key: &P256SigningKey, message: &[u8]) -> P256Signature {
        signing_key.sign(message)
    }

    pub fn verify(
        verifying_key: &P256VerifyingKey,
        message: &[u8],
        signature: &P256Signature,
    ) -> bool {
        verifying_key.verify(message, signature).is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECT RUSTCRYPTO ED25519 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod rustcrypto_ed25519 {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use rand::rngs::OsRng;

    pub fn keygen() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
        signing_key.sign(message)
    }

    pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        verifying_key.verify(message, signature).is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECT RUSTCRYPTO P256 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod rustcrypto_p256 {
    use p256::ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    };
    use rand_core::OsRng;

    pub fn keygen() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
        signing_key.sign(message)
    }

    pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        verifying_key.verify(message, signature).is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RING ED25519 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "bench-ring")]
mod ring_ed25519 {
    use ring::rand::SystemRandom;
    use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

    pub struct RingKeyPair {
        keypair: Ed25519KeyPair,
        public_key_bytes: Vec<u8>,
    }

    pub fn keygen() -> RingKeyPair {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let public_key_bytes = keypair.public_key().as_ref().to_vec();
        RingKeyPair {
            keypair,
            public_key_bytes,
        }
    }

    pub fn sign(keypair: &RingKeyPair, message: &[u8]) -> Vec<u8> {
        keypair.keypair.sign(message).as_ref().to_vec()
    }

    pub fn verify(keypair: &RingKeyPair, message: &[u8], signature: &[u8]) -> bool {
        let public_key = UnparsedPublicKey::new(&ED25519, &keypair.public_key_bytes);
        public_key.verify(message, signature).is_ok()
    }
}

#[cfg(feature = "bench-ring")]
mod ring_p256 {
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
        UnparsedPublicKey,
    };

    pub struct RingP256KeyPair {
        keypair: EcdsaKeyPair,
        public_key_bytes: Vec<u8>,
    }

    pub fn keygen() -> RingP256KeyPair {
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = keypair.public_key().as_ref().to_vec();
        RingP256KeyPair {
            keypair,
            public_key_bytes,
        }
    }

    pub fn sign(keypair: &RingP256KeyPair, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        keypair
            .keypair
            .sign(&rng, message)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    pub fn verify(keypair: &RingP256KeyPair, message: &[u8], signature: &[u8]) -> bool {
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &keypair.public_key_bytes);
        public_key.verify(message, signature).is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK GROUPS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_ed25519_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519/KeyGeneration");

    group.bench_function("Arcanum", |b| b.iter(|| arcanum_ed25519::keygen()));

    group.bench_function("RustCrypto", |b| b.iter(|| rustcrypto_ed25519::keygen()));

    #[cfg(feature = "bench-ring")]
    group.bench_function("ring", |b| b.iter(|| ring_ed25519::keygen()));

    group.finish();
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519/Sign");

    for size in SIZES {
        let message = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        let (signing_key, _) = arcanum_ed25519::keygen();
        group.bench_with_input(BenchmarkId::new("Arcanum", size), size, |b, _| {
            b.iter(|| arcanum_ed25519::sign(black_box(&signing_key), black_box(&message)))
        });

        // RustCrypto
        let (rc_signing_key, _) = rustcrypto_ed25519::keygen();
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, _| {
            b.iter(|| rustcrypto_ed25519::sign(black_box(&rc_signing_key), black_box(&message)))
        });

        // ring
        #[cfg(feature = "bench-ring")]
        {
            let ring_keypair = ring_ed25519::keygen();
            group.bench_with_input(BenchmarkId::new("ring", size), size, |b, _| {
                b.iter(|| ring_ed25519::sign(black_box(&ring_keypair), black_box(&message)))
            });
        }
    }

    group.finish();
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519/Verify");

    for size in SIZES {
        let message = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        let (signing_key, verifying_key) = arcanum_ed25519::keygen();
        let signature = arcanum_ed25519::sign(&signing_key, &message);
        group.bench_with_input(BenchmarkId::new("Arcanum", size), size, |b, _| {
            b.iter(|| {
                arcanum_ed25519::verify(
                    black_box(&verifying_key),
                    black_box(&message),
                    black_box(&signature),
                )
            })
        });

        // RustCrypto
        let (rc_signing_key, rc_verifying_key) = rustcrypto_ed25519::keygen();
        let rc_signature = rustcrypto_ed25519::sign(&rc_signing_key, &message);
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, _| {
            b.iter(|| {
                rustcrypto_ed25519::verify(
                    black_box(&rc_verifying_key),
                    black_box(&message),
                    black_box(&rc_signature),
                )
            })
        });

        // ring
        #[cfg(feature = "bench-ring")]
        {
            let ring_keypair = ring_ed25519::keygen();
            let ring_signature = ring_ed25519::sign(&ring_keypair, &message);
            group.bench_with_input(BenchmarkId::new("ring", size), size, |b, _| {
                b.iter(|| {
                    ring_ed25519::verify(
                        black_box(&ring_keypair),
                        black_box(&message),
                        black_box(&ring_signature),
                    )
                })
            });
        }
    }

    group.finish();
}

fn bench_p256_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA-P256/KeyGeneration");

    group.bench_function("Arcanum", |b| b.iter(|| arcanum_p256::keygen()));

    group.bench_function("RustCrypto", |b| b.iter(|| rustcrypto_p256::keygen()));

    #[cfg(feature = "bench-ring")]
    group.bench_function("ring", |b| b.iter(|| ring_p256::keygen()));

    group.finish();
}

fn bench_p256_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA-P256/Sign");

    for size in SIZES {
        let message = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        let (signing_key, _) = arcanum_p256::keygen();
        group.bench_with_input(BenchmarkId::new("Arcanum", size), size, |b, _| {
            b.iter(|| arcanum_p256::sign(black_box(&signing_key), black_box(&message)))
        });

        // RustCrypto
        let (rc_signing_key, _) = rustcrypto_p256::keygen();
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, _| {
            b.iter(|| rustcrypto_p256::sign(black_box(&rc_signing_key), black_box(&message)))
        });

        // ring
        #[cfg(feature = "bench-ring")]
        {
            let ring_keypair = ring_p256::keygen();
            group.bench_with_input(BenchmarkId::new("ring", size), size, |b, _| {
                b.iter(|| ring_p256::sign(black_box(&ring_keypair), black_box(&message)))
            });
        }
    }

    group.finish();
}

fn bench_p256_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA-P256/Verify");

    for size in SIZES {
        let message = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        let (signing_key, verifying_key) = arcanum_p256::keygen();
        let signature = arcanum_p256::sign(&signing_key, &message);
        group.bench_with_input(BenchmarkId::new("Arcanum", size), size, |b, _| {
            b.iter(|| {
                arcanum_p256::verify(
                    black_box(&verifying_key),
                    black_box(&message),
                    black_box(&signature),
                )
            })
        });

        // RustCrypto
        let (rc_signing_key, rc_verifying_key) = rustcrypto_p256::keygen();
        let rc_signature = rustcrypto_p256::sign(&rc_signing_key, &message);
        group.bench_with_input(BenchmarkId::new("RustCrypto", size), size, |b, _| {
            b.iter(|| {
                rustcrypto_p256::verify(
                    black_box(&rc_verifying_key),
                    black_box(&message),
                    black_box(&rc_signature),
                )
            })
        });

        // ring
        #[cfg(feature = "bench-ring")]
        {
            let ring_keypair = ring_p256::keygen();
            let ring_signature = ring_p256::sign(&ring_keypair, &message);
            group.bench_with_input(BenchmarkId::new("ring", size), size, |b, _| {
                b.iter(|| {
                    ring_p256::verify(
                        black_box(&ring_keypair),
                        black_box(&message),
                        black_box(&ring_signature),
                    )
                })
            });
        }
    }

    group.finish();
}

fn bench_algorithm_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("SignatureComparison/256B");

    let message = vec![0u8; 256];
    group.throughput(Throughput::Bytes(256));

    // Ed25519
    let (ed_signing_key, _) = arcanum_ed25519::keygen();
    group.bench_function("Arcanum/Ed25519", |b| {
        b.iter(|| arcanum_ed25519::sign(black_box(&ed_signing_key), black_box(&message)))
    });

    // ECDSA-P256
    let (p256_signing_key, _) = arcanum_p256::keygen();
    group.bench_function("Arcanum/ECDSA-P256", |b| {
        b.iter(|| arcanum_p256::sign(black_box(&p256_signing_key), black_box(&message)))
    });

    // RustCrypto Ed25519
    let (rc_ed_signing_key, _) = rustcrypto_ed25519::keygen();
    group.bench_function("RustCrypto/Ed25519", |b| {
        b.iter(|| rustcrypto_ed25519::sign(black_box(&rc_ed_signing_key), black_box(&message)))
    });

    // RustCrypto P256
    let (rc_p256_signing_key, _) = rustcrypto_p256::keygen();
    group.bench_function("RustCrypto/ECDSA-P256", |b| {
        b.iter(|| rustcrypto_p256::sign(black_box(&rc_p256_signing_key), black_box(&message)))
    });

    #[cfg(feature = "bench-ring")]
    {
        let ring_ed_keypair = ring_ed25519::keygen();
        group.bench_function("ring/Ed25519", |b| {
            b.iter(|| ring_ed25519::sign(black_box(&ring_ed_keypair), black_box(&message)))
        });

        let ring_p256_keypair = ring_p256::keygen();
        group.bench_function("ring/ECDSA-P256", |b| {
            b.iter(|| ring_p256::sign(black_box(&ring_p256_keypair), black_box(&message)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH VERIFICATION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

/// Benchmark batch verification vs sequential verification for different batch sizes.
fn bench_ed25519_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519/BatchVerify");

    for &batch_size in BATCH_SIZES {
        // Generate unique keypairs, messages, and signatures for each item in batch
        let items: Vec<_> = (0..batch_size)
            .map(|i| {
                let (signing_key, verifying_key) = arcanum_ed25519::keygen();
                let message = format!("message_{}", i).into_bytes();
                let signature = arcanum_ed25519::sign(&signing_key, &message);
                (verifying_key, message, signature)
            })
            .collect();

        // Prepare references for the batch API
        let refs: Vec<_> = items
            .iter()
            .map(|(vk, msg, sig)| (vk, msg.as_slice(), sig))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        // Batch verification (optimized)
        group.bench_with_input(
            BenchmarkId::new("Batch", batch_size),
            &batch_size,
            |b, _| b.iter(|| arcanum_ed25519::verify_batch(black_box(&refs))),
        );

        // Sequential verification (baseline)
        group.bench_with_input(
            BenchmarkId::new("Sequential", batch_size),
            &batch_size,
            |b, _| b.iter(|| arcanum_ed25519::verify_sequential(black_box(&refs))),
        );
    }

    group.finish();
}

/// Benchmark batch verification with same key (common use case: many messages, one signer).
fn bench_ed25519_batch_same_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519/BatchVerify/SameKey");

    for &batch_size in BATCH_SIZES {
        // Single keypair signing multiple messages
        let (signing_key, verifying_key) = arcanum_ed25519::keygen();
        let items: Vec<_> = (0..batch_size)
            .map(|i| {
                let message = format!("message_{}", i).into_bytes();
                let signature = arcanum_ed25519::sign(&signing_key, &message);
                (message, signature)
            })
            .collect();

        // Prepare references with same verifying key for all
        let refs: Vec<_> = items
            .iter()
            .map(|(msg, sig)| (&verifying_key, msg.as_slice(), sig))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        // Batch verification
        group.bench_with_input(
            BenchmarkId::new("Batch", batch_size),
            &batch_size,
            |b, _| b.iter(|| arcanum_ed25519::verify_batch(black_box(&refs))),
        );

        // Sequential verification
        group.bench_with_input(
            BenchmarkId::new("Sequential", batch_size),
            &batch_size,
            |b, _| b.iter(|| arcanum_ed25519::verify_sequential(black_box(&refs))),
        );
    }

    group.finish();
}

/// Benchmark batch verification with large messages.
fn bench_ed25519_batch_large_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519/BatchVerify/LargeMessages");

    // Use fixed batch size with varying message sizes
    const BATCH: usize = 32;
    const MESSAGE_SIZES: &[usize] = &[256, 1024, 4096];

    for &msg_size in MESSAGE_SIZES {
        let items: Vec<_> = (0..BATCH)
            .map(|_| {
                let (signing_key, verifying_key) = arcanum_ed25519::keygen();
                let message = vec![0xab_u8; msg_size];
                let signature = arcanum_ed25519::sign(&signing_key, &message);
                (verifying_key, message, signature)
            })
            .collect();

        let refs: Vec<_> = items
            .iter()
            .map(|(vk, msg, sig)| (vk, msg.as_slice(), sig))
            .collect();

        group.throughput(Throughput::Bytes((BATCH * msg_size) as u64));

        group.bench_with_input(BenchmarkId::new("Batch", msg_size), &msg_size, |b, _| {
            b.iter(|| arcanum_ed25519::verify_batch(black_box(&refs)))
        });

        group.bench_with_input(
            BenchmarkId::new("Sequential", msg_size),
            &msg_size,
            |b, _| b.iter(|| arcanum_ed25519::verify_sequential(black_box(&refs))),
        );
    }

    group.finish();
}

/// Throughput benchmark: signatures verified per second.
fn bench_ed25519_batch_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519/BatchVerify/Throughput");
    group.sample_size(50);

    // Large batch for throughput measurement
    const BATCH: usize = 256;

    let items: Vec<_> = (0..BATCH)
        .map(|i| {
            let (signing_key, verifying_key) = arcanum_ed25519::keygen();
            let message = format!("throughput_message_{}", i).into_bytes();
            let signature = arcanum_ed25519::sign(&signing_key, &message);
            (verifying_key, message, signature)
        })
        .collect();

    let refs: Vec<_> = items
        .iter()
        .map(|(vk, msg, sig)| (vk, msg.as_slice(), sig))
        .collect();

    group.throughput(Throughput::Elements(BATCH as u64));

    group.bench_function("Batch/256", |b| {
        b.iter(|| arcanum_ed25519::verify_batch(black_box(&refs)))
    });

    group.bench_function("Sequential/256", |b| {
        b.iter(|| arcanum_ed25519::verify_sequential(black_box(&refs)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ed25519_keygen,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_p256_keygen,
    bench_p256_sign,
    bench_p256_verify,
    bench_algorithm_comparison,
    // Batch verification benchmarks
    bench_ed25519_batch_verify,
    bench_ed25519_batch_same_key,
    bench_ed25519_batch_large_messages,
    bench_ed25519_batch_throughput,
);
criterion_main!(benches);
