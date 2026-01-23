//! Benchmarks for post-quantum cryptographic algorithms.
//!
//! Measures performance of ML-KEM and ML-DSA at various security levels,
//! plus hybrid schemes combining classical and post-quantum crypto.

#![allow(unused_imports, clippy::redundant_closure, dead_code)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-768 Benchmarks (using typed wrapper API)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ml-kem")]
fn bench_ml_kem_768(c: &mut Criterion) {
    use arcanum_pqc::{KeyEncapsulation, MlKem768};

    let mut group = c.benchmark_group("ML-KEM-768");

    group.bench_function("keygen", |b| b.iter(|| MlKem768::generate_keypair()));

    let (dk, ek) = MlKem768::generate_keypair();

    group.bench_function("encapsulate", |b| b.iter(|| MlKem768::encapsulate(&ek)));

    let (ct, _) = MlKem768::encapsulate(&ek);

    group.bench_function("decapsulate", |b| {
        b.iter(|| MlKem768::decapsulate(&dk, &ct))
    });

    // Full KEM operation (encap + decap)
    group.bench_function("full_kem", |b| {
        b.iter(|| {
            let (ct, ss1) = MlKem768::encapsulate(&ek);
            let ss2 = MlKem768::decapsulate(&dk, &ct).unwrap();
            assert_eq!(ss1, ss2);
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-512 Benchmarks (using bytes API)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ml-kem")]
fn bench_ml_kem_512(c: &mut Criterion) {
    use arcanum_pqc::MlKem512;

    let mut group = c.benchmark_group("ML-KEM-512");

    group.bench_function("keygen", |b| b.iter(|| MlKem512::generate_keypair()));

    let (dk, ek) = MlKem512::generate_keypair();

    group.bench_function("encapsulate", |b| b.iter(|| MlKem512::encapsulate(&ek)));

    let (ct, _) = MlKem512::encapsulate(&ek).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| MlKem512::decapsulate(&dk, &ct))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-1024 Benchmarks (using bytes API)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ml-kem")]
fn bench_ml_kem_1024(c: &mut Criterion) {
    use arcanum_pqc::MlKem1024;

    let mut group = c.benchmark_group("ML-KEM-1024");

    group.bench_function("keygen", |b| b.iter(|| MlKem1024::generate_keypair()));

    let (dk, ek) = MlKem1024::generate_keypair();

    group.bench_function("encapsulate", |b| b.iter(|| MlKem1024::encapsulate(&ek)));

    let (ct, _) = MlKem1024::encapsulate(&ek).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| MlKem1024::decapsulate(&dk, &ct))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-65 Benchmarks (using typed wrapper API)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ml-dsa")]
fn bench_ml_dsa_65(c: &mut Criterion) {
    use arcanum_pqc::{MlDsa65, PostQuantumSignature};

    let mut group = c.benchmark_group("ML-DSA-65");

    group.bench_function("keygen", |b| b.iter(|| MlDsa65::generate_keypair()));

    let (sk, vk) = MlDsa65::generate_keypair();

    // Benchmark signing with various message sizes
    for size in [32, 256, 1024, 4096, 16384].iter() {
        let message = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("sign", size), &message, |b, msg| {
            b.iter(|| MlDsa65::sign(&sk, msg))
        });
    }

    // Benchmark verification
    let message = b"benchmark message for ML-DSA-65";
    let signature = MlDsa65::sign(&sk, message);

    group.bench_function("verify", |b| {
        b.iter(|| MlDsa65::verify(&vk, message, &signature))
    });

    // Full sign + verify cycle
    group.bench_function("sign_verify_cycle", |b| {
        let msg = b"full cycle test message";
        b.iter(|| {
            let sig = MlDsa65::sign(&sk, msg);
            MlDsa65::verify(&vk, msg, &sig).unwrap();
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-44 Benchmarks (using bytes API)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ml-dsa")]
fn bench_ml_dsa_44(c: &mut Criterion) {
    use arcanum_pqc::MlDsa44Ops;

    let mut group = c.benchmark_group("ML-DSA-44");

    group.bench_function("keygen", |b| b.iter(|| MlDsa44Ops::generate_keypair()));

    let (sk, vk) = MlDsa44Ops::generate_keypair();
    let message = b"benchmark message for ML-DSA-44";
    let signature = MlDsa44Ops::sign(&sk, message).unwrap();

    group.bench_function("sign", |b| b.iter(|| MlDsa44Ops::sign(&sk, message)));

    group.bench_function("verify", |b| {
        b.iter(|| MlDsa44Ops::verify(&vk, message, &signature))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-87 Benchmarks (using bytes API)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ml-dsa")]
fn bench_ml_dsa_87(c: &mut Criterion) {
    use arcanum_pqc::MlDsa87Ops;

    let mut group = c.benchmark_group("ML-DSA-87");

    group.bench_function("keygen", |b| b.iter(|| MlDsa87Ops::generate_keypair()));

    let (sk, vk) = MlDsa87Ops::generate_keypair();
    let message = b"benchmark message for ML-DSA-87";
    let signature = MlDsa87Ops::sign(&sk, message).unwrap();

    group.bench_function("sign", |b| b.iter(|| MlDsa87Ops::sign(&sk, message)));

    group.bench_function("verify", |b| {
        b.iter(|| MlDsa87Ops::verify(&vk, message, &signature))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Native ML-DSA Benchmarks (FIPS 204 Implementation)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ml-dsa-native")]
fn bench_ml_dsa_native_44(c: &mut Criterion) {
    use arcanum_pqc::ml_dsa::{MlDsa, MlDsa44};

    let mut group = c.benchmark_group("ML-DSA-44-Native");

    group.bench_function("keygen", |b| b.iter(|| MlDsa44::generate_keypair()));

    let (sk, vk) = MlDsa44::generate_keypair();
    let message = b"benchmark message for native ML-DSA-44";

    group.bench_function("sign", |b| b.iter(|| MlDsa44::sign(&sk, message)));

    let signature = MlDsa44::sign(&sk, message);

    group.bench_function("verify", |b| {
        b.iter(|| MlDsa44::verify(&vk, message, &signature))
    });

    group.bench_function("sign_verify_cycle", |b| {
        b.iter(|| {
            let sig = MlDsa44::sign(&sk, message);
            MlDsa44::verify(&vk, message, &sig).unwrap();
        })
    });

    group.finish();
}

#[cfg(feature = "ml-dsa-native")]
fn bench_ml_dsa_native_65(c: &mut Criterion) {
    use arcanum_pqc::ml_dsa::{MlDsa, MlDsa65};

    let mut group = c.benchmark_group("ML-DSA-65-Native");

    group.bench_function("keygen", |b| b.iter(|| MlDsa65::generate_keypair()));

    let (sk, vk) = MlDsa65::generate_keypair();
    let message = b"benchmark message for native ML-DSA-65";

    group.bench_function("sign", |b| b.iter(|| MlDsa65::sign(&sk, message)));

    let signature = MlDsa65::sign(&sk, message);

    group.bench_function("verify", |b| {
        b.iter(|| MlDsa65::verify(&vk, message, &signature))
    });

    group.bench_function("sign_verify_cycle", |b| {
        b.iter(|| {
            let sig = MlDsa65::sign(&sk, message);
            MlDsa65::verify(&vk, message, &sig).unwrap();
        })
    });

    group.finish();
}

#[cfg(feature = "ml-dsa-native")]
fn bench_ml_dsa_native_87(c: &mut Criterion) {
    use arcanum_pqc::ml_dsa::{MlDsa, MlDsa87};

    let mut group = c.benchmark_group("ML-DSA-87-Native");

    group.bench_function("keygen", |b| b.iter(|| MlDsa87::generate_keypair()));

    let (sk, vk) = MlDsa87::generate_keypair();
    let message = b"benchmark message for native ML-DSA-87";

    group.bench_function("sign", |b| b.iter(|| MlDsa87::sign(&sk, message)));

    let signature = MlDsa87::sign(&sk, message);

    group.bench_function("verify", |b| {
        b.iter(|| MlDsa87::verify(&vk, message, &signature))
    });

    group.bench_function("sign_verify_cycle", |b| {
        b.iter(|| {
            let sig = MlDsa87::sign(&sk, message);
            MlDsa87::verify(&vk, message, &sig).unwrap();
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hybrid X25519-ML-KEM-768 Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "hybrid")]
fn bench_hybrid_x25519_ml_kem_768(c: &mut Criterion) {
    use arcanum_pqc::X25519MlKem768;

    let mut group = c.benchmark_group("X25519-ML-KEM-768");

    group.bench_function("keygen", |b| b.iter(|| X25519MlKem768::generate_keypair()));

    let (dk, ek) = X25519MlKem768::generate_keypair();

    group.bench_function("encapsulate", |b| {
        b.iter(|| X25519MlKem768::encapsulate(&ek))
    });

    let (ct, _) = X25519MlKem768::encapsulate(&ek);

    group.bench_function("decapsulate", |b| {
        b.iter(|| X25519MlKem768::decapsulate(&dk, &ct))
    });

    // Full hybrid KEM operation
    group.bench_function("full_hybrid_kem", |b| {
        b.iter(|| {
            let (ct, ss1) = X25519MlKem768::encapsulate(&ek);
            let ss2 = X25519MlKem768::decapsulate(&dk, &ct).unwrap();
            assert_eq!(ss1, ss2);
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEM Comparison Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "ml-kem", feature = "hybrid"))]
fn bench_kem_comparison(c: &mut Criterion) {
    use arcanum_pqc::{KeyEncapsulation, MlKem768, X25519MlKem768};

    let mut group = c.benchmark_group("KEM-Comparison");

    // ML-KEM-768 only
    let (_dk_768, ek_768) = MlKem768::generate_keypair();
    group.bench_function("ML-KEM-768/encapsulate", |b| {
        b.iter(|| MlKem768::encapsulate(&ek_768))
    });

    // Hybrid X25519 + ML-KEM-768
    let (_dk_hybrid, ek_hybrid) = X25519MlKem768::generate_keypair();
    group.bench_function("X25519-ML-KEM-768/encapsulate", |b| {
        b.iter(|| X25519MlKem768::encapsulate(&ek_hybrid))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLH-DSA Benchmarks (Native FIPS 205 Implementation)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "slh-dsa")]
fn bench_slh_dsa_128f(c: &mut Criterion) {
    use arcanum_pqc::slh_dsa::{SlhDsa, SlhDsaSha2_128f};

    let mut group = c.benchmark_group("SLH-DSA-SHA2-128f");

    // Key generation is slow for SLH-DSA, use fewer samples
    group.sample_size(10);

    group.bench_function("keygen", |b| b.iter(|| SlhDsaSha2_128f::generate_keypair()));

    let (sk, vk) = SlhDsaSha2_128f::generate_keypair();
    let message = b"benchmark message for SLH-DSA-SHA2-128f";

    group.bench_function("sign", |b| b.iter(|| SlhDsaSha2_128f::sign(&sk, message)));

    let signature = SlhDsaSha2_128f::sign(&sk, message);

    group.bench_function("verify", |b| {
        b.iter(|| SlhDsaSha2_128f::verify(&vk, message, &signature))
    });

    group.bench_function("sign_verify_cycle", |b| {
        b.iter(|| {
            let sig = SlhDsaSha2_128f::sign(&sk, message);
            SlhDsaSha2_128f::verify(&vk, message, &sig).unwrap();
        })
    });

    group.finish();
}

#[cfg(feature = "slh-dsa")]
fn bench_slh_dsa_128s(c: &mut Criterion) {
    use arcanum_pqc::slh_dsa::{SlhDsa, SlhDsaSha2_128s};

    let mut group = c.benchmark_group("SLH-DSA-SHA2-128s");

    // SLH-DSA-128s has smaller signatures but slower signing
    group.sample_size(10);

    group.bench_function("keygen", |b| b.iter(|| SlhDsaSha2_128s::generate_keypair()));

    let (sk, vk) = SlhDsaSha2_128s::generate_keypair();
    let message = b"benchmark message for SLH-DSA-SHA2-128s";

    group.bench_function("sign", |b| b.iter(|| SlhDsaSha2_128s::sign(&sk, message)));

    let signature = SlhDsaSha2_128s::sign(&sk, message);

    group.bench_function("verify", |b| {
        b.iter(|| SlhDsaSha2_128s::verify(&vk, message, &signature))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Criterion Groups
// ═══════════════════════════════════════════════════════════════════════════════

// Full feature set: ml-kem + ml-dsa + hybrid + slh-dsa
#[cfg(all(
    feature = "ml-kem",
    feature = "ml-dsa",
    feature = "hybrid",
    feature = "slh-dsa"
))]
criterion_group!(
    benches,
    bench_ml_kem_512,
    bench_ml_kem_768,
    bench_ml_kem_1024,
    bench_ml_dsa_44,
    bench_ml_dsa_65,
    bench_ml_dsa_87,
    bench_hybrid_x25519_ml_kem_768,
    bench_kem_comparison,
    bench_slh_dsa_128f,
    bench_slh_dsa_128s,
);

// ml-kem + ml-dsa + hybrid (no slh-dsa)
#[cfg(all(
    feature = "ml-kem",
    feature = "ml-dsa",
    feature = "hybrid",
    not(feature = "slh-dsa")
))]
criterion_group!(
    benches,
    bench_ml_kem_512,
    bench_ml_kem_768,
    bench_ml_kem_1024,
    bench_ml_dsa_44,
    bench_ml_dsa_65,
    bench_ml_dsa_87,
    bench_hybrid_x25519_ml_kem_768,
    bench_kem_comparison,
);

// ml-kem + ml-dsa + slh-dsa (no hybrid)
#[cfg(all(
    feature = "ml-kem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    not(feature = "hybrid")
))]
criterion_group!(
    benches,
    bench_ml_kem_512,
    bench_ml_kem_768,
    bench_ml_kem_1024,
    bench_ml_dsa_44,
    bench_ml_dsa_65,
    bench_ml_dsa_87,
    bench_slh_dsa_128f,
    bench_slh_dsa_128s,
);

// ml-kem + ml-dsa only
#[cfg(all(
    feature = "ml-kem",
    feature = "ml-dsa",
    not(feature = "hybrid"),
    not(feature = "slh-dsa")
))]
criterion_group!(
    benches,
    bench_ml_kem_512,
    bench_ml_kem_768,
    bench_ml_kem_1024,
    bench_ml_dsa_44,
    bench_ml_dsa_65,
    bench_ml_dsa_87,
);

// ml-kem + slh-dsa only
#[cfg(all(feature = "ml-kem", feature = "slh-dsa", not(feature = "ml-dsa")))]
criterion_group!(
    benches,
    bench_ml_kem_512,
    bench_ml_kem_768,
    bench_ml_kem_1024,
    bench_slh_dsa_128f,
    bench_slh_dsa_128s,
);

// ml-kem only
#[cfg(all(
    feature = "ml-kem",
    not(feature = "ml-dsa"),
    not(feature = "ml-dsa-native"),
    not(feature = "slh-dsa")
))]
criterion_group!(
    benches,
    bench_ml_kem_512,
    bench_ml_kem_768,
    bench_ml_kem_1024,
);

// ml-dsa + slh-dsa only
#[cfg(all(feature = "ml-dsa", feature = "slh-dsa", not(feature = "ml-kem")))]
criterion_group!(
    benches,
    bench_ml_dsa_44,
    bench_ml_dsa_65,
    bench_ml_dsa_87,
    bench_slh_dsa_128f,
    bench_slh_dsa_128s,
);

// ml-dsa only
#[cfg(all(feature = "ml-dsa", not(feature = "ml-kem"), not(feature = "slh-dsa")))]
criterion_group!(benches, bench_ml_dsa_44, bench_ml_dsa_65, bench_ml_dsa_87,);

// slh-dsa only
#[cfg(all(feature = "slh-dsa", not(feature = "ml-kem"), not(feature = "ml-dsa")))]
criterion_group!(benches, bench_slh_dsa_128f, bench_slh_dsa_128s,);

// ml-dsa-native only
#[cfg(all(
    feature = "ml-dsa-native",
    not(feature = "ml-kem"),
    not(feature = "ml-dsa"),
    not(feature = "slh-dsa")
))]
criterion_group!(
    benches,
    bench_ml_dsa_native_44,
    bench_ml_dsa_native_65,
    bench_ml_dsa_native_87,
);

// ml-kem + ml-dsa-native
#[cfg(all(
    feature = "ml-kem",
    feature = "ml-dsa-native",
    not(feature = "ml-dsa"),
    not(feature = "slh-dsa")
))]
criterion_group!(
    benches,
    bench_ml_kem_512,
    bench_ml_kem_768,
    bench_ml_kem_1024,
    bench_ml_dsa_native_44,
    bench_ml_dsa_native_65,
    bench_ml_dsa_native_87,
);

// No features enabled
#[cfg(not(any(
    feature = "ml-kem",
    feature = "ml-dsa",
    feature = "ml-dsa-native",
    feature = "slh-dsa"
)))]
criterion_group!(benches,);

criterion_main!(benches);
