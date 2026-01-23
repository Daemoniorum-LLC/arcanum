//! Benchmarks for HoloCrypt containers.
//!
//! Tests performance of:
//! - Container seal/unseal operations
//! - PQC envelope operations
//! - Selective disclosure (Merkle proofs)
//! - Property proofs

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════════
// TEST DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestData {
    id: u64,
    name: String,
    payload: Vec<u8>,
}

impl TestData {
    fn new(size: usize) -> Self {
        Self {
            id: 42,
            name: "benchmark-data".to_string(),
            payload: vec![0xAB; size],
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOLOCRYPT CONTAINER BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "encryption", feature = "signatures", feature = "merkle"))]
fn bench_holocrypt_seal_unseal(c: &mut Criterion) {
    use arcanum_holocrypt::container::HoloCrypt;

    let mut group = c.benchmark_group("HoloCrypt/seal_unseal");

    for size in [256, 1024, 4096, 16384, 65536, 262144] {
        let data = TestData::new(size);
        let (sealing_key, opening_key) = HoloCrypt::<TestData>::generate_keypair();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal", size), &size, |b, _| {
            b.iter(|| {
                let container = HoloCrypt::seal(black_box(&data), &sealing_key).unwrap();
                black_box(container)
            })
        });

        // Pre-seal for unseal benchmark
        let sealed = HoloCrypt::seal(&data, &sealing_key).unwrap();

        group.bench_with_input(BenchmarkId::new("unseal", size), &size, |b, _| {
            b.iter(|| {
                let recovered: TestData = sealed.unseal(black_box(&opening_key)).unwrap();
                black_box(recovered)
            })
        });
    }

    group.finish();
}

#[cfg(all(feature = "encryption", feature = "signatures", feature = "merkle"))]
fn bench_holocrypt_keygen(c: &mut Criterion) {
    use arcanum_holocrypt::container::HoloCrypt;

    c.bench_function("HoloCrypt/keygen", |b| {
        b.iter(|| {
            let (sealing, opening) = HoloCrypt::<TestData>::generate_keypair();
            black_box((sealing, opening))
        })
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQC CONTAINER BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(
    feature = "pqc",
    feature = "encryption",
    feature = "merkle",
    feature = "signatures"
))]
fn bench_pqc_container(c: &mut Criterion) {
    use arcanum_holocrypt::pqc::{PqcContainer, PqcKeyPair};

    let mut group = c.benchmark_group("HoloCrypt-PQC/seal_unseal");

    for size in [256, 1024, 4096, 16384] {
        let data = TestData::new(size);
        let keypair = PqcKeyPair::generate();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal", size), &size, |b, _| {
            b.iter(|| {
                let container =
                    PqcContainer::seal(black_box(&data), keypair.encapsulation_key()).unwrap();
                black_box(container)
            })
        });

        // Pre-seal for unseal benchmark
        let sealed = PqcContainer::seal(&data, keypair.encapsulation_key()).unwrap();

        group.bench_with_input(BenchmarkId::new("unseal", size), &size, |b, _| {
            b.iter(|| {
                let recovered: TestData = sealed
                    .unseal(black_box(keypair.decapsulation_key()))
                    .unwrap();
                black_box(recovered)
            })
        });
    }

    group.finish();
}

#[cfg(feature = "pqc")]
fn bench_pqc_keygen(c: &mut Criterion) {
    use arcanum_holocrypt::pqc::PqcKeyPair;

    c.bench_function("HoloCrypt-PQC/keygen", |b| {
        b.iter(|| {
            let keypair = PqcKeyPair::generate();
            black_box(keypair)
        })
    });
}

#[cfg(all(feature = "pqc", feature = "encryption", feature = "merkle"))]
fn bench_pqc_envelope(c: &mut Criterion) {
    use arcanum_holocrypt::pqc::{PqcEnvelope, PqcKeyPair};

    let mut group = c.benchmark_group("HoloCrypt-PQC/envelope");
    let keypair = PqcKeyPair::generate();
    let content_key = [0x42u8; 32];

    group.bench_function("wrap", |b| {
        b.iter(|| {
            let envelope =
                PqcEnvelope::wrap(black_box(&content_key), keypair.encapsulation_key()).unwrap();
            black_box(envelope)
        })
    });

    let envelope = PqcEnvelope::wrap(&content_key, keypair.encapsulation_key()).unwrap();

    group.bench_function("unwrap", |b| {
        b.iter(|| {
            let key = envelope
                .unwrap(black_box(keypair.decapsulation_key()))
                .unwrap();
            black_box(key)
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// SELECTIVE DISCLOSURE BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "merkle")]
fn bench_merkle_proof(c: &mut Criterion) {
    use arcanum_holocrypt::selective::MerkleTreeBuilder;

    let mut group = c.benchmark_group("HoloCrypt/selective_disclosure");

    for num_chunks in [16, 64, 256, 1024] {
        let chunks: Vec<Vec<u8>> = (0..num_chunks)
            .map(|i| format!("chunk-{}-data-payload", i).into_bytes())
            .collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

        group.bench_with_input(
            BenchmarkId::new("build_tree", num_chunks),
            &num_chunks,
            |b, _| {
                b.iter(|| {
                    let tree = MerkleTreeBuilder::from_chunks(black_box(&chunk_refs));
                    black_box(tree)
                })
            },
        );

        let tree = MerkleTreeBuilder::from_chunks(&chunk_refs);
        let root = tree.root();

        group.bench_with_input(
            BenchmarkId::new("generate_proof", num_chunks),
            &num_chunks,
            |b, _| {
                b.iter(|| {
                    // Prove a random chunk
                    let proof = tree.generate_proof(black_box(num_chunks / 2)).unwrap();
                    black_box(proof)
                })
            },
        );

        let proof = tree.generate_proof(num_chunks / 2).unwrap();
        let chunk = &chunks[num_chunks / 2];

        group.bench_with_input(
            BenchmarkId::new("verify_proof", num_chunks),
            &num_chunks,
            |b, _| {
                b.iter(|| {
                    let valid = proof.verify(black_box(chunk), black_box(&root));
                    black_box(valid)
                })
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY PROOFS BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "zkp", feature = "merkle"))]
fn bench_property_proofs(c: &mut Criterion) {
    use arcanum_holocrypt::properties::PropertyProofBuilder;

    let mut group = c.benchmark_group("HoloCrypt/property_proofs");
    let commitment = [0x42u8; 32];

    // Range proof benchmark
    group.bench_function("range_proof_build", |b| {
        b.iter(|| {
            let proof =
                PropertyProofBuilder::build_range_proof(black_box(50), 0, 100, commitment).unwrap();
            black_box(proof)
        })
    });

    let range_proof = PropertyProofBuilder::build_range_proof(50, 0, 100, commitment).unwrap();

    group.bench_function("range_proof_verify", |b| {
        b.iter(|| {
            let result = range_proof.verify(black_box(&commitment));
            black_box(result)
        })
    });

    // Greater-than proof
    group.bench_function("greater_than_proof_build", |b| {
        b.iter(|| {
            let proof =
                PropertyProofBuilder::build_greater_than_proof(black_box(100), 50, commitment)
                    .unwrap();
            black_box(proof)
        })
    });

    // Hash preimage proof
    group.bench_function("hash_preimage_proof_build", |b| {
        let preimage = b"secret preimage data";
        b.iter(|| {
            let proof =
                PropertyProofBuilder::build_hash_preimage_proof(black_box(preimage), commitment)
                    .unwrap();
            black_box(proof)
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRITERION GROUPS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "encryption", feature = "signatures", feature = "merkle"))]
criterion_group!(
    benches_basic,
    bench_holocrypt_seal_unseal,
    bench_holocrypt_keygen,
);

#[cfg(all(
    feature = "pqc",
    feature = "encryption",
    feature = "merkle",
    feature = "signatures"
))]
criterion_group!(
    benches_pqc,
    bench_pqc_container,
    bench_pqc_keygen,
    bench_pqc_envelope,
);

#[cfg(feature = "merkle")]
criterion_group!(benches_merkle, bench_merkle_proof,);

#[cfg(all(feature = "zkp", feature = "merkle"))]
criterion_group!(benches_zkp, bench_property_proofs,);

// Conditional main based on features
#[cfg(all(
    feature = "encryption",
    feature = "signatures",
    feature = "merkle",
    feature = "pqc",
    feature = "zkp"
))]
criterion_main!(benches_basic, benches_pqc, benches_merkle, benches_zkp);

#[cfg(all(
    feature = "encryption",
    feature = "signatures",
    feature = "merkle",
    not(feature = "pqc"),
    not(feature = "zkp")
))]
criterion_main!(benches_basic, benches_merkle);

#[cfg(all(
    feature = "encryption",
    feature = "signatures",
    feature = "merkle",
    feature = "pqc",
    not(feature = "zkp")
))]
criterion_main!(benches_basic, benches_pqc, benches_merkle);

// Fallback for minimal features
#[cfg(not(all(feature = "encryption", feature = "signatures", feature = "merkle")))]
fn main() {
    eprintln!("HoloCrypt benchmarks require: encryption, signatures, merkle features");
}
