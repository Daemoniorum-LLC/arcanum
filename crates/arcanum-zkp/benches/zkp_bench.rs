//! Benchmarks for zero-knowledge proof operations.
//!
//! Measures performance of:
//! - Bulletproofs range proofs (prove/verify)
//! - Schnorr proofs (discrete log, equality)
//! - Pedersen commitments

#![allow(clippy::redundant_closure)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// ═══════════════════════════════════════════════════════════════════════════════
// Bulletproofs Range Proof Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "bulletproofs")]
fn bench_range_proofs(c: &mut Criterion) {
    use arcanum_zkp::RangeProof;

    let mut group = c.benchmark_group("Bulletproofs");

    // Benchmark proving with various bit ranges
    for n_bits in [8, 16, 32, 64].iter() {
        let value = if *n_bits < 64 {
            1u64 << (*n_bits - 1)
        } else {
            u64::MAX / 2
        };

        group.bench_with_input(
            BenchmarkId::new("prove", format!("{}_bits", n_bits)),
            n_bits,
            |b, &n_bits| b.iter(|| RangeProof::prove(value, n_bits)),
        );
    }

    // Benchmark verification with various bit ranges
    for n_bits in [8, 16, 32, 64].iter() {
        let value = if *n_bits < 64 {
            1u64 << (*n_bits - 1)
        } else {
            u64::MAX / 2
        };
        let proof = RangeProof::prove(value, *n_bits).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify", format!("{}_bits", n_bits)),
            &proof,
            |b, proof| b.iter(|| proof.verify(*n_bits)),
        );
    }

    // Benchmark serialization/deserialization
    let proof_32 = RangeProof::prove(1000u64, 32).unwrap();
    let bytes = proof_32.to_bytes();

    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("serialize_32bit", |b| b.iter(|| proof_32.to_bytes()));

    group.bench_function("deserialize_32bit", |b| {
        b.iter(|| RangeProof::from_bytes(&bytes, 32))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Schnorr Proof Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "schnorr-proofs")]
fn bench_schnorr_proofs(c: &mut Criterion) {
    use arcanum_zkp::curve::{RISTRETTO_BASEPOINT_POINT, Scalar};
    use arcanum_zkp::{DiscreteLogProof, EqualityProof, SchnorrProofBuilder};
    use rand::RngCore;

    let mut group = c.benchmark_group("Schnorr");

    // Generate random secret for benchmarks
    let mut secret_bytes = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);
    let g = RISTRETTO_BASEPOINT_POINT;
    let public = secret * g;

    // Benchmark discrete log proof
    group.bench_function("dlog_prove", |b| {
        b.iter(|| DiscreteLogProof::prove(&secret, &public))
    });

    let dlog_proof = DiscreteLogProof::prove(&secret, &public);

    group.bench_function("dlog_verify", |b| b.iter(|| dlog_proof.verify(&public)));

    // Benchmark equality proof (same discrete log in two groups)
    let g2 = Scalar::from(42u64) * g;
    let y1 = secret * g;
    let y2 = secret * g2;

    group.bench_function("equality_prove", |b| {
        b.iter(|| EqualityProof::prove(&secret, &g, &g2, &y1, &y2))
    });

    let eq_proof = EqualityProof::prove(&secret, &g, &g2, &y1, &y2);

    group.bench_function("equality_verify", |b| {
        b.iter(|| eq_proof.verify(&g, &g2, &y1, &y2))
    });

    // Benchmark multi-statement Schnorr proof
    let g3 = Scalar::from(123u64) * g;
    let y3 = secret * g3;

    group.bench_function("multi_3_statements_prove", |b| {
        b.iter(|| {
            SchnorrProofBuilder::new(b"benchmark-proof")
                .add_statement(g, y1)
                .add_statement(g2, y2)
                .add_statement(g3, y3)
                .prove(&secret)
        })
    });

    let multi_proof = SchnorrProofBuilder::new(b"benchmark-proof")
        .add_statement(g, y1)
        .add_statement(g2, y2)
        .add_statement(g3, y3)
        .prove(&secret);

    group.bench_function("multi_3_statements_verify", |b| {
        let verifier = SchnorrProofBuilder::new(b"benchmark-proof")
            .add_statement(g, y1)
            .add_statement(g2, y2)
            .add_statement(g3, y3);
        b.iter(|| verifier.verify(&multi_proof))
    });

    // Benchmark serialization
    let bytes = dlog_proof.to_bytes();
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    group.bench_function("dlog_serialize", |b| b.iter(|| dlog_proof.to_bytes()));

    group.bench_function("dlog_deserialize", |b| {
        b.iter(|| DiscreteLogProof::from_bytes(&bytes))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pedersen Commitment Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_pedersen(c: &mut Criterion) {
    use arcanum_zkp::{PedersenCommitment, PedersenOpening};

    let mut group = c.benchmark_group("Pedersen");

    // Benchmark opening generation
    group.bench_function("opening_random", |b| b.iter(|| PedersenOpening::random()));

    // Benchmark commitment creation
    group.bench_function("commit", |b| {
        b.iter(|| {
            let opening = PedersenOpening::random();
            PedersenCommitment::commit(42u64, &opening)
        })
    });

    // Setup for verification and homomorphic benchmarks
    let value = 42u64;
    let opening = PedersenOpening::random();
    let commitment = PedersenCommitment::commit(value, &opening);

    // Benchmark verification
    group.bench_function("verify", |b| b.iter(|| commitment.verify(value, &opening)));

    // Benchmark homomorphic addition
    let value2 = 100u64;
    let opening2 = PedersenOpening::random();
    let commitment2 = PedersenCommitment::commit(value2, &opening2);

    group.bench_function("homomorphic_add", |b| {
        b.iter(|| commitment.add(&commitment2))
    });

    // Benchmark opening addition (for homomorphic verification)
    group.bench_function("opening_add", |b| b.iter(|| opening.add(&opening2)));

    // Verify homomorphic sum
    let sum_commitment = commitment.add(&commitment2);
    let sum_opening = opening.add(&opening2);
    let sum_value = value + value2;

    group.bench_function("verify_sum", |b| {
        b.iter(|| sum_commitment.verify(sum_value, &sum_opening))
    });

    // Benchmark serialization
    let bytes = commitment.to_bytes();
    group.throughput(Throughput::Bytes(bytes.len() as u64));

    group.bench_function("serialize", |b| b.iter(|| commitment.to_bytes()));

    group.bench_function("deserialize", |b| {
        b.iter(|| PedersenCommitment::from_bytes(&bytes))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Criterion Groups
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "bulletproofs", feature = "schnorr-proofs"))]
criterion_group!(
    benches,
    bench_range_proofs,
    bench_schnorr_proofs,
    bench_pedersen
);

#[cfg(all(feature = "bulletproofs", not(feature = "schnorr-proofs")))]
criterion_group!(benches, bench_range_proofs, bench_pedersen);

#[cfg(all(not(feature = "bulletproofs"), feature = "schnorr-proofs"))]
criterion_group!(benches, bench_schnorr_proofs, bench_pedersen);

#[cfg(not(any(feature = "bulletproofs", feature = "schnorr-proofs")))]
criterion_group!(benches, bench_pedersen);

criterion_main!(benches);
