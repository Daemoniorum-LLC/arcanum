//! Benchmarks for threshold cryptographic operations.
//!
//! Measures performance of:
//! - Shamir secret sharing (split/combine)
//! - FROST threshold signatures (2-round signing)
//! - Distributed Key Generation (DKG)

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// ═══════════════════════════════════════════════════════════════════════════════
// Shamir Secret Sharing Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "shamir")]
fn bench_shamir(c: &mut Criterion) {
    use arcanum_threshold::shamir::ShamirScheme;

    let mut group = c.benchmark_group("Shamir");

    // Benchmark splitting with various secret sizes
    for size in [32, 64, 128, 256, 1024].iter() {
        let secret: Vec<u8> = (0..*size as u8).collect();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("split-3of5", size), &secret, |b, s| {
            b.iter(|| ShamirScheme::split(s, 3, 5))
        });
    }

    // Benchmark different threshold configurations
    let secret = vec![42u8; 32];

    for (t, n) in [(2, 3), (3, 5), (5, 10), (10, 20)].iter() {
        group.bench_with_input(
            BenchmarkId::new("split", format!("{}of{}", t, n)),
            &(*t, *n),
            |b, &(t, n)| b.iter(|| ShamirScheme::split(&secret, t, n)),
        );
    }

    // Benchmark combining
    let shares = ShamirScheme::split(&secret, 3, 5).unwrap();

    group.bench_function("combine-3of5", |b| {
        b.iter(|| ShamirScheme::combine(&shares[..3]))
    });

    // Benchmark with larger threshold
    let shares_10of20 = ShamirScheme::split(&secret, 10, 20).unwrap();

    group.bench_function("combine-10of20", |b| {
        b.iter(|| ShamirScheme::combine(&shares_10of20[..10]))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// FROST Threshold Signature Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "frost")]
fn bench_frost(c: &mut Criterion) {
    use arcanum_threshold::frost::{
        FrostSigner, FrostVerifier, GroupVerifyingKey, PublicKeyPackage, SigningPackage,
        trusted_dealer_keygen,
    };

    let mut group = c.benchmark_group("FROST");

    // Benchmark key generation
    group.bench_function("keygen-2of3", |b| b.iter(|| trusted_dealer_keygen(2, 3)));

    group.bench_function("keygen-3of5", |b| b.iter(|| trusted_dealer_keygen(3, 5)));

    group.bench_function("keygen-5of10", |b| b.iter(|| trusted_dealer_keygen(5, 10)));

    // Setup for signing benchmarks
    let (shares, pubkey_package) = trusted_dealer_keygen(2, 3).unwrap();
    let message = b"benchmark message for FROST signing";

    // Create signers
    let signers: Vec<FrostSigner> = shares
        .iter()
        .take(2)
        .map(|s| {
            let kp = frost_ed25519::keys::KeyPackage::try_from(s.clone()).unwrap();
            FrostSigner::new(kp)
        })
        .collect();

    // Benchmark round 1 (commitment generation)
    group.bench_function("round1", |b| b.iter(|| signers[0].round1()));

    // Prepare for round 2 benchmark
    let mut all_nonces = Vec::new();
    let mut all_commitments = Vec::new();
    for signer in &signers {
        let (nonces, commitments) = signer.round1().unwrap();
        all_nonces.push(nonces);
        all_commitments.push(commitments);
    }
    let signing_package = SigningPackage::new(&all_commitments, message).unwrap();

    // Benchmark round 2 (signature share generation)
    group.bench_function("round2", |b| {
        b.iter(|| signers[0].round2(message, &all_nonces[0], &signing_package))
    });

    // Collect signature shares for aggregation benchmark
    let signature_shares: Vec<_> = signers
        .iter()
        .enumerate()
        .map(|(i, signer)| {
            signer
                .round2(message, &all_nonces[i], &signing_package)
                .unwrap()
        })
        .collect();

    // Setup verifier
    let group_key = GroupVerifyingKey::from_frost(pubkey_package.verifying_key()).unwrap();
    let verifier = FrostVerifier::new(&group_key).unwrap();
    let pkg = PublicKeyPackage::from_frost(pubkey_package);

    // Benchmark aggregation
    group.bench_function("aggregate", |b| {
        b.iter(|| verifier.aggregate(&signing_package, &signature_shares, &pkg))
    });

    // Benchmark verification
    let signature = verifier
        .aggregate(&signing_package, &signature_shares, &pkg)
        .unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| verifier.verify(message, &signature))
    });

    // Full signing flow (end-to-end)
    group.bench_function("full_sign_2of3", |b| {
        b.iter(|| {
            // Round 1
            let mut nonces = Vec::new();
            let mut commitments = Vec::new();
            for signer in &signers {
                let (n, c) = signer.round1().unwrap();
                nonces.push(n);
                commitments.push(c);
            }

            // Create package
            let pkg = SigningPackage::new(&commitments, message).unwrap();

            // Round 2
            let shares: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(i, s)| s.round2(message, &nonces[i], &pkg).unwrap())
                .collect();

            // Aggregate
            let pubkey_pkg = PublicKeyPackage::from_frost(trusted_dealer_keygen(2, 3).unwrap().1);
            let group_key = GroupVerifyingKey::from_frost(
                trusted_dealer_keygen(2, 3).unwrap().1.verifying_key(),
            )
            .unwrap();
            let verifier = FrostVerifier::new(&group_key).unwrap();
            let _ = verifier.aggregate(&pkg, &shares, &pubkey_pkg);
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// DKG Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "dkg")]
fn bench_dkg(c: &mut Criterion) {
    use arcanum_threshold::dkg::{DkgParticipant, run_dkg};

    let mut group = c.benchmark_group("DKG");

    // Benchmark participant creation
    group.bench_function("participant_new", |b| {
        b.iter(|| DkgParticipant::new(1, 2, 3))
    });

    // Benchmark round 1
    group.bench_function("round1", |b| {
        b.iter(|| {
            let mut p = DkgParticipant::new(1, 2, 3).unwrap();
            p.round1()
        })
    });

    // Benchmark full DKG ceremony for different configurations
    for (t, n) in [(2, 3), (3, 5), (5, 10)].iter() {
        group.bench_with_input(
            BenchmarkId::new("full_dkg", format!("{}of{}", t, n)),
            &(*t as u16, *n as u16),
            |b, &(t, n)| b.iter(|| run_dkg(t, n)),
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Criterion Groups
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "shamir", feature = "frost", feature = "dkg"))]
criterion_group!(benches, bench_shamir, bench_frost, bench_dkg);

#[cfg(all(feature = "shamir", feature = "frost", not(feature = "dkg")))]
criterion_group!(benches, bench_shamir, bench_frost);

#[cfg(all(feature = "shamir", not(feature = "frost")))]
criterion_group!(benches, bench_shamir);

#[cfg(all(not(feature = "shamir"), feature = "frost"))]
criterion_group!(benches, bench_frost);

#[cfg(not(any(feature = "shamir", feature = "frost")))]
criterion_group!(benches,);

criterion_main!(benches);
