//! Asymmetric cryptography benchmarks.
//!
//! Benchmarks key generation, key exchange, and encryption operations.

#![allow(clippy::unit_arg)]

#[cfg(feature = "rsa")]
use criterion::{BenchmarkId, Throughput};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[cfg(feature = "rsa")]
use arcanum_asymmetric::RsaPrivateKey;
use arcanum_asymmetric::{
    P256SecretKey, P384SecretKey, X25519PublicKey, X25519SecretKey, x25519::X25519,
};

// ═══════════════════════════════════════════════════════════════════════════════
// X25519 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_x25519_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_keygen");

    group.bench_function("generate_keypair", |b| {
        b.iter(|| {
            let secret = X25519SecretKey::generate();
            let _public = black_box(secret.public_key());
        });
    });

    group.bench_function("public_key_derivation", |b| {
        let secret = X25519SecretKey::generate();
        b.iter(|| black_box(secret.public_key()));
    });

    group.finish();
}

fn bench_x25519_dh(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_dh");

    let alice_secret = X25519SecretKey::generate();
    let bob_secret = X25519SecretKey::generate();
    let bob_public = bob_secret.public_key();

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| black_box(alice_secret.diffie_hellman(&bob_public)));
    });

    group.bench_function("ephemeral_dh", |b| {
        let bob_public = bob_secret.public_key();
        b.iter(|| {
            let (ephemeral, _public) = X25519SecretKey::ephemeral();
            black_box(ephemeral.diffie_hellman(&bob_public))
        });
    });

    group.finish();
}

fn bench_x25519_triple_dh(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_triple_dh");

    let alice_identity = X25519SecretKey::generate();
    let alice_ephemeral = X25519SecretKey::generate();
    let bob_identity = X25519SecretKey::generate();
    let bob_ephemeral = X25519SecretKey::generate();

    let bob_identity_pub = bob_identity.public_key();
    let bob_ephemeral_pub = bob_ephemeral.public_key();

    group.bench_function("triple_dh", |b| {
        b.iter(|| {
            black_box(X25519::triple_dh(
                &alice_identity,
                &alice_ephemeral,
                &bob_identity_pub,
                &bob_ephemeral_pub,
            ))
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// RSA BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "rsa")]
fn bench_rsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_keygen");
    group.sample_size(10); // RSA keygen is slow

    for bits in [2048, 3072, 4096] {
        group.bench_with_input(BenchmarkId::new("generate", bits), &bits, |b, &bits| {
            b.iter(|| black_box(RsaPrivateKey::generate(bits).unwrap()));
        });
    }

    group.finish();
}

#[cfg(feature = "rsa")]
fn bench_rsa_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_encrypt_decrypt");

    // Test with different key sizes
    for bits in [2048, 3072, 4096] {
        let private_key = RsaPrivateKey::generate(bits).unwrap();
        let public_key = private_key.public_key();

        // Small message (32 bytes - typical symmetric key)
        let small_msg = b"0123456789abcdef0123456789abcdef";

        // Maximum message size depends on key size and padding
        // For OAEP with SHA-256: max = key_size_bytes - 2*hash_size - 2 = bits/8 - 66
        let max_msg_size = bits / 8 - 66;
        let large_msg = vec![0xABu8; max_msg_size];

        // Encrypt benchmarks
        group.throughput(Throughput::Bytes(small_msg.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(format!("encrypt_oaep_{}_small", bits), bits),
            &(&public_key, small_msg.as_slice()),
            |b, (key, msg)| {
                b.iter(|| black_box(key.encrypt_oaep(msg).unwrap()));
            },
        );

        group.throughput(Throughput::Bytes(large_msg.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(format!("encrypt_oaep_{}_large", bits), bits),
            &(&public_key, large_msg.as_slice()),
            |b, (key, msg)| {
                b.iter(|| black_box(key.encrypt_oaep(msg).unwrap()));
            },
        );

        // Decrypt benchmarks
        let ciphertext_small = public_key.encrypt_oaep(small_msg).unwrap();
        let ciphertext_large = public_key.encrypt_oaep(&large_msg).unwrap();

        group.throughput(Throughput::Bytes(small_msg.len() as u64));
        group.bench_function(
            BenchmarkId::new(format!("decrypt_oaep_{}_small", bits), bits),
            |b| {
                b.iter(|| {
                    black_box(
                        private_key
                            .decrypt_oaep(ciphertext_small.as_bytes())
                            .unwrap(),
                    )
                });
            },
        );

        group.throughput(Throughput::Bytes(large_msg.len() as u64));
        group.bench_function(
            BenchmarkId::new(format!("decrypt_oaep_{}_large", bits), bits),
            |b| {
                b.iter(|| {
                    black_box(
                        private_key
                            .decrypt_oaep(ciphertext_large.as_bytes())
                            .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

#[cfg(feature = "rsa")]
fn bench_rsa_sign_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_sign_verify");

    for bits in [2048, 3072, 4096] {
        let private_key = RsaPrivateKey::generate(bits).unwrap();
        let public_key = private_key.public_key();
        let message = b"The quick brown fox jumps over the lazy dog";

        // PSS signing
        group.bench_with_input(
            BenchmarkId::new(format!("sign_pss_{}", bits), bits),
            &message.as_slice(),
            |b, msg| {
                b.iter(|| black_box(private_key.sign_pss(msg)));
            },
        );

        // PSS verification
        let signature = private_key.sign_pss(message);
        group.bench_with_input(
            BenchmarkId::new(format!("verify_pss_{}", bits), bits),
            &(message.as_slice(), &signature),
            |b, (msg, sig)| {
                b.iter(|| black_box(public_key.verify_pss(msg, sig).unwrap()));
            },
        );

        // PKCS#1 signing
        group.bench_with_input(
            BenchmarkId::new(format!("sign_pkcs1_{}", bits), bits),
            &message.as_slice(),
            |b, msg| {
                b.iter(|| black_box(private_key.sign_pkcs1(msg)));
            },
        );

        // PKCS#1 verification
        let pkcs1_sig = private_key.sign_pkcs1(message);
        group.bench_with_input(
            BenchmarkId::new(format!("verify_pkcs1_{}", bits), bits),
            &(message.as_slice(), &pkcs1_sig),
            |b, (msg, sig)| {
                b.iter(|| black_box(public_key.verify_pkcs1(msg, sig).unwrap()));
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDH BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_ecdh_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_keygen");

    group.bench_function("p256_generate", |b| {
        b.iter(|| black_box(P256SecretKey::generate()));
    });

    group.bench_function("p384_generate", |b| {
        b.iter(|| black_box(P384SecretKey::generate()));
    });

    group.finish();
}

fn bench_ecdh_dh(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_dh");

    // P-256
    let alice_p256 = P256SecretKey::generate();
    let bob_p256 = P256SecretKey::generate();
    let bob_p256_public = bob_p256.public_key();

    group.bench_function("p256_diffie_hellman", |b| {
        b.iter(|| black_box(alice_p256.diffie_hellman(&bob_p256_public)));
    });

    // P-384
    let alice_p384 = P384SecretKey::generate();
    let bob_p384 = P384SecretKey::generate();
    let bob_p384_public = bob_p384.public_key();

    group.bench_function("p384_diffie_hellman", |b| {
        b.iter(|| black_box(alice_p384.diffie_hellman(&bob_p384_public)));
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPARISON: X25519 vs ECDH P-256 vs RSA
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_key_exchange_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_exchange_comparison");

    // X25519
    let x25519_alice = X25519SecretKey::generate();
    let x25519_bob = X25519SecretKey::generate();
    let x25519_bob_pub = x25519_bob.public_key();

    group.bench_function("x25519", |b| {
        b.iter(|| black_box(x25519_alice.diffie_hellman(&x25519_bob_pub)));
    });

    // ECDH P-256
    let p256_alice = P256SecretKey::generate();
    let p256_bob = P256SecretKey::generate();
    let p256_bob_pub = p256_bob.public_key();

    group.bench_function("ecdh_p256", |b| {
        b.iter(|| black_box(p256_alice.diffie_hellman(&p256_bob_pub)));
    });

    // ECDH P-384
    let p384_alice = P384SecretKey::generate();
    let p384_bob = P384SecretKey::generate();
    let p384_bob_pub = p384_bob.public_key();

    group.bench_function("ecdh_p384", |b| {
        b.iter(|| black_box(p384_alice.diffie_hellman(&p384_bob_pub)));
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERIALIZATION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    // X25519 serialization
    let x25519_secret = X25519SecretKey::generate();
    let x25519_public = x25519_secret.public_key();
    let x25519_bytes = x25519_secret.to_bytes();

    group.bench_function("x25519_to_bytes", |b| {
        b.iter(|| black_box(x25519_secret.to_bytes()));
    });

    group.bench_function("x25519_from_bytes", |b| {
        b.iter(|| black_box(X25519SecretKey::from_bytes(&x25519_bytes)));
    });

    group.bench_function("x25519_public_to_hex", |b| {
        b.iter(|| black_box(x25519_public.to_hex()));
    });

    let hex_str = x25519_public.to_hex();
    group.bench_function("x25519_public_from_hex", |b| {
        b.iter(|| black_box(X25519PublicKey::from_hex(&hex_str).unwrap()));
    });

    group.finish();
}

#[cfg(feature = "rsa")]
fn bench_rsa_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_serialization");

    let rsa_private = RsaPrivateKey::generate(2048).unwrap();
    let rsa_der = rsa_private.to_pkcs8_der().unwrap();

    group.bench_function("rsa_2048_to_pkcs8_der", |b| {
        b.iter(|| black_box(rsa_private.to_pkcs8_der().unwrap()));
    });

    group.bench_function("rsa_2048_from_pkcs8_der", |b| {
        b.iter(|| black_box(RsaPrivateKey::from_pkcs8_der(&rsa_der).unwrap()));
    });

    group.finish();
}

#[cfg(feature = "rsa")]
criterion_group!(
    benches,
    bench_x25519_keygen,
    bench_x25519_dh,
    bench_x25519_triple_dh,
    bench_rsa_keygen,
    bench_rsa_encrypt_decrypt,
    bench_rsa_sign_verify,
    bench_ecdh_keygen,
    bench_ecdh_dh,
    bench_key_exchange_comparison,
    bench_serialization,
    bench_rsa_serialization,
);

#[cfg(not(feature = "rsa"))]
criterion_group!(
    benches,
    bench_x25519_keygen,
    bench_x25519_dh,
    bench_x25519_triple_dh,
    bench_ecdh_keygen,
    bench_ecdh_dh,
    bench_key_exchange_comparison,
    bench_serialization,
);

criterion_main!(benches);
