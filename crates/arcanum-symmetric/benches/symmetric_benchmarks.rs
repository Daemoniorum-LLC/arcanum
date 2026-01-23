//! Comprehensive benchmarks for symmetric encryption algorithms.
//!
//! Compares Arcanum implementations against peer libraries:
//! - RustCrypto (direct backend)
//! - ring (BoringSSL wrapper)
//! - sodiumoxide (libsodium bindings)

#![allow(clippy::redundant_closure)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

// Message sizes for benchmarking (covering various use cases)
const SIZES: &[usize] = &[64, 256, 1024, 4096, 16384, 65536];

// ═══════════════════════════════════════════════════════════════════════════════
// ARCANUM AES-256-GCM BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod arcanum_aes {
    use arcanum_symmetric::{Aes256Gcm, Cipher};

    pub fn keygen() -> (Vec<u8>, Vec<u8>) {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();
        (key, nonce)
    }

    pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        Aes256Gcm::encrypt(key, nonce, plaintext, None).unwrap()
    }

    pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        Aes256Gcm::decrypt(key, nonce, ciphertext, None).unwrap()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARCANUM CHACHA20-POLY1305 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod arcanum_chacha {
    use arcanum_symmetric::{ChaCha20Poly1305Cipher, Cipher};

    pub fn keygen() -> (Vec<u8>, Vec<u8>) {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        (key, nonce)
    }

    pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        ChaCha20Poly1305Cipher::encrypt(key, nonce, plaintext, None).unwrap()
    }

    pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        ChaCha20Poly1305Cipher::decrypt(key, nonce, ciphertext, None).unwrap()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECT RUSTCRYPTO BENCHMARKS (Arcanum's backend)
// ═══════════════════════════════════════════════════════════════════════════════

mod rustcrypto_aes {
    use aead::{Aead, KeyInit};
    use aes_gcm::Aes256Gcm;
    use rand_core::{OsRng, RngCore};

    pub fn keygen() -> ([u8; 32], [u8; 12]) {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
        (key, nonce)
    }

    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher.encrypt(nonce, plaintext).unwrap()
    }

    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).unwrap()
    }
}

mod rustcrypto_chacha {
    use aead::{Aead, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    use rand_core::{OsRng, RngCore};

    pub fn keygen() -> ([u8; 32], [u8; 12]) {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
        (key, nonce)
    }

    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher.encrypt(nonce, plaintext).unwrap()
    }

    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).unwrap()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RING BENCHMARKS (BoringSSL wrapper - peer library)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "bench-ring")]
mod ring_aes {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use ring::rand::{SecureRandom, SystemRandom};

    pub fn keygen() -> (Vec<u8>, [u8; 12]) {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill(&mut key).unwrap();
        rng.fill(&mut nonce).unwrap();
        (key, nonce)
    }

    pub fn encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .unwrap();
        in_out
    }

    pub fn decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = ciphertext.to_vec();
        let plaintext = key.open_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
        plaintext.to_vec()
    }
}

#[cfg(feature = "bench-ring")]
mod ring_chacha {
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    use ring::rand::{SecureRandom, SystemRandom};

    pub fn keygen() -> (Vec<u8>, [u8; 12]) {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill(&mut key).unwrap();
        rng.fill(&mut nonce).unwrap();
        (key, nonce)
    }

    pub fn encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .unwrap();
        in_out
    }

    pub fn decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = ciphertext.to_vec();
        let plaintext = key.open_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
        plaintext.to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK GROUPS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_aes256_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-GCM");

    for size in SIZES {
        let plaintext = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        let (key, nonce) = arcanum_aes::keygen();
        let ciphertext = arcanum_aes::encrypt(&key, &nonce, &plaintext);

        group.bench_with_input(BenchmarkId::new("Arcanum/encrypt", size), size, |b, _| {
            b.iter(|| {
                arcanum_aes::encrypt(black_box(&key), black_box(&nonce), black_box(&plaintext))
            })
        });

        group.bench_with_input(BenchmarkId::new("Arcanum/decrypt", size), size, |b, _| {
            b.iter(|| {
                arcanum_aes::decrypt(black_box(&key), black_box(&nonce), black_box(&ciphertext))
            })
        });

        // RustCrypto (direct)
        let (rc_key, rc_nonce) = rustcrypto_aes::keygen();
        let rc_ciphertext = rustcrypto_aes::encrypt(&rc_key, &rc_nonce, &plaintext);

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    rustcrypto_aes::encrypt(
                        black_box(&rc_key),
                        black_box(&rc_nonce),
                        black_box(&plaintext),
                    )
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    rustcrypto_aes::decrypt(
                        black_box(&rc_key),
                        black_box(&rc_nonce),
                        black_box(&rc_ciphertext),
                    )
                })
            },
        );

        // ring (when feature enabled)
        #[cfg(feature = "bench-ring")]
        {
            let (ring_key, ring_nonce) = ring_aes::keygen();
            let ring_ciphertext = ring_aes::encrypt(&ring_key, &ring_nonce, &plaintext);

            group.bench_with_input(BenchmarkId::new("ring/encrypt", size), size, |b, _| {
                b.iter(|| {
                    ring_aes::encrypt(
                        black_box(&ring_key),
                        black_box(&ring_nonce),
                        black_box(&plaintext),
                    )
                })
            });

            group.bench_with_input(BenchmarkId::new("ring/decrypt", size), size, |b, _| {
                b.iter(|| {
                    ring_aes::decrypt(
                        black_box(&ring_key),
                        black_box(&ring_nonce),
                        black_box(&ring_ciphertext),
                    )
                })
            });
        }
    }

    group.finish();
}

fn bench_chacha20_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20-Poly1305");

    for size in SIZES {
        let plaintext = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Arcanum
        let (key, nonce) = arcanum_chacha::keygen();
        let ciphertext = arcanum_chacha::encrypt(&key, &nonce, &plaintext);

        group.bench_with_input(BenchmarkId::new("Arcanum/encrypt", size), size, |b, _| {
            b.iter(|| {
                arcanum_chacha::encrypt(black_box(&key), black_box(&nonce), black_box(&plaintext))
            })
        });

        group.bench_with_input(BenchmarkId::new("Arcanum/decrypt", size), size, |b, _| {
            b.iter(|| {
                arcanum_chacha::decrypt(black_box(&key), black_box(&nonce), black_box(&ciphertext))
            })
        });

        // RustCrypto (direct)
        let (rc_key, rc_nonce) = rustcrypto_chacha::keygen();
        let rc_ciphertext = rustcrypto_chacha::encrypt(&rc_key, &rc_nonce, &plaintext);

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    rustcrypto_chacha::encrypt(
                        black_box(&rc_key),
                        black_box(&rc_nonce),
                        black_box(&plaintext),
                    )
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    rustcrypto_chacha::decrypt(
                        black_box(&rc_key),
                        black_box(&rc_nonce),
                        black_box(&rc_ciphertext),
                    )
                })
            },
        );

        // ring (when feature enabled)
        #[cfg(feature = "bench-ring")]
        {
            let (ring_key, ring_nonce) = ring_chacha::keygen();
            let ring_ciphertext = ring_chacha::encrypt(&ring_key, &ring_nonce, &plaintext);

            group.bench_with_input(BenchmarkId::new("ring/encrypt", size), size, |b, _| {
                b.iter(|| {
                    ring_chacha::encrypt(
                        black_box(&ring_key),
                        black_box(&ring_nonce),
                        black_box(&plaintext),
                    )
                })
            });

            group.bench_with_input(BenchmarkId::new("ring/decrypt", size), size, |b, _| {
                b.iter(|| {
                    ring_chacha::decrypt(
                        black_box(&ring_key),
                        black_box(&ring_nonce),
                        black_box(&ring_ciphertext),
                    )
                })
            });
        }
    }

    group.finish();
}

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyGeneration");

    group.bench_function("Arcanum/AES-256-GCM", |b| b.iter(|| arcanum_aes::keygen()));

    group.bench_function("Arcanum/ChaCha20-Poly1305", |b| {
        b.iter(|| arcanum_chacha::keygen())
    });

    group.bench_function("RustCrypto/AES-256-GCM", |b| {
        b.iter(|| rustcrypto_aes::keygen())
    });

    group.bench_function("RustCrypto/ChaCha20-Poly1305", |b| {
        b.iter(|| rustcrypto_chacha::keygen())
    });

    #[cfg(feature = "bench-ring")]
    {
        group.bench_function("ring/AES-256-GCM", |b| b.iter(|| ring_aes::keygen()));

        group.bench_function("ring/ChaCha20-Poly1305", |b| {
            b.iter(|| ring_chacha::keygen())
        });
    }

    group.finish();
}

fn bench_algorithm_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("AlgorithmComparison/4KB");

    let plaintext = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    // Arcanum AES-256-GCM
    let (aes_key, aes_nonce) = arcanum_aes::keygen();
    group.bench_function("Arcanum/AES-256-GCM", |b| {
        b.iter(|| {
            arcanum_aes::encrypt(
                black_box(&aes_key),
                black_box(&aes_nonce),
                black_box(&plaintext),
            )
        })
    });

    // Arcanum ChaCha20-Poly1305
    let (chacha_key, chacha_nonce) = arcanum_chacha::keygen();
    group.bench_function("Arcanum/ChaCha20-Poly1305", |b| {
        b.iter(|| {
            arcanum_chacha::encrypt(
                black_box(&chacha_key),
                black_box(&chacha_nonce),
                black_box(&plaintext),
            )
        })
    });

    // RustCrypto AES-256-GCM
    let (rc_aes_key, rc_aes_nonce) = rustcrypto_aes::keygen();
    group.bench_function("RustCrypto/AES-256-GCM", |b| {
        b.iter(|| {
            rustcrypto_aes::encrypt(
                black_box(&rc_aes_key),
                black_box(&rc_aes_nonce),
                black_box(&plaintext),
            )
        })
    });

    // RustCrypto ChaCha20-Poly1305
    let (rc_chacha_key, rc_chacha_nonce) = rustcrypto_chacha::keygen();
    group.bench_function("RustCrypto/ChaCha20-Poly1305", |b| {
        b.iter(|| {
            rustcrypto_chacha::encrypt(
                black_box(&rc_chacha_key),
                black_box(&rc_chacha_nonce),
                black_box(&plaintext),
            )
        })
    });

    #[cfg(feature = "bench-ring")]
    {
        let (ring_aes_key, ring_aes_nonce) = ring_aes::keygen();
        group.bench_function("ring/AES-256-GCM", |b| {
            b.iter(|| {
                ring_aes::encrypt(
                    black_box(&ring_aes_key),
                    black_box(&ring_aes_nonce),
                    black_box(&plaintext),
                )
            })
        });

        let (ring_chacha_key, ring_chacha_nonce) = ring_chacha::keygen();
        group.bench_function("ring/ChaCha20-Poly1305", |b| {
            b.iter(|| {
                ring_chacha::encrypt(
                    black_box(&ring_chacha_key),
                    black_box(&ring_chacha_nonce),
                    black_box(&plaintext),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_aes256_gcm,
    bench_chacha20_poly1305,
    bench_keygen,
    bench_algorithm_comparison,
);
criterion_main!(benches);
