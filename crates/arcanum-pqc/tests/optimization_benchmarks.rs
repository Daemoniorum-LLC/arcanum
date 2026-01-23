//! ML-DSA Optimization Benchmark Tests (TDD Red Phase)
//!
//! These tests assert performance targets from SPEC-OPT-MLDSA-001.
//! They are designed to FAIL with the current unoptimized implementation.
//!
//! ## Usage
//!
//! Run with release optimizations for accurate timing:
//! ```
//! cargo test --package arcanum-pqc --test optimization_benchmarks --release --features ml-dsa-native
//! ```
//!
//! ## Test Categories
//!
//! - `target_*`: Performance targets (expected to fail initially)
//! - `correctness_*`: Functional correctness (must always pass)
//! - `baseline_*`: Record current performance (informational)

#![cfg(feature = "ml-dsa-native")]
#![allow(dead_code, unused_imports)]

use std::time::{Duration, Instant};

use arcanum_pqc::ml_dsa::keygen::generate_keypair_internal;
use arcanum_pqc::ml_dsa::params::{Params44, Params65, Params87};
use arcanum_pqc::ml_dsa::poly::Poly;
use arcanum_pqc::ml_dsa::{MlDsa, MlDsa44, MlDsa65, MlDsa87};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants: Performance Targets from SPEC-OPT-MLDSA-001
// ═══════════════════════════════════════════════════════════════════════════════

/// Minimum Viable Optimization targets
mod mvo_targets {
    use std::time::Duration;

    /// ML-DSA-65 keygen MVO target
    pub const KEYGEN_65: Duration = Duration::from_micros(100);
    /// ML-DSA-65 sign MVO target
    pub const SIGN_65: Duration = Duration::from_micros(150);
    /// ML-DSA-65 verify MVO target
    pub const VERIFY_65: Duration = Duration::from_micros(80);

    /// ML-DSA-44 targets (proportionally lower)
    pub const KEYGEN_44: Duration = Duration::from_micros(60);
    pub const SIGN_44: Duration = Duration::from_micros(100);
    pub const VERIFY_44: Duration = Duration::from_micros(50);

    /// ML-DSA-87 targets (proportionally higher)
    pub const KEYGEN_87: Duration = Duration::from_micros(150);
    pub const SIGN_87: Duration = Duration::from_micros(300);
    pub const VERIFY_87: Duration = Duration::from_micros(120);
}

/// Stretch goal targets
mod stretch_targets {
    use std::time::Duration;

    pub const KEYGEN_65: Duration = Duration::from_micros(60);
    pub const SIGN_65: Duration = Duration::from_micros(90);
    pub const VERIFY_65: Duration = Duration::from_micros(50);
}

/// Component-level targets
mod component_targets {
    use std::time::Duration;

    /// NTT transform (single polynomial)
    pub const NTT_SINGLE: Duration = Duration::from_micros(5);
    /// Batch NTT (4 polynomials)
    pub const NTT_BATCH_4: Duration = Duration::from_micros(8);
    /// Polynomial addition
    pub const POLY_ADD: Duration = Duration::from_nanos(50);
    /// Polynomial reduction
    pub const POLY_REDUCE: Duration = Duration::from_nanos(100);
    /// ExpandA (ML-DSA-65)
    pub const EXPAND_A_65: Duration = Duration::from_micros(40);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a random-ish polynomial for benchmarking
fn random_poly(seed: u32) -> Poly {
    let mut poly = Poly::zero();
    for i in 0..256 {
        // Deterministic pseudo-random coefficients
        poly.coeffs[i] =
            ((seed.wrapping_mul(i as u32 + 1).wrapping_add(0x9e3779b9)) % 8380417) as i32;
    }
    poly
}

/// Benchmark helper: run function N times and return average duration
fn benchmark<F: FnMut()>(mut f: F, iterations: u32) -> Duration {
    // Warmup
    for _ in 0..10 {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    start.elapsed() / iterations
}

// ═══════════════════════════════════════════════════════════════════════════════
// Baseline Tests (Informational - record current performance)
// ═══════════════════════════════════════════════════════════════════════════════

/// Record baseline keygen performance (informational, always passes)
#[test]
fn baseline_mldsa65_keygen() {
    let elapsed = benchmark(
        || {
            let _ = MlDsa65::generate_keypair();
        },
        50,
    );

    println!("BASELINE ML-DSA-65 keygen: {:?}", elapsed);
    println!("  MVO target: {:?}", mvo_targets::KEYGEN_65);
    println!(
        "  Gap: {:.2}x",
        elapsed.as_nanos() as f64 / mvo_targets::KEYGEN_65.as_nanos() as f64
    );
}

/// Record baseline sign performance
#[test]
fn baseline_mldsa65_sign() {
    let (sk, _) = MlDsa65::generate_keypair();
    let msg = b"benchmark message for signing performance test";

    let elapsed = benchmark(
        || {
            let _ = MlDsa65::sign(&sk, msg);
        },
        50,
    );

    println!("BASELINE ML-DSA-65 sign: {:?}", elapsed);
    println!("  MVO target: {:?}", mvo_targets::SIGN_65);
    println!(
        "  Gap: {:.2}x",
        elapsed.as_nanos() as f64 / mvo_targets::SIGN_65.as_nanos() as f64
    );
}

/// Record baseline verify performance
#[test]
fn baseline_mldsa65_verify() {
    let (sk, vk) = MlDsa65::generate_keypair();
    let msg = b"benchmark message for verification performance test";
    let sig = MlDsa65::sign(&sk, msg);

    let elapsed = benchmark(
        || {
            let _ = MlDsa65::verify(&vk, msg, &sig);
        },
        100,
    );

    println!("BASELINE ML-DSA-65 verify: {:?}", elapsed);
    println!("  MVO target: {:?}", mvo_targets::VERIFY_65);
    println!(
        "  Gap: {:.2}x",
        elapsed.as_nanos() as f64 / mvo_targets::VERIFY_65.as_nanos() as f64
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MVO Target Tests (RED PHASE - expected to fail initially)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-44 keygen must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa44_keygen_mvo() {
    let elapsed = benchmark(
        || {
            let _ = MlDsa44::generate_keypair();
        },
        100,
    );

    assert!(
        elapsed < mvo_targets::KEYGEN_44,
        "ML-DSA-44 keygen {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::KEYGEN_44,
        elapsed.as_nanos() as f64 / mvo_targets::KEYGEN_44.as_nanos() as f64
    );
}

/// ML-DSA-44 sign must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa44_sign_mvo() {
    let (sk, _) = MlDsa44::generate_keypair();
    let msg = b"benchmark message";

    let elapsed = benchmark(
        || {
            let _ = MlDsa44::sign(&sk, msg);
        },
        100,
    );

    assert!(
        elapsed < mvo_targets::SIGN_44,
        "ML-DSA-44 sign {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::SIGN_44,
        elapsed.as_nanos() as f64 / mvo_targets::SIGN_44.as_nanos() as f64
    );
}

/// ML-DSA-44 verify must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa44_verify_mvo() {
    let (sk, vk) = MlDsa44::generate_keypair();
    let msg = b"benchmark message";
    let sig = MlDsa44::sign(&sk, msg);

    let elapsed = benchmark(
        || {
            let _ = MlDsa44::verify(&vk, msg, &sig);
        },
        100,
    );

    assert!(
        elapsed < mvo_targets::VERIFY_44,
        "ML-DSA-44 verify {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::VERIFY_44,
        elapsed.as_nanos() as f64 / mvo_targets::VERIFY_44.as_nanos() as f64
    );
}

/// ML-DSA-65 keygen must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa65_keygen_mvo() {
    let elapsed = benchmark(
        || {
            let _ = MlDsa65::generate_keypair();
        },
        100,
    );

    assert!(
        elapsed < mvo_targets::KEYGEN_65,
        "ML-DSA-65 keygen {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::KEYGEN_65,
        elapsed.as_nanos() as f64 / mvo_targets::KEYGEN_65.as_nanos() as f64
    );
}

/// ML-DSA-65 sign must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa65_sign_mvo() {
    let (sk, _) = MlDsa65::generate_keypair();
    let msg = b"benchmark message";

    let elapsed = benchmark(
        || {
            let _ = MlDsa65::sign(&sk, msg);
        },
        100,
    );

    assert!(
        elapsed < mvo_targets::SIGN_65,
        "ML-DSA-65 sign {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::SIGN_65,
        elapsed.as_nanos() as f64 / mvo_targets::SIGN_65.as_nanos() as f64
    );
}

/// ML-DSA-65 verify must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa65_verify_mvo() {
    let (sk, vk) = MlDsa65::generate_keypair();
    let msg = b"benchmark message";
    let sig = MlDsa65::sign(&sk, msg);

    let elapsed = benchmark(
        || {
            let _ = MlDsa65::verify(&vk, msg, &sig);
        },
        100,
    );

    assert!(
        elapsed < mvo_targets::VERIFY_65,
        "ML-DSA-65 verify {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::VERIFY_65,
        elapsed.as_nanos() as f64 / mvo_targets::VERIFY_65.as_nanos() as f64
    );
}

/// ML-DSA-87 keygen must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa87_keygen_mvo() {
    let elapsed = benchmark(
        || {
            let _ = MlDsa87::generate_keypair();
        },
        50,
    );

    assert!(
        elapsed < mvo_targets::KEYGEN_87,
        "ML-DSA-87 keygen {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::KEYGEN_87,
        elapsed.as_nanos() as f64 / mvo_targets::KEYGEN_87.as_nanos() as f64
    );
}

/// ML-DSA-87 sign must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa87_sign_mvo() {
    let (sk, _) = MlDsa87::generate_keypair();
    let msg = b"benchmark message";

    let elapsed = benchmark(
        || {
            let _ = MlDsa87::sign(&sk, msg);
        },
        50,
    );

    assert!(
        elapsed < mvo_targets::SIGN_87,
        "ML-DSA-87 sign {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::SIGN_87,
        elapsed.as_nanos() as f64 / mvo_targets::SIGN_87.as_nanos() as f64
    );
}

/// ML-DSA-87 verify must meet MVO target
#[test]
#[ignore = "RED PHASE: Optimization not yet implemented"]
fn target_mldsa87_verify_mvo() {
    let (sk, vk) = MlDsa87::generate_keypair();
    let msg = b"benchmark message";
    let sig = MlDsa87::sign(&sk, msg);

    let elapsed = benchmark(
        || {
            let _ = MlDsa87::verify(&vk, msg, &sig);
        },
        50,
    );

    assert!(
        elapsed < mvo_targets::VERIFY_87,
        "ML-DSA-87 verify {:?} exceeds MVO target {:?} (gap: {:.2}x)",
        elapsed,
        mvo_targets::VERIFY_87,
        elapsed.as_nanos() as f64 / mvo_targets::VERIFY_87.as_nanos() as f64
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Component-Level Target Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// NTT single polynomial must meet target
#[test]
#[ignore = "RED PHASE: AVX2 NTT not yet implemented"]
fn target_ntt_single() {
    let mut poly = random_poly(12345);

    let elapsed = benchmark(
        || {
            poly.ntt();
            poly.inv_ntt();
        },
        1000,
    );

    // Divide by 2 since we did both NTT and InvNTT
    let per_transform = elapsed / 2;

    assert!(
        per_transform < component_targets::NTT_SINGLE,
        "NTT {:?} exceeds target {:?} (gap: {:.2}x)",
        per_transform,
        component_targets::NTT_SINGLE,
        per_transform.as_nanos() as f64 / component_targets::NTT_SINGLE.as_nanos() as f64
    );
}

/// Polynomial addition must meet target
#[test]
#[ignore = "RED PHASE: SIMD poly ops not yet implemented"]
fn target_poly_add() {
    let a = random_poly(111);
    let b = random_poly(222);

    let elapsed = benchmark(
        || {
            let _ = a.add(&b);
        },
        10000,
    );

    assert!(
        elapsed < component_targets::POLY_ADD,
        "poly_add {:?} exceeds target {:?} (gap: {:.2}x)",
        elapsed,
        component_targets::POLY_ADD,
        elapsed.as_nanos() as f64 / component_targets::POLY_ADD.as_nanos() as f64
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Stretch Goal Target Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-65 keygen stretch goal
#[test]
#[ignore = "STRETCH GOAL: Requires all optimizations"]
fn target_mldsa65_keygen_stretch() {
    let elapsed = benchmark(
        || {
            let _ = MlDsa65::generate_keypair();
        },
        100,
    );

    assert!(
        elapsed < stretch_targets::KEYGEN_65,
        "ML-DSA-65 keygen {:?} exceeds stretch target {:?}",
        elapsed,
        stretch_targets::KEYGEN_65
    );
}

/// ML-DSA-65 sign stretch goal
#[test]
#[ignore = "STRETCH GOAL: Requires all optimizations"]
fn target_mldsa65_sign_stretch() {
    let (sk, _) = MlDsa65::generate_keypair();
    let msg = b"benchmark message";

    let elapsed = benchmark(
        || {
            let _ = MlDsa65::sign(&sk, msg);
        },
        100,
    );

    assert!(
        elapsed < stretch_targets::SIGN_65,
        "ML-DSA-65 sign {:?} exceeds stretch target {:?}",
        elapsed,
        stretch_targets::SIGN_65
    );
}

/// ML-DSA-65 verify stretch goal
#[test]
#[ignore = "STRETCH GOAL: Requires all optimizations"]
fn target_mldsa65_verify_stretch() {
    let (sk, vk) = MlDsa65::generate_keypair();
    let msg = b"benchmark message";
    let sig = MlDsa65::sign(&sk, msg);

    let elapsed = benchmark(
        || {
            let _ = MlDsa65::verify(&vk, msg, &sig);
        },
        100,
    );

    assert!(
        elapsed < stretch_targets::VERIFY_65,
        "ML-DSA-65 verify {:?} exceeds stretch target {:?}",
        elapsed,
        stretch_targets::VERIFY_65
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Correctness Tests (Must Always Pass)
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify optimizations don't break correctness
#[test]
fn correctness_sign_verify_roundtrip() {
    for _ in 0..10 {
        let (sk, vk) = MlDsa65::generate_keypair();
        let msg = b"correctness test message";
        let sig = MlDsa65::sign(&sk, msg);

        assert!(
            MlDsa65::verify(&vk, msg, &sig).is_ok(),
            "Sign/verify roundtrip failed"
        );
    }
}

/// Verify keygen is deterministic with same seed
#[test]
fn correctness_keygen_determinism() {
    let seed = [42u8; 32];

    let kp1 = generate_keypair_internal::<Params65>(&seed);
    let kp2 = generate_keypair_internal::<Params65>(&seed);

    assert_eq!(kp1.rho, kp2.rho, "Keygen not deterministic");
}

/// Verify all parameter sets work correctly
#[test]
fn correctness_all_param_sets() {
    // ML-DSA-44
    let (sk44, vk44) = MlDsa44::generate_keypair();
    let sig44 = MlDsa44::sign(&sk44, b"test44");
    assert!(MlDsa44::verify(&vk44, b"test44", &sig44).is_ok());

    // ML-DSA-65
    let (sk65, vk65) = MlDsa65::generate_keypair();
    let sig65 = MlDsa65::sign(&sk65, b"test65");
    assert!(MlDsa65::verify(&vk65, b"test65", &sig65).is_ok());

    // ML-DSA-87
    let (sk87, vk87) = MlDsa87::generate_keypair();
    let sig87 = MlDsa87::sign(&sk87, b"test87");
    assert!(MlDsa87::verify(&vk87, b"test87", &sig87).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Summary Report
// ═══════════════════════════════════════════════════════════════════════════════

/// Print comprehensive performance summary
#[test]
fn report_performance_summary() {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║         ML-DSA OPTIMIZATION BENCHMARK REPORT                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ML-DSA-44
    let keygen44 = benchmark(
        || {
            let _ = MlDsa44::generate_keypair();
        },
        50,
    );
    let (sk44, vk44) = MlDsa44::generate_keypair();
    let sign44 = benchmark(
        || {
            let _ = MlDsa44::sign(&sk44, b"msg");
        },
        50,
    );
    let sig44 = MlDsa44::sign(&sk44, b"msg");
    let verify44 = benchmark(
        || {
            let _ = MlDsa44::verify(&vk44, b"msg", &sig44);
        },
        100,
    );

    // ML-DSA-65
    let keygen65 = benchmark(
        || {
            let _ = MlDsa65::generate_keypair();
        },
        50,
    );
    let (sk65, vk65) = MlDsa65::generate_keypair();
    let sign65 = benchmark(
        || {
            let _ = MlDsa65::sign(&sk65, b"msg");
        },
        50,
    );
    let sig65 = MlDsa65::sign(&sk65, b"msg");
    let verify65 = benchmark(
        || {
            let _ = MlDsa65::verify(&vk65, b"msg", &sig65);
        },
        100,
    );

    // ML-DSA-87
    let keygen87 = benchmark(
        || {
            let _ = MlDsa87::generate_keypair();
        },
        30,
    );
    let (sk87, vk87) = MlDsa87::generate_keypair();
    let sign87 = benchmark(
        || {
            let _ = MlDsa87::sign(&sk87, b"msg");
        },
        30,
    );
    let sig87 = MlDsa87::sign(&sk87, b"msg");
    let verify87 = benchmark(
        || {
            let _ = MlDsa87::verify(&vk87, b"msg", &sig87);
        },
        50,
    );

    println!("┌──────────────┬────────────┬────────────┬────────────┐");
    println!("│ Operation    │  Current   │ MVO Target │    Gap     │");
    println!("├──────────────┼────────────┼────────────┼────────────┤");

    let gap = |current: Duration, target: Duration| -> String {
        format!(
            "{:.2}x",
            current.as_nanos() as f64 / target.as_nanos() as f64
        )
    };

    println!(
        "│ DSA-44 keygen│ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        keygen44,
        mvo_targets::KEYGEN_44,
        gap(keygen44, mvo_targets::KEYGEN_44)
    );
    println!(
        "│ DSA-44 sign  │ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        sign44,
        mvo_targets::SIGN_44,
        gap(sign44, mvo_targets::SIGN_44)
    );
    println!(
        "│ DSA-44 verify│ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        verify44,
        mvo_targets::VERIFY_44,
        gap(verify44, mvo_targets::VERIFY_44)
    );
    println!("├──────────────┼────────────┼────────────┼────────────┤");
    println!(
        "│ DSA-65 keygen│ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        keygen65,
        mvo_targets::KEYGEN_65,
        gap(keygen65, mvo_targets::KEYGEN_65)
    );
    println!(
        "│ DSA-65 sign  │ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        sign65,
        mvo_targets::SIGN_65,
        gap(sign65, mvo_targets::SIGN_65)
    );
    println!(
        "│ DSA-65 verify│ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        verify65,
        mvo_targets::VERIFY_65,
        gap(verify65, mvo_targets::VERIFY_65)
    );
    println!("├──────────────┼────────────┼────────────┼────────────┤");
    println!(
        "│ DSA-87 keygen│ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        keygen87,
        mvo_targets::KEYGEN_87,
        gap(keygen87, mvo_targets::KEYGEN_87)
    );
    println!(
        "│ DSA-87 sign  │ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        sign87,
        mvo_targets::SIGN_87,
        gap(sign87, mvo_targets::SIGN_87)
    );
    println!(
        "│ DSA-87 verify│ {:>8.1?} │ {:>8.1?} │ {:>10} │",
        verify87,
        mvo_targets::VERIFY_87,
        gap(verify87, mvo_targets::VERIFY_87)
    );
    println!("└──────────────┴────────────┴────────────┴────────────┘");

    println!("\nTarget Status: MVO = Minimum Viable Optimization");
    println!("Gap > 1.0x means current performance exceeds target (needs optimization)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Arcanum-DSA vs ML-DSA Comparison
// ═══════════════════════════════════════════════════════════════════════════════

use arcanum_pqc::arcanum_dsa::{ArcanumDsa, ArcanumDsa44, ArcanumDsa65, ArcanumDsa87};

/// Compare Arcanum-DSA vs ML-DSA performance
#[test]
fn report_arcanum_vs_mldsa_comparison() {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║       ARCANUM-DSA vs ML-DSA PERFORMANCE COMPARISON           ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("Security note: Arcanum-DSA uses SIMD-optimized L values:");
    println!(
        "  - Arcanum-65: K=4, L=8 (dim 3072) vs ML-DSA-65: K=6, L=5 (dim 2816) → +9% security"
    );
    println!(
        "  - Arcanum-87: K=8, L=8 (dim 4096) vs ML-DSA-87: K=8, L=7 (dim 3840) → +7% security\n"
    );

    // ─────────────────────────────────────────────────────────────────────────────
    // Level 2 (44) - Identical parameters
    // ─────────────────────────────────────────────────────────────────────────────
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ LEVEL 2 (44): Parameters identical (K=4, L=4)                   │");
    println!("├─────────────────────────────────────────────────────────────────┤");

    let ml_keygen44 = benchmark(
        || {
            let _ = MlDsa44::generate_keypair();
        },
        50,
    );
    let ar_keygen44 = benchmark(
        || {
            let _ = ArcanumDsa44::generate_keypair();
        },
        50,
    );

    let (ml_sk44, ml_vk44) = MlDsa44::generate_keypair();
    let (ar_sk44, ar_vk44) = ArcanumDsa44::generate_keypair();

    let ml_sign44 = benchmark(
        || {
            let _ = MlDsa44::sign(&ml_sk44, b"msg");
        },
        50,
    );
    let ar_sign44 = benchmark(
        || {
            let _ = ArcanumDsa44::sign(&ar_sk44, b"msg");
        },
        50,
    );

    let ml_sig44 = MlDsa44::sign(&ml_sk44, b"msg");
    let ar_sig44 = ArcanumDsa44::sign(&ar_sk44, b"msg");

    let ml_verify44 = benchmark(
        || {
            let _ = MlDsa44::verify(&ml_vk44, b"msg", &ml_sig44);
        },
        100,
    );
    let ar_verify44 = benchmark(
        || {
            let _ = ArcanumDsa44::verify(&ar_vk44, b"msg", &ar_sig44);
        },
        100,
    );

    println!(
        "│ keygen:  ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_keygen44,
        ar_keygen44,
        ar_keygen44.as_nanos() as f64 / ml_keygen44.as_nanos() as f64
    );
    println!(
        "│ sign:    ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_sign44,
        ar_sign44,
        ar_sign44.as_nanos() as f64 / ml_sign44.as_nanos() as f64
    );
    println!(
        "│ verify:  ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_verify44,
        ar_verify44,
        ar_verify44.as_nanos() as f64 / ml_verify44.as_nanos() as f64
    );
    println!("└─────────────────────────────────────────────────────────────────┘\n");

    // ─────────────────────────────────────────────────────────────────────────────
    // Level 3 (65) - SIMD-optimized
    // ─────────────────────────────────────────────────────────────────────────────
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ LEVEL 3 (65): Arcanum K=4,L=8 vs ML-DSA K=6,L=5                 │");
    println!("├─────────────────────────────────────────────────────────────────┤");

    let ml_keygen65 = benchmark(
        || {
            let _ = MlDsa65::generate_keypair();
        },
        50,
    );
    let ar_keygen65 = benchmark(
        || {
            let _ = ArcanumDsa65::generate_keypair();
        },
        50,
    );

    let (ml_sk65, ml_vk65) = MlDsa65::generate_keypair();
    let (ar_sk65, ar_vk65) = ArcanumDsa65::generate_keypair();

    let ml_sign65 = benchmark(
        || {
            let _ = MlDsa65::sign(&ml_sk65, b"msg");
        },
        50,
    );
    let ar_sign65 = benchmark(
        || {
            let _ = ArcanumDsa65::sign(&ar_sk65, b"msg");
        },
        50,
    );

    let ml_sig65 = MlDsa65::sign(&ml_sk65, b"msg");
    let ar_sig65 = ArcanumDsa65::sign(&ar_sk65, b"msg");

    let ml_verify65 = benchmark(
        || {
            let _ = MlDsa65::verify(&ml_vk65, b"msg", &ml_sig65);
        },
        100,
    );
    let ar_verify65 = benchmark(
        || {
            let _ = ArcanumDsa65::verify(&ar_vk65, b"msg", &ar_sig65);
        },
        100,
    );

    println!(
        "│ keygen:  ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_keygen65,
        ar_keygen65,
        ar_keygen65.as_nanos() as f64 / ml_keygen65.as_nanos() as f64
    );
    println!(
        "│ sign:    ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_sign65,
        ar_sign65,
        ar_sign65.as_nanos() as f64 / ml_sign65.as_nanos() as f64
    );
    println!(
        "│ verify:  ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_verify65,
        ar_verify65,
        ar_verify65.as_nanos() as f64 / ml_verify65.as_nanos() as f64
    );
    println!("└─────────────────────────────────────────────────────────────────┘\n");

    // ─────────────────────────────────────────────────────────────────────────────
    // Level 5 (87) - SIMD-optimized
    // ─────────────────────────────────────────────────────────────────────────────
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ LEVEL 5 (87): Arcanum K=8,L=8 vs ML-DSA K=8,L=7                 │");
    println!("├─────────────────────────────────────────────────────────────────┤");

    let ml_keygen87 = benchmark(
        || {
            let _ = MlDsa87::generate_keypair();
        },
        30,
    );
    let ar_keygen87 = benchmark(
        || {
            let _ = ArcanumDsa87::generate_keypair();
        },
        30,
    );

    let (ml_sk87, ml_vk87) = MlDsa87::generate_keypair();
    let (ar_sk87, ar_vk87) = ArcanumDsa87::generate_keypair();

    let ml_sign87 = benchmark(
        || {
            let _ = MlDsa87::sign(&ml_sk87, b"msg");
        },
        30,
    );
    let ar_sign87 = benchmark(
        || {
            let _ = ArcanumDsa87::sign(&ar_sk87, b"msg");
        },
        30,
    );

    let ml_sig87 = MlDsa87::sign(&ml_sk87, b"msg");
    let ar_sig87 = ArcanumDsa87::sign(&ar_sk87, b"msg");

    let ml_verify87 = benchmark(
        || {
            let _ = MlDsa87::verify(&ml_vk87, b"msg", &ml_sig87);
        },
        50,
    );
    let ar_verify87 = benchmark(
        || {
            let _ = ArcanumDsa87::verify(&ar_vk87, b"msg", &ar_sig87);
        },
        50,
    );

    println!(
        "│ keygen:  ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_keygen87,
        ar_keygen87,
        ar_keygen87.as_nanos() as f64 / ml_keygen87.as_nanos() as f64
    );
    println!(
        "│ sign:    ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_sign87,
        ar_sign87,
        ar_sign87.as_nanos() as f64 / ml_sign87.as_nanos() as f64
    );
    println!(
        "│ verify:  ML-DSA {:>8.1?}  │  Arcanum {:>8.1?}  │  ratio: {:.2}x │",
        ml_verify87,
        ar_verify87,
        ar_verify87.as_nanos() as f64 / ml_verify87.as_nanos() as f64
    );
    println!("└─────────────────────────────────────────────────────────────────┘\n");

    // ─────────────────────────────────────────────────────────────────────────────
    // Size comparison
    // ─────────────────────────────────────────────────────────────────────────────
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ SIZE COMPARISON (bytes)                                         │");
    println!("├───────────┬─────────────┬─────────────┬─────────────────────────┤");
    println!("│ Level     │   ML-DSA    │  Arcanum    │  Diff (Arcanum-ML-DSA)  │");
    println!("├───────────┼─────────────┼─────────────┼─────────────────────────┤");

    use arcanum_pqc::arcanum_dsa::params::{
        Params44 as ArParams44, Params65 as ArParams65, Params87 as ArParams87,
    };
    use arcanum_pqc::ml_dsa::params::{
        MlDsaParams, Params44 as MlParams44, Params65 as MlParams65, Params87 as MlParams87,
    };

    // Level 2 sizes
    println!(
        "│ L2 PK     │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams44::PK_SIZE,
        ArParams44::PK_SIZE,
        ArParams44::PK_SIZE as i32 - MlParams44::PK_SIZE as i32
    );
    println!(
        "│ L2 SK     │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams44::SK_SIZE,
        ArParams44::SK_SIZE,
        ArParams44::SK_SIZE as i32 - MlParams44::SK_SIZE as i32
    );
    println!(
        "│ L2 SIG    │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams44::SIG_SIZE,
        ArParams44::SIG_SIZE,
        ArParams44::SIG_SIZE as i32 - MlParams44::SIG_SIZE as i32
    );
    println!("├───────────┼─────────────┼─────────────┼─────────────────────────┤");

    // Level 3 sizes
    println!(
        "│ L3 PK     │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams65::PK_SIZE,
        ArParams65::PK_SIZE,
        ArParams65::PK_SIZE as i32 - MlParams65::PK_SIZE as i32
    );
    println!(
        "│ L3 SK     │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams65::SK_SIZE,
        ArParams65::SK_SIZE,
        ArParams65::SK_SIZE as i32 - MlParams65::SK_SIZE as i32
    );
    println!(
        "│ L3 SIG    │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams65::SIG_SIZE,
        ArParams65::SIG_SIZE,
        ArParams65::SIG_SIZE as i32 - MlParams65::SIG_SIZE as i32
    );
    println!("├───────────┼─────────────┼─────────────┼─────────────────────────┤");

    // Level 5 sizes
    println!(
        "│ L5 PK     │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams87::PK_SIZE,
        ArParams87::PK_SIZE,
        ArParams87::PK_SIZE as i32 - MlParams87::PK_SIZE as i32
    );
    println!(
        "│ L5 SK     │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams87::SK_SIZE,
        ArParams87::SK_SIZE,
        ArParams87::SK_SIZE as i32 - MlParams87::SK_SIZE as i32
    );
    println!(
        "│ L5 SIG    │    {:>5}    │    {:>5}    │        {:>+6}           │",
        MlParams87::SIG_SIZE,
        ArParams87::SIG_SIZE,
        ArParams87::SIG_SIZE as i32 - MlParams87::SIG_SIZE as i32
    );
    println!("└───────────┴─────────────┴─────────────┴─────────────────────────┘\n");

    println!("Note: Ratio < 1.0 means Arcanum is faster, > 1.0 means slower");
    println!("      Size differences reflect SIMD-friendly L values");
}
