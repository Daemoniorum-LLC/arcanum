#!/bin/bash
# Phase 5 — P2: Feature Combination Matrix (TDD-CORE-NOSTD-001 §5.2)
# Verifies all valid feature combinations compile cleanly.
set -e

FEATURES=(
    ""
    "alloc"
    "alloc,encoding"
    "alloc,encoding,serde"
    "alloc,serde"
    "alloc,async"
    "alloc,encoding,serde,async"
    "std"
    "std,serde"
    "std,encoding"
    "std,encoding,serde"
    "std,encoding,serde,async"
    "std,encoding,serde,async,hazmat"
)

for feat in "${FEATURES[@]}"; do
    if [ -z "$feat" ]; then
        echo "=== --no-default-features ==="
        cargo check -p arcanum-core --no-default-features
    else
        echo "=== --no-default-features --features $feat ==="
        cargo check -p arcanum-core --no-default-features --features "$feat"
    fi
done

echo "=== default features (regression) ==="
cargo check -p arcanum-core
cargo test -p arcanum-core

echo "ALL FEATURE COMBINATIONS PASS"
