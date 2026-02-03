#!/bin/bash
# Phase 1 — P0: Feature Profile Compilation (TDD-CORE-NOSTD-001 §1.1)
# Verifies the crate compiles under all primary feature profiles.
set -e

echo "=== Profile: bare no_std ==="
cargo check -p arcanum-core --no-default-features

echo "=== Profile: no_std + alloc ==="
cargo check -p arcanum-core --no-default-features --features alloc

echo "=== Profile: no_std + alloc + encoding ==="
cargo check -p arcanum-core --no-default-features --features "alloc,encoding"

echo "=== Profile: no_std + alloc + encoding + serde ==="
cargo check -p arcanum-core --no-default-features --features "alloc,encoding,serde"

echo "=== Profile: full std (regression) ==="
cargo check -p arcanum-core

echo "ALL PROFILES PASS"
