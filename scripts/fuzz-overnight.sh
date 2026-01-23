#!/bin/bash
# Overnight fuzzing script for Arcanum cryptographic primitives
#
# Usage:
#   ./scripts/fuzz-overnight.sh              # Run all targets for 8 hours
#   ./scripts/fuzz-overnight.sh 3600         # Run all targets for 1 hour (3600 seconds)
#   ./scripts/fuzz-overnight.sh 0            # Run indefinitely (Ctrl+C to stop)
#
# Prerequisites:
#   cargo install cargo-fuzz
#   rustup default nightly  (or use rustup run nightly)

set -euo pipefail

# Configuration
DURATION_SECS="${1:-28800}"  # Default: 8 hours (28800 seconds)
FUZZ_DIR="$(dirname "$0")/../fuzz"
LOG_DIR="${FUZZ_DIR}/logs"
CORPUS_DIR="${FUZZ_DIR}/corpus"
ARTIFACTS_DIR="${FUZZ_DIR}/artifacts"

# All fuzz targets
TARGETS=(
    "fuzz_aes_gcm"
    "fuzz_chacha20poly1305"
    "fuzz_blake3"
    "fuzz_ed25519"
    "fuzz_x25519"
    "fuzz_p256"
    "fuzz_ml_kem"
    "fuzz_ml_dsa"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            Arcanum Overnight Fuzzing Session                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo

# Create directories
mkdir -p "$LOG_DIR" "$CORPUS_DIR" "$ARTIFACTS_DIR"

# Check for nightly toolchain
if ! rustup run nightly cargo --version &>/dev/null; then
    echo -e "${RED}Error: Nightly Rust toolchain required${NC}"
    echo "Install with: rustup install nightly"
    exit 1
fi

# Check for cargo-fuzz
if ! cargo fuzz --version &>/dev/null; then
    echo -e "${RED}Error: cargo-fuzz not installed${NC}"
    echo "Install with: cargo install cargo-fuzz"
    exit 1
fi

cd "$FUZZ_DIR"

# Calculate time per target
NUM_TARGETS=${#TARGETS[@]}
if [ "$DURATION_SECS" -gt 0 ]; then
    TIME_PER_TARGET=$((DURATION_SECS / NUM_TARGETS))
    echo -e "${YELLOW}Duration: ${DURATION_SECS}s total, ${TIME_PER_TARGET}s per target${NC}"
else
    TIME_PER_TARGET=0
    echo -e "${YELLOW}Duration: Running indefinitely (Ctrl+C to stop)${NC}"
fi

echo -e "${YELLOW}Targets: ${NUM_TARGETS}${NC}"
echo -e "${YELLOW}Log directory: ${LOG_DIR}${NC}"
echo

# Timestamp for this run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Track results
declare -A RESULTS

# Function to run a single fuzz target
run_fuzz_target() {
    local target="$1"
    local duration="$2"
    local log_file="${LOG_DIR}/${TIMESTAMP}_${target}.log"

    echo -e "${BLUE}[$(date +%H:%M:%S)] Starting: ${target}${NC}"

    local args=("-j$(nproc)")
    if [ "$duration" -gt 0 ]; then
        args+=("--" "-max_total_time=$duration")
    fi

    if cargo fuzz run "$target" "${args[@]}" &> "$log_file"; then
        echo -e "${GREEN}[$(date +%H:%M:%S)] Completed: ${target} (no crashes)${NC}"
        RESULTS[$target]="OK"
    else
        local exit_code=$?
        if [ $exit_code -eq 77 ]; then
            # Exit code 77 means crash found
            echo -e "${RED}[$(date +%H:%M:%S)] CRASH FOUND: ${target}${NC}"
            RESULTS[$target]="CRASH"
            # Copy artifacts
            if [ -d "${FUZZ_DIR}/artifacts/${target}" ]; then
                cp -r "${FUZZ_DIR}/artifacts/${target}" "${ARTIFACTS_DIR}/${TIMESTAMP}_${target}"
            fi
        else
            echo -e "${YELLOW}[$(date +%H:%M:%S)] Finished: ${target} (exit code: ${exit_code})${NC}"
            RESULTS[$target]="EXIT:$exit_code"
        fi
    fi
}

# Trap Ctrl+C for clean shutdown
cleanup() {
    echo
    echo -e "${YELLOW}Received interrupt signal, cleaning up...${NC}"
    pkill -P $$ 2>/dev/null || true
    print_summary
    exit 0
}
trap cleanup SIGINT SIGTERM

# Print summary
print_summary() {
    echo
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                      Fuzzing Summary                           ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo

    local crashes=0
    local ok=0

    for target in "${TARGETS[@]}"; do
        local result="${RESULTS[$target]:-NOT_RUN}"
        if [ "$result" = "OK" ]; then
            echo -e "  ${GREEN}✓${NC} $target"
            ((ok++))
        elif [ "$result" = "CRASH" ]; then
            echo -e "  ${RED}✗${NC} $target - CRASH FOUND!"
            ((crashes++))
        elif [ "$result" = "NOT_RUN" ]; then
            echo -e "  ${YELLOW}○${NC} $target - Not run"
        else
            echo -e "  ${YELLOW}?${NC} $target - $result"
        fi
    done

    echo
    echo -e "Logs saved to: ${LOG_DIR}"

    if [ $crashes -gt 0 ]; then
        echo -e "${RED}WARNING: $crashes crash(es) found!${NC}"
        echo -e "Check artifacts in: ${ARTIFACTS_DIR}"
        exit 1
    else
        echo -e "${GREEN}All targets completed without crashes.${NC}"
    fi
}

# Run all targets sequentially
echo -e "${YELLOW}Starting fuzzing at $(date)${NC}"
echo

for target in "${TARGETS[@]}"; do
    run_fuzz_target "$target" "$TIME_PER_TARGET"
done

print_summary
