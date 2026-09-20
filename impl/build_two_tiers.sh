#!/usr/bin/env bash
# Two PQClean implementation tiers for E1/E4 (fairness, following Paul et al.).
#   portable : scalar clean-C cores AND scalar fips202 Keccak (PQTUF_NO_AVX2),
#              rustc baseline x86-64 (no implicit AVX2) -> AVX2-free binary.
#   avx2     : PQClean AVX2 cores (simd-avx2) + 4x AVX2 Keccak.
# Both use separate target dirs; only PQClean SIMD differs between the two.
set -e
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/pqbench" && pwd)"
ROOT="$(cd "$PWD/../.." && pwd)"
rm -rf target-portable target-avx2

audit() { # $1 = target dir label, $2 = dir
  for b in pqbench rolebench; do
    f="$2/release/$b"
    [ -f "$f" ] && echo "  [$1] $b ymm=$(objdump -d "$f" 2>/dev/null | grep -cE '%ymm')"
  done
}

echo "########## TIER 1: portable / scalar clean-C ##########"
export CARGO_TARGET_DIR="$PWD/target-portable"
export PQTUF_NO_AVX2=1
export RUSTFLAGS="-C target-cpu=x86-64"
cargo build --release --bins 2>&1 | tail -3
audit portable target-portable
mkdir -p "$ROOT/results/e1_primitives/portable" "$ROOT/results/e4_latency/portable"
./target-portable/release/pqbench "$ROOT/results/e1_primitives/portable"
./target-portable/release/rolebench "$ROOT/results/e4_latency/portable" 1000
unset PQTUF_NO_AVX2 RUSTFLAGS

echo "########## TIER 2: AVX2-optimized ##########"
export CARGO_TARGET_DIR="$PWD/target-avx2"
unset PQTUF_NO_AVX2
cargo build --release --features simd-avx2 --bins 2>&1 | tail -3
audit avx2 target-avx2
mkdir -p "$ROOT/results/e1_primitives/avx2" "$ROOT/results/e4_latency/avx2"
./target-avx2/release/pqbench "$ROOT/results/e1_primitives/avx2"
./target-avx2/release/rolebench "$ROOT/results/e4_latency/avx2" 1000
unset CARGO_TARGET_DIR
echo "########## BOTH TIERS DONE ##########"
