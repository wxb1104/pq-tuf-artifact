#!/usr/bin/env bash
# Build a portable (clean-C, no AVX/AVX2) variant into a separate target dir,
# verify no ymm/AVX2 instructions were emitted, then run E1 and E4 on it.
set -e
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/pqbench" && pwd)"
PD="$PWD/target-portable"; ROOT="$(cd "$PWD/../.." && pwd)"

echo "=== building PORTABLE (target-cpu=x86-64, -mno-avx2) ==="
export CARGO_TARGET_DIR="$PD"
export RUSTFLAGS="-C target-cpu=x86-64 -C target-feature=-avx,-avx2"
export CFLAGS="-O3 -fPIC -mno-avx -mno-avx2"
cargo build --release --bins 2>&1 | tail -4

echo "=== AVX2 instruction audit (want ~0) ==="
for b in pqbench rolebench bridge; do
  f="$PD/release/$b"
  [ -f "$f" ] && echo "$b ymm-count=$(objdump -d "$f" 2>/dev/null | grep -cE '%ymm|vpmov|vpand|vpor ')"
done

echo "=== E1 portable primitives ==="
E1P="$ROOT/results/e1_primitives/portable"
mkdir -p "$E1P"
"$PD/release/pqbench" "$E1P"

echo "=== E4 portable role verification ==="
E4P="$ROOT/results/e4_latency/portable"
mkdir -p "$E4P"
"$PD/release/rolebench" "$E4P" 1000
echo "=== PORTABLE DONE ==="
