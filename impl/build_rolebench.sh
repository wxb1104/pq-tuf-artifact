#!/usr/bin/env bash
set -e
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/pqbench" && pwd)"
echo "=== building rolebench (AVX2/native) ==="
cargo build --release --bin rolebench 2>&1 | tail -15
ROOT="$(cd "$PWD/../.." && pwd)"; mkdir -p "$ROOT/results/e4_latency/avx2"
echo "=== running rolebench AVX2 (1000 iters) ==="
./target/release/rolebench "$ROOT/results/e4_latency/avx2" 1000
echo "=== ROLEBENCH AVX2 DONE ==="
