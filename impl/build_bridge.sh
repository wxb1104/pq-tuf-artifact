#!/usr/bin/env bash
set -e
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/pqbench" && pwd)"
cargo build --release --bin bridge 2>&1 | tail -15
echo "===== smoke ====="
printf 'ping\nsizes mldsa65\nsizes fndsa512\nsizes slhdsa128s\nkeygen mldsa44\nquit\n' | ./target/release/bridge
echo "===== BRIDGE BUILD DONE ====="
