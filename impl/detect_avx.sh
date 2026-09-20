#!/usr/bin/env bash
echo "--- cpu flags ---"
grep -o -m1 -E 'avx2|avx512f|avx ' /proc/cpuinfo | sort -u
grep -m1 'model name' /proc/cpuinfo
echo "nproc=$(nproc)"
echo "--- toolchain ---"
which objdump || echo "no objdump"
echo "--- avx2 insn count in current binaries ---"
for b in pqbench bridge; do
  f="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pqbench/target/release/$b"
  if [ -f "$f" ]; then
    if command -v objdump >/dev/null; then
      n=$(objdump -d "$f" 2>/dev/null | grep -cE '%ymm|vpmov|vpand|vpor ')
      echo "$b avx2-ish-insns=$n"
    else
      echo "$b exists (no objdump)"
    fi
  else
    echo "$b missing"
  fi
done
