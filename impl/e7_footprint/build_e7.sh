#!/usr/bin/env bash
# E7 verify-only footprint from PQClean C, two tiers.
# Usage: bash build_e7.sh [scheme_key ...]   (default: all)
set -u
# Locate the cargo registry root (run `cargo fetch` or build_bridge.sh first).
REG="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 1 -type d 2>/dev/null | sort | tail -1)"
# all schemes live (vendored, self-contained) under the dilithium crate tree
PQ="$REG/pqcrypto-dilithium-0.5.0/pqclean/crypto_sign"
if [ ! -d "$PQ" ]; then
  PQ="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 3 -type d -path "*pqcrypto-dilithium-*/pqclean/crypto_sign" 2>/dev/null | head -1)"
fi
if [ -z "$PQ" ] || [ ! -d "$PQ" ]; then
  echo "PQClean not found; run (cd impl/pqbench && cargo fetch) then retry." >&2; exit 1
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=$ROOT/impl/e7_footprint/build
OUT=$ROOT/results/e7_budget
mkdir -p "$OUT" "$WORK"

# key|pqclean-dir
SCHEMES=(
  "mldsa44|dilithium2"
  "mldsa65|dilithium3"
  "mldsa87|dilithium5"
  "fndsa512|falcon-512"
  "fndsa1024|falcon-1024"
  "slhdsa128s|sphincs-sha2-128s-simple"
  "slhdsa128f|sphincs-sha2-128f-simple"
  "slhdsa256s|sphincs-sha2-256s-simple"
  "slhdsa256f|sphincs-sha2-256f-simple"
)
if [ "$#" -gt 0 ]; then FILTER=("$@"); else FILTER=(); fi

echo "scheme,tier,impl,flash_code_B,rodata_B,data_B,bss_B,flash_total_B,static_ram_B,heap_peak_verify_B,max_stack_frame_B" \
  > "$OUT/e7_footprint.csv"

build_one () {
  local key="$1" dir="$2" tier="$3" impl="$4"
  local src="$PQ/$dir/$impl"
  local w="$WORK/$tier/$key"; mkdir -p "$w"; rm -f "$w"/*.o "$w"/*.su "$w"/a.out
  if [ "$tier" = "portable" ]; then
    local CF="-O3 -ffunction-sections -fdata-sections -march=x86-64 -mno-avx2 -fstack-usage"
  else
    local CF="-O3 -ffunction-sections -fdata-sections -march=native -fstack-usage"
  fi
  # compile scheme objects
  local f
  for f in "$src"/*.c; do
    gcc $CF -I"$src" -c "$f" -o "$w/$(basename "${f%.c}").o" || return 1
  done
  if [ "$tier" = "avx2" ]; then
    local s
    for s in "$src"/*.S; do
      [ -e "$s" ] || continue
      gcc -O3 -march=native -I"$src" -c "$s" -o "$w/$(basename "${s%.S}").o" || return 1
    done
  fi
  # harness + link, gc-sections, malloc wrap
  gcc $CF -I"$src" -c "$ROOT/impl/e7_footprint/harness.c" -o "$w/harness.o" || return 1
  gcc $CF -o "$w/a.out" "$w"/*.o \
     -Wl,--gc-sections \
     -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free -Wl,--wrap=realloc \
     || return 1
  local run; run="$("$w/a.out")"; echo "  [$key/$tier/$impl] $run"
  local heap; heap="$(echo "$run" | sed -n 's/.*HEAP_PEAK=\([0-9]*\).*/\1/p')"
  [ -n "$heap" ] || heap="RUN_FAIL"
  # nm: sum PQCLEAN symbols by section class
  local sums
  sums="$(nm --print-size --size-sort "$w/a.out" 2>/dev/null \
    | grep PQCLEAN | awk '{sz=strtonum("0x"$2); t=$3;
        if(t=="T"||t=="t") code+=sz;
        else if(t=="R"||t=="r"||t=="C"||t=="c") rod+=sz;
        else if(t=="D"||t=="d"||t=="G"||t=="g") dat+=sz;
        else if(t=="B"||t=="b") bss+=sz;
      } END{printf "%d %d %d %d",code+0,rod+0,dat+0,bss+0}')"
  read -r code rod dat bss <<< "$sums"
  local flash=$((code+rod+dat)) sram=$((dat+bss))
  # max single-function stack frame (conservative, not call-chain summed)
  local stk; stk="$(cat "$w"/*.su 2>/dev/null | awk -F'\t' '{if($2+0>m)m=$2+0} END{print m+0}')"
  echo "$key,$tier,$impl,$code,$rod,$dat,$bss,$flash,$sram,$heap,$stk" >> "$OUT/e7_footprint.csv"
}

for entry in "${SCHEMES[@]}"; do
  key="${entry%%|*}"; dir="${entry##*|}"
  if [ "${#FILTER[@]}" -gt 0 ]; then
    skip=1; for fx in "${FILTER[@]}"; do [ "$fx" = "$key" ] && skip=0; done; [ "$skip" = 1 ] && continue
  fi
  echo "== $key ($dir) =="
  build_one "$key" "$dir" portable clean
  if [ -d "$PQ/$dir/avx2" ]; then
    build_one "$key" "$dir" avx2 avx2
  else
    echo "  [$key] no avx2 impl in PQClean -> portable clean only"
  fi
done
echo "wrote $OUT/e7_footprint.csv"
column -t -s, "$OUT/e7_footprint.csv"
