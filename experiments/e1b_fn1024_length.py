#!/usr/bin/env python3
"""E1b -- FN-DSA-1024 detached-signature length distribution (n=3000).

FN-DSA signatures are variable-length (Padded variants aside); E1's main table
records a representative length, so here we characterise the full distribution
to justify the byte model's use of a representative FN-1024 signature size.
Length depends on the signing randomness, not on the portable/AVX2 optimisation
tier, so it is measured once through the Rust PQClean bridge.
"""
import os, sys, csv, statistics
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "impl"))
from pqtuf import pqbackend as pqb

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "e1_primitives")
N = 3000
br = pqb.PQBridge.get()
lens = []
for i in range(N):
    pk, sk = br.keygen("fndsa1024")
    sig = br.sign("fndsa1024", sk, f"len-probe-1024-{i}".encode())
    lens.append(len(sig))
lens.sort()
def q(p):
    return lens[min(N - 1, int(round(p * (N - 1))))]
row = {
    "variant": "fndsa1024", "n": N,
    "min": lens[0], "p25": q(0.25), "median": q(0.5), "p75": q(0.75),
    "max": lens[-1], "mean": round(statistics.fmean(lens), 3),
    "stdev": round(statistics.pstdev(lens), 3),
    "distinct_lengths": len(set(lens)),
}
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "fndsa1024_siglen.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(row.keys()))
    w.writeheader(); w.writerow(row)
print(row)
# small histogram of the most common lengths
from collections import Counter
for L, c in sorted(Counter(lens).items())[:12]:
    print(L, c)
