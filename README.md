# Artifact: Quorum-Aware Hybrid Threshold Migration for TUF and Uptane

Reproducible research artifact accompanying the manuscript

> **Post-Quantum Software-Update Security: Quorum-Aware Hybrid Threshold
> Migration for TUF and Uptane**

The artifact provides the quorum-aware post-quantum software-update framework,
the out-of-tree python-tuf extension, the PQClean benchmark bridge, the
embedded footprint harness, the full experiment driver set (E1–E10), and the
raw measurement data behind every table and figure in the paper.

## 1. What is implemented

* **Quorum-aware hybrid threshold design** — per-role accountable
  multi-signer policies with both a classical threshold `t` and a minimum
  number `k` of quantum-safe (pure-PQ or hybrid) signers; the feasibility
  predicate, minimum deployment `h_r*`, and minimum per-file quantum-safe
  signature count `q_min` (Section 4 of the paper).
* **Hybrid signer with explicit downgrade binding** — length-prefixed
  composite signatures `len || sigma_C || sigma_Q` with per-component domain
  separation, registered as new `securesystemslib` key types so that
  verification runs through the unmodified python-tuf metadata path.
* **Role-lifecycle mixed configuration (OPT)** and the **uniform `(t,k)`
  baseline (QA)**, plus the full-hybrid (F) and classical (C) baselines.
* **Dual-threshold post-quantum root bootstrap (BOOT)** with staged
  old-side/new-side signature acceptance.
* **Uptane Director/Image two-repository deployment** with full Primary
  verification and partial Secondary/ECU verification.
* A **22-case functional-fidelity attack matrix** (threshold, quantum-safe
  quorum, agility/downgrade, root rotation, freshness) — every attack rejected,
  every legitimate monotonic operation accepted.

The implementation introduces no new cryptographic primitive: it composes
NIST-standardized ML-DSA, FN-DSA (Falcon), and SLH-DSA (SPHINCS+) via
PQClean/pqcrypto-rs with the classical Ed25519 baseline.

## 2. Repository layout

```
.
├── impl/
│   ├── pqtuf/                 # framework package (out-of-tree python-tuf extension)
│   │   ├── repo.py            #   metadata construction, per-role (t,k) policies, wire sizes
│   │   ├── quorum.py          #   feasibility, h_r*, q_min, quantum-safe counting
│   │   ├── client.py          #   update state machine; rollback/freeze/mismatch/quorum errors
│   │   ├── rotate.py          #   dual-threshold root bootstrap (Algorithm 3)
│   │   ├── uptane.py          #   Director/Image repositories; full vs partial verification
│   │   ├── signers.py         #   PQ/hybrid securesystemslib Key/Signer registration
│   │   └── pqbackend.py       #   persistent in-process bridge to PQClean (Rust)
│   ├── pqbench/               # Rust benchmark crate (PQClean via pqcrypto-rs)
│   │   ├── src/main.rs        #   E1 primitive micro-benchmark (pqbench)
│   │   ├── src/bin/bridge.rs  #   line-protocol sign/verify bridge used by the framework
│   │   ├── src/bin/rolebench.rs # E4 role verification latency sweep
│   │   └── vendor/            # vendored pqcrypto-internals (scalar-Keccak switch)
│   ├── e7_footprint/          # E7 verify-only MCU footprint harness (gcc + PQClean C)
│   ├── tests/                 # 71-assertion regression suite
│   └── build_*.sh / run_*.sh  # build and test entry points
├── experiments/               # experiment drivers E1b–E10 and plotting
├── results/                   # all raw measurements (CSV/JSON) and rendered figures
└── requirements.txt
```

## 3. Requirements

* **Hardware used in the paper:** Intel Core i7-12700, 16 GiB RAM.
* **OS/toolchain:** Ubuntu 24.04 (validated under WSL2), a recent stable
  Rust toolchain (edition 2021) with `cargo`, `gcc/binutils` (`objdump`,
  `nm`) for E7, and Python 3.
* **Python packages:** install with `pip install -r requirements.txt`
  (python-tuf 7.0.1, securesystemslib 1.5.1, cryptography 50.0.1, plus
  numpy/pandas/matplotlib).
* **Network:** only needed once, for `cargo` to fetch the pinned
  pqcrypto/ed25519 crates (`Cargo.lock` included). All experiments run
  offline after that. No TUF repository is contacted over the network; the
  prototype builds and verifies real metadata in process.

## 4. Build and run the test suite

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Build the PQClean bridge and benchmarks (release, AVX2 tier by default)
bash impl/build_bridge.sh

# All 71 key/signing, quorum, repository-integration, and attack assertions
bash impl/run_all_tests.sh
```

The framework locates the bridge relative to its own source tree, and every
script resolves the repository root from its own location, so the repository
can be cloned to any path.

## 5. Reproducing the experiments

Each experiment writes CSV/JSON under `results/<experiment>/`. The shipped
data in `results/` is the exact measurement set used in the paper, so the
tables and figures can be re-derived without re-running anything; the drivers
are provided to reproduce the numbers from scratch.

| ID | Experiment | Driver / entry point | Outputs (`results/…`) | Paper |
|----|-----------|----------------------|-----------------------|-------|
| E1 | Primitive sizes, latency, hybrid additivity; two tiers | `impl/build_two_tiers.sh` (Rust `pqbench`), `experiments/run_e1b.sh`, `experiments/run_analyze_e1_e4.sh` | `e1_primitives/…` | Table 4, Figs. 2–3 |
| E2 | `(n,t,k)` byte grid, capacity-model validation | `experiments/run_e2.sh` (`e2_byte_grid.py`) | `e2_byte_grid/…` | Eqs. (19)–(26) |
| E3/E9 | Threshold, quorum, agility, rotation, freshness attack matrix | `experiments/run_e3.sh` (`e3_attack_matrix.py`) | `e3_security/e3_attack_matrix.csv` | Table 5, Fig. 4, App. C |
| E4 | Role verification latency, linearity in `k` | `impl/build_rolebench.sh` (Rust `rolebench`), `experiments/run_analyze_e1_e4.sh` | `e4_latency/…`, `e4_latency/e4_fit.csv` | Table 6, Fig. 5 |
| E5 | Role-lifecycle mixed configuration wire bytes | `experiments/run_e5.sh` (`e5_role_mixed.py`) | `e5_roles/…` | Table 7, Fig. 6 |
| E6 | Uptane Director/Image full vs partial verification | `experiments/run_e6.sh` (`e6_uptane.py`) | `e6_uptane/…` | Tables 8–9, Fig. 7 |
| E7 | ECU verify-only flash/RAM feasible region | `impl/e7_footprint/build_e7.sh`, `experiments/run_e7.sh`, `run_e7_analyze.sh` | `e7_budget/…` | Table 10, Fig. 8 |
| E8 | Three-stage dual-threshold root rotation | `experiments/run_e8.sh` (`e8_rotation.py`) | `e8_rotation/…` | Table 11, Fig. 9 |
| E10 | End-to-end annual lifecycle amortization | `experiments/run_e10.sh` (`e10_lifecycle.py`) | `e10_lifecycle/…` | Table 12, Fig. 10 |

Figure 1 (the mechanism schematic) is rendered by
`experiments/fig1_mechanism.py` and is conceptual rather than data-driven.

### Two implementation tiers (E1/E4 fairness control)

`bash impl/build_two_tiers.sh` builds both tiers into separate target
directories so that only the PQClean SIMD choice differs:

* **portable** — scalar clean-C cores and scalar FIPS-202 Keccak
  (`PQTUF_NO_AVX2`, `target-cpu=x86-64`); the script audits the binaries for
  AVX2 `ymm` instructions (count ≈ 0);
* **avx2** — PQClean AVX2 cores (`--features simd-avx2`) with 4× AVX2 Keccak.

`bash impl/detect_avx.sh` reports CPU flags and the AVX2-instruction count of
the built binaries.

### E7 embedded footprint — scope and how to run

E7 compiles each scheme's verify-only PQClean C with
`-ffunction-sections -fdata-sections`, links with `--gc-sections`, wraps the
heap allocators to measure peak verification heap, and reports the largest
single-function stack frame. The PQClean C trees are fetched by cargo into the
local registry; run `(cd impl/pqbench && cargo fetch)` once first if
`build_e7.sh` cannot locate them. Consistent with the paper, the numbers are a
**scalar x86 proxy** for relative flash/RAM trends: the host has no
QEMU/ARM cross-toolchain, so they are not cross-compiled 256/128 KB-class MCU
measurements, and no vendor-specific KB claim is made.

## 6. Headline results reproduced by the data

* Hybrid verification time is additive to within a 0.000 µs measured residual
  (the two component checks run back-to-back in process).
* Capacity predictions match every grid cell as an exact integer multiple of
  the 6634-byte hybrid signature slope, with the fixed intercept isolated.
* The mixed OPT configuration cuts the per-update critical path by ≈63% and
  partial-ECU Uptane bytes by ≈73% versus full hybrid, and annual steady-state
  bytes by ≈67% (Primary) / ≈71% (ECU), while the three measured rotation
  spikes add only ≈3%/≈6% over a year.
* All 18 attack cases are rejected and all 4 legitimate operations accepted
  across the G1–G5 matrix; the four negative root-rotation stages are
  rejected and the legal three-stage rotation is accepted.

## 7. Attribution

This artifact composes existing open-source components: the reference
[python-tuf](https://github.com/theupdateframework/python-tuf) metadata
library, [securesystemslib](https://github.com/secure-systems-lab/securesystemslib),
the Rust [pqcrypto](https://github.com/rustpq/pqcrypto) bindings and
[PQClean](https://github.com/PQClean/PQClean) C implementations of ML-DSA,
FN-DSA (Falcon), and SLH-DSA (SPHINCS+), and Ed25519 via
ed25519-dalek. The vendored `pqcrypto-internals` is the crates.io release
with a build switch (`PQTUF_NO_AVX2`) that disables the always-on AVX2 Keccak
to obtain a true scalar tier. All cryptographic security is inherited from
these primitives; this artifact contributes the quorum-aware migration
construction, not new cryptography.
