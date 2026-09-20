#!/usr/bin/env python3
"""
E2: (n,t,k) metadata-byte grid, validating the tight capacity model.

Uses fixed-length schemes so byte counts are deterministic and formula
residuals are exact:
  C = ed25519 (64B sig), H = ed25519||ML-DSA-65 hybrid (64+3309 B),
  Q = ML-DSA-65 (3309 B).
Produces:
  e2a_linear_m.csv  B_r linear in number m of attached signatures
  e2b_qa_k.csv      B_QA linear in k; endpoints k=0 (classical), k=t (naive)
  e2c_n.csv         fixed t,k: release bytes invariant in n; root keys grow
  e2d_save.csv      SAVE / rho observed vs closed form (SAVE)
  fit.json          per-class single-signature marginal bytes (slope) & base
"""
import csv
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]   # pq-tuf/
sys.path.insert(0, str(BASE / "impl"))

import numpy as np
from tuf.api.metadata import Metadata, TargetFile, Targets

from pqtuf.repo import PQTUFRepo, RoleConfig, measure

OUT = BASE / "results" / "e2_byte_grid"
OUT.mkdir(parents=True, exist_ok=True)

C = "ed25519"
H = "hyb:ed25519:mldsa65"
Q = "mldsa65"
BLOB = b"firmware-payload" * 625  # 10000 B, fixed so o_r is constant


def root_cfg():
    return RoleConfig([C, H, "fndsa1024"], 3, 2)


def target_md(repo, signer_idx):
    md = Metadata(Targets(
        version=1, expires=repo.root.signed.expires,
        targets={"fw.bin": TargetFile(len(BLOB),
                 {"sha256": __import__("hashlib").sha256(BLOB).hexdigest()},
                 "fw.bin")}))
    for i in signer_idx:
        md.sign(repo.policies["targets"].signers[i], append=True)
    return md


def probe(schemes, t, k, signer_idx):
    repo = PQTUFRepo({"root": root_cfg(),
                      "targets": RoleConfig(schemes, t, k)})
    md = target_md(repo, signer_idx)
    return measure(md)["wire"], repo, md


def linfit(x, y):
    x = np.array(x, float); y = np.array(y, float)
    A = np.vstack([x, np.ones_like(x)]).T
    slope, intercept = np.linalg.lstsq(A, y, rcond=None)[0]
    yhat = slope * x + intercept
    ss_res = float(((y - yhat) ** 2).sum())
    ss_tot = float(((y - y.mean()) ** 2).sum())
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 1.0
    return float(slope), float(intercept), float(r2)


# ---------------- (a) B_r linear in m ---------------- #
rows = []
fits = {}
for label, scheme in (("C", C), ("H", H), ("Q", Q)):
    n = 7
    schemes = [scheme] * n
    repo = PQTUFRepo({"root": root_cfg(),
                      "targets": RoleConfig(schemes, 1, 1 if scheme != C else 0)})
    xs, ys = [], []
    for m in range(0, n + 1):
        md = target_md(repo, list(range(m)))
        w = measure(md)["wire"]
        xs.append(m); ys.append(w)
        rows.append({"class": label, "n": n, "m": m, "wire": w})
    slope, intercept, r2 = linfit(xs, ys)
    fits[label] = {"slope": slope, "intercept": intercept, "r2": r2}
with open(OUT / "e2a_linear_m.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["class", "n", "m", "wire"]); w.writeheader(); w.writerows(rows)

eC, eH, eQ = fits["C"]["slope"], fits["H"]["slope"], fits["Q"]["slope"]
o_r = fits["C"]["intercept"]
print(f"(a) single-sig marginal bytes: e_C={eC:.1f} e_H={eH:.1f} e_Q={eQ:.1f} base o={o_r:.1f}")
print(f"    R2: C={fits['C']['r2']:.6f} H={fits['H']['r2']:.6f} Q={fits['Q']['r2']:.6f}")

# ---------------- (b) B_QA linear in k; endpoints ---------------- #
n, t = 9, 5
rows = []
for k in range(0, t + 1):
    c_cnt = t - k                 # minimal robust config c = t-k
    h_cnt = n - c_cnt
    schemes = [C] * c_cnt + [H] * h_cnt
    chosen = list(range(c_cnt)) + list(range(c_cnt, c_cnt + k))  # (t-k) C + k H
    wire_qa, repo, _ = probe(schemes, t, k, chosen)
    pred_qa = o_r + (t - k) * eC + k * eH
    # naive: t hybrid signatures; full-PQ: t pure-Q signatures
    wire_naive, _, _ = probe([H] * n, t, t, list(range(t)))
    wire_pq, _, _ = probe([Q] * n, t, t, list(range(t)))
    rows.append({"n": n, "t": t, "k": k, "wire_qa": wire_qa,
                 "pred_qa": round(pred_qa, 1),
                 "resid": round(wire_qa - pred_qa, 3),
                 "wire_naive": wire_naive, "wire_fullpq": wire_pq})
with open(OUT / "e2b_qa_k.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
kb = [r["k"] for r in rows]; qa = [r["wire_qa"] for r in rows]
sQA, iQA, r2QA = linfit(kb, qa)
print(f"(b) B_QA vs k slope={sQA:.2f} (pred e_H-e_C={eH-eC:.2f}), R2={r2QA:.6f}")
print(f"    k=0 {rows[0]['wire_qa']} (classical), k=t {rows[-1]['wire_qa']} "
      f"(naive {rows[-1]['wire_naive']}, full-PQ {rows[-1]['wire_fullpq']})")
print(f"    max |resid| vs formula = {max(abs(r['resid']) for r in rows):.3f} B")

# ---------------- (c) fixed t,k, vary n: release invariant, root keys grow -- #
t, k = 3, 1
rows = []
for n in range(t, 11):
    c_cnt = t - k
    h_cnt = n - c_cnt
    schemes = [C] * c_cnt + [H] * h_cnt
    chosen = list(range(c_cnt)) + list(range(c_cnt, c_cnt + k))
    wire_tgt, repo, _ = probe(schemes, t, k, chosen)
    km = measure(repo.root)
    rows.append({"n": n, "t": t, "k": k,
                 "targets_wire": wire_tgt,
                 "root_keys_block": km["keys_block"],
                 "root_wire": km["wire"]})
with open(OUT / "e2c_n.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
tgt_var = max(r["targets_wire"] for r in rows) - min(r["targets_wire"] for r in rows)
sRoot, _, r2Root = linfit([r["n"] for r in rows], [r["root_keys_block"] for r in rows])
print(f"(c) targets release range over n={t}..10: {tgt_var} B (want 0); "
      f"root keys slope={sRoot:.1f} B/key, R2={r2Root:.6f}")

# ---------------- (d) SAVE / rho vs closed form ---------------- #
rows = []
for t in (2, 3, 4, 5, 7, 9):
    for k in range(0, t + 1):
        n = t + 2
        c_cnt = t - k
        h_cnt = n - c_cnt
        schemes = [C] * c_cnt + [H] * h_cnt
        chosen = list(range(c_cnt)) + list(range(c_cnt, c_cnt + k))
        qa, _, _ = probe(schemes, t, k, chosen)
        naive, _, _ = probe([H] * n, t, t, list(range(t)))
        save_obs = naive - qa
        save_pred = (t - k) * (eH - eC)
        rho_obs = save_obs / naive
        rho_pred = (t - k) / t * (eH - eC) / eH
        rows.append({"t": t, "k": k, "naive": naive, "qa": qa,
                     "save_obs": save_obs, "save_pred": round(save_pred, 1),
                     "rho_obs": round(rho_obs, 5), "rho_pred": round(rho_pred, 5)})
with open(OUT / "e2d_save.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
max_resid_save = max(abs(r["save_obs"] - r["save_pred"]) for r in rows)
max_resid_rho = max(abs(r["rho_obs"] - r["rho_pred"]) for r in rows)
print(f"(d) SAVE max resid={max_resid_save:.2f} B; rho max resid={max_resid_rho:.6f}")

with open(OUT / "fit.json", "w") as f:
    json.dump({"fits": fits, "sQA_vs_k": {"slope": sQA, "r2": r2QA},
               "root_keys_slope": sRoot}, f, indent=2)
print("E2 CSVs written to", OUT)
