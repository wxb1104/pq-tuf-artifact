#!/usr/bin/env python3
"""E5 -- per-role, role-mixed (OPT) repository byte experiment on a real
python-tuf multi-role repository with a delegated target role (TAP 3).

Four strategies share the SAME (n,t) per role; only the key classes and k vary:
  C    classical-only (all Ed25519, k=0)
  F    full hybrid (every key Ed25519||ML-DSA-65, k=t)
  QA   quorum-aware hybrid, uniform ML-DSA-65, per-role k (QMIN attaches t)
  OPT  role-lifecycle mixed: root = Ed||ML-DSA-87 fully-QS (k=t); the
       high-frequency timestamp/snapshot roles use the short-signature
       Ed||FN-DSA-512; offline targets/vendor use Ed||ML-DSA-65.

Every metadata file is real compact-JSON python-tuf metadata; bytes are
measured, never estimated. We then fit the additive capacity model
(signature block ~ counts of attached signatures by type; root key block ~
counts of published public keys by type) to confirm the formalization's byte
model (sec 6.2) holds across roles and mixed algorithms.
"""
import os, csv, json, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "impl"))
from pqtuf.repo import PQTUFRepo, RoleConfig, measure  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "e5_roles")
FIG = os.path.join(ROOT, "results", "figures")
os.makedirs(OUT, exist_ok=True)
os.makedirs(FIG, exist_ok=True)
plt.rcParams.update({
    "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.5,
    "figure.dpi": 130, "savefig.dpi": 300, "legend.frameon": False,
})
STRAT_COLOR = {"C": "#999999", "F": "#D55E00", "QA": "#0072B2", "OPT": "#009E73"}
STRAT_LABEL = {"C": "classical-only", "F": "full hybrid",
               "QA": "quorum-aware (uniform)", "OPT": "role-mixed (ours)"}
ROLE_COLOR = {"timestamp": "#56B4E9", "snapshot": "#0072B2",
              "targets": "#E69F00", "vendor": "#CC79A7"}

ED = "ed25519"
H65 = "hyb:ed25519:mldsa65"
H87 = "hyb:ed25519:mldsa87"
HFN = "hyb:ed25519:fndsa512"

# fixed (n,t) per role (vendor is a TAP-3 delegated target role)
NT = {"root": (5, 3), "timestamp": (3, 2), "snapshot": (3, 2),
      "targets": (4, 3), "vendor": (3, 2)}
ROLE_ORDER = ["root", "timestamp", "snapshot", "targets", "vendor"]

TGT_FILES = {"app/fw1.bin": b"A" * 4096, "app/cfg.json": b"B" * 512,
             "app/meta.txt": b"C" * 128}
VENDOR_FILES = {"vendor/lib1.bin": b"D" * 2048, "vendor/lic.dat": b"E" * 256}


def schemes_for(strategy, role):
    n, t = NT[role]
    if strategy == "C":
        return [ED] * n, 0
    if strategy == "F":
        return [H65] * n, t
    if strategy == "QA":
        if role == "root":
            return [ED] + [H65] * (n - 1), 2
        if role in ("timestamp", "snapshot", "vendor"):
            return [ED] + [H65] * (n - 1), 1
        if role == "targets":
            return [ED, ED] + [H65] * (n - 2), 1
    if strategy == "OPT":
        if role == "root":
            return [H87] * n, t
        if role in ("timestamp", "snapshot"):
            return [ED] + [HFN] * (n - 1), 1
        if role in ("targets", "vendor"):
            n_c = 2 if role == "targets" else 1
            return [ED] * n_c + [H65] * (n - n_c), 1
    raise ValueError(strategy)


def alg_of(scheme):
    if scheme == ED:
        return "ed"
    return {"mldsa65": "h65", "mldsa87": "h87",
            "fndsa512": "hfn"}[scheme.split(":")[2]]


def build(strategy):
    top = {}
    delegate = {}
    for role in ["root", "timestamp", "snapshot", "targets"]:
        sch, k = schemes_for(strategy, role)
        top[role] = RoleConfig(sch, NT[role][1], k)
    vsch, vk = schemes_for(strategy, "vendor")
    delegate["vendor"] = RoleConfig(vsch, NT["vendor"][1], vk)

    repo = PQTUFRepo(top, name="image")
    repo.publish_targets(TGT_FILES, role="targets", version=1,
                         schedule="quorum", delegate=delegate)
    repo.publish_delegated("targets", "vendor", VENDOR_FILES, version=1,
                           schedule="quorum")
    repo.publish_snapshot(target_roles=("targets", "vendor"), version=1,
                          schedule="quorum")
    repo.publish_timestamp(version=1, schedule="quorum")

    # verify every role: stock TUF threshold + Algorithm-2 QS count
    verify = {}
    for role in ROLE_ORDER:
        try:
            res = repo.verify(role)
            verify[role] = f"ok(v={res.valid},qs={res.qs_valid})"
        except Exception as e:
            verify[role] = f"FAIL:{type(e).__name__}:{e}"
    return repo, verify


def _scheme_of(s):
    # CryptoSigner has no scheme attribute (Ed25519); PQSigner exposes .scheme;
    # HybridSigner stores it on the UnifiedKey ._uk.scheme.
    sch = getattr(s, "scheme", None)
    if sch is None:
        uk = getattr(s, "_uk", None)
        sch = getattr(uk, "scheme", "ed25519") if uk is not None else "ed25519"
    return sch


def attached_composition(repo, role):
    """Count the signatures QMIN actually attaches for one publication."""
    pol = repo.policies[role]
    chosen = pol.quorum_signers()
    comp = {"ed": 0, "h65": 0, "h87": 0, "hfn": 0}
    for s in chosen:
        comp[alg_of(_scheme_of(s))] += 1
    return comp


def plot(rows):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.2, 2.9))

    # (a) per-role wire bytes, grouped by strategy, log scale
    x = np.arange(len(ROLE_ORDER)); w = 0.2
    for i, strat in enumerate(["C", "F", "QA", "OPT"]):
        d = {r["role"]: r for r in rows if r["strategy"] == strat}
        vals = [d[role]["wire"] for role in ROLE_ORDER]
        ax1.bar(x + (i - 1.5) * w, vals, width=w, color=STRAT_COLOR[strat],
                label=STRAT_LABEL[strat])
    ax1.set_yscale("log")
    ax1.set_xticks(x); ax1.set_xticklabels(
        ["root", "time-\nstamp", "snap-\nshot", "targets", "vendor\n(deleg.)"],
        fontsize=7.5)
    ax1.set_ylabel("metadata wire size (bytes, log)")
    ax1.set_title("(a) per-role metadata size", fontsize=9)
    ax1.legend(fontsize=6.3, loc="upper right")

    # (b) per-update critical path (root is one-off / amortized): stacked
    crit = ["timestamp", "snapshot", "targets", "vendor"]
    strats = ["C", "F", "QA", "OPT"]
    xb = np.arange(len(strats)); bottom = np.zeros(len(strats))
    for role in crit:
        seg = []
        for strat in strats:
            d = {r["role"]: r for r in rows if r["strategy"] == strat}
            seg.append(d[role]["wire"])
        seg = np.array(seg, float)
        ax2.bar(xb, seg, bottom=bottom, color=ROLE_COLOR[role],
                label=role.replace("vendor", "vendor (deleg.)"))
        bottom += seg
    for i, tot in enumerate(bottom):
        ax2.text(i, tot + 1200, f"{int(tot/1000)}k", ha="center", fontsize=7.5)
    ax2.set_xticks(xb); ax2.set_xticklabels(
        ["classical-\nonly", "full\nhybrid", "quorum-\naware", "role-mixed\n(ours)"],
        fontsize=7.5)
    ax2.set_ylabel("per-update verified metadata (bytes)")
    ax2.set_title("(b) ECU per-update critical path (root amortized)", fontsize=9)
    ax2.legend(fontsize=6.5, loc="upper right")
    ax2.set_ylim(top=bottom.max() * 1.18)

    fig.tight_layout()
    for ext in ("pdf", "png"):
        p = os.path.join(FIG, f"fig_e5_role_mixed.{ext}")
        fig.savefig(p, bbox_inches="tight")
    plt.close(fig)
    print("wrote fig_e5_role_mixed (pdf/png)")


def main():
    rows = []
    raw = {}
    verifies = {}
    for strat in ["C", "F", "QA", "OPT"]:
        repo, verify = build(strat)
        verifies[strat] = verify
        m = repo.measure_all()
        raw[strat] = (repo, m)
        for role in ROLE_ORDER:
            d = m[role]
            comp = attached_composition(repo, role)
            pol = repo.policies[role]
            rows.append({
                "strategy": strat, "role": role, "n": pol.n, "t": pol.t,
                "k": pol.k, "wire": d["wire"],
                "signed_canonical": d["signed_canonical"],
                "sig_block": d["signatures_block"],
                "keys_block": d["keys_block"], "n_sig": d["n_sig"],
                "att_ed": comp["ed"], "att_h65": comp["h65"],
                "att_h87": comp["h87"], "att_hfn": comp["hfn"],
                "sig_lens": ";".join(map(str, d["sig_bytes"])),
                "verify": verify[role],
            })

    sp = os.path.join(OUT, "e5_role_bytes.csv")
    with open(sp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print("wrote", sp)

    # ---- verification status ---- #
    for strat in ["C", "F", "QA", "OPT"]:
        bad = {r: v for r, v in verifies[strat].items() if not v.startswith("ok")}
        print(f"  {strat}: " + ("ALL ROLES VERIFY" if not bad else f"FAIL {bad}"))

    # ---- additive signature-block model (mixed algorithms, all roles) ---- #
    # A signature is hex-encoded (2 chars/byte) plus a fixed per-signature JSON
    # envelope (keyid field + 64-byte keyid + sig field). So over every role
    # and strategy:  sig_block = a + b_n * n_sig + b_b * sum(sig_len_bytes),
    # with b_b expected to be exactly 2. This is the mixed-algorithm analogue of
    # the E2 linearity test and must hold regardless of which PQ family a role
    # uses (it depends only on the realized signature lengths, recorded in CSV).
    nsig = np.array([r["n_sig"] for r in rows], float)
    sbytes = np.array([sum(map(int, r["sig_lens"].split(";"))) for r in rows], float)
    y = np.array([r["sig_block"] for r in rows], float)
    X = np.column_stack([np.ones_like(nsig), nsig, sbytes])
    beta, _, _, _ = np.linalg.lstsq(X, y, rcond=None)
    yhat = X @ beta
    r2 = 1 - float(((y - yhat) ** 2).sum()) / float(((y - y.mean()) ** 2).sum())
    print(f"  sig_block = {beta[0]:.1f} + {beta[1]:.1f}*n_sig + "
          f"{beta[2]:.4f}*sum(sig_bytes)   R2={r2:.6f} "
          f"max|res|={int(np.abs(y-yhat).max())} B  (slope/byte expect 2)")

    # ---- root key-block model (root holds public keys for ALL top roles) ---- #
    # keys_block vs realized sum of public-key bytes; slope expected = 2 (hex).
    kx, ky, kn = [], [], []
    for strat in ["C", "F", "QA", "OPT"]:
        repo, m = raw[strat]
        pub_bytes = sum(len(bytes.fromhex(k.keyval["public"]))
                        for k in repo.root.signed.keys.values())
        kx.append(pub_bytes); ky.append(m["root"]["keys_block"])
        kn.append(len(repo.root.signed.keys))
    kx = np.array(kx, float); ky = np.array(ky, float)
    K = np.column_stack([np.ones_like(kx), kx])
    kb, _, _, _ = np.linalg.lstsq(K, ky, rcond=None)
    khat = K @ kb
    kr2 = 1 - float(((ky - khat) ** 2).sum()) / float(((ky - ky.mean()) ** 2).sum())
    print(f"  root keys_block = {kb[0]:.1f} + {kb[1]:.4f}*sum(pubkey_bytes)   "
          f"R2={kr2:.6f} max|res|={int(np.abs(ky-khat).max())} B "
          f"(n_keys={sorted(set(kn))}, slope/byte expect 2)")

    # ---- per-update critical path (ECU downloads every update) ---- #
    crit_roles = ["timestamp", "snapshot", "targets", "vendor"]
    summary = []
    for strat in ["C", "F", "QA", "OPT"]:
        d = {r["role"]: r for r in rows if r["strategy"] == strat}
        crit = sum(d[r]["wire"] for r in crit_roles)
        root_w = d["root"]["wire"]
        summary.append((strat, root_w, crit))
    print("\n  strategy  root(B)  per-update critical path (B)")
    base_crit = summary[0][2]
    for strat, rw, crit in summary:
        print(f"    {strat:4s}  {rw:7d}  {crit:7d}   "
              f"{(crit / base_crit - 1) * 100:+6.1f}% vs classical")
    f_crit = next(c for s, _, c in summary if s == "F")
    opt_crit = next(c for s, _, c in summary if s == "OPT")
    qa_crit = next(c for s, _, c in summary if s == "QA")
    print(f"  OPT per-update saves {100 * (1 - opt_crit / f_crit):.1f}% vs full-hybrid; "
          f"QA saves {100 * (1 - qa_crit / f_crit):.1f}%")

    with open(os.path.join(OUT, "e5_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["strategy", "root_wire_B", "per_update_critical_B"])
        w.writerows(summary)
    print("wrote", os.path.join(OUT, "e5_summary.csv"))

    plot(rows)


if __name__ == "__main__":
    main()
