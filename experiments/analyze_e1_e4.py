#!/usr/bin/env python3
"""E1 (primitive sizing/timing, two tiers) and E4 (role verification latency)
analysis. Reads results/ written by the Rust pqbench/rolebench binaries,
fits the linear verification-cost model  T = a + b*k  (formalization sec 6.3),
and emits summary CSVs plus publication figures. Nothing here is estimated:
every number is read from the measured CSVs.
"""
import os, re, csv, glob, math
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
FIG = os.path.join(RES, "figures")
os.makedirs(FIG, exist_ok=True)
TIERS = ["portable", "avx2"]
PQS = {"mldsa65": ("ML-DSA-65", "ml-dsa"), "fndsa512": ("FN-DSA-512", "fn-dsa")}

plt.rcParams.update({
    "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.5,
    "figure.dpi": 130, "savefig.dpi": 300, "legend.frameon": False,
})
C = {"blue": "#0072B2", "orange": "#E69F00", "green": "#009E73",
     "red": "#D55E00", "purple": "#CC79A7", "grey": "#555555"}

# ---------------- E1 ---------------- #
def load_e1(tier):
    p = os.path.join(RES, "e1_primitives", tier, "algostats.csv")
    out = {}
    with open(p) as f:
        for r in csv.DictReader(f):
            out[r["variant"]] = r
    return out

def analyze_e1():
    e1 = {t: load_e1(t) for t in TIERS}
    variants = list(e1["avx2"].keys())
    rows = []
    for v in variants:
        a, p = e1["avx2"][v], e1["portable"][v]
        rows.append({
            "variant": v, "family": a["family"], "level": a["level"],
            "pk": int(a["pk"]), "sk": int(a["sk"]), "sig": int(a["sig"]),
            "verify_avx2_us": float(a["verify_med_us"]),
            "verify_portable_us": float(p["verify_med_us"]),
            "sign_avx2_us": float(a["sign_med_us"]),
            "sign_portable_us": float(p["sign_med_us"]),
            "keygen_avx2_us": float(a["keygen_med_us"]),
            "keygen_portable_us": float(p["keygen_med_us"]),
            "verify_speedup_portable_over_avx2":
                round(float(p["verify_med_us"]) / float(a["verify_med_us"]), 2),
        })
    sp = os.path.join(RES, "e1_primitives", "summary_e1_two_tier.csv")
    with open(sp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print("wrote", sp)

    # Fig E1a: pk vs sig size (log-log)
    fig, ax = plt.subplots(figsize=(3.6, 3.0))
    fam_color = {"classical": C["grey"], "ml-dsa": C["blue"],
                 "fn-dsa": C["orange"], "slh-dsa": C["green"]}
    for r in rows:
        ax.scatter(r["pk"], r["sig"], s=34, color=fam_color[r["family"]],
                   edgecolor="k", linewidth=0.4, zorder=3)
        # SLH points share pk=32/64: put every label to the right with small
        # per-point vertical nudges so they never collide with each other.
        # Labels sit at each marker's own y (log-axis spacing already separates
        # same-pk SLH/FN points); only the tight ML-DSA trio is offset.
        dx = {"ed25519": (8, 0), "mldsa44": (-10, 0), "mldsa65": (12, -15),
              "mldsa87": (12, 8), "fndsa512": (10, 0), "fndsa1024": (10, 0),
              "slhdsa128s": (10, 0), "slhdsa128f": (10, 0),
              "slhdsa256s": (10, 0), "slhdsa256f": (10, 0)}[r["variant"]]
        ha = "left" if dx[0] > 0 else "right"
        lab = {"ed25519": "Ed25519", "mldsa44": "ML-DSA-44",
               "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87",
               "fndsa512": "FN-DSA-512", "fndsa1024": "FN-DSA-1024",
               "slhdsa128s": "SLH-DSA-128s", "slhdsa128f": "SLH-DSA-128f",
               "slhdsa256s": "SLH-DSA-256s", "slhdsa256f": "SLH-DSA-256f"}[r["variant"]]
        ax.annotate(lab, (r["pk"], r["sig"]), xytext=(dx[0], dx[1]),
                    textcoords="offset points", ha=ha, fontsize=6.5)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlim(22, 5200); ax.set_ylim(40, 90000)
    ax.set_xlabel("public key size (bytes)")
    ax.set_ylabel("signature size (bytes)")
    handles = [plt.Line2D([], [], marker="o", ls="", color=c, label=l,
                          markeredgecolor="k", markersize=6)
               for l, c in [("classical", C["grey"]), ("ML-DSA", C["blue"]),
                            ("FN-DSA", C["orange"]), ("SLH-DSA", C["green"])]]
    ax.legend(handles=handles, loc="lower right", fontsize=7)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(FIG, f"fig_e1a_sizes.{ext}"), bbox_inches="tight")
    plt.close(fig)

    # Fig E1b: verify latency, two tiers (horizontal bars, log)
    order = ["ed25519", "mldsa44", "mldsa65", "mldsa87", "fndsa512",
             "fndsa1024", "slhdsa128s", "slhdsa128f", "slhdsa256s", "slhdsa256f"]
    labels = {"ed25519": "Ed25519", "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65",
              "mldsa87": "ML-DSA-87", "fndsa512": "FN-DSA-512",
              "fndsa1024": "FN-DSA-1024", "slhdsa128s": "SLH-128s",
              "slhdsa128f": "SLH-128f", "slhdsa256s": "SLH-256s",
              "slhdsa256f": "SLH-256f"}
    fig, ax = plt.subplots(figsize=(3.7, 3.4))
    y = np.arange(len(order)); h = 0.38
    av = [next(r for r in rows if r["variant"] == v)["verify_avx2_us"] for v in order]
    po = [next(r for r in rows if r["variant"] == v)["verify_portable_us"] for v in order]
    ax.barh(y + h/2, av, height=h, color=C["blue"], label="AVX2-optimized")
    ax.barh(y - h/2, po, height=h, color=C["orange"], label="portable clean-C")
    ax.set_yticks(y); ax.set_yticklabels([labels[v] for v in order], fontsize=7.5)
    ax.invert_yaxis(); ax.set_xscale("log")
    ax.set_xlabel("single-signature verify time (µs, log)")
    ax.set_xlim(right=3000)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.02), ncol=2, fontsize=7.5)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(FIG, f"fig_e1b_verify_twotier.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote E1 figures")
    return rows

# ---------------- E4 ---------------- #
def parse_e4(tier, pq):
    p = os.path.join(RES, "e4_latency", tier, f"rolebench_{pq}.csv")
    prim = {}
    va, va7, sc = [], [], []
    fnlen = None
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line.startswith("# primitive"):
                for name, val in re.findall(r"(ed25519|mldsa65|fndsa512|hybrid)=([0-9.]+)", line):
                    prim[name] = float(val)
            elif line.startswith("# fndsa512 sig length"):
                m = re.search(r"min=(\d+) med=(\d+) max=(\d+) mean=([0-9.]+)", line)
                if m:
                    fnlen = dict(zip(("min", "med", "max", "mean"),
                                     [int(m[1]), int(m[2]), int(m[3]), float(m[4])]), n=tier)
            elif line and not line.startswith("variant"):
                c = line.split(",")
                rec = dict(k=int(c[2]), m=int(c[3]), mode=c[4],
                           med=float(c[6]), p25=float(c[5]), p75=float(c[7]))
                if rec["m"] == 5 and rec["mode"] == "verifyall":
                    va.append(rec)
                elif rec["m"] == 7 and rec["mode"] == "verifyall":
                    va7.append(rec)
                elif rec["m"] == 7 and rec["mode"] == "shortcircuit":
                    sc.append(rec)
    va.sort(key=lambda r: r["k"]); va7.sort(key=lambda r: r["k"]); sc.sort(key=lambda r: r["k"])
    return prim, va, va7, sc, fnlen

def ols(x, y):
    x = np.asarray(x, float); y = np.asarray(y, float)
    b, a = np.polyfit(x, y, 1)
    yhat = b * x + a
    ss_res = float(((y - yhat) ** 2).sum())
    ss_tot = float(((y - y.mean()) ** 2).sum())
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else float("nan")
    return a, b, r2

def analyze_e4():
    fit_rows = []
    data = {}
    for tier in TIERS:
        for pq, (pretty, fam) in PQS.items():
            prim, va, va7, sc, fnlen = parse_e4(tier, pq)
            data[(tier, pq)] = (prim, va, va7, sc, fnlen)
            ks = [r["k"] for r in va]; med = [r["med"] for r in va]
            a, b, r2 = ols(ks, med)
            vc, vq = prim["ed25519"], prim[pq]
            fit_rows.append({
                "tier": tier, "pq": pq, "t": 5,
                "vC_ed_us": round(vc, 3), "vQ_us": round(vq, 3),
                "vH_meas_us": round(prim["hybrid"], 3),
                "vC_plus_vQ_us": round(vc + vq, 3),
                "fit_intercept_a_us": round(a, 3),
                "fit_slope_b_us": round(b, 3),
                "pred_slope_vQ_us": round(vq, 3),
                "slope_vs_vQ_ratio": round(b / vq, 4),
                "intercept_vs_t*vC_ratio": round(a / (5 * vc), 4),
                "R2": round(r2, 6),
                "fn_sig_len": "" if fnlen is None else
                    f"{fnlen['min']}-{fnlen['max']} (med {fnlen['med']}, mean {fnlen['mean']})",
            })
    sp = os.path.join(RES, "e4_latency", "e4_fit.csv")
    with open(sp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fit_rows[0].keys()))
        w.writeheader(); w.writerows(fit_rows)
    print("wrote", sp)
    for r in fit_rows:
        print(f"  {r['tier']:8s} {r['pq']:9s} slope b={r['fit_slope_b_us']:7.2f} "
              f"vQ={r['vQ_us']:7.2f} ratio={r['slope_vs_vQ_ratio']:.3f} "
              f"R2={r['R2']:.5f} vH={r['vH_meas_us']:.2f} vs vC+vQ={r['vC_plus_vQ_us']:.2f}")

    # Fig E4: 2 (tier) x 2 (pq) panels
    fig, axes = plt.subplots(2, 2, figsize=(7.0, 5.2), sharex=True)
    for col, pq in enumerate(["mldsa65", "fndsa512"]):
        for row, tier in enumerate(TIERS):
            ax = axes[row][col]
            prim, va, va7, sc, _ = data[(tier, pq)]
            kv = [r["k"] for r in va]
            ax.plot(kv, [r["med"] for r in va], "-o", color=C["blue"], ms=4,
                    label="verify-all, m=t=5 (threshold release)")
            a, b, r2 = ols(kv, [r["med"] for r in va])
            xx = np.linspace(0, 5, 50)
            ax.plot(xx, a + b * xx, "--", color=C["blue"], alpha=0.5,
                    label=f"OLS fit, R²={r2:.4f}")
            ax.plot([r["k"] for r in va7], [r["med"] for r in va7], "-s",
                    color=C["grey"], ms=4, label="verify-all, m=n=7 (all signers)")
            ax.plot([r["k"] for r in sc], [r["med"] for r in sc], "-^",
                    color=C["red"], ms=4, label="short-circuit, m=n=7")
            ax.set_title(f"{PQS[pq][0]} — {tier}", fontsize=9)
            ax.set_xlabel("k  (quantum-safe signers in quorum)")
            ax.set_ylabel("role verification time (µs)")
            if row == 0 and col == 0:
                ax.legend(fontsize=6.5, loc="upper left")
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(FIG, f"fig_e4_role_latency.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote E4 figure")

if __name__ == "__main__":
    analyze_e1()
    analyze_e4()
    print("E1/E4 analysis complete.")
