#!/usr/bin/env python3
"""E7 analysis -- verify-only flash/RAM footprint and MCU-budget feasibility.

Combines the measured PQClean verify-only footprint (e7_footprint.csv) with
E1 public-key/signature sizes and portable verify time. Conservative
verification RAM high-water mark = largest single stack frame + measured heap
peak + resident public key + resident signature buffer (all live during one
crypto_sign_open). Budget envelopes are ILLUSTRATIVE (Uptane gives no concrete
KB figure); portable clean-C is an x86 proxy, not a cross-compiled ARM number.
"""
import os, csv
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E7D = os.path.join(ROOT, "results", "e7_budget")
FIG = os.path.join(ROOT, "results", "figures")
plt.rcParams.update({
    "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.5,
    "figure.dpi": 130, "savefig.dpi": 300, "legend.frameon": False,
})
ORDER = ["mldsa44", "mldsa65", "mldsa87", "fndsa512", "fndsa1024",
         "slhdsa128s", "slhdsa128f", "slhdsa256s", "slhdsa256f"]
LAB = {"mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87",
       "fndsa512": "FN-DSA-512", "fndsa1024": "FN-DSA-1024",
       "slhdsa128s": "SLH-DSA-128s", "slhdsa128f": "SLH-DSA-128f",
       "slhdsa256s": "SLH-DSA-256s", "slhdsa256f": "SLH-DSA-256f"}
SHORT = {"mldsa44": "ML-44", "mldsa65": "ML-65", "mldsa87": "ML-87",
         "fndsa512": "FN-512", "fndsa1024": "FN-1024",
         "slhdsa128s": "SLH-128s", "slhdsa128f": "SLH-128f",
         "slhdsa256s": "SLH-256s", "slhdsa256f": "SLH-256f"}
COL = {"mldsa": "#0072B2", "fndsa": "#D55E00", "slhdsa": "#009E73"}


def fam(k):
    return "mldsa" if k.startswith("mldsa") else \
           "fndsa" if k.startswith("fndsa") else "slhdsa"


def read_e1(tier):
    d = {}
    with open(os.path.join(ROOT, "results/e1_primitives", tier,
                           "algostats.csv")) as f:
        for r in csv.DictReader(f):
            d[r["variant"]] = r
    return d


def main():
    fp = {}
    with open(os.path.join(E7D, "e7_footprint.csv")) as f:
        for r in csv.DictReader(f):
            fp[(r["scheme"], r["tier"])] = r
    e1p, e1a = read_e1("portable"), read_e1("avx2")

    rows = []
    for k in ORDER:
        for tier, e1 in (("portable", e1p), ("avx2", e1a)):
            if (k, tier) not in fp:
                continue
            r = fp[(k, tier)]
            e = e1[k]
            stack = int(r["max_stack_frame_B"])
            heap = int(r["heap_peak_verify_B"])
            pk, sig = int(e["pk"]), int(e["sig"])
            ram = stack + heap + pk + sig
            rows.append({
                "scheme": k, "tier": tier,
                "flash_verify_only_B": int(r["flash_total_B"]),
                "stack_frame_B": stack, "heap_peak_B": heap,
                "pk_B": pk, "sig_B": sig, "ram_verify_B": ram,
                "verify_us": float(e["verify_med_us"]),
            })
    with open(os.path.join(E7D, "e7_feasibility.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    port = {r["scheme"]: r for r in rows if r["tier"] == "portable"}
    avx = {r["scheme"]: r for r in rows if r["tier"] == "avx2"}

    # --------------------------- figure ----------------------------- #
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.9, 3.9))
    x = np.arange(len(ORDER)); wbar = 0.4
    ax1.bar(x - wbar/2, [port[k]["flash_verify_only_B"]/1024 for k in ORDER],
            width=wbar, color="#0072B2", label="portable clean-C")
    ax1.bar(x + wbar/2,
            [avx[k]["flash_verify_only_B"]/1024 if k in avx else np.nan
             for k in ORDER], width=wbar, color="#E69F00",
            label="AVX2-optimized")
    for ykb, ls in ((128, ":"), (256, "--"), (512, "-.")):
        ax1.axhline(ykb, color="gray", ls=ls, lw=0.8)
        ax1.text(len(ORDER)-0.4, ykb+8, f"{ykb} KB", fontsize=6,
                 ha="right", color="gray")
    ax1.set_xticks(x); ax1.set_xticklabels([SHORT[k] for k in ORDER],
                                           rotation=40, ha="right", fontsize=6.8)
    ax1.set_ylabel("flash (KB)")
    ax1.set_title("(a) verify-only code size (gc-sections)", fontsize=9, pad=10)
    ax1.legend(fontsize=7, loc="upper left", framealpha=0.9, edgecolor="none")
    ax1.set_ylim(top=560)

    # single illustrative budget envelope (larger envelopes lie off-panel)
    ax2.add_patch(Rectangle((0, 0), 256, 128, color="#009E73", alpha=0.10,
                            zorder=0))
    ax2.text(6, 132, "256/128 KB envelope (illustrative)", fontsize=6.2,
             color="#074", ha="left")
    # numbered points; single-column key on the empty right side, skipping the
    # 128 KB reference band
    for i, k in enumerate(ORDER, start=1):
        r = port[k]
        fx = r["flash_verify_only_B"]/1024
        fy = r["ram_verify_B"]/1024
        ax2.scatter(fx, fy, s=64, color=COL[fam(k)], zorder=3,
                    edgecolor="white", linewidth=0.8)
        if k == "slhdsa256f":   # sits almost on top of ML-DSA-44; lead the label out
            ax2.annotate(str(i), xy=(fx, fy), xytext=(fx + 13, fy - 12),
                         fontsize=6, color="white", fontweight="bold",
                         ha="center", va="center", zorder=5,
                         bbox=dict(boxstyle="circle,pad=0.22",
                                   fc=COL[fam(k)], ec="white", lw=0.8),
                         arrowprops=dict(arrowstyle="-", color="gray",
                                         lw=0.5, shrinkA=2, shrinkB=3))
        else:
            ax2.text(fx, fy, str(i), ha="center", va="center", fontsize=6,
                     color="white", fontweight="bold", zorder=4)
    yrows = [148, 138, 118, 106, 94, 82, 70, 58, 46]
    for i, k in enumerate(ORDER, start=1):
        ax2.text(130, yrows[i-1],
                 f"{i}  {LAB[k]}  ·  {port[k]['verify_us']/1000:.2f} ms",
                 fontsize=6.8, color=COL[fam(k)], va="center")
    ax2.set_xlim(0, 250); ax2.set_ylim(0, 158)
    ax2.set_xlabel("verify-only flash (KB, portable)")
    ax2.set_ylabel("RAM (KB)")
    ax2.set_title("(b) MCU flash/RAM envelopes (portable)", fontsize=9, pad=10)
    fig.tight_layout(w_pad=2.0)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(FIG, f"fig_e7_footprint.{ext}"),
                    bbox_inches="tight")
    plt.close(fig)

    print("scheme     tier     flashKB  ramKB  verify_us")
    for r in rows:
        print(f"{r['scheme']:10s} {r['tier']:8s} "
              f"{r['flash_verify_only_B']/1024:7.1f} "
              f"{r['ram_verify_B']/1024:6.1f} {r['verify_us']:9.1f}")
    print("\nwrote e7_feasibility.csv / fig_e7_footprint")


if __name__ == "__main__":
    main()
