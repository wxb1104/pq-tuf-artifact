#!/usr/bin/env python3
"""E6 -- PQ-Uptane two-repository experiment (Director + Image), full vs
resource-constrained partial (Secondary/ECU) verification.

Bytes are MEASURED on real python-tuf metadata (never estimated). Verification
latency is parameterized from the independently measured per-operation timings
(E1 primitive benchmark + E4 in-role calibration, which established
v_hybrid = v_classical + v_PQ with zero residual over four tier x algorithm
cells): a threshold release that attaches (t-k) classical and k hybrid
signatures costs  t*v_C + k*v_Q  to verify.

Strategies C/F/QA/OPT as in E5, applied to BOTH repos; OPT additionally puts the
short-signature FN-DSA hybrid on the high-frequency roles and the strongest
ML-DSA-87 hybrid (fully quantum-safe, k=t) on both root roles.
"""
import os, csv, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "impl"))
from pqtuf.repo import RoleConfig                     # noqa: E402
from pqtuf.uptane import UptaneDeployment             # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "e6_uptane")
FIG = os.path.join(ROOT, "results", "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({
    "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.5,
    "figure.dpi": 130, "savefig.dpi": 300, "legend.frameon": False,
})
ED, H65, H87, HFN = "ed25519", "hyb:ed25519:mldsa65", "hyb:ed25519:mldsa87", \
                    "hyb:ed25519:fndsa512"
TARGET, BLOB = "fw/ecu-app.bin", b"F" * 8192
STRATS = ["C", "F", "QA", "OPT"]
SCOLOR = {"C": "#999999", "F": "#D55E00", "QA": "#0072B2", "OPT": "#009E73"}
SLABEL = {"C": "classical-only", "F": "full hybrid", "QA": "quorum-aware",
          "OPT": "role-mixed (ours)"}


def top_config(strat, repo):
    """Top-4 role configs for one repo under a strategy."""
    def cfg(schemes, t, k):
        return RoleConfig(schemes, t, k)
    if strat == "C":
        return {r: cfg([ED] * n, t, 0) for r, (n, t) in NT.items()}
    if strat == "F":
        return {r: cfg([H65] * n, t, t) for r, (n, t) in NT.items()}
    if strat == "QA":
        d = {}
        for r, (n, t) in NT.items():
            k = 2 if r == "root" else 1
            nc = 1 if r != "targets" else 2
            d[r] = cfg([ED] * nc + [H65] * (n - nc), t, k)
        return d
    if strat == "OPT":
        d = {
            "root": cfg([H87] * NT["root"][0], NT["root"][1], NT["root"][1]),
            "timestamp": cfg([ED] + [HFN] * 2, 2, 1),
            "snapshot": cfg([ED] + [HFN] * 2, 2, 1),
            "targets": cfg([ED, ED, H65, H65], 3, 1),
        }
        return d
    raise ValueError(strat)


NT = {"root": (5, 3), "timestamp": (3, 2), "snapshot": (3, 2), "targets": (4, 3)}
VENDOR_NT = (3, 2)


def vendor_config(strat):
    n, t = VENDOR_NT
    if strat == "C":
        return RoleConfig([ED] * n, t, 0)
    if strat == "F":
        return RoleConfig([H65] * n, t, t)
    return RoleConfig([ED] + [H65] * (n - 1), t, 1)  # QA and OPT


def scheme_of(s):
    sch = getattr(s, "scheme", None)
    if sch is None:
        uk = getattr(s, "_uk", None)
        sch = getattr(uk, "scheme", ED) if uk is not None else ED
    return sch


def load_timings():
    """Per-op verify median (us) by tier. v_C and v_Q for mldsa65/fndsa512 come
    from the E4 in-role calibration (e4_fit.csv); mldsa87 from E1 algostats."""
    tim = {}
    for tier in ["portable", "avx2"]:
        e1 = {}
        with open(os.path.join(ROOT, "results/e1_primitives", tier,
                               "algostats.csv")) as f:
            for r in csv.DictReader(f):
                e1[r["variant"]] = float(r["verify_med_us"])
        fit = {}
        with open(os.path.join(ROOT, "results/e4_latency", "e4_fit.csv")) as f:
            for r in csv.DictReader(f):
                if r["tier"] == tier:
                    fit[r["pq"]] = (float(r["vC_ed_us"]), float(r["vQ_us"]))
        vc = fit["mldsa65"][0]
        tim[tier] = {
            "ed": vc,
            "h65": vc + fit["mldsa65"][1],
            "hfn": vc + fit["fndsa512"][1],
            "h87": vc + e1["mldsa87"],
        }
    return tim


def role_verify_us(repo, role, tim):
    """Predicted verify time for one role's threshold release from the REAL
    attached signer set (QMIN), summed over the measured per-op timings."""
    total = 0.0
    for s in repo.policies[role].quorum_signers():
        sch = scheme_of(s)
        key = "ed" if sch == ED else {"mldsa65": "h65", "mldsa87": "h87",
                                      "fndsa512": "hfn"}[sch.split(":")[2]]
        total += tim[key]
    return total


def main():
    tim = load_timings()
    byte_rows, time_rows = [], []
    detail_rows = []
    deps = {}
    for strat in STRATS:
        dep = UptaneDeployment(
            top_config(strat, "director"), top_config(strat, "image"),
            TARGET, BLOB, image_delegate={"vendor": vendor_config(strat)})
        deps[strat] = dep
        full = dep.primary_full_verify()
        part = dep.secondary_partial_verify()
        assert full["accepted"], f"{strat}: full verify failed"
        assert part["accepted"], f"{strat}: partial verify failed"
        w = dep.wire_bytes()
        d_root = w["director"]["root"]; i_root = w["image"]["root"]
        steady = w["full"] - d_root - i_root
        byte_rows.append({
            "strategy": strat,
            "full_bootstrap_B": w["full"], "full_steady_B": steady,
            "partial_ECU_B": w["partial"],
            "director_root_provisioned_B": w["director_root_provisioned"],
        })
        for side, repo in (("director", dep.director), ("image", dep.image)):
            mm = repo.measure_all()
            for role, d in mm.items():
                detail_rows.append({"strategy": strat, "repo": side,
                                    "role": role, "wire": d["wire"]})
        # latency (two tiers), threshold release
        for tier in ["portable", "avx2"]:
            tm = tim[tier]
            def rv(repo, role):
                return role_verify_us(repo, role, tm)
            d, im = dep.director, dep.image
            t_part = rv(d, "timestamp") + rv(d, "targets")
            t_full_steady = sum(rv(d, r) for r in ("timestamp", "snapshot",
                                                   "targets")) + \
                sum(rv(im, r) for r in ("timestamp", "snapshot", "targets",
                                        "vendor"))
            t_boot = t_full_steady + rv(d, "root") + rv(im, "root")
            time_rows.append({"strategy": strat, "tier": tier,
                              "T_partial_ECU_us": round(t_part, 1),
                              "T_full_steady_us": round(t_full_steady, 1),
                              "T_full_bootstrap_us": round(t_boot, 1)})
        print(f"  {strat}: full+partial verify OK | "
              f"W_partial={w['partial']}B W_full(steady)={steady}B "
              f"W_full(boot)={w['full']}B provisioned_Droot={d_root}B")

    with open(os.path.join(OUT, "e6_bytes.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(byte_rows[0].keys()))
        w.writeheader(); w.writerows(byte_rows)
    with open(os.path.join(OUT, "e6_latency.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(time_rows[0].keys()))
        w.writeheader(); w.writerows(time_rows)
    with open(os.path.join(OUT, "e6_role_detail.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(detail_rows[0].keys()))
        w.writeheader(); w.writerows(detail_rows)
    print("wrote e6_bytes.csv / e6_latency.csv / e6_role_detail.csv")

    # ratios vs full hybrid for the ECU partial path
    bf = {r["strategy"]: r for r in byte_rows}
    print("\n  ECU partial download (Director ts+targets), OPT vs F: "
          f"{100*(1-bf['OPT']['partial_ECU_B']/bf['F']['partial_ECU_B']):.1f}% saved")
    print(f"  provisioned Director root: OPT {bf['OPT']['director_root_provisioned_B']}B "
          f"(strongest ML-DSA-87, k=t) vs F {bf['F']['director_root_provisioned_B']}B")

    # ---- figure ---- #
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.2, 2.9))
    x = np.arange(len(STRATS)); wbar = 0.26
    for j, (key, lab) in enumerate([
            ("full_bootstrap_B", "bootstrap (incl. roots)"),
            ("full_steady_B", "steady state"),
            ("partial_ECU_B", "partial (ECU/Sec.)")]):
        vals = [bf[s][key] for s in STRATS]
        ax1.bar(x + (j - 1) * wbar, vals, width=wbar,
                color=["#bbbbbb", "#0072B2", "#D55E00"][j], label=lab)
    ax1.set_yscale("log")
    ax1.set_xticks(x); ax1.set_xticklabels(["classical", "full\nhybrid",
                                            "quorum-\naware", "role-mixed\n(ours)"],
                                           fontsize=7.5)
    ax1.set_ylabel("downloaded metadata (bytes, log)")
    ax1.set_title("(a) Uptane download budget", fontsize=9)
    ax1.legend(fontsize=5.9, loc='upper center', bbox_to_anchor=(0.5, -0.16),
               ncol=3, frameon=False, columnspacing=0.8,
               handlelength=1.3, handletextpad=0.4)

    # partial ECU verify latency, two tiers
    tf = {(r["strategy"], r["tier"]): r for r in time_rows}
    width = 0.38
    for j, tier in enumerate(["avx2", "portable"]):
        vals = [tf[(s, tier)]["T_partial_ECU_us"] / 1000.0 for s in STRATS]
        ax2.bar(x + (j - 0.5) * width, vals, width=width,
                color="#0072B2" if tier == "avx2" else "#E69F00",
                label=f"partial verify, {tier}")
    ax2.set_xticks(x); ax2.set_xticklabels(["classical", "full\nhybrid",
                                            "quorum-\naware", "role-mixed\n(ours)"],
                                           fontsize=7.5)
    ax2.set_ylabel("ECU partial verification time (ms)")
    ax2.set_title("(b) ECU partial verification (Director ts+targets)", fontsize=9)
    ax2.legend(fontsize=6.5)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(FIG, f"fig_e6_uptane.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote fig_e6_uptane (pdf/png)")


if __name__ == "__main__":
    main()
