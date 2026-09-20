#!/usr/bin/env python3
"""E10 -- end-to-end lifecycle amortization.

Per-update metadata bytes and verification times are the *measured* E5/E6
values on real python-tuf metadata. Cumulative cost over U updates is the
deterministic linear extension U * per-update (every steady-state update
re-publishes timestamp/snapshot/targets of identical structure). The three
measured E8 double-threshold root rollovers (classical -> hybrid k=1 -> k=2 ->
fully QS ML-DSA-87) are inserted every R updates; they are one-off migration
spikes that amortize over the deployment lifetime.

We report, for Primary (full, both repos) and ECU/Secondary (partial):
  * cumulative downloaded metadata vs U for C/F/QA/OPT,
  * the share of the three rollover spikes at U=365 (amortization),
  * cumulative verification time (both tiers).
No value is estimated: only multiplication/addition over measured singles.
"""
import os, csv, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E6 = os.path.join(ROOT, "results", "e6_uptane")
E8 = os.path.join(ROOT, "results", "e8_rotation")
OUT = os.path.join(ROOT, "results", "e10_lifecycle")
FIG = os.path.join(ROOT, "results", "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({
    "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.5,
    "figure.dpi": 130, "savefig.dpi": 300, "legend.frameon": False,
})
STRATS = ["C", "F", "QA", "OPT"]
LABEL = {"C": "classical", "F": "full hybrid", "QA": "quorum-aware",
         "OPT": "role-mixed (ours)"}
COLOR = {"C": "#999999", "F": "#D55E00", "QA": "#0072B2", "OPT": "#009E73"}
U_MAX = 365          # daily updates for one year
R = 90               # one root rollover per quarter during migration


def read_e6():
    byt, lat = {}, {}
    with open(os.path.join(E6, "e6_bytes.csv")) as f:
        for r in csv.DictReader(f):
            byt[r["strategy"]] = {
                "full_steady": int(r["full_steady_B"]),
                "partial": int(r["partial_ECU_B"]),
            }
    with open(os.path.join(E6, "e6_latency.csv")) as f:
        for r in csv.DictReader(f):
            lat[(r["strategy"], r["tier"])] = {
                "full": float(r["T_full_steady_us"]),
                "partial": float(r["T_partial_ECU_us"]),
            }
    return byt, lat


def read_e8_spikes():
    """Measured one-off rotated-root bytes for the three migration stages."""
    spikes = []
    with open(os.path.join(E8, "e8_rotation.csv")) as f:
        for r in csv.DictReader(f):
            if r["stage"] != "stage0":
                spikes.append(int(r["root_wire_B"]))
    return spikes   # stage1, stage2, stage3


def cumulative(per_update, spikes, n_repos, u_max=U_MAX, r=R):
    """Linear steady accumulation plus one-off rollover spikes.
    n_repos: Primary downloads both Director+Image roots (2); the ECU/
    Secondary only the Director root (1). Pass spikes=[] for a strategy with
    no measured migration path (steady-state comparison only)."""
    cu = np.zeros(u_max + 1)
    for u in range(1, u_max + 1):
        cu[u] = cu[u - 1] + per_update
        # migration rollover at u = r, 2r, 3r (three measured stages)
        stage = u // r
        if spikes and u % r == 0 and 1 <= stage <= len(spikes):
            cu[u] += spikes[stage - 1] * n_repos
    return cu


def main():
    byt, lat = read_e6()
    spikes = read_e8_spikes()
    print(f"measured rollover root bytes (single repo): {spikes}")
    U = np.arange(U_MAX + 1)

    curves_primary = {
        s: cumulative(byt[s]["full_steady"],
                      spikes if s == "OPT" else [], 2 if s == "OPT" else 0)
        for s in STRATS}
    curves_ecu = {
        s: cumulative(byt[s]["partial"],
                      spikes if s == "OPT" else [], 1 if s == "OPT" else 0)
        for s in STRATS}

    # ----------------------------- tables ----------------------------- #
    rows = []
    for s in STRATS:
        cp, ce = curves_primary[s], curves_ecu[s]
        spike_p = sum(spikes) * 2 if s == "OPT" else 0
        spike_e = sum(spikes) * 1 if s == "OPT" else 0
        rows.append({
            "strategy": s,
            "per_update_primary_B": byt[s]["full_steady"],
            "per_update_ECU_B": byt[s]["partial"],
            "primary_cum_365_B": int(cp[365]),
            "ECU_cum_365_B": int(ce[365]),
            "rollover_spikes_primary_B": spike_p,
            "rollover_share_primary_pct":
                round(100 * spike_p / cp[365], 2) if spike_p else "NA",
            "rollover_share_ECU_pct":
                round(100 * spike_e / ce[365], 2) if spike_e else "NA",
        })
    with open(os.path.join(OUT, "e10_cumulative.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    # savings of OPT and QA vs full hybrid at U=365
    def save(view, a, b="F"):
        d = curves_primary if view == "primary" else curves_ecu
        return 100 * (d[b][365] - d[a][365]) / d[b][365]
    print("\n  cumulative bytes at U=365:")
    for r_ in rows:
        rsp = r_["rollover_share_primary_pct"]
        rse = r_["rollover_share_ECU_pct"]
        rsp = f"{rsp}%" if rsp != "NA" else "no PQ migration"
        rse = f"{rse}%" if rse != "NA" else "no PQ migration"
        print(f"    {r_['strategy']:3s} primary={r_['primary_cum_365_B']/1e6:6.2f}MB "
              f"ECU={r_['ECU_cum_365_B']/1e6:5.2f}MB "
              f"rollover-share primary={rsp} ECU={rse}")
    print(f"\n  OPT vs full-hybrid cumulative saving at 365: "
          f"primary {save('primary','OPT'):.1f}%  ECU {save('ecu','OPT'):.1f}%")
    print(f"  QA  vs full-hybrid cumulative saving at 365: "
          f"primary {save('primary','QA'):.1f}%  ECU {save('ecu','QA'):.1f}%")

    # cumulative verification time (s) at U=365, both tiers
    vrows = []
    for tier in ["avx2", "portable"]:
        for s in STRATS:
            lf, le = lat[(s, tier)]["full"], lat[(s, tier)]["partial"]
            vrows.append({"tier": tier, "strategy": s,
                          "primary_verify_365_s": round(lf * 365 / 1e6, 3),
                          "ECU_verify_365_s": round(le * 365 / 1e6, 3)})
    with open(os.path.join(OUT, "e10_verify_cumulative.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(vrows[0].keys()))
        w.writeheader(); w.writerows(vrows)

    # ----------------------------- figure ----------------------------- #
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.4, 2.9))
    for s in STRATS:
        ax1.plot(U, curves_primary[s] / 1e6, color=COLOR[s],
                 label=LABEL[s], lw=1.8)
    # mark rollover spikes on the OPT primary curve
    optp = curves_primary["OPT"] / 1e6
    for j, uu in enumerate((R, 2 * R, 3 * R), start=1):
        ax1.scatter([uu], [optp[uu]], color="#009E73", s=14, zorder=5,
                    marker="^")
    ax1.annotate("3 dual-threshold root roll-overs", xy=(R, optp[R]),
                 xytext=(126, 2.6), fontsize=6.6, ha="left",
                 bbox=dict(boxstyle="round,pad=0.2", fc="white",
                           ec="0.7", lw=0.5, alpha=0.95),
                 arrowprops=dict(arrowstyle="->", lw=0.7, color="#009E73"))
    ax1.set_xlabel("number of updates $U$ (daily)")
    ax1.set_ylabel("cumulative metadata downloaded (MB)")
    ax1.set_title("(a) Primary, full verification (both repos)", fontsize=9)
    ax1.legend(fontsize=7, loc="upper left")

    for s in STRATS:
        ax2.plot(U, curves_ecu[s] / 1e6, color=COLOR[s],
                 label=LABEL[s], lw=1.8)
    opte = curves_ecu["OPT"] / 1e6
    for uu in (R, 2 * R, 3 * R):
        ax2.scatter([uu], [opte[uu]], color="#009E73", s=14, zorder=5,
                    marker="^")
    ax2.set_xlabel("number of updates $U$ (daily)")
    ax2.set_ylabel("cumulative metadata downloaded (MB)")
    ax2.set_title("(b) ECU/Secondary, partial verification", fontsize=9)
    ax2.legend(fontsize=7, loc="upper left")
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(FIG, f"fig_e10_lifecycle.{ext}"),
                    bbox_inches="tight")
    plt.close(fig)
    print("\nwrote e10_cumulative.csv / e10_verify_cumulative.csv / "
          "fig_e10_lifecycle")


if __name__ == "__main__":
    main()
