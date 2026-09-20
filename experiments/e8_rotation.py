#!/usr/bin/env python3
"""E8 -- post-quantum root self-bootstrapping over multiple rollover stages.

Chain (n=5, t=3 root throughout):
  stage 0  all Ed25519, k=0                      (current classical deployment)
  stage 1  1 Ed + 4 Ed||ML-DSA-65, k=1           (PQ introduced)
  stage 2  1 Ed + 4 Ed||ML-DSA-65, k=2           (PQ majority in every quorum)
  stage 3  5 Ed||ML-DSA-87, k=3=t                (fully quantum-safe, strongest)

Every transition N->N+1 is verified with the TUF double-threshold rule:
>=t_N old-root signatures AND >=t_{N+1} new-root signatures with >=k_{N+1}
quantum-safe, version+1, non-root role keys preserved (Algorithm 3, Prop P3).
We also run four negative cases (missing old side, missing new side, version
not incremented, QS-downgrade: t classical new-side signatures with k=1).

Bytes are measured on real root metadata; the one-off rollover verification
latency is parameterized from E1/E4 measured per-op timings (two tiers).
"""
import os, csv, copy, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "impl"))
from tuf.api.metadata import Metadata                 # noqa: E402
from pqtuf.repo import PQTUFRepo, RoleConfig, measure  # noqa: E402
from pqtuf.rotate import migrate_root, verify_rotation  # noqa: E402
from pqtuf.quorum import RolePolicy                    # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "e8_rotation")
FIG = os.path.join(ROOT, "results", "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({
    "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.5,
    "figure.dpi": 130, "savefig.dpi": 300, "legend.frameon": False,
})
ED, H65, H87 = "ed25519", "hyb:ed25519:mldsa65", "hyb:ed25519:mldsa87"
N, T = 5, 3
STAGES = [
    ("stage1", [ED] + [H65] * 4, 3, 1),
    ("stage2", [ED] + [H65] * 4, 3, 2),
    ("stage3", [H87] * 5, 3, 3),
]


def scheme_of(s):
    sch = getattr(s, "scheme", None)
    if sch is None:
        uk = getattr(s, "_uk", None)
        sch = getattr(uk, "scheme", ED) if uk is not None else ED
    return sch


def load_timings():
    tim = {}
    for tier in ["portable", "avx2"]:
        e1 = {}
        with open(os.path.join(ROOT, "results/e1_primitives", tier,
                               "algostats.csv")) as f:
            for r in csv.DictReader(f):
                e1[r["variant"]] = float(r["verify_med_us"])
        ed = e1["ed25519"]
        tim[tier] = {"ed": ed, "h65": ed + e1["mldsa65"],
                     "h87": ed + e1["mldsa87"]}
    return tim


def vkey(scheme, tm):
    if scheme == ED:
        return tm["ed"]
    return tm[{"mldsa65": "h65", "mldsa87": "h87"}[scheme.split(":")[2]]]


def rollover_verify_us(old_pol, new_pol, tm):
    """One-off verification of a rotated root: old-side t_N + new-side t_{N+1}
    signatures, over the measured per-op verify times."""
    tot = 0.0
    for s in old_pol.quorum_signers():
        tot += vkey(scheme_of(s), tm)
    for s in new_pol.quorum_signers():
        tot += vkey(scheme_of(s), tm)
    return tot


def baseline_root_us(pol, tm):
    """Steady-state root verification (one threshold, t signatures)."""
    return sum(vkey(scheme_of(s), tm) for s in pol.quorum_signers())


def build_stage0():
    cfgs = {
        "root": RoleConfig([ED] * N, T, 0),
        "timestamp": RoleConfig([ED] + [H65] * 2, 2, 1),
        "snapshot": RoleConfig([ED] + [H65] * 2, 2, 1),
        "targets": RoleConfig([ED, ED, H65, H65], 3, 1),
    }
    return PQTUFRepo(cfgs, name="image")


def custom_migrate(old_repo, new_pol, bump_version=True, sign_old=True,
                   new_side_signers=None):
    """Migrate with explicit controls for negative tests."""
    old_pol = old_repo.policies["root"]
    new_signed = copy.deepcopy(old_repo.root.signed)
    if bump_version:
        new_signed.version = old_repo.root.signed.version + 1
    for s in old_pol.signers:
        kid = s.public_key.keyid
        if kid in new_signed.roles["root"].keyids:
            new_signed.revoke_key(kid, "root")
    for s in new_pol.signers:
        new_signed.add_key(s.public_key, "root")
    new_signed.roles["root"].threshold = new_pol.t
    quorum = copy.deepcopy(new_signed.unrecognized_fields.get("x-pqtuf-quorum", {}))
    quorum["root"] = {"t": new_pol.t, "k": new_pol.k,
                      "schemes": [s.public_key.scheme for s in new_pol.signers]}
    new_signed.unrecognized_fields["x-pqtuf-quorum"] = quorum
    new_md = Metadata(new_signed)
    if sign_old:
        for s in old_pol.quorum_signers():
            new_md.sign(s, append=True)
    side = new_side_signers
    if side is None:
        side = new_pol.quorum_signers()
    for s in side:
        new_md.sign(s, append=True)
    return new_md


def main():
    tim = load_timings()
    repo = build_stage0()

    # baseline steady-state root (t signatures, no rollover)
    base = measure(repo.root)
    chain_rows = [{
        "stage": "stage0", "k": 0, "root_wire_B": base["wire"],
        "n_sig": base["n_sig"], "keys_block": base["keys_block"],
        "sig_block": base["signatures_block"], "accepted": True,
        "verify_avx2_us": round(baseline_root_us(repo.policies["root"],
                                                 tim["avx2"]), 1),
        "verify_portable_us": round(baseline_root_us(repo.policies["root"],
                                                     tim["portable"]), 1),
    }]

    cur = repo
    for name, schemes, t_new, k_new in STAGES:
        old_pol = cur.policies["root"]
        new_md, new_pol, n_old, n_new = migrate_root(cur, schemes, t_new, k_new)
        rep = verify_rotation(cur, new_md, new_pol)
        d = measure(new_md)
        row = {
            "stage": name, "k": k_new, "root_wire_B": d["wire"],
            "n_sig": d["n_sig"], "keys_block": d["keys_block"],
            "sig_block": d["signatures_block"], "accepted": rep["accepted"],
            "old_threshold_ok": rep["old_threshold_ok"],
            "new_threshold_ok": rep["new_threshold_ok"],
            "new_qs_valid": rep["new_quorum"]["qs_valid"],
            "version_ok": rep["version_ok"],
            "nonroot_preserved": rep["nonroot_keys_preserved"],
            "n_old_sigs": n_old, "n_new_sigs": n_new,
            "verify_avx2_us": round(rollover_verify_us(old_pol, new_pol,
                                                       tim["avx2"]), 1),
            "verify_portable_us": round(rollover_verify_us(old_pol, new_pol,
                                                           tim["portable"]), 1),
        }
        chain_rows.append(row)
        # advance the chain: rotated root becomes the trusted current root
        cur.root = new_md
        cur.meta["root"] = new_md
        cur.policies["root"] = new_pol
        cur.configs["root"] = RoleConfig(schemes, t_new, k_new)
        print(f"  {name}: accepted={rep['accepted']} old={rep['old_threshold_ok']} "
              f"new={rep['new_threshold_ok']} qs={rep['new_quorum']['qs_valid']} "
              f"ver={rep['version_ok']} preserved={rep['nonroot_keys_preserved']} "
              f"wire={d['wire']}B n_sig={d['n_sig']}")

    with open(os.path.join(OUT, "e8_rotation.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(chain_rows[-1].keys()))
        w.writeheader(); w.writerows(chain_rows)

    # ---------------- negative cases on stage0 -> stage1 ---------------- #
    repo2 = build_stage0()
    good_schemes, gt, gk = [ED] + [H65] * 4, 3, 1
    attacks = []

    # A: missing old side
    from pqtuf import signers as _sg
    good_pol = RolePolicy("root", [_sg.make_signer(s) for s in good_schemes], gt, gk)
    md_no_old = custom_migrate(repo2, good_pol, sign_old=False)
    r = verify_rotation(repo2, md_no_old, good_pol)
    attacks.append(("A_missing_old_side", False, r["accepted"],
                    r["old_threshold_ok"], r["new_threshold_ok"],
                    r["new_quorum"]["qs_ok"], r["version_ok"]))

    # B: missing new side (only old signatures)
    md_no_new = custom_migrate(repo2, good_pol, new_side_signers=[])
    r = verify_rotation(repo2, md_no_new, good_pol)
    attacks.append(("B_missing_new_side", False, r["accepted"],
                    r["old_threshold_ok"], r["new_threshold_ok"],
                    r["new_quorum"]["qs_ok"], r["version_ok"]))

    # C: version not incremented
    md_no_ver = custom_migrate(repo2, good_pol, bump_version=False)
    r = verify_rotation(repo2, md_no_ver, good_pol)
    attacks.append(("C_version_not_incremented", False, r["accepted"],
                    r["old_threshold_ok"], r["new_threshold_ok"],
                    r["new_quorum"]["qs_ok"], r["version_ok"]))

    # D: QS downgrade -- new side has t=3 valid classical signatures, quota k=1
    weak_pol = RolePolicy("root", [_sg.make_signer(ED) for _ in range(5)], 3, 1)
    md_weak = custom_migrate(repo2, weak_pol,
                             new_side_signers=weak_pol.signers[:3])
    r = verify_rotation(repo2, md_weak, weak_pol)
    attacks.append(("D_QS_downgrade_t_classical", False, r["accepted"],
                    r["old_threshold_ok"], r["new_threshold_ok"],
                    r["new_quorum"]["qs_ok"], r["version_ok"]))

    with open(os.path.join(OUT, "e8_attacks.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "expect_accepted", "observed_accepted",
                    "old_ok", "new_ok", "new_qs_ok", "version_ok"])
        w.writerows(attacks)
    print("\n  negative cases (expect all observed_accepted=False):")
    for a in attacks:
        ok = "PASS" if a[1] == a[2] and a[2] is False else "CHECK"
        print(f"    [{ok}] {a[0]}: accepted={a[2]} old={a[3]} new={a[4]} "
              f"qs={a[5]} ver={a[6]}")

    # ------------------------------- figure ------------------------------ #
    stages = [r["stage"] for r in chain_rows]
    x = np.arange(len(stages))
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.2, 2.8))
    wire = [r["root_wire_B"] for r in chain_rows]
    nsig = [r["n_sig"] for r in chain_rows]
    bars = ax1.bar(x, wire, color=["#999999", "#E69F00", "#0072B2", "#009E73"])
    for b, n in zip(bars, nsig):
        ax1.text(b.get_x() + b.get_width() / 2, b.get_height() + 1200,
                 f"{n} sig", ha="center", fontsize=7)
    ax1.set_xticks(x); ax1.set_xticklabels(["stage 0\n(k=0)", "stage 1\n(k=1)",
                                            "stage 2\n(k=2)", "stage 3\n(k=3)"],
                                           fontsize=7.5)
    ax1.set_ylabel("rotated root metadata (bytes)")
    ax1.set_title("(a) one-off double-threshold root size", fontsize=9)
    ax1.set_ylim(top=max(wire) * 1.15)

    w = 0.38
    ax2.bar(x - w/2, [r["verify_avx2_us"] / 1000 for r in chain_rows],
            width=w, color="#0072B2", label="AVX2-optimized")
    ax2.bar(x + w/2, [r["verify_portable_us"] / 1000 for r in chain_rows],
            width=w, color="#E69F00", label="portable clean-C")
    ax2.set_xticks(x); ax2.set_xticklabels(["stage 0", "stage 1", "stage 2",
                                            "stage 3"], fontsize=7.5)
    ax2.set_ylabel("root verification time (ms)")
    ax2.set_title("(b) rollover verification (stages 1-3 one-off)", fontsize=9)
    ax2.legend(fontsize=7)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(FIG, f"fig_e8_rotation.{ext}"),
                    bbox_inches="tight")
    plt.close(fig)
    print("wrote fig_e8_rotation (pdf/png)")


if __name__ == "__main__":
    main()
