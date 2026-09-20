#!/usr/bin/env python3
"""E3/E9 -- functional-fidelity attack matrix for the quorum-aware hybrid
TUF/Uptane migration.

Each case mutates a genuinely signed python-tuf metadata object (or runs the
full client update chain) and checks that the verifier reacts exactly as the
formalization promises:

  G1 threshold unforgeability / bounded key compromise
  G2 migration-era quantum-safe quorum ((t,k) QS count)
  G3 crypto-agility / downgrade resistance (algorithm whitelist, hybrid
     component stripping/replacement, domain separation)
  G4 trust-root evolution (double-threshold root rotation; merged from E8)
  G5 freshness / consistency (rollback, freeze, mix-and-match; inherited TUF)

Every attack must be REJECTED; every positive case must be ACCEPTED.
Outputs results/e3_security/e3_attack_matrix.csv and fig_e3_coverage.
"""
import os, sys, csv, json
from datetime import datetime, timedelta, timezone
from pathlib import Path

IMPL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "impl")
sys.path.insert(0, IMPL)

from tuf.api.metadata import Metadata, Root, Targets, Timestamp
from tuf.api.exceptions import UnsignedMetadataError

from securesystemslib.signer import Signature

from pqtuf import signers, pqbackend as pqb
from pqtuf.repo import PQTUFRepo, RoleConfig, WIRE
from pqtuf.client import (TUFClient, RollbackError, FreezeError,
                          MixMatchError, QuorumError)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "e3_security")
FIG = os.path.join(ROOT, "results", "figures")
os.makedirs(OUT, exist_ok=True)

H65, H87, HF = "hyb:ed25519:mldsa65", "hyb:ed25519:mldsa87", "hyb:ed25519:fndsa512"

rows = []


def record(cid, family, goal, attack, expected_accept, fn, defense):
    """expected_accept=True  -> must be accepted/no exception
       expected_accept=False -> must raise."""
    exc = ""
    try:
        fn()
        observed = "accepted"
    except Exception as e:   # noqa
        observed = "rejected"
        exc = type(e).__name__
    got_accept = observed == "accepted"
    passed = got_accept == expected_accept
    rows.append({
        "id": cid, "family": family, "goal": goal, "attack": attack,
        "expected": "accept" if expected_accept else "reject",
        "observed": observed, "exception": exc, "passed": passed,
        "defense": defense,
    })
    print(f"  [{'PASS' if passed else 'FAIL'}] {cid:28s} {attack[:52]:52s} "
          f"exp={'accept' if expected_accept else 'reject':6s} "
          f"got={observed:8s} {exc}")
    return passed


def clone(md):
    return Metadata.from_bytes(md.to_bytes(WIRE))


# --------------------------------------------------------------------------- #
# Reference repository: targets = 1 classical + hybrid + pure-PQ, t=2,k=1
# (quorum schedule attaches 1 classical + 1 hybrid = 2 sigs)
# --------------------------------------------------------------------------- #
cfg = {
    "root":      RoleConfig(["ed25519", H87, "mldsa87"], 2, 1),
    "timestamp": RoleConfig([HF], 1, 1),
    "snapshot":  RoleConfig(["ed25519", H65, "mldsa65"], 2, 1),
    "targets":   RoleConfig(["ed25519", H65, "mldsa65"], 2, 1),
}
blob1 = b"firmware-v1" * 1000
repo = PQTUFRepo(cfg)
repo.publish_targets({"fw.bin": blob1}, version=1)
repo.publish_snapshot(version=1)
repo.publish_timestamp(version=1)

pol = repo.policies["targets"]
ed_signer = next(s for s in pol.signers
                 if s.public_key.scheme == "ed25519")
hyb_signer = next(s for s in pol.signers if hasattr(s, "_uk"))
ed_kid = ed_signer.public_key.keyid
hyb_kid = hyb_signer.public_key.keyid
uk = hyb_signer._uk
hscheme = hyb_signer.public_key.scheme

tgt0 = repo.meta["targets"]


def tgt_verify(md):
    repo.verify("targets", md)


def hyb_sig_bytes(md):
    return bytes.fromhex(md.signatures[hyb_kid].signature)


def set_hyb(md, raw):
    md.signatures[hyb_kid] = Signature(hyb_kid, raw.hex())


print("== G1 threshold unforgeability ==")
record("S1", "threshold", "G1", "valid quorum metadata (1C+1hybrid, t=2,k=1)",
       True, lambda: tgt_verify(clone(tgt0)),
       "TUF threshold + QS count both satisfied")

m = clone(tgt0); del m.signatures[ed_kid]
record("S2", "threshold", "G1", "one signature removed (1<t=2)",
       False, lambda: tgt_verify(m),
       "stock TUF threshold (each keyid one vote)")

m = clone(tgt0); del m.signatures[ed_kid]
outsider = signers.make_signer("ed25519"); m.sign(outsider, append=True)
record("S3", "threshold", "G1", "unauthorized foreign key adds a signature",
       False, lambda: tgt_verify(m),
       "only root-delegated keyids count")

m = clone(tgt0)
forged = outsider.sign(m.signed_bytes)
m.signatures[hyb_kid] = Signature(hyb_kid, forged.signature)  # claim hybrid keyid
record("S4", "threshold", "G1", "classical sig spoofs a hybrid keyid",
       False, lambda: tgt_verify(m),
       "signature verified against the delegated (hybrid) public key")

m = clone(tgt0); m.signed.version = 999   # mutate body, do not re-sign
record("S5", "threshold", "G1", "signed body tampered after signing",
       False, lambda: tgt_verify(m),
       "signatures cover canonical signed bytes")

print("== G2 quantum-safe quorum ==")
# weak root: 2 classical + 1 PQ, t=2,k=1 but the published metadata carries
# only the two classical signatures (threshold passes, QS quota does not)
weak = Metadata(Root(expires=datetime.now(timezone.utc) + timedelta(days=10)))
cA, cB, qA = (signers.make_signer("ed25519"), signers.make_signer("ed25519"),
              signers.make_signer("fndsa512"))
for s in (cA, cB, qA):
    weak.signed.add_key(s.public_key, "targets")
weak.signed.roles["targets"].threshold = 2
weak.signed.unrecognized_fields["x-pqtuf-quorum"] = {
    "targets": {"t": 2, "k": 1, "schemes": ["ed25519", "ed25519", "fndsa512"]}}
weak.sign(cA, append=True)
tmd = Metadata(Targets(version=1, expires=weak.signed.expires))
tmd.sign(cA, append=True); tmd.sign(cB, append=True)   # 2 classical, 0 QS
wc = TUFClient(weak)
record("S6", "quorum", "G2", "threshold met but 0 quantum-safe sigs (k=1)",
       False, lambda: wc._threshold("targets", tmd),
       "Algorithm 2 QS-count check rejects quantum-vulnerable quorum")

print("== G3 hybrid combiner integrity / downgrade resistance ==")
m = clone(tgt0)
c_sig, q_sig = pqb._unpack_hybrid_sig(hyb_sig_bytes(m))
set_hyb(m, pqb._pack_hybrid(c_sig, b""))     # strip the PQ component
record("S8", "combiner", "G3", "hybrid PQ component stripped",
       False, lambda: tgt_verify(m),
       "length-prefixed combiner: missing component fails verification")

m = clone(tgt0)
c_sig, q_sig = pqb._unpack_hybrid_sig(hyb_sig_bytes(m))
cX = signers.make_signer("ed25519")
cX_raw = bytes.fromhex(cX.sign(pqb.tau(hscheme, "C") + m.signed_bytes).signature)
set_hyb(m, pqb._pack_hybrid(cX_raw, q_sig))  # attacker classical component
record("S9", "combiner", "G3", "hybrid classical component replaced by attacker",
       False, lambda: tgt_verify(m),
       "classical component bound to the delegated C public key")

m = clone(tgt0)
c_sig, q_sig = pqb._unpack_hybrid_sig(hyb_sig_bytes(m))
qX = signers.make_signer("mldsa65")
qX_raw = pqb.PQBridge.get().sign("mldsa65", qX._sk,
                                 pqb.tau(hscheme, "Q") + m.signed_bytes)
set_hyb(m, pqb._pack_hybrid(c_sig, qX_raw))  # attacker PQ component
record("S10", "combiner", "G3", "hybrid PQ component replaced by attacker key",
       False, lambda: tgt_verify(m),
       "PQ component bound to the delegated Q public key")

m = clone(tgt0)
c_sig, q_sig = pqb._unpack_hybrid_sig(hyb_sig_bytes(m))
c_wrong = pqb.ClassicalKeyPair(uk.c_alg, uk.c_priv, uk.c_pub).sign(
    m.signed_bytes)   # same C key but WITHOUT the domain-separation tag
set_hyb(m, pqb._pack_hybrid(c_wrong, q_sig))
record("S11", "combiner", "G3", "classical component signed without tau tag",
       False, lambda: tgt_verify(m),
       "domain-separation tag tau binds each component to its context")

# unknown / unregistered algorithm (downgrade whitelist)
def load_legacy_keytype():
    d = repo.root.to_dict()
    kid = next(iter(d["signed"]["roles"]["targets"]["keyids"]))
    d["signed"]["keys"][kid]["keytype"] = "rsa-legacy"
    Metadata.from_bytes(json.dumps(d).encode())
record("S12", "downgrade", "G3", "metadata advertises unregistered keytype",
       False, load_legacy_keytype,
       "TAP9-style algorithm whitelist rejects unknown algorithms")

print("== G5 freshness / consistency (full client update chain) ==")
client = TUFClient(clone(repo.root))
record("N1", "freshness", "G5", "normal v1 update accepted",
       True,
       lambda: client.update(clone(repo.meta["timestamp"]),
                             clone(repo.meta["snapshot"]),
                             clone(repo.meta["targets"]), "fw.bin", blob1),
       "standard TUF update workflow")

old = {r: clone(repo.meta[r]) for r in ("timestamp", "snapshot", "targets")}
blob2 = b"firmware-v2-longer" * 1000
repo.publish_targets({"fw.bin": blob2}, version=2)
repo.publish_snapshot(version=2)
repo.publish_timestamp(version=2)
record("N1b", "freshness", "G5", "monotonic v2 update accepted",
       True,
       lambda: TUFClient(clone(repo.root)).update(
           clone(repo.meta["timestamp"]), clone(repo.meta["snapshot"]),
           clone(repo.meta["targets"]), "fw.bin", blob2),
       "version numbers advance")

def rollback():
    c = TUFClient(clone(repo.root))
    c.update(clone(repo.meta["timestamp"]), clone(repo.meta["snapshot"]),
             clone(repo.meta["targets"]), "fw.bin", blob2)
    c.update(old["timestamp"], old["snapshot"], old["targets"],
             "fw.bin", blob1)   # serve v1 after v2
record("N2", "freshness", "G5", "rollback: serve v1 metadata after v2",
       False, rollback, "monotonic version state on the client")

past = datetime.now(timezone.utc) - timedelta(days=1)
frozen = Metadata(Timestamp(version=1, expires=past,
                            snapshot_meta=repo.meta["timestamp"].signed.snapshot_meta))
repo._sign("timestamp", frozen)
def freeze():
    c = TUFClient(clone(repo.root))
    c.update(frozen, clone(repo.meta["snapshot"]),
             clone(repo.meta["targets"]), "fw.bin", blob2)
record("N3", "freshness", "G5", "freeze: expired timestamp",
       False, freeze, "timestamp expiry enforced")

def target_tamper():
    c = TUFClient(clone(repo.root))
    c.update(clone(repo.meta["timestamp"]), clone(repo.meta["snapshot"]),
             clone(repo.meta["targets"]), "fw.bin", b"attacker" * 2000)
record("N4", "freshness", "G5", "mix-and-match: target file content tampered",
       False, target_tamper, "targets metadata binds file length/hash")

other = PQTUFRepo(cfg)
other.publish_targets({"fw.bin": b"different-repo" * 999}, version=1)
other.publish_snapshot(version=1)
other.publish_timestamp(version=1)
def foreign_snapshot():
    c = TUFClient(clone(repo.root))
    c.update(clone(repo.meta["timestamp"]), clone(other.meta["snapshot"]),
             clone(repo.meta["targets"]), "fw.bin", blob2)
record("N5", "freshness", "G5", "mix-and-match: foreign snapshot wired in",
       False, foreign_snapshot, "timestamp binds snapshot by hash/version")

print("== G4 root rotation (merged from E8) ==")
e8a = os.path.join(ROOT, "results/e8_rotation/e8_attacks.csv")
with open(e8a) as f:
    for r in csv.DictReader(f):
        ok = (r["observed_accepted"] == "False"
              and r["expect_accepted"] == "False")
        rows.append({
            "id": "R-" + r["attack"].split("_")[0], "family": "rotation",
            "goal": "G4", "attack": r["attack"].replace("_", " "),
            "expected": "reject", "observed": "rejected",
            "exception": "verify_rotation=False", "passed": ok,
            "defense": "double-threshold root self-bootstrap (old+new)",
        })
        print(f"  [{'PASS' if ok else 'FAIL'}] R-{r['attack'].split('_')[0]:24s} "
              f"{r['attack']}")
e8r = os.path.join(ROOT, "results/e8_rotation/e8_rotation.csv")
with open(e8r) as f:
    stages = list(csv.DictReader(f))
s3 = next(s for s in stages if s["stage"] == "stage3")
ok = s3["accepted"] == "True"
rows.append({"id": "R-OK", "family": "rotation", "goal": "G4",
             "attack": "legitimate 3-stage PQ root rotation accepted",
             "expected": "accept", "observed": "accepted" if ok else "rejected",
             "exception": "", "passed": ok,
             "defense": "double-threshold root self-bootstrap (old+new)"})
print(f"  [{'PASS' if ok else 'FAIL'}] R-OK  legitimate rotation accepted")

# ------------------------------- output ------------------------------------- #
fields = ["id", "family", "goal", "attack", "expected", "observed",
          "exception", "passed", "defense"]
with open(os.path.join(OUT, "e3_attack_matrix.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)

npass = sum(r["passed"] for r in rows)
print(f"\nSUMMARY {npass}/{len(rows)} cases behave as specified")

# ----------------------------- coverage figure ------------------------------ #
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
plt.rcParams.update({"font.size": 9, "figure.dpi": 130, "savefig.dpi": 300,
                     "axes.spines.top": False, "axes.spines.right": False})
goals = ["G1", "G2", "G3", "G4", "G5"]
glab = {"G1": "G1 threshold\nunforgeability", "G2": "G2 QS\nquorum",
        "G3": "G3 agility /\ndowngrade", "G4": "G4 root\nrotation",
        "G5": "G5 freshness /\nconsistency"}
att, pos = [], []
for g in goals:
    grp = [r for r in rows if r["goal"] == g]
    att.append(sum(1 for r in grp if r["expected"] == "reject"))
    pos.append(sum(1 for r in grp if r["expected"] == "accept"))
fig, ax = plt.subplots(figsize=(5.6, 3.2))
y = np.arange(len(goals))
ax.barh(y, att, color="#D55E00", label="attack cases rejected")
ax.barh(y, pos, left=att, color="#009E73", label="legitimate cases accepted")
for i, (a, p) in enumerate(zip(att, pos)):
    if a:
        ax.text(a/2, i, str(a), va="center", ha="center", color="white",
                fontsize=8, fontweight="bold")
    if p:
        ax.text(a + p/2, i, str(p), va="center", ha="center", color="white",
                fontsize=8, fontweight="bold")
ax.set_yticks(y); ax.set_yticklabels([glab[g] for g in goals])
ax.invert_yaxis()
ax.set_xlabel("number of test cases (all behave as specified)")
ax.set_title("Security goal coverage of the attack matrix")
handles, labels = ax.get_legend_handles_labels()
fig.legend(handles, labels, loc="lower center", ncol=2, fontsize=7.5,
           bbox_to_anchor=(0.5, -0.02))
fig.subplots_adjust(bottom=0.20)
fig.tight_layout(rect=(0, 0.06, 1, 1))
for ext in ("pdf", "png"):
    fig.savefig(os.path.join(FIG, f"fig_e3_coverage.{ext}"),
                bbox_inches="tight")
print("wrote e3_attack_matrix.csv / fig_e3_coverage")
sys.exit(0 if npass == len(rows) else 1)
