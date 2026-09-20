#!/usr/bin/env python3
"""Integration tests on real python-tuf metadata (fast schemes only)."""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqtuf.repo import PQTUFRepo, RoleConfig, measure, WIRE
from pqtuf import rotate
from pqtuf.uptane import UptaneDeployment
from pqtuf.quorum import count_on_keys
from tuf.api.metadata import Metadata, Root, Targets

ok = fail = 0
def check(name, cond):
    global ok, fail
    if cond: ok += 1; print("  PASS", name)
    else: fail += 1; print("  FAIL", name)

H_FN = "hyb:ed25519:fndsa512"
H_ML = "hyb:ed25519:mldsa65"

print("== A. full multi-role quorum-aware repository ==")
cfg = {
    "root":      RoleConfig(["ed25519", H_FN, "fndsa1024", "mldsa87"], t=3, k=2),
    "timestamp": RoleConfig([H_FN], t=1, k=1),
    "snapshot":  RoleConfig(["ed25519", H_ML, "mldsa65"], t=2, k=1),
    "targets":   RoleConfig(["ed25519", H_FN, "fndsa1024"], t=2, k=1),
}
repo = PQTUFRepo(cfg)
fw = b"firmware-image-bytes" * 5000
repo.publish_targets({"fw.bin": fw})
repo.publish_snapshot()
repo.publish_timestamp()
for r in ("root", "targets", "snapshot", "timestamp"):
    res = repo.verify(r)
    check(f"{r}: threshold+quorum accepted (valid={res.valid},qs={res.qs_valid})",
          res.accepted)

print("== B. exact wire byte accounting ==")
for r, m in repo.measure_all().items():
    print(f"   {r:9s} wire={m['wire']:7d}B  n_sig={m['n_sig']} "
          f"sig_bytes={m['sig_bytes']} keys_block={m['keys_block']}")
check("byte accounting produced", all(measure(md)["wire"] > 0
                                      for md in repo.meta.values()))

print("== C. threshold shortfall and tamper are rejected ==")
m = Metadata(Targets(version=1, expires=repo.meta['targets'].signed.expires))
m.sign(repo.policies['targets'].signers[0], append=True)  # only 1 of t=2
try:
    repo.tuf_verify("targets", m); check("1<t rejected", False)
except Exception: check("1<t rejected", True)

bad = Metadata.from_bytes(repo.meta["targets"].to_bytes(WIRE))
bad.signed.version = 99  # invalidate every signature over signed payload
res = repo.quorum_result("targets", bad)
check("tampered metadata: no valid signature", res.valid == 0 and not res.accepted)

print("== D. P2 in a FEASIBLE config: threshold passing implies quorum met ==")
pol = repo.policies["targets"]
import itertools
holds = True
for combo in itertools.combinations(range(pol.n), pol.t):
    md = Metadata(Targets(version=2, expires=repo.meta['targets'].signed.expires))
    for i in combo:
        md.sign(pol.signers[i], append=True)
    r = repo.quorum_result("targets", md)
    if r.threshold_ok and not r.qs_ok:
        holds = False
check("every t-subset meeting threshold has >=k QS (Proposition P2)", holds)

print("== E. QS-count check rejects all-classical threshold in a WEAK config ==")
# bypass the feasibility constructor to emulate a transition/weak deployment:
# 2 classical + 1 QS, t=2, k=1 (c=2 > t-k=1, infeasible by P2)
weak = Metadata(Rot := Root(expires=__import__('datetime').datetime.now(
    __import__('datetime').timezone.utc) + __import__('datetime').timedelta(days=10)))
from pqtuf import signers
c1, c2 = signers.make_signer("ed25519"), signers.make_signer("ed25519")
q1 = signers.make_signer("fndsa512")
for s in (c1, c2, q1):
    weak.signed.add_key(s.public_key, "targets")
weak.signed.roles["targets"].threshold = 2
weak.sign(c1, append=True); weak.sign(c2, append=True)  # bootstrap root sigs later
tmd = Metadata(Targets(version=1, expires=weak.signed.expires))
tmd.sign(c1, append=True); tmd.sign(c2, append=True)  # 2 classical, 0 QS
qr = count_on_keys(weak.signed.keys, weak.signed.roles["targets"].keyids,
                   tmd.signed_bytes, tmd.signatures, t=2, k=1)
check("threshold passes (2 valid) but QS quota fails -> QVerify rejects",
      qr.threshold_ok and not qr.qs_ok)

print("== F. root double-threshold PQ rollover (Algorithm 3 / P3) ==")
stage0 = PQTUFRepo({
    "root":      RoleConfig(["ed25519", "ed25519", "ed25519"], t=2, k=0),
    "timestamp": cfg["timestamp"], "snapshot": cfg["snapshot"],
    "targets": cfg["targets"],
})
new_root_md, new_pol, nold, nnew = rotate.migrate_root(
    stage0, ["ed25519", H_FN, "fndsa1024"], t_new=2, k_new=1
)
rep = rotate.verify_rotation(stage0, new_root_md, new_pol)
print("   rotation report:", rep)
check("rotation accepted (old+t new threshold, new quorum, version+1, keys kept)",
      rep["accepted"])
# sabotage: drop one OLD-side signature -> old threshold must fail
sab = Metadata.from_bytes(new_root_md.to_bytes(WIRE))
old_kids = [s.public_key.keyid for s in stage0.policies["root"].signers]
sab.signatures = {k: v for k, v in sab.signatures.items() if k not in old_kids[:1]}
rep2 = rotate.verify_rotation(stage0, sab, new_pol)
check("missing old-threshold signature rejected", not rep2["accepted"]
      and not rep2["old_threshold_ok"])

print("== G. Uptane: Director/Image full + ECU partial + agreement ==")
dcfg = {"root": cfg["root"], "timestamp": cfg["timestamp"],
        "snapshot": cfg["snapshot"],
        "targets": RoleConfig(["ed25519", H_FN, "fndsa1024"], t=2, k=1)}
up = UptaneDeployment(dcfg, dcfg, "fw.bin", fw)
full = up.primary_full_verify()
part = up.secondary_partial_verify()
wb = up.wire_bytes()
check("Primary full verification accepted", full["accepted"])
check("Secondary partial verification accepted", part["accepted"])
check("Director/Image target agreement", full["target_agreement"])
print(f"   W_full={wb['full']}B  W_partial={wb['partial']}B  "
      f"(pre-provisioned Director root={wb['director_root_provisioned']}B)")
print("   director wires:", wb["director"])
print("   image wires:", wb["image"])
# custom attack: a compromised Director legitimately signs a target whose
# length/hash disagrees with the Image repo (valid Director threshold+quorum,
# but cross-repo agreement must fail)
up.director.publish_targets({"fw.bin": b"malicious-firmware-image" * 10},
                           version=2)
full2 = up.primary_full_verify()
check("Director/Image disagreement (custom attack) rejected",
      not full2["target_agreement"])

print(f"\nSUMMARY: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
