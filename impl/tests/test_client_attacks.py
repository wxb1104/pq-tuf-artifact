#!/usr/bin/env python3
"""E9 security regression: the client chain rejects rollback, freeze,
mix-and-match, target tampering, and quantum-safe-quota shortfall."""
import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tuf.api.metadata import Metadata, Root, Timestamp
from tuf.api.serialization.json import JSONSerializer

from pqtuf.repo import PQTUFRepo, RoleConfig, WIRE
from pqtuf.client import (TUFClient, RollbackError, FreezeError,
                          MixMatchError, QuorumError)
from pqtuf import signers

ok = fail = 0
def check(name, cond):
    global ok, fail
    if cond: ok += 1; print("  PASS", name)
    else: fail += 1; print("  FAIL", name)

H_FN, H_ML = "hyb:ed25519:fndsa512", "hyb:ed25519:mldsa65"
cfg = {
    "root":      RoleConfig(["ed25519", H_FN, "fndsa1024", "mldsa87"], 3, 2),
    "timestamp": RoleConfig([H_FN], 1, 1),
    "snapshot":  RoleConfig(["ed25519", H_ML, "mldsa65"], 2, 1),
    "targets":   RoleConfig(["ed25519", H_FN, "fndsa1024"], 2, 1),
}

def build(blob, ver=1):
    r = PQTUFRepo(cfg)
    r.publish_targets({"fw.bin": blob}, version=ver)
    r.publish_snapshot(version=ver)
    r.publish_timestamp(version=ver)
    return r

def clone(md):
    return Metadata.from_bytes(md.to_bytes(WIRE))

blob1 = b"firmware-v1" * 1000
r1 = build(blob1, 1)
client = TUFClient(clone(r1.root))

print("== normal update accepted ==")
res = client.update(clone(r1.meta["timestamp"]), clone(r1.meta["snapshot"]),
                    clone(r1.meta["targets"]), "fw.bin", blob1)
check("v1 update accepted", res["accepted"])

print("== rollback attack (serve older metadata after v2) ==")
old_ts, old_snap, old_tgt = (clone(r1.meta["timestamp"]),
                             clone(r1.meta["snapshot"]),
                             clone(r1.meta["targets"]))
blob2 = b"firmware-v2-longer" * 1000
# same repository/keys, version incremented to 2
r1.publish_targets({"fw.bin": blob2}, version=2)
r1.publish_snapshot(version=2)
r1.publish_timestamp(version=2)
res2 = client.update(clone(r1.meta["timestamp"]), clone(r1.meta["snapshot"]),
                     clone(r1.meta["targets"]), "fw.bin", blob2)
check("v2 update accepted (monotonic)", res2["accepted"])
try:
    client.update(old_ts, old_snap, old_tgt, "fw.bin", blob1)
    check("rollback to v1 rejected", False)
except RollbackError:
    check("rollback to v1 rejected", True)
except Exception as e:
    check(f"rollback rejected (got {type(e).__name__})", False)

print("== freeze attack (expired timestamp) ==")
c3 = TUFClient(clone(r1.root))
past = datetime.now(timezone.utc) - timedelta(days=1)
sm = r1.meta["timestamp"].signed.snapshot_meta
frozen = Metadata(Timestamp(version=1, expires=past, snapshot_meta=sm))
r1._sign("timestamp", frozen)
try:
    c3.update(frozen, clone(r1.meta["snapshot"]), clone(r1.meta["targets"]),
              "fw.bin", blob1)
    check("expired timestamp rejected", False)
except FreezeError:
    check("expired timestamp rejected", True)

print("== mix-and-match: target file tampered ==")
c4 = TUFClient(clone(r1.root))
try:
    c4.update(clone(r1.meta["timestamp"]), clone(r1.meta["snapshot"]),
              clone(r1.meta["targets"]), "fw.bin", b"attacker-content" * 1000)
    check("tampered target file rejected", False)
except MixMatchError:
    check("tampered target file rejected", True)

print("== mix-and-match: snapshot not matching timestamp hash ==")
c5 = TUFClient(clone(r1.root))
other = build(b"different-repo-content" * 999, 1)
try:
    c5.update(clone(r1.meta["timestamp"]), clone(other.meta["snapshot"]),
              clone(r1.meta["targets"]), "fw.bin", blob1)
    check("foreign snapshot rejected", False)
except MixMatchError:
    check("foreign snapshot rejected", True)

print("== quantum-safe quota shortfall (weak/transition config) ==")
weak = Metadata(Root(expires=datetime.now(timezone.utc) + timedelta(days=10)))
cA, cB, qA = (signers.make_signer("ed25519"), signers.make_signer("ed25519"),
              signers.make_signer("fndsa512"))
for s in (cA, cB, qA):
    weak.signed.add_key(s.public_key, "targets")
weak.signed.roles["targets"].threshold = 2
weak.signed.unrecognized_fields["x-pqtuf-quorum"] = {
    "targets": {"t": 2, "k": 1, "schemes": ["ed25519", "ed25519", "fndsa512"]}}
weak.sign(cA, append=True)  # root self-signature not used in _threshold check
from tuf.api.metadata import Targets
tmd = Metadata(Targets(version=1, expires=weak.signed.expires))
tmd.sign(cA, append=True); tmd.sign(cB, append=True)  # 2 classical, 0 QS
try:
    wc = TUFClient(weak)
    wc._threshold("targets", tmd)
    check("all-classical threshold with k=1 rejected", False)
except QuorumError:
    check("all-classical threshold with k=1 rejected", True)

print(f"\nSUMMARY: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
