#!/usr/bin/env python3
"""Smoke test: real PQ/hybrid sign+verify, tamper rejection, combiner binding,
and python-tuf threshold verification with the registered custom keytypes."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqtuf import pqbackend as pqb
from pqtuf import signers
from securesystemslib.signer import Key
from tuf.api.metadata import Metadata, Root, Targets

ok = 0
fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS {name}")
    else:
        fail += 1
        print(f"  FAIL {name}")


print("== 1. pure-PQ roundtrip over bridge (real PQClean signatures) ==")
for alg in pqb.PQ_ALGS:
    k = pqb.UnifiedKey.generate(alg)
    msg = b"tuf-metadata-canonical-payload"
    sig = pqb.unified_sign(k, msg)
    good = pqb.unified_verify(alg, k.pq_pk, msg, sig)
    bad = pqb.unified_verify(alg, k.pq_pk, msg + b"x", sig)
    check(f"{alg}: verify ok ({len(k.pq_pk)}B pk, {len(sig)}B sig)", good)
    check(f"{alg}: tamper rejected", not bad)

print("== 2. hybrid combiner: both components required, domain separated ==")
for hyb in ["hyb:ed25519:fndsa512", "hyb:ed25519:mldsa65", "hyb:ed25519:slhdsa128f"]:
    k = pqb.UnifiedKey.generate(hyb)
    msg = b"hybrid-payload"
    sig = pqb.unified_sign(k, msg)
    pub = pqb.hybrid_public(k.c_pub, k.pq_pk)
    check(f"{hyb} verify", pqb.unified_verify(hyb, pub, msg, sig))
    check(f"{hyb} tamper rejected", not pqb.unified_verify(hyb, pub, msg + b"!", sig))
    # component stripping: split signature and feed only one component twice-ish
    la = int.from_bytes(sig[:4], "little")
    c_sig = sig[4 : 4 + la]
    rest = sig[4 + la :]
    lb = int.from_bytes(rest[:4], "little")
    q_sig = rest[4 : 4 + lb]
    # forge a blob claiming both present but Q replaced by zeros of same length
    fake_q = b"\x00" * len(q_sig)
    stripped = (
        len(c_sig).to_bytes(4, "little") + c_sig
        + len(fake_q).to_bytes(4, "little") + fake_q
    )
    check(f"{hyb} Q-component replacement rejected",
          not pqb.unified_verify(hyb, pub, msg, stripped))

print("== 3. registered Key serialization roundtrip (verifier side) ==")
s = signers.PQSigner.generate("fndsa512")
sig = s.sign(b"payload")
d = s.public_key.to_dict()
k2 = Key.from_dict(s.public_key.keyid, d)
try:
    k2.verify_signature(sig, b"payload")
    check("fndsa512 Key.from_dict verify", True)
except Exception as e:
    check(f"fndsa512 Key.from_dict verify ({e})", False)

hs = signers.HybridSigner.generate("ed25519", "mldsa65")
hsig = hs.sign(b"payload")
hd = hs.public_key.to_dict()
hk2 = Key.from_dict(hs.public_key.keyid, hd)
try:
    hk2.verify_signature(hsig, b"payload")
    check("hybrid Key.from_dict verify", True)
except Exception as e:
    check(f"hybrid Key.from_dict verify ({e})", False)

print("== 4. python-tuf threshold with mixed classes (1 C, 1 H, 1 Q; t=2) ==")
root = Metadata(Root())
c_signer = signers.make_signer("ed25519")          # classical
h_signer = signers.make_signer("hyb:ed25519:fndsa512")  # hybrid (QS)
q_signer = signers.make_signer("slhdsa128f")       # pure PQ (QS)
three = [c_signer, h_signer, q_signer]
for sg in three:
    root.signed.add_key(sg.public_key, "targets")
root.signed.roles["targets"].threshold = 2

def threshold_accept(signers_used, label, expect=True):
    m = Metadata(Targets())
    for sg in signers_used:
        m.sign(sg, append=True)
    try:
        root.verify_delegate("targets", m)
        accepted = True
    except Exception:
        accepted = False
    check(f"{label} -> {'ACCEPTED' if accepted else 'rejected'}",
          accepted == expect)
    return accepted

threshold_accept([c_signer], "1 classical sig (t=2)", expect=False)
threshold_accept([c_signer, h_signer], "classical+hybrid (1 QS)", expect=True)
threshold_accept([c_signer, q_signer], "classical+PQ (1 QS)", expect=True)
threshold_accept([h_signer, q_signer], "hybrid+PQ (2 QS)", expect=True)
threshold_accept(three, "all three", expect=True)

print("== 5. keyid stability across rebuild ==")
kA = signers.PQSigner.generate("mldsa65").public_key
kB = Key.from_dict(kA.keyid, kA.to_dict())
check("keyid stable", kA.keyid == kB.keyid and kA == kB)

print(f"\nSUMMARY: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
