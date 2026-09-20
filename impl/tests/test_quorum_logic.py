#!/usr/bin/env python3
"""Unit tests for Proposition P2 and the QMIN signing schedule (combinatorial
part; real-signature verification is covered in repo integration tests)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqtuf.quorum import RolePolicy

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1; print("  PASS", name)
    else:
        fail += 1; print("  FAIL", name)


class StubKey:
    def __init__(self, keytype, kid):
        self.keytype = keytype
        self.keyid = kid


class StubSigner:
    def __init__(self, keytype, i):
        self.public_key = StubKey(keytype, f"{keytype}-{i}")


def mk(c, q, t, k):
    signers = [StubSigner("ed25519", i) for i in range(c)]
    signers += [StubSigner("pq", i) for i in range(q)]
    return RolePolicy("r", signers, t, k)


def composition(r):
    """quorum_signers counts (n_classical, n_qs) actually attached."""
    chosen = r.quorum_signers()
    nc = sum(1 for s in chosen if s.public_key.keytype == "ed25519")
    nq = sum(1 for s in chosen if s.public_key.keytype == "pq")
    return nc, nq


print("== P2 feasibility (c <= t-k  <=>  h >= n-t+k) ==")
r = mk(c=1, q=2, t=2, k=1)
check("n3 t2 k1 c1: feasible", r.feasible and r.h_star == 2)
nc, nq = composition(r)
check("n3 t2 k1: attach 1C+1Q", (nc, nq) == (1, 1) and r.q_min() == 1)

r = mk(c=2, q=1, t=2, k=1)
check("n3 t2 k1 c2: INFEASIBLE (all-classical t-subset exists)",
      not r.feasible and r.feasibility_error() is not None)

r = mk(c=1, q=3, t=3, k=2)
check("n4 t3 k2 c1: feasible, h*=3", r.feasible and r.h_star == 3)
nc, nq = composition(r)
check("n4 t3 k2: attach 1C+2Q", (nc, nq) == (1, 2) and r.q_min() == 2)

r = mk(c=2, q=2, t=3, k=2)
check("n4 t3 k2 c2: INFEASIBLE (subset with only 1 QS)", not r.feasible)

print("== degeneracies ==")
r = mk(c=0, q=3, t=2, k=2)   # k=t, all must be QS
check("k=t requires h=n, attach 0C+2Q",
      r.feasible and r.h_star == 3 and composition(r) == (0, 2))
r = mk(c=1, q=2, t=2, k=2)   # k=t but a classical key present
check("k=t with a classical key infeasible", not r.feasible)

r = mk(c=3, q=0, t=2, k=0)   # classical TUF baseline
check("k=0 always feasible, attach 2C+0Q",
      r.feasible and composition(r) == (2, 0) and r.q_min() == 0)

r = mk(c=0, q=1, t=1, k=1)   # online single-key role
check("t=1 k=1 => h*=n=1, single QS sig",
      r.feasible and r.h_star == 1 and composition(r) == (0, 1))
r = mk(c=1, q=0, t=1, k=1)
check("t=1 k=1 with only classical: infeasible", not r.feasible)

r = mk(c=1, q=2, t=3, k=2)   # n=t, no redundancy
check("n=t: h*=k=2", r.feasible and r.h_star == 2 and composition(r) == (1, 2))

print("== QMIN when classical keys are scarce (c < t-k) ==")
r = mk(c=0, q=4, t=3, k=1)   # no classical at all
nc, nq = composition(r)
check("c=0: must attach 0C+3Q (q_min=max(1,3)=3)",
      (nc, nq) == (0, 3) and r.q_min() == 3)
r = mk(c=1, q=4, t=4, k=1)   # c=1 < t-k=3
nc, nq = composition(r)
check("c=1,t=4,k=1: attach 1C+3Q (q_min=max(1,3)=3)",
      (nc, nq) == (1, 3) and r.q_min() == 3)

print(f"\nSUMMARY: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
