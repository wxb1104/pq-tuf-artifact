"""
quorum.py -- quorum-aware hybrid threshold (formalization §3).

A role has n independent keys, threshold t, and a quantum-safe quota k:
EVERY t-sized valid signer subset must contain >= k quantum-safe (pure-PQ or
hybrid) signers. Proposition P2: this is equivalent to

        c <= t - k   <=>   h >= n - t + k,   h* = n - t + k

Algorithm 1 (QSign) minimizes the number of PQ/hybrid signatures actually
produced for one publication: (t-k) classical + k quantum-safe = t sigs.
Algorithm 2 (QVerify) adds the single QS-count check on top of the unchanged
TUF threshold verification (each keyid at most one vote).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .signers import Signer, key_is_qs


@dataclass
class RolePolicy:
    role: str
    signers: list[Signer]
    t: int
    k: int

    def __post_init__(self):
        self.n = len(self.signers)
        if not (1 <= self.t <= self.n):
            raise ValueError(f"{self.role}: threshold {self.t} not in [1,{self.n}]")
        if not (0 <= self.k <= self.t):
            raise ValueError(f"{self.role}: quota {self.k} not in [0,{self.t}]")
        self.qs = [key_is_qs(s.public_key) for s in self.signers]
        self.h = sum(self.qs)          # number of quantum-safe keys
        self.c = self.n - self.h       # classical keys
        self.h_star = self.n - self.t + self.k if self.k > 0 else 0

    # ---- Proposition P2: configuration robustness (any online t-subset) ----
    @property
    def feasible(self) -> bool:
        """True iff every t-subset of valid signers contains >= k QS keys."""
        if self.k == 0:
            return True
        return self.c <= self.t - self.k   # <=> h >= n - t + k

    def feasibility_error(self) -> str | None:
        if not self.feasible:
            return (
                f"{self.role}: n={self.n} t={self.t} k={self.k} has c={self.c} "
                f"classical keys; need c<={self.t - self.k} (h>={self.h_star}); "
                f"a t-subset with only {self.k - 1} QS signer can pass."
            )
        return None

    # ---- Algorithm 1: quorum-aware signing schedule (QMIN) ----
    def quorum_signers(self) -> list[Signer]:
        """Minimum QS signatures for one publication: (t-k) C + k QS."""
        c_keys = [s for s, q in zip(self.signers, self.qs) if not q]
        q_keys = [s for s, q in zip(self.signers, self.qs) if q]
        n_c = min(len(c_keys), self.t - self.k)
        n_q = self.t - n_c
        if n_q > len(q_keys):
            raise RuntimeError(
                f"{self.role}: need {n_q} QS signers but only {len(q_keys)} "
                f"(configuration infeasible)"
            )
        chosen = c_keys[:n_c] + q_keys[:n_q]
        assert len(chosen) == self.t
        return chosen

    def q_min(self) -> int:
        """Minimum number of QS signatures actually attached (QMIN)."""
        return max(self.k, self.t - self.c)

    # baseline schedules for comparison experiments
    def threshold_signers_all_classical_first(self) -> list[Signer]:
        """Naive threshold publication ignoring class (first t available)."""
        return self.signers[: self.t]

    def all_signers(self) -> list[Signer]:
        return list(self.signers)


@dataclass
class QuorumResult:
    threshold_ok: bool
    qs_ok: bool
    valid: int
    qs_valid: int
    t: int
    k: int
    per_keyid: dict = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.threshold_ok and self.qs_ok


def count_on_keys(keys: dict, keyids: list, payload: bytes,
                  signatures: dict, t: int, k: int) -> QuorumResult:
    """Low-level Algorithm-2 count over an explicit key map and keyid allow-list
    (works for top-level roles via Root and delegated roles via Delegations)."""
    allow = set(keyids)
    valid, qs_valid = 0, 0
    per: dict = {}
    seen: set[str] = set()
    for keyid, sig in signatures.items():
        if keyid in seen or keyid not in allow:
            continue
        seen.add(keyid)
        key = keys.get(keyid)
        if key is None:
            per[keyid] = "no-key"
            continue
        try:
            key.verify_signature(sig, payload)
        except Exception:
            per[keyid] = "invalid"
            continue
        is_qs = key_is_qs(key)
        valid += 1
        if is_qs:
            qs_valid += 1
        per[keyid] = "qs-valid" if is_qs else "c-valid"
    return QuorumResult(
        threshold_ok=valid >= t, qs_ok=qs_valid >= k,
        valid=valid, qs_valid=qs_valid, t=t, k=k, per_keyid=per,
    )


def count_signatures(root_signed, role: str, delegated, t: int, k: int) -> QuorumResult:
    """
    Algorithm 2 over a real python-tuf Metadata object.
    `root_signed` is the Root signed container supplying keys/keyids.
    Counts valid signatures (each keyid at most one vote) and the QS subset.
    """
    role_info = root_signed.roles[role]
    return count_on_keys(
        root_signed.keys, role_info.keyids,
        delegated.signed_bytes, delegated.signatures, t, k,
    )


def verify_quorum(root_signed, role: str, delegated, t: int, k: int) -> QuorumResult:
    return count_signatures(root_signed, role, delegated, t, k)
