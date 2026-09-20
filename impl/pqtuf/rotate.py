"""
rotate.py -- post-quantum root self-bootstrapping via the TUF double-threshold
root rollover (formalization §3.8, Algorithm 3, Proposition P3).

A new root N+1 must carry:
  * >= t_N   valid signatures under the OLD root keys (old threshold), and
  * >= t_{N+1} valid signatures under the NEW root keys, of which >= k_{N+1}
    are quantum-safe (new threshold AND new quorum),
and version must increment by exactly one. The new root object also contains
every non-root role's keys (unchanged roles keep their trusted keys).
"""
from __future__ import annotations

import copy

from tuf.api.metadata import Metadata

from . import signers
from .quorum import RolePolicy, count_on_keys


def migrate_root(old_repo, root_schemes_new: list[str], t_new: int, k_new: int):
    """Produce a rotated root Metadata signed by both old and new root sets."""
    old_pol = old_repo.policies["root"]
    t_old = old_pol.t

    new_signed = copy.deepcopy(old_repo.root.signed)
    new_signed.version = old_repo.root.signed.version + 1

    # remove old root keys from the new root's root-role keyid list/key map
    for s in old_pol.signers:
        kid = s.public_key.keyid
        if kid in new_signed.roles["root"].keyids:
            new_signed.revoke_key(kid, "root")

    # install new root keys
    new_pol = RolePolicy(
        "root", [signers.make_signer(sc) for sc in root_schemes_new], t_new, k_new
    )
    err = new_pol.feasibility_error()
    if err:
        raise ValueError(err)
    for s in new_pol.signers:
        new_signed.add_key(s.public_key, "root")
    new_signed.roles["root"].threshold = t_new

    # authenticated quorum policy update inside the signed root
    quorum = new_signed.unrecognized_fields.get("x-pqtuf-quorum", {})
    quorum = copy.deepcopy(quorum)
    quorum["root"] = {
        "t": t_new, "k": k_new,
        "schemes": [s.public_key.scheme for s in new_pol.signers],
    }
    new_signed.unrecognized_fields["x-pqtuf-quorum"] = quorum

    new_md = Metadata(new_signed)

    # OLD side: old threshold signatures (classical in the stage-0 bootstrap)
    for s in old_pol.quorum_signers():
        new_md.sign(s, append=True)
    n_old = t_old
    # NEW side: new threshold with the new quantum-safe quota
    for s in new_pol.quorum_signers():
        new_md.sign(s, append=True)
    n_new = t_new

    return new_md, new_pol, n_old, n_new


def verify_rotation(old_repo, new_md: Metadata, new_pol: RolePolicy):
    """Validate the double-threshold rollover + new quorum + version increment."""
    report = {}
    old_root_md = old_repo.root
    old_pol = old_repo.policies["root"]

    # 1) old threshold under old root keys
    old_ok = True
    try:
        old_root_md.verify_delegate("root", new_md)
    except Exception as e:
        old_ok = False
        report["old_error"] = type(e).__name__
    report["old_threshold_ok"] = old_ok

    # 2) new threshold under new root keys (self-referential root verification)
    new_ok = True
    try:
        new_md.verify_delegate("root", new_md)
    except Exception as e:
        new_ok = False
        report["new_error"] = type(e).__name__
    report["new_threshold_ok"] = new_ok

    # 3) new quantum-safe quota over the NEW root key set
    qres = count_on_keys(
        new_md.signed.keys,
        new_md.signed.roles["root"].keyids,
        new_md.signed_bytes,
        new_md.signatures,
        new_pol.t,
        new_pol.k,
    )
    report["new_quorum"] = {
        "valid": qres.valid, "qs_valid": qres.qs_valid,
        "t": new_pol.t, "k": new_pol.k, "qs_ok": qres.qs_ok,
    }

    # 4) version increments by exactly one
    report["version_ok"] = (
        new_md.signed.version == old_root_md.signed.version + 1
    )

    # 5) non-root role keys preserved
    preserved = all(
        set(new_md.signed.roles[r].keyids)
        == set(old_root_md.signed.roles[r].keyids)
        for r in ("targets", "snapshot", "timestamp")
        if r in old_root_md.signed.roles
    )
    report["nonroot_keys_preserved"] = preserved

    report["accepted"] = (
        old_ok and new_ok and qres.qs_ok
        and report["version_ok"] and preserved
    )
    return report
