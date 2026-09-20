"""
repo.py -- a real python-tuf multi-role repository with quorum-aware hybrid
threshold signing and exact on-the-wire byte accounting.

Roles: root, timestamp, snapshot, targets (+ arbitrary delegated target roles,
TAP 3). Every signature is produced by the registered PQ/hybrid/classical
signers and verified by stock python-tuf threshold verification plus the
Algorithm-2 QS-count check.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

from . import signers
from .quorum import RolePolicy, count_on_keys

WIRE = JSONSerializer(compact=True)
CANON = JSONSerializer(compact=True)  # signed_bytes is canonical regardless
TOP_ROLES = ["root", "targets", "snapshot", "timestamp"]


def _future(days=3650):
    return datetime.now(timezone.utc) + timedelta(days=days)


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass
class RoleConfig:
    schemes: list[str]
    t: int
    k: int

    @property
    def n(self) -> int:
        return len(self.schemes)


def measure(md: Metadata) -> dict:
    """Exact byte accounting for one metadata file (compact JSON wire form)."""
    wire = md.to_bytes(WIRE)
    d = md.to_dict()
    signed = d["signed"]
    sigs = d["signatures"]
    sig_list = list(sigs.values()) if isinstance(sigs, dict) else sigs
    sig_block = json.dumps(sigs, separators=(",", ":")).encode()
    keys_block = b""
    if "keys" in signed:
        keys_block = json.dumps(signed["keys"], separators=(",", ":")).encode()
    sig_lens = sorted(
        (len(bytes.fromhex(s["sig"])) for s in sig_list),
        reverse=True,
    )
    return {
        "wire": len(wire),
        "signed_canonical": len(md.signed_bytes),
        "signatures_block": len(sig_block),
        "keys_block": len(keys_block),
        "n_sig": len(d["signatures"]),
        "sig_bytes": sig_lens,
    }


class PQTUFRepo:
    def __init__(self, configs: dict[str, RoleConfig], name: str = "image"):
        self.name = name
        self.configs = configs
        self.policies: dict[str, RolePolicy] = {}
        for role, cfg in configs.items():
            pol = RolePolicy(
                role, [signers.make_signer(s) for s in cfg.schemes], cfg.t, cfg.k
            )
            err = pol.feasibility_error()
            if err:
                raise ValueError(err)
            self.policies[role] = pol

        self.root = Metadata(Root(expires=_future()))
        for role, pol in self.policies.items():
            if role in TOP_ROLES:
                for s in pol.signers:
                    self.root.signed.add_key(s.public_key, role)
                self.root.signed.roles[role].threshold = pol.t
        # quorum policy travels inside the signed root (algorithm agility /
        # downgrade protection: k is authenticated, formalization §3.6).
        self.root.signed.unrecognized_fields["x-pqtuf-quorum"] = {
            role: {"t": p.t, "k": p.k,
                   "schemes": [s.public_key.scheme for s in p.signers]}
            for role, p in self.policies.items()
        }
        self._sign("root", self.root)
        self.meta: dict[str, Metadata] = {"root": self.root}
        self._target_files: dict[str, bytes] = {}

    # ----------------------------- signing ----------------------------- #
    def _chosen(self, role: str, schedule: str) -> list:
        pol = self.policies[role]
        if schedule == "quorum":
            return pol.quorum_signers()
        if schedule == "all":
            return pol.all_signers()
        if schedule == "threshold-naive":
            return pol.threshold_signers_all_classical_first()
        raise ValueError(schedule)

    def _sign(self, role: str, md: Metadata, schedule: str = "quorum") -> None:
        for s in self._chosen(role, schedule):
            md.sign(s, append=True)

    # --------------------------- target roles --------------------------- #
    def publish_targets(self, files: dict[str, bytes], role: str = "targets",
                        version: int = 1, schedule: str = "quorum",
                        delegate: dict[str, RoleConfig] | None = None) -> Metadata:
        targets = {}
        for fname, blob in files.items():
            self._target_files[fname] = blob
            targets[fname] = TargetFile(
                len(blob), {"sha256": _sha256(blob)}, fname
            )
        delegations = None
        if delegate:
            dkeys: dict = {}
            droles: dict[str, DelegatedRole] = {}
            for dname, dcfg in delegate.items():
                dpol = RolePolicy(
                    dname, [signers.make_signer(s) for s in dcfg.schemes],
                    dcfg.t, dcfg.k,
                )
                err = dpol.feasibility_error()
                if err:
                    raise ValueError(err)
                self.policies[dname] = dpol
                self.configs[dname] = dcfg
                for s in dpol.signers:
                    dkeys[s.public_key.keyid] = s.public_key
                droles[dname] = DelegatedRole(
                    dname, [s.public_key.keyid for s in dpol.signers],
                    dpol.t, False, paths=["*"]
                )
            delegations = Delegations(dkeys, droles)
        md = Metadata(Targets(version=version, expires=_future(),
                              targets=targets, delegations=delegations))
        self._sign(role, md, schedule)
        self.meta[role] = md
        return md

    def publish_delegated(self, parent: str, name: str,
                          files: dict[str, bytes], version: int = 1,
                          schedule: str = "quorum") -> Metadata:
        targets = {
            f: TargetFile(len(b), {"sha256": _sha256(b)}, f)
            for f, b in files.items()
        }
        md = Metadata(Targets(version=version, expires=_future(), targets=targets))
        self._sign(name, md, schedule)
        self.meta[name] = md
        return md

    # --------------------- snapshot / timestamp ------------------------ #
    def publish_snapshot(self, target_roles=("targets",), version: int = 1,
                         schedule: str = "quorum") -> Metadata:
        meta = {}
        for r in target_roles:
            raw = self.meta[r].to_bytes(WIRE)
            meta[f"{r}.json"] = MetaFile(
                self.meta[r].signed.version, len(raw), {"sha256": _sha256(raw)}
            )
        md = Metadata(Snapshot(version=version, expires=_future(), meta=meta))
        self._sign("snapshot", md, schedule)
        self.meta["snapshot"] = md
        return md

    def publish_timestamp(self, version: int = 1,
                          schedule: str = "quorum") -> Metadata:
        raw = self.meta["snapshot"].to_bytes(WIRE)
        snap_meta = MetaFile(
            self.meta["snapshot"].signed.version, len(raw),
            {"sha256": _sha256(raw)}
        )
        md = Metadata(Timestamp(version=version, expires=_future(),
                                snapshot_meta=snap_meta))
        self._sign("timestamp", md, schedule)
        self.meta["timestamp"] = md
        return md

    # ----------------------------- verify ------------------------------ #
    def tuf_verify(self, role: str, md: Metadata) -> bool:
        """Stock TUF threshold verification (keyid one-vote), incl. delegates."""
        if role in TOP_ROLES:
            self.root.verify_delegate(role, md)
            return True
        # delegated role: parent is targets
        self.meta["targets"].verify_delegate(role, md)
        return True

    def quorum_result(self, role: str, md: Metadata):
        pol = self.policies[role]
        if role in TOP_ROLES:
            keys = self.root.signed.keys
            keyids = self.root.signed.roles[role].keyids
        else:
            deleg = self.meta["targets"].signed.delegations
            keys = deleg.keys
            keyids = deleg.roles[role].keyids
        return count_on_keys(keys, keyids, md.signed_bytes,
                             md.signatures, pol.t, pol.k)

    def verify(self, role: str, md: Metadata | None = None):
        md = md or self.meta[role]
        self.tuf_verify(role, md)          # raises UnsignedMetadataError if <t
        res = self.quorum_result(role, md)
        if not res.qs_ok:
            raise ValueError(
                f"{role}: quorum QS quota unmet ({res.qs_valid}<{pol_k(self,role)})"
            )
        return res

    def measure_all(self) -> dict[str, dict]:
        return {r: measure(md) for r, md in self.meta.items()}


def pol_k(repo: PQTUFRepo, role: str) -> int:
    return repo.policies[role].k
