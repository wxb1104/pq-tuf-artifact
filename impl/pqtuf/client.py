"""
client.py -- a real TUF/Uptane client verification chain with the quorum QS
check, implementing the reference update workflow (TUF §6) so that the classic
supply-chain attacks are rejected:

  * rollback attack   -- metadata version must be monotonically non-decreasing
  * freeze attack     -- timestamp must not be expired
  * mix-and-match     -- timestamp binds snapshot; snapshot binds targets by
                         version/length/hash; targets bind target files
  * threshold/quorum  -- every metadata needs >= t valid signatures of which
                         >= k are quantum-safe (Algorithm 2)

The trusted root is provisioned out-of-band (and rotated via the double-
threshold root rollover). The client reads (t,k) from the signed root.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.serialization.json import JSONSerializer

from .quorum import count_on_keys

WIRE = JSONSerializer(compact=True)


class UpdateError(Exception):
    """Base class for client-side update rejection."""


class RollbackError(UpdateError):
    pass


class FreezeError(UpdateError):
    pass


class MixMatchError(UpdateError):
    pass


class QuorumError(UpdateError):
    pass


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _quorum_check(root_signed, role: str, md) -> None:
    t = root_signed.roles[role].threshold
    qfield = root_signed.unrecognized_fields.get("x-pqtuf-quorum", {})
    k = qfield.get(role, {}).get("k", 0)
    keys = root_signed.keys
    keyids = root_signed.roles[role].keyids
    res = count_on_keys(keys, keyids, md.signed_bytes, md.signatures, t, k)
    if not res.threshold_ok:
        raise UnsignedMetadataError(
            f"{role}: {res.valid}/{t} valid signatures"
        )
    if not res.qs_ok:
        raise QuorumError(f"{role}: only {res.qs_valid}/{k} quantum-safe sigs")


def _bind(meta_file, raw: bytes, label: str) -> None:
    """Enforce length/hash binding advertised by a parent metadata."""
    if meta_file.length is not None and len(raw) != meta_file.length:
        raise MixMatchError(f"{label}: length {len(raw)}!={meta_file.length}")
    if meta_file.hashes:
        for algo, want in meta_file.hashes.items():
            got = hashlib.new(algo, raw).hexdigest()
            if got != want:
                raise MixMatchError(f"{label}: {algo} mismatch")


class TUFClient:
    """Stateful single-repo TUF client (the Primary logic for one repo)."""

    def __init__(self, trusted_root):
        self.root = trusted_root                     # Metadata[Root]
        self.versions: dict[str, int] = {}

    def _threshold(self, role: str, md) -> None:
        self.root.verify_delegate(role, md)          # stock TUF threshold
        _quorum_check(self.root.signed, role, md)    # + QS quota

    def update(self, timestamp, snapshot, targets, target_name: str,
               target_bytes: bytes, now: datetime | None = None,
               allow_equal: bool = True) -> dict:
        now = now or datetime.now(timezone.utc)

        # 1. timestamp: signature/quorum, freshness (freeze), rollback
        self._threshold("timestamp", timestamp)
        if timestamp.signed.expires <= now:
            raise FreezeError("timestamp expired")
        self._monotonic("timestamp", timestamp.signed.version,
                        allow_equal=allow_equal)

        # 2. timestamp binds snapshot
        snap_raw = snapshot.to_bytes(WIRE)
        sm = timestamp.signed.snapshot_meta
        _bind(sm, snap_raw, "snapshot")
        if sm.version is not None and snapshot.signed.version != sm.version:
            raise MixMatchError("snapshot version != timestamp snapshot_meta")
        self._threshold("snapshot", snapshot)
        self._monotonic("snapshot", snapshot.signed.version, allow_equal)

        # 3. snapshot binds targets
        tm = snapshot.signed.meta.get("targets.json")
        if tm is None:
            raise MixMatchError("snapshot has no targets.json meta")
        tgt_raw = targets.to_bytes(WIRE)
        _bind(tm, tgt_raw, "targets")
        if tm.version is not None and targets.signed.version != tm.version:
            raise MixMatchError("targets version != snapshot meta")
        self._threshold("targets", targets)
        self._monotonic("targets", targets.signed.version, allow_equal)

        # 4. targets binds the actual target file
        tf = targets.signed.targets.get(target_name)
        if tf is None:
            raise MixMatchError(f"target {target_name} not in targets metadata")
        if len(target_bytes) != tf.length:
            raise MixMatchError("target file length mismatch")
        for algo, want in tf.hashes.items():
            if hashlib.new(algo, target_bytes).hexdigest() != want:
                raise MixMatchError(f"target file {algo} mismatch")

        return {"accepted": True,
                "versions": {r: self.versions[r] for r in self.versions}}

    def _monotonic(self, role: str, version: int, allow_equal: bool) -> None:
        prev = self.versions.get(role)
        if prev is not None:
            if version < prev or (version == prev and not allow_equal):
                raise RollbackError(
                    f"{role}: version {version} < previously seen {prev}"
                )
        self.versions[role] = version
