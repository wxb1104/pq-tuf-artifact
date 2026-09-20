"""
uptane.py -- PQ-Uptane: two TUF repositories (Director + Image) with
Primary full verification and resource-constrained Secondary/ECU partial
verification (Uptane standard §5.4.4).

  * Image repo: human-controlled, low-frequency, may delegate (TAP 3).
  * Director repo: online, signs per-vehicle/ECU target metadata, never delegates.
  * Full (Primary): verify both repos root->timestamp->snapshot->targets and
    require Director/Image agreement on target length & hash (custom-attack).
  * Partial (Secondary ECU): pre-provisioned Director root; verify only
    Director timestamp + Director targets (threshold + quantum-safe quota).
"""
from __future__ import annotations

from .repo import PQTUFRepo, RoleConfig, measure


class UptaneDeployment:
    def __init__(self, director_cfg: dict, image_cfg: dict,
                 target_name: str, target_blob: bytes,
                 image_delegate: dict | None = None):
        self.target_name = target_name
        self.target_blob = target_blob

        self.director = PQTUFRepo(director_cfg, name="director")
        self.image = PQTUFRepo(image_cfg, name="image")

        # Image repo: targets (+ optional delegation), snapshot, timestamp
        self.image.publish_targets(
            {target_name: target_blob}, delegate=image_delegate
        )
        tgt_roles = ["targets"] + (list(image_delegate) if image_delegate else [])
        if image_delegate:
            for dn in image_delegate:
                self.image.publish_delegated(
                    "targets", dn, {target_name: target_blob}
                )
        self.image.publish_snapshot(target_roles=tuple(tgt_roles))
        self.image.publish_timestamp()

        # Director repo: online per-vehicle targets (no delegation), snap, ts
        self.director.publish_targets({target_name: target_blob})
        self.director.publish_snapshot(target_roles=("targets",))
        self.director.publish_timestamp()

    # ---------------------------- verification --------------------------- #
    def _verify_repo(self, repo: PQTUFRepo, roles) -> dict:
        out = {}
        for r in roles:
            out[r] = repo.verify(r)
        return out

    def primary_full_verify(self) -> dict:
        """Full verification on the Primary; includes cross-repo agreement."""
        res = {"director": {}, "image": {}}
        for r in ("timestamp", "snapshot", "targets"):
            res["director"][r] = self.director.verify(r)
            res["image"][r] = self.image.verify(r)
        # Director/Image must agree on target length and hash
        d_t = self.director.meta["targets"].signed.targets[self.target_name]
        i_t = self.image.meta["targets"].signed.targets[self.target_name]
        agree = (
            d_t.length == i_t.length
            and d_t.hashes.get("sha256") == i_t.hashes.get("sha256")
        )
        res["target_agreement"] = agree
        res["accepted"] = agree and all(
            q.accepted
            for side in ("director", "image")
            for q in res[side].values()
        )
        return res

    def secondary_partial_verify(self) -> dict:
        """Minimal ECU verification: Director timestamp + Director targets,
        against the pre-provisioned Director root (not downloaded)."""
        res = {
            "timestamp": self.director.verify("timestamp"),
            "targets": self.director.verify("targets"),
        }
        res["accepted"] = all(q.accepted for q in res.values())
        return res

    # ----------------------------- accounting ---------------------------- #
    def wire_bytes(self) -> dict:
        dm = self.director.measure_all()
        im = self.image.measure_all()
        # the two repos share role names; sum them separately so Director roles
        # are not overwritten by Image roles when the dicts are merged.
        full = sum(m["wire"] for m in dm.values()) + \
            sum(m["wire"] for m in im.values())
        # partial: Director timestamp + Director targets only; Director root
        # is pre-provisioned and therefore not part of the download budget
        part = dm["timestamp"]["wire"] + dm["targets"]["wire"]
        return {
            "full": full,
            "partial": part,
            "director": {r: dm[r]["wire"] for r in dm},
            "image": {r: im[r]["wire"] for r in im},
            "director_root_provisioned": dm["root"]["wire"],
        }
