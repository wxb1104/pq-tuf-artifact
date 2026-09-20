"""
signers.py -- crypto-agility adapter layer for python-tuf / securesystemslib.

Registers out-of-tree, TUF-spec-compliant (TUF §4.2.2 allows arbitrary
keytype/scheme/crypto-library) key types:

  * ('pq',  <bridge alg>)         pure PQ signer (ML-DSA / FN-DSA / SLH-DSA)
  * ('hyb', '<classical>:<pq>')   labelled parallel hybrid combiner

Verification is dispatched through KEY_FOR_TYPE_AND_SCHEME, so the stock
python-tuf threshold verification (Metadata.verify_delegate) verifies our PQ
and hybrid signatures unchanged; the only added logic is the quorum QS-count
check in quorum.py (formalization Algorithm 2, step 7).
"""
from __future__ import annotations

import hashlib

from securesystemslib.formats import encode_canonical
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    CryptoSigner,
    Key,
    Signature,
    Signer,
)

try:  # location varies across securesystemslib releases
    from securesystemslib.exceptions import UnverifiedSignatureError
except Exception:  # pragma: no cover
    from securesystemslib.signer import UnverifiedSignatureError  # type: ignore

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import pqbackend as pqb

_PQ_KEYTYPE = "pq"
_HYB_KEYTYPE = "hyb"
_REGISTERED = False


def _keyid(keytype: str, scheme: str, public_hex: str) -> str:
    """TUF keyid = SHA256(canonical JSON of the KEY object), TUF §4.2.1."""
    key_dict = {
        "keytype": keytype,
        "scheme": scheme,
        "keyval": {"public": public_hex},
    }
    canon = encode_canonical(key_dict)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class PQKey(Key):
    """Public key for a pure post-quantum scheme backed by the PQClean bridge."""

    def __init__(self, keyid: str, scheme: str, public_hex: str, unrec=None):
        super().__init__(
            keyid, _PQ_KEYTYPE, scheme, {"public": public_hex}, unrec
        )

    @classmethod
    def build(cls, scheme: str, pk: bytes) -> "PQKey":
        ph = pk.hex()
        return cls(_keyid(_PQ_KEYTYPE, scheme, ph), scheme, ph)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict) -> "PQKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, scheme, keyval["public"], key_dict)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        if signature.keyid != self.keyid:
            raise UnverifiedSignatureError(
                f"keyid mismatch {signature.keyid} != {self.keyid}"
            )
        try:
            sig = bytes.fromhex(signature.signature)
            pk = bytes.fromhex(self.keyval["public"])
            ok = pqb.unified_verify(self.scheme, pk, data, sig)
        except Exception as e:
            raise UnverifiedSignatureError(f"PQ verify error: {e}") from e
        if not ok:
            raise UnverifiedSignatureError(
                f"Failed to verify PQ signature by {self.keyid}"
            )


class PQSigner(Signer):
    def __init__(self, scheme: str, sk: bytes, public_key: PQKey):
        self.scheme = scheme
        self._sk = sk
        self._public_key = public_key

    @classmethod
    def generate(cls, scheme: str) -> "PQSigner":
        pk, sk = pqb.PQBridge.get().keygen(scheme)
        return cls(scheme, sk, PQKey.build(scheme, pk))

    @property
    def public_key(self) -> Key:
        return self._public_key

    def sign(self, payload: bytes) -> Signature:
        sig = pqb.PQBridge.get().sign(self.scheme, self._sk, payload)
        return Signature(self._public_key.keyid, sig.hex())

    @classmethod
    def from_priv_key_uri(cls, *a, **k):  # not used; keys are programmatic
        raise NotImplementedError("instantiate with PQSigner.generate()")


class HybridKey(Key):
    """Public key for a labelled classical||PQ parallel hybrid combiner."""

    def __init__(self, keyid: str, scheme: str, public_hex: str, unrec=None):
        super().__init__(
            keyid, _HYB_KEYTYPE, scheme, {"public": public_hex}, unrec
        )

    @classmethod
    def build(cls, scheme: str, c_pub: bytes, q_pub: bytes) -> "HybridKey":
        ph = pqb.hybrid_public(c_pub, q_pub).hex()
        return cls(_keyid(_HYB_KEYTYPE, scheme, ph), scheme, ph)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict) -> "HybridKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, scheme, keyval["public"], key_dict)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        if signature.keyid != self.keyid:
            raise UnverifiedSignatureError(
                f"keyid mismatch {signature.keyid} != {self.keyid}"
            )
        try:
            sig = bytes.fromhex(signature.signature)
            pub = bytes.fromhex(self.keyval["public"])
            ok = pqb.unified_verify(self.scheme, pub, data, sig)
        except Exception as e:
            raise UnverifiedSignatureError(f"hybrid verify error: {e}") from e
        if not ok:
            raise UnverifiedSignatureError(
                f"Failed to verify hybrid signature by {self.keyid}"
            )


class HybridSigner(Signer):
    def __init__(self, uk: pqb.UnifiedKey, public_key: HybridKey):
        self._uk = uk
        self._public_key = public_key

    @classmethod
    def generate(cls, classical: str = "ed25519", pq: str = "fndsa512") -> "HybridSigner":
        scheme = f"hyb:{classical}:{pq}"
        uk = pqb.UnifiedKey.generate(scheme)
        key = HybridKey.build(scheme, uk.c_pub, uk.pq_pk)
        return cls(uk, key)

    @property
    def public_key(self) -> Key:
        return self._public_key

    def sign(self, payload: bytes) -> Signature:
        sig = pqb.unified_sign(self._uk, payload)
        return Signature(self._public_key.keyid, sig.hex())

    @classmethod
    def from_priv_key_uri(cls, *a, **k):
        raise NotImplementedError("instantiate with HybridSigner.generate()")


def key_is_qs(key: Key) -> bool:
    """Quantum-safe class: pure-PQ or hybrid (formalization κ∈{Q,H})."""
    return key.keytype in (_PQ_KEYTYPE, _HYB_KEYTYPE)


def make_signer(scheme: str) -> Signer:
    """Unified factory for classical / pure-PQ / hybrid signers."""
    if scheme == "ed25519":
        return CryptoSigner(Ed25519PrivateKey.generate())
    if scheme in pqb.PQ_ALGS:
        return PQSigner.generate(scheme)
    if scheme.startswith("hyb:"):
        _, c, q = scheme.split(":")
        return HybridSigner.generate(c, q)
    raise ValueError(f"unknown scheme {scheme}")


def register() -> None:
    """Idempotently register all PQ and hybrid (keytype, scheme) verifiers."""
    global _REGISTERED
    if _REGISTERED:
        return
    for alg in pqb.PQ_ALGS:
        KEY_FOR_TYPE_AND_SCHEME[(_PQ_KEYTYPE, alg)] = PQKey
    for c in pqb.CLASSICAL_ALGS:
        for q in pqb.PQ_ALGS:
            KEY_FOR_TYPE_AND_SCHEME[(_HYB_KEYTYPE, f"hyb:{c}:{q}")] = HybridKey
    _REGISTERED = True


register()
