"""
pqbackend.py -- low-level post-quantum / classical signature primitives.

PQ algorithms (ML-DSA, FN-DSA, SLH-DSA) are executed by the long-lived Rust
`bridge` binary (PQClean via pqcrypto-rs), so every signature in the prototype
is a *real* standardized PQ signature with the true byte length and real
verification semantics -- no simulated/mock PQ signatures. Classical
Ed25519/ECDSA use pyca/cryptography. The same PQClean source/versions back
the E1 primitive benchmark (pqbench), keeping sizes/timings consistent.

Line protocol see impl/pqbench/src/bin/bridge.rs.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization

_BRIDGE_BIN = (
    Path(__file__).resolve().parents[1] / "pqbench" / "target" / "release" / "bridge"
)

# bridge alg name -> (NIST family, NIST security level, QS?, stateful?)
PQ_ALGS: dict[str, tuple[str, int]] = {
    "mldsa44": ("ml-dsa", 2),
    "mldsa65": ("ml-dsa", 3),
    "mldsa87": ("ml-dsa", 5),
    "fndsa512": ("fn-dsa", 1),
    "fndsa1024": ("fn-dsa", 5),
    "slhdsa128s": ("slh-dsa", 1),
    "slhdsa128f": ("slh-dsa", 1),
    "slhdsa256s": ("slh-dsa", 5),
    "slhdsa256f": ("slh-dsa", 5),
}
CLASSICAL_ALGS = {"ed25519": ("ed25519", 1), "ecdsa-p256": ("ecdsa", 1)}


def is_quantum_safe(scheme: str) -> bool:
    """A signer is quantum-safe if it is pure-PQ or hybrid (carries a PQ part)."""
    return scheme in PQ_ALGS or scheme.startswith("hyb:")


def pq_family(scheme: str) -> str:
    if scheme in PQ_ALGS:
        return PQ_ALGS[scheme][0]
    if scheme.startswith("hyb:"):
        return "hybrid"
    return CLASSICAL_ALGS.get(scheme, ("?", 0))[0]


class PQBridge:
    """Persistent subprocess wrapper (one bridge serves the whole process)."""

    _instance: "PQBridge | None" = None
    _lock_factory = threading.Lock

    def __init__(self, bin_path: Path | str | None = None) -> None:
        path = str(bin_path or _BRIDGE_BIN)
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"bridge binary not found: {path}; build with impl/build_bridge.sh"
            )
        self.proc = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._wlock = threading.Lock()
        # warm-up
        pong = self._raw("ping")
        if "pong" not in pong:
            raise RuntimeError(f"bridge warm-up failed: {pong!r}")

    @classmethod
    def get(cls) -> "PQBridge":
        with cls._lock_factory():
            if cls._instance is None:
                cls._instance = PQBridge()
            return cls._instance

    def _raw(self, line: str) -> str:
        with self._wlock:
            assert self.proc.stdin and self.proc.stdout
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
            return self.proc.stdout.readline().strip()

    def _call(self, line: str) -> dict[str, str]:
        resp = self._raw(line)
        if not resp.startswith("OK"):
            raise RuntimeError(f"bridge error: {resp}  (request: {line[:40]}...)")
        out: dict[str, str] = {}
        for tok in resp.split()[1:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                out[k] = v
        return out

    def keygen(self, alg: str) -> tuple[bytes, bytes]:
        r = self._call(f"keygen {alg}")
        return bytes.fromhex(r["pk"]), bytes.fromhex(r["sk"])

    def sign(self, alg: str, sk: bytes, msg: bytes) -> bytes:
        r = self._call(f"sign {alg} {sk.hex()} {msg.hex()}")
        return bytes.fromhex(r["sig"])

    def verify(self, alg: str, pk: bytes, msg: bytes, sig: bytes) -> bool:
        r = self._call(f"verify {alg} {pk.hex()} {msg.hex()} {sig.hex()}")
        return r.get("valid") == "1"

    def sizes(self, alg: str, probes: int = 1) -> tuple[int, list[int]]:
        """(public-key bytes, list of signature byte lengths over probes)."""
        r = self._call(f"sizes {alg}")
        pk_len = int(r["pk"])
        sig_lens: list[int] = []
        for _ in range(probes):
            pk, sk = self.keygen(alg)
            sig = self.sign(alg, sk, os.urandom(64))
            sig_lens.append(len(sig))
        return pk_len, sig_lens

    def close(self) -> None:
        try:
            self._raw("quit")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()


# ----------------------------- classical keys ----------------------------- #

@dataclass
class ClassicalKeyPair:
    alg: str
    priv: object
    pub_bytes: bytes  # raw ed25519 (32B) / uncompressed point for ecdsa

    @classmethod
    def generate(cls, alg: str = "ed25519") -> "ClassicalKeyPair":
        if alg == "ed25519":
            priv = Ed25519PrivateKey.generate()
            pub = priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        elif alg == "ecdsa-p256":
            from cryptography.hazmat.primitives.asymmetric import ec

            priv = ec.generate_private_key(SECP256R1())
            pub = priv.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        else:
            raise ValueError(alg)
        return cls(alg, priv, pub)

    def sign(self, msg: bytes) -> bytes:
        if self.alg == "ed25519":
            return self.priv.sign(msg)
        assert isinstance(self.priv, EllipticCurvePrivateKey)
        return self.priv.sign(msg, ECDSA(SHA256()))

    @staticmethod
    def verify(alg: str, pub_bytes: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            if alg == "ed25519":
                Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, msg)
            elif alg == "ecdsa-p256":
                from cryptography.hazmat.primitives.asymmetric import ec

                pub = ec.EllipticCurvePublicKey.from_encoded_point(
                    SECP256R1(), pub_bytes
                )
                pub.verify(sig, msg, ECDSA(SHA256()))
            else:
                return False
            return True
        except Exception:
            return False


# --------------------------- unified key generation ------------------------ #

@dataclass
class UnifiedKey:
    """A single signing key for any scheme; .scheme drives the signers layer."""

    scheme: str          # 'ed25519' | PQ bridge alg | 'hyb:<classical>:<pq>'
    qs: bool
    # classical component (hybrid/classical only)
    c_alg: str | None = None
    c_priv: object | None = None
    c_pub: bytes = b""
    # PQ component (pq/hybrid only), raw bytes handled by bridge
    pq_alg: str | None = None
    pq_sk: bytes = b""
    pq_pk: bytes = b""

    @classmethod
    def generate(cls, scheme: str) -> "UnifiedKey":
        if scheme in CLASSICAL_ALGS:
            kp = ClassicalKeyPair.generate(scheme)
            return cls(scheme, False, c_alg=scheme, c_priv=kp.priv, c_pub=kp.pub_bytes)
        if scheme in PQ_ALGS:
            pk, sk = PQBridge.get().keygen(scheme)
            return cls(scheme, True, pq_alg=scheme, pq_sk=sk, pq_pk=pk)
        if scheme.startswith("hyb:"):
            _, c_alg, pq_alg = scheme.split(":")
            if c_alg not in CLASSICAL_ALGS or pq_alg not in PQ_ALGS:
                raise ValueError(f"bad hybrid scheme {scheme}")
            kp = ClassicalKeyPair.generate(c_alg)
            pk, sk = PQBridge.get().keygen(pq_alg)
            return cls(
                scheme, True,
                c_alg=c_alg, c_priv=kp.priv, c_pub=kp.pub_bytes,
                pq_alg=pq_alg, pq_sk=sk, pq_pk=pk,
            )
        raise ValueError(f"unknown scheme {scheme}")


# domain-separation tags (TAP 9 style algorithm binding; prevents component
# stripping / cross-context replay in the hybrid combiner, formalization §1.2)
def tau(scheme: str, component: str) -> bytes:
    return f"PQTUF-v1|{scheme}|{component}|".encode()


def unified_sign(k: UnifiedKey, data: bytes) -> bytes:
    if k.scheme in CLASSICAL_ALGS:
        return ClassicalKeyPair(k.c_alg, k.c_priv, k.c_pub).sign(data)
    if k.scheme in PQ_ALGS:
        return PQBridge.get().sign(k.pq_alg, k.pq_sk, data)
    # hybrid: labelled parallel combiner, both components over same payload
    c_sig = ClassicalKeyPair(k.c_alg, k.c_priv, k.c_pub).sign(
        tau(k.scheme, "C") + data
    )
    q_sig = PQBridge.get().sign(k.pq_alg, k.pq_sk, tau(k.scheme, "Q") + data)
    return _pack_hybrid(c_sig, q_sig)


def unified_verify(scheme: str, public: bytes, data: bytes, sig: bytes) -> bool:
    try:
        if scheme in CLASSICAL_ALGS:
            return ClassicalKeyPair.verify(scheme, public, data, sig)
        if scheme in PQ_ALGS:
            return PQBridge.get().verify(scheme, public, data, sig)
        if scheme.startswith("hyb:"):
            _, c_alg, pq_alg = scheme.split(":")
            c_pub, q_pub = _unpack_hybrid_pub(public)
            c_sig, q_sig = _unpack_hybrid_sig(sig)
            ok_c = ClassicalKeyPair.verify(
                c_alg, c_pub, tau(scheme, "C") + data, c_sig
            )
            ok_q = PQBridge.get().verify(
                pq_alg, q_pub, tau(scheme, "Q") + data, q_sig
            )
            return ok_c and ok_q
    except Exception:
        return False
    return False


def hybrid_public(c_pub: bytes, q_pub: bytes) -> bytes:
    return _pack_hybrid(c_pub, q_pub)


def _pack_hybrid(a: bytes, b: bytes) -> bytes:
    # 4-byte little-endian length prefix then concatenation (unambiguous)
    return len(a).to_bytes(4, "little") + a + len(b).to_bytes(4, "little") + b


def _unpack_hybrid_pub(blob: bytes) -> tuple[bytes, bytes]:
    return _split2(blob)


def _unpack_hybrid_sig(blob: bytes) -> tuple[bytes, bytes]:
    return _split2(blob)


def _split2(blob: bytes) -> tuple[bytes, bytes]:
    la = int.from_bytes(blob[:4], "little")
    a = blob[4 : 4 + la]
    rest = blob[4 + la :]
    lb = int.from_bytes(rest[:4], "little")
    b = rest[4 : 4 + lb]
    if len(a) != la or len(b) != lb or 4 + la + 4 + lb != len(blob):
        raise ValueError("malformed hybrid blob")
    return a, b
