"""PQ-TUF / PQ-Uptane research prototype package."""
from . import pqbackend, signers  # noqa: F401
from .signers import (  # noqa: F401
    HybridKey,
    HybridSigner,
    PQKey,
    PQSigner,
    key_is_qs,
    make_signer,
    register,
)

register()
