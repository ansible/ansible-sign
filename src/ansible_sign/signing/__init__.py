"""
This package handles various ways of signing Ansible content.

All verification methods contain two modules:

1) A verifier subclass of SignatureVerifier, which makes no assumptions about
   the verification strategy used. All it demands is the implementation of a
   'verify' method.

2) A signer subclass of SignatureSigner, which similarly makes no assumptions
   leaving it to each subclass to implement sign() as it sees fit.
"""

from .gpg import GPGSigner  # noqa: F401
from .gpg import GPGVerifier  # noqa: F401
from .sigstore import SigstoreVerifier  # noqa: F401

__all__ = [
   "GPGSigner",
   "GPGVerifier",
   "SigstoreVerifier",
]

# from .base import *
