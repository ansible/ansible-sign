"""
This package handles various ways of signing Ansible content.

All verification methods contain two modules:

1) A verifier subclass of SignatureVerifier, which makes no assumptions about
   the verification strategy used. All it demands is the implementation of a
   'verify' method.

2) A signer subclass of SignatureSigner, which similarly makes no assumptions
   leaving it to each subclass to implement sign() as it sees fit.
"""

from .gpg import GPGSigner, GPGVerifier  # noqa

# from .base import *
