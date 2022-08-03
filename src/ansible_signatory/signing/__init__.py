"""
This package handles various ways of signing Ansible content.

All verification methods subclass SignatureVerifier, which makes no assumptions
about the verification strategy used. All it demands is the implementation of ah
'verify' method.
"""

from .gpg import *
from .base import *
