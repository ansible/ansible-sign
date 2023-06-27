"""This module handles Sigstore signature generation for Ansible content using the sigstore-python library."""

from sigstore.sign import Signer as SigstoreBaseSigner
from sigstore.sign import SigningResult as SigstoreBaseSigningResult

from ansible_sign.signing.base import SignatureSigner as AnsibleBaseSignatureSigner
from ansible_sign.signing.base import SignatureSigningResult as AnsibleBaseSignatureSigningResult

__author__ = "Maya Costantini"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


class SigstoreSigner(SigstoreBaseSigner, AnsibleBaseSignatureSigner):
    """A wrapper around the sigstore Signer class."""


class SigstoreSigningResult(SigstoreBaseSigningResult, AnsibleBaseSignatureSigningResult):
    """A wrapper class around the sigstore SigningResult class."""
