"""
This module handles GPG signature verification for Ansible content. It makes use
of python-gnupg (which ultimately shells out to GPG).
"""

import argparse
import gnupg
import os
import sys
import tempfile

from ansible_sign import __version__
from ansible_sign.signing.base import (
    SignatureVerifier,
    SignatureVerificationResult,
)

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


class GPGVerifier(SignatureVerifier):
    def __init__(self, pubkey, manifest_path, detached_signature_path):
        super(GPGVerifier, self).__init__()

        if pubkey is None:
            raise RuntimeError("pubkey must not be None")
        self.pubkey = pubkey

        if manifest_path is None:
            raise RuntimeError("manifest_path must not be None")
        self.manifest_path = manifest_path

        if detached_signature_path is None:
            raise RuntimeError("detached_signature_path must not be None")
        self.detached_signature_path = detached_signature_path

    def verify(self) -> SignatureVerificationResult:
        if not os.path.exists(self.detached_signature_path):
            return SignatureVerificationResult(
                success=False,
                summary="The specified detached signature path does not exist.",
            )

        extra = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            gpg = gnupg.GPG(gnupghome=tmpdir)
            import_result = gpg.import_keys(self.pubkey)
            extra["gpg_pubkeys_imported"] = import_result.count
            extra["gpg_fingerprints"] = import_result.fingerprints

            with open(self.detached_signature_path, "rb") as sig:
                verified = gpg.verify_file(sig, self.manifest_path)

            if not verified:
                extra["stderr"] = verified.stderr
                return SignatureVerificationResult(
                    success=False,
                    summary="Signature verification of checksum file failed.",
                    extra_information=extra,
                )

            extra["stderr"] = verified.stderr
            extra["fingerprint"] = verified.fingerprint
            extra["creation_date"] = verified.creation_date
            extra["status"] = verified.status
            extra["timestamp"] = verified.timestamp

            return SignatureVerificationResult(
                success=True,
                summary="Verification of checksum file succeeded.",
                extra_information=extra,
            )
