"""
This module handles GPG signature verification for Ansible content. It makes use
of python-gnupg (which ultimately shells out to GPG).
"""

import gnupg
import os

from ansible_sign.signing.base import (
    SignatureVerifier,
    SignatureVerificationResult,
)

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


class GPGVerifier(SignatureVerifier):
    def __init__(
        self, manifest_path, detached_signature_path, gpg_home=None, keyring=None
    ):
        super(GPGVerifier, self).__init__()

        if manifest_path is None:
            raise RuntimeError("manifest_path must not be None")
        self.manifest_path = manifest_path

        if detached_signature_path is None:
            raise RuntimeError("detached_signature_path must not be None")
        self.detached_signature_path = detached_signature_path

        self.gpg_home = gpg_home
        self.keyring = keyring

    def verify(self) -> SignatureVerificationResult:
        if not os.path.exists(self.detached_signature_path):
            return SignatureVerificationResult(
                success=False,
                summary="The specified detached signature path does not exist.",
            )

        extra = {}

        gpg = gnupg.GPG(gnupghome=self.gpg_home, keyring=self.keyring)

        with open(self.detached_signature_path, "rb") as sig:
            verified = gpg.verify_file(sig, self.manifest_path)

        if not verified:
            extra["stderr"] = verified.stderr
            return SignatureVerificationResult(
                success=False,
                summary="GPG signature verification failed.",
                extra_information=extra,
            )

        extra["stderr"] = verified.stderr
        extra["fingerprint"] = verified.fingerprint
        extra["creation_date"] = verified.creation_date
        extra["status"] = verified.status
        extra["timestamp"] = verified.timestamp

        return SignatureVerificationResult(
            success=True,
            summary="GPG signature verification succeeded.",
            extra_information=extra,
        )
