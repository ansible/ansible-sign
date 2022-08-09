"""
This module handles GPG signature generation for Ansible content. It makes use
of python-gnupg (which ultimately shells out to GPG).
"""

import argparse
import gnupg
import os
import sys
import tempfile

from ansible_sign import __version__
from ansible_sign.signing.base import (
    SignatureSigner,
    SignatureSigningResult,
)

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


class GPGSigner(SignatureSigner):
    def __init__(self, privkey, manifest_path, output_path, passphrase=None):
        super(GPGSigner, self).__init__()

        if privkey is None:
            raise RuntimeError("privkey must not be None")
        self.privkey = privkey

        if manifest_path is None:
            raise RuntimeError("manifest_path must not be None")
        self.manifest_path = manifest_path

        if output_path is None:
            raise RuntimeError("output_path must not be None")
        self.output_path = output_path

        self.passphrase = passphrase

    def sign(self) -> SignatureSigningResult:
        # TODO: We currently use the default GPG home directory in the signing
        # case and assume the secret key exists in it. Is there a better way to
        # do this?
        gpg = gnupg.GPG()
        with open(self.manifest_path, "rb") as f:
            sign_result = gpg.sign_file(
                f,
                keyid=self.privkey,
                passphrase=self.passphrase,
                detach=True,
                output=self.output_path,
            )

        return SignatureSigningResult(
            success=sign_result.returncode == 0 and sign_result.status is not None,
            summary=sign_result.status,
            extra_information={
                "stderr": sign_result.stderr,
                "fingerprint": sign_result.fingerprint,
                "hash_algo": sign_result.hash_algo,
                "timestamp": sign_result.timestamp,
            },
        )
