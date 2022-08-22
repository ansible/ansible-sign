"""
This module handles GPG signature generation for Ansible content. It makes use
of python-gnupg (which ultimately shells out to GPG).
"""

import gnupg

from ansible_sign.signing.base import (
    SignatureSigner,
    SignatureSigningResult,
)

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


class GPGSigner(SignatureSigner):
    def __init__(
        self,
        manifest_path,
        output_path,
        privkey=None,
        passphrase=None,
        gpg_home=None,
    ):
        super(GPGSigner, self).__init__()

        if manifest_path is None:
            raise RuntimeError("manifest_path must not be None")
        self.manifest_path = manifest_path

        if output_path is None:
            raise RuntimeError("output_path must not be None")
        self.output_path = output_path

        self.privkey = privkey
        self.passphrase = passphrase
        self.gpg_home = gpg_home

    def sign(self) -> SignatureSigningResult:
        # TODO: We currently use the default GPG home directory in the signing
        # case and assume the secret key exists in it. Is there a better way to
        # do this?
        gpg = gnupg.GPG(gnupghome=self.gpg_home)
        with open(self.manifest_path, "rb") as f:
            sign_result = gpg.sign_file(
                f,
                keyid=self.privkey,
                passphrase=self.passphrase,
                detach=True,
                output=self.output_path,
            )

        extra_information = {}
        for k in ("stderr", "fingerprint", "hash_algo", "timestamp", "returncode"):
            if hasattr(sign_result, k):
                extra_information[k] = getattr(sign_result, k)

        return SignatureSigningResult(
            success=sign_result.returncode == 0 and sign_result.status is not None,
            summary=sign_result.status,
            extra_information=extra_information,
        )
