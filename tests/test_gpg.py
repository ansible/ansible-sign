import os
import pytest

from ansible_sign.signing import *

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
)


@pytest.mark.parametrize(
    "directory, expected",
    [
        ("hao-signed", True),
        ("hao-signed-invalid", False),
    ],
)
def test_gpg(directory, expected):
    pubkey = open(os.path.join(FIXTURES_DIR, "gpgkeys", "hao_pubkey.txt"), "r").read()
    manifest_path = os.path.join(FIXTURES_DIR, "gpg", directory, "sha256sum.txt")
    signature_path = os.path.join(FIXTURES_DIR, "gpg", directory, "sha256sum.txt.sig")
    verifier = GPGVerifier(
        pubkey,
        manifest_path=manifest_path,
        detached_signature_path=signature_path,
    )
    result = verifier.verify()
    assert result.success is expected
