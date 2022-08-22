import os
import pytest

from ansible_sign.cli import main

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "checksum",
)


@pytest.mark.parametrize(
    "args, exp_stdout_substr, exp_stderr_substr, exp_rc",
    [
        (
            [
                "project",
                "gpg-sign",
                "tests/fixtures/checksum/missing-manifest",
            ],
            "Could not find a MANIFEST.in file in the specified project.",
            "",
            1,
        ),
    ],
)
def test_main(capsys, args, exp_stdout_substr, exp_stderr_substr, exp_rc):
    rc = main(args)
    captured = capsys.readouterr()
    assert exp_stdout_substr in captured.out
    assert exp_stderr_substr in captured.err

    if rc is None:
        rc = 0

    assert rc == exp_rc


def test_gpg_validate_manifest_with_keyring(capsys, signed_project_and_gpg):
    project_root = signed_project_and_gpg[0]
    gpg_home = signed_project_and_gpg[1]
    keyring = os.path.join(gpg_home, "pubring.kbx")
    args = [
        "project",
        "gpg-verify",
        f"--keyring={keyring}",
        str(project_root),
    ]
    rc = main(args)
    captured = capsys.readouterr()
    assert "Signature validation SUCCEEDED!" in captured.out
    assert rc in (None, 0)
