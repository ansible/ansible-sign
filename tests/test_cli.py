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


@pytest.mark.parametrize(
    "use_passphrase",
    [True, False],
    ids=[
        "GPG signing with key that requires passphrase",
        "GPG signing with key that does NOT require passphrase",
    ],
)
def test_gpg_sign_with_gnupg_home(capsys, mocker, request, unsigned_project_with_checksum_manifest, use_passphrase):
    if use_passphrase:
        gpg_home = request.getfixturevalue("gpg_home_with_secret_key")
    else:
        gpg_home = request.getfixturevalue("gpg_home_with_secret_key_no_pass")

    project_root = unsigned_project_with_checksum_manifest
    args = [
        "project",
        "gpg-sign",
        f"--gnupg-home={gpg_home}",
    ]

    # If testing with pass-phrase use built in passphrase prompt.
    # We'll mock this return value below.
    if use_passphrase:
        args.append("--prompt-passphrase")

    # Final argument, the project root.
    args.append(str(project_root))

    # We mock getpass() even if we don't use --prompt-passphrase, this lets us
    # assert that we don't call it when we don't mean to.
    m = mocker.patch("getpass.getpass", return_value="doYouEvenPassphrase")

    rc = main(args)
    captured = capsys.readouterr()
    assert "GPG signing successful!" in captured.out
    assert "GPG summary: signature created" in captured.out
    assert rc in (None, 0)

    if use_passphrase:
        m.assert_called_once()
    else:
        m.assert_not_called()
