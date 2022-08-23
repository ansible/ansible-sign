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
            "If you are attempting to sign a project, please create this file",
            "",
            1,
        ),
        (
            [
                "project",
                "gpg-verify",
                "tests/fixtures/checksum/manifest-success",
            ],
            "Signature file does not exist",
            "",
            1,
        ),
        (
            [
                "project",
                "gpg-verify",
                "--gnupg-home=/dir/that/does/not/exist/321",
                "tests/fixtures/gpg/hao-signed",
            ],
            "Specified GnuPG home is not a directory:",
            "",
            1,
        ),
    ],
)
def test_main(capsys, args, exp_stdout_substr, exp_stderr_substr, exp_rc):
    """
    Test the CLI, making no assumptions about the environment, such as having a
    GPG keypair, or even a GPG home directory."
    """
    rc = main(args)
    captured = capsys.readouterr()
    assert exp_stdout_substr in captured.out
    assert exp_stderr_substr in captured.err

    if rc is None:
        rc = 0

    assert rc == exp_rc


@pytest.mark.parametrize(
    "args, exp_stdout_substr, exp_stderr_substr, exp_rc",
    [
        (
            [
                "project",
                "gpg-verify",
                "--keyring={gpghome}/pubring.kbx",
                "tests/fixtures/gpg/hao-signed-missing-manifest",
            ],
            "ensure that the project directory includes this file after",
            "",
            1,
        ),
        (
            [
                "project",
                "gpg-verify",
                "--gnupg-home={gpghome}",
                "tests/fixtures/gpg/hao-signed-missing-manifest",
            ],
            "ensure that the project directory includes this file after",
            "",
            1,
        ),
        (
            [
                "project",
                "gpg-verify",
                "--gnupg-home={gpghome}",
                "--keyring=/file/does/not/exist",
                "tests/fixtures/gpg/hao-signed-missing-manifest",
            ],
            "Specified keyring file not found:",
            "",
            1,
        ),
    ],
)
def test_main_with_pubkey_in_keyring(capsys, gpg_home_with_hao_pubkey, args, exp_stdout_substr, exp_stderr_substr, exp_rc):
    """
    Test the CLI assuming that there is (only) a public key in the keyring.
    """
    interpolation = {"gpghome": gpg_home_with_hao_pubkey}
    interpolated_args = [arg.format(**interpolation) for arg in args]
    rc = main(interpolated_args)
    captured = capsys.readouterr()
    assert exp_stdout_substr in captured.out
    assert exp_stderr_substr in captured.err

    if rc is None:
        rc = 0

    assert rc == exp_rc


@pytest.mark.parametrize(
    "project_fixture, exp_stdout_substr, exp_stderr_substr, exp_rc",
    [
        ("signed_project_and_gpg", "GPG signature verification succeeded", "", 0),
        ("signed_project_broken_manifest", "Invalid line encountered in checksum manifest", "", 1),
        ("signed_project_missing_manifest", "Checksum manifest file does not exist:", "", 1),
        ("signed_project_modified_manifest", "Checksum validation failed.", "", 2),
        ("signed_project_with_different_gpg_home", "Re-run with the global --debug flag", "", 3),
    ],
    ids=[
        "valid checksum file and signature",
        "valid signature but broken checksum file",
        "missing checksum file entirely",
        "checksum file with wrong hashes",
        "matching pubkey does not exist in gpg home",
    ],
)
def test_gpg_verify_manifest_scenario(capsys, request, project_fixture, exp_stdout_substr, exp_stderr_substr, exp_rc):
    """
    Test `ansible-sign project gpg-verify` given different project directory
    scenarios (fixtures).
    """
    (project_root, gpg_home) = request.getfixturevalue(project_fixture)
    keyring = os.path.join(gpg_home, "pubring.kbx")
    args = [
        "project",
        "gpg-verify",
        f"--keyring={keyring}",
        str(project_root),
    ]
    rc = main(args)
    captured = capsys.readouterr()
    assert exp_stdout_substr in captured.out
    assert exp_stderr_substr in captured.err

    if rc is None:
        rc = 0

    assert rc == exp_rc


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
