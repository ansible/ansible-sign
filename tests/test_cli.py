import os
import sys
import pytest

from ansible_sign.cli import main

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"
IS_GITHUB_ACTION_MACOS = (
    sys.platform == "darwin" and os.environ.get("CI", "false") == "true"
)


@pytest.mark.parametrize(
    "args, exp_stdout_substr, exp_stderr_substr, exp_rc",
    [
        (
            [
                "--debug",
                "--nocolor",
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
                "--debug",
                "--nocolor",
                "project",
                "gpg-sign",
                "tests/fixtures/checksum/manifest-syntax-error",
            ],
            "An error was encountered while parsing MANIFEST.in: unknown action 'invalid-directive'",
            "",
            1,
        ),
        (
            [
                "--debug",
                "--nocolor",
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
                "--debug",
                "--nocolor",
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
                "--debug",
                "--nocolor",
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
                "--debug",
                "--nocolor",
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
                "--debug",
                "--nocolor",
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
def test_main_with_pubkey_in_keyring(
    capsys, gpg_home_with_hao_pubkey, args, exp_stdout_substr, exp_stderr_substr, exp_rc
):
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
        pytest.param(
            "signed_project_and_gpg",
            "GPG signature verification succeeded",
            "",
            0,
            id="valid checksum file and signature",
            marks=pytest.mark.xfail(
                IS_GITHUB_ACTION_MACOS,
                reason="https://github.com/ansible/ansible-sign/issues/51",
            ),
        ),
        pytest.param(
            "signed_project_broken_manifest",
            "Invalid line encountered in checksum manifest",
            "",
            1,
            id="valid signature but broken checksum file",
            marks=pytest.mark.xfail(
                IS_GITHUB_ACTION_MACOS,
                reason="https://github.com/ansible/ansible-sign/issues/51",
            ),
        ),
        pytest.param(
            "signed_project_missing_manifest",
            "Checksum manifest file does not exist:",
            "",
            1,
            id="missing checksum file entirely",
        ),
        pytest.param(
            "signed_project_modified_manifest",
            "Checksum validation failed.",
            "",
            2,
            id="checksum file with wrong hashes",
            marks=pytest.mark.xfail(
                IS_GITHUB_ACTION_MACOS,
                reason="https://github.com/ansible/ansible-sign/issues/51",
            ),
        ),
        pytest.param(
            "signed_project_with_different_gpg_home",
            "Re-run with the global --debug flag",
            "",
            3,
            id="matching pubkey does not exist in gpg home",
        ),
        pytest.param(
            "signed_project_broken_manifest_in",
            "An error was encountered while parsing MANIFEST.in: unknown action 'invalid-directive'",
            "",
            1,
            id="broken MANIFEST.in after signing",
            marks=pytest.mark.xfail(
                IS_GITHUB_ACTION_MACOS,
                reason="https://github.com/ansible/ansible-sign/issues/51",
            ),
        ),
    ],
)
def test_gpg_verify_manifest_scenario(
    capsys, request, project_fixture, exp_stdout_substr, exp_stderr_substr, exp_rc
):
    """
    Test `ansible-sign project gpg-verify` given different project directory
    scenarios (fixtures).
    """
    (project_root, gpg_home) = request.getfixturevalue(project_fixture)
    keyring = os.path.join(gpg_home, "pubring.kbx")
    args = [
        "--debug",
        "--nocolor",
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
    ("mock", "env_var", False),
    ids=[
        "GPG signing with key that requires passphrase (mocked stdin)",
        "GPG signing with key that requires passphrase (via env var)",
        "GPG signing with key that does NOT require passphrase",
    ],
)
def test_gpg_sign_with_gnupg_home(
    capsys, mocker, request, unsigned_project_with_checksum_manifest, use_passphrase
):
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
    if use_passphrase == "mock":
        args.append("--prompt-passphrase")
    elif use_passphrase == "env_var":
        os.environ["ANSIBLE_SIGN_GPG_PASSPHRASE"] = "doYouEvenPassphrase"

    # Final argument, the project root.
    args.append(str(project_root))

    if use_passphrase == "mock":
        m = mocker.patch("getpass.getpass", return_value="doYouEvenPassphrase")
    else:
        # We mock getpass() even if we don't use --prompt-passphrase, this lets us
        # assert that we don't call it when we don't mean to.
        m = mocker.patch("getpass.getpass", return_value="INCORRECT")

    rc = main(args)
    captured = capsys.readouterr()
    assert "GPG signing successful!" in captured.out
    assert "GPG summary: signature created" in captured.out
    assert rc in (None, 0)

    if use_passphrase == "mock":
        m.assert_called_once()
    else:
        m.assert_not_called()


def test_gpg_sign_with_broken_symlink(
    capsys, unsigned_project_with_broken_symlink, gpg_home_with_secret_key_no_pass
):
    """
    Test that we show a warning when there's a broken symlink in the project
    directory. This works around a distlib.manifest bug, but tests our handling
    of it.
    """
    project_root = str(unsigned_project_with_broken_symlink)
    args = [
        "project",
        "gpg-sign",
        f"--gnupg-home={gpg_home_with_secret_key_no_pass}",
        project_root,
    ]
    rc = main(args)
    captured = capsys.readouterr()
    assert "Broken symlink found at" in captured.out
    assert rc == 1


def test_main_color(capsys, signed_project_and_gpg):
    """
    Test the CLI's handling of disabling color output:
    1) via global --nocolor flag
    2) via NO_COLOR env-var
    """

    (project_root, gpg_home) = signed_project_and_gpg
    args = ["project", "gpg-verify", f"--gnupg-home={gpg_home}", str(project_root)]
    args_nocolor = [
        "--nocolor",
        "project",
        "gpg-verify",
        f"--gnupg-home={gpg_home}",
        str(project_root),
    ]

    no_color_expected = "[OK   ]"
    color_expected = "[\033[92mOK   \033[0m]"

    # normal -- we should have color here
    rc = main(args)
    captured = capsys.readouterr()
    assert color_expected in captured.out
    assert rc in (0, None)

    # --nocolor -- should disable color
    rc = main(args_nocolor)
    captured = capsys.readouterr()
    assert no_color_expected in captured.out
    assert rc in (0, None)

    # env var with --nocolor -- should *really* disable color
    os.environ["NO_COLOR"] = "foo"
    rc = main(args_nocolor)
    captured = capsys.readouterr()
    assert no_color_expected in captured.out
    assert rc in (0, None)

    # env var without --nocolor -- should still disable color
    # and it should not matter what $NO_COLOR is set to
    no_color_values = (
        "foo",
        "0",
        "False",
        "false",
        "true",
        "1",
        "_",
        "$",
    )
    for value in no_color_values:
        os.environ["NO_COLOR"] = value
        rc = main(args)
        captured = capsys.readouterr()
        assert no_color_expected in captured.out

    # but if it's empty, ignore it
    os.environ["NO_COLOR"] = ""
    rc = main(args)
    captured = capsys.readouterr()
    assert rc in (0, None)
    assert color_expected in captured.out
