import os
import pytest

from ansible_sign.cli import *
from ansible_sign.checksum.differ import *

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
                "checksum-manifest",
                "tests/fixtures/checksum/manifest-success",
            ],
            "dc920c7f31a4869fb9f94519a4a77f6c7c43c6c3e66b0e57a5bcda52e9b02ce3  dir/hello2",
            "",
            0,
        ),
        (
            [
                "project",
                "validate-checksum",
                "--checksum-file=nonexistent",
                "tests/fixtures/checksum/manifest-success",
            ],
            "Checksum file does not exist: tests/fixtures/checksum/manifest-success/nonexistent",
            "",
            1,
        ),
        (
            [
                "project",
                "validate-checksum",
                "tests/fixtures/checksum/invalid-checksum-1",
            ],
            "Invalid line encountered in checksum manifest:",
            "",
            1,
        ),
        (
            [
                "project",
                "validate-checksum",
                "tests/fixtures/checksum/invalid-checksum-2",
            ],
            "Invalid line encountered in checksum manifest:",
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


def test_validate_checksum_via_main_success(capsys):
    """
    test validate-checksum
    """

    args = [
        "project",
        "validate-checksum",
        f"tests/fixtures/checksum/manifest-success",
    ]
    rc = main(args)
    captured = capsys.readouterr()
    assert captured.out == "Checksum validation SUCCEEDED!\n"
    assert captured.err == ""

    if rc is None:
        rc = 0

    assert rc == 0


def test_validate_checksum_via_main_failure(capsys):
    """
    test validate-checksum fails correctly
    """

    args = [
        "project",
        "validate-checksum",
        f"tests/fixtures/checksum/manifest-files-changed",
    ]
    rc = main(args)
    captured = capsys.readouterr()
    assert "Checksum validation FAILED!" in captured.out
    assert "Checksum mismatch: hello1" in captured.out
    assert captured.err == ""

    if rc is None:
        rc = 0

    assert rc == 2


@pytest.mark.parametrize(
    "fixture",
    [
        "manifest-success",
        "manifest-no-ansible-sign-dir",
    ],
)
def test_checksum_manifest_output_flag(capsys, tmp_path, fixture):
    args = ["project", "checksum-manifest", f"tests/fixtures/checksum/{fixture}"]
    rc = main(args)
    captured = capsys.readouterr()
    expected_out = """d2d1320f7f4fe3abafe92765732d2aa6c097e7adf05bbd53481777d4a1f0cdab  MANIFEST.in
dc920c7f31a4869fb9f94519a4a77f6c7c43c6c3e66b0e57a5bcda52e9b02ce3  dir/hello2
2a1b1ab320215205675234744dc03f028b46da4d94657bbb7dca7b1a3a25e91e  hello1
"""
    assert captured.out == expected_out
    assert rc in (None, 0)

    # Now do it again, but write to a file
    args = [
        "project",
        "checksum-manifest",
        f"--output={tmp_path / 'sha256sum.txt'}",
        f"tests/fixtures/checksum/{fixture}",
    ]
    rc = main(args)
    assert rc in (None, 0)

    with open(tmp_path / "sha256sum.txt") as f:
        assert f.read() == expected_out


def test_gpg_validate_manifest_with_keyring(capsys, signed_project_and_gpg):
    project_root = signed_project_and_gpg[0]
    gpg_home = signed_project_and_gpg[1]
    keyring = os.path.join(gpg_home, "pubring.kbx")
    args = [
        "project",
        "gpg-validate-manifest",
        f"--keyring={keyring}",
        str(project_root),
    ]
    rc = main(args)
    captured = capsys.readouterr()
    assert "Signature validation SUCCEEDED!" in captured.out
    assert rc in (None, 0)
