import os
import pytest

from ansible_signatory.cli import *
from ansible_signatory.checksum.differ import *

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "checksum",
)


@pytest.mark.parametrize(
    "fixture, expected",
    [
        ("git-success", GitChecksumFileExistenceDiffer),
        ("manifest-success", DistlibManifestChecksumFileExistenceDiffer),
        ("directory-success", DirectoryChecksumFileExistenceDiffer),
    ],
)
def test_determine_differ_from_auto(fixture, expected):
    root = os.path.join(FIXTURES_DIR, fixture)
    assert determine_differ_from_auto(root) == expected


@pytest.mark.parametrize(
    "args, exp_stdout_substr, exp_stderr_substr, exp_rc",
    [
        (
            ["checksum-manifest", "tests/fixtures/checksum/manifest-success"],
            "dc920c7f31a4869fb9f94519a4a77f6c7c43c6c3e66b0e57a5bcda52e9b02ce3  dir/hello2",
            "",
            0,
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
