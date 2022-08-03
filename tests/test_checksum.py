import os
import pytest

from ansible_signatory.checksum import *

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "checksum",
)


def test_simple_gnu_generate():
    root = os.path.join(
        FIXTURES_DIR,
        "directory-success",
    )
    checksum = ChecksumFile(
        root,
        differ=DirectoryChecksumFileExistenceDiffer,
    )
    generated_manifest = checksum.generate_gnu_style()
    actual_manifest = open(
        os.path.join(
            root,
            "sha256sum.txt",
        ),
        "r",
    ).read()
    assert generated_manifest == actual_manifest


@pytest.mark.parametrize(
    "directory_prefix, differ_cls",
    [
        (
            "directory",
            DirectoryChecksumFileExistenceDiffer,
        ),
        (
            "git",
            GitChecksumFileExistenceDiffer,
        ),
    ],
)
@pytest.mark.parametrize(
    "fixture, diff_output",
    [
        (
            "files-added",
            "{'added': ['hello2', 'hello3'], 'removed': []}",
        ),
        (
            "files-added-removed",
            "{'added': ['hello2', 'hello3'], 'removed': ['hello1']}",
        ),
        (
            "files-removed",
            "{'added': [], 'removed': ['hello1']}",
        ),
        (
            "files-changed",
            "Checksum mismatch: hello1",
        ),
        (
            "success",
            True,
        ),
    ],
)
def test_directory_diff(
    directory_prefix,
    differ_cls,
    fixture,
    diff_output,
):
    root = os.path.join(
        FIXTURES_DIR,
        f"{directory_prefix}-{fixture}",
    )
    checksum = ChecksumFile(
        root,
        differ=differ_cls,
    )
    actual_manifest = open(
        os.path.join(
            root,
            "sha256sum.txt",
        ),
        "r",
    ).read()
    parsed_manifest = checksum.parse(actual_manifest)
    if diff_output is True:
        assert checksum.verify(parsed_manifest)
    else:
        with pytest.raises(ChecksumMismatch) as ex:
            checksum.verify(parsed_manifest)
        assert str(ex.value) == diff_output
