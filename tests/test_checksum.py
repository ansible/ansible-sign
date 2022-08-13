import os
import pytest

from ansible_sign.checksum import *

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "checksum",
)

DUPLICATE_LINES_FIXTURE = """
2a1b1ab320215205675234744dc03f028b46da4d94657bbb7dca7b1a3a25e91e  tests/fixtures/checksum/directory-success/hello1
2a1b1ab320215205675234744dc03f028b46da4d94657bbb7dca7b1a3a25e91e  tests/fixtures/checksum/directory-success/hello1
""".strip()

# Missing extra space
INVALID_LINE_FIXTURE1 = """
2a1b1ab320215205675234744dc03f028b46da4d94657bbb7dca7b1a3a25e91e tests/fixtures/checksum/directory-success/hello1
""".strip()

# Hash isn't 64 characters long
INVALID_LINE_FIXTURE2 = """
2a1b1ab320215205675234744dc03f028b46da4d94657bbb7dca7b1a3a25e91  tests/fixtures/checksum/directory-success/hello1
""".strip()


def test_simple_gnu_generate():
    root = os.path.join(
        FIXTURES_DIR,
        "manifest-success",
    )
    checksum = ChecksumFile(
        root,
        differ=DistlibManifestChecksumFileExistenceDiffer,
    )
    generated_manifest = checksum.generate_gnu_style()
    actual_manifest = open(
        os.path.join(
            root,
            ".ansible-sign",
            "sha256sum.txt",
        ),
        "r",
    ).read()
    assert generated_manifest == actual_manifest


@pytest.mark.parametrize(
    "fixture, exc_substr",
    [
        (DUPLICATE_LINES_FIXTURE, "Duplicate path in checksum, line 2"),
        (INVALID_LINE_FIXTURE1, "Unparsable checksum, line 1"),
        (INVALID_LINE_FIXTURE2, "Unparsable checksum, line 1"),
    ],
)
def test_parse_invalid_manifests(fixture, exc_substr):
    checksum = ChecksumFile("/tmp", differ=None)
    with pytest.raises(InvalidChecksumLine) as exc:
        checksum.parse(fixture)
    assert exc_substr in str(exc)


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
    fixture,
    diff_output,
):
    root = os.path.join(
        FIXTURES_DIR,
        f"manifest-{fixture}",
    )
    checksum = ChecksumFile(
        root,
        differ=DistlibManifestChecksumFileExistenceDiffer,
    )
    actual_manifest = open(
        os.path.join(
            root,
            ".ansible-sign",
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


def test_manifest_evil_file_added():
    """
    Test a specific scenario: We wildcard *.yml but NOT *.yaml.
    We want to ensure an unexpected evil.yaml blocks validation.
    """

    root = os.path.join(
        FIXTURES_DIR,
        "manifest-files-added-not-in-manifest",
    )
    checksum = ChecksumFile(
        root,
        differ=DistlibManifestChecksumFileExistenceDiffer,
    )
    actual_manifest = open(
        os.path.join(
            root,
            ".ansible-sign",
            "sha256sum.txt",
        ),
        "r",
    ).read()
    parsed_manifest = checksum.parse(actual_manifest)
    with pytest.raises(ChecksumMismatch) as ex:
        checksum.verify(parsed_manifest)


def test_missing_manifest():
    root = os.path.join(FIXTURES_DIR, "missing-manifest")
    checksum = ChecksumFile(
        root,
        differ=DistlibManifestChecksumFileExistenceDiffer,
    )

    with pytest.raises(FileNotFoundError) as ex:
        checksum.verify({})

    assert "missing-manifest/MANIFEST.in" in str(ex)
