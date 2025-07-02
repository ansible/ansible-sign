import os
import pytest

from ansible_sign.checksum import (
    ChecksumFile,
    InvalidChecksumLine,
    ChecksumMismatch,
    DistlibManifestChecksumFileExistenceDiffer,
)

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

# Weird checksum file that for some reason has some blank lines in it.
# The blank lines should just be skipped.
# We should never generate such a file, but the parser handles it just to be
# safe, and so we need this for coverage.
BLANK_LINES_FIXTURE = """

d2d1320f7f4fe3abafe92765732d2aa6c097e7adf05bbd53481777d4a1f0cdab  MANIFEST.in
dc920c7f31a4869fb9f94519a4a77f6c7c43c6c3e66b0e57a5bcda52e9b02ce3  dir/hello2

2a1b1ab320215205675234744dc03f028b46da4d94657bbb7dca7b1a3a25e91e  hello1


""".strip()


@pytest.mark.parametrize(
    "fixture",
    [
        "manifest-success",
        "manifest-with-blank-lines-and-comments",
    ],
)
def test_simple_gnu_generate(fixture):
    root = os.path.join(
        FIXTURES_DIR,
        fixture,
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


def test_parse_manifest_with_blank_lines():
    checksum = ChecksumFile("/tmp", differ=None)
    parsed = checksum.parse(BLANK_LINES_FIXTURE)
    assert len(parsed) == 3
    assert (
        parsed["MANIFEST.in"]
        == "d2d1320f7f4fe3abafe92765732d2aa6c097e7adf05bbd53481777d4a1f0cdab"
    )
    assert (
        parsed["dir/hello2"]
        == "dc920c7f31a4869fb9f94519a4a77f6c7c43c6c3e66b0e57a5bcda52e9b02ce3"
    )
    assert (
        parsed["hello1"]
        == "2a1b1ab320215205675234744dc03f028b46da4d94657bbb7dca7b1a3a25e91e"
    )


def test_parse_manifest_with_only_blank_lines():
    checksum = ChecksumFile("/tmp", differ=None)
    parsed = checksum.parse("\n\n\n\n\n")
    assert len(parsed) == 0


def test_parse_manifest_empty():
    """
    Don't throw on empty manifest, but return an empty dict.
    """
    checksum = ChecksumFile("/tmp", differ=None)
    parsed = checksum.parse("")
    assert len(parsed) == 0


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
    with pytest.raises(ChecksumMismatch):
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
