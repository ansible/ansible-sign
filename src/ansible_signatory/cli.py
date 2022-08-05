import argparse
import logging
import os
import sys

from ansible_signatory import __version__
from ansible_signatory.checksum import (
    ChecksumFile,
    ChecksumMismatch,
    InvalidChecksumLine,
)
from ansible_signatory.checksum.differ import *
from ansible_signatory.signing import *

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"

_logger = logging.getLogger(__name__)


DIFFER_MAP = {
    "git": GitChecksumFileExistenceDiffer,
    "directory": DirectoryChecksumFileExistenceDiffer,
    "manifest": DistlibManifestChecksumFileExistenceDiffer,
}


def parse_args(args):
    """Parse command line parameters

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--help"]``).

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """

    parser = argparse.ArgumentParser(
        description="Signing and validation for Ansible content"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ansible-signatory {ver}".format(ver=__version__),
    )
    parser.add_argument(
        "--debug",
        help="Print a bunch of debug info",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
    )

    # Future-proofing for future content types.
    content_type_parser = parser.add_subparsers(required=True, dest="content_type")

    project = content_type_parser.add_parser(
        "project",
        help="Act on an Ansible project directory",
    )
    project_commands = project.add_subparsers(required=True, dest="command")

    # command: validate-checksum
    cmd_validate_checksum = project_commands.add_parser(
        "validate-checksum",
        help="Perform checksum file validation (NOT including signature signing)",
    )
    cmd_validate_checksum.set_defaults(func=validate_checksum)
    cmd_validate_checksum.add_argument(
        "--checksum-file",
        help="The checksum file to use (default: %(default)s)",
        required=False,
        metavar="CHECKSUM_FILE",
        dest="checksum_file",
        default="sha256sum.txt",
    )
    cmd_validate_checksum.add_argument(
        "--scm",
        help="The source code management system (if any) storing the files. Used for skipping files that the SCM ignores. (choices: %(choices)s; default: %(default)s)",
        required=False,
        metavar="SCM",
        dest="scm",
        default="manifest",
        choices=list(DIFFER_MAP.keys()) + ["auto"],
    )
    cmd_validate_checksum.add_argument(
        "--ignore-file-list-differences",
        help="Do not fail validation even if files have been added or removed, and the current manifest is out of date. Only check those files listed in the manifest. (default: %(default)s)",
        default=False,
        action="store_true",
        dest="ignore_file_list_differences",
    )
    cmd_validate_checksum.add_argument(
        "--algorithm",
        help="Which checksum hashing algorithm to use. (default: %(default)s)",
        required=False,
        choices=ChecksumFile.MODES,
        metavar="ALGORITHM",
        dest="algorithm",
        default="sha256",
    )
    cmd_validate_checksum.add_argument(
        "project_root",
        help="The directory containing the files being validated and verified",
        metavar="PROJECT_ROOT",
    )

    # command: gpg-validate-manifest
    cmd_gpg_validate_manifest = project_commands.add_parser(
        "gpg-validate-checksum",
        help="Perform signature validation on the checksum manifest (NOT including checksum verification)",
    )
    cmd_gpg_validate_manifest.set_defaults(func=gpg_validate_manifest)
    cmd_gpg_validate_manifest.add_argument(
        "--signature-file",
        help="An optional detached signature file. (default: %(default)s)",
        required=False,
        metavar="SIGNATURE_FILE",
        dest="signature_file",
        default="sha256sum.txt.sig",
    )
    # TODO: Allow using the user's real keyring and accept a fingerprint instead.
    cmd_gpg_validate_manifest.add_argument(
        "pubkey_file",
        help="Path to the GPG public key to import",
        metavar="PUBKEY_FILE",
    )
    cmd_gpg_validate_manifest.add_argument(
        "checksum_file",
        help="The checksum file that was signed. (default: %(default)s)",
        metavar="CHECKSUM_FILE",
        default="sha256sum.txt",
    )

    # command: gpg-sign-manifest
    # TODO: Allow for inline signatures.
    cmd_gpg_sign_manifest = project_commands.add_parser(
        "gpg-sign-manifest",
        help="Perform GPG signing on the checksum manifest",
    )
    cmd_gpg_sign_manifest.set_defaults(func=gpg_sign_manifest)
    cmd_gpg_sign_manifest.add_argument(
        "--output",
        help="An optional filename to which to write the resulting detached signature. (default: %(default)s)",
        required=False,
        metavar="OUTPUT",
        dest="output",
        default="sha256sum.txt.sig",
    )
    # TODO: Allow using the user's real keyring and accept a fingerprint instead.
    cmd_gpg_sign_manifest.add_argument(
        "pubkey_file",
        help="Path to the GPG public key to import",
        metavar="PUBKEY_FILE",
    )
    cmd_gpg_sign_manifest.add_argument(
        "checksum_file",
        help="The checksum file that was signed. (default: %(default)s)",
        metavar="CHECKSUM_FILE",
        default="sha256sum.txt",
    )

    # command: checksum-manifest
    cmd_checksum_manifest = project_commands.add_parser(
        "checksum-manifest",
        help="Generate a checksum manifest file for the project",
    )
    cmd_checksum_manifest.set_defaults(func=checksum_manifest)
    cmd_checksum_manifest.add_argument(
        "--algorithm",
        help="Which checksum hashing algorithm to use. (default: %(default)s)",
        required=False,
        choices=ChecksumFile.MODES,
        metavar="ALGORITHM",
        dest="algorithm",
        default="sha256",
    )
    cmd_checksum_manifest.add_argument(
        "--output",
        help="An optional filename to which to write the resulting manifest. (default: %(default)s)",
        required=False,
        metavar="OUTPUT",
        dest="output",
        default="-",
    )
    cmd_checksum_manifest.add_argument(
        "--scm",
        help="The source code management system (if any) storing the files. Used for skipping files that the SCM ignores. (choices: %(choices)s; default: %(default)s)",
        required=False,
        metavar="SCM",
        dest="scm",
        default="manifest",
        choices=list(DIFFER_MAP.keys()) + ["auto"],
    )
    cmd_checksum_manifest.add_argument(
        "project_root",
        help="The directory containing the files being validated and verified",
        metavar="PROJECT_ROOT",
    )
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )


def get_differ(scm, project_root):
    if scm == "auto":
        return determine_differ_from_auto(project_root)

    # This key is guaranteed to exist by the arg choices limit
    return DIFFER_MAP[scm]


def determine_differ_from_auto(project_root):
    """
    Attempt to determine the SCM a project is using, if any.
    """

    root_files = os.listdir(project_root)
    if "MANIFEST.in" in root_files:
        return DistlibManifestChecksumFileExistenceDiffer
    if ".git" in root_files:
        return GitChecksumFileExistenceDiffer
    # if '.svn' in root_files:
    #    return SubversionChecksumFileExistenceDiffer
    return DirectoryChecksumFileExistenceDiffer


def validate_checksum(args):
    differ = get_differ(args.scm, args.project_root)
    checksum = ChecksumFile(args.project_root, differ=differ, mode=args.algorithm)
    checksum_file = os.path.join(args.project_root, args.checksum_file)

    if not os.path.exists(checksum_file):
        print(f"Checksum file does not exist: {checksum_file}")
        return 1

    checksum_file_contents = open(checksum_file, "r").read()

    try:
        manifest = checksum.parse(checksum_file_contents)
    except InvalidChecksumLine as e:
        print(f"Invalid line encountered in checksum manifest: {e}")
        return 1

    try:
        checksum.verify(manifest, diff=not args.ignore_file_list_differences)
    except ChecksumMismatch as e:
        print("Checksum validation FAILED!")
        print(str(e))
        return 2

    print("Checksum validation SUCCEEDED!")


def gpg_validate_manifest(args):
    if not os.path.exists(args.signature_file):
        # It might be nice to try falling back to inline signature if the
        # detached one is default and does not exist.
        print(f"Signature file does not exist: {args.signature_file}")
        return 1

    if not os.path.exists(args.pubkey_file):
        print(f"Public key file does not exist: {args.pubkey_file}")
        return 1
    if not os.path.exists(args.checksum_file):
        print(f"Checksum file does not exist: {args.checksum_file}")
        return 1

    # Right now we only handle gpg
    with open(args.pubkey_file) as f:
        pubkey = f.read()
    verifier = GPGVerifier(
        pubkey,
        manifest_path=args.checksum_file,
        detached_signature_path=args.signature_file,
    )
    result = verifier.verify()
    if result.success is True:
        print("Signature validation SUCCEEDED!")
        print(result.summary)
        return 0
    print("Signature validation FAILED!")
    print(result.summary)
    print(result.extra_information)
    return 3


def gpg_sign_manifest(args):
    print("todo")


def checksum_manifest(args):
    differ = get_differ(args.scm, args.project_root)
    checksum = ChecksumFile(args.project_root, differ=differ, mode=args.algorithm)
    checksum_file_contents = checksum.generate_gnu_style()
    if args.output == "-":
        print(checksum_file_contents, end="")
    else:
        with open(args.output, "w") as f:
            f.write(checksum_file_contents)
            print(f"Wrote {args.output}")


def main(args):
    """Wrapper allowing :func:`fib` to be called with string arguments in a CLI fashion

    Instead of returning the value from :func:`fib`, it prints the result to the
    ``stdout`` in a nicely formatted message.

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--verbose", "42"]``).
    """
    args = parse_args(args)
    setup_logging(args.loglevel)
    _logger.debug("Starting crazy calculations...")
    exitcode = args.func(args)
    _logger.info("Script ends here")
    return exitcode


def run():
    """Calls :func:`main` passing the CLI arguments extracted from :obj:`sys.argv`

    This function can be used as entry point to create console scripts with setuptools.
    """
    return main(sys.argv[1:])


if __name__ == "__main__":
    run()
