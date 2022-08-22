import argparse
import getpass
import logging
import os
import sys

from ansible_sign import __version__
from ansible_sign.checksum import (
    ChecksumFile,
    ChecksumMismatch,
    InvalidChecksumLine,
)
from ansible_sign.checksum.differ import DistlibManifestChecksumFileExistenceDiffer
from ansible_sign.signing import GPGSigner, GPGVerifier

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"

_logger = logging.getLogger(__name__)

# This is relative to the project root passed in by the user at runtime.
ANSIBLE_SIGN_DIR = ".ansible-sign"


def parse_args(args):
    """Parse command line parameters

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--help"]``).

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """

    parser = argparse.ArgumentParser(description="Signing and validation for Ansible content")
    parser.add_argument(
        "--version",
        action="version",
        version="ansible-sign {ver}".format(ver=__version__),
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
        default=os.path.join(ANSIBLE_SIGN_DIR, "sha256sum.txt"),
    )
    cmd_validate_checksum.add_argument(
        "--ignore-file-list-differences",
        help=(
            "Do not fail validation even if files have been added or removed, "
            "and the current manifest is out of date. Only check those files "
            "listed in the manifest. (default: %(default)s)"
        ),
        default=False,
        action="store_true",
        dest="ignore_file_list_differences",
    )
    cmd_validate_checksum.add_argument(
        "project_root",
        help="The directory containing the files being validated and verified",
        metavar="PROJECT_ROOT",
    )

    # command: gpg-verify
    cmd_gpg_verify = project_commands.add_parser(
        "gpg-verify",
        help=("Perform signature validation AND checksum verification on the checksum manifest"),
    )
    cmd_gpg_verify.set_defaults(func=gpg_verify)
    cmd_gpg_verify.add_argument(
        "--signature-file",
        help=("An optional detached signature file, relative to the project root. (default: %(default)s)"),
        required=False,
        metavar="SIGNATURE_FILE",
        dest="signature_file",
        default=os.path.join(ANSIBLE_SIGN_DIR, "sha256sum.txt.sig"),
    )
    cmd_gpg_verify.add_argument(
        "--manifest-file",
        help=("The signed checksum manifest file, relative to the project root. (default: %(default)s)"),
        required=False,
        metavar="MANIFEST_FILE",
        dest="manifest_file",
        default=os.path.join(ANSIBLE_SIGN_DIR, "sha256sum.txt"),
    )
    cmd_gpg_verify.add_argument(
        "--keyring",
        help=("The GPG keyring file to use to find the matching public key. (default: the user's default keyring)"),
        required=False,
        metavar="KEYRING",
        dest="keyring",
        default=None,
    )
    cmd_gpg_verify.add_argument(
        "--gnupg-home",
        help=("A valid GNUPG home directory. (default: the GNUPG default, usually ~/.gnupg)"),
        required=False,
        metavar="GNUPG_HOME",
        dest="gnupg_home",
        default=None,
    )
    cmd_gpg_verify.add_argument(
        "project_root",
        help="The directory containing the files being validated and verified",
        metavar="PROJECT_ROOT",
    )

    # command: gpg-sign
    cmd_gpg_sign = project_commands.add_parser(
        "gpg-sign",
        help="Generate a checksum manifest and GPG sign it",
    )
    cmd_gpg_sign.set_defaults(func=gpg_sign)
    cmd_gpg_sign.add_argument(
        "--signature-output",
        help=("An optional filename to which to write the resulting detached signature. (default: %(default)s)"),
        required=False,
        metavar="SIGNATURE",
        dest="signature_output",
        default=os.path.join(ANSIBLE_SIGN_DIR, "sha256sum.txt.sig"),
    )
    cmd_gpg_sign.add_argument(
        "--manifest-output",
        help=("An optional filename to which to write the resulting checksum manifest. (default: %(default)s)"),
        required=False,
        metavar="MANIFEST",
        dest="manifest_output",
        default=os.path.join(ANSIBLE_SIGN_DIR, "sha256sum.txt"),
    )
    cmd_gpg_sign.add_argument(
        "--manifest",
        help=("A manifest to use as input instead of generating one. (default: %(default)s)"),
        required=False,
        metavar="MANIFEST_INPUT",
        dest="manifest_input",
        default=None,
    )
    cmd_gpg_sign.add_argument(
        "--fingerprint",
        help=("The GPG private key fingerprint to sign with. (default: First usable key in the user's keyring)"),
        required=False,
        metavar="PRIVATE_KEY",
        dest="fingerprint",
        default=None,
    )
    cmd_gpg_sign.add_argument(
        "-p",
        "--prompt-passphrase",
        help="Prompt for a GPG key passphrase",
        required=False,
        dest="prompt_passphrase",
        default=False,
        action="store_true",
    )
    cmd_gpg_sign.add_argument(
        "--gnupg-home",
        help=("A valid GNUPG home directory. (default: the GNUPG default, usually ~/.gnupg)"),
        required=False,
        metavar="GNUPG_HOME",
        dest="gnupg_home",
        default=None,
    )
    cmd_gpg_sign.add_argument(
        "project_root",
        help="The directory containing the files being validated and verified",
        metavar="PROJECT_ROOT",
    )

    # command: checksum-manifest
    cmd_checksum_manifest = project_commands.add_parser(
        "checksum-manifest",
        help="Generate a checksum manifest file for the project",
    )
    cmd_checksum_manifest.set_defaults(func=checksum_manifest)
    cmd_checksum_manifest.add_argument(
        "--output",
        help="An optional filename to which to write the resulting manifest. (default: %(default)s)",
        required=False,
        metavar="OUTPUT",
        dest="output",
        default="-",
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
    logging.basicConfig(level=loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S")


def _generate_checksum_manifest(project_root):
    differ = DistlibManifestChecksumFileExistenceDiffer
    checksum = ChecksumFile(project_root, differ=differ)
    try:
        manifest = checksum.generate_gnu_style()
    except FileNotFoundError as e:
        if str(e).endswith("/MANIFEST.in"):
            print("Could not find a MANIFEST.in file in the specified project.")
            print("If you are attempting to sign a project, please create this file.")
            print("See the ansible-sign documentation for more information.")
            return False
        raise e
    _logger.debug(
        "Full calculated checksum manifest (%s):\n%s",
        project_root,
        manifest,
    )
    return manifest


def validate_checksum(args):
    differ = DistlibManifestChecksumFileExistenceDiffer
    checksum = ChecksumFile(args.project_root, differ=differ)
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


def gpg_verify(args):
    signature_file = os.path.join(args.project_root, args.signature_file)
    manifest_file = os.path.join(args.project_root, args.manifest_file)

    if not os.path.exists(signature_file):
        print(f"Signature file does not exist: {signature_file}")
        return 1

    if not os.path.exists(manifest_file):
        print(f"Checksum manifest file does not exist: {manifest_file}")
        return 1

    if args.keyring is not None and not os.path.exists(args.keyring):
        print(f"Specified keyring file not found: {args.keyring}")
        return 1

    if args.gnupg_home is not None and not os.path.isdir(args.gnupg_home):
        print(f"Specified GNUPG home is not a directory: {args.gnupg_home}")
        return 1

    verifier = GPGVerifier(
        manifest_path=manifest_file,
        detached_signature_path=signature_file,
        gpg_home=args.gnupg_home,
        keyring=args.keyring,
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


def _write_file_or_print(dest, contents):
    if dest == "-":
        print(contents, end="")
        return

    outdir = os.path.dirname(dest)

    if len(outdir) > 0 and not os.path.isdir(outdir):
        _logger.info("Creating output directory: %s", outdir)
        os.makedirs(outdir)

    with open(dest, "w") as f:
        f.write(contents)
        _logger.info("Wrote to file: %s", dest)


def gpg_sign(args):
    # Step 1: Manifest
    # If --manifest is given, then use that file as the input manifest to sign.
    # Otherwise, generate the manifest from scratch.
    if args.manifest_input is None:
        # It was NOT given, so we need to generate it. But we can't if the user
        # is trying to pass "-" to _generate_checksum_manifest().
        if args.manifest_output == "-":
            print("Cannot output checksum manifest to stdout, because then we couldn't sign it!")
            return 1

        manifest_output = os.path.join(args.project_root, args.manifest_output)
        checksum_file_contents = _generate_checksum_manifest(args.project_root)
        if checksum_file_contents is False:
            return 1
        _write_file_or_print(manifest_output, checksum_file_contents)
        manifest_path = manifest_output
    else:
        manifest_input = os.path.join(args.project_root, args.manifest_input)
        if not os.path.exists(manifest_input):
            print(f"Checksum manifest file does not exist: {manifest_input}")
            return 1
        manifest_path = manifest_input

    # Step 2: Signing
    # Do they need a passphrase?
    passphrase = None
    if args.prompt_passphrase:
        passphrase = getpass.getpass("GPG Key Passphrase: ")

    signer = GPGSigner(
        manifest_path=manifest_path,
        output_path=args.signature_output,
        privkey=args.fingerprint,
        passphrase=passphrase,
        gpg_home=args.gnupg_home,
    )
    result = signer.sign()
    if result.success:
        print("GPG signing successful!")
        retcode = 0
    else:
        print("GPG signing FAILED!")
        retcode = 4

    print(f"Checksum manifest: {manifest_path}")
    print(f"GPG summary: {result.summary}")
    print(f"GPG Details: {result.extra_information}")
    return retcode


def checksum_manifest(args):
    checksum_file_contents = _generate_checksum_manifest(args.project_root)
    _write_file_or_print(args.output, checksum_file_contents)


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
