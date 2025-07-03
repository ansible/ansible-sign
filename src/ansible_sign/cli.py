import argparse
from distlib.manifest import DistlibException
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

# This is relative to the project root passed in by the user at runtime.
ANSIBLE_SIGN_DIR = ".ansible-sign"


class AnsibleSignCLI:
    def __init__(self, args):
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Parsing args: %s", str(args))
        self.args = self.parse_args(args)
        logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
        logging.basicConfig(
            level=self.args.loglevel,
            stream=sys.stdout,
            format=logformat,
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def run_command(self):
        """
        parse_args() will set self.args.func() to the function we wish to
        execute, based on the subcommand the user ran. These 'action functions'
        will return the integer exit code with which we exit at the very end.

        Roughly:
        0 = success
        1 = error (e.g. file missing, permissions issue, couldn't parse checksum file, etc.)
        2 = checksum verification failed
        3 = signature verification failed
        4 = signing failed
        """
        return self.args.func()

    def parse_args(self, args):
        """
        Parse command line parameters

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
            version="ansible-sign {ver}".format(ver=__version__),
        )
        parser.add_argument(
            "--debug",
            help="Print a bunch of debug info",
            action="store_const",
            dest="loglevel",
            const=logging.DEBUG,
        )
        parser.add_argument(
            "--nocolor",
            help="Disable color output",
            required=False,
            dest="nocolor",
            default=True if len(os.environ.get("NO_COLOR", "")) else False,
            action="store_true",
        )

        # Future-proofing for future content types.
        content_type_parser = parser.add_subparsers(
            required=True, dest="content_type", metavar="CONTENT_TYPE"
        )

        project = content_type_parser.add_parser(
            "project",
            help="Act on an Ansible project directory",
        )
        project_commands = project.add_subparsers(required=True, dest="command")

        # command: gpg-verify
        cmd_gpg_verify = project_commands.add_parser(
            "gpg-verify",
            help=(
                "Perform signature validation AND checksum verification on the checksum manifest"
            ),
        )
        cmd_gpg_verify.set_defaults(func=self.gpg_verify)
        cmd_gpg_verify.add_argument(
            "--keyring",
            help=(
                "The GPG keyring file to use to find the matching public key. (default: the user's default keyring)"
            ),
            required=False,
            metavar="KEYRING",
            dest="keyring",
            default=None,
        )
        cmd_gpg_verify.add_argument(
            "--gnupg-home",
            help=(
                "A valid GnuPG home directory. (default: the GnuPG default, usually ~/.gnupg)"
            ),
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
        cmd_gpg_sign.set_defaults(func=self.gpg_sign)
        cmd_gpg_sign.add_argument(
            "--fingerprint",
            help=(
                "The GPG private key fingerprint to sign with. (default: First usable key in the user's keyring)"
            ),
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
            help=(
                "A valid GnuPG home directory. (default: the GnuPG default, usually ~/.gnupg)"
            ),
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
        return parser.parse_args(args)

    def _generate_checksum_manifest(self):
        differ = DistlibManifestChecksumFileExistenceDiffer
        checksum = ChecksumFile(self.args.project_root, differ=differ)
        try:
            manifest = checksum.generate_gnu_style()
        except FileNotFoundError as e:
            if os.path.islink(e.filename):
                self._error(
                    f"Broken symlink found at {e.filename} -- this is not supported. Aborting."
                )
                return False

            if e.filename.endswith("/MANIFEST.in"):
                self._error(
                    "Could not find a MANIFEST.in file in the specified project."
                )
                self._note(
                    "If you are attempting to sign a project, please create this file."
                )
                self._note("See the ansible-sign documentation for more information.")
                return False
            raise e
        except DistlibException as e:
            self._error(f"An error was encountered while parsing MANIFEST.in: {e}")
            if self.args.loglevel != logging.DEBUG:
                self._note(
                    "You can use the --debug global flag to view the full traceback."
                )
            self.logger.debug(e, exc_info=e)
            return False
        for warning in checksum.warnings:
            self._warn(warning)
        self.logger.debug(
            "Full calculated checksum manifest (%s):\n%s",
            self.args.project_root,
            manifest,
        )
        return manifest

    def _error(self, msg):
        if self.args.nocolor:
            print(f"[ERROR] {msg}")
        else:
            print(f"[\033[91mERROR\033[0m] {msg}")

    def _ok(self, msg):
        if self.args.nocolor:
            print(f"[OK   ] {msg}")
        else:
            print(f"[\033[92mOK   \033[0m] {msg}")

    def _note(self, msg):
        if self.args.nocolor:
            print(f"[NOTE ] {msg}")
        else:
            print(f"[\033[94mNOTE \033[0m] {msg}")

    def _warn(self, msg):
        if self.args.nocolor:
            print(f"[WARN ] {msg}")
        else:
            print(f"[\033[93mWARN \033[0m] {msg}")

    def validate_checksum(self):
        """
        Validate a checksum manifest file. Print a pretty message and return an
        appropriate exit code.

        NOTE that this function does not actually check the path for existence, it
        leaves that to the caller (which in nearly all cases would need to do so
        anyway). This function will throw FileNotFoundError if the manifest does not
        exist.
        """
        differ = DistlibManifestChecksumFileExistenceDiffer
        checksum = ChecksumFile(self.args.project_root, differ=differ)
        checksum_path = os.path.join(
            self.args.project_root, ".ansible-sign", "sha256sum.txt"
        )
        checksum_file_contents = open(checksum_path, "r").read()

        try:
            manifest = checksum.parse(checksum_file_contents)
        except InvalidChecksumLine as e:
            self._error(f"Invalid line encountered in checksum manifest: {e}")
            return 1

        try:
            checksum.verify(manifest, diff=True)
        except ChecksumMismatch as e:
            self._error("Checksum validation failed.")
            self._error(str(e))
            return 2
        except FileNotFoundError as e:
            if os.path.islink(e.filename):
                self._error(
                    f"Broken symlink found at {e.filename} -- this is not supported. Aborting."
                )
                return 1

            if e.filename.endswith("MANIFEST.in"):
                self._error(
                    "Could not find a MANIFEST.in file in the specified project."
                )
                self._note(
                    "If you are attempting to verify a signed project, please ensure that the project directory includes this file after signing."
                )
                self._note("See the ansible-sign documentation for more information.")
                return 1
        except DistlibException as e:
            self._error(f"An error was encountered while parsing MANIFEST.in: {e}")
            if self.args.loglevel != logging.DEBUG:
                self._note(
                    "You can use the --debug global flag to view the full traceback."
                )
            self.logger.debug(e, exc_info=e)
            return 1

        for warning in checksum.warnings:
            self._warn(warning)

        self._ok("Checksum validation succeeded.")
        return 0

    def gpg_verify(self):
        signature_file = os.path.join(
            self.args.project_root, ".ansible-sign", "sha256sum.txt.sig"
        )
        manifest_file = os.path.join(
            self.args.project_root, ".ansible-sign", "sha256sum.txt"
        )

        if not os.path.exists(signature_file):
            self._error(f"Signature file does not exist: {signature_file}")
            return 1

        if not os.path.exists(manifest_file):
            self._error(f"Checksum manifest file does not exist: {manifest_file}")
            return 1

        if self.args.keyring is not None and not os.path.exists(self.args.keyring):
            self._error(f"Specified keyring file not found: {self.args.keyring}")
            return 1

        if self.args.gnupg_home is not None and not os.path.isdir(self.args.gnupg_home):
            self._error(
                f"Specified GnuPG home is not a directory: {self.args.gnupg_home}"
            )
            return 1

        verifier = GPGVerifier(
            manifest_path=manifest_file,
            detached_signature_path=signature_file,
            gpg_home=self.args.gnupg_home,
            keyring=self.args.keyring,
        )

        result = verifier.verify()

        if result.success is not True:
            self._error(result.summary)
            self._note("Re-run with the global --debug flag for more information.")
            self.logger.debug(result.extra_information)
            return 3

        self._ok(result.summary)

        # GPG verification is done and we are still here, so return based on
        # checksum validation now.
        return self.validate_checksum()

    def _write_file_or_print(self, dest, contents):
        if dest == "-":
            print(contents, end="")
            return

        outdir = os.path.dirname(dest)

        if len(outdir) > 0 and not os.path.isdir(outdir):
            self.logger.info("Creating output directory: %s", outdir)
            os.makedirs(outdir)

        with open(dest, "w") as f:
            f.write(contents)
            self.logger.info("Wrote to file: %s", dest)

    def gpg_sign(self):
        # Step 1: Manifest
        manifest_path = os.path.join(
            self.args.project_root, ".ansible-sign", "sha256sum.txt"
        )
        checksum_file_contents = self._generate_checksum_manifest()
        if checksum_file_contents is False:
            return 1
        self._write_file_or_print(manifest_path, checksum_file_contents)

        # Step 2: Signing
        # Do they need a passphrase?
        passphrase = None
        if self.args.prompt_passphrase:
            self.logger.debug("Prompting for GPG key passphrase")
            passphrase = getpass.getpass("GPG Key Passphrase: ")
        elif "ANSIBLE_SIGN_GPG_PASSPHRASE" in os.environ:
            self.logger.debug(
                "Taking GPG key passphrase from ANSIBLE_SIGN_GPG_PASSPHRASE env var"
            )
            passphrase = os.environ["ANSIBLE_SIGN_GPG_PASSPHRASE"]
        elif "GPG_TTY" in os.environ:
            self.logger.debug("GPG_TTY is set, taking passphrase from GPG agent")
        else:
            os.environ["GPG_TTY"] = os.ttyname(sys.stdin.fileno())

        signature_path = os.path.join(
            self.args.project_root, ".ansible-sign", "sha256sum.txt.sig"
        )
        signer = GPGSigner(
            manifest_path=manifest_path,
            output_path=signature_path,
            privkey=self.args.fingerprint,
            passphrase=passphrase,
            gpg_home=self.args.gnupg_home,
        )
        result = signer.sign()
        if result.success:
            self._ok("GPG signing successful!")
            retcode = 0
        else:
            self._error("GPG signing FAILED!")
            self._note("Re-run with the global --debug flag for more information.")
            retcode = 4

        self._note(f"Checksum manifest: {manifest_path}")
        self._note(f"GPG summary: {result.summary}")
        self.logger.debug(f"GPG Details: {result.extra_information}")
        return retcode


def main(args):
    cli = AnsibleSignCLI(args)
    cli.logger.debug("Running requested command/passing to function")
    exitcode = cli.run_command()
    cli.logger.info("Script ends here, rc=%d", exitcode)
    return exitcode


def run():
    """Calls :func:`main` passing the CLI arguments extracted from :obj:`sys.argv`

    This function can be used as entry point to create console scripts with setuptools.
    """
    return main(sys.argv[1:])


if __name__ == "__main__":
    run()
