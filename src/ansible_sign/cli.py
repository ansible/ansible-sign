import argparse
from cryptography.x509 import load_pem_x509_certificates
from distlib.manifest import DistlibException
import getpass
import logging
import os
from pathlib import Path
from sigstore._internal.ctfe import CTKeyring
from sigstore._internal.fulcio.client import (
    ExpiredCertificate,
    FulcioClient,
)
from sigstore._internal.keyring import Keyring
from sigstore._internal.rekor.client import (
    RekorClient,
    RekorKeyring,
)
from sigstore._internal.tuf import TrustUpdater
from sigstore.errors import Error
from sigstore.oidc import (
    detect_credential,
    ExpiredIdentity,

    IdentityToken,
    Issuer,
)
from sigstore.sign import SigningContext
from sigstore.transparency import LogEntry
from sigstore.verify import (
    CertificateVerificationFailure,
    LogEntryMissing,
    policy,
    VerificationMaterials,
    VerificationFailure,
)
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle
import sys
from textwrap import dedent
from typing import cast

from ansible_sign import __version__
from ansible_sign.checksum import (
    ChecksumFile,
    ChecksumMismatch,
    InvalidChecksumLine,
)
from ansible_sign.checksum.differ import DistlibManifestChecksumFileExistenceDiffer
from ansible_sign.signing import GPGSigner
from ansible_sign.signing import GPGVerifier
from ansible_sign.signing import SigstoreVerifier


__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


# This is relative to the project root passed in by the user at runtime.
ANSIBLE_SIGN_DIR = ".ansible-sign"

DEFAULT_PROD_OAUTH_ISSUER_URL = "https://oauth2.sigstore.dev/auth"
DEFAULT_STAGING_OAUTH_ISSUER_URL = "https://oauth2.sigstage.dev/auth"
DEFAULT_PROD_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_PROD_FULCIO_URL = "https://fulcio.sigstore.dev"


class SigstoreVerificationError(Error):
    """Raised when the verifier returns a `VerificationFailure` result."""

    def __init__(self, result: VerificationFailure):
        self.message = f"Verification failed: {result.reason}"
        self.result = result

    def diagnostics(self) -> str:
        message = f"Failure reason: {self.result.reason}\n"

        if isinstance(self.result, CertificateVerificationFailure):
            message += dedent(
                f"""
                The given certificate could not be verified against the
                root of trust.

                This may be a result of connecting to the wrong Fulcio instance
                (for example, staging instead of production, or vice versa).

                Additional context:

                {self.result.exception}
                """
            )
        elif isinstance(self.result, LogEntryMissing):
            message += dedent(
                f"""
                These signing artifacts could not be matched to a entry
                in the configured transparency log.

                This may be a result of connecting to the wrong Rekor instance
                (for example, staging instead of production, or vice versa).

                Additional context:

                Signature: {self.result.signature}

                Artifact hash: {self.result.artifact_hash}
                """
            )
        else:
            message += dedent(
                f"""
                A verification error occurred.

                Additional context:

                {self.result}
                """
            )

        return message


def _boolify_env(envvar: str):
    """
    An `argparse` helper for turning an environment variable into a boolean.
    The semantics here closely mirror `distutils.util.strtobool`.
    See: <https://docs.python.org/3/distutils/apiref.html#distutils.util.strtobool>
    """
    val = os.getenv(envvar)
    if val is None:
        return False

    val = val.lower()
    if val in {"y", "yes", "true", "t", "on", "1"}:
        return True
    elif val in {"n", "no", "false", "f", "off", "0"}:
        return False
    else:
        raise ValueError(f"can't coerce '{val}' to a boolean")


def _add_shared_instance_options(sigstore_command):
    """Add shared instance options for sigstore-sign and sigtsore-verify subcommands."""
    sigstore_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help=(
            "Use sigstore's staging instances, instead of the default production instances. "
            "This option will be deprecated in favor of the global `--staging` option "
            "in a future release."
        ),
    )
    sigstore_command.add_argument(
        "--rekor-url",
        metavar="URL",
        type=str,
        default=DEFAULT_PROD_REKOR_URL,
        help=(
            "The Rekor instance to use (conflicts with --staging). "
            "This option will be deprecated in favor of the global `--rekor-url` option "
            "in a future release."
        ),
    )
    sigstore_command.add_argument(
        "--rekor-root-pubkey",
        metavar="FILE",
        type=argparse.FileType("rb"),
        default=None,
        help=(
            "A PEM-encoded root public key for Rekor itself (conflicts with --staging). "
            "This option will be deprecated in favor of the global `--rekor-root-pubkey` option "
            "in a future release."
        ),
    )

def _add_shared_oidc_options(sigstore_command):
    """
    Common OIDC options, shared between sigstore-sign and sigstore-get-identity-token subcommands.
    """
    sigstore_command.add_argument(
        "--oidc-client-id",
        metavar="ID",
        type=str,
        default=os.getenv("SIGSTORE_OIDC_CLIENT_ID", "sigstore"),
        help="The custom OpenID Connect client ID to use during OAuth2",
    )
    sigstore_command.add_argument(
        "--oidc-client-secret",
        metavar="SECRET",
        type=str,
        default=os.getenv("SIGSTORE_OIDC_CLIENT_SECRET"),
        help="The custom OpenID Connect client secret to use during OAuth2",
    )
    sigstore_command.add_argument(
        "--oidc-disable-ambient-providers",
        action="store_true",
        default=_boolify_env("SIGSTORE_OIDC_DISABLE_AMBIENT_PROVIDERS"),
        help="Disable ambient OpenID Connect credential detection (e.g. on GitHub Actions)",
    )
    sigstore_command.add_argument(
        "--oidc-issuer",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_OIDC_ISSUER", DEFAULT_PROD_OAUTH_ISSUER_URL),
        help="The OpenID Connect issuer to use (conflicts with --staging)",
    )
    sigstore_command.add_argument(
        "--oauth-force-oob",
        action="store_true",
        default=_boolify_env("SIGSTORE_OAUTH_FORCE_OOB"),
        help="Force an out-of-band OAuth flow and do not automatically start the default web browser",
    )


def _add_shared_verification_options(sigstore_command):
    """
    Common verification options, shared between sigstore-verify subcommands.
    """
    sigstore_command.add_argument(
        "--cert-identity",
        metavar="IDENTITY",
        type=str,
        default=os.getenv("SIGSTORE_CERT_IDENTITY"),
        help="The identity to check for in the certificate's Subject Alternative Name",
        required=True,
    )
    sigstore_command.add_argument(
        "--offline",
        action="store_true",
        default=_boolify_env("SIGSTORE_OFFLINE"),
        help="Perform offline verification; requires a Sigstore bundle",
    )


class AnsibleSignCLI:
    def __init__(self, args):
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Parsing args: %s", str(args))
        self.args = self.parse_args(args)
        logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
        logging.basicConfig(level=self.args.loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S")

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
        parser.add_argument(
            "--nocolor",
            help="Disable color output",
            required=False,
            dest="nocolor",
            default=True if len(os.environ.get("NO_COLOR", "")) else False,
            action="store_true",
        )

        # Future-proofing for future content types.
        content_type_parser = parser.add_subparsers(required=True, dest="content_type", metavar="CONTENT_TYPE")

        project = content_type_parser.add_parser(
            "project",
            help="Act on an Ansible project directory",
        )
        project_commands = project.add_subparsers(required=True, dest="command")

        # command: gpg-verify
        cmd_gpg_verify = project_commands.add_parser(
            "gpg-verify",
            help=("Perform GPG signature validation AND checksum verification on the checksum manifest"),
        )
        cmd_gpg_verify.set_defaults(func=self.gpg_verify)
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
            help=("A valid GnuPG home directory. (default: the GnuPG default, usually ~/.gnupg)"),
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
            help=("A valid GnuPG home directory. (default: the GnuPG default, usually ~/.gnupg)"),
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

        # command: sigstore-verify
        cmd_sigstore_verify = project_commands.add_parser(
            "sigstore-verify", help="Perform Sigstore signature validation AND checksum verification on the checksum manifest"
        )
        sigstore_verify_subcommand = cmd_sigstore_verify.add_subparsers(dest="sigstore_verify_subcommand")
        # subcommand: sigstore-verify identity
        verify_identity = sigstore_verify_subcommand.add_parser(
            "identity",
            help="Verify against a known identity and identity provider",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        verify_identity.add_argument(
            "project_root",
            help="The directory containing the files being validated and verified",
            metavar="PROJECT_ROOT",
        )
        verify_identity.set_defaults(func=self.sigstore_verify_identity)

        verification_options = verify_identity.add_argument_group("Verification options")
        _add_shared_verification_options(verification_options)
        verification_options.add_argument(
            "--cert-oidc-issuer",
            metavar="URL",
            type=str,
            default=os.getenv("SIGSTORE_CERT_OIDC_ISSUER"),
            help="The OIDC issuer URL to check for in the certificate's OIDC issuer extension",
            required=True,
        )
        instance_options = verify_identity.add_argument_group("Sigstore instance options")
        _add_shared_instance_options(instance_options)
        instance_options.add_argument(
            "--certificate-chain",
            metavar="FILE",
            type=argparse.FileType("rb"),
            help=(
                "Path to a list of CA certificates in PEM format which will be needed when building "
                "the certificate chain for the Fulcio signing certificate"
            ),
        )

        # subcommand: sigstore-verify github
        verify_github = sigstore_verify_subcommand.add_parser(
            "github",
            help="verify against GitHub Actions-specific claims",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        verify_github.add_argument(
            "project_root",
            help="The directory containing the files being validated and verified",
            metavar="PROJECT_ROOT",
        )
        verify_github.set_defaults(func=self.sigstore_verify_github)

        verification_options = verify_github.add_argument_group("Verification options")
        _add_shared_verification_options(verification_options)
        verification_options.add_argument(
            "--trigger",
            dest="workflow_trigger",
            metavar="EVENT",
            type=str,
            default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_TRIGGER"),
            help="The GitHub Actions event name that triggered the workflow",
        )
        verification_options.add_argument(
            "--sha",
            dest="workflow_sha",
            metavar="SHA",
            type=str,
            default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_SHA"),
            help="The `git` commit SHA that the workflow run was invoked with",
        )
        verification_options.add_argument(
            "--name",
            dest="workflow_name",
            metavar="NAME",
            type=str,
            default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_NAME"),
            help="The name of the workflow that was triggered",
        )
        verification_options.add_argument(
            "--repository",
            dest="workflow_repository",
            metavar="REPO",
            type=str,
            default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_REPOSITORY"),
            help="The repository slug that the workflow was triggered under",
        )
        verification_options.add_argument(
            "--ref",
            dest="workflow_ref",
            metavar="REF",
            type=str,
            default=os.getenv("SIGSTORE_VERIFY_GITHUB_WORKFLOW_REF"),
            help="The `git` ref that the workflow was invoked with",
        )
        instance_options = verify_github.add_argument_group("Sigstore instance options")
        _add_shared_instance_options(instance_options)
        instance_options.add_argument(
            "--certificate-chain",
            metavar="FILE",
            type=argparse.FileType("rb"),
            help=(
                "Path to a list of CA certificates in PEM format which will be needed when building " "the certificate chain for the Fulcio signing certificate"
            ),
        )

        # command: sigstore-sign
        cmd_sigstore_sign = project_commands.add_parser(
            "sigstore-sign", formatter_class=argparse.ArgumentDefaultsHelpFormatter, help="Sign a project using Sigstore"
        )
        cmd_sigstore_sign.add_argument(
            "project_root",
            help="The directory containing the files being validated and verified",
            metavar="PROJECT_ROOT",
        )
        cmd_sigstore_sign.set_defaults(func=self.sigstore_sign)
        oidc_options = cmd_sigstore_sign.add_argument_group("OpenID Connect options")
        oidc_options.add_argument(
            "--identity-token",
            metavar="TOKEN",
            type=str,
            default=os.getenv("SIGSTORE_IDENTITY_TOKEN"),
            help="the OIDC identity token to use",
        )
        _add_shared_oidc_options(oidc_options)

        output_options = cmd_sigstore_sign.add_argument_group("Output options")
        output_options.add_argument(
            "--no-bundle",
            action="store_true",
            default=False,
            help=("Don't emit sha256sum.txt.sigstore output file"),
        )
        output_options.add_argument(
            "--overwrite",
            action="store_true",
            default=_boolify_env("SIGSTORE_OVERWRITE"),
            help="Overwrite preexisting signature and certificate outputs, if present",
        )

        instance_options = cmd_sigstore_sign.add_argument_group("Sigstore instance options")
        _add_shared_instance_options(instance_options)
        instance_options.add_argument(
            "--fulcio-url",
            metavar="URL",
            type=str,
            default=os.getenv("SIGSTORE_FULCIO_URL", DEFAULT_PROD_FULCIO_URL),
            help="The Fulcio instance to use (conflicts with --staging)",
        )
        instance_options.add_argument(
            "--ctfe",
            dest="ctfe_pem",
            metavar="FILE",
            type=argparse.FileType("rb"),
            help="A PEM-encoded public key for the CT log (conflicts with --staging)",
            default=os.getenv("SIGSTORE_CTFE"),
        )

        # command: sigstore-get-identity-token
        get_identity_token = project_commands.add_parser("sigstore-get-identity-token", help="Get an OIDC identity token to generate Sigstore signatures")
        _add_shared_oidc_options(get_identity_token)

        return parser.parse_args(args)

    def _generate_checksum_manifest(self):
        differ = DistlibManifestChecksumFileExistenceDiffer
        checksum = ChecksumFile(self.args.project_root, differ=differ)
        try:
            manifest = checksum.generate_gnu_style()
        except FileNotFoundError as e:
            if os.path.islink(e.filename):
                self._error(f"Broken symlink found at {e.filename} -- this is not supported. Aborting.")
                return False

            if e.filename.endswith("/MANIFEST.in"):
                self._error("Could not find a MANIFEST.in file in the specified project.")
                self._note("If you are attempting to sign a project, please create this file.")
                self._note("See the ansible-sign documentation for more information.")
                return False
            raise e
        except DistlibException as e:
            self._error(f"An error was encountered while parsing MANIFEST.in: {e}")
            if self.args.loglevel != logging.DEBUG:
                self._note("You can use the --debug global flag to view the full traceback.")
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
        checksum_path = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt")
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
                self._error(f"Broken symlink found at {e.filename} -- this is not supported. Aborting.")
                return 1

            if e.filename.endswith("MANIFEST.in"):
                self._error("Could not find a MANIFEST.in file in the specified project.")
                self._note("If you are attempting to verify a signed project, please ensure that the project directory includes this file after signing.")
                self._note("See the ansible-sign documentation for more information.")
                return 1
        except DistlibException as e:
            self._error(f"An error was encountered while parsing MANIFEST.in: {e}")
            if self.args.loglevel != logging.DEBUG:
                self._note("You can use the --debug global flag to view the full traceback.")
            self.logger.debug(e, exc_info=e)
            return 1

        for warning in checksum.warnings:
            self._warn(warning)

        self._ok("Checksum validation succeeded.")
        return 0

    def gpg_verify(self):
        signature_file = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt.sig")
        manifest_file = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt")

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
            self._error(f"Specified GnuPG home is not a directory: {self.args.gnupg_home}")
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
        manifest_path = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt")
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
            self.logger.debug("Taking GPG key passphrase from ANSIBLE_SIGN_GPG_PASSPHRASE env var")
            passphrase = os.environ["ANSIBLE_SIGN_GPG_PASSPHRASE"]
        else:
            os.environ["GPG_TTY"] = os.ttyname(sys.stdin.fileno())

        signature_path = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt.sig")
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

    def sigstore_sign(self):
        # Step 1 Manifest
        self.logger.debug(self)
        manifest_path = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt")
        checksum_file_contents = self._generate_checksum_manifest()
        if checksum_file_contents is False:
            return 1
        self._write_file_or_print(manifest_path, checksum_file_contents)

        # Step 2 Signing
        manifest_path = Path(manifest_path)
        if not manifest_path.is_file():
            self._error(f"Input must be a file: {manifest_path}")
            return 1

        bundle = manifest_path.parent / f"{manifest_path.name}.sigstore"

        if not self.args.overwrite:
            if not self.args.no_bundle and bundle.exists():
                self._error(f"Refusing to overwrite output without --overwrite: {bundle}")
                return 1

        # Select the signing context to use
        if self.args.staging:
            self.logger.debug("sign: staging instances requested")
            signing_ctx = SigningContext.staging()
            self.args.oidc_issuer = DEFAULT_STAGING_OAUTH_ISSUER_URL
        elif self.args.fulcio_url == DEFAULT_PROD_FULCIO_URL and self.args.rekor_url == DEFAULT_PROD_REKOR_URL:
            signing_ctx = SigningContext.production()
        else:
            # Assume "production" keys if none are given as arguments
            updater = TrustUpdater.production()
            if self.args.ctfe_pem is not None:
                ctfe_keys = [self.args.ctfe_pem.read()]
            else:
                ctfe_keys = updater.get_ctfe_keys()
            if self.args.rekor_root_pubkey is not None:
                rekor_keys = [self.args.rekor_root_pubkey.read()]
            else:
                rekor_keys = updater.get_rekor_keys()

            ct_keyring = CTKeyring(Keyring(ctfe_keys))
            rekor_keyring = RekorKeyring(Keyring(rekor_keys))

            signing_ctx = SigningContext(
                fulcio=FulcioClient(self.args.fulcio_url),
                rekor=RekorClient(self.args.rekor_url, rekor_keyring, ct_keyring),
            )

        # The order of precedence for identities is as follows:
        #
        # 1) Explicitly supplied identity token
        # 2) Ambient credential detected in the environment, unless disabled
        # 3) Interactive OAuth flow
        identity: IdentityToken | None
        if self.args.identity_token:
            identity = IdentityToken(self.args.identity_token)
        else:
            identity = self.sigstore_get_identity_token()

        if not identity:
            self._error("No identity token supplied or detected!")
            return 1

        with signing_ctx.signer(identity) as signer:
            self.logger.debug(f"signing for {manifest_path}")
            with open(manifest_path, mode="rb", buffering=0) as io:
                try:
                    result = signer.sign(input_=io)
                except ExpiredIdentity as exp_identity:
                    print("Signature failed: identity token has expired")
                    raise exp_identity
                except ExpiredCertificate as exp_certificate:
                    print("Signature failed: Fulcio signing certificate has expired")
                    raise exp_certificate

            print("Using ephemeral certificate:")
            print(result.cert_pem)

            print(f"Transparency log entry created at index: {result.log_entry.log_index}")

            if not self.args.no_bundle:
                with open(bundle, "w") as io:
                    print(result.to_bundle().to_json(), file=io)
                print(f"Sigstore bundle written to {bundle}")

    def _collect_verification_state(self):
        """
        Performs CLI functionality common across all sigstore-verify subcommands.
        Returns a tuple of the active verifier instance and a list of `(file, materials)`
        tuples, where `file` is the path to the file being verified (for display
        purposes) and `materials` is the `VerificationMaterials` to verify with.
        """

        manifest_file = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt")
        manifest_file = Path(manifest_file)
        bundle_path = manifest_file.parent / f"{manifest_file.name}.sigstore"

        if not bundle_path.is_file():
            self._error(f"Sigstore bundle file for signature verification not found: {bundle_path}")
            return 1, 1

        if self.args.staging:
            self.logger.debug("verify: staging instances requested")
            verifier = SigstoreVerifier.staging()
        elif self.args.rekor_url == DEFAULT_PROD_REKOR_URL:
            verifier = SigstoreVerifier.production()
        else:
            if not self.args.certificate_chain:
                self._error("Custom Rekor URL used without specifying --certificate-chain")
                return 1, 1

            try:
                certificate_chain = load_pem_x509_certificates(self.args.certificate_chain.read())
            except ValueError as error:
                self._error(f"Invalid certificate chain: {error}")
                return 1, 1

            if self.args.rekor_root_pubkey is not None:
                rekor_keys = [self.args.rekor_root_pubkey.read()]
            else:
                updater = TrustUpdater.production()
                rekor_keys = updater.get_rekor_keys()

            verifier = SigstoreVerifier(
                rekor=RekorClient(
                    url=self.args.rekor_url,
                    rekor_keyring=RekorKeyring(Keyring(rekor_keys)),
                    # We don't use the CT keyring in verification so we can supply an empty keyring
                    ct_keyring=CTKeyring(Keyring()),
                ),
                fulcio_certificate_chain=certificate_chain,
            )

        entry: LogEntry | None = None
        manifest_path = os.path.join(manifest_file.parent, manifest_file.name)

        self.logger.debug(f"Using Sigtsore bundle file at {bundle_path}")
        bundle_bytes = bundle_path.read_bytes()
        bundle = Bundle().from_json(bundle_bytes)

        with open(manifest_path, mode="rb", buffering=0) as io:
            materials = VerificationMaterials.from_bundle(input_=io, bundle=bundle, offline=self.args.offline)
            all_materials = [bundle_path, materials]

        return (verifier, all_materials)

    def sigstore_verify_identity(self):
        verifier, file_with_materials = self._collect_verification_state()

        if (verifier, file_with_materials) == (1, 1):
            self._error("Failed to collect Verifier instance and verification materials")
            return 1

        policy_ = policy.Identity(
            identity=self.args.cert_identity,
            issuer=self.args.cert_oidc_issuer,
        )

        file, materials = file_with_materials
        result = verifier.verify(
            materials=materials,
            policy=policy_,
        )

        if result:
            print(f"OK: {file}")
        else:
            print(f"FAIL: {file}")
            raise SigstoreVerificationError(cast(VerificationFailure, result))

    def sigstore_verify_github(self):
        # Every GitHub verification begins with an identity policy,
        # for which we know the issuer URL ahead of time.
        # We then add more policies, as configured by the user's passed-in options.
        inner_policies: list[policy.VerificationPolicy] = [
            policy.Identity(
                identity=self.args.cert_identity,
                issuer="https://token.actions.githubusercontent.com",
            )
        ]

        if self.args.workflow_trigger:
            inner_policies.append(policy.GitHubWorkflowTrigger(self.args.workflow_trigger))
        if self.args.workflow_sha:
            inner_policies.append(policy.GitHubWorkflowSHA(self.args.workflow_sha))
        if self.args.workflow_name:
            inner_policies.append(policy.GitHubWorkflowName(self.args.workflow_name))
        if self.args.workflow_repository:
            inner_policies.append(policy.GitHubWorkflowRepository(self.args.workflow_repository))
        if self.args.workflow_ref:
            inner_policies.append(policy.GitHubWorkflowRef(self.args.workflow_ref))

        policy_ = policy.AllOf(inner_policies)

        verifier, files_with_materials = self._collect_verification_state()
        file, materials = files_with_materials
        
        result = verifier.verify(materials=materials, policy=policy_)

        if result:
            print(f"OK: {file}")
        else:
            print(f"FAIL: {file}")
            raise SigstoreVerificationError(cast(VerificationFailure, result))


    def sigstore_get_identity_token(self):
        token = None
        if not self.args.oidc_disable_ambient_providers:
            token = detect_credential()
            
        if token:
            return IdentityToken(token)

        if self.args.staging:
            issuer = Issuer.staging()
        elif self.args.oidc_issuer == DEFAULT_PROD_OAUTH_ISSUER_URL:
            issuer = Issuer.production()
        else:
            issuer = Issuer(self.args.oidc_issuer)

        if self.args.oidc_client_secret is None:
            self.args.oidc_client_secret = ""  # nosec: B105
        
        token = issuer.identity_token(
            client_id=self.args.oidc_client_id,
            client_secret=self.args.oidc_client_secret,
            force_oob=self.args.oauth_force_oob,
        )

        return token


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
