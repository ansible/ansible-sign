import argparse
import base64
from distlib.manifest import DistlibException
import getpass
import logging
import os
from pathlib import Path
from sigstore._internal.ctfe import CTKeyring
from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import get_identity_token
from sigstore._internal.fulcio.client import FulcioClient
from sigstore._internal.oidc.ambient import GitHubOidcPermissionCredentialError
from sigstore._internal.oidc.ambient import detect_credential
from sigstore._internal.rekor.client import RekorClient
from sigstore._verify import policy
from sigstore._verify import VerificationMaterials
import sys

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
from ansible_sign.signing import SigstoreSigner


__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"



# This is relative to the project root passed in by the user at runtime.
ANSIBLE_SIGN_DIR = ".ansible-sign"

DEFAULT_OAUTH_ISSUER = "https://oauth2.sigstore.dev/auth"
STAGING_OAUTH_ISSUER = "https://oauth2.sigstage.dev/auth"
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"


class _Embedded:
    """
    A repr-wrapper for reading embedded resources, needed to help `argparse`
    render defaults correctly.
    """

    def __init__(self, name: str):
        self._name = name

    def read(self) -> bytes:
        return resources.read_binary("sigstore._store", self._name)

    def __repr__(self) -> str:
        return f"{self._name} (embedded)"

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

def _add_shared_instance_options(sigstore_command: argparse.ArgumentParser):
    """Add shared instance options for Sigstore sign and verify subcommands."""
    sigstore_command.add_argument(
        "--staging",
        action="store_true",
        default=_boolify_env("SIGSTORE_STAGING"),
        help="Use sigstore's staging instances, instead of the default production instances",
    )
    sigstore_command.add_argument(
        "--rekor-url",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_REKOR_URL", DEFAULT_REKOR_URL),
        help="The Rekor instance to use (conflicts with --staging)",
    )

def _add_shared_oidc_options(sigstore_command: argparse.ArgumentParser):
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
        default=os.getenv("SIGSTORE_OIDC_ISSUER", DEFAULT_OAUTH_ISSUER),
        help="The OpenID Connect issuer to use (conflicts with --staging)",
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
            "sigstore-verify",
            help=("Verify a Sigstore signature.")
        )
        cmd_sigstore_verify.set_defaults(func=self.sigstore_verify)

        # Sigstore instance options
        _add_shared_instance_options(cmd_sigstore_verify)
        cmd_sigstore_verify.add_argument(
            "--certificate",
            "--cert",
            metavar="FILE",
            type=Path,
            default=os.getenv("SIGSTORE_CERTIFICATE"),
            help="The PEM-encoded certificate to verify against; not used with multiple inputs",
        )
        cmd_sigstore_verify.add_argument(
            "--signature",
            metavar="FILE",
            type=Path,
            default=os.getenv("SIGSTORE_SIGNATURE"),
            help="The signature to verify against; not used with multiple inputs",
        )
        cmd_sigstore_verify.add_argument(
            "--cert-identity",
            metavar="IDENTITY",
            type=str,
            default=os.getenv("SIGSTORE_CERT_IDENTITY"),
            help="The identity to check for in the certificate's Subject Alternative Name",
            required=True,
        )
        cmd_sigstore_verify.add_argument(
            "--cert-oidc-issuer",
            metavar="URL",
            type=str,
            default=os.getenv("SIGSTORE_CERT_OIDC_ISSUER"),
            help="The OIDC issuer URL to check for in the certificate's OIDC issuer extension",
            required=True,
        )
        cmd_sigstore_verify.add_argument(
            "project_root",
            help="The directory containing the files being validated and verified",
            metavar="PROJECT_ROOT",
        )

        #command: sigstore-sign
        cmd_sigstore_sign = project_commands.add_parser(
            "sigstore-sign",
            help=("Generate a checksum manifest and sign it using Sigstore.")
        )
        cmd_sigstore_sign.set_defaults(func=self.sigstore_sign)

        # Sigstore instance options
        _add_shared_instance_options(cmd_sigstore_sign)
        cmd_sigstore_sign.add_argument(
        "--fulcio-url",
        metavar="URL",
        type=str,
        default=os.getenv("SIGSTORE_FULCIO_URL", DEFAULT_FULCIO_URL),
        help="The Fulcio instance to use (conflicts with --staging)",
        )
        cmd_sigstore_sign.add_argument(
            "--ctfe",
            dest="ctfe_pem",
            metavar="FILE",
            type=argparse.FileType("rb"),
            help="A PEM-encoded public key for the CT log (conflicts with --staging)",
            default=os.getenv("SIGSTORE_CTFE", _Embedded("ctfe.pub")),
        )
        cmd_sigstore_sign.add_argument(
            "--rekor-root-pubkey",
            metavar="FILE",
            type=argparse.FileType("rb"),
            help="A PEM-encoded root public key for Rekor itself (conflicts with --staging)",
            default=os.getenv("SIGSTORE_REKOR_ROOT_PUBKEY", _Embedded("rekor.pub")),
        )

        # Sigstore OIDC options
        _add_shared_oidc_options(cmd_sigstore_sign)
        cmd_sigstore_sign.add_argument(
        "--identity-token",
        metavar="TOKEN",
        type=str,
        default=os.getenv("SIGSTORE_IDENTITY_TOKEN"),
        help="the OIDC identity token to use",
        )
        
        # Sigstore output options
        cmd_sigstore_sign.add_argument(
        "--no-default-files",
        action="store_true",
        default=_boolify_env("SIGSTORE_NO_DEFAULT_FILES"),
        help="Don't emit the default output files ({input}.sig, {input}.crt, {input}.rekor)",
        )
        cmd_sigstore_sign.add_argument(
            "--signature",
            "--output-signature",
            metavar="FILE",
            type=Path,
            default=os.getenv("SIGSTORE_OUTPUT_SIGNATURE"),
            help=(
                "Write a single signature to the given file; does not work with multiple input files"
            ),
        )
        cmd_sigstore_sign.add_argument(
            "--certificate",
            "--output-certificate",
            metavar="FILE",
            type=Path,
            default=os.getenv("SIGSTORE_OUTPUT_CERTIFICATE"),
            help=(
                "Write a single certificate to the given file; does not work with multiple input files"
            ),
        )
        cmd_sigstore_sign.add_argument(
            "--overwrite",
            action="store_true",
            default=_boolify_env("SIGSTORE_OVERWRITE"),
            help="Overwrite preexisting signature and certificate outputs, if present",
        )
        cmd_sigstore_sign.add_argument(
            "project_root",
            help="The directory containing the files being validated and verified",
            metavar="PROJECT_ROOT",
        )

        # command: sigstore_get_identity_token
        cmd_sigstore_get_identity_token = project_commands.add_parser(
            "sigstore-get-identity-token",
            help=("Get identity token used to authenticate with Sigstore.")
        )
        _add_shared_oidc_options(cmd_sigstore_get_identity_token)
        cmd_sigstore_get_identity_token.set_defaults(func=self.sigstore_get_identity_token)

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

    def sigstore_verify(self):
        # Fail if --certificate or --signature is specified and we
        # have more than one input.
        if (self.args.certificate or self.args.signature) and len(
            self.args.files
        ) > 1:
            self.logger.error(
                "--certificate and --signature can only be used "
                "with a single input file"
            )

        manifest_file = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt")
        signature_file = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt.sig")
        cert_file = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt.crt")

        if not os.path.exists(manifest_file):
            self.logger.error(f"Checksum manifest file does not exist: {manifest_file}")
            return 1

        if not os.path.exists(signature_file):
            self.logger.error(f"Signature file does not exist: {signature_file}")
            return 1

        if not os.path.exists(cert_file):
            self.logger.error(f"Certificate file does not exist: {cert_file}")
            return 1

        # The converse of `sign`: we build up an expected input map and check
        # that we have everything so that we can fail early.
        input_map = {}
        manifest_file = Path(manifest_file)
        if not manifest_file.is_file():
            self.logger.error(f"Input must be a file: {manifest_file}")

        sig, cert = self.args.signature, self.args.certificate
        if sig is None:
            sig = manifest_file.parent / f"{manifest_file.name}.sig"
        if cert is None:
            cert = manifest_file.parent / f"{manifest_file.name}.crt"

        missing = []
        if not sig.is_file():
            missing.append(str(sig))
        if not cert.is_file():
            missing.append(str(cert))

        if missing:
            self.logger.error(
                f"Missing verification materials for {(manifest_file)}: {', '.join(missing)}"
            )

        input_map[manifest_file] = {"cert": cert, "sig": sig}

        if self.args.staging:
            self.logger.debug("verify: staging instances requested")
            verifier = SigstoreVerifier.staging()
        elif self.args.rekor_url == DEFAULT_REKOR_URL:
            verifier = SigstoreVerifier.production()
        else:
            # TODO: We need CLI flags that allow the user to figure the Fulcio cert chain
            # for verification.
            self.logger.error(
                "Custom Rekor and Fulcio configuration for verification isn't fully supported yet!",
            )

        for file, inputs in input_map.items():
            # Load the signing certificate
            self.logger.debug(f"Using certificate from: {inputs['cert']}")
            cert_pem = inputs["cert"].read_text()

            # Load the signature
            self.logger.debug(f"Using signature from: {inputs['sig']}")
            b64_signature = inputs["sig"].read_text()

            entry: Optional[RekorEntry] = None

            self.logger.debug(f"Verifying contents from: {file}")

            materials = VerificationMaterials(
                input_=file.read_bytes(),
                cert_pem=cert_pem,
                signature=base64.b64decode(b64_signature),
                offline_rekor_entry=entry,
            )

            policy_ = policy.Identity(
                identity=self.args.cert_identity,
                issuer=self.args.cert_oidc_issuer,
            )

            result = verifier.verify(
                materials=materials,
                policy=policy_,
            )

            if result:
                print(f"OK: {file}")
            else:
                result = cast(VerificationFailure, result)
                print(f"FAIL: {file}")
                print(f"Failure reason: {result.reason}", file=sys.stderr)

                if isinstance(result, CertificateVerificationFailure):
                    # If certificate verification failed, it's either because of
                    # a chain issue or some outdated state in sigstore itself.
                    # These might already be resolved in a newer version, so
                    # we suggest that users try to upgrade and retry before
                    # anything else.
                    print(
                        dedent(
                            f"""
                            This may be a result of an outdated `sigstore` installation.
                            Consider upgrading with:
                                python -m pip install --upgrade sigstore
                            Additional context:
                            {result.exception}
                            """
                        ),
                        file=sys.stderr,
                    )
                elif isinstance(result, RekorEntryMissing):
                    # If Rekor lookup failed, it's because the certificate either
                    # wasn't logged after creation or because the user requested the
                    # wrong Rekor instance (e.g., staging instead of production).
                    # The latter is significantly more likely, so we add
                    # some additional context to the output indicating it.
                    #
                    # NOTE: Even though the latter is more likely, it's still extremely
                    # unlikely that we'd hit this -- we should always fail with
                    # `CertificateVerificationFailure` instead, as the cert store should
                    # fail to validate due to a mismatch between the leaf and the trusted
                    # root + intermediates.
                    print(
                        dedent(
                            f"""
                            These signing artifacts could not be matched to a entry
                            in the configured transparency log.
                            This may be a result of connecting to the wrong Rekor instance
                            (for example, staging instead of production, or vice versa).
                            Additional context:
                            Signature: {result.signature}
                            Artifact hash: {result.artifact_hash}
                            """
                        ),
                        file=sys.stderr,
                    )

                sys.exit(1)

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

    def sigstore_sign(self):
        # Step 1 Manifest
        self.logger.debug(self)
        manifest_path = os.path.join(self.args.project_root, ".ansible-sign", "sha256sum.txt")
        checksum_file_contents = self._generate_checksum_manifest()
        if checksum_file_contents is False:
            return 1
        self._write_file_or_print(manifest_path, checksum_file_contents)

        # Step 2 Signing
        # `--no-default-files` has no effect on `--{signature,certificate}`, but we
        # forbid it because it indicates user confusion.
        if self.args.no_default_files and (
            self.args.signature or self.args.certificate
        ):
            self.logger.error(
                "--no-default-files may not be combined with --signature, "
                "or --certificate",
            )

        # Fail if `--signature` or `--certificate` is specified *and* we have more
        # than one input.
        if (self.args.signature or self.args.certificate) and len(
            self.args.files
        ) > 1:
            self.logger.error(
                "Error: --signature and --certificate can't be used "
                "with explicit outputs for multiple inputs",
            )

        # Build up the map of inputs -> outputs ahead of any signing operations,
        # so that we can fail early if overwriting without `--overwrite`.
        output_map = {}
        manifest_path = Path(manifest_path)
        if not manifest_path.is_file():
            self.logger.error(f"Input must be a file: {manifest_path}")

        sig, cert = self.args.signature, self.args.certificate
        if not sig and not cert and not self.args.no_default_files:
            sig = manifest_path.parent / f"{manifest_path.name}.sig"
            cert = manifest_path.parent / f"{manifest_path.name}.crt"

        if not self.args.overwrite:
            extants = []
            if sig and sig.exists():
                extants.append(str(sig))
            if cert and cert.exists():
                extants.append(str(cert))

            if extants:
                self.logger.error(
                    "Refusing to overwrite outputs without --overwrite: "
                    f"{', '.join(extants)}"
                )

        output_map[manifest_path] = {"cert": cert, "sig": sig}

        # Select the signer to use.
        if self.args.staging:
            self.logger.debug("sign: staging instances requested")
            signer = SigstoreSigner.staging()
            self.args.oidc_issuer = STAGING_OAUTH_ISSUER
        elif self.args.fulcio_url == DEFAULT_FULCIO_URL and self.args.rekor_url == DEFAULT_REKOR_URL:
            signer = SigstoreSigner.production()
        else:
            ct_keyring = CTKeyring([load_pem_public_key(self.args.ctfe_pem.read())])
            signer = SigstoreSigner(
                fulcio=FulcioClient(self.args.fulcio_url),
                rekor=RekorClient(
                    self.args.rekor_url, self.args.rekor_root_pubkey.read(), ct_keyring
                ),
            )

        # The order of precedence is as follows:
        #
        # 1) Explicitly supplied identity token
        # 2) Ambient credential detected in the environment, unless disabled
        # 3) Interactive OAuth flow
        if not self.args.identity_token:
            self.args.identity_token = self.sigstore_get_identity_token()
        if not self.args.identity_token:
            self.logger.error("No identity token supplied or detected!")

        for file, outputs in output_map.items():
            self.logger.debug(f"signing for {file.name}")
            result = signer.sign(
                input_=file.read_bytes(),
                identity_token=self.args.identity_token,
            )

            print("Using ephemeral certificate:")
            print(result.cert_pem)

            print(f"Transparency log entry created at index: {result.log_entry.log_index}")

            sig_output: TextIO
            if outputs["sig"]:
                sig_output = outputs["sig"].open("w")
            else:
                sig_output = sys.stdout

            print(result.b64_signature, file=sig_output)
            if outputs["sig"] is not None:
                print(f"Signature written to {outputs['sig']}")

            if outputs["cert"] is not None:
                with outputs["cert"].open(mode="w") as io:
                    print(result.cert_pem, file=io)
                print(f"Certificate written to {outputs['cert']}")

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

    def sigstore_get_identity_token(self):
        token = None
        if not self.args.oidc_disable_ambient_providers:
            try:
                token = detect_credential()
            except GitHubOidcPermissionCredentialError as exception:
                # Provide some common reasons for why we hit permission errors in
                # GitHub Actions.
                print(
                    dedent(
                        f"""
                        Insufficient permissions for GitHub Actions workflow.
                        The most common reason for this is incorrect
                        configuration of the top-level `permissions` setting of the
                        workflow YAML file. It should be configured like so:
                            permissions:
                            id-token: write
                        Relevant documentation here:
                            https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings
                        Another possible reason is that the workflow run has been
                        triggered by a PR from a forked repository. PRs from forked
                        repositories typically cannot be granted write access.
                        Relevant documentation here:
                            https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token
                        Additional context:
                        {exception}
                        """
                    ),
                    file=sys.stderr,
                )
                sys.exit(1)

        if not token:
            issuer = Issuer(self.args.oidc_issuer)

            if self.args.oidc_client_secret is None:
                self.args.oidc_client_secret = ""  # nosec: B105

            token = get_identity_token(
                self.args.oidc_client_id,
                self.args.oidc_client_secret,
                issuer,
            )
        return token
                
def main(args):
    cli = AnsibleSignCLI(args)
    cli.logger.debug("Running requested command/passing to function")
    exitcode = cli.run_command()
    # TODO: change return code logic
    # cli.logger.info("Script ends here, rc=%d", exitcode)
    return exitcode


def run():
    """Calls :func:`main` passing the CLI arguments extracted from :obj:`sys.argv`

    This function can be used as entry point to create console scripts with setuptools.
    """
    return main(sys.argv[1:])


if __name__ == "__main__":
    run()
