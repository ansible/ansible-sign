from distlib.manifest import Manifest
import os

from .base import ChecksumFileExistenceDiffer


class DistlibManifestChecksumFileExistenceDiffer(ChecksumFileExistenceDiffer):
    """
    Read in a MANIFEST.in file and process it. Use the results for comparing
    what is listed in the checksum file with what is "reality".
    """

    always_added_files = set(["MANIFEST.in"])

    def gather_files(self, verifying=False):
        files_set = set()

        manifest_path = os.path.join(self.root, "MANIFEST.in")

        if not os.path.exists(manifest_path):
            # open() would do this, but let us be explicit, the file must exist.
            raise FileNotFoundError(manifest_path)

        with open(manifest_path, "r") as f:
            manifest_in = f.read()

        manifest = Manifest(self.root)
        lines = manifest_in.splitlines()

        if verifying:
            lines = ["global-include *"] + lines

        for line in lines:
            line = line.strip()

            # distlib.manifest bombs on empty lines.
            # It also doesn't appear to allow comments, so let's hack those in.
            if not line or line[0] == "#":
                continue

            try:
                manifest.process_directive(line)
            except FileNotFoundError as e:
                if os.path.islink(e.filename):
                    self.warnings.add(f"Found (and ignored) broken symlink: {e.filename}")
                else:
                    # If we didn't get here due to broken symlink, then there's
                    # something else weird going on. Re-raise the exception and
                    # bail.
                    raise e

        for path in manifest.files:
            files_set.add(os.path.relpath(path, start=self.root))

        return files_set
