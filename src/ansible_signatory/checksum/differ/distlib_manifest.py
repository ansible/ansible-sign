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

        with open(os.path.join(self.root, "MANIFEST.in"), "r") as f:
            manifest_in = f.read()

        manifest = Manifest(self.root)
        lines = manifest_in.splitlines()

        if verifying:
            lines = ["include **"] + lines

        for line in lines:
            manifest.process_directive(line)

        for path in manifest.files:
            files_set.add(os.path.relpath(path, start=self.root))

        return files_set
