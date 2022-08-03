from distlib.manifest import Manifest
import os

from .base import ChecksumFileExistenceDiffer


class DistlibManifestChecksumFileExistenceDiffer(ChecksumFileExistenceDiffer):
    """
    Read in a MANIFEST.in file and process it. Use the results for comparing
    what is listed in the checksum file with what is "reality".
    """

    def gather_files(self):
        files_set = set()

        with open(os.path.join(self.root, "MANIFEST.in"), "r") as f:
            manifest_in = f.read()

        manifest = Manifest(self.root)

        for line in manifest_in.splitlines():
            manifest.process_directive(line)

        for path in manifest.files:
            files_set.add(os.path.relpath(path, start=self.root))

        return files_set
