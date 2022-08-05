import os

from .base import ChecksumFileExistenceDiffer


class DirectoryChecksumFileExistenceDiffer(ChecksumFileExistenceDiffer):
    """
    Given a directory on the filesystem, assume that every file in it,
    except those ignored in 'ignored_files', are part of the checksum manifest.
    """

    def gather_files(self, verifying=False):
        files_set = set()
        for base, dirs, files in os.walk(self.root):
            relative = os.path.relpath(base, self.root)
            for filename in files:
                files_set.add(os.path.join(relative, filename))
        return files_set
