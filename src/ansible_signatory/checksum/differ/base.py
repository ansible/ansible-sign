import os


class ChecksumFileExistenceDiffer:
    """
    When checking checksum files, it can be important to ensure not only that
    the files listed have correct hashes, but that no files were added that
    are not listed.

    This is particularly important in situations where files might get
    "wildcard-included" -- whereby an extra file slipping in could present a
    security risk.

    This class, and subclasses of it, provide an implementation that
    ChecksumFileValidator instances can use to list all "interesting" files that
    should be listed in the checksum file.
    """

    ignored_files = set(
        [
            "sha256sum.txt",
            "sha256sum.txt.sig",
        ]
    )

    def __init__(self, root):
        self.root = root
        self.files = self.gather_files()

    def gather_files(self):
        return set()

    def list_files(self):
        """
        Return a (sorted, normalized) list of files.
        """
        files = set(os.path.normpath(f) for f in self.files) - self.ignored_files
        return sorted(files)

    def compare_filelist(self, checksum_paths):
        """
        Given a set of paths (from a checksum file), see if files have since
        been added or removed from the root directory and any deeper
        directories.

        The given set of paths is used as the source of truth and additions
        and deletions are list with respect to it.
        """

        real_paths = set(self.list_files())
        out = {}
        out["added"] = sorted(real_paths - checksum_paths)
        out["removed"] = sorted(checksum_paths - real_paths)
        return out
