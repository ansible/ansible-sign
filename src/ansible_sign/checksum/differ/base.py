import os
from pathlib import PurePath


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

    # These are tuples of path elements, compared to the path's parts (as
    # presented by pathlib).
    ignored_paths = set([
        ".ansible-sign",
        ".ansible-sign/**",
    ])

    # Files that get added to the manifest in list_files() even if not
    # explicitly found by gather_files()
    always_added_files = set()

    # When gathering files, any warnings we encounter can be propagated up.
    # This is a place to store them.
    warnings = set()

    def __init__(self, root):
        self.root = root

    def gather_files(self, verifying=False):
        return set()

    def list_files(self, verifying):
        """
        Return a (sorted, normalized) list of files.

        Individual differs can implement logic based on whether we are
        using this to generate a manifest or to verify one, and 'verifying'
        is what is used to toggle this logic.
        """
        gathered = self.gather_files(verifying=verifying)
        files = set(os.path.normpath(f) for f in gathered)

        for path in files.copy():
            for ignored_path in self.ignored_paths:
                if PurePath(path).match(ignored_path):
                    files.remove(path)

        for path in self.always_added_files:
            if not os.path.exists(os.path.join(self.root, path)):
                raise FileNotFoundError(path)
            files.add(path)

        return sorted(files)

    def compare_filelist(self, checksum_paths):
        """
        Given a set of paths (from a checksum file), see if files have since
        been added or removed from the root directory and any deeper
        directories.

        The given set of paths is used as the source of truth and additions
        and deletions are list with respect to it.
        """

        real_paths = set(self.list_files(verifying=True))
        out = {}
        out["added"] = sorted(real_paths - checksum_paths)
        out["removed"] = sorted(checksum_paths - real_paths)
        return out
