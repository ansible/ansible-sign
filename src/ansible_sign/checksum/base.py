import hashlib
import os


class InvalidChecksumLine(Exception):
    pass


class NoDifferException(Exception):
    pass


class ChecksumMismatch(Exception):
    pass


class ChecksumFile:
    """
    Slurp a checksum file and be able to check and compare its contents to a
    given root directory. Also: be able to write out a checksum file.

    We only allow sha256 for now, though supporting 512, etc. would be easy.
    """

    def __init__(self, root, differ=None):
        self.root = root
        if differ is not None:
            self.differ = differ(root=self.root)
        else:
            from .differ.distlib_manifest import (
                DistlibManifestChecksumFileExistenceDiffer,
            )

            self.differ = DistlibManifestChecksumFileExistenceDiffer(root=self.root)

    @property
    def differ_warnings(self):
        """
        A differ can store a set of warnings (as strings) in the_differ.warnings
        which we can propagate up here. This allows calling code to display any
        warnings found during diffing time.
        """

        return self.differ.warnings

    @property
    def warnings(self):
        """
        Right now this is just the same as differ_warnings. In the future it
        might include warnings that we differ in methods in this class as well.
        """

        return self.differ_warnings

    def _parse_gnu_style(self, line):
        """
        Attempt to parse a GNU style line checksum line, returning False if
        we are unable to.

        A GNU style line looks like this:
        f712979c4c5dfe739253908d122f5c87faa8b5de6f15ba7a1548ae028ff22d13  hello_world.yml

        Or maybe like this:
        f82da8b4f98a3d3125fbc98408911f65dbc8dc38c0f38e258ebe290a8ad3d3c0 *binary
        """

        parts = line.split(" ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            return False

        if len(parts[1]) < 2 or parts[1][0] not in (" ", "*"):
            return False

        shasum = parts[0]
        path = parts[1][1:]
        return (path, shasum)

    def parse(self, checksum_file_contents):
        """
        Given a complete checksum manifest as a string, parse it and return a
        dict with the result, keyed on each filename or path.
        """
        checksums = {}
        for idx, line in enumerate(checksum_file_contents.splitlines()):
            if not line.strip():
                continue
            # parsed = self._parse_bsd_style(line)
            # if parsed is False:
            parsed = self._parse_gnu_style(line)
            if parsed is False:
                raise InvalidChecksumLine(
                    f"Unparsable checksum, line {idx + 1}: {line}"
                )
            path = parsed[0]
            shasum = parsed[1]
            if path in checksums:
                raise InvalidChecksumLine(
                    f"Duplicate path in checksum, line {idx + 1}: {line}"
                )
            checksums[path] = shasum
        return checksums

    def diff(self, paths):
        """
        Given a collection of paths, use the differ to figure out which files
        (in reality) have been added/removed from the project root (or latest
        SCM tree).
        """

        paths = set(paths)
        return self.differ.compare_filelist(paths)

    def generate_gnu_style(self):
        """
        Using the root directory and 'differ' class given to the constructor,
        generate a GNU-style checksum manifest file. This is always generated
        from scratch by finding the list of relevant files in the root directory
        (by asking the differ), and calculating the checksum for each of them.

        The resulting list is always sorted by filename.
        """
        lines = []
        calculated = self.calculate_checksums_from_root(verifying=False)
        for path, checksum in sorted(calculated.items()):
            # *two* spaces here - it's important for compat with coreutils.
            lines.append(f"{checksum}  {path}")
        return "\n".join(lines) + "\n"

    def calculate_checksum(self, path):
        shasum = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                shasum.update(chunk)
        return shasum.hexdigest()

    def calculate_checksums_from_root(self, verifying):
        """
        Using the root of the project and the differ class passed to the
        constructor, iterate over all files in the project and calculate their
        checksums. Return a dictionary of the result, keyed on the filename.

        Just calling this is not enough in many cases- you want to ensure that
        the files in the checksum list are the same ones present in reality.
        diff() above does just that. Use that in combination with this method,
        or use verify() which does it for you.
        """
        out = {}
        for path in self.differ.list_files(verifying=verifying):
            shasum = self.calculate_checksum(os.path.join(self.root, path))
            out[path] = shasum
        return out

    def verify(self, parsed_manifest_dct, diff=True):
        """
        Takes a parsed manifest file (e.g. using parse(), with paths as keys and
        checksums as values).

        Then calculates the current list of files in the project root. If paths
        have been added or removed, ChecksumMismatch is raised.

        Otherwise, each the checksum of file in the project root (and subdirs)
        is calculated and that result is checked to be equal to the parsed
        checksums passed in.
        """

        if diff:
            # If there are any differences in existing paths, fail the check...
            differences = self.diff(parsed_manifest_dct.keys())
            if differences["added"] or differences["removed"]:
                raise ChecksumMismatch(differences)

        recalculated = self.calculate_checksums_from_root(verifying=True)
        mismatches = set()
        for parsed_path, parsed_checksum in parsed_manifest_dct.items():
            if recalculated[parsed_path] != parsed_checksum:
                mismatches.add(parsed_path)
        if mismatches:
            raise ChecksumMismatch(f"Checksum mismatch: {', '.join(mismatches)}")

        return True
