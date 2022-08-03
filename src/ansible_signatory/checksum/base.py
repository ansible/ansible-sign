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

    MODES = ("sha256",)

    def __init__(self, root, differ=None, mode="sha256"):
        self.root = root
        if differ is not None:
            self.differ = differ(root=self.root)
        else:
            self.differ = DirectoryChecksumFileExistenceDiffer(root=self.root)
        if mode not in self.MODES:
            raise Exception(f"mode argument must be one of: {', '.join(self.MODES)}")
        self.mode = mode

    # def _parse_bsd_style(self, line):
    #     """
    #     Attempt to parse a BSD style checksum line, returning False if we
    #     are unable to.
    #
    #     Only supports SHA256 for right now, since the indices will have to
    #     change for other shasum variants.
    #
    #     A BSD style line looks like this:
    #     SHA256 (hello_world.yml) = f712979c4c5dfe739253908d122f5c87faa8b5de6f15ba7a1548ae028ff22d13
    #     """
    #
    #     # Each BSD line is prefixed with 'SHA256 ('. Then, starting from the
    #     # right (and assuming sha256 only, for now) we can count 68
    #     # characters ( sha length and ") = " ) to look for another pattern.
    #     if line.startswith("SHA256 (") and line[-68:-64] == ") = ":
    #         # If both of those criteria match, we are pretty confident this
    #         # is a BSD style line. From the right, split once at the = sign
    #         # and parse out the path, and we are done. If the split
    #         # doesn't work, or the sha isn't length 64, then assume it's
    #         # not a BSD line, after all.
    #         parts = line.rsplit(" = ", 1)
    #         if len(parts) == 2 and len(parts[1]) == 64:
    #             path = parts[0][8:-1]
    #             shasum = parts[1]
    #         return (path, shasum)
    #     return False

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
        calculated = self.calculate_checksums_from_root()
        for path, checksum in sorted(calculated.items()):
            # *two* spaces here - it's important for compat with coreutils.
            lines.append(f"{checksum}  {path}")
        return "\n".join(lines) + "\n"

    def calculate_checksum(self, path):
        fullpath = os.path.join(self.root, path)
        shasum = hashlib.sha256()
        with open(fullpath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                shasum.update(chunk)
        return shasum.hexdigest()

    def calculate_checksums_from_root(self):
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
        for path in self.differ.list_files():
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

        recalculated = self.calculate_checksums_from_root()
        mismatches = set()
        for parsed_path, parsed_checksum in parsed_manifest_dct.items():
            if recalculated[parsed_path] != parsed_checksum:
                mismatches.add(parsed_path)
        if mismatches:
            raise ChecksumMismatch(f"Checksum mismatch: {', '.join(mismatches)}")

        return True
