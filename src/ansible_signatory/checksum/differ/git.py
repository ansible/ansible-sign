import git

from .base import ChecksumFileExistenceDiffer


class GitChecksumFileExistenceDiffer(ChecksumFileExistenceDiffer):
    """
    Use gitpython to get walk the file tree of a git repository at HEAD of the
    branch that is currently checked out.
    """

    def gather_files(self):
        repo = git.Repo(self.root)
        files = set()
        stack = [repo.head.commit.tree]
        while stack:
            tree = stack.pop()
            for blob in tree.blobs:
                files.add(blob.path)
            for inner in tree.trees:
                stack.append(inner)
        return set(files)
