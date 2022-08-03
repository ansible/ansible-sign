# `ansible-signatory`

This is a library and auxillary CLI tool for dealing with Ansible content
verification.

It does the following:

- checksum manifest generation and validation (sha256sum)
- GPG detached signature generation and validation (using python-gnupg) for
  content

Checksum manifest validation includes (optionally and by default) checking the
source directory to ensure that no files have been added or removed. This is
particularly important, since Ansible playbooks might wildcard-include files.

Of course, this "diff" check varies by project and the SCM being used. We
include "differs" for several of the more common SCMs, including all those
that can be used natively with AWX.
