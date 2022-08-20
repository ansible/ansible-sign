# `ansible-sign`

This is a library and auxillary CLI tool for dealing with Ansible content
verification.

It does the following:

- checksum manifest generation and validation (sha256sum)
- GPG detached signature generation and validation (using python-gnupg) for
  content

Note: The API (library) part of this package is not officially supported and
might change as time goes on. CLI commands should be considered stable within
major verions (the `X` of version `X.Y.Z`).
