# `ansible-sign`

This is a library and auxillary CLI tool for dealing with Ansible content
verification.

It does the following:

- checksum manifest generation and validation (sha256sum)
- GPG detached signature generation and validation (using python-gnupg) for
  content
