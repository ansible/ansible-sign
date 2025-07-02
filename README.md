# `ansible-sign`

This is a library and auxiliary CLI tool for dealing with Ansible content
verification.

It does the following:

- checksum manifest generation and validation (sha256sum)
- GPG detached signature generation and validation (using python-gnupg) for
  content

Note: The API (library) part of this package is not officially supported and
might change as time goes on. CLI commands should be considered stable within
major versions (the `X` of version `X.Y.Z`).

Documentation can be found on [ansible-sign.readthedocs.io](https://ansible.readthedocs.io/projects/sign/en/latest/)
including a
[rundown/tutorial](https://ansible.readthedocs.io/projects/sign/en/latest/rundown.html)
explaining how to use the CLI for basic project signing and verification.

## Community

Need help or want to discuss the project? See our [Community guide](https://ansible.readthedocs.io/projects/sign/en/latest/community.html) join the conversation.
