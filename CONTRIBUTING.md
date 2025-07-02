# Contributing

Hello! Want to contribute to `ansible-sign`? Good news - you're in the right place.

## Things to know prior to submitting code

- All code and doc submissions are done through pull requests against the `main` branch.
- Take care to make sure no merge commits are in the submission, and use `git rebase` vs `git merge` for this reason.
- We ask all of our community members and contributors to adhere to the [Ansible code of conduct]. If you have questions, or need assistance, please reach out to our community team at [codeofconduct@ansible.com].

## Setting up your development environment

In this example we are using [virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/en/latest/), but any virtual environment will do.

```bash
$ pip install virtualenvwrapper # Follow installation instructions at https://virtualenvwrapper.readthedocs.io/en/latest/
$ mkvirtualenv ansible-sign
$ pip install -e .
```

When done making changes, run:

```
$ deactivate
```

To reactivate the virtual environment:

```
$ workon ansible-sign
```

## Linting and Unit Tests

`tox` is used to run linters and tests.

```
$ pip install tox
$ tox
```

[Ansible code of conduct]: http://docs.ansible.com/ansible/latest/community/code_of_conduct.html
[codeofconduct@ansible.com]: mailto:codeofconduct@ansible.com
