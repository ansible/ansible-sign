=======================================
Rundown of ``ansible-sign`` (CLI) usage
=======================================

For Ansible Automation Platform content developers (project maintainers), the
primary and supported way of using **ansible-sign** is through the command-line
interface that comes with it.

The command-line interface aims to make it easy to use cryptographic technology
like GPG to validate that specified files within a project have not been
tampered with in any way.

Though in the future other means of signing and validating might be supported,
GPG is the only currently supported means of signing and validation. As such, the
rest of this tutorial assumes the use of GPG.

The process of creating a GPG public/private keypair for signing content is well
documented online, such as in this `Red Hat "Enable Sysadmin" blog post`_. As
such, we will assume that you have a valid GPG keypair already available and in
your default GnuPG keyring.

You can verify that you have a keypair with the following command:

.. code-block:: shell
   :caption: Verifying that a valid secret GPG key exists for signing content

   $ gpg --list-secret-keys

If the above command produces no output, or one line of output that says that a
"trustdb" was created, then you do not have a secret key in your default
keyring. In this case, refer to the aforementioned blog post to learn how to create a new keypair.

If it produces output other than that, then you have a valid secret key
and are ready to move on to
:ref:`using ansible-sign<ansible-sign-install>`.

Adding a GPG key to AWX or Ansible Automation Controller
========================================================

In the command line, run the following commands:

.. code-block:: shell

    $ gpg --list-keys
    $ gpg --export --armour <key fingerprint> > my_public_key.asc

#. In AWX/Automation Controller, click “Credentials" then the "Add" button
#. Give the new credential a meaningful name (for example, "infrastructure team public GPG key")
#. For "Credential Type" select "GPG Public Key"
#. Click "Browse" to navigate to and select the file that you created earlier (``my_public_key.asc``)
#. Finally, click the "Save" button to finish

This credential can now be selected in "Project" settings. Once selected, content verification will automatically take place on future project syncs.

Vist `the GnuPG documentation`_ for more information regarding GPG keys.
For more information regarding generating a GPG keypair, visit the `Red Hat "Enable Sysadmin" blog post`_.

.. _the GnuPG documentation: https://www.gnupg.org/documentation/index.html
.. _Red Hat "Enable Sysadmin" blog post: https://www.redhat.com/sysadmin/creating-gpg-keypairs

.. _ansible-sign-install:

How to Access the ``ansible-sign`` CLI Utility
==============================================

Run the following command to install ``ansible-sign``:

.. code-block:: shell
   :caption: Installing ``ansible-sign``

   $ pip install ansible-sign

.. note::

   An **alternative** approach to install ``ansible-sign`` is using the ``ansible-dev-tools`` package.
   `Ansible Development Tools (ADT) <https://ansible.readthedocs.io/projects/dev-tools/>`_ is a single Python package that includes all necessary tools to
   set up a development environment, generate new collections, build and test the content consistently, resulting in robust automation.

   .. code-block:: shell

      # This also installs ansible-core if it is not already installed
      $ pip3 install ansible-dev-tools

Once it’s installed, run:

.. code-block:: shell
   :caption: Verify that ``ansible-sign`` was successfully installed.

   $ ansible-sign --version

You should see output similar to the following (possibly with a different version number):

.. code-block:: shell
   :caption: The output of ``ansible-sign --version``

   ansible-sign 0.1

Congratulations! You have successfully installed ``ansible-sign``!


The Project Directory
=====================

We will start with a simple Ansible project directory. The `Ansible
documentation`_ goes into more sophisticated examples of project directory
structures.

In our sample project, we have a very simple structure. An ``inventory`` file,
and two small playbooks under a ``playbooks`` directory.

.. code-block:: shell
   :caption: Our sample project

   $ cd sample-project/
   $ tree -a .
   .
   ├── inventory
   └── playbooks
       ├── get_uptime.yml
       └── hello.yml

   1 directory, 3 files

.. note::

   Future commands that we run will assume that your Working Directory is the
   root of your project. ``ansible-sign project`` commands, as a rule, always
   take the project root directory as their last argument, thus we will simply
   use ``.`` to indicate the current Working Directory.

Signing Content
===============

The way that ``ansible-sign`` protects content from tampering is by taking
checksums (sha256) of all of the secured files in the project, compiling those
into a checksum manifest file, and then finally signing that manifest file.

Thus, the first step toward signing content is to create a file that tells
``ansible-sign`` which files to protect. This file should be called
``MANIFEST.in`` and live in the project root directory.

Internally, ``ansible-sign`` makes use of the ``distlib.manifest`` module of
Python's distlib_ library, and thus ``MANIFEST.in`` must follow the syntax that
this library specifies. The Python Packaging User Guide has an `explanation of
the MANIFEST.in file directives`_.

For our sample project, we will include two directives. Our ``MANIFEST.in`` will
look like this:

.. code-block::
   :caption: ``MANIFEST.in``

   include inventory
   recursive-include playbooks *.yml

With this file in place, we can generate our checksum manifest file and sign
it. These steps both happen in a single ``ansible-sign`` command.

.. code-block::
   :caption: Generating a checksum manifest file and signing it

   $ ansible-sign project gpg-sign .
   [OK   ] GPG signing successful!
   [NOTE ] Checksum manifest: ./.ansible-sign/sha256sum.txt
   [NOTE ] GPG summary: signature created


Congratulations, you've now signed your first project!

Notice that the ``gpg-sign`` subcommand lives under the ``project``
subcommand. For signing project content, every command will start with
``ansible-sign project``. As noted above, as a rule, every ``ansible-sign
project`` command takes the project root directory as its final argument.

.. hint::

   As mentioned earlier, ``ansible-sign`` by default makes use of your default
   keyring and looks for the first available secret key that it can find, to sign
   your project. You can specify a specific secret key to use with the
   ``--fingerprint`` option, or even a completely independent GPG home directory
   with the ``--gnupg-home`` option.

.. note::

   If you are using a desktop environment, GnuPG will automatically pop up a
   dialog asking for your secret key's passphrase. If this functionality does
   not work, or you are working without a desktop environment (e.g., via SSH),
   you can use the ``-p``/``--prompt-passphrase`` flag after ``gpg-sign`` in the
   above command, which will cause ``ansible-sign`` to prompt for the password
   instead.

If we now look at the structure of the project directory, we'll notice that a
new ``.ansible-sign`` directory has been created. This directory houses the
checksum manifest and a detached GPG signature for it.

.. code-block:: shell
   :caption: Our sample project after signing

   $ tree -a .
   .
   ├── .ansible-sign
   │   ├── sha256sum.txt
   │   └── sha256sum.txt.sig
   ├── inventory
   ├── MANIFEST.in
   └── playbooks
       ├── get_uptime.yml
       └── hello.yml

.. _Ansible documentation: https://docs.ansible.com/ansible/latest/user_guide/sample_setup.html
.. _distlib: https://pypi.org/project/distlib/
.. _explanation of the MANIFEST.in file directives: https://packaging.python.org/en/latest/guides/using-manifest-in/#manifest-in-commands


Verifying Content
=================

If you come in contact with a signed Ansible project and want to verify that it
has not been altered, you can use ``ansible-sign`` to check both that the
signature is valid and that the checksums of the files match what the checksum
manifest says they should be. In particular, the ``ansible-sign project
gpg-verify`` command can be used to automatically verify both of these
conditions.

.. code-block:: shell
   :caption: Verifying our sample project

   $ ansible-sign project gpg-verify .
   [OK   ] GPG signature verification succeeded.
   [OK   ] Checksum validation succeeded.


.. hint::

   Once again, by default ``ansible-sign`` makes use of your default GPG
   keyring to look for a matching public key. You can specify a keyring file
   with the ``--keyring`` option, or a different GPG home with the
   ``--gnugpg-home`` option.

If verification fails for any reason, some information will be printed to help
you debug the cause. More verbosity can be enabled by passing the global
``--debug`` flag, immediately after ``ansible-sign`` in your commands.

Signing and Verifying content with Sigstore
===========================================

``ansible-sign`` now supports signing and verifying projects using `Sigstore <https://www.sigstore.dev/>`_.
Sigstore is a new standard for signing, verifying and protecting software.
It allows developers to sign artifacts using a "keyless" signing flow and to store signing materials in a tamper-resistant transparency log.

-----------------------
How does Sigstore work?
-----------------------

Sigstore signs artifacts by authentifying signers via an OpenID Connect flow, redirecting them to an identity provider such as Google, Microsoft or GitHub.
When a proof of identity is obtained from one of those providers, it is used to generate an ephemeral signing certificate with Sigstore's Certificate Authority `Fulcio <https://docs.sigstore.dev/fulcio/overview/>`_.
The Sigstore client then uses this certificate and an ephemeral key pair to sign the artifact,
and stores the signing materials in the `Rekor <https://docs.sigstore.dev/rekor/overview/>`_
transparency log for everyone to verify the integrity and authenticity of the artifact signature.

The ``ansible-sign`` command line uses the ``sigstore-python`` CLI under the hood, providing similar utilities,
adapted to Ansible project signing.
For further documentation about the different options available, refer to the `sigstore-python documentation <https://sigstore.github.io/sigstore-python/sigstore.html>`_
or to the client `GitHub repository <https://github.com/sigstore/sigstore-python>`_.

General documentation about Sigstore can be found on `docs.sigstore.dev <https://docs.sigstore.dev/>`_.

------------------------------------------------------------------------
Tutorial: signing and verifying content with `ansible-sign` and Sigstore
------------------------------------------------------------------------

The Sigstore signing utility is available under the `ansible-sign project sigstore-sign` subcommands.
For more information about the different command line arguments available, use ansible-sign project sigstore-sign --help`.

By default, ``ansible-sign`` will use the Sigstore public good instances of Fulcio, Rekor and of the OpenID Connect issuer.
If you wish to connect to private instances of Sigstore, specify the corresponding URLs with the ``--rekor-url``, ``--fulcio-url`` and ``--oidc-issuer`` options.

As for the GPG signing workflow, ``ansible-sign`` generates a file containing the checksums of files specified in the project ``MANIFEST.in`` under the ``.ansible-sign/`` directory
and then signs this artifact file. The siging materials generated by Sigstore (bundled in a ``sha256sum.txt.sigstore`` file) are stored under the same directory.
See the :ref:`Signing Content` section of the documentation for more information on how this manifest is generated.

Different options exist to authentify with an OIDC provider:
If no specific command line option is specified, Sigstore will first look for `ambient credentials <https://dlorenc.medium.com/a-bit-of-ambiance-comes-to-sigstore-f80d1d6b1c30>`_
in the environment. This approach is well adapted to automated signing workflows, for example in the context of GitHub Actions.
If no ambient credentials are found, the client will start an interactive browser session where the signer can authentify through
a supported OIDC provider.
It is also possible to directly pass an identity token obtained from an OIDC provider via the ``--identity-token`` command line option.

Here is an example of the command output when using the interactive session method to authentify:

.. code-block:: shell
   :caption: Generating a checksum manifest file and signing it with Sigstore

   $ ansible-sign project sigstore-sign .
   Waiting for browser interaction...
   Using ephemeral certificate:
   -----BEGIN CERTIFICATE-----
   MIICujCCAkGgAwIBAgIUEzqVrbrUo417s+8H0MsRrb9fAqcwCgYIKoZIzj0EAwMw
   NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
   cm1lZGlhdGUwHhcNMjMwMjA5MTAyNDAzWhcNMjMwMjA5MTAzNDAzWjAAMHYwEAYH
   KoZIzj0CAQYFK4EEACIDYgAEBL9AcKhNxgzTRUz2OfhsW+Ipw7841Ct4gCRbpsZe
   ipSIC0WATguVYyIhQR3T/bIZk+KbLeyhVx2oM6cMUcg342Lc/8UIL2rPini46yo2
   A2hsZC2IVqgYPtKOA7u0NueBo4IBQzCCAT8wDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
   JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQkI8srmkuqcWkY/3lC9Z956oLVLDAf
   BgNVHSMEGDAWgBTf0+nPViQRlvmo2OkoVaLGLhhkPzAhBgNVHREBAf8EFzAVgRNt
   Y29zdGFudEByZWRoYXQuY29tMCkGCisGAQQBg78wAQEEG2h0dHBzOi8vYWNjb3Vu
   dHMuZ29vZ2xlLmNvbTCBiQYKKwYBBAHWeQIEAgR7BHkAdwB1AN09MGrGxxEyYxke
   HJlnNwKiSl643jyt/4eKcoAvKe6OAAABhjW0I/QAAAQDAEYwRAIgPkB9qTeaoPwn
   26r0KvDN/wkuHSa6tUYE5RMlmZpOY+kCIHOUROUVEQJxgWUFDWLm6bRmWdXCZ+gD
   aqx+L0IYxCPEMAoGCCqGSM49BAMDA2cAMGQCMF+lOS9FZtYe5RsE08n6YmN4MTvE
   OlUyiCqKyZJV4jjeSn5F+icnWOF3Z7XuOTyulAIwKh2iH6SEvT8LMvpkwag1ydy/
   a9fNmx6YE1hue2QQPSkAvKTUoK2d+/i1RFyjt27G
   -----END CERTIFICATE-----

   Transparency log entry created at index: 12964841
   Sigstore bundle written to /home/sample-project/.ansible-sign/sha256sum.txt.sigstore

The signature materials are now written under the ``.ansible-sign/`` directory of your project and the entry created in the Rekor Transparency log. Congratulations!

Let's now take a look at the different ways to verify a project signed with Sigstore.
``ansible-sign`` will assume that the project signing materials are always located under ``.ansible-sign/``;
this is why the command should specify the path of the project root when verifying a signature.

The Sigstore verify options are available under the ``ansible-sign project sigstore-verify`` subcommand, either using ``ansible-sign project sigstore-verify identity``
for projects signed by authentifying through an OIDC provider
``or ansible-sign project sigstore-verify github`` for projects signed by a GitHub workflow.

Verifying a project signature requires to pass the expected OIDC issuer and signer OIDC signer identity Sigstore expects to find on the signing certificate,
respectively via the ``--cert-oidc-issuer`` and ``--cert-identity`` options.

**Offline verification:** Sigstore supports offline verification of signatures, which means a verification without
connecting to the Rekor instance where the signature entry was previously logged.
This type of verification uses the Sigstore bundle ``sha256sum.txt.sigstore`` file generated while signing the artifact.
and requires the ``--offline`` flag to be passed to the command.
Note: while this type of verification is useful in disconnected environments, it is considered slightly weaker than the usual mode
because it does not compute the `inclusion proof <https://github.com/google/trillian/blob/master/docs/TransparentLogging.md#inclusion-proofs-vs-promises>`_
of the signature entry in the transparency log.

.. code-block:: shell
   :caption: Verifying the project signature with Sigstore

   $ ansible-sign project sigstore-verify identity . --cert-identity youremail@example.com --cert-oidc-issuer https://accounts.google.com
   OK: /home/sample-project/.ansible-sign/sha256sum.txt

The output of the command shows that the checksums file signature was verified successfully.


Notes About Automation
======================

In environments with highly-trusted CI environments, it is possible to automate
the signing process. For example, one might store their GPG private key in a
GitHub Actions secret, and import that into GnuPG in the CI environment. One
could then run through the signing workflow above within the normal CI
workflow/container/environment.

When signing a project using GPG, the environment variable
``ANSIBLE_SIGN_GPG_PASSPHRASE`` can be set to the passphrase of the signing
key. This can be injected (and masked/secured) in a CI pipeline.

``ansible-sign`` will return with a different exit-code depending on the
scenario at hand, both during signing and verification. This can also be useful
in the context of CI and automation, as a CI environment can act differently
based on the failure (for example, sending alerts for some errors but silently
failing for others).

These codes are used fairly consistently within the code, and can be considered
stable:

.. list-table:: Status codes that ``ansible-sign`` can exit with
   :widths: 15 35 50
   :header-rows: 1

   * - Exit code
     - Approximate meaning
     - Example scenarios
   * - 0
     - Success
     - * Signing was successful
       * Verification was successful
   * - 1
     - General failure
     - * The checksum manifest file contained a syntax error during verification
       * The signature file did not exist during verification
       * ``MANIFEST.in`` did not exist during signing
   * - 2
     - Checksum verification failure
     - * The checksum hashes calculated during verification differed from what
         was in the signed checksum manifest. (That is, a project file was
         changed but the signing process was not recompleted.)
   * - 3
     - Signature verification failure
     - * The signer's public key was not in the user's GPG keyring
       * The wrong GnuPG home directory or keyring file was specified
       * The signed checksum manifest file was modified in some way
   * - 4
     - Signing process failure
     - * The signer's private key was not found in the GPG keyring
       * The wrong GnuPG home directory or keyring file was specified
