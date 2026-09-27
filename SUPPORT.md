# Getting help

Serberus is alpha software maintained by one person in their own time. There
is no support agreement and no guaranteed response time. Questions are
welcome, and answered as time allows.

## Where to ask

- **Questions, problems and ideas:** open an issue on this repository's
  **Issues** tab on GitHub. Use the question template to ask how Serberus
  works or how to deploy or configure it, the bug report template for
  something that doesn't work, and the feature request template for
  something you'd like it to do. There is no discussion forum.
- **Security vulnerabilities:** don't open an issue. Report them privately as
  described in [SECURITY.md](SECURITY.md).

## Before you ask

- Read the [README](README.md), [SECURITY.md](SECURITY.md) and the
  [docs index](docs/README.md). Most "how do I" answers are in
  [docs/SERBERUS-OVERVIEW.md](docs/SERBERUS-OVERVIEW.md) or
  [PKG/README.md](PKG/README.md).
- Include the Serberus version or commit, the macOS version, the enforcement
  mode, and what `serberus status` reports. For an install or uninstall
  problem, include the package's lines from the installer log,
  `/var/log/install.log`. The Serberus scripts also send their messages to
  the system log under tags such as `com.herojoneslabs.serberus.postinstall`.
  Remove credentials, account names and other
  identifying details from anything you paste.

## If you're locked out of `sudo`

Follow the recovery steps in the README's lockout note and in
[SECURITY.md](SECURITY.md#deploying-safely): sign in as a `pamBypass`
account, or install the uninstall package. The kill switch
(`daemonEnabled = false`) frees `sudo` only while the daemon is running.
Don't wait for an answer on an issue first.
