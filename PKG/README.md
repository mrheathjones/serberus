# Building installer packages

Each script here builds one macOS installer package (`.pkg`). Pick by what you
are deploying and where.

| Script | What it installs | For |
|---|---|---|
| `build-pkg.sh` → `PKG/build/Serberus-<version>-signed.pkg` (the unsigned intermediate is `Serberus-<version>.pkg`) | The daemon (as `serberusd.app`, carrying the Endpoint Security provisioning profile when the build has one), the PAM module, the SerberusAuth authorization plugin, the `serberus` CLI, and `uninstall.sh` with `pam-lib.sh` in `/Library/Application Support/Serberus/`. Developer ID signed and notarized. | Production endpoints |
| `build-combined-pkg.sh` → `SerberusTest-<version>.pkg` | Everything for a test Mac in one package: the core package plus the Sentinel app package below, core first. | Test Macs |
| `build-core-test-pkg.sh` → `SerberusCore-<version>.pkg` | The core: the daemon (flat binary), the PAM module, the SerberusAuth authorization plugin, and the `serberus` CLI. No Sentinel apps. | Test Macs |
| `build-sentinel-app-pkg.sh` → `SerberusSentinelApp-<version>.pkg` | The Sentinel apps: Serberus Sentinel (with its Finder extension), the menu-bar agent, Guardian, and their LaunchAgents. | Test Macs, or production endpoints when built as described in [Production Sentinel package](#production-sentinel-package) |
| `build-commander-pkg.sh` → `SerberusCommander-<version>.pkg` | Serberus Commander, the admin app. | Admin Macs |
| `build-test-pkg.sh` → `Serberus-daemon-test-<version>.pkg` | The daemon only. | Testing |
| `build-pam-test-pkg.sh` → `Serberus-pam-test-<version>.pkg` | The PAM module only. Refuses to install unless a break-glass config is in place and the daemon is installed and loaded. | Testing |
| `build-uninstall-pkg.sh` → `SerberusUninstall-<version>.pkg` | No payload. Removes every Serberus endpoint component in a safe order and restores the AuthorizationDB. Never touches Commander or its policy library. | Any Mac |
| `build-authuribrowser-pkg.sh` → `AuthURIBrowser-<version>.pkg` | Auth URI Browser (from `extras/`), a read-only tool for exploring authorization rights. | Anywhere |

## Signing

Every script except the uninstaller and Auth URI Browser needs a signing
identity from your Apple Developer team, passed in the environment. Run the
scripts as your normal user, not with `sudo`: `codesign` needs your login
keychain.

The test packages are signed with an **Apple Development** identity. A Developer
ID signature with the hardened runtime is killed at launch unless the build is
notarized, so keep Developer ID for the production package. Use one identity
for everything: the test packages refuse a daemon with no Team ID, and they
pin the PAM module and the SerberusAuth plugin to the daemon's team. There is
no ad-hoc fallback.

```bash
SIGNING_IDENTITY="Apple Development: Your Name (CERTID)" ./PKG/build-combined-pkg.sh
```

`INSTALLER_IDENTITY` (a "Developer ID Installer" identity) signs the package
itself, and `NOTARY_PROFILE` notarizes it, where the script supports that. The
Commander, Sentinel app, and Auth URI Browser scripts also check the signed app
against your team, which they read from `DEVELOPMENT_TEAM` in
`Config/Local.xcconfig` or the environment.

`build-pkg.sh` also needs `DEVELOPMENT_TEAM` (in `Config/Local.xcconfig` or the
environment). The Endpoint Security exec gate is optional, set with `ESF`:

- `ESF=on`, or `PROVISION_PROFILE` given: the daemon carries the Endpoint
  Security entitlement, which needs `PROVISION_PROFILE`, a Developer ID
  provisioning profile for the daemon's App ID that includes it. Apple grants
  that entitlement only on request; see
  [docs/esf-provisioning-and-notarization.md](../docs/esf-provisioning-and-notarization.md).
  `ESF=on` without a readable profile stops the build.
- `ESF=off`, or no `PROVISION_PROFILE`: the daemon is signed with no
  entitlements and no profile, and the exec gate is off. Curated `sudo`,
  AuthorizationDB rules and JIT admin work as usual.

The package records which one it is as `execGate` (`enabled` or `disabled`)
in `version.plist`. The running daemon records its exec gate state in
`state.plist` (`execGate`), and `serberus status` shows it, for example
`Exec gate        off (no Endpoint Security entitlement)`.

The package scripts read the product version from the repository's `VERSION`
file. The production package is named after it; the test packages keep their
own package numbers (`PKG_VERSION`, and `COMBINED_VERSION` for the combined
package) for their receipts, and the core test package records the product
version in `version.plist`.

### Production Sentinel package

The production package installs no Sentinel apps, and a production daemon
accepts the menu-bar agent only when it carries Serberus's private
`com.herojoneslabs.serberus.is-ui-sentinel` entitlement. Without the agent,
prompt rules are denied, and JIT requests and Install/Uninstall with Serberus
don't work. Build the Sentinel app package for production like this:

```bash
SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
SENTINEL_WITH_ENTITLEMENT=1 \
INSTALLER_IDENTITY="Developer ID Installer: Your Name (TEAMID)" \
  ./PKG/build-sentinel-app-pkg.sh
```

With `SENTINEL_WITH_ENTITLEMENT=1` the script signs the menu-bar agent with
`Support/SerberusSentinel.entitlements`, which carries that entitlement. The
Sentinel app, its Finder extension and Guardian are signed without it; they
don't need it. Every bundle is signed with Hardened Runtime and a secure
timestamp, and checked for your `DEVELOPMENT_TEAM`. Use a Developer ID
Application identity. The script doesn't check the identity type, but an
Apple Development-signed agent can't carry the entitlement (which is why the
test packages relax the daemon's check instead). The script doesn't
notarize. Submit the signed
package (`build-test/sentinel-app/SerberusSentinelApp-<version>-signed.pkg`)
with `xcrun notarytool submit --wait` and staple it, as `build-pkg.sh` does
for the production package. The package keeps the test ring's receipt
identifier (`com.herojoneslabs.serberus.sentinelapptestpkg`) and output
folder.

## Test packages are not for production

The test packages turn on development shortcuts in the daemon's LaunchDaemon
configuration: file-based signing keys when the System Keychain can't be used
(both the core and the daemon-only package) and, in the core package, a relaxed
check on the Sentinel's private entitlement (Apple Development signatures
can't carry it without a provisioning profile). Use them on test Macs only.

## Install order and removal

Deliver a configuration profile with a working `pamBypass` (see
[SECURITY.md](../SECURITY.md#deploying-safely)) **before** any package that
includes the PAM module, then install the daemon before, or with, the PAM
module. The combined package does this in the right order.

- **Every installer wires `sudo_local` last**, and only after the daemon is
  up: the same process for longer than launchd's 5-second restart throttle,
  with no restart recorded, and, where the package passes them, a
  `state.plist` written since the daemon started and a healthy
  `serberus status` from a CLI signed by the daemon's team. The PAM-only
  package passes no `state.plist`. The scripts that wire `sudo_local` have
  an `EXIT` trap, so an unexpected exit takes the same abort path as a
  failed step.
- **The production postinstall stops early with the real reason** when
  `/usr/local/bin`, `/usr/local` or `/usr` isn't root-only (the CLI goes
  there), and refuses to wire `sudo_local` while an MDM-managed PAM
  configuration or a `pam.conf` exists (under
  `/private/var/db/ManagedConfigurationFiles/com.apple.pam/`, `/etc/pam.conf`,
  or `/usr/local/etc/`): OpenPAM would read sudo's policy from there, and
  `pam_serberus` would never run.
- **Upgrades tear down first.** Before the new files land, the preinstall
  writes the upgrade marker (`/Library/Application Support/Serberus/.upgrade-in-progress`),
  removes the sudoers drop-in, unwires `sudo_local`, boots the daemon out and
  waits until launchd no longer lists it (up to 25 seconds: its 20-second
  exit timeout plus 5; launchd's own default is 5), checks the drop-in
  again, runs the old daemon's `--demote-jit` so JIT admin sessions end, and
  checks the drop-in once more. The new daemon ends any JIT session still
  live when it starts after an upgrade, and deletes the marker. If the drop-in is still
  there after its first removal, the upgrade stops before `sudo_local` is
  unwired. If the daemon is still loaded after the wait, `--demote-jit` isn't
  run and the manual steps are logged. If the upgrade fails later, the Mac is
  left with native `sudo`, not blanket denial.
- **A daemon binary runs as root only if it passes a strict check.** Before
  any script runs `--demote-jit` or `--restore-authdb`, the binary must have
  a strictly valid Apple-issued signature with the identifier
  `com.herojoneslabs.serberus.daemon` and the team recorded at install time
  (`installTeamID` in `/Library/Application Support/Serberus/version.plist`;
  without that record, the installed PAM module's team). With neither, or
  when the check fails, the script prints the manual steps instead of
  running it. The one exception is the production postinstall's abort path,
  which checks the daemon it has just installed against that daemon's own
  team. `uninstall.sh` never runs `--restore-authdb` while the daemon is
  still loaded.
  `--demote-jit` exit 3 (no grant store, nothing to demote) is logged as
  information; exit 1 means JIT admins may remain, and is loud but doesn't
  stop the script.
- **A stray `pam_serberus.so.2` is removed.** OpenPAM loads
  `/usr/local/lib/pam/pam_serberus.so.2` in preference to the module, so the
  installers and uninstallers delete one if they find it.
- **A production install over a test ring** removes the flat test daemon,
  the test uninstall helpers and their receipts.
- **The production preinstall runs the break-glass preflight** before it
  changes anything. Unless the config is in `monitor` or `audit`, at least one
  `pamBypass` entry must exist on the Mac (a user under exactly that name, or
  a group with at least one member); a missing config counts as `enforce`. If
  the check fails, nothing is installed.
- **The core test package** aborts only when a delivered `enforce` config has
  a `pamBypass` in which no entry exists on the Mac, whether or not a
  last-known-good snapshot exists. With no config yet, it installs and the
  daemon waits for one.
- **The PAM-only test package** needs a break-glass config and an installed,
  loaded daemon; its preinstall checks both.
- **The daemon-only test package**, on an upgrade, puts back the `sudo_local`
  line its preinstall removed, once the new daemon is up and the installed
  module passes its checks.
- **The Sentinel app package** starts and stops its LaunchAgents in every
  logged-in user session, not only the one at the console.

The production postinstall also warns if Apple's `/etc/pam.d/sudo` doesn't
include `sudo_local` as its first `auth` line. It never edits that file.

Installer output is in `/var/log/install.log`. The Serberus scripts also send
their messages to the system log, tagged `com.herojoneslabs.serberus.preinstall`,
`com.herojoneslabs.serberus.postinstall` and the like.

To remove Serberus, install the package from `build-uninstall-pkg.sh`. It
removes every endpoint component, the support folder, the logs, the keychain
items and the Sentinel's per-user files, and never Commander, its receipt or
its policy library. On a Mac with the production package you can also run
`sudo "/Library/Application Support/Serberus/uninstall.sh"`, which that
package installs. Without `--purge` it keeps the data in the support folder
(state, grants, the last-known-good config, `version.plist`), the logs and
the keychain keys, so a reinstall picks up where it left off; `--purge`
deletes that data, and never the apps, the uninstall helpers or the install
markers. The test packages install their own uninstall scripts in the same
folder. The uninstall package, `uninstall.sh` and the core and daemon-only
test helpers work in this order: remove the sudoers drop-in, unwire
`sudo_local`, disable the daemon, boot it out and wait until it's gone, check
the drop-in again, demote any JIT admins, check the drop-in once more, then
restore the AuthorizationDB. The PAM-only and Sentinel app helpers remove
only what their packages installed; the Sentinel app helper's `--purge`
deletes the Sentinel's per-user files and never Commander's library beside
them. The authorization plugin is removed only
when the restore succeeded, `authdb-backups` holds no pending record (a
`.json`, `.branches` or `.projection` file; a `.standin` record never
blocks), and no Serberus composition row invokes SerberusAuth and no right
delegates to one. A comment in a right never counts, since anyone who can
create a right can write any comment. `verify-uninstall.sh` checks that a Mac
is clean afterwards (`--ea` prints the result as a Jamf extension attribute).

`tools/demote-console-user-from-admin.sh` is a Jamf script for moving the
console user from administrator to standard user before rollout. Parameter 4
is the organisation name shown in its messages (default "your IT team"). It
leaves system accounts alone (a name starting with `_`, such as Setup
Assistant's `_mbsetupuser`, or a uid below 500). It refuses unless another
usable admin account remains: one that exists, is enabled, can sign in, holds
a SecureToken and is a volume owner of the boot volume. An admin who is one
only through an active Serberus JIT grant (matched by name or uid) doesn't
count, because the grant takes the membership with it when it ends; if the
grant store exists but can't be read, the script demotes no one. With the
`jamf_connect` JIT provider, an admin with a Jamf Connect elevation in the
last 8 hours and no later removal in the unified log doesn't count either,
and if that log can't be read, no one is demoted. It has no override.

## Tests

`tests/test-pam-lib.sh` and `tests/test-sentinel-lib.sh` exercise the shell
logic that edits `/etc/pam.d/sudo_local` and `/etc/sudoers.d`, and check the
install and uninstall scripts every builder generates, using temporary files
only. Run them
with `bash`. CI runs both, plus `bash -n` on every shell script.
