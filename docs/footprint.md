# What Serberus changes on a Mac

Everything a Serberus install puts on a Mac or changes there, what talks to
the network, and how to check the installed binaries. Paths are those of the
production package unless a line says otherwise. What each uninstaller
removes is under [Removing it](#removing-it); `PKG/verify-uninstall.sh`
checks that a Mac is clean afterwards.

## Files and folders

| Path | What it is |
|---|---|
| `/Library/PrivilegedHelperTools/serberusd.app` | The daemon, as a bundle carrying the Endpoint Security provisioning profile. The test packages install a flat binary at `/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon` instead. |
| `/usr/local/lib/pam/pam_serberus.so` | The PAM module (`root:wheel`, `0444`; folder `0755`). |
| `/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle` | The authorization plugin. Installed but inert in 0.9.0: per-app rules are disabled, so no right Serberus writes invokes it and it denies every request. |
| `/usr/local/bin/serberus` | The command-line tool. |
| `/Library/Application Support/Serberus/` | The daemon's support folder: `state.plist` (including `execGate`, whether the Endpoint Security exec gate runs), `version.plist` (component versions, `execGate`, and `installTeamID`, the team the install validated), `grants.sqlite` (root only on disk; the Intel tab's diagnostics collection hands the requesting user a copy), `last-known-good-config.plist`, `clock-high-water.plist` (the latest wall-clock time the daemon has seen, root only), `last-daemon-build.plist` (which daemon build ran last, root only), `authdb-backups/`, `install-staging/` (root only), `fleet-summary.plist`, `recent-events.json` (root only), `fleet-events.json` (root only, and only while debug telemetry is on), `appmanagement-state.plist`, `.install-markers/`, and `pam-lib.sh` with the package's uninstall script. During an upgrade the preinstall adds `.upgrade-in-progress` (root only), which the new daemon deletes when it starts. On a test Mac whose System keychain can't be used, the test packages' daemon keeps its signing keys here instead, as `.log-hmac-key.key` and `.grants-hmac-key.key` (owner only). |
| `/Library/Application Support/Serberus/Serberus Sentinel Agent.app`, `Serberus Guardian.app` | The menu-bar agent and its watchdog (Sentinel app package). The agent also adds **Install with Serberus** and **Uninstall with Serberus** to the Services menu. |
| `/Applications/Serberus Sentinel.app` | The user app, with the Finder extension inside it (Sentinel app package). |
| `/Library/Logs/Serberus/` | The signed decision log (`decisions-YYYY-MM-DD.jsonl`), the integrity log (`integrity-YYYY-MM-DD.jsonl`), each with a `.jsonl.hmac` signature file, `daemon.stdout.log`, `daemon.stderr.log`, and `captures/` for the Intel tab's log captures. The two logs are `0644`, readable by every local user. A macOS update can recreate the folder with other permissions and without the earlier logs (see [SECURITY.md](../SECURITY.md#known-limitations)). |
| `~/Library/Application Support/Serberus/` | Per user, from the Sentinel: `jamf-uploads.json` (files uploaded to Jamf), `rules-cache.json` (the last rules the agent showed), `elevation-history.json` (the user's own elevation history), and `pending-route` (which screen the app should open). |
| `~/Library/Application Support/Serberus/` on an admin Mac | From Commander: `policies.json` (the policy library) and `capture-reviews.json`. |

## launchd jobs

| Plist | Runs |
|---|---|
| `/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist` | The daemon, as root, `KeepAlive` with a 5-second restart throttle. |
| `/Library/LaunchAgents/com.herojoneslabs.serberus.sentinel.plist` | The Sentinel menu-bar agent, in each user's session. |
| `/Library/LaunchAgents/com.herojoneslabs.serberus.guardian.plist` | Guardian, which offers to relaunch the agent if a user quits it (it does nothing unless `guardianEnabled` is on). |
| `/Library/LaunchAgents/com.herojoneslabs.serberus.finderext-elect.plist` | A run-once-at-login job that enables the Finder extension for each user with `pluginkit`. |

The three LaunchAgents come with the Sentinel app package.

## `sudo`

- **`/etc/pam.d/sudo_local`** gets one line, above any other `auth` line:

  ```
  auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
  ```

  The installer creates the file from `Support/sudo_local` if there isn't one,
  or adds the line to an existing one. Apple's `/etc/pam.d/sudo` is never
  edited; it already includes `sudo_local`.
- **`/etc/sudoers.d/serberus`** (`root:wheel`, `0440`) is written by the
  daemon, in `enforce` mode only and only while the PAM gate verifies. It lists
  the commands enrolled users may reach through `sudo`, never with
  `NOPASSWD`, and sets `timestamp_timeout=0` for them. Its first line marks it
  as Serberus's. See [sudoers-provisioning.md](sudoers-provisioning.md).
- **sudo's timestamps** in `/var/db/sudo/ts/` are deleted, never created or
  edited. macOS's sudo names each file after the user's uid (`ts/501`); older
  sudo used the name, and Serberus deletes both. `pam_serberus` deletes the
  invoking user's after a request it evaluated. The daemon deletes a user's
  when their JIT admin elevation ends, and every user's whenever `sudo` gating
  begins (entering `enforce`, or starting in it). See
  [SerberusPAM.md](SerberusPAM.md#authentication-flow).

## AuthorizationDB

| Mode | What changes |
|---|---|
| `monitor`, `audit`, awaiting config, kill switch | Nothing. Rights Serberus changed earlier are restored. |
| `enforce` | Only the rights your rules name. An `allow` rewrites the right to "the logged-in user or an admin, with their own password" (only when the right is natively a plain admin gate). A `deny` sets it to `class=deny`. An identity-scoped rule changes nothing in 0.9.0: the rule is logged as skipped, and extra rows named `com.herojoneslabs.serberus.branch.*` that an older build wrote are removed on the next reconcile. A right macOS doesn't define is created, and removed again on restore. |

Every row Serberus writes carries the comment `Managed by serberusd; do not
edit.`, except the admin-gate stand-in a restore may leave when no original
could be recovered, which Serberus tracks with a `.standin` record instead.
The original definition of each right it changes is kept in
`/Library/Application Support/Serberus/authdb-backups/`. The comment is only
a hint: anyone who can create a right can copy it, so the uninstallers go by
Serberus's records and a live check for rows that invoke SerberusAuth. Login, screensaver,
FileVault unlock, Platform SSO and the AuthorizationDB's own rules are never
changed. See [SECURITY.md](../SECURITY.md#authorization-rights).

## Keychain

The daemon keeps two HMAC keys in the **System** keychain, as generic
passwords with the service `com.herojoneslabs.serberus.daemon`: account
`log-hmac-key` (signs the decision log) and account `grants-hmac-key` (signs
each row of `grants.sqlite`). The test packages' daemon falls back to
owner-only key files in the support folder when the System keychain can't be
used. On an admin Mac, Commander keeps its Jamf API client secret in the user's
keychain under the service `com.herojoneslabs.serberus.commander.mdm`.

## Group membership

Just-in-time admin with the `serberus` provider adds the user to the local
`admin` group for the length of the grant, and removes them when it ends,
when the provider stops being `serberus`, when the kill switch is turned on,
after an upgrade, and on uninstall.
Serberus never removes an admin it didn't add. When a JIT account has been
deleted, the daemon also removes its leftover name from `admin`'s
`GroupMembership` and its GeneratedUID from `GroupMembers`, so an account
created later under the same name isn't an admin. Nothing else changes group
membership. With the
`jamf_connect` provider, Jamf Connect or Self Service+ adds and removes the
user; Serberus only reads its log entries.

## Processes

The daemon runs system tools (for example `dseditgroup`, `dscl`, `lsbom` and
`installer`) as short-lived children with a time limit. It reads their output
as it arrives, and stops one whose output passes 64 MiB, which counts as a
failure.

While the JIT provider is `jamf_connect` and Serberus is on, the daemon keeps
one `/usr/bin/log stream --style ndjson` child running, filtered to Jamf
Connect's privilege-elevation entries, and restarts it after 5 seconds if it
exits. The child runs in its own process group and can't outlive the daemon.
When it starts watching, it also runs `log show` once over the last 8 hours,
for at most 60 seconds. Windows are kept in memory; each one opened or closed
is written to the decision log. When a user chooses the Jamf Connect item in
the Sentinel menu, the Sentinel runs the Jamf Connect command (by default
`/usr/local/bin/jamfconnect acc-promo --elevate`) in that user's session. See
[SECURITY.md](../SECURITY.md#just-in-time-admin).

## Network

- **The daemon makes no network connections.** Nor do the PAM module, the
  authorization plugin, the CLI and Guardian. None of them sends telemetry.
- **Serberus Sentinel** talks only to your Jamf Pro server, over HTTPS, and
  only when a user uploads a capture from the Intel tab. It uses the Jamf Pro
  URL and API client in the config profile; the URL must be `https`.
- **Commander** talks only to the Jamf Pro server set in its settings, to
  read inventory and uploaded captures for Fleet Observer and, when turned
  on, to publish profiles.
  It doesn't refuse an `http://` URL itself, but no Serberus app relaxes App
  Transport Security, which blocks plain HTTP.
- Apart from a capture a user uploads, Serberus data reaches Jamf only
  through the extension attributes, which Jamf's own agent runs during
  inventory.

## Configuration profiles you deliver

Serberus reads only its own managed preference domains (see
[SERBERUS-OVERVIEW.md](SERBERUS-OVERVIEW.md#5-managed-preference-domains-how-you-configure-it)).
Two Apple payloads are also part of a deployment, both in
`Support/sample-profiles/`:

- **PPPC** (`com.apple.TCC.configuration-profile-policy`): Full Disk Access for
  the daemon, needed only for the Endpoint Security exec-gate.
- **Managed login items** (`com.apple.servicemanagement`): marks the daemon,
  the LaunchAgents and the Finder extension as managed, so users can't turn
  them off.

## Verify the installed binaries

Each component must be validly signed by your team. For each one, `codesign
-dr -` shows the designated requirement, and `codesign --verify --strict`
checks the signature. Replace `TEAMID` in the expected output with your Team
ID.

**Daemon**

```bash
codesign -dr - /Library/PrivilegedHelperTools/serberusd.app
codesign --verify --strict --verbose=2 /Library/PrivilegedHelperTools/serberusd.app
```

Expected, in this shape:

```
designated => identifier "com.herojoneslabs.serberus.daemon" and anchor apple generic and … certificate leaf[subject.OU] = TEAMID
/Library/PrivilegedHelperTools/serberusd.app: valid on disk
/Library/PrivilegedHelperTools/serberusd.app: satisfies its Designated Requirement
```

**PAM module**

```bash
codesign -dr - /usr/local/lib/pam/pam_serberus.so
codesign --verify --strict --verbose=2 /usr/local/lib/pam/pam_serberus.so
```

Expected: `identifier "com.herojoneslabs.serberus.pam"`, the same `anchor apple
generic` and `TEAMID`, then `valid on disk` and `satisfies its Designated
Requirement`.

**Authorization plugin**

```bash
codesign -dr - /Library/Security/SecurityAgentPlugins/SerberusAuth.bundle
codesign --verify --strict --verbose=2 /Library/Security/SecurityAgentPlugins/SerberusAuth.bundle
```

Expected: `identifier "com.herojoneslabs.serberus.authplugin"`, the same
`anchor apple generic` and `TEAMID`, then `valid on disk` and `satisfies its
Designated Requirement`.

That shape is a Developer ID signature's. A test package's Apple Development
signature shows the certificate's name instead of `subject.OU`; `codesign -dv`
prints the team as `TeamIdentifier=` for either.

The team must be the same in all three: the module accepts replies only from a
daemon of its own team, the installers refuse a module or plugin from another
team, and the daemon refuses a plugin from another team. (The daemon doesn't
check the module's signature: it checks that its caller is Apple's `sudo`.) `serberus status` then reports the daemon's state
and mode; the states are explained in
[SERBERUS-OVERVIEW.md](SERBERUS-OVERVIEW.md#72-reported-daemon-state-precedence-order).

## Removing it

- **The uninstall package** (`PKG/build-uninstall-pkg.sh`) removes every
  endpoint component, the support folder, the logs, the System keychain
  items, the LaunchAgents and the Sentinel's per-user files, restores the
  AuthorizationDB and forgets the receipts. It never touches Commander, its
  receipt or its policy library.
- **`uninstall.sh`** (production package) and the test packages' helpers
  remove the components their package installed. Without `--purge` they keep
  the data: the support folder's state, grants, `last-known-good-config.plist`
  and `version.plist`, the logs and the keychain keys, so a reinstall
  enforces the old last-known-good policy at once. `--purge` deletes that
  data, and never the apps, the uninstall helpers, `pam-lib.sh` or
  `.install-markers/`. The Sentinel app helper
  (`uninstall-serberus-sentinel-app.sh`) leaves the daemon's data alone: its
  `--purge` deletes the Sentinel's four per-user files, then their folder
  only if nothing else is left in it, so Commander's library beside them
  stays.
- **Commander** comes with its own uninstall helper,
  `uninstall-serberus-commander.sh`, in the support folder.

See [PKG/README.md](../PKG/README.md#install-order-and-removal) for the order
the uninstallers work in.
