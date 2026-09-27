# Security Policy

Serberus runs as root, sits in the `sudo` PAM stack, and rewrites the macOS
AuthorizationDB. A defect here can open a privilege-escalation path or lock
people out of `sudo`, so security reports get priority over everything else.

## Summary

- **What Serberus enforces.** For standard (non-admin) users: which `sudo`
  commands they may run, which authorization rights they may use, time-limited
  admin (JIT), and, when a profile turns it on, installing and removing apps.
  Policy comes only from computer-level MDM profiles. In `enforce` mode `sudo`
  fails closed when the daemon can't answer; `monitor` and `audit` change
  nothing on the Mac.
- **Trust boundaries.** Trusted: local administrators and root, the MDM
  server, `pamBypass` members, a JIT admin inside their window, and anyone who
  can sign code with your Apple Developer team. Not trusted: standard users,
  other processes in their session, and anything they can write. See
  [Trust assumptions](#trust-assumptions).
- **The three biggest limitations.**
  1. Rules match a command and its first argument only, and the sudoers
     drop-in allows any arguments (see
     [Known limitations](#known-limitations)).
  2. A JIT admin is a full admin for the window, and whatever they change
     outlives it.
  3. Serberus is alpha and hasn't had an independent security audit. Jamf
     Connect JIT and Install with Serberus are experimental: each has been
     run end to end on one test Mac only, on macOS 26.7 (see
     [Verified live](#verified-live)).

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
open the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- the component (`serberusd`, `pam_serberus`, `SerberusAuth`, Sentinel,
  Commander, the CLI, or the installer scripts)
- the Serberus version or commit, and the macOS version
- the enforcement mode (`enforce`, `audit`, or `monitor`) and the relevant
  configuration-profile keys, with credentials and identifiers removed
- steps to reproduce, and what an attacker gains

This is a single-maintainer project. You can expect an acknowledgement within
7 days. Please allow a reasonable window for a fix before disclosing publicly.

## Supported versions

Serberus is alpha software, currently version 0.9.0. Only the latest commit
on the default branch receives security fixes.

## Security model

### What Serberus is designed to enforce

Serberus narrows what **standard (non-admin) users** can do with `sudo` and
with authorization rights, according to policy delivered by MDM
configuration profiles. Policy is read only from computer-level profiles
(the root-owned plists in `/Library/Managed Preferences`) or from the daemon's
last-known-good snapshot of them. Ordinary preference files and user-level
profiles are ignored.

- **Two-gate `sudo`.** A path-only sudoers drop-in (`/etc/sudoers.d/serberus`)
  lets an enrolled standard user reach `sudo`. `pam_serberus` then asks
  `serberusd` over XPC for a verdict on the full command and arguments. The
  daemon writes the drop-in only in `enforce` mode, and only while the PAM gate
  is verifiably in place:
  - the first active `auth` line of Apple's `/etc/pam.d/sudo` is
    `auth include sudo_local`;
  - `/etc/pam.d/sudo_local` has an active `requisite` `pam_serberus` line above
    every other `auth` line;
  - neither file has any other `include` line;
  - both files, the module and its parent folders are root-owned and not
    writable by anyone else.

  The daemon reads both files with the same rules as the OpenPAM in macOS:
  `#` starts a comment anywhere on a line, and quotes are ordinary
  characters. It reads each file whole, and a file longer than 256 KiB
  counts as not wired rather than being judged on its first part. Every
  active line must be one OpenPAM accepts (a valid facility, a valid control
  flag and a module, or `include` with exactly one policy name), because one
  bad line anywhere makes OpenPAM reject the whole file. A file containing a
  carriage return, a backslash or another control byte anywhere, or a quote
  or a non-ASCII byte outside a comment, counts as not wired, because its
  meaning would depend on parser details (a quote inside a comment, such as
  an apostrophe in an admin's note, is fine). Every other module either file
  names must also be on a root-only path, because `sudo` loads it as root:
  a module under a folder a user owns, such as Homebrew's `pam_reattach`
  under `/opt/homebrew`, counts as not wired. Modules named without a path
  that load from the sealed `/usr/lib/pam` are exempt. Any `include` other
  than that first `auth include sudo_local` counts as not wired too: OpenPAM
  loads the modules of an included policy into `sudo` as root, and Serberus
  doesn't follow includes to check them, so put lines such as `pam_tid.so`
  in `sudo_local` itself. "Root-only" counts
  ACLs as well as mode bits: an ACL entry that lets anyone but root write
  counts as writable. So does a
  `/usr/local/lib/pam/pam_serberus.so.2` beside the module: OpenPAM loads
  that file in preference to the one named. So does any PAM configuration that
  OpenPAM could read in place of those two files: `/etc/pam.conf`, or a
  `sudo`, `sudo_local` or `pam.conf` under
  `/private/var/db/ManagedConfigurationFiles/com.apple.pam/` or
  `/usr/local/etc/`. None of these exists on a stock Mac.

  Otherwise it removes the drop-in and reports `degraded (pam_not_wired)`.
  When the daemon leaves `enforce` mode it removes the drop-in before anything
  else. It watches the config profile, so a mode change takes effect at once
  rather than on the next 30-second reload.
- **The drop-in keeps `sudo` gated.** While `/etc/sudoers.d/serberus` exists,
  `pam_serberus` never passes a request through for a user outside
  `pamBypass`, other than a JIT admin inside their window (see [When `sudo`
  behaves natively](#when-sudo-behaves-natively)). Bootstrap, the kill switch,
  `monitor` and `audit` are all evaluated as `enforce` until the drop-in is
  gone, so the drop-in can't hand out `sudo` that nothing checks.
- **Installers wire `sudo` last and unwire it first.** A package that
  installs the daemon wires the PAM module into `sudo_local` only after the
  new daemon has kept one PID for longer than launchd's restart throttle,
  with no restarts, and has written a `state.plist` after it was started. A
  package that ships the `serberus` CLI, including the production package,
  also requires the CLI to be present, signed by the daemon's team, and able
  to report the daemon's status. The PAM-only test package, which installs
  no daemon, requires the one already installed to keep one PID with no
  restarts, and doesn't check `state.plist`. The production postinstall also refuses to
  wire `sudo_local` while an MDM-managed PAM configuration or a `pam.conf`
  (the files listed above) exists, and stops with the reason when
  `/usr/local/bin`, where the CLI goes, isn't root-only. On an upgrade or
  uninstall, the drop-in is removed before `sudo_local` is unwired; if the
  drop-in is still there after its removal, the teardown stops before
  `sudo_local` is touched.
- **The PAM module pins the daemon.** It looks the daemon up in the system
  domain only, so an agent running in the user's session can't answer in its
  place. The reply must come from root, from code that satisfies a
  code-signing requirement: identifier `com.herojoneslabs.serberus.daemon`,
  `anchor apple generic`, and the module's own Team ID. Anything else counts
  as an unreachable daemon. The module reads its config and the snapshot only
  when the files and their folders are root-owned and not writable by others,
  and never through a symlink.
- **The daemon's PAM interface has one caller.** The PAM module runs inside
  `sudo`, so the daemon checks the process it runs in: the caller must be
  Apple's `/usr/bin/sudo` (identifier `com.apple.sudo`), running as root.
  There is no other way to reach that interface.
- **`sudo` is parsed exactly as sudo parses it.** `pam_serberus` reads the
  argument vector sudo itself received and finds the command with sudo's own
  option table. Anything it can't evaluate with certainty is denied in
  `enforce` mode. That includes unknown or ambiguous options, `-s`, `-i`, `-e`,
  `sudoedit` (however it's invoked, including through a renamed link to
  `sudo`), `-l`, `-v`, `-D`, `-R`, `NAME=value` assignments before the command,
  and an empty program name, among others; see
  [docs/SerberusPAM.md](docs/SerberusPAM.md#how-the-command-is-discovered) for
  the full list. Run a shell explicitly (`sudo /bin/zsh`) if policy allows one.
- **No `sudo` timestamp reuse.** The drop-in sets `timestamp_timeout=0` for
  every enrolled user, so each curated `sudo` goes back through Serberus. That
  is the main control. As a second layer, when `pam_serberus` has evaluated a
  request against the daemon (`enforce` or `audit`), it deletes the invoking
  user's sudo timestamp (the user sudo reports as `PAM_RUSER`) when sudo sets
  up credentials. In the cases where it steps aside (below), sudo's own
  timestamp behaviour is left alone. The daemon deletes timestamps too: a
  user's when their JIT admin elevation ends, and every user's whenever
  `sudo` gating begins (see [Just-in-time admin](#just-in-time-admin)).
  macOS's sudo (1.9.15 and later) names a timestamp file after the user's
  numeric uid, `/var/db/sudo/ts/<uid>`; older releases used the user name.
  Serberus deletes the uid file, and the name file as well. On-Mac testing
  confirmed uid names with sudo 1.9.17p2 on macOS 26.7.
- **Fail-closed PAM in `enforce` mode.** If `serberusd` is unreachable, times
  out, or answers with anything malformed, `pam_serberus` denies.
- **Caller validation.** `serberusd` validates every XPC caller by its audit
  token, never by PID. Serberus's apps must be signed by the same Apple
  Developer team as the daemon, which reads that team from its own signature,
  so an unsigned or ad-hoc-signed daemon trusts no app.
- **Prompts reach only the requesting user.** An approval prompt is shown on,
  and answered by, the Sentinel of the user who asked, identified by that
  Sentinel's audit token. If that user has no Sentinel running, the request is
  denied.
- **Prompts show hidden characters.** The command line and the requesting
  app's path, in a prompt and in My Activity, show hidden characters as
  visible escapes instead of hiding them: a bidi override appears as
  `\u{202E}`, a zero-width space as `\u{200B}`, a newline as `\n`. Nothing is
  removed and the command is never cut off: a long one scrolls in the prompt
  and wraps in My Activity. So a command can't be made to read differently
  from what runs. Arguments are joined with spaces and not quoted, so an
  argument that contains a space reads like two.
- **A prompt can't be approved blind.** Approve, the button and ⌘↩ alike,
  works only after the prompt has been the focused window, visible and not
  overlapped by another app's window for a full second. It's disabled again
  the moment any of that stops, and arming again takes another second. While
  it's disabled, a click on the prompt or a ⌘↩ (held or repeated) starts the
  second over, and a click is judged on the prompt's state at that moment. So
  a click or keystroke timed with the prompt's appearance, or one that lands
  on it through a window placed over it, doesn't approve. Deny (the button, or
  Return when no justification is asked for) and the timeout always work.
  This applies to every prompt: `sudo`, authorization rights, installs and
  uninstalls. Escape doesn't deny in 0.9.0: it beeps and leaves the prompt up
  (a known issue found in on-Mac testing).
  - The overlap check reads the window server's list of windows, which needs
    no Screen Recording permission, every 200 milliseconds and on every click.
    It ignores Serberus's own windows, fully transparent ones, and three
    Apple processes whose windows sit above every app's as a matter of
    course: the Dock, the screenshot tool and VoiceOver, identified by
    Apple's code signature. Any other window over the prompt disables
    Approve, a notification banner included, until it's moved away; the
    prompt can be dragged clear. If the window server can't answer, the
    prompt counts as covered. On macOS 26.7 the screenshot tool's selection
    overlay (⇧⌘4) isn't recognised, so a prompt stays disabled while one is
    up; it arms normally once the screenshot is taken or cancelled.
- **Corrupt state fails closed.** A last-known-good configuration snapshot that
  exists but cannot be read causes enforcement, never pass-through.
- **Setting the clock back doesn't extend a grant.** This matters because
  opening the Date & Time right (`system.preferences.datetime`) can be
  allowed.
  - Within one boot, a timed grant (including JIT admin) expires on whichever
    comes first: the wall clock, or a deadline on the continuous clock, which
    keeps counting through sleep and can't be set. A clock set earlier than
    the grant's issue time counts as expired, and the daemon revokes expired
    grants on every reload tick, so an expired grant never comes back when the
    clock moves again.
  - The continuous clock starts again at each reboot. When the daemon starts,
    it gives every live timed grant a new continuous deadline for this boot,
    from what is left of it by the wall clock. That can only shorten a grant.
  - The daemon records the latest wall-clock time it has seen, root-only, in
    `/Library/Application Support/Serberus/clock-high-water.plist` (at
    startup, on every reload tick and at shutdown). If, when it starts, the
    clock is more than 120 seconds behind that mark, it revokes every timed
    grant and demotes every JIT admin, then resets the mark. A legitimate
    large backward correction made while the daemon wasn't running therefore
    also ends every timed grant, once.
- **Grants are signed.** Each row of `grants.sqlite` carries an HMAC made with
  a key in the System keychain. If the key is lost while rows remain, the
  daemon never mints a new one: it reports `degraded (grants_db_error)`,
  refuses JIT and grants that need the store, and demotes the user of every
  JIT row it can no longer verify. To recover, restore the key, or remove
  `grants.sqlite` (its grants are lost) and restart the daemon. The database
  schema is at version 3, which adds the account's GeneratedUID to JIT rows;
  an older daemon refuses to open it, so a downgrade needs the file removed.

### When `sudo` behaves natively

In these cases `pam_serberus` steps aside and `sudo` behaves as it would
without Serberus (sudoers plus the user's password, and sudo's own
timestamp, so a recent authentication is reused as usual). One exception:
while the sudoers drop-in exists, an enrolled user still gets its
`timestamp_timeout=0`, so `sudo` asks an enrolled JIT admin for the password
every time.

- **Bootstrap:** the Mac has never had a Serberus config, and there is no
  last-known-good snapshot.
- **Kill switch:** `daemonEnabled` is `false`.
- **Break-glass:** the user, or a group they belong to, is in `pamBypass`.
  The sample configs put the `admin` group there, which makes every admin
  break-glass, a JIT or Jamf Connect-elevated user included: Serberus never
  sees their `sudo`. To have Serberus govern JIT and Jamf Connect
  elevations, list only named break-glass accounts.
- **`monitor` mode:** no evaluation at all.
- **`audit` mode:** the request is evaluated and logged, then allowed through,
  even if the daemon is unreachable. Because the daemon evaluated it, the
  user's sudo timestamp is cleared afterwards, so in `audit` mode sudo asks
  for the password every time. There are two exceptions: a JIT admin inside
  their window gets the `native` answer in `audit` mode too, which keeps
  their timestamp; and `sudo -v` and `sudo -l` write a timestamp without
  setting up credentials, so nothing clears it.
- **A JIT admin inside their window:** the user holds an active Serberus JIT
  grant or an observed Jamf Connect elevation, from the provider that is set
  now, and is in the local `admin` group at the moment of the request. The
  daemon answers `native`, and `pam_serberus` steps aside for any command
  (see [Just-in-time admin](#just-in-time-admin)).

Break-glass and a JIT admin inside their window always apply. The other four
apply only once the sudoers drop-in is gone; while it exists, other users are
evaluated as in `enforce` mode.

### Just-in-time admin

A user can ask for time-limited admin from the Sentinel menu, from one of two
providers (`com.herojoneslabs.serberus.jit`, key `provider`). With
`serberus`, the daemon adds the user to the local `admin` group for a bounded
window and removes them when it ends. With `jamf_connect`, the menu item runs
the privilege elevation of Jamf Connect or Self Service+, which owns the
reason prompt, eligibility, duration and demotion. The `jamf_connect`
provider is experimental: it has been run end to end once, with Self
Service+ and its bundled Jamf Connect on macOS 26.7 (see
[Verified live](#verified-live)).

- **An elevated admin gets native `sudo`.** For a `sudo` request, the daemon
  answers `native` when both hold at that moment:
  - the user has an active Serberus JIT grant (matched by name and uid) while
    the provider is `serberus`, or an open Jamf Connect elevation window the
    daemon observed while the provider is `jamf_connect`; and
  - a live directory check says the user is in the local `admin` group. An
    unknown answer isn't enough.

  `pam_serberus` then returns `PAM_IGNORE`, so `sudo` behaves as it would
  without Serberus, password prompt and timestamp included, whatever the
  command. The decision is logged with rule `jit-native` or
  `jit-native-jamf-connect`. A user who is an admin gains nothing from this
  that macOS wouldn't give them anyway.
- **Jamf Connect elevations are observed, not attested.** While the provider
  is `jamf_connect` and Serberus is on, the daemon runs `/usr/bin/log stream
  --style ndjson` with a predicate for the subsystems `com.jamf.connect.daemon.ssp`
  and `com.jamf.connect` and the category `PrivilegeElevation`. An entry counts
  only when the process that logged it (`processImagePath`, which the logging
  system records from the real sender, not the message) runs from inside
  `/Applications/Jamf Connect.app/`, `/Applications/Self Service+.app/`,
  `/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/` (the Jamf
  Connect daemon inside Self Service; the rest of Self Service, including the
  Jamf Connect menu app inside it, isn't trusted) or `/Library/Application
  Support/JamfConnect/`, and its whole message is one of Jamf's forms: a user
  elevated for a number of minutes, a user added to the admin group, a user
  removed from the admin group, or the time remaining. Matching text inside a
  longer message doesn't count, so the reason a user types (logged as `User
  <user> elevated to admin for stated reason: <reason>`) never opens or ends a
  window. A user name that isn't a plain short name (a redacted `<private>`,
  for example) is ignored. The `log` child runs in its own process group and
  can't outlive the daemon: it is stopped when observation stops or the
  daemon exits, and it exits by itself if the daemon dies.
  - Anyone who can put a binary in those folders, which needs admin rights
    (`/Applications` is admin-writable), can write entries that pass these
    checks. So an observed window never counts on its own: it only ever
    combines with the user's live `admin` membership, which a forged entry
    can't create. A forged entry for a user who isn't an admin changes
    nothing.
  - A window lasts for the minutes Jamf logged, capped at 8 hours (the JIT
    maximum). An "added to the admin group" entry has no duration: its window
    lasts 15 minutes (Serberus's default JIT window) until the time remaining
    Jamf logs right after it, within 60 seconds, sets the length (still
    capped at 8 hours). If that entry never comes, or another window is open
    so it can't be matched, the window stays at 15 minutes and the user is
    gated early rather than late. Jamf doesn't always log the time
    remaining: in on-Mac testing (Self Service+ with bundled Jamf Connect,
    macOS 26.7) it logged only the added and removed entries. Then native
    `sudo` lasts 15 minutes, and after that the user is gated by Serberus
    again even while Jamf still has them in `admin`. That fails closed.
    Like a grant, a window is bounded on both the wall clock and the
    continuous clock, so setting the clock doesn't extend it. It ends early on a removal entry, on a shorter time remaining
    (applied only when exactly one window is open, since that entry names no
    user), when the user is no longer in `admin` (checked on every reload
    tick), or when observation stops. Windows are kept in memory only. When
    the observer starts it reads the last 8 hours of the log once, so an
    elevation that began before the daemon started still counts, in either
    form; windows restored that way aren't logged again, and a history entry
    no newer than the user's last live entry is ignored.
  - An opened and a closed window are written to the decision log as
    `jit_admin_elevation` and `jit_admin_demotion` with rule `jamf-connect`.
- **Sudo timestamps don't outlive an elevation.** A timestamp lets `sudo` skip
  authentication, and with it `pam_serberus`, until it expires. So the daemon
  deletes the user's timestamp (`/var/db/sudo/ts/<uid>`, and
  `/var/db/sudo/ts/<user>` for older sudo) when a Serberus JIT grant ends
  (demotion, expiry, the kill switch, the clock-rollback check or
  `--demote-jit`) and when an observed Jamf Connect window ends. It also
  deletes every user's timestamp whenever `sudo` gating begins: when it moves
  into `enforce` from another mode, the kill switch or bootstrap, and when it
  starts in `enforce`. That includes the timestamps of break-glass users.
- **The Jamf Connect command is pinned.** The Sentinel runs it in the user's
  session, only from an absolute path, by default `/usr/local/bin/jamfconnect
  acc-promo --elevate`. A relative path or bare name in the profile is
  ignored and the default is used. Before showing the item and again right
  before running it, the Sentinel resolves symlinks and checks that the file
  passes a strict code-signature check against `anchor apple generic and
  certificate leaf[subject.OU] = "483DWKW443"`, Jamf's team. That team is
  fixed in the code; no profile key changes it. Otherwise the item is shown
  disabled. It runs the resolved path it checked, not the symlink, so the
  link can't be re-pointed in between. The check doesn't ask for revocation
  (`kSecCSEnforceRevocationChecks`): that needs Apple's OCSP service, so a
  Mac that is offline or behind a filtering proxy would find a genuine Jamf
  binary failing or the menu stalling. A revoked Jamf certificate is left to
  macOS's own revocation handling. The command runs as the user, from a path
  only root or an admin can write.
- **Jamf Connect has to allow it.** The `jamf_connect` provider needs
  privilege elevation turned on in the Jamf Connect or Self Service+ profile,
  with `URLCommandLineElevation` enabled so the command line can start it.
- **The kill switch refuses Serberus JIT only.** With `daemonEnabled` set to
  `false`, the daemon demotes every Serberus JIT admin and refuses new
  requests, but the Jamf Connect hand-off stays available, because Jamf
  Connect, not Serberus, performs that elevation. The observer stops, and
  `pam_serberus` passes `sudo` through anyway once the drop-in is gone.
- **Turning Serberus JIT off ends open windows.** When the provider stops
  being `serberus` (set to `disabled` or `jamf_connect`, or the JIT profile
  removed), a Serberus JIT grant stops earning native `sudo` at once, and the
  daemon demotes every open window on its next reload tick, within about 30
  seconds, as an expiry would. A daemon that starts under such a policy
  demotes the window instead of re-arming it, and a demotion that fails is
  retried on every tick. A JIT profile that can't be read counts as removed,
  even for a moment (while MDM reinstalls it, for example), so it can end a
  window early; the user can then ask again.
- **Eligibility is checked only when a window is requested.** Removing a user
  from an eligible group, or changing `eligibleGroups`, doesn't end a window
  they already have. To end one user's window early, remove them from `admin`
  with a root command, for example a Jamf policy running
  `dseditgroup -o edit -d <user> -t user admin`; their `sudo` stops being
  native as soon as they're out of `admin`. The kill switch, or switching the
  provider away from `serberus`, ends every window.
- **A reused uid isn't mistaken for a rename.** A Serberus JIT grant records
  the account's GeneratedUID, which is part of the row's HMAC. If the uid later
  belongs to an account with another GeneratedUID, the promoted account is
  treated as gone and the new account isn't demoted. The same GeneratedUID
  under a new name is a rename, and the renamed account is demoted. Rows
  written before the GeneratedUID was recorded get it at daemon startup when
  their name and uid still name the same account; a row whose name and uid
  no longer match keeps treating a reused uid as a rename.
- **A retired account leaves nothing in `admin`.** Deleting an account
  doesn't remove it from groups, and macOS also resolves local membership by
  name, so an account created later with the same short name would be an
  admin from the start. When the daemon retires the grant of an account that
  is gone, it removes the account's name from `admin`'s `GroupMembership` and
  its GeneratedUID from `GroupMembers`.

### Authorization rights

- **Rights change only in `enforce` mode.** In `monitor` and `audit` mode the
  AuthorizationDB is left native, and switching back from `enforce` restores
  it.
- **A deny rule blocks everyone.** An authURI `deny` makes the right unusable
  for every account, administrators and `pamBypass` members included:
  break-glass applies to `sudo` only.
- **Root-equivalent rights can't be opened to everyone.** A plain `allow` rule
  on a right that gives a path to root (administrator privileges, installing
  daemons or helpers, changing users and admins, directory binding, sharing,
  TCC, configuration profiles, `authopen`, disk management, developer tools
  under `com.apple.dt.`, and others) is ignored and logged. Some rights are
  never touched at all (login, unlock, the authorization database's own
  rules). The lists are `protectedRightPrefixes` and
  `rootEquivalentRightPrefixes` in `AuthRightTargetPolicy`, in
  `Sources/PrivMgrCore/Policy/RuleSchema.swift`. A test reads macOS's own list
  of rights and fails if any admin-gated right hasn't been classified.
- **A plain allow is checked against the right's live definition.** An
  `allow` rewrites a right to "the session owner or an admin", so the daemon
  applies it only when the right is natively a plain admin gate. It reads the
  right's current definition and follows its rule references. A right gated
  by an entitlement, a mechanism, being at the console, the session owner or
  a group other than `admin`, or its own mechanisms (such as an extra
  authentication step) is refused and left native, and so is a right that is
  already open (`class=allow`) to every caller. For example,
  `system.print.admin` (gated to the `lpadmin` group),
  `system.preferences.location` and the `system.volume.*` rights (which a
  user at the console already satisfies) are refused. A right whose native
  gate is admin membership with no password (`is-admin`,
  `authenticate-user` false) counts as a plain admin gate, so after an
  `allow` an admin has to type a password where macOS asked for none.
  - **A right macOS doesn't define** is checked against the wildcard authd
    would answer it from (`system.` resolves to the `default` rule, a plain
    admin gate), then created, and stays created on later passes. For example
    `system.preferences.dateandtime.changetimezone`, which isn't defined on a
    stock Mac, is created this way.
  - **Rights an app creates at runtime** are covered only if the app created
    the right before Serberus did. If Serberus creates it first, it is checked
    against the governing wildcard instead of the definition the app would
    have written.
  - **A right a user created proves nothing.** Any user can create a right
    macOS doesn't define (`config.add.` is `class=allow`), with any
    definition, including a copy of Serberus's marker comment or a reference
    to Serberus's composition rows. A right macOS doesn't ship, that Serberus
    has no record of, and whose definition isn't Serberus's counts as
    foreign. An `allow` on it must also pass as the undefined right it would
    otherwise be (the governing wildcard must be a plain admin gate). A
    `deny` on any right macOS doesn't ship is always written, whatever chain
    the right, or the wildcard that governs its name, runs. On restore and
    uninstall a foreign original is put back, and one that passes itself off
    as Serberus's is replaced with an admin gate. A definition that refers to
    another right's composition rows can't make Serberus remove them.
  - **A user's copy of a right is removed before a deny is written.**
    Any standard user can create a new authorization right, and root can
    then remove it but not overwrite it (seen in on-Mac testing on macOS
    26.7.1). When a `deny` rule targets a right macOS doesn't ship and a user
    created that right first, Serberus removes the user's version and writes
    the deny. The user's version is kept as the right's recorded original,
    never trusted.
  - **The live definition is re-checked.** If a right's definition changes
    underneath Serberus (an admin, an app or a macOS update replaces it), the
    new definition is checked again. If it still passes, it becomes the
    original that restore puts back; if not, Serberus stops managing the right
    and leaves the new definition in place.
  - **The rewrite keeps the native credential settings.** An `allow` keeps the
    native right's `timeout`, `shared` and `password-only` settings, so a
    credential isn't reusable for longer than macOS allows and a right that
    needs a typed password still needs one. For a right that accepts any of
    several rules, it takes the most restrictive across the branches a person
    authenticates through: the shortest `timeout` (a branch with none counts
    as unlimited), `shared` only when every such branch sets it, and
    `password-only` when any does. Serberus records a digest of each
    definition it writes and rewrites one that was edited in place.
  - **The check is bounded.** The classifier follows at most 256 rule
    references and refuses a larger rule graph, a loop, an undefined
    reference, or a `k-of-n` that no caller can satisfy.
- **Some targets are refused outright.** A rule may not name:
  - a right with characters other than ASCII letters, digits, `.`, `_` and
    `-`;
  - an authorization rule class (a name with no dot, such as `is-admin`);
  - a right ending in `.` (which authd treats as a wildcard);
  - one of Serberus's own composition rows.

  A `deny` may not target the login, screensaver, disk-unlock or Platform SSO
  rights, and an `allow` may not target disk unlock or Platform SSO. A right
  that macOS ships as a chain of mechanisms (such as the login and smart-card
  rights), directly or through the rules it references (such as keychain
  unlock), is left native.
- **One failed write doesn't stop the rest.** Every `deny` is written before
  any other right, and each right and composition is applied on its own: if
  one can't be read or written, or its original can't be saved first (a full
  disk, for example), the rest of the policy is still applied. Serberus never
  rewrites a right without a saved original to restore it from, so a right
  that fails keeps the definition it had, and nothing is denied in its place.
  The daemon then reports `degraded (authdb_failure)`, names the rights in its
  integrity log, and retries on every reload tick, about every 30 seconds,
  until they're applied.
- **Restore is checked.** Serberus records a digest of every AuthorizationDB
  row it owns, and trusts a saved copy of a right's original definition only
  when it matches the digest it recorded. When no verified original exists,
  restore writes Apple's shipped definition from
  `/System/Library/Security/authorization.plist`, or an admin gate for a name
  Apple doesn't ship. That admin-gate stand-in carries no marker; Serberus
  recognises it by a `.standin` record in `authdb-backups`, never by its
  comment. A restore also sweeps the live AuthorizationDB for rights Serberus
  wrote, and removes its own composition rows that nothing references any
  more. In a chain someone else wrote, it removes only the SerberusAuth
  entries. It never writes a stand-in over a protected right: such a right
  is logged for an admin to repair by hand, and `serberusd --restore-authdb`
  exits non-zero while it, any right that still references the SerberusAuth
  plugin, or any Serberus-written right the sweep couldn't reset remains (its
  records are kept, so the next restore tries again). A protected right that
  macOS doesn't ship and Serberus never wrote isn't counted: any user can
  create a new right, and one they created can't block a restore.
- **The uninstallers decide from Serberus's records, not from comments.** They
  remove the plugin and `authdb-backups` only when `authdb-backups` holds no
  pending record (a `.json`, `.branches` or `.projection` file; a `.standin`
  record never blocks) and a live query finds no Serberus composition row
  that invokes SerberusAuth and no right that delegates to one. A comment
  proves nothing, since anyone who can create a right can copy the marker
  Serberus writes. A right outside Serberus's own rows that invokes
  SerberusAuth doesn't block removal: once the plugin is gone, that right
  fails for every caller, and it breaks nothing else.
- **Per-app (identity-scoped) rules are disabled in 0.9.0.** A rule
  with an App Identity definition (`appTeamID` + `appBundleID`) is ignored:
  the daemon composes nothing, logs the rule as skipped, and the right keeps
  its native definition. A right an older build composed is restored on the
  next reconcile. The SerberusAuth plugin is still installed but denies every
  request, and Commander reports each such rule as a validation error, which
  blocks export. A pin profile doesn't make the daemon report `degraded`.
  There is no way in this release to allow one app on a root-equivalent
  right. See [Known limitations](#known-limitations) and
  [docs/authuri-identity-scoped-rules.md](docs/authuri-identity-scoped-rules.md#disabled-in-090).

### Install and Uninstall with Serberus

These are off unless an `appmanagement` profile turns them on. Both are
experimental: Install has been run end to end under the real root daemon on
one test Mac only, on macOS 26.7 (see [Verified live](#verified-live)).

- **Install** takes a flat `.pkg` or an `.app` (not a bundle-style `.mpkg`).
  Only Developer ID software qualifies: Mac App Store and Apple-signed items
  are refused, as install items and as the app being replaced. Gatekeeper must
  accept the item as notarized Developer ID software, **and** its publisher
  (signing Team ID) must be allowed. Notarization is required unless the
  profile sets `requireNotarization = false`, which also accepts Developer ID
  software that isn't notarized. By default only Team IDs listed in
  `allowedPublisherTeamIDs` are allowed, and an empty list allows none.
  `publisherScope = "any"` allows every Developer ID publisher. Choose that
  knowingly: a package's install scripts run as root.
- **Allowing a Team ID trusts everything that team has notarized.** Every
  package, and every version of every app, is accepted, with the limits on
  replacing an app below. So don't allow the team that signs your Serberus
  packages: any user could then install any package it ever signed, including
  the uninstall package and older Serberus releases.
- **The item is checked in a root-only copy.** Every entry in the source must
  be readable by the requesting user (mode bits and ACL deny entries both
  count), and hard-linked files and special files are refused. The copy must
  fit a size and file budget, extended attributes included. The copy itself
  runs as the requesting user, into a folder inside a root-only staging area,
  so root never reads a file's contents on the user's behalf. Root does read
  the source's metadata first (names, sizes, owners, modes and ACLs) to check
  it. It is made with
  `/bin/cp`, which copies symlinks as symlinks, keeps extended attributes
  (code signatures need them) and doesn't copy ACLs or file flags. `ditto`
  can't be used here: it looks up the path of the folder it runs in, and the
  user can't reach that folder by path. (Root's later copy of an app into
  `/Applications` still uses `ditto`.) The copy has the user's
  primary group only, not their other groups, so an item the user can read
  only through a supplementary group can't be staged, and the install says
  so. Root then takes the copy
  over under a fixed name, so neither the user's file nor its name can
  influence the result, and resets ownership, file flags, set-ID bits and
  ACLs on it. The publisher is read from the signature, which must validate
  strictly, and must match the team Gatekeeper reports.
- **Items in protected folders need the daemon's Full Disk Access.** macOS
  privacy protection (TCC) covers folders such as `~/Downloads` and
  `~/Desktop`. In on-Mac testing (macOS 26.7), with Full Disk Access granted
  to `serberusd`, items installed from `~/Downloads`, `~/Desktop` and
  `/Users/Shared`. Without it, only items in folders TCC doesn't protect
  installed: for `~/Downloads` and `~/Desktop`, TCC refused root's check of
  the item before the copy. The message then says Install with Serberus
  needs a flat package or an app "that you can read", although the cause is
  the daemon's missing Full Disk Access.
- **Some packages are refused and must be deployed by IT.**
  - A relocatable or per-user package.
  - A package whose install location isn't root-only: every existing folder on
    the way must be owned by root and not writable by other users (group
    write is accepted only for `wheel` or `admin`), with no ACL granting
    access. `/Users/Shared` and the temporary folders are never accepted as an
    install location.
  - A package with a payload path anyone but root could steer, the requesting
    user or any other local user. Every path in every component's bill of
    materials is checked, under its install location and any custom
    location, from `/` down. A path is refused when an existing component on
    it (a symlink included) is owned by anyone but root, or is writable by
    anyone but root; when it sits in a folder anyone but root can write to,
    unless that folder is sticky; or when a missing component would be
    created in a folder anyone but root can write to, sticky or not. Group
    write for `admin` or `wheel` is accepted, and ACL entries count as write
    access. So a payload that goes into an existing root-owned vendor folder
    in `/Users/Shared` installs, but one that would create a new folder there
    is refused. In practice, Homebrew packages (`/opt/homebrew` belongs to
    the admin who installed Homebrew) and updates to an app an admin dragged
    into `/Applications` (owned by that admin) must be deployed by IT.
  - A package that writes through a symlink it installs itself, when that
    symlink leads outside its own install location or into a shared folder.
    The on-disk checks can't see such a link, because it doesn't exist
    yet.
  - A package whose `Distribution` references content that wasn't inspected:
    every `pkg-ref` must name a component in the package itself.
- **Requests are limited.** Each user can have one request in progress, and
  the daemon two in total. Errors shown to the user are generic, and every
  refusal before staging uses the same message; details go to the daemon's
  log. In the decision log, which every local user can read, a target inside
  a user's home folder is written as `…/<name> [sha256:<hash>]`.
- Installed apps are owned by root, never by the user who installed them.
- **An `.app` must be a real application bundle** (`CFBundlePackageType`
  `APPL`), and it is installed under a name its own bundle declares
  (`CFBundleDisplayName` or `CFBundleName`), not the file name the user
  chose. A download renamed `Foo 2.app` installs as `Foo.app`.
- **Replacing an app.** An app can replace an installed app only if both are
  signed by the same team and have the same bundle ID, and never if either is
  a Serberus app or on `protectedBundleIdentifiers`. It can't replace a newer
  installed copy of itself, and it can't be installed next to a newer copy of
  the same bundle ID kept under another name in `/Applications` or
  `/Applications/Utilities`. Versions are compared as dotted numbers on
  `CFBundleVersion` (or `CFBundleShortVersionString` when either side lacks
  it); if the two can't be compared on the same key, the install is refused,
  for a copy under another name as for the app being replaced.
- **`protectedBundleIdentifiers` and the Serberus-app check cover app installs
  and uninstall only.** A `.pkg` from an allowed team runs `installer` as root,
  and nothing checks afterwards what it installed or replaced.
- **Uninstall** moves an app that sits directly in `/Applications` or
  `/Applications/Utilities` to the requesting user's Trash, after a
  confirmation that is always shown. Apps inside other bundles can't be
  targeted. An app is refused, and must be removed by IT, when it or an app
  nested inside it is on `protectedBundleIdentifiers`, carries a LaunchDaemon,
  a LaunchAgent or a privileged helper, declares `SMPrivilegedExecutables` or
  `SMAuthorizedClients`, or is referenced by a job in `/Library/LaunchDaemons`
  or `/Library/LaunchAgents` (by program path, any program argument, working
  directory, label or associated bundle ID).
- **Uninstall doesn't recognise apps that host system extensions.** An app
  that installs a system extension (a security agent, a VPN or network
  filter, a DriverKit driver) isn't refused on that account. Any app not on
  `protectedBundleIdentifiers` can be removed this way, so list every app users
  must not remove, above all your security and management agents.
- **The Trash hand-off gives the user only what they could already read.**
  Only world-readable, single-link files, and folders everyone can list and
  search, are handed over to the user in the Trash, and not when an ACL deny
  entry takes that access from the user. Everything else, including
  everything inside a folder the user couldn't search, is deleted as root.
- **The Trash must be on the same volume.** The move is a rename, so if the
  user's Trash is on another volume it fails and the app stays where it is.
- **Any app in the user's session can raise the prompt.** Besides the Finder
  extension, the Sentinel agent offers Install with Serberus and Uninstall
  with Serberus as Services, in the Services menu and the Services submenu of
  Finder's right-click menu. The Services API doesn't say which app called,
  so any app the user runs can raise the install or uninstall prompt for a
  file it chooses. The prompt is the control: it can't be approved until it
  has been focused, visible and uncovered for a second (see
  [What Serberus is designed to enforce](#what-serberus-is-designed-to-enforce)).
- **Keep `promptBeforeAction` on.** It applies to installs. With it off, any
  process running in the user's session can ask Serberus to install an allowed
  package without the user seeing a prompt.

### Trust assumptions

These are outside what Serberus defends against:

- **Local administrators and root are trusted.** Anyone who can write to
  `/etc/pam.d`, `/etc/sudoers.d`, the AuthorizationDB, or
  `/Library/LaunchDaemons` can remove or bypass Serberus.
- **The MDM channel is trusted.** Whoever controls the MDM server controls
  Serberus policy.
- **Break-glass members are trusted.** Users and groups in `pamBypass` skip
  Serberus for `sudo` entirely. That is deliberate: it guarantees a bad policy
  can't lock everyone out of `sudo`.
- **Standard users who are granted temporary (JIT) admin are admins** for the
  duration of the grant, with everything that implies.
  - A JIT grant is written to the grant store before the user is promoted, and
    JIT is refused while the grant store is unavailable, and while the kill
    switch is on (the Jamf Connect hand-off stays available). The kill
    switch is checked again right before and right after the promotion, so
    one that arrives while a request is in progress still stops it. If the
    membership lands after a demotion of the same grant has begun, the user
    is removed from `admin` again, and a row records it so every recovery
    path retries until the removal lands. The grant's clock keeps running
    while the Mac sleeps, and the daemon demotes any overdue grant on its
    next reload.
  - A JIT grant is retired without a demotion only when the account is
    confirmed gone: nothing resolves by its name or its uid, the local
    directory node has no such record, and no network directory is
    configured. A renamed account (same uid, new name) is demoted under its
    new name. On a Mac bound to a directory, a deleted account can't be
    confirmed gone, so its grant stays active and the demotion is retried, and
    `serberusd --demote-jit` reports it as a failure (exit 1).
  - An upgrade ends JIT sessions. The package's preinstall writes a
    root-only marker (`/Library/Application Support/Serberus/.upgrade-in-progress`),
    boots the old daemon out, waits up to 25 seconds (the daemon's 20-second
    exit timeout plus 5) until launchd no longer lists it, then runs its
    `--demote-jit`, but only if that binary passes a strict signature,
    identifier and team check. The new daemon also ends every live JIT
    session when it starts after an upgrade: when its own build differs from
    the one that ran last, or when the marker is there (it trusts the marker
    only as a small, root-owned regular file that isn't group- or
    other-writable, and deletes it after startup). So a session the old
    daemon couldn't end still ends.
  - Every other place the scripts run the daemon as a one-shot
    (`--demote-jit`, `--restore-authdb`) makes the same check first, and
    prints manual steps instead of running a binary that fails it. The team
    is the one recorded at install time in
    `/Library/Application Support/Serberus/version.plist` (`installTeamID`,
    the team the daemon was signed and validated with); on a Mac without that
    record, the installed PAM module's team. With neither, the daemon isn't
    run. The production postinstall's abort path, which runs the daemon the
    same package has just installed, checks it against that daemon's own
    team. `uninstall.sh` never runs `--restore-authdb` while the daemon is
    still loaded. `serberusd --demote-jit` exits 0 on success, 1 on failure,
    2 on a usage error, and 3 when there is no grant store (nothing to
    demote).
  - Demotion, including the one every uninstall runs, removes only the admin
    membership Serberus added. Anything the user changed while they were an
    admin, such as another admin account, a LaunchDaemon, a sudoers file or a
    root process they left running, outlives the grant and the uninstall. A
    JIT admin can also boot `serberusd` out with `launchctl bootout`; nothing
    then demotes them until the daemon runs again, and it demotes an overdue
    grant when it starts.
  - A JIT admin inside their window gets native `sudo`, whatever the command
    (see [Just-in-time admin](#just-in-time-admin)), and satisfies every
    authorization right that accepts an admin. See
    [Authorization rights](#authorization-rights) for root-equivalent rights,
    and the install-rights limitation below.
- **Anyone on the signing team is trusted.** App callers are pinned to the
  daemon's team, and that includes development-signed builds from the same
  team.

### Known limitations

- **Per-app rules can't be trusted, so they are off.** The SerberusAuth
  plugin identified the requesting app by authd's `creator-audit-token` hint.
  authd merges the caller's `AuthorizationCreate` / `AuthorizationCopyRights`
  environment into the hints after it sets that hint, so a caller can supply
  its own. Confirmed live on macOS 26.7: an unsigned program run by a standard
  user borrowed the identity of a running, root-installed Jamf Composer and
  got the pinned path (the user's own password) on
  `com.apple.ServiceManagement.blesshelper`. In 0.9.0 per-app rules are
  disabled (see [Authorization rights](#authorization-rights)). A replacement
  that decides from Endpoint Security authorization events is planned.
- **Rules match the command and its first argument only.** `argPattern` is
  matched against the first argument, and the sudoers drop-in allows any
  arguments. A rule for a binary whose later arguments matter (an interpreter,
  `installer`, anything with `-c` or plugin options) can allow more than
  intended. Prefer narrowly-scoped binaries, or a wrapper script you control.
  An allowed interpreter, or any tool that runs code or config named in its
  arguments, is as good as a root shell for the user.
- **Allowed commands run with a clean environment.** The drop-in sets
  `!env_keep` for every enrolled principal, so an allowed command runs with
  root's `HOME`, sudo's standard `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`) and
  no `EDITOR`/`VISUAL`; terminal and locale variables still pass. Without it,
  macOS's sudoers would hand root the user's `HOME` (`~/.zshenv`, Python
  user site-packages, `~/.gitconfig`) and sudo would keep the user's `PATH`.
  A wrapper script that needs `/usr/local/bin` must use absolute paths or set
  `PATH` itself.
- **`*` in a path pattern also matches `/`.** `/usr/local/bin/*` matches
  files in subfolders too. Prefer exact paths for anything sensitive.
- **The binary is identified when the request is evaluated**, a moment before
  `sudo` runs it. Don't write rules for binaries in folders a standard user
  can write to.
- **Enrolling from an identity-provider group trusts the state file.** With
  `idpSource = "jamf_connect_state"`, enrolment requires a root-owned state
  file by default (`requireRootOwnedState`). Setting it to `false` accepts the
  user-owned Jamf Connect file, which the user can edit to enrol themselves.
- **Strict IdP mode can be defeated with an old state file.** The state file
  lives in the user's own `~/Library/Preferences`. A user who kept a copy of
  an earlier root-owned state file, from a time they were in an enrolling
  group, can put it back and still be enrolled. Fixing this needs the state
  file in a location only root can write.
- **Allowing install rights lets users run installers as root.** An `allow`
  rule on `system.install.*` or `com.apple.pkgkit.*` lets a standard user
  approve package installs with their own password, and packages run scripts
  as root.
- **Decision logs are readable by every local user.** The Sentinel's Intel tab
  reads `/Library/Logs/Serberus` directly, so the decision log is not private:
  any local user can see other users' `sudo` commands and justification text.
  Arguments are logged only for rules that set `logArguments`, which is off by
  default. Common secret forms in arguments (password and token options,
  `NAME=value` secrets, credentials in URLs, credential headers, and
  tool-specific forms such as `security`, `dscl`, `dsconfigad`, `pwpolicy`,
  `git -c`, `curl -H`, `wget --header`, `keytool`, `redis-cli -a`,
  `smbclient -U`, `vault login`, `openssl passwd`, `launchctl setenv` and
  `defaults write` with a sensitive key) are redacted, in the log and in the
  command text sent to the Sentinel prompt. So is the command run through a
  wrapper, with the same rules: a shell's `-c` string, `env`, `xargs`,
  `launchctl asuser`, `nohup`, `nice`, `caffeinate`, `timeout`, `time`,
  `arch`, `command`, `builtin`, `exec`, `doas`, `sudo`, `chroot`, `script`,
  `su -c`, `osascript -e`, and the `-e` or `-c` program of Perl, Ruby,
  Python and Node. Redaction can't recognise every form, so don't turn on
  argument logging for commands whose arguments may carry sensitive data.
  Arguments captured while debug mode (`debugModeEnabled`) is on are kept in
  memory and in the root-only `recent-events.json` and `fleet-events.json`
  (the copy the extension attributes read, which Jamf then collects), never
  in the decision log. Install and uninstall targets inside a user's home
  folder are logged as `…/<name> [sha256:<hash>]`.
- **Diagnostics aren't limited to the requesting user.** The grant database
  is readable by root only on disk, but the Intel tab's log collection, which
  any local user can request, includes a copy of it (`grants.sqlite`: user
  names, uids, GeneratedUIDs, paths and hashes, no justification text) and of
  the sudoers drop-in, which names every enrolled user and the commands they
  may run and is otherwise readable by root only. It also includes other
  users' authorization activity.
- **`targetpw`, `rootpw` and `runaspw` change whose request it is.** Under
  these sudoers `Defaults`, which only root can set, sudo sets `PAM_USER` to
  the target user (or root) rather than the invoking user. `pam_serberus`
  doesn't detect them: it checks `pamBypass` against that name and sends it to
  the daemon, which evaluates rules, grants and the JIT check for the target
  user. A `pamBypass` entry or a rule that covers the target therefore covers
  every user who can authenticate as it. Only the timestamp that
  `pam_serberus` deletes is still the invoking user's (`PAM_RUSER`). Don't
  combine these settings with Serberus.
- **The installers' liveness check doesn't talk to the daemon.** Before wiring
  `sudo_local`, a package checks launchd's view of the job (one stable PID, no
  restarts) and that the daemon has written `state.plist` since it was
  started; `serberus status` reads that same file. None of it is a live XPC
  round trip, so a daemon that writes its state but can't answer requests
  passes the check.
- **Bare command names are resolved the way sudo resolves them**, along the
  caller's `PATH`. macOS's sudoers sets no `secure_path`; one you add isn't
  visible to the PAM module, so where you set one, write rules with absolute
  paths. This is only how the command is found: the command itself runs with
  a standard `PATH` (see the `!env_keep` note above).
- **The PAM module lives under `/usr/local/lib/pam`.** Installers refuse to
  wire it, and the daemon withholds the sudoers drop-in, unless `/usr`,
  `/usr/local`, `/usr/local/lib` and `/usr/local/lib/pam` are all owned by
  root and writable by nobody else, the `admin` group included (an old Intel
  Homebrew layout, for example, makes `/usr/local` admin-writable). ACL
  entries count.
- **Jamf API credentials in configuration profiles are not secret.** The
  optional Jamf Pro client ID and secret in `com.herojoneslabs.serberus.config`
  are stored as managed preferences. Treat them as readable by any local user.
  The Sentinel uses them to attach a capture to the Mac's own computer record,
  which needs Read Computers and Update Computers. Those privileges aren't
  limited to that one Mac: anyone who recovers the secret can read every
  computer's inventory and change any computer record, attachments included.
  Use a dedicated API client for this and nothing else, limit it further if
  your Jamf Pro allows (to a site, for example), and rotate the secret through
  MDM.
- **The Endpoint Security exec-gate is optional.** It needs Apple's Endpoint
  Security entitlement, which Apple grants on request. A production package
  built without it (`ESF=off`, or no provisioning profile) has the exec gate
  off; `sudo`, AuthorizationDB rights and JIT admin are enforced as usual.
  `version.plist` and `state.plist` record it as `execGate`, and
  `serberus status` shows it.
- **The Endpoint Security exec-gate needs Full Disk Access.** Without a PPPC
  profile granting it to `serberusd`, the daemon reports `pending_pppc` and the
  exec-gate is inactive. `sudo` and AuthorizationDB enforcement still work.
  Install with Serberus then can't read items in TCC-protected folders such
  as `~/Downloads` and `~/Desktop` (see
  [Install and Uninstall with Serberus](#install-and-uninstall-with-serberus)).
- **The exec-gate is narrow.** It watches a binary only while some user holds
  a live grant for it, and then denies an elevated run of it by a different
  standard user from a login session. It never blocks `pamBypass` members,
  current administrators, or anything not started from a login session, and
  it isn't a general block on binaries. See
  [docs/esf-provisioning-and-notarization.md](docs/esf-provisioning-and-notarization.md#step-7--verify-esf-is-live).
- **Test packages are for testing.** The test packages, including the
  combined `SerberusTest-<version>.pkg`, enable development shortcuts in the
  daemon, such as a file-based signing key. Use the production package
  (`Serberus-<version>-signed.pkg`) and a Developer ID build of the Sentinel
  apps for real deployments (see [PKG/README.md](PKG/README.md)). The
  production package doesn't need the Endpoint Security entitlement; without
  it the exec gate is off.
- **A macOS update can reset the log folder.** On the test Mac, the
  macOS 26.7.1 update recreated third-party folders in `/Library/Logs`.
  `/Library/Logs/Serberus` came back as `0744` with only the files written
  after the update: the earlier decision and integrity logs, and their HMAC
  chain, were gone. Nothing marks the gap in the audit trail. Until the
  folder is `0755` again, the Sentinel Intel tab's History can't read the
  log as the user; `sudo chmod 755 /Library/Logs/Serberus` restores it.
  Forward the logs you must keep off the Mac (the Jamf extension attributes,
  or a log shipper).
- **Use one profile per Serberus preference domain.** macOS merges
  computer-level profiles that set the same domain key by key, and the last
  one applied wins. Where a domain is split on purpose (the enrollment
  profile, or rule profiles with their own `rules_*` keys), each profile must
  set different keys. On the test Mac, a config profile that also carried
  `com.herojoneslabs.serberus.appmanagement` made `publisherScope` flip
  between `allowlist` and `any`. See
  [docs/jamf-profile-delivery.md](docs/jamf-profile-delivery.md).

### Verified live

What has been exercised end to end on a real Mac, and what hasn't. Everything
else is covered by the unit tests only. The on-Mac testing on 2026-09-28 ran on one
Apple Silicon test Mac on macOS 26.7 (26.7.1 for the last item), with test
packages, and Self Service+ with its bundled Jamf Connect.

| Area | Status |
|---|---|
| sudo's timestamp file names | Verified: named by uid, not by name, with sudo 1.9.17p2 (macOS 26.7, 2026-09-28) |
| Whether sudo authenticates before sudoers refuses | Verified: sudo asks for the password first, and Serberus evaluates and logs the request that sudoers then refuses (macOS 26.7, 2026-09-28) |
| Whether a caller can spoof the creator hint | Verified: spoofable; per-app rules disabled in 0.9.0, and the disabled state checked live: the right stays native and the daemon healthy (macOS 26.7, 2026-09-28) |
| Identity-scoped rules on `com.apple.ServiceManagement.daemons.modify` and `com.apple.ServiceManagement.blesshelper` | Disabled in 0.9.0. Earlier builds were run end to end with honest callers on macOS 27, and on `blesshelper` on macOS 26.7 |
| The SerberusAuth mechanism loading into SecurityAgent and receiving its hints | Verified on macOS 27 with the research probe, and on macOS 26.7 in on-Mac testing |
| Install with Serberus: the staging copy runs as the user | Verified: `/bin/cp` runs with the requesting user's uid and primary group; this needed a fix (macOS 26.7, 2026-09-28) |
| Install with Serberus and TCC | Verified: with the daemon's Full Disk Access, items install from `~/Downloads` and `~/Desktop`; without it, only from folders TCC doesn't protect, and protected folders are refused by root's pre-scan (macOS 26.7, 2026-09-28) |
| Install with Serberus: primary group only | Verified: an item readable only through a supplementary group is refused with the documented message (macOS 26.7, 2026-09-28) |
| Install with Serberus: publisher allowlist | Verified: listed teams install, unlisted teams are refused (macOS 26.7, 2026-09-28) |
| Jamf Connect JIT (`jamf_connect` provider) | Verified with Self Service+ and its bundled Jamf Connect: the observer sees the elevation, `sudo` is native inside the window, and gated again after it; this needed a fix (macOS 26.7, 2026-09-28) |
| Prompt arming | Verified: the first-second rule, an overlay before and over the prompt, an overlay hidden from screen capture, focus loss, Stage Manager, a second display, a full-screen Space, after a screenshot, a hidden Dock, VoiceOver, lock and unlock, a very long command, and the Install prompt raised through the Services menu. Escape doesn't deny, a known issue (macOS 26.7, 2026-09-28) |
| Whether a standard user can create `config.modify.<right>` or `config.remove.<right>` | Verified: they can't (`-60005`). They can create a new right, which root can remove but not overwrite (macOS 26.7.1, 2026-09-28) |
| The items listed below | Not verified |

See [docs/authuri-identity-scoped-rules.md](docs/authuri-identity-scoped-rules.md)
for the identity-scoped runs and why per-app rules are disabled.

### Not yet verified on a real Mac

These haven't been tested live yet:

- **The sudo timestamp after a gated request.** Serberus deletes the user's
  timestamp after a request it evaluated, so the next `sudo` is evaluated
  again. On-Mac testing confirmed the file name, but didn't run a gated admin
  twice to see the second request reach Serberus.
- **Jamf Connect:**
  - that the user's sudo timestamp file is deleted when the window ends;
  - that a daemon restart during a window restores it from the log;
  - releases other than the Self Service+ build on the test Mac, and a
    stand-alone Jamf Connect.
- **Install with Serberus:** uninstall under the real root daemon, and the
  allowlist with a notarized package from your own team.
- **Removing a user's copy of a right.** Removing a user's copy of a right before writing a
  deny hasn't been run on a real Mac.
- **Production packages.** On-Mac testing used test packages. The notarized,
  Developer ID-signed production package and Sentinel apps haven't been run
  through it.
- **macOS 27.** The items verified above ran on macOS 26.7 only; they haven't
  been repeated on macOS 27.

## Deploying safely

Serberus changes how privilege works on a Mac. Before deploying it anywhere
that matters:

1. **Test on a machine you can afford to break**, such as a macOS VM, never
   your only admin account.
2. **Always set `pamBypass`** to at least one real account or group that
   exists on the Mac. An `enforce` config is not adopted when `pamBypass` is
   empty or when none of its entries exists on the Mac: the daemon and the PAM
   module keep the last-known-good config, or stay in bootstrap on a Mac that
   never had one, and the daemon reports `degraded (bypass_unresolvable)` for
   the second case. It logs each entry that doesn't resolve, even when others
   do. A user entry must be the account's short name exactly, including case:
   an entry that the directory matches only by case or through an alias
   (`ITAdmin` for `itadmin`) counts as not resolving, because the PAM module
   compares the exact name, byte for byte (an entry containing a NUL never
   resolves). A group entry counts only when at least one of its members is
   an existing account: a name in its `GroupMembership` list that is exactly
   an account's name (a deleted account's name left in the group doesn't
   count), a `GroupMembers` GeneratedUID that resolves to an account, or an
   account whose primary group it is. Members of nested groups don't count.
   The daemon, the PAM module and the installers' break-glass preflight apply
   the same rule, and the daemon and the module log a group with no such
   member as having no members. Prefer local accounts, and list at least one
   user under `users` rather than relying on a group alone: a group of
   network accounts gives no break-glass while the directory is unreachable.
   If the entries of a last-known-good snapshot stop resolving, the daemon
   keeps enforcing it (it fails closed) and reports
   `degraded (bypass_unresolvable)`.
3. **Know the kill switch.** Setting `daemonEnabled` to `false` in
   `com.herojoneslabs.serberus.config` tears enforcement down: the
   AuthorizationDB is restored, the sudoers drop-in is removed, and JIT admins
   are demoted. It must be a real boolean; an integer `0` is ignored. It
   frees `sudo` only while the daemon runs: `pam_serberus` passes a request
   through under the kill switch only once the drop-in is gone, and only the
   daemon or an uninstaller removes it. If the daemon is down, use a
   `pamBypass` account or the uninstall package.
4. **Know how to uninstall.** The uninstall package
   (`PKG/build-uninstall-pkg.sh`) removes every endpoint component in a safe
   order, restores the AuthorizationDB, and deletes the support folder, the
   logs, the keychain items and the Sentinel's per-user files. It never
   touches Commander or its policy library. The production package also
   installs `/Library/Application Support/Serberus/uninstall.sh`, which
   removes what it installed when run as root; without `--purge` it keeps the
   data (state, grants, the last-known-good config, logs and keychain keys),
   so a reinstall picks up the old policy. `--purge` deletes that data and
   never the apps. The test packages install their own uninstall scripts in
   the same folder. [docs/footprint.md](docs/footprint.md) lists what each
   one removes.
5. **Roll out in rings**, starting in `monitor` or `audit` mode, which change
   nothing on the Mac, before `enforce`.
6. **Know the defaults that matter.**
   - `logArguments` is off by default. Turn it on only for rules whose
     arguments you need in the decision log, which every local user can read.
   - `timeBoundGrantsEnabled` is on by default. A rule's
     `maxGrantDurationSeconds` decides whether an approval issues a grant:
     `-1` evaluates every use and never grants, `0` (the default) uses the
     org default `defaultGrantDurationMinutes`, and a number of seconds
     grants for that long, up to 24 hours. A rule set to `0` while the org
     default is also 0 issues no grant. A use with no grant is evaluated
     again, apart from the decision cache (the rule's `cacheSeconds`, else
     `sudoCacheSeconds`; both are 0 by default). Commander calls these "One
     time only", "Use org default" and "Set a time limit". A value below `-1`
     drops the rule, and the daemon reports `degraded (rule_parse_error)`; a
     value above 86,400 is capped at 24 hours.
   - Setting `timeBoundGrantsEnabled` to `false` turns grants off: no
     approval is remembered, so a prompt rule asks every time and a silent
     rule is a plain allow. Only a time-bound grant lets a prompt rule skip
     its prompt, and only until it expires. A grant with no expiry, left by an
     older version, is revoked on the next reload while the switch is off, or
     given an expiry (the duration the rule would issue now, counted from
     then) while it's on, or revoked when the rule would issue none.
   - A grant is tied to its profile, its rule and the binary's hash. When
     the policy is reloaded, grants whose rule or profile is gone, or whose
     rule is now `-1`, are revoked.

See [docs/SERBERUS-OVERVIEW.md](docs/SERBERUS-OVERVIEW.md#7-safety-mechanisms)
for the full safety design.

## No warranty

Serberus is provided "as is", without warranty of any kind, under the terms of
the [Apache License 2.0](LICENSE).
