# SerberusPAM (the sudo PAM module)

`pam_serberus.so` is the C PAM module (signing identifier `com.herojoneslabs.serberus.pam`).
It is installed at **`/usr/local/lib/pam/pam_serberus.so`** (dir `root:wheel 0755`,
file `root:wheel 0444`) and referenced by **absolute path** from
`/etc/pam.d/sudo_local` (source: `Support/sudo_local`):

```
auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
```

> Why `/usr/local`: `/usr/lib/pam` sits on the sealed read-only APFS system
> snapshot. On macOS 11 and later nothing (root, installer payloads, scripts)
> can write there. `/usr/local` is the only firmlinked-writable location under
> `/usr`. A bare module name isn't used: libpam searches more than one
> directory for one, so it wouldn't pin which file sudo loads. OpenPAM also
> loads `<path>.2` in preference to the path it is given, so the installers
> remove any `pam_serberus.so.2` beside the module, and the daemon reports
> sudo as not wired while one exists.
> The trailing `# serberus-managed` marker is how install/uninstall tooling
> recognizes the Serberus-owned line without disturbing user lines (the
> OpenPAM in macOS treats `#` anywhere on a line as the start of a comment, so
> sudo never sees it).
>
> Why `requisite` rather than `required`: when Serberus denies, the stack
> returns immediately, so `pam_opendirectory` never asks for a password whose
> outcome is already decided. Success and `PAM_IGNORE` continue down the stack
> exactly as they would with `required`.

## Trust model

The module runs **inside the untrusted sudo process**. It never decides
policy: it gathers the request, applies the break-glass bypass checks, and
asks the root daemon (the policy authority) over XPC. In `enforce` mode it
**fails closed**: a deny and an unreachable daemon both return `PAM_MAXTRIES`
(a hard deny that also ends sudo's password-retry loop), never `PAM_IGNORE`.
The only path that returns `PAM_AUTH_ERR` is a failure to read the user name
(`pam_get_user`), which is also a deny.

The module does not bring an identity of its own to the daemon. Because it
runs inside sudo, the XPC connection carries **sudo's** identity, and that is
what the daemon checks (`validatePAMHost` in
`Sources/PrivMgrCore/XPC/XPCConnectionValidator.swift`): the peer must have
euid 0, a valid non-ad-hoc signature that satisfies `anchor apple`, signing
identifier `com.apple.sudo`, and executable path `/usr/bin/sudo`. That is the
only way into the daemon's PAM interface. The daemon never sees the module's
own code signature. Accepting the host only lets the request reach rule
evaluation; the policy engine still decides.

In the other direction, the module pins the daemon (`ask_daemon` in
`pam_serberus.c`, requirement built in `Sources/pam_serberus/pam_decisions.h`):

- It looks up the Mach service `com.herojoneslabs.serberus.daemon` in the
  **system** domain only. sudo runs in the invoking user's session, where a
  user's own LaunchAgent could otherwise advertise the same name and answer.
- The peer must satisfy a code-signing requirement: identifier
  `com.herojoneslabs.serberus.daemon`, `anchor apple generic`, and a leaf
  certificate whose team is the module's own Team ID. A module whose signature
  was read and carries no Team ID (ad-hoc, for local development) still
  requires the identifier on an Apple-issued certificate. A module whose own
  signature can't be read trusts no daemon at all.
- Every reply must come from a process running as root.

Any failure counts as an unreachable daemon, which denies in `enforce`.

## Authentication flow

`pam_sm_authenticate` in `Sources/pam_serberus/pam_serberus.c`:

0. **Resolve the config source.**
   - *Managed*: the MDM-delivered config is present and safely enforceable. The normal case.
   - *Last-known-good*: the delivered config is absent or not safely enforceable
     (profile removed, unscoped, or only partly delivered), but the daemon's
     snapshot at `/Library/Application Support/Serberus/last-known-good-config.plist`
     exists. The module reads `enforcementMode` and `pamBypass` from the
     snapshot, so removing the profile neither disables Serberus nor removes
     break-glass.
   - *Bootstrap*: neither exists; this Mac has never been configured.
     → `PAM_IGNORE`, and the daemon is not consulted.
1. **Kill switch** (`daemonEnabled = false`) → `PAM_IGNORE` for every user; the daemon is not consulted.
2. `user ∈ pamBypass.users` → `PAM_IGNORE` (falls through to `pam_opendirectory.so`)
3. `user ∈ any pamBypass.groups` → `PAM_IGNORE`, checked with **`mbr_check_membership`**, not `getgrnam` (catches users added via `dscl`)
4. `enforcementMode == monitor` → `PAM_IGNORE` (no interception)
5. Ask the daemon. Decision `native` → `PAM_IGNORE`, whatever the mode and
   the command: the user is a JIT admin inside their window (an active
   Serberus JIT grant or an observed Jamf Connect elevation) and in the local
   `admin` group right now. Only the reply to the initial request may say
   `native`; on a poll it counts as a deny, and a decision string the module
   doesn't know is a deny too (`serberus_decision_code` in `pam_decisions.h`).
   Otherwise, `enforcementMode == audit` → `PAM_IGNORE` whatever the
   answer, including an unreachable daemon (the daemon logs would-grant/would-deny).
6. `enforce` + a command form the module can't evaluate (see below) → deny, even if the daemon allowed it.
7. `enforce` + decision `allow` → `PAM_SUCCESS`
8. `enforce` + decision `deny` **or** daemon unreachable/timeout → `PAM_MAXTRIES`, with a message that
   tells a policy deny, a declined or timed-out Sentinel prompt, and an unavailable service apart.

So sudo runs natively in exactly these cases: bootstrap, kill switch,
`pamBypass` users and groups, `monitor` mode, `audit` mode (including when the
daemon is unreachable), and a `native` decision for a JIT admin inside their
window. Everything else under `enforce` fails closed.

**The drop-in rule.** Bootstrap, the kill switch, `monitor` and `audit` pass
through only once the Serberus sudoers drop-in is gone. The module checks for
`/etc/sudoers.d/serberus` (a regular file, not followed through a symlink) on
every authentication. While it is there, a user outside `pamBypass` is
evaluated exactly as in `enforce` mode: ask the daemon, and deny on a deny or
an unreachable daemon (a `native` decision still passes through). The drop-in is what lets standard users reach sudo, and
the daemon removes it on its next reload pass: at once when the managed config
file changes (the daemon watches it), otherwise on the next ~30-second tick.
Without this rule there would be a short window of curated `sudo` with no
policy behind it. `pamBypass`
users still pass through. The decision is `serberus_auth_posture` in
`Sources/pam_serberus/pam_decisions.h`.

After a deny, a per-process latch makes any retry round in the same sudo
process return `PAM_MAXTRIES` at once, so the Sentinel prompt is not raised
again.

**sudo timestamps.** The main control is in the drop-in: it sets
`timestamp_timeout=0` for every enrolled user, so sudo never reuses an earlier
authentication for a curated command. As a second layer, `pam_sm_setcred`
deletes the invoking user's ticket in `/var/db/sudo/ts` when sudo calls it with
`PAM_ESTABLISH_CRED` or `PAM_REINITIALIZE_CRED` (sudo 1.9 uses the latter),
but only when `pam_sm_authenticate` gated the request: it evaluated it
against the daemon, in `enforce` or `audit` (or under the drop-in rule), and
the answer wasn't `native` (`serberus_decision_marks_gated`). In bootstrap,
under the kill switch, in `monitor` mode, for `pamBypass` users and after a
`native` decision the module steps aside, and sudo's own timestamp behaviour
is untouched, so sudo behaves exactly as it would without Serberus. When sudo
skips authentication altogether (a valid ticket, or `NOPASSWD`), the module
isn't asked and there is nothing to clear.

The daemon deletes timestamps as well (`SudoTimestampDirectory`, with the same
safe-name rule): a user's when their Serberus JIT grant ends or an observed
Jamf Connect elevation ends, so a ticket from inside the window can't skip the
gate afterwards, and every user's whenever `sudo` gating begins (moving into
`enforce` from another mode, the kill switch or bootstrap, and starting in
`enforce`), break-glass users' included.

The ticket belongs to the invoking user, whom sudo puts in `PAM_RUSER`. The
`PAM_USER` that `pam_sm_authenticate` recorded (`pam_set_data`) is used only
when `PAM_RUSER` is unset, because under `targetpw`, `rootpw` or `runaspw` it
names the target or root. `PAM_USER` at `pam_setcred` time is never used:
sudo 1.9 has reset it to the runas user, usually root, by then. A name that is
empty, `.`, `..` or contains `/` is refused. sudo 1.9.15 and later, which
macOS ships, name the ticket file after the user's numeric uid
(`/var/db/sudo/ts/501`), and older releases after the user name. So the name
is resolved with `getpwnam_r` (the account's own name must equal it exactly)
and `/var/db/sudo/ts/<uid>` is deleted, and so is `/var/db/sudo/ts/<name>`.
The daemon deletes both files too.
The daemon's `GrantStore` and decision cache are the only caching Serberus
relies on.

## Configuration it reads

The module reads the computer-level managed plist
`/Library/Managed Preferences/com.herojoneslabs.serberus.config.plist` directly
(`Sources/pam_serberus/pam_config.c`). That managed (MDM profile) layer of
`com.herojoneslabs.serberus.config` is the only preferences layer it reads:
there is no fallback domain, and values written with an unmanaged
`defaults write` are ignored. The one other file it reads is the daemon's
last-known-good snapshot described above.

Both files are honoured only when the file and the folder holding it are
owned by root and not writable by group or others. Each file is opened
without following a symlink (`O_NOFOLLOW`) and checked on the open
descriptor. A managed config that fails these checks counts as absent. A
snapshot that fails them still marks the Mac as configured (its existence is
what rules out bootstrap), and reads as `enforce` with no bypass.

A managed plist that is absent, unreadable, unparseable, or empty counts as
absent. So does one that sets `enforce` with an empty `pamBypass`, or with a
`pamBypass` none of whose entries names an account or group on this Mac
(users are looked up with `getpwnam`, groups with `getgrnam`), because it is
not safely enforceable. A group counts only when at least one of its members
is an existing account (`serberus_config_group_has_members`):

- a name in its `gr_mem` list (`GroupMembership`) that is exactly an existing
  account's name; a deleted account's name left in the group doesn't count;
- a GeneratedUID in its `GroupMembers` attribute (read from Open Directory)
  that resolves to an existing account; a group's UUID doesn't count;
- an account whose primary group it is, found by a `getpwent` scan of at most
  100,000 accounts. A group id above `INT32_MAX` (`nobody`, `nogroup`) never
  matches this way.

Members of nested groups don't count. An existing group with no such member is
logged as `pamBypass group <name> has no members` and doesn't count. A
`pamBypass` name is compared byte for byte, and one containing a NUL character
never resolves. Prefer local accounts and groups, and list at least one user
under `users`: a group of network accounts gives no break-glass while the
directory is unreachable, and a group that lists no members by name costs an
account scan inside `sudo` on each authentication. The daemon
(`LocalAccounts.groupHasMembers`) and the installers' preflight
(`serberus_pam_group_resolves` in `PKG/Scripts/pam-lib.sh`, through
`dscacheutil` and `dscl /Search`) use the same definition. A user entry counts only when the account's name is
exactly the entry, including case: directory lookups also match another case
or an alias, but the bypass check compares the exact login name, so such an
entry would never match. Group lookups retry with a larger buffer when a
group's record is too large for the first one. The daemon makes the same decision. In those cases step 0 applies: the module uses the
last-known-good snapshot if one exists, and otherwise passes sudo through
(bootstrap). Inside a config it does use, an unknown `enforcementMode` value
reads as `enforce`, and a snapshot file that exists but can't be parsed reads as
`enforce` with no bypass. There is no environment-variable override.

## How the command is discovered

A PAM auth module is not handed the target command by sudo. Since the module
runs *as* the sudo process, it reads the argument vector sudo's `main` received
(`_NSGetArgc()` / `_NSGetArgv()`) and finds the command with
`Sources/pam_serberus/sudo_args.c`, which mirrors the
option tables of sudo 1.9's own argument parser (short and long options,
including long-option prefix matching). Any disagreement with sudo would let
Serberus approve one command while sudo runs another, so the parser refuses
anything it can't be certain about. In `enforce` mode these invocations are
denied (they are still sent to the daemon, so they are logged):

- `-s`, `-i`, `-e` / `sudoedit`, `-l`, `-v`, `-V`, `-h` / `--host`, `-K`, `-U`,
  `-R` (chroot), `-D` (chdir), and the platform-specific `-a`, `-c`, `-r`, `-t`;
- unknown or ambiguous options, and options missing their value;
- `NAME=value` environment assignments before the command;
- any invocation where the program is not plainly `sudo`. sudo decides whether
  to run as `sudoedit` from `getprogname()`, which on macOS is the last path
  component of `argv[0]` as the process was started, so an `argv[0]` of
  `sudoedit` (`exec -a sudoedit /usr/bin/sudo`), or a link named `sudoedit`
  (or `lt-sudoedit`) pointing at `/usr/bin/sudo`, would otherwise slip past. The module requires
  `getprogname()`, the exec path, and `argv[0]` all to name `sudo` (sudo's
  `lt-` prefix is ignored), and treats an empty `argv[0]` as unevaluable.

`Sources/pam_serberus/sudo_args.h` is the authoritative list.

The command is then resolved to an absolute path. A name containing `/` goes
through `realpath`. A bare name is looked up on `PATH` the way sudo does:
entries in order, relative ones included, empty ones skipped and `.` last; the
first regular file with an execute bit wins, then `realpath`; a safe default
path is used when `PATH` is unset. A `secure_path` set in sudoers isn't visible
to the module, so where you use one, write rules with absolute paths. A command that can't be resolved is sent as typed, and the daemon's
canonicalization denies it. The command and its arguments are sent to the
daemon (the `argv` key in the XPC contract), so per-argument rules work through
PAM, not only through ESF. ESF is the per-exec enforcement layer; PAM is the
authentication gate.

## Build & install (developer)

```bash
# 1. Build and sign, as yourself (not with sudo; universal arm64 + x86_64).
#    Output: ~/serberus-live/pam_serberus.so, outside any synced folder.
#    LIVE_DIR (the folder) or OUTPUT (the file) changes where.
SIGNING_IDENTITY="Apple Development: Your Name (CERTID)" ./Support/build-pam.sh --build

# 2. Install that module to /usr/local/lib/pam. This step doesn't build.
sudo SIGNING_IDENTITY="Apple Development: Your Name (CERTID)" ./Support/build-pam.sh --install
# then:  sudo echo serberus-test   (routes through the daemon)
```

`--build` refuses to run under sudo, because it would write root-owned files
into your home and root can't use your login keychain. Without
`SIGNING_IDENTITY` it signs ad-hoc, which is fine for a compile check but
can't be installed.

`--install` never builds. It installs the module step 1 produced, re-verified
after it is copied into place. sudo drops `SIGNING_IDENTITY` from the
environment, so pass it on the `sudo` line as shown, with the identity the
installed daemon is signed with; without it, `--install` refuses before it
checks or changes anything. If you set `LIVE_DIR` or `OUTPUT` in step 1, pass
the same value through `sudo` too, because the install looks for the module
there.

`--install` guards against breaking sudo:

- **Break-glass preflight** (the same shared check the pkg installers run,
  from `PKG/Scripts/pam-lib.sh`). It runs before anything on the system is
  changed. It passes when the effective `enforcementMode` is `audit` or
  `monitor`, or when `pamBypass` names at least one user that exists on the
  Mac under exactly that name (case included), or one group that exists and
  has at least one member. Otherwise it refuses, including when no config is present at all
  (treated as `enforce`). Like the module, the preflight reads only the
  managed plist; a value set in root's own preferences satisfies neither.
- **Preflight vs. bootstrap**: the preflight is stricter than the module. On a
  Mac that has never been configured (no managed config and no snapshot), the
  module passes sudo through untouched, but the preflight still refuses,
  because it treats the missing config as `enforce` with no bypass.
- **A running daemon from the same team.** The daemon's launchd job must be
  running, with the same process for a few seconds, and the installed daemon
  must carry a Team ID. The module must be validly signed by that same team.
  An ad-hoc module, or a daemon installed ad-hoc by `serberusd-devtool.sh`,
  fails this check. Sign both with the same Apple Development identity.
- **Architecture check**: refuses a module that lacks this Mac's native slice.
- **No versioned copy.** A stray `/usr/local/lib/pam/pam_serberus.so.2` is
  removed, because OpenPAM would load it instead of the module.
- **Directory chain.** `/usr`, `/usr/local`, `/usr/local/lib`,
  `/usr/local/lib/pam` and the module must be root-owned, not writable by
  group or others, and not symlinks. This is checked before anything is
  copied, and it is never skipped.
- **`/etc/pam.d/sudo` check**: warns if Apple's file doesn't include
  `sudo_local` as its first `auth` line. The script never edits that file.
- **`sudo_local` is never merged.** If `/etc/pam.d/sudo_local` is absent, it is
  created from `Support/sudo_local`. If it already exists, it is left untouched:
  - a legacy bare-name `pam_serberus.so` line gets a loud warning. Replace it
    with the absolute-path line above: a bare name doesn't pin which file sudo
    loads, and the daemon never counts it as wired;
  - if there is no active `pam_serberus.so` line, the module is installed but
    not wired, and the script prints the line to add. Add it as the **first**
    `auth` line, so a module such as Touch ID's `pam_tid.so` can't satisfy sudo
    before Serberus evaluates the request.

  Apple owns `/etc/pam.d/sudo`, which includes `sudo_local`. The pkg
  installers, unlike this script, do merge the Serberus line into an existing
  `sudo_local`, above its first `auth` line. Either way, a `sudo_local` that
  pulls in another policy with `include` stays not wired: put the lines it
  includes into `sudo_local` itself.

`--install --force` is for development only. It skips the break-glass
preflight and the daemon and team checks, deliberately, and installs an
ad-hoc module when `SIGNING_IDENTITY` isn't passed. It does not skip the
directory-chain check. With
`--force`, remember that an ad-hoc module can't reach an ad-hoc daemon: the
module requires an Apple-issued daemon signature, so every non-bypass `sudo`
is denied in `enforce` mode.

The shared XPC key contract lives in
`Sources/SerberusXPCShim/include/serberus_xpc_keys.h`. Both this C module and
the Swift daemon include it, so the wire format has a single source of truth.

## Signing

The daemon never checks the module's signature (see Trust model), but the
module still has to be validly signed to load, and its Team ID is what it pins
the daemon to. Native arm64 code must carry a valid signature, and a module
whose signature is missing or invalidated (for example by a Finder-info
extended attribute that a file-sync service adds) fails to load inside sudo,
which breaks sudo for every user, bypass users included. `build-pam.sh`
therefore strips extended attributes, signs with Hardened Runtime and the
stable identifier `com.herojoneslabs.serberus.pam`, and verifies the result.

The installers and `build-pam.sh --install` require the module to be signed by
the installed daemon's team, and refuse a daemon with no Team ID. An ad-hoc
module is only for `--install --force` experiments. For distribution,
`PKG/build-pkg.sh` re-signs the module with your Developer ID Application
identity and Hardened Runtime so the whole pkg payload can be notarized.

## End-to-end testing

The end-to-end check (`sudo echo` actually routing through the installed module
to a running daemon) needs a root install of both the daemon and the module on
a test Mac, signed by the same team. The daemon accepts the request because it
comes from Apple's `sudo`; the module accepts the reply only from a daemon
signed by its own team. The Sentinel approval prompt depends on the team too:
the daemon derives its team from its own code signature and accepts only a
Sentinel app signed by that same team, so an ad-hoc-signed daemon accepts no
app callers at all.
