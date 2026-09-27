# Serberus — Live ESF (provisioning profile) + `.pkg` notarization

Two production gates, walked through end to end. To ship your own build you need, in one Apple
Developer team:
- **Developer ID Application: Your Name (YOURTEAMID)** — signs the daemon bundle, the `serberus` CLI,
  the PAM module and the SerberusAuth authorization plugin.
- **Developer ID Installer: Your Name (YOURTEAMID)** — signs the `.pkg`.
- For the exec gate only: Apple's approval of the **Endpoint Security** entitlement for that team
  (requested from Apple; without it the capability in Step 1 does not appear). It is optional:
  `PKG/build-pkg.sh` with `ESF=off`, or without `PROVISION_PROFILE`, builds the production package
  with the exec gate off, and Part 1 doesn't apply. Curated `sudo`, AuthorizationDB rules and JIT
  admin don't need it.

Serberus does not hardcode a team. The build scripts take it from `DEVELOPMENT_TEAM` (the
environment, or `Config/Local.xcconfig`; copy `Config/Local.xcconfig.example`), and at run time the
daemon reads its team from its own code signature and trusts only app callers signed by that same
team.

---

## Part 1 — Enabling Endpoint Security for live use

### Why this is more involved than the sudo / authURI gates

`com.apple.developer.endpoint-security.client` is a **restricted** entitlement. AMFI only honors it
when it's authorized by **either** a provisioning profile (for your own Mac / direct distribution)
**or** notarization (for end-user Macs). And — the catch — **a bare command-line Mach-O cannot carry
a provisioning profile.** So `serberusd` must be wrapped in an **app-like bundle** whose
`Contents/embedded.provisionprofile` holds the profile. This is Apple's documented pattern for
"signing a daemon with a restricted entitlement."

> Until this is done, `serberusd` logs `ESF subscription unavailable (serving without exec
> enforcement)` and runs without exec enforcement (the sudo prompt round-trip and authURI gating
> work without it).

### Step 1 — Register an explicit App ID with the Endpoint Security capability

[developer.apple.com](https://developer.apple.com) → **Certificates, Identifiers & Profiles** →
**Identifiers** → **+** → **App IDs** → **App**:
- Description: `Serberus Daemon`
- Bundle ID: **Explicit** → `com.herojoneslabs.serberus.daemon`  ← *not* a wildcard; ES requires an explicit ID
- Under **Additional Capabilities**, enable **Endpoint Security** (it only appears once Apple has
  approved ES for your team).

> **Use your own bundle ID.** An explicit App ID can belong to only one developer team, and
> `com.herojoneslabs.serberus.daemon` is registered to the maintainer's team. Unless you are the
> maintainer, pick your own daemon bundle ID (for example `com.example.serberus.daemon`) and change it
> everywhere the daemon's identity is written down before you build:
> - `Sources/PrivMgrCore/BundleConfig.swift` (`daemonBundleID` and `machService`), which the Swift
>   code reads;
> - `Support/build-serberusd-bundle.sh` (`BUNDLE_ID`) and `Support/serberusd-distribution.entitlements`;
> - the LaunchDaemon plist `Support/com.herojoneslabs.serberus.daemon.plist` (label, Mach service and
>   program path);
> - the PAM module, which pins the daemon (`Sources/pam_serberus/pam_decisions.h` and
>   `pam_serberus.c`);
> - `project.yml` (the `serberusd` target's `OTHER_CODE_SIGN_FLAGS` sets the signing identifier),
>   then run `xcodegen generate`;
> - the package and developer scripts in `PKG/` and `Support/`, and the sample profiles.
>
> `/usr/bin/grep -rl com.herojoneslabs.serberus.daemon .` lists every file. The same applies to any
> other App ID you register, such as one for the Sentinel agent's provisioning profile: the apps'
> bundle IDs are set in `project.yml` and `BundleConfig.swift`.

### Step 2 — Create a **Developer ID** provisioning profile

**Profiles** → **+** → under **Distribution** choose **Developer ID** (the type used for ES /
system extensions distributed outside the App Store) →
- App ID: `com.herojoneslabs.serberus.daemon`
- Certificate: **Developer ID Application: Your Name (YOURTEAMID)**
- Generate, download → e.g. `serberusd.provisionprofile`.

Verify it provisions all machines (required for direct distribution):
```bash
security cms -D -i serberusd.provisionprofile | grep -A1 ProvisionsAllDevices   # expect <true/>
```

### Step 3 — Distribution entitlements (all THREE are required)

A profile-authorized restricted entitlement needs `application-identifier` to connect the binary's
entitlement claims to the profile (per Apple DTS), plus the team ID and the ES key.
`Support/serberusd-distribution.entitlements` is a **template**:

```xml
<!-- Support/serberusd-distribution.entitlements -->
<key>com.apple.application-identifier</key>
<string>__TEAM_ID__.com.herojoneslabs.serberus.daemon</string>
<key>com.apple.developer.team-identifier</key>
<string>__TEAM_ID__</string>
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

Don't pass it to `codesign` directly. `Support/build-serberusd-bundle.sh` replaces `__TEAM_ID__`
with your team (via `Support/team-id-lib.sh`, from `DEVELOPMENT_TEAM`) and signs with the rendered
copy, `serberusd-distribution.entitlements` in its output directory. Rendered for team
`YOURTEAMID`, the first value reads `YOURTEAMID.com.herojoneslabs.serberus.daemon`.
(`Support/serberusd.entitlements` carries the ES key only and no build uses it. AMFI kills a binary
that claims the restricted entitlement without a profile that authorizes it, and a bare command-line
binary can't embed one, so the `serberusd` Xcode target signs with no entitlements at all. The PKG
builders build that target unsigned and sign the daemon themselves: the production package through
`build-serberusd-bundle.sh` with the rendered distribution entitlements, the test packages with an
empty entitlements file, so a test daemon runs without ESF.)

### Step 4 — Wrap the daemon in an app-like bundle

```
serberusd.app/
  Contents/
    Info.plist                              CFBundleIdentifier = com.herojoneslabs.serberus.daemon
                                            CFBundleExecutable = com.herojoneslabs.serberus.daemon
                                            CFBundlePackageType = APPL
    MacOS/
      com.herojoneslabs.serberus.daemon             ← the serberusd Mach-O
    embedded.provisionprofile               ← the downloaded profile (renamed), in Contents/
```

`Support/build-serberusd-bundle.sh` builds this layout, renders the entitlements, and signs:
```bash
SIGNING_IDENTITY="Developer ID Application: Your Name (YOURTEAMID)" \
PROVISION_PROFILE="$HOME/serberusd.provisionprofile" \
  ./Support/build-serberusd-bundle.sh
# needs a Release serberusd (DAEMON_BIN, default .build/xcode/Build/Products/Release/serberusd);
# writes .build/bundle/serberusd.app (OUTPUT_DIR overrides)
```

It copies the profile into `Contents/embedded.provisionprofile` first, then signs the **bundle**
once with the rendered entitlements and Hardened Runtime (for an app bundle that applies the
entitlements to the main executable and seals the embedded profile), then verifies. The manual
equivalent, with the rendered file:
```bash
ID="Developer ID Application: Your Name (YOURTEAMID)"
cp serberusd.provisionprofile serberusd.app/Contents/embedded.provisionprofile
codesign --force --options runtime \
  --entitlements .build/bundle/serberusd-distribution.entitlements \
  --sign "$ID" serberusd.app
codesign --verify --strict --verbose=2 serberusd.app
codesign -d --entitlements - serberusd.app/Contents/MacOS/com.herojoneslabs.serberus.daemon   # confirm 3 entitlements
```

### Step 5 — Install + point launchd at the wrapped binary

Install the **bundle** at `/Library/PrivilegedHelperTools/serberusd.app`. The shipped LaunchDaemon
plist (`Support/com.herojoneslabs.serberus.daemon.plist`) already points `Program` at the
executable **inside** it:
```xml
<key>Program</key>
<string>/Library/PrivilegedHelperTools/serberusd.app/Contents/MacOS/com.herojoneslabs.serberus.daemon</string>
```
Load it into the **system** domain:
```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist
```
The pkg postinstall does this for you. `Support/serberusd-devtool.sh` does **not**: it installs the
bare, unprofiled `serberusd` at `/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon`
and writes its own plist at the same `/Library/LaunchDaemons` path pointing there, so a
devtool-installed daemon never has ESF. Run `serberusd-devtool.sh --uninstall` before installing the
bundle.

### Step 6 — Grant Full Disk Access

ESF requires FDA for `serberusd`.
- **Test Mac:** System Settings → Privacy & Security → **Full Disk Access** → **+** → add
  `…/serberusd.app/Contents/MacOS/com.herojoneslabs.serberus.daemon` (use ⌘⇧G to type the path).
- **Production:** deliver a **PPPC** configuration profile via MDM granting `SystemPolicyAllFiles` to
  the daemon's code requirement (no user interaction). Start from
  `Support/sample-profiles/serberus-daemon-fda-pppc-production.mobileconfig` (the `serberusd.app`
  bundle, Developer ID). The test packages' flat daemon uses
  `serberus-daemon-fda-pppc-test.mobileconfig` instead. Replace the maintainer's Team ID in either.
  After the profile lands, restart the daemon (`sudo launchctl kickstart -k
  system/com.herojoneslabs.serberus.daemon`): it starts the ESF client only at startup.

### Step 7 — Verify ESF is live

```bash
sudo log show --last 2m --predicate 'subsystem == "com.herojoneslabs.serberus"' --info | grep -i esf
# expect: "ESF subscription active"
serberus status        # daemon State, Enforcement mode, version and Exec gate
```
`serberus status` reports the exec gate from `state.plist` (`execGate`): `on`, `off (no Endpoint
Security entitlement)`, or `off, unavailable` / `off, not started` with the reason. The log line
above shows the subscription itself.

**What the exec-gate does.** It is a narrow backstop behind the `sudo`/PAM gate, not a ban on
binaries:
- A path is monitored only while some user holds a live grant for it. A rule on its own, even an
  exact-match `sudo` allow, monitors nothing, and a rule with no grant duration never issues a grant.
- For a monitored path, an elevated exec (effective uid 0) from a login session is denied when the
  logged-in user (the audit user, which survives `sudo`) holds no live grant for that path. In
  practice: a standard user can't run a binary as root on the strength of *another* user's grant.
- `pamBypass` members and current `admin` members are always allowed. So is an exec that didn't come
  from a login session (launchd daemons, a root-run `jamf` policy, MDM installs), and any exec that
  isn't elevated.
- If the decision isn't made within the kernel's deadline, the exec is denied.

It doesn't block anything the `sudo` gate would otherwise let through for the user who holds the
grant, and it doesn't block a binary nobody holds a grant for.

To exercise it, use two `sudo` allow rules for the same binary that match different arguments
(`argPattern`): rule 1 with `maxGrantDurationSeconds` set, so it issues a grant, and rule 2 with no
grant duration. Leave `defaultGrantDurationMinutes` at 0 and `timeBoundGrantsEnabled` on (both
defaults). With a single rule, user B's own `sudo` would issue B a grant too, and B's exec would be
allowed.
1. As standard user A, run the binary through rule 1. It runs, and `sudo serberus grants`, run by an
   admin, lists A's grant.
2. While A's grant is live, have standard user B (enrolled, not in `pamBypass`, not an admin) run
   it through rule 2. `sudo` approves it, but the exec is refused and the command fails to start.
   The daemon doesn't log individual exec denials.
3. Repeat step 2 as an admin or a `pamBypass` member: it runs.
4. Once A's grant expires or is revoked, the path is no longer monitored, and B's run from step 2
   succeeds.

> **SIP stays on.** With a valid profile installed, the entitlement is authorized on that Mac
> without disabling SIP. Notarization (Part 2) extends that authorization to *other* Macs.

---

## Part 2 — `.pkg` build, signing & notarization

`PKG/build-pkg.sh` orchestrates the **whole** pipeline — Release build → wrap + sign the daemon
bundle (via `Support/build-serberusd-bundle.sh`) → sign CLI, PAM module and SerberusAuth plugin → assemble payload →
`pkgbuild` → `productsign` → `notarytool submit --wait` → `stapler staple` → verify — driven by
environment variables.

### One-time: store notary credentials

Use an **app-specific password** ([appleid.apple.com](https://appleid.apple.com) → Sign-In &
Security → App-Specific Passwords) or an App Store Connect API key:
```bash
xcrun notarytool store-credentials serberus-notary \
  --apple-id you@example.com --team-id YOURTEAMID
# paste the app-specific password when prompted
```

### Build + sign + notarize in one run

```bash
DEVELOPMENT_TEAM="YOURTEAMID" \
SIGNING_IDENTITY="Developer ID Application: Your Name (YOURTEAMID)" \
PROVISION_PROFILE="$HOME/serberusd.provisionprofile" \
INSTALLER_IDENTITY="Developer ID Installer: Your Name (YOURTEAMID)" \
NOTARY_PROFILE="serberus-notary" \
  PKG/build-pkg.sh
```
- `SIGNING_IDENTITY` is **required**. `PROVISION_PROFILE` is required for the exec gate (`ESF=on`,
  the default when a profile is given); leave it out, or set `ESF=off`, to build without Endpoint
  Security. The package records `execGate` (`enabled` or `disabled`) in `version.plist`.
- `DEVELOPMENT_TEAM` can be left out when `Config/Local.xcconfig` sets it. It must be the same team
  as the signing identity and the profile.
- Omit `INSTALLER_IDENTITY` → unsigned installer `PKG/build/Serberus-<version>.pkg`. Omit
  `NOTARY_PROFILE` too: with `NOTARY_PROFILE` set and no signed installer, the build fails
  ("Cannot notarize").
- Omit `NOTARY_PROFILE` → build + sign only; the script prints the one-time `notarytool
  store-credentials` setup and asks you to re-run with `NOTARY_PROFILE` set.

Output: `PKG/build/Serberus-<version>-signed.pkg` (the version comes from the `VERSION` file), notarized + stapled, verified with
`stapler validate` + `spctl -a -vvv -t install` (expect `source=Notarized Developer ID`).

### What it runs under the hood (for debugging)

1. `xcodebuild` builds `serberusd`, `serberus`, `pam_serberus` and the `SerberusAuth` plugin
   (Release, unsigned) into `.build/xcode`.
2. `Support/build-serberusd-bundle.sh` wraps `serberusd` in the signed `serberusd.app` (profile +
   the 3 entitlements, rendered for your team).
3. `PKG/build-pkg.sh` itself signs `serberus`, `pam_serberus.so` and `SerberusAuth.bundle` in the
   payload (Developer ID + Hardened Runtime + secure timestamp, with explicit identifiers
   `com.herojoneslabs.serberus.cli` and `com.herojoneslabs.serberus.pam`; the plugin keeps its
   bundle ID and carries no entitlements). It also puts `uninstall.sh` and `pam-lib.sh` in the
   payload, at `/Library/Application Support/Serberus/`.
4. `pkgbuild` → component pkg → `productsign --sign "Developer ID Installer: …"` → signed installer.
5. `xcrun notarytool submit … --keychain-profile serberus-notary --wait` → `xcrun stapler staple`.

If notarization is **Invalid**, read the log (most often a binary missing hardened runtime, or an
unsigned nested item):
```bash
xcrun notarytool log <submission-id> --keychain-profile serberus-notary
```

### Notes

- **Notarization vouches for the ES entitlement.** On end-user Macs the profile need not be installed
  and SIP need not be disabled — the stapled notarization ticket authorizes the restricted entitlement.
- The daemon **bundle's** notarization is validated as part of the pkg submission (notarytool
  recurses into the payload), so the embedded provisioning profile + entitlements must be correct
  before submitting.
- Sources: Apple "Signing a daemon with a restricted entitlement"; Apple Developer Forums
  [thread 673190](https://developer.apple.com/forums/thread/673190),
  [thread 712570](https://developer.apple.com/forums/thread/712570).
