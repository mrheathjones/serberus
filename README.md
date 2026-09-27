# Serberus

A native macOS privilege-management system for Apple Silicon Macs managed with
Jamf Pro. Serberus lets standard users do specific privileged tasks without
being made administrators: run curated `sudo` commands, use specific System
Settings rights, and request time-limited admin. All of it is governed by
policy delivered as MDM configuration profiles. It is macOS-native and
Jamf-first, and aims to cover the core of what tools like BeyondTrust EPM and
Delinea Privilege Manager do. It is for Mac admins who run Jamf Pro and
want their users to work as standard users, and who can build, sign and test
it themselves.

> Security, reliability, recoverability, and auditability take priority over
> convenience. When in doubt, Serberus fails closed.

> [!WARNING]
> **Status: alpha, for lab and pilot use.** Serberus is at version 0.9.0 and
> has not been through an independent security audit, and it is maintained
> by one person. There are no prebuilt packages. Jamf Connect JIT and
> Install with Serberus are experimental: each has been run end to end on
> one test Mac only, on macOS 26.7 (see
> [SECURITY.md](SECURITY.md#verified-live)). Use
> Serberus on Macs you can afford to break, and don't rely on it as your only
> control on production Macs yet.

> [!IMPORTANT]
> **Serberus can lock everyone out of `sudo`.** In `enforce` mode the PAM
> module denies every `sudo` that no rule allows, and denies all of them if the
> daemon is down. Only the accounts in `pamBypass`, and a JIT admin inside
> their window, keep native `sudo`. So:
>
> 1. Deliver a configuration profile with a working `pamBypass` account
>    **before** installing any package that includes the PAM module.
> 2. Start in `monitor` or `audit` mode.
>
> If you do get locked out, sign in as a `pamBypass` account or install the
> uninstall package. The kill switch (`daemonEnabled = false`) helps only
> while the daemon is running, since the daemon removes the sudoers drop-in
> that keeps `sudo` gated. As a last resort, boot into macOS Recovery and
> delete the `pam_serberus` line from `/etc/pam.d/sudo_local` on the data
> volume, and delete `/etc/sudoers.d/serberus` too, or enrolled users keep
> `sudo` for the listed commands with any arguments. See
> [SECURITY.md](SECURITY.md#deploying-safely).

## Before you start

Serberus runs as root, sits in the `sudo` PAM stack, and rewrites the macOS
AuthorizationDB. Read [SECURITY.md](SECURITY.md) (its summary, the threat
model under "Security model", and [Deploying safely](SECURITY.md#deploying-safely))
before deploying it anywhere that matters.

Serberus has three enforcement modes, set with `enforcementMode`:

| Mode | What it does |
|---|---|
| `monitor` | Observes only. `sudo` and authorization rights behave natively, and nothing is evaluated. |
| `audit` | Evaluates each `sudo` request and logs what it would have decided, then lets it through. Rights stay native. |
| `enforce` | Applies the policy: curated `sudo` for enrolled users, the AuthorizationDB rules, and fail-closed `sudo`. |

`monitor` and `audit` change nothing on the Mac: no sudoers drop-in, and the
AuthorizationDB stays native. Start in one of them.

- **You build and sign it yourself.** There are no prebuilt releases yet.
  Serberus components only trust binaries signed by the same Apple Developer
  team, so every component must be signed by your team.
- **The Endpoint Security exec gate is optional.** It uses
  `com.apple.developer.endpoint-security.client`, which Apple grants only on
  request. Curated `sudo`, AuthorizationDB rules and JIT admin don't use it.
  The production package (`PKG/build-pkg.sh`) builds with it when you give it
  an Endpoint Security provisioning profile, and without it otherwise
  (`ESF=off`), in which case the exec gate is off and `serberus status` says
  so. The gate itself is narrow: it only stops a standard user from running a
  binary as root while another user holds a grant for that binary. It is not
  a general block on binaries. See
  [docs/esf-provisioning-and-notarization.md](docs/esf-provisioning-and-notarization.md#step-7--verify-esf-is-live).
- **Know what it changes.** [docs/footprint.md](docs/footprint.md) lists what
  Serberus changes on a Mac (files, launchd jobs, `sudo` and AuthorizationDB
  changes, keychain items, group changes), what talks to the network (the
  daemon doesn't), and how to verify the installed binaries.
- **Jamf Pro only.** Serberus is built and tested with Jamf Pro. Commander
  lists Microsoft Intune, Mosyle, and Kandji in its settings, but only Jamf
  Pro is implemented.

## Requirements

- macOS 26 or later on Apple Silicon. Serberus is built for that platform and
  was tested only there. Earlier macOS releases and Intel Macs were not
  tested and are not supported.
- Xcode 26 or later
- An Apple Developer account, to sign and install (the tests don't need one)
- Jamf Pro, to deploy

## Quick start

Everything builds from one Xcode project. There are no packages to install:

```bash
open Serberus.xcodeproj
```

Run the full test suite from Xcode (⌘U with the **AllTests** scheme) or the
terminal. No team or developer account is needed:

```bash
xcodebuild -project Serberus.xcodeproj -scheme AllTests -destination 'platform=macOS' test
```

That runs about 2,000 tests. CI (`.github/workflows/ci.yml`) runs them, the
installer shell tests in `PKG/tests/`, and a Release build of every target
on each push to `main` and each pull request.

To build signed apps, set your Apple Developer team once in a local file that
git ignores:

```bash
cp Config/Local.xcconfig.example Config/Local.xcconfig
```

Then set `DEVELOPMENT_TEAM` in `Config/Local.xcconfig`. See
[CONTRIBUTING.md](CONTRIBUTING.md#building) for details.

The quickest way to explore is the **SerberusCommander** scheme: its Decision
Simulator runs the daemon's rule engine in-process, so it works without
installing anything.

## Schemes

| Scheme | What it builds |
|---|---|
| **SerberusCommander** | Commander, the admin app. Authors rule profiles, runs the Decision Simulator, exports `.mobileconfig` files, and can publish to Jamf (off by default: profiles published through the API show blank in the Jamf console). |
| **SerberusSentinel** | Serberus Sentinel, the user-facing app in `/Applications`, with My Activity, My Rules, and Intel (diagnostics) tabs. It embeds the Finder extension that adds **Install/Uninstall with Serberus**. |
| **SerberusSentinelAgent** | The hidden menu-bar agent. Registers with the daemon and shows elevation prompts. |
| **SerberusGuardian** | A watchdog that offers to relaunch the Sentinel agent if a user quits it. |
| **serberusd** | The root LaunchDaemon, the only policy authority. |
| **serberus** | The command-line tool: `list`, `status`, `grants`, `version`, `simulate`, `help`. |
| **SerberusAuth** | The SecurityAgent authorization plugin built for per-app AuthorizationDB rules. Per-app rules are disabled in 0.9.0, so the plugin is installed but denies every request (see [docs/authuri-identity-scoped-rules.md](docs/authuri-identity-scoped-rules.md#disabled-in-090)). |
| **SerberusAuthProbe** | The research spike behind the authorization plugin, kept in `extras/`. Not part of the product. |
| **AllTests** | Every test bundle. |

The PAM module (`pam_serberus.so`) has no shared scheme (Xcode creates one
automatically). Build it with `Support/build-pam.sh --build`, with
`SIGNING_IDENTITY` set to your Apple Development identity: without one the
module is signed ad-hoc, which is enough for CI but not for an install (see
[Installing on a test Mac](#installing-on-a-test-mac)).

## Architecture at a glance

- **Daemon (`serberusd`).** The only trusted policy authority. Runs as root,
  evaluates policy, and issues and revokes grants. Validates every XPC caller
  by audit token, never PID: Serberus's apps must be signed by the daemon's
  own team, and PAM requests must come from Apple's `sudo` running as root.
- **PAM module (`pam_serberus.so`).** Runs inside `sudo`, applies the
  break-glass bypass, then asks the daemon about the exact command sudo will
  run. It accepts an answer only from a root daemon signed by its own team. In
  `enforce` mode it fails closed if the daemon is unreachable. See
  [SECURITY.md](SECURITY.md#when-sudo-behaves-natively) for when `sudo`
  behaves natively instead.
- **Authorization plugin (`SerberusAuth`).** Runs inside SecurityAgent. It
  was built to check which app is requesting an AuthorizationDB right, but
  the app's identity comes from a value the caller can forge, so
  per-app rules are disabled in 0.9.0 and the plugin denies every request.
  See [SECURITY.md](SECURITY.md#known-limitations).
- **Sentinel.** The menu-bar agent shows daemon state, active grants, and
  elevation prompts. The full app shows a user's activity, rules, and
  diagnostics. Neither evaluates policy.
- **Commander.** The admin app. Authors and simulates policy and exports or
  publishes it to Jamf. Distributed separately from the endpoint components.

See [docs/SERBERUS-OVERVIEW.md](docs/SERBERUS-OVERVIEW.md) for the full system
map (a diagram of who talks to whom), the `sudo` decision flow, and the
safety design, and
[docs/README.md](docs/README.md) for the other docs.

## Project layout

```
Serberus.xcodeproj        The project (open this)
project.yml               XcodeGen spec that generates the project
Config/                   Signing settings (your team goes in Local.xcconfig)
Sources/
  PrivMgrCore/            Shared engine: rules, grants, logging, Jamf, XPC
  SerberusXPCShim/        C shim: audit-token SPI and shared XPC keys
  SerberusUI/             Shared icons and design system
  SerberusDaemonCore/     Daemon logic: state machine, PAM evaluation, AuthorizationDB
  serberusd/              Daemon entry point
  pam_serberus/           PAM module (C)
  SerberusAuth/           Authorization plugin
  PolicyBuilderCore/      Commander view models
  SerberusCommander/      Commander app
  SerberusSentinelCore/   Sentinel view models
  SerberusSentinelShared/ Code shared by the Sentinel app and agent
  SerberusSentinel/       Sentinel app
  SerberusSentinelAgent/  Sentinel menu-bar agent
  SerberusFinderExtension/ Finder extension
  SerberusGuardian/       Sentinel watchdog
  SerberusIntelCore/      Diagnostics and log-capture logic
  SerberusCLICore/        CLI logic
  SerberusCLI/            CLI entry point
Tests/                    One test bundle per *Core library, plus PAM config tests
Support/                  Files the build and installers use (see below)
PKG/                      Installer packages: pre/postinstall, uninstall, build scripts
docs/                     Design and reference docs (index: docs/README.md)
extras/                   Side tools that aren't part of the product (see extras/README.md)
```

Shared code is built as **static libraries**, so the apps and command-line
tools are self-contained binaries with nothing to embed or deploy.

`Support/` holds what the build and the installers use: the LaunchDaemon and
LaunchAgent plists, entitlements, the `sudo_local` template, the developer
scripts (`build-pam.sh`, `serberusd-devtool.sh`, `build-serberusd-bundle.sh`
and the libraries they share), the Jamf schemas, sample profiles and rules,
and the Jamf extension attributes. `Support/Generated/` holds the Info.plists
that `xcodegen generate` writes for the targets that need one; they are
committed because the committed Xcode project refers to them, so commit them
together with `project.yml`.

## Installing on a test Mac

The daemon, PAM module, and authorization plugin need root to install. Running
the apps doesn't install them. For local testing:

- `sudo Support/serberusd-devtool.sh --verify-cycle` installs, restarts, and
  uninstalls the daemon. Build it in Release first:
  `xcodebuild -project Serberus.xcodeproj -scheme serberusd -configuration Release -derivedDataPath .build/xcode CODE_SIGNING_ALLOWED=NO build`.
  The devtool signs the binary itself. It refuses to uninstall the daemon while
  the PAM module is wired into `sudo_local`, because `sudo` would then fail
  closed.
- The PAM module is built and installed in two steps:

  ```bash
  # 1. As yourself (not with sudo). Writes ~/serberus-live/pam_serberus.so;
  #    LIVE_DIR or OUTPUT changes where.
  SIGNING_IDENTITY="Apple Development: Your Name (CERTID)" ./Support/build-pam.sh --build

  # 2. Install the module built in step 1. It doesn't build anything.
  sudo SIGNING_IDENTITY="Apple Development: Your Name (CERTID)" ./Support/build-pam.sh --install
  ```

  sudo drops `SIGNING_IDENTITY` from the environment, so pass it on the `sudo`
  line as shown, and pass `LIVE_DIR` or `OUTPUT` the same way if you set one in
  step 1. Use the identity the installed daemon is signed with. The install
  refuses unless the daemon is running and has a Team ID, the module is signed
  by that same team, and the break-glass preflight passes. The devtool's
  default ad-hoc signature won't do: install the daemon from a test package, or
  sign it yourself first and install it with the devtool's
  `SKIP_DAEMON_SIGN=1`. `--force` skips those checks and is for development
  only; it never skips the check that the module's folders are root-only. The
  install creates `/etc/pam.d/sudo_local` if there isn't one, and leaves an
  existing one alone, printing the line to add. See
  [docs/SerberusPAM.md](docs/SerberusPAM.md#build--install-developer).
- The package scripts in `PKG/` build installers. See
  [PKG/README.md](PKG/README.md) for which one to use: the combined test
  package (`SerberusTest-<version>.pkg`) installs everything on a test Mac,
  the core test package (`SerberusCore-<version>.pkg`) installs the daemon,
  PAM module, plugin and CLI without the Sentinel apps, and the production
  package (`PKG/build-pkg.sh`, which writes
  `PKG/build/Serberus-<version>-signed.pkg`) needs a Developer ID identity.

The daemon only writes its sudoers drop-in once the PAM module is correctly
wired. Until then it reports `degraded (pam_not_wired)` and standard users get
no extra `sudo` access.

A production install needs a Developer ID Application identity, Hardened
Runtime, and notarization. Apple's Endpoint Security entitlement is optional:
without it the package is built with the exec gate off. The production
package installs no Sentinel apps: build those separately with
`SENTINEL_WITH_ENTITLEMENT=1` and a Developer ID identity (see
[PKG/README.md](PKG/README.md#production-sentinel-package)). The test packages
are for lab Macs.

To deploy with Jamf Pro, follow the checklist in
[docs/SERBERUS-OVERVIEW.md](docs/SERBERUS-OVERVIEW.md#94-deploy-with-jamf-pro).
The profiles in `Support/sample-profiles/` name the maintainer's team
(`M5RQTPC7A2`) in their code requirements; replace it with yours. Its
[README](Support/sample-profiles/README.md) says which file is for what.

### Components, bundle IDs and packages

For PPPC, login-item and other payloads that name a Serberus component:

| Component | Bundle ID or signing identifier | Installed at | Package |
|---|---|---|---|
| Daemon (`serberusd`) | `com.herojoneslabs.serberus.daemon` | `/Library/PrivilegedHelperTools/serberusd.app` (production) or `/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon` (test) | Production, or `SerberusCore` |
| PAM module | `com.herojoneslabs.serberus.pam` | `/usr/local/lib/pam/pam_serberus.so` | Production, or `SerberusCore` |
| Authorization plugin | `com.herojoneslabs.serberus.authplugin` | `/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle` | Production, or `SerberusCore` |
| CLI | `com.herojoneslabs.serberus.cli` | `/usr/local/bin/serberus` | Production, or `SerberusCore` |
| Serberus Sentinel (the app) | `com.herojoneslabs.serberus.intel` | `/Applications/Serberus Sentinel.app` | `SerberusSentinelApp` |
| Finder extension | `com.herojoneslabs.serberus.intel.finderext` | inside Serberus Sentinel | `SerberusSentinelApp` |
| Sentinel menu-bar agent | `com.herojoneslabs.serberus.sentinel` | `/Library/Application Support/Serberus/Serberus Sentinel Agent.app` | `SerberusSentinelApp` |
| Guardian | `com.herojoneslabs.serberus.guardian` | `/Library/Application Support/Serberus/Serberus Guardian.app` | `SerberusSentinelApp` |
| Commander | `com.herojoneslabs.serberus.commander` | `/Applications/Serberus Commander.app` | `SerberusCommander` |

The Sentinel app keeps the `.intel` bundle ID, and the agent is the one with
`.sentinel`. The core and production packages install no Sentinel apps; the
combined test package includes both halves, and a production Mac gets them
from a Developer ID build of `SerberusSentinelApp`.

## Changing targets

The project is generated from `project.yml` with
[XcodeGen](https://github.com/yonaskolb/XcodeGen). You only need it to add or
change targets, because the `.xcodeproj` is committed:

```bash
brew install xcodegen
xcodegen generate
```

## How Serberus is built

Serberus was written by its maintainer with substantial help from an AI coding
assistant (Anthropic's Claude), which is why commits carry a
`Co-Authored-By: Claude` trailer. The maintainer reviews every change. The
repository starts at the 0.9.0 release; the development history before it isn't
published. Before publication the code also went through several rounds of review,
themselves AI-assisted, covering security, accuracy and sensitive content.
None of that replaces an independent human security audit; see the status note
above.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) to build, test, and submit changes,
and [SUPPORT.md](SUPPORT.md) for where to ask questions.
Report security vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), not in public issues.

## License

Serberus is licensed under the [Apache License 2.0](LICENSE).
Copyright 2026 Heath Jones.
