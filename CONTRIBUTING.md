# Contributing to Serberus

Thanks for your interest. Serberus is security software that runs as root and
changes how privilege works on a Mac, so contributions are held to a high bar
for correctness and safety. This guide explains how to build, test, and submit
changes.

**Found a security vulnerability?** Don't open an issue or pull request.
Follow [SECURITY.md](SECURITY.md) instead.

## Before you start

For anything larger than a small fix, open an issue first to discuss the
approach. It saves you from building something that can't be merged.

## Requirements

- An Apple Silicon Mac running macOS 26 or later (the only platform Serberus
  is built and tested for)
- Xcode 26 or later, selected as the active developer directory
  (Swift Testing needs full Xcode, not the Command Line Tools)

There are no third-party dependencies. Please keep it that way. A change that
adds a dependency needs a strong reason, discussed in an issue first.

## Building

Open the project and pick a scheme:

```bash
open Serberus.xcodeproj
```

### Set your team

Signed builds use your own Apple Developer team. Set it once, in a local file
that git ignores:

```bash
cp Config/Local.xcconfig.example Config/Local.xcconfig
```

Then set `DEVELOPMENT_TEAM` in `Config/Local.xcconfig` to your 10-character
Team ID. Xcode reads it, and so do `Support/build-serberusd-bundle.sh`,
`Support/serberusd-devtool.sh`, and the Commander, Sentinel app, and Auth URI
Browser package scripts. `PKG/build-pkg.sh` and `PKG/build-combined-pkg.sh`
use it through the scripts they call. The package scripts that sign code
also take the signing identity in the `SIGNING_IDENTITY` environment
variable (and `INSTALLER_IDENTITY` to sign the package itself); see
[PKG/README.md](PKG/README.md). To set the team for a single build instead:

```bash
xcodebuild -project Serberus.xcodeproj -scheme SerberusCommander DEVELOPMENT_TEAM=ABCDE12345 build
```

Don't set a team in Xcode's **Signing & Capabilities** pane: that writes it
into the project file.

Serberus components trust each other only when one team signs them all. The
daemon reads its own team from its code signature and rejects app callers
signed by any other team, so build and sign every component with the same
team. (The PAM module is the exception on the daemon's side: it runs inside
`sudo`, so the daemon checks that its caller is Apple's `/usr/bin/sudo` running
as root instead. The module, in turn, accepts replies only from a daemon signed
by its own team, and the installers refuse a module or plugin from another
team. The daemon refuses a plugin from another team; it doesn't check the
module's signature.)

If you deploy your own build, the sample profiles in `Support/sample-profiles/`
name the maintainer's team (`M5RQTPC7A2`) in their code requirements. Replace
it with yours; see [Support/sample-profiles/README.md](Support/sample-profiles/README.md).

### The Endpoint Security entitlement

`serberusd` can use the `com.apple.developer.endpoint-security.client`
entitlement, which Apple grants only on request, for its exec gate. Without
your own approved entitlement you can build and unit-test everything, build
the test packages, and build the production package with `ESF=off` (see
[PKG/README.md](PKG/README.md#signing)); you can't produce a daemon that runs
with the Endpoint Security exec gate. `sudo`, AuthorizationDB enforcement and
JIT admin don't depend on the entitlement.

The `serberusd` Xcode target signs with no entitlements, so an Xcode-signed
daemon launches (without the exec-gate). The package scripts sign the daemon
themselves; see
[docs/esf-provisioning-and-notarization.md](docs/esf-provisioning-and-notarization.md#step-3--distribution-entitlements-all-three-are-required).

The entitlement comes with an explicit App ID for the daemon, and an App ID
can belong to only one developer team. `com.herojoneslabs.serberus.daemon` is
registered to the maintainer, so to ship your own Endpoint Security build you
must change the daemon's bundle ID: in `Sources/PrivMgrCore/BundleConfig.swift`,
`Support/build-serberusd-bundle.sh`, `project.yml` (the `serberusd` target's
`OTHER_CODE_SIGN_FLAGS`, then `xcodegen generate`), and the other files that
repeat it (the LaunchDaemon plist, the distribution entitlements, the PAM
module and the package scripts). The apps' bundle IDs are in `project.yml` and
`BundleConfig.swift`, if you register App IDs for them too.
[docs/esf-provisioning-and-notarization.md](docs/esf-provisioning-and-notarization.md#step-1--register-an-explicit-app-id-with-the-endpoint-security-capability)
lists the files.

## Testing

Every change needs tests, and the full suite must pass:

```bash
xcodebuild -project Serberus.xcodeproj -scheme AllTests -destination 'platform=macOS' test
```

Or press ⌘U in Xcode with the **AllTests** scheme selected.

If you change the installer shell logic (`PKG/Scripts/`, or any `PKG/build-*.sh`
script, including the core test package's `PKG/build-core-test-pkg.sh`), also
run the shell tests. They use temporary files only:

```bash
bash PKG/tests/test-pam-lib.sh
bash PKG/tests/test-sentinel-lib.sh
```

The tests don't need a team or an Apple Developer account, so you can run
them straight after cloning.

- Tests use **Swift Testing** (`import Testing`, `@Test`, `#expect`), not
  XCTest.
- Each `*Core` library has its own test bundle under `Tests/`. Put logic in a
  `*Core` library so it can be tested without a running daemon.
- Test fixtures must use synthetic identifiers only: no real usernames, serial
  numbers, hostnames, or Jamf URLs. Use values like `jdoe`,
  `example.jamfcloud.com`, and `ABCDE12345`.

### Testing the system components

The daemon, PAM module, and AuthorizationDB plugin need root to install, and a
mistake can break `sudo`. **Test them only on a machine you can afford to
break**, such as a macOS VM, and always configure a `pamBypass` break-glass
account first. See [SECURITY.md](SECURITY.md#deploying-safely).

## Changing targets

The Xcode project is generated from `project.yml` with
[XcodeGen](https://github.com/yonaskolb/XcodeGen). To add or change a target,
edit `project.yml` and regenerate:

```bash
brew install xcodegen
xcodegen generate
```

Commit both `project.yml` and the regenerated `Serberus.xcodeproj` (and
`Support/Generated/`, if it changed). Don't hand-edit the project file; your
change will be lost on the next regeneration.

## Changing the version

The product version lives in three places that must agree:

- the `VERSION` file at the repository root, which the package scripts read;
- `MARKETING_VERSION` in `project.yml` (then run `xcodegen generate`);
- `DaemonVersion.current` in `Sources/SerberusDaemonCore/DaemonPaths.swift`.

Change all three together, then run `xcodegen generate` so the committed
`Serberus.xcodeproj` carries the new `MARKETING_VERSION` too.
`PKG/tests/test-sentinel-lib.sh` fails if any of them, or the project file,
differs. The test packages keep their own package numbers for their receipts;
the core test package, like the production package, records the product
version in `version.plist`.

## Code guidelines

- **Swift 6** with strict concurrency. Don't silence concurrency diagnostics
  with `@unchecked Sendable` or `nonisolated(unsafe)` without a comment
  explaining why it's safe.
- **Fail closed.** When the daemon or PAM module can't reach a confident
  decision in `enforce` mode, the answer is deny. The only pass-throughs are
  the deliberate ones in [SECURITY.md](SECURITY.md#when-sudo-behaves-natively); don't add new ones.
- **Never log secrets.** Passwords, tokens, API keys, and client secrets must
  not reach any log. Route new logging through the existing redaction in
  `Sources/PrivMgrCore/Logging/Redaction.swift`.
- **Match the surrounding code.** Follow the naming, structure, and comment
  style of the file you're editing.
- **Shell scripts** use Bash and carry the script information header block
  used by the existing scripts in `PKG/` and `Support/`.

## Submitting a pull request

1. Fork the repository and create a branch from the default branch.
2. Make your change, with tests.
3. Run the full `AllTests` suite and confirm it passes.
4. Open a pull request that explains **what** changed and **why**. If the change
   affects enforcement, fail-closed behaviour, or the installer, say so
   explicitly and describe how you tested it.

Keep pull requests focused on one change. Large mixed pull requests are hard to
review safely.

The repository's pull request template (`.github/PULL_REQUEST_TEMPLATE.md`)
asks for these points, and the issue templates in `.github/ISSUE_TEMPLATE/`
cover questions, bug reports and feature requests. Security reports go through private
reporting instead.

GitHub Actions runs on every pull request and every push to `main`
(`.github/workflows/ci.yml`). It runs the full test suite and the installer
shell tests, checks every shell script with `bash -n`, and builds the product apps and
tools in the Xcode project plus the PAM module. It doesn't build the side
tools in `extras/` (such as Auth URI Browser and SerberusAuthProbe), and it
doesn't run ShellCheck.

## License

Serberus is licensed under the [Apache License 2.0](LICENSE). By submitting a
contribution, you agree that it's licensed under the same terms, as described
in section 5 of the license.
