# Sample profiles

Ready-made configuration profiles for testing Serberus with Jamf Pro. Most
files start with a comment that explains them in more detail; the table below
describes every file.

Serberus reads only **computer-level** profiles. Scope every Serberus profile
to computers, not users: a user-level profile is ignored. See
[docs/jamf-profile-delivery.md](../../docs/jamf-profile-delivery.md) for how
each shape behaves in Jamf.

## Before you use them

- **Replace the maintainer's Team ID.** `M5RQTPC7A2` is the maintainer's
  Apple Developer team. The PPPC profiles and the managed login items profile
  name it; replace it with the team that signs your build. The managed
  background items profile matches by label prefix, and names the team only
  in a commented-out alternative rule.
- **Replace the placeholders.** `REPLACE_WITH_A_BREAK_GLASS_ADMIN` must become
  a real local admin account, spelled exactly as its short name (case
  included). In the 1:1 profiles, Jamf fills in `$USERNAME`; outside Jamf, put
  a real short name there.
- **Replace the example values.** `serberus-prompts-branding.mobileconfig`
  sets `brandTitle` to the placeholder "Serberus". Users see it on every
  approval prompt, so put your organisation's name there.
  `serberus-config-enforce-messages.mobileconfig` enrols a user named
  `standarduser`. Change both to your own values.
- **Start in `monitor` mode**, and always keep a working `pamBypass`. See
  [SECURITY.md](../../SECURITY.md#deploying-safely).
- **An `allow` on an authorization right needs a native admin gate.** The
  daemon applies it only when macOS natively asks for an admin password for
  that right (Date & Time and Printing do). Rights such as
  `system.print.admin` or `system.preferences.location` are refused and left
  native. See
  [SECURITY.md](../../SECURITY.md#authorization-rights).
- If you copy a profile to make a second one, give the copy new
  `PayloadUUID` values (`uuidgen`).

## Which file is which

### Config domain (`com.herojoneslabs.serberus.config`)

| File | Mode | Use |
|---|---|---|
| `com.herojoneslabs.serberus.config.plist` | `monitor` | Break-glass starter config, as a flat plist. Commented examples show the grant-duration keys. |
| `serberus-config-breakglass.mobileconfig` | `monitor` | The same break-glass config as a full profile. Deliver it before any package that includes the PAM module. |
| `serberus-config-monitor.mobileconfig` | `monitor` | Monitor mode with the `admin` group as break-glass. |
| `serberus-config-enforce-messages.mobileconfig` | `enforce` | Enforce mode with custom `sudo` deny and allow messages. |
| `serberus-config-1to1-username.mobileconfig` | `enforce` | Enforce mode for a Mac with one standard user, enrolled in curated `sudo` through Jamf's `$USERNAME` variable. |
| `serberus-config-1to1-username.plist` | `enforce` | The same values as a flat plist. |

### Rules domain (`com.herojoneslabs.serberus.rules`)

| File | Use |
|---|---|
| `com.herojoneslabs.serberus.rules.plist` | The `rules_sudo_test` and `rules_authuri_test` rule sets as a flat plist. |
| `rules_sudo_test.mobileconfig` | Test `sudo` rules: prompt for `/bin/echo`, allow `/usr/bin/true`, deny `/sbin/shutdown`. |
| `rules_authuri_test.mobileconfig` | Test authorization-right rules: deny Date & Time, allow Printing. |
| `rules_sudo_1to1.mobileconfig` | `sudo` rules for the 1:1 config, including a prompt for `jamf recon` (only `recon` as the first argument; later arguments aren't checked). |
| `rules_sudo_jamf.mobileconfig` | Lets an enrolled user run `sudo jamf recon` and `sudo jamf log` only. Like the other samples that name `jamf`, it names only the friendly path `/usr/local/bin/jamf`; for production, add the same rules for `/usr/local/jamf/bin/jamf` (see [Rule 1](../../docs/policy-authoring-symlinked-binaries.md#rule-1--author-both-the-friendly-and-resolved-paths)). |
| `serberus-rules-combined-native.mobileconfig` | One native `rules` array (the Jamf Custom Schema shape) with both rule types. |
| `serberus-rules-sudo-subdomain.mobileconfig` | A native `rules` array in the `.rules.sudo` sub-domain. |
| `serberus-rules-authuri-subdomain.mobileconfig` | A native `rules` array in the `.rules.authuri` sub-domain. Pair it with the sudo one. One rule names `system.preferences.dateandtime.changetimezone`, which a stock Mac doesn't define; the daemon checks it against the `system.` wildcard (a plain admin gate) and creates it. |

Rules apply only in `enforce` mode.

### Other domains and Apple payloads

| File | Use |
|---|---|
| `serberus-prompts-branding.mobileconfig` | Branding and button labels for the approval prompt (`com.herojoneslabs.serberus.prompts`). |
| `serberus-daemon-fda-pppc-test.mobileconfig` | Full Disk Access for the daemon the **test packages** install: the flat binary in `/Library/PrivilegedHelperTools`, Apple Development signed, matched by path. |
| `serberus-daemon-fda-pppc-production.mobileconfig` | Full Disk Access for the daemon the **production package** installs: `serberusd.app`, Developer ID signed, matched by bundle ID. |
| `serberus-managed-login-items.mobileconfig` | Marks Serberus's LaunchDaemon, LaunchAgents and Finder extension as managed login items, by Team ID. |
| `serberus-managed-background-items.mobileconfig` | The same, matched by launchd label prefix instead of Team ID. Use one of the two. |

The daemon needs Full Disk Access for the Endpoint Security exec-gate, and
for Install with Serberus to read items in TCC-protected folders such as
`~/Downloads` and `~/Desktop`. Without it, `sudo` and authorization-right
enforcement still work.

## `.plist` or `.mobileconfig`

- A **`.plist`** is the bare settings for one domain. In Jamf, create a profile
  and use *Application & Custom Settings → Upload File*, with the preference
  domain set to the domain above. Jamf builds the payload, so the console shows
  and can edit the values.
- A **`.mobileconfig`** is a whole profile. Upload it in *Configuration
  Profiles → Upload*. It deploys correctly, but for the Serberus domains Jamf's
  console shows the payload as blank.

`SampleArtifactTests` (in `Tests/PrivMgrCoreTests/`) checks these files on
every test run: they must parse, use native values in the config domain, pass
the daemon's rule reader, and have unique payload UUIDs.
