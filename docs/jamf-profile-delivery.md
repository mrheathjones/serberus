# Getting Serberus rule profiles into Jamf Pro

Serberus authors policies locally and delivers them as **computer-level**
(`System`-scoped) configuration profiles in seven managed preference domains:

| Domain | Carries |
| --- | --- |
| `com.herojoneslabs.serberus.rules` | the compiled rule set (JSON under `rules_*` keys) |
| `com.herojoneslabs.serberus.config` | daemon enforcement mode + PAM break-glass (+ `commanderPublishEnabled`: admin-console gate that reveals Commander's "Publish to Jamf" for rule policies — off by default because API-published profiles render blank in the console) |
| `com.herojoneslabs.serberus.jit` | just-in-time local-admin policy |
| `com.herojoneslabs.serberus.prompts` | the elevation prompt: button labels, branding, minimum justification length, menu bar top-rules count, audit recipient label |
| `com.herojoneslabs.serberus.notify` | how many days of decision logs to keep (`logRetentionDays`). The domain keeps its original name; its Jamf schema is titled "Serberus — Log retention". |
| `com.herojoneslabs.serberus.appmanagement` | Install and Uninstall with Serberus: on/off, and which publishers may be installed |
| `com.herojoneslabs.serberus.debug` | opt-in per-device debug telemetry (scope only while debugging) |

Serberus reads only computer-level profiles: the root-owned
`/Library/Managed Preferences/<domain>.plist` they write. **User-level
profiles are ignored**, and so is a value set locally with `defaults write`.
If you delivered any Serberus domain as a user-level profile, deliver it as a
computer-level profile instead. That includes `commanderPublishEnabled`,
which Commander reads from a computer-level config profile on the admin's Mac.
Jamf custom schemas for each domain are in
[`Support/jamf-schemas/`](../Support/jamf-schemas/), and sample profiles in
[`Support/sample-profiles/`](../Support/sample-profiles/README.md).

**Use one profile per domain.** macOS merges computer-level profiles that
set the same domain key by key, and the last one applied wins, so two
profiles that both carry a domain can leave a mix of their values. On a test
Mac, a config profile that also carried
`com.herojoneslabs.serberus.appmanagement` made `publisherScope` flip
between `allowlist` and `any` as the profiles were reapplied. Deliver each
domain in one profile. Where a domain is split on purpose, each profile must
set different keys: the enrollment schema below sets only `sudoEnrollment`,
and rule profiles carry their own `rules_*` keys.

Changes apply without restarting anything. The daemon re-reads every domain
about every 30 seconds, and re-reads the config domain as soon as its plist
changes.

The prompt timeout is not in the prompts domain. It is `promptTimeoutSeconds`
in the config domain, and the daemon caps it at 60 seconds. Whether a prompt
asks for a reason is set on each rule (`requireJustification`).

The config domain has a second schema,
`com.herojoneslabs.serberus.config.enrollment.json`. It carries only
`sudoEnrollment`, so you can scope enrollment as its own profile (for example
per device, with `$USERNAME`) and keep the main config profile org-wide. Only
one profile may set `sudoEnrollment`. If two profiles set it, macOS keeps one
and drops the other without warning, so leave it unset in the main config
profile when you use the enrollment schema.

## Whether the console shows the payload (important)

Jamf Pro's GUI only *renders* a custom-settings payload when Jamf **builds** it —
i.e. through **Application & Custom Settings** (Upload File or Custom Schema), or
when the profile is **signed**. When you **upload or API-push a whole
`.mobileconfig`** (even one wrapped in `com.apple.ManagedClient.preferences`),
Jamf's importer *stores and deploys it correctly but shows no payloads in the
console* — a long-standing Jamf limitation, not a Serberus bug. So:

| How it reaches Jamf | Deploys? | Renders in console? |
| --- | --- | --- |
| Save `.mobileconfig` → *Configuration Profiles → Upload* | ✅ | ❌ (Jamf importer hides it) |
| **Publish to Jamf** (API) | ✅ | ❌ (same importer path) |
| Save `.plist` → *Application & Custom Settings → Upload File* | ✅ | ✅ (Jamf builds it) |
| **Custom Schema** (build/edit in Jamf) | ✅ | ✅ (Jamf builds it) |

Serberus still emits the `com.apple.ManagedClient.preferences` (MCX
`Forced`/`mcx_preference_settings`) shape, and the on-device
`/Library/Managed Preferences/<domain>.plist` is byte-identical across all
paths — so enforcement is the same regardless. If you need the **console to show
the payload**, use one of the two Application & Custom Settings paths below.

## Five ways to author / deliver rules

### From Serberus Commander (Policies → policy card, or the Details editor)

1. **Save `.mobileconfig`** — the whole profile. *Configuration Profiles →
   Upload*. Deploys; does not render in the console.
2. **Save `.plist`** — the flat settings dict
   (`com.herojoneslabs.serberus.rules.plist`). Jamf → new profile →
   *Application & Custom Settings → Upload File*, preference domain
   `com.herojoneslabs.serberus.rules`. **Renders + editable** (Jamf builds the
   MCX payload). Multiple such profiles union per-domain on the device.
3. **Publish to Jamf** — creates or updates the profile through the Jamf API.
   It needs a complete Jamf connection in Settings **and**
   `commanderPublishEnabled = true` in a computer-level
   `com.herojoneslabs.serberus.config` profile scoped to *this admin Mac*.
   Author that profile in Settings → Daemon configuration → "Allow Serberus
   Commander to publish rules directly to Jamf", and deliver it through Jamf;
   only the managed value counts, a local `defaults write` does not. Until it
   lands, Commander hides the Publish buttons on the policy card, in Edit
   Policy and in the Export sheet, and the Export sheet's guide lists
   "Publish to Jamf (off on this Mac)" with the key name. The profile is
   matched by the name `Serberus — <policy id>` (the *stable id*, so a
   display-name rename still updates in place). Deploys; **does not render in
   the console**: the rule enforces, but nobody can read or modify it there.
   For rules other engineers must be able to edit in Jamf, use way 4.
4. **Save Jamf Schema** — the **console-editable** export. Writes
   the shipped Custom Schema (`Support/jamf-schemas/com.herojoneslabs.serberus.rules.json`)
   with `__preferencedomain` set to a **per-policy sub-domain**
   (`com.herojoneslabs.serberus.rules.<policy-slug>`) and the form **pre-filled**
   with the policy's compiled rules (as the properties' `default` values).
   Jamf → new profile → *Application & Custom Settings → External Applications →
   Add → Custom Schema* → paste/upload the JSON → the domain is pre-filled, the
   rules appear as rows in the form → scope and save. **Renders + fully
   editable by anyone with console access.** Generated by `JamfRulesSchema`
   (PrivMgrCore) as the exact inverse of the daemon's native reader
   (`Rule.fromManagedDictionary`), so the form shows precisely what the daemon
   enforces; a test keeps the embedded template identical to the Support file.
   **One owner per policy:** a policy delivered as a schema should NOT also be
   published from Commander (both compose on the device and edits diverge).
   Jamf Pro pre-populates the `rules` rows from the schema's `default`, so the
   uploaded form opens with the policy's rules filled in. The form is
   **type-aware**: an authorization-right-only policy
   carries just `id`, `type` (locked to *Authorization right*), `action`,
   `description`, `priority`, `authURI`, `appTeamID`, `appBundleID` — the sudo fields (command path, match
   type, argument regex) and the elevation / justification /
   grant-duration / cache / identity-pin fields are pruned, because the
   AuthorizationDB projection enforces allow/deny on the right only and would
   never use them; a sudo-only policy drops `authURI`, `appTeamID` and `appBundleID` and locks
   `type` to *Sudo command*; a mixed policy keeps the full 18-field form. Rules edited in Jamf
   bypass Commander's validation / simulator, exactly like way 5.

   `appTeamID` and `appBundleID` stay in the schemas so existing profiles
   still parse, but they are ignored in 0.9.0: per-app rules are disabled,
   the daemon logs such a rule as skipped, and Commander won't export
   one. See [authuri-identity-scoped-rules.md](authuri-identity-scoped-rules.md#disabled-in-090).

   An `allow` on an authorization right has no elevation choice: the user
   unlocks the right with their own password, and no Serberus prompt is shown.
   So the authorization-right schemas carry no `elevationType`, and Commander
   hides "Ask first" for a rule that matches only authorization rights. The
   rule and JIT `notify` fields are gone too (nothing ever read them); an
   older profile that still carries them keeps working. The config schema
   pre-fills `enforcementMode` with `monitor`.

The `.mobileconfig` and the `.plist` always carry byte-identical rules — the
generator validates and encodes both from the same compiled profiles.

### Directly in Jamf (Custom Schema)

5. **Build rules inside Jamf** — Jamf → new profile → *Application & Custom
   Settings → External Applications → Custom Schema*, paste
   `Support/jamf-schemas/com.herojoneslabs.serberus.rules.json`, preference
   domain `com.herojoneslabs.serberus.rules`. Jamf renders an **add-rows form**
   for sudo commands and authorization rights. **Renders + fully editable.**

   The daemon reads this **native** form (a `rules` array of flat rule objects)
   *alongside* the `rules_*` JSON strings from ways 1–3, so all authoring
   methods compose on-device. A rule missing its `id`, `type`, `action`, or its
   type's match target (`commandPattern` for sudo unless `matchType` is `any`;
   `authURI` for authuri) is **dropped with a log finding** — a half-filled Jamf
   row never becomes an allow-anything rule.

   **Only one profile per domain may carry the `rules` array.** macOS keeps
   one value per key, so with two such profiles on the same domain it silently
   keeps one array and drops the other, and nothing is logged. If the dropped
   one held your deny rules, those commands are no longer denied. Give each
   schema-authored profile its own sub-domain instead
   (`com.herojoneslabs.serberus.rules.<suffix>`, with the schemas
   `…rules.sudo.json` and `…rules.authuri.json` in `Support/jamf-schemas/`);
   the daemon reads the base domain and every sub-domain.

   Note: rules authored directly in Jamf bypass Serberus's Policy Builder
   validation, conflict detection, and Decision Simulator — the daemon still
   validates structurally and logs findings, but the app-side safety checks
   don't run. Authoring in Serberus Commander (ways 1–4) keeps those.

## Sample artifacts

`Support/sample-profiles/` ships ready-made copies of both shapes (validated by
`SampleArtifactTests`; see its [README](../Support/sample-profiles/README.md)):

- `rules_sudo_test.mobileconfig`, `rules_authuri_test.mobileconfig`,
  `rules_sudo_1to1.mobileconfig` — MCX-wrapped, upload-as-is.
- `com.herojoneslabs.serberus.rules.plist` — the flat settings plist for the
  *Application & Custom Settings → Upload File* flow.
