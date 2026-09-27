# Identity-scoped authURI rules (per-app posture on a right)

## Disabled in 0.9.0

Per-app rules do nothing in Serberus 0.9.0. A rule with an App Identity definition (`appTeamID` + `appBundleID` on an authorization right) is ignored, and the right keeps its native definition for every caller.

**What was found.** The SerberusAuth plugin identified the requesting app from authd's `creator-audit-token` hint. authd copies the caller's `AuthorizationCreate` / `AuthorizationCopyRights` environment into the hints after it sets `client-pid`, `creator-pid`, `creator-audit-token` and the other process hints (`engine_authorize` in Apple's `engine.m`). A caller can therefore supply its own `creator-audit-token` and replace the real one. This was confirmed live on macOS 26.7: an unsigned program run by a standard user borrowed the identity of a running, root-installed Jamf Composer and got the pinned easier path (the user's own password) on `com.apple.ServiceManagement.blesshelper`.

**Why it is disabled.** Every check the plugin makes (signature, team, hardened runtime, bundle writability) is made on a process the caller chose. The pin is only as strong as the hint, and the hint is caller-controlled. The other process hints (`client-pid`, `creator-pid`) are set before the same merge, so they can't be trusted either. A fix needs an identity the caller can't supply.

**What happens to an existing pin profile.**

- The daemon composes nothing. It logs each pin once per reload: `authdb: rule '<id>' on '<right>' skipped: per-app (App Identity) rules are disabled in Serberus 0.9.0: the app's identity comes from a value the caller can forge; the right keeps its native definition`.
- A right an older build composed is restored to its native definition on the next reconcile (daemon start or policy reload), so upgrading removes the composition.
- The daemon stays healthy. A pin profile does not make it report `degraded`.
- The SerberusAuth plugin is still installed but denies every request (`MechanismInvoke: DENY … reason=per-app rules are disabled in this build`). A composed right that has not been restored yet falls through to its native branch.
- A plain `allow` on a root-equivalent right such as `blesshelper` is still skipped. Its log reason now ends "there is no per-app allow in this release".
- Commander reports each pin as a validation error (`app-identity-disabled`), which blocks export and direct publish. It no longer offers App Identity for a new definition. The Decision Simulator never matches a pin and says so in Warnings.
- The Jamf schema keeps the `appTeamID` / `appBundleID` fields so existing profiles still parse; their descriptions say they are ignored.

**What replaces it.** A design where the daemon decides from Endpoint Security authorization-petition events, which carry an identity the caller cannot forge, is planned for a later release.

The rest of this document describes the disabled feature. It is kept as a design reference and as the record of what was verified. Nothing below is active in 0.9.0.

---

**What was built (disabled in 0.9.0).** An identity-scoped rule lets one named app use an authorization right with the session owner's (or an admin's) password, while every other caller keeps the right's native rule. It is enforced by an authorization-plugin mechanism, `SerberusAuth:identity` in `SerberusAuth.bundle`, which ships in both the production package and the core test package. Before per-app rules were disabled, it was run end to end for `com.apple.ServiceManagement.daemons.modify` and `com.apple.ServiceManagement.blesshelper` on macOS 27, and for `blesshelper` again on macOS 26.7 in on-Mac testing on 2026-09-28 (Composer's own request was allowed with the user's own password); for `daemons.modify` on macOS 26 there is a capture of the request resolving, not a full run (see the [verification table](#verification-table--advisory-only-no-enforcement-gate)). Those runs used honest callers only; they did not test a caller that forges the creator hint. An earlier design that tried to do this with static rules doesn't work, and the reason is recorded [below](#the-static-approach-does-not-work-proved-on-macos-27).

## Live verification (macOS 27, standard user, before per-app rules were disabled)

| Case | Result |
|---|---|
| Composer → `blesshelper` (direct) | ALLOW, creator = client = `com.jamfsoftware.Composer` (483DWKW443) |
| Composer → `daemons.modify` (smd-mediated) | ALLOW, **creator = Composer, client `<unresolved>`** — the client is `/usr/libexec/smd`, so only the creator identifies the app |
| VS Code → `daemons.modify` | DENY by the mechanism, then **falls through to the native branch** (`is-root`, `is-admin-nonshared`, `authenticate-admin-nonshared`); standard user authenticated but is not an admin → `-60006`. Native behaviour intact. |
| Devin → `daemons.modify` | same as VS Code |
| Devin → `daemons.modify`, **admin account** | DENY by the mechanism, falls through, `is-admin-nonshared` → *does satisfy* → authenticated → **granted**. Native behaviour preserved for admins. |
| `/usr/bin/security` → `blesshelper` (non-pinned) | DENY by the mechanism, falls through to `…blesshelper.native-default`, standard user authenticated and correctly refused (`group=admin`). Proves fall-through also lands on a bare `class=user` branch. |

Two things this settles for good. **The creator is the identity that matters** — a client-only check would have denied Composer on its own `daemons.modify` leg. The mechanism therefore matches the creator only; the client is not used to allow a caller. **`k-of-n` fall-through works**: a denied mechanism branch does not fail the evaluation, authd moves to the next branch, so every non-pinned caller keeps the right's native rule. That also makes root/MDM safe, since `is-root` is the first sub-rule of the native branch.

**`enableBiometrics` (config key, default OFF) — the risk it trades away.** Turning it ON removes the admin fallback for pinned apps: only the session owner can approve, a nearby admin can no longer authenticate on a standard user's behalf, anyone enrolled in Touch ID on that Mac can approve with a fingerprint alone, and a shared or kiosk Mac whose console account is not the intended approver loses that path entirely. That is stated at authoring time in three places — the Jamf schema description, the Commander Settings caption, and an amber notice that appears under the toggle only while it is ON — so the admin enabling it is the one accepting the trade.

**How it works.** macOS offers Touch ID only when the CURRENT user alone can satisfy a rule; a rule that also admits `group=admin` makes SecurityAgent show the name-and-password form, because biometrics cannot stand in for a different person. Turning the key ON drops the admin clause from the **auth half only**, so the console user gets Touch ID; the cost is that a passing admin can no longer approve on a standard user's behalf. OFF is session-owner-**or**-admin, the broader principal set and the shipped default. The identity half, the composite, and the preserved native branch are identical either way. The daemon reads the key per compose rather than caching it, so an MDM push takes effect on the next policy reload.

Note this also fixed a nominal-vs-enforced gap. When the password step was a bare `builtin:authenticate` inside the mechanism chain, it had no principal constraint at all: *any* valid local account's credentials satisfied it, while the comment claimed session-owner-or-admin. Moving authentication into a `class=user` rule made the stated posture real.

**Admins are not exempt from Serberus here — the NATIVE rule allows them.** `pamBypass` is a sudo/PAM concept and has no equivalent on the authURI path (nothing in the composer, the mechanism, or the decision layer reads it). An admin gets through a composed right only because the preserved native branch contains `is-admin-nonshared`. A plain `deny` authuri rule therefore blocks admins too — there is no native branch to fall through to.

Note on retries: the identity half is written with `tries: 1` and the auth half with `tries: 3` (`AppIdentityBranch.identityBody` / `authBody`). The auth half's three tries are what give a *matched* app three password attempts.

**One install is three authorizations, and that is why an app branch is three rows.** Measured live: a single helper install produces three evaluations — the app asks once directly, then `/usr/libexec/smd` asks twice more on its behalf. The first build put the password mechanisms inside the `evaluate-mechanisms` branch, and the user was prompted **three times** for one install.

Adding `timeout: 30` to that branch did nothing, and the reason is worth recording:

- authd **never credential-checks an `evaluate-mechanisms` rule** — it runs the chain, every evaluation. The engine transcripts show `running mechanism SerberusAuth:identity` followed straight by `builtin:authenticate`, with no `Validating credential … for …app.<team>.<bundle>` line, whereas the native `class=user` rule does log exactly that.
- authd **silently discards** a `timeout` key written onto an `evaluate-mechanisms` rule. Verified by reading the rule back on macOS 27: the key is simply absent.

So the two jobs live in different rule classes and neither class can do both: only `evaluate-mechanisms` runs a mechanism, and only `class=user` credential-caches. The app branch is therefore a **`k-of-n: 2` AND** over an identity half and an auth half. Identity is checked on every evaluation (no bypass), while the authentication sits in a `class=user` rule where `timeout` persists, so one operation prompts once. `shared: false` stays on the auth half: a *shared* credential goes in the global pool where any caller can satisfy from it, which is the bypass it exists to prevent.

## The static approach does not work (proved on macOS 27)

The first implementation wrote each app branch as `class=user` plus a `requirement` key holding the app's compiled code requirement. **authd ignores it.** Every key Apple's own `/System/Library/Security/authorization.plist` uses was dumped and there is no `requirement` among them; a live capture then showed authd validating the *Composer* branch for a *Visual Studio Code* request, and granting. A static rule cannot distinguish callers at all, so that shape silently gave every caller the lighter posture — the exact opposite of the feature's purpose.

The only component that can see the caller is a **mechanism**: authd hands it `client-pid` and `creator-audit-token`, which resolve to a code signature. A probe (`SerberusAuthProbe`, now in `extras/`) confirmed on macOS 27 that a Developer ID-signed bundle loads into `SecurityAgentHelper`, that all five hints arrive, and that both resolve to a signing identifier + team. SerberusAuth decides on the creator audit token only; the client PID is logged but never trusted.

**It does not.** authd merges the caller's environment into the hints after setting `creator-audit-token`, so a caller can replace it. This was confirmed on a real Mac (macOS 26.7), and it is why per-app rules are [disabled in 0.9.0](#disabled-in-090).

The `creator` is the identity that matters. On an `SMJobBless`-style call the client is `/usr/libexec/smd` and only the creator is the real app; on a direct `SMAppService` call the two are the same process. The mechanism matches the creator only, resolved from the `creator-audit-token` hint (an audit token, not a PID, so PID reuse can't point the check at a different process).

**How the mechanism resolves a caller** (`SerberusCodeIdentity.resolve` in `Sources/SerberusAuth/SerberusAuthMechanism.swift`). A caller only has an identity when its signature is valid, it carries a signing identifier and a well-formed Team ID (exactly 10 uppercase letters and digits), and it is signed by Apple for that team: `anchor apple generic` and either a leaf certificate whose OU is the team (Developer ID or development signing) or Apple's Mac App Store marker. A self-signed certificate or a hand-built code directory can claim any identifier and Team ID, so an intact signature alone is not enough. The creator must also be signed with the hardened runtime, and it must not carry `com.apple.security.get-task-allow`, `com.apple.security.cs.allow-dyld-environment-variables`, `com.apple.security.cs.disable-library-validation`, `com.apple.security.cs.disable-executable-page-protection` or `com.apple.security.cs.allow-unsigned-executable-memory`; each of those would let another process inject code into the pinned app, or let the app run code that was never signed. Unsigned, ad-hoc and Apple platform callers never resolve, so they never match a pin. Any caller that can't be resolved, or a missing `authorize-right` hint, is a DENY. The mechanism reads the managed policy on every invocation, so an MDM push takes effect on the next authorization.

**The app must not be writable by the requesting user** (`SerberusBundleWritabilityPolicy` in `Sources/PrivMgrCore/Policy/AuthURIIdentityDecision.swift`). The signature check covers the running code, not every file in the bundle: an app the user can write to could have its helpers, frameworks or resources swapped, and anything under a folder the user can write to could be renamed away and replaced. So the mechanism refuses the creator when the requesting user owns, or can write to (by mode or through an ACL entry), any file or folder in its bundle or any folder above it, up to `/`. The walk starts at the outermost enclosing bundle (`.app`, `.xpc`, `.bundle`, `.framework` or `.appex`), so for a helper or XPC service inside an app everything beside it is covered. The bundle must be on a local volume that honours ownership and that root mounted; on a volume that ignores ownership (such as a disk image a user attached), a network volume or a volume a user mounted, owner and mode don't say who can write, so the creator is refused. A bundle too large to check (over 400,000 entries) is refused too. The walk runs on every authorization; for an app the size of Xcode (about 170,000 entries) it takes about a second. A refused app falls through to the right's native branch like any other non-matching caller. In practice, pin apps installed in `/Applications` by root, not copies in a user's own folders.

**A pin is a Team ID and a bundle ID, not a path.** Every copy of the app that the team signed matches, whatever its location or version, including older versions with known flaws. Before pinning an app to a root-equivalent right, check that a standard user can't make it do the privileged work for them, for example through AppleScript, a command-line interface, a plug-in folder or a settings file. If they can, the pin gives them that right.

## What it is

A plain authuri rule **rewrites** a right's definition for every caller. An identity-scoped rule instead gives **one app** (pinned by Team ID + bundle ID) a lighter posture on **one right** and leaves everyone else on the right's native behaviour. The posture is fixed: every app branch is `authenticate-session-owner-or-admin` — the console user with their own password, or any admin with theirs. There is no posture field anywhere in the schema. The daemon does that by **composing** the right, never rewriting it:

```
<right>                              class=rule, k-of-n=1, rule=[ app-1, app-2, …, native-default ]
  com.herojoneslabs.serberus.branch.<right>.app.<TEAM>.<bundle>            class=rule, k-of-n=2 over the two halves below   (one per app)
    …app.<TEAM>.<bundle>.identity                                          evaluate-mechanisms: SerberusAuth:identity
    …app.<TEAM>.<bundle>.auth                                              class=user, session-owner (+ group=admin unless enableBiometrics), timeout=30
  com.herojoneslabs.serberus.branch.<right>.native-default        the right's ORIGINAL definition, captured live
```

- **native-default** is captured from the live auth.db on first touch (the existing checksummed snapshot) and written back as a named row. It is never hardcoded — Apple changes right definitions across OS versions.
- **One row per app**, each independent. N apps per right.
- **Order matters**: authd evaluates a `k-of-n` array in order and stops at the first success. App branches go **first** (a non-matching caller is denied by the identity mechanism and moves on); native-default is **last**, so it stays the fallback every other caller lands on.
- Rules are authored **individually per app/right pair** — no shared identity list, no rule spanning rights. Retiring an app deletes exactly its row and drops it from the array.
- **Enforce mode only.** Like plain authuri rules, compositions are written to the AuthorizationDB only when `enforcementMode` is `enforce`. In `monitor` and `audit` the daemon reconciles every right back to its native definition, which also undoes rights applied under an earlier `enforce`.
- **Why the ServiceManagement rights need this.** A plain `allow` rule never opens a root-equivalent right, such as `com.apple.ServiceManagement.*` or `system.privilege.admin`. The full list is `rootEquivalentRightPrefixes` in `AuthRightTargetPolicy` (`Sources/PrivMgrCore/Policy/RuleSchema.swift`). The daemon logs and ignores such an allow (a `deny` still applies), because an allow projects to the session owner's own password and would give every standard user root. Letting one verified app use such a right is what an identity-scoped rule is for.

## Where it lives

| Layer | Code |
|---|---|
| Vocabulary (branch, requirement compiler, row naming, verification table, macOS major parsing) | `Sources/PrivMgrCore/Policy/AuthURIIdentityScope.swift` |
| **The identity decision** (which pinned app a caller matches) | `Sources/PrivMgrCore/Policy/AuthURIIdentityDecision.swift` |
| **The mechanism** (`SerberusAuth.bundle` — ObjC C-ABI shim + Swift) | `Sources/SerberusAuth/` |
| Wire schema (`Rule.appIdentity`; Jamf flat keys `appTeamID` / `appBundleID` — no posture key) | `RuleSchema.swift`, `JamfRulesSchema.swift`, `Support/jamf-schemas/*.rules*.json` |
| Validation (pin format, scope guard, plain+identity mix, duplicate pins, `allow` warning) | `PolicyValidator.swift` |
| Engine / simulator (Team-ID pin; syntax-only + provisional caveats) | `RuleEngine.swift`, `DecisionSimulator.swift` |
| Composer (compose / minimal diff / retire / drift repair / restore sweep) | `Sources/SerberusDaemonCore/AuthorizationDBManager.swift` |
| Owned-row ledger (`<right>.branches` sidecar beside the snapshot) | `AuthorizationDB.swift` |
| Authoring: **App Identity is a definition kind** (`RuleDefinition.appTeamID/appBundleID`, `DefinitionKind`, `RuleDefinition.appIdentityBranch()` builds the wire `AppIdentityBranch`; posture is fixed, so there is no posture mapping) + compile + publish gate + OS risk signal | `PolicyBuilderCore/RuleDefinition.swift`, `RuleDraft.swift`, `PolicyCompiler.swift`, `PolicyBuilderModel.swift` |
| Commander: Definitions → New Definition → **App Identity** (composer tile + form), filtered rights browser | `SerberusCommander/DefinitionComposerSheet.swift`, `DefinitionsView.swift`, `PolicyBuilderTools.swift` (`AuthURIBrowserSheet.Mode`) |
| Per-branch instrumentation (Capture) | `PrivMgrCore/Identity/BranchMatchResolver.swift`, `SerberusIntelCore/CaptureSession.swift`, `RuleCapture.swift` |

**Admins never match a pin.** `/Applications` is `root:admin 0775`, so an admin (a JIT admin inside their window included) can write to every app there, and the plugin refuses the pin for them. They get through the right's native branch instead, as before.

## Authoring in Commander

In 0.9.0 the App Identity tile and menu item are shown as unavailable, with a one-line reason, and cannot be picked. An existing App Identity definition still opens, with the `app-identity-disabled` error shown first. The rights browser lists the identity-only rights like any other right, typing one does not switch the form, drag and drop does not start an App Identity definition, and capture import drafts a plain authorization-right definition. The list below describes the behaviour with per-app rules enabled.

App Identity is the third **definition kind** (Definitions → New Definition → Sudo command / Authorization right / App Identity). The form is the Authorization-right form plus **Team ID** and **Bundle ID (code-signing identifier)**; it stores as a `.authuri` definition with `appTeamID` / `appBundleID` set, so rules reference it like any other definition and nothing on the wire grows a third mechanism.

- **Posture is fixed** at `authenticate-session-owner-or-admin` for every app branch; the rule's silent/prompt setting does not change it. A deny rule on an App Identity definition is a validation error, and the daemon also rejects an identity-scoped `deny` at runtime (deny the right with a plain definition).
- **Browse rights** in the Authorization-right form hides the identity-only rights (`daemons.modify`, `blesshelper`); in the App Identity form it shows only those, with their scope state.
- **Typing an identity-only right** into the plain Authorization-right form switches the draft to App Identity on the spot (with a notice). A plain **allow** on such a right gets a validation warning (`app-identity-required`); a plain deny is still allowed.
- **Drag & drop / Add App…** (PPPC-Utility style): drop an `.app` anywhere on the New Definition sheet, whatever kind is selected, or click Add App… (open panel filtered to app bundles). `AppBundleInspector` reads the bundle's signing identifier, Team ID and designated requirement from its code signature, the draft switches to App Identity, and the pin fields, name and description fill in; the signature facts show read-only under the form. Apple platform apps and ad-hoc builds (no Team ID) are flagged as not pinnable.
- **Verify after any change to `shared`/`timeout`/the branch shape:** trigger a pinned app (expect ONE prompt), then within 30 s trigger a NON-pinned app on the same right and confirm the plugin still logs a `DENY` for it. If the second app sails through without a mechanism line, the credential is crossing authorizations and `timeout` must go. Also watch whether a non-pinned app gets an *extra* prompt: `k-of-n: 2` should fail as soon as the identity half denies, but if authd evaluates the auth half anyway the user sees a prompt from our branch before the native one.
- **Capture import** drafts an identity-only right as App Identity with the captured Team ID pre-filled; the bundle ID is left for the admin (authd's line does not carry it).

## Verification table — advisory only (no enforcement gate)

`AuthURIIdentityScopeRegistry.current` is **code**, versioned with the product, not admin-editable policy. It records, per right, whether identity scoping is known to work and which macOS majors that was verified on. **It never gates enforcement**: a right's verification state never stops the daemon composing a rule. The daemon still leaves a right native when the SerberusAuth plugin is missing or fails its check (reported as `degraded (auth_plugin_unavailable)`), when the right doesn't exist, when macOS defines it as a mechanism chain, or when it is protected. The table only produces warnings — in Commander (composer, validator, simulator), in the Sentinel (provisional rules are badged "Testing — not verified" in the user's rule list), and in the daemon's integrity log.

| Right | State | Verified on | Notes |
|---|---|---|---|
| `com.apple.ServiceManagement.daemons.modify` | verified-eligible | macOS 26–27 | End to end on macOS 27; on macOS 26, a capture of a pure-`SMAppService` app resolving directly. Verified for BOTH request shapes: direct (`SMAppService`, client == creator) and `smd`-mediated (`SMJobBless`, client is smd, creator is the app). |
| `com.apple.ServiceManagement.blesshelper` | verified-eligible | macOS 27 | Verified end to end: pinned app allowed, non-pinned denied then falling through to its bare `class=user` native branch. The pinned app's own request was also allowed on macOS 26.7 (tested on a real Mac, 2026-09-28). |
| `com.apple.system.install.software`, `system.install.software`, `system.install.*`, `com.apple.pkgkit.*` | confirmed-ineligible | — | Caller is always `Installer.app` / the mediator, never the payload. |
| everything else | unknown | — | Not verified. Commander's rights browser does not offer it and labels it "Not verified — blocked"; if a rule names it anyway, the validator warns and the daemon composes it and logs a `configuration_error`. |

Where the warnings show:

1. **Commander**: the App Identity form shows the right's state badge and notes; the validator emits WARNINGS (never errors) for unknown/ineligible/provisional rights and for a plain allow on an identity-only right; the Decision Simulator repeats them. Nothing blocks export or direct MDM publish on verification state — scope the Jamf profile to the test Mac(s) yourself while a right is under test.
2. **Sentinel**: a provisional identity-scoped rule's title carries the "Testing — not verified" badge.
3. **Daemon**: `AuthorizationDBManager.compose` logs a `configuration_error` integrity event (and an error-level log line) for an unverified or ineligible right, a notice for a provisional one, then composes exactly as authored.

**OS-version warning:** a fleet Mac (Fleet Observer `osVersion`) or the local daemon (`ProcessInfo` major) on a major newer than the entry's verified range raises a loud warning — Dashboard risk signal `unverified_os`, the composer's scope notes, and a `configuration_error` integrity event + `error`-level daemon log. It warns; it does not block.

## Failure class caught by the drift check

An admin flipping the top-level away from a pure OR — `k-of-n` set to 2, removed entirely (authd treats a bare rule array as AND), or the native-default row dropped — silently turns "easier path for approved apps" into a **lockout**: the app must now also pass the admin gate, and nothing in the live decision path surfaces it. `AuthorizationDBManager.compositionDrift(in:nativeRow:)` detects all three on every apply/reconcile pass; the daemon logs `COMPOSITION DRIFT` at error level, emits a `configuration_error` integrity event, and rewrites the top-level back to `k-of-n 1` over the owned rows.

## Snapshot / restore

- `apply` snapshots the native definition once (existing store) and records the owned rows in a `<right>.branches` sidecar (deliberately not `.json`, so snapshot enumeration never mistakes it for a right).
- `restoreAll` / `restore(names:)` / `--restore-authdb`: write the original back, trying in order the snapshot, the preserved native-default row (when its digest verifies), Apple's shipped definition from `/System/Library/Security/authorization.plist`, and only then the admin-gate stand-in (tracked by a `.standin` record, not by a marker), then sweep every owned row (sidecar ∪ rows the live top-level references under our prefix). A row macOS refuses to remove is neutralized to `class=deny`.
- `reconcile` is differential: a right that keeps some apps stays desired, so only the retired app's row is deleted; retiring the last app drops the right, which restores it.

## Decision Simulator caveat

In 0.9.0 a pin never matches in the simulator, and Warnings says the per-app branch is ignored and why. The rest of this section describes the behaviour with per-app rules enabled.

The engine checks the Team ID pin; it cannot replay authd's live signature match. The simulator therefore validates the compiled requirement's **syntax only** (same `SecRequirementCreateWithString` gate the daemon uses) and says so in Warnings; a provisional right adds "eligibility itself is unconfirmed".

## Branch instrumentation

The question this was built for (does an app that needs **both** `blesshelper` and `daemons.modify`, such as Jamf **Composer.app**, get `smd`-mediated resolution on the `daemons.modify` leg?) is answered by the live verification above: the client on that leg is `/usr/libexec/smd`, and the mechanism allows it by matching the creator.

Every authuri attempt in a Sentinel Capture on a composed right carries:

- `predictedBranch` — the app row whose compiled requirement the logged client binary satisfies (`SecStaticCodeCheckValidity` against the requirement, run on the recording Mac), or `native-default` when none does. The prediction uses the client path only, so an `smd`-mediated attempt shows `native-default` even when the mechanism matched the creator.
- `branchEvidence` — raw authd/authorizationhost lines from the attempt that **name** a branch row, verbatim. authd's own word, when it gives one; empty otherwise.

Both show in the Sentinel's Capture review and Commander's Import Capture sheet ("branch: …", "authd named a branch ×N"). The mechanism's own `ALLOW`/`DENY` log lines (subsystem `com.herojoneslabs.serberus.authplugin`), which name the matched pin, the creator and the client, are the authoritative record.

### Verifying a right

To move a right in `AuthURIIdentityScopeRegistry.current` (a code change, reviewed like any other):

1. Author an App Identity definition for a real app on the right, reference it from an allow rule, and publish the policy as a config profile scoped to your test Mac(s) in `enforce` mode.
2. Confirm the composition landed: `security authorizationdb read <right>` should show `k-of-n 1` over the app row(s) + `…native-default`.
3. Drive the pinned app through to an actual grant, then a non-pinned app, as a standard user and as an admin.
4. Read the mechanism's log lines: the pinned app should log `ALLOW` with the expected creator; the non-pinned app should log `DENY` and then get the right's native behaviour.
5. Update the registry entry (verified-eligible or confirmed-ineligible, with the macOS majors it was tested on).

## Settled by live verification

The original static design left three things to prove on live hardware. All are now settled, and a fourth question, asked later, settled against the feature:

- **A `requirement` key on a `class=user` sub-rule**: authd ignores it (see "The static approach does not work"). The identity check moved into the `SerberusAuth:identity` mechanism.
- **Rows written with `AuthorizationRightSet` resolve as `rule` delegates**: the composed rights in the live verification evaluated their app and native-default rows by name.
- **Evaluation order (apps first)**: confirmed. A pinned app is decided by its own branch, and a denied app branch falls through to `native-default`.
- **Whether a caller can forge the creator hint**: it can. authd merges the caller's environment into the hints after setting `creator-audit-token` (confirmed on a real Mac, macOS 26.7). Per-app rules are [disabled in 0.9.0](#disabled-in-090).
