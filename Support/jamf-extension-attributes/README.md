# Serberus — Jamf Extension Attributes

Create these in Jamf Pro (**Settings → Computer Management → Extension Attributes → New**),
one per script, named in **your** convention — the table uses `EA_Serberus_<Purpose>`. The only
rule: **the display name must contain `Serberus`** (any case, any separators: `EA_Serberus_State`,
`Serberus: State`, `serberus_mode` all work). Serberus Commander's Fleet Observer shows every such
EA as device posture — three chips on the device card (State, Mode, Version rank first, then the
rest by name; the chip label is the name minus the convention, e.g. "Last Upload") and all of them in
the device detail. Input Type is *Script* for all of them; paste the matching file as the script body.

| Display name | Data type | Script | Reads | Value |
|---|---|---|---|---|
| `EA_Serberus_Mode` | String | `EA_Serberus_Mode.sh` | `state.plist : enforcementMode` | `enforce` / `audit` / `monitor` / `not installed` / `unknown` (no mode in `state.plist`) |
| `EA_Serberus_State` | String | `EA_Serberus_State.sh` | `state.plist : state` (+ `degradedReason`) | `healthy` · `degraded (<reason>)` · `awaiting_config` · `pending_pppc` · `pending_profiles` · `kill_switch` · `not installed` · `unknown (state.plist unreadable)` — `<reason>` ∈ `config_invalid`, `bypass_unresolvable`, `config_missing`, `grants_db_error`, `authdb_failure`, `pam_not_wired`, `rule_parse_error`, `auth_plugin_unavailable`, `xpc_failure`, `reload_stalled` |
| `EA_Serberus_Version` | String | `EA_Serberus_Version.sh` | `state.plist : daemonVersion` | e.g. `0.9.0`, or `not installed` / `unknown` |
| `EA_Serberus_Uploads` | String | `EA_Serberus_Uploads.sh` | every user's `jamf-uploads.json` ledger | `none` or `capture N · intel M · newest YYYY-MM-DD HH:MM UTC`; `ERROR: jq not installed` without `/usr/bin/jq` |
| `EA_Serberus_Last_Upload` | **Date** | `EA_Serberus_Last_Upload.sh` | same ledger | `YYYY-MM-DD hh:mm:ss` (UTC) or empty |
| `EA_Serberus_Denials_24h` | **Integer** | `EA_Serberus_Denials_24h.sh` | `fleet-summary.plist : denials24h` | count of `denied` + `would-deny` decisions in the last 24h, or empty |
| `EA_Serberus_Grants_Active` | **Integer** | `EA_Serberus_Grants_Active.sh` | `fleet-summary.plist : activeGrants` | live (unexpired, unrevoked) grants, or empty |
| `EA_Serberus_Prompts_24h` | **Integer** | `EA_Serberus_Prompts_24h.sh` | `fleet-summary.plist : prompts24h` | decisions that raised a prompt in the last 24h, or empty |
| `EA_Serberus_Last_Decision` | **Date** | `EA_Serberus_Last_Decision.sh` | `fleet-summary.plist : lastDecisionAt` | `YYYY-MM-DD hh:mm:ss` (UTC) of the newest decision, or empty |
| `EA_Serberus_Recent_Events` | **String** | `EA_Serberus_Recent_Events.sh` | `fleet-events.json` | JSON array of the last-24h individual **denials & prompts** (`{at, kind, target, user, outcome, prompt, reason?, justification?}` — `justification` is the user's redacted reason, present on approved prompts that required one), or empty. At most 64 KiB: a longer list keeps the newest whole events that fit, so the value is always a valid JSON array. **Debug-gated** — see below |

## Fleet telemetry — decision counts & trends

The four telemetry EAs above read `fleet-summary.plist` =
`/Library/Application Support/Serberus/fleet-summary.plist`, which `serberusd` rewrites
on every 30-second reload tick (world-readable, atomic) from its signed decision log
(`/Library/Logs/Serberus/decisions-*.jsonl`) plus the live grant store. The count keys
are a **true rolling 24 hours** (audit-mode `would-grant`/`would-deny` fold into the grant/deny totals, so
the numbers read the same whether a Mac is enforcing or observing); `lastDecisionAt` is the **genuine
newest** decision even if older than 24h, so a silent Mac reads as silent. Absent file ⇒ Serberus not
installed / no reload tick yet ⇒ every telemetry EA reports empty. Integer EAs let smart groups
range-compare; Commander's Dashboard **sums** them across the Serberus fleet for its trend tiles.

These are **counts, not a live per-decision feed** — they refresh only as often as Jamf recon runs, so a
number is only as fresh as the device's last inventory update (Commander surfaces the `lastContact` /
`updatedAt` beside each figure so a stale number reads as stale).

## Debug telemetry — the individual denials & prompts list (opt-in)

`EA_Serberus_Recent_Events` carries the **individual** last-24h denial and prompt decisions (not just counts)
as a JSON array, which Commander lists on the device record (Fleet Observer → a device → **Recent Elevations**).
Because this is per-decision detail (command/right, user, time, outcome, and the user's redacted justification — arguments are redacted),
it is **gated behind a dedicated config profile** so it only reaches Jamf inventory while you are actively
debugging:

- The daemon **always** collects the events locally (`recent-events.json`, root-only).
- While debug mode is on, the daemon also captures each `sudo` request's redacted arguments. They stay in
  memory and in these two root-only files, and so reach Jamf through this EA; they never go into the
  decision log, which every local user can read.
- It publishes them to the EA-inspected path (`fleet-events.json`, also root-only `0600`, since the EA
  runs as root) **only while the
  `com.herojoneslabs.serberus.debug` profile is installed with `debugModeEnabled = true`** (schema:
  `Support/jamf-schemas/com.herojoneslabs.serberus.debug.json`).
- When you set it false, or **remove the profile**, the daemon deletes `fleet-events.json` within one reload
  tick (≤ 30s) — the EA then reports empty and no per-decision detail remains in Jamf.

**Recommended use:** scope the debug profile to a small smart group (or one Mac) only while investigating, then
remove it. Nothing per-decision leaves a Mac unless this profile is on it.

`state.plist` = `/Library/Application Support/Serberus/state.plist`, written by
`serberusd` on every state transition (world-readable; `updatedAt` is the last *change*, not a heartbeat).

`jamf-uploads.json` = `~/Library/Application Support/Serberus/jamf-uploads.json`,
written by **Serberus Sentinel** after every successful *Upload to Jamf* (Intel → Capture, Intel → Export
bundle): a JSON array of `{kind: capture|intel, fileName, uploadedAt, computerID, serialNumber, sizeBytes}`,
pruned to the last 30 days / 200 entries by the writer — and the Uploads EA applies the same 30-day window
itself, so a Mac that uploaded once and never again stops being flagged after 30 days. It is the **device-side "I uploaded files" signal** — the EA
reports it at the next recon (inventory update), so Jamf smart groups and Commander's posture chips can flag
devices with something to harvest.

What is still *on the record* is Commander's job: Fleet Observer → **Uploads** reads the attachments straight
from the Jamf inventory, lets you **Download** / **Import** (captures) / **Reject** (reviewed, no definition)
and **Delete** the file from the record (API role *Update Computers*; there is a "Delete from Jamf after
download, import, or reject" switch). Commander also keeps its own review ledger
(`~/Library/Application Support/Serberus/capture-reviews.json`, keyed by upload file
name): an upload counts as **waiting** only while it is on a record AND not yet imported / rejected /
downloaded — so the Dashboard's "Uploads waiting" and the menu-bar badge clear on review even when the
switch is off and the file stays on the record (shown as Imported / Rejected / Downloaded there). The EA
ages out on its own (30-day window) — it says "this Mac uploaded recently", not "still pending".

**Which Macs Commander shows.** Fleet Observer lists only Macs with inventory evidence of Serberus: a
EA named with "Serberus" carrying a real value (this is the main reason to deploy `EA_Serberus_State`), a Serberus
package receipt (`PACKAGE_RECEIPTS` — Jamf-policy installs like `SerberusCore-<version>.pkg`), or a
Serberus upload on the record. Everything else in Jamf is hidden behind the "Include Macs without
Serberus" switch. Other file uploads on a record (your standard logs) are never listed, downloaded, or
deleted — only `Serberus-Capture-*` / `.serberuscapture` / `Serberus-Intel-*` files.

Suggested smart groups:

- **Serberus — uploads waiting**: `EA_Serberus_Uploads` *is not* `none`
- **Serberus — uploaded in last 7 days**: `EA_Serberus_Last_Upload` *less than x days ago* `7`
- **Serberus — not enforcing**: `EA_Serberus_Mode` *is not* `enforce`
- **Serberus — healthy**: `EA_Serberus_State` *is* `healthy`
- **Serberus — degraded**: `EA_Serberus_State` *like* `degraded`
- **Serberus — no working break-glass**: `EA_Serberus_State` *like* `bypass_unresolvable` (enforcing, but no `pamBypass` entry resolves on the Mac: no user under its exact name, no group with members)
- **Serberus — sudo not gated**: `EA_Serberus_State` *like* `pam_not_wired` (the sudoers drop-in is withheld until the PAM gate verifies)
- **Serberus — awaiting config**: `EA_Serberus_State` *is* `awaiting_config` (the enrolment-race state worth flagging)
- **Serberus — high-denial Macs**: `EA_Serberus_Denials_24h` *more than* `20`
- **Serberus — prompt-fatigue hotspots**: `EA_Serberus_Prompts_24h` *more than* `10`
- **Serberus — outstanding elevation**: `EA_Serberus_Grants_Active` *more than* `0`
- **Serberus — silent for 7+ days** (mis-scoped / inert policy): `EA_Serberus_Last_Decision` *more than x days ago* `7`

Requirements on the Mac: `/usr/bin/jq`, which ships with macOS 15 and later, for the two ledger EAs
(`EA_Serberus_Uploads`, `EA_Serberus_Last_Upload`) and for trimming an oversized
`EA_Serberus_Recent_Events` value (without it, an oversized value is reported as `[]`); nothing else (the other EAs use only PlistBuddy,
`date` and other base tools, called by absolute path). All scripts are written for Bash 3.2, are
side-effect-free, and always emit a `<result>`.

Also available (uninstall ring only): `PKG/verify-uninstall.sh --ea` → `CLEAN` / `DIRTY: n issue(s)`.
