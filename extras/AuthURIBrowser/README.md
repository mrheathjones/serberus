# Auth URI Browser

A standalone, portable macOS app that lists every authorization right and
named rule on the Mac it runs on, with its description and a badge for who
can satisfy it (root, admin, standard user, anyone, entitled app, …).

No dependency on the rest of Serberus — it is a single SwiftPM executable
target wrapped in an `.app` bundle. Copy the built app anywhere and run it.

## Sources of truth

| Source | What it gives | Access |
|---|---|---|
| `/System/Library/Security/authorization.plist` | The system template: every Apple right + rule with its `comment` description | world-readable |
| `AuthorizationRightGet` (same as `security authorizationdb read`) | The **live** definition of each named right from `/var/db/auth.db`, including local overrides | any user |
| `sqlite3 /var/db/auth.db` via an admin prompt (**Discover custom rights**) | The full row list, so third-party / MDM / Serberus-added rights that are not in the template show up too | admin password, once |

## Badges

Each right is resolved through its `rule` delegations and mechanism lists to
the set of principals that can satisfy it:

- **Root** — `allow-root`; a root process passes silently
- **Admin** — `group = admin`; a key glyph means a password prompt, "(member)" means membership only
- **Group _name_** — another group such as `_developer` or `_lpadmin`
- **Standard user** — session owner or any local user (key glyph = password)
- **Entitled app** — gated only by an entitlement (`builtin:entitled`)
- **Anyone** — `class = allow`
- **Mechanisms** — decided by authorization plug-ins (login, keychain unlock…)
- **Denied** — `class = deny`
- **Unresolved** — delegates to a rule that is not defined on this Mac

Extra tags: **wildcard** (prefix rule ending in `.`), **overridden** (live
definition differs from the system template *and* the row was rewritten after
creation — a local override by MDM, a tool such as Serberus, or
`security authorizationdb write`), **differs** (differs from the template but
never rewritten — Apple ships a few rows like that, e.g. `system.preferences.sharing`),
**modified** (rewritten after creation but still matching the template, which
Apple's own updates do), **custom** (only
in the live db).

## Command line

```bash
"build/Auth URI Browser.app/Contents/MacOS/AuthURIBrowser" --dump [--rules]   # TSV of every right with badges
open "build/Auth URI Browser.app" --args --select system.preferences.datetime  # open straight onto a right
```

## Look

The UI uses the Serberus design system (tokens mirrored from Commander's
`DesignSystem/Theme.swift` and Sentinel's `SentinelTheme.swift`): graphite
ground, surface-1 cards with hairlines, emerald reserved for selection and
actions, eyebrow section labels, the sigil icon chip, and a branded sidebar
with a status footer. `Scripts/make_icon.swift` renders the app icon (sigil
tile + key badge) to `Icon.icns`.

## Build

```bash
Scripts/package_app.sh            # → build/Auth URI Browser.app (ad-hoc signed)
Scripts/run.sh                    # build + launch
```

Requires Xcode's toolchain (`DEVELOPER_DIR` defaults to `/Applications/Xcode.app`).
Minimum macOS 14.
