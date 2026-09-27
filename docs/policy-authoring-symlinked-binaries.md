# Authoring curated `sudo` policy for symlinked & powerful binaries

Some of the binaries operators most want to curate — `jamf` and other vendor
management tools — are installed behind a **symlink** and act as **subcommand
dispatchers** (`jamf recon`, `jamf policy`, `jamf removeFramework`). Both traits
affect how curated-`sudo` rules match. This guide explains how to write rules
that actually match and actually constrain.

Read alongside [`docs/sudoers-provisioning.md`](sudoers-provisioning.md), which
is the authoritative reference for the coarse `/etc/sudoers.d/serberus` layer and
the enrollment model this guide's fine-layer rules sit on top of.

---

## At a glance

When you curate a symlinked / powerful binary, do all of the following:

1. **Author two rules — the friendly symlink AND the resolved real path**
   (`/usr/local/bin/jamf` *and* `/usr/local/jamf/bin/jamf`), each with the same
   `matchType`/`argPattern`. This is the only shape robust to the symlink being
   absent at evaluation time. See [Rule 1](#rule-1--author-both-the-friendly-and-resolved-paths)
   for exactly why a friendly-only rule silently goes inert and denies when the
   symlink isn't present on disk (the third failure below), and why a
   resolved-only rule drops the friendly path `sudo` matches on.
2. **Use `matchType: exact` for a single binary**, not `prefix-regex`. A prefix
   over-matches sibling binaries and subdirectories.
3. **Anchor every argument regex** — `^recon$`, never a bare `recon`.
4. **Allow-list subcommands explicitly** — one exact, anchored rule per permitted
   subcommand; rely on deny-by-default for everything else.
5. **Cover every alias path** users actually invoke (if there is more than one).
6. Confirm the fine layer is live: `pam_serberus` installed + wired **and**
   `enforcementMode = enforce`. The daemon writes the coarse sudoers grant only
   in that state. In `audit`/`monitor`, or with the module not wired, it removes
   the grant, so enrolled standard users can't run the curated commands at all.

---

## Background: the `jamf` symlink case

`/usr/local/bin/jamf` is a **symlink** to the real binary
`/usr/local/jamf/bin/jamf`. A rule authored as `commandPattern:
/usr/local/bin/jamf`, `matchType: prefix-regex`, `argPattern: recon` misbehaved
in **three** independent ways on managed Macs, before the first two were fixed:

- **`sudo jamf recon` was refused at the sudoers layer.** The coarse generator
  canonicalizes (symlink-resolves) the command path, so
  `/etc/sudoers.d/serberus` listed the **resolved** path
  `/usr/local/jamf/bin/jamf` — but `sudo` matches the **symlink** path the user
  typed (`/usr/local/bin/jamf`). The two didn't match → sudoers refused the
  command, whatever the daemon had answered. Serberus now handles this: the generator emits **both** the
  authored (friendly) and the resolved forms (dual-path).
- **Any `jamf` subcommand was permitted** (recon-only was not enforced) whenever
  the request did reach the daemon — because the daemon matched the request's
  **canonical** command against the rule's **raw** (symlink) `commandPattern`, so
  the rule never matched, went inert, and its `argPattern` was never applied.
  Serberus now handles this too: the daemon canonicalizes the rule's
  `commandPattern` before comparing.
- **Every `sudo jamf …` was denied by the daemon (fail-closed).** The daemon's
  rule-pattern canonicalization uses `resolvingSymlinksInPath`, which only
  rewrites a symlink that is **present on disk at evaluation time**. When the
  `/usr/local/bin/jamf` symlink is absent — a partially-installed framework, a
  reinstall that hasn't recreated the link yet, an image where jamf lives only at
  `/usr/local/jamf/bin/jamf` — the friendly pattern stays raw, never equals the
  canonical command, matches **no rule**, and denies. Reinstalling the daemon does
  not help: the rule lives in the `com.herojoneslabs.serberus.rules` MDM profile,
  not the pkg.

> **The third mode is why a friendly-only rule is fragile.** Symlink resolution at
> match time is a runtime dependency on filesystem state you don't control. The
> **resolved real path never has this dependency** — it matches the canonical
> command directly. So author the resolved path for the fine layer, and *also* the
> friendly path (a second rule) so the coarse `sudoers` gate still has the entry
> `sudo` keys on. The daemon now emits a **load-time warning** (`policy load: rule
> '…' … neither resolves through a symlink nor exists on disk`) whenever an
> `.exact`/`.prefixRegex` pattern would silently go inert this way — grep the
> `com.herojoneslabs.serberus` subsystem after a policy change to catch it.

---

## Rule 1 — Author both the friendly and resolved paths

> **Shortcut (recommended):** in the app, edit an **exact** sudo definition and
> fill in the optional **Resolved path** field (e.g. friendly
> `/usr/local/bin/jamf`, resolved `/usr/local/jamf/bin/jamf`). `PolicyCompiler`
> then emits **both** `.exact` wire rules from that one definition — you author
> the shared matcher/pins/argPattern once and get the friendly+resolved pair
> automatically (the twin's wire id gets a `__2` suffix). The two-rule shape
> below is what that compiles to; author it by hand only if you're editing raw
> wire/JSON. Do **not** use a wildcard to cover both paths — the daemon matches a
> glob with `fnmatch(3)` without `FNM_PATHNAME`, so `*` also matches `/`, and a
> pattern such as `/usr/local/*/jamf` matches more binaries than the two you
> meant.

Authored by hand, that's **two rules** — one on the friendly path and one on the
resolved real path — with identical `matchType`, `argPattern`, action, and
elevation:

```bash
$ which jamf
/usr/local/bin/jamf                  # friendly (symlink) — what sudo matches
$ readlink -f /usr/local/bin/jamf
/usr/local/jamf/bin/jamf             # resolved (real binary) — what the daemon matches
```

- Rule A — `commandPattern: /usr/local/bin/jamf`  (friendly)
- Rule B — `commandPattern: /usr/local/jamf/bin/jamf`  (resolved)

Each layer needs a different one of these, and **neither single rule satisfies
both layers on its own:**

| | Coarse (`sudoers`) needs… | Fine (daemon) needs… |
|---|---|---|
| **What it keys on** | the **friendly** path `sudo` resolves via `secure_path` | the **canonical** (resolved) command |
| **Friendly-only rule (A)** | ✅ emits friendly + resolved (dual-path) | ⚠️ matches **only while the symlink resolves on disk** — inert + deny if absent |
| **Resolved-only rule (B)** | ❌ generator emits **only** the resolved path; the friendly entry `sudo` matches is missing | ✅ matches directly, symlink-independent |
| **Both rules (A + B)** | ✅ friendly always present (from A) | ✅ always matches (from B) |

- **Why not friendly-only?** The daemon resolves the rule pattern with
  `resolvingSymlinksInPath` at match time. That only rewrites a symlink **present
  on disk**; if `/usr/local/bin/jamf` is absent, Rule A stays raw
  (`/usr/local/bin/jamf`), never equals the canonical command
  (`/usr/local/jamf/bin/jamf`), matches nothing, and **fail-closes to deny**. This
  is the third failure described above.
- **Why not resolved-only?** The coarse generator can *add* the resolved form to a
  friendly-authored rule (it symlink-resolves it), but it **cannot derive the
  friendly symlink from a resolved path** — there's no reverse lookup. A
  resolved-only rule therefore produces a drop-in with **only**
  `/usr/local/jamf/bin/jamf`, and `sudo jamf` (which `sudo` sees as the friendly
  `/usr/local/bin/jamf`) is denied at the coarse gate.
- **Both rules** gives the coarse layer the friendly entry (always emitted from
  Rule A, symlink or not) and the fine layer a resolved match that never depends
  on symlink state (Rule B). The fine layer collapses both to the same canonical
  binary, so Rule A is harmless when present and Rule B carries the match when the
  symlink is gone.

> **Watch the daemon log.** After any rules-profile change, the daemon emits
> `policy load: rule '…' … neither resolves through a symlink nor exists on disk`
> for any `.exact`/`.prefixRegex` pattern that would silently match nothing. Treat
> that line as "this rule is inert — fix the path."

---

## Rule 2 — Prefer `exact` over `prefix-regex` for a single binary

For a **single** binary, use `matchType: exact` (the default when `matchType` is
omitted). `exact` matches the canonical executable path **and nothing else**.

`prefix-regex` matches the pattern **plus everything under it at a path-component
boundary** (`command == prefix` **or** `command.hasPrefix(prefix + "/")`). Point
it at a directory-ish prefix and it over-authorizes:

| `commandPattern` | `matchType` | Also matches | Risk |
|---|---|---|---|
| `/usr/local/bin/jamf` | `exact` | nothing else | ✅ tightest |
| `/usr/local/bin/jamf` | `prefix-regex` | `/usr/local/bin/jamf` **and** `/usr/local/bin/jamf/anything` | usually harmless for a leaf file, but conceptually wrong |
| `/usr/local/bin` | `prefix-regex` | `/usr/local/bin/jamf`, `/usr/local/bin/anything-else` | ❌ authorizes every sibling binary |

Reserve `prefix-regex` for the case it is designed for: deliberately covering an
entire install tree (e.g. every helper under a vendor directory) — and only when
you have accepted that every current and future file under that prefix is in
scope.

### The argument filter works with every match type

The **engine applies `argPattern` for *every* match type** — `exact`, `glob`,
`prefix-regex`, `regex`, `any` — not just `prefix-regex`. In the rule engine the
argument regex is checked immediately after the command match, regardless of how
the command matched (`RuleEngine.sudoMatches`).

Commander's sudo definition form shows the **Argument filter** field for every
match style, so you can author the recommended shape below (exact + anchored
`argPattern`) directly. The "Path prefix + argument regex" label on the
`prefix-regex` style is only a name; the other styles take an argument filter
too.

---

## Rule 3 — Anchor the argument regex

Always anchor: **`^recon$`**, never a bare **`recon`**.

`argPattern` is a regular expression applied to the **first argument** (the
subcommand — `argv`'s first element). Author it anchored so it denotes exactly one
token.

**How Serberus actually matches (so you're not surprised):** the daemon evaluates
`argPattern` as a **full-string** regex — the *entire* argument must match the
pattern (`PatternMatcher.fullRegexMatch`). So a bare `recon` already behaves like
`^recon$` in the daemon's fine layer and will not, by itself, match
`reconfigure`. Anchor explicitly anyway, because:

- **Intent is unambiguous.** `^recon$` says "the subcommand is exactly `recon`" to
  the next person reading the policy — no reliance on implicit full-string
  semantics.
- **Alternations match every alternative in full.** The daemon wraps the
  pattern as `\A(?:…)\z`, so `recon|reconfigure` matches both `recon` and
  `reconfigure`, in an allow or a deny. Anchors don't narrow a quantifier:
  `recon.*` and `^recon.*$` both match `reconfigure`, so write the exact
  tokens you mean.
- **Only the daemon reads `argPattern`.** The coarse sudoers layer is path-only
  and does **not** enforce the subcommand at all (`sudoers` would match arguments
  with shell `fnmatch(3)` globbing, a different engine from the daemon's full-string
  regex — see the deferred-enhancement note under the two-layer model). So your
  anchored `^recon$` is enforced solely on the fine side; author it there and rely
  on the daemon for every argument decision.

Anchor the **whole** token set, e.g. one exact subcommand per rule:
`^recon$`, `^policy$`, `^manage$`.

---

## The two-layer enforcement model

Every curated `sudo` decision passes through two independent gates. Author for
both.

| Layer | Mechanism | Enforces | Granularity |
|---|---|---|---|
| **Coarse** | `/etc/sudoers.d/serberus` (generated) | *May this enrolled principal invoke `sudo` for this command **path** at all?* | **Path only** (friendly + resolved). `argPattern` is **not** enforced here — see below. |
| **Fine** | `pam_serberus.so` → daemon rule engine | ALLOW / PROMPT / DENY on the full request (`argPattern`, elevation, identity pins, grants) | The authoritative decision |

Key consequences for authoring:

- **The fine layer is the *sole* enforcer of arguments.** `argPattern`, prompt,
  deny, Team ID / hash pins, and grant caching live only in the daemon. The coarse
  sudoers layer is a **path-only** allowlist that bounds blast radius and lets
  `sudo` reach PAM — it is *deliberately weaker* than the fine policy and can never
  widen it. It does **not** pin the subcommand: the generator ignores `argPattern`
  entirely and emits path-only specs. (Pinning a literal `jamf recon` into the
  drop-in was tried and reverted — `sudo` requires an *exact full-argument* match,
  so a `jamf recon` spec denies the real-world `sudo jamf recon -verbose`, which the
  fine gate allows; a coarse layer must never deny what the fine gate permits.) See
  [`docs/sudoers-provisioning.md`](sudoers-provisioning.md) for the coarse-layer
  invariants (never `NOPASSWD`, never `ALL`, never a deny line, run-as-root only).
- **Fine enforcement requires the module wired *and* `enforcementMode =
  enforce`.** In `audit` mode the daemon logs the would-be decision but PAM
  passes the request through (`PAM_IGNORE`) — a prompt/deny does **not** block. In
  `monitor` mode the daemon performs no evaluation at all. Only `enforce` actually
  denies/prompts. Validate `enforcementMode` before relying on `argPattern` to
  constrain a powerful binary.

---

## Powerful binaries: allow-list subcommands, deny by default

`jamf` and similar dispatchers expose destructive subcommands
(`jamf removeFramework`, `jamf resetPassword`). Curate them with an
**allow-list of specific subcommands**, never a blanket grant on the binary.

Don't write a rule for `brew` at all. `/opt/homebrew` belongs to the user who
installed Homebrew, so a rule that runs `brew` as root hands that user root,
and Homebrew refuses to run as root anyway. The same goes for any binary in a
folder a standard user can write to (see
[SECURITY.md](../SECURITY.md#known-limitations)).

**Pattern: one exact, anchored rule per permitted subcommand.**

- `commandPattern: /usr/local/bin/jamf`, `matchType: exact`, `argPattern: ^recon$`
- `commandPattern: /usr/local/bin/jamf`, `matchType: exact`, `argPattern: ^policy$`

Everything else — `jamf removeFramework`, an unlisted subcommand, no subcommand at
all — hits **no rule and is denied**: the engine fails closed on no-match, and an
`argPattern`-constrained rule cannot match an argument-less invocation. You never
need (and should never author) a catch-all `matchType: any` or a broad
`prefix-regex` on a powerful binary — those are the shapes that turn an allow-list
into an allow-everything.

### The residual coarse-layer fallback (and its limits)

The coarse grant is **path-only**. If it stood without the fine layer, an
enrolled user could run *any* subcommand of the allow-listed binary
(`jamf removeFramework`), not just the curated one. The coarse layer does **not**
narrow the subcommand.

So the daemon writes the drop-in only when the fine layer is live:
`enforcementMode` is `enforce` and `pam_serberus` is wired as the first
`requisite` auth line in `/etc/pam.d/sudo_local`. In `audit`/`monitor` it removes
the drop-in. If the module is not wired, it removes the drop-in and reports
`degraded` (`pam_not_wired`). See the safety section of
[`docs/sudoers-provisioning.md`](sudoers-provisioning.md).

> **Why not pin the argument at the coarse layer?** It was tried (emit
> `jamf recon` into the drop-in when `argPattern` is a single literal) and
> **reverted**. `sudo` matches a command spec's arguments with an *exact,
> full-argument* comparison, so a `jamf recon` spec authorizes **only** the bare
> `sudo jamf recon` and **denies** the everyday `sudo jamf recon -verbose` (and any
> recon-with-flags) — even though the fine gate allows it (the daemon applies
> `argPattern` to `argv[0]` alone and leaves trailing args unconstrained). A coarse
> layer that denies what the fine layer permits is a functional brick, so the
> generator stays path-only and defers argument enforcement to the daemon.
>
> **Future enhancement (intentionally deferred).** Coarse-layer argument
> enforcement *is* expressible via a sudoers **regex/glob argument** rather than a
> bare literal — e.g. `^recon( .*)?$` (or the `fnmatch` `recon` / `recon *` pair) to
> allow `recon` with or without trailing flags. This is deferred because it needs
> careful construction and live `visudo`/`sudo` testing: a naive `^recon.*$` would
> over-authorize `reconfigure`, and the coarse layer matches arguments with shell
> `fnmatch(3)`, not the daemon's full-string regex, so the two engines must be
> reconciled per-token before this can ship safely.

The coarse layer also still cannot express prompt, deny, identity pins, or caching.

Operational takeaways:

- **Keep the fine layer live.** Enrolled standard users get curated `sudo` only
  while `enforcementMode = enforce` and the module is wired. Watch for a
  `degraded` state with reason `pam_not_wired`, which means the daemon has pulled
  the grant. The coarse layer is a path allowlist only — it is **not** a
  subcommand allowlist.
- **Tear down coarse-first.** When decommissioning, remove
  `/etc/sudoers.d/serberus` *before* unwiring the module / stopping the daemon, so
  you never leave the coarse grant standing without the fine gate (see the
  teardown-ordering section of
  [`docs/sudoers-provisioning.md`](sudoers-provisioning.md)).

---

## Symlink edge cases: cover every alias path

The daemon canonicalizes to the real binary, so a rule authored on **any** path
that resolves to the target will match a request that arrives on **any** path
resolving to the same target. That handles the common single-symlink case
transparently.

Where you must be deliberate is **multiple distinct alias paths** users actually
invoke. `sudo` (the coarse layer) keys on the *literal* path the user typed, and
the coarse drop-in authorizes the friendly + resolved pair for each rule. If your
fleet invokes the same tool through more than one alias — e.g. a wrapper in
`/usr/local/bin` **and** a direct call to `/opt/vendor/bin/tool`, or a
site-specific `/usr/local/sbin/jamf` shim — author **one rule per alias path** so
every invocation route is covered at the coarse layer. The fine layer will
collapse them to the same canonical binary, but the coarse layer needs each
literal entry point named.

Rule of thumb: enumerate the paths your users type (survey `which`, wrapper
scripts, and any `PATH` shims), and give each its own rule.

---

## Worked example: curated `sudo jamf recon` for an enrolled standard user

Goal: enrolled standard users may run `sudo jamf recon` (silent or prompted) and
nothing else on `jamf`.

**Rules (authoring shape) — one per path form, identical otherwise:**

- Rule A — `type: sudo`, `action: allow`, `match.commandPattern: /usr/local/bin/jamf` (friendly), `match.matchType: exact`, `match.argPattern: ^recon$`, `elevation.type: prompt` (or `silent`)
- Rule B — identical, but `match.commandPattern: /usr/local/jamf/bin/jamf` (resolved real binary)

Author both so the coarse gate always has the friendly entry `sudo` matches and
the fine gate always has a resolved match that doesn't depend on the
`/usr/local/bin/jamf` symlink existing (see [Rule 1](#rule-1--author-both-the-friendly-and-resolved-paths)).

**What each layer does:**

1. **Coarse** — the drop-in authorizes the `jamf` **path** at both
   `/usr/local/bin/jamf` (from Rule A) and `/usr/local/jamf/bin/jamf` (from Rule B,
   and from Rule A when the symlink resolves at generation time). It is
   **path-only**: `argPattern` is not enforced here, so *any* `jamf` subcommand
   (`recon`, `removeFramework`, …) passes the coarse gate. Subcommand restriction is
   the fine layer's job.
2. **Fine** (`enforce` mode, module wired) — the daemon canonicalizes the request
   command to `/usr/local/jamf/bin/jamf` and matches **Rule B directly** (Rule A
   also matches when the symlink resolves). It applies `^recon$` against the
   subcommand and returns ALLOW / PROMPT. `sudo jamf policy` matches the command
   but fails `^recon$` → no rule → **deny**.

**To also permit `jamf policy`,** add the same *pair* with `argPattern: ^policy$`
(four rules total) rather than loosening any rule to a broader pattern.

---

## Related docs

- [`sudoers-provisioning.md`](sudoers-provisioning.md) — the coarse
  `/etc/sudoers.d/serberus` layer: what it emits, the match-type translation
  table, the never-emitted invariants, enrollment (`sudoEnrollment`), the
  fail-closed install/teardown pipeline, and teardown ordering.
- [`SerberusPAM.md`](SerberusPAM.md) — the fine gate (`pam_serberus`) that
  the coarse drop-in feeds.
</content>
