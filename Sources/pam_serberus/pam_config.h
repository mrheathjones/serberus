/*
 * pam_config.h — managed-preferences config reading for pam_serberus.so.
 *
 * Extracted from pam_serberus.c so the break-glass parsing (enforcementMode +
 * pamBypass) is unit-testable outside a PAM stack. This module is PURE config
 * parsing: no PAM types, no XPC, no membership checks (mbr_check_membership
 * stays in pam_serberus.c — it needs real OpenDirectory).
 *
 * Read order mirrors PrivMgrCore's ManagedPreferencesReader/CFPreferencesSource:
 * the computer-level managed plist (written by the MDM client under
 * /Library/Managed Preferences) is read DIRECTLY via CFPropertyListCreateWithData
 * and it is the ONLY layer read. There is no CFPreferences fallback: a euid-0
 * sudo process never sees the managed layer through CFPreferences composite
 * reads anyway, and the unforced layers are not policy (inside setuid sudo they
 * may resolve to a location the invoking user controls).
 *
 * The managed plist path is an EXPLICIT parameter so tests can point it at
 * temp fixtures. The production caller (pam_serberus.c) hardcodes the real
 * path; there is deliberately NO environment-variable override anywhere in
 * this module — env-controlled paths inside a requisite PAM module would be a
 * privilege hole.
 *
 * Fail-closed defaults throughout: absent/invalid config means "enforce" with
 * an empty bypass set.
 *
 * The ONE exception is BOOTSTRAP (serberus_config_resolve_source below): a Mac
 * that has NEVER had a usable config — no managed config AND no last-known-good
 * snapshot on disk — is left exactly as Serberus found it (sudo passes through
 * natively). That fail-open is scoped by the EXISTENCE of the snapshot file, so
 * once a Mac has been configured even once it can never re-enter bootstrap:
 * removing the profile falls back to the snapshot, which is enforceable by
 * construction and therefore still carries its break-glass pamBypass.
 */

#ifndef SERBERUS_PAM_CONFIG_H
#define SERBERUS_PAM_CONFIG_H

#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h> /* uid_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Last-known-good config snapshot, written ATOMICALLY (temp + rename) by the
 * daemon every time it adopts a safely-enforceable managed config, and read
 * here when the managed config is absent or unsafe. 0644 root:wheel, so it is
 * world-readable and therefore carries NO Jamf credentials. (pam_serberus
 * itself reads it at euid 0, inside setuid sudo.)
 *
 * Its key shape is a strict SUBSET of the com.herojoneslabs.serberus.config
 * managed domain (same names, same nesting), so every reader in this file
 * parses it with the exact same code path as the managed plist.
 * KEEP IN SYNC with PrivMgrCore BundleConfig.lastKnownGoodConfigPath.
 */
#define SERBERUS_LKG_CONFIG_PATH \
    "/Library/Application Support/Serberus/last-known-good-config.plist"

/* Which config source governs this authentication (serberus_config_resolve_source). */
#define SERBERUS_CONFIG_SOURCE_MANAGED          0 /* delivered config, present + enforceable */
#define SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD  1 /* snapshot: profile absent/unsafe/partial */
#define SERBERUS_CONFIG_SOURCE_BOOTSTRAP        2 /* never configured — do not enforce */

/*
 * Copies the effective enforcement mode into `out`: exactly "enforce",
 * "audit", or "monitor". Absent key, wrong type, unparseable plist, or an
 * unknown mode string all yield "enforce" (fail closed).
 */
void serberus_config_copy_enforcement_mode(const char *managed_plist_path,
                                           char *out, size_t out_size);

/*
 * Copies the string value for `key` from the effective config source into
 * `out` (NUL-terminated, truncated to out_size). Reads ONLY the plist at
 * `managed_plist_path` (the managed plist or the last-known-good snapshot —
 * there is no fallback domain), exactly like the other accessors. Returns
 * true only when the key is present AND a NON-EMPTY string; otherwise `out`
 * is set to "" and the function returns false. Used for the optional
 * user-facing sudo messages (`sudoDenyMessage` / `sudoAllowMessage`) — absent
 * ⇒ caller uses its default.
 */
bool serberus_config_copy_string(const char *managed_plist_path,
                                 CFStringRef key,
                                 char *out, size_t out_size);

/*
 * True when the effective config's daemonEnabled key is NOT explicitly false.
 * Absent key, wrong type, or unparseable source all yield TRUE (fail toward
 * enforcing), matching the daemon's SerberusConfig default. A value of `false`
 * is the KILL SWITCH: pam_serberus passes sudo through (PAM_IGNORE) without
 * consulting the daemon, mirroring the daemon's own kill-switch teardown
 * (authdb restored, sudoers drop-in removed). Read from whichever source
 * governs this authentication (managed OR last-known-good).
 */
bool serberus_config_daemon_enabled(const char *managed_plist_path);

/*
 * Returns a retained CFArray of the strings in pamBypass.<inner_key>
 * ("users" or "groups"), or NULL when the key is absent or mistyped.
 * Non-string array members are filtered out (they can never match a user or
 * group name and must not trip up callers). Caller releases the result.
 * (CF_RETURNS_RETAINED lets Swift Testing import it memory-managed.)
 */
CFArrayRef serberus_config_copy_bypass_array(const char *managed_plist_path,
                                             CFStringRef inner_key) CF_RETURNS_RETAINED;

/*
 * True when `user` appears (exact, case-sensitive match) in pamBypass.users.
 * Absent/invalid config returns false (no bypass — fail closed).
 */
bool serberus_config_user_in_bypass_users(const char *managed_plist_path,
                                          const char *user);

/*
 * True when the config source has DELIVERED anything at all: the plist at
 * `managed_plist_path` parses to a dictionary with at least one key (no other
 * preferences layer is consulted). Mirrors
 * ManagedPreferencesReader.configIsPresent() — an absent config must be
 * distinguishable from a config whose every value happens to equal the
 * fail-safe defaults.
 */
bool serberus_config_is_present(const char *managed_plist_path);

/*
 * True when the config can be enforced without risking a lockout:
 *   enforcementMode != "enforce"  (monitor/audit deny nothing), OR
 *   pamBypass has at least one string member across users + groups.
 * Byte-parity with SerberusConfig.isEnforceable and with the pkg preinstall's
 * break-glass preflight. An unparseable/absent source is NOT enforceable
 * (enforce + empty bypass).
 */
bool serberus_config_is_enforceable(const char *managed_plist_path);

/*
 * Decides WHICH config governs an authentication. Mirrors the daemon's
 * EffectiveConfigResolver so PAM and the daemon can never diverge:
 *
 *   MANAGED         — the delivered config is present AND enforceable, and
 *                     in enforce at least one pamBypass entry resolves.
 *   LAST_KNOWN_GOOD — it is not, but a snapshot FILE EXISTS at `lkg_path`
 *                     (profile removed, unscoped, or only a partial profile
 *                     landed). Read config from the snapshot; break-glass
 *                     survives. NOTE: existence alone selects this source — a
 *                     corrupt/hand-edited snapshot lands here too and then
 *                     fails CLOSED through the normal readers (enforce, no
 *                     bypass, daemon consulted), never in bootstrap.
 *   BOOTSTRAP       — neither: this Mac has never been configured. The caller
 *                     MUST pass sudo through untouched (PAM_IGNORE).
 *
 * `lkg_path` NULL/empty is treated as "no snapshot". Existence is probed with
 * lstat, and only ENOENT/ENOTDIR reads as absent (never access(), which
 * inside setuid sudo checks with the invoking user's real uid) — the contents are deliberately not consulted here, and nor is
 * the file-trust check below: a snapshot that exists but fails it still
 * selects LAST_KNOWN_GOOD, where the readers treat it as absent and so fail
 * CLOSED (enforce, no bypass) rather than re-entering bootstrap.
 */
int serberus_config_resolve_source(const char *managed_plist_path,
                                   const char *lkg_path);

/*
 * Answers whether a pamBypass name exists on this Mac (a user when
 * `is_group` is false, a group otherwise).
 */
typedef bool (*serberus_name_resolver)(const char *name, bool is_group);

/* Production resolver: getpwnam_r / getgrnam_r, retrying on ERANGE with a
 * growing buffer up to 1 MiB. A user resolves only under its canonical name
 * (the exact pw_name): break-glass matching is exact, so a case variant or an
 * alias that Open Directory would find can never match anyone. A group
 * resolves only when it has at least one member that is an existing account
 * (serberus_config_group_has_members); any other existing group is logged as
 * having no members and does not resolve. */
bool serberus_config_default_name_resolves(const char *name, bool is_group);

/* Whether an account's canonical name (pw_name) is exactly `name`; if so and
 * `uid` is not NULL, stores its uid. getpwnam_r with the growing buffer. */
bool serberus_config_user_uid_exact(const char *name, uid_t *uid);

/* serberus_config_user_uid_exact without the uid. */
bool serberus_config_user_exists(const char *name);

/* Answers whether some account's primary group is `gid`. */
typedef bool (*serberus_primary_gid_probe)(gid_t gid);

/* Production probe: a getpwent scan of the accounts the directory search
 * policy enumerates, bounded at 100,000 entries. A gid above INT32_MAX never
 * matches (dscacheutil prints it negative, and the installer preflight skips
 * it). The answer for each gid is kept for the life of the process. */
bool serberus_config_primary_gid_in_use(gid_t gid);

/* Whether `uuid_text` is a GeneratedUID that mbr_uuid_to_id maps to a USER id
 * for which getpwuid_r finds an account. A group's UUID, an unparseable
 * string, or a uid with no account does not count. */
bool serberus_config_generated_uid_names_user(const char *uuid_text);

/* Production: whether any value of the Open Directory GroupMembers attribute
 * of the group named `group` passes serberus_config_generated_uid_names_user. */
bool serberus_config_group_generated_uid_member(const char *group);

/* The directory lookups behind a group's break-glass membership. Injectable
 * so tests do not depend on the host's accounts. A NULL entry answers false. */
typedef struct serberus_group_probes
{
    /* An account whose canonical name is exactly `name` exists. */
    bool (*user_exists)(const char *name);
    /* A GroupMembers GeneratedUID of the group named `group` names an
     * existing account. */
    bool (*generated_uid_member)(const char *group);
    /* Some account's primary group is `gid`. */
    serberus_primary_gid_probe primary_gid_in_use;
} serberus_group_probes;

/* The production probes (serberus_config_user_exists,
 * serberus_config_group_generated_uid_member,
 * serberus_config_primary_gid_in_use). */
extern const serberus_group_probes serberus_config_default_group_probes;

/* The break-glass definition of a group with members, shared with the
 * daemon (LocalAccounts.groupHasMembers) and the installer preflight
 * (serberus_pam_group_resolves in pam-lib.sh). A member is any of:
 *   - a non-empty name in `members` (the group's gr_mem, NULL-terminated;
 *     NULL means none) that is exactly an existing account's name;
 *   - a GroupMembers GeneratedUID of the group named `group` that resolves to
 *     an existing account;
 *   - an account whose primary group is `gid`.
 * A deleted account's name left behind in the group does not count, and
 * nested groups do not count. NULL `probes` answers false. */
bool serberus_config_group_has_members(const char *group, char *const *members,
                                       gid_t gid, const serberus_group_probes *probes);

/* serberus_config_group_lookup outcomes. */
#define SERBERUS_GROUP_NOT_FOUND   0
#define SERBERUS_GROUP_EMPTY       1 /* exists, no member that resolves */
#define SERBERUS_GROUP_HAS_MEMBERS 2

/* getgrnam_r(name), classified by serberus_config_group_has_members with
 * `probes`. */
int serberus_config_group_lookup(const char *name, const serberus_group_probes *probes);

/* `string` as a malloc'd UTF-8 C string sized for it (the caller frees), or
 * NULL when it is NULL, can't be converted, or contains U+0000 (a C string
 * would silently end there, so "root\0x" would read as "root"). */
__attribute__((visibility("hidden")))
char *serberus_config_copy_cstring(CFStringRef string);

/*
 * serberus_config_resolve_source with an explicit resolver (tests). An
 * enforcing managed config counts as MANAGED only when at least one
 * pamBypass entry resolves; otherwise it falls back exactly like an
 * unenforceable one. NULL selects the production resolver.
 */
int serberus_config_resolve_source_with(const char *managed_plist_path,
                                        const char *lkg_path,
                                        serberus_name_resolver resolver);

/*
 * File trust. Every reader above honors a plist only when its directory is a
 * real (lstat, non-symlink) directory owned by the required owner and not
 * group/other-writable, AND the file — opened O_NOFOLLOW and checked on the
 * open descriptor — is a regular file owned by the required owner and not
 * group/other-writable. A file failing the checks reads as ABSENT (parity
 * with ManagedPreferencesReader / CFPreferencesSource). The required owner is
 * root (uid 0) in production; this covers both the managed plist
 * (/Library/Managed Preferences) and the snapshot (/Library/Application
 * Support/Serberus).
 *
 * Both functions below are HIDDEN: they exist for the test bundle (which
 * compiles this file directly) and are not exported from pam_serberus.so.
 *
 * serberus_config_set_required_owner_uid_for_testing — lets tests point the
 * readers at temp fixtures they own. Never called by the module.
 *
 * serberus_config_file_is_trusted_for_owner — the trust check alone, against
 * an explicit owner (does not touch the global), so tests can assert a
 * rejection without racing parallel tests that set the global.
 */
__attribute__((visibility("hidden")))
void serberus_config_set_required_owner_uid_for_testing(uid_t uid);

__attribute__((visibility("hidden")))
bool serberus_config_file_is_trusted_for_owner(const char *path, uid_t required_owner);

#ifdef __cplusplus
}
#endif

#endif /* SERBERUS_PAM_CONFIG_H */
