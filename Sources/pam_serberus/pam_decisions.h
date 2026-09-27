/*
 * pam_decisions.h — pure, header-only decision helpers for pam_serberus.so.
 *
 * Everything here is a side-effect-free function of its arguments (no file,
 * XPC, or PAM-handle access), so PAMConfigTests can exercise the exact code
 * the module runs. Header-only (static inline) on purpose: the module and the
 * test bundle both compile it from this one definition with no extra sources
 * to keep in the build lists.
 */

#ifndef SERBERUS_PAM_DECISIONS_H
#define SERBERUS_PAM_DECISIONS_H

#include <security/pam_appl.h> /* PAM_ESTABLISH_CRED, PAM_REINITIALIZE_CRED */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h> /* uid_t */

#include "pam_config.h" /* SERBERUS_CONFIG_SOURCE_* */
#include "serberus_xpc_keys.h" /* SERBERUS_XPC_DECISION_* */

#ifdef __cplusplus
extern "C" {
#endif

/* Signing identifier of the daemon (BundleConfig.daemonBundleID). */
#define SERBERUS_DAEMON_SIGNING_IDENTIFIER "com.herojoneslabs.serberus.daemon"

/* The sudoers drop-in the daemon provisions (BundleConfig.sudoersDropInPath). */
#define SERBERUS_SUDOERS_DROP_IN_PATH "/etc/sudoers.d/serberus"

/* ---- daemon peer pinning -------------------------------------------------- */

/* Length of an Apple Team ID. */
#define SERBERUS_TEAM_ID_LENGTH 10

/*
 * An Apple Team ID is exactly 10 upper-case alphanumerics. Anything else —
 * including a character that could close the quoted string in a requirement —
 * is refused rather than escaped, so the requirement text can never be
 * injected into.
 */
static inline bool serberus_team_id_is_well_formed(const char *team)
{
    if (team == NULL)
    {
        return false;
    }
    size_t length = strnlen(team, SERBERUS_TEAM_ID_LENGTH + 1);
    if (length != SERBERUS_TEAM_ID_LENGTH)
    {
        return false;
    }
    for (size_t i = 0; i < length; i++)
    {
        char c = team[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
        {
            return false;
        }
    }
    return true;
}

/*
 * Builds the code-signing requirement the daemon peer must satisfy into `out`:
 *
 *   team known:   identifier "<daemon>" and anchor apple generic
 *                 and certificate leaf[subject.OU] = "<team>"
 *   team NULL/"": identifier "<daemon>" and anchor apple generic
 *
 * The no-team form is for a module that is itself unsigned or ad-hoc (a dev
 * build): there is no team to pin to, but the peer must still carry the
 * daemon's identifier on an Apple-issued certificate, and the caller also
 * requires the peer to run as root.
 *
 * Returns false — and leaves `out` empty — for a malformed team or a buffer
 * too small to hold the whole requirement (never a truncated, weaker one).
 */
static inline bool serberus_daemon_peer_requirement(const char *team,
                                                    char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
    {
        return false;
    }
    out[0] = '\0';

    int written;
    if (team == NULL || team[0] == '\0')
    {
        written = snprintf(out, out_size,
                           "identifier \"%s\" and anchor apple generic",
                           SERBERUS_DAEMON_SIGNING_IDENTIFIER);
    }
    else
    {
        if (!serberus_team_id_is_well_formed(team))
        {
            return false;
        }
        written = snprintf(out, out_size,
                           "identifier \"%s\" and anchor apple generic and "
                           "certificate leaf[subject.OU] = \"%s\"",
                           SERBERUS_DAEMON_SIGNING_IDENTIFIER, team);
    }
    if (written < 0 || (size_t)written >= out_size)
    {
        out[0] = '\0';
        return false;
    }
    return true;
}

/* ---- daemon replies ------------------------------------------------------- */

/* The result of one daemon exchange (and of the whole ask). */
#define SERBERUS_DECIDE_DENY     0
#define SERBERUS_DECIDE_ALLOW    1
#define SERBERUS_DECIDE_UNREACH (-1) /* unreachable / reply timeout */
#define SERBERUS_DECIDE_PENDING  2   /* prompt in flight; keep polling */
#define SERBERUS_DECIDE_NATIVE   3   /* JIT admin in their window: step aside */

/*
 * Maps a reply's `decision` string to a SERBERUS_DECIDE_* code. Strict: only
 * the exact known values map to anything but DENY, so a missing, garbled or
 * future value fails closed.
 */
static inline int serberus_decision_code(const char *decision)
{
    if (decision == NULL)
    {
        return SERBERUS_DECIDE_DENY;
    }
    if (strcmp(decision, SERBERUS_XPC_DECISION_ALLOW) == 0)
    {
        return SERBERUS_DECIDE_ALLOW;
    }
    if (strcmp(decision, SERBERUS_XPC_DECISION_PROMPT_PENDING) == 0
        || strcmp(decision, SERBERUS_XPC_DECISION_PENDING) == 0)
    {
        return SERBERUS_DECIDE_PENDING;
    }
    if (strcmp(decision, SERBERUS_XPC_DECISION_NATIVE) == 0)
    {
        return SERBERUS_DECIDE_NATIVE;
    }
    return SERBERUS_DECIDE_DENY; /* "deny" or any unknown value */
}

/*
 * A poll reply that is neither allow, deny nor pending is a protocol error:
 * `native` is only ever an answer to the initial request, so seen on a poll it
 * counts as a deny.
 */
static inline int serberus_poll_code(int code)
{
    return code == SERBERUS_DECIDE_NATIVE ? SERBERUS_DECIDE_DENY : code;
}

/*
 * Whether pam_sm_authenticate marks the request gated (so pam_sm_setcred
 * clears sudo's ticket) once the daemon answered `decision`. A native reply is
 * NOT gated: the JIT admin gets sudo's native behaviour, ticket included (the
 * daemon clears that ticket when the window ends).
 */
static inline bool serberus_decision_marks_gated(int decision)
{
    return decision != SERBERUS_DECIDE_NATIVE;
}

/* ---- pam_sm_setcred ------------------------------------------------------- */

/*
 * Whether pam_sm_setcred should delete the invoking user's sudo timestamp.
 *
 * Only when `gated`: pam_sm_authenticate evaluated this request against the
 * daemon (enforce or audit) instead of stepping aside. Bootstrap, the kill
 * switch, monitor, pamBypass users and a `native` reply (a JIT admin inside
 * their window; see serberus_decision_marks_gated) get sudo's native ticket
 * behaviour.
 * sudo 1.9.x calls pam_setcred(PAM_REINITIALIZE_CRED) from begin_session
 * rather than PAM_ESTABLISH_CRED, so both flags count. (The primary control
 * for enrolled users is the drop-in's `timestamp_timeout=0`; this is defense
 * in depth, and keeps a gated admin from skipping the gate on a ticket.)
 */
static inline bool serberus_setcred_should_clear_timestamp(int flags, bool gated)
{
    return gated && (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) != 0;
}

/* sudo's per-user timestamp directory (sudo 1.9 `timestampdir`). */
#define SERBERUS_SUDO_TIMESTAMP_DIR "/var/db/sudo/ts"

/*
 * Whether `name` may be used as a file name under SERBERUS_SUDO_TIMESTAMP_DIR:
 * non-empty, no '/', and not "." or "..". Anything else could name a file
 * outside the directory (or the directory itself), so it is refused.
 */
static inline bool serberus_timestamp_user_is_safe(const char *name)
{
    if (name == NULL || name[0] == '\0')
    {
        return false;
    }
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    {
        return false;
    }
    return strchr(name, '/') == NULL;
}

/*
 * The user whose ticket pam_sm_setcred should clear, or NULL.
 *
 * sudo keys the ticket to the INVOKING user, which is what it sets PAM_RUSER
 * to, so `ruser` is the one that counts. `authenticated` (the PAM_USER
 * pam_sm_authenticate recorded with pam_set_data) is used only when PAM_RUSER
 * is unset: it is the invoking user by default, but the target or root under
 * `targetpw` / `rootpw` / `runaspw`. PAM_USER at setcred time is never used
 * (sudo 1.9 has reset it to the runas user by then). A PAM_RUSER that is set
 * but unsafe is refused outright, never replaced by `authenticated`.
 */
static inline const char *serberus_timestamp_ticket_user(const char *ruser,
                                                         const char *authenticated)
{
    const char *name = ruser != NULL ? ruser : authenticated;
    return serberus_timestamp_user_is_safe(name) ? name : NULL;
}

/*
 * Builds the NAME-keyed timestamp path of the ticket user
 * (serberus_timestamp_ticket_user) into `out`. sudo before 1.9.15 names the
 * ticket this way; pam_sm_setcred removes it as a fallback beside the uid file
 * (serberus_timestamp_uid_path).
 *
 * Returns false — and leaves `out` empty — when there is no usable name or the
 * path does not fit.
 */
static inline bool serberus_timestamp_path(const char *ruser,
                                           const char *authenticated,
                                           char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
    {
        return false;
    }
    out[0] = '\0';

    const char *name = serberus_timestamp_ticket_user(ruser, authenticated);
    if (name == NULL)
    {
        return false;
    }
    int written = snprintf(out, out_size, "%s/%s", SERBERUS_SUDO_TIMESTAMP_DIR, name);
    if (written < 0 || (size_t)written >= out_size)
    {
        out[0] = '\0';
        return false;
    }
    return true;
}

/*
 * Builds the UID-keyed timestamp path, "<dir>/<decimal uid>", into `out`.
 * sudo 1.9.15 and later (macOS ships 1.9.17) name each ticket after the
 * invoking user's numeric uid; see sudoers_timestamp(5). The caller resolves
 * the ticket user to its uid by exact name.
 *
 * Returns false — and leaves `out` empty — when the path does not fit.
 */
static inline bool serberus_timestamp_uid_path(uid_t uid, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
    {
        return false;
    }
    int written = snprintf(out, out_size, "%s/%u", SERBERUS_SUDO_TIMESTAMP_DIR,
                           (unsigned int)uid);
    if (written < 0 || (size_t)written >= out_size)
    {
        out[0] = '\0';
        return false;
    }
    return true;
}

/* ---- authentication posture ----------------------------------------------- */

/* What pam_sm_authenticate does for a user who is NOT in pamBypass. */
#define SERBERUS_POSTURE_PASS_THROUGH 0 /* PAM_IGNORE, daemon not asked */
#define SERBERUS_POSTURE_AUDIT        1 /* ask the daemon (it logs), then PAM_IGNORE */
#define SERBERUS_POSTURE_ENFORCE      2 /* ask the daemon; deny/unreachable -> deny */

/*
 * The posture for one authentication, from the resolved config source, the
 * kill switch, the effective enforcementMode ("enforce"/"audit"/"monitor"),
 * and whether the Serberus sudoers drop-in is on disk.
 *
 * The drop-in is what lets a STANDARD user reach sudo at all. After a switch
 * to audit/monitor or the kill switch the daemon removes it in its next
 * reload pass: at once when its watch on the managed config file sees the
 * change, otherwise on the next ~30 s reload tick. Either way there is a
 * window, and a never-configured Mac should not have a drop-in at all. While
 * it is still present, passing sudo through would let those
 * users run curated commands with no policy at all — so every posture that
 * would pass through (bootstrap, kill switch, monitor, audit) is ENFORCE
 * instead until the drop-in is gone. pamBypass users are exempt; the caller
 * checks them before consulting this.
 */
static inline int serberus_auth_posture(int config_source, bool kill_switch,
                                        const char *mode, bool drop_in_present)
{
    if (config_source == SERBERUS_CONFIG_SOURCE_BOOTSTRAP || kill_switch)
    {
        return drop_in_present ? SERBERUS_POSTURE_ENFORCE : SERBERUS_POSTURE_PASS_THROUGH;
    }
    if (mode != NULL && strcmp(mode, "monitor") == 0)
    {
        return drop_in_present ? SERBERUS_POSTURE_ENFORCE : SERBERUS_POSTURE_PASS_THROUGH;
    }
    if (mode != NULL && strcmp(mode, "audit") == 0)
    {
        return drop_in_present ? SERBERUS_POSTURE_ENFORCE : SERBERUS_POSTURE_AUDIT;
    }
    /* "enforce", NULL, or anything unrecognized: fail closed. */
    return SERBERUS_POSTURE_ENFORCE;
}

#ifdef __cplusplus
}
#endif

#endif /* SERBERUS_PAM_DECISIONS_H */
