/*
 * pam_serberus.so — Serberus PAM module.
 *
 * Installed at /usr/local/lib/pam/pam_serberus.so (444, root:wheel), referenced
 * by ABSOLUTE path from /etc/pam.d/sudo_local (/usr/lib/pam is on the sealed
 * read-only system snapshot on macOS 11+ and cannot hold third-party modules).
 * Bundle ID com.herojoneslabs.serberus.pam.
 *
 * Trust boundary: this module runs in the (untrusted) sudo process. It never
 * decides policy — it gathers the request, applies the break-glass bypass
 * checks, and asks the root daemon (the policy authority) over XPC. It fails
 * CLOSED: if the daemon is unreachable it hard-denies, never PAM_IGNORE,
 * unless a bypass already applied.
 *
 * Authentication logic (docs/SerberusPAM.md, "Authentication flow"):
 *   0. resolve the config SOURCE (below): managed, last-known-good, or
 *      bootstrap                          -> bootstrap: PAM_IGNORE, daemon not asked
 *   1. kill switch (daemonEnabled false)  -> PAM_IGNORE for EVERY user, daemon
 *      not asked (checked on the managed plist first, then on the source)
 *   2. user in pamBypass.users            -> PAM_IGNORE
 *   3. user in any pamBypass.groups       -> PAM_IGNORE   (mbr_check_membership)
 *   4. enforcementMode monitor            -> PAM_IGNORE   (no interception)
 *   5. ask daemon; audit mode             -> PAM_IGNORE   (pass-through, logged,
 *      even when the daemon is unreachable)
 *
 *   DROP-IN RULE (overrides 0, 1, 4 and 5 — serberus_auth_posture in
 *   pam_decisions.h): while the Serberus sudoers drop-in
 *   (/etc/sudoers.d/serberus, lstat regular file) is still on disk, NOTHING
 *   passes through for a user outside pamBypass. The drop-in is what lets
 *   standard users reach sudo at all; after a switch to audit/monitor or the
 *   kill switch the daemon removes it in its next reload pass (at once when
 *   its managed-config file watch fires, else on the ~30 s reload tick), and
 *   passing sudo through in that window would let those users run the
 *   curated commands with no policy. So bootstrap, kill switch, monitor and
 *   audit are evaluated exactly as enforce (ask the daemon; deny/unreachable
 *   -> deny) until the drop-in is gone. pamBypass users still pass through
 *   (steps 2-3 run first, against the source's own bypass; a bootstrap Mac
 *   has none). Bootstrap is pass-through only when no drop-in exists.
 *
 *   5a. daemon answers native            -> PAM_IGNORE (a JIT admin inside
 *      their window and in `admin` right now: sudo runs exactly as native
 *      macOS, password prompt included; the request is not marked gated, so
 *      sudo's ticket is kept — the daemon deletes it when the window ends).
 *      Only the initial reply may say native; on a poll it is a deny, and any
 *      decision string this build does not know is a deny.
 *   6. enforce + a command form the module can't evaluate (sudo_args: unknown
 *      options, -s/-i/-e/..., sudoedit by program name, empty argv[0])
 *                                         -> deny, whatever the daemon said
 *   7. enforce + decision allow           -> PAM_SUCCESS
 *   8. enforce + deny / unreachable       -> PAM_MAXTRIES (hard deny; MAXTRIES
 *      so sudo ends its retry loop — with the sudo_local `requisite` control
 *      the stack also returns immediately, no post-deny password theater; a
 *      same-process latch keeps retries from re-raising the Sentinel prompt)
 *
 * Config source (step 0, mirroring the daemon's EffectiveConfigResolver so the
 * two halves of the product can never disagree about which config is in force):
 *
 *   MANAGED         — the delivered config is present AND enforceable. Normal.
 *   LAST_KNOWN_GOOD — it is not (profile removed/unscoped, or only a partial
 *                     profile such as a standalone sudoEnrollment landed), but
 *                     the daemon's snapshot file exists: read enforcementMode +
 *                     pamBypass from it. The snapshot is enforceable BY
 *                     CONSTRUCTION (the daemon only ever persists a config that
 *                     is), so BREAK-GLASS SURVIVES profile removal — and so
 *                     removing the profile can never disable Serberus.
 *   BOOTSTRAP       — neither exists: this Mac has NEVER been configured (the
 *                     Jamf Core pkg beat the config profile through the APNS
 *                     queue). Pass sudo through untouched (PAM_IGNORE): do not
 *                     consult the daemon, deny nothing. The daemon is in
 *                     awaitingConfig and mutating nothing; when the profile
 *                     lands it snapshots, and this Mac can never return here.
 *
 * That bootstrap pass-through is the ONLY fail-open in this module, and it is
 * gated on the ABSENCE OF THE SNAPSHOT FILE — not on its contents. A snapshot
 * that exists but is corrupt selects LAST_KNOWN_GOOD, where the readers fail
 * closed (enforce, no bypass, daemon consulted).
 *
 * Config files are honored only when root-owned and not group/other-writable,
 * inside a root-owned, non-group/other-writable real directory, and opened
 * O_NOFOLLOW (pam_config.c); anything else reads as absent.
 *
 * Daemon identity (ask_daemon): the Mach service is looked up in the SYSTEM
 * domain (XPC_CONNECTION_MACH_SERVICE_PRIVILEGED) — sudo runs in the invoking
 * user's launchd session, where a user LaunchAgent could otherwise advertise
 * the same name and answer "allow". The peer is also pinned by a code-signing
 * requirement (daemon identifier + anchor apple generic + this module's own
 * Team ID when it has one) and must run as root (euid 0) on every reply. Any
 * failure is treated as the daemon being unreachable (enforce: deny).
 */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/openpam.h> /* pam_error() for user-facing deny messages */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h> /* SecStaticCode*: the module's own Team ID */
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <os/log.h>
#include <membership.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>  /* snprintf */
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <dlfcn.h>       /* dladdr: this module's own path */
#include <crt_externs.h> /* _NSGetArgc/_NSGetArgv: sudo's own argc/argv */

#include "pam_config.h"
#include "pam_decisions.h"
#include "sudo_args.h"
#include "serberus_xpc_keys.h"

#define SERBERUS_MACH_SERVICE  "com.herojoneslabs.serberus.daemon"

/* Computer-level MDM profiles land here. A euid-0 sudo process never sees this
 * layer through CFPreferences composite reads (the daemon has the same
 * limitation), so pam_config reads the plist directly, and
 * reads nothing else. Hardcoded — never environment-derived. */
#define SERBERUS_MANAGED_CONFIG_PLIST \
    "/Library/Managed Preferences/com.herojoneslabs.serberus.config.plist"

/* The daemon's last-known-good config snapshot (SERBERUS_LKG_CONFIG_PATH, from
 * pam_config.h) is the fallback source when the managed config is absent or
 * unsafe, and its EXISTENCE is the "this Mac has been configured" marker. Also
 * hardcoded — never environment-derived. */

/* Unified-log handle. Subsystem matches BundleConfig.logSubsystem so PAM lines
 * sit alongside the daemon's:
 *   log stream --predicate 'subsystem == "com.herojoneslabs.serberus"'
 * Never logs the invoking user's arguments — only the config-resolution branch. */
static os_log_t serberus_log(void)
{
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.herojoneslabs.serberus", "pam");
    });
    return log;
}

/* Non-prompted XPC reply timeout. Every single send-with-reply —
 * the initial request and each poll — is bounded by this, so no PAM thread ever
 * blocks more than 5 seconds on one call. */
#define SERBERUS_XPC_TIMEOUT_SECONDS 5

/* Prompt round-trip. A `.prompt` rule returns prompt_pending + a
 * requestID; PAM then polls while the user decides. The poll phase is bounded
 * BOTH by a poll count and by a hard wall-clock deadline: a responsive daemon
 * resolves around its own 60s watchdog (PAMEvaluator.maxPromptWindowSeconds) —
 * still inside this ~64s poll-count window, with ~4s / ~4 polls of margin to
 * observe the deny — while a hung daemon, whose each poll eats the full 5s reply
 * timeout, is capped at the deadline rather than 80 * (0.8 + 5)s ≈ 7.8 minutes.
 * Worst-case block is SERBERUS_PROMPT_MAX_SECONDS + one in-flight reply timeout. */
#define SERBERUS_PROMPT_POLL_INTERVAL_US 800000 /* 0.8 seconds between polls */
#define SERBERUS_PROMPT_MAX_POLLS        80     /* upper bound on poll count */
#define SERBERUS_PROMPT_MAX_SECONDS      70     /* hard wall-clock cap on the poll phase */

/* The SERBERUS_DECIDE_* result codes of a daemon exchange live in
 * pam_decisions.h, next to serberus_decision_code(), which maps the reply. */

/* ---- config readers (pam_config: the managed plist or the snapshot, nothing else) ----
 *
 * Every reader below takes the RESOLVED plist path chosen by
 * serberus_config_resolve_source, so the managed config and the last-known-good
 * snapshot go through byte-identical parsing. */

static bool user_in_bypass_users(const char *config_path,
                                 const char *user)
{
    return serberus_config_user_in_bypass_users(config_path, user);
}

/* Membership-framework group check — catches users added via dscl, which a
 * bare getgrnam member-list parse would miss. */
static bool user_in_group_membership(const char *user, CFStringRef group_name)
{
    char *group_cstr = serberus_config_copy_cstring(group_name);
    if (group_cstr == NULL)
    {
        return false;
    }

    struct passwd *pw = getpwnam(user);
    struct group *gr = getgrnam(group_cstr);
    free(group_cstr);
    if (pw == NULL || gr == NULL)
    {
        return false;
    }

    uuid_t user_uuid;
    uuid_t group_uuid;
    if (mbr_uid_to_uuid(pw->pw_uid, user_uuid) != 0)
    {
        return false;
    }
    if (mbr_gid_to_uuid(gr->gr_gid, group_uuid) != 0)
    {
        return false;
    }

    int is_member = 0;
    if (mbr_check_membership(user_uuid, group_uuid, &is_member) != 0)
    {
        return false;
    }
    return is_member != 0;
}

static bool user_in_bypass_groups(const char *config_path,
                                  const char *user)
{
    bool found = false;
    CFArrayRef groups = serberus_config_copy_bypass_array(
        config_path, CFSTR("groups"));
    if (groups != NULL)
    {
        CFIndex count = CFArrayGetCount(groups);
        for (CFIndex i = 0; i < count; i++)
        {
            /* pam_config filters to string members; the type check stays as
             * defense in depth inside a requisite PAM module. */
            CFStringRef group = (CFStringRef)CFArrayGetValueAtIndex(groups, i);
            if (group != NULL
                && CFGetTypeID(group) == CFStringGetTypeID()
                && user_in_group_membership(user, group))
            {
                found = true;
                break;
            }
        }
        CFRelease(groups);
    }
    return found;
}

/* enforcementMode: "enforce" (default) | "audit" | "monitor". */
static void copy_enforcement_mode(const char *config_path,
                                  char *out, size_t out_size)
{
    serberus_config_copy_enforcement_mode(config_path, out, out_size);
}

/* Max length of an admin-supplied sudo message template (sudoDenyMessage /
 * sudoAllowMessage); longer values are truncated by the reader. */
#define SERBERUS_SUDO_MSG_MAX 1024

/* Max length of the DISPLAY command line: a full path plus a generous argv
 * tail. Display only — matching always uses the command and argv separately. */
#define SERBERUS_CMDLINE_MAX (PATH_MAX + 512)

/* Joins the resolved command path and its arguments into ONE display string —
 * "/usr/local/bin/jamf recon". `sudo`'s own denial text names the whole command
 * line, so a Serberus message naming only the binary reads as a different (and
 * more confusing) refusal: "'/usr/local/bin/jamf' is not permitted" is wrong
 * when `jamf recon` IS permitted and only `jamf policy` was refused.
 *
 * Bounded: strlcpy/strlcat always NUL-terminate and truncate rather than
 * overflow. MUST be called BEFORE free_argv() — argv does not survive it.
 * `argc` is the count of arguments AFTER the command (discover_command's
 * contract), so the join reproduces the invocation as the user typed it. */
static void build_command_line(const char *command, char *const *argv, int argc,
                               char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
    {
        return;
    }
    strlcpy(out, command, out_size);
    for (int i = 0; i < argc; i++)
    {
        if (argv == NULL || argv[i] == NULL)
        {
            continue;
        }
        strlcat(out, " ", out_size);
        strlcat(out, argv[i], out_size);
    }
}

/* Emits a user-facing policy message through the PAM conversation.
 *
 * `template` is ADMIN-SUPPLIED (from the config profile). The literal token
 * "{command}" is replaced with `command_line` (the command AND its arguments)
 * using bounded byte copies — NEVER via printf — so neither the template nor the
 * command line (which may contain % or %n) can reach a format-string
 * interpreter. The assembled text is then handed to pam_error/pam_info with a
 * literal "%s" format for the same reason. `is_error` selects PAM_ERROR_MSG
 * (deny) vs PAM_TEXT_INFO (allow); both are no-ops when the app installed no
 * conversation, so this can never crash a requisite module. */
static void emit_policy_message(pam_handle_t *pamh, const char *template,
                                const char *command_line, int is_error)
{
    static const char token[] = "{command}";
    const size_t token_len = sizeof(token) - 1;

    char out[SERBERUS_SUDO_MSG_MAX + SERBERUS_CMDLINE_MAX];
    size_t oi = 0;
    for (size_t i = 0; template[i] != '\0' && oi + 1 < sizeof(out);)
    {
        if (strncmp(&template[i], token, token_len) == 0)
        {
            for (size_t c = 0; command_line[c] != '\0' && oi + 1 < sizeof(out); c++)
            {
                out[oi++] = command_line[c];
            }
            i += token_len;
        }
        else
        {
            out[oi++] = template[i++];
        }
    }
    out[oi] = '\0';

    if (is_error)
    {
        pam_error(pamh, "%s", out);
    }
    else
    {
        pam_info(pamh, "%s", out);
    }
}

/* ---- command discovery (this process is sudo; read its own argv) ---- */

/*
 * Copies the path sudo was exec'd through — the string the kernel stores
 * FIRST in KERN_PROCARGS2, ahead of argv — into out. This is the path given
 * to execve (a symlink's own name when invoked through one). getprogname()
 * follows argv[0], not this path, so it is checked alongside both. Returns
 * false on any failure, including a buffer with no NUL inside it or an empty
 * path.
 */
static bool copy_exec_path(char *out, size_t out_size)
{
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, getpid() };
    size_t size = 0;
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size <= sizeof(int))
    {
        return false;
    }
    char *buffer = (char *)malloc(size);
    if (buffer == NULL)
    {
        return false;
    }
    bool ok = false;
    if (sysctl(mib, 3, buffer, &size, NULL, 0) == 0 && size > sizeof(int))
    {
        const char *path = buffer + sizeof(int);
        size_t available = size - sizeof(int);
        size_t length = strnlen(path, available);
        if (length > 0 && length < available && length < out_size)
        {
            memcpy(out, path, length + 1);
            ok = true;
        }
    }
    free(buffer);
    return ok;
}

/*
 * Finds the command this sudo process will run, from sudo's own argv, and
 * returns it in command_out (canonicalized) with its arguments in argv_out
 * (caller frees each + the array). On any failure command_out[0] is '\0' and
 * *unevaluable_out stays true.
 *
 * The argument vector comes from _NSGetArgc()/_NSGetArgv(): this module runs
 * inside sudo, so these are exactly the argc/argv sudo's main() received.
 * sudo 1.9.17 never rewrites that vector before PAM runs — initprogname2()
 * only calls setprogname(), and parse_args() walks it with a '+'-prefixed
 * (non-permuting) getopt_long and advances a local copy of the pointer. It is
 * NOT re-assembled from KERN_PROCARGS2: that buffer has no separator between
 * the exec path's NUL padding and argv[0], so an empty argv[0] vanished into
 * the padding and every argument shifted by one (the last "argument" being
 * the first environment string).
 */
static void discover_command(char *command_out, size_t command_size,
                             char ***argv_out, int *argv_count_out,
                             bool *unevaluable_out)
{
    command_out[0] = '\0';
    *argv_out = NULL;
    *argv_count_out = 0;
    /* Until a command is positively identified, the invocation is treated as
     * one Serberus can't evaluate, and enforce mode denies it. */
    *unevaluable_out = true;

    int *argc_ptr = _NSGetArgc();
    char ***argv_ptr = _NSGetArgv();
    if (argc_ptr == NULL || argv_ptr == NULL || *argv_ptr == NULL)
    {
        return;
    }
    int argc = *argc_ptr;
    char **args = *argv_ptr;
    if (argc < 1 || args[0] == NULL || args[0][0] == '\0')
    {
        return; /* no argv[0], or an empty one: unevaluable */
    }

    /* sudoedit is chosen by the program name, not by an option: getprogname()
     * (what sudo's parse_args used), the execve path it came from, and
     * argv[0] must all say "sudo". */
    char exec_path[PATH_MAX];
    if (!copy_exec_path(exec_path, sizeof(exec_path))
        || !serberus_sudo_invocation_name_ok(getprogname(), exec_path, args[0]))
    {
        return;
    }

    /* Find the command exactly as sudo's own parser does. Anything it can't
     * be certain about (unknown options, -s/-i/-e/-l and other modes that
     * don't run the named command, VAR=value assignments) leaves the command
     * empty and the invocation marked unevaluable. */
    int index = 0;
    serberus_sudo_args_result parsed =
        serberus_find_sudo_command(argc, (const char *const *)args, &index);
    if (parsed != SERBERUS_SUDO_ARGS_COMMAND)
    {
        return;
    }

    /* Resolve the command path. A command containing a '/' is already a path
     * (absolute or relative): realpath() handles it. A BARE name is what sudo
     * looks up on PATH — search it the way sudoers' find_path() does (see
     * serberus_find_in_path for the residual differences). In every case an
     * unresolved command falls back to the raw name (fail-closed: the daemon's
     * requireExists + canonicalization then denies). */
    const char *cmd = args[index];
    char resolved[PATH_MAX];
    if (strchr(cmd, '/') != NULL)
    {
        if (realpath(cmd, resolved) != NULL)
        {
            strlcpy(command_out, resolved, command_size);
        }
        else
        {
            strlcpy(command_out, cmd, command_size);
        }
    }
    else if (!serberus_find_in_path(cmd, getenv("PATH"), command_out, command_size))
    {
        strlcpy(command_out, cmd, command_size);
    }

    /* Remaining tokens are the command's arguments. */
    int rest = argc - (index + 1);
    if (rest > 0)
    {
        char **rest_argv = (char **)calloc((size_t)rest, sizeof(char *));
        if (rest_argv == NULL)
        {
            /* Fail closed: never ship a partial request (command without its
             * argv could match a broader rule than the real invocation). */
            command_out[0] = '\0';
            return;
        }
        for (int j = 0; j < rest; j++)
        {
            const char *arg = args[index + 1 + j];
            rest_argv[j] = arg != NULL ? strdup(arg) : NULL;
            if (rest_argv[j] == NULL)
            {
                for (int k = 0; k < j; k++)
                {
                    free(rest_argv[k]);
                }
                free(rest_argv);
                command_out[0] = '\0';
                return;
            }
        }
        *argv_out = rest_argv;
        *argv_count_out = rest;
    }
    *unevaluable_out = false;
}

static void free_argv(char **argv, int count)
{
    if (argv == NULL)
    {
        return;
    }
    for (int i = 0; i < count; i++)
    {
        free(argv[i]);
    }
    free(argv);
}

/* ---- daemon XPC round trip ---- */

/*
 * The Team ID in THIS module's own code signature, "" when the signature is
 * readable but carries no team (unsigned / ad-hoc dev build), or the "?"
 * sentinel when it can't be read at all. Computed once per process.
 *
 * SecCodeCopySelf names the host process (sudo), not a loaded bundle, so the
 * module finds its own file with dladdr and reads that file's static
 * signature. The Team ID is only used to PIN the daemon peer (the module
 * trusts only a daemon from its own team). Only a signature that was read and
 * has no team degrades to the no-team requirement (the daemon's identifier on
 * an Apple-issued certificate plus euid 0). A signature that can't be read,
 * or a team value that is present but malformed, yields a value the
 * requirement builder refuses, so the daemon reads as unreachable (fail
 * closed), never as the weaker form.
 */
static const char *serberus_module_team_id(void)
{
    static char team[64];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        /* Until the signature has been read, the answer is "unreadable". */
        strlcpy(team, "?", sizeof(team));
        const char *failed = NULL;
        Dl_info info;
        CFURLRef url = NULL;
        SecStaticCodeRef code = NULL;
        CFDictionaryRef signing = NULL;
        if (dladdr((const void *)&serberus_module_team_id, &info) == 0
            || info.dli_fname == NULL || info.dli_fname[0] == '\0')
        {
            failed = "dladdr found no path for the module";
        }
        else if ((url = CFURLCreateFromFileSystemRepresentation(
                      NULL, (const UInt8 *)info.dli_fname,
                      (CFIndex)strlen(info.dli_fname), false)) == NULL)
        {
            failed = "the module path could not be made a URL";
        }
        else if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess
                 || code == NULL)
        {
            failed = "SecStaticCodeCreateWithPath failed";
        }
        else if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing)
                     != errSecSuccess
                 || signing == NULL)
        {
            failed = "SecCodeCopySigningInformation failed";
        }
        else
        {
            CFTypeRef value = CFDictionaryGetValue(signing, kSecCodeInfoTeamIdentifier);
            if (value == NULL)
            {
                team[0] = '\0'; /* readable, no team: the dev-build form */
            }
            else if (CFGetTypeID(value) != CFStringGetTypeID()
                     || !CFStringGetCString((CFStringRef)value, team, sizeof(team),
                                            kCFStringEncodingUTF8))
            {
                /* Unrepresentable / oversized: a value the builder refuses. */
                strlcpy(team, "?", sizeof(team));
            }
        }
        if (signing != NULL)
        {
            CFRelease(signing);
        }
        if (code != NULL)
        {
            CFRelease(code);
        }
        if (url != NULL)
        {
            CFRelease(url);
        }
        if (failed != NULL)
        {
            os_log_error(serberus_log(),
                         "pam: cannot read the module's own code signature (%{public}s) — "
                         "refusing to trust any daemon peer",
                         failed);
        }
    });
    return team;
}

/* Sends one request and waits up to SERBERUS_XPC_TIMEOUT_SECONDS for the reply.
 * Returns one of the SERBERUS_DECIDE_* codes. When the reply is prompt_pending
 * or pending, the result is SERBERUS_DECIDE_PENDING; if the reply also carries a
 * requestID and request_id_out is non-NULL, it is copied out for polling.
 * A deny reply may carry an optional verdict detail ("denied" = the user
 * declined the prompt, "timed-out" = it expired); when verdict_out is
 * non-NULL it is copied out. Absent on older daemons — callers must treat an
 * empty verdict as "no detail", never as an error. */
static int send_and_decode(xpc_connection_t conn, xpc_object_t request,
                           char *request_id_out, size_t request_id_size,
                           char *verdict_out, size_t verdict_size)
{
    __block int code = SERBERUS_DECIDE_UNREACH;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

    xpc_connection_send_message_with_reply(conn, request, queue, ^(xpc_object_t reply) {
        /* A peer failing the code-signing requirement never gets here as a
         * dictionary (libxpc delivers XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT
         * -> stays UNREACH). The euid is known once a message has arrived from
         * the peer — i.e. now — and must be root: the real daemon is a root
         * LaunchDaemon, and nothing else may answer for it. */
        if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY && xpc_connection_get_euid(conn) != 0)
        {
            os_log_error(serberus_log(),
                         "pam: daemon peer is not running as root (euid %u) — "
                         "treating the daemon as unreachable",
                         (unsigned)xpc_connection_get_euid(conn));
        }
        else if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY)
        {
            /* Strict: a missing or unknown decision is a deny (fail closed). */
            const char *decision = xpc_dictionary_get_string(reply, SERBERUS_XPC_KEY_DECISION);
            code = serberus_decision_code(decision);
            if (code == SERBERUS_DECIDE_PENDING)
            {
                const char *request_id = xpc_dictionary_get_string(reply, SERBERUS_XPC_KEY_REQUEST_ID);
                if (request_id != NULL && request_id_out != NULL)
                {
                    strlcpy(request_id_out, request_id, request_id_size);
                }
            }
            else if (code == SERBERUS_DECIDE_DENY)
            {
                const char *verdict = xpc_dictionary_get_string(reply, SERBERUS_XPC_KEY_VERDICT);
                if (verdict != NULL && verdict_out != NULL)
                {
                    strlcpy(verdict_out, verdict, verdict_size);
                }
            }
        }
        dispatch_semaphore_signal(sema);
    });

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW,
                                             (int64_t)SERBERUS_XPC_TIMEOUT_SECONDS * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(sema, deadline) != 0)
    {
        code = SERBERUS_DECIDE_UNREACH; /* timeout -> unreachable */
    }
    /* Deliberately do NOT dispatch_release(sema): on the timeout path the reply
     * handler is still outstanding and will signal `sema` when it eventually
     * fires (or the connection is cancelled). The block does not retain the
     * semaphore (non-ARC C), so releasing it here would be a use-after-free.
     * `sema` is reclaimed when this short-lived PAM process exits. */
    return code;
}

/* Returns 1 = allow, 0 = deny, -1 = unreachable/timeout, and
 * SERBERUS_DECIDE_NATIVE when the daemon answered the initial request with
 * `native` (a JIT admin inside their window).
 *
 * Two-phase: the initial sudo request gets a 5s reply. A silent
 * allow/deny returns immediately. A `.prompt` rule returns prompt_pending + a
 * requestID; PAM then polls the same connection every 0.8s for up to ~64s,
 * each poll its own bounded 5s exchange, until the user's verdict arrives.
 *
 * Outcome detail (for user-facing messaging only — never for the decision):
 *   *prompted_out  = 1 when a prompt round-trip happened (a Sentinel prompt
 *                    was raised for this request).
 *   *timed_out_out = 1 when a prompted request ended by expiry rather than an
 *                    explicit user choice (daemon-reported "timed-out" verdict,
 *                    or the local poll window elapsing while the daemon was
 *                    still reachable). */
static int ask_daemon(const char *user, const char *command,
                      char **argv, int argv_count, const char *tty,
                      int *prompted_out, int *timed_out_out)
{
    *prompted_out = 0;
    *timed_out_out = 0;

    /* Pin the peer BEFORE creating the connection: a requirement that can't
     * be built (malformed team) means no trustworthy daemon -> unreachable. */
    char requirement[256];
    if (!serberus_daemon_peer_requirement(serberus_module_team_id(),
                                          requirement, sizeof(requirement)))
    {
        os_log_error(serberus_log(),
                     "pam: cannot build the daemon code-signing requirement — "
                     "treating the daemon as unreachable");
        return -1;
    }

    /* PRIVILEGED: look the name up in the system (root) bootstrap, never the
     * invoking user's session, where a user LaunchAgent could squat on it. */
    xpc_connection_t conn = xpc_connection_create_mach_service(
        SERBERUS_MACH_SERVICE, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (conn == NULL)
    {
        return -1;
    }
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        (void)event; /* connection-level errors handled via the reply timeout */
    });
    if (xpc_connection_set_peer_code_signing_requirement(conn, requirement) != 0)
    {
        os_log_error(serberus_log(),
                     "pam: rejected daemon code-signing requirement — treating "
                     "the daemon as unreachable");
        /* libxpc traps on releasing a never-resumed connection. Resuming sends
         * nothing (a Mach-service connection only connects on first send), and
         * the cancel lands before any message could. */
        xpc_connection_resume(conn);
        xpc_connection_cancel(conn);
        xpc_release(conn);
        return -1;
    }
    xpc_connection_resume(conn);

    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(request, SERBERUS_XPC_KEY_TYPE, SERBERUS_XPC_TYPE_SUDO);
    xpc_dictionary_set_string(request, SERBERUS_XPC_KEY_USER, user);
    xpc_dictionary_set_string(request, SERBERUS_XPC_KEY_COMMAND, command);
    xpc_dictionary_set_int64(request, SERBERUS_XPC_KEY_PID, (int64_t)getpid());
    if (tty != NULL)
    {
        xpc_dictionary_set_string(request, SERBERUS_XPC_KEY_TTY, tty);
    }

    xpc_object_t argv_array = xpc_array_create(NULL, 0);
    for (int i = 0; i < argv_count; i++)
    {
        xpc_array_set_string(argv_array, XPC_ARRAY_APPEND, argv[i]);
    }
    xpc_dictionary_set_value(request, SERBERUS_XPC_KEY_ARGV, argv_array);
    xpc_release(argv_array); /* the request now retains it */

    /* Phase 1: the initial request. */
    char request_id[64] = {0};
    int code = send_and_decode(conn, request, request_id, sizeof(request_id), NULL, 0);
    xpc_release(request); /* libxpc retains its own copy for the in-flight send */
    if (code != SERBERUS_DECIDE_PENDING || request_id[0] == '\0')
    {
        xpc_connection_cancel(conn);
        xpc_release(conn);
        /* PENDING without a requestID is unsatisfiable: fail closed. */
        return (code == SERBERUS_DECIDE_PENDING) ? -1 : code;
    }
    /* From here only allow / deny / pending are valid answers. */

    *prompted_out = 1;

    /* Phase 2: poll until the user decides or the window elapses. The loop is
     * bounded by both the poll count and a hard wall-clock deadline, so a hung
     * daemon (each poll eating the full reply timeout) cannot stretch the block
     * far past the deadline. */
    int result = -1;
    int daemon_answered = 0; /* any poll reply at all (pending counts) */
    char verdict[24] = {0};
    time_t poll_start = time(NULL);
    for (int i = 0; i < SERBERUS_PROMPT_MAX_POLLS; i++)
    {
        if (time(NULL) - poll_start >= SERBERUS_PROMPT_MAX_SECONDS)
        {
            break; /* deadline reached -> classified below */
        }

        usleep(SERBERUS_PROMPT_POLL_INTERVAL_US);

        xpc_object_t poll = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(poll, SERBERUS_XPC_KEY_TYPE, SERBERUS_XPC_TYPE_POLL_PROMPT);
        xpc_dictionary_set_string(poll, SERBERUS_XPC_KEY_REQUEST_ID, request_id);

        /* send_and_decode is synchronous, so the poll dict is done once it
         * returns — release it so the poll window doesn't accumulate dicts. */
        int poll_code = serberus_poll_code(send_and_decode(conn, poll, NULL, 0, verdict, sizeof(verdict)));
        xpc_release(poll);
        if (poll_code != SERBERUS_DECIDE_UNREACH)
        {
            daemon_answered = 1;
        }
        if (poll_code == SERBERUS_DECIDE_ALLOW)
        {
            result = 1;
            break;
        }
        if (poll_code == SERBERUS_DECIDE_DENY)
        {
            result = 0;
            /* Daemon-side timeout also arrives as a deny; the verdict detail
             * (absent from older daemons) tells the two apart for messaging. */
            if (strcmp(verdict, SERBERUS_XPC_VERDICT_TIMED_OUT) == 0)
            {
                *timed_out_out = 1;
            }
            break;
        }
        /* PENDING (still waiting) or a transient UNREACH: keep polling. */
    }

    /* Window elapsed with the daemon still answering polls: the PROMPT timed
     * out (deny), not the service. Never-answered stays -1 (outage). */
    if (result == -1 && daemon_answered)
    {
        result = 0;
        *timed_out_out = 1;
    }

    xpc_connection_cancel(conn);
    xpc_release(conn);
    return result;
}

/* ---- PAM entry points ---- */

/* Set once Serberus has denied in THIS sudo process. sudo re-runs the whole
 * auth stack on every password retry — in the same process, so the module
 * instance (and this flag) persist across rounds. Without it, each retry
 * would re-ask the daemon, re-raise the Sentinel prompt, and re-print the
 * denial — the "looping prompt" bug. A sudo process serves exactly one
 * user+command, so the latch can never leak across requests. */
static int serberus_denied_this_process = 0;

/* pam_set_data keys read back by pam_sm_setcred. GATED is present only when
 * pam_sm_authenticate evaluated the request against the daemon (enforce or
 * audit); AUTH_USER is the PAM_USER it authenticated, the fallback timestamp
 * name when PAM_RUSER is unset. */
#define SERBERUS_PAM_DATA_GATED     "com.herojoneslabs.serberus.pam.gated"
#define SERBERUS_PAM_DATA_AUTH_USER "com.herojoneslabs.serberus.pam.auth_user"

static void serberus_free_pam_data(pam_handle_t *pamh, void *data, int status)
{
    (void)pamh;
    (void)status;
    free(data);
}

static void serberus_keep_pam_data(pam_handle_t *pamh, void *data, int status)
{
    (void)pamh;
    (void)data;
    (void)status;
}

/* Marks this request as gated for pam_sm_setcred and records `user`. Best
 * effort: a failed record only loses the fallback name (setcred still uses
 * PAM_RUSER); a failed mark leaves sudo's ticket alone, which is the native
 * behaviour and what the drop-in's timestamp_timeout=0 already covers for
 * enrolled users. */
static void record_gated_request(pam_handle_t *pamh, const char *user)
{
    static const char gated_marker = 1;
    (void)pam_set_data(pamh, SERBERUS_PAM_DATA_GATED, (void *)&gated_marker,
                       serberus_keep_pam_data);

    char *auth_user = strdup(user);
    if (auth_user != NULL
        && pam_set_data(pamh, SERBERUS_PAM_DATA_AUTH_USER, auth_user,
                        serberus_free_pam_data) != PAM_SUCCESS)
    {
        free(auth_user);
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;

    if (serberus_denied_this_process)
    {
        /* Already denied this invocation: end sudo's retry loop silently
         * (message was printed on the first round). */
        return PAM_MAXTRIES;
    }

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL)
    {
        return PAM_AUTH_ERR; /* fail closed */
    }

    /*
     * Choosing the config source — which config governs this authentication?
     *
     * The MANAGED source is the MDM-written plist; the LAST_KNOWN_GOOD source is
     * the daemon's snapshot file. Each is read on its own, with no CFPreferences
     * layer behind it, so nothing but management or the snapshot can contribute
     * the break-glass we are relying on.
     *
     * Only an explicit BOOTSTRAP verdict passes sudo through; ANY other value —
     * including one this build does not recognize — takes the fail-closed
     * MANAGED path, so a future/garbled return can never become a fail-open.
     */
    const char *config_path = SERBERUS_MANAGED_CONFIG_PLIST;

    int config_source = serberus_config_resolve_source(SERBERUS_MANAGED_CONFIG_PLIST,
                                                       SERBERUS_LKG_CONFIG_PATH);

    /* Is the Serberus sudoers drop-in still on disk? While it is, nothing
     * passes through for a non-bypass user (the DROP-IN RULE in the header
     * comment; serberus_auth_posture). */
    struct stat drop_in_st;
    bool drop_in_present = lstat(SERBERUS_SUDOERS_DROP_IN_PATH, &drop_in_st) == 0
                           && S_ISREG(drop_in_st.st_mode);

    bool kill_switch = false;
    if (config_source == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
    {
        /* This Mac has never had a usable config: no delivered config AND no
         * last-known-good snapshot. Serberus is INERT — sudo behaves exactly as
         * it would without the module. Nothing is denied, the daemon is not
         * consulted, and the daemon (awaitingConfig) is mutating nothing either.
         * The ~30s managed-prefs poll re-evaluates; when the profile lands, the
         * daemon writes the snapshot and this branch is unreachable forever.
         * (Unless a Serberus drop-in is on disk — then the posture below is
         * ENFORCE with no bypass: config_path stays the absent managed plist.) */
        if (!drop_in_present)
        {
            os_log(serberus_log(),
                   "pam: awaiting config (no managed config, no last-known-good "
                   "snapshot at %{public}s) — passing sudo through untouched",
                   SERBERUS_LKG_CONFIG_PATH);
            return PAM_IGNORE;
        }
        os_log_error(serberus_log(),
                     "pam: no config and no last-known-good snapshot, but the "
                     "sudoers drop-in %{public}s exists — enforcing (no bypass)",
                     SERBERUS_SUDOERS_DROP_IN_PATH);
    }
    else
    {
        /* Kill switch on a PRESENT managed config, checked on the MANAGED config
         * DIRECTLY and BEFORE the last-known-good fallback below. A kill switch is
         * `daemonEnabled == false` regardless of whether it carries a pamBypass; a
         * bypass-less kill switch is `is_enforceable == false`, so
         * serberus_config_resolve_source would classify it LAST_KNOWN_GOOD and this
         * code would then read the SNAPSHOT's daemonEnabled (always true — kill
         * switches are never snapshotted) and start enforcing the snapshot while the
         * daemon has torn its enforcement down, denying non-bypass users. The daemon
         * keys the kill switch on the managed daemonEnabled first
         * (EffectiveConfigResolver), so pam must too. An ABSENT config resolved to BOOTSTRAP or
         * LAST_KNOWN_GOOD, and is_present is false for it. */
        kill_switch = serberus_config_is_present(SERBERUS_MANAGED_CONFIG_PLIST)
                      && !serberus_config_daemon_enabled(SERBERUS_MANAGED_CONFIG_PLIST);

        if (config_source == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)
        {
            /* Delivered config absent or not safely enforceable (unscoped profile,
             * removed profile, or a partial one) on a Mac that HAS been configured:
             * run on the snapshot. It is enforceable by construction, so its
             * pamBypass break-glass is intact — removing the profile cannot disable
             * Serberus, and cannot lock admins out either. (Under a managed kill
             * switch the snapshot still supplies the bypass the drop-in rule
             * honors.) */
            config_path = SERBERUS_LKG_CONFIG_PATH;
            if (!kill_switch)
            {
                os_log(serberus_log(),
                       "pam: managed config missing or not safely enforceable — "
                       "falling back to the last-known-good snapshot (still "
                       "enforcing; break-glass intact)");
            }
        }

        /* Kill switch (daemonEnabled == false in the effective config, managed or
         * last-known-good). The daemon tears its enforcement down — restores the
         * authdb and removes the sudoers drop-in — so sudo passes through
         * natively, exactly like monitor mode (step 4), WITHOUT consulting the
         * daemon, for EVERY user regardless of break-glass membership: once the
         * drop-in is gone. Until then the drop-in rule enforces. */
        if (!kill_switch && !serberus_config_daemon_enabled(config_path))
        {
            kill_switch = true;
        }
        if (kill_switch && !drop_in_present)
        {
            os_log(serberus_log(),
                   "pam: daemon disabled (kill switch) — passing sudo through untouched");
            return PAM_IGNORE;
        }
    }

    char mode[32];
    copy_enforcement_mode(config_path, mode, sizeof(mode));

    /* Pass-through postures that need no bypass lookup (monitor with no
     * drop-in). Bootstrap / kill switch without a drop-in returned above. */
    int posture = serberus_auth_posture(config_source, kill_switch, mode, drop_in_present);
    if (posture == SERBERUS_POSTURE_PASS_THROUGH)
    {
        return PAM_IGNORE; /* monitor mode performs no interception */
    }

    /* Break-glass bypass: users and groups fall through to opendirectory. */
    if (user_in_bypass_users(config_path, user))
    {
        return PAM_IGNORE;
    }
    if (user_in_bypass_groups(config_path, user))
    {
        return PAM_IGNORE;
    }

    if (posture == SERBERUS_POSTURE_ENFORCE
        && (config_source == SERBERUS_CONFIG_SOURCE_BOOTSTRAP || kill_switch
            || strcmp(mode, "enforce") != 0))
    {
        os_log(serberus_log(),
               "pam: mode %{public}s%{public}s but the sudoers drop-in %{public}s "
               "is still present — enforcing until the daemon removes it",
               mode, kill_switch ? " (kill switch)" : "",
               SERBERUS_SUDOERS_DROP_IN_PATH);
    }

    const char *tty = NULL;
    pam_get_item(pamh, PAM_TTY, (const void **)&tty);

    char command[PATH_MAX];
    char **cmd_argv = NULL;
    int cmd_argc = 0;
    bool unevaluable = true;
    discover_command(command, sizeof(command), &cmd_argv, &cmd_argc, &unevaluable);

    /* DISPLAY string for the user-facing messages: the command AND its
     * arguments, as invoked. Built HERE because free_argv() below releases argv
     * long before the allow/deny message blocks run. Display only — the daemon
     * still receives `command` and `cmd_argv` separately for matching. */
    char command_line[SERBERUS_CMDLINE_MAX];
    build_command_line(command, cmd_argv, cmd_argc, command_line, sizeof(command_line));

    int prompted = 0;
    int prompt_timed_out = 0;
    int decision = ask_daemon(user, command, cmd_argv, cmd_argc, tty,
                              &prompted, &prompt_timed_out);
    free_argv(cmd_argv, cmd_argc);

    /* The daemon evaluated the request (enforce or audit): sudo's ticket is
     * cleared after it (pam_sm_setcred) — unless the answer was `native`. */
    if (serberus_decision_marks_gated(decision))
    {
        record_gated_request(pamh, user);
    }

    /* A JIT admin inside their window (an active Serberus JIT grant or an
     * observed Jamf Connect elevation, and in `admin` right now): step aside
     * entirely. sudo proceeds exactly as native macOS, password prompt and
     * ticket included. Checked before `unevaluable`: native does not depend on
     * the command, only on who is asking. */
    if (decision == SERBERUS_DECIDE_NATIVE)
    {
        os_log(serberus_log(), "pam: JIT admin inside their window — native sudo");
        return PAM_IGNORE;
    }

    /* Audit mode (and no drop-in): the daemon evaluated and logged
     * would-grant/would-deny; all requests pass through to native behavior. */
    if (posture == SERBERUS_POSTURE_AUDIT)
    {
        return PAM_IGNORE;
    }

    /* Enforce. An invocation the parser couldn't evaluate is still sent to the
     * daemon so it's logged, but it's denied whatever the answer. */
    if (unevaluable)
    {
        decision = 0;
    }
    if (decision == 1)
    {
        /* Optional admin-configured allow message (config profile
         * `sudoAllowMessage`, with an optional {command} token). Absent ⇒ no
         * message (unchanged behavior). Bypass users never reach here, so this
         * annotates only policy-gated allows. Emitting a message never changes
         * the PAM_SUCCESS return. */
        char allow_tmpl[SERBERUS_SUDO_MSG_MAX];
        if (serberus_config_copy_string(config_path,
                                        CFSTR("sudoAllowMessage"),
                                        allow_tmpl, sizeof(allow_tmpl)))
        {
            emit_policy_message(pamh, allow_tmpl, command_line, 0);
        }
        return PAM_SUCCESS;
    }
    /* deny (0) and unreachable (-1) both hard-deny. Before failing closed,
     * surface a user-facing reason so a deny is not mistaken for a wrong
     * password — and CLASSIFIED: a deny the user chose in the Sentinel prompt
     * must not read as "not permitted by policy" (the policy PERMITTED the
     * attempt; the user declined it).
     *
     * SAFETY: every branch below denies. The return is PAM_MAXTRIES (not
     * PAM_AUTH_ERR) so sudo ends its password-retry loop instead of running
     * up to three pointless rounds; any PAM host that treats MAXTRIES like a
     * plain failure still denies — the change can only fail CLOSED. The
     * `serberus_denied_this_process` latch guarantees a retrying host never
     * re-raises the Sentinel prompt in this process regardless. The command
     * is interpolated with a literal "%s" format (never as the format string
     * itself) or via emit_policy_message's non-printf substitution, so a
     * command containing % or %n cannot corrupt the format machinery. */
    serberus_denied_this_process = 1;
    if (decision == 0 && prompted && !prompt_timed_out)
    {
        /* The user declined the Sentinel prompt. Config override:
         * `sudoPromptDeniedMessage` (optional {command} token). */
        char declined_tmpl[SERBERUS_SUDO_MSG_MAX];
        if (serberus_config_copy_string(config_path,
                                        CFSTR("sudoPromptDeniedMessage"),
                                        declined_tmpl, sizeof(declined_tmpl)))
        {
            emit_policy_message(pamh, declined_tmpl, command_line, 1);
        }
        else
        {
            char declined_msg[SERBERUS_CMDLINE_MAX + 96];
            snprintf(declined_msg, sizeof(declined_msg),
                     "serberus: you declined the request for '%s' — nothing was changed",
                     command_line);
            declined_msg[sizeof(declined_msg) - 1] = '\0';
            pam_error(pamh, "%s", declined_msg);
        }
    }
    else if (decision == 0 && prompted)
    {
        /* The prompt expired unanswered. Config override:
         * `sudoPromptTimeoutMessage` (optional {command} token). */
        char timeout_tmpl[SERBERUS_SUDO_MSG_MAX];
        if (serberus_config_copy_string(config_path,
                                        CFSTR("sudoPromptTimeoutMessage"),
                                        timeout_tmpl, sizeof(timeout_tmpl)))
        {
            emit_policy_message(pamh, timeout_tmpl, command_line, 1);
        }
        else
        {
            char timeout_msg[SERBERUS_CMDLINE_MAX + 96];
            snprintf(timeout_msg, sizeof(timeout_msg),
                     "serberus: the approval request for '%s' timed out — denied",
                     command_line);
            timeout_msg[sizeof(timeout_msg) - 1] = '\0';
            pam_error(pamh, "%s", timeout_msg);
        }
    }
    else if (decision == 0)
    {
        /* Policy deny. Prefer the admin-configured message (config profile
         * `sudoDenyMessage`, with an optional {command} token); otherwise the
         * built-in text, which already names the attempted command. */
        char deny_tmpl[SERBERUS_SUDO_MSG_MAX];
        if (serberus_config_copy_string(config_path,
                                        CFSTR("sudoDenyMessage"),
                                        deny_tmpl, sizeof(deny_tmpl)))
        {
            emit_policy_message(pamh, deny_tmpl, command_line, 1);
        }
        else
        {
            /* The built-in text names the FULL command line for the same reason
             * the token does: `jamf policy` being refused while `jamf recon` is
             * allowed must not read as "'jamf' is not permitted". */
            char deny_msg[SERBERUS_CMDLINE_MAX + 96];
            snprintf(deny_msg, sizeof(deny_msg),
                     "serberus: '%s' is not permitted by policy "
                     "(contact IT if this is unexpected)",
                     command_line);
            deny_msg[sizeof(deny_msg) - 1] = '\0';
            pam_error(pamh, "%s", deny_msg);
        }
    }
    else
    {
        /* Service unavailable (fail-closed) — a different situation from a
         * policy deny, deliberately kept as a fixed message so it reads as an
         * outage, not a rule. Not customizable by `sudoDenyMessage`. */
        pam_error(pamh, "%s",
                  "serberus: policy service unavailable — denying (fail-closed)");
    }
    return PAM_MAXTRIES;
}

/*
 * Disable sudo's native timestamp caching for requests Serberus gated, by
 * deleting the invoking user's timestamp after the auth. The daemon
 * GrantStore is then the only cache for them. sudo 1.9.x calls
 * pam_setcred(PAM_REINITIALIZE_CRED) from begin_session (not
 * PAM_ESTABLISH_CRED), so both flags count
 * (serberus_setcred_should_clear_timestamp).
 *
 * Only a request pam_sm_authenticate evaluated against the daemon (enforce or
 * audit) is cleared. Bootstrap, the kill switch, monitor and pamBypass users
 * keep sudo's native ticket, as does any run where sudo skipped
 * authentication (a valid ticket, or NOPASSWD): nothing was recorded, so
 * there is nothing to clear. Enrolled standard users never hold a valid
 * ticket anyway, because the drop-in sets `timestamp_timeout=0` for them.
 *
 * The user is PAM_RUSER, the invoking user sudo keys the ticket to; the
 * PAM_USER pam_sm_authenticate recorded is only the fallback, since it is the
 * target under targetpw / rootpw. PAM_USER itself is never read here: sudo 1.9
 * sets it to the runas user (usually root) before pam_setcred. An unsafe name
 * is refused (serberus_timestamp_ticket_user).
 *
 * sudo 1.9.15 and later name the ticket after the user's numeric uid, so the
 * name is resolved with getpwnam_r — the returned pw_name must equal it
 * exactly — and "<dir>/<uid>" is removed. The name-keyed file older sudo
 * writes is removed too.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    const void *gated = NULL;
    if (pam_get_data(pamh, SERBERUS_PAM_DATA_GATED, &gated) != PAM_SUCCESS)
    {
        gated = NULL;
    }
    if (serberus_setcred_should_clear_timestamp(flags, gated != NULL))
    {
        const char *ruser = NULL;
        if (pam_get_item(pamh, PAM_RUSER, (const void **)&ruser) != PAM_SUCCESS)
        {
            ruser = NULL;
        }
        const void *recorded = NULL;
        if (pam_get_data(pamh, SERBERUS_PAM_DATA_AUTH_USER, &recorded) != PAM_SUCCESS)
        {
            recorded = NULL;
        }
        const char *ticket_user =
            serberus_timestamp_ticket_user(ruser, (const char *)recorded);
        char ts_path[PATH_MAX];
        uid_t ticket_uid = 0;
        if (ticket_user != NULL
            && serberus_config_user_uid_exact(ticket_user, &ticket_uid)
            && serberus_timestamp_uid_path(ticket_uid, ts_path, sizeof(ts_path)))
        {
            unlink(ts_path);
        }
        if (serberus_timestamp_path(ruser, (const char *)recorded,
                                    ts_path, sizeof(ts_path)))
        {
            unlink(ts_path);
        }
    }
    return PAM_SUCCESS;
}
