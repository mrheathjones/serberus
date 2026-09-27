/*
 * pam_config.c — managed-preferences config reading for pam_serberus.so.
 *
 * See pam_config.h for the contract. Runs inside the (euid-0) sudo process as
 * part of a `requisite` PAM module: every path here must be crash-free and
 * fail CLOSED (absent/invalid = enforce, no bypass).
 */

#include "pam_config.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <membership.h>
#include <os/lock.h>
#include <os/log.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>

/* Defensive cap on the managed plist size. MDM-delivered config plists are a
 * few KB; anything past this is malformed and treated as absent. Accepted
 * divergence from the daemon: CFPreferencesSource has no such cap and still
 * honors an oversized plist, while PAM treats it as absent -> fail-closed
 * enforce with no bypass. */
#define SERBERUS_CONFIG_MAX_PLIST_BYTES (4 * 1024 * 1024)

/* ---- file trust (mirrors ManagedPreferencesReader / CFPreferencesSource) ----
 *
 * A config file is honored only when BOTH hold, exactly as on the Swift side:
 *
 *   - its directory is a real directory (lstat: not a symlink) owned by the
 *     required owner and not group/other-writable, so nobody else can drop or
 *     swap a plist into it; and
 *   - the file, opened O_NOFOLLOW and checked on the OPEN descriptor (fstat —
 *     the file checked is the file read), is a regular file owned by the
 *     required owner and not group/other-writable.
 *
 * A file failing either check is treated as ABSENT — the same as the Swift
 * reader returning nil. The required owner is root; only the test bundle
 * changes it (serberus_config_set_required_owner_uid_for_testing). */

static uid_t serberus_config_required_owner_uid = 0;

void serberus_config_set_required_owner_uid_for_testing(uid_t uid)
{
    serberus_config_required_owner_uid = uid;
}

/* ManagedPreferencesReader.isTrusted(ownerUID:mode:requiredOwnerUID:). */
static bool owner_and_mode_are_trusted(uid_t owner, mode_t mode, uid_t required_owner)
{
    return owner == required_owner && (mode & (S_IWGRP | S_IWOTH)) == 0;
}

/* The directory holding `path` (everything before the last '/'), checked with
 * lstat so a symlinked directory is refused. A path with no '/' has no
 * directory we can vouch for and is refused. */
static bool parent_directory_is_trusted(const char *path, uid_t required_owner)
{
    const char *slash = strrchr(path, '/');
    if (slash == NULL)
    {
        return false;
    }
    char directory[PATH_MAX];
    size_t length = (size_t)(slash - path);
    if (length == 0)
    {
        length = 1; /* "/file" -> "/" */
    }
    if (length >= sizeof(directory))
    {
        return false;
    }
    memcpy(directory, path, length);
    directory[length] = '\0';

    struct stat st;
    if (lstat(directory, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        return false;
    }
    return owner_and_mode_are_trusted(st.st_uid, st.st_mode, required_owner);
}

/* Opens `path` read-only for a trusted config file, or returns -1 (absent,
 * a symlink, not a regular file, or failing the owner/mode checks). */
static int open_trusted_config_file(const char *path, uid_t required_owner)
{
    if (path == NULL || path[0] == '\0'
        || !parent_directory_is_trusted(path, required_owner))
    {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
    {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)
        || !owner_and_mode_are_trusted(st.st_uid, st.st_mode, required_owner))
    {
        close(fd);
        return -1;
    }
    return fd;
}

bool serberus_config_file_is_trusted_for_owner(const char *path, uid_t required_owner)
{
    int fd = open_trusted_config_file(path, required_owner);
    if (fd < 0)
    {
        return false;
    }
    close(fd);
    return true;
}

/* ---- managed plist (direct read) ---- */

/* Reads the whole file at `path` into a CFData, or NULL on any failure —
 * including a file that fails the trust checks above. */
static CFDataRef copy_file_data(const char *path)
{
    int fd = open_trusted_config_file(path, serberus_config_required_owner_uid);
    if (fd < 0)
    {
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)
        || st.st_size <= 0 || st.st_size > SERBERUS_CONFIG_MAX_PLIST_BYTES)
    {
        close(fd);
        return NULL;
    }

    size_t size = (size_t)st.st_size;
    unsigned char *bytes = (unsigned char *)malloc(size);
    if (bytes == NULL)
    {
        close(fd);
        return NULL;
    }

    size_t total = 0;
    while (total < size)
    {
        ssize_t n = read(fd, bytes + total, size - total);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        if (n == 0)
        {
            break; /* truncated underneath us */
        }
        total += (size_t)n;
    }
    close(fd);

    if (total != size)
    {
        free(bytes);
        return NULL;
    }

    /* kCFAllocatorMalloc frees `bytes` with free() when the CFData is done. */
    CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, bytes, (CFIndex)size,
                                                 kCFAllocatorMalloc);
    if (data == NULL)
    {
        free(bytes);
        return NULL;
    }
    return data;
}

/* The computer-level managed plist as a retained dictionary, or NULL when
 * absent, unreadable, unparseable, or not a dictionary. A malformed file is
 * treated exactly like an absent one (there is no other preferences layer to
 * fall back to — only this plist and, via resolve_source, the last-known-good
 * snapshot are ever read) and never crashes sudo — this mirrors
 * CFPreferencesSource.managedDomainDictionary. */
static CFDictionaryRef copy_managed_dictionary(const char *managed_plist_path)
{
    if (managed_plist_path == NULL || managed_plist_path[0] == '\0')
    {
        return NULL;
    }

    CFDataRef data = copy_file_data(managed_plist_path);
    if (data == NULL)
    {
        return NULL;
    }

    CFPropertyListRef plist = CFPropertyListCreateWithData(
        NULL, data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(data);
    if (plist == NULL)
    {
        return NULL;
    }
    if (CFGetTypeID(plist) != CFDictionaryGetTypeID())
    {
        CFRelease(plist);
        return NULL;
    }
    return (CFDictionaryRef)plist;
}

/* Retained effective value for `key`. Per-key precedence mirrors
 * CFPreferencesSource.value(forKey:domain:): only the managed plist counts
 * (a key PRESENT there is authoritative even if mistyped — the typed readers
 * below then fail closed). The unforced CFPreferences layers are never read:
 * inside setuid sudo they may resolve to a location the invoking user
 * controls, and root-written ones would be policy MDM can't see. */
static CFTypeRef copy_config_value(const char *managed_plist_path,
                                   CFStringRef key)
{
    CFDictionaryRef managed = copy_managed_dictionary(managed_plist_path);
    if (managed != NULL)
    {
        CFTypeRef value = CFDictionaryGetValue(managed, key);
        if (value != NULL)
        {
            CFRetain(value);
            CFRelease(managed);
            return value;
        }
        CFRelease(managed);
    }
    return NULL;
}

/* ---- public readers ---- */

void serberus_config_copy_enforcement_mode(const char *managed_plist_path,
                                           char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
    {
        return;
    }
    strlcpy(out, "enforce", out_size);

    CFTypeRef value = copy_config_value(managed_plist_path,
                                        CFSTR("enforcementMode"));
    if (value == NULL)
    {
        return;
    }
    if (CFGetTypeID(value) == CFStringGetTypeID())
    {
        char candidate[32] = {0};
        if (CFStringGetCString((CFStringRef)value, candidate, sizeof(candidate),
                               kCFStringEncodingUTF8))
        {
            if (strcmp(candidate, "enforce") == 0
                || strcmp(candidate, "audit") == 0
                || strcmp(candidate, "monitor") == 0)
            {
                strlcpy(out, candidate, out_size);
            }
            /* Unknown mode string -> keep "enforce" (fail closed), matching
             * ManagedPreferencesReader.readConfig()'s invalid-value default. */
        }
    }
    CFRelease(value);
}

bool serberus_config_copy_string(const char *managed_plist_path,
                                 CFStringRef key,
                                 char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
    {
        return false;
    }
    out[0] = '\0';

    CFTypeRef value = copy_config_value(managed_plist_path, key);
    if (value == NULL)
    {
        return false;
    }

    bool ok = false;
    if (CFGetTypeID(value) == CFStringGetTypeID())
    {
        /* A present-but-empty string is treated as ABSENT so the caller falls
         * back to its default rather than emitting a blank line. Conversion
         * failure (e.g. a value that does not fit out_size in the requested
         * encoding) also yields absent. */
        if (CFStringGetCString((CFStringRef)value, out, out_size, kCFStringEncodingUTF8)
            && out[0] != '\0')
        {
            ok = true;
        }
        else
        {
            out[0] = '\0';
        }
    }
    CFRelease(value);
    return ok;
}

bool serberus_config_daemon_enabled(const char *managed_plist_path)
{
    /* Absent/wrong-typed key => enabled (fail TOWARD enforcing), matching the
     * daemon's SerberusConfig.daemonEnabled default. Only an explicit boolean
     * false is the kill switch. */
    bool enabled = true;
    CFTypeRef value = copy_config_value(managed_plist_path,
                                        CFSTR("daemonEnabled"));
    if (value != NULL)
    {
        if (CFGetTypeID(value) == CFBooleanGetTypeID())
        {
            enabled = CFBooleanGetValue((CFBooleanRef)value);
        }
        /* A non-boolean daemonEnabled keeps the default TRUE (never a fail-open
         * kill switch from a mistyped value). */
        CFRelease(value);
    }
    return enabled;
}

CFArrayRef serberus_config_copy_bypass_array(const char *managed_plist_path,
                                             CFStringRef inner_key)
{
    CFMutableArrayRef result = NULL;
    CFTypeRef bypass = copy_config_value(managed_plist_path,
                                         CFSTR("pamBypass"));
    if (bypass != NULL && CFGetTypeID(bypass) == CFDictionaryGetTypeID())
    {
        CFTypeRef inner = CFDictionaryGetValue((CFDictionaryRef)bypass, inner_key);
        if (inner != NULL && CFGetTypeID(inner) == CFArrayGetTypeID())
        {
            /* Filter to string members: a non-string can never name a user or
             * group, and downstream loops must not have to defend against it. */
            CFIndex count = CFArrayGetCount((CFArrayRef)inner);
            result = CFArrayCreateMutable(NULL, count, &kCFTypeArrayCallBacks);
            if (result != NULL)
            {
                for (CFIndex i = 0; i < count; i++)
                {
                    CFTypeRef element = CFArrayGetValueAtIndex((CFArrayRef)inner, i);
                    if (element != NULL && CFGetTypeID(element) == CFStringGetTypeID())
                    {
                        CFArrayAppendValue(result, element);
                    }
                }
            }
        }
    }
    if (bypass != NULL)
    {
        CFRelease(bypass);
    }
    return result;
}

/* Count of STRING members across pamBypass.users + pamBypass.groups in one
 * config source. serberus_config_copy_bypass_array already filters non-strings
 * (they can never name a user or group), so this is a plain sum of the two
 * array counts. Absent/mistyped pamBypass -> 0. */
static CFIndex bypass_member_count(const char *managed_plist_path)
{
    CFIndex total = 0;
    CFArrayRef users = serberus_config_copy_bypass_array(managed_plist_path,
                                                         CFSTR("users"));
    if (users != NULL)
    {
        total += CFArrayGetCount(users);
        CFRelease(users);
    }
    CFArrayRef groups = serberus_config_copy_bypass_array(managed_plist_path,
                                                          CFSTR("groups"));
    if (groups != NULL)
    {
        total += CFArrayGetCount(groups);
        CFRelease(groups);
    }
    return total;
}

bool serberus_config_is_present(const char *managed_plist_path)
{
    CFDictionaryRef managed = copy_managed_dictionary(managed_plist_path);
    if (managed != NULL)
    {
        bool has_keys = CFDictionaryGetCount(managed) > 0;
        CFRelease(managed);
        if (has_keys)
        {
            return true;
        }
    }

    return false;
}

bool serberus_config_is_enforceable(const char *managed_plist_path)
{
    char mode[32];
    serberus_config_copy_enforcement_mode(managed_plist_path,
                                          mode, sizeof(mode));
    if (strcmp(mode, "enforce") != 0)
    {
        /* monitor / audit deny nothing — inherently safe to run with. */
        return true;
    }
    /* enforce is safe only with a break-glass population. */
    return bypass_member_count(managed_plist_path) > 0;
}

/* getpwnam_r / getgrnam_r buffer schedule: start at 4 KiB and grow 4x on
 * ERANGE up to 1 MiB — the same schedule as the daemon's LocalAccounts, so a
 * large directory group (whose whole member list lands in the buffer)
 * resolves on both sides or on neither. */
#define SERBERUS_LOOKUP_BUFFER_INITIAL 4096
#define SERBERUS_LOOKUP_BUFFER_MAX     (1 << 20)

/* Upper bound on the accounts serberus_config_primary_gid_in_use reads, so a
 * directory that enumerates without end cannot stall sudo. The daemon's
 * LocalAccounts uses the same bound. */
#define SERBERUS_PRIMARY_GID_SCAN_MAX  100000

/* How many distinct gids serberus_config_primary_gid_in_use remembers. A
 * pamBypass list names a handful of groups; past this the scan just runs. */
#define SERBERUS_PRIMARY_GID_CACHE_SLOTS 16

bool serberus_config_user_uid_exact(const char *name, uid_t *uid)
{
    if (name == NULL || name[0] == '\0')
    {
        return false;
    }
    for (size_t size = SERBERUS_LOOKUP_BUFFER_INITIAL;
         size <= SERBERUS_LOOKUP_BUFFER_MAX; size *= 4)
    {
        char *buffer = (char *)malloc(size);
        if (buffer == NULL)
        {
            return false;
        }
        struct passwd pwd;
        struct passwd *result = NULL;
        int status = getpwnam_r(name, &pwd, buffer, size, &result);
        /* Open Directory finds users case-insensitively and through their
         * RecordName aliases; only the canonical name itself counts. */
        bool found = status == 0 && result != NULL && pwd.pw_name != NULL
                     && strcmp(pwd.pw_name, name) == 0;
        if (found && uid != NULL)
        {
            *uid = pwd.pw_uid;
        }
        free(buffer);
        if (status != ERANGE)
        {
            return found;
        }
    }
    return false;
}

bool serberus_config_user_exists(const char *name)
{
    return serberus_config_user_uid_exact(name, NULL);
}

/* Whether getpwuid_r finds an account with `uid`. */
static bool uid_has_account(uid_t uid)
{
    for (size_t size = SERBERUS_LOOKUP_BUFFER_INITIAL;
         size <= SERBERUS_LOOKUP_BUFFER_MAX; size *= 4)
    {
        char *buffer = (char *)malloc(size);
        if (buffer == NULL)
        {
            return false;
        }
        struct passwd pwd;
        struct passwd *result = NULL;
        int status = getpwuid_r(uid, &pwd, buffer, size, &result);
        free(buffer);
        if (status != ERANGE)
        {
            return status == 0 && result != NULL;
        }
    }
    return false;
}

static bool primary_gid_scan(gid_t gid)
{
    bool found = false;
    size_t scanned = 0;
    setpwent();
    struct passwd *pwd;
    while (!found && scanned < SERBERUS_PRIMARY_GID_SCAN_MAX
           && (pwd = getpwent()) != NULL)
    {
        found = pwd->pw_gid == gid;
        scanned++;
    }
    endpwent();
    return found;
}

bool serberus_config_primary_gid_in_use(gid_t gid)
{
    /* dscacheutil prints a gid above INT32_MAX as a negative number, which the
     * installer preflight never matches; skip it here too (nobody, nogroup). */
    if (gid > (gid_t)INT32_MAX)
    {
        return false;
    }

    /* A scan reads up to 100,000 accounts, and sudo can ask about the same
     * group more than once in one run (the source resolution, then the
     * snapshot's), so the answer is kept for the life of the process. The
     * lock also serializes getpwent's process-wide cursor. */
    static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
    static struct
    {
        gid_t gid;
        bool in_use;
    } cache[SERBERUS_PRIMARY_GID_CACHE_SLOTS];
    static size_t cached = 0;

    os_unfair_lock_lock(&lock);
    for (size_t i = 0; i < cached; i++)
    {
        if (cache[i].gid == gid)
        {
            bool in_use = cache[i].in_use;
            os_unfair_lock_unlock(&lock);
            return in_use;
        }
    }
    bool in_use = primary_gid_scan(gid);
    if (cached < SERBERUS_PRIMARY_GID_CACHE_SLOTS)
    {
        cache[cached].gid = gid;
        cache[cached].in_use = in_use;
        cached++;
    }
    os_unfair_lock_unlock(&lock);
    return in_use;
}

bool serberus_config_generated_uid_names_user(const char *uuid_text)
{
    if (uuid_text == NULL)
    {
        return false;
    }
    uuid_t uuid;
    if (uuid_parse(uuid_text, uuid) != 0)
    {
        return false;
    }
    id_t id = 0;
    int type = -1;
    if (mbr_uuid_to_id(uuid, &id, &type) != 0 || type != ID_TYPE_UID)
    {
        return false;
    }
    return uid_has_account((uid_t)id);
}

/* ---- GroupMembers through CFOpenDirectory ----
 *
 * getgrnam_r reports a group's GroupMembership names (gr_mem) only. Its
 * GroupMembers attribute — the members' GeneratedUIDs, which is all some
 * tools record — is read from Open Directory. CFOpenDirectory is loaded on
 * first use rather than linked, so the module's (and the test bundle's)
 * link line stays CoreFoundation + Security, and a sudo that never reaches
 * this path never loads it. */

#define SERBERUS_CFOPENDIRECTORY_PATH                                            \
    "/System/Library/Frameworks/OpenDirectory.framework/Versions/A/Frameworks/" \
    "CFOpenDirectory.framework/Versions/A/CFOpenDirectory"
#define SERBERUS_OD_NODE_TYPE_AUTHENTICATION 0x2201u /* kODNodeTypeAuthentication */

typedef CFTypeRef (*od_node_create_fn)(CFAllocatorRef, CFTypeRef, uint32_t, CFErrorRef *);
typedef CFTypeRef (*od_copy_record_fn)(CFTypeRef, CFStringRef, CFStringRef, CFTypeRef,
                                       CFErrorRef *);
typedef CFArrayRef (*od_copy_values_fn)(CFTypeRef, CFStringRef, CFErrorRef *);

static struct
{
    od_node_create_fn node_create;
    od_copy_record_fn copy_record;
    od_copy_values_fn copy_values;
    const CFTypeRef *session_default;
    const CFStringRef *record_type_groups;
    const CFStringRef *attribute_group_members;
} od_api;

static bool od_api_load(void)
{
    static dispatch_once_t once;
    static bool loaded = false;
    dispatch_once(&once, ^{
        void *handle = dlopen(SERBERUS_CFOPENDIRECTORY_PATH, RTLD_LAZY | RTLD_LOCAL);
        if (handle == NULL)
        {
            return;
        }
        od_api.node_create = (od_node_create_fn)dlsym(handle, "ODNodeCreateWithNodeType");
        od_api.copy_record = (od_copy_record_fn)dlsym(handle, "ODNodeCopyRecord");
        od_api.copy_values = (od_copy_values_fn)dlsym(handle, "ODRecordCopyValues");
        od_api.session_default = (const CFTypeRef *)dlsym(handle, "kODSessionDefault");
        od_api.record_type_groups = (const CFStringRef *)dlsym(handle, "kODRecordTypeGroups");
        od_api.attribute_group_members =
            (const CFStringRef *)dlsym(handle, "kODAttributeTypeGroupMembers");
        loaded = od_api.node_create != NULL && od_api.copy_record != NULL
                 && od_api.copy_values != NULL && od_api.session_default != NULL
                 && od_api.record_type_groups != NULL && *od_api.record_type_groups != NULL
                 && od_api.attribute_group_members != NULL
                 && *od_api.attribute_group_members != NULL;
    });
    return loaded;
}

bool serberus_config_group_generated_uid_member(const char *group)
{
    if (group == NULL || group[0] == '\0' || !od_api_load())
    {
        return false;
    }
    CFStringRef name = CFStringCreateWithCString(NULL, group, kCFStringEncodingUTF8);
    if (name == NULL)
    {
        return false;
    }
    bool found = false;
    CFTypeRef node = od_api.node_create(NULL, *od_api.session_default,
                                        SERBERUS_OD_NODE_TYPE_AUTHENTICATION, NULL);
    CFArrayRef attributes = CFArrayCreate(NULL, (const void **)od_api.attribute_group_members,
                                          1, &kCFTypeArrayCallBacks);
    CFTypeRef record = NULL;
    if (node != NULL && attributes != NULL)
    {
        record = od_api.copy_record(node, *od_api.record_type_groups, name, attributes, NULL);
    }
    CFArrayRef values = NULL;
    if (record != NULL)
    {
        values = od_api.copy_values(record, *od_api.attribute_group_members, NULL);
    }
    if (values != NULL)
    {
        CFIndex count = CFArrayGetCount(values);
        for (CFIndex i = 0; i < count && !found; i++)
        {
            CFTypeRef value = CFArrayGetValueAtIndex(values, i);
            char text[64];
            if (value != NULL && CFGetTypeID(value) == CFStringGetTypeID()
                && CFStringGetCString((CFStringRef)value, text, sizeof(text),
                                      kCFStringEncodingUTF8))
            {
                found = serberus_config_generated_uid_names_user(text);
            }
        }
        CFRelease(values);
    }
    if (record != NULL)
    {
        CFRelease(record);
    }
    if (attributes != NULL)
    {
        CFRelease(attributes);
    }
    if (node != NULL)
    {
        CFRelease(node);
    }
    CFRelease(name);
    return found;
}

const serberus_group_probes serberus_config_default_group_probes = {
    .user_exists = serberus_config_user_exists,
    .generated_uid_member = serberus_config_group_generated_uid_member,
    .primary_gid_in_use = serberus_config_primary_gid_in_use,
};

bool serberus_config_group_has_members(const char *group, char *const *members,
                                       gid_t gid, const serberus_group_probes *probes)
{
    if (probes == NULL)
    {
        return false;
    }
    if (members != NULL && probes->user_exists != NULL)
    {
        for (char *const *member = members; *member != NULL; member++)
        {
            if ((*member)[0] != '\0' && probes->user_exists(*member))
            {
                return true;
            }
        }
    }
    if (group != NULL && probes->generated_uid_member != NULL
        && probes->generated_uid_member(group))
    {
        return true;
    }
    return probes->primary_gid_in_use != NULL && probes->primary_gid_in_use(gid);
}

static os_log_t config_log(void)
{
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.herojoneslabs.serberus", "pam");
    });
    return log;
}

int serberus_config_group_lookup(const char *name, const serberus_group_probes *probes)
{
    if (name == NULL || name[0] == '\0')
    {
        return SERBERUS_GROUP_NOT_FOUND;
    }
    for (size_t size = SERBERUS_LOOKUP_BUFFER_INITIAL;
         size <= SERBERUS_LOOKUP_BUFFER_MAX; size *= 4)
    {
        char *buffer = (char *)malloc(size);
        if (buffer == NULL)
        {
            return SERBERUS_GROUP_NOT_FOUND;
        }
        struct group grp;
        struct group *result = NULL;
        int status = getgrnam_r(name, &grp, buffer, size, &result);
        int outcome = SERBERUS_GROUP_NOT_FOUND;
        if (status == 0 && result != NULL)
        {
            /* gr_mem and gr_name point into `buffer`: check before the free.
             * GroupMembers is read under the record's own name. */
            outcome = serberus_config_group_has_members(grp.gr_name, grp.gr_mem,
                                                        grp.gr_gid, probes)
                          ? SERBERUS_GROUP_HAS_MEMBERS
                          : SERBERUS_GROUP_EMPTY;
        }
        free(buffer);
        if (status != ERANGE)
        {
            return outcome;
        }
    }
    return SERBERUS_GROUP_NOT_FOUND;
}

bool serberus_config_default_name_resolves(const char *name, bool is_group)
{
    if (name == NULL || name[0] == '\0')
    {
        return false;
    }
    if (!is_group)
    {
        /* Break-glass matches PAM_USER exactly
         * (serberus_config_user_in_bypass_users), so a user entry resolves
         * only when it IS the account's canonical name: "ITAdmin" or an alias
         * of itadmin would pass a directory lookup yet never match anyone. */
        return serberus_config_user_exists(name);
    }
    int outcome = serberus_config_group_lookup(name, &serberus_config_default_group_probes);
    if (outcome == SERBERUS_GROUP_EMPTY)
    {
        /* An existing group bypasses nobody unless one of its members is an
         * account that exists (the installer preflight's rule). */
        os_log_error(config_log(),
                     "pam: pamBypass group %{public}s has no members that resolve "
                     "to an account — it provides no break-glass",
                     name);
    }
    return outcome == SERBERUS_GROUP_HAS_MEMBERS;
}

char *serberus_config_copy_cstring(CFStringRef string)
{
    if (string == NULL)
    {
        return NULL;
    }
    CFIndex length = CFStringGetLength(string);
    CFIndex maximum = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
    if (maximum < 0 || maximum == LONG_MAX) /* kCFNotFound, or no room for the NUL */
    {
        return NULL;
    }
    CFIndex size = maximum + 1;
    char *out = (char *)malloc((size_t)size);
    if (out == NULL)
    {
        return NULL;
    }
    CFIndex used = 0;
    if (CFStringGetBytes(string, CFRangeMake(0, length), kCFStringEncodingUTF8, 0, false,
                         (UInt8 *)out, maximum, &used) != length
        || used < 0 || used > maximum)
    {
        free(out);
        return NULL;
    }
    out[used] = '\0';
    /* A C string ends at the first NUL, so "root\0x" would be read as "root".
     * The daemon compares the whole name, so such a string is refused here
     * rather than silently shortened. */
    if (memchr(out, '\0', (size_t)used) != NULL)
    {
        free(out);
        return NULL;
    }
    return out;
}

/* True when at least one pamBypass member names an account that exists on
 * this Mac (users via getpwnam_r, exact name) or a group that has at least one
 * member that is an existing account (see serberus_config_group_has_members).
 * An entry containing U+0000 never resolves (serberus_config_copy_cstring). */
static bool bypass_has_resolvable_member(const char *managed_plist_path,
                                         serberus_name_resolver resolver)
{
    static const struct
    {
        CFStringRef key;
        bool is_group;
    } lists[] = {{CFSTR("users"), false}, {CFSTR("groups"), true}};

    bool resolved = false;
    for (size_t l = 0; l < sizeof(lists) / sizeof(lists[0]) && !resolved; l++)
    {
        CFArrayRef names = serberus_config_copy_bypass_array(managed_plist_path,
                                                             lists[l].key);
        if (names == NULL)
        {
            continue;
        }
        CFIndex count = CFArrayGetCount(names);
        for (CFIndex i = 0; i < count && !resolved; i++)
        {
            char *name = serberus_config_copy_cstring(
                (CFStringRef)CFArrayGetValueAtIndex(names, i));
            if (name != NULL)
            {
                resolved = resolver(name, lists[l].is_group);
                free(name);
            }
        }
        CFRelease(names);
    }
    return resolved;
}

/* Whether anything is at `path`, by lstat. Only a definite "no such file"
 * counts as absent; any other failure (EACCES on a parent, EIO) counts as
 * present, so a probe that can't tell selects the fail-closed source. lstat,
 * not access(): inside setuid sudo access() checks with the invoking user's
 * real uid, which a directory that user can't search would turn into
 * "absent" — and absent here means the bootstrap pass-through. */
static bool path_exists(const char *path)
{
    struct stat st;
    if (lstat(path, &st) == 0)
    {
        return true;
    }
    return errno != ENOENT && errno != ENOTDIR;
}

int serberus_config_resolve_source(const char *managed_plist_path,
                                   const char *lkg_path)
{
    return serberus_config_resolve_source_with(managed_plist_path, lkg_path,
                                               serberus_config_default_name_resolves);
}

int serberus_config_resolve_source_with(const char *managed_plist_path,
                                        const char *lkg_path,
                                        serberus_name_resolver resolver)
{
    /* The delivered config governs only when it is present, enforceable, and
     * (in enforce) at least one break-glass entry resolves. A profile whose
     * every pamBypass entry is a typo is treated like an empty one, exactly
     * as the daemon's EffectiveConfigResolver does. */
    if (serberus_config_is_present(managed_plist_path)
        && serberus_config_is_enforceable(managed_plist_path))
    {
        char mode[32];
        serberus_config_copy_enforcement_mode(managed_plist_path,
                                              mode, sizeof(mode));
        if (strcmp(mode, "enforce") != 0
            || bypass_has_resolvable_member(managed_plist_path,
                                            resolver != NULL
                                                ? resolver
                                                : serberus_config_default_name_resolves))
        {
            return SERBERUS_CONFIG_SOURCE_MANAGED;
        }
    }

    /* EXISTENCE — not readability, not validity — is the "this Mac has been
     * configured" marker, and it is the only thing standing between a tampered
     * Mac and the bootstrap pass-through. A snapshot that exists but is corrupt
     * therefore still selects LAST_KNOWN_GOOD, where the readers fail CLOSED. */
    if (lkg_path != NULL && lkg_path[0] != '\0' && path_exists(lkg_path))
    {
        return SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD;
    }

    return SERBERUS_CONFIG_SOURCE_BOOTSTRAP;
}

bool serberus_config_user_in_bypass_users(const char *managed_plist_path,
                                          const char *user)
{
    if (user == NULL || user[0] == '\0')
    {
        return false;
    }

    bool found = false;
    CFArrayRef users = serberus_config_copy_bypass_array(managed_plist_path,
                                                         CFSTR("users"));
    if (users != NULL)
    {
        CFStringRef target = CFStringCreateWithCString(NULL, user,
                                                       kCFStringEncodingUTF8);
        if (target != NULL)
        {
            CFIndex count = CFArrayGetCount(users);
            for (CFIndex i = 0; i < count; i++)
            {
                CFStringRef element = (CFStringRef)CFArrayGetValueAtIndex(users, i);
                if (element != NULL
                    && CFStringCompare(element, target, 0) == kCFCompareEqualTo)
                {
                    found = true;
                    break;
                }
            }
            CFRelease(target);
        }
        CFRelease(users);
    }
    return found;
}
