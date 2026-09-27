/*
 * sudo_args.c — find the command sudo is about to run. See sudo_args.h.
 *
 * The option tables below are sudo 1.9.17's (src/parse_args.c): the short
 * options come from "+Aa:BbC:c:D:Eeg:Hh::iKklNnPp:R:r:SsT:t:U:u:Vv" and the
 * long options from sudo_long_opts. Both tables list EVERY sudo option,
 * including the ones Serberus refuses, so that long-option prefix matching
 * resolves exactly as sudo's getopt_long does.
 */
#include "sudo_args.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* How an option takes its value, as in getopt_long. */
typedef enum
{
    ARG_NONE,
    ARG_REQUIRED, /* attached (-uroot, --user=root) or the next token */
    ARG_OPTIONAL  /* attached only (-hhost, --preserve-env=LIST) */
} arg_kind;

typedef struct
{
    char name;
    arg_kind arg;
    bool allowed; /* false: the invocation doesn't run the command as-is */
} short_option;

typedef struct
{
    const char *name;
    arg_kind arg;
    bool allowed;
} long_option;

static const short_option short_options[] = {
    { 'A', ARG_NONE, true },      /* askpass */
    { 'a', ARG_REQUIRED, false }, /* BSD auth type */
    { 'B', ARG_NONE, true },      /* bell */
    { 'b', ARG_NONE, true },      /* background */
    { 'C', ARG_REQUIRED, true },  /* close-from */
    { 'c', ARG_REQUIRED, false }, /* BSD login class */
    { 'D', ARG_REQUIRED, false }, /* chdir */
    { 'E', ARG_NONE, true },      /* preserve-env */
    { 'e', ARG_NONE, false },     /* edit (sudoedit) */
    { 'g', ARG_REQUIRED, true },  /* group */
    { 'H', ARG_NONE, true },      /* set-home */
    { 'h', ARG_OPTIONAL, false }, /* help, or -hhost */
    { 'i', ARG_NONE, false },     /* login shell */
    { 'K', ARG_NONE, false },     /* remove-timestamp */
    { 'k', ARG_NONE, true },      /* reset-timestamp */
    { 'l', ARG_NONE, false },     /* list */
    { 'N', ARG_NONE, true },      /* no-update */
    { 'n', ARG_NONE, true },      /* non-interactive */
    { 'P', ARG_NONE, true },      /* preserve-groups */
    { 'p', ARG_REQUIRED, true },  /* prompt */
    { 'R', ARG_REQUIRED, false }, /* chroot */
    { 'r', ARG_REQUIRED, false }, /* SELinux role */
    { 'S', ARG_NONE, true },      /* stdin */
    { 's', ARG_NONE, false },     /* shell */
    { 'T', ARG_REQUIRED, true },  /* command-timeout */
    { 't', ARG_REQUIRED, false }, /* SELinux type */
    { 'U', ARG_REQUIRED, false }, /* other-user (list mode) */
    { 'u', ARG_REQUIRED, true },  /* user */
    { 'V', ARG_NONE, false },     /* version */
    { 'v', ARG_NONE, false },     /* validate */
};

static const long_option long_options[] = {
    { "askpass", ARG_NONE, true },
    { "auth-type", ARG_REQUIRED, false },
    { "background", ARG_NONE, true },
    { "bell", ARG_NONE, true },
    { "chdir", ARG_REQUIRED, false },
    { "chroot", ARG_REQUIRED, false },
    { "close-from", ARG_REQUIRED, true },
    { "command-timeout", ARG_REQUIRED, true },
    { "edit", ARG_NONE, false },
    { "group", ARG_REQUIRED, true },
    { "help", ARG_NONE, false },
    { "host", ARG_REQUIRED, false },
    { "list", ARG_NONE, false },
    { "login", ARG_NONE, false },
    { "login-class", ARG_REQUIRED, false },
    { "no-update", ARG_NONE, true },
    { "non-interactive", ARG_NONE, true },
    { "other-user", ARG_REQUIRED, false },
    { "preserve-env", ARG_OPTIONAL, true },
    { "preserve-groups", ARG_NONE, true },
    { "prompt", ARG_REQUIRED, true },
    { "remove-timestamp", ARG_NONE, false },
    { "reset-timestamp", ARG_NONE, true },
    { "role", ARG_REQUIRED, false },
    { "set-home", ARG_NONE, true },
    { "shell", ARG_NONE, false },
    { "stdin", ARG_NONE, true },
    { "type", ARG_REQUIRED, false },
    { "user", ARG_REQUIRED, true },
    { "validate", ARG_NONE, false },
    { "version", ARG_NONE, false },
};

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static const short_option *find_short(char name)
{
    for (size_t i = 0; i < COUNT(short_options); i++)
    {
        if (short_options[i].name == name)
        {
            return &short_options[i];
        }
    }
    return NULL;
}

/* getopt_long matching: an exact name wins; otherwise a prefix must match
 * exactly one option. No two sudo long options share a meaning, so any second
 * prefix match is ambiguous, which sudo rejects too. */
static const long_option *find_long(const char *name, size_t length)
{
    const long_option *prefix_match = NULL;
    int prefix_matches = 0;
    for (size_t i = 0; i < COUNT(long_options); i++)
    {
        if (strncmp(long_options[i].name, name, length) != 0)
        {
            continue;
        }
        if (long_options[i].name[length] == '\0')
        {
            return &long_options[i];
        }
        prefix_match = &long_options[i];
        prefix_matches++;
    }
    return prefix_matches == 1 ? prefix_match : NULL;
}

/* Returns how many argv tokens a "-xyz" cluster consumes, or -1 to reject. */
static int parse_short_cluster(int argc, const char *const argv[], int index)
{
    const char *token = argv[index];
    for (size_t j = 1; token[j] != '\0'; j++)
    {
        const short_option *option = find_short(token[j]);
        if (option == NULL || !option->allowed)
        {
            return -1;
        }
        if (option->arg == ARG_REQUIRED)
        {
            if (token[j + 1] != '\0')
            {
                return 1; /* value attached: -uroot */
            }
            if (index + 1 < argc && argv[index + 1] != NULL)
            {
                return 2; /* value is the next token, whatever it looks like */
            }
            return -1;
        }
    }
    return 1;
}

/* Returns how many argv tokens a "--name[=value]" option consumes, or -1. */
static int parse_long_option(int argc, const char *const argv[], int index)
{
    const char *name = argv[index] + 2;
    const char *equals = strchr(name, '=');
    size_t length = equals != NULL ? (size_t)(equals - name) : strlen(name);
    if (length == 0)
    {
        return -1;
    }
    const long_option *option = find_long(name, length);
    if (option == NULL || !option->allowed)
    {
        return -1;
    }
    switch (option->arg)
    {
    case ARG_NONE:
        return equals == NULL ? 1 : -1;
    case ARG_OPTIONAL:
        return 1; /* a value only ever comes attached with '=' */
    case ARG_REQUIRED:
        if (equals != NULL)
        {
            return 1;
        }
        if (index + 1 < argc && argv[index + 1] != NULL)
        {
            return 2;
        }
        return -1;
    }
    return -1;
}

/* sudo's is_envar: NAME=value, unless it starts with '/' or '='. */
static bool is_environment_assignment(const char *token)
{
    return token[0] != '/' && token[0] != '=' && strchr(token, '=') != NULL;
}

/* True when `path` names sudo the way sudo's initprogname2() reads a program
 * name: the last path component, minus a leading libtool "lt-" prefix (sudo
 * strips it only when something follows it), must be exactly "sudo". NULL,
 * empty, and trailing-slash names are rejected. */
static bool names_sudo(const char *path)
{
    if (path == NULL || path[0] == '\0')
    {
        return false;
    }
    const char *name = strrchr(path, '/');
    name = name != NULL ? name + 1 : path;
    if (name[0] == 'l' && name[1] == 't' && name[2] == '-' && name[3] != '\0')
    {
        name += 3;
    }
    return strcmp(name, "sudo") == 0;
}

bool serberus_sudo_invocation_name_ok(const char *progname,
                                      const char *exec_path,
                                      const char *argv0)
{
    return names_sudo(progname) && names_sudo(exec_path) && names_sudo(argv0);
}

serberus_sudo_args_result serberus_find_sudo_command(int argc,
                                                     const char *const argv[],
                                                     int *command_index)
{
    if (argc < 1 || argv == NULL || argv[0] == NULL || command_index == NULL)
    {
        return SERBERUS_SUDO_ARGS_UNSUPPORTED;
    }

    /* argv[0] must name sudo. An empty argv[0] is refused outright (a reader
     * that skipped it would shift every argument by one), and anything else —
     * "sudoedit", "lt-sudoedit", an arbitrary name — is not a form this parser
     * mirrors. Edit mode itself is decided by getprogname(), which the caller
     * checks with serberus_sudo_invocation_name_ok. */
    if (!names_sudo(argv[0]))
    {
        return SERBERUS_SUDO_ARGS_UNSUPPORTED;
    }

    int index = 1;
    while (index < argc)
    {
        const char *token = argv[index];
        if (token == NULL)
        {
            return SERBERUS_SUDO_ARGS_UNSUPPORTED;
        }
        if (strcmp(token, "--") == 0)
        {
            index++; /* whatever follows is the command, even NAME=value */
            break;
        }
        if (token[0] == '-' && token[1] != '\0')
        {
            int consumed = token[1] == '-'
                ? parse_long_option(argc, argv, index)
                : parse_short_cluster(argc, argv, index);
            if (consumed < 0)
            {
                return SERBERUS_SUDO_ARGS_UNSUPPORTED;
            }
            index += consumed;
            continue;
        }
        if (is_environment_assignment(token))
        {
            return SERBERUS_SUDO_ARGS_UNSUPPORTED;
        }
        break; /* the first non-option is the command */
    }

    if (index >= argc)
    {
        return SERBERUS_SUDO_ARGS_NO_COMMAND;
    }
    *command_index = index;
    return SERBERUS_SUDO_ARGS_COMMAND;
}

/* ---- bare-name command lookup ---- */

/* Search path used when PATH is unset or empty. A fixed list of system roots,
 * never derived from anything the invoking user controls. */
#define SERBERUS_DEFAULT_PATH "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

/* sudo_goodpath(): stat() succeeds, a regular file, and ANY execute bit set.
 * Deliberately stat() and not access(X_OK): access() checks the REAL uid (the
 * invoking user), while sudo stats as the runas user (normally root). This
 * module runs in sudo with euid 0, so stat() sees what root-sudo sees; with
 * access(), a root-only executable earlier in PATH would be skipped here but
 * run by sudo. */
static bool is_executable_file(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0 && S_ISREG(sb.st_mode)
        && (sb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

static bool canonicalize(const char *candidate, char *out, size_t out_size)
{
    char resolved[PATH_MAX];
    if (realpath(candidate, resolved) != NULL)
    {
        strlcpy(out, resolved, out_size);
    }
    else
    {
        strlcpy(out, candidate, out_size);
    }
    return true;
}

bool serberus_find_in_path(const char *cmd, const char *path_env,
                           char *out, size_t out_size)
{
    if (cmd == NULL || cmd[0] == '\0' || strchr(cmd, '/') != NULL
        || out == NULL || out_size == 0)
    {
        return false;
    }

    const char *cursor = (path_env != NULL && path_env[0] != '\0')
        ? path_env : SERBERUS_DEFAULT_PATH;
    bool check_dot = false;
    char candidate[PATH_MAX];

    while (*cursor != '\0')
    {
        const char *entry_end = strchr(cursor, ':');
        if (entry_end == NULL)
        {
            entry_end = cursor + strlen(cursor);
        }
        size_t length = (size_t)(entry_end - cursor);

        if (length == 0)
        {
            /* Empty entry (leading/trailing/double colon). sudo_strsplit()
             * skips separators, so sudo never sees it: skip, NOT the CWD. */
        }
        else if (length == 1 && cursor[0] == '.')
        {
            /* sudo searches "." LAST, after every other entry (and with
             * sudoers' ignore_dot refuses what it finds there). */
            check_dot = true;
        }
        else
        {
            /* Absolute AND relative entries, in PATH order, exactly as sudo's
             * find_path() does. A relative entry resolves against the CWD,
             * which sudo and this module share (same process, and -D/--chdir
             * is refused by the parser). Skipping it would be unsafe: sudo
             * would run "<rel>/cmd" while Serberus evaluated a later match. */
            if (length >= sizeof(candidate))
            {
                return false; /* sudo: ENAMETOOLONG ends the search */
            }
            int n = snprintf(candidate, sizeof(candidate), "%.*s/%s",
                             (int)length, cursor, cmd);
            if (n < 0 || (size_t)n >= sizeof(candidate))
            {
                return false; /* likewise */
            }
            if (is_executable_file(candidate))
            {
                return canonicalize(candidate, out, out_size); /* first match wins */
            }
        }
        cursor = *entry_end == ':' ? entry_end + 1 : entry_end;
    }

    if (check_dot)
    {
        int n = snprintf(candidate, sizeof(candidate), "./%s", cmd);
        if (n > 0 && (size_t)n < sizeof(candidate) && is_executable_file(candidate))
        {
            return canonicalize(candidate, out, out_size);
        }
    }
    return false;
}
