/*
 * sudo_args.h — find the command sudo is about to run, from sudo's own argv.
 *
 * pam_serberus runs inside sudo and must evaluate EXACTLY the command sudo
 * will execute. It can't ask sudo, so it re-parses sudo's command line. Any
 * disagreement between this parser and sudo is a policy bypass: Serberus would
 * approve one command while sudo runs another. So this mirrors sudo 1.9's
 * parse_args() (getopt_long with "+Aa:BbC:c:D:Eeg:Hh::iKklNnPp:R:r:SsT:t:U:u:Vv"
 * and its long-option table) and fails closed on anything it can't be certain
 * about:
 *
 *   - unknown or ambiguous options, and options missing their value;
 *   - invocations that don't run the named command as-is: -e/sudoedit, -s,
 *     -i, -l, -v, -V, -h/--host, -K, -U, -R (chroot), -D (chdir), and the
 *     platform-specific -a, -c, -r, -t;
 *   - VAR=value environment assignments before the command;
 *   - an argv[0] that doesn't name sudo (empty, "sudoedit", anything else).
 *
 * The argv must be sudo's REAL argument vector (pam_serberus takes it from
 * _NSGetArgc()/_NSGetArgv(), i.e. what sudo's main() received), never one
 * re-assembled from KERN_PROCARGS2 by string counting: an empty argv[0] makes
 * such a reader shift every argument by one.
 *
 * serberus_find_sudo_command and serberus_sudo_invocation_name_ok are pure (no
 * I/O). serberus_find_in_path stats the filesystem. All three are unit-tested
 * directly by the PAMConfigTests bundle.
 */
#ifndef SERBERUS_SUDO_ARGS_H
#define SERBERUS_SUDO_ARGS_H

#include <stdbool.h>
#include <stddef.h>

typedef enum
{
    /* A command was found at *command_index; its arguments follow it. */
    SERBERUS_SUDO_ARGS_COMMAND = 0,
    /* sudo was given no command. */
    SERBERUS_SUDO_ARGS_NO_COMMAND = 1,
    /* An option or form Serberus can't evaluate safely. The caller must deny. */
    SERBERUS_SUDO_ARGS_UNSUPPORTED = 2
} serberus_sudo_args_result;

/*
 * Parses sudo's full argv (argv[0] is the program name). On
 * SERBERUS_SUDO_ARGS_COMMAND, *command_index is the index of the command in
 * argv; otherwise it is left unchanged.
 */
serberus_sudo_args_result serberus_find_sudo_command(int argc,
                                                     const char *const argv[],
                                                     int *command_index);

/*
 * True only when this sudo process is running as plain `sudo`, not sudoedit.
 *
 * sudo 1.9.17 takes its mode from its program name: main() calls
 * initprogname2(argv[0], {"sudo", "sudoedit"}), which prefers getprogname(),
 * strips a leading "lt-", and parse_args() enters edit mode when the result is
 * "sudoedit". On macOS getprogname() is the last path component of argv[0] as
 * the process was started (`exec -a sudoedit /usr/bin/sudo` sets it), so a
 * caller-chosen argv[0], or a symlink named "sudoedit" or "lt-sudoedit"
 * pointing at /usr/bin/sudo, runs sudoedit.
 *
 * getprogname() is the name parse_args() actually used, so it is the check
 * that decides; argv[0] is read separately because it is what the command
 * parser mirrors, and the execve path is checked as well so that no name the
 * process was reached by disagrees. Each of the three — `progname`
 * (getprogname() in the sudo process), `exec_path` (the execve path, the first
 * string of KERN_PROCARGS2) and `argv0` — must, after taking its last path
 * component and stripping a leading "lt-", be exactly "sudo". NULL or empty ->
 * false. Callers must treat false as unevaluable (deny in enforce).
 */
bool serberus_sudo_invocation_name_ok(const char *progname,
                                      const char *exec_path,
                                      const char *argv0);

/*
 * Resolves a BARE command name (no '/') the way sudoers' find_path() does, so
 * Serberus evaluates the binary sudo will run:
 *   - PATH entries in order, absolute AND relative (a relative entry resolves
 *     against the CWD, which this module shares with sudo);
 *   - empty entries skipped (sudo_strsplit() never yields them);
 *   - "." searched LAST, after every other entry;
 *   - a candidate qualifies when stat() finds a regular file with any execute
 *     bit (sudo_goodpath()), not via access(), which checks the real uid;
 *   - a candidate path of PATH_MAX or more ends the search, as in sudo.
 * The first match is canonicalized with realpath() (the raw candidate if that
 * fails) into `out`. `path_env` NULL or empty searches a fixed default of
 * system directories. Returns false (out untouched) when nothing matches or
 * `cmd` is empty or contains a '/'.
 *
 * Residual differences from sudo, by design (the module can't see sudoers):
 *   - sudoers `secure_path` replaces the user's PATH for non-exempt users; this
 *     searches the caller's PATH. macOS ships no secure_path.
 *   - sudo stats as the RUNAS user (then retries as the invoking user); this
 *     stats as root (the module's euid). Identical for `-u root`, the only
 *     common case; `-u <user>` can differ on directories that user can't search.
 *   - with sudoers `ignore_dot`, sudo refuses a match found via "."; this
 *     still returns it, which only means Serberus evaluates a command sudo
 *     will not run.
 */
bool serberus_find_in_path(const char *cmd, const char *path_env,
                           char *out, size_t out_size);

#endif /* SERBERUS_SUDO_ARGS_H */
