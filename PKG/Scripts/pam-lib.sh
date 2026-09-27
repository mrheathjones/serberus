# shellcheck shell=bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: pam-lib.sh
# Author: Heath Jones
# Date: 2026-07-11
# Modified: 2026-09-27
# Purpose: Sourced library of the safety-critical PAM wiring logic shared by
#          the Serberus installer scripts (PKG/Scripts/pre/postinstall and
#          uninstall.sh, the generated test-pkg pre/postinstalls + uninstall
#          helpers, the uninstall pkg, Support/build-pam.sh and
#          Support/serberusd-devtool.sh) and the unit test harness
#          (PKG/tests/test-pam-lib.sh):
#            - idempotent /etc/pam.d/sudo_local line-merge (Serberus line
#              FIRST, existing user lines never clobbered)
#            - marker-aware removal (sudo_local reference removed BEFORE the
#              module is deleted; file deleted only when Serberus created it)
#            - break-glass preflight (managed-prefs-first config read; fails
#              CLOSED against installation when enforce-or-absent config has
#              no RESOLVABLE pamBypass user/group — installing pam_serberus
#              then would brick sudo)
#            - module path-chain safety (every directory from /usr down to
#              the module root-owned, not group/other-writable, no symlinks)
#            - same-team code-signature checks and a launchd "job is really
#              running" wait used before sudo_local is wired
#          Functions take the paths they act on as parameters; the /etc and
#          /Library defaults (SERBERUS_AUTHDB_PATH, SERBERUS_VERSION_PLIST,
#          SERBERUS_UPGRADE_MARKER and the like) are only fallbacks, so tests
#          run entirely on temp fixtures.
#          This file is SOURCED, never executed: it sets no shell options and
#          never exits; callers own set -euo pipefail, logging, ownership,
#          and modes.
# Version: 1.8 - (a) The gate on removing the SerberusAuth plugin and the
#          authdb-backups (serberus_authdb_free_of_serberus) no longer
#          trusts a comment. It passes only when authdb-backups holds no
#          pending record (.json, .branches or .projection;
#          serberus_authdb_records_pending; .standin is ignored) and no live
#          composition row invokes SerberusAuth and no right delegates to a
#          composition row (SERBERUS_AUTHDB_QUERY). A right a standard user
#          created with the marker comment blocks nothing. (b)
#          serberus_launchd_wait_gone waits SERBERUS_DAEMON_BOOTOUT_WAIT, the
#          daemon's ExitTimeOut plus 5 s (25 s). (c) serberus_daemon_trusted
#          no longer falls back to the team of the binary about to run: with
#          no recorded installTeamID and no signed PAM module installed, the
#          daemon is refused. (d) New
#          serberus_write_upgrade_marker (SERBERUS_UPGRADE_MARKER), written by
#          the preinstalls on an upgrade for the new daemon. (e) New
#          serberus_purge_support_data: --purge removes data only, never the
#          apps, uninstall helpers or install markers. (f) New
#          serberus_cli_dir_is_root_only, so an install can say why it stops
#          when /usr/local/bin is not root-only. (g)
#          serberus_pam_path_is_root_locked is ACL-aware
#          (serberus_pam_path_acl_grants_write, from `ls -led`): an ALLOW
#          entry granting write, append, add_file, add_subdirectory, delete,
#          delete_child, writesecurity or chown to anyone but user:root fails
#          it, as the daemon's PAMGateACL does. An entry is read from the
#          right, so a principal whose name has a space ("group:CORP\Domain
#          Users") is read whole, and a line that does not parse counts as
#          granting write. (h) Break-glass: a pamBypass
#          group counts only when a member resolves to an existing account (a
#          gr_mem name, a GroupMembers GeneratedUID, or an account whose
#          primary gid it is; nested groups do not count), the same rule as
#          pam_config.c and the daemon. (i) pamBypass names are passed
#          NUL-separated and compared byte for byte
#          (serberus_pam_plist_string); a name containing U+0000 resolves
#          nothing. (j) The sudo_local merge reads lines as OpenPAM does:
#          the facility and control flag match in any case, and `#` starts
#          a comment anywhere. (k) New serberus_pam_shadowing_policy_present:
#          a policy file that would shadow /etc/pam.d/sudo (the MDM-managed
#          pam.d or pam.conf, /etc/pam.conf, /usr/local/etc) is reported, the
#          same list as the daemon's PAMGateVerifier.
#          1.7 - (a) The sudo_local merge and removal (and the temp-file
#          install under them) refuse a DIRECTORY at the sudo_local path
#          (FAILED, status 1) instead of dropping a file inside it. (b)
#          Break-glass: a pamBypass user counts only when the directory
#          record's name equals the entry exactly (a case or alias match is
#          reported and provides no bypass: pam_serberus compares the exact
#          login name), and a pamBypass group counts only when it has at
#          least one member (its users list, or an account the directory
#          search policy lists whose primary group it is — the same rule as
#          pam_config.c and the daemon). (c) New serberus_launchd_wait_gone: after a bootout,
#          poll `launchctl print` until the job is gone, for up to the
#          daemon's ExitTimeOut (SERBERUS_DAEMON_EXIT_TIMEOUT, 20 s). (d) New
#          serberus_recorded_team: the Team ID an install recorded in the
#          root-owned version.plist (installTeamID), for callers to pin
#          serberus_daemon_trusted to. (e) New
#          serberus_pam_remove_versioned_module and
#          SERBERUS_PAM_MODULE_VERSIONED_PATH: OpenPAM loads
#          pam_serberus.so.2 in preference to pam_serberus.so, so installers
#          and uninstallers remove a stray one. (f) SERBERUS_AUTHDB_QUERY
#          (the gate on deleting the SerberusAuth plugin) matches only rights
#          that invoke a SerberusAuth: mechanism or carry the daemon's managed
#          marker, no longer any right whose name or comment mentions
#          serberus (a right a standard user created could block the
#          uninstall).
#          1.6 - (a) serberus_launchd_wait_running: the same-pid window is
#          now 8 s (longer than the LaunchDaemon's 5 s ThrottleInterval, so a
#          daemon that dies after a few seconds is seen restarting); launchd's
#          `runs` counter must not advance and no non-zero `last exit code`
#          (or terminating signal) may appear while waiting; when given a
#          state.plist and a bootstrap mark, the daemon must have written a
#          state (not `unknown`) whose updatedAt is not older than the mark,
#          so a state left by the previous daemon never counts; a CLI path
#          that is given but missing fails the check. The pid that passed is
#          kept in SERBERUS_LAUNCHD_UP_PID for serberus_launchd_pid_unchanged,
#          which callers run right before merging sudo_local. New
#          serberus_launchd_bootstrap_mark, serberus_launchd_job_field and
#          serberus_daemon_state_fresh. (b) New serberus_daemon_trusted: strict
#          signature, Apple anchor, identifier com.herojoneslabs.serberus.daemon
#          and the pinned team, checked before any daemon one-shot is run; new
#          serberus_daemon_manual_steps prints the by-hand fallback. (c)
#          serberus_pam_remove_sudoers_dropin re-checks the path after rm and
#          prints FAILED (status 1) when the drop-in is still there. (d) The
#          sudo_local merge/remove helpers delete their temp file and print
#          FAILED (status 1) when the chmod or mv fails.
#          1.5 - (a) sudo_local writes go through a temp file that gets the
#          final mode BEFORE the atomic mv: merge/create stamp 0444 (the mode
#          the installers ship), removal keeps the file's original mode. A
#          DANGLING sudo_local symlink is replaced by a regular file instead
#          of being written through to its target. (b) New
#          serberus_pam_module_dir_is_safe: the directory half of the chain
#          check, run BEFORE any chown/chmod of the module (callers then lock
#          the module with chown -h / chmod -h); serberus_pam_module_path_is_safe
#          builds on it. (c) serberus_launchd_wait_running now requires the
#          SAME pid across ~3 s (a crash-looping job is briefly "running" at
#          every respawn) and, when given a trusted serberus CLI, a successful
#          `serberus status` that is not STALE. New serberus_launchd_job_pid
#          and serberus_cli_health_ok. (d) New serberus_run_bounded: runs a
#          one-shot with a hard deadline (macOS has no timeout(1)); 124 on
#          timeout. (e) New serberus_authdb_free_of_serberus: read-only
#          sqlite3 check that no AuthorizationDB right still names
#          SerberusAuth/Serberus — gates deleting the plugin and backups.
#          (f) New serberus_pam_sudo_includes_sudo_local: /etc/pam.d/sudo must
#          carry `auth include sudo_local` as its FIRST active auth line (the
#          daemon reports degraded pam_not_wired otherwise); read-only.
#          (g) New serberus_daemon_rearm_if_wired: the safety net every
#          teardown EXIT trap calls — while sudo_local still has an active
#          pam_serberus line, keep the daemon label enabled (and loaded).
#          1.4 - (a) sudo_local merge now converges on the canonical
#          POSITION too: a `present` or legacy Serberus line that is not the
#          FIRST active auth line (e.g. below `auth sufficient pam_tid.so`, so
#          Touch ID ends the chain before Serberus runs) is removed and the
#          canonical line re-inserted above the first active auth line.
#          Already-canonical files stay byte-identical; a symlinked
#          sudo_local is replaced by a regular file (the daemon refuses a
#          link). A creation template is used only when it is itself
#          canonical. (b) Tool defaults are
#          absolute paths (no PATH lookup as root); the PAM_LIB_* overrides
#          remain for tests. (c) New serberus_pam_module_path_is_safe: the
#          module and every directory above it must be root-owned, not
#          group/other-writable and not symlinks (refuses Intel-Homebrew
#          /usr/local layouts); missing directories are created root:wheel
#          0755. (d) serberus_pam_user_resolves resolves NAMES only
#          (dscacheutil) and rejects all-digit names — `id -u 501` succeeds
#          but pam_serberus compares login names, so a UID provides no
#          break-glass. (e) New serberus_codesign_team_id /
#          serberus_codesign_satisfies_team (module must be signed by the
#          daemon's team) and serberus_launchd_job_running /
#          serberus_launchd_wait_running (a loaded-but-crashing job is not
#          "up").
#          1.3 - `requisite` control; legacy `required` lines rewritten on
#          upgrade.
#          1.2 - Added serberus_pam_remove_sudoers_dropin: marker-guarded,
#          single-exact-path (`rm -f`, no glob/visudo) removal of the coarse
#          /etc/sudoers.d/serberus standard-user allowlist, for teardown paths
#          to call UNCONDITIONALLY and BEFORE unwiring sudo_local / removing the
#          module (fine gate must outlive the coarse gate — else fail-open).
#          1.1 - Module relocated to /usr/local/lib/pam/pam_serberus.so
#          (/usr/lib/pam sits on the SEALED read-only system snapshot on
#          macOS 11+ — nothing can install there) and the sudo_local auth
#          line now references it by ABSOLUTE path; removal/strip logic
#          still matches legacy bare-name lines. Break-glass preflight now
#          RESOLVES each pamBypass user (id) and group (dscacheutil) — a
#          typo'd entry ("brekglass") provides zero real bypass, so a
#          non-empty-but-unresolvable list no longer passes; resolver
#          functions are overridable for tests.
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

####################################################################
############## Begin Define Variables Block ########################
####################################################################
##############################
### Core Defined Variables ###
### MODIFY AT YOUR OWN RISK ##
##############################

# Deliberately NOT readonly and prefixed PAM_LIB_/SERBERUS_PAM_ so sourcing
# scripts (which declare their own readonly tool variables) never collide and
# double-sourcing is harmless.
# Absolute paths, never a PATH lookup: this library runs as root inside
# installer scripts, and a PATH entry an unprivileged user can write (e.g.
# /usr/local/bin) would let them plant a tool root then executes. The
# overrides exist for the test harness only.
PAM_LIB_AWK="${PAM_LIB_AWK:-/usr/bin/awk}"
PAM_LIB_CAT="${PAM_LIB_CAT:-/bin/cat}"
PAM_LIB_CHMOD="${PAM_LIB_CHMOD:-/bin/chmod}"
PAM_LIB_CHOWN="${PAM_LIB_CHOWN:-/usr/sbin/chown}"
PAM_LIB_CODESIGN="${PAM_LIB_CODESIGN:-/usr/bin/codesign}"
PAM_LIB_DATE="${PAM_LIB_DATE:-/bin/date}"
PAM_LIB_DSCACHEUTIL="${PAM_LIB_DSCACHEUTIL:-/usr/bin/dscacheutil}"
PAM_LIB_DSCL="${PAM_LIB_DSCL:-/usr/bin/dscl}"
PAM_LIB_GREP="${PAM_LIB_GREP:-/usr/bin/grep}"
PAM_LIB_ID="${PAM_LIB_ID:-/usr/bin/id}"
PAM_LIB_LAUNCHCTL="${PAM_LIB_LAUNCHCTL:-/bin/launchctl}"
PAM_LIB_LS="${PAM_LIB_LS:-/bin/ls}"
PAM_LIB_MKDIR="${PAM_LIB_MKDIR:-/bin/mkdir}"
PAM_LIB_MV="${PAM_LIB_MV:-/bin/mv}"
PAM_LIB_PLUTIL="${PAM_LIB_PLUTIL:-/usr/bin/plutil}"
PAM_LIB_RM="${PAM_LIB_RM:-/bin/rm}"
PAM_LIB_SLEEP="${PAM_LIB_SLEEP:-/bin/sleep}"
PAM_LIB_SQLITE3="${PAM_LIB_SQLITE3:-/usr/bin/sqlite3}"
PAM_LIB_STAT="${PAM_LIB_STAT:-/usr/bin/stat}"

PAM_LIB_VERSION="1.8"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

# Marker tags. The managed tag rides as a trailing comment on the auth line
# (OpenPAM treats an unquoted # word as start-of-comment, so sudo never sees
# it); the created tag marks a sudo_local file that Serberus itself created,
# which is the ONLY kind of file removal may delete outright.
SERBERUS_PAM_MANAGED_TAG="# serberus-managed"
SERBERUS_PAM_CREATED_TAG="# serberus-created"

# Canonical on-disk module location. /usr/lib/pam sits on the SEALED
# read-only APFS system snapshot on macOS 11+ — nothing (root, installer
# payloads, scripts) can ever write there — so the module lives under the
# /usr/local firmlink and sudo_local MUST reference it by ABSOLUTE path
# (libpam searches more than one directory for a bare module name, so a bare
# name does not pin which file sudo loads, and the daemon never counts it as
# wired).
SERBERUS_PAM_MODULE_DIR="/usr/local/lib/pam"
SERBERUS_PAM_MODULE_PATH="${SERBERUS_PAM_MODULE_DIR}/pam_serberus.so"

# OpenPAM's loader tries "<path>.2" BEFORE "<path>", even for an absolute
# path, so a file here is what sudo would really run. Serberus never ships
# one; installers and uninstallers remove any they find
# (serberus_pam_remove_versioned_module), and the daemon reports sudo as not
# wired while one exists.
SERBERUS_PAM_MODULE_VERSIONED_PATH="${SERBERUS_PAM_MODULE_PATH}.2"

# The single Serberus PAM line. It must be the FIRST active auth line so that
# a pre-existing `auth sufficient pam_tid.so` (Touch ID) can never satisfy
# sudo before Serberus evaluates the request — the daemon refuses to write the
# sudoers drop-in unless it is.
# `requisite`: a Serberus deny returns the stack immediately (no post-deny
# password prompt from pam_opendirectory); success and PAM_IGNORE continue
# exactly as `required` did. Upgrades from the older `required` control, and
# lines sitting below another auth line, are moved/rewritten by
# serberus_pam_merge_sudo_local.
SERBERUS_PAM_AUTH_LINE="auth       requisite      ${SERBERUS_PAM_MODULE_PATH} ${SERBERUS_PAM_MANAGED_TAG}"

# Header written when Serberus creates sudo_local from scratch.
SERBERUS_PAM_CREATED_HEADER="# sudo_local: created by com.herojoneslabs.serberus ${SERBERUS_PAM_CREATED_TAG}"

# Legacy create-if-absent header (Support/sudo_local and the pre-1.1
# production postinstall) — treated like the created tag so uninstalls of
# older installs still clean up fully.
SERBERUS_PAM_LEGACY_HEADER_RE='^# sudo_local: managed by com\.herojoneslabs\.serberus'

# Every line removal strips: any reference to the module (once the module is
# deleted, ANY surviving reference — ours or hand-added — dlopen-fails inside
# the `requisite` line and bricks sudo), plus Serberus marker/managed comments.
# `pam_serberus\.so` is a deliberate SUBSTRING match so it covers BOTH the
# legacy bare-name form (`pam_serberus.so`, pre-relocation installs) and the
# new absolute-path form (`/usr/local/lib/pam/pam_serberus.so`).
SERBERUS_PAM_STRIP_RE="pam_serberus\.so|# serberus-(managed|created)|${SERBERUS_PAM_LEGACY_HEADER_RE}"

# Coarse sudoers drop-in that lets STANDARD (non-admin) users invoke the
# curated sudo commands at all — a per-command allowlist of the curated
# command paths only, while pam_serberus + the daemon stay the authoritative
# FINE policy. Its removal MUST run BEFORE the module/sudo_local are torn down
# (see serberus_pam_remove_sudoers_dropin): the drop-in is the coarse gate, the
# module is the fine gate; removing the fine gate first would leave standard
# users able to sudo the curated paths with NO fine enforcement — a fail-OPEN.
# Path mirrors PrivMgrCore BundleConfig.sudoersDropInPath — KEEP IN SYNC.
SERBERUS_SUDOERS_PATH="/etc/sudoers.d/serberus"

# Ownership marker guarding removal: Serberus deletes this drop-in ONLY when
# the file carries its managed header, so a same-named admin-authored file at
# the exact path is never destroyed. The generator stamps the header as its
# FIRST line (PrivMgrCore SudoersGenerator.defaultHeader /
# BundleConfig.sudoersManagedHeader) — the two variants differ only in the
# trailing "DO NOT EDIT" / "do not edit" case and dash, so this guard anchors
# on the stable path+domain prefix they share and matches both. Deliberately
# specific (full drop-in path + reverse-DNS domain) so it cannot false-match an
# unrelated admin comment. KEEP IN SYNC with those Swift headers.
SERBERUS_SUDOERS_MARKER_RE='^# /etc/sudoers\.d/serberus: managed by com\.herojoneslabs\.serberus'

# Mode a sudo_local that Serberus creates or rewrites ships with (the
# installers have always stamped root:wheel 0444). The temp file gets it
# BEFORE the atomic mv, so the live file is never briefly group/other-
# writable or left at the umask default if a later step fails.
SERBERUS_PAM_SUDO_LOCAL_MODE="444"

# The code-signing identifier every build signs serberusd with (the scripts'
# `codesign --identifier`, project.yml OTHER_CODE_SIGN_FLAGS). The PAM module
# and the clients pin it in their peer requirement, and root runs a daemon
# one-shot only when the binary carries it (serberus_daemon_trusted).
SERBERUS_DAEMON_IDENTIFIER="com.herojoneslabs.serberus.daemon"

# Root-owned record of the installed versions. Every installer also writes the
# Team ID it validated the daemon against (installTeamID); teardowns pin the
# daemon to that team (serberus_recorded_team) before executing it.
SERBERUS_VERSION_PLIST="/Library/Application Support/Serberus/version.plist"
SERBERUS_INSTALL_TEAM_KEY="installTeamID"

# How long launchd gives the daemon to exit after SIGTERM before it sends
# SIGKILL: the ExitTimeOut the LaunchDaemon plist sets (20 s; launchd's own
# default is 5 s).
SERBERUS_DAEMON_EXIT_TIMEOUT=20

# How long serberus_launchd_wait_gone waits for a booted-out daemon to leave
# launchd: its ExitTimeOut plus 5 s, so a daemon that uses its whole
# ExitTimeOut (and is then killed) is still seen as gone.
SERBERUS_DAEMON_BOOTOUT_WAIT=$((SERBERUS_DAEMON_EXIT_TIMEOUT + 5))

# Root-only marker the production preinstall writes on an upgrade, before it
# stops the old daemon (serberus_write_upgrade_marker). The new daemon reads
# it at startup, and removes it, to end the JIT sessions the old daemon left
# open.
SERBERUS_UPGRADE_MARKER="/Library/Application Support/Serberus/.upgrade-in-progress"

# Live AuthorizationDB (root-only). Read with sqlite3 -readonly, never written.
SERBERUS_AUTHDB_PATH="/var/db/auth.db"

# The daemon's records (root-only, flat): one file per right, named <right>
# with "/" replaced by "_", plus a suffix. .json (snapshot or tombstone),
# .branches (composition ownership) and .projection (projection digest) are
# pending work and block removing the plugin and the backups; .standin (the
# admin-auth stand-in digest) is kept on purpose after a restore and blocks
# nothing. A successful restore removes the .json, .branches and .projection
# files of every right it restored.
SERBERUS_AUTHDB_BACKUPS_PATH="/Library/Application Support/Serberus/authdb-backups"
SERBERUS_AUTHDB_BLOCKING_SUFFIXES="json branches projection"

# Live rights that still need the plugin: a composition row
# (AuthURIIdentityScope.rowPrefix) that invokes a SerberusAuth: mechanism
# (plugin name compared without wildcards; sqlite's LIKE ignores ASCII case),
# and any right that delegates to a composition row. Never a comment: a
# standard user can create rights (config.add.* is class=allow) and write
# any comment, the daemon's marker included. KEEP IN SYNC with
# PKG/Scripts/uninstall.sh FALLBACK_AUTHDB_QUERY and PKG/verify-uninstall.sh
# check_authorization_db.
SERBERUS_AUTHDB_QUERY="SELECT DISTINCT r.name FROM rules r JOIN mechanisms_map mm ON mm.r_id = r.id JOIN mechanisms m ON m.id = mm.m_id WHERE m.plugin LIKE 'SerberusAuth' AND r.name LIKE 'com.herojoneslabs.serberus.branch.%' UNION SELECT DISTINCT r.name FROM rules r JOIN delegates_map dm ON dm.r_id = r.id JOIN rules d ON d.id = dm.d_id WHERE d.name LIKE 'com.herojoneslabs.serberus.branch.%';"

##################################
### End User Defined Variables ###
##################################
####################################################################
############## End Define Variables Block ##########################
####################################################################

###################################################################################
############## Begin Function Block ###############################################
###################################################################################

########################################
######## sudo_local line-merge #########
########################################

# True when an ACTIVE (non-comment) line in the file references
# pam_serberus.so. `^[^#]*` cannot cross a comment character, so commented-out
# lines and mentions inside trailing comments do not count.
serberus_pam_sudo_local_has_module() {
    local sudo_local="$1"
    [[ -f "${sudo_local}" ]] || return 1
    "${PAM_LIB_GREP}" -Eq '^[^#]*pam_serberus\.so' "${sudo_local}"
}

# True when sudo_local is already in the canonical shape: exactly ONE active
# line references pam_serberus.so, and the FIRST active auth line is
# `auth requisite /usr/local/lib/pam/pam_serberus.so …` (trailing module
# arguments/comments allowed, so an admin's hand-written canonical line is
# left alone). Anything else — a legacy control, a bare-name path, a
# duplicate, the line sitting below pam_tid.so, or sudo_local being a
# SYMLINK (the daemon lstat()s it and refuses one; a merge replaces the link
# with a regular file carrying the same lines) — is not canonical.
# Lines are read the way OpenPAM reads them: `#` starts a comment anywhere on
# a line, and the facility and control flag match in any case (`AUTH
# Requisite …` is an auth line), exactly as the daemon's verifier reads them.
#   $1 sudo_local path
serberus_pam_sudo_local_is_canonical() {
    local sudo_local="$1"
    [[ -f "${sudo_local}" && ! -L "${sudo_local}" ]] || return 1
    "${PAM_LIB_AWK}" -v module="${SERBERUS_PAM_MODULE_PATH}" '
        /^[^#]*pam_serberus\.so/ { count++ }
        {
            active = $0
            sub(/#.*/, "", active)
            n = split(active, word)
        }
        !seen && n > 0 && tolower(word[1]) == "auth" {
            seen = 1; control = tolower(word[2]); path = word[3]
        }
        END {
            if (count == 1 && seen && control == "requisite" && path == module) exit 0
            exit 1
        }
    ' "${sudo_local}"
}

# Gives <tmp> its final <mode>, then moves it over <target> atomically. When
# either step fails the temp file is deleted (a failed mv must not leave a
# sudo_local.serberus-*.<pid> file behind) and 1 is returned. A DIRECTORY at
# <target> (or a link to one) is refused: mv would drop the temp file inside
# it and report success.
#   $1 temp file, $2 target path, $3 octal mode
serberus_pam_install_temp() {
    local tmp="$1"
    local target="$2"
    local mode="$3"
    if [[ -d "${target}" ]]
    then
        "${PAM_LIB_RM}" -f "${tmp}"
        return 1
    fi
    if "${PAM_LIB_CHMOD}" "${mode}" "${tmp}" && "${PAM_LIB_MV}" -f "${tmp}" "${target}"
    then
        return 0
    fi
    "${PAM_LIB_RM}" -f "${tmp}"
    return 1
}

# Idempotent merge of the Serberus auth line into sudo_local.
#   $1 sudo_local path
#   $2 optional creation template (Support/sudo_local — the single source of
#      truth for from-scratch content); used only when it is itself
#      canonical, otherwise a minimal built-in header + auth line is written.
# Prints exactly one of:
#   created — file did not exist; Serberus created it (created tag stamped)
#   merged  — the canonical line was inserted above the first active auth
#             line (or appended); any existing Serberus line that was not
#             canonical (wrong control, bare-name path, duplicate, or BELOW
#             another auth line such as pam_tid.so) was removed first
#   present — already canonical; file untouched (byte-identical)
#   FAILED  — the temp file could not be written or moved into place, or
#             sudo_local is a directory (status 1; the temp file is removed
#             and sudo_local is unchanged)
# Never touches Apple-owned /etc/pam.d/sudo — callers only ever pass
# sudo_local. Ownership/mode are the caller's job (root context only).
serberus_pam_merge_sudo_local() {
    local sudo_local="$1"
    local template="${2:-}"
    local tmp

    # A directory (or a link to one) is not a sudo_local we can rewrite; awk
    # reads it as empty and mv would drop the result inside it.
    if [[ -d "${sudo_local}" ]]
    then
        printf 'FAILED'
        return 1
    fi

    # A DANGLING symlink (-L but not -e) is not "absent": writing to it would
    # create whatever file it points at. Remove the link itself and create a
    # regular file in its place (a live link is replaced by the rewrite below,
    # exactly as canonicalization does).
    if [[ -L "${sudo_local}" && ! -e "${sudo_local}" ]]
    then
        "${PAM_LIB_RM}" -f "${sudo_local}"
    fi

    if [[ ! -e "${sudo_local}" ]]
    then
        tmp="${sudo_local}.serberus-create.$$"
        "${PAM_LIB_RM}" -f "${tmp}"
        if [[ -n "${template}" && -f "${template}" ]] \
            && serberus_pam_sudo_local_is_canonical "${template}"
        then
            {
                printf '%s\n' "${SERBERUS_PAM_CREATED_HEADER}"
                "${PAM_LIB_CAT}" "${template}"
            } > "${tmp}"
        else
            printf '%s\n%s\n' "${SERBERUS_PAM_CREATED_HEADER}" \
                "${SERBERUS_PAM_AUTH_LINE}" > "${tmp}"
        fi
        if ! serberus_pam_install_temp "${tmp}" "${sudo_local}" "${SERBERUS_PAM_SUDO_LOCAL_MODE}"
        then
            printf 'FAILED'
            return 1
        fi
        printf 'created'
        return 0
    fi

    if serberus_pam_sudo_local_is_canonical "${sudo_local}"
    then
        printf 'present'
        return 0
    fi

    # Drop every ACTIVE Serberus line (commented-out ones are the admin's and
    # pass through), then insert the canonical line ABOVE the first remaining
    # auth line so nothing (pam_tid.so included) can end the chain before
    # Serberus; append when no auth line exists. The facility matches in any
    # case and `#` starts a comment anywhere, as OpenPAM reads it (`AUTH
    # sufficient pam_tid.so` is an auth line). Every other line passes
    # through byte-identical and in order.
    tmp="${sudo_local}.serberus-merge.$$"
    "${PAM_LIB_RM}" -f "${tmp}"
    "${PAM_LIB_AWK}" -v line="${SERBERUS_PAM_AUTH_LINE}" '
        BEGIN { inserted = 0 }
        /^[^#]*pam_serberus\.so/ { next }
        {
            active = $0
            sub(/#.*/, "", active)
            split(active, word)
            if (!inserted && tolower(word[1]) == "auth") { print line; inserted = 1 }
            print
        }
        END { if (!inserted) print line }
    ' "${sudo_local}" > "${tmp}" || {
        "${PAM_LIB_RM}" -f "${tmp}"
        printf 'FAILED'
        return 1
    }
    if ! serberus_pam_install_temp "${tmp}" "${sudo_local}" "${SERBERUS_PAM_SUDO_LOCAL_MODE}"
    then
        printf 'FAILED'
        return 1
    fi
    printf 'merged'
}

# Marker-aware removal of the Serberus wiring from sudo_local. MUST run
# BEFORE the module file is deleted — never the reverse order.
#   $1 sudo_local path
# Prints exactly one of:
#   absent    — no sudo_local; nothing to do
#   untouched — no Serberus content in the file; left byte-identical
#   cleaned   — Serberus lines removed; user lines preserved, file kept
#   deleted   — Serberus created this file and nothing active remained
#   FAILED    — the rewrite could not be moved into place, or sudo_local is a
#               directory (status 1; the temp file is removed and sudo_local
#               is unchanged)
serberus_pam_remove_sudo_local() {
    local sudo_local="$1"

    if [[ -d "${sudo_local}" ]]
    then
        printf 'FAILED'
        return 1
    fi

    if [[ ! -e "${sudo_local}" ]]
    then
        printf 'absent'
        return 0
    fi

    if ! "${PAM_LIB_GREP}" -Eq "${SERBERUS_PAM_STRIP_RE}" "${sudo_local}"
    then
        printf 'untouched'
        return 0
    fi

    local created=0
    if "${PAM_LIB_GREP}" -Fq "${SERBERUS_PAM_CREATED_TAG}" "${sudo_local}" \
        || "${PAM_LIB_GREP}" -Eq "${SERBERUS_PAM_LEGACY_HEADER_RE}" "${sudo_local}"
    then
        created=1
    fi

    # The rewritten file keeps the ORIGINAL permission bits (an admin's
    # pre-existing sudo_local may legitimately be 0644); unreadable => the
    # shipped 0444.
    local mode
    mode=$("${PAM_LIB_STAT}" -L -f '%Lp' "${sudo_local}" 2>/dev/null) || mode=""
    if [[ ! "${mode}" =~ ^[0-7]{3,4}$ ]]
    then
        mode="${SERBERUS_PAM_SUDO_LOCAL_MODE}"
    fi

    # grep -v exits 1 when nothing survives — that is a valid outcome here.
    local tmp="${sudo_local}.serberus-remove.$$"
    "${PAM_LIB_RM}" -f "${tmp}"
    "${PAM_LIB_GREP}" -Ev "${SERBERUS_PAM_STRIP_RE}" "${sudo_local}" > "${tmp}" || true

    # Delete the file only when Serberus created it AND no active
    # (non-comment, non-blank) line remains; a file that pre-existed us — or
    # gained user lines since — is preserved minus the Serberus lines.
    if [[ "${created}" -eq 1 ]] \
        && ! "${PAM_LIB_GREP}" -Eq '^[[:space:]]*[^#[:space:]]' "${tmp}"
    then
        "${PAM_LIB_RM}" -f "${tmp}" "${sudo_local}"
        printf 'deleted'
        return 0
    fi

    if ! serberus_pam_install_temp "${tmp}" "${sudo_local}" "${mode}"
    then
        printf 'FAILED'
        return 1
    fi
    printf 'cleaned'
}

# Read-only check of Apple's /etc/pam.d/sudo: its FIRST active auth line must
# be `auth include sudo_local`, or sudo_local (and pam_serberus with it) is
# never consulted — or is consulted only after another module already
# decided. The daemon reports degraded(pam_not_wired) in that case. Serberus
# never edits /etc/pam.d/sudo (Apple-owned; OS updates restore it), so
# callers only WARN.
#   $1 path to the sudo PAM file (/etc/pam.d/sudo live)
# Returns 0 when wired; 1 otherwise, with the reason on stderr.
serberus_pam_sudo_includes_sudo_local() {
    local pam_sudo="$1"
    if [[ ! -f "${pam_sudo}" ]]
    then
        printf '%s is missing — sudo_local is never included\n' "${pam_sudo}" >&2
        return 1
    fi
    local first
    first=$("${PAM_LIB_AWK}" '
        /^[[:space:]]*#/ { next }
        $1 == "auth" { print $2 " " $3; exit }
    ' "${pam_sudo}" 2>/dev/null) || first=""
    if [[ "${first}" == "include sudo_local" ]]
    then
        return 0
    fi
    printf '%s: first active auth line is "auth %s", not "auth include sudo_local" — pam_serberus would not gate sudo (the daemon reports degraded pam_not_wired)\n' \
        "${pam_sudo}" "${first:-<none>}" >&2
    return 1
}

# Where else macOS's OpenPAM can load sudo's policy from, in place of the
# /etc/pam.d/sudo and sudo_local Serberus wires: the MDM-managed pam.d and
# pam.conf, /etc/pam.conf, and /usr/local/etc. The same list as the daemon's
# PAMGateVerifier (defaultShadowingPolicyPaths); test-pam-lib.sh checks they
# match. None exists on a stock Mac. While one does, the daemon reports
# degraded(pam_not_wired), so wiring sudo_local would gate nothing.
SERBERUS_PAM_SHADOWING_POLICY_PATHS=(
    "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d/sudo"
    "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d/sudo_local"
    "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.conf"
    "/etc/pam.conf"
    "/usr/local/etc/pam.d/sudo"
    "/usr/local/etc/pam.d/sudo_local"
    "/usr/local/etc/pam.conf"
)

# Prints each shadowing policy path (SERBERUS_PAM_SHADOWING_POLICY_PATHS) that
# exists, one per line. Anything there counts, a dangling symlink included,
# exactly as the daemon's lstat does.
#   $1 optional root prefix (tests): each path is looked up under it
# Returns 0 when at least one exists, 1 when none does.
serberus_pam_shadowing_policy_present() {
    local root="${1:-}"
    local path
    local found=1
    root="${root%/}"
    for path in "${SERBERUS_PAM_SHADOWING_POLICY_PATHS[@]}"
    do
        if [[ -e "${root}${path}" || -L "${root}${path}" ]]
        then
            printf '%s\n' "${path}"
            found=0
        fi
    done
    return "${found}"
}

########################################
###### sudoers drop-in removal #########
########################################

# Marker-guarded removal of the coarse Serberus sudoers drop-in.
#
# SAFETY: this runs in EVERY teardown path, UNCONDITIONALLY — it is NOT gated
# behind --purge. The drop-in is only a coarse per-command allowlist; the real
# gate is pam_serberus (via sudo_local) + the daemon. So removal ORDER matters:
# callers MUST remove the drop-in BEFORE they unwire sudo_local / delete the
# module. Tearing the fine gate down first would, for the window until the
# drop-in is gone (or forever, if a later teardown step aborts), leave standard
# users able to sudo the curated command paths with NO fine enforcement — the
# exact fail-OPEN this feature must never produce.
#
#   $1 optional drop-in path (defaults to SERBERUS_SUDOERS_PATH; tests pass a
#      fixture path).
#
# Touches ONLY that one exact path: `rm -f` on the literal path — never a glob,
# never `-r`, never a directory. It never runs visudo (deleting a whole file
# cannot introduce a sudoers syntax error, so there is nothing to validate) and
# never touches any other /etc/sudoers.d entry or the main sudoers file.
#
# Marker-guarded: the file is deleted only when one of its lines matches
# SERBERUS_SUDOERS_MARKER_RE (the generator writes that header as the first
# line; the match accepts it on any line), so a hand-authored admin file
# sitting at the same path is PRESERVED. Any doubt fails SAFE toward
# preservation.
#
# Prints exactly one of:
#   absent  — no file at the path; nothing to do
#   foreign — a file exists but carries no Serberus marker; left byte-identical
#   removed — Serberus-marked drop-in deleted
#   FAILED  — the drop-in is STILL there after the rm (immutable flag, a
#             root agent re-creating it, …); status 1. Callers use $(...),
#             where set -e does not apply, so they must test the status or
#             the output and STOP before unwiring sudo_local: tearing the PAM
#             gate down under a surviving drop-in is the fail-open.
serberus_pam_remove_sudoers_dropin() {
    local dropin="${1:-${SERBERUS_SUDOERS_PATH}}"

    if [[ ! -e "${dropin}" ]]
    then
        printf 'absent'
        return 0
    fi

    if ! "${PAM_LIB_GREP}" -Eq "${SERBERUS_SUDOERS_MARKER_RE}" "${dropin}"
    then
        printf 'foreign'
        return 0
    fi

    "${PAM_LIB_RM}" -f "${dropin}" 2>/dev/null || true
    if [[ -e "${dropin}" || -L "${dropin}" ]]
    then
        printf 'FAILED'
        return 1
    fi
    printf 'removed'
}

########################################
######## Break-glass preflight #########
########################################

# Every reader below consults ONLY the managed (MDM-delivered) config plist,
# exactly like Sources/pam_serberus/pam_config.c and the daemon. There is no
# fallback layer: a value in root's own preferences (`defaults write`) is
# ignored at sudo time, so it must not satisfy this preflight either.
#
# Effective enforcementMode: a mistyped or unknown value fails closed to
# "enforce".
#   $1 managed plist path (/Library/Managed Preferences/…config.plist live)
# Prints exactly one of: enforce | audit | monitor (absent/invalid ⇒ enforce).
serberus_pam_effective_mode() {
    local managed="$1"
    local plist
    local mode

    for plist in "${managed}"
    do
        [[ -f "${plist}" ]] || continue
        if "${PAM_LIB_PLUTIL}" -type enforcementMode "${plist}" >/dev/null 2>&1
        then
            # Key present in this layer — authoritative, stop falling through.
            if [[ "$("${PAM_LIB_PLUTIL}" -type enforcementMode "${plist}" 2>/dev/null)" == "string" ]]
            then
                mode=$("${PAM_LIB_PLUTIL}" -extract enforcementMode raw -o - "${plist}" 2>/dev/null) || mode=""
                case "${mode}" in
                    enforce|audit|monitor)
                        printf '%s' "${mode}"
                        return 0
                        ;;
                esac
            fi
            printf 'enforce'
            return 0
        fi
    done

    printf 'enforce'
}

# True when the config source has DELIVERED anything at all, mirroring
# pam_config.c's serberus_config_is_present (and PrivMgrCore
# ManagedPreferencesReader.configIsPresent): the managed plist FILE exists and
# carries at least one of the known config keys. An ABSENT config
# (no delivered key anywhere) must be distinguishable from a PRESENT config
# whose every value happens to equal the fail-safe defaults — that distinction
# is what lets the preinstall abort ONLY on the genuine brick (present, enforce,
# no resolvable break-glass, no last-known-good) rather than on the survivable
# enrollment-race / awaiting-config case.
#   $1 managed plist path
# Returns 0 (present) or 1 (absent).
serberus_pam_config_present() {
    local managed="$1"
    local plist
    local key
    for plist in "${managed}"
    do
        [[ -f "${plist}" ]] || continue
        for key in daemonEnabled enforcementMode sudoCacheSeconds \
            promptTimeoutSeconds pamBypass sudoEnrollment jamfProURL \
            jamfAPIClientID jamfAPIClientSecret
        do
            if "${PAM_LIB_PLUTIL}" -type "${key}" "${plist}" >/dev/null 2>&1
            then
                return 0
            fi
        done
    done
    return 1
}

# Count of STRING members across pamBypass.users + pamBypass.groups in the
# managed config (non-string members are excluded exactly like pam_config.c filters them —
# they can never match a user or group name). Mistyped pamBypass ⇒ 0.
#   $1 managed plist path
# Prints a non-negative integer.
serberus_pam_bypass_count() {
    local managed="$1"
    local plist

    for plist in "${managed}"
    do
        [[ -f "${plist}" ]] || continue
        if "${PAM_LIB_PLUTIL}" -type pamBypass "${plist}" >/dev/null 2>&1
        then
            if [[ "$("${PAM_LIB_PLUTIL}" -type pamBypass "${plist}" 2>/dev/null)" != "dictionary" ]]
            then
                printf '0'
                return 0
            fi
            local total=0
            local inner
            local count
            local index
            local member_type
            for inner in users groups
            do
                if [[ "$("${PAM_LIB_PLUTIL}" -type "pamBypass.${inner}" "${plist}" 2>/dev/null)" == "array" ]]
                then
                    # `plutil -extract <array> raw` prints the element count.
                    count=$("${PAM_LIB_PLUTIL}" -extract "pamBypass.${inner}" raw -o - "${plist}" 2>/dev/null) || count=0
                    for ((index = 0; index < count; index++))
                    do
                        member_type=$("${PAM_LIB_PLUTIL}" -type "pamBypass.${inner}.${index}" "${plist}" 2>/dev/null) || member_type=""
                        if [[ "${member_type}" == "string" ]]
                        then
                            total=$((total + 1))
                        fi
                    done
                fi
            done
            printf '%s' "${total}"
            return 0
        fi
    done

    printf '0'
}

# The string at <key path> in <plist>, exactly as stored, in
# SERBERUS_PAM_PLIST_STRING (a variable, not stdout: command substitution
# would strip trailing newlines, and names are compared byte for byte).
# `plutil -extract … raw` appends one newline, which is removed; nothing else
# is trimmed. A shell variable cannot hold U+0000, so a value containing one
# is detected (read -d '' stops at it) and reported by status 3, with only
# the part before it kept.
#   $1 key path, $2 plist path
# Returns 0, or 3 when the value contains U+0000.
serberus_pam_plist_string() {
    local keypath="$1"
    local plist="$2"
    local value=""
    SERBERUS_PAM_PLIST_STRING=""
    if IFS= read -r -d '' value \
        < <("${PAM_LIB_PLUTIL}" -extract "${keypath}" raw -o - "${plist}" 2>/dev/null)
    then
        SERBERUS_PAM_PLIST_STRING="${value}"
        return 3
    fi
    SERBERUS_PAM_PLIST_STRING="${value%$'\n'}"
    return 0
}

# Every non-empty STRING member of the managed pamBypass (same per-element
# string filtering as serberus_pam_bypass_count), as NUL-terminated pairs:
# `users` NUL <name> NUL, or `groups` NUL <name> NUL. Names are passed on
# byte for byte — spaces, tabs and newlines included — so the preflight
# looks up exactly what pam_serberus and the daemon look up. A name
# containing U+0000 is emitted with kind `nul-users` / `nul-groups` (and only
# the part before the NUL): the module and the daemon never resolve such an
# entry, and neither does the preflight. Read the output with
# `IFS= read -r -d ''`. Prints nothing when pamBypass is absent or mistyped.
#   $1 managed plist path
serberus_pam_bypass_entries() {
    local managed="$1"
    local plist

    for plist in "${managed}"
    do
        [[ -f "${plist}" ]] || continue
        if "${PAM_LIB_PLUTIL}" -type pamBypass "${plist}" >/dev/null 2>&1
        then
            if [[ "$("${PAM_LIB_PLUTIL}" -type pamBypass "${plist}" 2>/dev/null)" != "dictionary" ]]
            then
                return 0
            fi
            local inner
            local count
            local index
            local member_type
            local kind
            for inner in users groups
            do
                if [[ "$("${PAM_LIB_PLUTIL}" -type "pamBypass.${inner}" "${plist}" 2>/dev/null)" == "array" ]]
                then
                    # `plutil -extract <array> raw` prints the element count.
                    count=$("${PAM_LIB_PLUTIL}" -extract "pamBypass.${inner}" raw -o - "${plist}" 2>/dev/null) || count=0
                    for ((index = 0; index < count; index++))
                    do
                        member_type=$("${PAM_LIB_PLUTIL}" -type "pamBypass.${inner}.${index}" "${plist}" 2>/dev/null) || member_type=""
                        if [[ "${member_type}" == "string" ]]
                        then
                            kind="${inner}"
                            serberus_pam_plist_string "pamBypass.${inner}.${index}" "${plist}" \
                                || kind="nul-${inner}"
                            if [[ -n "${SERBERUS_PAM_PLIST_STRING}" || "${kind}" == nul-* ]]
                            then
                                printf '%s\0%s\0' "${kind}" "${SERBERUS_PAM_PLIST_STRING}"
                            fi
                        fi
                    done
                fi
            done
            return 0
        fi
    done
}

# Resolver hooks — overridable (redefine the function, or point
# PAM_LIB_DSCACHEUTIL / PAM_LIB_DSCL at a mock) so the test harness never
# depends on the accounts of the machine running it.
# True when <name> resolves to a real local/directory user BY NAME.
# pam_serberus compares the pamBypass entries against the LOGIN NAME, so a
# numeric UID ("501") in the list never matches anyone even though
# `id -u 501` succeeds. All-digit entries are therefore rejected outright and
# the lookup is by name only (dscacheutil exits 0 for unknown users but
# prints nothing, so test its output). Directory lookups are case-insensitive
# and accept aliases ("ITAdmin" finds itadmin), but pam_serberus matches the
# exact login name, so the entry counts only when the record's `name:` equals
# it byte for byte.
# Returns 0 (exact match), 1 (no such user) or 2 (found only by case or
# alias; the account's real name is left in SERBERUS_PAM_RESOLVED_NAME).
serberus_pam_user_resolves() {
    local name="$1"
    local record
    local resolved
    SERBERUS_PAM_RESOLVED_NAME=""
    [[ -n "${name}" ]] || return 1
    if [[ "${name}" =~ ^[0-9]+$ ]]
    then
        return 1
    fi
    record=$("${PAM_LIB_DSCACHEUTIL}" -q user -a name "${name}" 2>/dev/null) || record=""
    [[ -n "${record}" ]] || return 1
    resolved=$(printf '%s\n' "${record}" | "${PAM_LIB_AWK}" '
        /^name: / { sub(/^name: /, ""); print; exit }
    ')
    if [[ "${resolved}" == "${name}" ]]
    then
        return 0
    fi
    SERBERUS_PAM_RESOLVED_NAME="${resolved}"
    return 2
}

# True when <uuid> is a GeneratedUID that names an existing account — what
# pam_config.c and the daemon decide with mbr_uuid_to_id + getpwuid_r:
# - a compatibility UUID FFFFEEEE-DDDD-CCCC-BBBB-AAAA<8 hex> stands for that
#   uid, which must resolve (`dscacheutil -q user -a uid`);
# - any other UUID must be the GeneratedUID of a user record on the search
#   path (`dscl /Search -search /Users GeneratedUID`). A group's UUID never
#   is, so it does not count.
# Overridable for tests.
# Returns 0 (names an account) or 1.
serberus_pam_generated_uid_resolves() {
    local uuid
    local uid
    uuid=$(printf '%s' "$1" | "${PAM_LIB_AWK}" '{ print toupper($0) }')
    if [[ "${uuid}" =~ ^FFFFEEEE-DDDD-CCCC-BBBB-AAAA([0-9A-F]{8})$ ]]
    then
        uid=$((16#${BASH_REMATCH[1]}))
        [[ -n "$("${PAM_LIB_DSCACHEUTIL}" -q user -a uid "${uid}" 2>/dev/null)" ]]
        return
    fi
    [[ "${uuid}" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]] || return 1
    [[ -n "$("${PAM_LIB_DSCL}" /Search -search /Users GeneratedUID "${uuid}" 2>/dev/null)" ]]
}

# True when a GroupMembers GeneratedUID of the group record <name> (its
# canonical name: `dscl` paths are case-sensitive) names an existing account
# (serberus_pam_generated_uid_resolves). `dscacheutil` shows only the
# GroupMembership names, and some tools record a member by GeneratedUID alone.
# Overridable for tests.
# Returns 0 (such a member exists) or 1.
serberus_pam_group_generated_uid_member() {
    local group="$1"
    local uuid
    [[ -n "${group}" && "${group}" != */* ]] || return 1
    while IFS= read -r uuid
    do
        if serberus_pam_generated_uid_resolves "${uuid}"
        then
            return 0
        fi
    done < <("${PAM_LIB_DSCL}" /Search -read "/Groups/${group}" GroupMembers 2>/dev/null \
        | "${PAM_LIB_AWK}" '
            /^GroupMembers:/ { on = 1; sub(/^GroupMembers:/, "") }
            /^[^ \t]/ { on = 0 }
            on { for (i = 1; i <= NF; i++) print $i }
        ')
    return 1
}

# True when <name> resolves to a real local/directory group that has at least
# one member that is an existing account:
# - a name on its `users:` line (the group's gr_mem) that is exactly an
#   account's name (serberus_pam_user_resolves returns 0) — a deleted
#   account's name left behind in the group does not count;
# - a GroupMembers GeneratedUID that names an account
#   (serberus_pam_group_generated_uid_member);
# - an account the directory search policy lists (`dscl /Search`, the set
#   getpwent enumerates) whose primary group it is. A gid dscacheutil prints
#   as negative (above INT32_MAX: nobody, nogroup) never matches.
# Nested groups do not count. This is the definition pam_config.c
# (serberus_config_group_has_members) and the daemon
# (LocalAccounts.groupHasMembers) use; keep the three identical.
# dscacheutil exits 0 even for unknown groups but prints nothing, so test its
# output. An existing but EMPTY group (created by a prestage before anyone is
# added to it) bypasses nobody.
# Returns 0 (has members), 1 (no such group) or 2 (exists, no members).
serberus_pam_group_resolves() {
    local name="$1"
    local record
    local canonical
    local members
    local member
    local gid
    local -a listed=()
    [[ -n "${name}" ]] || return 1
    record=$("${PAM_LIB_DSCACHEUTIL}" -q group -a name "${name}" 2>/dev/null) || record=""
    [[ -n "${record}" ]] || return 1
    canonical=$(printf '%s\n' "${record}" | "${PAM_LIB_AWK}" '
        /^name: / { sub(/^name: /, ""); print; exit }
    ')
    members=$(printf '%s\n' "${record}" | "${PAM_LIB_AWK}" '
        /^users:/ { sub(/^users:[[:space:]]*/, ""); print; exit }
    ')
    read -r -a listed <<< "${members}"
    for member in ${listed[@]+"${listed[@]}"}
    do
        if serberus_pam_user_resolves "${member}"
        then
            return 0
        fi
    done
    if serberus_pam_group_generated_uid_member "${canonical:-${name}}"
    then
        return 0
    fi
    gid=$(printf '%s\n' "${record}" | "${PAM_LIB_AWK}" '/^gid: / { print $2; exit }')
    if [[ "${gid}" =~ ^[0-9]+$ ]] \
        && "${PAM_LIB_DSCL}" /Search -list /Users PrimaryGroupID 2>/dev/null \
            | "${PAM_LIB_AWK}" -v gid="${gid}" '$2 == gid { found = 1 } END { exit !found }'
    then
        return 0
    fi
    return 2
}

# Count of effective pamBypass entries that RESOLVE to a real user or group.
# A typo'd entry ("brekglass") is worthless at sudo time — pam_serberus can
# never match it — so only resolvable entries count toward break-glass.
# Each unresolvable entry is reported on STDERR (one line each) so callers
# can route them into their own logging; the count goes to STDOUT.
#   $1 managed plist path
# Prints a non-negative integer.
serberus_pam_resolvable_bypass_count() {
    local managed="$1"
    local resolvable=0
    local kind
    local name
    local status

    # NUL-separated pairs: names are compared byte for byte, never trimmed
    # or split, exactly as pam_serberus and the daemon compare them.
    while IFS= read -r -d '' kind && IFS= read -r -d '' name
    do
        [[ -n "${kind}" ]] || continue
        case "${kind}" in
            nul-users|nul-groups)
                printf 'pamBypass %s entry "%s…" contains a NUL character — provides NO break-glass\n' \
                    "${kind#nul-}" "${name}" >&2
                ;;
            users)
                status=0
                serberus_pam_user_resolves "${name}" || status=$?
                case "${status}" in
                    0)
                        resolvable=$((resolvable + 1))
                        ;;
                    2)
                        printf 'pamBypass user "%s" matches account "%s" only by case or alias; sudo compares the exact login name — provides NO break-glass\n' \
                            "${name}" "${SERBERUS_PAM_RESOLVED_NAME:-?}" >&2
                        ;;
                    *)
                        printf 'pamBypass user "%s" does not resolve to a real account — provides NO break-glass\n' "${name}" >&2
                        ;;
                esac
                ;;
            groups)
                status=0
                serberus_pam_group_resolves "${name}" || status=$?
                case "${status}" in
                    0)
                        resolvable=$((resolvable + 1))
                        ;;
                    2)
                        printf 'pamBypass group "%s" exists but has no members that are existing accounts — provides NO break-glass\n' "${name}" >&2
                        ;;
                    *)
                        printf 'pamBypass group "%s" does not resolve to a real group — provides NO break-glass\n' "${name}" >&2
                        ;;
                esac
                ;;
        esac
    done < <(serberus_pam_bypass_entries "${managed}")

    printf '%s' "${resolvable}"
}

# Break-glass preflight: is it SAFE to wire pam_serberus.so into sudo with
# the effective config? pam_serberus FAILS CLOSED — in enforce mode every
# sudo not explicitly allowed by a rule denies, and daemon-unreachable is a
# hard deny — so the only safe installs are pass-through modes or a bypass
# list with at least one entry that RESOLVES to a real user/group (a
# populated-but-typo'd list provides zero bypass). Absent config means
# enforce + no bypass = sudo bricked for everyone: FAIL.
#   $1 managed plist path
# Returns 0 (safe) or 1 (would brick sudo — caller must ABORT the install
# and must NOT modify any sudo configuration). Unresolvable entries are
# reported on stderr via serberus_pam_resolvable_bypass_count.
serberus_pam_preflight_break_glass() {
    local managed="$1"
    local mode

    mode=$(serberus_pam_effective_mode "${managed}")
    if [[ "${mode}" == "monitor" || "${mode}" == "audit" ]]
    then
        return 0
    fi

    if [[ "$(serberus_pam_resolvable_bypass_count "${managed}")" -gt 0 ]]
    then
        return 0
    fi

    return 1
}

########################################
###### Module path-chain safety ########
########################################

# Ownership/mode hook — prints "<uid> <octal permission bits>" for a path
# WITHOUT following a final symlink. Overridable so tests can model a
# root-owned tree without being root.
serberus_pam_path_owner_mode() {
    "${PAM_LIB_STAT}" -f '%u %Lp' "$1" 2>/dev/null
}

# Directory-creation hook (root:wheel 0755). Overridable for tests, which
# cannot chown to root.
serberus_pam_make_root_dir() {
    "${PAM_LIB_MKDIR}" -m 755 "$1" \
        && "${PAM_LIB_CHOWN}" root:wheel "$1" \
        && "${PAM_LIB_CHMOD}" 755 "$1"
}

# ACL hook — prints `ls -led` of <path> (the mode line, then one line per
# extended ACL entry; never follows a final symlink). Overridable for tests.
serberus_pam_path_acl_listing() {
    "${PAM_LIB_LS}" -led -- "$1" 2>/dev/null
}

# True when an ALLOW entry of <path>'s extended ACL grants write to anyone
# but user:root — another user, or any group (the mode check allows no group
# write either). Write is any of write, append, add_file, add_subdirectory,
# delete, delete_child, writesecurity or chown, the same set the daemon's
# PAMGateACL refuses. DENY entries grant nothing; inherited and inherit-only
# entries count. A path that does not exist has no ACL; an ACL that cannot be
# read counts as granting write. The offending entry is printed on stdout.
# ls prints an entry as " N: <principal>[ inherited] <allow|deny> <perms>",
# with the principal's name as is, spaces included ("group:CORP\Domain
# Users"), so each entry is read from the right: the perms, the action, an
# optional "inherited", and the principal is what is left. Fields are split
# on single spaces, as ls writes them, so the principal compares exactly.
# Any other line after the mode line counts as granting write.
#   $1 path
serberus_pam_path_acl_grants_write() {
    local path="$1"
    if [[ ! -e "${path}" && ! -L "${path}" ]]
    then
        return 1
    fi
    local listing
    if ! listing=$(serberus_pam_path_acl_listing "${path}") || [[ -z "${listing}" ]]
    then
        printf 'unreadable ACL'
        return 0
    fi
    "${PAM_LIB_AWK}" -F '[ ]' '
        NR == 1 { next }
        {
            # Well formed: "" (the leading space), "N:", the principal (one
            # field or more), the action, the perms. NF >= 5 also keeps
            # $(NF - 1) in range: a bad field index would kill awk, and
            # its exit status would read as "no write".
            grants = 1
            if (NF >= 5 && $1 == "" && $2 ~ /^[0-9]+:$/ && ($(NF - 1) == "allow" || $(NF - 1) == "deny")) {
                action = $(NF - 1)
                perms = $NF
                last = NF - 2
                if (last > 3 && $last == "inherited") last--
                who = $3
                for (k = 4; k <= last; k++) who = who " " $k
                if (action != "allow" || who == "user:root") next
                grants = 0
                n = split(perms, p, ",")
                for (k = 1; k <= n; k++) {
                    if (p[k] ~ /^(write|append|add_file|add_subdirectory|delete|delete_child|writesecurity|chown)$/) grants = 1
                }
            }
            if (grants) {
                sub(/^[ \t]+/, "")
                print
                found = 1
                exit
            }
        }
        END { exit found ? 0 : 1 }
    ' <<< "${listing}"
}

# One component of the chain: owned by uid 0, not group/other-writable, and
# no extended ACL entry lets anyone but root write it.
# $1 path, $2 human kind ("directory" / "module"). Reasons go to stderr.
serberus_pam_path_is_root_locked() {
    local path="$1"
    local kind="$2"
    local info
    local uid
    local mode
    if ! info=$(serberus_pam_path_owner_mode "${path}") || [[ -z "${info}" ]]
    then
        printf 'cannot stat %s %s\n' "${kind}" "${path}" >&2
        return 1
    fi
    read -r uid mode <<< "${info}"
    if [[ ! "${uid}" =~ ^[0-9]+$ || ! "${mode}" =~ ^[0-7]+$ ]]
    then
        printf 'unreadable owner/mode for %s %s (%s)\n' "${kind}" "${path}" "${info}" >&2
        return 1
    fi
    if [[ "${uid}" != "0" ]]
    then
        printf '%s %s is owned by uid %s, not root — that user could replace the module sudo loads\n' \
            "${kind}" "${path}" "${uid}" >&2
        return 1
    fi
    if (( (8#${mode}) & 8#022 ))
    then
        printf '%s %s is group- or other-writable (mode %s) — anyone in that group could replace the module sudo loads\n' \
            "${kind}" "${path}" "${mode}" >&2
        return 1
    fi
    local entry
    if entry=$(serberus_pam_path_acl_grants_write "${path}")
    then
        printf '%s %s has an ACL entry that lets someone other than root write it (%s)\n' \
            "${kind}" "${path}" "${entry}" >&2
        return 1
    fi
    return 0
}

# Is it safe to reference <module> from sudo_local? sudo dlopens the module as
# root on every authentication, so EVERY directory from the top of the chain
# down to the module — and the module itself — must be owned by root, not
# group- or other-writable, and not a symlink; otherwise whoever controls a
# weak link can swap in their own code and own sudo. The chain is derived from
# the module path itself: /usr/local/lib/pam/pam_serberus.so checks /usr,
# /usr/local, /usr/local/lib, /usr/local/lib/pam and the module.
# A MISSING directory in the chain is created root:wheel 0755 (only after
# everything above it passed). An Intel Homebrew layout (user-owned
# /usr/local/lib) fails here — wiring must be refused, not "fixed", because
# chowning Homebrew's tree back to root is the admin's decision.
#   $1 absolute module path
#   $2 optional root prefix (tests): components at or above it are not
#      checked, so a fixture tree under a temp dir can be used.
# Returns 0 (safe) or 1 (refuse to wire); reasons are printed on stderr.
serberus_pam_module_path_is_safe() {
    local module="$1"
    local root="${2:-}"

    serberus_pam_module_dir_is_safe "${module}" "${root}" || return 1

    if [[ -L "${module}" ]]
    then
        printf 'module %s is a symlink — refusing\n' "${module}" >&2
        return 1
    fi
    if [[ ! -f "${module}" ]]
    then
        printf 'module %s is missing or not a regular file\n' "${module}" >&2
        return 1
    fi
    serberus_pam_path_is_root_locked "${module}" "module"
}

# The DIRECTORY half of serberus_pam_module_path_is_safe: every directory from
# the top of the chain down to the module's parent is root-owned, not
# group/other-writable and not a symlink (missing ones are created root:wheel
# 0755). Installers run this BEFORE they chown/chmod the module, so a
# user-controlled directory is refused instead of having root operate inside
# it. The module itself is not inspected.
#   $1 absolute module path, $2 optional root prefix (tests)
# Returns 0 (safe) or 1; reasons on stderr.
serberus_pam_module_dir_is_safe() {
    local module="$1"
    local root="${2:-}"
    root="${root%/}"

    if [[ "${module}" != /* ]]
    then
        printf 'module path %s is not absolute\n' "${module}" >&2
        return 1
    fi
    if [[ -n "${root}" && "${module}" != "${root}/"* ]]
    then
        printf 'module path %s is not under %s\n' "${module}" "${root}" >&2
        return 1
    fi

    local rel="${module#"${root}"}"
    rel="${rel#/}"
    local -a parts=()
    IFS='/' read -r -a parts <<< "${rel}"
    local count="${#parts[@]}"
    if [[ "${count}" -lt 2 ]]
    then
        printf 'module path %s has no parent directory to check\n' "${module}" >&2
        return 1
    fi

    local dir="${root}"
    local index
    local part
    for ((index = 0; index < count - 1; index++))
    do
        part="${parts[index]}"
        if [[ -z "${part}" || "${part}" == "." || "${part}" == ".." ]]
        then
            printf 'module path %s has an empty or relative component\n' "${module}" >&2
            return 1
        fi
        dir="${dir}/${part}"
        if [[ -L "${dir}" ]]
        then
            printf 'directory %s is a symlink — refusing (its target is not what sudo_local names)\n' "${dir}" >&2
            return 1
        fi
        if [[ ! -e "${dir}" ]]
        then
            if ! serberus_pam_make_root_dir "${dir}"
            then
                printf 'could not create %s root:wheel 0755\n' "${dir}" >&2
                return 1
            fi
        fi
        if [[ ! -d "${dir}" ]]
        then
            printf '%s exists but is not a directory\n' "${dir}" >&2
            return 1
        fi
        if ! serberus_pam_path_is_root_locked "${dir}" "directory"
        then
            printf 'fix: sudo chown root:wheel "%s" && sudo chmod go-w "%s" (on Intel Macs Homebrew owns /usr/local subdirectories — decide how to reconcile that before wiring Serberus)\n' \
                "${dir}" "${dir}" >&2
            return 1
        fi
    done
    return 0
}

# Removes a stray "<module>.2" (SERBERUS_PAM_MODULE_VERSIONED_PATH), which
# OpenPAM would load in place of the module. `rm -f` on the exact path never
# follows a symlink. Prints absent / removed / FAILED (status 1: still there).
#   $1 optional path (default SERBERUS_PAM_MODULE_VERSIONED_PATH)
serberus_pam_remove_versioned_module() {
    local path="${1:-${SERBERUS_PAM_MODULE_VERSIONED_PATH}}"
    if [[ ! -e "${path}" && ! -L "${path}" ]]
    then
        printf 'absent'
        return 0
    fi
    if [[ -d "${path}" && ! -L "${path}" ]]
    then
        printf 'FAILED'
        return 1
    fi
    "${PAM_LIB_RM}" -f "${path}" 2>/dev/null || true
    if [[ -e "${path}" || -L "${path}" ]]
    then
        printf 'FAILED'
        return 1
    fi
    printf 'removed'
}

# Lock the module down AFTER serberus_pam_module_dir_is_safe passed: refuse a
# symlink, then root:wheel 0444 on the path ITSELF (-h: never follow a link
# that appeared in between). Returns 1 (reason on stderr) when it cannot.
#   $1 absolute module path
serberus_pam_lock_module() {
    local module="$1"
    if [[ -L "${module}" ]]
    then
        printf 'module %s is a symlink — refusing to chown/chmod through it\n' "${module}" >&2
        return 1
    fi
    if [[ ! -f "${module}" ]]
    then
        printf 'module %s is missing or not a regular file\n' "${module}" >&2
        return 1
    fi
    "${PAM_LIB_CHOWN}" -h root:wheel "${module}" \
        && "${PAM_LIB_CHMOD}" -h 444 "${module}"
}

########################################
####### Code-signature team checks #####
########################################

# Prints the TeamIdentifier a signed path carries (10 uppercase letters or
# digits) and returns 0; returns 1 for ad-hoc/unsigned code ("not set") or
# anything unreadable. codesign -dv reports on STDERR, so both streams are
# captured before parsing (no pipe into an early-exiting reader).
#   $1 path (bundle or Mach-O)
serberus_codesign_team_id() {
    local info
    local team
    info=$("${PAM_LIB_CODESIGN}" -dv "$1" 2>&1) || return 1
    team=$("${PAM_LIB_AWK}" -F= '/^TeamIdentifier=/ { print $2; exit }' <<< "${info}")
    [[ "${team}" =~ ^[A-Z0-9]{10}$ ]] || return 1
    printf '%s' "${team}"
}

# True when <path> has a valid strict signature from an Apple-issued
# certificate whose leaf carries <team> — i.e. it was signed by the SAME
# team as the daemon, not merely by someone.
#   $1 path, $2 team identifier
serberus_codesign_satisfies_team() {
    local path="$1"
    local team="$2"
    [[ "${team}" =~ ^[A-Z0-9]{10}$ ]] || return 1
    "${PAM_LIB_CODESIGN}" --verify --strict \
        -R "=anchor apple generic and certificate leaf[subject.OU] = \"${team}\"" \
        "${path}" >/dev/null 2>&1
}

# True when <path> is a serberusd that root may EXECUTE (--demote-jit,
# --restore-authdb, --remove-sudoers): a strict, valid signature from an
# Apple-issued certificate, the identifier com.herojoneslabs.serberus.daemon
# and the pinned team. The team is <team> when given (the install's recorded
# installTeamID), otherwise the team the installed PAM module carries. With
# neither, the binary is refused: the team of the binary about to run proves
# nothing about who built it. An ad-hoc, unsigned, re-identified, tampered or
# foreign-team binary fails; an empty or malformed team never matches.
# Callers that get 1 must NOT run the binary and should print
# serberus_daemon_manual_steps instead.
#   $1 daemon path (the bundle or its executable), $2 optional team
# Returns 0 (trusted) or 1 (reason on stderr).
serberus_daemon_trusted() {
    local path="$1"
    local team="${2:-}"
    if [[ -z "${path}" || -L "${path}" ]] || [[ ! -f "${path}" && ! -d "${path}" ]]
    then
        printf 'daemon %s is missing or a symlink — not executing it\n' "${path:-<none>}" >&2
        return 1
    fi
    if [[ -z "${team}" && -f "${SERBERUS_PAM_MODULE_PATH}" && ! -L "${SERBERUS_PAM_MODULE_PATH}" ]]
    then
        team=$(serberus_codesign_team_id "${SERBERUS_PAM_MODULE_PATH}" 2>/dev/null) \
            || team=""
    fi
    if [[ ! "${team}" =~ ^[A-Z0-9]{10}$ ]]
    then
        printf 'no Team ID to pin %s to (no installTeamID recorded, no signed PAM module installed) — not executing it\n' "${path}" >&2
        return 1
    fi
    if ! "${PAM_LIB_CODESIGN}" --verify --strict \
        -R "=anchor apple generic and identifier \"${SERBERUS_DAEMON_IDENTIFIER}\" and certificate leaf[subject.OU] = \"${team}\"" \
        "${path}" >/dev/null 2>&1
    then
        printf '%s is not a valid %s signed by team %s — not executing it\n' \
            "${path}" "${SERBERUS_DAEMON_IDENTIFIER}" "${team}" >&2
        return 1
    fi
    return 0
}

# Prints the Team ID the last install recorded in version.plist
# (installTeamID) and returns 0. Returns 1, printing nothing, when the file is
# missing, a symlink, not root-owned, group/other-writable, or carries no
# well-formed team; callers then pass nothing to serberus_daemon_trusted,
# which falls back to the installed module's team, or refuses the daemon.
#   $1 optional version.plist path (default SERBERUS_VERSION_PLIST)
serberus_recorded_team() {
    local plist="${1:-${SERBERUS_VERSION_PLIST}}"
    local team
    [[ -f "${plist}" && ! -L "${plist}" ]] || return 1
    serberus_pam_path_is_root_locked "${plist}" "version file" 2>/dev/null || return 1
    team=$("${PAM_LIB_PLUTIL}" -extract "${SERBERUS_INSTALL_TEAM_KEY}" raw -o - "${plist}" 2>/dev/null) \
        || return 1
    [[ "${team}" =~ ^[A-Z0-9]{10}$ ]] || return 1
    printf '%s' "${team}"
}

# The by-hand fallback when the daemon may not be executed: one instruction
# per line on stdout, for the caller to route into its own log.
#   $1 demote | restore | sudoers, $2 optional authdb-backups directory
serberus_daemon_manual_steps() {
    local what="$1"
    local backups="${2:-/Library/Application Support/Serberus/authdb-backups}"
    case "${what}" in
        demote)
            printf '%s\n' \
                "!!! JIT-granted users may STILL be local admins. Check the admin group:" \
                "!!!   dscl . -read /Groups/admin GroupMembership" \
                "!!! and remove each JIT-granted user by hand:" \
                "!!!   sudo dseditgroup -o edit -d <user> -t user admin"
            ;;
        restore)
            printf '%s\n' \
                "!!! Restore each right Serberus changed by hand from ${backups}/<right>.json:" \
                "!!!   sudo security authorizationdb write <right> < ${backups}/<right>.json"
            ;;
        sudoers)
            printf '%s\n' \
                "!!! Remove the Serberus sudoers drop-in by hand:" \
                "!!!   sudo rm -f ${SERBERUS_SUDOERS_PATH}"
            ;;
    esac
}

########################################
######## launchd job liveness ##########
########################################

# True when system/<label> is loaded AND has a live process. `launchctl
# print` succeeding only proves the job is LOADED: a daemon AMFI kills at
# every spawn (or that crashes on start) stays loaded in a KeepAlive respawn
# loop and never serves a request, so "loaded" is not "up". Requires the
# job's own top-level `state = running` and `pid = N` lines (nested
# endpoint sections are indented further and are not matched).
#   $1 launchd label
serberus_launchd_job_running() {
    serberus_launchd_job_pid "$1" >/dev/null
}

# Prints the pid of system/<label> when the job is loaded AND running (its own
# top-level `state = running` and `pid = N` lines); returns 1 otherwise.
#   $1 launchd label
serberus_launchd_job_pid() {
    local out
    out=$("${PAM_LIB_LAUNCHCTL}" print "system/$1" 2>/dev/null) || return 1
    serberus_launchd_pid_from_output "${out}"
}

# The pid in one `launchctl print` capture when the job's own top-level lines
# say `state = running` and `pid = N`; returns 1 otherwise.
#   $1 launchctl print output
serberus_launchd_pid_from_output() {
    "${PAM_LIB_GREP}" -Eq $'^\tstate = running$' <<< "$1" || return 1
    local pid
    pid=$("${PAM_LIB_AWK}" -F' = ' $'/^\tpid = [0-9]+$/ { print $2; exit }' <<< "$1")
    [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "${pid}"
}

# Prints the value of one of the job's OWN top-level `<field> = <value>` lines
# from a `launchctl print system/<label>` capture (nested sections are indented
# further and never match). Prints nothing when the field is absent.
#   $1 launchctl print output, $2 field name (e.g. runs, "last exit code")
serberus_launchd_job_field() {
    "${PAM_LIB_AWK}" -v key="$2" '
        index($0, "\t" key " = ") == 1 { print substr($0, length(key) + 5); exit }
    ' <<< "$1"
}

# Waits until system/<label> is no longer loaded after a `launchctl bootout`.
# bootout can return while the job is still being torn down, and a daemon
# one-shot (--demote-jit, --restore-authdb) must not run beside a live daemon
# that still holds the grant store. Polls `launchctl print` once a second.
#   $1 launchd label, $2 optional timeout in seconds (default
#   SERBERUS_DAEMON_BOOTOUT_WAIT, the daemon's ExitTimeOut plus 5 s)
# Returns 0 once the job is gone; 1 (reason on stderr) when it is still loaded
# after the timeout — callers must then skip the one-shots and print the
# manual steps.
serberus_launchd_wait_gone() {
    local label="$1"
    local timeout="${2:-${SERBERUS_DAEMON_BOOTOUT_WAIT}}"
    local waited=0
    while "${PAM_LIB_LAUNCHCTL}" print "system/${label}" >/dev/null 2>&1
    do
        if [[ "${waited}" -ge "${timeout}" ]]
        then
            printf 'system/%s is still loaded %ss after its bootout\n' "${label}" "${timeout}" >&2
            return 1
        fi
        "${PAM_LIB_SLEEP}" 1
        waited=$((waited + 1))
    done
    return 0
}

# Epoch seconds to take IMMEDIATELY before `launchctl bootstrap`; pass it to
# serberus_launchd_wait_running so only a state the NEW daemon wrote counts.
serberus_launchd_bootstrap_mark() {
    "${PAM_LIB_DATE}" -u +%s
}

# True when <state_plist> holds a state the daemon wrote at or after <since>
# (epoch seconds): a readable `state` that is not `unknown`, and an ISO 8601
# `updatedAt` (DaemonStateController writes both) no older than the mark. A
# state.plist left by the PREVIOUS daemon, or none at all, fails. Every real
# state passes, degraded(pam_not_wired) included — that one is expected until
# sudo_local is wired. Reason on stderr.
#   $1 state.plist path, $2 epoch seconds (serberus_launchd_bootstrap_mark)
serberus_daemon_state_fresh() {
    local plist="$1"
    local since="$2"
    if [[ ! -f "${plist}" || -L "${plist}" ]]
    then
        printf '%s is missing — the daemon has not written a state yet\n' "${plist}" >&2
        return 1
    fi
    local state
    state=$("${PAM_LIB_PLUTIL}" -extract state raw -o - "${plist}" 2>/dev/null) || state=""
    if [[ -z "${state}" || "${state}" == "unknown" ]]
    then
        printf '%s has no usable state (%s)\n' "${plist}" "${state:-missing}" >&2
        return 1
    fi
    local updated
    updated=$("${PAM_LIB_PLUTIL}" -extract updatedAt raw -o - "${plist}" 2>/dev/null) || updated=""
    # 2026-09-25T10:11:12.345Z -> 2026-09-25T10:11:12 (UTC)
    local stamp="${updated%%.*}"
    stamp="${stamp%Z}"
    local epoch
    if [[ ! "${stamp}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] \
        || ! epoch=$("${PAM_LIB_DATE}" -j -u -f '%Y-%m-%dT%H:%M:%S' "${stamp}" +%s 2>/dev/null)
    then
        printf '%s has no readable updatedAt (%s)\n' "${plist}" "${updated:-missing}" >&2
        return 1
    fi
    if [[ ! "${since}" =~ ^[0-9]+$ ]] || (( epoch < since ))
    then
        printf '%s was last written at %s, before this bootstrap — a state left by the previous daemon does not count\n' \
            "${plist}" "${updated}" >&2
        return 1
    fi
    return 0
}

# Seconds a pid must stay the same before the job counts as up. Longer than
# the LaunchDaemon's ThrottleInterval (5 s), so a daemon that dies a few
# seconds after starting is seen restarting inside the window.
SERBERUS_LAUNCHD_STABLE_SECONDS=8

# The pid serberus_launchd_wait_running accepted; serberus_launchd_pid_unchanged
# compares against it right before sudo_local is merged.
SERBERUS_LAUNCHD_UP_PID=""

# Waits up to <timeout> seconds (default 10; the stability window is added on
# top) for system/<label> to be RUNNING WITH THE SAME PID for
# SERBERUS_LAUNCHD_STABLE_SECONDS consecutive one-second polls. A job in a
# crash / AMFI-kill respawn loop shows `state = running` for a moment at
# every spawn, so a single "running" poll proves nothing; a changing pid
# restarts the window. launchd's own counters are checked on every poll
# (serberus_launchd_counters_ok): when `runs` advances past the value first
# seen, or a new non-zero `last exit code` / `last terminating signal` is
# recorded, the daemon restarted — refused, not retried. Afterwards, with
# <state_plist> and <since>, the daemon must have written a fresh state
# (serberus_daemon_state_fresh), and with <cli>, `<cli> status` must succeed
# (serberus_cli_health_ok); a <cli> that is given but missing FAILS (the
# packages that pass one ship it). Finally the pid and counters are re-read.
#   $1 launchd label, $2 optional timeout seconds,
#   $3 optional serberus CLI path, $4 optional team the CLI must be signed by,
#   $5 optional state.plist path, $6 optional bootstrap mark (epoch seconds,
#   serberus_launchd_bootstrap_mark),
#   $7 optional 1|0 (default 1 when $6 is given): the job record is fresh
#   since that bootstrap, so ANY recorded non-zero exit or terminating signal
#   refuses — pass 0 when the caller itself restarted the job (kickstart -k)
# Returns 0 when up (SERBERUS_LAUNCHD_UP_PID set), 1 otherwise (reason on
# stderr).
serberus_launchd_wait_running() {
    local label="$1"
    local timeout="${2:-10}"
    local cli="${3:-}"
    local team="${4:-}"
    local state_plist="${5:-}"
    local since="${6:-}"
    local fresh_job="${7:-}"
    if [[ -z "${fresh_job}" ]]
    then
        if [[ -n "${since}" ]]
        then
            fresh_job=1
        else
            fresh_job=0
        fi
    fi
    local budget=$((timeout + SERBERUS_LAUNCHD_STABLE_SECONDS))
    local attempt
    local out
    local pid
    local have_base=0
    local base_runs=""
    local base_exit=""
    local base_signal=""
    local stable_pid=""
    local stable_count=0
    local up=1
    SERBERUS_LAUNCHD_UP_PID=""
    for ((attempt = 0; attempt <= budget; attempt++))
    do
        out=$("${PAM_LIB_LAUNCHCTL}" print "system/${label}" 2>/dev/null) || out=""
        # The baseline is the first capture with a RUNNING process (before the
        # first spawn launchd may still report runs = 0).
        if [[ "${have_base}" -eq 0 ]] && serberus_launchd_pid_from_output "${out}" >/dev/null
        then
            have_base=1
            base_runs=$(serberus_launchd_job_field "${out}" "runs")
            base_exit=$(serberus_launchd_job_field "${out}" "last exit code")
            base_signal=$(serberus_launchd_job_field "${out}" "last terminating signal")
        fi
        if [[ -n "${out}" ]] && [[ "${have_base}" -eq 1 || "${fresh_job}" -eq 1 ]]
        then
            if ! serberus_launchd_counters_ok "${label}" "${out}" "${base_runs}" \
                "${base_exit}" "${base_signal}" "${fresh_job}"
            then
                return 1
            fi
        fi
        if pid=$(serberus_launchd_pid_from_output "${out}")
        then
            if [[ "${pid}" == "${stable_pid}" ]]
            then
                stable_count=$((stable_count + 1))
            else
                stable_pid="${pid}"
                stable_count=0
            fi
            if [[ "${stable_count}" -ge "${SERBERUS_LAUNCHD_STABLE_SECONDS}" ]]
            then
                up=0
                break
            fi
        else
            stable_pid=""
            stable_count=0
        fi
        "${PAM_LIB_SLEEP}" 1
    done
    if [[ "${up}" -ne 0 ]]
    then
        printf 'system/%s never kept one running pid for %ss within %ss (crash or AMFI kill loop?)\n' \
            "${label}" "${SERBERUS_LAUNCHD_STABLE_SECONDS}" "${budget}" >&2
        return 1
    fi

    if [[ -n "${state_plist}" && -n "${since}" ]]
    then
        local fresh=1
        for ((attempt = 0; attempt < 5; attempt++))
        do
            if serberus_daemon_state_fresh "${state_plist}" "${since}" 2>/dev/null
            then
                fresh=0
                break
            fi
            "${PAM_LIB_SLEEP}" 2
        done
        if [[ "${fresh}" -ne 0 ]]
        then
            serberus_daemon_state_fresh "${state_plist}" "${since}" || true
            return 1
        fi
    fi

    if [[ -n "${cli}" ]]
    then
        if [[ ! -e "${cli}" ]]
        then
            printf 'serberus CLI %s is missing — the health check cannot run\n' "${cli}" >&2
            return 1
        fi
        serberus_cli_health_ok "${cli}" "${team}" || return 1
    fi

    # The checks above took time: the job must still be the same process with
    # the same counters.
    if ! out=$("${PAM_LIB_LAUNCHCTL}" print "system/${label}" 2>/dev/null) \
        || ! serberus_launchd_counters_ok "${label}" "${out}" "${base_runs}" \
            "${base_exit}" "${base_signal}" "${fresh_job}"
    then
        printf 'system/%s is no longer loaded, or restarted during the health checks\n' "${label}" >&2
        return 1
    fi
    if ! pid=$(serberus_launchd_pid_from_output "${out}") || [[ "${pid}" != "${stable_pid}" ]]
    then
        printf 'system/%s pid changed (%s -> %s) during the health checks\n' \
            "${label}" "${stable_pid}" "${pid:-none}" >&2
        return 1
    fi
    SERBERUS_LAUNCHD_UP_PID="${stable_pid}"
    return 0
}

# True when a `last exit code` / `last terminating signal` value records a
# FAILURE: a non-zero numeric exit ("1", "9: Killed"), or any signal.
#   $1 exit-code value, $2 signal value
serberus_launchd_exit_is_failure() {
    local code="$1"
    local signal="$2"
    if [[ -n "${signal}" ]]
    then
        return 0
    fi
    if [[ "${code}" =~ ^([0-9]+) ]] && [[ "${BASH_REMATCH[1]}" -ne 0 ]]
    then
        return 0
    fi
    return 1
}

# launchd's own counters for one `launchctl print` capture, against the first
# capture's values: `runs` must not have advanced, and no NEW failed exit may
# be recorded. With <fresh_job> 1 (the job record dates from this bootstrap)
# ANY recorded failed exit refuses, the first capture's included. Reason on
# stderr.
#   $1 label, $2 launchctl print output, $3 base runs, $4 base last exit code,
#   $5 base last terminating signal, $6 fresh_job 1|0
serberus_launchd_counters_ok() {
    local label="$1"
    local out="$2"
    local base_runs="$3"
    local base_exit="$4"
    local base_signal="$5"
    local fresh_job="$6"
    local runs
    runs=$(serberus_launchd_job_field "${out}" "runs")
    if [[ "${base_runs}" =~ ^[0-9]+$ && "${runs}" =~ ^[0-9]+$ ]] && (( runs > base_runs ))
    then
        printf 'system/%s restarted while waiting (runs %s -> %s)\n' "${label}" "${base_runs}" "${runs}" >&2
        return 1
    fi
    local last_exit
    local signal
    last_exit=$(serberus_launchd_job_field "${out}" "last exit code")
    signal=$(serberus_launchd_job_field "${out}" "last terminating signal")
    if serberus_launchd_exit_is_failure "${last_exit}" "${signal}"
    then
        if [[ "${fresh_job}" -eq 1 ]] \
            || [[ "${last_exit}" != "${base_exit}" || "${signal}" != "${base_signal}" ]]
        then
            printf 'system/%s exited since it was started (last exit code = %s%s)\n' \
                "${label}" "${last_exit:-none}" "${signal:+, last terminating signal = ${signal}}" >&2
            return 1
        fi
    fi
    return 0
}

# True when system/<label> still runs the pid serberus_launchd_wait_running
# accepted (SERBERUS_LAUNCHD_UP_PID). Callers run it IMMEDIATELY before
# merging sudo_local, so a daemon that died after the checks is never wired.
#   $1 launchd label
serberus_launchd_pid_unchanged() {
    local label="$1"
    local pid
    if [[ -z "${SERBERUS_LAUNCHD_UP_PID}" ]]
    then
        printf 'system/%s was never confirmed up\n' "${label}" >&2
        return 1
    fi
    if ! pid=$(serberus_launchd_job_pid "${label}") || [[ "${pid}" != "${SERBERUS_LAUNCHD_UP_PID}" ]]
    then
        printf 'system/%s pid changed (%s -> %s) since it was confirmed up\n' \
            "${label}" "${SERBERUS_LAUNCHD_UP_PID}" "${pid:-none}" >&2
        return 1
    fi
    return 0
}

# True when every directory above <cli> (for /usr/local/bin/serberus:
# /usr/local/bin, /usr/local and /usr) is a real directory, root-owned and not
# group/other-writable. Root runs the CLI as part of the install's "daemon
# up" check, so an install on a Mac whose /usr/local/bin a user owns (Intel
# Homebrew) must stop, and say that this is why. The first directory that
# fails is named on stderr.
#   $1 CLI path
serberus_cli_dir_is_root_only() {
    local cli="$1"
    local dir="${cli%/*}"
    while [[ -n "${dir}" ]]
    do
        if [[ -L "${dir}" ]] || ! serberus_pam_path_is_root_locked "${dir}" "directory" 2>/dev/null
        then
            printf 'not running %s: %s is not a root-only directory (it must be a real directory, owned by root and not group- or other-writable)\n' \
                "${cli}" "${dir}" >&2
            return 1
        fi
        dir="${dir%/*}"
    done
    return 0
}

# Health check through the serberus CLI: `serberus status` exits 0 once the
# daemon has written state.plist (1 = not installed/never started) and flags
# a state older than 15 minutes as STALE. Root EXECUTES this file, and
# /usr/local/bin can be user-owned (Intel Homebrew), so the CLI runs only when
# it and every directory above it are root-owned, not group/other-writable
# and not symlinks — and, when <team> is given, signed by that team.
# Otherwise the check fails (callers treat that as "not up").
#   $1 CLI path, $2 optional team identifier
serberus_cli_health_ok() {
    local cli="$1"
    local team="${2:-}"
    if ! serberus_cli_dir_is_root_only "${cli}"
    then
        return 1
    fi
    if [[ -L "${cli}" || ! -f "${cli}" ]] || ! serberus_pam_path_is_root_locked "${cli}" "CLI"
    then
        printf 'not running %s: not a root-owned, root-only regular file\n' "${cli}" >&2
        return 1
    fi
    if [[ -n "${team}" ]] && ! serberus_codesign_satisfies_team "${cli}" "${team}"
    then
        printf 'not running %s: not signed by team %s\n' "${cli}" "${team}" >&2
        return 1
    fi
    # A freshly started daemon rewrites state.plist during startup; give it a
    # few tries before a missing or STALE state counts as "not up".
    local out=""
    local status=0
    local attempt
    for ((attempt = 0; attempt < 5; attempt++))
    do
        status=0
        out=$(serberus_run_bounded 20 "${cli}" status 2>&1) || status=$?
        if [[ "${status}" -eq 0 && "${out}" != *"STALE"* ]]
        then
            return 0
        fi
        "${PAM_LIB_SLEEP}" 2
    done
    printf '%s status did not report a fresh state (exit %s): %s\n' "${cli}" "${status}" "${out}" >&2
    return 1
}

########################################
########## Bounded one-shots ###########
########################################

# Runs <command…> with a hard deadline (macOS ships no timeout(1)): the
# command runs in the background and is polled once a second; after <seconds>
# it gets SIGTERM, then SIGKILL two seconds later. Returns the command's own
# exit status, or 124 on timeout (reported on stderr). Callers treat 124 as a
# LOUD failure — a hung --demote-jit or --restore-authdb must never stall an
# installer forever, nor pass silently.
#   $1 seconds, $2… command and arguments
serberus_run_bounded() {
    local limit="$1"
    shift
    "$@" &
    local child=$!
    # The deadline is measured in real elapsed time (bash's SECONDS) with the
    # real /bin/sleep, never the overridable PAM_LIB_SLEEP: a test that stubs
    # sleep out must not turn the deadline into zero and kill a live command.
    local started="${SECONDS}"
    while kill -0 "${child}" 2>/dev/null
    do
        if (( SECONDS - started >= limit ))
        then
            kill -TERM "${child}" 2>/dev/null || true
            /bin/sleep 2
            kill -KILL "${child}" 2>/dev/null || true
            wait "${child}" 2>/dev/null || true
            printf 'TIMED OUT after %ss (killed): %s\n' "${limit}" "$*" >&2
            return 124
        fi
        /bin/sleep 0.2
    done
    local status=0
    wait "${child}" || status=$?
    return "${status}"
}

########################################
####### AuthorizationDB residue ########
########################################

# True (0) when <backups> holds pending records: a file ending in .json,
# .branches or .projection directly in it (SERBERUS_AUTHDB_BLOCKING_SUFFIXES;
# .standin and anything else are ignored). Prints their names on stdout. A
# folder that exists but cannot be listed counts as pending. A missing folder
# holds nothing.
#   $1 optional backups directory (default SERBERUS_AUTHDB_BACKUPS_PATH)
serberus_authdb_records_pending() {
    local dir="${1:-${SERBERUS_AUTHDB_BACKUPS_PATH}}"
    if [[ ! -e "${dir}" && ! -L "${dir}" ]]
    then
        return 1
    fi
    if [[ -L "${dir}" || ! -d "${dir}" || ! -r "${dir}" || ! -x "${dir}" ]]
    then
        printf '%s (cannot be listed)\n' "${dir}"
        return 0
    fi
    local restore_globs
    restore_globs=$(shopt -p nullglob dotglob) || true
    shopt -s nullglob dotglob
    local -a entries=()
    local suffix
    for suffix in ${SERBERUS_AUTHDB_BLOCKING_SUFFIXES}
    do
        entries+=("${dir}"/*."${suffix}")
    done
    eval "${restore_globs}"
    local entry
    local found=1
    # ${entries[@]+…}: bash 3.2 treats an empty array as unset under set -u.
    for entry in ${entries[@]+"${entries[@]}"}
    do
        printf '%s\n' "${entry##*/}"
        found=0
    done
    return "${found}"
}

# True ONLY when the SerberusAuth plugin and the authdb-backups may go:
#   - <backups> holds no pending record (serberus_authdb_records_pending), and
#   - a read-only query of the AuthorizationDB ran and found no composition
#     row invoking SerberusAuth and no right delegating to a composition row
#     (SERBERUS_AUTHDB_QUERY).
# Callers also require the daemon's --restore-authdb to have exited 0 (or,
# with no daemon, nothing to restore). A right a standard user created,
# whatever its comment says, blocks nothing. A database or backups folder
# that cannot be read returns 1, so callers KEEP the plugin and the backups:
# deleting the plugin under a right that still names it fails every
# authorization for that right, and the backups are the only copy of the
# originals. Offending names / errors on stderr.
#   $1 optional database path (default SERBERUS_AUTHDB_PATH; tests pass one)
#   $2 optional backups directory (default SERBERUS_AUTHDB_BACKUPS_PATH)
serberus_authdb_free_of_serberus() {
    local db="${1:-${SERBERUS_AUTHDB_PATH}}"
    local backups="${2:-${SERBERUS_AUTHDB_BACKUPS_PATH}}"
    local pending
    if pending=$(serberus_authdb_records_pending "${backups}")
    then
        printf 'AuthorizationDB records still pending in %s: %s\n' "${backups}" \
            "$(printf '%s' "${pending}" | "${PAM_LIB_AWK}" 'BEGIN { ORS = " " } { print }')" >&2
        return 1
    fi
    if [[ ! -r "${db}" ]]
    then
        printf 'cannot read %s — cannot confirm no right still references SerberusAuth\n' "${db}" >&2
        return 1
    fi
    local names
    if ! names=$("${PAM_LIB_SQLITE3}" -readonly "${db}" "${SERBERUS_AUTHDB_QUERY}" 2>&1)
    then
        printf 'could not query %s: %s\n' "${db}" "${names}" >&2
        return 1
    fi
    if [[ -n "${names}" ]]
    then
        printf 'AuthorizationDB right(s) still reference Serberus: %s\n' "$(printf '%s' "${names}" | "${PAM_LIB_AWK}" 'BEGIN { ORS = " " } { print }')" >&2
        return 1
    fi
    return 0
}

########################################
####### Upgrade marker #################
########################################

# Writes the upgrade marker (SERBERUS_UPGRADE_MARKER): one line,
# `startedAt=<UTC ISO 8601>`, root:wheel 0600. The new daemon reads it at
# startup, ends the JIT sessions the old daemon left open, and removes it.
# Written only into a directory that is a real directory, root-owned and not
# group/other-writable (nobody else can plant or swap the file); any existing
# file or symlink at the path is replaced. Returns 1 (reason on stderr) when
# it could not be written.
#   $1 optional marker path (default SERBERUS_UPGRADE_MARKER; tests pass one)
serberus_write_upgrade_marker() {
    local marker="${1:-${SERBERUS_UPGRADE_MARKER}}"
    local dir="${marker%/*}"
    if [[ ! -d "${dir}" || -L "${dir}" ]] \
        || ! serberus_pam_path_is_root_locked "${dir}" "upgrade marker directory" 2>/dev/null
    then
        printf 'not writing %s: %s is not a root-only directory\n' "${marker}" "${dir}" >&2
        return 1
    fi
    if [[ -d "${marker}" && ! -L "${marker}" ]]
    then
        printf 'not writing %s: a directory is in its place\n' "${marker}" >&2
        return 1
    fi
    "${PAM_LIB_RM}" -f "${marker}" 2>/dev/null || true
    local stamp
    stamp=$("${PAM_LIB_DATE}" -u +%Y-%m-%dT%H:%M:%SZ)
    if ! ( umask 077 && set -o noclobber && printf 'startedAt=%s\n' "${stamp}" > "${marker}" ) 2>/dev/null
    then
        printf 'could not write %s\n' "${marker}" >&2
        return 1
    fi
    "${PAM_LIB_CHMOD}" 600 "${marker}" 2>/dev/null || true
    "${PAM_LIB_CHOWN}" 0:0 "${marker}" 2>/dev/null || true
    return 0
}

########################################
####### Data purge #####################
########################################

# The --purge of a teardown: removes the DATA in the support folder (state,
# grants, caches, keys, the upgrade marker, and authdb-backups unless
# <keep_backups> is 1) and nothing else. Kept: apps (*.app: the Sentinel
# agent, Guardian), every uninstall helper (uninstall*.sh) and pam-lib.sh,
# and the install-marker directory (.install-markers), which belong to their
# own packages. Prints each removed path on stdout. A missing folder, or a
# symlink in its place, is left alone.
#   $1 support folder, $2 keep_backups (1 = keep authdb-backups; default 0)
serberus_purge_support_data() {
    local dir="$1"
    local keep_backups="${2:-0}"
    if [[ ! -d "${dir}" || -L "${dir}" ]]
    then
        return 0
    fi
    local restore_globs
    restore_globs=$(shopt -p nullglob dotglob) || true
    shopt -s nullglob dotglob
    local -a entries=("${dir}"/*)
    eval "${restore_globs}"
    local entry
    # ${entries[@]+…}: bash 3.2 treats an empty array as unset under set -u.
    for entry in ${entries[@]+"${entries[@]}"}
    do
        case "${entry##*/}" in
            *.app | uninstall*.sh | pam-lib.sh | .install-markers)
                continue
                ;;
            authdb-backups)
                if [[ "${keep_backups}" == "1" ]]
                then
                    continue
                fi
                ;;
        esac
        "${PAM_LIB_RM}" -rf -- "${entry}"
        printf '%s\n' "${entry}"
    done
    return 0
}

########################################
####### Teardown safety net ############
########################################

# The rule every teardown EXIT trap enforces: while <sudo_local> still has an
# ACTIVE pam_serberus line, the daemon behind it must stay enabled and loaded
# — a wired `requisite` module with no daemon denies every non-bypass sudo,
# and a disabled label would not come back after a reboot either. Enables the
# label, and bootstraps <plist> when the job is not loaded. Best-effort by
# design (it runs on failure paths); returns 0 when nothing was wired, 1 when
# it had to act.
#   $1 sudo_local path, $2 launchd label, $3 LaunchDaemon plist path
serberus_daemon_rearm_if_wired() {
    local sudo_local="$1"
    local label="$2"
    local plist="$3"
    if ! serberus_pam_sudo_local_has_module "${sudo_local}"
    then
        return 0
    fi
    "${PAM_LIB_LAUNCHCTL}" enable "system/${label}" 2>/dev/null || true
    if ! "${PAM_LIB_LAUNCHCTL}" print "system/${label}" >/dev/null 2>&1 && [[ -f "${plist}" ]]
    then
        "${PAM_LIB_LAUNCHCTL}" bootstrap system "${plist}" 2>/dev/null || true
    fi
    printf '%s still has an active pam_serberus line — kept system/%s enabled and loaded\n' \
        "${sudo_local}" "${label}" >&2
    return 1
}

###################################################################################
############## End Function Block #################################################
###################################################################################
