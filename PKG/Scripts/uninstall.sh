#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: uninstall.sh
# Author: Heath Jones
# Date: 2026-06-13
# Modified: 2026-09-26
# Purpose: Serberus uninstaller for the production pkg's components. Run as
#          root. ORDER IS SAFETY-CRITICAL:
#            1. remove the coarse /etc/sudoers.d/serberus drop-in;
#            2. unwire /etc/pam.d/sudo_local (stop, daemon still running, on
#               failure);
#            3. launchctl disable the daemon (a reboot cannot bring it back),
#               then launchctl bootout and wait until launchd has dropped the
#               job (then re-check the drop-in: the daemon could rewrite it
#               until it stopped);
#            4. <daemon> --demote-jit (JIT admins lose admin; loud on failure),
#               then the drop-in once more;
#            5. <daemon> --restore-authdb (bundle or flat test binary);
#               a daemon runs only after its signature passes (strict,
#               Apple anchor, identifier, pinned team) — otherwise the
#               manual steps are printed instead;
#            6. delete SerberusAuth.bundle + authdb-backups ONLY if 5 succeeded
#               AND authdb-backups holds no pending record AND a read-only
#               check of /var/db/auth.db finds no composition row invoking
#               SerberusAuth and no right delegating to one;
#            7. remove module (and any stray pam_serberus.so.2), plist, CLI,
#               flat binary, bundle; forget receipts.
#          --purge also removes data only: state, grants, logs, caches and
#          the daemon's System-keychain items (authdb-backups survive a
#          failed restore). Apps and the other packages' uninstall helpers in
#          the support folder are never purged.
#          Installed by the production pkg as
#          /Library/Application Support/Serberus/uninstall.sh (with pam-lib.sh).
# Version: 1.9 - (a) The gate on deleting the plugin and the backups no
#          longer trusts a comment: after a restore that exited 0, both stay
#          while authdb-backups holds a .json, .branches or .projection record
#          (.standin files are kept on purpose and ignored), a composition
#          row (com.herojoneslabs.serberus.branch.*) invokes SerberusAuth, or
#          a right delegates to a composition row. A right a standard user
#          created with the marker comment blocks nothing. With no daemon,
#          only those record files (not a .standin) mean there is something
#          to restore.
#          (b) --restore-authdb, like --demote-jit, never runs beside a daemon
#          that is still loaded. (c) The post-bootout wait is the daemon's
#          ExitTimeOut plus 5 s (25 s). (d) The daemon runs only when pinned
#          to the recorded install team or the installed PAM module's team;
#          with neither, the manual steps are printed. (e) --purge removes
#          data only; the Sentinel agent and Guardian apps and the other
#          uninstall helpers stay.
#          1.8 - (a) The daemon is disabled after sudo_local is unwired,
#          right before the bootout: an uninstall interrupted between a
#          disable and the unwire would leave sudo_local wired behind a
#          daemon launchd never starts. (b) After the bootout the script waits
#          (up to the daemon's 20 s ExitTimeOut) until launchd has dropped
#          the job; if it is still loaded no one-shot runs and the manual
#          steps are printed. (c) The drop-in is checked again after
#          --demote-jit. (d) The daemon is pinned to the Team ID the install
#          recorded in version.plist, when there is one. (e) A failed
#          sudo_local rewrite is reported (FAILED) instead of ending the
#          script under set -e. (f) Also removes
#          /usr/local/lib/pam/pam_serberus.so.2, which OpenPAM would load in
#          place of the module. (g) The AuthorizationDB residue check that
#          gates deleting the plugin matches only rights that invoke a
#          SerberusAuth: mechanism or carry the daemon's managed marker (not
#          any right whose name or comment mentions serberus).
#          1.7 - (a) Sources only a pam-lib.sh whose whole path is
#          root-only: the installed copy under the support dir first, the one
#          next to this script only when every directory above it is
#          root-owned, not group/other-writable and not a symlink. (b) A daemon
#          binary is executed (--demote-jit, --restore-authdb) only when its
#          signature passes: strict, Apple anchor, identifier
#          com.herojoneslabs.serberus.daemon, the team of the installed PAM
#          module (or its own); otherwise the manual dseditgroup / security
#          authorizationdb steps are printed. (c) A sudoers drop-in that
#          survives its removal stops the teardown BEFORE sudo_local is
#          unwired. (d) --demote-jit exit 3 (no grant store) is
#          informational.
#          1.6 - (a) EXIT trap: an unexpected exit (e.g. a STEP 2 failure
#          under set -e) re-enables — and reloads — the daemon while
#          sudo_local still has an active pam_serberus line. (b) umask 022.
#          (c) --demote-jit / --restore-authdb run with a 120 s deadline; a
#          timeout is a loud failure. (d) The plugin and backups are removed
#          only when the restore exited 0 AND the live AuthorizationDB no
#          longer references Serberus (sqlite3 -readonly). (e) The daemon's
#          new exit semantics: --restore-authdb exits non-zero while any right
#          still references SerberusAuth; --demote-jit exits 1 when it cannot
#          demote or verify.
#          1.5 - New teardown order (disable -> drop-in -> unwire -> bootout ->
#          demote JIT -> restore authdb -> plugin only if the restore
#          succeeded -> files -> receipts). Defines log_error (it was called
#          but undefined, so a failed restore path died under set -e). Tools
#          by absolute path. Forgets the daemon/PAM pkg receipts and, with
#          --purge, the daemon's System-keychain items.
#          1.4 - (a) Both gates (drop-in, then sudo_local) are removed BEFORE
#          the daemon is stopped, so a failed unwire can't leave sudo wired
#          to a module with no daemon behind it (every sudo denied). (b) The
#          AuthorizationDB restore also finds a flat test-ring daemon
#          binary, and fails loudly when backups exist but nothing can
#          restore them. (c) SerberusAuth.bundle is removed after the
#          restore. (d) PATH no longer includes /usr/local/bin. For a full
#          removal of every component, use the uninstall pkg
#          (PKG/build-uninstall-pkg.sh).
#          1.3 - Remove the coarse /etc/sudoers.d/serberus standard-user
#          allowlist FIRST in the teardown order (before sudo_local is unwired
#          and the module deleted), UNCONDITIONALLY — not gated behind --purge:
#          the drop-in is the coarse gate and pam_serberus the fine gate, so a
#          coarse gate outliving the fine gate is fail-open. Removal is
#          marker-guarded (only a file carrying the Serberus managed header is
#          deleted) and scoped to that ONE exact path — no glob, no visudo,
#          nothing else under /etc/sudoers.d touched. Via pam-lib.sh
#          serberus_pam_remove_sudoers_dropin when sourced, identical inline
#          fallback otherwise.
#          1.2 - (a) PAM module path is now /usr/local/lib/pam/
#          pam_serberus.so (/usr/lib/pam is on the sealed read-only system
#          snapshot); the legacy path is still cleaned up if present.
#          (b) sudo_local removal is now MARKER-AWARE via pam-lib.sh (sourced
#          when staged alongside this script or installed under the support
#          dir, with an identical inline fallback): only Serberus-managed
#          lines are stripped — legacy bare-name and absolute-path forms
#          both — user lines whose comments merely MENTION serberus survive,
#          and the file is deleted only when Serberus CREATED it and nothing
#          active remains (the old substring `grep -v serberus` destroyed
#          user lines like `pam_tid.so # keep above serberus` and deleted
#          comments-only user files Serberus never created).
#          1.1 - SAFETY-CRITICAL ordering fix: /etc/pam.d/sudo_local is now
#          unwired BEFORE the PAM module is deleted (the old
#          order could strand a wired reference to a deleted module —
#          dlopen failure inside sudo's auth stack = sudo bricked for
#          everyone). sudo_local removal is also line-aware now: user PAM
#          lines (e.g. pam_tid.so) are preserved and the file is only deleted
#          when no non-Serberus lines remain.
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

set -euo pipefail
umask 022

# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute tool paths: this runs as root, so nothing is resolved via PATH.
readonly AWK="/usr/bin/awk"
readonly BASENAME="/usr/bin/basename"
readonly CODESIGN="/usr/bin/codesign"
readonly DIRNAME="/usr/bin/dirname"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly KILLALL="/usr/bin/killall"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly MV="/bin/mv"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly PLUTIL="/usr/bin/plutil"
readonly RM="/bin/rm"
readonly SECURITY="/usr/bin/security"
readonly SLEEP="/bin/sleep"
readonly SQLITE3="/usr/bin/sqlite3"
readonly STAT="/usr/bin/stat"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.9"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.uninstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
# The daemon is installed as an app-like bundle (carries the ES provisioning profile).
readonly DAEMON_BUNDLE="/Library/PrivilegedHelperTools/serberusd.app"
readonly DAEMON_BINARY="${DAEMON_BUNDLE}/Contents/MacOS/com.herojoneslabs.serberus.daemon"
# Test-ring installs ship the daemon as a flat binary instead.
readonly DAEMON_BINARY_FLAT="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
# The authorization plugin identity-scoped rules compose into rights. Removed
# only AFTER the AuthorizationDB restore: a right still naming a deleted
# mechanism fails every authorization for it.
readonly AUTH_PLUGIN="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
# Canonical module location (/usr/lib/pam is on the sealed read-only system
# snapshot — keep in sync with pam-lib.sh SERBERUS_PAM_MODULE_PATH). The
# legacy path is still removed if a pre-relocation install somehow left one.
readonly PAM_MODULE="/usr/local/lib/pam/pam_serberus.so"
readonly PAM_MODULE_LEGACY="/usr/lib/pam/pam_serberus.so"
# OpenPAM loads "<module>.2" in preference to the module; Serberus never ships
# one, but any stray copy goes too (pam-lib.sh
# SERBERUS_PAM_MODULE_VERSIONED_PATH).
readonly PAM_MODULE_VERSIONED="${PAM_MODULE}.2"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly CLI_BINARY="/usr/local/bin/serberus"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly AUTHDB_BACKUPS="${SUPPORT_DIR}/authdb-backups"
# Records installTeamID, the team the install validated the daemon against
# (pam-lib.sh SERBERUS_VERSION_PLIST / SERBERUS_INSTALL_TEAM_KEY).
readonly VERSION_PLIST="${SUPPORT_DIR}/version.plist"
# Seconds to wait for a booted-out daemon to leave launchd: its ExitTimeOut
# (20 s, set in the LaunchDaemon plist) plus 5 s (pam-lib.sh
# SERBERUS_DAEMON_BOOTOUT_WAIT).
readonly DAEMON_BOOTOUT_WAIT=25
readonly LOG_DIR="/Library/Logs/Serberus"
# Pre-rename Sentinel location, removed if an old install left it. Current
# Sentinel components belong to their own pkg and its uninstall helper.
readonly SENTINEL_APP="${SUPPORT_DIR}/SerberusSentinel.app"

# Marker semantics mirrored from PKG/Scripts/pam-lib.sh — KEEP IN SYNC. Used
# by the inline fallback when no pam-lib.sh can be sourced. The
# `pam_serberus\.so` substring deliberately matches BOTH the legacy bare-name
# line and the new absolute-path line.
readonly FALLBACK_CREATED_TAG='# serberus-created'
readonly FALLBACK_LEGACY_HEADER_RE='^# sudo_local: managed by com\.herojoneslabs\.serberus'
readonly FALLBACK_STRIP_RE="pam_serberus\.so|# serberus-(managed|created)|${FALLBACK_LEGACY_HEADER_RE}"

# Coarse sudoers drop-in that lets standard users run the curated sudo
# commands. Removed UNCONDITIONALLY (NOT gated behind --purge) and BEFORE the
# PAM module/sudo_local are torn down — the drop-in is the coarse gate, the
# module the fine gate, and a coarse gate outliving the fine gate is fail-open.
# Path + marker mirror pam-lib.sh SERBERUS_SUDOERS_PATH / _MARKER_RE (and the
# PrivMgrCore Swift headers) — KEEP IN SYNC. Used by the inline fallback below
# when no pam-lib.sh can be sourced.
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"
readonly FALLBACK_SUDOERS_MARKER_RE='^# /etc/sudoers\.d/serberus: managed by com\.herojoneslabs\.serberus'

# Receipts of every package that installs the components this script removes
# (production, and the daemon/PAM test rings). GUI-app receipts belong to
# their own uninstall helpers and the full uninstall pkg.
readonly RECEIPTS=(
    "${ORG_PLIST_DOMAIN}.pkg"
    "${ORG_PLIST_DOMAIN}.testpkg"
    "${ORG_PLIST_DOMAIN}.pamtestpkg"
    "${ORG_PLIST_DOMAIN}.sentineltestpkg"
    "${ORG_PLIST_DOMAIN}.coretestpkg"
)

# System-keychain items the daemon creates (HMAC keys). Removed with --purge.
readonly KEYCHAIN_SERVICE="${ORG_PLIST_DOMAIN}.daemon"
readonly SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"

# Pass --purge to also remove state, grants, logs, and keychain items.
readonly PURGE="${1:-}"

# Hard deadline for each daemon one-shot (--demote-jit, --restore-authdb).
readonly ONESHOT_TIMEOUT=120

# The identifier every build signs serberusd with — mirrors pam-lib.sh
# SERBERUS_DAEMON_IDENTIFIER (KEEP IN SYNC); used when pam-lib.sh is
# unavailable.
readonly DAEMON_IDENTIFIER="com.herojoneslabs.serberus.daemon"

# Live AuthorizationDB and the residue query — mirrors pam-lib.sh
# SERBERUS_AUTHDB_QUERY (KEEP IN SYNC); used when pam-lib.sh is unavailable.
readonly AUTH_DB="/var/db/auth.db"
readonly FALLBACK_AUTHDB_QUERY="SELECT DISTINCT r.name FROM rules r JOIN mechanisms_map mm ON mm.r_id = r.id JOIN mechanisms m ON m.id = mm.m_id WHERE m.plugin LIKE 'SerberusAuth' AND r.name LIKE 'com.herojoneslabs.serberus.branch.%' UNION SELECT DISTINCT r.name FROM rules r JOIN delegates_map dm ON dm.r_id = r.id JOIN rules d ON d.id = dm.d_id WHERE d.name LIKE 'com.herojoneslabs.serberus.branch.%';"

# Set to 1 by restore_authorization_db when the AuthorizationDB is known to
# be back to native (restore exited 0, or there was nothing to restore, AND
# the live database no longer references Serberus). It GATES deleting the
# plugin and the backups.
AUTHDB_RESTORE_OK=0
PAM_LIB_LOADED=0
# Set when the drop-in is still present after the post-bootout removal; the
# script then finishes the teardown but exits 1.
DROPIN_SURVIVED=0
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut;
# no one-shot is run beside it (manual steps are printed instead).
DAEMON_GONE=1

# Success marker, set right before the final exit 0. Without it the EXIT trap
# keeps the daemon enabled while sudo_local is still wired.
UNINSTALL_SUCCEEDED=0

##################################
### End User Defined Variables ###
##################################
####################################################################
############## End Define Variables Block ##########################
####################################################################

###################################################################################
############## Begin Function Block ###############################################
###################################################################################
##############################
### Core Defined Functions ###
### MODIFY AT YOUR OWN RISK ##
##############################

log_info() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.info "[INFO] $*"
    printf '[INFO] %s\n' "$*"
}

log_warn() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.warning "[WARN] $*"
    printf '[WARN] %s\n' "$*" >&2
}

log_error() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.err "[ERROR] $*"
    printf '[ERROR] %s\n' "$*" >&2
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_warn "Must run as root"
        exit 1
    fi
}

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

# EXIT trap: an exit without the success marker — e.g. a step failing under
# set -e after STEP 3 disabled the daemon — must never leave sudo_local wired
# behind a disabled daemon. While an ACTIVE pam_serberus line remains, the
# label is re-enabled and the job reloaded.
on_exit() {
    local status=$?
    if [[ "${UNINSTALL_SUCCEEDED}" -eq 1 ]]
    then
        return 0
    fi
    set +e
    if "${GREP}" -Eq '^[^#]*pam_serberus\.so' "${SUDO_LOCAL}" 2>/dev/null
    then
        log_error "Exiting (status ${status}) with ${SUDO_LOCAL} still wired — re-enabling ${DAEMON_LABEL}."
        reenable_daemon
        if ! "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1 && [[ -f "${LAUNCHD_PLIST}" ]]
        then
            "${LAUNCHCTL}" bootstrap system "${LAUNCHD_PLIST}" 2>/dev/null \
                || log_error "Could not reload ${DAEMON_LABEL} — every non-bypass sudo is denied until it runs."
        fi
    fi
    exit "${status}"
}

# Runs a daemon one-shot with a hard deadline: pam-lib.sh serberus_run_bounded
# when loaded, otherwise the same poll-and-kill loop inline (macOS has no
# timeout(1)). 124 = timed out. $1 seconds, $2… command.
run_bounded() {
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        serberus_run_bounded "$@"
        return $?
    fi
    local limit="$1"
    shift
    "$@" &
    local child=$!
    local waited=0
    while kill -0 "${child}" 2>/dev/null
    do
        if [[ "${waited}" -ge "${limit}" ]]
        then
            kill -TERM "${child}" 2>/dev/null || true
            "${SLEEP}" 2
            kill -KILL "${child}" 2>/dev/null || true
            wait "${child}" 2>/dev/null || true
            log_error "TIMED OUT after ${limit}s (killed): $*"
            return 124
        fi
        "${SLEEP}" 1
        waited=$((waited + 1))
    done
    local status=0
    wait "${child}" || status=$?
    return "${status}"
}

# True (0) when authdb-backups holds a pending record: a file ending in
# .json, .branches or .projection directly in it (.standin and anything else
# are ignored), or the folder cannot be listed. The inline twin of pam-lib.sh
# serberus_authdb_records_pending.
authdb_records_pending() {
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        serberus_authdb_records_pending "${AUTHDB_BACKUPS}" > /dev/null
        return $?
    fi
    if [[ ! -e "${AUTHDB_BACKUPS}" && ! -L "${AUTHDB_BACKUPS}" ]]
    then
        return 1
    fi
    if [[ -L "${AUTHDB_BACKUPS}" || ! -d "${AUTHDB_BACKUPS}" || ! -r "${AUTHDB_BACKUPS}" ]]
    then
        return 0
    fi
    local -a entries=()
    shopt -s nullglob dotglob
    entries=("${AUTHDB_BACKUPS}"/*.json "${AUTHDB_BACKUPS}"/*.branches "${AUTHDB_BACKUPS}"/*.projection)
    shopt -u nullglob dotglob
    [[ "${#entries[@]}" -gt 0 ]]
}

# True only when authdb-backups holds no pending record and a read-only
# query of the live AuthorizationDB found no composition row invoking
# SerberusAuth and no right delegating to one (pam-lib.sh
# serberus_authdb_free_of_serberus, or the same checks inline).
authdb_free_of_serberus() {
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        serberus_authdb_free_of_serberus "${AUTH_DB}" "${AUTHDB_BACKUPS}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        return $?
    fi
    if authdb_records_pending
    then
        log_error "AuthorizationDB records are still pending in ${AUTHDB_BACKUPS}"
        return 1
    fi
    local names
    if ! names=$("${SQLITE3}" -readonly "${AUTH_DB}" "${FALLBACK_AUTHDB_QUERY}" 2>&1)
    then
        log_error "Could not query ${AUTH_DB}: ${names}"
        return 1
    fi
    if [[ -n "${names}" ]]
    then
        log_error "AuthorizationDB right(s) still reference Serberus: ${names}"
        return 1
    fi
    return 0
}

# STEP 3 — disable only once sudo_local is unwired (right before the
# bootout), so a reboot cannot relaunch the daemon, and an interrupted run
# never leaves sudo_local wired behind a disabled daemon. A daemon that
# restarts after the unwire cannot re-provision its drop-in. A later install
# re-enables the label.
disable_daemon() {
    log_info "Disabling ${DAEMON_LABEL}"
    "${LAUNCHCTL}" disable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl disable system/${DAEMON_LABEL} failed"
}

# Make sure the label is enabled when the teardown must stop early with sudo
# still wired: a disabled daemon plus a wired sudo_local would deny every
# sudo after the next reboot.
reenable_daemon() {
    "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl enable system/${DAEMON_LABEL} failed"
}

# STEP 3 — bootout, then wait until launchd no longer lists the job (pam-lib
# serberus_launchd_wait_gone, or the same poll inline): the one-shots must
# not run beside a daemon that still holds the grant store.
bootout_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_info "Booting out ${DAEMON_LABEL}"
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
        then
            serberus_launchd_wait_gone "${DAEMON_LABEL}" "${DAEMON_BOOTOUT_WAIT}" \
                2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) || DAEMON_GONE=0
        else
            local waited=0
            while "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
            do
                if [[ "${waited}" -ge "${DAEMON_BOOTOUT_WAIT}" ]]
                then
                    DAEMON_GONE=0
                    break
                fi
                "${SLEEP}" 1
                waited=$((waited + 1))
            done
        fi
        if [[ "${DAEMON_GONE}" -ne 1 ]]
        then
            log_error "${DAEMON_LABEL} is still loaded ${DAEMON_BOOTOUT_WAIT}s after its bootout — no daemon one-shot will run."
        fi
    fi
}

# The Team ID the install recorded in version.plist (pam-lib.sh
# serberus_recorded_team, or the same checks inline: a root-owned regular
# file no group/other can write). Prints nothing when there is none.
recorded_team() {
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        serberus_recorded_team "${VERSION_PLIST}" 2>/dev/null || true
        return 0
    fi
    path_is_root_locked "${VERSION_PLIST}" || return 0
    local team
    team=$("${PLUTIL}" -extract installTeamID raw -o - "${VERSION_PLIST}" 2>/dev/null) || team=""
    if [[ "${team}" =~ ^[A-Z0-9]{10}$ ]]
    then
        printf '%s' "${team}"
    fi
}

# True when <path> may be EXECUTED as root: pam-lib.sh serberus_daemon_trusted
# when loaded, otherwise the same check inline — a strict signature from an
# Apple-issued certificate with the daemon identifier and the team the install
# recorded in version.plist, else the installed PAM module's team. With
# neither, the daemon is refused: its own team proves nothing. An empty team
# never matches. $1 daemon path.
daemon_trusted() {
    local path="$1"
    local team
    team=$(recorded_team)
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        serberus_daemon_trusted "${path}" "${team}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        return $?
    fi
    [[ -f "${path}" && ! -L "${path}" ]] || return 1
    if [[ -n "${team}" ]]
    then
        "${CODESIGN}" --verify --strict \
            -R "=anchor apple generic and identifier \"${DAEMON_IDENTIFIER}\" and certificate leaf[subject.OU] = \"${team}\"" \
            "${path}" >/dev/null 2>&1
        return $?
    fi
    if [[ -f "${PAM_MODULE}" && ! -L "${PAM_MODULE}" ]]
    then
        team=$("${CODESIGN}" -dv "${PAM_MODULE}" 2>&1 | "${AWK}" -F= '/^TeamIdentifier=/ { print $2; exit }') || team=""
    fi
    if [[ ! "${team}" =~ ^[A-Z0-9]{10}$ ]]
    then
        log_error "No Team ID to pin ${path} to (no installTeamID recorded, no signed PAM module installed) — not executing it."
        return 1
    fi
    "${CODESIGN}" --verify --strict \
        -R "=anchor apple generic and identifier \"${DAEMON_IDENTIFIER}\" and certificate leaf[subject.OU] = \"${team}\"" \
        "${path}" >/dev/null 2>&1
}

# The manual fallback when no daemon may be executed. $1 demote | restore
print_manual_steps() {
    case "$1" in
        demote)
            log_error "!!! JIT-granted users may STILL be local admins. Check the admin group"
            log_error "!!! (dscl . -read /Groups/admin GroupMembership) and remove each one with"
            log_error "!!!   sudo dseditgroup -o edit -d <user> -t user admin"
            ;;
        restore)
            log_error "!!! Restore each right Serberus changed by hand from ${AUTHDB_BACKUPS}/<right>.json:"
            log_error "!!!   sudo security authorizationdb write <right> < ${AUTHDB_BACKUPS}/<right>.json"
            ;;
    esac
}

# STEP 4 — demote every JIT admin recorded in the grant store. Runs after the
# bootout (the one-shot mode must not race the live daemon) and before any
# file is removed. Tries the production bundle binary, then the flat
# test-ring binary; a binary runs only when daemon_trusted passes. Never
# aborts the teardown, but a failure is loud: those users would otherwise stay
# local admins forever. Exit 3 = no grant store, nothing to demote.
demote_jit_admins() {
    local candidate
    local found=0
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "Not running --demote-jit beside a daemon that is still loaded."
        print_manual_steps demote
        return 0
    fi
    for candidate in "${DAEMON_BINARY}" "${DAEMON_BINARY_FLAT}"
    do
        if [[ ! -x "${candidate}" ]]
        then
            continue
        fi
        found=1
        if ! daemon_trusted "${candidate}"
        then
            log_error "${candidate} failed its signature check (strict, identifier ${DAEMON_IDENTIFIER}, team) — NOT executing it."
            continue
        fi
        log_info "Demoting JIT admins (${candidate} --demote-jit)"
        local status=0
        run_bounded "${ONESHOT_TIMEOUT}" "${candidate}" --demote-jit || status=$?
        case "${status}" in
            0)
                log_info "JIT admins demoted"
                return 0
                ;;
            3)
                log_info "No grant store — no JIT admins to demote"
                return 0
                ;;
        esac
        log_error "--demote-jit FAILED via ${candidate} (exit ${status}; 124 = timed out)"
    done
    if [[ "${found}" -eq 0 ]]
    then
        log_error "No daemon binary found — JIT admins could NOT be demoted."
    fi
    print_manual_steps demote
    return 0
}

# STEP 5 — restore every right Serberus rewrote, with whichever daemon binary
# exists, and only once launchd has dropped the booted-out daemon. Sets AUTHDB_RESTORE_OK=1 only when the AuthorizationDB is known to be
# native again (restore exited 0, or no binary AND no backups — nothing was
# ever rewritten).
restore_authorization_db() {
    local binary=""
    local untrusted=0
    local candidate
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "Not running --restore-authdb beside a daemon that is still loaded."
        print_manual_steps restore
        return 0
    fi
    for candidate in "${DAEMON_BINARY}" "${DAEMON_BINARY_FLAT}"
    do
        if [[ ! -x "${candidate}" ]]
        then
            continue
        fi
        if daemon_trusted "${candidate}"
        then
            binary="${candidate}"
            break
        fi
        untrusted=1
        log_error "${candidate} failed its signature check (strict, identifier ${DAEMON_IDENTIFIER}, team) — NOT executing it for --restore-authdb."
    done
    if [[ -z "${binary}" ]]
    then
        if authdb_records_pending
        then
            log_error "AuthorizationDB backups exist but no trusted daemon binary can restore them."
            log_error "Rights Serberus changed stay changed. Reinstall, then uninstall, or restore them by hand:"
            print_manual_steps restore
            return 0
        fi
        if [[ "${untrusted}" -eq 1 ]]
        then
            log_info "No AuthorizationDB backups — nothing for the untrusted daemon to restore"
        fi
        log_info "No daemon binary and no AuthorizationDB backups — nothing to restore"
        if authdb_free_of_serberus
        then
            AUTHDB_RESTORE_OK=1
        fi
        return 0
    fi
    log_info "Restoring AuthorizationDB from backups (${binary})"
    local status=0
    run_bounded "${ONESHOT_TIMEOUT}" "${binary}" --restore-authdb || status=$?
    if [[ "${status}" -ne 0 ]]
    then
        log_error "AuthorizationDB restore FAILED (exit ${status}; 124 = timed out) — review ${AUTHDB_BACKUPS} manually"
        print_manual_steps restore
        return 0
    fi
    # Exit 0 is necessary but not sufficient: confirm read-only that no right
    # still references Serberus before the plugin may go.
    if authdb_free_of_serberus
    then
        AUTHDB_RESTORE_OK=1
    else
        log_error "The restore exited 0 but the AuthorizationDB still references Serberus — keeping the plugin and backups"
    fi
}

# STEP 6 — ONLY after a successful restore. Composed rights reference
# "SerberusAuth:identity"; deleting the bundle while one still does makes every
# authorization for that right fail. On a failed restore the plugin and the
# backups (the only record of the native rights) are both kept.
remove_auth_plugin_if_restored() {
    if [[ "${AUTHDB_RESTORE_OK}" -ne 1 ]]
    then
        log_warn "Keeping ${AUTH_PLUGIN} and ${AUTHDB_BACKUPS}: the AuthorizationDB restore did not"
        log_warn "succeed, and rights that still reference SerberusAuth:identity would fail without it."
        return 0
    fi
    if [[ -e "${AUTH_PLUGIN}" ]]
    then
        remove_component "${AUTH_PLUGIN}"
        "${KILLALL}" SecurityAgent authorizationhost 2>/dev/null || true
    fi
    remove_component "${AUTHDB_BACKUPS}"
}

remove_component() {
    local path="$1"
    if [[ -e "${path}" ]]
    then
        log_info "Removing ${path}"
        "${RM}" -rf "${path}"
    fi
}

# True when <path> is owned by root, not group/other-writable and not a
# symlink. $1 path.
path_is_root_locked() {
    local path="$1"
    local info
    local uid
    local mode
    [[ -e "${path}" && ! -L "${path}" ]] || return 1
    info=$("${STAT}" -f '%u %Lp' "${path}" 2>/dev/null) || return 1
    read -r uid mode <<< "${info}"
    [[ "${uid}" == "0" && "${mode}" =~ ^[0-7]+$ ]] || return 1
    (( ! ( (8#${mode}) & 8#022 ) ))
}

# True when <file> and EVERY directory above it (up to /) are root-locked, the
# same chain rule pam-lib.sh serberus_cli_health_ok applies before root runs
# the CLI: nobody but root can swap the file between the check and the
# source. $1 absolute file path.
path_chain_is_root_only() {
    local file="$1"
    [[ "${file}" == /* && -f "${file}" ]] || return 1
    path_is_root_locked "${file}" || return 1
    local dir="${file%/*}"
    while [[ -n "${dir}" ]]
    do
        path_is_root_locked "${dir}" || return 1
        dir="${dir%/*}"
    done
    path_is_root_locked "/"
}

# Source the shared marker-aware sudo_local logic when a trusted pam-lib.sh
# is available. The installed copy under the support dir comes first; the
# copy next to this script is used only when its whole directory chain is
# root-only (a copy in ~/Downloads is refused: its owner could swap the file
# between the check and the source). Otherwise the inline logic below, which
# implements the same semantics, is used. Returns 1 when none qualifies.
source_pam_lib_if_present() {
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        return 0
    fi
    local sibling_dir
    sibling_dir=$(cd "$("${DIRNAME}" "$0")" 2>/dev/null && pwd) || sibling_dir=""
    local candidate
    for candidate in \
        "${SUPPORT_DIR}/pam-lib.sh" \
        ${sibling_dir:+"${sibling_dir}/pam-lib.sh"}
    do
        if path_chain_is_root_only "${candidate}"
        then
            # shellcheck source=/dev/null
            source "${candidate}"
            PAM_LIB_LOADED=1
            log_info "Using marker-aware sudo_local logic from ${candidate}"
            return 0
        fi
    done
    return 1
}

# Inline fallback with the SAME semantics as pam-lib.sh
# serberus_pam_remove_sudo_local: strip only Serberus-managed content
# (FALLBACK_STRIP_RE — legacy bare-name AND absolute-path module lines,
# marker/managed comments); delete the file ONLY when Serberus created it
# (created tag or legacy managed header) and no active line remains;
# otherwise preserve every user line — including lines whose trailing
# comments merely mention serberus (e.g. `pam_tid.so # keep above serberus`)
# and comments-only files Serberus never created.
fallback_remove_sudo_local() {
    if [[ -d "${SUDO_LOCAL}" ]]
    then
        printf 'FAILED'
        return 1
    fi
    if ! "${GREP}" -Eq "${FALLBACK_STRIP_RE}" "${SUDO_LOCAL}"
    then
        printf 'untouched'
        return 0
    fi

    local created=0
    if "${GREP}" -Fq "${FALLBACK_CREATED_TAG}" "${SUDO_LOCAL}" \
        || "${GREP}" -Eq "${FALLBACK_LEGACY_HEADER_RE}" "${SUDO_LOCAL}"
    then
        created=1
    fi

    # grep -v exits 1 when nothing survives — a valid outcome here.
    local tmp="${SUDO_LOCAL}.serberus-uninstall.$$"
    "${GREP}" -Ev "${FALLBACK_STRIP_RE}" "${SUDO_LOCAL}" > "${tmp}" || true

    if [[ "${created}" -eq 1 ]] \
        && ! "${GREP}" -Eq '^[[:space:]]*[^#[:space:]]' "${tmp}"
    then
        "${RM}" -f "${tmp}" "${SUDO_LOCAL}"
        printf 'deleted'
        return 0
    fi

    "${MV}" -f "${tmp}" "${SUDO_LOCAL}"
    printf 'cleaned'
}

# Inline fallback with the SAME semantics as pam-lib.sh
# serberus_pam_remove_sudoers_dropin: delete the coarse sudoers drop-in ONLY
# when it carries the Serberus managed header (FALLBACK_SUDOERS_MARKER_RE), so
# a same-named admin-authored file is preserved. `rm -f` on the ONE exact path
# — never a glob, never a directory, and never visudo (deleting a whole file
# cannot add a syntax error). $1 = path.
fallback_remove_sudoers_dropin() {
    local dropin="$1"
    if ! "${GREP}" -Eq "${FALLBACK_SUDOERS_MARKER_RE}" "${dropin}"
    then
        printf 'foreign'
        return 0
    fi
    "${RM}" -f "${dropin}" 2>/dev/null || true
    if [[ -e "${dropin}" || -L "${dropin}" ]]
    then
        printf 'FAILED'
        return 1
    fi
    printf 'removed'
}

# STEP 1 — remove the coarse Serberus sudoers drop-in. Called UNCONDITIONALLY
# (NOT behind --purge) and BEFORE unwire_sudo_local / module removal (and once
# more after the bootout, since the running daemon could rewrite it): the
# drop-in is only a coarse per-command allowlist and pam_serberus is the fine
# gate, so tearing the fine gate down while the coarse allowlist survives would
# hand standard users unmediated sudo to the curated command paths (fail-open).
# Marker-aware and single-path; the Apple-owned main sudoers file and every
# other /etc/sudoers.d entry are never touched. A drop-in that is STILL there
# after the rm returns 1: the caller must not unwire sudo_local.
remove_sudoers_dropin() {
    if [[ ! -e "${SUDOERS_DROPIN}" ]]
    then
        return 0
    fi

    local result
    if source_pam_lib_if_present
    then
        result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    else
        log_info "No pam-lib.sh found — using the built-in marker-guarded fallback"
        result=$(fallback_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    fi
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        log_error "Remove it by hand (chflags noschg,nouchg first if set): sudo rm -f ${SUDOERS_DROPIN}"
        return 1
    fi
    return 0
}

# STEP 1 wrapper: a drop-in that survives stops the teardown BEFORE the PAM
# gate is touched; the daemon stays enabled and keeps running behind both
# (the enable also undoes a disable an earlier, interrupted run left).
remove_sudoers_dropin_or_stop() {
    if ! remove_sudoers_dropin
    then
        log_error "Stopping here: sudo_local stays wired and ${DAEMON_LABEL} stays enabled (the PAM gate must outlive the drop-in)."
        reenable_daemon
        exit 1
    fi
}

# The re-checks after the bootout and after --demote-jit: the PAM gate is
# already gone, so the teardown continues, loudly, and the script exits 1 at
# the end.
recheck_sudoers_dropin() {
    if ! remove_sudoers_dropin
    then
        DROPIN_SURVIVED=1
    fi
}

# STEP 2 — unwire /etc/pam.d/sudo_local. MUST run BEFORE the PAM module is
# deleted — pam_serberus is wired as a `requisite` auth line, and a surviving
# reference to a deleted module dlopen-fails inside sudo and bricks it for
# everyone (bypass users included; they are only evaluated once the module
# loads). Marker-aware: only Serberus-managed lines are stripped (legacy
# bare-name and absolute-path forms); user PAM lines such as pam_tid.so are
# preserved, and the file is deleted only when Serberus created it and no
# active line remains. Apple-owned /etc/pam.d/sudo is never touched.
# On failure the daemon is re-enabled (it is still running — the bootout has
# not happened) and the teardown stops, so sudo keeps a live daemon behind it.
unwire_sudo_local() {
    if [[ ! -e "${SUDO_LOCAL}" ]]
    then
        return 0
    fi

    local result
    if source_pam_lib_if_present
    then
        result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    else
        log_info "No pam-lib.sh found — using the built-in marker-aware fallback"
        result=$(fallback_remove_sudo_local) || result="FAILED"
    fi
    log_info "sudo_local unwire: ${result} (${SUDO_LOCAL})"

    # Never delete the module (or stop the daemon) while an ACTIVE reference remains.
    if "${GREP}" -Eq '^[^#]*pam_serberus\.so' "${SUDO_LOCAL}" 2>/dev/null
    then
        log_error "An active pam_serberus.so line remains in ${SUDO_LOCAL} —"
        log_error "stopping here: the daemon stays enabled and running, and the module is kept"
        log_error "(a dangling reference, or a wired module with no daemon, denies every sudo)."
        reenable_daemon
        exit 1
    fi
}

# STEP 7 — files. The module goes only after STEP 2 verified no reference.
remove_components() {
    remove_component "${PAM_MODULE}"
    remove_component "${PAM_MODULE_VERSIONED}"
    remove_component "${PAM_MODULE_LEGACY}"
    remove_component "${LAUNCHD_PLIST}"
    remove_component "${CLI_BINARY}"
    remove_component "${DAEMON_BINARY_FLAT}"
    remove_component "${DAEMON_BUNDLE}"
    remove_component "${SENTINEL_APP}"
}

# This package's own tools in the support folder: uninstall.sh (this script,
# already read by bash) and pam-lib.sh, which stays while another package's
# uninstall helper (uninstall-*.sh) may still source it.
remove_own_tools() {
    remove_component "${SUPPORT_DIR}/uninstall.sh"
    local -a helpers=()
    shopt -s nullglob
    helpers=("${SUPPORT_DIR}"/uninstall-*.sh)
    shopt -u nullglob
    if [[ "${#helpers[@]}" -eq 0 ]]
    then
        remove_component "${SUPPORT_DIR}/pam-lib.sh"
    else
        log_info "Keeping ${SUPPORT_DIR}/pam-lib.sh — ${helpers[0]} may still use it"
    fi
}

forget_receipts() {
    local receipt
    for receipt in "${RECEIPTS[@]}"
    do
        if "${PKGUTIL}" --pkg-info "${receipt}" >/dev/null 2>&1
        then
            log_info "Forgetting receipt ${receipt}"
            "${PKGUTIL}" --forget "${receipt}" >/dev/null 2>&1 || true
        fi
    done
}

# --purge: data only — state, grants, caches, logs, keychain items (pam-lib.sh
# serberus_purge_support_data, or the same rule inline). Apps (*.app), the
# uninstall helpers, pam-lib.sh and the install-marker directory in the
# support folder belong to other packages and are kept. When the
# AuthorizationDB restore failed, authdb-backups (the only copy of the native
# rights) is kept too.
purge_data() {
    log_warn "Purging data: state, grants, caches, logs, and keychain items (apps and helpers are kept)"
    local keep_backups=1
    if [[ "${AUTHDB_RESTORE_OK}" -eq 1 ]]
    then
        keep_backups=0
    fi
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        local removed
        while IFS= read -r removed
        do
            [[ -n "${removed}" ]] && log_info "Removed ${removed}"
        done < <(serberus_purge_support_data "${SUPPORT_DIR}" "${keep_backups}")
    elif [[ -d "${SUPPORT_DIR}" && ! -L "${SUPPORT_DIR}" ]]
    then
        local entry
        local -a entries=()
        shopt -s nullglob dotglob
        entries=("${SUPPORT_DIR}"/*)
        shopt -u nullglob dotglob
        # ${entries[@]+…}: bash 3.2 treats an empty array as unset under set -u.
        for entry in ${entries[@]+"${entries[@]}"}
        do
            case "${entry##*/}" in
                *.app | uninstall*.sh | pam-lib.sh | .install-markers)
                    continue
                    ;;
                authdb-backups)
                    [[ "${keep_backups}" -eq 1 ]] && continue
                    ;;
            esac
            remove_component "${entry}"
        done
    fi
    if [[ "${keep_backups}" -eq 1 && -e "${AUTHDB_BACKUPS}" ]]
    then
        log_warn "Kept ${AUTHDB_BACKUPS} — the AuthorizationDB restore did not succeed."
    fi
    remove_component "${LOG_DIR}"

    local account
    for account in log-hmac-key grants-hmac-key
    do
        "${SECURITY}" delete-generic-password -a "${account}" -s "${KEYCHAIN_SERVICE}" \
            "${SYSTEM_KEYCHAIN}" >/dev/null 2>&1 || true
    done
    while "${SECURITY}" delete-generic-password -s "${KEYCHAIN_SERVICE}" \
        "${SYSTEM_KEYCHAIN}" >/dev/null 2>&1
    do
        : # keep deleting until none remain
    done
}

##################################
### End User Defined Functions ###
##################################
###################################################################################
############## End Function Block #################################################
###################################################################################

#####################################################
################## Run Script Block #################
#####################################################

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting"

require_root
# Load the marker-aware logic up front (when a trusted copy exists) so the
# EXIT trap and the bounded one-shots can use it.
source_pam_lib_if_present || log_info "No trusted pam-lib.sh — using the built-in fallbacks"
trap on_exit EXIT

# ORDER (see the header): drop-in -> unwire -> disable -> bootout (wait until
# gone) -> drop-in re-check -> demote JIT -> drop-in re-check -> restore
# authdb -> plugin (only if restored) -> files -> receipts. The coarse drop-in
# goes before the fine PAM gate so the allowlist is never stranded
# (fail-open); sudo_local is unwired while the daemon still runs and is still
# enabled, so a failed or interrupted unwire never leaves sudo wired to a
# module with no daemon behind it.
remove_sudoers_dropin_or_stop
unwire_sudo_local
disable_daemon
bootout_daemon
recheck_sudoers_dropin
demote_jit_admins
recheck_sudoers_dropin
restore_authorization_db
remove_auth_plugin_if_restored
remove_components
forget_receipts

# Apple-owned /etc/pam.d/sudo is never touched.

if [[ "${PURGE}" == "--purge" ]]
then
    purge_data
    remove_own_tools
else
    log_info "Preserved state, grants, and logs under ${SUPPORT_DIR} (pass --purge to remove)"
fi

UNINSTALL_SUCCEEDED=1
if [[ "${DROPIN_SURVIVED}" -eq 1 ]]
then
    log_error "${SCRIPT_NAME} finished, but ${SUDOERS_DROPIN} is still present — remove it by hand."
    exit 1
fi
log_info "${SCRIPT_NAME} completed successfully"
exit 0

###########################################################
################## End Script Block #######################
###########################################################
