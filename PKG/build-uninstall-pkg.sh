#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-uninstall-pkg.sh
# Author: Heath Jones
# Date: 2026-08-21
# Modified: 2026-09-26
# Purpose: Build a SELF-CONTAINED "nuke everything" uninstaller —
#          SerberusUninstall-<v>.pkg — so a test machine can be wiped clean
#          (then reinstalled fresh) with a single Jamf policy / double-click.
#          It is a --nopayload pkg: all the work is in its postinstall, which
#          runs as root at install time and does the FULL, SAFE teardown:
#            1. stop the GUI (menu bar agent, Guardian, election agent — in
#               EVERY logged-in GUI session — and the apps)
#            2. remove the coarse /etc/sudoers.d/serberus drop-in
#            3. unwire the Serberus line from /etc/pam.d/sudo_local — if a
#               line survives, keep the daemon enabled and STOP (sudo keeps a
#               live daemon behind its module)
#            4. launchctl disable the daemon (no reboot relaunch)
#            5. launchctl bootout and wait until launchd has dropped the job,
#               then re-check the drop-in (the daemon could rewrite it until
#               it stopped)
#            6. <daemon> --demote-jit (production bundle or flat test binary;
#               bounded; loud but non-fatal on failure), then the drop-in
#               once more (a surviving drop-in makes the pkg exit 1)
#            7. <daemon> --restore-authdb (whichever binary exists; bounded)
#            8. remove the SerberusAuth plugin + authdb-backups ONLY if (7)
#               succeeded AND the live AuthorizationDB no longer references
#               Serberus — composed rights still reference the plugin
#            9. remove the module (and any stray pam_serberus.so.2), plist,
#               CLI, flat daemon binary and bundle
#           10. remove the GUI apps, LaunchAgents, Finder extension
#               registration, support dir, logs, transient files, keychain
#               items and the Sentinel's per-user files
#               (symlink/ownership-checked), then forget every endpoint
#               receipt
#          Commander (the admin console) is never touched: not its app, its
#          receipt, its uninstall helper, or the policy library in each
#          user's ~/Library/Application Support/Serberus.
#          SAFETY: the sudo_local / sudoers surgery uses the SAME tested
#          functions the install path uses — pam-lib.sh is shipped INSIDE this
#          pkg (next to the postinstall) and sourced, so this does not depend on
#          any on-disk helper still being present and never hand-rolls the
#          dangerous PAM/sudo edits. PKG/verify-uninstall.sh audits the result.
# Version: 1.5 - Generated postinstall: removes every endpoint component
#          and never Commander (its receipt, uninstall helper, relaunch
#          marker, Jamf receipt stub and per-user policy library stay); per
#          user, only the Sentinel's files are deleted. The plugin gate is
#          pam-lib.sh 1.8's (no pending .json, .branches or .projection
#          record, no composition row invoking SerberusAuth, no right
#          delegating to one; a .standin never blocks); the post-bootout wait is
#          ExitTimeOut plus 5 s; a daemon with no recorded or module team is
#          not run.
#          1.4 - Generated postinstall: the disable comes after the unwire;
#          the one-shots run only once launchd has dropped the booted-out
#          job and pin the daemon to the team recorded in version.plist; a
#          drop-in that survives a re-check makes the pkg exit 1; a stray
#          pam_serberus.so.2 is removed; per-user caches are found through
#          the account records.
#          1.3 - Generated postinstall: a daemon binary runs (--demote-jit,
#          --restore-authdb) only after pam-lib serberus_daemon_trusted
#          passes, otherwise the manual steps are logged; --demote-jit exit 3
#          (no grant store) is informational; a sudoers drop-in that survives
#          its removal stops the teardown before sudo_local is unwired; the
#          per-user cache purge runs AS the user (sudo -u), after the
#          symlink/owner checks.
#          1.2 - Generated postinstall: umask 022; EXIT trap keeps the daemon
#          enabled while sudo_local is still wired; refuses a target volume
#          other than "/" ($3); bounded one-shots; plugin removal also needs a
#          clean live AuthorizationDB; LaunchAgents booted out of every
#          logged-in GUI session, not just the console user's (Guardian is
#          KeepAlive and respawned elsewhere). Builder: house layout, absolute
#          tool paths, multi-line functions.
#          1.1 - New teardown order (disable -> drop-in -> unwire -> bootout
#          -> demote JIT -> restore authdb -> plugin only if restored ->
#          files). The restore and demote try the flat test-ring binary too
#          (the old comment claiming it never exists was wrong: every test
#          ring installs it). Also removes the CLI and the flat binary,
#          forgets the production receipt, keeps authdb-backups when the
#          restore fails, refuses per-user deletes through symlinks or
#          foreign-owned directories, and cleans the root-only install-marker
#          directory with the support dir. Generated script: system-only PATH
#          and absolute tools. New --emit-scripts <dir> mode for the shell
#          tests.
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER unless you only need an unsigned pkg):
#
#   ./PKG/build-uninstall-pkg.sh
#   INSTALLER_IDENTITY="Developer ID Installer: Your Name (YOURTEAMID)" ./PKG/build-uninstall-pkg.sh
#   ./PKG/build-uninstall-pkg.sh --emit-scripts <dir>   # write the scripts only (tests)
#
# Optional env:
#   INSTALLER_IDENTITY   sign the .pkg (Jamf policy installs accept unsigned).
#   PKG_VERSION          package version (default 1.0).
#
# Deploy: install SerberusUninstall-<v>.pkg (Jamf policy or double-click), then
# reinstall SerberusTest-<v>.pkg (or the production package) clean. The uninstaller carries NO payload, so its
# own receipt is harmless; it also forgets itself best-effort.

####################################################################
############## Begin Define Variables Block ########################
####################################################################
##############################
### Core Defined Variables ###
### MODIFY AT YOUR OWN RISK ##
##############################

set -euo pipefail

# System directories only; every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly BASENAME="/usr/bin/basename"
readonly BASH_BIN="/bin/bash"
readonly CAT="/bin/cat"
readonly CHMOD="/bin/chmod"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly MKDIR="/bin/mkdir"
readonly PKGBUILD="/usr/bin/pkgbuild"
readonly PRODUCTSIGN="/usr/bin/productsign"
readonly RM="/bin/rm"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.5"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly PAM_LIB_SRC="${REPO_DIR}/PKG/Scripts/pam-lib.sh"

readonly PKG_IDENTIFIER="${ORG_PLIST_DOMAIN}.uninstalltestpkg"
readonly PKG_VERSION="${PKG_VERSION:-1.0}"

readonly MODE="${1:---build}"
readonly EMIT_DIR="${2:-}"

readonly BUILD_DIR="${SCRIPT_DIR}/build-test/uninstall"
if [[ "${MODE}" == "--emit-scripts" && -n "${EMIT_DIR}" ]]
then
    readonly STAGING_DIR="${EMIT_DIR}"
else
    readonly STAGING_DIR="${SERBERUS_PKG_STAGING:-${HOME}/Library/Caches/${ORG_PLIST_DOMAIN}/pkg-uninstall}"
fi
readonly SCRIPTS_DIR="${STAGING_DIR}/scripts"
readonly OUTPUT_PKG="${BUILD_DIR}/SerberusUninstall-${PKG_VERSION}.pkg"
readonly SIGNED_PKG="${BUILD_DIR}/SerberusUninstall-${PKG_VERSION}-signed.pkg"

readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"

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
    printf '[INFO] %s\n' "$*"
}

log_error() {
    printf '[ERROR] %s\n' "$*" >&2
}

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

verify_inputs() {
    if [[ ! -f "${PAM_LIB_SRC}" ]]
    then
        log_error "Missing ${PAM_LIB_SRC} — the uninstaller ships it for the safe sudo_local un-wiring."
        exit 1
    fi
}

# The pam-lib.sh library ships alongside the postinstall so the teardown sources
# the SAME tested sudo_local / sudoers functions the installer uses.
stage_pam_lib() {
    "${CP}" "${PAM_LIB_SRC}" "${SCRIPTS_DIR}/pam-lib.sh"
    "${CHMOD}" 644 "${SCRIPTS_DIR}/pam-lib.sh"
}

write_postinstall() {
    "${CAT}" > "${SCRIPTS_DIR}/postinstall" <<'POSTINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: postinstall (SerberusUninstall)
# Author: Heath Jones
# Date: 2026-08-21
# Modified: 2026-09-26
# Purpose: Serberus FULL UNINSTALL — runs as root at pkg-install time.
#          Best-effort by design (no `set -e`): a teardown must not abort and
#          strand a half-removed machine. The hard ordering rules are
#          enforced explicitly: the coarse sudoers drop-in goes before
#          sudo_local is unwired, sudo_local is unwired (and verified) before
#          the daemon is disabled and stopped or the module is deleted, JIT
#          admins are demoted and the AuthorizationDB restored only once
#          launchd has dropped the booted-out daemon, and the SerberusAuth
#          plugin is deleted only after a SUCCESSFUL restore that leaves no
#          right referencing Serberus in the live AuthorizationDB. An EXIT
#          trap keeps the daemon enabled while sudo_local is still wired. A
#          drop-in that survives a re-check after the bootout does not stop
#          the teardown, but the pkg then fails (exit 1).
# Version: 2.4 - (a) Commander is never removed: its receipt, its
#          uninstall helper and relaunch marker in the support folder, its Jamf
#          receipt stub and its policy library in each user's
#          ~/Library/Application Support/Serberus all stay; per user only the
#          Sentinel's files go. (b) The plugin gate no longer trusts a
#          comment (pam-lib.sh 1.8), and with no daemon only pending .json,
#          .branches or .projection records (not a .standin) mean there is
#          something to restore. (c) The post-bootout wait is the
#          daemon's ExitTimeOut plus 5 s. (d) A daemon with no recorded or
#          module team is not run.
#          2.3 - (a) The daemon is disabled after sudo_local is unwired,
#          right before the bootout, so an interrupted run never leaves
#          sudo_local wired behind a disabled daemon. (b) After the bootout
#          the script waits (up to the daemon's 20 s ExitTimeOut) until
#          launchd has dropped the job; if it is still loaded no one-shot
#          runs and the manual steps are logged. (c) The daemon is pinned to
#          the Team ID the install recorded in version.plist. (d) The drop-in
#          is re-checked after --demote-jit too; one that survives makes the
#          pkg exit 1. (e) Also removes a stray
#          /usr/local/lib/pam/pam_serberus.so.2. (f) Per-user caches are
#          found through the account records (short name and home), not the
#          names of the folders under /Users.
#          2.2 - The daemon is executed only when serberus_daemon_trusted
#          passes (strict signature, Apple anchor, identifier, pinned team);
#          otherwise the manual steps are logged. --demote-jit exit 3 (no
#          grant store) is informational. A surviving sudoers drop-in stops
#          the teardown before sudo_local is unwired. Per-user caches are
#          removed as their owner, not as root.
#          2.1 - umask 022; EXIT trap re-arms the daemon while sudo_local is
#          still wired; refuses a target volume other than "/" ($3); bounded
#          one-shots (a timeout is a loud failure); plugin removal gated on a
#          clean live AuthorizationDB; LaunchAgents booted out of EVERY
#          logged-in GUI session.
#          2.0 - Teardown order above; demote/restore try both daemon
#          binaries; CLI + flat binary removed; symlink/owner-checked
#          per-user purge; system-only PATH and absolute tools.
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

####################################################################
############## Begin Define Variables Block ########################
####################################################################

set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly AWK="/usr/bin/awk"
readonly DIRNAME="/usr/bin/dirname"
readonly ID="/usr/bin/id"
readonly KILLALL="/usr/bin/killall"
readonly LAUNCHCTL="/bin/launchctl"
readonly LS="/bin/ls"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly PKILL="/usr/bin/pkill"
readonly PLUGINKIT="/usr/bin/pluginkit"
readonly PS="/bin/ps"
readonly RM="/bin/rm"
readonly RMDIR="/bin/rmdir"
readonly DSCL="/usr/bin/dscl"
readonly SCUTIL="/usr/sbin/scutil"
readonly SECURITY="/usr/bin/security"
readonly SORT="/usr/bin/sort"
readonly STAT="/usr/bin/stat"
readonly SUDO="/usr/bin/sudo"

SCRIPT_DIR="$("${DIRNAME}" "$0")"
readonly SCRIPT_DIR
readonly PAM_LIB_PATH="${SCRIPT_DIR}/pam-lib.sh"

readonly ORG="com.herojoneslabs.serberus"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly AUTHDB_BACKUPS="${SUPPORT_DIR}/authdb-backups"
readonly LOG_DIR="/Library/Logs/Serberus"
# Production installs the daemon as an app BUNDLE (it carries the ES
# provisioning profile); every test ring installs a FLAT binary at
# DAEMON_BINARY_FLAT. Either may be present, so both are tried and removed.
readonly DAEMON_BUNDLE="/Library/PrivilegedHelperTools/serberusd.app"
readonly DAEMON_BINARY="${DAEMON_BUNDLE}/Contents/MacOS/${ORG}.daemon"
readonly DAEMON_BINARY_FLAT="/Library/PrivilegedHelperTools/${ORG}.daemon"
readonly AUTH_PLUGIN="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
readonly DAEMON_PLIST="/Library/LaunchDaemons/${ORG}.daemon.plist"
readonly DAEMON_LABEL="${ORG}.daemon"
readonly CLI_BINARY="/usr/local/bin/serberus"
readonly AGENT_PLIST="/Library/LaunchAgents/${ORG}.sentinel.plist"
readonly AGENT_LABEL="${ORG}.sentinel"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"
readonly PAM_MODULE="/usr/local/lib/pam/pam_serberus.so"
readonly PAM_MODULE_LEGACY="/usr/lib/pam/pam_serberus.so"
readonly FULLAPP="/Applications/Serberus Sentinel.app"
readonly FULLAPP_OLD="/Applications/SerberusSentinel.app"
readonly FULLAPP_STRAY="/Applications/Serberus Sentinel"
readonly AGENT_APP="${SUPPORT_DIR}/Serberus Sentinel Agent.app"
readonly AGENT_APP_OLD="${SUPPORT_DIR}/SerberusSentinelAgent.app"
# Guardian (invisible watchdog): app under SUPPORT_DIR (removed with it) + its own
# LaunchAgent. KeepAlive=true, so it MUST be booted out or it relaunches forever.
readonly GUARDIAN_LABEL="${ORG}.guardian"
readonly GUARDIAN_PLIST="/Library/LaunchAgents/${ORG}.guardian.plist"
readonly GUARDIAN_APP="${SUPPORT_DIR}/Serberus Guardian.app"
# Finder-extension election LaunchAgent (per-user login helper).
readonly ELECT_LABEL="${ORG}.finderext-elect"
readonly ELECT_PLIST="/Library/LaunchAgents/${ORG}.finderext-elect.plist"
# Finder Sync extension bundle id (embedded in the full app; removed with it).
readonly FINDER_EXT_ID="${ORG}.intel.finderext"
# Commander's files, which this package never touches: its uninstall helper
# in the support folder, its relaunch marker in the install-marker directory
# and its library in each user's ~/Library/Application Support/Serberus.
readonly COMMANDER_HELPER="${SUPPORT_DIR}/uninstall-serberus-commander.sh"
readonly INSTALL_MARKER_DIR="${SUPPORT_DIR}/.install-markers"
readonly COMMANDER_MARKER="${INSTALL_MARKER_DIR}/commander-relaunch"
# The Sentinel's own per-user files (SentinelRulesStore,
# ElevationHistoryStore, SentinelRouteHandoff, JamfUploadLedger). Commander's
# policies.json and capture-reviews.json share the folder and stay.
readonly SENTINEL_USER_FILES=(
    "rules-cache.json"
    "elevation-history.json"
    "pending-route"
    "jamf-uploads.json"
)
# System-keychain items the daemon created (HMAC signing keys).
readonly KEYCHAIN_SERVICE="${ORG}.daemon"
readonly SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"

# Every receipt an endpoint Serberus build script registers (grep PKG/*.sh
# for PKG_IDENTIFIER / *_RECEIPT / PRODUCT_ID), production included.
# Commander's (…commanderpkg) is deliberately absent: the admin console is
# not part of the endpoint, and this package never removes it.
readonly RECEIPTS=(
    "${ORG}.pkg"
    "${ORG}.sentineltestpkg"
    "${ORG}.pamtestpkg"
    "${ORG}.testpkg"
    "${ORG}.sentinelapptestpkg"
    "${ORG}.combined"
    "${ORG}.coretestpkg"
    "${ORG}.uninstalltestpkg"
)

# Hard deadline for each daemon one-shot (--demote-jit, --restore-authdb).
readonly ONESHOT_TIMEOUT=120

# Installer passes the target volume as $3.
readonly TARGET_VOLUME="${3:-}"

# Set to 1 by restore_authorization_db once the AuthorizationDB is known to be
# native again; it GATES deleting the plugin and the authdb backups.
AUTHDB_RESTORE_OK=0
CONSOLE_UID=""
# Every uid with a logged-in GUI session (fast user switching included).
GUI_UIDS=()
# Success marker; without it the EXIT trap keeps the daemon enabled behind a
# wired sudo_local.
UNINSTALL_SUCCEEDED=0
# Set when the drop-in is still present at a re-check after the bootout; the
# teardown finishes but the pkg exits 1.
DROPIN_SURVIVED=0
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut;
# no one-shot runs beside it (manual steps are logged instead).
DAEMON_GONE=1

####################################################################
############## End Define Variables Block ##########################
####################################################################

###################################################################################
############## Begin Function Block ###############################################
###################################################################################

log() {
    /usr/bin/printf '[uninstall] %s\n' "$*"
}

log_error() {
    /usr/bin/printf '[uninstall] ERROR: %s\n' "$*" >&2
}

# Serberus lives on the running system; an uninstall aimed at another volume
# would tear down THIS Mac's sudo gate by mistake.
require_boot_volume() {
    if [[ "${TARGET_VOLUME}" != "/" ]]
    then
        log_error "Target volume is '${TARGET_VOLUME}', not '/'. Run the uninstaller against the running system."
        exit 1
    fi
}

# EXIT trap: stopping early must never leave sudo_local wired behind a
# disabled or unloaded daemon.
on_exit() {
    local status=$?
    if [[ "${UNINSTALL_SUCCEEDED}" -eq 1 ]]
    then
        return 0
    fi
    if ! serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${DAEMON_PLIST}"
    then
        log_error "stopped early (status ${status}) with ${SUDO_LOCAL} still wired — ${DAEMON_LABEL} kept enabled"
    fi
    exit "${status}"
}

# The safety-critical sudo_local / sudoers functions (same code as the
# installer). Without them nothing is touched: hand-rolled PAM edits are how
# sudo gets bricked.
source_pam_lib() {
    if [[ ! -f "${PAM_LIB_PATH}" ]]
    then
        log_error "${PAM_LIB_PATH} missing from the pkg — refusing to touch sudo configuration."
        exit 1
    fi
    # shellcheck disable=SC1090
    source "${PAM_LIB_PATH}"
}

resolve_console_uid() {
    local console_user
    # shellcheck disable=SC2016 — $3 is awk's field, not a shell variable
    console_user=$("${SCUTIL}" <<< "show State:/Users/ConsoleUser" | "${AWK}" '/Name :/ && $3 != "loginwindow" { print $3 }')
    if [[ -n "${console_user}" ]]
    then
        CONSOLE_UID=$("${ID}" -u "${console_user}" 2>/dev/null || printf '')
    fi
}

# Every logged-in GUI session has its own loginwindow running as that user
# (the login screen's runs as root), so the non-root loginwindow owners are
# exactly the gui/<uid> domains the LaunchAgents can live in — background
# fast-user-switching sessions included. The console user is added in case
# ps misses it.
resolve_gui_uids() {
    local uid
    GUI_UIDS=()
    while IFS= read -r uid
    do
        if [[ "${uid}" =~ ^[0-9]+$ && "${uid}" -gt 0 ]]
        then
            GUI_UIDS+=("${uid}")
        fi
    done < <({
        "${PS}" -axo uid=,comm= 2>/dev/null | "${AWK}" '$2 ~ /\/loginwindow$/ { print $1 }'
        printf '%s\n' "${CONSOLE_UID}"
    } | "${SORT}" -un)
}

# --- stop the GUI (menu bar agent + guardian + election agent + apps) ---
stop_gui() {
    local uid
    # ${GUI_UIDS[@]+…}: bash 3.2 treats an empty array as unset under set -u.
    for uid in ${GUI_UIDS[@]+"${GUI_UIDS[@]}"}
    do
        "${LAUNCHCTL}" bootout "gui/${uid}/${AGENT_LABEL}" 2>/dev/null || true
        # Guardian is KeepAlive=true — boot it out of EVERY session, or it
        # respawns in the ones left behind.
        "${LAUNCHCTL}" bootout "gui/${uid}/${GUARDIAN_LABEL}" 2>/dev/null || true
        "${LAUNCHCTL}" bootout "gui/${uid}/${ELECT_LABEL}" 2>/dev/null || true
        # Deregister the Finder Sync extension (best-effort; it goes away with the app).
        "${LAUNCHCTL}" asuser "${uid}" "${PLUGINKIT}" -e ignore -i "${FINDER_EXT_ID}" 2>/dev/null || true
    done
    local macos
    for macos in \
        "${FULLAPP}/Contents/MacOS/" \
        "${FULLAPP_OLD}/Contents/MacOS/" \
        "${AGENT_APP}/Contents/MacOS/" \
        "${AGENT_APP_OLD}/Contents/MacOS/" \
        "${GUARDIAN_APP}/Contents/MacOS/"
    do
        "${PKILL}" -f "^${macos//./\\.}" 2>/dev/null || true
    done
}

# --- disable only once sudo_local is unwired, right before the bootout: a
# reboot must not relaunch the daemon, and an interrupted run must never leave
# sudo_local wired behind a disabled daemon. A later install re-enables the
# label. ---
disable_daemon() {
    "${LAUNCHCTL}" disable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log "WARNING: launchctl disable system/${DAEMON_LABEL} failed"
}

# Routes serberus_daemon_manual_steps into the log. $1 demote | restore | sudoers
log_manual_steps() {
    local line
    while IFS= read -r line
    do
        log_error "${line}"
    done < <(serberus_daemon_manual_steps "$1" "${AUTHDB_BACKUPS}")
}

# --- coarse sudoers drop-in (marker-guarded, single exact path). Called again
# after the bootout: the still-running daemon could rewrite it until then.
# Returns 1 when the drop-in is STILL there after the rm. ---
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log "sudoers drop-in: ${result}"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        log_manual_steps sudoers
        return 1
    fi
    return 0
}

# First removal: a surviving drop-in STOPS the teardown before sudo_local is
# unwired — the PAM gate must outlive the drop-in. The daemon stays enabled
# and keeps running behind both.
remove_sudoers_dropin_or_stop() {
    if ! remove_sudoers_dropin
    then
        log_error "STOPPING: sudo_local stays wired and ${DAEMON_LABEL} stays enabled. Run this uninstaller again once the drop-in is gone."
        "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null || true
        exit 1
    fi
}

# The re-checks after the bootout and after --demote-jit: the PAM gate is
# already gone, so the teardown continues, loudly, and the pkg exits 1.
recheck_sudoers_dropin() {
    if ! remove_sudoers_dropin
    then
        log_error "the drop-in outlived the PAM gate — remove it by hand"
        DROPIN_SURVIVED=1
    fi
}

# --- unwire sudo_local BEFORE the daemon stops or the module is deleted. If
# an active line survives, STOP: keep the (still running) daemon enabled so
# sudo keeps a live daemon behind its module, and leave the rest in place. ---
unwire_sudo_local() {
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log "sudo_local unwire: ${result}"
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_error "an active pam_serberus line still remains in ${SUDO_LOCAL}."
        log_error "STOPPING: the daemon stays enabled and running and ${PAM_MODULE} is kept"
        log_error "(a dangling reference, or a wired module with no daemon, denies every sudo)."
        log_error "Fix ${SUDO_LOCAL} by hand, then run this uninstaller again."
        "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null || true
        exit 1
    fi
}

# Bootout, then wait (up to the daemon's ExitTimeOut) until launchd has
# dropped the job: no one-shot may run beside a live daemon.
bootout_daemon() {
    if ! "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        return 0
    fi
    "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
    if ! serberus_launchd_wait_gone "${DAEMON_LABEL}"
    then
        DAEMON_GONE=0
        log_error "${DAEMON_LABEL} is still loaded after its bootout — no daemon one-shot will run"
    fi
}

# serberus_daemon_trusted with the team the install recorded in version.plist
# (falls back to the installed module's team; with neither, the daemon is
# refused). $1 daemon path.
daemon_trusted() {
    local team
    team=$(serberus_recorded_team 2>/dev/null) || team=""
    serberus_daemon_trusted "$1" "${team}"
}

# --- demote every JIT admin in the grant store (after the bootout, before any
# file is removed). A binary runs only when serberus_daemon_trusted passes.
# Non-fatal, but LOUD: they would stay admins forever. Exit 3 = no grant
# store, nothing to demote. ---
demote_jit_admins() {
    local candidate
    local status
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_manual_steps demote
        return 0
    fi
    for candidate in "${DAEMON_BINARY}" "${DAEMON_BINARY_FLAT}"
    do
        if [[ ! -x "${candidate}" ]]
        then
            continue
        fi
        if ! daemon_trusted "${candidate}"
        then
            log_error "${candidate} failed its signature check — NOT executing it for --demote-jit"
            continue
        fi
        status=0
        serberus_run_bounded "${ONESHOT_TIMEOUT}" "${candidate}" --demote-jit || status=$?
        case "${status}" in
            0)
                log "JIT admins demoted (${candidate})"
                return 0
                ;;
            3)
                log "no grant store — no JIT admins to demote (${candidate})"
                return 0
                ;;
        esac
        log_error "--demote-jit FAILED via ${candidate} (exit ${status}; 124 = timed out)"
    done
    log_error "!!! JIT admins could NOT be demoted."
    log_manual_steps demote
    return 0
}

# --- restore the AuthorizationDB (undo authURI rewrites) with whichever daemon
# binary exists. AUTHDB_RESTORE_OK=1 only when the db is known native again. ---
restore_authorization_db() {
    local binary=""
    local candidate
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_manual_steps restore
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
        log_error "${candidate} failed its signature check — NOT executing it for --restore-authdb"
    done
    if [[ -z "${binary}" ]]
    then
        # Pending records (.json, .branches, .projection) mean there is
        # something to restore; a .standin alone does not.
        if serberus_authdb_records_pending "${AUTHDB_BACKUPS}" > /dev/null
        then
            log_error "authdb backups exist but no trusted daemon binary can restore them"
            log_manual_steps restore
        else
            log "no daemon binary and no pending authdb records — nothing to restore"
            if serberus_authdb_free_of_serberus
            then
                AUTHDB_RESTORE_OK=1
            fi
        fi
        return 0
    fi
    local status=0
    serberus_run_bounded "${ONESHOT_TIMEOUT}" "${binary}" --restore-authdb || status=$?
    if [[ "${status}" -ne 0 ]]
    then
        log_error "authdb restore FAILED (exit ${status}; 124 = timed out) — inspect ${AUTHDB_BACKUPS}/*.json"
        log_manual_steps restore
        return 0
    fi
    log "AuthorizationDB rights restored from snapshots (${binary})"
    # Exit 0 is necessary but not sufficient: the live database must no
    # longer reference Serberus before the plugin may go.
    if serberus_authdb_free_of_serberus
    then
        AUTHDB_RESTORE_OK=1
    else
        log_error "the restore exited 0 but the AuthorizationDB still references Serberus — keeping the plugin and backups"
    fi
}

# --- ORDER IS LOAD-BEARING: the plugin (and the backups, the only record of
# the native rights) go only after a SUCCESSFUL restore. A right still naming
# "SerberusAuth:identity" with the bundle gone cannot be evaluated. ---
remove_auth_plugin_if_restored() {
    if [[ "${AUTHDB_RESTORE_OK}" -ne 1 ]]
    then
        log_error "KEEPING ${AUTH_PLUGIN} and ${AUTHDB_BACKUPS}: the restore did not succeed and"
        log_error "composed rights still reference the plugin."
        return 0
    fi
    if [[ -d "${AUTH_PLUGIN}" ]]
    then
        "${RM}" -rf "${AUTH_PLUGIN}"
        "${KILLALL}" SecurityAgent authorizationhost 2>/dev/null || true
        log "removed authorization plugin ${AUTH_PLUGIN}"
    fi
    "${RM}" -rf "${AUTHDB_BACKUPS}"
}

# --- module (sudo_local verified clean above), plist, CLI, both daemon forms ---
remove_daemon_files() {
    "${RM}" -f "${PAM_MODULE}" "${SERBERUS_PAM_MODULE_VERSIONED_PATH}" "${PAM_MODULE_LEGACY}"
    "${RM}" -f "${DAEMON_PLIST}" "${CLI_BINARY}" "${DAEMON_BINARY_FLAT}"
    "${RM}" -rf "${DAEMON_BUNDLE}"
    log "removed PAM module, LaunchDaemon plist, CLI and daemon"
}

# --- GUI apps + LaunchAgents + stray folder + legacy orphans ---
remove_gui() {
    "${RM}" -f "${AGENT_PLIST}" "${GUARDIAN_PLIST}" "${ELECT_PLIST}"
    "${RM}" -rf "${FULLAPP}" "${FULLAPP_OLD}" "${AGENT_APP}" "${AGENT_APP_OLD}" "${GUARDIAN_APP}"
    # The extension-less stray FOLDER: remove only when it holds a Serberus .app
    # or is empty, so a same-named folder of unrelated files is never nuked.
    if [[ -d "${FULLAPP_STRAY}" && ! -L "${FULLAPP_STRAY}" ]]
    then
        if [[ -d "${FULLAPP_STRAY}/SerberusSentinel.app" || -d "${FULLAPP_STRAY}/Serberus Sentinel.app" ]]
        then
            "${RM}" -rf "${FULLAPP_STRAY}"
        else
            "${RMDIR}" "${FULLAPP_STRAY}" 2>/dev/null || true
        fi
    fi
    # Pre-rename / pre-split app names from earlier rings (best-effort).
    local old
    for old in \
        "/Applications/SerberusIntel.app" \
        "/Applications/SerberusAgent.app" \
        "/Applications/SerberusCapture.app" \
        "/Applications/Serberus.app"
    do
        "${RM}" -rf "${old}"
    done
}

# --- support dir (incl. the root-only install-marker dir) + logs. Every
# endpoint file goes; Commander's uninstall helper and relaunch marker stay
# (the folder itself goes only once it is empty). A failed restore keeps
# authdb-backups. ---
remove_support_and_logs() {
    if [[ -d "${SUPPORT_DIR}" && ! -L "${SUPPORT_DIR}" ]]
    then
        local entry
        local -a entries=()
        shopt -s nullglob dotglob
        entries=("${SUPPORT_DIR}"/* "${INSTALL_MARKER_DIR}"/*)
        shopt -u nullglob dotglob
        # ${entries[@]+…}: bash 3.2 treats an empty array as unset under set -u.
        for entry in ${entries[@]+"${entries[@]}"}
        do
            case "${entry}" in
                "${COMMANDER_HELPER}" | "${COMMANDER_MARKER}")
                    continue
                    ;;
                "${INSTALL_MARKER_DIR}")
                    if [[ ! -L "${INSTALL_MARKER_DIR}" ]]
                    then
                        continue
                    fi
                    ;;
                "${AUTHDB_BACKUPS}")
                    if [[ "${AUTHDB_RESTORE_OK}" -ne 1 ]]
                    then
                        continue
                    fi
                    ;;
            esac
            "${RM}" -rf "${entry}"
        done
        "${RMDIR}" "${INSTALL_MARKER_DIR}" 2>/dev/null || true
        "${RMDIR}" "${SUPPORT_DIR}" 2>/dev/null || true
        if [[ "${AUTHDB_RESTORE_OK}" -ne 1 && -e "${AUTHDB_BACKUPS}" ]]
        then
            log_error "kept ${AUTHDB_BACKUPS} (restore failed) — ${SUPPORT_DIR} is not fully removed"
        fi
        if [[ -e "${COMMANDER_HELPER}" ]]
        then
            log "kept Commander's ${COMMANDER_HELPER} (Commander is not removed by this package)"
        fi
    fi
    "${RM}" -rf "${LOG_DIR}"
}

# --- transient /tmp artifacts: LaunchAgent stdout/stderr and the pre-1.x
# relaunch markers (rm -f removes a symlink itself, never its target). ---
remove_transient_files() {
    "${RM}" -f /tmp/"${ORG}".*.log 2>/dev/null || true
    "${RM}" -f "/private/tmp/${ORG}.fullapp-relaunch" 2>/dev/null || true
}

# --- System-keychain items the daemon created (HMAC signing keys) ---
remove_keychain_items() {
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

# Delete the Sentinel's files (SENTINEL_USER_FILES) from
# <home>/Library/Application Support/Serberus, then the folder only if that
# leaves it empty: Commander keeps its policy library in the same folder, and
# this package never removes it. Only when every component on the way (home,
# Library, Application Support, Serberus) is a real directory, not a
# symlink, owned by the account the home belongs to — and then AS THAT USER
# (sudo -u), never as root: the checks are only a first filter, since the
# user could swap a component for a symlink between the check and the rm;
# running as the user means such a swap can only reach what the user could
# delete anyway. $1 short name, $2 home (both from the account record, so a
# renamed account or a home outside /Users is found).
purge_user_cache() {
    local user="$1"
    local home="$2"
    local uid
    uid=$("${ID}" -u "${user}" 2>/dev/null) || return 0
    local path="${home}"
    local part
    local owner
    for part in "" "Library" "Application Support" "Serberus"
    do
        if [[ -n "${part}" ]]
        then
            path="${path}/${part}"
        fi
        if [[ -L "${path}" ]]
        then
            log "skipping ${path}: it is a symlink"
            return 0
        fi
        if [[ ! -d "${path}" ]]
        then
            return 0
        fi
        owner=$("${STAT}" -f '%u' "${path}" 2>/dev/null) || return 0
        if [[ "${owner}" != "${uid}" ]]
        then
            log "skipping ${path}: owned by uid ${owner}, not ${user} (${uid})"
            return 0
        fi
    done
    if [[ "${uid}" == "0" ]]
    then
        log "skipping ${path}: root's own home is not purged"
        return 0
    fi
    local -a files=()
    local file
    for file in "${SENTINEL_USER_FILES[@]}"
    do
        files+=("${path}/${file}")
    done
    "${SUDO}" -n -u "${user}" "${RM}" -f -- "${files[@]}" 2>/dev/null \
        || log "could not remove the Sentinel's files in ${path} as ${user}"
    "${SUDO}" -n -u "${user}" "${RMDIR}" -- "${path}" 2>/dev/null || true
}

# Every local account with a home folder, by its record: short name and
# NFSHomeDirectory. Service accounts (leading "_") and homes that are not
# absolute paths (or /var/empty) are skipped.
purge_user_caches() {
    local user
    local home
    while read -r user home
    do
        if [[ -z "${user}" || "${user}" == _* ]] \
            || [[ "${home}" != /* || "${home}" == "/var/empty" ]]
        then
            continue
        fi
        purge_user_cache "${user}" "${home}"
    done < <("${DSCL}" . -list /Users NFSHomeDirectory 2>/dev/null)
}

forget_receipts() {
    local pkg
    for pkg in "${RECEIPTS[@]}"
    do
        "${PKGUTIL}" --forget "${pkg}" >/dev/null 2>&1 || true
    done
    # Jamf's own policy-install stubs (what the PACKAGE_RECEIPTS inventory
    # section reports as installedByJamfPro) survive a plain pkg uninstall and
    # would keep this Mac listed as "Serberus installed" in Commander's Fleet
    # Observer. Best effort; this uninstaller's OWN stub is written by the jamf
    # binary after this script runs, so Commander ignores receipts named
    # "*Uninstall*" as well.
    # Commander's stubs (SerberusCommander*) stay with Commander.
    local stub
    for stub in "/Library/Application Support/JAMF/Receipts/"Serberus*.pkg
    do
        case "${stub##*/}" in
            SerberusCommander*)
                continue
                ;;
        esac
        [[ -e "${stub}" || -L "${stub}" ]] && "${RM}" -f "${stub}" 2>/dev/null
    done
}

###################################################################################
############## End Function Block #################################################
###################################################################################

#####################################################
################## Run Script Block #################
#####################################################

log "Serberus uninstall starting (installer log: /var/log/install.log)"
require_boot_volume
source_pam_lib
trap on_exit EXIT
resolve_console_uid
resolve_gui_uids

stop_gui
remove_sudoers_dropin_or_stop
unwire_sudo_local
disable_daemon
bootout_daemon
recheck_sudoers_dropin
demote_jit_admins
recheck_sudoers_dropin
restore_authorization_db
remove_auth_plugin_if_restored
remove_daemon_files
remove_gui
remove_support_and_logs
remove_transient_files
remove_keychain_items
purge_user_caches
forget_receipts

UNINSTALL_SUCCEEDED=1
if [[ "${DROPIN_SURVIVED}" -eq 1 ]]
then
    log_error "Serberus removed, but ${SUDOERS_DROPIN} is still present — remove it by hand."
    exit 1
fi
log "Serberus removed. Audit with PKG/verify-uninstall.sh, then reinstall the combined pkg clean."
exit 0

###########################################################
################## End Script Block #######################
###########################################################
POSTINSTALL_EOF
    "${CHMOD}" 755 "${SCRIPTS_DIR}/postinstall"

    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/postinstall"
    then
        log_error "Generated postinstall failed bash -n"
        exit 1
    fi
}

build_pkg() {
    "${MKDIR}" -p "${BUILD_DIR}"
    "${RM}" -f "${OUTPUT_PKG}" "${SIGNED_PKG}"

    log_info "Building ${OUTPUT_PKG} (--nopayload; postinstall does the teardown)"
    "${PKGBUILD}" \
        --nopayload \
        --scripts "${SCRIPTS_DIR}" \
        --identifier "${PKG_IDENTIFIER}" \
        --version "${PKG_VERSION}" \
        "${OUTPUT_PKG}"

    if [[ -n "${INSTALLER_IDENTITY}" ]]
    then
        log_info "Signing pkg with '${INSTALLER_IDENTITY}'"
        "${PRODUCTSIGN}" --sign "${INSTALLER_IDENTITY}" "${OUTPUT_PKG}" "${SIGNED_PKG}"
    fi
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (mode ${MODE})"
case "${MODE}" in
    --emit-scripts)
        if [[ -z "${EMIT_DIR}" ]]
        then
            log_error "--emit-scripts requires a target directory"
            exit 1
        fi
        verify_inputs
        "${MKDIR}" -p "${SCRIPTS_DIR}"
        stage_pam_lib
        write_postinstall
        log_info "Scripts emitted to ${SCRIPTS_DIR}"
        exit 0
        ;;
    --build)
        ;;
    *)
        printf 'Usage: %s [--build|--emit-scripts <dir>]\n' "${SCRIPT_NAME}" >&2
        exit 1
        ;;
esac

verify_inputs
"${RM}" -rf "${STAGING_DIR}"
"${MKDIR}" -p "${SCRIPTS_DIR}"
stage_pam_lib
write_postinstall
build_pkg
log_info "Done."
log_info "  pkg: ${OUTPUT_PKG}"
if [[ -n "${INSTALLER_IDENTITY}" ]]
then
    log_info "  signed: ${SIGNED_PKG}"
fi
log_info "Install it to fully remove Serberus, then reinstall SerberusTest-<v>.pkg (or the production package) clean."

###########################################################
################## End Script Block #######################
###########################################################
