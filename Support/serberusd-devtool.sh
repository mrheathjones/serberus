#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: serberusd-devtool.sh
# Author: Heath Jones
# Date: 2026-06-13
# Modified: 2026-09-26
# Purpose: Developer install/uninstall/restart/verify tool for the Serberus
#          root LaunchDaemon (serberusd). Local Mac only — production endpoints
#          are served by the PKG installer, not this script.
# Version: 1.5 - (a) The post-bootout wait is the daemon's ExitTimeOut
#          plus 5 s (25 s). (b) --purge removes the daemon's data only
#          (pam-lib.sh serberus_purge_support_data); the apps and uninstall
#          helpers in the support folder stay. (c) The plugin gate and the
#          daemon pin are pam-lib.sh 1.8's. (d) The usage line lists --force
#          for --install and --restart.
#          1.4 - (a) After every bootout the tool waits (up to the daemon's
#          20 s ExitTimeOut) until launchd no longer lists the job; --install
#          and --restart then bootstrap, and --uninstall runs its one-shots
#          only when the job is gone. (b) The installed daemon is pinned to
#          the Team ID the last install recorded in version.plist, when there
#          is one. (c) --uninstall re-checks the drop-in after --demote-jit.
#          1.3 - (a) --install and --restart REFUSE while sudo_local has an
#          active pam_serberus line unless --force (the daemon is stopped and
#          replaced underneath a wired `requisite` module). (b) The new binary
#          is copied to a temp file in /Library/PrivilegedHelperTools, signed
#          and checked there, then moved over the live one (atomic), never
#          `cp` over the running file. (c) After the bootstrap the tool waits
#          for the daemon with pam-lib serberus_launchd_wait_running (8 s
#          stable pid, no restart, a state.plist written since the
#          bootstrap). (d) If a bootstrap fails while sudo_local is wired, the
#          EXIT trap re-arms the daemon (serberus_daemon_rearm_if_wired).
#          (e) SKIP_DAEMON_SIGN checks the prebuilt binary's identifier
#          (com.herojoneslabs.serberus.daemon) and, when DEVELOPMENT_TEAM is
#          known, its team; a mismatch is refused. (f) --demote-jit /
#          --restore-authdb run only when serberus_daemon_trusted passes;
#          --demote-jit exit 3 (no grant store) is informational. (g) A
#          sudoers drop-in that survives its removal stops --uninstall.
#          1.2 - (a) --install signs the flat daemon with an explicit
#          --identifier com.herojoneslabs.serberus.daemon (codesign would
#          otherwise derive "com.herojoneslabs.serberus" from the file name,
#          and the PAM module / Sentinel clients pin the full identifier).
#          (b) --demote-jit / --restore-authdb run with a 120 s deadline
#          (pam-lib.sh serberus_run_bounded; a timeout is a loud failure).
#          (c) --purge keeps authdb-backups when the restore failed or the
#          live AuthorizationDB still references Serberus. (d) umask 022;
#          pam-lib.sh is sourced once, up front.
#          1.1 - (a) --uninstall and --verify-cycle REFUSE while
#          /etc/pam.d/sudo_local has an active pam_serberus line (removing
#          the daemon under a wired module makes sudo fail closed for everyone
#          outside the bypass list) unless --force is given. (b) --uninstall
#          follows the shared teardown order: disable -> sudoers drop-in ->
#          bootout -> drop-in re-check -> demote JIT -> restore authdb ->
#          files. (c) --install/--restart `launchctl enable` before bootstrap
#          (an uninstall leaves the label disabled). (d) The suggested
#          xcodebuild passes CODE_SIGNING_ALLOWED=NO: Xcode would otherwise
#          sign with the ES-entitlement file, and this tool re-signs with an
#          empty entitlements file anyway (unless SKIP_DAEMON_SIGN is set).
#          (e) System-only PATH and absolute tool paths (it runs as root).
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

# System directories only: this runs as root, and /usr/local/bin can be
# user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Binary paths (absolute: nothing is resolved via PATH)
readonly BASENAME="/usr/bin/basename"
readonly CHMOD="/bin/chmod"
readonly CHOWN="/usr/sbin/chown"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DATE="/bin/date"
readonly DIRNAME="/usr/bin/dirname"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly MKDIR="/bin/mkdir"
readonly MKTEMP="/usr/bin/mktemp"
readonly MV="/bin/mv"
readonly PLUTIL="/usr/bin/plutil"
readonly RM="/bin/rm"
readonly SLEEP="/bin/sleep"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

# Org identity
readonly ORG_NAME="Serberus"
readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"

# Script metadata
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.5"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.devtool"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)

declare -a TEMP_FILES=()

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly BUNDLE_ID="com.herojoneslabs.serberus.daemon"
readonly DAEMON_LABEL="${BUNDLE_ID}"
readonly INSTALL_BINARY_PATH="/Library/PrivilegedHelperTools/${BUNDLE_ID}"
readonly PLIST_PATH="/Library/LaunchDaemons/${BUNDLE_ID}.plist"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly LOG_DIR="/Library/Logs/Serberus"
readonly STATE_PLIST="${SUPPORT_DIR}/state.plist"

# Pre-built serberusd binary. Build first (non-root) from the repo root:
#   xcodebuild -project Serberus.xcodeproj -scheme serberusd -configuration Release \
#     -derivedDataPath .build/xcode CODE_SIGNING_ALLOWED=NO build
# CODE_SIGNING_ALLOWED=NO: --install signs the binary itself (hardened
# runtime, the daemon identifier, an empty entitlements file), so Xcode's
# signature would only be replaced.
# Override with SERBERUSD_BINARY=/path ./serberusd-devtool.sh --install
readonly DEFAULT_BINARY="${SCRIPT_DIR}/../.build/xcode/Build/Products/Release/serberusd"
readonly SERBERUSD_BINARY="${SERBERUSD_BINARY:-${DEFAULT_BINARY}}"

# Ad-hoc signing ("-") is sufficient to load the daemon locally, but an
# ad-hoc daemon trusts no app caller (it has no team to pin them to). Production
# requires a Developer ID Application identity from your team, Hardened
# Runtime, the entitlements file, and notarization.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"

# Set SKIP_DAEMON_SIGN=1 to install a binary that was ALREADY signed before
# install (no re-sign). Needed for Apple Development signing: `sudo codesign`
# cannot build that cert's chain to the WWDR intermediate (it lives in the
# logging-in user's login keychain), so sign as the user first, then install.
readonly SKIP_DAEMON_SIGN="${SKIP_DAEMON_SIGN:-}"

# Teardown gates (pam-lib.sh semantics). /etc/pam.d/sudo_local wired to
# pam_serberus + no daemon = every non-bypass sudo denied, so --uninstall and
# --verify-cycle refuse while it is wired unless --force is passed.
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"
readonly PAM_LIB_SH="${SCRIPT_DIR}/../PKG/Scripts/pam-lib.sh"
readonly TEAM_ID_LIB="${SCRIPT_DIR}/team-id-lib.sh"
# Seconds to wait after a bootstrap for a running pid (the 8 s stability
# window is added on top).
readonly DAEMON_START_TIMEOUT=10
# Mirrors pam-lib.sh SERBERUS_SUDOERS_MARKER_RE — KEEP IN SYNC (fallback when
# the repo copy of pam-lib.sh is unavailable).
readonly FALLBACK_SUDOERS_MARKER_RE='^# /etc/sudoers\.d/serberus: managed by com\.herojoneslabs\.serberus'
readonly AUTH_PLUGIN="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
readonly AUTHDB_BACKUPS="${SUPPORT_DIR}/authdb-backups"
# Hard deadline for each daemon one-shot (--demote-jit, --restore-authdb).
readonly ONESHOT_TIMEOUT=120
# Seconds to wait for a booted-out daemon to leave launchd: its ExitTimeOut
# (20 s, set in the LaunchDaemon plist) plus 5 s (pam-lib.sh
# SERBERUS_DAEMON_BOOTOUT_WAIT).
readonly DAEMON_BOOTOUT_WAIT=25

# 1 once pam-lib.sh has been sourced (load_pam_lib).
PAM_LIB_LOADED=0
# Set when a bootstrap failed; the EXIT trap then re-arms a daemon that a
# still-wired sudo_local depends on.
BOOTSTRAP_FAILED=0

readonly MODE="${1:---status}"

# Flags after the mode, any order: --purge (uninstall), --force (skip the
# wired-sudo_local refusal).
PURGE_FLAG=0
FORCE_FLAG=0

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

# ── Logging ──────────────────────────────────────────────────────────────────
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

# ── Cleanup (trapped on EXIT/INT/TERM) ───────────────────────────────────────
cleanup() {
    local exit_code=$?
    local f
    for f in "${TEMP_FILES[@]:-}"
    do
        if [[ -f "${f}" ]]
        then
            "${RM}" -f "${f}"
        fi
    done
    # A failed bootstrap under a wired sudo_local leaves every non-bypass sudo
    # denied: keep the label enabled and try to load it again.
    if [[ "${BOOTSTRAP_FAILED}" -eq 1 && "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${PLIST_PATH}" || true
    fi
    exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# ── Preflight ────────────────────────────────────────────────────────────────
require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_error "Must run as root (use sudo)"
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

write_entitlements() {
    local entitlements_file
    entitlements_file=$("${MKTEMP}")
    TEMP_FILES+=("${entitlements_file}")
    "/bin/cat" > "${entitlements_file}" <<'ENTITLEMENTS_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>
ENTITLEMENTS_EOF
    printf '%s' "${entitlements_file}"
}

write_daemon_plist() {
    # Dev escape hatches (default-secure — all unset in production):
    #   SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT — accept a locally-signed Sentinel that
    #     can't embed the private entitlement without a provisioning profile.
    #   SERBERUS_DEV_KEY_FALLBACK — allow a root-only on-disk HMAC key when the
    #     System Keychain is unavailable, so grants + the signed decision log
    #     persist for local testing instead of degrading to NullGrantStore.
    local env_entries=""
    local dev_var
    for dev_var in SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT SERBERUS_DEV_KEY_FALLBACK
    do
        local value="${!dev_var:-}"
        if [[ -n "${value}" ]]
        then
            log_info "Daemon env: ${dev_var}=${value} (dev)"
            env_entries+="        <key>${dev_var}</key>"$'\n'"        <string>${value}</string>"$'\n'
        fi
    done

    local env_block=""
    if [[ -n "${env_entries}" ]]
    then
        env_block="    <key>EnvironmentVariables</key>"$'\n'"    <dict>"$'\n'"${env_entries}    </dict>"$'\n'
    fi

    "/bin/cat" > "${PLIST_PATH}" <<DAEMON_PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${DAEMON_LABEL}</string>
    <key>Program</key>
    <string>${INSTALL_BINARY_PATH}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_BINARY_PATH}</string>
    </array>
    <key>MachServices</key>
    <dict>
        <key>${BUNDLE_ID}</key>
        <true/>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>RunAtLoad</key>
    <true/>
${env_block}    <key>StandardOutPath</key>
    <string>${LOG_DIR}/daemon.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/daemon.stderr.log</string>
</dict>
</plist>
DAEMON_PLIST_EOF

    "${CHOWN}" root:wheel "${PLIST_PATH}"
    "${CHMOD}" 644 "${PLIST_PATH}"

    if ! "${PLUTIL}" -lint "${PLIST_PATH}" >/dev/null 2>&1
    then
        log_error "Generated plist failed plutil -lint: ${PLIST_PATH}"
        return 1
    fi
}

ensure_directories() {
    local dir
    for dir in "${SUPPORT_DIR}" "${LOG_DIR}" "${SUPPORT_DIR}/authdb-backups"
    do
        "${MKDIR}" -p "${dir}"
        "${CHOWN}" root:wheel "${dir}"
    done
    "${CHMOD}" 755 "${SUPPORT_DIR}"
    "${CHMOD}" 755 "${LOG_DIR}"
    "${CHMOD}" 700 "${SUPPORT_DIR}/authdb-backups"
}

# True when sudo_local has an ACTIVE (uncommented) pam_serberus line.
sudo_local_is_wired() {
    [[ -f "${SUDO_LOCAL}" ]] && "${GREP}" -Eq '^[^#]*pam_serberus\.so' "${SUDO_LOCAL}"
}

# Stopping, replacing or removing the daemon while sudo_local still loads
# pam_serberus makes sudo fail CLOSED (daemon unreachable = deny) for everyone
# outside the bypass list — for the whole restart window, or for good if the
# new daemon never comes up. Refuse unless --force.
#   $1 what is about to happen (removed | stopped and replaced | restarted)
refuse_if_sudo_wired() {
    local action="${1:-removed}"
    if ! sudo_local_is_wired
    then
        return 0
    fi
    if [[ "${FORCE_FLAG}" -eq 1 ]]
    then
        log_warn "--force: ${SUDO_LOCAL} is wired to pam_serberus and the daemon is being ${action} —"
        log_warn "every sudo outside the pamBypass list is DENIED while no daemon answers."
        return 0
    fi
    log_error "${SUDO_LOCAL} has an active pam_serberus line. With the daemon ${action} now,"
    log_error "sudo fails closed for everyone outside the pamBypass list. Unwire it first:"
    log_error "  the uninstall pkg (PKG/build-uninstall-pkg.sh) or the PAM test pkg's helper, or"
    log_error "  remove the pam_serberus line from ${SUDO_LOCAL} (Support/build-pam.sh installed it)."
    log_error "Re-run with --force to proceed anyway."
    exit 1
}

# The repo copy of the shared library (bounded one-shots, AuthorizationDB
# check, marker-guarded drop-in removal). Optional for --install/--status.
load_pam_lib() {
    if [[ -f "${PAM_LIB_SH}" ]]
    then
        # shellcheck source=../PKG/Scripts/pam-lib.sh
        source "${PAM_LIB_SH}"
        PAM_LIB_LOADED=1
    fi
}

# Logs the by-hand fallback (pam-lib.sh serberus_daemon_manual_steps).
#   $1 demote | restore | sudoers
log_manual_steps() {
    local line
    if [[ "${PAM_LIB_LOADED}" -ne 1 ]]
    then
        return 0
    fi
    while IFS= read -r line
    do
        log_error "${line}"
    done < <(serberus_daemon_manual_steps "$1" "${AUTHDB_BACKUPS}")
}

# Runs a daemon one-shot with a hard deadline (pam-lib.sh), and only when the
# installed binary passes serberus_daemon_trusted (strict signature, Apple
# anchor, identifier com.herojoneslabs.serberus.daemon, the pinned team) — an
# ad-hoc dev build never qualifies, so its one-shots are left to the manual
# steps. Without the library the one-shot is refused rather than run
# unbounded. Returns the one-shot's status (124 = timeout), or 125 when it
# was not run.
run_daemon_oneshot() {
    if [[ "${PAM_LIB_LOADED}" -ne 1 ]]
    then
        log_error "${PAM_LIB_SH} not found — refusing to run $1 without a deadline"
        return 125
    fi
    if ! daemon_is_gone
    then
        log_error "${DAEMON_LABEL} is still loaded — NOT executing $1 beside it"
        return 125
    fi
    local team
    team=$(serberus_recorded_team 2>/dev/null) || team=""
    if ! serberus_daemon_trusted "${INSTALL_BINARY_PATH}" "${team}"
    then
        log_error "${INSTALL_BINARY_PATH} failed its signature check — NOT executing it for $1"
        return 125
    fi
    serberus_run_bounded "${ONESHOT_TIMEOUT}" "${INSTALL_BINARY_PATH}" "$1"
}

# Marker-guarded removal of the coarse sudoers drop-in (pam-lib.sh when the
# repo copy is present, identical inline fallback otherwise).
remove_sudoers_dropin() {
    if [[ ! -e "${SUDOERS_DROPIN}" ]]
    then
        return 0
    fi
    local result
    if [[ "${PAM_LIB_LOADED}" -eq 1 ]]
    then
        result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    elif "${GREP}" -Eq "${FALLBACK_SUDOERS_MARKER_RE}" "${SUDOERS_DROPIN}"
    then
        "${RM}" -f "${SUDOERS_DROPIN}" 2>/dev/null || true
        if [[ -e "${SUDOERS_DROPIN}" || -L "${SUDOERS_DROPIN}" ]]
        then
            result="FAILED"
        else
            result="removed"
        fi
    else
        result="foreign"
    fi
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal — remove it by hand (chflags noschg,nouchg first if set)."
        return 1
    fi
    return 0
}

enable_daemon() {
    "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl enable system/${DAEMON_LABEL} failed"
}

daemon_is_loaded() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        return 0
    fi
    return 1
}

# True once launchd no longer lists the job.
daemon_is_gone() {
    ! daemon_is_loaded
}

# Bootout, then wait (up to its ExitTimeOut plus 5 s) until launchd has
# dropped the job: a bootstrap or a one-shot must not race the old instance.
bootout_if_loaded() {
    if daemon_is_loaded
    then
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        local waited=0
        while daemon_is_loaded
        do
            if [[ "${waited}" -ge "${DAEMON_BOOTOUT_WAIT}" ]]
            then
                log_error "${DAEMON_LABEL} is still loaded ${DAEMON_BOOTOUT_WAIT}s after its bootout"
                return 0
            fi
            "${SLEEP}" 1
            waited=$((waited + 1))
        done
    fi
}

# Bootstraps the label and waits until the daemon is really up (pam-lib
# serberus_launchd_wait_running: one pid for 8 s, no restart, a state.plist
# written since the bootstrap). A failed bootstrap is flagged for the EXIT
# trap, which re-arms the daemon while sudo_local is wired.
bootstrap_and_wait() {
    local mark
    mark=$("${DATE}" -u +%s)
    if ! "${LAUNCHCTL}" bootstrap system "${PLIST_PATH}"
    then
        BOOTSTRAP_FAILED=1
        log_error "launchctl bootstrap failed for ${PLIST_PATH}"
        return 1
    fi
    if [[ "${PAM_LIB_LOADED}" -ne 1 ]]
    then
        log_warn "${PAM_LIB_SH} not found — not waiting for the daemon to come up"
        return 0
    fi
    if ! serberus_launchd_wait_running "${DAEMON_LABEL}" "${DAEMON_START_TIMEOUT}" "" "" "${STATE_PLIST}" "${mark}"
    then
        log_error "${DAEMON_LABEL} did not come up (no stable pid, a restart, or no fresh state.plist) — see ${LOG_DIR}/daemon.stderr.log"
        return 1
    fi
    log_info "${DAEMON_LABEL} is up (pid ${SERBERUS_LAUNCHD_UP_PID})"
}

# SKIP_DAEMON_SIGN: the prebuilt binary must already carry the identifier the
# PAM module and the clients pin, and — when DEVELOPMENT_TEAM is known — that
# team; otherwise the daemon would load and every peer would reject it.
#   $1 path of the (temp) copy to check
check_presigned_binary() {
    local path="$1"
    local team=""
    if [[ -f "${TEAM_ID_LIB}" ]]
    then
        # shellcheck source=team-id-lib.sh
        source "${TEAM_ID_LIB}"
        team=$(serberus_team_id "${SCRIPT_DIR}/..") || team=""
    fi
    local identifier
    identifier=$("${CODESIGN}" -dv "${path}" 2>&1 | "/usr/bin/awk" -F= '/^Identifier=/ { print $2; exit }') || identifier=""
    if [[ "${identifier}" != "${BUNDLE_ID}" ]]
    then
        log_error "pre-signed binary has identifier '${identifier:-none}', not ${BUNDLE_ID}; re-sign it with --identifier ${BUNDLE_ID}"
        return 1
    fi
    if [[ "${PAM_LIB_LOADED}" -eq 1 && -n "${team}" ]]
    then
        if ! serberus_daemon_trusted "${path}" "${team}"
        then
            log_error "pre-signed binary is not a valid ${BUNDLE_ID} signed by team ${team} (DEVELOPMENT_TEAM)"
            return 1
        fi
    elif ! "${CODESIGN}" --verify --strict "${path}" 2>/dev/null
    then
        log_error "pre-signed binary does not pass codesign --verify --strict"
        return 1
    fi
    return 0
}

do_install() {
    log_info "Installing ${BUNDLE_ID} v${SCRIPT_VERSION}"

    if [[ ! -f "${SERBERUSD_BINARY}" ]]
    then
        log_error "Built binary not found: ${SERBERUSD_BINARY}"
        log_error "Build first: xcodebuild -project Serberus.xcodeproj -scheme serberusd -configuration Release -derivedDataPath .build/xcode CODE_SIGNING_ALLOWED=NO build"
        return 1
    fi

    refuse_if_sudo_wired "stopped and replaced"
    ensure_directories

    # Stage in the SAME directory, sign and check the copy there, then mv it
    # over the live binary: the rename is atomic, so the path never holds a
    # half-written or unsigned file.
    local install_dir
    install_dir=$("${DIRNAME}" "${INSTALL_BINARY_PATH}")
    "${MKDIR}" -p "${install_dir}"
    local staged
    staged=$("${MKTEMP}" "${install_dir}/.serberusd.XXXXXX")
    TEMP_FILES+=("${staged}")
    "${CP}" "${SERBERUSD_BINARY}" "${staged}"
    "${CHOWN}" root:wheel "${staged}"
    "${CHMOD}" 755 "${staged}"

    if [[ -n "${SKIP_DAEMON_SIGN}" ]]
    then
        # The binary was signed before install (as the user, whose login keychain
        # can build the Apple Development chain). Copying preserves the embedded
        # signature; confirm it carries the pinned identifier (and team).
        log_info "SKIP_DAEMON_SIGN set — using the pre-signed binary"
        if ! check_presigned_binary "${staged}"
        then
            return 1
        fi
    else
        local entitlements_file
        entitlements_file=$(write_entitlements)
        # Explicit --identifier: for a flat binary named
        # com.herojoneslabs.serberus.daemon codesign would derive
        # "com.herojoneslabs.serberus", and the PAM module and the
        # Sentinel/Intel clients pin the daemon peer to the full identifier.
        log_info "Signing with identity '${SIGNING_IDENTITY}' (identifier ${BUNDLE_ID})"
        if ! "${CODESIGN}" --force --sign "${SIGNING_IDENTITY}" \
            --identifier "${BUNDLE_ID}" \
            --options runtime \
            --entitlements "${entitlements_file}" \
            "${staged}"
        then
            log_error "codesign failed"
            return 1
        fi
    fi

    if ! "${MV}" -f "${staged}" "${INSTALL_BINARY_PATH}"
    then
        log_error "could not move the new binary into place at ${INSTALL_BINARY_PATH}"
        return 1
    fi

    write_daemon_plist || return 1

    bootout_if_loaded
    # An uninstall leaves the label disabled; bootstrap refuses a disabled job.
    enable_daemon
    bootstrap_and_wait || return 1

    log_info "Install complete"
}

do_uninstall() {
    log_info "Uninstalling ${BUNDLE_ID}"
    refuse_if_sudo_wired "removed"

    # ORDER: disable (no KeepAlive/reboot relaunch) -> coarse sudoers drop-in
    # -> bootout -> drop-in re-check (the daemon could rewrite it until it
    # stopped) -> demote JIT -> restore authdb -> files.
    "${LAUNCHCTL}" disable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl disable system/${DAEMON_LABEL} failed"
    if ! remove_sudoers_dropin
    then
        enable_daemon
        return 1
    fi
    bootout_if_loaded
    remove_sudoers_dropin || log_manual_steps sudoers

    # JIT admins would otherwise stay admins forever. Loud, not fatal. Exit 3
    # means there is no grant store: nothing to demote.
    local demote_status=125
    if [[ -x "${INSTALL_BINARY_PATH}" ]]
    then
        demote_status=0
        run_daemon_oneshot --demote-jit || demote_status=$?
    fi
    case "${demote_status}" in
        0)
            log_info "JIT admins demoted"
            ;;
        3)
            log_info "No grant store — no JIT admins to demote"
            ;;
        *)
            log_error "--demote-jit FAILED, timed out, was not run, or no daemon binary (status ${demote_status})"
            log_manual_steps demote
            ;;
    esac
    # --demote-jit can take up to ONESHOT_TIMEOUT: look for the drop-in again.
    remove_sudoers_dropin || log_manual_steps sudoers

    # Restore any AuthorizationDB rights Serberus modified BEFORE removing the
    # binary (the binary performs the restore). Otherwise a `deny` authuri rule
    # would survive uninstall and leave a System-Settings pane (or admin auth)
    # blocked. A restore failure here is serious — surface it loudly with manual
    # remediation rather than swallowing it.
    # restore_ok gates --purge: authdb-backups (the only record of the native
    # rights) survive unless the restore exited 0 AND the live database no
    # longer references Serberus.
    local restore_ok=0
    if [[ -x "${INSTALL_BINARY_PATH}" ]]
    then
        log_info "Restoring AuthorizationDB rights from snapshots"
        if run_daemon_oneshot --restore-authdb
        then
            if serberus_authdb_free_of_serberus
            then
                restore_ok=1
            else
                log_error "The restore exited 0 but the AuthorizationDB still references Serberus (see above)."
            fi
        else
            log_error "AuthorizationDB restore FAILED or was not run — some rights may still be modified (a 'deny' could block a Settings pane or admin auth)."
            log_error "Recover manually: inspect ${SUPPORT_DIR}/authdb-backups/*.json and run 'sudo security authorizationdb write <right> < <original>', or reset a stuck right with 'sudo security authorizationdb write <right> authenticate-admin'."
            if [[ -d "${AUTH_PLUGIN}" ]]
            then
                log_error "Leave ${AUTH_PLUGIN} in place until those rights are restored — they may still reference it."
            fi
        fi
    elif [[ -e "${PLIST_PATH}" || -e "${INSTALL_BINARY_PATH}" ]]
    then
        log_error "Daemon binary missing/non-executable at ${INSTALL_BINARY_PATH}; CANNOT auto-restore AuthorizationDB rights. If you used authuri rules, restore manually from ${SUPPORT_DIR}/authdb-backups/."
    elif [[ "${PAM_LIB_LOADED}" -eq 1 ]] && serberus_authdb_free_of_serberus
    then
        restore_ok=1
    fi

    if [[ -f "${PLIST_PATH}" ]]
    then
        "${RM}" -f "${PLIST_PATH}"
    fi
    if [[ -f "${INSTALL_BINARY_PATH}" ]]
    then
        "${RM}" -f "${INSTALL_BINARY_PATH}"
    fi

    # Preserve state.plist and grants.sqlite, as the PKG preinstall does.
    # Pass --purge to remove the daemon's data (pam-lib.sh
    # serberus_purge_support_data): never the apps or the uninstall helpers
    # in the support folder.
    if [[ "${PURGE_FLAG}" -eq 1 ]]
    then
        if [[ "${PAM_LIB_LOADED}" -ne 1 ]]
        then
            log_error "${PAM_LIB_SH} not found — not purging ${SUPPORT_DIR}"
        elif [[ "${restore_ok}" -eq 1 ]]
        then
            log_warn "Purging daemon data under ${SUPPORT_DIR}"
            serberus_purge_support_data "${SUPPORT_DIR}" 0 > /dev/null
        else
            log_warn "Purging daemon data under ${SUPPORT_DIR} EXCEPT ${AUTHDB_BACKUPS} (the restore did not succeed)"
            serberus_purge_support_data "${SUPPORT_DIR}" 1 > /dev/null
        fi
    fi

    log_info "Uninstall complete"
}

do_restart() {
    log_info "Restarting ${BUNDLE_ID}"
    if [[ ! -f "${PLIST_PATH}" ]]
    then
        log_error "Not installed: ${PLIST_PATH} missing"
        return 1
    fi
    refuse_if_sudo_wired "restarted"
    bootout_if_loaded
    enable_daemon
    bootstrap_and_wait || return 1
    log_info "Restart complete"
}

do_status() {
    if daemon_is_loaded
    then
        log_info "Daemon is LOADED in system domain"
    else
        log_info "Daemon is NOT loaded"
    fi

    if [[ -f "${STATE_PLIST}" ]]
    then
        local state
        state=$("${PLIST_BUDDY}" -c "Print :state" "${STATE_PLIST}" 2>/dev/null || printf 'unreadable')
        log_info "state.plist state = ${state}"
    else
        log_info "state.plist not present yet"
    fi
}

assert_state_written() {
    local attempt=0
    local max_attempts=10
    while [[ ${attempt} -lt ${max_attempts} ]]
    do
        if [[ -f "${STATE_PLIST}" ]]
        then
            return 0
        fi
        "${SLEEP}" 1
        attempt=$((attempt + 1))
    done
    return 1
}

do_verify_cycle() {
    log_info "=== install/uninstall/restart verification cycle ==="

    # The cycle ends with an uninstall — refuse up front (before installing
    # anything) rather than half-way through.
    refuse_if_sudo_wired "removed"

    do_install || return 1

    if ! daemon_is_loaded
    then
        log_error "VERIFY FAIL: daemon not loaded after install"
        return 1
    fi
    log_info "PASS: daemon loaded after install"

    if ! assert_state_written
    then
        log_error "VERIFY FAIL: state.plist not written after install"
        return 1
    fi
    log_info "PASS: state.plist written"

    do_restart || return 1
    if ! daemon_is_loaded
    then
        log_error "VERIFY FAIL: daemon not loaded after restart"
        return 1
    fi
    log_info "PASS: daemon survived restart"

    do_uninstall
    if daemon_is_loaded
    then
        log_error "VERIFY FAIL: daemon still loaded after uninstall"
        return 1
    fi
    log_info "PASS: daemon removed after uninstall"

    log_info "=== verification cycle PASSED ==="
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

require_root
load_pam_lib

# Flags after the mode, in any order.
for flag in "${@:2}"
do
    case "${flag}" in
        --purge) PURGE_FLAG=1 ;;
        --force) FORCE_FLAG=1 ;;
        *)
            printf 'Unknown option: %s\n' "${flag}" >&2
            exit 1
            ;;
    esac
done

case "${MODE}" in
    --install)
        do_install
        ;;
    --uninstall)
        do_uninstall
        ;;
    --restart)
        do_restart
        ;;
    --status)
        do_status
        ;;
    --verify-cycle)
        do_verify_cycle
        ;;
    *)
        printf 'Usage: %s [--install [--force]|--uninstall [--purge] [--force]|--restart [--force]|--status|--verify-cycle [--force]]\n' "${SCRIPT_NAME}" >&2
        exit 1
        ;;
esac

log_info "${SCRIPT_NAME} completed successfully"

###########################################################
################## End Script Block #######################
###########################################################
