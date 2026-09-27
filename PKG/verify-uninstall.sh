#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: verify-uninstall.sh
# Author: Heath Jones
# Date: 2026-08-22
# Modified: 2026-09-26
# Purpose: Read-only audit confirming a Serberus uninstall actually left the
#          machine clean — the postinstall of SerberusUninstall-*.pkg
#          (PKG/build-uninstall-pkg.sh), or PKG/Scripts/uninstall.sh --purge on
#          a production-only Mac. This is the SPEC of "clean": every path,
#          label, receipt and keychain item that teardown removes has a check
#          here, plus a defense-in-depth sweep of the raw AuthorizationDB for
#          any leftover Serberus content the per-right checks wouldn't catch.
#          Never modifies anything. (A label left DISABLED in launchd by the
#          teardown is expected and not a finding: the next install enables
#          it before bootstrap.)
# Version: 1.4 - (a) The AuthorizationDB sweep reports what the teardowns
#          gate the plugin on (composition rows that invoke SerberusAuth and
#          rights that delegate to a composition row) and any composition
#          row (com.herojoneslabs.serberus.branch.*) left behind. The marker
#          comment is no longer evidence: a right a standard user created
#          with it is not reported. (b) Commander is not part of the endpoint: its receipt,
#          its uninstall helper and relaunch marker in the support folder,
#          and its files in each user's ~/Library/Application Support/Serberus
#          (policies.json, capture-reviews.json) are not findings. Per-user
#          checks look for the Sentinel's own files.
#          1.3 - Also reports a leftover /usr/local/lib/pam/pam_serberus.so.2
#          (OpenPAM loads it in place of pam_serberus.so). The AuthorizationDB
#          sweep uses the narrowed residue query: rights that invoke a
#          SerberusAuth: mechanism or carry the daemon's managed marker.
#          1.2 - The AuthorizationDB sweep also finds rights whose
#          MECHANISMS reference the SerberusAuth plugin (join through
#          mechanisms_map), the same query the teardowns now gate the plugin
#          removal on (pam-lib.sh SERBERUS_AUTHDB_QUERY). LaunchAgent jobs are
#          checked in EVERY logged-in GUI session, not only the console
#          user's. umask 022.
#          1.1 - Checks the SerberusAuth plugin, the serberus CLI, the
#          Guardian and Finder-extension election LaunchAgents (plists and
#          console-user jobs), the daemon's System-keychain items, and the
#          production + Commander receipts. System-only PATH and absolute
#          tool paths (it runs as root). Header names the right teardowns.
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

# Deliberately NOT `set -e`: this script runs an independent checklist and
# must complete every check even when earlier ones fail, so the full report
# reflects everything found rather than stopping at the first problem.
set -uo pipefail
umask 022

# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute tool paths: this runs as root, so nothing is resolved via PATH.
readonly AWK="/usr/bin/awk"
readonly BASENAME="/usr/bin/basename"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly LAUNCHCTL="/bin/launchctl"
readonly PGREP="/usr/bin/pgrep"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly PS="/bin/ps"
readonly SCUTIL="/usr/sbin/scutil"
readonly SECURITY="/usr/bin/security"
readonly SORT="/usr/bin/sort"
readonly SQLITE3="/usr/bin/sqlite3"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.4"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

# Every path/label below is copied verbatim from PKG/Scripts/uninstall.sh and
# the postinstall PKG/build-uninstall-pkg.sh generates — KEEP IN SYNC. This
# script checks that each one is now ABSENT (or, for sudo_local, has no
# ACTIVE Serberus reference — the file itself may legitimately still exist
# for other PAM lines).
readonly DAEMON_LABEL="${ORG_PLIST_DOMAIN}.daemon"
readonly DAEMON_BUNDLE="/Library/PrivilegedHelperTools/serberusd.app"
readonly DAEMON_BINARY_LEGACY_APP="${DAEMON_BUNDLE}/Contents/MacOS/${ORG_PLIST_DOMAIN}.daemon"
readonly DAEMON_BINARY_FLAT="/Library/PrivilegedHelperTools/${ORG_PLIST_DOMAIN}.daemon"
readonly DAEMON_PLIST="/Library/LaunchDaemons/${ORG_PLIST_DOMAIN}.daemon.plist"
readonly AUTH_PLUGIN="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
readonly CLI_BINARY="/usr/local/bin/serberus"

# Every per-user LaunchAgent the GUI pkg installs: label + plist.
readonly AGENT_LABELS=(
    "${ORG_PLIST_DOMAIN}.sentinel"
    "${ORG_PLIST_DOMAIN}.guardian"
    "${ORG_PLIST_DOMAIN}.finderext-elect"
)

# System-keychain items the daemon creates (HMAC keys).
readonly KEYCHAIN_SERVICE="${ORG_PLIST_DOMAIN}.daemon"
readonly SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"

readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"
readonly PAM_MODULE="/usr/local/lib/pam/pam_serberus.so"
readonly PAM_MODULE_LEGACY="/usr/lib/pam/pam_serberus.so"

readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly LOG_DIR="/Library/Logs/Serberus"

# App path variants across every rename/split this project has gone through —
# same list PKG/build-uninstall-pkg.sh's postinstall removes.
readonly APP_PATHS=(
    "/Applications/Serberus Sentinel.app"
    "/Applications/SerberusSentinel.app"
    "/Applications/Serberus Sentinel"
    "${SUPPORT_DIR}/Serberus Sentinel Agent.app"
    "${SUPPORT_DIR}/SerberusSentinelAgent.app"
    "${SUPPORT_DIR}/Serberus Guardian.app"
    "/Applications/SerberusIntel.app"
    "/Applications/SerberusAgent.app"
    "/Applications/SerberusCapture.app"
    "/Applications/Serberus.app"
)

# Known Serberus endpoint pkgutil receipt identifiers (excluding the
# uninstaller's own receipt, which forgetting is a nice-to-have, not a
# cleanliness signal, and Commander's: the admin console is not part of the
# endpoint and no endpoint uninstaller removes it).
readonly RECEIPT_IDS=(
    "${ORG_PLIST_DOMAIN}.pkg"
    "${ORG_PLIST_DOMAIN}.sentineltestpkg"
    "${ORG_PLIST_DOMAIN}.pamtestpkg"
    "${ORG_PLIST_DOMAIN}.testpkg"
    "${ORG_PLIST_DOMAIN}.sentinelapptestpkg"
    "${ORG_PLIST_DOMAIN}.combined"
    "${ORG_PLIST_DOMAIN}.coretestpkg"
)

readonly AUTH_DB="/var/db/auth.db"

# What Commander keeps in the support folder (its uninstall helper, and its
# relaunch marker under the install-marker directory). Not findings.
readonly COMMANDER_SUPPORT_ENTRIES=(
    "uninstall-serberus-commander.sh"
    ".install-markers"
)
readonly COMMANDER_MARKER_ENTRIES=(
    "commander-relaunch"
)

# The Sentinel's per-user files under ~/Library/Application Support/Serberus
# (SentinelRulesStore, ElevationHistoryStore, SentinelRouteHandoff,
# JamfUploadLedger). The same folder holds Commander's library, which stays.
readonly SENTINEL_USER_FILES=(
    "rules-cache.json"
    "elevation-history.json"
    "pending-route"
    "jamf-uploads.json"
)

# --run|--ea from the Run Script Block dispatch below.
readonly MODE="${1:---run}"

# Collected by the check_* functions.
declare -a PROBLEMS=()

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

log_problem() {
    PROBLEMS+=("$*")
    printf '[FOUND] %s\n' "$*"
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        printf '[ERROR] Must run as root (some checks read root-only paths)\n' >&2
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

# --- Step 1: no Serberus GUI process still running ---
check_no_running_processes() {
    local pattern
    for pattern in "Serberus Sentinel" "SerberusSentinel" "Serberus Guardian" "serberusd"
    do
        if "${PGREP}" -f "${pattern}" > /dev/null 2>&1
        then
            log_problem "A process matching '${pattern}' is still running"
        fi
    done
}

# --- Step 2: coarse sudoers drop-in gone ---
check_sudoers_dropin() {
    if [[ -e "${SUDOERS_DROPIN}" ]]
    then
        log_problem "${SUDOERS_DROPIN} still exists"
    fi
}

# --- Step 3: sudo_local has no ACTIVE pam_serberus reference (the file
# itself may legitimately still exist for other PAM lines — only an active,
# uncommented reference to the now-deleted module is a problem, since that's
# exactly the dangling-reference shape that bricks sudo) ---
check_sudo_local_wiring() {
    if [[ ! -e "${SUDO_LOCAL}" ]]
    then
        return 0
    fi
    if "${GREP}" -Eq '^[^#]*pam_serberus\.so' "${SUDO_LOCAL}" 2>/dev/null
    then
        log_problem "${SUDO_LOCAL} still has an ACTIVE pam_serberus.so reference — sudo may be bricked"
    fi
}

# --- Step 4: PAM module gone (both canonical and legacy paths), plus the
# authorization plugin and the CLI ---
check_pam_module() {
    if [[ -e "${AUTH_PLUGIN}" ]]
    then
        log_problem "${AUTH_PLUGIN} still exists (an AuthorizationDB restore that failed keeps it on purpose)"
    fi
    if [[ -e "${CLI_BINARY}" ]]
    then
        log_problem "${CLI_BINARY} still exists"
    fi
    if [[ -e "${PAM_MODULE}" ]]
    then
        log_problem "${PAM_MODULE} still exists"
    fi
    if [[ -e "${PAM_MODULE}.2" || -L "${PAM_MODULE}.2" ]]
    then
        log_problem "${PAM_MODULE}.2 still exists"
    fi
    if [[ -e "${PAM_MODULE_LEGACY}" ]]
    then
        log_problem "${PAM_MODULE_LEGACY} still exists"
    fi
}

# --- Step 5: AuthorizationDB clean — defense in depth beyond any single
# right's own definition, since we don't know ahead of time which rights a
# given install customized. A report only, never a gate. Queries the raw db
# read-only (sqlite3, root read access to /var/db/auth.db) for the rights the
# teardowns gate the plugin removal on (a composition row invoking
# SerberusAuth, or a right delegating to a composition row — pam-lib.sh
# SERBERUS_AUTHDB_QUERY), plus any row left under the composition prefix
# com.herojoneslabs.serberus.branch.*. A comment is never evidence: a
# standard user can create config.add.* rights and write any comment. ---
check_authorization_db() {
    if [[ ! -e "${AUTH_DB}" ]]
    then
        log_problem "${AUTH_DB} not found — cannot verify AuthorizationDB state (unexpected on any real Mac)"
        return 0
    fi
    if [[ ! -x "${SQLITE3}" ]]
    then
        log_problem "sqlite3 not found — cannot verify AuthorizationDB state"
        return 0
    fi

    # KEEP IN SYNC with pam-lib.sh SERBERUS_AUTHDB_QUERY.
    local query="SELECT DISTINCT r.name FROM rules r JOIN mechanisms_map mm ON mm.r_id = r.id JOIN mechanisms m ON m.id = mm.m_id WHERE m.plugin LIKE 'SerberusAuth' AND r.name LIKE 'com.herojoneslabs.serberus.branch.%' UNION SELECT DISTINCT r.name FROM rules r JOIN delegates_map dm ON dm.r_id = r.id JOIN rules d ON d.id = dm.d_id WHERE d.name LIKE 'com.herojoneslabs.serberus.branch.%';"
    local branch_query="SELECT DISTINCT name FROM rules WHERE name LIKE 'com.herojoneslabs.serberus.branch.%';"
    local names
    local rows
    if ! names=$("${SQLITE3}" -readonly "${AUTH_DB}" "${query}" 2>/dev/null) \
        || ! rows=$("${SQLITE3}" -readonly "${AUTH_DB}" "${branch_query}" 2>/dev/null)
    then
        log_problem "Could not query ${AUTH_DB} (schema mismatch or permission denied) — verify manually with: sqlite3 ${AUTH_DB} \"${query}\""
        return 0
    fi
    if [[ -n "${names}" ]]
    then
        log_problem "AuthorizationDB right(s) still reference Serberus: ${names}"
    fi
    if [[ -n "${rows}" ]]
    then
        log_problem "AuthorizationDB composition row(s) left behind: ${rows}"
    fi
}

# --- Step 6: daemon gone (binary, LaunchDaemon plist, not loaded) ---
check_daemon() {
    if [[ -e "${DAEMON_BUNDLE}" ]]
    then
        log_problem "${DAEMON_BUNDLE} still exists"
    fi
    if [[ -e "${DAEMON_BINARY_FLAT}" ]]
    then
        log_problem "${DAEMON_BINARY_FLAT} still exists"
    fi
    if [[ -e "${DAEMON_PLIST}" ]]
    then
        log_problem "${DAEMON_PLIST} still exists"
    fi
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" > /dev/null 2>&1
    then
        log_problem "${DAEMON_LABEL} is still loaded in launchd"
    fi
}

# --- Step 7: GUI apps + LaunchAgent gone, every path variant across every
# rename/split this project has had ---
check_gui_apps() {
    local path
    for path in "${APP_PATHS[@]}"
    do
        if [[ -e "${path}" ]]
        then
            log_problem "${path} still exists"
        fi
    done
    local label
    for label in "${AGENT_LABELS[@]}"
    do
        if [[ -e "/Library/LaunchAgents/${label}.plist" ]]
        then
            log_problem "/Library/LaunchAgents/${label}.plist still exists"
        fi
    done

    # Every logged-in GUI session (each runs a loginwindow as its user; the
    # login screen's runs as root), plus the console user.
    local console_user console_uid=""
    # shellcheck disable=SC2016 — $3 is awk's own field var inside the single-quoted program, not a shell var
    console_user=$("${SCUTIL}" <<< "show State:/Users/ConsoleUser" | "${AWK}" '/Name :/ && $3 != "loginwindow" { print $3 }')
    if [[ -n "${console_user}" ]]
    then
        console_uid=$("${ID}" -u "${console_user}" 2>/dev/null)
    fi
    local gui_uid
    while IFS= read -r gui_uid
    do
        for label in "${AGENT_LABELS[@]}"
        do
            if "${LAUNCHCTL}" print "gui/${gui_uid}/${label}" > /dev/null 2>&1
            then
                log_problem "${label} is still loaded in the launchd session of uid ${gui_uid}"
            fi
        done
    done < <({
        "${PS}" -axo uid=,comm= 2>/dev/null | "${AWK}" '$2 ~ /\/loginwindow$/ { print $1 }'
        printf '%s\n' "${console_uid}"
    } | "${AWK}" '/^[0-9]+$/ && $1 > 0' | "${SORT}" -un)
}

# True when <name> is one of the words that follow. $1 name, $2… words.
name_in() {
    local name="$1"
    shift
    local word
    for word in "$@"
    do
        [[ "${name}" == "${word}" ]] && return 0
    done
    return 1
}

# --- Step 8: support dir + logs gone. Commander's own entries (its
# uninstall helper and relaunch marker) may stay. ---
check_support_and_logs() {
    if [[ -L "${SUPPORT_DIR}" || ( -e "${SUPPORT_DIR}" && ! -d "${SUPPORT_DIR}" ) ]]
    then
        log_problem "${SUPPORT_DIR} still exists"
    elif [[ -d "${SUPPORT_DIR}" ]]
    then
        local entry
        local -a entries=()
        shopt -s nullglob dotglob
        entries=("${SUPPORT_DIR}"/* "${SUPPORT_DIR}"/.install-markers/*)
        shopt -u nullglob dotglob
        for entry in ${entries[@]+"${entries[@]}"}
        do
            if [[ "${entry%/*}" == "${SUPPORT_DIR}/.install-markers" ]]
            then
                name_in "${entry##*/}" "${COMMANDER_MARKER_ENTRIES[@]}" && continue
            else
                name_in "${entry##*/}" "${COMMANDER_SUPPORT_ENTRIES[@]}" && continue
            fi
            log_problem "${entry} still exists"
        done
    fi
    if [[ -e "${LOG_DIR}" ]]
    then
        log_problem "${LOG_DIR} still exists"
    fi
}

# --- Step 9: the Sentinel's per-user files gone, every user on the machine.
# Commander's library in the same folder is not a finding. ---
check_per_user_caches() {
    local home cache file
    for home in /Users/*
    do
        [[ -d "${home}" ]] || continue
        cache="${home}/Library/Application Support/Serberus"
        for file in "${SENTINEL_USER_FILES[@]}"
        do
            if [[ -e "${cache}/${file}" || -L "${cache}/${file}" ]]
            then
                log_problem "${cache}/${file} still exists"
            fi
        done
    done
}

# --- Step 10: no lingering Serberus pkgutil receipts ---
check_receipts() {
    local receipt
    for receipt in "${RECEIPT_IDS[@]}"
    do
        if "${PKGUTIL}" --pkg-info "${receipt}" > /dev/null 2>&1
        then
            log_problem "pkgutil receipt '${receipt}' still registered"
        fi
    done
}

# --- Step 11: the daemon's System-keychain items (HMAC keys) are gone ---
check_keychain_items() {
    if "${SECURITY}" find-generic-password -s "${KEYCHAIN_SERVICE}" "${SYSTEM_KEYCHAIN}" > /dev/null 2>&1
    then
        log_problem "System keychain still holds item(s) for service ${KEYCHAIN_SERVICE}"
    fi
}

run_all_checks() {
    check_no_running_processes
    check_sudoers_dropin
    check_sudo_local_wiring
    check_pam_module
    check_authorization_db
    check_daemon
    check_gui_apps
    check_support_and_logs
    check_per_user_caches
    check_receipts
    check_keychain_items
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

case "${MODE}" in
    --run)
        require_root
        log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} — verifying Serberus uninstall is clean and complete"
        run_all_checks
        if [[ "${#PROBLEMS[@]}" -eq 0 ]]
        then
            log_info "CLEAN — no Serberus components found. Safe to reinstall."
            exit 0
        else
            printf '[RESULT] NOT CLEAN — %d issue(s) found:\n' "${#PROBLEMS[@]}"
            for problem in "${PROBLEMS[@]}"
            do
                printf '  - %s\n' "${problem}"
            done
            exit 1
        fi
        ;;
    --ea)
        # Extension Attribute contract: fast, side-effect-free, <r>VALUE</r>
        # as the only stdout, no set -e reliance (already off in this script).
        if [[ "$("${ID}" -u)" -ne 0 ]]
        then
            printf '<result>ERROR: must run as root</result>\n'
            exit 0
        fi
        run_all_checks > /dev/null 2>&1
        if [[ "${#PROBLEMS[@]}" -eq 0 ]]
        then
            printf '<result>CLEAN</result>\n'
        else
            printf '<result>DIRTY: %d issue(s)</result>\n' "${#PROBLEMS[@]}"
        fi
        exit 0
        ;;
    *)
        printf 'Usage: %s [--run|--ea]\n' "${SCRIPT_NAME} " >&2
        printf '  --run  human-readable report + exit 0 (clean) / 1 (not clean) — for a Jamf policy script or manual use\n' >&2
        printf '  --ea   single-line Jamf Extension Attribute output — for continuous fleet smart-group monitoring\n' >&2
        exit 2
        ;;
esac

###########################################################
################## End Script Block #######################
###########################################################
