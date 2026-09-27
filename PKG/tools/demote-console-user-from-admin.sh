#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: demote-console-user-from-admin.sh
# Author: Heath Jones
# Date: 2026-08-20
# Modified: 2026-09-28
# Purpose: If the current console (GUI) user is a member of the local
#          admin group, remove them from it — but only when another USABLE
#          admin remains (exists, enabled, can authenticate, holds a
#          SecureToken and, on Apple silicon, is a volume owner, and is not an
#          admin only through a Serberus JIT grant or a Jamf Connect
#          elevation), so the Mac can still be administered, unlocked and
#          updated. No-op if already standard, and for system accounts
#          (Setup Assistant's _mbsetupuser and the like).
#
#          Jamf script parameters:
#            $4  the organisation name shown in messages to the admin
#                (default "your IT team").
#
#          Jamf Connect: when the Serberus JIT provider is jamf_connect
#          (com.herojoneslabs.serberus.jit, key provider), any user may be a
#          temporary admin, and nothing on disk marks who is. The best
#          available signal is the one serberusd itself follows: Jamf
#          Connect's PrivilegeElevation entries in the unified log, from a
#          process inside Jamf Connect, Self Service+, the Jamf Connect
#          daemon inside Self Service (JCDaemon.app) or
#          /Library/Application Support/JamfConnect. An admin with an
#          elevation in the last 8 hours (the JIT ceiling) that has no later
#          "removed from admin" entry is not counted as the admin left
#          behind. When that log cannot be read, nothing is demoted. The
#          signal can miss an elevation older than 8 hours, and an admin can
#          fake an entry (which only makes this script more cautious).
# Version: 1.6 - Jamf Connect bundled in Self Service: entries from its
#          daemon (/Applications/Self Service.app/Contents/MacOS/JCDaemon.app)
#          count, and "Added user <user> to admin group" counts as an
#          elevation, as in serberusd.
#          1.5 - (a) System accounts are never demoted: a console user whose
#          name starts with "_" (Setup Assistant runs as _mbsetupuser) or
#          whose uid is below 500 is left alone, and "_" accounts never count
#          as the admin left behind. (b) With the jamf_connect JIT provider,
#          an admin with a recent Jamf Connect elevation is not counted, and
#          when the unified log cannot be read nothing is demoted. (c) Serberus
#          JIT grants are matched by uid as well as name, so a renamed JIT
#          account is still recognised. (d) The organisation name is Jamf
#          parameter 4, default "your IT team", instead of a hardcoded
#          name.
#          1.4 - An admin who holds an unrevoked Serberus JIT admin grant
#          (a jit_admin row in the root-only grants.sqlite, read with
#          sqlite3 -readonly) is not counted as the admin left behind: the
#          grant expires and takes the membership with it. When the grant
#          store exists but cannot be read, nothing is demoted.
#          1.3 - (a) "Usable" other admins must also hold a SecureToken
#          (sysadminctl -secureTokenStatus) and, on Apple silicon, be a
#          volume owner of the boot volume (diskutil apfs listUsers /) —
#          otherwise demoting the console user can leave no one able to
#          unlock FileVault, authorize software updates or manage the Mac.
#          (b) The parameter-4 "force" override is REMOVED: demoting the
#          last usable admin is never done by this script. (c) umask 022.
#          1.2 - Tools by absolute path (no `which` under root).
#          1.1 - Only usable admin accounts (existing, not disabled, with an
#          authentication method) count toward "another admin remains",
#          and PATH no longer includes /usr/local/bin.
#          1.0 - Initial Script
#
#
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
readonly DATE="/bin/date"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly LOGGER="/usr/bin/logger"

# Jamf parameter 4: the organisation name used in messages.
readonly ORG_NAME_FRIENDLY="${4:-your IT team}"
readonly ORG_PLIST_DOMAIN="com.herojoneslabs"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.6"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.${SCRIPT_NAME%.sh}"
readonly JAMF_LOG="/var/log/jamf.log"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DISKUTIL="/usr/sbin/diskutil"
readonly JQ="/usr/bin/jq"
readonly LOG_BIN="/usr/bin/log"
readonly PLUTIL="/usr/bin/plutil"
readonly DSCL="/usr/bin/dscl"
readonly DSEDITGROUP="/usr/sbin/dseditgroup"
readonly SCUTIL="/usr/sbin/scutil"
readonly SQLITE3="/usr/bin/sqlite3"
readonly SYSADMINCTL="/usr/sbin/sysadminctl"
readonly SYSCTL="/usr/sbin/sysctl"
readonly TEE="/usr/bin/tee"

# $1-$3 reserved by Jamf (mount point, computer name, username); $4 is the
# organisation name (above). There is no "demote anyway" parameter: leaving a
# Mac with no usable admin is never this script's call.

# Accounts below this uid are system accounts; a console user below it is
# never demoted.
readonly FIRST_USER_UID=500

# Volume owners of the boot volume, read once (Apple silicon only): the
# `diskutil apfs listUsers /` blocks, e.g.
#   +-- 8B2FC34C-1CDC-4D51-A19E-5CB666728994
#   |   Type: Local Open Directory User
#   |   Volume Owner: Yes
VOLUME_OWNERS=""
IS_APPLE_SILICON=0

# Serberus's grant store (root-only). A JIT admin grant is a row with these
# sentinel values (PrivMgrCore JITAdminGrant) that is not yet revoked; the
# user's admin membership lasts only until the grant expires.
readonly GRANT_DB="/Library/Application Support/Serberus/grants.sqlite"
readonly JIT_QUERY="SELECT DISTINCT user FROM grants WHERE profileKey = 'jit_admin' AND canonicalPath = 'group:admin' AND revokedAt IS NULL;"
readonly JIT_UID_QUERY="SELECT DISTINCT uid FROM grants WHERE profileKey = 'jit_admin' AND canonicalPath = 'group:admin' AND revokedAt IS NULL;"
# Users holding an unrevoked JIT admin grant, one per line (load_jit_admins),
# and their uids (a renamed account keeps its uid).
JIT_ADMINS=""
JIT_ADMIN_UIDS=""

# The Serberus JIT provider, from the managed profile (Jamf Connect support).
readonly JIT_MANAGED_PLIST="/Library/Managed Preferences/com.herojoneslabs.serberus.jit.plist"
# Jamf Connect's privilege-elevation entries, as serberusd follows them
# (JamfConnectLogParser): subsystem, category, the sender's location, and the
# 8-hour JIT ceiling as the look-back.
readonly JC_LOG_PREDICATE='(subsystem == "com.jamf.connect.daemon.ssp" OR subsystem == "com.jamf.connect") AND category == "PrivilegeElevation"'
readonly JC_LOOKBACK="8h"
# Users with a Jamf Connect elevation still open in the log (load_jc_elevated).
JC_ELEVATED=""

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
    printf '%s %s[%s]: [INFO] %s\n' "$("${DATE}" '+%Y-%m-%d %H:%M:%S')" "${SCRIPT_NAME}" "$$" "$*" | "${TEE}" -ai "${JAMF_LOG}"
}

log_warn() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.warning "[WARN] $*"
    printf '%s %s[%s]: [WARN] %s\n' "$("${DATE}" '+%Y-%m-%d %H:%M:%S')" "${SCRIPT_NAME}" "$$" "$*" | "${TEE}" -ai "${JAMF_LOG}"
}

log_error() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.err "[ERROR] $*"
    printf '%s %s[%s]: [ERROR] %s\n' "$("${DATE}" '+%Y-%m-%d %H:%M:%S')" "${SCRIPT_NAME}" "$$" "$*" | "${TEE}" -ai "${JAMF_LOG}"
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_error "Must run as root (use sudo, or deploy via Jamf policy)"
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

get_console_user() {
    "${SCUTIL}" <<< "show State:/Users/ConsoleUser" | "${AWK}" '/Name :/ { print $3 }'
}

# Apple silicon (checked through sysctl: `uname -m` reports x86_64 under
# Rosetta) — only there does macOS gate boot-volume administration on being a
# volume owner.
detect_apple_silicon() {
    if [[ "$("${SYSCTL}" -n hw.optional.arm64 2>/dev/null)" == "1" ]]
    then
        IS_APPLE_SILICON=1
        # GUIDs listed as "Volume Owner: Yes", upper-case, one per line.
        VOLUME_OWNERS=$("${DISKUTIL}" apfs listUsers / 2>/dev/null | "${AWK}" '
            /^[|+ ]*\+-- / { guid = toupper($NF) }
            /Volume Owner: Yes/ && guid != "" { print guid }
        ') || VOLUME_OWNERS=""
    fi
}

# Reads the users with an unrevoked JIT admin grant into JIT_ADMINS. No grant
# store (Serberus not installed) means none. Returns 1 when the store exists
# but cannot be read: the caller must then not demote anyone, because a
# JIT-only admin could be the one counted as "another admin".
load_jit_admins() {
    if [[ ! -e "${GRANT_DB}" && ! -L "${GRANT_DB}" ]]
    then
        return 0
    fi
    if [[ -L "${GRANT_DB}" || ! -f "${GRANT_DB}" ]]
    then
        log_error "${GRANT_DB} is not a regular file"
        return 1
    fi
    if ! JIT_ADMINS=$("${SQLITE3}" -readonly -cmd ".timeout 5000" "${GRANT_DB}" "${JIT_QUERY}" 2>/dev/null) \
        || ! JIT_ADMIN_UIDS=$("${SQLITE3}" -readonly -cmd ".timeout 5000" "${GRANT_DB}" "${JIT_UID_QUERY}" 2>/dev/null)
    then
        JIT_ADMINS=""
        JIT_ADMIN_UIDS=""
        log_error "Could not read JIT grants from ${GRANT_DB}"
        return 1
    fi
    return 0
}

# The Serberus JIT provider from the managed profile, or nothing.
jit_provider() {
    [[ -f "${JIT_MANAGED_PLIST}" ]] || return 0
    "${PLUTIL}" -extract provider raw -o - "${JIT_MANAGED_PLIST}" 2>/dev/null || true
}

# Prints, one per line, the users whose latest Jamf Connect
# PrivilegeElevation entry (from ndjson `log show` output on stdin; lines
# that are not JSON, such as the tool's banner, are skipped) is an
# elevation, not a removal. Only entries sent from inside Jamf Connect, Self
# Service+, Self Service's JCDaemon.app or /Library/Application
# Support/JamfConnect count; the message forms are serberusd's
# (JamfConnectLogParser).
jc_open_elevations() {
    "${JQ}" -rR '
        fromjson? | select(type == "object")
        | select((.processImagePath // "") | test("^(/Applications/Jamf Connect\\.app/|/Applications/Self Service\\+\\.app/|/Applications/Self Service\\.app/Contents/MacOS/JCDaemon\\.app/|/Library/Application Support/JamfConnect/)"))
        | (.eventMessage // "") as $m
        | if ($m | test("^(user\\s+)?\"?[A-Za-z0-9._@-]+\"?\\s+elevated\\s+to\\s+admin(istrator)?\\s+for\\s+[0-9]+\\s+minutes?\\.?$"; "i"))
          then "E\t" + ($m | capture("^(user\\s+)?\"?(?<u>[A-Za-z0-9._@-]+)"; "i").u)
          elif ($m | test("^added\\s+user\\s+\"?[A-Za-z0-9._@-]+\"?\\s+to\\s+(the\\s+)?admin\\s+group\\.?$"; "i"))
          then "E\t" + ($m | capture("^added\\s+user\\s+\"?(?<u>[A-Za-z0-9._@-]+)"; "i").u)
          elif ($m | test("^removed\\s+user\\s+\"?[A-Za-z0-9._@-]+\"?\\s+from\\s+(the\\s+)?admin\\s+group\\.?$"; "i"))
          then "R\t" + ($m | capture("^removed\\s+user\\s+\"?(?<u>[A-Za-z0-9._@-]+)"; "i").u)
          else empty end
    ' 2>/dev/null | "${AWK}" -F'\t' '
        { state[$2] = $1 }
        END { for (u in state) if (state[u] == "E") print u }
    '
}

# With the jamf_connect provider, reads the users Jamf Connect elevated in
# the last JC_LOOKBACK and has not yet removed (JC_ELEVATED). Returns 1 when
# the log cannot be read: elevation then cannot be ruled out.
load_jc_elevated() {
    if [[ "$(jit_provider)" != "jamf_connect" ]]
    then
        return 0
    fi
    log_info "JIT provider is jamf_connect — checking Jamf Connect elevations of the last ${JC_LOOKBACK}"
    if [[ ! -x "${JQ}" ]]
    then
        log_error "${JQ} is not available — cannot read Jamf Connect elevations"
        return 1
    fi
    local entries
    if ! entries=$("${LOG_BIN}" show --style ndjson --last "${JC_LOOKBACK}" --predicate "${JC_LOG_PREDICATE}" 2>/dev/null)
    then
        log_error "Could not read the unified log for Jamf Connect elevations"
        return 1
    fi
    JC_ELEVATED=$(jc_open_elevations <<< "${entries}")
    return 0
}

# True for system accounts: a name starting with "_" (e.g. _mbsetupuser,
# which Setup Assistant runs as and which is an admin), or a uid below
# FIRST_USER_UID. $1 short name.
is_system_account() {
    local user="$1"
    [[ "${user}" == _* ]] && return 0
    local uid
    uid=$("${ID}" -u "${user}" 2>/dev/null) || return 1
    [[ "${uid}" =~ ^[0-9]+$ ]] && (( uid < FIRST_USER_UID ))
}

# Whether an admin account can actually be used to administer this Mac: it
# exists, isn't disabled, has a way to authenticate, holds a SecureToken
# (FileVault unlock, enabling other users, software updates) and — on Apple
# silicon — is a volume owner of the boot volume. Anything less must not
# count as the admin left behind. Logs go to stderr: this runs inside
# count_other_admins' command substitution, whose stdout is the count.
admin_account_usable() {
    local user="$1"
    if ! "${ID}" -u "${user}" >/dev/null 2>&1
    then
        return 1
    fi
    if [[ "${user}" == _* ]]
    then
        log_info "Admin '${user}' is a system account — not counted as a usable admin" >&2
        return 1
    fi
    if [[ -n "${JIT_ADMINS}" ]] && printf '%s\n' "${JIT_ADMINS}" | "${GREP}" -qxF -- "${user}"
    then
        log_info "Admin '${user}' holds an active Serberus JIT grant — not counted as a usable admin" >&2
        return 1
    fi
    local user_uid
    user_uid=$("${ID}" -u "${user}" 2>/dev/null) || user_uid=""
    if [[ -n "${JIT_ADMIN_UIDS}" && -n "${user_uid}" ]] \
        && printf '%s\n' "${JIT_ADMIN_UIDS}" | "${GREP}" -qxF -- "${user_uid}"
    then
        log_info "Admin '${user}' (uid ${user_uid}) holds an active Serberus JIT grant — not counted as a usable admin" >&2
        return 1
    fi
    if [[ -n "${JC_ELEVATED}" ]] && printf '%s\n' "${JC_ELEVATED}" | "${GREP}" -qxF -- "${user}"
    then
        log_info "Admin '${user}' has an open Jamf Connect elevation — not counted as a usable admin" >&2
        return 1
    fi
    local authority
    if ! authority=$("${DSCL}" . -read "/Users/${user}" AuthenticationAuthority 2>/dev/null)
    then
        return 1
    fi
    if [[ "${authority}" == *"DisabledUser"* ]]
    then
        return 1
    fi
    if [[ "${authority}" != *"ShadowHash"* && "${authority}" != *"LocalCachedUser"* && "${authority}" != *"Kerberosv5"* ]]
    then
        return 1
    fi

    # sysadminctl reports on stderr: "Secure token is ENABLED for user <Real Name>".
    local token_status
    token_status=$("${SYSADMINCTL}" -secureTokenStatus "${user}" 2>&1) || token_status=""
    if [[ "${token_status}" != *"is ENABLED"* ]]
    then
        log_info "Admin '${user}' holds no SecureToken — not counted as a usable admin" >&2
        return 1
    fi

    if [[ "${IS_APPLE_SILICON}" -eq 1 ]]
    then
        local guid
        guid=$("${DSCL}" . -read "/Users/${user}" GeneratedUID 2>/dev/null | "${AWK}" '{ print toupper($2) }') || guid=""
        if [[ -z "${guid}" ]] || ! printf '%s\n' "${VOLUME_OWNERS}" | "${GREP}" -qx "${guid}"
        then
            log_info "Admin '${user}' is not a volume owner of / — not counted as a usable admin" >&2
            return 1
        fi
    fi
    return 0
}

# Count usable local admin members other than the given user (and root).
count_other_admins() {
    local exclude_user="$1"
    local members
    members=$("${DSCL}" . -read /Groups/admin GroupMembership 2>/dev/null || true)
    members=${members#GroupMembership:}
    local count=0
    local m
    # shellcheck disable=SC2086 — intentional word-splitting of the member list
    for m in ${members}
    do
        if [[ "${m}" != "${exclude_user}" && "${m}" != "root" ]] && admin_account_usable "${m}"
        then
            count=$((count + 1))
        fi
    done
    printf '%s\n' "${count}"
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

current_user=$(get_console_user)

if [[ -z "${current_user}" || "${current_user}" == "loginwindow" || "${current_user}" == "root" ]]
then
    log_warn "No standard console user logged in (got '${current_user:-<none>}') — nothing to do"
    exit 0
fi

# Setup Assistant runs as _mbsetupuser, an admin: demoting a system account
# mid-setup breaks enrollment. Never touched.
if is_system_account "${current_user}"
then
    log_warn "Console user '${current_user}' is a system account — nothing to do"
    exit 0
fi

if ! "${DSEDITGROUP}" -o checkmember -m "${current_user}" admin >/dev/null 2>&1
then
    log_info "User '${current_user}' is NOT a local admin — no change needed"
    exit 0
fi

log_info "User '${current_user}' IS a local admin — evaluating demotion"

detect_apple_silicon
if ! load_jit_admins
then
    log_error "Refusing to demote '${current_user}': without the JIT grants, an admin who is one only"
    log_error "until a Serberus grant expires could be counted as the admin left behind."
    exit 1
fi
if ! load_jc_elevated
then
    log_error "Refusing to demote '${current_user}': Jamf Connect elevations cannot be ruled out, and a"
    log_error "temporary admin could be counted as the admin left behind. Contact ${ORG_NAME_FRIENDLY}."
    exit 1
fi
other_admins=$(count_other_admins "${current_user}")

if [[ "${other_admins}" -lt 1 ]]
then
    log_error "'${current_user}' is the only USABLE local admin (enabled, able to authenticate, holding a"
    log_error "SecureToken and — on Apple silicon — a volume owner). Refusing to demote: the Mac would be"
    log_error "left with no one able to unlock FileVault, install updates or administer it. Grant another"
    log_error "admin a SecureToken (sysadminctl -secureTokenOn) first, then re-run, or contact ${ORG_NAME_FRIENDLY}."
    exit 1
fi

if ! "${DSEDITGROUP}" -o edit -d "${current_user}" -t user admin
then
    log_error "Failed to remove '${current_user}' from admin group"
    exit 1
fi

if "${DSEDITGROUP}" -o checkmember -m "${current_user}" admin >/dev/null 2>&1
then
    log_error "Removal reported success but '${current_user}' is STILL an admin — investigate"
    exit 1
fi

log_info "Removed '${current_user}' from local admin group — now a standard user"
log_info "${SCRIPT_NAME} completed successfully"

###########################################################
################## End Script Block #######################
###########################################################
