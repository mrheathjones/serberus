#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: authprobe-spike.sh
# Author: Heath Jones
# Date: 2026-08-21
# Modified: 2026-09-26
# Purpose: Fully scripted runner for the SerberusAuthProbe spike (chunk 2 of
#          docs/authuri-prompt-plugin-design.md -- THE GATE). Automates every
#          mechanical step of the spike:
#          build, install, the three test stages, cleanup, and a standalone
#          restore escape hatch. Local test-Mac tool only -- NOT deployed via
#          Jamf, never run on a fleet Mac or a daily driver.
# Version: 1.3 - Messages and comments name docs/authuri-prompt-plugin-design.md
#          and describe its questions instead of numbering them;
#          SCRIPT_VERSION matches this header.
#          1.2 - comment wording only.
#          1.1 - System tools by absolute path (several run under sudo,
#          and PATH puts user-writable Homebrew directories first).
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

# Both Homebrew prefixes: /opt/homebrew (Apple Silicon) and /usr/local
# (Intel) — this script is the first one in the repo to shell out to a
# Homebrew-only tool (xcodegen), and the repo's usual PATH template
# (/usr/local/bin only) silently misses it on Apple Silicon.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute paths for every system tool: several run under sudo, and PATH puts
# user-writable Homebrew directories first (for xcodegen), where a planted
# `rm`/`cp`/`security` would otherwise be what root executes.
readonly BASENAME="/usr/bin/basename"
readonly CAT="/bin/cat"
readonly CHOWN="/usr/sbin/chown"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DATE="/bin/date"
readonly DIFF="/usr/bin/diff"
readonly DIRNAME="/usr/bin/dirname"
readonly GREP="/usr/bin/grep"
readonly KILL="/bin/kill"
readonly KILLALL="/usr/bin/killall"
readonly LOG="/usr/bin/log"
readonly LOGGER="/usr/bin/logger"
readonly MKDIR="/bin/mkdir"
readonly MV="/bin/mv"
readonly OPEN="/usr/bin/open"
readonly RM="/bin/rm"
readonly SECURITY="/usr/bin/security"
readonly SLEEP="/bin/sleep"
readonly SUDO="/usr/bin/sudo"
readonly TEE="/usr/bin/tee"

readonly ORG_NAME="Serberus"
readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.3"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.authprobespike"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly REPO_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

# Build-only binaries. Not every machine running this script needs them — the
# realistic workflow is: build on a Mac with Xcode + XcodeGen (--build), then
# copy this script + the built .bundle to the actual test Mac and run
# --install/--stage1/--stage2/--stage3/--cleanup there. Resolved softly so a
# missing Xcode on the test Mac doesn't block every other command.
XCODEBUILD=""
if command -v xcodebuild > /dev/null 2>&1
then
    XCODEBUILD="$(which xcodebuild)"
fi
readonly XCODEBUILD

XCODEGEN=""
if command -v xcodegen > /dev/null 2>&1
then
    XCODEGEN="$(which xcodegen)"
fi
readonly XCODEGEN

CLANG=""
if command -v clang > /dev/null 2>&1
then
    CLANG="$(which clang)"
fi
readonly CLANG

readonly DEVELOPER_DIR_PATH="/Applications/Xcode.app/Contents/Developer"

readonly DERIVED_DATA_DIR="/tmp/serberus-authprobe-dd"
readonly BUNDLE_PATH="${DERIVED_DATA_DIR}/Build/Products/Debug/SerberusAuthProbe.bundle"
readonly INSTALLED_BUNDLE_PATH="/Library/Security/SecurityAgentPlugins/SerberusAuthProbe.bundle"

# Trigger helper (authprobe-trigger.c) — see that file's header
# comment for why Stage 1/2 don't use `security authorize`.
readonly TRIGGER_SOURCE_PATH="${SCRIPT_DIR}/authprobe-trigger.c"
readonly TRIGGER_HELPER_PATH="${DERIVED_DATA_DIR}/authprobe-trigger"

readonly RESULTS_DIR="/tmp/serberus-authprobe-results"
readonly LOG_SUBSYSTEM="com.herojoneslabs.spike.authprobe"
readonly TRIGGER_TIMEOUT_SECONDS=20

readonly DATETIME_RIGHT="system.preferences.datetime"
readonly DATETIME_BACKUP_PATH="${HOME}/system.preferences.datetime.backup.plist"

# The three test rights Stage 1/2 write and remove — one mechanism verdict
# each. Bash 3.2-safe indexed array (no associative arrays).
STAGE1_VERDICTS=(allow deny undefined)

# Mutable state for the trap-based restore-on-exit guards in Stage 2/3. Never
# readonly — these get flipped by do_stage2/do_stage3 and read by the
# matching restore_* function, including from a trap fired by an interrupt.
MOVED_BUNDLE_PATH=""
STAGE3_RESTORE_NEEDED=0

# Order-independent argument parsing: --yes may appear before OR after the
# command (`--yes --stage3` and `--stage3 --yes` both work). MODE is the
# first non---yes argument; a plain `MODE="${1:---help}"` would have broken
# on `--yes --stage3` by taking the literal string "--yes" as the mode.
YES_FLAG=0
MODE="--help"
for arg in "$@"
do
    if [[ "${arg}" == "--yes" ]]
    then
        YES_FLAG=1
        continue
    fi
    MODE="${arg}"
done
readonly YES_FLAG
readonly MODE

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

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

# ── Confirmation gates ───────────────────────────────────────────────────────
confirm() {
    local prompt="$1"
    if [[ "${YES_FLAG}" -eq 1 ]]
    then
        return 0
    fi
    local reply
    read -r -p "${prompt} [type yes to continue]: " reply
    if [[ "${reply}" != "yes" ]]
    then
        log_error "Aborted."
        exit 1
    fi
}

# Stronger gate for Stage 3 (the one real macOS-owned right this whole spike
# touches) — always requires the typed match, --yes does NOT bypass this one.
confirm_exact() {
    local prompt="$1"
    local expected="$2"
    local reply
    read -r -p "${prompt}: " reply
    if [[ "${reply}" != "${expected}" ]]
    then
        log_error "Confirmation text did not match '${expected}'. Aborted — nothing was written."
        exit 1
    fi
}

# ── Preconditions ────────────────────────────────────────────────────────────
require_bundle_built() {
    if [[ ! -d "${BUNDLE_PATH}" ]]
    then
        log_error "${BUNDLE_PATH} not found — run '${SCRIPT_NAME} --build' first."
        exit 1
    fi
}

require_trigger_helper_built() {
    if [[ ! -x "${TRIGGER_HELPER_PATH}" ]]
    then
        log_error "${TRIGGER_HELPER_PATH} not found — run '${SCRIPT_NAME} --build' first."
        exit 1
    fi
}

require_bundle_installed() {
    if [[ ! -e "${INSTALLED_BUNDLE_PATH}/Contents/MacOS/SerberusAuthProbe" ]]
    then
        log_error "${INSTALLED_BUNDLE_PATH} not found — run '${SCRIPT_NAME} --build' then '--install' first."
        exit 1
    fi
}

# Zero-risk, read-only, no-sudo — mirrors the howto's Prereqs step 1. Purely
# informational: this never aborts, since a missing entitlement is evidence
# for the bundle-load question (docs/authuri-prompt-plugin-design.md), not a
# reason to refuse the test.
check_library_validation_entitlement() {
    log_info "Prereq check: SecurityAgentHelper's com.apple.private.security.clear-library-validation entitlement"
    local entitlements=""
    if ! entitlements=$("${CODESIGN}" -d --entitlements - /usr/libexec/SecurityAgentHelper 2>&1)
    then
        log_warn "Could not read SecurityAgentHelper's entitlements (codesign failed) — skipping this check"
        return 0
    fi
    if printf '%s' "${entitlements}" | "${GREP}" -q "com.apple.private.security.clear-library-validation"
    then
        log_info "Present — consistent with a non-platform-signed bundle being able to load (the bundle-load question)"
    else
        log_warn "NOT found. This OS build may not carry the entitlement the load hypothesis in docs/authuri-prompt-plugin-design.md assumes — treat the bundle-load question as genuinely open, not assumed. Proceeding anyway; this is still the fastest way to find out"
    fi
}

# ── Host / bundle lifecycle ──────────────────────────────────────────────────
kill_security_hosts() {
    log_info "Killing SecurityAgent + authorizationhost so the next evaluation maps the current bundle"
    if ! "${SUDO}" "${KILLALL}" SecurityAgent authorizationhost > /dev/null 2>&1
    then
        : # neither was running — fine, nothing to kill
    fi
}

restore_moved_bundle() {
    if [[ -n "${MOVED_BUNDLE_PATH}" && -e "${MOVED_BUNDLE_PATH}" ]]
    then
        log_info "Restoring bundle from ${MOVED_BUNDLE_PATH}"
        "${SUDO}" "${MV}" "${MOVED_BUNDLE_PATH}" "${INSTALLED_BUNDLE_PATH}"
        kill_security_hosts
        MOVED_BUNDLE_PATH=""
    fi
}

restore_datetime_right() {
    if [[ "${STAGE3_RESTORE_NEEDED}" -eq 1 ]]
    then
        log_info "Restoring ${DATETIME_RIGHT} from ${DATETIME_BACKUP_PATH}"
        "${SUDO}" "${SECURITY}" authorizationdb write "${DATETIME_RIGHT}" < "${DATETIME_BACKUP_PATH}"
        kill_security_hosts
        STAGE3_RESTORE_NEEDED=0
    fi
}

# Bash quirk: when a trap is registered for INT, a SIGINT that interrupts the
# `read` builtin runs the trap and then RESUMES the read instead of aborting
# it — so a plain `trap restore_datetime_right INT` would restore the real
# right correctly but then silently sit at the same prompt as if nothing
# happened (observed: Ctrl-C during Stage 3's "press Enter" pause
# restores state instantly, then just keeps waiting for input). These two
# wrappers are registered for INT/TERM specifically so a tester's Ctrl-C
# actually ends the script after restoring, instead of quietly resuming.
handle_stage2_interrupt() {
    log_warn "Interrupted — restoring the plugin bundle before exiting"
    restore_moved_bundle
    exit 130
}

handle_stage3_interrupt() {
    log_warn "Interrupted — restoring ${DATETIME_RIGHT} before exiting"
    restore_datetime_right
    exit 130
}

# ── security authorizationdb helpers ─────────────────────────────────────────
# write_authdb_right <right-name> <comment> <mechanism> [mechanism...]
# Requires root (writes /var/db/auth.db).
write_authdb_right() {
    local right_name="$1"
    shift
    local comment="$1"
    shift

    local mechanisms_xml=""
    local mechanism
    for mechanism in "$@"
    do
        mechanisms_xml="${mechanisms_xml}        <string>${mechanism}</string>
"
    done

    log_info "Writing authorizationdb right '${right_name}' -> mechanisms: $*"
    # `identifier`/`requirement` are set EXPLICITLY here, deliberately
    # unsatisfiable by any real caller. Confirmed live: `security
    # authorizationdb write` auto-injects a `requirement` pinned to ITS OWN
    # code identity (`identifier "com.apple.security" and anchor apple`) on
    # a brand-new right when the input plist doesn't set one. A satisfied
    # `requirement` is a fast-path bypass that skips class/mechanisms
    # evaluation entirely — so writing with `security` and then triggering
    # with `security authorize` (the same binary) self-satisfies that
    # auto-injected requirement and grants immediately without ever running
    # the mechanism. Every real Apple evaluate-mechanisms right we compared
    # against (e.g. `authenticate`) has NO requirement key at all — this
    # bypass isn't how real rights are supposed to work, it's an artifact of
    # using one tool for both write and trigger. Overriding to a clause that
    # can never match anything neutralizes the bypass so evaluation actually
    # reaches class/mechanisms.
    if ! "${CAT}" <<PLIST_EOF | "${SUDO}" "${SECURITY}" authorizationdb write "${right_name}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>class</key>
    <string>evaluate-mechanisms</string>
    <key>mechanisms</key>
    <array>
${mechanisms_xml}    </array>
    <key>shared</key>
    <false/>
    <key>timeout</key>
    <integer>0</integer>
    <key>tries</key>
    <integer>1</integer>
    <key>comment</key>
    <string>${comment}</string>
    <key>identifier</key>
    <string>com.herojoneslabs.serberus.authprobe.spike</string>
    <key>requirement</key>
    <string>identifier "com.herojoneslabs.serberus.authprobe.spike.no-such-caller" and anchor apple</string>
</dict>
</plist>
PLIST_EOF
    then
        log_error "authorizationdb write FAILED for '${right_name}' — the right below is almost certainly NOT what actually got queried"
    fi

    # Read back what actually landed, rather than trusting the write call's
    # own success/failure alone — this is the direct evidence for whether
    # the right macOS is about to evaluate matches what we intended.
    log_info "Readback of '${right_name}' as currently registered:"
    if ! "${SECURITY}" authorizationdb read "${right_name}" 2>&1
    then
        log_warn "Could not read back '${right_name}' — it may not exist at all"
    fi
}

# ── Timeout wrapper (macOS ships no GNU `timeout`) ───────────────────────────
# run_with_timeout <seconds> <command...>
run_with_timeout() {
    local timeout_seconds="$1"
    shift

    "$@" &
    local cmd_pid=$!
    local waited=0

    while "${KILL}" -0 "${cmd_pid}" 2>/dev/null
    do
        if [[ ${waited} -ge ${timeout_seconds} ]]
        then
            log_warn "Command timed out after ${timeout_seconds}s — killing pid ${cmd_pid}"
            if ! "${KILL}" -TERM "${cmd_pid}" 2>/dev/null
            then
                : # already exited — fine
            fi
            if ! wait "${cmd_pid}" 2>/dev/null
            then
                : # expected — we just killed it
            fi
            return 124
        fi
        "${SLEEP}" 1
        waited=$((waited + 1))
    done

    local wait_status=0
    if ! wait "${cmd_pid}"
    then
        wait_status=$?
    fi
    return "${wait_status}"
}

# ── Unified log capture ───────────────────────────────────────────────────────
# pull_logs <start-timestamp> <out-file>
pull_logs() {
    local start_ts="$1"
    local out_file="$2"

    "${SLEEP}" 1
    if ! "${LOG}" show --predicate "subsystem == \"${LOG_SUBSYSTEM}\"" --style compact --start "${start_ts}" > "${out_file}" 2>&1
    then
        log_warn "log show reported an error — see ${out_file}"
    fi
    "${CAT}" "${out_file}"
}

# If the bundle fails to LOAD (codesigning/dlopen/library-validation), our
# own code never runs, so pull_logs's subsystem filter sees nothing — but
# the OS itself usually logs something about the load failure under the
# hosting processes' own names, not our subsystem. This is the same window,
# filtered by process instead, to catch that.
pull_broad_logs() {
    local start_ts="$1"
    local out_file="$2"

    if ! "${LOG}" show --predicate 'process == "SecurityAgentHelper" OR process == "authorizationhost" OR process == "security"' --style compact --start "${start_ts}" > "${out_file}" 2>&1
    then
        log_warn "log show reported an error — see ${out_file}"
    fi
    "${CAT}" "${out_file}"
}

# ── Trigger a right via the CLI (no daemon, no System Settings) ─────────────
# trigger_right <right-name> <report-label>
trigger_right() {
    local right_name="$1"
    local label="$2"
    local start_ts
    start_ts=$("${DATE}" '+%Y-%m-%d %H:%M:%S')
    local out_file="${RESULTS_DIR}/${label}.trigger.log"
    local log_file="${RESULTS_DIR}/${label}.unified-log.txt"
    local broad_log_file="${RESULTS_DIR}/${label}.broad-log.txt"

    # NOT `security authorize`: confirmed live that `security
    # authorizationdb write` unconditionally stamps a new right's
    # identifier/requirement to `security`'s OWN code identity, so
    # triggering with `security authorize` (same binary) always
    # self-satisfies that stamp and bypasses class/mechanisms entirely —
    # see authprobe-trigger.c's header comment. This helper has a
    # different code identity, so it doesn't get the free pass.
    log_info "Triggering: ${TRIGGER_HELPER_PATH} ${right_name}"
    local exit_code=0
    if ! run_with_timeout "${TRIGGER_TIMEOUT_SECONDS}" "${TRIGGER_HELPER_PATH}" "${right_name}" > "${out_file}" 2>&1
    then
        exit_code=$?
    fi
    log_info "trigger helper exited ${exit_code} — output:"
    "${CAT}" "${out_file}"

    log_info "Unified log window for this trigger (our subsystem only):"
    pull_logs "${start_ts}" "${log_file}"

    log_info "Unified log window for this trigger (SecurityAgentHelper/authorizationhost/security — catches a load failure our own code never got a chance to log):"
    pull_broad_logs "${start_ts}" "${broad_log_file}"

    log_info "Saved: ${out_file}"
    log_info "Saved: ${log_file}"
    log_info "Saved: ${broad_log_file}"
}

# ── Commands ──────────────────────────────────────────────────────────────────
do_build() {
    if [[ -z "${XCODEBUILD}" ]]
    then
        log_error "xcodebuild not found — is Xcode installed (not just Command Line Tools)?"
        exit 1
    fi

    # Non-blocking heads-up, not a hard gate: codesigning needs the Apple
    # Development cert's chain to the WWDR intermediate, which lives in the
    # login keychain — inaccessible if it's locked or if this shell doesn't
    # have a normal local console session (hit live: "unable to build chain
    # to self-signed root", errSecInternalComponent). A locked/SSH-only
    # session is the most common cause; still attempt the build regardless
    # since this check can't distinguish every cause cleanly.
    if ! "${SECURITY}" find-identity -v -p codesigning 2>/dev/null | "${GREP}" -q "1) "
    then
        log_warn "No codesigning identities visible right now — if the build below fails with an 'unable to build chain to self-signed root' or errSecInternalComponent error, the login keychain is probably locked or inaccessible from this session. Try: security unlock-keychain ~/Library/Keychains/login.keychain-db (and prefer a local Terminal session over SSH/remote if you're on one)."
    fi

    if [[ ! -e "${REPO_DIR}/Serberus.xcodeproj/project.pbxproj" ]]
    then
        log_error "${REPO_DIR}/Serberus.xcodeproj not found. Copy the whole repo (the .xcodeproj is committed) to this Mac, or build on a Mac with Xcode + XcodeGen and copy the built .bundle + this script over instead."
        exit 1
    fi

    # XcodeGen is optional here, not required: this repo commits the generated
    # Serberus.xcodeproj ("Contributors do NOT need XcodeGen... just open it",
    # project.yml's own header comment) — it only needs regenerating when
    # project.yml has changed since the .xcodeproj was last committed/copied.
    # A test Mac with no Homebrew/XcodeGen at all can still build straight
    # from the committed .xcodeproj.
    if [[ -n "${XCODEGEN}" ]]
    then
        log_info "Regenerating Xcode project (xcodegen generate)"
        ( cd "${REPO_DIR}" && "${XCODEGEN}" generate )
    else
        log_warn "xcodegen not found — building directly against the existing Serberus.xcodeproj as committed/copied. If project.yml changed since that .xcodeproj was generated, this build won't reflect it; regenerate it on a Mac that has XcodeGen and re-copy."
    fi

    # Always start from a clean derived-data dir. Reusing it across runs
    # risks codesign failing with "resource fork, Finder information, or
    # similar detritus not allowed" — hit live — if Finder ever browsed
    # into it (auto-drops .DS_Store) or any other tool left extended
    # attributes/AppleDouble files inside the built .bundle. This is
    # disposable build output, not worth trying to detect/strip cruft from
    # incrementally; wiping it is simpler and guaranteed to work.
    "${RM}" -rf "${DERIVED_DATA_DIR}"

    log_info "Building SerberusAuthProbe (Debug) -> ${DERIVED_DATA_DIR}"
    export DEVELOPER_DIR="${DEVELOPER_DIR_PATH}"
    # `generic/platform=macOS`, not `platform=macOS` — the latter makes
    # xcodebuild resolve the local Mac as a connected "device" via
    # DVTDeviceOperation, which can fail with "Encountered a build number
    # "" that is incompatible with DVTBuildVersion" on some Xcode/macOS
    # combinations (hit live on a test Mac). generic/ skips that resolution
    # entirely and still produces a real build product for a macOS-only
    # bundle target.
    if ! "${XCODEBUILD}" build \
        -project "${REPO_DIR}/Serberus.xcodeproj" \
        -scheme SerberusAuthProbe \
        -destination 'generic/platform=macOS' \
        -derivedDataPath "${DERIVED_DATA_DIR}"
    then
        log_error "Build failed"
        exit 1
    fi

    if [[ ! -d "${BUNDLE_PATH}" ]]
    then
        log_error "Build reported success but ${BUNDLE_PATH} is missing — unexpected"
        exit 1
    fi

    log_info "Built ${BUNDLE_PATH}"

    if [[ -z "${CLANG}" ]]
    then
        log_error "clang not found — needed to build the Stage 1/2 trigger helper (authprobe-trigger.c)"
        exit 1
    fi
    if [[ ! -e "${TRIGGER_SOURCE_PATH}" ]]
    then
        log_error "${TRIGGER_SOURCE_PATH} not found"
        exit 1
    fi

    log_info "Building the Stage 1/2 trigger helper -> ${TRIGGER_HELPER_PATH}"
    if ! "${CLANG}" -Wall -Wextra -framework Security -o "${TRIGGER_HELPER_PATH}" "${TRIGGER_SOURCE_PATH}"
    then
        log_error "Trigger helper build failed"
        exit 1
    fi

    log_info "Built ${TRIGGER_HELPER_PATH}"
}

do_install() {
    require_bundle_built
    check_library_validation_entitlement
    confirm "About to install ${BUNDLE_PATH} to ${INSTALLED_BUNDLE_PATH} (requires sudo). This is a THROWAWAY diagnostic plugin — only do this on the designated test Mac, never a fleet Mac or your daily driver"

    "${SUDO}" "${MKDIR}" -p "$("${DIRNAME}" "${INSTALLED_BUNDLE_PATH}")"

    if [[ -e "${INSTALLED_BUNDLE_PATH}" ]]
    then
        "${SUDO}" "${RM}" -rf "${INSTALLED_BUNDLE_PATH}"
    fi

    "${SUDO}" "${CP}" -R "${BUNDLE_PATH}" "$("${DIRNAME}" "${INSTALLED_BUNDLE_PATH}")/"
    "${SUDO}" "${CHOWN}" -R root:wheel "${INSTALLED_BUNDLE_PATH}"

    kill_security_hosts

    log_info "Installed ${INSTALLED_BUNDLE_PATH}"
}

do_stage1() {
    require_bundle_installed
    require_trigger_helper_built
    confirm "Stage 1: writes three invented authorization rights (com.herojoneslabs.serberus.spike.{allow,deny,undefined}) and triggers each via the trigger helper (not 'security authorize' — see authprobe-trigger.c). Nothing here touches a right macOS itself queries"

    "${MKDIR}" -p "${RESULTS_DIR}"

    local verdict
    local right_name
    for verdict in "${STAGE1_VERDICTS[@]}"
    do
        right_name="com.herojoneslabs.serberus.spike.${verdict}"
        write_authdb_right "${right_name}" "SerberusAuthProbe spike — ${verdict} path" "SerberusAuthProbe:${verdict}"
        kill_security_hosts
        trigger_right "${right_name}" "stage1-${verdict}"
    done

    log_info "Stage 1 cleanup: removing the three invented rights"
    for verdict in "${STAGE1_VERDICTS[@]}"
    do
        right_name="com.herojoneslabs.serberus.spike.${verdict}"
        if ! "${SUDO}" "${SECURITY}" authorizationdb remove "${right_name}" > /dev/null 2>&1
        then
            log_warn "Could not remove ${right_name} (may already be gone)"
        fi
    done

    log_info "Stage 1 complete. Reports in ${RESULTS_DIR}/stage1-*"
}

do_stage2() {
    require_bundle_installed
    require_trigger_helper_built
    confirm "Stage 2: temporarily moves the installed bundle aside to test absent-bundle behavior (the absent-bundle question), writing/reusing the Stage 1 'allow' right to trigger it"

    "${MKDIR}" -p "${RESULTS_DIR}"

    local right_name="com.herojoneslabs.serberus.spike.allow"
    write_authdb_right "${right_name}" "SerberusAuthProbe spike — Stage 2 absent-bundle test" "SerberusAuthProbe:allow"

    MOVED_BUNDLE_PATH="/tmp/SerberusAuthProbe.bundle.moved.$$"
    trap restore_moved_bundle EXIT
    trap handle_stage2_interrupt INT TERM

    "${SUDO}" "${MV}" "${INSTALLED_BUNDLE_PATH}" "${MOVED_BUNDLE_PATH}"
    kill_security_hosts

    log_warn "Bundle is now absent — this is the absent-bundle question's exact scenario. If the trigger hangs past ${TRIGGER_TIMEOUT_SECONDS}s the script kills it itself"
    trigger_right "${right_name}" "stage2-absent-bundle"

    restore_moved_bundle
    trap - EXIT INT TERM

    if ! "${SUDO}" "${SECURITY}" authorizationdb remove "${right_name}" > /dev/null 2>&1
    then
        log_warn "Could not remove ${right_name} (may already be gone)"
    fi

    log_info "Stage 2 complete. Bundle restored. Report in ${RESULTS_DIR}/stage2-absent-bundle.*"
}

do_stage3() {
    require_bundle_installed

    log_warn "Stage 3 touches a REAL macOS-owned right: ${DATETIME_RIGHT}. This is the one part of the whole spike that is not purely inert"
    confirm_exact "Type the exact right name to continue" "${DATETIME_RIGHT}"

    "${MKDIR}" -p "${RESULTS_DIR}"

    log_info "Backing up ${DATETIME_RIGHT} to ${DATETIME_BACKUP_PATH}"
    "${SECURITY}" authorizationdb read "${DATETIME_RIGHT}" > "${DATETIME_BACKUP_PATH}"
    if [[ ! -s "${DATETIME_BACKUP_PATH}" ]]
    then
        log_error "Backup came back empty — refusing to continue. Nothing has been written yet"
        exit 1
    fi
    "${CP}" "${DATETIME_BACKUP_PATH}" "${RESULTS_DIR}/${DATETIME_RIGHT}.backup.plist"

    STAGE3_RESTORE_NEEDED=1
    trap restore_datetime_right EXIT
    trap handle_stage3_interrupt INT TERM

    write_authdb_right "${DATETIME_RIGHT}" \
        "SerberusAuthProbe spike — TEMPORARY, restored automatically" \
        "SerberusAuthProbe:allow" "builtin:authenticate" "builtin:authenticate,privileged"
    kill_security_hosts

    if ! "${OPEN}" "x-apple.systempreferences:com.apple.preference.datetime"
    then
        log_warn "Could not auto-open System Settings — open Date & Time manually"
    fi

    local start_ts
    start_ts=$("${DATE}" '+%Y-%m-%d %H:%M:%S')

    printf '\n'
    printf 'System Settings -> General -> Date & Time should now be open.\n'
    printf 'Click the lock and attempt a change. Watch for:\n'
    printf '  - Q2: does the mechanism actually run at all (checked below via the log window)?\n'
    printf '  - Q7: any window focus steal (a known macOS 26.1 regression) even though the mechanism has no UI?\n'
    printf '  - Q9: which password prompt does builtin:authenticate show — session owner, or an admin picker?\n'
    printf '\n'
    read -r -p "Press Enter once you have finished testing in System Settings: " _

    pull_logs "${start_ts}" "${RESULTS_DIR}/stage3-datetime.unified-log.txt"
    pull_broad_logs "${start_ts}" "${RESULTS_DIR}/stage3-datetime.broad-log.txt"

    restore_datetime_right
    trap - EXIT INT TERM

    log_info "Verifying the restore"
    if "${DIFF}" <("${SECURITY}" authorizationdb read "${DATETIME_RIGHT}") "${DATETIME_BACKUP_PATH}" > /dev/null 2>&1
    then
        log_info "Verified: ${DATETIME_RIGHT} matches its backup"
    else
        log_error "MISMATCH: ${DATETIME_RIGHT} does NOT match its backup. Run: ${SCRIPT_NAME} --restore-datetime"
        exit 1
    fi

    log_info "Stage 3 complete. Log window saved to ${RESULTS_DIR}/stage3-datetime.unified-log.txt"
}

# Standalone escape hatch — independent of any in-process trap state, safe to
# run any time (fresh invocation, after a crash, after Ctrl-C that a SIGKILL
# would have skipped past a trap) as long as the backup file exists.
do_restore_datetime() {
    if [[ ! -s "${DATETIME_BACKUP_PATH}" ]]
    then
        log_error "No backup found at ${DATETIME_BACKUP_PATH} — nothing to restore from"
        exit 1
    fi

    log_info "Restoring ${DATETIME_RIGHT} from ${DATETIME_BACKUP_PATH}"
    "${SUDO}" "${SECURITY}" authorizationdb write "${DATETIME_RIGHT}" < "${DATETIME_BACKUP_PATH}"
    kill_security_hosts

    if "${DIFF}" <("${SECURITY}" authorizationdb read "${DATETIME_RIGHT}") "${DATETIME_BACKUP_PATH}" > /dev/null 2>&1
    then
        log_info "Verified: ${DATETIME_RIGHT} matches its backup"
    else
        log_error "MISMATCH persists after restore. Investigate manually: security authorizationdb read ${DATETIME_RIGHT}"
        exit 1
    fi
}

do_cleanup() {
    confirm "Cleanup: removes the installed plugin bundle, removes any lingering Stage 1 rights, and verifies ${DATETIME_RIGHT} against its backup if one exists"

    local had_problem=0

    if [[ -e "${INSTALLED_BUNDLE_PATH}" ]]
    then
        "${SUDO}" "${RM}" -rf "${INSTALLED_BUNDLE_PATH}"
        log_info "Removed ${INSTALLED_BUNDLE_PATH}"
    fi
    kill_security_hosts

    local verdict
    local right_name
    for verdict in "${STAGE1_VERDICTS[@]}"
    do
        right_name="com.herojoneslabs.serberus.spike.${verdict}"
        if "${SECURITY}" authorizationdb read "${right_name}" > /dev/null 2>&1
        then
            if ! "${SUDO}" "${SECURITY}" authorizationdb remove "${right_name}" > /dev/null 2>&1
            then
                log_warn "Could not remove ${right_name}"
            else
                log_info "Removed lingering right ${right_name}"
            fi
        fi
    done

    if [[ -s "${DATETIME_BACKUP_PATH}" ]]
    then
        if "${DIFF}" <("${SECURITY}" authorizationdb read "${DATETIME_RIGHT}") "${DATETIME_BACKUP_PATH}" > /dev/null 2>&1
        then
            log_info "${DATETIME_RIGHT} matches its backup — clean"
        else
            log_error "${DATETIME_RIGHT} does NOT match its backup. Run: ${SCRIPT_NAME} --restore-datetime"
            had_problem=1
        fi
    else
        log_info "No ${DATETIME_RIGHT} backup found — Stage 3 was never run, nothing to verify"
    fi

    log_info "Cleanup complete"
    if [[ "${had_problem}" -eq 1 ]]
    then
        exit 1
    fi
}

do_all() {
    do_build
    do_install
    do_stage1
    do_stage2
    log_info "'--all' complete (build, install, stage1, stage2). Stage 3 is opt-in only — run '${SCRIPT_NAME} --stage3' separately when ready"
}

print_usage() {
    "${CAT}" <<USAGE_EOF
Usage: ${SCRIPT_NAME} <command> [--yes]

Runs the SerberusAuthProbe spike (docs/authuri-prompt-plugin-design.md chunk 2).
ONLY run this on the designated
test Mac — never a fleet Mac, never your daily driver.

Commands:
  --build             Build SerberusAuthProbe.bundle (regenerates the Xcode project first if xcodegen is
                      available; otherwise builds directly against the committed .xcodeproj)
  --install           Install the built bundle to ${INSTALLED_BUNDLE_PATH}
  --stage1            Safe CLI-only test against three invented rights (the load, deny, Undefined, hint and host-identity questions)
  --stage2            Absent-bundle test (the absent-bundle question) — auto move/restore
  --stage3            Real System Settings right test (the Settings, focus and chained-authenticate questions) — backup/restore/verify
  --restore-datetime  Standalone escape hatch: restore ${DATETIME_RIGHT} from its backup
  --cleanup           Full teardown: remove bundle, remove lingering rights, verify datetime
  --all               --build, --install, --stage1, --stage2 in sequence (--stage3 always separate/opt-in)

  --yes               Skip the "type yes" confirmations (does NOT skip Stage 3's typed right-name gate)

Reports are written to ${RESULTS_DIR}/.
USAGE_EOF
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

# Capture EVERYTHING (not just the per-trigger report files individual
# commands write) to one session log — this is what settles ambiguous
# results: did a write actually succeed, what exactly did each command
# print, in what order. Added after the first real run's per-trigger
# reports alone weren't enough to tell "mechanism never ran" apart from
# "a write silently failed" — this makes that distinction directly visible
# without needing to re-instrument and re-run again.
"${MKDIR}" -p "${RESULTS_DIR}"
readonly SESSION_LOG="${RESULTS_DIR}/session-$("${DATE}" '+%Y%m%d-%H%M%S').log"
exec > >("${TEE}" -a "${SESSION_LOG}") 2>&1

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (mode ${MODE})"
log_info "Full session output: ${SESSION_LOG}"

case "${MODE}" in
    --build)
        do_build
        ;;
    --install)
        do_install
        ;;
    --stage1)
        do_stage1
        ;;
    --stage2)
        do_stage2
        ;;
    --stage3)
        do_stage3
        ;;
    --restore-datetime)
        do_restore_datetime
        ;;
    --cleanup)
        do_cleanup
        ;;
    --all)
        do_all
        ;;
    --help|-h)
        print_usage
        exit 0
        ;;
    *)
        print_usage
        exit 1
        ;;
esac

log_info "${SCRIPT_NAME} completed successfully"

###########################################################
################## End Script Block #######################
###########################################################
