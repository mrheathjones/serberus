#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-test-pkg.sh
# Author: Heath Jones
# Date: 2026-07-09
# Modified: 2026-09-26
# Purpose: Build the TEST-RING Serberus daemon PKG for Jamf policy deployment.
#          Packages the bare serberusd binary (Apple Development signed, no ESF
#          bundle, no provisioning profile, no PAM, no notarization) plus its
#          LaunchDaemon plist, an on-disk uninstall helper and the shared
#          pam-lib.sh. Suitable for authURI live testing only — production
#          endpoints use build-pkg.sh.
# Version: 1.6 - Generated scripts: the uninstall helper's --purge removes
#          data only (apps and other helpers stay) and gates the plugin on
#          pam-lib.sh 1.8's records-and-rights check (pending .json,
#          .branches or .projection records, composition rows invoking
#          SerberusAuth, rights delegating to them; never a comment), and
#          with no daemon only those records mean something to restore
#          (a .standin does not); the preinstall writes the
#          upgrade marker for the new daemon and logs the SCRIPT_VERSION its
#          header states; teardowns wait ExitTimeOut plus 5 s after a bootout.
#          1.5 - Generated scripts: teardowns wait for launchd to drop the
#                job after a bootout before any one-shot and pin the daemon
#                to the team recorded in version.plist (when present); the
#                disable comes after the unwire; the preinstall re-checks
#                the drop-in right after the bootout and runs the old
#                daemon's --demote-jit whenever its binary exists; the
#                uninstall helper sources pam-lib.sh only through a root-only
#                path chain and exits 1 when the drop-in survives; the
#                re-wire removes a stray pam_serberus.so.2 first.
#          1.4 - Refuses SIGNING_IDENTITY="-" (no ad-hoc fallback). Generated
#                scripts: the postinstall ABORTS unless the daemon passes
#                pam-lib serberus_daemon_trusted (strict signature, Apple
#                anchor, identifier, Team ID); every daemon one-shot (helper,
#                legacy restore, preinstall --demote-jit before the upgrade
#                bootout) is gated on it; stricter liveness (bootstrap mark,
#                8 s window, no restart, fresh state.plist, pid re-read
#                before the re-wire); a surviving sudoers drop-in stops every
#                teardown before sudo_local is unwired; --demote-jit exit 3 is
#                informational; each chown/chmod is checked. The payload
#                carries no bundle, so pkgbuild needs no component plist
#                (asserted by test-sentinel-lib.sh).
#          1.3 - pam-lib.sh is staged into the pkg scripts (and installed
#                beside the uninstall helper) so every abort and teardown can
#                unwire sudo_local. Generated scripts: umask 022; EXIT traps;
#                teardown-first upgrade in the preinstall (the postinstall
#                re-wires what it removed, after the new daemon is up and the
#                module checks out); the abort keeps the daemon running when an
#                active pam_serberus line survives the unwire; stable-pid
#                liveness; bounded one-shots with SERBERUS_DEV_KEY_FALLBACK
#                exported (as the LaunchDaemon sets it); an unverified daemon
#                is never executed by the abort path; plugin + backups removed
#                only when the live AuthorizationDB is clean; boot volume ($3)
#                required. The daemon is signed with an explicit identifier
#                (peers pin com.herojoneslabs.serberus.daemon). Absolute
#                builder tool paths.
#          1.2 - Builds under PKG/build-test/daemon (its own subdir: the old
#                `rm -rf PKG/build-test` wiped every other test pkg's output).
#                New --emit-scripts <dir> mode for the shell tests. Generated
#                scripts: system-only PATH and absolute tools; the postinstall
#                enables the label before bootstrap, waits for a running pid,
#                and every abort disables + boots out the daemon and removes
#                the sudoers drop-in; the uninstall helper follows the new
#                teardown order (disable -> drop-in -> unwire -> bootout ->
#                demote JIT -> restore -> plugin only if restored -> files).
#          1.1 - preinstall now uninstalls any PREVIOUS Serberus daemon before
#                install: restores its AuthorizationDB from its own snapshots,
#                boots it out, removes its artifacts, and forgets its receipts.
#                Covers both the current com.herojoneslabs prefix and the legacy
#                com.heath prefix (old test/prod rings).
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER, never sudo — codesign needs the Apple
# Development chain in your login keychain):
#
#   SIGNING_IDENTITY=<Apple Development cert hash or name> ./PKG/build-test-pkg.sh
#
# Optional env:
#   INSTALLER_IDENTITY  "Developer ID Installer: Your Name (YOURTEAMID)"
#                       — signs the .pkg (recommended; unsigned still installs
#                       via Jamf *policy*, but PreStage/InstallApplication and
#                       double-click installs require a signed pkg)
#   DAEMON_BIN          path to a prebuilt Release serberusd (skips xcodebuild)
#   PKG_VERSION         package version (default 1.0.0)
#   SERBERUS_DEV_KEY_FALLBACK          baked into the LaunchDaemon env (default 1)
#   SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT baked into the LaunchDaemon env if set
#
# Modes:
#   (default / --build)       build the pkg
#   --emit-scripts <dir>      write the generated scripts + uninstall helper to
#                             <dir> without building (shell tests)
#
# Deploy: upload the built pkg to Jamf, install via policy. Teardown on the
# test machine (or via a Jamf teardown policy):
#   sudo "/Library/Application Support/Serberus/uninstall-serberusd-test.sh"

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

readonly AWK="/usr/bin/awk"
readonly BASENAME="/usr/bin/basename"
readonly BASH_BIN="/bin/bash"
readonly CAT="/bin/cat"
readonly CHMOD="/bin/chmod"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly ID="/usr/bin/id"
readonly MKDIR="/bin/mkdir"
readonly PKGBUILD="/usr/bin/pkgbuild"
readonly PLUTIL="/usr/bin/plutil"
readonly PRODUCTSIGN="/usr/bin/productsign"
readonly RM="/bin/rm"
readonly XATTR="/usr/bin/xattr"
# The xcodebuild shim in /usr/bin resolves the selected Xcode.
readonly XCODEBUILD="/usr/bin/xcodebuild"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.6"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

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
readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly LOG_DIR="/Library/Logs/Serberus"
readonly UNINSTALL_HELPER_NAME="uninstall-serberusd-test.sh"
# The shared sudo_local / teardown library: staged into the pkg scripts (the
# pre/postinstall source it) and installed beside the uninstall helper.
readonly PAM_LIB_NAME="pam-lib.sh"
readonly PAM_LIB_SRC="${SCRIPT_DIR}/Scripts/${PAM_LIB_NAME}"

# Distinct identifier from the production pkg (com.herojoneslabs.serberus.pkg) so
# receipts never masquerade as a production install.
readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.testpkg"
readonly PKG_VERSION="${PKG_VERSION:-1.0.0}"
readonly MODE="${1:---build}"
readonly EMIT_DIR="${2:-}"
# Its OWN subdir of build-test, so the `rm -rf` below can never clobber a
# sibling test pkg's output (core/, pam/, sentinel-app/, …).
if [[ "${MODE}" == "--emit-scripts" && -n "${EMIT_DIR}" ]]
then
    readonly BUILD_DIR="${EMIT_DIR}"
else
    readonly BUILD_DIR="${SCRIPT_DIR}/build-test/daemon"
fi
readonly PAYLOAD_DIR="${BUILD_DIR}/payload"
readonly SCRIPTS_DIR="${BUILD_DIR}/scripts"
readonly OUTPUT_PKG="${BUILD_DIR}/Serberus-daemon-test-${PKG_VERSION}.pkg"
readonly SIGNED_PKG="${BUILD_DIR}/Serberus-daemon-test-${PKG_VERSION}-signed.pkg"

# Built artifact. Built by build_daemon() unless DAEMON_BIN points elsewhere.
readonly XCODE_PRODUCTS="${REPO_DIR}/.build/xcode/Build/Products/Release"
readonly DAEMON_BIN_OVERRIDE="${DAEMON_BIN:-}"
readonly DAEMON_BIN="${DAEMON_BIN:-${XCODE_PRODUCTS}/serberusd}"

# Signing inputs. SIGNING_IDENTITY is REQUIRED and should be the Apple
# Development identity (hash or name) — un-notarized Developer ID + Hardened
# Runtime is AMFI-killed at launch, and this test pkg never notarizes.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"

# Dev escape hatches baked into the LaunchDaemon EnvironmentVariables. This is
# a TEST-RING pkg, so the on-disk HMAC key fallback defaults ON; the Sentinel
# entitlement skip stays off unless exported (only needed for prompt-rule
# testing with a locally-signed Sentinel). Both are unset in production.
readonly SERBERUS_DEV_KEY_FALLBACK="${SERBERUS_DEV_KEY_FALLBACK:-1}"
readonly SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT="${SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT:-}"

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

log_warn() {
    printf '[WARN] %s\n' "$*" >&2
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
    # Must NOT run as root: `sudo codesign` cannot build the Apple Development
    # chain (the cert lives in the logging-in user's login keychain), and
    # pkgbuild's default `recommended` ownership makes root ownership at
    # install time, so a non-root build is correct.
    if [[ "$("${ID}" -u)" -eq 0 ]]
    then
        log_error "Run as the logged-in user, not root (codesign needs your login keychain)."
        exit 1
    fi

    # No ad-hoc fallback: an ad-hoc daemon has no Team ID for the module, the
    # plugin or its own execution checks to pin to.
    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_error "SIGNING_IDENTITY is required and may not be \"-\" (Apple Development cert hash or name; ad-hoc is refused)."
        log_error "  security find-identity -v -p codesigning   # list identities"
        log_error "  SIGNING_IDENTITY=<hash> ./PKG/${SCRIPT_NAME}"
        exit 1
    fi

    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        log_warn "INSTALLER_IDENTITY unset — the installer pkg will be UNSIGNED."
        log_warn "Jamf policy installs accept unsigned pkgs; set INSTALLER_IDENTITY to sign."
    fi

    if [[ ! -f "${PAM_LIB_SRC}" ]]
    then
        log_error "Missing ${PAM_LIB_SRC} — pam-lib.sh ships inside the pkg scripts and payload."
        exit 1
    fi
}

# The generated scripts source pam-lib.sh from their own directory (pkgbuild
# ships every file in --scripts alongside them); the payload copy serves the
# on-disk uninstall helper.
stage_pam_lib() {
    "${CP}" "${PAM_LIB_SRC}" "${SCRIPTS_DIR}/${PAM_LIB_NAME}"
    "${CHMOD}" 644 "${SCRIPTS_DIR}/${PAM_LIB_NAME}"
    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/${PAM_LIB_NAME}"
    then
        log_error "pam-lib.sh failed bash -n: ${SCRIPTS_DIR}/${PAM_LIB_NAME}"
        exit 1
    fi
}

build_daemon() {
    if [[ -n "${DAEMON_BIN_OVERRIDE}" ]]
    then
        log_info "Using prebuilt daemon binary: ${DAEMON_BIN}"
        if [[ ! -f "${DAEMON_BIN}" ]]
        then
            log_error "DAEMON_BIN not found: ${DAEMON_BIN}"
            exit 1
        fi
        return 0
    fi

    log_info "Building serberusd (Release) from Serberus.xcodeproj"
    "${XCODEBUILD}" \
        -project "${REPO_DIR}/Serberus.xcodeproj" \
        -scheme serberusd \
        -configuration Release \
        -derivedDataPath "${REPO_DIR}/.build/xcode" \
        CODE_SIGNING_ALLOWED=NO \
        build >/dev/null

    if [[ ! -f "${DAEMON_BIN}" ]]
    then
        log_error "Build completed but binary not found: ${DAEMON_BIN}"
        exit 1
    fi
}

write_entitlements() {
    local entitlements_file="${BUILD_DIR}/serberusd-test.entitlements"
    "${CAT}" > "${entitlements_file}" <<'ENTITLEMENTS_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>
ENTITLEMENTS_EOF
    printf '%s' "${entitlements_file}"
}

# Mirrors Support/serberusd-devtool.sh write_daemon_plist(), except the plist
# lands in the payload and the dev env vars are resolved at BUILD time.
write_daemon_plist() {
    local plist_path="${PAYLOAD_DIR}/Library/LaunchDaemons/${BUNDLE_ID}.plist"

    local env_entries=""
    local dev_var
    for dev_var in SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT SERBERUS_DEV_KEY_FALLBACK
    do
        local value="${!dev_var:-}"
        if [[ -n "${value}" ]]
        then
            log_info "Daemon env baked into plist: ${dev_var}=${value} (dev)"
            env_entries+="        <key>${dev_var}</key>"$'\n'"        <string>${value}</string>"$'\n'
        fi
    done

    local env_block=""
    if [[ -n "${env_entries}" ]]
    then
        env_block="    <key>EnvironmentVariables</key>"$'\n'"    <dict>"$'\n'"${env_entries}    </dict>"$'\n'
    fi

    "${CAT}" > "${plist_path}" <<DAEMON_PLIST_EOF
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

    "${CHMOD}" 644 "${plist_path}"

    if ! "${PLUTIL}" -lint "${plist_path}" >/dev/null 2>&1
    then
        log_error "Generated LaunchDaemon plist failed plutil -lint: ${plist_path}"
        exit 1
    fi
}

# On-endpoint teardown helper, shipped in the payload so a Jamf teardown
# policy (or a local admin) can remove the test install AND restore the
# AuthorizationDB in one step. Fully literal heredoc — it runs on the target.
write_uninstall_helper() {
    local helper_path="${PAYLOAD_DIR}${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}"

    "${CAT}" > "${helper_path}" <<'UNINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: uninstall-serberusd-test.sh
# Author: Heath Jones
# Date: 2026-07-09
# Modified: 2026-09-26
# Purpose: Remove the TEST-RING Serberus daemon install. ORDER IS
#          SAFETY-CRITICAL:
#            1. remove the coarse /etc/sudoers.d/serberus drop-in
#               (marker-guarded, that one exact path);
#            2. unwire /etc/pam.d/sudo_local if the PAM test pkg wired it —
#               on failure the daemon stays enabled and the teardown stops;
#            3. launchctl disable (no reboot relaunch), launchctl bootout and
#               wait until launchd has dropped the job (then re-check the
#               drop-in);
#            4. <daemon> --demote-jit (bounded; loud, non-fatal on failure),
#               then the drop-in once more;
#            5. <daemon> --restore-authdb (bounded);
#            6. remove SerberusAuth.bundle + authdb-backups ONLY if 5 succeeded
#               AND the live AuthorizationDB no longer references Serberus;
#            7. remove the plist, the flat binary (and a production bundle or
#               CLI if present), forget the receipt.
#          A drop-in that survives the later re-checks does not stop the
#          teardown, but the script exits 1.
#          The PAM module itself belongs to the PAM test pkg and its helper.
#          The marker-aware logic comes from the pam-lib.sh this pkg installs
#          beside the helper; without a trusted copy nothing is changed.
#          An EXIT trap keeps the daemon enabled (and loaded) whenever the
#          script stops early with sudo_local still wired.
#          Pass --purge to also remove daemon data under
#          /Library/Application Support/Serberus (never the apps or the
#          other uninstall helpers).
# Version: 1.5 - (a) --purge removes data only: the Sentinel agent and
#          Guardian apps, the other uninstall helpers and the install markers
#          stay. (b) The plugin gate is pam-lib.sh 1.8's: no pending .json,
#          .branches or .projection record, no composition row invoking
#          SerberusAuth and no right delegating to one; never a comment. With
#          no daemon, only those records (not a .standin) mean there is
#          something to restore. (c) The post-bootout wait
#          is the daemon's ExitTimeOut plus 5 s (25 s). (d) With no recorded
#          install team and no signed PAM module, the daemon is not run.
#          1.4 - (a) pam-lib.sh is sourced only when it and every directory
#          above it are root-only. (b) The daemon is disabled after
#          sudo_local is unwired, right before the bootout, and the one-shots
#          run only once launchd has dropped the job (waited for up to its
#          20 s ExitTimeOut). (c) The daemon is pinned to the Team ID the
#          install recorded in version.plist. (d) The drop-in is re-checked
#          after --demote-jit too, and one that survives a re-check makes the
#          script exit 1.
#          1.3 - A daemon binary runs (--demote-jit, --restore-authdb) only
#          after serberus_daemon_trusted passes (strict signature, Apple
#          anchor, identifier com.herojoneslabs.serberus.daemon, pinned team);
#          otherwise the manual steps are printed. --demote-jit exit 3 (no
#          grant store) is informational. A sudoers drop-in that survives its
#          removal stops the teardown before sudo_local is unwired.
#          1.2 - Requires the pam-lib.sh this pkg now installs; EXIT trap
#          re-arms the daemon while sudo_local is still wired; umask 022;
#          bounded one-shots (SERBERUS_DEV_KEY_FALLBACK exported, as the
#          LaunchDaemon sets it); plugin removal also needs a clean live
#          AuthorizationDB; pam-lib.sh is removed only when no other helper
#          still needs it.
#          1.1 - New teardown order (disable -> drop-in -> unwire -> bootout
#          -> demote JIT -> restore -> plugin only if restored -> files);
#          system-only PATH and absolute tools.
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
readonly BASENAME="/usr/bin/basename"
readonly ENV="/usr/bin/env"
readonly ID="/usr/bin/id"
readonly KILLALL="/usr/bin/killall"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly LS="/bin/ls"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly RM="/bin/rm"
readonly STAT="/usr/bin/stat"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.5"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.uninstall-test"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly INSTALL_BINARY_PATH="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly DAEMON_BUNDLE="/Library/PrivilegedHelperTools/serberusd.app"
readonly DAEMON_BUNDLE_BINARY="${DAEMON_BUNDLE}/Contents/MacOS/com.herojoneslabs.serberus.daemon"
readonly PLIST_PATH="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
readonly CLI_PATH="/usr/local/bin/serberus"
readonly AUTH_PLUGIN_PATH="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly AUTHDB_BACKUPS="${SUPPORT_DIR}/authdb-backups"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"
# Installed by this pkg (and by the PAM / core test pkgs).
readonly INSTALLED_PAM_LIB="${SUPPORT_DIR}/pam-lib.sh"
# Other on-disk helpers that source the shared pam-lib.sh. It is removed only
# when none of them remains.
readonly OTHER_HELPERS=(
    "${SUPPORT_DIR}/uninstall-serberus-sentinel-test.sh"
    "${SUPPORT_DIR}/uninstall-serberus-pam-test.sh"
    "${SUPPORT_DIR}/uninstall.sh"
)
readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.testpkg"
# Hard deadline for each daemon one-shot (--demote-jit, --restore-authdb).
readonly ONESHOT_TIMEOUT=120
readonly PURGE_FLAG="${1:-}"

AUTHDB_RESTORE_OK=0
# Success marker; without it the EXIT trap re-arms a daemon behind a wired
# sudo_local.
UNINSTALL_SUCCEEDED=0
# Set when the drop-in is still present at a re-check after the bootout; the
# teardown finishes but the script exits 1.
DROPIN_SURVIVED=0
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut;
# no one-shot runs beside it (manual steps are logged instead).
DAEMON_GONE=1

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

# True when <file> and EVERY directory above it (up to /) are root-locked, so
# nobody but root can swap the file between this check and the source.
# $1 absolute file path.
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

# Source the marker-aware logic this pkg installs — only a regular,
# root-owned, not group/other-writable copy under a root-only directory chain
# (root runs it). Without one, nothing is changed: improvising the PAM edits
# is how sudo gets bricked.
source_pam_lib() {
    if path_chain_is_root_only "${INSTALLED_PAM_LIB}"
    then
        # shellcheck source=/dev/null
        source "${INSTALLED_PAM_LIB}"
        return 0
    fi
    log_error "${INSTALLED_PAM_LIB} is missing or not root-only — nothing was changed."
    log_error "Reinstall the daemon test pkg (it installs pam-lib.sh), or tear down by hand in THIS ORDER:"
    log_error "  1. sudo rm -f ${SUDOERS_DROPIN}   (only if its first line is the Serberus managed header)"
    log_error "  2. remove the pam_serberus.so line from ${SUDO_LOCAL}"
    log_error "  3. sudo launchctl disable system/${DAEMON_LABEL}; sudo launchctl bootout system/${DAEMON_LABEL}"
    log_error "  4. wait until: sudo launchctl print system/${DAEMON_LABEL}   reports it is not found"
    log_error "  5. sudo ${INSTALL_BINARY_PATH} --demote-jit; sudo ${INSTALL_BINARY_PATH} --restore-authdb"
    log_error "  6. sudo rm -f ${PLIST_PATH} ${INSTALL_BINARY_PATH}; sudo pkgutil --forget ${PKG_IDENTIFIER}"
    exit 1
}

# EXIT trap: stopping early must never leave sudo_local wired behind a
# disabled or unloaded daemon.
on_exit() {
    local status=$?
    if [[ "${UNINSTALL_SUCCEEDED}" -eq 1 ]]
    then
        return 0
    fi
    set +e
    if ! serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${PLIST_PATH}"
    then
        log_error "Stopped early (status ${status}) with ${SUDO_LOCAL} still wired — ${DAEMON_LABEL} re-enabled."
    fi
    exit "${status}"
}

# STEP 3 — disable only once sudo_local is unwired, right before the bootout:
# an interrupted run must never leave sudo_local wired behind a disabled
# daemon. A later install re-enables the label.
disable_daemon() {
    log_info "Disabling ${DAEMON_LABEL}"
    "${LAUNCHCTL}" disable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl disable system/${DAEMON_LABEL} failed"
}

# Routes serberus_daemon_manual_steps into the log. $1 demote | restore | sudoers
log_manual_steps() {
    local line
    while IFS= read -r line
    do
        log_error "${line}"
    done < <(serberus_daemon_manual_steps "$1" "${AUTHDB_BACKUPS}")
}

# STEP 1 (and again after the bootout) — marker-guarded, one exact path.
# Returns 1 when the drop-in is STILL there after the rm.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        log_manual_steps sudoers
        return 1
    fi
    return 0
}

# STEP 1: a surviving drop-in stops the teardown BEFORE sudo_local is
# unwired — the PAM gate must outlive it; the daemon stays enabled.
remove_sudoers_dropin_or_stop() {
    if ! remove_sudoers_dropin
    then
        log_error "Stopping: sudo_local stays wired and ${DAEMON_LABEL} stays enabled."
        "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null || true
        exit 1
    fi
}

# The re-checks after the bootout and after --demote-jit: the PAM gate is
# already gone, so the teardown continues, loudly, and exits 1 at the end.
recheck_sudoers_dropin() {
    if ! remove_sudoers_dropin
    then
        log_error "The drop-in outlived the PAM gate — remove it by hand."
        DROPIN_SURVIVED=1
    fi
}

# STEP 2 — unwire a sudo_local the PAM test pkg wired, while the daemon still
# runs. A surviving active line keeps the daemon enabled and stops the
# teardown.
unwire_sudo_local() {
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_info "sudo_local unwire: ${result} (${SUDO_LOCAL})"
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_error "An active pam_serberus.so line remains in ${SUDO_LOCAL} — stopping; the daemon stays enabled and running."
        "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null || true
        exit 1
    fi
}

# STEP 3 — bootout, then wait (up to the daemon's ExitTimeOut) until launchd
# has dropped the job: no one-shot may run beside a live daemon.
bootout_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_info "Booting out ${DAEMON_LABEL}"
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        if ! serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            DAEMON_GONE=0
            log_error "${DAEMON_LABEL} is still loaded after its bootout — no daemon one-shot will run."
        fi
    fi
}

# serberus_daemon_trusted with the team the install recorded in version.plist
# (falls back to the installed module's team; with neither, the daemon is
# refused). $1 daemon path.
daemon_trusted() {
    local team
    team=$(serberus_recorded_team 2>/dev/null) || team=""
    serberus_daemon_trusted "$1" "${team}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
}

# Runs a daemon one-shot with the deadline. SERBERUS_DEV_KEY_FALLBACK=1 is
# what this ring's LaunchDaemon sets. $1 binary, $2 flag.
run_daemon_oneshot() {
    serberus_run_bounded "${ONESHOT_TIMEOUT}" \
        "${ENV}" SERBERUS_DEV_KEY_FALLBACK=1 "$1" "$2"
}

# STEP 4 — demote every JIT admin (after the bootout, before the binary goes).
# A binary runs only when serberus_daemon_trusted passes. Exit 3 = no grant
# store, nothing to demote.
demote_jit_admins() {
    local candidate
    local status
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_manual_steps demote
        return 0
    fi
    for candidate in "${INSTALL_BINARY_PATH}" "${DAEMON_BUNDLE_BINARY}"
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
        log_info "Demoting JIT admins (${candidate} --demote-jit)"
        status=0
        run_daemon_oneshot "${candidate}" --demote-jit || status=$?
        case "${status}" in
            0)
                return 0
                ;;
            3)
                log_info "No grant store — no JIT admins to demote"
                return 0
                ;;
        esac
        log_error "--demote-jit FAILED via ${candidate} (exit ${status}; 124 = timed out)"
    done
    log_error "!!! JIT admins could NOT be demoted."
    log_manual_steps demote
    return 0
}

# STEP 5 — restore AuthorizationDB rights BEFORE removing the binary — the
# binary performs the restore. Otherwise a `deny` authuri rule would survive
# uninstall and leave a System Settings pane (or admin auth) blocked. Exit 0
# is not enough: the live database must no longer reference Serberus.
restore_authdb() {
    local binary=""
    local candidate
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_manual_steps restore
        return 0
    fi
    for candidate in "${INSTALL_BINARY_PATH}" "${DAEMON_BUNDLE_BINARY}"
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
            log_error "No trusted daemon binary; CANNOT auto-restore the AuthorizationDB."
            log_manual_steps restore
        elif serberus_authdb_free_of_serberus 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            AUTHDB_RESTORE_OK=1
        fi
        return 0
    fi
    log_info "Restoring AuthorizationDB rights from snapshots (${binary})"
    local status=0
    run_daemon_oneshot "${binary}" --restore-authdb || status=$?
    if [[ "${status}" -ne 0 ]]
    then
        log_error "AuthorizationDB restore FAILED (exit ${status}; 124 = timed out) — some rights may still be modified."
        log_error "Recover manually: inspect ${AUTHDB_BACKUPS}/*.json and run"
        log_error "  sudo security authorizationdb write <right> < <original>"
        log_error "or reset a stuck right: sudo security authorizationdb write <right> authenticate-admin"
        return 0
    fi
    if serberus_authdb_free_of_serberus 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        AUTHDB_RESTORE_OK=1
    else
        log_error "The restore exited 0 but the AuthorizationDB still references Serberus — keeping the plugin and backups."
    fi
}

# STEP 6 — the plugin (if another pkg installed it) and the backups go only
# after a SUCCESSFUL restore: rights may still reference SerberusAuth:identity.
remove_auth_plugin_if_restored() {
    if [[ "${AUTHDB_RESTORE_OK}" -ne 1 ]]
    then
        log_warn "Keeping ${AUTH_PLUGIN_PATH} (if present) and ${AUTHDB_BACKUPS}: the restore did not succeed."
        return 0
    fi
    if [[ -d "${AUTH_PLUGIN_PATH}" ]]
    then
        log_info "Removing authorization plugin ${AUTH_PLUGIN_PATH}"
        "${RM}" -rf "${AUTH_PLUGIN_PATH}"
        "${KILLALL}" SecurityAgent authorizationhost 2>/dev/null || true
    fi
    "${RM}" -rf "${AUTHDB_BACKUPS}"
}

# pam-lib.sh is shared with the other Serberus helpers; keep it while any of
# them is still installed.
remove_pam_lib_if_unused() {
    local helper
    for helper in "${OTHER_HELPERS[@]}"
    do
        if [[ -e "${helper}" ]]
        then
            log_info "Keeping ${INSTALLED_PAM_LIB} — ${helper} still uses it"
            return 0
        fi
    done
    "${RM}" -f "${INSTALLED_PAM_LIB}"
}

# STEP 7 — files, receipt, data.
remove_artifacts() {
    "${RM}" -f "${PLIST_PATH}" "${INSTALL_BINARY_PATH}" "${CLI_PATH}"
    "${RM}" -rf "${DAEMON_BUNDLE}"

    "${PKGUTIL}" --forget "${PKG_IDENTIFIER}" >/dev/null 2>&1 || true

    if [[ "${PURGE_FLAG}" == "--purge" ]]
    then
        # Data only (pam-lib.sh serberus_purge_support_data): the apps, the
        # other uninstall helpers and the install markers stay.
        local keep_backups=1
        if [[ "${AUTHDB_RESTORE_OK}" -eq 1 ]]
        then
            keep_backups=0
            log_info "Purging Serberus data under ${SUPPORT_DIR}"
        else
            log_warn "Purging Serberus data under ${SUPPORT_DIR} EXCEPT ${AUTHDB_BACKUPS} (the restore did not succeed)"
        fi
        serberus_purge_support_data "${SUPPORT_DIR}" "${keep_backups}" > /dev/null
        "${RM}" -f "${SUPPORT_DIR}/uninstall-serberusd-test.sh"
        remove_pam_lib_if_unused
    else
        # Preserve state.plist and grants.sqlite; remove only this helper and
        # (when unused) pam-lib.sh. Pass --purge to remove everything.
        "${RM}" -f "${SUPPORT_DIR}/uninstall-serberusd-test.sh"
        remove_pam_lib_if_unused
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting"

require_root
source_pam_lib
trap on_exit EXIT

# ORDER: drop-in -> unwire -> disable -> bootout (wait until gone) -> drop-in
# -> demote JIT -> drop-in -> restore authdb -> plugin (only if restored) ->
# files.
remove_sudoers_dropin_or_stop
unwire_sudo_local
disable_daemon
bootout_daemon
recheck_sudoers_dropin
demote_jit_admins
recheck_sudoers_dropin
restore_authdb
remove_auth_plugin_if_restored
remove_artifacts

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
UNINSTALL_EOF

    "${CHMOD}" 755 "${helper_path}"

    if ! "${BASH_BIN}" -n "${helper_path}"
    then
        log_error "Generated uninstall helper failed bash -n: ${helper_path}"
        exit 1
    fi
}

write_preinstall() {
    local preinstall_path="${SCRIPTS_DIR}/preinstall"

    "${CAT}" > "${preinstall_path}" <<'PREINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: preinstall
# Author: Heath Jones
# Date: 2026-07-09
# Modified: 2026-09-26
# Purpose: Serberus TEST-RING daemon PKG preinstall. Before new binaries are
#          laid down: uninstall a legacy com.heath.serberus daemon, then — on
#          an upgrade — the TEARDOWN-FIRST sequence: remove the coarse
#          sudoers drop-in, unwire sudo_local (a PAM test pkg may have wired
#          it; marker-aware; stop with the old daemon still running if a line
#          survives), boot the daemon out (label left ENABLED so a reboot
#          restores the old daemon) and re-check the drop-in. A failed or
#          interrupted upgrade therefore falls back to native sudo. When a
#          line WAS unwired, a root-only marker tells the postinstall to
#          re-wire once the new daemon is up. Preserves state and grant data.
# Version: 1.6 - (a) On an upgrade, writes the root-only marker
#          /Library/Application Support/Serberus/.upgrade-in-progress before
#          the teardown, so the new daemon ends open JIT sessions at startup.
#          (b) The post-bootout wait is the daemon's ExitTimeOut plus 5 s.
#          (c) SCRIPT_VERSION matches this header.
#          1.5 - (a) After the bootout the script waits (up to the daemon's
#          20 s ExitTimeOut) until launchd no longer lists the job; if it is
#          still loaded --demote-jit is skipped and the manual steps logged.
#          (b) The OLD daemon's --demote-jit now runs whenever its binary is
#          on disk (it used to require the job to still be loaded, which it
#          never is after the bootout). (c) The drop-in is checked straight
#          after the bootout and again after --demote-jit; one that survives
#          once sudo_local is unwired re-bootstraps the old daemon, which
#          removes its own drop-in while the PAM gate is unwired. (d) The old
#          daemon is pinned to the Team ID the last install recorded in
#          version.plist, when there is one. (e) A legacy com.heath daemon
#          is booted out (and waited for) before its --restore-authdb.
#          1.4 - A sudoers drop-in that survives its removal stops the upgrade
#          (before sudo_local is unwired on the first pass). The OLD daemon's
#          --demote-jit runs after the bootout (the old binary is still on disk), only after
#          serberus_daemon_trusted; exit 3 (no grant store) is informational,
#          other failures are loud but not fatal. The legacy com.heath
#          restore runs only for a binary that passes the same check;
#          otherwise the manual steps are logged.
#          1.3 - Teardown-first upgrade via the staged pam-lib.sh (+ re-wire
#          marker); umask 022; refuses a target volume other than "/" ($3);
#          EXIT trap keeps a daemon behind a still-wired sudo_local.
#          1.2 - System-only PATH and absolute tools.
#          1.1 - Uninstalls a legacy com.heath.serberus daemon first.
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
readonly BASENAME="/usr/bin/basename"
readonly DIRNAME="/usr/bin/dirname"
readonly ENV="/usr/bin/env"
readonly ID="/usr/bin/id"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly MKDIR="/bin/mkdir"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly RM="/bin/rm"
readonly STAT="/usr/bin/stat"
readonly TOUCH="/usr/bin/touch"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.6"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.test-preinstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"

# The installed (OLD) daemon an upgrade stops: a test ring's flat binary, or a
# production bundle. Its --demote-jit runs after the bootout (the old binary is still on disk).
readonly OLD_DAEMON_BINARY_FLAT="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly OLD_DAEMON_BINARY_BUNDLE="/Library/PrivilegedHelperTools/serberusd.app/Contents/MacOS/com.herojoneslabs.serberus.daemon"
# Hard deadline for the old daemon's --demote-jit and the legacy restore.
readonly ONESHOT_TIMEOUT=120
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
# Root-only handshake with the postinstall: present => re-wire sudo_local.
readonly MARKER_DIR="${SUPPORT_DIR}/.install-markers"
readonly REWIRE_MARKER="${MARKER_DIR}/daemon-test-rewire-sudo-local"

# Legacy (pre-rename) footprint. Before the bundle-ID rename the daemon shipped
# under the com.heath.serberus prefix; a test Mac carrying that build must have
# it fully uninstalled — and its AuthorizationDB rewrites reverted from its OWN
# snapshots — before the new-prefix daemon lands, otherwise the new daemon
# snapshots already-modified rights as if pristine and the old rewrites are
# orphaned (its support dir, and thus its snapshots, live at a different path).
readonly LEGACY_DAEMON_LABEL="com.heath.serberus.daemon"
readonly LEGACY_BINARY="/Library/PrivilegedHelperTools/com.heath.serberus.daemon"
readonly LEGACY_PLIST="/Library/LaunchDaemons/com.heath.serberus.daemon.plist"
readonly LEGACY_SUPPORT_DIR="/Library/Application Support/com.heath.serberus"
readonly LEGACY_TEST_RECEIPT="com.heath.serberus.testpkg"
readonly LEGACY_PROD_RECEIPT="com.heath.serberus.pkg"

# Installer passes the target volume as $3.
readonly TARGET_VOLUME="${3:-}"

# Success marker; without it the EXIT trap re-arms a daemon behind a wired
# sudo_local.
PREINSTALL_SUCCEEDED=0
# Set to 1 once the unwire step has run (see remove_sudoers_dropin).
SUDO_LOCAL_UNWIRED=0
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut.
DAEMON_GONE=1

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
}

log_warn() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.warning "[WARN] $*"
}

log_error() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.err "[ERROR] $*"
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_warn "preinstall not running as root"
        exit 1
    fi
}

# Serberus rewires THIS Mac's sudo and AuthorizationDB; installing onto any
# other volume is refused before anything is touched.
require_boot_volume() {
    if [[ "${TARGET_VOLUME}" != "/" ]]
    then
        log_error "Target volume is '${TARGET_VOLUME}', not '/'. Serberus must be installed on the running system."
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

# pkgbuild ships every file in the scripts dir alongside this script.
source_pam_lib() {
    local lib
    lib="$("${DIRNAME}" "$0")/pam-lib.sh"
    if [[ ! -f "${lib}" ]]
    then
        log_error "pam-lib.sh missing from pkg scripts — aborting before anything changes (fail closed)."
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${lib}"
}

# Safety net for an UNEXPECTED exit: a sudo_local that is still wired keeps
# its daemon enabled and loaded.
on_exit() {
    local status=$?
    if [[ "${PREINSTALL_SUCCEEDED}" -eq 1 ]]
    then
        return 0
    fi
    set +e
    log_error "preinstall exiting with status ${status} before completing"
    serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    exit "${status}"
}

# Teardown-first, step 1 (and again after the bootout): the coarse gate goes
# before the fine one. Marker-guarded, that one exact path. A drop-in that is
# still there after the rm stops the upgrade: on the first call that is before
# sudo_local is unwired, so the old daemon keeps running behind both gates.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        if [[ "${SUDO_LOCAL_UNWIRED}" -eq 1 ]]
        then
            # With the PAM gate unwired, the old daemon's provisioning pass
            # removes its own drop-in, so bring it back rather than leave the
            # drop-in with nothing behind it.
            log_error "sudo_local is already unwired — re-bootstrapping the old daemon so it removes its drop-in."
            if ! "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1 \
                && [[ -f "${LAUNCHD_PLIST}" ]]
            then
                "${LAUNCHCTL}" bootstrap system "${LAUNCHD_PLIST}" 2>/dev/null \
                    || log_error "launchctl bootstrap ${LAUNCHD_PLIST} failed"
            fi
        fi
        log_error "Stopping the upgrade. Remove the file by hand (chflags noschg,nouchg first if set), then reinstall."
        exit 1
    fi
}

# The marker lives in a ROOT-ONLY directory; a symlinked support or marker
# directory is never followed.
write_rewire_marker() {
    if [[ -L "${SUPPORT_DIR}" || -L "${MARKER_DIR}" ]]
    then
        log_warn "refusing a symlinked ${SUPPORT_DIR} / ${MARKER_DIR} — sudo_local will NOT be re-wired"
        return 0
    fi
    "${MKDIR}" -p "${SUPPORT_DIR}"
    "${MKDIR}" -p -m 700 "${MARKER_DIR}"
    if [[ "$("${STAT}" -f '%u' "${MARKER_DIR}" 2>/dev/null)" != "0" ]]
    then
        log_warn "${MARKER_DIR} is not root-owned — sudo_local will NOT be re-wired"
        return 0
    fi
    "${RM}" -f "${REWIRE_MARKER}"
    "${TOUCH}" "${REWIRE_MARKER}"
}

# Teardown-first, step 2, while the OLD daemon still runs. A surviving active
# line stops the upgrade with that daemon still behind it.
unwire_sudo_local() {
    if ! serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        return 0
    fi
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_info "sudo_local unwire: ${result} (${SUDO_LOCAL})"
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_error "An ACTIVE pam_serberus line remains in ${SUDO_LOCAL} — aborting the upgrade with the"
        log_error "current daemon still running behind it. Fix ${SUDO_LOCAL} by hand, then reinstall."
        exit 1
    fi
    write_rewire_marker
}

# Demote JIT admins with the OLD daemon binary once the daemon has been booted
# out: if the upgrade then fails, nothing else would expire their grants. The
# binary runs only when serberus_daemon_trusted passes (strict signature,
# Apple anchor, the daemon identifier, the team the last install recorded).
# Never fatal, but loud: exit 1 means users may still be admins; exit 3 means
# there is no grant store.
demote_jit_with_old_daemon() {
    local binary=""
    local candidate
    for candidate in "${OLD_DAEMON_BINARY_FLAT}" "${OLD_DAEMON_BINARY_BUNDLE}"
    do
        if [[ -x "${candidate}" && ! -L "${candidate}" ]]
        then
            binary="${candidate}"
            break
        fi
    done
    if [[ -z "${binary}" ]]
    then
        log_info "No installed daemon binary — no JIT grants to demote"
        return 0
    fi
    local line
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "The booted-out daemon is still loaded — NOT running --demote-jit beside it."
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps demote)
        return 0
    fi
    local team
    team=$(serberus_recorded_team 2>/dev/null) || team=""
    if ! serberus_daemon_trusted "${binary}" "${team}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "The installed daemon ${binary} failed its signature check — NOT executing it for --demote-jit."
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps demote)
        return 0
    fi
    log_info "Demoting JIT admins with the installed daemon (${binary} --demote-jit)"
    local status=0
    serberus_run_bounded "${ONESHOT_TIMEOUT}" \
        "${ENV}" SERBERUS_DEV_KEY_FALLBACK=1 "${binary}" --demote-jit \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) || status=$?
    case "${status}" in
        0)
            log_info "JIT admins demoted"
            ;;
        3)
            log_info "No grant store — no JIT admins to demote"
            ;;
        *)
            log_error "--demote-jit FAILED (exit ${status}; 124 = timed out) — continuing the upgrade"
            while IFS= read -r line
            do
                log_error "${line}"
            done < <(serberus_daemon_manual_steps demote)
            ;;
    esac
    return 0
}

# Teardown-first, step 3. The label stays ENABLED: a reboot before the
# postinstall brings the old daemon back.
# On an upgrade (the old daemon is loaded or its plist is installed), tell the
# NEW daemon at its first start to end the JIT sessions the old one left open
# (pam-lib.sh serberus_write_upgrade_marker). Never fatal.
write_upgrade_marker() {
    if ! "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1 && [[ ! -e "${LAUNCHD_PLIST}" ]]
    then
        return 0
    fi
    if serberus_write_upgrade_marker 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_info "Upgrade marker written (${SERBERUS_UPGRADE_MARKER})"
    else
        log_warn "Could not write the upgrade marker ${SERBERUS_UPGRADE_MARKER}"
    fi
}

bootout_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_info "Booting out running daemon ${DAEMON_LABEL} (label stays enabled)"
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        if ! serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            DAEMON_GONE=0
            log_error "${DAEMON_LABEL} is still loaded after its bootout"
        fi
    else
        log_info "Daemon not currently loaded"
    fi
}

# Fully remove a PREVIOUS-generation (pre-rename, com.heath) daemon if present.
# This is NOT the same as the same-prefix upgrade handled by bootout_daemon: the
# legacy daemon owns a different support dir, so we must revert its
# AuthorizationDB rewrites using ITS OWN binary + snapshots here, before it is
# removed. The legacy support dir is deleted only when that restore succeeds, so
# a failed restore leaves the original-rights snapshots in place for manual
# recovery.
uninstall_legacy_daemon() {
    if [[ ! -e "${LEGACY_BINARY}" ]] \
        && [[ ! -e "${LEGACY_PLIST}" ]] \
        && ! "${PKGUTIL}" --pkg-info "${LEGACY_TEST_RECEIPT}" >/dev/null 2>&1 \
        && ! "${PKGUTIL}" --pkg-info "${LEGACY_PROD_RECEIPT}" >/dev/null 2>&1
    then
        log_info "No legacy com.heath.serberus daemon detected"
        return 0
    fi

    log_warn "Legacy com.heath.serberus daemon detected — uninstalling before install"

    # Boot the legacy daemon out FIRST, and wait until launchd has dropped
    # it: its one-shot must not run beside the live daemon.
    local legacy_gone=1
    if "${LAUNCHCTL}" print "system/${LEGACY_DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_info "Booting out legacy daemon ${LEGACY_DAEMON_LABEL}"
        "${LAUNCHCTL}" bootout "system/${LEGACY_DAEMON_LABEL}" 2>/dev/null || true
        serberus_launchd_wait_gone "${LEGACY_DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) || legacy_gone=0
    fi

    local restore_ok=1
    local line
    if [[ -x "${LEGACY_BINARY}" && "${legacy_gone}" -ne 1 ]]
    then
        log_error "Legacy daemon ${LEGACY_DAEMON_LABEL} is still loaded — NOT running its --restore-authdb; preserving ${LEGACY_SUPPORT_DIR}"
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps restore "${LEGACY_SUPPORT_DIR}/authdb-backups")
    elif [[ -x "${LEGACY_BINARY}" ]] \
        && ! serberus_daemon_trusted "${LEGACY_BINARY}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        # A pre-rename build may not carry today's identifier or team: it is
        # never executed on trust it cannot prove.
        log_error "Legacy binary ${LEGACY_BINARY} failed its signature check — NOT executing it; preserving ${LEGACY_SUPPORT_DIR}"
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps restore "${LEGACY_SUPPORT_DIR}/authdb-backups")
    elif [[ -x "${LEGACY_BINARY}" ]]
    then
        log_info "Reverting legacy AuthorizationDB rewrites (${LEGACY_BINARY} --restore-authdb)"
        if serberus_run_bounded "${ONESHOT_TIMEOUT}" "${LEGACY_BINARY}" --restore-authdb
        then
            restore_ok=0
        else
            log_error "Legacy AuthorizationDB restore FAILED (or timed out) — preserving ${LEGACY_SUPPORT_DIR} for manual recovery"
        fi
    else
        log_warn "Legacy binary missing or non-executable — cannot auto-revert its AuthorizationDB rewrites"
    fi

    if [[ -e "${LEGACY_PLIST}" ]]
    then
        "${RM}" -f "${LEGACY_PLIST}"
    fi
    if [[ -e "${LEGACY_BINARY}" ]]
    then
        "${RM}" -f "${LEGACY_BINARY}"
    fi

    "${PKGUTIL}" --forget "${LEGACY_TEST_RECEIPT}" >/dev/null 2>&1 || true
    "${PKGUTIL}" --forget "${LEGACY_PROD_RECEIPT}" >/dev/null 2>&1 || true

    if [[ "${restore_ok}" -eq 0 ]] && [[ -d "${LEGACY_SUPPORT_DIR}" ]]
    then
        log_info "Removing orphaned legacy support dir ${LEGACY_SUPPORT_DIR}"
        "${RM}" -rf "${LEGACY_SUPPORT_DIR}"
    fi

    log_info "Legacy daemon uninstall complete"
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
require_boot_volume
source_pam_lib
trap on_exit EXIT

uninstall_legacy_daemon

# Teardown-first on an upgrade: drop-in -> unwire -> bootout (wait until gone)
# -> drop-in -> demote JIT (old binary, trusted only) -> drop-in. The drop-in
# is checked straight after the bootout (the old daemon could re-provision it
# until then) and again after the demote, which can take up to
# ONESHOT_TIMEOUT. Each step is a no-op on a fresh install.
remove_sudoers_dropin
write_upgrade_marker
unwire_sudo_local
SUDO_LOCAL_UNWIRED=1
bootout_daemon
remove_sudoers_dropin
demote_jit_with_old_daemon
remove_sudoers_dropin

# Intentionally preserved across same-prefix upgrades:
#   /Library/Application Support/Serberus/state.plist
#   /Library/Application Support/Serberus/grants.sqlite

PREINSTALL_SUCCEEDED=1
log_info "${SCRIPT_NAME} completed successfully"
exit 0

###########################################################
################## End Script Block #######################
###########################################################
PREINSTALL_EOF

    "${CHMOD}" 755 "${preinstall_path}"

    if ! "${BASH_BIN}" -n "${preinstall_path}"
    then
        log_error "Generated preinstall failed bash -n: ${preinstall_path}"
        exit 1
    fi
}

write_postinstall() {
    local postinstall_path="${SCRIPTS_DIR}/postinstall"

    "${CAT}" > "${postinstall_path}" <<'POSTINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: postinstall
# Author: Heath Jones
# Date: 2026-07-09
# Modified: 2026-09-26
# Purpose: Serberus TEST-RING daemon PKG postinstall — validate the
#          bare-binary payload (no ESF bundle, no PAM), fix ownership, ensure
#          support directories, enable + bootstrap the LaunchDaemon and wait
#          until it is actually UP (one pid for 8 s with no launchd restart, a
#          state.plist written by THIS daemon, plus a healthy `serberus
#          status` when a trusted CLI is installed). This pkg
#          legitimately runs without PAM and never writes sudoers; it touches
#          sudo_local only to RE-WIRE a line its own preinstall removed for
#          the upgrade (and only after the module passes the same checks the
#          PAM test pkg applies — otherwise sudo stays native, loudly). Any
#          failure — including an unexpected exit, via the EXIT trap — takes
#          the ONE abort path: remove the sudoers drop-in, unwire sudo_local
#          (a SURVIVING line keeps the daemon enabled and running, exit 1),
#          disable + bootout, demote JIT admins, restore the
#          AuthorizationDB (never executing a daemon that fails signature
#          verification), exit 1.
# Version: 1.4 - (a) The abort path disables the daemon after sudo_local is
#          unwired, right before the bootout, and runs the one-shots only
#          once launchd has dropped the job (waited for up to its 20 s
#          ExitTimeOut). (b) Before re-wiring sudo_local, a stray
#          /usr/local/lib/pam/pam_serberus.so.2 (OpenPAM loads it in place of
#          the module) is removed; if it cannot be, sudo stays native.
#          1.3 - (a) The daemon must pass serberus_daemon_trusted (strict
#          signature, Apple anchor, identifier com.herojoneslabs.serberus.daemon,
#          its Team ID) or the install ABORTS; a plain `codesign --verify`
#          (which an ad-hoc signature passes) no longer counts. (b) "Up" adds
#          the bootstrap mark: no launchd restart or failed exit, a fresh
#          state.plist, an 8 s window; the pid is re-read before the re-wire.
#          (c) A sudoers drop-in that survives its removal stops the abort
#          path before sudo_local is unwired. (d) Each chown/chmod is checked
#          on its own. (e) --demote-jit exit 3 (no grant store) is
#          informational.
#          1.2 - Sources the staged pam-lib.sh (this pkg now ships it); EXIT
#          trap; abort keeps the daemon running when an active line
#          survives; stable-pid liveness; bounded one-shots with
#          SERBERUS_DEV_KEY_FALLBACK exported (as the LaunchDaemon sets it);
#          re-wires sudo_local after an upgrade teardown; umask 022; refuses
#          a target volume other than "/" ($3).
#          1.1 - Enable before bootstrap; "up" means a running pid within
#          ~10 s, not a loaded job; every abort disables + boots out the
#          daemon and removes the sudoers drop-in; system-only PATH and
#          absolute tools.
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
readonly BASENAME="/usr/bin/basename"
readonly CHMOD="/bin/chmod"
readonly CHOWN="/usr/sbin/chown"
readonly CODESIGN="/usr/bin/codesign"
readonly DIRNAME="/usr/bin/dirname"
readonly ENV="/usr/bin/env"
readonly FILE="/usr/bin/file"
readonly ID="/usr/bin/id"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly MKDIR="/bin/mkdir"
readonly PLUTIL="/usr/bin/plutil"
readonly RM="/bin/rm"
readonly SLEEP="/bin/sleep"
readonly STAT="/usr/bin/stat"
readonly UNAME="/usr/bin/uname"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.4"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.test-postinstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly DAEMON_BINARY="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly STATE_PLIST="${SUPPORT_DIR}/state.plist"
readonly LOG_DIR="/Library/Logs/Serberus"
readonly AUTHDB_BACKUPS="${SUPPORT_DIR}/authdb-backups"
readonly UNINSTALL_HELPER="${SUPPORT_DIR}/uninstall-serberusd-test.sh"
readonly INSTALLED_PAM_LIB="${SUPPORT_DIR}/pam-lib.sh"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"
readonly PAM_MODULE="/usr/local/lib/pam/pam_serberus.so"
# A trusted CLI (installed by another Serberus pkg) adds `serberus status` to
# the "up" check; without one the stable-pid check stands alone.
readonly CLI_BINARY="/usr/local/bin/serberus"
# The preinstall's root-only handshake: present => re-wire sudo_local.
readonly MARKER_DIR="${SUPPORT_DIR}/.install-markers"
readonly REWIRE_MARKER="${MARKER_DIR}/daemon-test-rewire-sudo-local"
# Seconds to wait after bootstrap for a running pid (plus the 8 s stability
# window).
readonly DAEMON_START_TIMEOUT=10
# Hard deadline for each daemon one-shot (--demote-jit, --restore-authdb).
readonly ONESHOT_TIMEOUT=120

# Installer passes the target volume as $3.
readonly TARGET_VOLUME="${3:-}"

# Success marker: set right before the final exit 0. The EXIT trap runs the
# abort path whenever the script ends without it.
INSTALL_SUCCEEDED=0
ABORT_IN_PROGRESS=0
# Set by assess_daemon_trust (read-only). The install requires it, and the
# abort path executes the daemon only when it is set.
DAEMON_TRUSTED=0
DAEMON_TEAM=""
# Epoch seconds taken right before `launchctl bootstrap`.
BOOTSTRAP_MARK=""
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut;
# the abort path then skips the one-shots and logs the manual steps.
DAEMON_GONE=1

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
}

log_warn() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.warning "[WARN] $*"
}

log_error() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.err "[ERROR] $*"
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_error "Must run as root"
        exit 1
    fi
}

# Serberus rewires THIS Mac's sudo and AuthorizationDB; installing onto any
# other volume is refused.
require_boot_volume() {
    if [[ "${TARGET_VOLUME}" != "/" ]]
    then
        log_error "Target volume is '${TARGET_VOLUME}', not '/'. Serberus must be installed on the running system."
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

file_mode() {
    "${STAT}" -f '%Lp' "$1" 2>/dev/null || printf 'missing'
}

# pkgbuild ships every file in the scripts dir alongside this script.
source_pam_lib() {
    local lib
    lib="$("${DIRNAME}" "$0")/pam-lib.sh"
    if [[ ! -f "${lib}" ]]
    then
        log_error "pam-lib.sh missing from pkg scripts — aborting (fail closed)."
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${lib}"
}

# Any exit without the success marker — a failed ensure_directories or
# fix_ownership, or any other `set -e` casualty — takes the abort path.
on_exit() {
    local status=$?
    if [[ "${INSTALL_SUCCEEDED}" -eq 1 || "${ABORT_IN_PROGRESS}" -eq 1 ]]
    then
        return 0
    fi
    abort_install "unexpected exit (status ${status}) before the install completed"
}

# Read-only: is the installed daemon trusted — serberus_daemon_trusted with
# its own Team ID (strict signature, Apple anchor, the daemon identifier)?
# The install requires it (there is no ad-hoc fallback), and only then may the
# abort path EXECUTE the daemon. The team pins the re-wired module and the
# CLI health check.
assess_daemon_trust() {
    DAEMON_TRUSTED=0
    DAEMON_TEAM=""
    if [[ -f "${DAEMON_BINARY}" ]] \
        && DAEMON_TEAM=$(serberus_codesign_team_id "${DAEMON_BINARY}" 2>/dev/null) \
        && serberus_daemon_trusted "${DAEMON_BINARY}" "${DAEMON_TEAM}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        DAEMON_TRUSTED=1
    else
        DAEMON_TEAM=""
    fi
}

install_validation_passes() {
    local ok=0

    # 1. Daemon binary present with mode 755.
    if [[ ! -f "${DAEMON_BINARY}" ]] || [[ "$(file_mode "${DAEMON_BINARY}")" != "755" ]]
    then
        log_error "criterion 1 FAIL: daemon binary missing or not mode 755"
        ok=1
    fi

    # 2. LaunchDaemon plist present and parses.
    if [[ ! -f "${LAUNCHD_PLIST}" ]] || ! "${PLUTIL}" -lint "${LAUNCHD_PLIST}" >/dev/null 2>&1
    then
        log_error "criterion 2 FAIL: LaunchDaemon plist missing or unparseable"
        ok=1
    fi

    # 3. Plist contains KeepAlive and ThrottleInterval.
    if ! "${PLIST_BUDDY}" -c "Print :KeepAlive" "${LAUNCHD_PLIST}" >/dev/null 2>&1 \
        || ! "${PLIST_BUDDY}" -c "Print :ThrottleInterval" "${LAUNCHD_PLIST}" >/dev/null 2>&1
    then
        log_error "criterion 3 FAIL: plist missing KeepAlive/ThrottleInterval"
        ok=1
    fi

    # 4. The daemon passes serberus_daemon_trusted: a strict signature from
    #    an Apple-issued certificate, identifier
    #    com.herojoneslabs.serberus.daemon and a Team ID. An ad-hoc or
    #    re-identified daemon is refused — the install aborts rather than run
    #    a root daemon nothing can be pinned to.
    if [[ "${DAEMON_TRUSTED}" -ne 1 ]]
    then
        log_error "criterion 4 FAIL: daemon signature invalid, ad-hoc, or not identified as com.herojoneslabs.serberus.daemon with a Team ID"
        ok=1
    fi

    return ${ok}
}

ensure_directories() {
    local dir
    for dir in "${SUPPORT_DIR}" "${AUTHDB_BACKUPS}" "${LOG_DIR}"
    do
        "${MKDIR}" -p "${dir}"
        "${CHOWN}" root:wheel "${dir}"
    done
    "${CHMOD}" 755 "${SUPPORT_DIR}"
    "${CHMOD}" 755 "${LOG_DIR}"
    "${CHMOD}" 700 "${AUTHDB_BACKUPS}"
}

# Belt and braces: the pkg is built non-root with `recommended` ownership,
# so re-assert ownership/modes explicitly (never through a symlink).
# Each step is checked on its own, so a failed chown is never hidden by a
# chmod that succeeds after it.
fix_ownership() {
    "${CHOWN}" -h root:wheel "${DAEMON_BINARY}" "${LAUNCHD_PLIST}" || return 1
    "${CHMOD}" -h 755 "${DAEMON_BINARY}" || return 1
    "${CHMOD}" -h 644 "${LAUNCHD_PLIST}" || return 1
    if [[ -f "${UNINSTALL_HELPER}" && ! -L "${UNINSTALL_HELPER}" ]]
    then
        "${CHOWN}" -h root:wheel "${UNINSTALL_HELPER}" || return 1
        "${CHMOD}" -h 755 "${UNINSTALL_HELPER}" || return 1
    fi
    if [[ -f "${INSTALLED_PAM_LIB}" && ! -L "${INSTALLED_PAM_LIB}" ]]
    then
        "${CHOWN}" -h root:wheel "${INSTALLED_PAM_LIB}" || return 1
        "${CHMOD}" -h 644 "${INSTALLED_PAM_LIB}" || return 1
    fi
    return 0
}

# Returns nonzero instead of exiting so the caller can take the abort path.
bootstrap_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) || true
    fi

    # An earlier uninstall or abort leaves the label DISABLED, and bootstrap
    # refuses a disabled service — enable first.
    "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl enable system/${DAEMON_LABEL} failed"

    log_info "Bootstrapping ${DAEMON_LABEL}"
    # Taken BEFORE the bootstrap: only a state.plist written after it counts.
    BOOTSTRAP_MARK=$(serberus_launchd_bootstrap_mark)
    if ! "${LAUNCHCTL}" bootstrap system "${LAUNCHD_PLIST}"
    then
        log_error "launchctl bootstrap failed"
        return 1
    fi
}

# The arch sudo demands on this Mac (sudo runs arm64e on Apple silicon).
native_module_arch() {
    local machine
    machine=$("${UNAME}" -m)
    case "${machine}" in
        arm64|arm64e)
            printf 'arm64'
            ;;
        *)
            printf '%s' "${machine}"
            ;;
    esac
}

# The preinstall removed a sudo_local line for the upgrade (root-only marker).
# Put it back ONLY when the installed module passes the PAM test pkg's checks
# against THIS daemon (root-only directory chain, signed by the daemon's
# team, native arch); otherwise sudo stays native and the reason is logged
# loudly — run the PAM (or core) test pkg to wire it again.
rewire_if_previously_unwired() {
    if [[ -L "${MARKER_DIR}" || ! -f "${REWIRE_MARKER}" || -L "${REWIRE_MARKER}" ]]
    then
        return 0
    fi
    if [[ "$("${STAT}" -f '%u' "${REWIRE_MARKER}" 2>/dev/null)" != "0" ]]
    then
        "${RM}" -f "${REWIRE_MARKER}"
        return 0
    fi
    "${RM}" -f "${REWIRE_MARKER}"
    log_info "The preinstall unwired sudo_local for this upgrade — re-wiring"
    local file_desc
    if [[ -z "${DAEMON_TEAM}" ]]
    then
        log_error "!!! NOT re-wiring sudo_local: the daemon carries no Team ID to pin ${PAM_MODULE} to. sudo stays native."
        return 0
    fi
    if ! serberus_pam_module_path_is_safe "${PAM_MODULE}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) \
        || ! serberus_codesign_satisfies_team "${PAM_MODULE}" "${DAEMON_TEAM}"
    then
        log_error "!!! NOT re-wiring sudo_local: ${PAM_MODULE} is not root-only or not signed by team ${DAEMON_TEAM}. sudo stays native."
        return 0
    fi
    if ! file_desc=$("${FILE}" -b "${PAM_MODULE}" 2>/dev/null) || [[ "${file_desc}" != *"$(native_module_arch)"* ]]
    then
        log_error "!!! NOT re-wiring sudo_local: ${PAM_MODULE} does not cover the native arch. sudo stays native."
        return 0
    fi
    # OpenPAM would load a stray <module>.2 in place of the module.
    local versioned
    versioned=$(serberus_pam_remove_versioned_module) || versioned="FAILED"
    if [[ "${versioned}" == "FAILED" ]]
    then
        log_error "!!! NOT re-wiring sudo_local: ${SERBERUS_PAM_MODULE_VERSIONED_PATH} could not be removed. sudo stays native."
        return 0
    fi
    # Last look before sudo is gated again: still the daemon confirmed up.
    if ! serberus_launchd_pid_unchanged "${DAEMON_LABEL}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "${DAEMON_LABEL} restarted after it was confirmed up — NOT re-wiring sudo_local"
        return 1
    fi
    local merge_result
    merge_result=$(serberus_pam_merge_sudo_local "${SUDO_LOCAL}") || merge_result="FAILED"
    if ! serberus_pam_sudo_local_is_canonical "${SUDO_LOCAL}"
    then
        log_error "!!! re-wired sudo_local is not canonical (${merge_result}) — rolling back ($(serberus_pam_remove_sudo_local "${SUDO_LOCAL}")). sudo stays native."
        return 0
    fi
    if ! "${CHOWN}" -h root:wheel "${SUDO_LOCAL}" || ! "${CHMOD}" -h go-w "${SUDO_LOCAL}"
    then
        log_error "could not set root:wheel / go-w on ${SUDO_LOCAL}"
        return 1
    fi
    log_info "sudo_local re-wired (${merge_result})"
}

# ---- The ONE abort path (same ORDER as the uninstall helper) ----

disable_daemon() {
    "${LAUNCHCTL}" disable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl disable system/${DAEMON_LABEL} failed"
}

# Returns 1 when the drop-in is STILL there: the caller must not unwire.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log_error "abort path: sudoers drop-in removal result=${result}"
    [[ "${result}" != "FAILED" ]]
}

# Routes serberus_daemon_manual_steps into the log. $1 demote | restore | sudoers
log_manual_steps() {
    local line
    while IFS= read -r line
    do
        log_error "${line}"
    done < <(serberus_daemon_manual_steps "$1" "${AUTHDB_BACKUPS}")
}

# With the daemon going down, a sudo_local the PAM test pkg wired would deny
# every non-bypass sudo: unwire it (marker-aware). Returns 1 when an ACTIVE
# line SURVIVES.
unwire_sudo_local() {
    if ! serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        return 0
    fi
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_error "abort path: sudo_local unwire result=${result}"
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        return 1
    fi
    return 0
}

bootout_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        if ! serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            DAEMON_GONE=0
            log_error "abort path: ${DAEMON_LABEL} is still loaded after its bootout"
        fi
    fi
}

# Runs a daemon one-shot with the deadline. SERBERUS_DEV_KEY_FALLBACK=1 is
# what this ring's LaunchDaemon sets.
run_daemon_oneshot() {
    serberus_run_bounded "${ONESHOT_TIMEOUT}" \
        "${ENV}" SERBERUS_DEV_KEY_FALLBACK=1 "${DAEMON_BINARY}" "$1" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
}

# Exit 3 = no grant store, nothing to demote.
demote_jit_admins() {
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "abort path: the daemon is still loaded — NOT running --demote-jit beside it."
        log_manual_steps demote
        return 0
    fi
    if [[ "${DAEMON_TRUSTED}" -ne 1 || ! -x "${DAEMON_BINARY}" ]]
    then
        log_error "abort path: the daemon failed its signature check (or is missing) — NOT executing it."
        log_manual_steps demote
        return 0
    fi
    local status=0
    run_daemon_oneshot --demote-jit || status=$?
    case "${status}" in
        0)
            log_info "abort path: JIT admins demoted"
            ;;
        3)
            log_info "abort path: no grant store — no JIT admins to demote"
            ;;
        *)
            log_error "abort path: --demote-jit FAILED (exit ${status}; 124 = timed out)"
            log_manual_steps demote
            ;;
    esac
}

restore_authdb() {
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "abort path: the daemon is still loaded — NOT running --restore-authdb beside it."
        log_manual_steps restore
        return 0
    fi
    if [[ "${DAEMON_TRUSTED}" -ne 1 || ! -x "${DAEMON_BINARY}" ]]
    then
        log_error "abort path: the daemon failed its signature check (or is missing) — NOT executing it for --restore-authdb."
        log_manual_steps restore
        return 0
    fi
    local status=0
    run_daemon_oneshot --restore-authdb || status=$?
    if [[ "${status}" -ne 0 ]]
    then
        log_error "abort path: authdb restore FAILED (exit ${status}; 124 = timed out) — review ${AUTHDB_BACKUPS}"
    fi
}

# drop-in (a SURVIVING drop-in re-arms the daemon and stops here, before the
# PAM gate is touched) -> unwire (a SURVIVING line re-arms the daemon and
# stops here) -> disable -> bootout (wait until gone) -> drop-in again ->
# demote JIT -> restore authdb -> exit 1.
# A reboot cannot resurrect an ungated daemon.
abort_install() {
    ABORT_IN_PROGRESS=1
    set +e
    log_error "ABORTING: $*"
    "${RM}" -f "${REWIRE_MARKER}" 2>/dev/null
    if ! remove_sudoers_dropin
    then
        log_error "!!! The Serberus sudoers drop-in SURVIVED its removal — NOT unwiring ${SUDO_LOCAL}."
        log_manual_steps sudoers
        serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        exit 1
    fi
    if ! unwire_sudo_local
    then
        log_error "!!! An ACTIVE pam_serberus line SURVIVED the unwire in ${SUDO_LOCAL}."
        log_error "!!! Keeping ${DAEMON_LABEL} ENABLED and RUNNING behind it (a wired module with no"
        log_error "!!! daemon denies every sudo). Remove the line by hand, then run ${UNINSTALL_HELPER}."
        serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        exit 1
    fi
    disable_daemon
    bootout_daemon
    if ! remove_sudoers_dropin
    then
        log_manual_steps sudoers
    fi
    demote_jit_admins
    restore_authdb
    exit 1
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (installer log: /var/log/install.log)"

require_root
require_boot_volume
source_pam_lib
trap on_exit EXIT
assess_daemon_trust
ensure_directories

if ! install_validation_passes
then
    abort_install "install validation failed"
fi

if ! fix_ownership
then
    abort_install "could not set ownership/modes on the payload"
fi

if ! bootstrap_daemon
then
    abort_install "launchctl bootstrap failed"
fi

# One pid held for 8 s with no launchd restart (a kill loop is briefly
# "running" at each respawn), a state.plist written since the bootstrap, plus
# `serberus status` when another Serberus pkg installed the CLI (this pkg does
# not ship it).
HEALTH_CLI=""
if [[ -e "${CLI_BINARY}" ]]
then
    HEALTH_CLI="${CLI_BINARY}"
fi
if ! serberus_launchd_wait_running "${DAEMON_LABEL}" "${DAEMON_START_TIMEOUT}" "${HEALTH_CLI}" "${DAEMON_TEAM}" "${STATE_PLIST}" "${BOOTSTRAP_MARK}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
then
    abort_install "${DAEMON_LABEL} never came up (no stable pid within ${DAEMON_START_TIMEOUT}s, a restart, no fresh state.plist, or serberus status failed)"
fi
log_info "Daemon ${DAEMON_LABEL} is running (pid ${SERBERUS_LAUNCHD_UP_PID})"

if ! rewire_if_previously_unwired
then
    abort_install "sudo_local could not be re-wired safely"
fi

INSTALL_SUCCEEDED=1
log_info "${SCRIPT_NAME} completed successfully"
exit 0

###########################################################
################## End Script Block #######################
###########################################################
POSTINSTALL_EOF

    "${CHMOD}" 755 "${postinstall_path}"

    if ! "${BASH_BIN}" -n "${postinstall_path}"
    then
        log_error "Generated postinstall failed bash -n: ${postinstall_path}"
        exit 1
    fi
}

assemble_payload() {
    log_info "Assembling payload at ${PAYLOAD_DIR}"
    "${MKDIR}" -p "${PAYLOAD_DIR}/Library/PrivilegedHelperTools"
    "${MKDIR}" -p "${PAYLOAD_DIR}/Library/LaunchDaemons"
    "${MKDIR}" -p "${PAYLOAD_DIR}${SUPPORT_DIR}/authdb-backups"
    "${MKDIR}" -p "${PAYLOAD_DIR}${LOG_DIR}"

    "${CP}" "${DAEMON_BIN}" "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"
    "${CHMOD}" 755 "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"

    local entitlements_file
    entitlements_file=$(write_entitlements)
    # Explicit --identifier: for a flat binary named com.herojoneslabs.serberus.daemon
    # codesign would derive "com.herojoneslabs.serberus" (it treats ".daemon"
    # as an extension), and the PAM module and the Sentinel/Intel clients pin
    # the daemon peer to `identifier "com.herojoneslabs.serberus.daemon" and
    # anchor apple generic and certificate leaf[subject.OU] = "<team>"`.
    log_info "Signing daemon binary with identity '${SIGNING_IDENTITY}' (identifier ${BUNDLE_ID})"
    if ! "${CODESIGN}" --force --sign "${SIGNING_IDENTITY}" \
        --identifier "${BUNDLE_ID}" \
        --options runtime \
        --entitlements "${entitlements_file}" \
        "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"
    then
        log_error "codesign failed"
        exit 1
    fi
    local daemon_identifier
    daemon_identifier=$("${CODESIGN}" --display --verbose=2 "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}" 2>&1 \
        | "${AWK}" -F= '/^Identifier=/{print $2}')
    if [[ "${daemon_identifier}" != "${BUNDLE_ID}" ]]
    then
        log_error "Daemon signing identifier is '${daemon_identifier}', expected '${BUNDLE_ID}' (peers pin it)."
        exit 1
    fi
    if ! "${CODESIGN}" --verify "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"
    then
        log_error "signed binary failed codesign --verify"
        exit 1
    fi

    write_daemon_plist
    write_uninstall_helper
    "${CP}" "${PAM_LIB_SRC}" "${PAYLOAD_DIR}${SUPPORT_DIR}/${PAM_LIB_NAME}"
    "${CHMOD}" 644 "${PAYLOAD_DIR}${SUPPORT_DIR}/${PAM_LIB_NAME}"

    # Payload modes only — the pkg is built as the user, so ownership comes
    # from pkgbuild's default `recommended` mapping (root:wheel under
    # /Library) and is re-asserted by the postinstall.
    "${CHMOD}" 755 "${PAYLOAD_DIR}${SUPPORT_DIR}"
    "${CHMOD}" 700 "${PAYLOAD_DIR}${SUPPORT_DIR}/authdb-backups"
    "${CHMOD}" 755 "${PAYLOAD_DIR}${LOG_DIR}"

    # Strip removable extended attributes (a cloud-synced working copy can
    # stamp every file) so
    # the payload BOM stays minimal. The kernel-managed com.apple.provenance
    # xattr survives this and appears as AppleDouble ._* entries in the BOM —
    # unavoidable on modern macOS and harmless (Installer restores it as an
    # xattr; no literal ._ files land on disk). Safe for the daemon: Mach-O
    # signatures are embedded, not xattr-stored.
    "${XATTR}" -rc "${PAYLOAD_DIR}"
}

build_package() {
    log_info "Building component pkg ${OUTPUT_PKG}"
    "${PKGBUILD}" \
        --root "${PAYLOAD_DIR}" \
        --scripts "${SCRIPTS_DIR}" \
        --identifier "${PKG_IDENTIFIER}" \
        --version "${PKG_VERSION}" \
        "${OUTPUT_PKG}"
    log_info "Built ${OUTPUT_PKG}"
}

sign_installer() {
    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        return 0
    fi
    log_info "Signing installer with '${INSTALLER_IDENTITY}'"
    "${PRODUCTSIGN}" --sign "${INSTALLER_IDENTITY}" "${OUTPUT_PKG}" "${SIGNED_PKG}"
    log_info "Signed installer: ${SIGNED_PKG}"
}

print_summary() {
    local pkg="${OUTPUT_PKG}"
    if [[ -f "${SIGNED_PKG}" ]]
    then
        pkg="${SIGNED_PKG}"
    fi
    log_info "──────────────────────────────────────────────────────────────"
    log_info "TEST-RING pkg ready: ${pkg}"
    log_info "Contains: ${INSTALL_BINARY_PATH} (bare binary, no ESF/PAM/Sentinel),"
    log_info "          /Library/LaunchDaemons/${BUNDLE_ID}.plist,"
    log_info "          ${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME},"
    log_info "          ${SUPPORT_DIR}/${PAM_LIB_NAME}"
    log_info "Deploy:   upload to Jamf, install via policy (rules arrive via the"
    log_info "          com.herojoneslabs.serberus.rules configuration profile)."
    log_info "Verify:   sudo launchctl print system/${DAEMON_LABEL}"
    log_info "          sudo security authorizationdb read <right>"
    log_info "Teardown: sudo \"${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}\" [--purge]"
    log_info "Receipt:  pkgutil --pkg-info ${PKG_IDENTIFIER}"
    log_info "NOT for production — use build-pkg.sh (notarized ESF bundle) instead."
    log_info "──────────────────────────────────────────────────────────────"
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
        "${MKDIR}" -p "${SCRIPTS_DIR}" "${PAYLOAD_DIR}${SUPPORT_DIR}"
        write_uninstall_helper
        write_preinstall
        write_postinstall
        stage_pam_lib
        log_info "Generated scripts written under ${BUILD_DIR}"
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
build_daemon
"${RM}" -rf "${BUILD_DIR}"
"${MKDIR}" -p "${BUILD_DIR}" "${SCRIPTS_DIR}"
assemble_payload
write_preinstall
write_postinstall
stage_pam_lib
build_package
sign_installer
print_summary

log_info "${SCRIPT_NAME} completed successfully"

###########################################################
################## End Script Block #######################
###########################################################
