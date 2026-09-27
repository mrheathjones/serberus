#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-commander-pkg.sh
# Author: Heath Jones
# Date: 2026-08-22
# Modified: 2026-09-26
# Purpose: Build the TEST-RING Serberus Commander PKG for Jamf policy
#          deployment (or a double-click install on a test Mac). Commander
#          is the ADMIN console: it authors policies, exports/publishes
#          profiles, simulates decisions, and reads the Jamf
#          inventory for the Fleet Observer. It is OUTSIDE the sudo safety
#          chain — no daemon, no PAM, no XPC registration — so every step
#          here is best-effort and a failed install can never leave a Mac
#          half-configured.
#            PAYLOAD     — /Applications/Serberus Commander.app
#                          uninstall helper under /Library/Application Support
#            PREINSTALL  — quit a running Commander (upgrade), remove the
#                          pre-rename "SerberusCommander.app" orphan
#            POSTINSTALL — relaunch Commander for the console user if the
#                          preinstall had to quit it (binary swap on update)
#          Signing: the app bundle is signed HERE, in staging outside any
#          cloud-synced folder (a sync provider can re-stamp
#          com.apple.FinderInfo continuously, which codesign rejects — same
#          reasoning as build-sentinel-app-pkg.sh).
#          Commander never needs the is-ui-sentinel entitlement.
# Version: 1.8 - Generated postinstall: its first log line says where the
#          installer log is (/var/log/install.log).
#          1.7 - Generated uninstall helper: per-user purges find each
#          account through its record (dscl short name and home), not the
#          name of a folder under /Users.
#          1.6 - Generated scripts: per-user purges (--purge) run AS the
#          user (sudo -u) after the symlink/owner checks, never as root;
#          pkill patterns are anchored to the bundle path (^…, dots
#          escaped); require_boot_volume accepts an empty $3 only for a manual
#          run, not under Installer.
#          1.5 - (a) The app is pinned BundleIsRelocatable=false
#          (pkgbuild --analyze component plist), so PackageKit cannot
#          "relocate" the install onto a copy LaunchServices knows elsewhere.
#          (b) Generated scripts: umask 022, an EXIT trap that logs a failed
#          run, and the pre/postinstall refuse a target volume other than "/"
#          ($3). (c) Absolute builder tool paths (notarytool/stapler via
#          /usr/bin/xcrun).
#          1.4 - Generated scripts: system-only PATH. The relaunch handshake
#          moved from a fixed /private/tmp name (a user could pre-plant a
#          symlink root would follow) to the root-only directory
#          /Library/Application Support/Serberus/.install-markers (0700),
#          checked for ! -L and owner 0 before use. The uninstall helper's
#          --purge refuses to delete through a symlinked or foreign-owned
#          component of a user's home.
#          1.3 - Team ID comes from DEVELOPMENT_TEAM (environment or
#          Config/Local.xcconfig) via Support/team-id-lib.sh instead of
#          being hardcoded; required only when signing.
#          1.2 - The DEPLOY pkg always has the clean name (…-<v>.pkg): when
#                signing, that IS the signed pkg and the unsigned intermediate
#                is …-<v>-unsigned.pkg — so grabbing SerberusCommander-<v>.pkg
#                always gets the installable one. An unsigned pkg fails
#                PackageKit trust even under `sudo installer` on a managed Mac.
#          1.1 - Signed-installer + notarization path: codesign with a secure
#                timestamp; INSTALLER_IDENTITY productsigns; NOTARY_PROFILE
#                submits + staples (Gatekeeper-clean double-click installs).
#          1.0 - Initial Script (pkg default 1.0)
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER, never sudo — codesign needs the signing
# chain in your login keychain):
#
#   SIGNING_IDENTITY=<Apple Development cert hash or name> ./PKG/build-commander-pkg.sh
#
# Optional env:
#   INSTALLER_IDENTITY   "Developer ID Installer: Your Name (YOURTEAMID)"
#                        — signs the .pkg (Jamf policy installs accept
#                        unsigned pkgs; a double-clicked unsigned pkg is
#                        REFUSED by Gatekeeper on modern macOS)
#   NOTARY_PROFILE       notarytool keychain profile (e.g. serberus-notary;
#                        created once with `xcrun notarytool store-credentials`)
#                        — submits the SIGNED pkg, waits, staples. Needs
#                        INSTALLER_IDENTITY. Without it the signed pkg still
#                        needs Privacy & Security → "Open Anyway" (or Jamf /
#                        `sudo installer -pkg … -target /`) to install.
#   COMMANDER_APP        path to a prebuilt Release "Serberus Commander.app"
#                        (present => skips the xcodebuild)
#   PKG_VERSION          package version (default 1.0)
#   SERBERUS_DERIVED     derivedDataPath for the xcodebuild (default
#                        <repo>/.build/xcode; use a path outside any
#                        cloud-synced folder if the build sandbox trips on
#                        header copies)
#
# Modes:
#   (default / --build)       build the pkg
#   --emit-scripts <dir>      write the generated pre/postinstall + uninstall
#                             helper to <dir> without building (bash -n checks)
#
# Deploy: upload the built pkg to Jamf and install via policy, or copy it to
# the test Mac and double-click (unsigned pkg: right-click → Open). Teardown:
#   sudo "/Library/Application Support/Serberus/uninstall-serberus-commander.sh" [--purge]

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
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly MKDIR="/bin/mkdir"
readonly PKGBUILD="/usr/bin/pkgbuild"
readonly PRODUCTSIGN="/usr/bin/productsign"
readonly RM="/bin/rm"
readonly SPCTL="/usr/sbin/spctl"
readonly XATTR="/usr/bin/xattr"
# The Xcode tools resolve through the /usr/bin shims (xcrun finds notarytool
# and stapler in the selected Xcode).
readonly XCODEBUILD="/usr/bin/xcodebuild"
readonly XCRUN="/usr/bin/xcrun"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.8"
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
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
# The Apple Developer Team ID the signed app must carry, from DEVELOPMENT_TEAM
# in the environment or Config/Local.xcconfig. Resolved here but only
# required when signing, so unsigned and prebuilt paths still work.
# shellcheck source=../Support/team-id-lib.sh
source "${REPO_DIR}/Support/team-id-lib.sh"
TEAM_ID=$(serberus_team_id "${REPO_DIR}") || TEAM_ID=""
readonly TEAM_ID

# ---- The admin console: "Serberus Commander.app" (/Applications) ----
readonly APP_SCHEME="SerberusCommander"
readonly APP_NAME="Serberus Commander.app"
readonly APP_BUNDLE_ID="${ORG_PLIST_DOMAIN}.commander"
readonly APP_INSTALL_DIR="/Applications"
# Pre-rename orphan: the bundle used to be "SerberusCommander.app" (no space,
# 2026-08-22 rename). Removed explicitly by pre/postinstall so /Applications
# never keeps both.
readonly APP_OLD_PATH="/Applications/SerberusCommander.app"
# Handshake between pre- and postinstall: the preinstall touches this when it
# quits a RUNNING Commander, so the postinstall relaunches it (swapping the
# visible binary on update). Absent on a fresh install → nothing pops up.
# It lives in a ROOT-ONLY directory (0700): a fixed name in world-writable
# /private/tmp let any user pre-plant a symlink that root's `touch` followed.
readonly INSTALL_MARKER_DIR="${SUPPORT_DIR}/.install-markers"
readonly RELAUNCH_MARKER="${INSTALL_MARKER_DIR}/commander-relaunch"
# Pre-1.4 marker location, removed if present (rm -f never follows a symlink).
readonly LEGACY_RELAUNCH_MARKER="/private/tmp/${ORG_PLIST_DOMAIN}.commander-relaunch"

# Generated-script helper: root deletes inside a user's home only through
# this guard. Literal (quoted heredoc) so it lands in the scripts verbatim.
SAFE_USER_REMOVE_FN=$("${CAT}" <<'SAFE_USER_REMOVE_EOF'
# A path inside a user's home is removed only when the home belongs to a
# real (non-root) account and EVERY component from the home down to the
# target is a real (non-symlink) directory/file owned by that account — and
# then AS THAT USER (sudo -u), never as root. The checks are a first filter
# only: the user could swap a component for a symlink between the check and
# the rm, and running as the user means such a swap reaches nothing the user
# could not delete anyway. The short name and home come from the account
# record (dscl), never from the name of a folder under /Users.
#   $1 short name, $2 home, $3 rm flag (-f or -rf), $4… path components
#   below the home
safe_user_remove() {
    local user="$1"
    local home="$2"
    local flag="$3"
    shift 3
    local uid
    uid=$(/usr/bin/id -u "${user}" 2>/dev/null) || return 0
    if [[ ! "${uid}" =~ ^[0-9]+$ || "${uid}" -eq 0 ]]
    then
        return 0
    fi
    local path="${home}"
    local part
    local owner
    for part in "" "$@"
    do
        if [[ -n "${part}" ]]
        then
            path="${path}/${part}"
        fi
        if [[ -L "${path}" ]]
        then
            printf '[WARN] skipping %s: it is a symlink\n' "${path}"
            return 0
        fi
        if [[ ! -e "${path}" ]]
        then
            return 0
        fi
        owner=$(/usr/bin/stat -f '%u' "${path}" 2>/dev/null) || return 0
        if [[ "${owner}" != "${uid}" ]]
        then
            printf '[WARN] skipping %s: owned by uid %s, not %s\n' "${path}" "${owner}" "${user}"
            return 0
        fi
    done
    if ! /usr/bin/sudo -n -u "${user}" /bin/rm "${flag}" -- "${path}" 2>/dev/null
    then
        printf '[WARN] could not remove %s as %s\n' "${path}" "${user}"
    fi
}
SAFE_USER_REMOVE_EOF
)
readonly SAFE_USER_REMOVE_FN

# Generated-script helpers for the relaunch handshake (root-only marker dir).
MARKER_FNS=$("${CAT}" <<'MARKER_FNS_EOF'
# The marker directory is trusted only when it (and the support dir above it)
# is a real directory owned by root; the marker only when it is a regular
# root-owned file. Anything else is ignored — never followed.
marker_dir_is_trusted() {
    [[ -d "${SUPPORT_DIR}" && ! -L "${SUPPORT_DIR}" ]] || return 1
    [[ "$(/usr/bin/stat -f '%u' "${SUPPORT_DIR}" 2>/dev/null)" == "0" ]] || return 1
    [[ -d "${MARKER_DIR}" && ! -L "${MARKER_DIR}" ]] || return 1
    [[ "$(/usr/bin/stat -f '%u' "${MARKER_DIR}" 2>/dev/null)" == "0" ]]
}

prepare_marker_dir() {
    if [[ -L "${SUPPORT_DIR}" ]]
    then
        return 1
    fi
    /bin/mkdir -p "${SUPPORT_DIR}" || return 1
    if [[ -L "${MARKER_DIR}" ]]
    then
        /bin/rm -f "${MARKER_DIR}"
    fi
    /bin/mkdir -p -m 700 "${MARKER_DIR}" 2>/dev/null || return 1
    marker_dir_is_trusted || return 1
    /bin/chmod 700 "${MARKER_DIR}"
}

marker_is_trusted() {
    marker_dir_is_trusted || return 1
    [[ -f "${MARKER}" && ! -L "${MARKER}" ]] || return 1
    [[ "$(/usr/bin/stat -f '%u' "${MARKER}" 2>/dev/null)" == "0" ]]
}
MARKER_FNS_EOF
)
readonly MARKER_FNS

# Generated-script helpers: the boot-volume guard and an EXIT trap that logs a
# failed run. Literal (quoted heredoc).
GUI_FNS=$("${CAT}" <<'GUI_FNS_EOF'
# The app installs onto the running system only (Installer passes it as $3).
# An empty $3 is accepted only for a manual run (sudo ./postinstall); under
# Installer (INSTALLER_TEMP / PACKAGE_PATH / COMMAND_LINE_INSTALL set) the
# target must be "/".
require_boot_volume() {
    local under_installer=0
    if [[ -n "${INSTALLER_TEMP:-}" || -n "${PACKAGE_PATH:-}" || -n "${COMMAND_LINE_INSTALL:-}" ]]
    then
        under_installer=1
    fi
    if [[ -z "${TARGET_VOLUME:-}" && "${under_installer}" -eq 0 ]]
    then
        return 0
    fi
    if [[ "${TARGET_VOLUME:-}" != "/" ]]
    then
        printf '[ERROR] Target volume is %s, not /. Serberus installs on the running system.\n' "${TARGET_VOLUME:-<empty>}" >&2
        exit 1
    fi
}

# Best-effort scripts still say when they failed.
on_exit() {
    local status=$?
    if [[ "${status}" -ne 0 ]]
    then
        /usr/bin/logger -t "com.herojoneslabs.serberus.gui-pkg" -p user.err "[ERROR] ${0##*/} exited with status ${status}"
    fi
}
GUI_FNS_EOF
)
readonly GUI_FNS

readonly UNINSTALL_HELPER_NAME="uninstall-serberus-commander.sh"

# Distinct identifier from every other Serberus pkg (…sentinelapptestpkg,
# …sentineltestpkg, …testpkg, …pamtestpkg, …pkg) so receipts never masquerade.
readonly PKG_IDENTIFIER="${ORG_PLIST_DOMAIN}.commanderpkg"
readonly PKG_VERSION="${PKG_VERSION:-1.0}"

readonly MODE="${1:---build}"
readonly EMIT_DIR="${2:-}"

# --emit-scripts redirects generated output into the caller's directory; a
# normal build works under PKG/build-test/commander — its OWN subdir of
# build-test, so `rm -rf` here can never clobber a sibling test pkg build.
if [[ "${MODE}" == "--emit-scripts" && -n "${EMIT_DIR}" ]]
then
    readonly BUILD_DIR="${EMIT_DIR}"
    readonly STAGING_DIR="${EMIT_DIR}"
else
    readonly BUILD_DIR="${SCRIPT_DIR}/build-test/commander"
    # Staged outside any cloud-synced folder (see the header: an .app cannot
    # be signed in one).
    readonly STAGING_DIR="${SERBERUS_PKG_STAGING:-${HOME}/Library/Caches/${ORG_PLIST_DOMAIN}/pkg-commander}"
fi
readonly PAYLOAD_DIR="${STAGING_DIR}/payload"
readonly SCRIPTS_DIR="${STAGING_DIR}/scripts"
readonly STAGED_APP="${PAYLOAD_DIR}${APP_INSTALL_DIR}/${APP_NAME}"
# The DEPLOYABLE pkg always has the clean name; when signing, the unsigned
# intermediate is the one with the suffix, so the obvious file is never the
# wrong one (an unsigned pkg fails PackageKit trust even under `sudo installer`).
readonly FINAL_PKG="${BUILD_DIR}/SerberusCommander-${PKG_VERSION}.pkg"
readonly UNSIGNED_PKG="${BUILD_DIR}/SerberusCommander-${PKG_VERSION}-unsigned.pkg"
# pkgbuild --analyze output, edited so no bundle in the payload is relocatable.
readonly COMPONENT_PLIST="${STAGING_DIR}/component.plist"

# Build artifact. Built by build_app() unless COMMANDER_APP points at a prebuilt one.
readonly DERIVED="${SERBERUS_DERIVED:-${REPO_DIR}/.build/xcode}"
readonly APP_BUILT="${COMMANDER_APP:-${DERIVED}/Build/Products/Release/${APP_NAME}}"

# Signing inputs. SIGNING_IDENTITY is REQUIRED and must be a REAL identity —
# the same Apple Development / Developer ID ring as the Sentinel apps, so the
# fleet runs one consistently-signed Serberus (hardened runtime + Team ID).
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"
readonly NOTARY_PROFILE="${NOTARY_PROFILE:-}"

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
    # Must NOT run as root: `sudo codesign` cannot build the signing chain
    # (the cert lives in the logged-in user's login keychain), and pkgbuild's
    # default `recommended` ownership produces root ownership at install time,
    # so a non-root build is correct.
    if [[ "$("${ID}" -u)" -eq 0 ]]
    then
        log_error "Run as the logged-in user, not root (codesign needs your login keychain)."
        exit 1
    fi

    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_error "SIGNING_IDENTITY is required and must be a REAL identity (same ring as the Sentinel pkgs)."
        log_error "  security find-identity -v -p codesigning   # list identities"
        log_error "  SIGNING_IDENTITY=<hash> ./PKG/${SCRIPT_NAME}"
        exit 1
    fi

    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        log_warn "INSTALLER_IDENTITY unset — the installer pkg will be UNSIGNED."
        log_warn "Jamf policy installs accept unsigned pkgs; a double-clicked unsigned pkg is refused by Gatekeeper."
    fi
    if [[ -n "${NOTARY_PROFILE}" && -z "${INSTALLER_IDENTITY}" ]]
    then
        log_error "NOTARY_PROFILE needs INSTALLER_IDENTITY (only a signed pkg can be notarized)."
        exit 1
    fi
}

# Release-build the app unless a prebuilt override is supplied.
build_app() {
    if [[ -n "${COMMANDER_APP:-}" ]]
    then
        log_info "Using prebuilt ${APP_SCHEME}: ${APP_BUILT}"
    else
        log_info "Building ${APP_SCHEME} (Release, signing deferred to staging)"
        "${XCODEBUILD}" \
            -project "${REPO_DIR}/Serberus.xcodeproj" \
            -scheme "${APP_SCHEME}" \
            -configuration Release \
            -derivedDataPath "${DERIVED}" \
            CODE_SIGNING_ALLOWED=NO \
            build >/dev/null
    fi
    if [[ ! -d "${APP_BUILT}" ]]
    then
        log_error "App bundle not found: ${APP_BUILT}"
        exit 1
    fi
}

# Copy the app into staging (outside cloud-synced folders), strip detritus, verify bundle
# ID, sign with hardened runtime, verify signature + Team ID.
stage_and_sign_app() {
    "${MKDIR}" -p "$("${DIRNAME}" "${STAGED_APP}")"
    "${RM}" -rf "${STAGED_APP}"
    "${CP}" -R "${APP_BUILT}" "${STAGED_APP}"
    "${CHMOD}" -R u+w "${STAGED_APP}"
    "${XATTR}" -rc "${STAGED_APP}"

    local built_id
    built_id=$("${PLIST_BUDDY}" -c 'Print :CFBundleIdentifier' "${STAGED_APP}/Contents/Info.plist")
    if [[ "${built_id}" != "${APP_BUNDLE_ID}" ]]
    then
        log_error "Bundle identifier mismatch: built '${built_id}', expected '${APP_BUNDLE_ID}'"
        exit 1
    fi

    # --timestamp: a secure timestamp is required for notarization (and is
    # harmless otherwise — it needs network access to Apple's timestamp server).
    log_info "Signing ${APP_NAME} with '${SIGNING_IDENTITY}'"
    "${CODESIGN}" --force --options runtime --timestamp --sign "${SIGNING_IDENTITY}" "${STAGED_APP}"

    if ! "${CODESIGN}" --verify --strict "${STAGED_APP}"
    then
        log_error "Signature verification failed for ${STAGED_APP} (stray xattr?)"
        exit 1
    fi

    # Capture first, then grep: piping codesign straight into `grep -q` under
    # pipefail intermittently fails on SIGPIPE.
    local sign_info
    if [[ -z "${TEAM_ID}" ]]
    then
        log_error "No Apple Developer Team ID configured. Set DEVELOPMENT_TEAM in"
        log_error "Config/Local.xcconfig (copy Config/Local.xcconfig.example) or the environment."
        exit 1
    fi
    sign_info=$("${CODESIGN}" -dv "${STAGED_APP}" 2>&1)
    if ! "${GREP}" -q "TeamIdentifier=${TEAM_ID}" <<< "${sign_info}"
    then
        log_error "Signature does not carry TeamIdentifier=${TEAM_ID}."
        exit 1
    fi
}

write_uninstall_helper() {
    local helper_dir="${PAYLOAD_DIR}${SUPPORT_DIR}"
    "${MKDIR}" -p "${helper_dir}"
    "${CAT}" > "${helper_dir}/${UNINSTALL_HELPER_NAME}" <<UNINSTALL_HELPER_EOF
#! /bin/bash
# Removes Serberus Commander (the admin console). --purge also removes each
# user's local policy library (policies.json) and Commander preferences.
# The Jamf API secret lives in the user's login keychain
# (service ${APP_BUNDLE_ID}.mdm) and is left alone — remove it in Keychain
# Access if required.
# Generated by build-commander-pkg.sh ${SCRIPT_VERSION} (2026-09-26).
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

${SAFE_USER_REMOVE_FN}

${GUI_FNS}
trap on_exit EXIT

if [[ "\$(/usr/bin/id -u)" -ne 0 ]]
then
    printf '[ERROR] Run as root (sudo).\n' >&2
    exit 1
fi
PURGE="0"
if [[ "\${1:-}" == "--purge" ]]
then
    PURGE="1"
fi
for macos in \\
    "${APP_INSTALL_DIR}/${APP_NAME}/Contents/MacOS/" \\
    "${APP_OLD_PATH}/Contents/MacOS/"
do
    /usr/bin/pkill -f "^\${macos//./\\\\.}" 2>/dev/null || true
done
/bin/rm -rf "${APP_INSTALL_DIR}/${APP_NAME}"
/bin/rm -rf "${APP_OLD_PATH}"
/usr/sbin/pkgutil --forget "${PKG_IDENTIFIER}" 2>/dev/null || true
/bin/rm -f "${RELAUNCH_MARKER}" "${LEGACY_RELAUNCH_MARKER}" 2>/dev/null || true
if [[ "\${PURGE}" == "1" ]]
then
    # Every local account with a home, by its record (short name + home):
    # a renamed account or a home outside /Users is still found. Service
    # accounts ("_…") and /var/empty homes are skipped.
    while read -r user_name user_home
    do
        if [[ -z "\${user_name}" || "\${user_name}" == _* ]] \\
            || [[ "\${user_home}" != /* || "\${user_home}" == "/var/empty" ]]
        then
            continue
        fi
        safe_user_remove "\${user_name}" "\${user_home}" -f "Library" "Application Support" "Serberus" "policies.json"
        safe_user_remove "\${user_name}" "\${user_home}" -f "Library" "Preferences" "${APP_BUNDLE_ID}.plist"
    done < <(/usr/bin/dscl . -list /Users NFSHomeDirectory 2>/dev/null)
fi
printf '[INFO] Serberus Commander removed.\n'
exit 0
UNINSTALL_HELPER_EOF
    "${CHMOD}" 755 "${helper_dir}/${UNINSTALL_HELPER_NAME}"
    if ! "${BASH_BIN}" -n "${helper_dir}/${UNINSTALL_HELPER_NAME}"
    then
        log_error "Generated uninstall helper failed bash -n"
        exit 1
    fi
}

write_preinstall() {
    "${CAT}" > "${SCRIPTS_DIR}/preinstall" <<PREINSTALL_EOF
#! /bin/bash
# Serberus Commander preinstall: quit a running Commander so the bundle can be
# swapped, remembering to relaunch it; remove the pre-rename orphan. Best
# effort — never blocks the install (except installing onto a volume other
# than the running system, which is refused).
# Generated by build-commander-pkg.sh ${SCRIPT_VERSION} (2026-09-26).
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

SUPPORT_DIR="${SUPPORT_DIR}"
MARKER_DIR="${INSTALL_MARKER_DIR}"
MARKER="${RELAUNCH_MARKER}"
TARGET_VOLUME="\${3:-}"
${MARKER_FNS}

${GUI_FNS}
trap on_exit EXIT
require_boot_volume

/bin/rm -f "\${MARKER}" "${LEGACY_RELAUNCH_MARKER}" 2>/dev/null || true
was_running="0"
for macos in \\
    "${APP_INSTALL_DIR}/${APP_NAME}/Contents/MacOS/" \\
    "${APP_OLD_PATH}/Contents/MacOS/"
do
    if /usr/bin/pkill -f "^\${macos//./\\\\.}" 2>/dev/null
    then
        was_running="1"
    fi
done
if [[ "\${was_running}" == "1" ]]
then
    if prepare_marker_dir
    then
        /usr/bin/touch "\${MARKER}" 2>/dev/null || true
    fi
    /bin/sleep 1
fi
/bin/rm -rf "${APP_OLD_PATH}"
exit 0
PREINSTALL_EOF
    "${CHMOD}" 755 "${SCRIPTS_DIR}/preinstall"
    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/preinstall"
    then
        log_error "Generated preinstall failed bash -n"
        exit 1
    fi
}

write_postinstall() {
    "${CAT}" > "${SCRIPTS_DIR}/postinstall" <<POSTINSTALL_EOF
#! /bin/bash
# Serberus Commander postinstall: relaunch for the console user only when the
# preinstall had to quit a running Commander. Best effort. Only a root-owned
# marker in the root-only marker directory counts.
# Generated by build-commander-pkg.sh ${SCRIPT_VERSION} (2026-09-26).
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

SUPPORT_DIR="${SUPPORT_DIR}"
MARKER_DIR="${INSTALL_MARKER_DIR}"
MARKER="${RELAUNCH_MARKER}"
TARGET_VOLUME="\${3:-}"
${MARKER_FNS}

${GUI_FNS}
trap on_exit EXIT
require_boot_volume
printf '[INFO] postinstall starting (installer log: /var/log/install.log)\n'

if ! marker_is_trusted
then
    exit 0
fi
/bin/rm -f "\${MARKER}"
console_user=\$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && \$3 != "loginwindow" { print \$3 }')
if [[ -z "\${console_user}" ]]
then
    exit 0
fi
console_uid=\$(/usr/bin/id -u "\${console_user}" 2>/dev/null || printf '')
if [[ -n "\${console_uid}" ]]
then
    /bin/launchctl asuser "\${console_uid}" /usr/bin/open "${APP_INSTALL_DIR}/${APP_NAME}" 2>/dev/null || true
fi
exit 0
POSTINSTALL_EOF
    "${CHMOD}" 755 "${SCRIPTS_DIR}/postinstall"
    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/postinstall"
    then
        log_error "Generated postinstall failed bash -n"
        exit 1
    fi
}

# pkgbuild's default lets PackageKit "relocate" the app onto ANY copy of it
# LaunchServices already knows about (a dev build in a working copy, a copy on
# the Desktop…) instead of /Applications. Pin every bundle pkgbuild --analyze
# finds to BundleIsRelocatable=false (same approach as
# build-authuribrowser-pkg.sh).
write_component_plist() {
    "${PKGBUILD}" --analyze --root "${PAYLOAD_DIR}" "${COMPONENT_PLIST}" >/dev/null
    local index=0
    while "${PLIST_BUDDY}" -c "Print :${index}" "${COMPONENT_PLIST}" >/dev/null 2>&1
    do
        if ! "${PLIST_BUDDY}" -c "Set :${index}:BundleIsRelocatable false" "${COMPONENT_PLIST}" 2>/dev/null
        then
            "${PLIST_BUDDY}" -c "Add :${index}:BundleIsRelocatable bool false" "${COMPONENT_PLIST}"
        fi
        index=$((index + 1))
    done
    if [[ "${index}" -eq 0 ]]
    then
        log_error "pkgbuild --analyze found no bundle in ${PAYLOAD_DIR}"
        exit 1
    fi
    if "${PLIST_BUDDY}" -c 'Print' "${COMPONENT_PLIST}" | "${GREP}" -q 'BundleIsRelocatable = true'
    then
        log_error "Component plist still marks a bundle relocatable: ${COMPONENT_PLIST}"
        exit 1
    fi
    log_info "Component plist: ${index} bundle(s) pinned non-relocatable"
}

build_pkg() {
    "${MKDIR}" -p "${BUILD_DIR}"
    "${RM}" -f "${FINAL_PKG}" "${UNSIGNED_PKG}"
    write_component_plist
    if [[ -n "${INSTALLER_IDENTITY}" ]]
    then
        # Build the raw pkg to the -unsigned name, then productsign it into the
        # clean deploy name.
        log_info "Building ${UNSIGNED_PKG}"
        "${PKGBUILD}" \
            --root "${PAYLOAD_DIR}" \
            --component-plist "${COMPONENT_PLIST}" \
            --scripts "${SCRIPTS_DIR}" \
            --identifier "${PKG_IDENTIFIER}" \
            --version "${PKG_VERSION}" \
            --install-location "/" \
            "${UNSIGNED_PKG}"
        log_info "Signing pkg with '${INSTALLER_IDENTITY}' → ${FINAL_PKG}"
        "${PRODUCTSIGN}" --sign "${INSTALLER_IDENTITY}" "${UNSIGNED_PKG}" "${FINAL_PKG}"
        "${RM}" -f "${UNSIGNED_PKG}"
        if [[ -n "${NOTARY_PROFILE}" ]]
        then
            notarize_pkg
        fi
    else
        # No installer identity: the clean name is the (unsigned) pkg.
        log_info "Building ${FINAL_PKG} (UNSIGNED)"
        "${PKGBUILD}" \
            --root "${PAYLOAD_DIR}" \
            --component-plist "${COMPONENT_PLIST}" \
            --scripts "${SCRIPTS_DIR}" \
            --identifier "${PKG_IDENTIFIER}" \
            --version "${PKG_VERSION}" \
            --install-location "/" \
            "${FINAL_PKG}"
    fi
}

# Submit the signed pkg, wait for Apple's verdict, staple the ticket, and
# confirm Gatekeeper now accepts it (source=Notarized Developer ID).
notarize_pkg() {
    log_info "Notarizing ${FINAL_PKG} (profile '${NOTARY_PROFILE}') — this waits for Apple"
    if ! "${XCRUN}" notarytool submit "${FINAL_PKG}" --keychain-profile "${NOTARY_PROFILE}" --wait
    then
        log_error "Notarization failed — read the log: xcrun notarytool log <submission-id> --keychain-profile ${NOTARY_PROFILE}"
        exit 1
    fi
    "${XCRUN}" stapler staple "${FINAL_PKG}"
    "${XCRUN}" stapler validate "${FINAL_PKG}"
    if ! "${SPCTL}" --assess --type install "${FINAL_PKG}"
    then
        log_error "spctl still rejects ${FINAL_PKG} after stapling"
        exit 1
    fi
    log_info "Notarized + stapled: ${FINAL_PKG}"
}

##################################
### End User Defined Functions ###
##################################
###################################################################################
############## End Function Block #################################################
###################################################################################

###################################################################################
############## Begin Script Body ##################################################
###################################################################################

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (mode: ${MODE})"

case "${MODE}" in
    --emit-scripts)
        if [[ -z "${EMIT_DIR}" ]]
        then
            log_error "--emit-scripts requires a target directory"
            exit 1
        fi
        "${MKDIR}" -p "${SCRIPTS_DIR}" "${PAYLOAD_DIR}"
        write_uninstall_helper
        write_preinstall
        write_postinstall
        log_info "Scripts emitted to ${EMIT_DIR}"
        exit 0
        ;;
    --build)
        ;;
    *)
        log_error "Unknown mode: ${MODE} (expected --build or --emit-scripts <dir>)"
        exit 1
        ;;
esac

verify_inputs
"${RM}" -rf "${STAGING_DIR}"
"${MKDIR}" -p "${PAYLOAD_DIR}" "${SCRIPTS_DIR}"
build_app
stage_and_sign_app
write_uninstall_helper
write_preinstall
write_postinstall
build_pkg

log_info "Done."
log_info "  pkg:      ${FINAL_PKG}  (deploy this one)"
if [[ -n "${INSTALLER_IDENTITY}" ]]
then
    if [[ -z "${NOTARY_PROFILE}" ]]
    then
        log_warn "Signed (Developer ID Installer) but NOT notarized: a double-click on another Mac needs"
        log_warn "Privacy & Security → Open Anyway; 'sudo installer -pkg <pkg> -target /' and Jamf policy work."
        log_warn "To notarize next time: xcrun notarytool store-credentials serberus-notary --apple-id <id> --team-id ${TEAM_ID}"
        log_warn "then rerun with NOTARY_PROFILE=serberus-notary."
    fi
else
    log_warn "UNSIGNED pkg: a double-click AND 'sudo installer' can be refused by PackageKit on a managed Mac."
    log_warn "Set INSTALLER_IDENTITY to a Developer ID Installer identity to produce an installable pkg."
fi
log_info "Installs: ${APP_INSTALL_DIR}/${APP_NAME}"
log_info "Deploy via Jamf policy, or copy to the test Mac and install."
log_info "Teardown: sudo \"${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}\" [--purge]"

exit 0

###################################################################################
############## End Script Body ####################################################
###################################################################################
