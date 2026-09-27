#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-sentinel-app-pkg.sh
# Author: Heath Jones
# Date: 2026-08-20
# Modified: 2026-09-26
# Purpose: Build the TEST-RING Serberus Sentinel GUI PKG for Jamf policy
#          deployment. This PKG installs the GUI apps and their LaunchAgents
#          (no daemon/PAM — that is the separate combined/Agent pkg):
#            1. "Serberus Sentinel.app" — the FULL user-facing app (Dock +
#               its own App menu). Regular app, bundle …serberus.intel (it
#               reuses the retired standalone-Intel identity so its Intel tab
#               is a first-class read-only `.intel` XPC caller — NO daemon
#               change). Installs to /Applications.
#            2. "Serberus Sentinel Agent.app" — the menu bar app + audit-prompt
#               handler. LSUIElement, bundle …serberus.sentinel (the daemon's
#               `.sentinel` caller). Installs HIDDEN under
#               /Library/Application Support/Serberus so
#               /Applications shows only the one full app. The LaunchAgent
#               supervises it.
#            3. "Serberus Guardian.app" — invisible watchdog (bundle
#               …serberus.guardian), hidden under the same support dir, kept
#               up by its own KeepAlive LaunchAgent.
#          The apps are SEPARATE processes: quitting the full app leaves the
#          menu bar agent (and its prompts) running; launching the full app
#          starts the agent if it is not already up.
#            PAYLOAD     — /Applications/Serberus Sentinel.app (embeds the
#                          Finder Sync extension)
#                          /Library/Application Support/Serberus/Serberus Sentinel Agent.app
#                          /Library/Application Support/Serberus/Serberus Guardian.app
#                          /Library/LaunchAgents/com.herojoneslabs.serberus.sentinel.plist
#                          /Library/LaunchAgents/com.herojoneslabs.serberus.guardian.plist
#                          /Library/LaunchAgents/com.herojoneslabs.serberus.finderext-elect.plist
#                          uninstall helper under /Library/Application Support
#            PREINSTALL  — bootout the three LaunchAgents + quit the apps (upgrade)
#            POSTINSTALL — fix LaunchAgent ownership, bootstrap them into the
#                          console user's gui session (starts the agent and
#                          Guardian now), enable the Finder extension;
#                          no console user => they start at next login
#          Keeping the GUI in its OWN pkg lets the UI iterate on test machines
#          without re-touching the validated daemon/PAM install: both apps are
#          OUTSIDE the sudo safety chain (they render prompts and read state
#          over XPC; the daemon fails CLOSED without them), so every step here
#          is BEST-EFFORT — a GUI install must never abort and leave a machine
#          half-configured.
#          Signing: each app bundle is signed HERE, in staging outside any
#          cloud-synced folder (a sync provider can re-stamp
#          com.apple.FinderInfo continuously, which codesign rejects — same
#          reasoning as build-core-test-pkg.sh).
#          Test ring uses an Apple Development identity, which CANNOT carry the
#          custom is-ui-sentinel entitlement (no provisioning profile mints
#          it) — the daemon pkg therefore bakes
#          SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT=1, and the daemon still pins
#          bundle ID + Team ID + Hardened Runtime + designated requirement.
#          Production (notarized Developer ID) adds the entitlement back to the
#          AGENT via SENTINEL_WITH_ENTITLEMENT=1 (the full app never needs it —
#          the `.intel` caller requires no entitlement).
# Version: 2.6 - Generated postinstall: its first log line says where the
#          installer log is (/var/log/install.log). Generated uninstall
#          helper: --purge removes only the Sentinel's four per-user files,
#          then their folder if that leaves it empty (Commander's library in
#          it stays); safe_user_remove gains an rmdir mode for that.
#          2.5 - Generated uninstall helper: per-user purges find each
#          account through its record (dscl short name and home), not the
#          name of a folder under /Users.
#          2.4 - Generated scripts: per-user purges (--purge) run AS the
#          user (sudo -u) after the symlink/owner checks, never as root;
#          pkill patterns are anchored to the bundle path (^…, dots
#          escaped); require_boot_volume accepts an empty $3 only for a manual
#          run, not under Installer.
#          2.3 - (a) Every bundle in the payload is pinned
#          BundleIsRelocatable=false (pkgbuild --analyze component plist), so
#          PackageKit cannot "relocate" an app onto a copy LaunchServices knows
#          elsewhere. (b) LaunchAgents are booted out of — and bootstrapped
#          into — EVERY logged-in GUI session (loginwindow owners), not only
#          the console user's: Guardian is KeepAlive and respawned in the
#          sessions left behind. (c) Generated scripts: umask 022, an EXIT
#          trap that logs a failed run, and the pre/postinstall refuse a
#          target volume other than "/" ($3). (d) Absolute builder tool paths.
#          2.2 - Generated scripts: system-only PATH. The pre/postinstall
#          relaunch handshake moved from a fixed /private/tmp name (a user
#          could pre-plant a symlink root would follow) to a root-only
#          directory, /Library/Application Support/Serberus/.install-markers
#          (0700), checked for ! -L and owner 0 before use. The uninstall
#          helper's --purge refuses to delete through a symlinked or
#          foreign-owned home, Library, Application Support or Serberus
#          directory.
#          2.1 - Team ID comes from DEVELOPMENT_TEAM (environment or
#          Config/Local.xcconfig) via Support/team-id-lib.sh instead of
#          being hardcoded; required only when signing.
#          2.0 - pkg default 3.0: 2-APP SPLIT. The single Sentinel app is now
#          two distinct apps — full "Serberus Sentinel.app" (/Applications,
#          Dock+App menu, bundle …intel) and "SerberusSentinelAgent.app"
#          (hidden under /Library/Application Support, LSUIElement, bundle
#          …sentinel). This pkg ships BOTH. No daemon change (full app reuses
#          the …intel identity for the read-only Intel interface). Needs the
#          core daemon pkg (build-core-test-pkg.sh) for the daemon.
#          1.9 - pkg default 2.0: Serberus Intel embedded as the Sentinel
#          window's Intel tab; standalone SerberusIntel.app retired.
#          (Earlier history trimmed — see git log.)
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER, never sudo — codesign needs the signing
# chain in your login keychain):
#
#   SIGNING_IDENTITY=<Apple Development cert hash or name> ./PKG/build-sentinel-app-pkg.sh
#
# Optional env:
#   INSTALLER_IDENTITY        "Developer ID Installer: Your Name (YOURTEAMID)"
#                             — signs the .pkg (Jamf policy installs accept
#                             unsigned pkgs; PreStage/double-click do not)
#   FULLAPP_APP               path to a prebuilt Release SerberusSentinel.app
#   AGENT_APP                 path to a prebuilt Release SerberusSentinelAgent.app
#                             (either present => skips that xcodebuild)
#   PKG_VERSION               package version (default 3.10)
#   SERBERUS_DERIVED          derivedDataPath for the xcodebuild (default
#                             <repo>/.build/xcode; use a path outside any
#                             cloud-synced folder if the build sandbox trips
#                             on header copies)
#   SENTINEL_WITH_ENTITLEMENT 1 => sign the AGENT with
#                             Support/SerberusSentinel.entitlements (Developer
#                             ID identities only — an Apple Development identity
#                             is AMFI-killed with a custom entitlement and no
#                             provisioning profile). The full app is NEVER
#                             signed with it.
#
# Modes:
#   (default / --build)       build the pkg
#   --emit-scripts <dir>      write the generated pre/postinstall + uninstall
#                             helper to <dir> without building (bash -n checks)
#
# Deploy: upload the built pkg to Jamf, install via policy (scope alongside —
# or after — the combined daemon pkg). Teardown on the test machine:
#   sudo "/Library/Application Support/Serberus/uninstall-serberus-sentinel-app.sh" [--purge]

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
readonly PLUTIL="/usr/bin/plutil"
readonly PRODUCTSIGN="/usr/bin/productsign"
readonly RM="/bin/rm"
readonly XATTR="/usr/bin/xattr"
# The xcodebuild shim in /usr/bin resolves the selected Xcode.
readonly XCODEBUILD="/usr/bin/xcodebuild"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="2.6"
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

# ---- Full user-facing app: "Serberus Sentinel.app" (/Applications) ----
# Bundle …intel: it reuses the retired standalone-Intel identity so its Intel
# tab is a first-class read-only `.intel` XPC caller (no daemon change).
readonly FULLAPP_SCHEME="SerberusSentinel"
readonly FULLAPP_NAME="Serberus Sentinel.app"
readonly FULLAPP_BUNDLE_ID="${ORG_PLIST_DOMAIN}.intel"
readonly FULLAPP_INSTALL_DIR="/Applications"
# Pre-rename orphan: the single app (pre-split) and the interim no-space full
# app both lived here. The app now installs as "Serberus Sentinel.app" (a
# different path), so the old one is removed explicitly by pre/postinstall.
readonly FULLAPP_OLD_PATH="/Applications/SerberusSentinel.app"
# Stray FOLDER (not the app bundle): some earlier upgrades left the app nested
# inside "/Applications/Serberus Sentinel/" (a plain folder, no .app). The
# app bundle is "Serberus Sentinel.app"; this is the extension-less sibling.
# preinstall removes it only when it is clearly ours (see write_preinstall).
readonly FULLAPP_STRAY_DIR="${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME%.app}"
# Handshake between pre- and postinstall: the preinstall touches this when it
# kills a RUNNING full app, so the postinstall knows to relaunch it (swapping
# the visible binary on update). Absent on a fresh install → no window pops up.
# It lives in a ROOT-ONLY directory (0700): a fixed name in world-writable
# /private/tmp let any user pre-plant a symlink that root's `touch` followed.
readonly INSTALL_MARKER_DIR="${SUPPORT_DIR}/.install-markers"
readonly FULLAPP_RELAUNCH_MARKER="${INSTALL_MARKER_DIR}/fullapp-relaunch"
# Pre-2.2 marker location, removed if present (rm -f never follows a symlink).
readonly LEGACY_RELAUNCH_MARKER="/private/tmp/${ORG_PLIST_DOMAIN}.fullapp-relaunch"

# ---- Menu bar agent: "SerberusSentinelAgent.app" (hidden under Support) ----
# Bundle …sentinel: the daemon's `.sentinel` caller (prompts + state). Hidden
# so /Applications shows only the one full app. The LaunchAgent supervises it.
readonly AGENT_SCHEME="SerberusSentinelAgent"
readonly AGENT_NAME="Serberus Sentinel Agent.app"
readonly AGENT_BUNDLE_ID="${ORG_PLIST_DOMAIN}.sentinel"
readonly AGENT_INSTALL_DIR="${SUPPORT_DIR}"
# Pre-rename orphan: the menu bar app used to install as SerberusSentinelAgent.app
# at the same directory. Removed explicitly by pre/postinstall so the hidden
# support dir never keeps both.
readonly AGENT_OLD_PATH="${SUPPORT_DIR}/SerberusSentinelAgent.app"

# ---- LaunchAgent (launchd job) — ships verbatim from Support/ ----
readonly LAUNCHAGENT_LABEL="${ORG_PLIST_DOMAIN}.sentinel"
readonly LAUNCHAGENT_PLIST_NAME="${LAUNCHAGENT_LABEL}.plist"
readonly LAUNCHAGENT_PLIST_SRC="${REPO_DIR}/Support/${LAUNCHAGENT_PLIST_NAME}"
readonly LAUNCHAGENT_PLIST_INSTALL="/Library/LaunchAgents/${LAUNCHAGENT_PLIST_NAME}"

# ---- Guardian: "Serberus Guardian.app" (hidden under Support, invisible) ----
# Watches the Sentinel and shows a persistent "relaunch me" panel when the user
# quits it (gated by managed `guardianEnabled`). Its LaunchAgent uses
# KeepAlive=true so the watchdog itself can't be turned off.
readonly GUARDIAN_SCHEME="SerberusGuardian"
readonly GUARDIAN_NAME="Serberus Guardian.app"
readonly GUARDIAN_BUNDLE_ID="${ORG_PLIST_DOMAIN}.guardian"
readonly GUARDIAN_INSTALL_DIR="${SUPPORT_DIR}"
readonly GUARDIAN_LAUNCHAGENT_LABEL="${ORG_PLIST_DOMAIN}.guardian"
readonly GUARDIAN_LAUNCHAGENT_PLIST_NAME="${GUARDIAN_LAUNCHAGENT_LABEL}.plist"
readonly GUARDIAN_LAUNCHAGENT_PLIST_SRC="${REPO_DIR}/Support/${GUARDIAN_LAUNCHAGENT_PLIST_NAME}"
readonly GUARDIAN_LAUNCHAGENT_PLIST_INSTALL="/Library/LaunchAgents/${GUARDIAN_LAUNCHAGENT_PLIST_NAME}"

# ---- Finder-extension election LaunchAgent (per-user, run-once-at-login) ----
# Elects the Finder Sync extension for EVERY user (the postinstall pluginkit only
# covers the install-time console user). Runs `pluginkit -e use` at each login.
readonly ELECT_LAUNCHAGENT_LABEL="${ORG_PLIST_DOMAIN}.finderext-elect"
readonly ELECT_LAUNCHAGENT_PLIST_NAME="${ELECT_LAUNCHAGENT_LABEL}.plist"
readonly ELECT_LAUNCHAGENT_PLIST_SRC="${REPO_DIR}/Support/${ELECT_LAUNCHAGENT_PLIST_NAME}"
readonly ELECT_LAUNCHAGENT_PLIST_INSTALL="/Library/LaunchAgents/${ELECT_LAUNCHAGENT_PLIST_NAME}"
readonly FINDER_EXT_BUNDLE_ID="${ORG_PLIST_DOMAIN}.intel.finderext"

readonly UNINSTALL_HELPER_NAME="uninstall-serberus-sentinel-app.sh"

# Distinct identifier from the core test pkg (…serberus.sentineltestpkg),
# the daemon test pkg (…serberus.testpkg), the PAM test pkg
# (…serberus.pamtestpkg) and the production pkg (…serberus.pkg), so receipts
# never masquerade as any of them.
readonly PKG_IDENTIFIER="${ORG_PLIST_DOMAIN}.sentinelapptestpkg"
readonly PKG_VERSION="${PKG_VERSION:-3.10}"

readonly MODE="${1:---build}"
readonly EMIT_DIR="${2:-}"

# --emit-scripts redirects generated output into the caller's directory; a
# normal build works under PKG/build-test/sentinel-app — its OWN subdir of
# build-test, so `rm -rf` here can never clobber a sibling test pkg build.
if [[ "${MODE}" == "--emit-scripts" && -n "${EMIT_DIR}" ]]
then
    readonly BUILD_DIR="${EMIT_DIR}"
    readonly STAGING_DIR="${EMIT_DIR}"
else
    readonly BUILD_DIR="${SCRIPT_DIR}/build-test/sentinel-app"
    # Staged outside any cloud-synced folder: a sync provider can re-stamp
    # com.apple.FinderInfo within seconds of any `xattr -c`, codesign rejects
    # that xattr outright, and an .app bundle's signature seals its resource
    # tree — so it cannot be signed in such a folder. Same fix as
    # build-core-test-pkg.sh.
    readonly STAGING_DIR="${SERBERUS_PKG_STAGING:-${HOME}/Library/Caches/${ORG_PLIST_DOMAIN}/pkg-sentinel-app}"
fi
readonly PAYLOAD_DIR="${STAGING_DIR}/payload"
readonly SCRIPTS_DIR="${STAGING_DIR}/scripts"
readonly STAGED_FULLAPP="${PAYLOAD_DIR}${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME}"
readonly STAGED_AGENT="${PAYLOAD_DIR}${AGENT_INSTALL_DIR}/${AGENT_NAME}"
readonly STAGED_GUARDIAN="${PAYLOAD_DIR}${GUARDIAN_INSTALL_DIR}/${GUARDIAN_NAME}"
readonly OUTPUT_PKG="${BUILD_DIR}/SerberusSentinelApp-${PKG_VERSION}.pkg"
readonly SIGNED_PKG="${BUILD_DIR}/SerberusSentinelApp-${PKG_VERSION}-signed.pkg"
# pkgbuild --analyze output, edited so no bundle in the payload is relocatable.
readonly COMPONENT_PLIST="${STAGING_DIR}/component.plist"

# Build artifacts. Built by build_apps() unless *_APP points at a prebuilt one.
readonly DERIVED="${SERBERUS_DERIVED:-${REPO_DIR}/.build/xcode}"
readonly FULLAPP_BUILT="${FULLAPP_APP:-${DERIVED}/Build/Products/Release/${FULLAPP_NAME}}"
readonly AGENT_BUILT="${AGENT_APP:-${DERIVED}/Build/Products/Release/${AGENT_NAME}}"
readonly GUARDIAN_BUILT="${GUARDIAN_APP:-${DERIVED}/Build/Products/Release/${GUARDIAN_NAME}}"

# Signing inputs. SIGNING_IDENTITY is REQUIRED and must be a REAL identity:
# the daemon's XPCConnectionValidator pins Team ID + Hardened Runtime + the
# designated requirement, so an ad-hoc app can never register for prompts.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"
readonly SENTINEL_WITH_ENTITLEMENT="${SENTINEL_WITH_ENTITLEMENT:-0}"
readonly APP_ENTITLEMENTS="${REPO_DIR}/Support/SerberusSentinel.entitlements"
# The Finder Sync extension embedded in the full app. It must be re-signed
# INNER-FIRST with Developer ID + its OWN sandbox entitlements before the outer
# app is signed (the outer sign is deliberately NOT `--deep`, which would strip
# the appex's sandbox entitlements). Its bundle id is prefixed by the container's.
readonly FINDEREXT_ENTITLEMENTS="${REPO_DIR}/Support/SerberusFinderExtension.entitlements"
readonly APPEX_REL="Contents/PlugIns/SerberusFinderExtension.appex"
readonly APPEX_BUNDLE_ID="${FULLAPP_BUNDLE_ID}.finderext"

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
#   $1 short name, $2 home, $3 rm flag (-f or -rf) or rmdir (the target goes
#   only if it is an empty directory; one with anything left in it stays,
#   silently), $4… path components below the home
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
    if [[ "${flag}" == "rmdir" ]]
    then
        /usr/bin/sudo -n -u "${user}" /bin/rmdir -- "${path}" 2>/dev/null || true
        return 0
    fi
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

# Generated-script helpers shared by the pre/postinstall and the uninstall
# helper: the boot-volume guard, an EXIT trap that logs a failed run, and the
# list of every logged-in GUI session (loginwindow runs as each logged-in
# user; the login screen's runs as root). Literal (quoted heredoc).
GUI_FNS=$("${CAT}" <<'GUI_FNS_EOF'
# The GUI installs onto the running system only (Installer passes it as $3).
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

# Every uid with a logged-in GUI session (fast user switching included), plus
# the console user in case ps misses it. One uid per line.
gui_uids() {
    local console_user
    local console_uid=""
    console_user=$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && $3 != "loginwindow" { print $3 }')
    if [[ -n "${console_user}" ]]
    then
        console_uid=$(/usr/bin/id -u "${console_user}" 2>/dev/null || printf '')
    fi
    {
        /bin/ps -axo uid=,comm= 2>/dev/null | /usr/bin/awk '$2 ~ /\/loginwindow$/ && $1 > 0 { print $1 }'
        printf '%s\n' "${console_uid}"
    } | /usr/bin/awk '/^[0-9]+$/ && $1 > 0' | /usr/bin/sort -un
}
GUI_FNS_EOF
)
readonly GUI_FNS

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

# A `pkill -f` pattern that matches ONLY a process whose command line starts
# with <path> (anchored, dots escaped), so root never signals an unrelated
# process that merely mentions the path in its arguments.
#   $1 absolute path prefix (…/Contents/MacOS/)
pkill_pattern() {
    local path="$1"
    printf '^%s' "${path//./\\.}"
}

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
        log_error "SIGNING_IDENTITY is required and must be a REAL identity — the daemon"
        log_error "pins Team ID + Hardened Runtime, so an ad-hoc agent can never register."
        log_error "  security find-identity -v -p codesigning   # list identities"
        log_error "  SIGNING_IDENTITY=<hash> ./PKG/${SCRIPT_NAME}"
        exit 1
    fi

    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        log_warn "INSTALLER_IDENTITY unset — the installer pkg will be UNSIGNED."
        log_warn "Jamf policy installs accept unsigned pkgs; set INSTALLER_IDENTITY to sign."
    fi

    if [[ "${SENTINEL_WITH_ENTITLEMENT}" == "1" && ! -f "${APP_ENTITLEMENTS}" ]]
    then
        log_error "SENTINEL_WITH_ENTITLEMENT=1 but ${APP_ENTITLEMENTS} is missing."
        exit 1
    fi

    if [[ ! -f "${LAUNCHAGENT_PLIST_SRC}" ]]
    then
        log_error "Missing ${LAUNCHAGENT_PLIST_SRC} — the LaunchAgent ships inside the pkg payload."
        exit 1
    fi

    if [[ ! -f "${GUARDIAN_LAUNCHAGENT_PLIST_SRC}" ]]
    then
        log_error "Missing ${GUARDIAN_LAUNCHAGENT_PLIST_SRC} — the Guardian LaunchAgent ships inside the pkg payload."
        exit 1
    fi

    if [[ ! -f "${ELECT_LAUNCHAGENT_PLIST_SRC}" ]]
    then
        log_error "Missing ${ELECT_LAUNCHAGENT_PLIST_SRC} — the Finder-extension election LaunchAgent ships in the payload."
        exit 1
    fi
}

# Release-build one app scheme unless a prebuilt override is supplied.
# $1 scheme, $2 built-path, $3 override-value ("" => build)
build_one() {
    local scheme="$1" built="$2" override="$3"
    if [[ -n "${override}" ]]
    then
        log_info "Using prebuilt ${scheme}: ${built}"
    else
        log_info "Building ${scheme} (Release, signing deferred to staging)"
        "${XCODEBUILD}" \
            -project "${REPO_DIR}/Serberus.xcodeproj" \
            -scheme "${scheme}" \
            -configuration Release \
            -derivedDataPath "${DERIVED}" \
            CODE_SIGNING_ALLOWED=NO \
            build >/dev/null
    fi
    if [[ ! -d "${built}" ]]
    then
        log_error "App bundle not found: ${built}"
        exit 1
    fi
}

build_apps() {
    build_one "${FULLAPP_SCHEME}" "${FULLAPP_BUILT}" "${FULLAPP_APP:-}"
    build_one "${AGENT_SCHEME}" "${AGENT_BUILT}" "${AGENT_APP:-}"
    build_one "${GUARDIAN_SCHEME}" "${GUARDIAN_BUILT}" "${GUARDIAN_APP:-}"
}

# Copy one app into staging (outside cloud-synced folders), strip detritus, verify bundle ID,
# sign, verify. $1 built-src, $2 staged-dst, $3 expected-bundle-id,
# $4 with-entitlement (0/1).
stage_and_sign_one() {
    local built="$1" staged="$2" expected_id="$3" with_entitlement="$4"
    # $5 (optional): path to a nested app-extension's entitlements. When set, the
    # embedded Finder Sync .appex is signed INNER-FIRST (Developer ID + those
    # sandbox entitlements) before the outer app, so the non-`--deep` outer sign
    # seals over an already-valid, correctly-entitled extension.
    local nested_ent="${5:-}"
    "${MKDIR}" -p "$("${DIRNAME}" "${staged}")"
    "${RM}" -rf "${staged}"
    "${CP}" -R "${built}" "${staged}"
    "${CHMOD}" -R u+w "${staged}"
    "${XATTR}" -rc "${staged}"

    # Inner-first: sign the embedded Finder Sync extension with its own sandbox
    # entitlements BEFORE the outer app (the outer sign is not `--deep`).
    if [[ -n "${nested_ent}" ]]
    then
        local appex="${staged}/${APPEX_REL}"
        if [[ ! -d "${appex}" ]]
        then
            log_error "Expected embedded extension missing: ${appex}"
            exit 1
        fi
        if [[ ! -f "${nested_ent}" ]]
        then
            log_error "Finder-extension entitlements missing: ${nested_ent}"
            exit 1
        fi
        log_info "Signing embedded $("${BASENAME}" "${appex}") INNER-FIRST (Developer ID + sandbox entitlements)"
        # --timestamp: a secure timestamp is required for notarization (and is
        # harmless otherwise) — matches build-commander-pkg.sh. Without it, both
        # the appex and the outer app are rejected by notarytool.
        "${CODESIGN}" --force --options runtime --timestamp --sign "${SIGNING_IDENTITY}" \
            --entitlements "${nested_ent}" "${appex}"
        if ! "${CODESIGN}" --verify --strict "${appex}"
        then
            log_error "Signature verification failed for embedded ${appex}"
            exit 1
        fi
    fi

    # The daemon's validator matches on the bundle identifier — fail the build
    # here rather than debugging a silent XPC rejection on the test machine.
    local built_id
    built_id=$("${PLIST_BUDDY}" -c 'Print :CFBundleIdentifier' "${staged}/Contents/Info.plist")
    if [[ "${built_id}" != "${expected_id}" ]]
    then
        log_error "Bundle identifier mismatch: built '${built_id}', expected '${expected_id}'"
        exit 1
    fi

    local -a sign_args=(--force --options runtime --timestamp --sign "${SIGNING_IDENTITY}")
    if [[ "${with_entitlement}" == "1" ]]
    then
        log_info "Signing $("${BASENAME}" "${staged}") WITH the is-ui-sentinel entitlement (Developer ID ring)"
        sign_args+=(--entitlements "${APP_ENTITLEMENTS}")
    fi
    log_info "Signing $("${BASENAME}" "${staged}") with '${SIGNING_IDENTITY}'"
    "${CODESIGN}" "${sign_args[@]}" "${staged}"

    if ! "${CODESIGN}" --verify --strict "${staged}"
    then
        log_error "Signature verification failed for ${staged} (stray xattr?)"
        exit 1
    fi

    # The validator's designated requirement pins the Team ID — verify the
    # signature actually carries it (an ad-hoc or wrong-team cert would pass
    # --verify --strict but be rejected on-device). Capture first, then grep:
    # piping codesign straight into `grep -q` under pipefail intermittently
    # fails on SIGPIPE (grep exits at first match; codesign dies 141).
    local sign_info
    if [[ -z "${TEAM_ID}" ]]
    then
        log_error "No Apple Developer Team ID configured. Set DEVELOPMENT_TEAM in"
        log_error "Config/Local.xcconfig (copy Config/Local.xcconfig.example) or the environment."
        exit 1
    fi
    sign_info=$("${CODESIGN}" -dv "${staged}" 2>&1)
    if ! "${GREP}" -q "TeamIdentifier=${TEAM_ID}" <<< "${sign_info}"
    then
        log_error "Signature does not carry TeamIdentifier=${TEAM_ID} — the daemon will reject it."
        exit 1
    fi
}

stage_and_sign_apps() {
    # Full app: NEVER the is-ui-sentinel entitlement (the `.intel` caller
    # requires none). It embeds the Finder Sync extension, which is re-signed
    # inner-first with its OWN sandbox entitlements (5th arg).
    stage_and_sign_one "${FULLAPP_BUILT}" "${STAGED_FULLAPP}" "${FULLAPP_BUNDLE_ID}" "0" "${FINDEREXT_ENTITLEMENTS}"
    # Menu bar agent: optionally the entitlement (Developer ID ring).
    stage_and_sign_one "${AGENT_BUILT}" "${STAGED_AGENT}" "${AGENT_BUNDLE_ID}" "${SENTINEL_WITH_ENTITLEMENT}"
    # Guardian: no entitlement, no nested extension — just Developer ID + hardened.
    stage_and_sign_one "${GUARDIAN_BUILT}" "${STAGED_GUARDIAN}" "${GUARDIAN_BUNDLE_ID}" "0"
}

# Stages one LaunchAgent plist into the payload with a plutil lint and a
# ProgramArguments path assertion (the plist must exec the app at its install
# path — a stale path would make launchd exec a binary the pkg no longer puts
# there). $1 src, $2 filename, $3 expected exec-path prefix.
stage_one_launch_agent() {
    local src="$1" name="$2" expected_exec_prefix="$3"
    "${CP}" "${src}" "${PAYLOAD_DIR}/Library/LaunchAgents/${name}"
    "${XATTR}" -c "${PAYLOAD_DIR}/Library/LaunchAgents/${name}"
    if ! "${PLUTIL}" -lint "${PAYLOAD_DIR}/Library/LaunchAgents/${name}" >/dev/null
    then
        log_error "LaunchAgent failed plutil -lint: ${src}"
        exit 1
    fi
    if ! "${GREP}" -qF "${expected_exec_prefix}" "${PAYLOAD_DIR}/Library/LaunchAgents/${name}"
    then
        log_error "LaunchAgent ${name} ProgramArguments does not point at ${expected_exec_prefix}."
        log_error "Update ${src} to exec the binary at its hidden install path."
        exit 1
    fi
}

# Both LaunchAgents (Sentinel + Guardian) ship verbatim from Support/ (root:wheel
# 644 fixed by postinstall; pkgbuild ownership handles the payload copy).
stage_launch_agent() {
    "${MKDIR}" -p "${PAYLOAD_DIR}/Library/LaunchAgents"
    stage_one_launch_agent "${LAUNCHAGENT_PLIST_SRC}" "${LAUNCHAGENT_PLIST_NAME}" \
        "${AGENT_INSTALL_DIR}/${AGENT_NAME}/Contents/MacOS/"
    stage_one_launch_agent "${GUARDIAN_LAUNCHAGENT_PLIST_SRC}" "${GUARDIAN_LAUNCHAGENT_PLIST_NAME}" \
        "${GUARDIAN_INSTALL_DIR}/${GUARDIAN_NAME}/Contents/MacOS/"
    # The election agent runs pluginkit (not an app) — assert on the extension id.
    stage_one_launch_agent "${ELECT_LAUNCHAGENT_PLIST_SRC}" "${ELECT_LAUNCHAGENT_PLIST_NAME}" \
        "${FINDER_EXT_BUNDLE_ID}"
}

# Uninstall helper, shipped in the payload so teardown never depends on
# having the repo. Single-quoted delimiter except where build-time constants
# must bake in — those are interpolated via the unquoted sections below.
write_uninstall_helper() {
    local helper_dir="${PAYLOAD_DIR}${SUPPORT_DIR}"
    "${MKDIR}" -p "${helper_dir}"

    "${CAT}" > "${helper_dir}/${UNINSTALL_HELPER_NAME}" <<UNINSTALL_HELPER_EOF
#! /bin/bash
# Serberus Sentinel GUI teardown (test ring). Run as root:
#   sudo "${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}" [--purge]
# Removes the GUI apps (full app, menu bar agent, Guardian), their
# LaunchAgents — booted out of EVERY logged-in GUI session — and the pkg
# receipt. --purge also removes the Sentinel's own files from each user's
# ~/Library/Application Support/Serberus (rules-cache.json,
# elevation-history.json, pending-route, jamf-uploads.json), then that folder
# only if it is left empty: Commander's policies.json and capture-reviews.json
# live there too and are never touched. The daemon pkg (and the rest of
# ${SUPPORT_DIR}) is untouched.
# Generated by build-sentinel-app-pkg.sh ${SCRIPT_VERSION} (2026-09-26).
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

${SAFE_USER_REMOVE_FN}

# The Sentinel's own per-user files (SentinelRulesStore,
# ElevationHistoryStore, SentinelRouteHandoff, JamfUploadLedger), then their
# folder only if that leaves it empty: Commander keeps its policy library in
# the same folder, and this helper never removes it. Every step goes through
# safe_user_remove.
#   \$1 short name, \$2 home (both from the account record)
purge_sentinel_files() {
    local user_name="\$1"
    local user_home="\$2"
    local file
    for file in \\
        "rules-cache.json" \\
        "elevation-history.json" \\
        "pending-route" \\
        "jamf-uploads.json"
    do
        safe_user_remove "\${user_name}" "\${user_home}" -f "Library" "Application Support" "Serberus" "\${file}"
    done
    safe_user_remove "\${user_name}" "\${user_home}" rmdir "Library" "Application Support" "Serberus"
}

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

# Boot the LaunchAgents out of EVERY logged-in GUI session (Guardian is
# KeepAlive and respawns in any session left behind), then quit the apps.
while IFS= read -r gui_uid
do
    /bin/launchctl bootout "gui/\${gui_uid}/${LAUNCHAGENT_LABEL}" 2>/dev/null || true
    /bin/launchctl bootout "gui/\${gui_uid}/${GUARDIAN_LAUNCHAGENT_LABEL}" 2>/dev/null || true
    /bin/launchctl bootout "gui/\${gui_uid}/${ELECT_LAUNCHAGENT_LABEL}" 2>/dev/null || true
done < <(gui_uids)
for macos in \\
    "${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME}/Contents/MacOS/" \\
    "${FULLAPP_OLD_PATH}/Contents/MacOS/" \\
    "${AGENT_INSTALL_DIR}/${AGENT_NAME}/Contents/MacOS/" \\
    "${AGENT_OLD_PATH}/Contents/MacOS/" \\
    "${GUARDIAN_INSTALL_DIR}/${GUARDIAN_NAME}/Contents/MacOS/"
do
    /usr/bin/pkill -f "^\${macos//./\\\\.}" 2>/dev/null || true
done

/bin/rm -f "${LAUNCHAGENT_PLIST_INSTALL}"
/bin/rm -f "${GUARDIAN_LAUNCHAGENT_PLIST_INSTALL}"
/bin/rm -f "${ELECT_LAUNCHAGENT_PLIST_INSTALL}"
/bin/rm -rf "${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME}"
/bin/rm -rf "${FULLAPP_OLD_PATH}"
/bin/rm -rf "${AGENT_INSTALL_DIR}/${AGENT_NAME}"
/bin/rm -rf "${AGENT_OLD_PATH}"
/bin/rm -rf "${GUARDIAN_INSTALL_DIR}/${GUARDIAN_NAME}"
# Stray "/Applications/Serberus Sentinel" folder (see preinstall) — same safe
# guard: only delete when it holds a Serberus .app or is empty.
if [[ -d "${FULLAPP_STRAY_DIR}" ]]
then
    if [[ -d "${FULLAPP_STRAY_DIR}/SerberusSentinel.app" || -d "${FULLAPP_STRAY_DIR}/${FULLAPP_NAME}" ]]
    then
        /bin/rm -rf "${FULLAPP_STRAY_DIR}"
    else
        /bin/rmdir "${FULLAPP_STRAY_DIR}" 2>/dev/null || true
    fi
fi
/usr/sbin/pkgutil --forget "${PKG_IDENTIFIER}" 2>/dev/null || true
/bin/rm -f "${FULLAPP_RELAUNCH_MARKER}" "${LEGACY_RELAUNCH_MARKER}" 2>/dev/null || true

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
        purge_sentinel_files "\${user_name}" "\${user_home}"
    done < <(/usr/bin/dscl . -list /Users NFSHomeDirectory 2>/dev/null)
fi

printf '[INFO] Serberus Sentinel GUI (both apps) removed.\n'
exit 0
UNINSTALL_HELPER_EOF

    "${CHMOD}" 755 "${helper_dir}/${UNINSTALL_HELPER_NAME}"

    if ! "${BASH_BIN}" -n "${helper_dir}/${UNINSTALL_HELPER_NAME}"
    then
        log_error "Generated uninstall helper failed bash -n"
        exit 1
    fi
}

# Preinstall: stop the running agent and both apps so the payload copy is clean
# (upgrade path). Everything best-effort — never fail a GUI app install.
write_preinstall() {
    "${CAT}" > "${SCRIPTS_DIR}/preinstall" <<PREINSTALL_EOF
#! /bin/bash
# SerberusSentinelApp-test preinstall — stop the running agents + apps before
# the payload lands. Best-effort by design: the GUI is outside the sudo safety
# chain, so nothing here may abort the install (except installing onto a
# volume other than the running system, which is refused).
# Generated by build-sentinel-app-pkg.sh ${SCRIPT_VERSION} (2026-09-26).
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

SUPPORT_DIR="${SUPPORT_DIR}"
MARKER_DIR="${INSTALL_MARKER_DIR}"
MARKER="${FULLAPP_RELAUNCH_MARKER}"
TARGET_VOLUME="\${3:-}"
${MARKER_FNS}

${GUI_FNS}
trap on_exit EXIT
require_boot_volume

# Boot the LaunchAgents out of EVERY logged-in GUI session. Guardian: BEFORE
# the payload swap — its KeepAlive=true would otherwise instantly relaunch a
# stale binary mid-install, in whichever session still had it.
while IFS= read -r gui_uid
do
    /bin/launchctl bootout "gui/\${gui_uid}/${LAUNCHAGENT_LABEL}" 2>/dev/null || true
    /bin/launchctl bootout "gui/\${gui_uid}/${GUARDIAN_LAUNCHAGENT_LABEL}" 2>/dev/null || true
    /bin/launchctl bootout "gui/\${gui_uid}/${ELECT_LAUNCHAGENT_LABEL}" 2>/dev/null || true
done < <(gui_uids)

# Stop the GUI apps by BUNDLE PATH (pkill -f), not process name: the full app's
# executable "Serberus Sentinel" is 17 chars and \`pgrep -x\` truncates the
# accounting name at 16. Includes the pre-rename path so an old app is stopped
# too. pkill -f returns 0 only if it matched something.
killed="0"
fullapp_running="0"
# Full app first — track whether it was RUNNING so the postinstall can relaunch
# it (only) if so, swapping the visible binary on update.
for macos in \\
    "${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME}/Contents/MacOS/" \\
    "${FULLAPP_OLD_PATH}/Contents/MacOS/"
do
    if /usr/bin/pkill -f "^\${macos//./\\\\.}" 2>/dev/null
    then
        killed="1"
        fullapp_running="1"
    fi
done
# Agent — always relaunched by the LaunchAgent bootstrap, so no marker needed.
for macos in \\
    "${AGENT_INSTALL_DIR}/${AGENT_NAME}/Contents/MacOS/" \\
    "${AGENT_OLD_PATH}/Contents/MacOS/"
do
    if /usr/bin/pkill -f "^\${macos//./\\\\.}" 2>/dev/null
    then
        killed="1"
    fi
done
# Guardian — stop the old process too (its job was booted out above so it won't
# relaunch); the postinstall bootstraps the fresh one.
if /usr/bin/pkill -f "$(pkill_pattern "${GUARDIAN_INSTALL_DIR}/${GUARDIAN_NAME}/Contents/MacOS/")" 2>/dev/null
then
    killed="1"
fi
/bin/rm -f "\${MARKER}" "${LEGACY_RELAUNCH_MARKER}" 2>/dev/null || true
if [[ "\${fullapp_running}" == "1" ]] && prepare_marker_dir
then
    /usr/bin/touch "\${MARKER}" 2>/dev/null || true
fi
if [[ "\${killed}" == "1" ]]
then
    /bin/sleep 1
fi

# Remove the pre-rename orphans so /Applications (and the hidden support dir)
# never keep both the old no-space bundles and the new spaced ones.
/bin/rm -rf "${FULLAPP_OLD_PATH}"
/bin/rm -rf "${AGENT_OLD_PATH}"

# Remove a stray "/Applications/Serberus Sentinel" FOLDER (extension-less
# sibling of the "Serberus Sentinel.app" bundle) that some earlier upgrades
# left behind with the app nested inside it. SAFE by construction: only delete
# it when it is identifiably ours — it holds a Serberus .app, or it is empty
# (\`rmdir\` refuses a non-empty dir) — so a same-named folder a user created
# for unrelated files is never touched.
stray="${FULLAPP_STRAY_DIR}"
if [[ -d "\${stray}" ]]
then
    /usr/bin/pkill -f "^\${stray//./\\\\.}/" 2>/dev/null || true
    if [[ -d "\${stray}/SerberusSentinel.app" || -d "\${stray}/${FULLAPP_NAME}" ]]
    then
        /bin/rm -rf "\${stray}"
    elif ! /bin/rmdir "\${stray}" 2>/dev/null
    then
        printf '[WARN] %s exists but is not a Serberus stray (has other contents); left in place.\\n' "\${stray}"
    fi
fi

exit 0
PREINSTALL_EOF

    "${CHMOD}" 755 "${SCRIPTS_DIR}/preinstall"

    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/preinstall"
    then
        log_error "Generated preinstall failed bash -n"
        exit 1
    fi
}

# Postinstall: fix LaunchAgent ownership, then start the agent in the console
# user's session. No console user => RunAtLoad starts it at next login. The
# full app is NOT auto-launched — it is user-launched (and starts the agent
# itself if needed).
write_postinstall() {
    "${CAT}" > "${SCRIPTS_DIR}/postinstall" <<POSTINSTALL_EOF
#! /bin/bash
# SerberusSentinelApp-test postinstall — ownership + LaunchAgent bootstrap in
# every logged-in GUI session. Best-effort by design (see preinstall); a
# failed bootstrap only defers the agents to the next login.
# Generated by build-sentinel-app-pkg.sh ${SCRIPT_VERSION} (2026-09-26).
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

SUPPORT_DIR="${SUPPORT_DIR}"
MARKER_DIR="${INSTALL_MARKER_DIR}"
MARKER="${FULLAPP_RELAUNCH_MARKER}"
TARGET_VOLUME="\${3:-}"
${MARKER_FNS}

${GUI_FNS}
trap on_exit EXIT
require_boot_volume
printf '[INFO] postinstall starting (installer log: /var/log/install.log)\n'

/usr/sbin/chown root:wheel "${LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null || true
/bin/chmod 644 "${LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null || true
/usr/sbin/chown root:wheel "${GUARDIAN_LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null || true
/bin/chmod 644 "${GUARDIAN_LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null || true
/usr/sbin/chown root:wheel "${ELECT_LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null || true
/bin/chmod 644 "${ELECT_LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null || true

# The console user (may be empty at the login window) gets the per-user
# extras below; the LaunchAgents go into every logged-in GUI session.
console_uid=""
console_user=\$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && \$3 != "loginwindow" { print \$3 }')
if [[ -n "\${console_user}" ]]
then
    console_uid=\$(/usr/bin/id -u "\${console_user}" 2>/dev/null || printf '')
fi

# The LaunchAgents go into EVERY logged-in GUI session (the preinstall booted
# them out of all of them). The console user's agent falls back to a direct
# launch when its bootstrap fails.
while IFS= read -r gui_uid
do
    /bin/launchctl bootout "gui/\${gui_uid}/${LAUNCHAGENT_LABEL}" 2>/dev/null || true
    if ! /bin/launchctl bootstrap "gui/\${gui_uid}" "${LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null
    then
        printf '[WARN] launchctl bootstrap of the agent failed for uid %s.\n' "\${gui_uid}"
        if [[ "\${gui_uid}" == "\${console_uid}" ]]
        then
            /bin/launchctl asuser "\${console_uid}" /usr/bin/open "${AGENT_INSTALL_DIR}/${AGENT_NAME}" 2>/dev/null || true
        fi
    fi

    # Guardian: bootstrap the fresh job (RunAtLoad starts it; KeepAlive keeps it up).
    /bin/launchctl bootout "gui/\${gui_uid}/${GUARDIAN_LAUNCHAGENT_LABEL}" 2>/dev/null || true
    if ! /bin/launchctl bootstrap "gui/\${gui_uid}" "${GUARDIAN_LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null
    then
        printf '[WARN] Guardian launchctl bootstrap failed for uid %s; it starts at next login.\n' "\${gui_uid}"
    fi

    # Finder-extension election agent (RunAtLoad runs pluginkit now for this
    # session's user; it also re-elects at every user's future login).
    /bin/launchctl bootout "gui/\${gui_uid}/${ELECT_LAUNCHAGENT_LABEL}" 2>/dev/null || true
    if ! /bin/launchctl bootstrap "gui/\${gui_uid}" "${ELECT_LAUNCHAGENT_PLIST_INSTALL}" 2>/dev/null
    then
        printf '[WARN] Finder-extension election agent bootstrap failed for uid %s; runs at next login.\n' "\${gui_uid}"
    fi
done < <(gui_uids)

if [[ -z "\${console_uid}" ]]
then
    printf '[INFO] No console user; the per-user Finder extension election runs at next login.\n'
    exit 0
fi

# Index the agent's two Finder Services (Install/Uninstall with Serberus). The
# agent lives under /Library/Application Support, a location LaunchServices does
# NOT auto-scan, so register the bundle explicitly — otherwise the right-click
# actions never appear even though the agent is running. (The agent's own
# NSUpdateDynamicServices() on launch then rebuilds the per-user Services menu;
# the declaration itself now carries NSRequiredContext + NSSendTypes so pbs
# actually presents them.) Best-effort: a miss only defers Services to re-login.
lsregister="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"
if [[ -x "\${lsregister}" ]]
then
    "\${lsregister}" -f "${AGENT_INSTALL_DIR}/${AGENT_NAME}" 2>/dev/null || true
fi

# Enable the Finder Sync extension for the console user — the TOP-LEVEL
# "Install/Uninstall with Serberus" right-click items (with the Sentinel icon).
# A Finder extension is OFF by default and pluginkit is the ONLY lever (the GUI
# toggle was removed and no MDM key enables it), so this must run in the console
# user's context (root would be a silent no-op). The appex rides inside the
# /Applications app (LS auto-scans it), so discovery is automatic. Best-effort:
# a miss defers to the next login. NOTE: this election covers the user logged in
# AT install time; other users get it at their next login via LaunchServices +
# a re-run (the extension id is ${APPEX_BUNDLE_ID}).
appex_path="${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME}/${APPEX_REL}"
/bin/launchctl asuser "\${console_uid}" /usr/bin/pluginkit -a "\${appex_path}" 2>/dev/null || true
/bin/launchctl asuser "\${console_uid}" /usr/bin/pluginkit -e use -i "${APPEX_BUNDLE_ID}" 2>/dev/null || true
# Reload Finder so the newly-enabled extension's menu items appear without a
# re-login (Finder relaunches immediately).
/bin/launchctl asuser "\${console_uid}" /usr/bin/killall -q Finder 2>/dev/null || true

# Relaunch the FULL app only if it was running when this update started (marker
# written by the preinstall) — so an update swaps the visible binary instead of
# leaving the old process on screen. Opened by explicit path (never a stale
# duplicate). A fresh install has no marker, so no window pops up unbidden.
# Only a root-owned marker in the root-only directory counts.
if marker_is_trusted
then
    /bin/rm -f "\${MARKER}"
    /bin/launchctl asuser "\${console_uid}" /usr/bin/open "${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME}" 2>/dev/null || true
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

# pkgbuild's default lets PackageKit "relocate" an app onto ANY copy of it
# LaunchServices already knows about (a dev build in a working copy, a copy on
# the Desktop…) instead of the payload path. Pin every bundle pkgbuild
# --analyze finds to BundleIsRelocatable=false (same approach as
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
    "${RM}" -f "${OUTPUT_PKG}" "${SIGNED_PKG}"

    write_component_plist
    log_info "Building ${OUTPUT_PKG}"
    "${PKGBUILD}" \
        --root "${PAYLOAD_DIR}" \
        --component-plist "${COMPONENT_PLIST}" \
        --scripts "${SCRIPTS_DIR}" \
        --identifier "${PKG_IDENTIFIER}" \
        --version "${PKG_VERSION}" \
        --install-location "/" \
        "${OUTPUT_PKG}"

    if [[ -n "${INSTALLER_IDENTITY}" ]]
    then
        log_info "Signing pkg with '${INSTALLER_IDENTITY}'"
        "${PRODUCTSIGN}" --sign "${INSTALLER_IDENTITY}" "${OUTPUT_PKG}" "${SIGNED_PKG}"
        log_info "Signed pkg: ${SIGNED_PKG}"
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

build_apps
stage_and_sign_apps
stage_launch_agent
write_uninstall_helper
write_preinstall
write_postinstall
build_pkg

log_info "Done."
log_info "  pkg:      ${OUTPUT_PKG}"
if [[ -n "${INSTALLER_IDENTITY}" ]]
then
    log_info "  signed:   ${SIGNED_PKG}"
fi
log_info "Installs: ${FULLAPP_INSTALL_DIR}/${FULLAPP_NAME}  +  ${AGENT_INSTALL_DIR}/${AGENT_NAME}"
log_info "Deploy via Jamf policy alongside the combined daemon pkg."
log_info "Teardown: sudo \"${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}\" [--purge]"

###########################################################
################## End Script Block #######################
###########################################################
