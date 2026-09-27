#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-authuribrowser-pkg.sh
# Author: Heath Jones
# Date: 2026-09-04
# Modified: 2026-09-25
# Purpose: Build the installer PKG for "Auth URI Browser.app" — the
#          standalone authorization-rights browser under extras/AuthURIBrowser/.
#          It is a read-only diagnostic tool with no daemon, PAM, or XPC
#          footprint, so the install is a plain app drop:
#            PAYLOAD     — /Applications/Auth URI Browser.app
#            PREINSTALL  — quit a running copy so the bundle can be swapped
#            POSTINSTALL — register the bundle with LaunchServices
#          Signing: the app is built ad-hoc by extras/AuthURIBrowser/Scripts/
#          package_app.sh into a scratch path outside any cloud-synced folder
#          (a sync provider can re-stamp com.apple.FinderInfo, which codesign
#          rejects — same reasoning as build-commander-pkg.sh), then copied
#          to staging and signed: ad-hoc by default (test ring), Developer ID
#          + hardened runtime when SIGNING_IDENTITY is set. The pkg is UNSIGNED by
#          default; productsigned when INSTALLER_IDENTITY is set and
#          notarized when NOTARY_PROFILE is.
# Version: 1.6 - (a) APP_SCRATCH defaults to a per-user cache directory
#          (~/Library/Caches/com.herojoneslabs/authuribrowser-build), not a
#          fixed path in world-writable /tmp another user could pre-create.
#          (b) --build | --emit-scripts <dir> argument handling like the other
#          builders; anything else is a usage error instead of a build.
#          (c) Generated scripts: an empty target volume is accepted only
#          outside Installer; pkill patterns are anchored to the bundle path.
#          1.5 - Absolute tool paths (no PATH lookup; xcrun through
#          /usr/bin); generated pre/postinstall set umask 022 and refuse a
#          target volume other than "/" ($3); neutral wording about where the
#          working copy lives.
#          1.4 - (a) The app build path agrees with package_app.sh: that
#          script reads SCRATCH, this one read an APP_SCRATCH it never passed
#          on, so a custom scratch path built in one place and packaged from
#          another. APP_SCRATCH (or SCRATCH) is now resolved once and handed
#          to package_app.sh as SCRATCH. (b) Generated pre/postinstall use a
#          system-only PATH. (c) Usage text states the real default version.
#          1.3 - Team ID comes from DEVELOPMENT_TEAM (environment or
#          Config/Local.xcconfig) via Support/team-id-lib.sh instead of
#          being hardcoded; required only when signing with an identity.
#          1.2 - BundleIsRelocatable=false via component plist: PackageKit was
#                relocating the install onto a dev build in the working copy
#                (registered by LaunchServices) and failing. pkg 1.1
#          1.1 - Unsigned pkg + ad-hoc app by default (test ring); app is
#                assembled in the SwiftPM scratch path outside cloud-synced
#                folders
#          1.0 - Initial Script (pkg default 1.0)
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER, never sudo):
#
#   ./PKG/build-authuribrowser-pkg.sh          # ad-hoc app, UNSIGNED pkg (test ring)
#   ./PKG/build-authuribrowser-pkg.sh --emit-scripts <dir>   # write the scripts only (tests)
#
# Optional env:
#   SIGNING_IDENTITY   "Developer ID Application: Your Name (YOURTEAMID)"
#                      — signs the app with hardened runtime (ad-hoc otherwise)
#   INSTALLER_IDENTITY "Developer ID Installer: Your Name (YOURTEAMID)"
#                      — productsigns the pkg (unsigned otherwise)
#   NOTARY_PROFILE   notarytool keychain profile — submits, waits, staples.
#                    Without it a double-clicked pkg needs Privacy & Security
#                    → "Open Anyway", or install with
#                    sudo installer -pkg <pkg> -target /
#   PKG_VERSION      package version (default 1.1)
#   APP_SCRATCH      where package_app.sh assembles the app (default
#                    $SCRATCH, else ~/Library/Caches/com.herojoneslabs/
#                    authuribrowser-build; keep it outside any cloud-synced
#                    folder and out of shared directories such as /tmp)
#
# Teardown:  sudo rm -rf "/Applications/Auth URI Browser.app"
#            sudo pkgutil --forget com.herojoneslabs.authuribrowserpkg

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
readonly ENV="/usr/bin/env"
readonly FIND="/usr/bin/find"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly MKDIR="/bin/mkdir"
readonly PKGBUILD="/usr/bin/pkgbuild"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly PRODUCTSIGN="/usr/bin/productsign"
readonly RM="/bin/rm"
readonly SPCTL="/usr/sbin/spctl"
readonly XATTR="/usr/bin/xattr"
# xcrun (the /usr/bin shim) finds notarytool and stapler in the selected Xcode.
readonly XCRUN="/usr/bin/xcrun"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

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

readonly ORG_DOMAIN="com.herojoneslabs"
# The Apple Developer Team ID a signed app must carry, from DEVELOPMENT_TEAM
# in the environment or Config/Local.xcconfig. Resolved here but only
# required when signing with an identity (ad-hoc builds don't need one).
# shellcheck source=../Support/team-id-lib.sh
source "${REPO_DIR}/Support/team-id-lib.sh"
TEAM_ID=$(serberus_team_id "${REPO_DIR}") || TEAM_ID=""
readonly TEAM_ID

readonly APP_NAME="Auth URI Browser.app"
readonly APP_BUNDLE_ID="${ORG_DOMAIN}.authuribrowser"
readonly APP_INSTALL_DIR="/Applications"
readonly APP_PROJECT_DIR="${REPO_DIR}/extras/AuthURIBrowser"
# package_app.sh assembles the bundle here (outside cloud-synced folders). It reads
# SCRATCH, so build_app() hands this value over explicitly — the two scripts
# must agree or the pkg would package a stale (or missing) bundle.
# The default is per-user: a fixed /tmp path could be pre-created by another
# local user, whose bundle this script would then sign and package.
readonly APP_SCRATCH="${APP_SCRATCH:-${SCRATCH:-${HOME}/Library/Caches/${ORG_DOMAIN}/authuribrowser-build}}"
readonly APP_BUILT="${APP_SCRATCH}/${APP_NAME}"

readonly PKG_IDENTIFIER="${ORG_DOMAIN}.authuribrowserpkg"
readonly PKG_VERSION="${PKG_VERSION:-1.1}"

readonly MODE="${1:---build}"
readonly EMIT_DIR="${2:-}"

readonly BUILD_DIR="${SCRIPT_DIR}/build-test/authuribrowser"
# Staged outside any cloud-synced folder (see the header).
if [[ "${MODE}" == "--emit-scripts" && -n "${EMIT_DIR}" ]]
then
    readonly STAGING_DIR="${EMIT_DIR}"
else
    readonly STAGING_DIR="${SERBERUS_PKG_STAGING:-${HOME}/Library/Caches/${ORG_DOMAIN}/pkg-authuribrowser}"
fi
readonly PAYLOAD_DIR="${STAGING_DIR}/payload"
readonly SCRIPTS_DIR="${STAGING_DIR}/scripts"
readonly COMPONENT_PLIST="${STAGING_DIR}/component.plist"
readonly STAGED_APP="${PAYLOAD_DIR}${APP_INSTALL_DIR}/${APP_NAME}"
readonly FINAL_PKG="${BUILD_DIR}/AuthURIBrowser-${PKG_VERSION}.pkg"
readonly UNSIGNED_PKG="${BUILD_DIR}/AuthURIBrowser-${PKG_VERSION}-unsigned.pkg"

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

# A `pkill -f` pattern that matches ONLY a process whose command line starts
# with <path> (anchored, dots escaped), so root never signals an unrelated
# process that merely mentions the path in its arguments.
#   $1 absolute path prefix (…/Contents/MacOS/)
pkill_pattern() {
    local path="$1"
    printf '^%s' "${path//./\\.}"
}

verify_inputs() {
    if [[ "$("${ID}" -u)" -eq 0 ]]
    then
        log_error "Run as the logged-in user, not root (codesign needs your login keychain)."
        exit 1
    fi
    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_warn "SIGNING_IDENTITY unset — the app will be AD-HOC signed (test ring)."
    fi
    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        log_warn "INSTALLER_IDENTITY unset — the installer pkg will be UNSIGNED (install with sudo installer or right-click → Open)."
    fi
    if [[ -n "${NOTARY_PROFILE}" && -z "${INSTALLER_IDENTITY}" ]]
    then
        log_error "NOTARY_PROFILE needs INSTALLER_IDENTITY (only a signed pkg can be notarized)."
        exit 1
    fi
    if [[ -n "${NOTARY_PROFILE}" && ( -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ) ]]
    then
        log_error "NOTARY_PROFILE needs a real SIGNING_IDENTITY (an ad-hoc app cannot be notarized)."
        exit 1
    fi
}

# Release-build the app with SwiftPM (ad-hoc signed; re-signed in staging).
build_app() {
    log_info "Building ${APP_NAME} via extras/AuthURIBrowser/Scripts/package_app.sh"
    "${ENV}" SCRATCH="${APP_SCRATCH}" \
        "${BASH_BIN}" "${APP_PROJECT_DIR}/Scripts/package_app.sh" release >/dev/null
    if [[ ! -d "${APP_BUILT}" ]]
    then
        log_error "App bundle not found: ${APP_BUILT}"
        exit 1
    fi
}

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
    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_info "Signing ${APP_NAME} ad-hoc"
        "${CODESIGN}" --force --sign - "${STAGED_APP}"
    else
        log_info "Signing ${APP_NAME} with '${SIGNING_IDENTITY}'"
        "${CODESIGN}" --force --options runtime --timestamp --sign "${SIGNING_IDENTITY}" "${STAGED_APP}"
    fi
    if ! "${CODESIGN}" --verify --strict "${STAGED_APP}"
    then
        log_error "Signature verification failed for ${STAGED_APP} (stray xattr?)"
        exit 1
    fi
    if [[ -n "${SIGNING_IDENTITY}" && "${SIGNING_IDENTITY}" != "-" ]]
    then
        if [[ -z "${TEAM_ID}" ]]
        then
            log_error "No Apple Developer Team ID configured. Set DEVELOPMENT_TEAM in"
            log_error "Config/Local.xcconfig (copy Config/Local.xcconfig.example) or the environment."
            exit 1
        fi
        local sign_info
        sign_info=$("${CODESIGN}" -dv "${STAGED_APP}" 2>&1)
        if ! "${GREP}" -q "TeamIdentifier=${TEAM_ID}" <<< "${sign_info}"
        then
            log_error "Signature does not carry TeamIdentifier=${TEAM_ID}."
            exit 1
        fi
    fi
}

write_preinstall() {
    "${CAT}" > "${SCRIPTS_DIR}/preinstall" <<PREINSTALL_EOF
#! /bin/bash
# Auth URI Browser preinstall: quit a running copy so the bundle can be
# swapped. Best effort — never blocks the install (a target volume other than
# the running system is refused).
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
# An empty \$3 is accepted only for a manual run; under Installer the target
# must be the running system.
if [[ -n "\${3:-}" || -n "\${INSTALLER_TEMP:-}\${PACKAGE_PATH:-}\${COMMAND_LINE_INSTALL:-}" ]] \\
    && [[ "\${3:-}" != "/" ]]
then
    printf '[ERROR] Target volume is %s, not /.\n' "\${3:-<empty>}" >&2
    exit 1
fi
if /usr/bin/pkill -f "$(pkill_pattern "${APP_INSTALL_DIR}/${APP_NAME}/Contents/MacOS/")" 2>/dev/null
then
    /bin/sleep 1
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

write_postinstall() {
    "${CAT}" > "${SCRIPTS_DIR}/postinstall" <<POSTINSTALL_EOF
#! /bin/bash
# Auth URI Browser postinstall: make sure LaunchServices knows the bundle.
set -uo pipefail
umask 022
# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
# An empty \$3 is accepted only for a manual run; under Installer the target
# must be the running system.
if [[ -n "\${3:-}" || -n "\${INSTALLER_TEMP:-}\${PACKAGE_PATH:-}\${COMMAND_LINE_INSTALL:-}" ]] \\
    && [[ "\${3:-}" != "/" ]]
then
    printf '[ERROR] Target volume is %s, not /.\n' "\${3:-<empty>}" >&2
    exit 1
fi
readonly LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
"\${LSREGISTER}" -f "${APP_INSTALL_DIR}/${APP_NAME}" 2>/dev/null || true
exit 0
POSTINSTALL_EOF
    "${CHMOD}" 755 "${SCRIPTS_DIR}/postinstall"
    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/postinstall"
    then
        log_error "Generated postinstall failed bash -n"
        exit 1
    fi
}

# pkgbuild's default lets PackageKit "relocate" the install onto ANY copy of
# the bundle LaunchServices already knows about (a dev build under the repo,
# a copy on the Desktop…) instead of /Applications — and a copy in a
# cloud-synced folder then fails the swap with "Operation not permitted".
# Pinning
# BundleIsRelocatable=false forces the payload path.
write_component_plist() {
    "${PKGBUILD}" --analyze --root "${PAYLOAD_DIR}" "${COMPONENT_PLIST}" >/dev/null
    local count index
    count=$("${PLIST_BUDDY}" -c 'Print' "${COMPONENT_PLIST}" | "${GREP}" -c 'BundleIsRelocatable' || true)
    if [[ "${count}" -eq 0 ]]
    then
        log_error "pkgbuild --analyze found no bundle in ${PAYLOAD_DIR}"
        exit 1
    fi
    for (( index = 0; index < count; index++ ))
    do
        "${PLIST_BUDDY}" -c "Set :${index}:BundleIsRelocatable false" "${COMPONENT_PLIST}"
    done
    log_info "Component plist: ${count} bundle(s) pinned non-relocatable"
}

build_pkg() {
    "${MKDIR}" -p "${BUILD_DIR}"
    "${RM}" -f "${FINAL_PKG}" "${UNSIGNED_PKG}"
    write_component_plist
    # Strip strippable xattrs from the WHOLE payload tree (not just the app).
    # com.apple.provenance survives this (the kernel re-applies it and xattr
    # cannot delete it), so the bom still lists a few ._AppleDouble entries —
    # the same as every other pkg in PKG/build-test; the installer ignores
    # them. The ad-hoc signature is unaffected: codesign seals file contents.
    "${XATTR}" -rc "${PAYLOAD_DIR}"
    "${FIND}" "${PAYLOAD_DIR}" -name '._*' -delete
    if ! "${CODESIGN}" --verify --strict "${STAGED_APP}"
    then
        log_error "Signature no longer verifies after xattr strip"
        exit 1
    fi
    if [[ -n "${INSTALLER_IDENTITY}" ]]
    then
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
    "${PKGUTIL}" --check-signature "${FINAL_PKG}" || true
}

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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (mode ${MODE})"
case "${MODE}" in
    --emit-scripts)
        if [[ -z "${EMIT_DIR}" ]]
        then
            log_error "--emit-scripts requires a target directory"
            exit 1
        fi
        "${MKDIR}" -p "${SCRIPTS_DIR}"
        write_preinstall
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
"${MKDIR}" -p "${PAYLOAD_DIR}" "${SCRIPTS_DIR}"
build_app
stage_and_sign_app
write_preinstall
write_postinstall
build_pkg
log_info "Done: ${FINAL_PKG}"
if [[ -z "${NOTARY_PROFILE}" ]]
then
    log_info "Not notarized — install with: sudo installer -pkg \"${FINAL_PKG}\" -target /"
fi

exit 0

###################################################################################
############## End Script Body ####################################################
###################################################################################
