#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-apps.sh
# Author: Heath Jones
# Date: 2026-06-13
# Modified: 2026-09-26
# Purpose: Convenience builder for UI work only — Release-build Serberus
#          Commander and the Serberus Sentinel window app from
#          Serberus.xcodeproj into dist/ (ad hoc) or LIVE_DIR (signed), so
#          they can be launched with `open`. It does not build the menu-bar
#          agent, Guardian or the daemon; the packages in PKG/ do that.
#          Day-to-day, just open Serberus.xcodeproj in Xcode and press Run.
# Version: 2.4 - The signing note no longer promises per-app entitlements
#          (none are passed; the Sentinel's needs a profile). Absolute tool
#          paths instead of `which`.
#          2.3 - comment cleanup (no dated notes)
#          2.2 - moved to extras/; respects xcode-select instead of forcing
#                /Applications/Xcode.app; system PATH; prints where the
#                apps actually went
#          2.1 - product names carry spaces ("Serberus Commander.app",
#                "Serberus Sentinel.app"); scheme and bundle name are
#                passed separately (was: assumed ${scheme}.app)
#
#
#
######################################################################
############## End Script Information Block ##########################
######################################################################

set -euo pipefail

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute tool paths; xcodebuild through its /usr/bin shim, which respects
# xcode-select.
readonly BASENAME="/usr/bin/basename"
readonly CHMOD="/bin/chmod"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly MKDIR="/bin/mkdir"
readonly RM="/bin/rm"
readonly XATTR="/usr/bin/xattr"
readonly XCODEBUILD="/usr/bin/xcodebuild"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly REPO_DIR=$(cd "$("${DIRNAME}" "$0")/.." && pwd)
readonly DIST_DIR="${REPO_DIR}/dist"
# Overridable: building under iCloud Drive intermittently trips a macOS build
# sandbox deny on the header-copy step. Set SERBERUS_DERIVED=/tmp/serberus-dd to
# build to a local path if you hit "Sandbox: ditto deny".
readonly DERIVED="${SERBERUS_DERIVED:-${REPO_DIR}/.build/xcode}"
readonly PRODUCTS="${DERIVED}/Build/Products/Release"

# Ad-hoc ("-") by default → a playable build for UI work, left in dist/. Set
# SIGNING_IDENTITY to a real identity (e.g. "Developer ID Application: Your Name
# (YOURTEAMID)", the daemon's team) to produce builds signed with that team and
# Hardened Runtime, for the live prompt round-trip. No entitlements are added:
# the Sentinel's custom entitlement needs a provisioning profile (see the note
# above the Sentinel build below), and Commander needs none.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"

# Signed apps are staged OUTSIDE iCloud Drive: iCloud stamps a com.apple.FinderInfo
# xattr onto anything under it, which invalidates a Developer ID signature and
# makes AMFI refuse to spawn the app ("Launchd job spawn failed"). A local dir
# is never touched by iCloud, so the signature stays valid.
readonly LIVE_DIR="${LIVE_DIR:-${HOME}/serberus-live}"

# EVERY build (ad-hoc too) is signed in a local staging dir first and only then
# copied to its destination. Signing in place under dist/ can race anything
# that re-adds com.apple.FinderInfo within seconds of `xattr -cr`: codesign
# then refuses ("resource fork, Finder information, or similar detritus not
# allowed") and, with the error hidden, set -e would abort the script, leaving
# an UNSIGNED app and no Sentinel build. Signing locally embeds the signature
# in the Mach-O before the xattr can come back; dist/ copies may later fail
# `codesign --verify --strict` (re-stamped xattrs) but still launch.
readonly MKTEMP=$(which mktemp)
readonly STAGE_ROOT=$("${MKTEMP}" -d "${TMPDIR:-/tmp}/serberus-build-apps.XXXXXX")
cleanup() { "${RM}" -rf "${STAGE_ROOT}"; }
trap cleanup EXIT

log_info() {
    printf '[INFO] %s\n' "$*"
}

# build_app <scheme> <product-name> [entitlements-file]
#   scheme       — the Xcode scheme/target (no spaces), e.g. SerberusCommander
#   product-name — PRODUCT_NAME from project.yml, i.e. the bundle name without
#                  ".app", e.g. "Serberus Commander" (may contain spaces)
build_app() {
    local scheme="$1"
    local product="$2"
    local entitlements="${3:-}"

    log_info "Building ${product}.app (scheme ${scheme}, Release)"
    "${XCODEBUILD}" \
        -project "${REPO_DIR}/Serberus.xcodeproj" \
        -scheme "${scheme}" \
        -configuration Release \
        -derivedDataPath "${DERIVED}" \
        CODE_SIGNING_ALLOWED=NO \
        build >/dev/null

    local out_dir="${DIST_DIR}"
    [[ "${SIGNING_IDENTITY}" != "-" ]] && out_dir="${LIVE_DIR}"
    "${MKDIR}" -p "${out_dir}"

    local app="${out_dir}/${product}.app"
    if [[ ! -d "${PRODUCTS}/${product}.app" ]]
    then
        log_info "ERROR: expected build product not found: ${PRODUCTS}/${product}.app (check PRODUCT_NAME in project.yml)"
        exit 1
    fi

    # Stage + sign locally (never in a cloud-synced folder — see STAGE_ROOT above).
    local staged="${STAGE_ROOT}/${product}.app"
    "${RM}" -rf "${staged}"
    "${CP}" -R "${PRODUCTS}/${product}.app" "${staged}"
    "${CHMOD}" -R u+w "${staged}"
    "${XATTR}" -cr "${staged}"

    if [[ "${SIGNING_IDENTITY}" != "-" ]]
    then
        # No --timestamp: a local test build doesn't need a notarization
        # timestamp, and it would require network access to timestamp.apple.com.
        local -a sign_args=(--force --options runtime --sign "${SIGNING_IDENTITY}")
        if [[ -n "${entitlements}" ]]
        then
            sign_args+=(--entitlements "${REPO_DIR}/${entitlements}")
        fi
        log_info "Signing ${product}.app with '${SIGNING_IDENTITY}'${entitlements:+ + ${entitlements}}"
        "${CODESIGN}" "${sign_args[@]}" "${staged}"
    else
        log_info "Signing ${product}.app ad-hoc"
        "${CODESIGN}" --force --sign "-" "${staged}"
    fi
    if ! "${CODESIGN}" --verify --strict "${staged}"
    then
        log_info "ERROR: signature verification failed for ${staged} (stray xattr?)"
        exit 1
    fi

    "${RM}" -rf "${app}"
    "${CP}" -R "${staged}" "${app}"
    log_info "Built ${app}"
}

log_info "${SCRIPT_NAME} starting (signing identity: ${SIGNING_IDENTITY})"

build_app "SerberusCommander" "Serberus Commander"
# The Sentinel is signed WITHOUT its custom entitlement: a locally
# Apple-Development-signed app bundle that declares a custom entitlement is
# AMFI-killed unless a provisioning profile authorizes it, and Xcode automatic
# signing refuses to mint a profile for a non-Apple entitlement. For the local
# live test, start the daemon with SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT=1 so it
# does not require the entitlement. A notarized production build adds it back.
build_app "SerberusSentinel" "Serberus Sentinel"

# The standalone SerberusIntel app was retired: its live
# authorizations / log history / export UI is now the Sentinel window's Intel
# tab. Nothing to build here any more. The hidden menu-bar agent
# ("Serberus Sentinel Agent.app") is packaged by PKG/build-sentinel-app-pkg.sh.

OUT_DIR="${DIST_DIR}"
[[ "${SIGNING_IDENTITY}" != "-" ]] && OUT_DIR="${LIVE_DIR}"
log_info "Done. Launch with:"
log_info "  open '${OUT_DIR}/Serberus Commander.app'"
log_info "  open '${OUT_DIR}/Serberus Sentinel.app'   # window (My Activity / My Rules / Intel)"
