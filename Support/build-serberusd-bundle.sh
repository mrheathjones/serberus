#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-serberusd-bundle.sh
# Author: Heath Jones
# Date: 2026-06-24
# Modified: 2026-09-26
# Purpose: Wrap the serberusd Mach-O in an app-like bundle (serberusd.app) so it
#          can carry the embedded.provisionprofile that authorizes the restricted
#          Endpoint Security entitlement, then Developer-ID-sign it. A bare CLI
#          daemon cannot hold a provisioning profile; this is Apple's documented
#          pattern (docs/esf-provisioning-and-notarization.md).
#          ESF=off builds the same bundle WITHOUT Endpoint Security: no
#          provisioning profile, and signed with no entitlements (the
#          application-identifier and team-identifier keys need a profile
#          too), so the daemon runs with the exec gate disabled.
# Version: 1.6 - ESF=off (set by build-pkg.sh when no provisioning profile
#          is given): the bundle is built and Developer-ID-signed without
#          the ES entitlement and without a profile, and verify_bundle
#          checks that no ES entitlement is present. ESF=on (the default)
#          is unchanged.
#          1.5 - (a) The bundle version comes from the repository's VERSION
#          file (Support/version-lib.sh). (b) Refuses ad-hoc signing
#          (SIGNING_IDENTITY="-"): an ad-hoc bundle carrying the Endpoint
#          Security entitlement is killed by AMFI at launch. (c) After
#          signing, the bundle's TeamIdentifier must equal the team rendered
#          into the entitlements.
#          1.4 - Bundle version 0.9.0 (the public release).
#          1.3 - (a) Signs with an explicit --identifier
#          com.herojoneslabs.serberus.daemon and verifies it: the PAM module
#          and the Sentinel/Intel clients pin the daemon peer to that
#          identifier + the team. (b) Absolute tool paths (no PATH lookup,
#          no bare grep/cat).
#          1.2 - Signs with --timestamp for any real (non-ad-hoc) identity:
#          notarytool rejects Developer ID code without a secure timestamp.
#          1.1 - The distribution entitlements are a template: __TEAM_ID__ is
#          filled in from DEVELOPMENT_TEAM (environment or
#          Config/Local.xcconfig, via Support/team-id-lib.sh) into a rendered
#          copy beside the bundle, instead of hardcoding one team.
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

# System directories only; every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly AWK="/usr/bin/awk"
readonly BASENAME="/usr/bin/basename"
readonly CAT="/bin/cat"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly GREP="/usr/bin/grep"
readonly MKDIR="/bin/mkdir"
readonly RM="/bin/rm"
readonly SED="/usr/bin/sed"
readonly SECURITY="/usr/bin/security"

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

# The explicit App ID the provisioning profile is issued for. Must match the
# CFBundleIdentifier and the application-identifier entitlement.
readonly BUNDLE_ID="com.herojoneslabs.serberus.daemon"
readonly EXECUTABLE_NAME="com.herojoneslabs.serberus.daemon"
# shellcheck source=version-lib.sh
source "${REPO_DIR}/Support/version-lib.sh"
BUNDLE_VERSION=$(serberus_product_version "${REPO_DIR}") || BUNDLE_VERSION=""
readonly BUNDLE_VERSION

# Inputs (override via environment):
#   SIGNING_IDENTITY    — "Developer ID Application: … (YOURTEAMID)" (required)
#   PROVISION_PROFILE   — path to the downloaded .provisionprofile (required)
#   DAEMON_BIN          — the serberusd Mach-O to wrap
#   ENTITLEMENTS        — distribution entitlements template (3 keys; any
#                         __TEAM_ID__ is replaced with the configured team)
#   DEVELOPMENT_TEAM    — Apple Developer Team ID (default: Config/Local.xcconfig)
#   OUTPUT_DIR          — where serberusd.app is written
#   ESF                 — on (default): ES entitlement + profile; off: neither
#                         (the exec gate is disabled)
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly PROVISION_PROFILE="${PROVISION_PROFILE:-}"
readonly ESF="${ESF:-on}"
readonly XCODE_PRODUCTS="${REPO_DIR}/.build/xcode/Build/Products/Release"
readonly DAEMON_BIN="${DAEMON_BIN:-${XCODE_PRODUCTS}/serberusd}"
readonly ENTITLEMENTS="${ENTITLEMENTS:-${REPO_DIR}/Support/serberusd-distribution.entitlements}"
readonly OUTPUT_DIR="${OUTPUT_DIR:-${REPO_DIR}/.build/bundle}"
# The entitlements actually signed with: ENTITLEMENTS with the team filled in.
readonly RENDERED_ENTITLEMENTS="${OUTPUT_DIR}/serberusd-distribution.entitlements"
# shellcheck source=team-id-lib.sh
source "${REPO_DIR}/Support/team-id-lib.sh"
TEAM_ID=$(serberus_team_id "${REPO_DIR}") || TEAM_ID=""
readonly TEAM_ID
readonly BUNDLE_PATH="${OUTPUT_DIR}/serberusd.app"

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
    local missing=0
    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_error "SIGNING_IDENTITY is required and ad-hoc \"-\" is refused (e.g. 'Developer ID Application: Your Name (YOURTEAMID)')"
        missing=1
    fi
    if [[ -z "${BUNDLE_VERSION}" ]]
    then
        log_error "${REPO_DIR}/VERSION is missing or not MAJOR.MINOR.PATCH"
        missing=1
    fi
    if [[ "${ESF}" != "on" && "${ESF}" != "off" ]]
    then
        log_error "ESF must be on or off (got: '${ESF}')"
        missing=1
    fi
    if [[ "${ESF}" == "on" ]] && { [[ -z "${PROVISION_PROFILE}" ]] || [[ ! -f "${PROVISION_PROFILE}" ]]; }
    then
        log_error "PROVISION_PROFILE must point to the downloaded .provisionprofile (got: '${PROVISION_PROFILE}'), or set ESF=off"
        missing=1
    fi
    if [[ ! -f "${DAEMON_BIN}" ]]
    then
        log_error "DAEMON_BIN not found: ${DAEMON_BIN} (build serberusd Release first)"
        missing=1
    fi
    if [[ ! -f "${ENTITLEMENTS}" ]]
    then
        log_error "ENTITLEMENTS not found: ${ENTITLEMENTS}"
        missing=1
    fi
    if [[ -z "${TEAM_ID}" ]]
    then
        log_error "No Apple Developer Team ID configured. Set DEVELOPMENT_TEAM in Config/Local.xcconfig (copy Config/Local.xcconfig.example) or the environment."
        missing=1
    fi
    if [[ ${missing} -ne 0 ]]
    then
        exit 1
    fi
}

verify_profile() {
    if [[ "${ESF}" == "off" ]]
    then
        log_info "ESF=off: no provisioning profile, no Endpoint Security entitlement — the exec gate is DISABLED"
        return 0
    fi
    # The ES entitlement needs a profile that provisions all machines; warn (not
    # fail) if that marker is absent so the build is still inspectable.
    if ! "${SECURITY}" cms -D -i "${PROVISION_PROFILE}" 2>/dev/null | "${GREP}" -q "ProvisionsAllDevices"
    then
        log_error "WARNING: ${PROVISION_PROFILE} has no ProvisionsAllDevices marker — confirm it is a Developer ID profile for an explicit App ID with the Endpoint Security capability."
    fi
}

render_entitlements() {
    if [[ "${ESF}" == "off" ]]
    then
        return 0
    fi
    # Fill the team into the entitlements template. The result must carry no
    # placeholder: signing with a literal __TEAM_ID__ would produce a daemon
    # AMFI refuses to launch.
    log_info "Rendering ${ENTITLEMENTS} for team ${TEAM_ID}"
    "${MKDIR}" -p "${OUTPUT_DIR}"
    "${SED}" "s/__TEAM_ID__/${TEAM_ID}/g" "${ENTITLEMENTS}" > "${RENDERED_ENTITLEMENTS}"
    if "${GREP}" -q "__TEAM_ID__" "${RENDERED_ENTITLEMENTS}"
    then
        log_error "Unfilled __TEAM_ID__ placeholder in ${RENDERED_ENTITLEMENTS}"
        exit 1
    fi
}

assemble_bundle() {
    log_info "Assembling ${BUNDLE_PATH}"
    "${RM}" -rf "${BUNDLE_PATH}"
    "${MKDIR}" -p "${BUNDLE_PATH}/Contents/MacOS"

    "${CP}" "${DAEMON_BIN}" "${BUNDLE_PATH}/Contents/MacOS/${EXECUTABLE_NAME}"
    if [[ "${ESF}" == "on" ]]
    then
        "${CP}" "${PROVISION_PROFILE}" "${BUNDLE_PATH}/Contents/embedded.provisionprofile"
    fi

    "${CAT}" > "${BUNDLE_PATH}/Contents/Info.plist" <<INFO_PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>serberusd</string>
    <key>CFBundleExecutable</key>
    <string>${EXECUTABLE_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${BUNDLE_VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${BUNDLE_VERSION}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>LSBackgroundOnly</key>
    <true/>
</dict>
</plist>
INFO_PLIST_EOF

    printf 'APPL????' > "${BUNDLE_PATH}/Contents/PkgInfo"
}

sign_bundle() {
    # Sign the bundle with the distribution entitlements + Hardened Runtime. For
    # an app bundle this applies the entitlements to the main executable and seals
    # the embedded.provisionprofile that authorizes the ES entitlement.
    # --timestamp: notarization requires a secure timestamp on Developer ID
    # code (verify_inputs has already refused ad-hoc "-").
    local -a sign_args=(--force --options runtime --timestamp)
    # ESF=off: no entitlements at all. application-identifier and
    # team-identifier are honoured only with a provisioning profile, and
    # without ES the daemon needs no code entitlement (Support/serberusd.entitlements).
    if [[ "${ESF}" == "on" ]]
    then
        sign_args+=(--entitlements "${RENDERED_ENTITLEMENTS}")
    fi
    log_info "Signing ${BUNDLE_PATH} with '${SIGNING_IDENTITY}' (ESF=${ESF})"
    # Explicit --identifier (it matches CFBundleIdentifier): the PAM module and
    # the Sentinel/Intel clients pin the daemon peer to `identifier
    # "com.herojoneslabs.serberus.daemon" and anchor apple generic and
    # certificate leaf[subject.OU] = "<team>"`.
    "${CODESIGN}" "${sign_args[@]}" \
        --identifier "${BUNDLE_ID}" \
        --sign "${SIGNING_IDENTITY}" \
        "${BUNDLE_PATH}"
}

verify_bundle() {
    log_info "Verifying signature + entitlements"
    "${CODESIGN}" --verify --strict --verbose=2 "${BUNDLE_PATH}"
    local identifier
    identifier=$("${CODESIGN}" --display --verbose=2 "${BUNDLE_PATH}" 2>&1 \
        | "${AWK}" -F= '/^Identifier=/{print $2}')
    if [[ "${identifier}" != "${BUNDLE_ID}" ]]
    then
        log_error "Signing identifier is '${identifier}', expected '${BUNDLE_ID}' (peers pin it)."
        exit 1
    fi
    # The certificate's team must be the team rendered into the entitlements
    # (application-identifier / team-identifier); AMFI refuses a mismatch, and
    # the installers pin the daemon to its team.
    local team
    team=$("${CODESIGN}" --display --verbose=2 "${BUNDLE_PATH}" 2>&1 \
        | "${AWK}" -F= '/^TeamIdentifier=/{print $2; exit}')
    if [[ "${team}" != "${TEAM_ID}" ]]
    then
        log_error "Signed by team '${team:-none}', but the entitlements were rendered for team ${TEAM_ID}."
        log_error "Use a SIGNING_IDENTITY from team ${TEAM_ID}, or set DEVELOPMENT_TEAM to the identity's team."
        exit 1
    fi
    local entitlements
    entitlements=$("${CODESIGN}" -d --entitlements :- "${BUNDLE_PATH}/Contents/MacOS/${EXECUTABLE_NAME}" 2>/dev/null) || entitlements=""
    if [[ "${ESF}" == "off" ]]
    then
        if "${GREP}" -q "endpoint-security" <<< "${entitlements}"
        then
            log_error "ESF=off but the bundle carries the Endpoint Security entitlement"
            exit 1
        fi
        log_info "No Endpoint Security entitlement (ESF=off): the exec gate is DISABLED in this build"
        return 0
    fi
    log_info "Embedded entitlements:"
    "${GREP}" -E "endpoint-security|application-identifier|team-identifier" <<< "${entitlements}" \
        || log_error "WARNING: expected ES/application-identifier/team-identifier entitlements not found"
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

verify_inputs
verify_profile
render_entitlements
assemble_bundle
sign_bundle
verify_bundle

log_info "Built ${BUNDLE_PATH}"
log_info "Install: copy to /Library/PrivilegedHelperTools/serberusd.app and point the LaunchDaemon plist's Program at Contents/MacOS/${EXECUTABLE_NAME} (the .pkg does this)."

###########################################################
################## End Script Block #######################
###########################################################
