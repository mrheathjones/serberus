#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-combined-pkg.sh
# Author: Heath Jones
# Date: 2026-08-21
# Modified: 2026-09-25
# Purpose: Build the ALL-IN-ONE Serberus TEST-RING installer — SerberusTest-<v>.pkg
#          — a DISTRIBUTION (product) pkg that bundles the two component pkgs
#          so a single install lays down everything:
#            • SerberusCore-<v>.pkg           (daemon, pam_serberus, the
#                                               SerberusAuth authorization
#                                               plugin, the serberus CLI;
#                                               PKG/build-core-test-pkg.sh)
#                                               ← installs FIRST
#            • SerberusSentinelApp-<v>.pkg     (full Serberus Sentinel.app with
#                                               its Finder Sync extension, the
#                                               "Serberus Sentinel Agent.app"
#                                               menu bar app, Serberus
#                                               Guardian.app, and the sentinel,
#                                               guardian and finderext-elect
#                                               LaunchAgents)
#          This is the "one pkg to deploy everything" build. The two component
#          pkgs remain independently deployable (build them with their own
#          scripts) so a device that only needs ONE half updated gets just that
#          pkg — because installing the combined pkg registers BOTH component
#          RECEIPTS, a later individual pkg upgrades that component in place.
#
#          WHY A DISTRIBUTION PKG (not a merged flat pkg): each half has its own
#          safety-critical pre/postinstall (the Agent's break-glass preflight +
#          sudo_local wiring; the App's agent bootstrap). A distribution pkg
#          runs each component's scripts unchanged and in order — Agent first,
#          so if its preflight ABORTS the genuine-brick case the App never
#          installs either. Merging them into one flat pkg would force one
#          script pair and lose that proven logic.
#
#          Order matters: the Agent (daemon + sudo gate) installs before the
#          App, so the enforcement half is in place before the UI starts.
# Version: 1.3 - Output renamed SerberusTest-<v>.pkg so the test build can
#          never be mistaken for the production Serberus-<v>.pkg.
#          1.2 - The core component is built by PKG/build-core-test-pkg.sh
#          (renamed from build-sentinel-test-pkg.sh) and named
#          SerberusCore-<v>.pkg; its receipt id (…sentineltestpkg) is
#          unchanged. Absolute tool paths.
#          1.1 - Header and usage text match the current component payloads
#          and the COMBINED_VERSION default.
#          1.0 - Initial Script
#
#
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER, never sudo — codesign needs your login
# keychain):
#
#   SIGNING_IDENTITY=<Apple Development cert hash or name> ./PKG/build-combined-pkg.sh
#
# Optional env:
#   INSTALLER_IDENTITY   "Developer ID Installer: Your Name (YOURTEAMID)" —
#                        signs the FINAL combined pkg (Jamf policy installs
#                        accept unsigned; PreStage/double-click need signed).
#   COMBINED_VERSION     version of SerberusTest-<v>.pkg (default 1.10).
#   AGENT_VERSION        version of the Core component (default: its own).
#   APP_VERSION          version of the App component (default: its own).
#   SERBERUS_DERIVED     derivedDataPath for the app xcodebuild (forwarded).
#   SENTINEL_WITH_ENTITLEMENT  forwarded to the App builder (Developer ID ring).
#
# The component pkgs it wraps are built UNSIGNED (installer-signature-wise) here
# and the wrapping distribution pkg is signed instead; build the standalone
# component pkgs with their own scripts if you want each individually signed.

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
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly ENV="/usr/bin/env"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly MKDIR="/bin/mkdir"
readonly MKTEMP="/usr/bin/mktemp"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly PRODUCTBUILD="/usr/bin/productbuild"
readonly RM="/bin/rm"
readonly SED="/usr/bin/sed"
readonly SORT="/usr/bin/sort"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.3"
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

# Component builders and their output directories (must match those scripts).
readonly AGENT_BUILDER="${SCRIPT_DIR}/build-core-test-pkg.sh"
readonly APP_BUILDER="${SCRIPT_DIR}/build-sentinel-app-pkg.sh"
readonly AGENT_OUT_DIR="${SCRIPT_DIR}/build-test/core"
readonly APP_OUT_DIR="${SCRIPT_DIR}/build-test/sentinel-app"

# Default component versions mirror the builders' own defaults; overridable so a
# combined build can pin exact component versions.
readonly AGENT_VERSION="${AGENT_VERSION:-3.8}"
readonly APP_VERSION="${APP_VERSION:-3.10}"
readonly COMBINED_VERSION="${COMBINED_VERSION:-1.10}"

readonly AGENT_PKG="${AGENT_OUT_DIR}/SerberusCore-${AGENT_VERSION}.pkg"
readonly APP_PKG="${APP_OUT_DIR}/SerberusSentinelApp-${APP_VERSION}.pkg"

readonly BUILD_DIR="${SCRIPT_DIR}/build-test/combined"
# "SerberusTest", never "Serberus": the production package is
# Serberus-<version>(-signed).pkg, and once a file is uploaded to Jamf its
# folder is gone — the name alone must say this is the test build.
readonly OUTPUT_PKG="${BUILD_DIR}/SerberusTest-${COMBINED_VERSION}.pkg"

# The product identifier for the distribution (distinct from the two component
# receipt ids, which are what actually register on-device).
readonly PRODUCT_ID="${ORG_PLIST_DOMAIN}.combined"

readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"

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
    if [[ "$("${ID}" -u)" -eq 0 ]]
    then
        log_error "Run as the logged-in user, not root (the component builds codesign with your login keychain)."
        exit 1
    fi

    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_error "SIGNING_IDENTITY is required — the component builders sign the daemon, PAM module, and app with it."
        log_error "  security find-identity -v -p codesigning   # list identities"
        log_error "  SIGNING_IDENTITY=<hash> ./PKG/${SCRIPT_NAME}"
        exit 1
    fi

    for builder in "${AGENT_BUILDER}" "${APP_BUILDER}"
    do
        if [[ ! -f "${builder}" ]]
        then
            log_error "Component builder not found: ${builder}"
            exit 1
        fi
    done
}

# Build the AGENT component pkg (daemon + PAM), UNSIGNED at the installer layer
# (INSTALLER_IDENTITY withheld) — the wrapping distribution pkg carries the
# installer signature. The daemon/PAM BINARIES are still signed via SIGNING_IDENTITY.
build_agent_component() {
    log_info "Building CORE component (SerberusCore: daemon + PAM + SerberusAuth + CLI), version ${AGENT_VERSION}"
    "${ENV}" PKG_VERSION="${AGENT_VERSION}" \
        SIGNING_IDENTITY="${SIGNING_IDENTITY}" \
        INSTALLER_IDENTITY="" \
        "${BASH_BIN}" "${AGENT_BUILDER}"
    if [[ ! -f "${AGENT_PKG}" ]]
    then
        log_error "Agent component build did not produce ${AGENT_PKG}"
        exit 1
    fi
}

# Build the APP component pkg (full app + menu bar agent app), UNSIGNED at the
# installer layer (each app BUNDLE is signed via SIGNING_IDENTITY).
build_app_component() {
    log_info "Building APP component (full app + menu bar agent), version ${APP_VERSION}"
    "${ENV}" PKG_VERSION="${APP_VERSION}" \
        SIGNING_IDENTITY="${SIGNING_IDENTITY}" \
        INSTALLER_IDENTITY="" \
        SERBERUS_DERIVED="${SERBERUS_DERIVED:-${REPO_DIR}/.build/xcode}" \
        SENTINEL_WITH_ENTITLEMENT="${SENTINEL_WITH_ENTITLEMENT:-0}" \
        "${BASH_BIN}" "${APP_BUILDER}"
    if [[ ! -f "${APP_PKG}" ]]
    then
        log_error "App component build did not produce ${APP_PKG}"
        exit 1
    fi
}

# Wrap the two component pkgs into one distribution (product) pkg. Agent is
# listed first so it installs first (daemon + sudo gate before the UI).
build_distribution() {
    "${MKDIR}" -p "${BUILD_DIR}"
    "${RM}" -f "${OUTPUT_PKG}"

    local staging
    staging=$("${MKTEMP}" -d)
    # productbuild references the component pkgs by filename from --package-path.
    "${CP}" "${AGENT_PKG}" "${staging}/"
    "${CP}" "${APP_PKG}" "${staging}/"

    local agent_base app_base distribution
    agent_base=$("${BASENAME}" "${AGENT_PKG}")
    app_base=$("${BASENAME}" "${APP_PKG}")
    distribution="${staging}/distribution.xml"

    # Synthesize a distribution from the two components (order = install order:
    # Agent first). Then stamp a product title + version onto it.
    log_info "Synthesizing distribution (Agent → App)"
    "${PRODUCTBUILD}" --synthesize \
        --package "${staging}/${agent_base}" \
        --package "${staging}/${app_base}" \
        "${distribution}"

    # Insert a human title and a product id/version right after <installer-...>.
    # BSD sed: -i '' for in-place, and a literal newline via a backslash-continued
    # replacement.
    "${SED}" -i '' "s|<installer-gui-script\(.*\)>|<installer-gui-script\1>\\
    <title>Serberus</title>\\
    <product id=\"${PRODUCT_ID}\" version=\"${COMBINED_VERSION}\"/>|" "${distribution}"

    log_info "Building combined pkg ${OUTPUT_PKG}"
    local -a args=(--distribution "${distribution}" --package-path "${staging}")
    if [[ -n "${INSTALLER_IDENTITY}" ]]
    then
        args+=(--sign "${INSTALLER_IDENTITY}")
        log_info "Signing combined pkg with '${INSTALLER_IDENTITY}'"
    fi
    "${PRODUCTBUILD}" "${args[@]}" "${OUTPUT_PKG}"

    "${RM}" -rf "${staging}"
}

# End-to-end sanity: the finished combined pkg must reference BOTH component
# receipts (so a later individual pkg upgrades in place) and both restored apps
# must be present.
verify_combined() {
    local ids
    ids=""
    if "${PKGUTIL}" --expand "${OUTPUT_PKG}" "${BUILD_DIR}/_verify" >/dev/null 2>&1
    then
        ids=$("${GREP}" -ho 'com.herojoneslabs.serberus.[a-z]*testpkg' "${BUILD_DIR}/_verify/Distribution" 2>/dev/null \
            | "${SORT}" -u) || ids=""
    fi
    "${RM}" -rf "${BUILD_DIR}/_verify"
    if [[ "${ids}" != *"sentineltestpkg"* || "${ids}" != *"sentinelapptestpkg"* ]]
    then
        log_error "Combined pkg does not reference both component receipts (agent + app):"
        log_error "  found: ${ids:-<none>}"
        exit 1
    fi
    log_info "Combined pkg references both component receipts: OK"
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting — SerberusTest-${COMBINED_VERSION}.pkg (Agent ${AGENT_VERSION} + App ${APP_VERSION})"

verify_inputs
build_agent_component
build_app_component
build_distribution
verify_combined

log_info "Done. Three deployable test-ring pkgs:"
log_info "  COMBINED: ${OUTPUT_PKG}"
log_info "  CORE:     ${AGENT_PKG}   (daemon + pam + SerberusAuth + CLI)"
log_info "  APP:      ${APP_PKG}   (full app + menu bar agent)"
log_info "Deploy the combined for a full install, or an individual pkg when only that half changed."

###########################################################
################## End Script Block #######################
###########################################################
