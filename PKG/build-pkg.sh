#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-pkg.sh
# Author: Heath Jones
# Date: 2026-06-13
# Modified: 2026-09-26
# Purpose: Build the Release products (serberusd, serberus CLI, pam_serberus,
#          SerberusAuth authorization plugin) from Serberus.xcodeproj,
#          assemble the Serberus endpoint payload, and build the component
#          PKG with pre/postinstall scripts. Production only: needs a
#          Developer ID identity. With the Endpoint Security provisioning
#          profile (PROVISION_PROFILE) the daemon carries the ES entitlement
#          and the exec gate is on; without it (or with ESF=off) the package
#          is built without ES, the exec gate is disabled, and the package
#          records execGate=disabled in version.plist. Curated sudo and the
#          AuthorizationDB rules do not need ES. Run as the logged-in user,
#          never root (codesign needs the login keychain).
# Version: 1.7 - (a) A supported production build without Endpoint Security:
#          ESF=off, or no PROVISION_PROFILE, signs serberusd with no
#          entitlements and no profile, prints that the exec gate is
#          disabled, and stages EXEC_GATE (enabled | disabled) for the
#          postinstall to record as execGate in version.plist. ESF=on still
#          requires the profile, and a given profile means ES is on.
#          1.6 - (a) The package version comes from the repository's VERSION
#          file (Support/version-lib.sh), and VERSION is staged beside the
#          postinstall, which writes it into version.plist.
#          1.5 - (a) Refuses SIGNING_IDENTITY="-": an ad-hoc daemon has no
#          Team ID, and the postinstall would abort every install of it.
#          (b) Package version 0.9.0.
#          1.4 - (a) uninstall.sh is no longer staged into --scripts (where
#          it was never installed): it ships in the PAYLOAD at
#          /Library/Application Support/Serberus/uninstall.sh (root:wheel
#          0755) together with pam-lib.sh (0644), so an admin can tear
#          Serberus down later. (b) Every bundle in the payload (serberusd.app,
#          SerberusAuth.bundle) is pinned BundleIsRelocatable=false via a
#          pkgbuild --analyze component plist — otherwise PackageKit may
#          "relocate" a bundle onto a copy LaunchServices knows elsewhere and
#          the daemon or plugin never lands at its fixed path. (c) Absolute
#          tool paths (Xcode tools through the /usr/bin shims). (d) The bundle
#          builder is invoked through env: the prefix assignments named
#          readonly variables, which bash refuses.
#          1.3 - (a) Ships the SerberusAuth authorization plugin at
#          /Library/Security/SecurityAgentPlugins/SerberusAuth.bundle
#          (Developer ID, hardened runtime, secure timestamp) — identity-
#          scoped authURI rules compose it into rights and could not work in
#          production without it. (b) --timestamp on every Developer ID
#          signature (notarytool rejects untimestamped code). (c) No more
#          `chown -R root:wheel` (it needed root, while codesign must NOT run
#          as root): pkgbuild --ownership recommended maps the payload to
#          root:wheel and the postinstall re-asserts ownership. Refuses to run
#          as root. (d) Header/error text: the script builds the Release
#          products itself.
#          1.2 - PAM module payload relocated to /usr/local/lib/pam/
#          pam_serberus.so: /usr/lib/pam sits on the SEALED read-only APFS
#          system snapshot (macOS 11+) — no installer payload can land
#          there — so the module ships under the /usr/local firmlink and
#          sudo_local references it by absolute path (pam-lib.sh).
#          1.1 - Explicit codesign identifiers on the re-signed CLI + PAM
#          module: a flat Mach-O otherwise defaults its identifier to the
#          filename. (The daemon validates sudo, not the module, as the PAM
#          peer; the identifier just names the module.) Scripts are now staged into
#          the build dir so the postinstall can source PKG/Scripts/pam-lib.sh
#          and create sudo_local from Support/sudo_local (single source of
#          truth).
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

# System directories only; every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly BASENAME="/usr/bin/basename"
readonly BASH_BIN="/bin/bash"
readonly CHMOD="/bin/chmod"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly DITTO="/usr/bin/ditto"
readonly ENV="/usr/bin/env"
readonly FIND="/usr/bin/find"
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
readonly SCRIPT_VERSION="1.7"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.pkg"
# The product version: one VERSION file at the repository root.
# shellcheck source=../Support/version-lib.sh
source "${REPO_DIR}/Support/version-lib.sh"
PKG_VERSION=$(serberus_product_version "${REPO_DIR}") || {
    printf '[ERROR] %s/VERSION is missing or not MAJOR.MINOR.PATCH\n' "${REPO_DIR}" >&2
    exit 1
}
readonly PKG_VERSION
readonly BUILD_DIR="${SCRIPT_DIR}/build"
readonly PAYLOAD_DIR="${BUILD_DIR}/payload"
readonly SCRIPTS_STAGE_DIR="${BUILD_DIR}/scripts"
readonly OUTPUT_PKG="${BUILD_DIR}/Serberus-${PKG_VERSION}.pkg"
readonly SIGNED_PKG="${BUILD_DIR}/Serberus-${PKG_VERSION}-signed.pkg"
# pkgbuild --analyze output, edited so no bundle in the payload is relocatable.
readonly COMPONENT_PLIST="${BUILD_DIR}/component.plist"

# Installed with the payload so an admin can run the teardown later:
#   sudo "/Library/Application Support/Serberus/uninstall.sh" [--purge]
readonly SUPPORT_DIR="/Library/Application Support/Serberus"

# Signing identifiers for the flat (non-bundle) payload binaries. A flat
# Mach-O otherwise defaults its identifier to its filename; these pin stable
# ones (the PAM identifier is BundleConfig.pamBundleID). Neither is
# daemon-validated: the PAM module runs inside sudo, so the daemon validates
# sudo as its peer, and the CLI reads plists and the database directly.
readonly PAM_IDENTIFIER="com.herojoneslabs.serberus.pam"
readonly CLI_IDENTIFIER="com.herojoneslabs.serberus.cli"

# Built artifacts. Built from Serberus.xcodeproj into .build/xcode by
# build_release_products() below; override via env if built elsewhere.
readonly XCODE_PRODUCTS="${REPO_DIR}/.build/xcode/Build/Products/Release"
readonly DAEMON_BIN="${DAEMON_BIN:-${XCODE_PRODUCTS}/serberusd}"
readonly CLI_BIN="${CLI_BIN:-${XCODE_PRODUCTS}/serberus}"
readonly PAM_SO="${PAM_SO:-${XCODE_PRODUCTS}/pam_serberus.so}"
readonly DAEMON_PLIST="${REPO_DIR}/Support/com.herojoneslabs.serberus.daemon.plist"

# The authorization mechanism bundle. Rights reference "SerberusAuth:identity"
# by NAME, so the bundle name and install path are frozen.
readonly AUTH_PLUGIN_NAME="SerberusAuth.bundle"
readonly AUTH_PLUGIN_BUILT="${AUTH_PLUGIN_BUILT:-${XCODE_PRODUCTS}/${AUTH_PLUGIN_NAME}}"
readonly AUTH_PLUGIN_INSTALL_DIR="/Library/Security/SecurityAgentPlugins"

# Signing / notarization inputs (see docs/esf-provisioning-and-notarization.md):
#   SIGNING_IDENTITY    — "Developer ID Application: Your Name (YOURTEAMID)"  (REQUIRED)
#   PROVISION_PROFILE   — path to the daemon's .provisionprofile      (ES on; optional)
#   ESF                 — on | off; unset = on when PROVISION_PROFILE is given, off otherwise
#   INSTALLER_IDENTITY  — "Developer ID Installer: Your Name (YOURTEAMID)"    (optional → unsigned installer)
#   NOTARY_PROFILE      — notarytool keychain profile name            (optional → skip notarize/staple)
# The Developer ID identity is REQUIRED: the installers pin the daemon to its
# team. The profile is needed only for the Endpoint Security exec gate.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly PROVISION_PROFILE="${PROVISION_PROFILE:-}"
readonly ESF_REQUESTED="${ESF:-}"
# on | off, set by resolve_esf_mode.
ESF_MODE=""
readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"
readonly NOTARY_PROFILE="${NOTARY_PROFILE:-}"

readonly BUNDLE_BUILD_SCRIPT="${REPO_DIR}/Support/build-serberusd-bundle.sh"
readonly BUNDLE_OUT_DIR="${BUILD_DIR}/bundle"
readonly DAEMON_BUNDLE="${BUNDLE_OUT_DIR}/serberusd.app"
readonly DAEMON_BUNDLE_INNER="${DAEMON_BUNDLE}/Contents/MacOS/com.herojoneslabs.serberus.daemon"

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

# codesign must run as the logged-in user: root cannot open the login
# keychain that holds the Developer ID identity. pkgbuild's `recommended`
# ownership produces root:wheel on the target regardless.
require_not_root() {
    if [[ "$("${ID}" -u)" -eq 0 ]]
    then
        log_error "Run as the logged-in user, not root (codesign needs your login keychain)."
        exit 1
    fi
}

build_release_products() {
    log_info "Building serberusd, serberus, pam_serberus and SerberusAuth (Release) from Serberus.xcodeproj"
    local scheme
    for scheme in serberusd serberus pam_serberus SerberusAuth
    do
        "${XCODEBUILD}" \
            -project "${REPO_DIR}/Serberus.xcodeproj" \
            -scheme "${scheme}" \
            -configuration Release \
            -derivedDataPath "${REPO_DIR}/.build/xcode" \
            CODE_SIGNING_ALLOWED=NO \
            build >/dev/null
    done
}

verify_inputs() {
    local missing=0
    local artifact
    for artifact in "${DAEMON_BIN}" "${CLI_BIN}" "${PAM_SO}" "${DAEMON_PLIST}"
    do
        if [[ ! -f "${artifact}" ]]
        then
            log_error "Missing build artifact: ${artifact}"
            missing=1
        fi
    done
    if [[ ! -d "${AUTH_PLUGIN_BUILT}" ]]
    then
        log_error "Missing build artifact: ${AUTH_PLUGIN_BUILT}"
        missing=1
    fi
    if [[ ${missing} -ne 0 ]]
    then
        log_error "The Release build above did not produce every artifact — check the xcodebuild"
        log_error "output (re-run: xcodebuild -project Serberus.xcodeproj -scheme <scheme> -configuration Release"
        log_error "-derivedDataPath .build/xcode build), or point DAEMON_BIN/CLI_BIN/PAM_SO/AUTH_PLUGIN_BUILT at prebuilt copies."
        exit 1
    fi

    # The installers pin the daemon to its signing team, so a Developer ID
    # identity is required. (Installer signing + notarization remain optional.)
    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_error "SIGNING_IDENTITY (a Developer ID identity; ad-hoc \"-\" is refused) is required."
        log_error "  SIGNING_IDENTITY=\"Developer ID Application: Your Name (YOURTEAMID)\""
        exit 1
    fi
    if ! resolve_esf_mode
    then
        exit 1
    fi
}

# Chooses the Endpoint Security mode (ESF_MODE): ESF=on needs the profile;
# ESF=off builds without ES even when a profile is given; unset means on
# when PROVISION_PROFILE is given and off otherwise. Returns 1 (reason
# logged) for ESF=on without a readable profile or an unknown ESF value.
resolve_esf_mode() {
    case "${ESF_REQUESTED}" in
        on)
            ESF_MODE="on"
            ;;
        off)
            ESF_MODE="off"
            if [[ -n "${PROVISION_PROFILE}" ]]
            then
                log_warn "ESF=off: PROVISION_PROFILE is ignored"
            fi
            ;;
        "")
            if [[ -n "${PROVISION_PROFILE}" ]]
            then
                ESF_MODE="on"
            else
                ESF_MODE="off"
            fi
            ;;
        *)
            log_error "ESF must be on or off (got '${ESF_REQUESTED}')"
            return 1
            ;;
    esac
    if [[ "${ESF_MODE}" == "on" ]]
    then
        if [[ -z "${PROVISION_PROFILE}" ]]
        then
            log_error "ESF=on needs PROVISION_PROFILE=/path/to/serberusd.provisionprofile"
            log_error "See docs/esf-provisioning-and-notarization.md (Part 1) to obtain the profile, or build with ESF=off."
            return 1
        fi
        if [[ ! -f "${PROVISION_PROFILE}" ]]
        then
            log_error "PROVISION_PROFILE not found: ${PROVISION_PROFILE}"
            return 1
        fi
        log_info "Endpoint Security: ON (profile ${PROVISION_PROFILE}) — the exec gate is enabled"
        return 0
    fi
    log_warn "=================================================================="
    log_warn "Endpoint Security: OFF — building WITHOUT the ES entitlement."
    log_warn "The EXEC GATE IS DISABLED on Macs that install this package."
    log_warn "Curated sudo and the AuthorizationDB rules work as usual."
    log_warn "The package records execGate=disabled in version.plist."
    log_warn "=================================================================="
    return 0
}

# enabled | disabled, for EXEC_GATE and version.plist.
exec_gate_state() {
    if [[ "${ESF_MODE}" == "on" ]]
    then
        printf 'enabled'
    else
        printf 'disabled'
    fi
}

build_and_sign_bundle() {
    log_info "Building + signing the daemon bundle (serberusd.app)"
    # Through env: SIGNING_IDENTITY, PROVISION_PROFILE and DAEMON_BIN are
    # readonly here, and bash refuses `readonly_var=… cmd` prefix assignments.
    local profile="${PROVISION_PROFILE}"
    if [[ "${ESF_MODE}" != "on" ]]
    then
        profile=""
    fi
    "${ENV}" SIGNING_IDENTITY="${SIGNING_IDENTITY}" \
        PROVISION_PROFILE="${profile}" \
        ESF="${ESF_MODE}" \
        DAEMON_BIN="${DAEMON_BIN}" \
        OUTPUT_DIR="${BUNDLE_OUT_DIR}" \
        "${BASH_BIN}" "${BUNDLE_BUILD_SCRIPT}"
}

assemble_payload() {
    log_info "Assembling payload at ${PAYLOAD_DIR}"
    "${MKDIR}" -p "${PAYLOAD_DIR}/Library/PrivilegedHelperTools"
    "${MKDIR}" -p "${PAYLOAD_DIR}/Library/LaunchDaemons"
    # /usr/lib/pam is on the sealed read-only system snapshot — the module
    # MUST live under the /usr/local firmlink (see pam-lib.sh, which wires
    # sudo_local to it by absolute path).
    "${MKDIR}" -p "${PAYLOAD_DIR}/usr/local/lib/pam"
    "${MKDIR}" -p "${PAYLOAD_DIR}/usr/local/bin"
    "${MKDIR}" -p "${PAYLOAD_DIR}${SUPPORT_DIR}/authdb-backups"

    # The signed daemon bundle — ditto preserves the code signature + the sealed
    # embedded.provisionprofile (ES builds only).
    "${DITTO}" "${DAEMON_BUNDLE}" "${PAYLOAD_DIR}/Library/PrivilegedHelperTools/serberusd.app"
    "${CP}" "${DAEMON_PLIST}" "${PAYLOAD_DIR}/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
    "${CP}" "${PAM_SO}" "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"
    "${CP}" "${CLI_BIN}" "${PAYLOAD_DIR}/usr/local/bin/serberus"
    # The admin-run teardown and the library it sources (marker-aware
    # sudo_local / sudoers removal, bounded one-shots, AuthorizationDB check).
    "${CP}" "${SCRIPT_DIR}/Scripts/uninstall.sh" "${PAYLOAD_DIR}${SUPPORT_DIR}/uninstall.sh"
    "${CP}" "${SCRIPT_DIR}/Scripts/pam-lib.sh" "${PAYLOAD_DIR}${SUPPORT_DIR}/pam-lib.sh"

    # Sign the auxiliary binaries (Developer ID + Hardened Runtime + secure
    # timestamp — notarytool rejects code without one) so the whole payload
    # passes notarization. Explicit --identifier on both, so neither carries a
    # filename-derived identifier.
    local -a sign_args=(--force --options runtime --sign "${SIGNING_IDENTITY}")
    if [[ "${SIGNING_IDENTITY}" != "-" ]]
    then
        sign_args+=(--timestamp)
    fi
    log_info "Signing CLI + PAM module"
    "${CODESIGN}" "${sign_args[@]}" \
        --identifier "${CLI_IDENTIFIER}" \
        "${PAYLOAD_DIR}/usr/local/bin/serberus"
    "${CODESIGN}" "${sign_args[@]}" \
        --identifier "${PAM_IDENTIFIER}" \
        "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"

    # Authorization plugin: copied, stripped of xattrs (codesign rejects
    # FinderInfo detritus on a bundle outright), signed as a bundle with NO
    # entitlements (a plug-in is not a main executable), and verified. The
    # postinstall requires it to carry the daemon's Team ID.
    local plugin="${PAYLOAD_DIR}${AUTH_PLUGIN_INSTALL_DIR}/${AUTH_PLUGIN_NAME}"
    "${MKDIR}" -p "${PAYLOAD_DIR}${AUTH_PLUGIN_INSTALL_DIR}"
    "${DITTO}" "${AUTH_PLUGIN_BUILT}" "${plugin}"
    "${XATTR}" -rc "${plugin}"
    log_info "Signing ${AUTH_PLUGIN_NAME}"
    "${CODESIGN}" "${sign_args[@]}" "${plugin}"
    if ! "${CODESIGN}" --verify --strict "${plugin}"
    then
        log_error "Signed ${AUTH_PLUGIN_NAME} failed codesign --verify --strict"
        exit 1
    fi

    # Modes per the install manifest. Ownership is NOT set here (that needs
    # root, and this script must not run as root): pkgbuild
    # --ownership recommended installs everything root:wheel, and the
    # postinstall re-asserts it.
    "${FIND}" "${PAYLOAD_DIR}/Library/PrivilegedHelperTools/serberusd.app" -type d -exec "${CHMOD}" 755 {} +
    "${CHMOD}" 755 "${PAYLOAD_DIR}/Library/PrivilegedHelperTools/serberusd.app/Contents/MacOS/com.herojoneslabs.serberus.daemon"
    "${CHMOD}" 644 "${PAYLOAD_DIR}/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
    "${CHMOD}" 755 "${PAYLOAD_DIR}/usr/local/lib/pam"
    "${CHMOD}" 444 "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"
    "${CHMOD}" 755 "${PAYLOAD_DIR}/usr/local/bin/serberus"
    "${CHMOD}" -R go-w "${plugin}"
    "${CHMOD}" 755 "${PAYLOAD_DIR}${SUPPORT_DIR}"
    "${CHMOD}" 700 "${PAYLOAD_DIR}${SUPPORT_DIR}/authdb-backups"
    "${CHMOD}" 755 "${PAYLOAD_DIR}${SUPPORT_DIR}/uninstall.sh"
    "${CHMOD}" 644 "${PAYLOAD_DIR}${SUPPORT_DIR}/pam-lib.sh"
}

# pkgbuild ships the whole --scripts directory alongside pre/postinstall, so
# staging lets both scripts source pam-lib.sh (the shared sudo_local merge,
# break-glass preflight and teardown logic) and the postinstall create
# sudo_local from Support/sudo_local — the single source of truth for its
# content. (uninstall.sh ships in the payload instead — see assemble_payload.)
stage_scripts() {
    log_info "Staging installer scripts at ${SCRIPTS_STAGE_DIR}"
    "${MKDIR}" -p "${SCRIPTS_STAGE_DIR}"
    "${CP}" "${SCRIPT_DIR}/Scripts/preinstall" \
        "${SCRIPT_DIR}/Scripts/postinstall" \
        "${SCRIPT_DIR}/Scripts/pam-lib.sh" \
        "${SCRIPTS_STAGE_DIR}/"
    "${CP}" "${REPO_DIR}/Support/sudo_local" "${SCRIPTS_STAGE_DIR}/sudo_local"
    # The postinstall writes this product version into version.plist.
    "${CP}" "${REPO_DIR}/VERSION" "${SCRIPTS_STAGE_DIR}/VERSION"
    # ...and whether this build has the Endpoint Security exec gate.
    printf '%s\n' "$(exec_gate_state)" > "${SCRIPTS_STAGE_DIR}/EXEC_GATE"
    "${CHMOD}" 755 "${SCRIPTS_STAGE_DIR}/preinstall" "${SCRIPTS_STAGE_DIR}/postinstall"
}

# pkgbuild's default lets PackageKit "relocate" a bundle onto ANY copy of it
# LaunchServices already knows about (a dev build in a working copy, a copy on
# the Desktop…) instead of the payload path — serberusd.app or
# SerberusAuth.bundle would then not land where the LaunchDaemon plist and
# the AuthorizationDB rights expect them. Pin every bundle pkgbuild --analyze
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
        log_error "pkgbuild --analyze found no bundle in ${PAYLOAD_DIR} (expected serberusd.app and SerberusAuth.bundle)"
        exit 1
    fi
    if "${PLIST_BUDDY}" -c 'Print' "${COMPONENT_PLIST}" | "${GREP}" -q 'BundleIsRelocatable = true'
    then
        log_error "Component plist still marks a bundle relocatable: ${COMPONENT_PLIST}"
        exit 1
    fi
    log_info "Component plist: ${index} bundle(s) pinned non-relocatable"
}

build_package() {
    write_component_plist
    log_info "Building component pkg ${OUTPUT_PKG}"
    "${PKGBUILD}" \
        --root "${PAYLOAD_DIR}" \
        --component-plist "${COMPONENT_PLIST}" \
        --scripts "${SCRIPTS_STAGE_DIR}" \
        --identifier "${PKG_IDENTIFIER}" \
        --version "${PKG_VERSION}" \
        --ownership recommended \
        "${OUTPUT_PKG}"
    log_info "Built ${OUTPUT_PKG}"
}

sign_installer() {
    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        log_warn "INSTALLER_IDENTITY unset — installer left UNSIGNED (${OUTPUT_PKG})."
        log_warn "Set INSTALLER_IDENTITY=\"Developer ID Installer: Your Name (YOURTEAMID)\" to sign + enable notarization."
        return 0
    fi
    log_info "Signing installer with '${INSTALLER_IDENTITY}'"
    "${PRODUCTSIGN}" --sign "${INSTALLER_IDENTITY}" "${OUTPUT_PKG}" "${SIGNED_PKG}"
    log_info "Signed installer: ${SIGNED_PKG}"
}

notarize_and_staple() {
    if [[ -z "${NOTARY_PROFILE}" ]]
    then
        log_warn "NOTARY_PROFILE unset — skipping notarization. One-time setup:"
        log_warn "  xcrun notarytool store-credentials serberus-notary --apple-id <id> --team-id YOURTEAMID"
        log_warn "Then re-run with NOTARY_PROFILE=serberus-notary."
        return 0
    fi
    if [[ ! -f "${SIGNED_PKG}" ]]
    then
        log_error "Cannot notarize: ${SIGNED_PKG} missing (set INSTALLER_IDENTITY so the installer is signed first)."
        return 1
    fi
    log_info "Submitting ${SIGNED_PKG} to the notary service (can take a few minutes)"
    "${XCRUN}" notarytool submit "${SIGNED_PKG}" --keychain-profile "${NOTARY_PROFILE}" --wait
    log_info "Stapling the notarization ticket"
    "${XCRUN}" stapler staple "${SIGNED_PKG}"
}

verify_final() {
    local pkg="${OUTPUT_PKG}"
    if [[ -f "${SIGNED_PKG}" ]]
    then
        pkg="${SIGNED_PKG}"
    fi
    log_info "Final package: ${pkg}"
    if [[ -n "${NOTARY_PROFILE}" ]] && [[ -f "${SIGNED_PKG}" ]]
    then
        "${XCRUN}" stapler validate "${pkg}" || log_warn "stapler validate failed"
        "${SPCTL}" -a -vvv -t install "${pkg}" 2>&1 || log_warn "spctl install assessment failed"
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

require_not_root
build_release_products
verify_inputs
"${RM}" -rf "${BUILD_DIR}"
"${MKDIR}" -p "${BUILD_DIR}"
build_and_sign_bundle
assemble_payload
stage_scripts
build_package
sign_installer
notarize_and_staple
verify_final

if [[ "${ESF_MODE}" != "on" ]]
then
    log_warn "Built WITHOUT Endpoint Security: the exec gate is DISABLED (execGate=disabled in version.plist)."
fi
log_info "${SCRIPT_NAME} completed successfully"

###########################################################
################## End Script Block #######################
###########################################################
